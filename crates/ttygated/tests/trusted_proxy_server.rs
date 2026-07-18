use std::{
    fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    panic::{AssertUnwindSafe, resume_unwind},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use axum::http::{HeaderValue, StatusCode, header};
use futures_util::{FutureExt, SinkExt, StreamExt};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{self, client::IntoClientRequest},
};
use ttygated::{
    config::parse,
    server::{AppState, serve},
    ticket::{Identity, TicketError},
};

const ORIGIN: &str = "https://terminal.example.test";
const PTY_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pty_child.sh");

struct RawResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }
}

struct TestServer {
    address: SocketAddr,
    state: AppState,
    task: JoinHandle<()>,
    marker: PathBuf,
    _directory: TempDir,
}

struct TlsProxy {
    address: SocketAddr,
    origin: String,
    connector: TlsConnector,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<bool>,
}

impl TlsProxy {
    async fn start(backend: SocketAddr, identity: &str) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let identity = identity.to_owned();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let identity = identity.clone();
                        connections.spawn(async move {
                            let _ = proxy_connection(acceptor, stream, backend, &identity).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed {
                            assert!(error.is_cancelled(), "proxy connection task failed: {error}");
                        }
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            true
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Self {
            address,
            origin: ORIGIN.to_owned(),
            connector,
            shutdown,
            task,
        }
    }

    async fn tls_stream(&self) -> TlsStream<TcpStream> {
        let stream = TcpStream::connect(self.address).await.unwrap();
        self.connector
            .connect(
                ServerName::try_from("localhost").unwrap().to_owned(),
                stream,
            )
            .await
            .unwrap()
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        origin: Option<&str>,
        cookie: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> RawResponse {
        let mut stream = self.tls_stream().await;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\nContent-Length: {}",
            self.address.port(),
            body.len()
        );
        if let Some(origin) = origin {
            request.push_str(&format!("\r\nOrigin: {origin}"));
        }
        if let Some(cookie) = cookie {
            request.push_str(&format!("\r\nCookie: {cookie}"));
        }
        for (name, value) in extra_headers {
            request.push_str(&format!("\r\n{name}: {value}"));
        }
        if !body.is_empty() {
            request.push_str("\r\nContent-Type: application/json");
        }
        request.push_str("\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response).await {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "TLS proxy response read failed: {error}"
            );
        }
        parse_response(&response)
    }

    async fn provision_cookie(&self) -> String {
        let response = self
            .request("POST", "/api/identity", Some(&self.origin), None, &[], b"")
            .await;
        assert_eq!(response.status, 204);
        std::str::from_utf8(response.header("set-cookie").unwrap())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    async fn issue_ticket(&self, cookie: &str) -> String {
        let response = self
            .request(
                "POST",
                "/api/sessions",
                Some(&self.origin),
                Some(cookie),
                &[],
                br#"{"target":"shell"}"#,
            )
            .await;
        assert_eq!(response.status, 201);
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn websocket(
        &self,
        origin: &str,
        cookie: &str,
    ) -> Result<WebSocketStream<TlsStream<TcpStream>>, tungstenite::Error> {
        let stream = self.tls_stream().await;
        let mut request = format!("wss://localhost:{}/api/ws", self.address.port())
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        client_async(request, stream)
            .await
            .map(|(socket, _)| socket)
    }

    async fn stop(self) -> bool {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("proxy task shutdown timed out")
            .expect("proxy task join failed")
    }
}

async fn proxy_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    backend: SocketAddr,
    identity: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = acceptor.accept(stream).await?;
    let mut request = Vec::new();
    let head_end = loop {
        if request.len() > 16 * 1024 {
            return Err("proxy request headers are too large".into());
        }
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        let read = client.read_buf(&mut request).await?;
        if read == 0 {
            return Err("proxy client closed before request headers".into());
        }
    };
    let rewritten = rewrite_identity_header(&request, head_end, identity)?;
    let destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), backend.port());
    let mut upstream = TcpStream::connect(destination).await?;
    upstream.write_all(&rewritten).await?;
    let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn rewrite_identity_header(
    request: &[u8],
    head_end: usize,
    identity: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let head = std::str::from_utf8(&request[..head_end])?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("proxy request line is missing")?;
    let mut rewritten = Vec::with_capacity(request.len() + identity.len() + 32);
    rewritten.extend_from_slice(request_line.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for line in lines {
        let Some((name, _)) = line.split_once(':') else {
            return Err("proxy request header is malformed".into());
        };
        if !name.eq_ignore_ascii_case("x-authenticated-user") {
            rewritten.extend_from_slice(line.as_bytes());
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"X-Authenticated-User: ");
    rewritten.extend_from_slice(identity.as_bytes());
    rewritten.extend_from_slice(b"\r\n\r\n");
    rewritten.extend_from_slice(&request[head_end + 4..]);
    Ok(rewritten)
}

fn fixture_pids(marker: &Path) -> Vec<i32> {
    let Ok(contents) = fs::read_to_string(marker) else {
        return Vec::new();
    };
    contents
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect()
}

fn process_exists(pid: i32) -> bool {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
    match kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(Errno::ESRCH) => false,
        Err(error) => panic!("failed to inspect PID {pid}: {error}"),
    }
}

fn kill_fixture_pids(pids: &[i32]) {
    use nix::{
        errno::Errno,
        sys::signal::{Signal, kill, killpg},
        unistd::Pid,
    };
    for group in pids.chunks(2) {
        if let Some(leader) = group.first().copied()
            && let Err(error) = killpg(Pid::from_raw(leader), Signal::SIGKILL)
            && error != Errno::ESRCH
        {
            panic!("failed to kill fixture process group {leader}: {error}");
        }
        for pid in group {
            if let Err(error) = kill(Pid::from_raw(*pid), Signal::SIGKILL)
                && error != Errno::ESRCH
            {
                panic!("failed to kill fixture PID {pid}: {error}");
            }
        }
    }
}

async fn wait_for_pids_absent(pids: &[i32], timeout: Duration) -> Result<(), ()> {
    tokio::time::timeout(timeout, async {
        while pids.iter().copied().any(process_exists) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| ())
}

async fn wait_for_fixture_pids(marker: &Path, expected: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture_pids(marker).len() != expected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("PTY fixture did not record expected PIDs");
}

async fn wait_for_fixture_absence(marker: &Path) {
    let pids = fixture_pids(marker);
    wait_for_pids_absent(&pids, Duration::from_secs(3))
        .await
        .expect("PTY fixture processes survived cleanup");
}

impl TestServer {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("proxy-fixture-pids");
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let source = format!(
            r#"
[server]
bind = "{address}"
mode = "production"
public_url = "{ORIGIN}"
[server.trusted_proxy]
trusted_sources = ["::1/128"]
[auth]
provider = "trusted-proxy"
identity_header = "x-authenticated-user"
[audit]
format = "json"
path = "./audit.jsonl"
recording = false
[limits]
max_sessions = 8
max_sessions_per_user = 2
idle_timeout_seconds = 5
absolute_timeout_seconds = 10
[[targets]]
name = "shell"
type = "pty"
command = [{PTY_FIXTURE:?}, "browser-track", {marker:?}]
"#
        );
        let state = AppState::from_config(&parse(&source).unwrap()).unwrap();
        let serving_state = state.clone();
        let task = tokio::spawn(async move {
            serve(listener, serving_state).await.unwrap();
        });
        Self {
            address,
            state,
            task,
            marker,
            _directory: directory,
        }
    }

    async fn request(&self, source: IpAddr, request: Vec<u8>) -> RawResponse {
        let (socket, destination) = match source {
            IpAddr::V4(_) => (
                TcpSocket::new_v4().unwrap(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.address.port()),
            ),
            IpAddr::V6(_) => (
                TcpSocket::new_v6().unwrap(),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.address.port()),
            ),
        };
        socket.bind(SocketAddr::new(source, 0)).unwrap();
        let mut stream = socket.connect(destination).await.unwrap();
        stream.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        parse_response(&response)
    }

    async fn stop(self) {
        let pids = fixture_pids(&self.marker);
        self.state.sessions().shutdown().await;
        self.task.abort();
        let _ = self.task.await;
        if wait_for_pids_absent(&pids, Duration::from_millis(500))
            .await
            .is_err()
        {
            kill_fixture_pids(&pids);
            wait_for_pids_absent(&pids, Duration::from_secs(3))
                .await
                .unwrap();
        }
    }
}

struct ProxyStack {
    backend: TestServer,
    proxy: TlsProxy,
}

impl ProxyStack {
    async fn start(identity: &str) -> Self {
        let backend = TestServer::start().await;
        let proxy = TlsProxy::start(backend.address, identity).await;
        Self { backend, proxy }
    }

    async fn stop(self) {
        self.proxy.stop().await;
        self.backend.stop().await;
    }
}

async fn with_proxy_test<F>(identity: &str, body: F)
where
    F: for<'stack> FnOnce(&'stack ProxyStack) -> Pin<Box<dyn Future<Output = ()> + Send + 'stack>>,
{
    let stack = ProxyStack::start(identity).await;
    let outcome = AssertUnwindSafe(body(&stack)).catch_unwind().await;
    stack.stop().await;
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

fn request(path: &str, headers: &[(&str, &[u8])], body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: terminal.example.test\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for (name, value) in headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    request
}

fn parse_response(bytes: &[u8]) -> RawResponse {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = &bytes[..split];
    let body = bytes[split + 4..].to_vec();
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines.next().unwrap();
    let status = std::str::from_utf8(status_line)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            Some((
                std::str::from_utf8(&line[..colon]).unwrap().to_owned(),
                line[colon + 1..]
                    .iter()
                    .copied()
                    .skip_while(|byte| *byte == b' ')
                    .collect(),
            ))
        })
        .collect();
    RawResponse {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn real_listener_accepts_configured_loopback_peer_identity() {
    let server = TestServer::start().await;

    let response = server
        .request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            request("/api/identity", &[("X-Authenticated-User", b"alice")], b""),
        )
        .await;

    assert_eq!(response.status, 204);
    let cookie = response.header("set-cookie").unwrap();
    for attribute in [
        b"Secure".as_slice(),
        b"HttpOnly",
        b"SameSite=Strict",
        b"Path=/",
    ] {
        assert!(
            cookie
                .windows(attribute.len())
                .any(|window| window == attribute)
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn direct_backend_client_cannot_gain_trust_with_forwarded_headers() {
    let server = TestServer::start().await;

    let response = server
        .request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            request(
                "/api/identity",
                &[
                    ("X-Authenticated-User", b"alice"),
                    ("X-Forwarded-For", b"127.0.0.1"),
                    ("X-Real-IP", b"127.0.0.1"),
                    ("Forwarded", b"for=127.0.0.1"),
                ],
                b"",
            ),
        )
        .await;

    assert_eq!(response.status, 503);
    assert!(response.header("set-cookie").is_none());
    server.stop().await;
}

#[tokio::test]
async fn real_listener_duplicate_and_malformed_identity_create_no_authority() {
    let server = TestServer::start().await;
    for headers in [
        vec![
            ("X-Authenticated-User", b"alice".as_slice()),
            ("X-Authenticated-User", b"alice".as_slice()),
        ],
        vec![("X-Authenticated-User", b"malformed identity".as_slice())],
        vec![("X-Authenticated-User", &[0xff, 0xfe])],
    ] {
        let response = server
            .request(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                request("/api/identity", &headers, b""),
            )
            .await;
        assert!(matches!(response.status, 400 | 503));
        assert!(response.header("set-cookie").is_none());
        let rendered = String::from_utf8_lossy(&response.body);
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("malformed identity"));
    }
    server.stop().await;
}

#[tokio::test]
async fn raw_http_optional_whitespace_has_explicit_semantic_identity_behavior() {
    let server = TestServer::start().await;
    let raw_identity_request = format!(
        "POST /api/identity HTTP/1.1\r\nHost: terminal.example.test\r\nOrigin: {ORIGIN}\r\nContent-Length: 0\r\nConnection: close\r\nX-Authenticated-User:\t alice \t\r\n\r\n"
    )
    .into_bytes();

    let identity = server
        .request(IpAddr::V6(Ipv6Addr::LOCALHOST), raw_identity_request)
        .await;
    assert_eq!(identity.status, 204);
    let cookie = identity
        .header("set-cookie")
        .unwrap()
        .split(|byte| *byte == b';')
        .next()
        .unwrap();
    let session = server
        .request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            request(
                "/api/sessions",
                &[("Cookie", cookie), ("Content-Type", b"application/json")],
                br#"{"target":"shell"}"#,
            ),
        )
        .await;
    assert_eq!(session.status, 201);
    let session_body = serde_json::from_slice::<serde_json::Value>(&session.body).unwrap();
    let ticket = session_body["ticket"].as_str().unwrap();
    let alice = Identity::new("alice").unwrap();
    assert_eq!(
        server
            .state
            .tickets()
            .redeem(ticket, &alice)
            .unwrap()
            .target()
            .name(),
        "shell"
    );
    server.stop().await;
}

#[tokio::test]
async fn untrusted_real_peer_cannot_replay_valid_ttygate_cookie() {
    let server = TestServer::start().await;
    let identity = server
        .request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            request("/api/identity", &[("X-Authenticated-User", b"alice")], b""),
        )
        .await;
    let cookie = identity
        .header("set-cookie")
        .unwrap()
        .split(|byte| *byte == b';')
        .next()
        .unwrap();
    let mut events = server.state.sessions().subscribe_events();

    let session = server
        .request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            request(
                "/api/sessions",
                &[
                    ("Cookie", cookie),
                    ("Content-Type", b"application/json"),
                    ("X-Authenticated-User", b"alice"),
                    ("X-Forwarded-For", b"::1"),
                ],
                br#"{"target":"shell"}"#,
            ),
        )
        .await;

    assert_eq!(session.status, 401);
    assert!(events.try_recv().is_err());
    server.stop().await;
}

#[tokio::test]
async fn failed_proxy_authentication_starts_no_session_or_pty() {
    let server = TestServer::start().await;
    let mut events = server.state.sessions().subscribe_events();

    let identity = server
        .request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            request(
                "/api/identity",
                &[
                    ("X-Authenticated-User", b"alice"),
                    ("X-Forwarded-For", b"127.0.0.1"),
                ],
                b"",
            ),
        )
        .await;
    assert_eq!(identity.status, 503);
    let session = server
        .request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            request(
                "/api/sessions",
                &[("Content-Type", b"application/json")],
                br#"{"target":"shell"}"#,
            ),
        )
        .await;

    assert_eq!(session.status, 401);
    assert!(events.try_recv().is_err());
    server.stop().await;
}

#[tokio::test]
async fn trusted_proxy_https_cookie_ticket_wss_reaches_real_pty_echo() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "alice").await;
    let cookie = proxy.provision_cookie().await;
    let ticket = proxy.issue_ticket(&cookie).await;
    let mut socket = proxy.websocket(&proxy.origin, &cookie).await.unwrap();
    socket
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    socket
        .send(tungstenite::Message::Binary(
            b"proxy-flow\r".to_vec().into(),
        ))
        .await
        .unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !output
            .windows(b"ECHO:proxy-flow".len())
            .any(|window| window == b"ECHO:proxy-flow")
        {
            if let tungstenite::Message::Binary(bytes) = socket.next().await.unwrap().unwrap() {
                output.extend_from_slice(&bytes);
            }
        }
    })
    .await
    .unwrap();
    socket.close(None).await.unwrap();
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn proxy_strips_spoofed_identity_before_injecting_authenticated_identity() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "alice").await;
    let identity = proxy
        .request(
            "POST",
            "/api/identity",
            Some(&proxy.origin),
            None,
            &[
                ("X-Authenticated-User", "mallory"),
                ("X-Authenticated-User", "mallory-again"),
            ],
            b"",
        )
        .await;
    assert_eq!(identity.status, 204);
    let cookie = std::str::from_utf8(identity.header("set-cookie").unwrap())
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let ticket = proxy.issue_ticket(&cookie).await;
    let mallory = Identity::new("mallory").unwrap();
    assert!(matches!(
        backend.state.tickets().redeem(&ticket, &mallory),
        Err(TicketError::WrongIdentity)
    ));
    let alice = Identity::new("alice").unwrap();
    assert_eq!(
        backend
            .state
            .tickets()
            .redeem(&ticket, &alice)
            .unwrap()
            .target()
            .name(),
        "shell"
    );
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn proxy_cookie_identity_binds_ticket_and_wrong_identity_cannot_redeem() {
    let backend = TestServer::start().await;
    let alice_proxy = TlsProxy::start(backend.address, "alice").await;
    let bob_proxy = TlsProxy::start(backend.address, "bob").await;
    let alice_cookie = alice_proxy.provision_cookie().await;
    let alice_ticket = alice_proxy.issue_ticket(&alice_cookie).await;
    let bob_cookie = bob_proxy.provision_cookie().await;
    let mut events = backend.state.sessions().subscribe_events();

    let mut bob = bob_proxy
        .websocket(&bob_proxy.origin, &bob_cookie)
        .await
        .unwrap();
    bob.send(tungstenite::Message::Text(
        format!(r#"{{"ticket":"{alice_ticket}"}}"#).into(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = bob.next().await {
            if matches!(message.unwrap(), tungstenite::Message::Close(_)) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(events.try_recv().is_err());

    let mut alice = alice_proxy
        .websocket(&alice_proxy.origin, &alice_cookie)
        .await
        .unwrap();
    alice
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{alice_ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    alice
        .send(tungstenite::Message::Binary(
            b"alice-only\r".to_vec().into(),
        ))
        .await
        .unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !output
            .windows(b"ECHO:alice-only".len())
            .any(|window| window == b"ECHO:alice-only")
        {
            if let tungstenite::Message::Binary(bytes) = alice.next().await.unwrap().unwrap() {
                output.extend_from_slice(&bytes);
            }
        }
    })
    .await
    .unwrap();
    alice.close(None).await.unwrap();
    bob_proxy.stop().await;
    alice_proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn existing_cookie_identity_survives_proxy_account_switch() {
    let backend = TestServer::start().await;
    let alice_proxy = TlsProxy::start(backend.address, "alice").await;
    let bob_proxy = TlsProxy::start(backend.address, "bob").await;
    let alice_cookie = alice_proxy.provision_cookie().await;

    let ticket = bob_proxy.issue_ticket(&alice_cookie).await;
    let bob = Identity::new("bob").unwrap();
    assert!(matches!(
        backend.state.tickets().redeem(&ticket, &bob),
        Err(TicketError::WrongIdentity)
    ));
    let alice = Identity::new("alice").unwrap();
    assert_eq!(
        backend
            .state
            .tickets()
            .redeem(&ticket, &alice)
            .unwrap()
            .target()
            .name(),
        "shell"
    );

    bob_proxy.stop().await;
    alice_proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn trusted_proxy_wrong_origin_rejects_http_session_creation() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "alice").await;
    let cookie = proxy.provision_cookie().await;

    let response = proxy
        .request(
            "POST",
            "/api/sessions",
            Some("https://attacker.invalid"),
            Some(&cookie),
            &[],
            br#"{"target":"shell"}"#,
        )
        .await;

    assert_eq!(response.status, 403);
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn trusted_proxy_wrong_origin_rejects_websocket_upgrade() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "alice").await;
    let cookie = proxy.provision_cookie().await;

    let error = proxy
        .websocket("https://attacker.invalid", &cookie)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        tungstenite::Error::Http(ref response) if response.status() == StatusCode::FORBIDDEN
    ));
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn failed_proxy_auth_leaves_no_cookie_ticket_session_or_pty() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "invalid identity").await;
    let mut events = backend.state.sessions().subscribe_events();

    let response = proxy
        .request("POST", "/api/identity", Some(&proxy.origin), None, &[], b"")
        .await;

    assert_eq!(response.status, 503);
    assert!(response.header("set-cookie").is_none());
    assert!(events.try_recv().is_err());
    proxy.stop().await;
    backend.stop().await;
}

#[tokio::test]
async fn repeated_trusted_proxy_startup_shutdown_reaps_all_tasks() {
    for iteration in 1..=20 {
        with_proxy_test("alice", |stack| {
            Box::pin(async move {
                let response = stack
                    .proxy
                    .request("GET", "/healthz", None, None, &[], b"")
                    .await;
                assert_eq!(response.status, 200, "iteration {iteration}");
            })
        })
        .await;
    }
}

#[tokio::test]
async fn repeated_failed_proxy_authentication_leaves_no_application_work() {
    for iteration in 1..=20 {
        with_proxy_test("invalid identity", |stack| {
            Box::pin(async move {
                let mut events = stack.backend.state.sessions().subscribe_events();
                let response = stack
                    .proxy
                    .request(
                        "POST",
                        "/api/identity",
                        Some(&stack.proxy.origin),
                        None,
                        &[],
                        b"",
                    )
                    .await;
                assert_eq!(response.status, 503, "iteration {iteration}");
                assert!(events.try_recv().is_err(), "iteration {iteration}");
                assert!(!stack.backend.marker.exists(), "iteration {iteration}");
            })
        })
        .await;
    }
}

#[tokio::test]
async fn repeated_proxy_websocket_drop_reaps_real_pty() {
    for iteration in 1..=20 {
        with_proxy_test("alice", |stack| {
            Box::pin(async move {
                let cookie = stack.proxy.provision_cookie().await;
                let ticket = stack.proxy.issue_ticket(&cookie).await;
                let mut socket = stack
                    .proxy
                    .websocket(&stack.proxy.origin, &cookie)
                    .await
                    .unwrap();
                socket
                    .send(tungstenite::Message::Text(
                        format!(r#"{{"ticket":"{ticket}"}}"#).into(),
                    ))
                    .await
                    .unwrap();
                wait_for_fixture_pids(&stack.backend.marker, 2).await;
                drop(socket);
                wait_for_fixture_absence(&stack.backend.marker).await;
                assert!(
                    fixture_pids(&stack.backend.marker)
                        .into_iter()
                        .all(|pid| !process_exists(pid)),
                    "iteration {iteration}"
                );
            })
        })
        .await;
    }
}

#[tokio::test]
async fn trusted_proxy_fixture_cleanup_awaits_shutdown_before_resuming_panic() {
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&observed);
    let task = tokio::spawn(async move {
        with_proxy_test("alice", move |stack| {
            Box::pin(async move {
                let cookie = stack.proxy.provision_cookie().await;
                let ticket = stack.proxy.issue_ticket(&cookie).await;
                let mut socket = stack
                    .proxy
                    .websocket(&stack.proxy.origin, &cookie)
                    .await
                    .unwrap();
                socket
                    .send(tungstenite::Message::Text(
                        format!(r#"{{"ticket":"{ticket}"}}"#).into(),
                    ))
                    .await
                    .unwrap();
                wait_for_fixture_pids(&stack.backend.marker, 2).await;
                *recorded.lock().unwrap() = fixture_pids(&stack.backend.marker);
                panic!("intentional trusted proxy fixture unwind");
            })
        })
        .await;
    });

    let error = task.await.unwrap_err();
    assert!(error.is_panic());
    for pid in observed.lock().unwrap().iter().copied() {
        assert!(
            !process_exists(pid),
            "fixture PID {pid} survived panic cleanup"
        );
    }
}

#[tokio::test]
async fn tls_proxy_stop_drains_active_connection_tasks() {
    let backend = TestServer::start().await;
    let proxy = TlsProxy::start(backend.address, "alice").await;
    let _held_open_connection = proxy.tls_stream().await;

    let drained = proxy.stop().await;

    assert!(
        drained,
        "proxy stop returned before connection tasks drained"
    );
    backend.stop().await;
}
