use std::{
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::http::{HeaderValue, StatusCode, header};
use futures_util::{SinkExt, StreamExt};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName},
    },
};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{self, client::IntoClientRequest},
};
use ttygated::{config, startup};

const PTY_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pty_child.sh");

struct HttpResponse {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

struct TlsTestServer {
    address: SocketAddr,
    origin: String,
    connector: TlsConnector,
    untrusted_connector: TlsConnector,
    marker: PathBuf,
    task: Option<JoinHandle<Result<(), startup::StartupError>>>,
    _directory: TempDir,
}

impl Drop for TlsTestServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        kill_fixture_pids(&fixture_pids(&self.marker));
    }
}

impl TlsTestServer {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("certificate.pem");
        let private_key_path = directory.path().join("private-key.pem");
        let marker = directory.path().join("fixture-pids");
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        write(&certificate_path, cert.pem().as_bytes(), 0o644);
        write(
            &private_key_path,
            signing_key.serialize_pem().as_bytes(),
            0o600,
        );

        let address = available_address();
        let origin = format!("https://localhost:{}", address.port());
        let source = configuration(
            address,
            &origin,
            &certificate_path,
            &private_key_path,
            &marker,
        );
        let config = config::parse(&source).unwrap();
        let task = tokio::spawn(async move { startup::start(&config).await });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();
        let trusted_connector = connector(roots);
        let untrusted_connector = connector(RootCertStore::empty());

        let server = Self {
            address,
            origin,
            connector: trusted_connector,
            untrusted_connector,
            marker,
            task: Some(task),
            _directory: directory,
        };
        for _ in 0..100 {
            if server.task.as_ref().unwrap().is_finished() {
                panic!("TLS server exited during startup");
            }
            if let Ok(response) = server.request("GET", "/healthz", None, None, b"").await
                && response.status == 200
            {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("TLS server did not become healthy");
    }

    async fn stop(mut self) -> Result<(), String> {
        let pids = fixture_pids(&self.marker);
        if let Some(task) = self.task.take() {
            task.abort();
            match task.await {
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(format!("TLS server join failed: {error}")),
                Ok(Err(error)) => return Err(format!("TLS server failed: {error}")),
                Ok(Ok(())) => {}
            }
        }
        if wait_for_absence(&pids, Duration::from_millis(500))
            .await
            .is_err()
        {
            kill_fixture_pids(&pids);
            wait_for_absence(&pids, Duration::from_secs(3)).await?;
        }
        Ok(())
    }

    async fn tls_stream(&self, name: &str) -> Result<TlsStream<TcpStream>, std::io::Error> {
        let tcp = TcpStream::connect(self.address).await?;
        self.connector
            .connect(ServerName::try_from(name.to_owned()).unwrap(), tcp)
            .await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        origin: Option<&str>,
        cookie: Option<&str>,
        body: &[u8],
    ) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        let stream = self.tls_stream("localhost").await?;
        request_on_tls(stream, self.address, method, path, origin, cookie, body).await
    }

    async fn provision_cookie(&self) -> String {
        let response = self
            .request("POST", "/api/identity", Some(&self.origin), None, b"")
            .await
            .unwrap();
        assert_eq!(response.status, 204);
        response
            .headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("set-cookie")
                    .then(|| value.trim())
            })
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
                br#"{"target":"shell"}"#,
            )
            .await
            .unwrap();
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
        let stream = self.tls_stream("localhost").await.unwrap();
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
}

fn available_address() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn configuration(
    address: SocketAddr,
    origin: &str,
    certificate: &Path,
    private_key: &Path,
    marker: &Path,
) -> String {
    format!(
        r#"
[server]
bind = "{address}"
mode = "dev"
public_url = "{origin}"
[server.tls]
certificate = {certificate:?}
private_key = {private_key:?}
[auth]
provider = "dev"
user = "tls-test"
[audit]
format = "json"
path = "./unused-tls-test-audit.jsonl"
recording = false
[limits]
max_sessions = 4
max_sessions_per_user = 4
idle_timeout_seconds = 30
absolute_timeout_seconds = 60
[[targets]]
name = "shell"
type = "pty"
command = [{PTY_FIXTURE:?}, "browser-track", {marker:?}]
"#
    )
}

fn connector(roots: RootCertStore) -> TlsConnector {
    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    set_mode(path, mode);
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

async fn request_on_tls(
    mut stream: TlsStream<TcpStream>,
    address: SocketAddr,
    method: &str,
    path: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    body: &[u8],
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\nContent-Length: {}",
        address.port(),
        body.len()
    );
    if let Some(origin) = origin {
        request.push_str(&format!("\r\nOrigin: {origin}"));
    }
    if let Some(cookie) = cookie {
        request.push_str(&format!("\r\nCookie: {cookie}"));
    }
    if !body.is_empty() {
        request.push_str("\r\nContent-Type: application/json");
    }
    request.push_str("\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_response(response)
}

fn parse_response(response: Vec<u8>) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("HTTP response has no header terminator")?;
    let headers = String::from_utf8(response[..split].to_vec())?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP response has no status")?
        .parse()?;
    Ok(HttpResponse {
        status,
        headers,
        body: response[split + 4..].to_vec(),
    })
}

async fn collect_binary_until(
    socket: &mut WebSocketStream<TlsStream<TcpStream>>,
    needle: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !output.windows(needle.len()).any(|window| window == needle) {
            match socket.next().await.unwrap().unwrap() {
                tungstenite::Message::Binary(bytes) => output.extend_from_slice(&bytes),
                tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
                other => panic!("expected terminal output, got {other:?}"),
            }
        }
    })
    .await
    .expect("terminal output timed out");
    output
}

#[tokio::test]
async fn https_serves_frontend_health_and_required_cookie_attributes() {
    let server = TlsTestServer::start().await;
    let health = server
        .request("GET", "/healthz", None, None, b"")
        .await
        .unwrap();
    assert_eq!(health.status, 200);
    assert_eq!(health.body, b"ok\n");
    let frontend = server.request("GET", "/", None, None, b"").await.unwrap();
    assert_eq!(frontend.status, 200);
    assert!(
        frontend
            .body
            .windows(15)
            .any(|window| window == b"<!doctype html>")
    );

    let identity = server
        .request("POST", "/api/identity", Some(&server.origin), None, b"")
        .await
        .unwrap();
    assert_eq!(identity.status, 204);
    let headers = identity.headers.to_ascii_lowercase();
    for attribute in ["secure", "httponly", "samesite=strict", "path=/"] {
        assert!(headers.contains(attribute), "{attribute} missing");
    }
}

#[tokio::test]
async fn https_exact_origin_creates_session_and_wss_ticket_reaches_real_pty() {
    let server = TlsTestServer::start().await;
    let cookie = server.provision_cookie().await;
    let ticket = server.issue_ticket(&cookie).await;
    let origin = server.origin.clone();
    let mut socket = server.websocket(&origin, &cookie).await.unwrap();
    socket
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    let ready = collect_binary_until(&mut socket, b"READY").await;
    assert!(ready.windows(5).any(|window| window == b"READY"));
    socket
        .send(tungstenite::Message::Binary(b"tls-echo\r".to_vec().into()))
        .await
        .unwrap();
    let echo = collect_binary_until(&mut socket, b"ECHO:tls-echo").await;
    assert!(echo.windows(13).any(|window| window == b"ECHO:tls-echo"));
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn plaintext_http_is_not_accepted_on_the_tls_listener() {
    let server = TlsTestServer::start().await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
    assert!(
        !response.starts_with(b"HTTP/1.1 200"),
        "TLS listener silently accepted plaintext HTTP"
    );
}

#[tokio::test]
async fn wrong_origin_https_session_creation_is_rejected() {
    let server = TlsTestServer::start().await;
    let cookie = server.provision_cookie().await;
    let response = server
        .request(
            "POST",
            "/api/sessions",
            Some("https://attacker.test"),
            Some(&cookie),
            br#"{"target":"shell"}"#,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 403);
}

#[tokio::test]
async fn wrong_origin_wss_upgrade_is_rejected_before_session_start() {
    let server = TlsTestServer::start().await;
    let cookie = server.provision_cookie().await;
    let error = server
        .websocket("https://attacker.test", &cookie)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        tungstenite::Error::Http(ref response) if response.status() == StatusCode::FORBIDDEN
    ));
    assert!(!server.marker.exists());
}

#[tokio::test]
async fn untrusted_certificate_and_wrong_hostname_fail_the_tls_handshake() {
    let server = TlsTestServer::start().await;
    let tcp = TcpStream::connect(server.address).await.unwrap();
    assert!(
        server
            .untrusted_connector
            .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
            .await
            .is_err()
    );
    let tcp = TcpStream::connect(server.address).await.unwrap();
    assert!(
        server
            .connector
            .connect(
                ServerName::try_from("wrong-host.example")
                    .unwrap()
                    .to_owned(),
                tcp
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tls_handshake_failure_starts_no_session_or_pty() {
    let server = TlsTestServer::start().await;
    let tcp = TcpStream::connect(server.address).await.unwrap();
    let _ = server
        .untrusted_connector
        .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!server.marker.exists());
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

async fn wait_for_absence(pids: &[i32], timeout: Duration) -> Result<(), String> {
    tokio::time::timeout(timeout, async {
        while pids.iter().copied().any(process_exists) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "fixture processes survived cleanup".to_owned())
}

async fn wait_until_absent(pids: &[i32]) {
    wait_for_absence(pids, Duration::from_secs(3))
        .await
        .unwrap();
}

fn synthetic_test_body_failure() -> Result<(), &'static str> {
    Err("synthetic test-body failure")
}

#[tokio::test]
async fn repeated_tls_startup_shutdown_reaps_daemon_and_pty() {
    for iteration in 1..=20 {
        let server = TlsTestServer::start().await;
        let cookie = server.provision_cookie().await;
        let ticket = server.issue_ticket(&cookie).await;
        let origin = server.origin.clone();
        let mut socket = server.websocket(&origin, &cookie).await.unwrap();
        socket
            .send(tungstenite::Message::Text(
                format!(r#"{{"ticket":"{ticket}"}}"#).into(),
            ))
            .await
            .unwrap();
        let _ = collect_binary_until(&mut socket, b"READY").await;
        let pids = fixture_pids(&server.marker);
        assert_eq!(
            pids.len(),
            2,
            "iteration {iteration} did not record PTY PIDs"
        );
        socket.close(None).await.unwrap();
        server.stop().await.unwrap();
        wait_until_absent(&pids).await;
    }
}

#[tokio::test]
async fn repeated_failed_tls_handshakes_leave_no_application_work() {
    for iteration in 1..=20 {
        let server = TlsTestServer::start().await;
        let tcp = TcpStream::connect(server.address).await.unwrap();
        assert!(
            server
                .untrusted_connector
                .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
                .await
                .is_err(),
            "iteration {iteration} unexpectedly completed an untrusted handshake"
        );
        assert!(
            fixture_pids(&server.marker).is_empty(),
            "iteration {iteration} started a PTY after a failed handshake"
        );
        server.stop().await.unwrap();
    }
}

#[tokio::test]
async fn tls_fixture_cleanup_runs_after_test_body_failure() {
    let server = TlsTestServer::start().await;
    let cookie = server.provision_cookie().await;
    let ticket = server.issue_ticket(&cookie).await;
    let origin = server.origin.clone();
    let mut socket = server.websocket(&origin, &cookie).await.unwrap();
    socket
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    let _ = collect_binary_until(&mut socket, b"READY").await;
    let pids = fixture_pids(&server.marker);
    assert_eq!(pids.len(), 2);

    drop(socket);
    let body_result = synthetic_test_body_failure();
    let cleanup_result = server.stop().await;
    assert_eq!(body_result, Err("synthetic test-body failure"));
    cleanup_result.unwrap();
    wait_until_absent(&pids).await;
}
