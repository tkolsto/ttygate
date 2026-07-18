use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket},
    task::JoinHandle,
};
use ttygated::{
    config::parse,
    server::{AppState, serve},
};

const ORIGIN: &str = "https://terminal.example.test";

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
}

impl TestServer {
    async fn start() -> Self {
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
command = ["/bin/sh"]
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
        self.state.sessions().shutdown().await;
        self.task.abort();
        let _ = self.task.await;
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
            request(
                "/api/identity",
                &[("X-Authenticated-User", b"alice")],
                b"",
            ),
        )
        .await;

    assert_eq!(response.status, 204);
    let cookie = response.header("set-cookie").unwrap();
    for attribute in [b"Secure".as_slice(), b"HttpOnly", b"SameSite=Strict", b"Path=/"] {
        assert!(
            cookie
                .windows(attribute.len())
                .any(|window| window == attribute)
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn real_listener_rejects_untrusted_ipv4_loopback_with_spoofed_forwarding_headers() {
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
