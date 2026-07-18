use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::http::{HeaderValue, StatusCode, header};
use futures_util::{SinkExt, StreamExt};
use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::frame::{
            Frame,
            coding::{Data, OpCode},
        },
    },
};
use ttygated::{
    auth::{AuthContext, AuthError, AuthProvider, DevAuthProvider, ProvisionedIdentity},
    config::{Limits, PtyTarget, SshTarget, SshUserPolicy, Target, TargetAllowlist},
    origin::OriginPolicy,
    protocol::{
        ClientControl, Resize, ServerControl, decode_server_control, encode_client_control,
    },
    server::{AppState, serve},
    session::LifecycleTransition,
    ticket::{Identity, TicketStore},
};

const ORIGIN: &str = "https://ttygate.local:7681";

struct TestServer {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn limits() -> Limits {
    Limits {
        max_sessions: 8,
        max_sessions_per_user: 4,
        idle_timeout: Duration::from_secs(5),
        absolute_timeout: Duration::from_secs(10),
        session_requests_per_window: 10,
        session_request_window: Duration::from_secs(60),
        authentication_failures_per_window: 20,
        authentication_failure_window: Duration::from_secs(60),
    }
}

fn target() -> Target {
    Target::Pty(PtyTarget {
        name: "shell".into(),
        executable: "/bin/cat".into(),
        argv: Vec::new(),
        read_only: false,
    })
}

fn fixture_target(arguments: &[&str], read_only: bool) -> Target {
    Target::Pty(PtyTarget {
        name: "fixture".into(),
        executable: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pty_child.sh"),
        argv: arguments.iter().map(|value| (*value).to_owned()).collect(),
        read_only,
    })
}

fn state_with_target(target: Target) -> AppState {
    let auth: Arc<dyn AuthProvider> = Arc::new(DevAuthProvider::new("developer").unwrap());
    state_with_components(target, TicketStore::new(Duration::from_secs(10), 32), auth)
}

fn state_with_components(
    target: Target,
    tickets: TicketStore,
    auth: Arc<dyn AuthProvider>,
) -> AppState {
    state_with_all(target, tickets, auth, limits())
}

fn state_with_all(
    target: Target,
    tickets: TicketStore,
    auth: Arc<dyn AuthProvider>,
    limits: Limits,
) -> AppState {
    AppState::new(
        OriginPolicy::new(ORIGIN).unwrap(),
        auth,
        TargetAllowlist::new(vec![target]).unwrap(),
        tickets,
        limits,
    )
}

fn state() -> AppState {
    state_with_target(target())
}

async fn issue_ticket(state: &AppState, identity: Identity, target: Target) -> String {
    let reservation = state
        .sessions()
        .reserve(
            &identity,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    state
        .tickets()
        .issue(identity, target, reservation)
        .unwrap()
        .as_str()
        .to_owned()
}

async fn start_server_with_state(state: AppState) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        serve(listener, state).await.unwrap();
    });
    TestServer { address, task }
}

async fn start_server() -> TestServer {
    start_server_with_state(state()).await
}

async fn provision_cookie(address: SocketAddr) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "POST /api/identity HTTP/1.1\r\nHost: {address}\r\nOrigin: {ORIGIN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    response
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn websocket_request(
    address: SocketAddr,
    origin: Option<&str>,
    cookie: Option<&str>,
) -> axum::http::Request<()> {
    let mut request = format!("ws://{address}/api/ws")
        .into_client_request()
        .unwrap();
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
    }
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
    }
    request
}

async fn rejected_status(request: axum::http::Request<()>) -> StatusCode {
    match connect_async(request).await {
        Err(tungstenite::Error::Http(response)) => response.status(),
        other => panic!("expected rejected upgrade, got {other:?}"),
    }
}

async fn connect_websocket(
    address: SocketAddr,
    cookie: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
    connect_async(websocket_request(address, Some(ORIGIN), Some(cookie)))
        .await
        .unwrap()
        .0
}

async fn next_server_control(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) -> ServerControl {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let message = socket
                .next()
                .await
                .expect("server closed without a typed response")
                .expect("server response failed");
            if let tungstenite::Message::Text(text) = message {
                break decode_server_control(text.as_bytes()).unwrap();
            }
        }
    })
    .await
    .expect("server response timed out")
}

async fn send_ticket(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    ticket: &str,
) {
    socket
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
}

async fn collect_binary_until(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    needle: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !output.windows(needle.len()).any(|window| window == needle) {
            match socket.next().await.unwrap().unwrap() {
                tungstenite::Message::Binary(bytes) => {
                    output.extend_from_slice(&bytes);
                }
                tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
                other => panic!("expected terminal output, got {other:?}"),
            }
        }
    })
    .await
    .expect("terminal output timed out");
    output
}

async fn next_close_code(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) -> u16 {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let tungstenite::Message::Close(frame) = socket.next().await.unwrap().unwrap() {
                break frame.map_or(1005, |frame| frame.code.into());
            }
        }
    })
    .await
    .expect("WebSocket close timed out")
}

fn parse_pid(output: &[u8], key: &str) -> u32 {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(key)
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing {key} in {}", String::from_utf8_lossy(output)))
}

fn process_exists(pid: u32) -> bool {
    let pid = Pid::from_raw(i32::try_from(pid).unwrap());
    match kill(pid, None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(error) => panic!("process probe failed: {error}"),
    }
}

async fn assert_absent(pid: u32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while process_exists(pid) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process {pid} survived WebSocket teardown"));
}

struct ProcessGroupGuard {
    leader: u32,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(leader: u32) -> Self {
        Self {
            leader,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = killpg(
                Pid::from_raw(i32::try_from(self.leader).unwrap()),
                Signal::SIGKILL,
            );
        }
    }
}

#[tokio::test]
async fn websocket_upgrade_requires_exact_origin_and_cookie_before_switching_protocols() {
    let server = start_server().await;
    let cookie = provision_cookie(server.address).await;

    for request in [
        websocket_request(server.address, None, Some(&cookie)),
        websocket_request(server.address, Some("https://attacker.test"), Some(&cookie)),
        websocket_request(server.address, Some("not-an-origin"), Some(&cookie)),
        websocket_request(server.address, Some(ORIGIN), None),
        websocket_request(server.address, Some(ORIGIN), Some("ttgate_session=invalid")),
        websocket_request(
            server.address,
            Some(ORIGIN),
            Some("ttgate_session=invalid; ttgate_session=duplicate"),
        ),
    ] {
        assert_ne!(
            rejected_status(request).await,
            StatusCode::SWITCHING_PROTOCOLS
        );
    }

    let mut duplicate_origin = websocket_request(server.address, Some(ORIGIN), Some(&cookie));
    duplicate_origin
        .headers_mut()
        .append(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    assert_eq!(
        rejected_status(duplicate_origin).await,
        StatusCode::FORBIDDEN
    );

    let mut duplicate_cookie = websocket_request(server.address, Some(ORIGIN), Some(&cookie));
    duplicate_cookie
        .headers_mut()
        .append(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(
        rejected_status(duplicate_cookie).await,
        StatusCode::UNAUTHORIZED
    );

    let (mut socket, response) = connect_async(websocket_request(
        server.address,
        Some(ORIGIN),
        Some(&cookie),
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    socket.close(None).await.unwrap();
}

struct CookieIdentityAuth;

impl AuthProvider for CookieIdentityAuth {
    fn establish(&self, _context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError> {
        Err(AuthError::Unknown)
    }

    fn authenticate(
        &self,
        _context: &AuthContext<'_>,
        cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError> {
        match cookie_header {
            Some("identity=alice") => Ok(Identity::new("alice").unwrap()),
            Some("identity=bob") => Ok(Identity::new("bob").unwrap()),
            Some(_) => Err(AuthError::Unknown),
            None => Err(AuthError::Missing),
        }
    }
}

#[tokio::test]
async fn websocket_rejects_query_and_subprotocol_authority_channels() {
    let server = start_server().await;
    let cookie = provision_cookie(server.address).await;

    let mut query = format!("ws://{}/api/ws?ticket=forbidden", server.address)
        .into_client_request()
        .unwrap();
    query
        .headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    query
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(rejected_status(query).await, StatusCode::BAD_REQUEST);

    let mut subprotocol = websocket_request(server.address, Some(ORIGIN), Some(&cookie));
    subprotocol.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("ticket-secret"),
    );
    assert_eq!(rejected_status(subprotocol).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_malformed_unknown_and_wrong_identity_handshakes_start_no_session() {
    let state = state();
    let mut events = state.sessions().subscribe_events();
    let wrong_identity_ticket =
        issue_ticket(&state, Identity::new("another-user").unwrap(), target()).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;

    let mut missing = connect_websocket(server.address, &cookie).await;
    assert!(matches!(
        next_server_control(&mut missing).await,
        ServerControl::Error(message) if message.code == "authorization-denied"
    ));

    for handshake in [
        "not-json".to_owned(),
        format!(r#"{{"ticket":"{}"}}"#, "A".repeat(43)),
        format!(r#"{{"ticket":"{wrong_identity_ticket}"}}"#),
    ] {
        let mut socket = connect_websocket(server.address, &cookie).await;
        socket
            .send(tungstenite::Message::Text(handshake.into()))
            .await
            .unwrap();
        assert!(matches!(
            next_server_control(&mut socket).await,
            ServerControl::Error(message) if message.code == "authorization-denied"
        ));
    }

    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn valid_ticket_starts_once_and_reuse_starts_no_second_session() {
    let state = state();
    let mut events = state.sessions().subscribe_events();
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), target()).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;

    let mut first = connect_websocket(server.address, &cookie).await;
    first
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    let created = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.transition, LifecycleTransition::Created);

    while let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_secs(2), first.next()).await
    {
        if matches!(message, tungstenite::Message::Close(_)) {
            break;
        }
    }

    let mut reused = connect_websocket(server.address, &cookie).await;
    reused
        .send(tungstenite::Message::Text(
            format!(r#"{{"ticket":"{ticket}"}}"#).into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        next_server_control(&mut reused).await,
        ServerControl::Error(message) if message.code == "authorization-denied"
    ));
    assert!(!matches!(
        events.try_recv(),
        Ok(event) if event.transition == LifecycleTransition::Created
    ));
}

#[tokio::test]
async fn wrong_identity_does_not_consume_the_ticket_through_websocket() {
    let configured = fixture_target(&[], false);
    let state = state_with_components(
        configured.clone(),
        TicketStore::new(Duration::from_secs(10), 32),
        Arc::new(CookieIdentityAuth),
    );
    let ticket = issue_ticket(&state, Identity::new("alice").unwrap(), configured).await;
    let mut events = state.sessions().subscribe_events();
    let server = start_server_with_state(state).await;

    let mut bob = connect_websocket(server.address, "identity=bob").await;
    send_ticket(&mut bob, &ticket).await;
    assert!(matches!(
        next_server_control(&mut bob).await,
        ServerControl::Error(message) if message.code == "authorization-denied"
    ));
    assert!(events.try_recv().is_err());

    let mut alice = connect_websocket(server.address, "identity=alice").await;
    send_ticket(&mut alice, &ticket).await;
    let _ = collect_binary_until(&mut alice, b"READY").await;
    assert_eq!(
        events.recv().await.unwrap().transition,
        LifecycleTransition::Created
    );
    alice.close(None).await.unwrap();
}

#[tokio::test]
async fn fragmented_transport_is_reassembled_before_handshake_parsing() {
    let configured = fixture_target(&[], false);
    let state = state_with_target(configured.clone());
    let mut events = state.sessions().subscribe_events();
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    let envelope = format!(r#"{{"ticket":"{ticket}"}}"#);
    let split = envelope.len() / 2;

    socket
        .send(tungstenite::Message::Frame(Frame::message(
            envelope.as_bytes()[..split].to_vec(),
            OpCode::Data(Data::Text),
            false,
        )))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(events.try_recv().is_err());

    socket
        .send(tungstenite::Message::Frame(Frame::message(
            envelope.as_bytes()[split..].to_vec(),
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .unwrap();
    let _ = collect_binary_until(&mut socket, b"READY").await;
    assert_eq!(
        events.recv().await.unwrap().transition,
        LifecycleTransition::Created
    );
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn ping_before_handshake_does_not_replace_or_extend_the_ticket_message() {
    let configured = fixture_target(&[], false);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    socket
        .send(tungstenite::Message::Ping(b"health".to_vec().into()))
        .await
        .unwrap();
    send_ticket(&mut socket, &ticket).await;
    let _ = collect_binary_until(&mut socket, b"READY").await;
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn expired_ssh_and_spawn_failure_tickets_are_safe_and_consumed() {
    let expired_target = fixture_target(&[], false);
    let expired_state = state_with_components(
        expired_target.clone(),
        TicketStore::new(Duration::from_millis(5), 32),
        Arc::new(DevAuthProvider::new("developer").unwrap()),
    );
    let expired = issue_ticket(
        &expired_state,
        Identity::new("developer").unwrap(),
        expired_target,
    )
    .await;
    let expired_server = start_server_with_state(expired_state).await;
    let expired_cookie = provision_cookie(expired_server.address).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut expired_socket = connect_websocket(expired_server.address, &expired_cookie).await;
    send_ticket(&mut expired_socket, &expired).await;
    assert!(matches!(
        next_server_control(&mut expired_socket).await,
        ServerControl::Error(message) if message.code == "authorization-denied"
    ));

    let ssh = Target::Ssh(SshTarget {
        name: "ssh".into(),
        host: "example.test".into(),
        port: 22,
        known_hosts: "/configured/known_hosts".into(),
        user_policy: SshUserPolicy::Fixed("configured".into()),
        read_only: false,
    });
    assert_consumed_start_failure(ssh, "session-denied").await;

    let spawn_failure = Target::Pty(PtyTarget {
        name: "missing".into(),
        executable: "/definitely/not/a/real/executable".into(),
        argv: vec!["browser-cannot-change-this".into()],
        read_only: false,
    });
    assert_consumed_start_failure(spawn_failure, "session-unavailable").await;
}

async fn assert_consumed_start_failure(target: Target, expected_code: &str) {
    let state = state_with_target(target.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), target).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;

    let mut first = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut first, &ticket).await;
    assert!(matches!(
        next_server_control(&mut first).await,
        ServerControl::Error(message) if message.code == expected_code
    ));

    let mut reused = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut reused, &ticket).await;
    assert!(matches!(
        next_server_control(&mut reused).await,
        ServerControl::Error(message) if message.code == "authorization-denied"
    ));
}

#[tokio::test]
async fn successful_ticket_bridges_real_pty_echo_resize_and_natural_exit() {
    let configured = fixture_target(&["natural-resistant", "/configured/path"], false);
    let state = state_with_target(configured.clone());
    let mut events = state.sessions().subscribe_events();
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut socket, &ticket).await;

    let ready = collect_binary_until(&mut socket, b"READY").await;
    assert!(
        ready
            .windows(b"ARG1:[natural-resistant]".len())
            .any(|window| window == b"ARG1:[natural-resistant]")
    );
    assert!(
        ready
            .windows(b"ARG2:[/configured/path]".len())
            .any(|window| window == b"ARG2:[/configured/path]")
    );
    assert!(
        ready
            .windows(b"INITIAL:24 80".len())
            .any(|window| window == b"INITIAL:24 80")
    );

    socket
        .send(tungstenite::Message::Binary(vec![0xff, b'\r'].into()))
        .await
        .unwrap();
    let opaque = collect_binary_until(&mut socket, &[0xff]).await;
    assert!(opaque.contains(&0xff));

    socket
        .send(tungstenite::Message::Binary(
            b"/bin/evil --browser-argv\r".to_vec().into(),
        ))
        .await
        .unwrap();
    let echoed = collect_binary_until(&mut socket, b"ECHO:/bin/evil --browser-argv").await;
    assert!(
        echoed
            .windows(b"ECHO:/bin/evil --browser-argv".len())
            .any(|window| window == b"ECHO:/bin/evil --browser-argv")
    );

    let resize =
        encode_client_control(&ClientControl::Resize(Resize::new(100, 40).unwrap())).unwrap();
    socket
        .send(tungstenite::Message::Text(resize.into()))
        .await
        .unwrap();
    socket
        .send(tungstenite::Message::Binary(b"size\r".to_vec().into()))
        .await
        .unwrap();
    let resized = collect_binary_until(&mut socket, b"RESIZED:40 100").await;
    assert!(
        resized
            .windows(b"RESIZED:40 100".len())
            .any(|window| window == b"RESIZED:40 100")
    );

    socket
        .send(tungstenite::Message::Binary(b"exit\r".to_vec().into()))
        .await
        .unwrap();
    let first_control = next_server_control(&mut socket).await;
    if first_control != ServerControl::ExitStatus(ttygated::protocol::ExitStatus::Code(0)) {
        let mut transitions = Vec::new();
        while let Ok(event) = events.try_recv() {
            transitions.push(event.transition);
        }
        panic!("unexpected control {first_control:?}; transitions {transitions:?}");
    }
    assert_eq!(
        next_server_control(&mut socket).await,
        ServerControl::Close(ttygated::protocol::CloseReason::Exited)
    );
}

#[tokio::test]
async fn reconnect_after_explicit_close_preserves_the_next_natural_exit_status() {
    let configured = fixture_target(&[], false);
    let state = state_with_target(configured.clone());
    let mut events = state.sessions().subscribe_events();
    let first_ticket = issue_ticket(
        &state,
        Identity::new("developer").unwrap(),
        configured.clone(),
    )
    .await;
    let second_ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;

    let mut first = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut first, &first_ticket).await;
    let _ = collect_binary_until(&mut first, b"READY").await;
    let close = encode_client_control(&ClientControl::Close).unwrap();
    first
        .send(tungstenite::Message::Text(close.into()))
        .await
        .unwrap();
    assert_eq!(
        next_server_control(&mut first).await,
        ServerControl::Close(ttygated::protocol::CloseReason::ClientRequest)
    );

    let mut second = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut second, &second_ticket).await;
    let _ = collect_binary_until(&mut second, b"READY").await;
    let resize =
        encode_client_control(&ClientControl::Resize(Resize::new(40, 17).unwrap())).unwrap();
    second
        .send(tungstenite::Message::Text(resize.into()))
        .await
        .unwrap();
    second
        .send(tungstenite::Message::Binary(b"exit\r".to_vec().into()))
        .await
        .unwrap();

    let first_control = next_server_control(&mut second).await;
    if first_control != ServerControl::ExitStatus(ttygated::protocol::ExitStatus::Code(0)) {
        let mut transitions = Vec::new();
        while let Ok(event) = events.try_recv() {
            transitions.push(event.transition);
        }
        panic!("unexpected control {first_control:?}; transitions {transitions:?}");
    }
    assert_eq!(
        next_server_control(&mut second).await,
        ServerControl::Close(ttygated::protocol::CloseReason::Exited)
    );
}

#[tokio::test]
async fn explicit_close_is_orderly_and_malformed_control_closes_with_1008() {
    for malformed in [false, true] {
        let configured = fixture_target(&[], false);
        let state = state_with_target(configured.clone());
        let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
        let server = start_server_with_state(state).await;
        let cookie = provision_cookie(server.address).await;
        let mut socket = connect_websocket(server.address, &cookie).await;
        send_ticket(&mut socket, &ticket).await;
        let _ = collect_binary_until(&mut socket, b"READY").await;

        if malformed {
            socket
                .send(tungstenite::Message::Text(
                    r#"{"version":1,"type":"resize","cols":"hostile","rows":24}"#.into(),
                ))
                .await
                .unwrap();
            assert!(matches!(
                next_server_control(&mut socket).await,
                ServerControl::Error(message) if message.code == "protocol-error"
            ));
            assert_eq!(
                next_server_control(&mut socket).await,
                ServerControl::Close(ttygated::protocol::CloseReason::ProtocolError)
            );
            assert_eq!(next_close_code(&mut socket).await, 1008);
        } else {
            let close = encode_client_control(&ClientControl::Close).unwrap();
            socket
                .send(tungstenite::Message::Text(close.into()))
                .await
                .unwrap();
            assert_eq!(
                next_server_control(&mut socket).await,
                ServerControl::Close(ttygated::protocol::CloseReason::ClientRequest)
            );
            assert_eq!(next_close_code(&mut socket).await, 1000);
        }
    }
}

#[tokio::test]
async fn read_only_input_is_rejected_before_the_real_pty() {
    let configured = fixture_target(&[], true);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut socket, &ticket).await;
    let _ = collect_binary_until(&mut socket, b"READY").await;
    socket
        .send(tungstenite::Message::Binary(
            b"read-only-sentinel\r".to_vec().into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        next_server_control(&mut socket).await,
        ServerControl::Error(message) if message.code == "session-denied"
    ));
    assert_eq!(
        next_server_control(&mut socket).await,
        ServerControl::Close(ttygated::protocol::CloseReason::Policy)
    );
}

#[tokio::test]
async fn dropped_transport_reaps_real_leader_and_descendant() {
    let configured = fixture_target(&["ignore-hup"], false);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut socket, &ticket).await;
    let ready = collect_binary_until(&mut socket, b"READY").await;
    let leader = parse_pid(&ready, "PID:");
    let descendant = parse_pid(&ready, "DESC:");
    let mut guard = ProcessGroupGuard::new(leader);

    drop(socket);
    assert_absent(leader).await;
    assert_absent(descendant).await;
    guard.disarm();
}

#[tokio::test]
async fn oversized_handshake_and_post_handshake_control_close_with_1009() {
    let configured = fixture_target(&[], false);
    let state = state_with_target(configured);
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;

    let mut transport_handshake = connect_websocket(server.address, &cookie).await;
    transport_handshake
        .send(tungstenite::Message::Frame(Frame::message(
            vec![b'x'; 32_768],
            OpCode::Data(Data::Text),
            false,
        )))
        .await
        .unwrap();
    transport_handshake
        .send(tungstenite::Message::Frame(Frame::message(
            vec![b'x'; 32_769],
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .unwrap();
    assert_eq!(next_close_code(&mut transport_handshake).await, 1009);

    let mut handshake = connect_websocket(server.address, &cookie).await;
    handshake
        .send(tungstenite::Message::Text("x".repeat(257).into()))
        .await
        .unwrap();
    assert!(matches!(
        next_server_control(&mut handshake).await,
        ServerControl::Error(message) if message.code == "protocol-error"
    ));
    let _ = next_server_control(&mut handshake).await;
    assert_eq!(next_close_code(&mut handshake).await, 1009);

    let configured = fixture_target(&[], false);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut protocol = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut protocol, &ticket).await;
    let _ = collect_binary_until(&mut protocol, b"READY").await;
    protocol
        .send(tungstenite::Message::Text("x".repeat(4_097).into()))
        .await
        .unwrap();
    assert!(matches!(
        next_server_control(&mut protocol).await,
        ServerControl::Error(message) if message.code == "protocol-error"
    ));
    let _ = next_server_control(&mut protocol).await;
    assert_eq!(next_close_code(&mut protocol).await, 1009);

    let configured = fixture_target(&[], false);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut binary = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut binary, &ticket).await;
    let _ = collect_binary_until(&mut binary, b"READY").await;
    binary
        .send(tungstenite::Message::Frame(Frame::message(
            vec![0; 32_768],
            OpCode::Data(Data::Binary),
            false,
        )))
        .await
        .unwrap();
    binary
        .send(tungstenite::Message::Frame(Frame::message(
            vec![0; 32_769],
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .unwrap();
    assert_eq!(next_close_code(&mut binary).await, 1009);
}

#[tokio::test]
async fn non_reading_client_drop_during_output_flood_reaps_process_group() {
    let configured = fixture_target(&["flood"], false);
    let state = state_with_target(configured.clone());
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut socket, &ticket).await;
    let ready = collect_binary_until(&mut socket, b"READY").await;
    let leader = parse_pid(&ready, "PID:");
    let descendant = parse_pid(&ready, "DESC:");
    let mut guard = ProcessGroupGuard::new(leader);

    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(socket);
    assert_absent(leader).await;
    assert_absent(descendant).await;
    guard.disarm();
}

#[tokio::test]
async fn connected_non_reader_backpressures_the_real_producer_until_timeout_reaps_it() {
    let temp = tempfile::tempdir().unwrap();
    let progress = temp.path().join("progress");
    let progress_arg = progress.to_str().unwrap();
    let configured = fixture_target(&["flood-count", progress_arg], false);
    let state = state_with_all(
        configured.clone(),
        TicketStore::new(Duration::from_secs(10), 32),
        Arc::new(DevAuthProvider::new("developer").unwrap()),
        Limits {
            max_sessions: 8,
            max_sessions_per_user: 4,
            idle_timeout: Duration::from_secs(5),
            absolute_timeout: Duration::from_secs(2),
            session_requests_per_window: 10,
            session_request_window: Duration::from_secs(60),
            authentication_failures_per_window: 20,
            authentication_failure_window: Duration::from_secs(60),
        },
    );
    let ticket = issue_ticket(&state, Identity::new("developer").unwrap(), configured).await;
    let server = start_server_with_state(state).await;
    let cookie = provision_cookie(server.address).await;
    let mut socket = connect_websocket(server.address, &cookie).await;
    send_ticket(&mut socket, &ticket).await;
    let ready = collect_binary_until(&mut socket, b"READY").await;
    let leader = parse_pid(&ready, "PID:");
    let descendant = parse_pid(&ready, "DESC:");
    let mut guard = ProcessGroupGuard::new(leader);

    let stalled_at = tokio::time::timeout(Duration::from_millis(1_500), async {
        let mut previous = 0_u64;
        let mut stable_samples = 0_u8;
        loop {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let current = std::fs::read_to_string(&progress)
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            if current > 0 && current == previous {
                stable_samples += 1;
                if stable_samples == 5 {
                    break current;
                }
            } else {
                stable_samples = 0;
                previous = current;
            }
        }
    })
    .await
    .expect("producer never became backpressured");
    assert!(stalled_at > 0);
    assert!(
        process_exists(leader),
        "producer stopped because it exited, not because output backpressured"
    );

    assert_absent(leader).await;
    assert_absent(descendant).await;
    drop(socket);
    guard.disarm();
}
