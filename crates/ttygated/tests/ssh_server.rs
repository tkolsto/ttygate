#![cfg(unix)]

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum_server::tls_rustls::RustlsConfig;
use futures_util::{SinkExt, StreamExt};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tempfile::TempDir;
use tokio::time::timeout;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, client::IntoClientRequest},
};
use ttygated::{
    audit::AuditLog,
    auth::{AuthProvider, DevAuthProvider},
    config::{
        AuditConfig, AuditFormat, AuthConfig, Config, Limits, ServerConfig, ServerMode,
        ServerTransport, SshTarget, SshUserPolicy, Target, TargetAllowlist,
    },
    origin::OriginPolicy,
    protocol::{Resize, ServerControl, decode_server_control},
    server::AppState,
    session::{
        ChildOutcome, Session, SessionCloseReason, SessionError, SessionManager, TimeoutKind,
    },
    ssh::{self, SshPreparationError},
    startup,
    ticket::{Identity, TicketStore},
    tls::TlsError,
};

const WAIT: Duration = Duration::from_secs(10);
const USER: &str = "integration-user";
const TARGET: &str = "real-ssh";
const IMAGE: &str = "ttygate-sshd-integration:local";
const BANNER_MARKER: &str = "debug1: Authentication succeeded (publickey).";
const SENTINEL_KNOWN_HOSTS: &str = "KNOWN_HOSTS_PATH_SENTINEL_943a";
const SENTINEL_IDENTITY: &str = "IDENTITY_PATH_SENTINEL_329f";
const SENTINEL_KNOWN_HOSTS_CONTENT: &str = "KNOWN_HOSTS_CONTENT_SENTINEL_617d";
const SENTINEL_PRIVATE_KEY_COMMENT: &str = "PRIVATE_KEY_CONTENT_SENTINEL_f10c";
const SENTINEL_HEADER: &str = "HEADER_SENTINEL_48af";
const SENTINEL_ENVIRONMENT: &str = "ENVIRONMENT_SENTINEL_60bd";
const SENTINEL_ARGUMENT: &str = "ProxyCommand=ARGV_SENTINEL_d9e7";
const SENTINEL_AUDIT_PATH: &str = "AUDIT_PATH_SENTINEL_76ce.jsonl";

static FIXTURE_SERIAL: OnceLock<AsyncMutex<()>> = OnceLock::new();
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct RealSshdFixture {
    container: ContainerGuard,
    directory: TempDir,
    _serial: AsyncMutexGuard<'static, ()>,
    port: u16,
    audit_path: PathBuf,
    ssh_executable: PathBuf,
}

struct WebsocketDenial {
    code: String,
    message: String,
    rendered: String,
    audit: String,
    cookie: String,
    ticket: String,
}

impl RealSshdFixture {
    async fn start() -> Self {
        Self::start_inner(None).await
    }

    async fn start_paused_after_container(
        started: tokio::sync::oneshot::Sender<(String, PathBuf)>,
    ) -> Self {
        Self::start_inner(Some(started)).await
    }

    async fn start_inner(started: Option<tokio::sync::oneshot::Sender<(String, PathBuf)>>) -> Self {
        let serial = FIXTURE_SERIAL
            .get_or_init(|| AsyncMutex::new(()))
            .lock()
            .await;
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap())
            .expect("create private sshd fixture directory");
        fs::set_permissions(
            directory.path(),
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        generate_key(directory.path().join("client_key"));
        generate_key(directory.path().join("wrong_client_key"));
        generate_key_with_comment(
            directory.path().join(SENTINEL_IDENTITY),
            SENTINEL_PRIVATE_KEY_COMMENT,
        );
        generate_key(directory.path().join("ssh_host_ed25519_key"));
        generate_key(directory.path().join("wrong_host_key"));
        fs::write(
            directory.path().join("banner"),
            format!("{BANNER_MARKER}\n"),
        )
        .unwrap();
        let container = format!(
            "ttygate-sshd-{}-{}",
            std::process::id(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sshd");
        command_ok(
            Command::new("docker")
                .args(["build", "-q", "-t", IMAGE])
                .arg(&fixture_dir),
            "build disposable sshd image",
        );
        command_ok(
            Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    &container,
                    "-e",
                    "TTYGATE_FIXTURE_SENTINEL=ENVIRONMENT_SENTINEL_60bd",
                    "-p",
                    "127.0.0.1::2222",
                    "-v",
                ])
                .arg(format!("{}:/fixture:ro", directory.path().display()))
                .arg(IMAGE),
            "start disposable sshd",
        );
        // Arm cleanup before the first readiness await. Dropping or cancelling
        // fixture construction can therefore never strand the container.
        let container = ContainerGuard { name: container };
        if let Some(started) = started {
            let _ = started.send((container.name.clone(), directory.path().to_owned()));
            std::future::pending::<()>().await;
            unreachable!("paused fixture construction resumes only through cancellation");
        }
        let port = wait_for_port(&container.name).await;
        let host_public = public_key_fields(&directory.path().join("ssh_host_ed25519_key.pub"));
        let wrong_public = public_key_fields(&directory.path().join("wrong_host_key.pub"));
        fs::write(
            directory.path().join("known_hosts"),
            format!("[127.0.0.1]:{port} {} {}\n", host_public.0, host_public.1),
        )
        .unwrap();
        fs::write(
            directory.path().join("mismatch_known_hosts"),
            format!("[127.0.0.1]:{port} {} {}\n", wrong_public.0, wrong_public.1),
        )
        .unwrap();
        fs::write(
            directory.path().join(SENTINEL_KNOWN_HOSTS),
            format!(
                "[localhost]:{port} {} {} {SENTINEL_KNOWN_HOSTS_CONTENT}\n",
                host_public.0, host_public.1
            ),
        )
        .unwrap();
        fs::write(directory.path().join("empty_known_hosts"), b"").unwrap();
        let audit_path = directory.path().join(SENTINEL_AUDIT_PATH);
        let ssh_executable = PathBuf::from("/usr/bin/ssh");
        assert!(
            ssh_executable.is_file(),
            "system OpenSSH client is required"
        );
        Self {
            container,
            directory,
            _serial: serial,
            port,
            audit_path,
            ssh_executable,
        }
    }

    fn target(&self, known_hosts: &str, identity: &str) -> SshTarget {
        SshTarget {
            name: TARGET.to_owned(),
            host: "127.0.0.1".to_owned(),
            port: self.port,
            ssh_executable: self.ssh_executable.clone(),
            identity_file: self.directory.path().join(identity),
            known_hosts: self.directory.path().join(known_hosts),
            user_policy: SshUserPolicy::Fixed("ttygate".to_owned()),
            read_only: false,
        }
    }

    fn refused_target(&self) -> SshTarget {
        let mut target = self.target("known_hosts", "client_key");
        target.port = unused_loopback_port();
        let host_public =
            public_key_fields(&self.directory.path().join("ssh_host_ed25519_key.pub"));
        fs::write(
            &target.known_hosts,
            format!(
                "[127.0.0.1]:{} {} {}\n",
                target.port, host_public.0, host_public.1
            ),
        )
        .unwrap();
        target
    }

    async fn manager(&self, target: SshTarget, limits: Limits) -> (Arc<SessionManager>, AppState) {
        let config = test_config(target.clone(), limits.clone(), self.audit_path.clone());
        let target_for_builder = target.clone();
        let limits_for_builder = limits.clone();
        let prepared = startup::prepare_with_ssh(
            &config,
            |_| async { Err::<RustlsConfig, TlsError>(TlsError::CertificateMalformed) },
            ssh::prepare,
            AuditLog::open,
            move |_config, audit| {
                let auth: Arc<dyn AuthProvider> = Arc::new(DevAuthProvider::new(USER).unwrap());
                Ok(AppState::new_for_test(
                    OriginPolicy::new("http://127.0.0.1:7681").unwrap(),
                    auth,
                    TargetAllowlist::new(vec![Target::Ssh(target_for_builder)]).unwrap(),
                    TicketStore::new(Duration::from_secs(10), 32),
                    limits_for_builder,
                    audit,
                ))
            },
        )
        .await
        .expect("prepare real SSH target");
        let state = prepared.state;
        (state.sessions(), state)
    }

    async fn session(&self) -> (Session, Arc<SessionManager>) {
        let (manager, _) = self
            .manager(self.target("known_hosts", "client_key"), default_limits())
            .await;
        let session = timeout(
            WAIT,
            manager.start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            ),
        )
        .await
        .expect("SSH admission timed out")
        .expect("SSH admission failed");
        (session, manager)
    }

    async fn websocket_denial(&self, target: SshTarget) -> WebsocketDenial {
        let (_manager, state) = self.manager(target, default_limits()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            ttygated::server::serve(listener, state).await.unwrap();
        });
        let cookie = provision_cookie(address).await;
        let ticket = issue_ticket(address, &cookie).await;
        let mut request = format!("ws://{address}/api/ws")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "http://127.0.0.1:7681".parse().unwrap());
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
        request
            .headers_mut()
            .insert("x-ttygate-test-sentinel", SENTINEL_HEADER.parse().unwrap());
        let mut socket = connect_async(request).await.unwrap().0;
        socket
            .send(tungstenite::Message::Text(
                format!(r#"{{"ticket":"{ticket}"}}"#).into(),
            ))
            .await
            .unwrap();
        let control = timeout(WAIT, async {
            loop {
                let message = socket.next().await.unwrap().unwrap();
                if let tungstenite::Message::Text(text) = message {
                    break decode_server_control(text.as_bytes()).unwrap();
                }
            }
        })
        .await
        .expect("curated real SSH WebSocket denial timed out");
        let rendered = format!("{control:?}");
        let ServerControl::Error(error) = control else {
            panic!("expected curated real SSH WebSocket error, got {rendered}");
        };
        drop(socket);
        server.abort();
        let _ = server.await;
        WebsocketDenial {
            code: error.code,
            message: error.message,
            rendered,
            audit: self.audit_text(),
            cookie,
            ticket,
        }
    }

    async fn assert_strict_success(&self) {
        let (mut session, _) = self.session().await;
        session
            .write(b"printf 'TTYGATE_REAL_SSH_OK\\n'\n".to_vec())
            .await
            .unwrap();
        let output = read_until(&mut session, "TTYGATE_REAL_SSH_OK").await;
        assert!(output.contains("TTYGATE_REAL_SSH_OK"));
        session.close().await.unwrap();
        self.assert_no_session_children().await;
    }

    async fn assert_empty_unknown_rejected(&self) {
        let target = Target::Ssh(self.target("empty_known_hosts", "client_key"));
        assert_eq!(
            ssh::prepare(&[target]).await.unwrap_err(),
            SshPreparationError::KnownHostsUnsafe
        );
        assert!(!self.audit_path.exists());
        self.assert_no_session_children().await;
    }

    async fn assert_host_key_mismatch(&self) {
        let denial = self
            .websocket_denial(self.target("mismatch_known_hosts", "client_key"))
            .await;
        assert_eq!(denial.code, "ssh-host-key-failed");
        assert_eq!(
            denial.message,
            "The SSH host identity could not be verified."
        );
        let audit = denial.audit;
        assert!(
            audit.contains("\"reason\":\"host-key-mismatch\""),
            "{audit}"
        );
        assert!(!audit.contains("session-started"), "{audit}");
        assert_eq!(audit.matches("\"event_type\":\"access-denied\"").count(), 1);
        self.assert_no_session_children().await;
    }

    async fn assert_refused_connection(&self) {
        let (manager, _) = self.manager(self.refused_target(), default_limits()).await;
        let error = manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, SessionError::SshConnectionFailed);
        assert!(
            self.audit_text()
                .contains("\"reason\":\"ssh-connection-failed\"")
        );
    }

    async fn assert_wrong_identity(&self) {
        let denial = self
            .websocket_denial(self.target("known_hosts", "wrong_client_key"))
            .await;
        assert_eq!(denial.code, "ssh-authentication-failed");
        assert_eq!(denial.message, "SSH authentication was rejected.");
        let audit = denial.audit;
        assert!(
            audit.contains("\"reason\":\"ssh-authentication-failed\""),
            "{audit}"
        );
        assert!(!audit.contains("session-started"), "{audit}");
        assert_eq!(audit.matches("\"event_type\":\"access-denied\"").count(), 1);
        self.assert_no_session_children().await;
    }

    async fn assert_remote_exit(&self) {
        let (mut session, _) = self.session().await;
        session.write(b"exit 7\n".to_vec()).await.unwrap();
        let closed = timeout(WAIT, session.wait_closed()).await.unwrap().unwrap();
        assert_eq!(closed.reason, SessionCloseReason::ChildExited);
        assert_eq!(closed.outcome, Some(ChildOutcome::Code(7)));
        self.assert_one_start_end("child-exited");
        self.assert_no_session_children().await;
    }

    async fn assert_resize(&self) {
        let (mut session, _) = self.session().await;
        session
            .write(b"printf 'SIZE1:'; stty size\n".to_vec())
            .await
            .unwrap();
        let initial = read_until(&mut session, "SIZE1:24 80").await;
        assert!(initial.contains("SIZE1:24 80"), "{initial}");
        session.resize(Resize::new(132, 41).unwrap()).await.unwrap();
        session
            .write(b"printf 'SIZE2:'; stty size\n".to_vec())
            .await
            .unwrap();
        let resized = read_until(&mut session, "SIZE2:41 132").await;
        assert!(resized.contains("SIZE2:41 132"), "{resized}");
        session.close().await.unwrap();
    }

    async fn assert_opaque_io(&self) {
        let sentinel = "TERMINAL_OPAQUE_d34db33f";
        let (mut session, _) = self.session().await;
        session
            .write(format!("printf '{sentinel}\\n'\n").into_bytes())
            .await
            .unwrap();
        assert!(read_until(&mut session, sentinel).await.contains(sentinel));
        session.close().await.unwrap();
        assert!(!self.audit_text().contains(sentinel));
    }

    async fn assert_sentinel_secrecy(&self) {
        let identity_path = self.directory.path().join(SENTINEL_IDENTITY);
        let known_hosts_path = self.directory.path().join(SENTINEL_KNOWN_HOSTS);
        let private_key = fs::read_to_string(&identity_path).unwrap();
        let known_hosts = fs::read_to_string(&known_hosts_path).unwrap();
        let mut sentinel_target = self.target(SENTINEL_KNOWN_HOSTS, SENTINEL_IDENTITY);
        sentinel_target.host = "localhost".to_owned();
        let denial = self.websocket_denial(sentinel_target).await;
        assert_eq!(denial.code, "ssh-authentication-failed");
        let frontend = format!("{} {} {}", denial.code, denial.message, denial.rendered);
        let known_host_public_data = known_hosts
            .split_whitespace()
            .nth(2)
            .expect("sentinel known-host public data");
        let mut sentinels = vec![
            denial.cookie.as_str(),
            denial.ticket.as_str(),
            SENTINEL_KNOWN_HOSTS,
            SENTINEL_IDENTITY,
            SENTINEL_KNOWN_HOSTS_CONTENT,
            SENTINEL_PRIVATE_KEY_COMMENT,
            SENTINEL_HEADER,
            SENTINEL_ENVIRONMENT,
            SENTINEL_ARGUMENT,
            BANNER_MARKER,
            "localhost",
            "ttygate",
            known_host_public_data,
            known_hosts_path.to_str().unwrap(),
            identity_path.to_str().unwrap(),
            self.audit_path.to_str().unwrap(),
        ];
        sentinels.extend(private_key.lines().filter(|line| line.len() > 20));
        for sentinel in sentinels {
            assert!(!denial.audit.contains(sentinel), "audit leaked {sentinel}");
            assert!(!frontend.contains(sentinel), "frontend leaked {sentinel}");
        }
        assert_eq!(
            denial
                .audit
                .matches("\"event_type\":\"access-denied\"")
                .count(),
            1
        );
        assert!(!denial.audit.contains("session-started"));
        assert!(!denial.audit.contains("session-ended"));
    }

    async fn assert_drop_reaps(&self) {
        let (_manager, state) = self
            .manager(self.target("known_hosts", "client_key"), default_limits())
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            ttygated::server::serve(listener, state).await.unwrap();
        });
        let cookie = provision_cookie(address).await;
        let ticket = issue_ticket(address, &cookie).await;
        let mut request = format!("ws://{address}/api/ws")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "http://127.0.0.1:7681".parse().unwrap());
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
        let mut socket = connect_async(request).await.unwrap().0;
        socket
            .send(tungstenite::Message::Text(
                format!(r#"{{"ticket":"{ticket}"}}"#).into(),
            ))
            .await
            .unwrap();
        socket
            .send(tungstenite::Message::Binary(
                b"printf 'WEBSOCKET_SSH_READY\\n'\n".to_vec().into(),
            ))
            .await
            .unwrap();
        timeout(WAIT, async {
            loop {
                if let Some(Ok(tungstenite::Message::Binary(bytes))) = socket.next().await
                    && bytes
                        .windows(b"WEBSOCKET_SSH_READY".len())
                        .any(|window| window == b"WEBSOCKET_SSH_READY")
                {
                    break;
                }
            }
        })
        .await
        .expect("real SSH WebSocket was not admitted");
        drop(socket);
        timeout(WAIT, async {
            loop {
                if self
                    .audit_text()
                    .contains("\"close_reason\":\"websocket-disconnect\"")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("WebSocket drop did not complete the SSH lifecycle");
        self.assert_no_session_children().await;
        server.abort();
        let _ = server.await;
    }

    async fn assert_cleanup_matrix(&self) {
        let mut reasons = Vec::new();
        let mut session_ids = Vec::new();

        let before = self.audit_events().len();
        let (mut explicit, _) = self.session().await;
        reasons.push(explicit.close().await.unwrap().reason);
        session_ids.push(self.assert_completed_session_since(before, "explicit"));

        let mut idle_limits = default_limits();
        idle_limits.idle_timeout = Duration::from_millis(150);
        let before = self.audit_events().len();
        let (idle_manager, _) = self
            .manager(self.target("known_hosts", "client_key"), idle_limits)
            .await;
        let mut idle = idle_manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        reasons.push(
            timeout(WAIT, idle.wait_closed())
                .await
                .unwrap()
                .unwrap()
                .reason,
        );
        session_ids.push(self.assert_completed_session_since(before, "idle-timeout"));

        let mut absolute_limits = default_limits();
        absolute_limits.absolute_timeout = Duration::from_millis(200);
        let before = self.audit_events().len();
        let (absolute_manager, _) = self
            .manager(self.target("known_hosts", "client_key"), absolute_limits)
            .await;
        let mut absolute = absolute_manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        absolute.write(b"true\n".to_vec()).await.unwrap();
        reasons.push(
            timeout(WAIT, absolute.wait_closed())
                .await
                .unwrap()
                .unwrap()
                .reason,
        );
        session_ids.push(self.assert_completed_session_since(before, "absolute-timeout"));

        let before = self.audit_events().len();
        let (mut shutdown_session, shutdown_manager) = self.session().await;
        timeout(WAIT, shutdown_manager.shutdown()).await.unwrap();
        reasons.push(shutdown_session.wait_closed().await.unwrap().reason);
        session_ids.push(self.assert_completed_session_since(before, "manager-shutdown"));

        command_ok(
            Command::new("docker").args(["pause", &self.container]),
            "pause sshd before caller-cancellation exercise",
        );
        let (cancel_manager, _) = self
            .manager(self.target("known_hosts", "client_key"), default_limits())
            .await;
        let cancellation_audit_start = self.audit_events().len();
        let cancelling_manager = Arc::clone(&cancel_manager);
        let connecting = tokio::spawn(async move {
            cancelling_manager
                .start(
                    Identity::new(USER).unwrap(),
                    TARGET,
                    Resize::new(80, 24).unwrap(),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        connecting.abort();
        assert!(connecting.await.unwrap_err().is_cancelled());
        command_ok(
            Command::new("docker").args(["unpause", &self.container]),
            "unpause sshd after caller cancellation",
        );
        self.assert_no_session_children().await;
        timeout(WAIT, async {
            loop {
                if self.audit_events().len() > cancellation_audit_start {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("pre-admission cancellation denial was not persisted");
        let cancellation_events = self.audit_events();
        let cancellation_events = &cancellation_events[cancellation_audit_start..];
        assert_eq!(cancellation_events.len(), 1, "{cancellation_events:?}");
        assert_eq!(cancellation_events[0]["event_type"], "access-denied");
        assert_eq!(cancellation_events[0]["category"], "target");
        assert_eq!(cancellation_events[0]["reason"], "session-cancelled");

        let before = self.audit_events().len();
        let mut after_cancel = cancel_manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        after_cancel.close().await.unwrap();
        session_ids.push(self.assert_completed_session_since(before, "explicit"));

        assert!(reasons.contains(&SessionCloseReason::Explicit));
        assert!(reasons.contains(&SessionCloseReason::Timeout(TimeoutKind::Idle)));
        assert!(reasons.contains(&SessionCloseReason::Timeout(TimeoutKind::Absolute)));
        assert!(reasons.contains(&SessionCloseReason::ManagerShutdown));
        let unique_session_ids = session_ids.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_session_ids.len(), session_ids.len());
        self.assert_no_session_children().await;
        let audit = self.audit_events();
        let started = audit
            .iter()
            .filter(|event| event["event_type"] == "session-started")
            .count();
        let ended = audit
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .count();
        assert_eq!(started, ended);
    }

    async fn assert_capacity_cleanup(&self) {
        let mut limits = default_limits();
        limits.max_sessions = 1;
        limits.max_sessions_per_user = 1;
        let (manager, _) = self
            .manager(self.target("known_hosts", "client_key"), limits)
            .await;
        let mut first = manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        let local_ssh_pid = self.local_ssh_pid();
        assert_eq!(
            manager
                .start(
                    Identity::new("second-user").unwrap(),
                    TARGET,
                    Resize::new(80, 24).unwrap(),
                )
                .await
                .unwrap_err(),
            SessionError::GlobalLimit
        );
        kill(Pid::from_raw(local_ssh_pid), Signal::SIGSTOP).unwrap();
        let closing = tokio::spawn(async move { first.close().await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            manager
                .start(
                    Identity::new("during-cleanup").unwrap(),
                    TARGET,
                    Resize::new(80, 24).unwrap(),
                )
                .await
                .unwrap_err(),
            SessionError::GlobalLimit
        );
        timeout(WAIT, closing)
            .await
            .expect("resistant local SSH cleanup timed out")
            .unwrap()
            .unwrap();
        self.assert_no_session_children().await;
        let mut second = manager
            .start(
                Identity::new("second-user").unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        second.close().await.unwrap();
    }

    async fn assert_no_remote_child(&self) {
        let (mut session, _) = self.session().await;
        session.close().await.unwrap();
        self.assert_no_session_children().await;
    }

    async fn assert_malicious_banner_rejected(&self) {
        let (manager, _) = self
            .manager(
                self.target("known_hosts", "wrong_client_key"),
                default_limits(),
            )
            .await;
        let error = manager
            .start(
                Identity::new(USER).unwrap(),
                TARGET,
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, SessionError::SshAuthenticationFailed);
        let audit = self.audit_text();
        assert!(!audit.contains("session-started"), "{audit}");
        assert!(!audit.contains(BANNER_MARKER), "{audit}");
        self.assert_no_session_children().await;
    }

    async fn assert_no_session_children(&self) {
        timeout(WAIT, async {
            loop {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &self.container.name,
                        "sh",
                        "-c",
                        "pgrep -a sshd | grep -v '\\[listener\\]' || true",
                    ])
                    .output()
                    .expect("inspect sshd processes");
                assert!(output.status.success());
                if output.stdout.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("sshd session child survived cleanup");
    }

    fn local_ssh_pid(&self) -> i32 {
        let needle = self.directory.path().join("client_key");
        let output = command_ok(
            Command::new("ps").args(["-eo", "pid=,command="]),
            "inspect local SSH fixture process",
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                if line.contains(needle.to_str().unwrap()) && line.contains("/usr/bin/ssh") {
                    line.split_whitespace().next()?.parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                panic!("local SSH process for fixture was absent from process inspection")
            })
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(&self.audit_path).unwrap_or_default()
    }

    fn audit_events(&self) -> Vec<serde_json::Value> {
        self.audit_text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn assert_one_start_end(&self, reason: &str) {
        let events = self.audit_events();
        let started = events
            .iter()
            .filter(|event| event["event_type"] == "session-started")
            .collect::<Vec<_>>();
        let ended = events
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .collect::<Vec<_>>();
        assert_eq!(started.len(), 1, "{events:?}");
        assert_eq!(ended.len(), 1, "{events:?}");
        assert_eq!(started[0]["session_id"], ended[0]["session_id"]);
        assert_eq!(ended[0]["close_reason"], reason);
    }

    fn assert_completed_session_since(&self, start: usize, reason: &str) -> String {
        let events = self.audit_events();
        let events = &events[start..];
        let started = events
            .iter()
            .filter(|event| event["event_type"] == "session-started")
            .collect::<Vec<_>>();
        let ended = events
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .collect::<Vec<_>>();
        assert_eq!(started.len(), 1, "{events:?}");
        assert_eq!(ended.len(), 1, "{events:?}");
        assert_eq!(started[0]["session_id"], ended[0]["session_id"]);
        assert_eq!(ended[0]["close_reason"], reason);
        assert!(
            events
                .iter()
                .all(|event| event["event_type"] != "access-denied"),
            "{events:?}"
        );
        started[0]["session_id"].as_str().unwrap().to_owned()
    }
}

struct ContainerGuard {
    name: String,
}

impl std::ops::Deref for ContainerGuard {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let output = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
        if !std::thread::panicking() {
            let output = output.expect("remove disposable sshd");
            assert!(
                output.status.success(),
                "docker cleanup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

fn generate_key(path: PathBuf) {
    command_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path),
        "generate ephemeral Ed25519 fixture key",
    );
}

fn generate_key_with_comment(path: PathBuf, comment: &str) {
    command_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(path),
        "generate sentinel-bearing ephemeral Ed25519 fixture key",
    );
}

fn command_ok(command: &mut Command, context: &str) -> Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{context}: {error}"));
    assert!(
        output.status.success(),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

async fn wait_for_port(container: &str) -> u16 {
    timeout(WAIT, async {
        loop {
            let output = Command::new("docker")
                .args(["port", container, "2222/tcp"])
                .output()
                .expect("query sshd port");
            if output.status.success()
                && let Some(port) = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .rsplit(':')
                    .next()
                    .and_then(|value| value.parse().ok())
                && TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .is_ok()
            {
                return port;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("sshd port was not published")
}

fn public_key_fields(path: &Path) -> (String, String) {
    let public = fs::read_to_string(path).unwrap();
    let mut fields = public.split_whitespace();
    (
        fields.next().unwrap().to_owned(),
        fields.next().unwrap().to_owned(),
    )
}

fn unused_loopback_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn default_limits() -> Limits {
    Limits {
        max_sessions: 8,
        max_sessions_per_user: 4,
        idle_timeout: Duration::from_secs(60),
        absolute_timeout: Duration::from_secs(600),
        session_requests_per_window: 100,
        session_request_window: Duration::from_secs(60),
        authentication_failures_per_window: 100,
        authentication_failure_window: Duration::from_secs(60),
    }
}

fn test_config(target: SshTarget, limits: Limits, audit_path: PathBuf) -> Config {
    Config {
        server: ServerConfig {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            mode: ServerMode::Dev,
            public_url: "http://127.0.0.1:7681".to_owned(),
            transport: ServerTransport::Plaintext,
        },
        auth: AuthConfig::Dev {
            user: USER.to_owned(),
        },
        audit: AuditConfig {
            path: audit_path,
            format: AuditFormat::Json,
            recording: false,
        },
        limits,
        targets: vec![Target::Ssh(target)],
    }
}

async fn read_until(session: &mut Session, marker: &str) -> String {
    timeout(WAIT, async {
        let mut output = Vec::new();
        loop {
            let chunk = session.read().await.expect("read SSH terminal");
            output.extend_from_slice(&chunk);
            let text = String::from_utf8_lossy(&output);
            if text.contains(marker) {
                return text.into_owned();
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("SSH output did not contain {marker}"))
}

async fn provision_cookie(address: SocketAddr) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "POST /api/identity HTTP/1.1\r\nHost: {address}\r\nOrigin: http://127.0.0.1:7681\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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

async fn issue_ticket(address: SocketAddr, cookie: &str) -> String {
    let body = format!(r#"{{"target":"{TARGET}"}}"#);
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "POST /api/sessions HTTP/1.1\r\nHost: {address}\r\nOrigin: http://127.0.0.1:7681\r\nCookie: {cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
    let body = response.split_once("\r\n\r\n").unwrap().1;
    serde_json::from_str::<serde_json::Value>(body).unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn strict_known_host_ssh_reaches_real_sshd() {
    RealSshdFixture::start().await.assert_strict_success().await;
}

#[tokio::test]
async fn empty_unknown_known_hosts_rejects_before_session_start() {
    RealSshdFixture::start()
        .await
        .assert_empty_unknown_rejected()
        .await;
}

#[tokio::test]
async fn mismatched_host_key_has_stable_frontend_and_audit_failure() {
    RealSshdFixture::start()
        .await
        .assert_host_key_mismatch()
        .await;
}

#[tokio::test]
async fn refused_port_is_distinct_connection_failure() {
    RealSshdFixture::start()
        .await
        .assert_refused_connection()
        .await;
}

#[tokio::test]
async fn wrong_identity_key_is_distinct_authentication_failure() {
    RealSshdFixture::start().await.assert_wrong_identity().await;
}

#[tokio::test]
async fn remote_exit_status_propagates_after_admission() {
    RealSshdFixture::start().await.assert_remote_exit().await;
}

#[tokio::test]
async fn ssh_resize_reaches_remote_pty() {
    RealSshdFixture::start().await.assert_resize().await;
}

#[tokio::test]
async fn ssh_terminal_input_output_are_opaque_and_absent_from_audit() {
    RealSshdFixture::start().await.assert_opaque_io().await;
}

#[tokio::test]
async fn ssh_secret_sentinels_never_reach_audit_or_frontend_errors() {
    RealSshdFixture::start()
        .await
        .assert_sentinel_secrecy()
        .await;
}

#[tokio::test]
async fn ssh_websocket_drop_terminates_and_reaps_local_process() {
    RealSshdFixture::start().await.assert_drop_reaps().await;
}

#[tokio::test]
async fn ssh_idle_absolute_explicit_cancellation_shutdown_and_unwind_complete_once() {
    RealSshdFixture::start().await.assert_cleanup_matrix().await;
}

#[tokio::test]
async fn resistant_ssh_cleanup_holds_capacity_until_group_reaped() {
    RealSshdFixture::start()
        .await
        .assert_capacity_cleanup()
        .await;
}

#[tokio::test]
async fn sshd_has_no_lingering_session_child_after_cleanup() {
    RealSshdFixture::start()
        .await
        .assert_no_remote_child()
        .await;
}

#[tokio::test]
async fn malicious_pre_auth_banner_cannot_forge_ssh_admission() {
    RealSshdFixture::start()
        .await
        .assert_malicious_banner_rejected()
        .await;
}

#[tokio::test]
async fn cancelled_fixture_construction_removes_container_materials_and_releases_lock() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let construction = tokio::spawn(RealSshdFixture::start_paused_after_container(started_tx));
    let (container, material_directory) = timeout(Duration::from_secs(60), started_rx)
        .await
        .expect("fixture did not arm cleanup")
        .expect("fixture report was dropped");
    construction.abort();
    assert!(matches!(
        construction.await,
        Err(error) if error.is_cancelled()
    ));
    assert!(!material_directory.exists());
    let inspect = Command::new("docker")
        .args(["inspect", &container])
        .output()
        .unwrap();
    assert!(
        !inspect.status.success(),
        "cancelled fixture container survived"
    );
    timeout(Duration::from_secs(60), RealSshdFixture::start())
        .await
        .expect("cancelled fixture retained the serial lock");
}
