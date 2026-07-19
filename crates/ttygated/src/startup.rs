use std::{
    future::Future,
    io,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::Path,
    sync::Arc,
};

use axum_server::tls_rustls::RustlsConfig;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::{
    audit::{AuditError, AuditLog},
    config::{Config, ConfigError, ServerTransport, Target, TlsConfig, validate_startup_contract},
    server::{self, AppState, ServerBuildError},
    service_manager::{self, ServiceManagerError},
    session::SessionManager,
    ssh::{self, PreparedSshTargets, SshPreparationError},
    tls::{self, TlsError},
};

pub struct PreparedServer {
    pub bind: SocketAddr,
    pub state: AppState,
    pub transport: PreparedTransport,
}

pub enum PreparedTransport {
    Plaintext,
    DirectTls(RustlsConfig),
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error(transparent)]
    Ssh(#[from] SshPreparationError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Application(#[from] ServerBuildError),
    #[error("listener could not be bound")]
    Bind(#[source] io::Error),
    #[error("server stopped because of a listener error")]
    Serve(#[source] io::Error),
    #[error("shutdown signal handling could not be installed")]
    Signal(#[source] io::Error),
    #[error(transparent)]
    ServiceManager(#[from] ServiceManagerError),
}

pub async fn start(config: &Config) -> Result<(), StartupError> {
    start_with(
        config,
        tls::load,
        AuditLog::open,
        AppState::from_config_with_audit_pending_ssh,
        bind_and_serve,
    )
    .await
}

pub async fn start_with<'a, TlsLoader, TlsFuture, AuditLoader, AppBuilder, Binder, BindFuture>(
    config: &'a Config,
    tls_loader: TlsLoader,
    audit_loader: AuditLoader,
    app_builder: AppBuilder,
    binder: Binder,
) -> Result<(), StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    AuditLoader: FnOnce(&Path) -> Result<AuditLog, AuditError>,
    AppBuilder: FnOnce(&Config, AuditLog) -> Result<AppState, ServerBuildError>,
    Binder: FnOnce(PreparedServer) -> BindFuture,
    BindFuture: Future<Output = Result<(), StartupError>>,
{
    start_with_ssh(
        config,
        tls_loader,
        ssh::prepare,
        audit_loader,
        app_builder,
        binder,
    )
    .await
}

pub async fn start_with_ssh<
    'a,
    TlsLoader,
    TlsFuture,
    SshLoader,
    SshFuture,
    AuditLoader,
    AppBuilder,
    Binder,
    BindFuture,
>(
    config: &'a Config,
    tls_loader: TlsLoader,
    ssh_loader: SshLoader,
    audit_loader: AuditLoader,
    app_builder: AppBuilder,
    binder: Binder,
) -> Result<(), StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    SshLoader: FnOnce(&'a [Target]) -> SshFuture,
    SshFuture: Future<Output = Result<PreparedSshTargets, SshPreparationError>>,
    AuditLoader: FnOnce(&Path) -> Result<AuditLog, AuditError>,
    AppBuilder: FnOnce(&Config, AuditLog) -> Result<AppState, ServerBuildError>,
    Binder: FnOnce(PreparedServer) -> BindFuture,
    BindFuture: Future<Output = Result<(), StartupError>>,
{
    let prepared =
        prepare_with_ssh(config, tls_loader, ssh_loader, audit_loader, app_builder).await?;
    binder(prepared).await
}

pub async fn prepare_with<'a, TlsLoader, TlsFuture, AuditLoader, AppBuilder>(
    config: &'a Config,
    tls_loader: TlsLoader,
    audit_loader: AuditLoader,
    app_builder: AppBuilder,
) -> Result<PreparedServer, StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    AuditLoader: FnOnce(&Path) -> Result<AuditLog, AuditError>,
    AppBuilder: FnOnce(&Config, AuditLog) -> Result<AppState, ServerBuildError>,
{
    prepare_with_ssh(config, tls_loader, ssh::prepare, audit_loader, app_builder).await
}

pub async fn prepare_with_ssh<
    'a,
    TlsLoader,
    TlsFuture,
    SshLoader,
    SshFuture,
    AuditLoader,
    AppBuilder,
>(
    config: &'a Config,
    tls_loader: TlsLoader,
    ssh_loader: SshLoader,
    audit_loader: AuditLoader,
    app_builder: AppBuilder,
) -> Result<PreparedServer, StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    SshLoader: FnOnce(&'a [Target]) -> SshFuture,
    SshFuture: Future<Output = Result<PreparedSshTargets, SshPreparationError>>,
    AuditLoader: FnOnce(&Path) -> Result<AuditLog, AuditError>,
    AppBuilder: FnOnce(&Config, AuditLog) -> Result<AppState, ServerBuildError>,
{
    validate_startup_contract(config)?;
    let transport = match &config.server.transport {
        ServerTransport::Plaintext => Some(PreparedTransport::Plaintext),
        ServerTransport::DirectTls(config) => {
            Some(PreparedTransport::DirectTls(tls_loader(config).await?))
        }
        ServerTransport::TrustedProxy(_) => Some(PreparedTransport::Plaintext),
    };
    let prepared_ssh = ssh_loader(&config.targets).await?;
    let audit = audit_loader(&config.audit.path)?;
    let state = app_builder(config, audit)?.with_prepared_ssh(&config.targets, prepared_ssh)?;
    Ok(PreparedServer {
        bind: config.server.bind,
        state,
        transport: transport.expect("every validated transport has a serving mode"),
    })
}

async fn bind_and_serve(prepared: PreparedServer) -> Result<(), StartupError> {
    match prepared.transport {
        PreparedTransport::Plaintext => {
            let listener = TcpListener::bind(prepared.bind)
                .await
                .map_err(StartupError::Bind)?;
            let shutdown = termination_signal().map_err(StartupError::Signal)?;
            service_manager::notify_ready()?;
            let _watchdog = service_manager::spawn_watchdog();
            let sessions = prepared.state.sessions();
            serve_until_shutdown(server::serve(listener, prepared.state), sessions, shutdown).await
        }
        PreparedTransport::DirectTls(tls) => {
            let listener = StdTcpListener::bind(prepared.bind).map_err(StartupError::Bind)?;
            let shutdown = termination_signal().map_err(StartupError::Signal)?;
            service_manager::notify_ready()?;
            let _watchdog = service_manager::spawn_watchdog();
            let sessions = prepared.state.sessions();
            serve_until_shutdown(
                server::serve_tls_on(listener, prepared.state, tls),
                sessions,
                shutdown,
            )
            .await
        }
    }
}

fn termination_signal() -> io::Result<impl Future<Output = ()>> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

async fn serve_until_shutdown(
    serve: impl Future<Output = io::Result<()>>,
    sessions: Arc<SessionManager>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), StartupError> {
    let mut serving = Box::pin(serve);
    let mut shutdown = Box::pin(shutdown);
    tokio::select! {
        result = &mut serving => result.map_err(StartupError::Serve),
        () = &mut shutdown => {
            drop(serving);
            sessions.shutdown().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::TcpListener as StdTcpListener,
        sync::{Arc, Mutex},
    };

    use axum_server::tls_rustls::RustlsConfig;
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use crate::{
        audit::{AuditError, AuditLog},
        config::{AuthConfig, ServerMode, ServerTransport, TlsConfig, parse},
        server::{AppState, ServerBuildError},
        tls::TlsError,
    };

    use super::{PreparedServer, PreparedTransport, StartupError, start, start_with};

    fn ssh_config() -> crate::config::Config {
        let mut config = parse(source()).unwrap();
        config.targets = vec![crate::config::Target::Ssh(crate::config::SshTarget {
            name: "remote".into(),
            host: "host.example".into(),
            port: 22,
            ssh_executable: "/test/ssh".into(),
            identity_file: "/test/identity".into(),
            known_hosts: "/test/known-hosts".into(),
            user_policy: crate::config::SshUserPolicy::Fixed("operator".into()),
            read_only: false,
        })];
        config
    }

    #[tokio::test]
    async fn ssh_prepared_map_mismatch_reaches_no_bind() {
        let config = ssh_config();
        let (record, observed) = phases();
        let ssh_record = Arc::clone(&record);
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);
        let error = super::start_with_ssh(
            &config,
            |_| async { unreachable!("plaintext config must not load TLS") },
            move |_| {
                ssh_record.lock().unwrap().push("ssh");
                std::future::ready(Ok(crate::ssh::PreparedSshTargets::from_test_names([
                    "unexpected",
                ])))
            },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Ok(test_audit())
            },
            move |config, audit| {
                app_record.lock().unwrap().push("app");
                AppState::from_config_with_audit_pending_ssh(config, audit)
            },
            move |_| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, StartupError::Ssh(_)));
        assert_eq!(*observed.lock().unwrap(), ["ssh", "audit", "app"]);
    }

    #[test]
    fn production_app_construction_rejects_unprepared_ssh_allowlist() {
        assert!(AppState::from_config_with_audit(&ssh_config(), test_audit()).is_err());
    }

    #[tokio::test]
    async fn startup_orders_ssh_preparation_and_transfers_exact_map_before_bind() {
        let mut config = ssh_config();
        config.server.public_url = "https://127.0.0.1:7681".into();
        config.server.transport = ServerTransport::DirectTls(TlsConfig {
            certificate: "/test/certificate".into(),
            private_key: "/test/private-key".into(),
        });
        let (record, observed) = phases();
        let tls_record = Arc::clone(&record);
        let ssh_record = Arc::clone(&record);
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        super::start_with_ssh(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { Ok(rustls_config().await) }
            },
            move |_| {
                ssh_record.lock().unwrap().push("ssh");
                std::future::ready(Ok(crate::ssh::PreparedSshTargets::from_test_names([
                    "remote",
                ])))
            },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Ok(test_audit())
            },
            move |config, audit| {
                app_record.lock().unwrap().push("app");
                AppState::from_config_with_audit_pending_ssh(config, audit)
            },
            move |prepared| {
                bind_record.lock().unwrap().push("bind");
                async move {
                    assert!(prepared.state.prepared_ssh().get("remote").is_some());
                    assert_eq!(prepared.state.prepared_ssh().iter().count(), 1);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            *observed.lock().unwrap(),
            ["tls", "ssh", "audit", "app", "bind"]
        );
    }

    #[tokio::test]
    async fn ssh_preparation_failure_reaches_neither_application_nor_bind() {
        let mut config = parse(source()).unwrap();
        config.targets = vec![crate::config::Target::Ssh(crate::config::SshTarget {
            name: "remote".into(),
            host: "host.example".into(),
            port: 22,
            ssh_executable: "/missing/ssh".into(),
            identity_file: "/missing/identity".into(),
            known_hosts: "/missing/known-hosts".into(),
            user_policy: crate::config::SshUserPolicy::Fixed("operator".into()),
            read_only: false,
        })];
        let (record, observed) = phases();
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            |_| async { unreachable!("plaintext config must not load TLS") },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                unreachable!("failed SSH preparation must not open audit")
            },
            move |_, _| {
                app_record.lock().unwrap().push("app");
                unreachable!("failed SSH preparation must not build app")
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, StartupError::Ssh(_)));
        assert!(observed.lock().unwrap().is_empty());
    }

    type PhaseLog = Arc<Mutex<Vec<&'static str>>>;

    fn source() -> &'static str {
        r#"
[server]
bind = "127.0.0.1:7681"
mode = "dev"
public_url = "http://127.0.0.1:7681"
[auth]
provider = "dev"
user = "local"
[audit]
format = "json"
path = "./audit.jsonl"
recording = false
[limits]
max_sessions = 8
max_sessions_per_user = 2
idle_timeout_seconds = 900
absolute_timeout_seconds = 14400
[[targets]]
name = "shell"
type = "pty"
command = ["/bin/sh"]
"#
    }

    fn trusted_proxy_source() -> String {
        source()
            .replace("mode = \"dev\"", "mode = \"production\"")
            .replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
            )
            .replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"",
            )
    }

    fn phases() -> (PhaseLog, PhaseLog) {
        let phases = Arc::new(Mutex::new(Vec::new()));
        (Arc::clone(&phases), phases)
    }

    fn test_audit() -> AuditLog {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        AuditLog::open(&directory.path().join("audit.jsonl")).unwrap()
    }

    async fn rustls_config() -> RustlsConfig {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        RustlsConfig::from_pem(
            cert.pem().into_bytes(),
            signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap()
    }

    #[cfg(unix)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &std::path::Path, _mode: u32) {}

    #[tokio::test]
    async fn invalid_configuration_reaches_neither_tls_app_nor_bind_phase() {
        let mut config = parse(source()).unwrap();
        config.server.mode = ServerMode::Production;
        let (record, observed) = phases();
        let tls_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { unreachable!("invalid config must not load TLS") }
            },
            |_| unreachable!("invalid config must not open audit"),
            move |_, _| {
                app_record.lock().unwrap().push("app");
                unreachable!("invalid config must not build app")
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, StartupError::Config(_)));
        assert!(observed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn audit_sink_failure_reaches_neither_application_nor_bind_phase() {
        let config = parse(source()).unwrap();
        let (record, observed) = phases();
        let tls_record = Arc::clone(&record);
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { unreachable!("plaintext config must not load TLS") }
            },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Err(AuditError::DestinationUnavailable)
            },
            move |_, _| {
                app_record.lock().unwrap().push("app");
                unreachable!("failed audit must not build app")
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, StartupError::Audit(_)));
        assert_eq!(*observed.lock().unwrap(), ["audit"]);
    }

    #[tokio::test]
    async fn occupied_direct_tls_address_reports_bind_error() {
        let occupied = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let certificate_path = directory.path().join("certificate.pem");
        let private_key_path = directory.path().join("private-key.pem");
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        fs::write(&certificate_path, cert.pem()).unwrap();
        fs::write(&private_key_path, signing_key.serialize_pem()).unwrap();
        set_mode(&private_key_path, 0o600);
        let source = source()
            .replace("127.0.0.1:7681", &address.to_string())
            .replace(
                "path = \"./audit.jsonl\"",
                &format!("path = {:?}", directory.path().join("audit.jsonl")),
            )
            .replace(
                &format!("public_url = \"http://{address}\""),
                &format!(
                    "public_url = \"https://localhost:{}\"\n[server.tls]\ncertificate = {certificate_path:?}\nprivate_key = {private_key_path:?}",
                    address.port()
                ),
            );
        let config = parse(&source).unwrap();

        let error = start(&config).await.unwrap_err();

        assert!(matches!(error, StartupError::Bind(_)), "{error}");
    }

    #[tokio::test]
    async fn invalid_tls_reaches_neither_app_nor_bind_phase() {
        let mut config = parse(source()).unwrap();
        config.server.public_url = "https://127.0.0.1:7681".into();
        config.server.transport = ServerTransport::DirectTls(TlsConfig {
            certificate: "/certificate.pem".into(),
            private_key: "/private-key.pem".into(),
        });
        let (record, observed) = phases();
        let tls_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { Err(TlsError::CertificateMalformed) }
            },
            |_| unreachable!("invalid TLS must not open audit"),
            move |_, _| {
                app_record.lock().unwrap().push("app");
                unreachable!("invalid TLS must not build app")
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(*observed.lock().unwrap(), ["tls"]);
        assert_eq!(error.to_string(), "TLS certificate file is malformed");
    }

    #[tokio::test]
    async fn production_trusted_proxy_startup_reaches_bind_only_with_real_provider() {
        let config = parse(&trusted_proxy_source()).unwrap();
        assert!(matches!(config.auth, AuthConfig::TrustedProxy { .. }));
        let (record, observed) = phases();
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        start_with(
            &config,
            |_| async { unreachable!("proxy transport does not load direct TLS") },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Ok(test_audit())
            },
            move |config, audit| {
                app_record.lock().unwrap().push("app");
                AppState::from_config_with_audit(config, audit)
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap();

        assert_eq!(*observed.lock().unwrap(), ["audit", "app", "bind"]);
    }

    #[test]
    fn trusted_proxy_config_constructs_real_provider() {
        let config = parse(&trusted_proxy_source()).unwrap();

        assert!(AppState::from_config_with_audit(&config, test_audit()).is_ok());
    }

    #[tokio::test]
    async fn trusted_proxy_provider_construction_failure_reaches_no_listener() {
        let config = parse(&trusted_proxy_source()).unwrap();
        let (record, observed) = phases();
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            |_| async { unreachable!("proxy transport does not load direct TLS") },
            |_| Ok(test_audit()),
            move |_, _| {
                app_record.lock().unwrap().push("app");
                Err(ServerBuildError::Authentication)
            },
            move |_: PreparedServer| {
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            StartupError::Application(ServerBuildError::Authentication)
        ));
        assert_eq!(*observed.lock().unwrap(), ["app"]);
    }

    #[tokio::test]
    async fn valid_plaintext_dev_runs_each_startup_phase_once_in_order() {
        let config = parse(source()).unwrap();
        let (record, observed) = phases();
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        start_with(
            &config,
            |_| async { unreachable!("plaintext does not load TLS") },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Ok(test_audit())
            },
            move |config, audit| {
                app_record.lock().unwrap().push("app");
                AppState::from_config_with_audit(config, audit)
            },
            move |prepared: PreparedServer| {
                assert!(matches!(prepared.transport, PreparedTransport::Plaintext));
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap();

        assert_eq!(*observed.lock().unwrap(), ["audit", "app", "bind"]);
    }

    #[tokio::test]
    async fn valid_direct_tls_dev_runs_each_startup_phase_once_in_order() {
        let mut config = parse(source()).unwrap();
        config.server.public_url = "https://127.0.0.1:7681".into();
        config.server.transport = ServerTransport::DirectTls(TlsConfig {
            certificate: "/certificate.pem".into(),
            private_key: "/private-key.pem".into(),
        });
        let (record, observed) = phases();
        let tls_record = Arc::clone(&record);
        let audit_record = Arc::clone(&record);
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        start_with(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { Ok(rustls_config().await) }
            },
            move |_| {
                audit_record.lock().unwrap().push("audit");
                Ok(test_audit())
            },
            move |config, audit| {
                app_record.lock().unwrap().push("app");
                AppState::from_config_with_audit(config, audit)
            },
            move |prepared: PreparedServer| {
                assert!(matches!(
                    prepared.transport,
                    PreparedTransport::DirectTls(_)
                ));
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap();

        assert_eq!(*observed.lock().unwrap(), ["tls", "audit", "app", "bind"]);
    }

    #[tokio::test]
    async fn startup_errors_are_stable_and_non_reflecting() {
        let mut config = parse(source()).unwrap();
        config.server.public_url = "http://operator-secret@private-host-sentinel.invalid".into();
        let error = start_with(
            &config,
            |_| async { unreachable!() },
            |_| unreachable!(),
            |_, _| unreachable!(),
            |_: PreparedServer| async { Ok(()) },
        )
        .await
        .unwrap_err()
        .to_string();
        for sentinel in ["operator-secret", "private-host-sentinel"] {
            assert!(!error.contains(sentinel), "{error:?} reflected {sentinel}");
        }
    }
}
