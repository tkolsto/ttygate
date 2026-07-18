use std::{future::Future, io, net::SocketAddr};

use axum_server::tls_rustls::RustlsConfig;
use thiserror::Error;
use tokio::net::TcpListener;

use crate::{
    config::{Config, ConfigError, ServerTransport, TlsConfig, validate_startup_contract},
    server::{self, AppState, ServerBuildError},
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
    Application(#[from] ServerBuildError),
    #[error("configured authentication provider is not implemented")]
    AuthenticationUnavailable,
    #[error("listener could not be bound")]
    Bind(#[source] io::Error),
    #[error("server stopped because of a listener error")]
    Serve(#[source] io::Error),
}

pub async fn start(config: &Config) -> Result<(), StartupError> {
    start_with(config, tls::load, AppState::from_config, bind_and_serve).await
}

pub async fn start_with<'a, TlsLoader, TlsFuture, AppBuilder, Binder, BindFuture>(
    config: &'a Config,
    tls_loader: TlsLoader,
    app_builder: AppBuilder,
    binder: Binder,
) -> Result<(), StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    AppBuilder: FnOnce(&Config) -> Result<AppState, ServerBuildError>,
    Binder: FnOnce(PreparedServer) -> BindFuture,
    BindFuture: Future<Output = Result<(), StartupError>>,
{
    let prepared = prepare_with(config, tls_loader, app_builder).await?;
    binder(prepared).await
}

pub async fn prepare_with<'a, TlsLoader, TlsFuture, AppBuilder>(
    config: &'a Config,
    tls_loader: TlsLoader,
    app_builder: AppBuilder,
) -> Result<PreparedServer, StartupError>
where
    TlsLoader: FnOnce(&'a TlsConfig) -> TlsFuture,
    TlsFuture: Future<Output = Result<RustlsConfig, TlsError>>,
    AppBuilder: FnOnce(&Config) -> Result<AppState, ServerBuildError>,
{
    validate_startup_contract(config)?;
    let transport = match &config.server.transport {
        ServerTransport::Plaintext => Some(PreparedTransport::Plaintext),
        ServerTransport::DirectTls(config) => {
            Some(PreparedTransport::DirectTls(tls_loader(config).await?))
        }
        ServerTransport::TrustedProxy(_) => None,
    };
    let state = app_builder(config)?;
    let transport = transport.ok_or(StartupError::AuthenticationUnavailable)?;
    Ok(PreparedServer {
        bind: config.server.bind,
        state,
        transport,
    })
}

async fn bind_and_serve(prepared: PreparedServer) -> Result<(), StartupError> {
    match prepared.transport {
        PreparedTransport::Plaintext => {
            let listener = TcpListener::bind(prepared.bind)
                .await
                .map_err(StartupError::Bind)?;
            server::serve(listener, prepared.state)
                .await
                .map_err(StartupError::Serve)
        }
        PreparedTransport::DirectTls(tls) => server::serve_tls(prepared.bind, prepared.state, tls)
            .await
            .map_err(StartupError::Serve),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum_server::tls_rustls::RustlsConfig;
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use crate::{
        config::{AuthConfig, ServerMode, ServerTransport, TlsConfig, parse},
        server::{AppState, ServerBuildError},
        tls::TlsError,
    };

    use super::{PreparedServer, PreparedTransport, StartupError, start_with};

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

    fn phases() -> (PhaseLog, PhaseLog) {
        let phases = Arc::new(Mutex::new(Vec::new()));
        (Arc::clone(&phases), phases)
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
            move |_| {
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
            move |_| {
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
    async fn unimplemented_trusted_proxy_authentication_fails_before_binding() {
        let source = source()
            .replace("mode = \"dev\"", "mode = \"production\"")
            .replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
            )
            .replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"",
            );
        let config = parse(&source).unwrap();
        assert!(matches!(config.auth, AuthConfig::TrustedProxy { .. }));
        let (record, observed) = phases();
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        let error = start_with(
            &config,
            |_| async { unreachable!("proxy transport does not load direct TLS") },
            move |config| {
                app_record.lock().unwrap().push("app");
                AppState::from_config(config)
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
            StartupError::Application(ServerBuildError::AuthenticationUnavailable)
        ));
        assert_eq!(*observed.lock().unwrap(), ["app"]);
    }

    #[tokio::test]
    async fn valid_plaintext_dev_runs_each_startup_phase_once_in_order() {
        let config = parse(source()).unwrap();
        let (record, observed) = phases();
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        start_with(
            &config,
            |_| async { unreachable!("plaintext does not load TLS") },
            move |config| {
                app_record.lock().unwrap().push("app");
                AppState::from_config(config)
            },
            move |prepared: PreparedServer| {
                assert!(matches!(prepared.transport, PreparedTransport::Plaintext));
                bind_record.lock().unwrap().push("bind");
                async { Ok(()) }
            },
        )
        .await
        .unwrap();

        assert_eq!(*observed.lock().unwrap(), ["app", "bind"]);
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
        let app_record = Arc::clone(&record);
        let bind_record = Arc::clone(&record);

        start_with(
            &config,
            move |_| {
                tls_record.lock().unwrap().push("tls");
                async { Ok(rustls_config().await) }
            },
            move |config| {
                app_record.lock().unwrap().push("app");
                AppState::from_config(config)
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

        assert_eq!(*observed.lock().unwrap(), ["tls", "app", "bind"]);
    }

    #[tokio::test]
    async fn startup_errors_are_stable_and_non_reflecting() {
        let mut config = parse(source()).unwrap();
        config.server.public_url = "http://operator-secret@private-host-sentinel.invalid".into();
        let error = start_with(
            &config,
            |_| async { unreachable!() },
            |_| unreachable!(),
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
