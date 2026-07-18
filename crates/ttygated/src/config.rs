use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use http::HeaderName;
use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

pub const DEFAULT_SESSION_REQUESTS_PER_WINDOW: u32 = 10;
pub const DEFAULT_SESSION_REQUEST_WINDOW: Duration = Duration::from_secs(60);
pub const DEFAULT_AUTHENTICATION_FAILURES_PER_WINDOW: u32 = 20;
pub const DEFAULT_AUTHENTICATION_FAILURE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    pub limits: Limits,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub mode: ServerMode,
    pub public_url: String,
    pub transport: ServerTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerMode {
    Dev,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerTransport {
    Plaintext,
    DirectTls(TlsConfig),
    TrustedProxy(TrustedProxyConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxyConfig {
    pub trusted_sources: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConfig {
    Dev { user: String },
    TrustedProxy { identity_header: HeaderName },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub format: AuditFormat,
    pub path: PathBuf,
    pub recording: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_sessions: usize,
    pub max_sessions_per_user: usize,
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
    pub session_requests_per_window: u32,
    pub session_request_window: Duration,
    pub authentication_failures_per_window: u32,
    pub authentication_failure_window: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Pty(PtyTarget),
    Ssh(SshTarget),
}

impl Target {
    pub fn name(&self) -> &str {
        match self {
            Self::Pty(target) => &target.name,
            Self::Ssh(target) => &target.name,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Pty(target) => target.read_only,
            Self::Ssh(target) => target.read_only,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetAllowlist {
    targets: BTreeMap<String, Target>,
}

impl TargetAllowlist {
    pub fn new(targets: Vec<Target>) -> Result<Self, ConfigError> {
        let mut by_name = BTreeMap::new();
        for (index, target) in targets.into_iter().enumerate() {
            validate_typed_target(index, &target)?;
            let name = target.name().to_owned();
            if by_name.insert(name.clone(), target).is_some() {
                return Err(validation(
                    format!("targets[{index}].name"),
                    "duplicates an earlier target name",
                ));
            }
        }
        Ok(Self { targets: by_name })
    }

    pub fn resolve(&self, name: &str) -> Result<&Target, UnknownTarget> {
        self.targets
            .get(name)
            .ok_or_else(|| UnknownTarget(name.to_owned()))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Target> {
        self.targets.values()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown configured target `{0}`")]
pub struct UnknownTarget(String);

impl UnknownTarget {
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyTarget {
    pub name: String,
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ssh_executable: PathBuf,
    pub identity_file: PathBuf,
    pub known_hosts: PathBuf,
    pub user_policy: SshUserPolicy,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshUserPolicy {
    Fixed(String),
    SameAsAuthenticatedUser,
    Mapping(BTreeMap<String, String>),
}

impl SshUserPolicy {
    pub fn resolve<'a>(&'a self, authenticated_user: &'a str) -> Result<&'a str, UserPolicyError> {
        let user = match self {
            Self::Fixed(user) => user,
            Self::SameAsAuthenticatedUser => authenticated_user,
            Self::Mapping(mapping) => mapping
                .get(authenticated_user)
                .ok_or_else(|| UserPolicyError::NotMapped(authenticated_user.to_owned()))?,
        };
        validate_username_value(user).map_err(|_| UserPolicyError::InvalidResolvedUser)?;
        Ok(user)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UserPolicyError {
    #[error("authenticated user is not present in the configured SSH user mapping")]
    NotMapped(String),
    #[error("resolved SSH user is not a valid configured username")]
    InvalidResolvedUser,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("configuration syntax or schema error: {message}")]
    Parse { message: String },
    #[error("invalid configuration field `{field}`: {message}")]
    Validation {
        field: String,
        message: &'static str,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: RawServer,
    auth: RawAuth,
    audit: RawAudit,
    limits: RawLimits,
    targets: Vec<RawTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind: SocketAddr,
    mode: ServerMode,
    public_url: String,
    #[serde(default)]
    tls: Option<RawTls>,
    #[serde(default)]
    trusted_proxy: Option<RawTrustedProxy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    #[serde(default)]
    certificate: Option<PathBuf>,
    #[serde(default)]
    private_key: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrustedProxy {
    #[serde(default)]
    trusted_sources: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    provider: RawAuthProvider,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    identity_header: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawAuthProvider {
    Dev,
    TrustedProxy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAudit {
    format: AuditFormat,
    path: PathBuf,
    recording: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_sessions: usize,
    max_sessions_per_user: usize,
    idle_timeout_seconds: u64,
    absolute_timeout_seconds: u64,
    #[serde(default)]
    session_requests_per_window: Option<u32>,
    #[serde(default)]
    session_request_window_seconds: Option<u64>,
    #[serde(default)]
    authentication_failures_per_window: Option<u32>,
    #[serde(default)]
    authentication_failure_window_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum RawTarget {
    Pty {
        name: String,
        command: Vec<String>,
        #[serde(default)]
        read_only: bool,
    },
    Ssh {
        name: String,
        host: String,
        port: u16,
        ssh_executable: PathBuf,
        identity_file: PathBuf,
        known_hosts: PathBuf,
        user_policy: RawUserPolicy,
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        user_mapping: Option<BTreeMap<String, String>>,
        #[serde(default)]
        read_only: bool,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawUserPolicy {
    Fixed,
    SameAsAuthUser,
    Mapping,
}

pub fn parse(source: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig =
        toml::from_str(source).map_err(|error: toml::de::Error| ConfigError::Parse {
            message: error.message().to_owned(),
        })?;
    let transport = convert_transport(raw.server.tls, raw.server.trusted_proxy)?;
    let auth = convert_auth(raw.auth)?;
    let targets = raw
        .targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| convert_target(index, target))
        .collect::<Result<Vec<_>, _>>()?;

    validate_literal_path(&raw.audit.path, "audit.path")?;
    validate_nonempty(
        &raw.server.public_url,
        "server.public_url",
        "must not be empty",
    )?;
    validate_limits(&raw.limits)?;
    TargetAllowlist::new(targets.clone())?;

    let config = Config {
        server: ServerConfig {
            bind: raw.server.bind,
            mode: raw.server.mode,
            public_url: raw.server.public_url,
            transport,
        },
        auth,
        audit: AuditConfig {
            format: raw.audit.format,
            path: raw.audit.path,
            recording: raw.audit.recording,
        },
        limits: Limits {
            max_sessions: raw.limits.max_sessions,
            max_sessions_per_user: raw.limits.max_sessions_per_user,
            idle_timeout: Duration::from_secs(raw.limits.idle_timeout_seconds),
            absolute_timeout: Duration::from_secs(raw.limits.absolute_timeout_seconds),
            session_requests_per_window: raw
                .limits
                .session_requests_per_window
                .unwrap_or(DEFAULT_SESSION_REQUESTS_PER_WINDOW),
            session_request_window: Duration::from_secs(
                raw.limits
                    .session_request_window_seconds
                    .unwrap_or(DEFAULT_SESSION_REQUEST_WINDOW.as_secs()),
            ),
            authentication_failures_per_window: raw
                .limits
                .authentication_failures_per_window
                .unwrap_or(DEFAULT_AUTHENTICATION_FAILURES_PER_WINDOW),
            authentication_failure_window: Duration::from_secs(
                raw.limits
                    .authentication_failure_window_seconds
                    .unwrap_or(DEFAULT_AUTHENTICATION_FAILURE_WINDOW.as_secs()),
            ),
        },
        targets,
    };
    validate_startup_contract(&config)?;
    Ok(config)
}

pub fn validate_startup_contract(config: &Config) -> Result<(), ConfigError> {
    let public_url = url::Url::parse(&config.server.public_url).map_err(|_| {
        validation(
            "server.public_url".into(),
            "must be an absolute HTTP or HTTPS origin URL",
        )
    })?;
    if !public_url.username().is_empty()
        || public_url.password().is_some()
        || public_url.host().is_none()
        || public_url.path() != "/"
        || public_url.query().is_some()
        || public_url.fragment().is_some()
    {
        return Err(validation(
            "server.public_url".into(),
            "must contain only an HTTP or HTTPS origin without credentials, path, query, or fragment",
        ));
    }

    let expected_scheme = match config.server.transport {
        ServerTransport::Plaintext => "http",
        ServerTransport::DirectTls(_) | ServerTransport::TrustedProxy(_) => "https",
    };
    if public_url.scheme() != expected_scheme {
        return Err(validation(
            "server.public_url".into(),
            "scheme must match the configured transport boundary",
        ));
    }

    if matches!(config.auth, AuthConfig::Dev { .. }) && !config.server.bind.ip().is_loopback() {
        return Err(validation(
            "server.bind".into(),
            "development authentication requires a loopback listener",
        ));
    }

    if config.server.mode == ServerMode::Production
        && !config.server.bind.ip().is_loopback()
        && matches!(config.server.transport, ServerTransport::Plaintext)
    {
        return Err(validation(
            "server.transport".into(),
            "public production binding requires direct TLS or a complete trusted-proxy contract",
        ));
    }

    if config.server.mode == ServerMode::Production && matches!(config.auth, AuthConfig::Dev { .. })
    {
        return Err(validation(
            "auth.provider".into(),
            "development authentication is not allowed in production",
        ));
    }

    match (&config.auth, &config.server.transport) {
        (AuthConfig::TrustedProxy { .. }, ServerTransport::TrustedProxy(_)) => {}
        (AuthConfig::TrustedProxy { .. }, _) => {
            return Err(validation(
                "auth.provider".into(),
                "trusted-proxy authentication requires the trusted-proxy transport contract",
            ));
        }
        (AuthConfig::Dev { .. }, ServerTransport::TrustedProxy(_)) => {
            return Err(validation(
                "auth.provider".into(),
                "trusted-proxy transport requires trusted-proxy authentication",
            ));
        }
        (AuthConfig::Dev { .. }, _) => {}
    }

    Ok(())
}

fn convert_transport(
    tls: Option<RawTls>,
    trusted_proxy: Option<RawTrustedProxy>,
) -> Result<ServerTransport, ConfigError> {
    match (tls, trusted_proxy) {
        (None, None) => Ok(ServerTransport::Plaintext),
        (Some(_), Some(_)) => Err(validation(
            "server.transport".into(),
            "direct TLS and trusted proxy cannot both be configured",
        )),
        (Some(tls), None) => {
            let certificate = tls.certificate.ok_or_else(|| {
                validation(
                    "server.tls.certificate".into(),
                    "is required when direct TLS is configured",
                )
            })?;
            let private_key = tls.private_key.ok_or_else(|| {
                validation(
                    "server.tls.private_key".into(),
                    "is required when direct TLS is configured",
                )
            })?;
            validate_literal_path(&certificate, "server.tls.certificate")?;
            validate_literal_path(&private_key, "server.tls.private_key")?;
            Ok(ServerTransport::DirectTls(TlsConfig {
                certificate,
                private_key,
            }))
        }
        (None, Some(proxy)) => {
            let sources = proxy.trusted_sources.ok_or_else(|| {
                validation(
                    "server.trusted_proxy.trusted_sources".into(),
                    "is required when trusted proxy is configured",
                )
            })?;
            if sources.is_empty() {
                return Err(validation(
                    "server.trusted_proxy.trusted_sources".into(),
                    "must contain at least one trusted source CIDR",
                ));
            }
            let mut canonical = BTreeSet::new();
            let trusted_sources = sources
                .iter()
                .map(|source| {
                    let network = IpNet::from_str(source).map_err(|_| {
                        validation(
                            "server.trusted_proxy.trusted_sources".into(),
                            "contains an invalid CIDR",
                        )
                    })?;
                    let network = network.trunc();
                    if network.to_string() != *source {
                        return Err(validation(
                            "server.trusted_proxy.trusted_sources".into(),
                            "must contain canonical CIDRs",
                        ));
                    }
                    if !canonical.insert(network) {
                        return Err(validation(
                            "server.trusted_proxy.trusted_sources".into(),
                            "must not contain duplicate CIDRs",
                        ));
                    }
                    Ok(network)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ServerTransport::TrustedProxy(TrustedProxyConfig {
                trusted_sources,
            }))
        }
    }
}

fn convert_auth(raw: RawAuth) -> Result<AuthConfig, ConfigError> {
    match raw.provider {
        RawAuthProvider::Dev => {
            if raw.identity_header.is_some() {
                return Err(validation(
                    "auth.identity_header".into(),
                    "is only valid for trusted-proxy authentication",
                ));
            }
            let user = raw.user.ok_or_else(|| {
                validation("auth.user".into(), "is required for dev authentication")
            })?;
            validate_nonempty(&user, "auth.user", "must not be empty")?;
            Ok(AuthConfig::Dev { user })
        }
        RawAuthProvider::TrustedProxy => {
            if raw.user.is_some() {
                return Err(validation(
                    "auth.user".into(),
                    "is only valid for dev authentication",
                ));
            }
            let identity_header = raw.identity_header.ok_or_else(|| {
                validation(
                    "auth.identity_header".into(),
                    "is required for trusted-proxy authentication",
                )
            })?;
            let identity_header = HeaderName::from_str(&identity_header).map_err(|_| {
                validation(
                    "auth.identity_header".into(),
                    "must be a valid HTTP header name",
                )
            })?;
            Ok(AuthConfig::TrustedProxy { identity_header })
        }
    }
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&source)
}

fn convert_target(index: usize, raw: RawTarget) -> Result<Target, ConfigError> {
    match raw {
        RawTarget::Pty {
            name,
            mut command,
            read_only,
        } => {
            if command.is_empty() {
                return Err(ConfigError::Validation {
                    field: format!("targets[{index}].command"),
                    message: "must contain an executable",
                });
            }
            let executable = PathBuf::from(command.remove(0));
            validate_literal_path(&executable, &format!("targets[{index}].command[0]"))?;
            validate_target_name(&name, &format!("targets[{index}].name"))?;
            Ok(Target::Pty(PtyTarget {
                name,
                executable,
                argv: command,
                read_only,
            }))
        }
        RawTarget::Ssh {
            name,
            host,
            port,
            ssh_executable,
            identity_file,
            known_hosts,
            user_policy,
            user,
            user_mapping,
            read_only,
        } => {
            validate_target_name(&name, &format!("targets[{index}].name"))?;
            validate_nonempty(
                &host,
                &format!("targets[{index}].host"),
                "must not be empty",
            )?;
            if port == 0 {
                return Err(validation(
                    format!("targets[{index}].port"),
                    "must be between 1 and 65535",
                ));
            }
            validate_literal_path(&ssh_executable, &format!("targets[{index}].ssh_executable"))?;
            validate_literal_path(&identity_file, &format!("targets[{index}].identity_file"))?;
            validate_literal_path(&known_hosts, &format!("targets[{index}].known_hosts"))?;
            let policy = match user_policy {
                RawUserPolicy::SameAsAuthUser => {
                    reject_stray_policy_fields(index, &user, &user_mapping)?;
                    SshUserPolicy::SameAsAuthenticatedUser
                }
                RawUserPolicy::Fixed => {
                    if user_mapping.is_some() {
                        return Err(validation(
                            format!("targets[{index}].user_mapping"),
                            "is only valid for mapping user policy",
                        ));
                    }
                    let user = user.ok_or_else(|| {
                        validation(
                            format!("targets[{index}].user"),
                            "is required for fixed user policy",
                        )
                    })?;
                    validate_username(&user, &format!("targets[{index}].user"))?;
                    SshUserPolicy::Fixed(user)
                }
                RawUserPolicy::Mapping => {
                    if user.is_some() {
                        return Err(validation(
                            format!("targets[{index}].user"),
                            "is only valid for fixed user policy",
                        ));
                    }
                    let mapping = user_mapping.ok_or_else(|| {
                        validation(
                            format!("targets[{index}].user_mapping"),
                            "is required for mapping user policy",
                        )
                    })?;
                    if mapping.is_empty() {
                        return Err(validation(
                            format!("targets[{index}].user_mapping"),
                            "must contain at least one mapping",
                        ));
                    }
                    for (identity, username) in &mapping {
                        validate_identity(identity, &format!("targets[{index}].user_mapping"))?;
                        validate_username(username, &format!("targets[{index}].user_mapping"))?;
                    }
                    SshUserPolicy::Mapping(mapping)
                }
            };
            Ok(Target::Ssh(SshTarget {
                name,
                host,
                port,
                ssh_executable,
                identity_file,
                known_hosts,
                user_policy: policy,
                read_only,
            }))
        }
    }
}

fn validation(field: String, message: &'static str) -> ConfigError {
    ConfigError::Validation { field, message }
}

fn validate_nonempty(value: &str, field: &str, message: &'static str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(validation(field.to_owned(), message));
    }
    Ok(())
}

fn validate_target_name(name: &str, field: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(validation(
            field.to_owned(),
            "must be 1-128 ASCII letters, digits, dots, underscores, or hyphens and not start with a hyphen",
        ));
    }
    Ok(())
}

fn validate_literal_path(path: &Path, field: &str) -> Result<(), ConfigError> {
    let Some(value) = path.to_str() else {
        return Err(validation(field.to_owned(), "must be valid UTF-8"));
    };
    let has_expansion_syntax = value.starts_with('~')
        || value
            .chars()
            .any(|character| matches!(character, '$' | '*' | '?' | '[' | ']' | '`' | '{' | '}'));
    if value.is_empty() || value.contains('\0') || has_expansion_syntax {
        return Err(validation(
            field.to_owned(),
            "must be a non-empty literal path without expansion syntax",
        ));
    }
    Ok(())
}

fn validate_limits(raw: &RawLimits) -> Result<(), ConfigError> {
    const MAX_SESSIONS: usize = 1_000_000;
    const MAX_RATE_ALLOWANCE: u32 = 1_000_000;
    const MAX_TIMEOUT_SECONDS: u64 = 366 * 24 * 60 * 60;
    for (field, value) in [
        ("limits.max_sessions", raw.max_sessions),
        ("limits.max_sessions_per_user", raw.max_sessions_per_user),
    ] {
        if value == 0 || value > MAX_SESSIONS {
            return Err(validation(
                field.to_owned(),
                "must be between 1 and 1000000",
            ));
        }
    }
    for (field, value) in [
        ("limits.idle_timeout_seconds", raw.idle_timeout_seconds),
        (
            "limits.absolute_timeout_seconds",
            raw.absolute_timeout_seconds,
        ),
    ] {
        if value == 0 || value > MAX_TIMEOUT_SECONDS {
            return Err(validation(
                field.to_owned(),
                "must be between 1 and 31622400 seconds",
            ));
        }
    }
    for (field, value) in [
        (
            "limits.session_requests_per_window",
            raw.session_requests_per_window
                .unwrap_or(DEFAULT_SESSION_REQUESTS_PER_WINDOW),
        ),
        (
            "limits.authentication_failures_per_window",
            raw.authentication_failures_per_window
                .unwrap_or(DEFAULT_AUTHENTICATION_FAILURES_PER_WINDOW),
        ),
    ] {
        if value == 0 || value > MAX_RATE_ALLOWANCE {
            return Err(validation(
                field.to_owned(),
                "must be between 1 and 1000000",
            ));
        }
    }
    for (field, value) in [
        (
            "limits.session_request_window_seconds",
            raw.session_request_window_seconds
                .unwrap_or(DEFAULT_SESSION_REQUEST_WINDOW.as_secs()),
        ),
        (
            "limits.authentication_failure_window_seconds",
            raw.authentication_failure_window_seconds
                .unwrap_or(DEFAULT_AUTHENTICATION_FAILURE_WINDOW.as_secs()),
        ),
    ] {
        if value == 0 || value > MAX_TIMEOUT_SECONDS {
            return Err(validation(
                field.to_owned(),
                "must be between 1 and 31622400 seconds",
            ));
        }
    }
    if raw.max_sessions_per_user > raw.max_sessions {
        return Err(validation(
            "limits.max_sessions_per_user".into(),
            "must not exceed limits.max_sessions",
        ));
    }
    if raw.idle_timeout_seconds > raw.absolute_timeout_seconds {
        return Err(validation(
            "limits.idle_timeout_seconds".into(),
            "must not exceed limits.absolute_timeout_seconds",
        ));
    }
    Ok(())
}

fn reject_stray_policy_fields(
    index: usize,
    user: &Option<String>,
    mapping: &Option<BTreeMap<String, String>>,
) -> Result<(), ConfigError> {
    if user.is_some() {
        return Err(validation(
            format!("targets[{index}].user"),
            "is only valid for fixed user policy",
        ));
    }
    if mapping.is_some() {
        return Err(validation(
            format!("targets[{index}].user_mapping"),
            "is only valid for mapping user policy",
        ));
    }
    Ok(())
}

fn validate_identity(value: &str, field: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(validation(
            field.to_owned(),
            "contains an invalid authenticated identity",
        ));
    }
    Ok(())
}

fn validate_username(value: &str, field: &str) -> Result<(), ConfigError> {
    validate_username_value(value).map_err(|()| {
        validation(
            field.to_owned(),
            "contains an invalid or option-like SSH username",
        )
    })
}

fn validate_username_value(value: &str) -> Result<(), ()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || bytes.last() == Some(&b'-')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(());
    }
    Ok(())
}

fn validate_typed_target(index: usize, target: &Target) -> Result<(), ConfigError> {
    validate_target_name(target.name(), &format!("targets[{index}].name"))?;
    match target {
        Target::Pty(target) => {
            validate_literal_path(&target.executable, &format!("targets[{index}].command[0]"))?
        }
        Target::Ssh(target) => {
            validate_nonempty(
                &target.host,
                &format!("targets[{index}].host"),
                "must not be empty",
            )?;
            if target.port == 0 {
                return Err(validation(
                    format!("targets[{index}].port"),
                    "must be between 1 and 65535",
                ));
            }
            validate_literal_path(
                &target.ssh_executable,
                &format!("targets[{index}].ssh_executable"),
            )?;
            validate_literal_path(
                &target.identity_file,
                &format!("targets[{index}].identity_file"),
            )?;
            validate_literal_path(
                &target.known_hosts,
                &format!("targets[{index}].known_hosts"),
            )?;
            match &target.user_policy {
                SshUserPolicy::Fixed(user) => {
                    validate_username(user, &format!("targets[{index}].user"))?;
                }
                SshUserPolicy::SameAsAuthenticatedUser => {}
                SshUserPolicy::Mapping(mapping) => {
                    if mapping.is_empty() {
                        return Err(validation(
                            format!("targets[{index}].user_mapping"),
                            "must contain at least one mapping",
                        ));
                    }
                    for (identity, user) in mapping {
                        validate_identity(identity, &format!("targets[{index}].user_mapping"))?;
                        validate_username(user, &format!("targets[{index}].user_mapping"))?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        time::Duration,
    };

    use tempfile::tempdir;

    use super::{
        AuditFormat, AuthConfig, ConfigError, PtyTarget, ServerMode, ServerTransport, SshTarget,
        SshUserPolicy, Target, TargetAllowlist, load, parse,
    };

    const COMPLETE_CONFIG: &str = r#"
[server]
bind = "127.0.0.1:7681"
mode = "dev"
public_url = "http://127.0.0.1:7681"

[auth]
provider = "dev"
user = "local"

[audit]
format = "json"
path = "./ttygate-audit.jsonl"
recording = false

[limits]
max_sessions = 8
max_sessions_per_user = 2
idle_timeout_seconds = 900
absolute_timeout_seconds = 14400

[[targets]]
name = "local-shell"
type = "pty"
command = ["/bin/bash", "-l"]
read_only = false

[[targets]]
name = "lab-host"
type = "ssh"
host = "lab.example.internal"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "same-as-auth-user"
"#;

    #[test]
    fn parses_complete_rewrite_plan_example() {
        let config = parse(COMPLETE_CONFIG).expect("complete example should parse");

        assert_eq!(config.server.mode, ServerMode::Dev);
        assert_eq!(config.server.bind.to_string(), "127.0.0.1:7681");
        assert!(matches!(
            config.auth,
            AuthConfig::Dev { ref user } if user == "local"
        ));
        assert_eq!(config.server.transport, ServerTransport::Plaintext);
        assert_eq!(config.audit.format, AuditFormat::Json);
        assert_eq!(config.limits.max_sessions, 8);
        assert_eq!(config.targets.len(), 2);
        assert!(matches!(
            &config.targets[0],
            Target::Pty(target)
                if target.executable.to_string_lossy() == "/bin/bash"
                    && target.argv == ["-l"]
        ));
        assert!(matches!(
            &config.targets[1],
            Target::Ssh(target)
                if target.user_policy == SshUserPolicy::SameAsAuthenticatedUser
        ));
    }

    #[test]
    fn missing_rate_limit_fields_use_documented_mode_independent_defaults() {
        let dev = parse(COMPLETE_CONFIG).unwrap();
        assert_eq!(dev.limits.session_requests_per_window, 10);
        assert_eq!(dev.limits.session_request_window, Duration::from_secs(60));
        assert_eq!(dev.limits.authentication_failures_per_window, 20);
        assert_eq!(
            dev.limits.authentication_failure_window,
            Duration::from_secs(60)
        );

        for source in [
            COMPLETE_CONFIG.replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/cert.pem\"\nprivate_key = \"/key.pem\"",
            ),
            COMPLETE_CONFIG
                .replace("mode = \"dev\"", "mode = \"production\"")
                .replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
                )
                .replace(
                    "provider = \"dev\"\nuser = \"local\"",
                    "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"",
                ),
        ] {
            let config = parse(&source).unwrap();
            assert_eq!(config.limits, dev.limits);
        }
    }

    #[test]
    fn zero_rate_allowances_and_windows_fail_closed() {
        for (field, value) in [
            ("session_requests_per_window", "0"),
            ("session_request_window_seconds", "0"),
            ("authentication_failures_per_window", "0"),
            ("authentication_failure_window_seconds", "0"),
        ] {
            let source = COMPLETE_CONFIG.replace(
                "absolute_timeout_seconds = 14400",
                &format!("absolute_timeout_seconds = 14400\n{field} = {value}"),
            );
            let error = parse(&source).unwrap_err().to_string();
            assert!(
                error.contains(&format!("limits.{field}")),
                "{error:?} did not contain {field:?}"
            );
        }
    }

    #[test]
    fn explicit_rate_limit_configuration_is_typed() {
        let source = COMPLETE_CONFIG.replace(
            "absolute_timeout_seconds = 14400",
            "absolute_timeout_seconds = 14400\nsession_requests_per_window = 7\nsession_request_window_seconds = 11\nauthentication_failures_per_window = 13\nauthentication_failure_window_seconds = 17",
        );
        let limits = parse(&source).unwrap().limits;
        assert_eq!(limits.session_requests_per_window, 7);
        assert_eq!(limits.session_request_window, Duration::from_secs(11));
        assert_eq!(limits.authentication_failures_per_window, 13);
        assert_eq!(
            limits.authentication_failure_window,
            Duration::from_secs(17)
        );
    }

    #[test]
    fn overflowing_rate_limit_values_fail_closed_without_reflection() {
        for (field, value) in [
            ("session_requests_per_window", "1000001"),
            ("session_request_window_seconds", "31622401"),
            ("authentication_failures_per_window", "1000001"),
            ("authentication_failure_window_seconds", "31622401"),
        ] {
            let source = COMPLETE_CONFIG.replace(
                "absolute_timeout_seconds = 14400",
                &format!("absolute_timeout_seconds = 14400\n{field} = {value}"),
            );
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(&format!("limits.{field}")));
            assert!(!error.contains(value));
        }
    }

    #[test]
    fn unknown_rate_limit_fields_remain_rejected() {
        let source = COMPLETE_CONFIG.replace(
            "absolute_timeout_seconds = 14400",
            "absolute_timeout_seconds = 14400\nsession_request_burst_typo = 10",
        );
        let error = parse(&source).unwrap_err().to_string();
        assert!(matches!(parse(&source), Err(ConfigError::Parse { .. })));
        assert!(!error.contains("local-shell"));
    }

    #[test]
    fn rate_limit_configuration_is_compatible_with_all_transport_modes() {
        let explicit = "\nsession_requests_per_window = 7\nsession_request_window_seconds = 11\nauthentication_failures_per_window = 13\nauthentication_failure_window_seconds = 17";
        let sources = [
            COMPLETE_CONFIG.replace(
                "absolute_timeout_seconds = 14400",
                &format!("absolute_timeout_seconds = 14400{explicit}"),
            ),
            COMPLETE_CONFIG
                .replace(
                    "absolute_timeout_seconds = 14400",
                    &format!("absolute_timeout_seconds = 14400{explicit}"),
                )
                .replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/cert.pem\"\nprivate_key = \"/key.pem\"",
                ),
            COMPLETE_CONFIG
                .replace(
                    "absolute_timeout_seconds = 14400",
                    &format!("absolute_timeout_seconds = 14400{explicit}"),
                )
                .replace("mode = \"dev\"", "mode = \"production\"")
                .replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
                )
                .replace(
                    "provider = \"dev\"\nuser = \"local\"",
                    "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"",
                ),
        ];

        for source in sources {
            let limits = parse(&source).unwrap().limits;
            assert_eq!(limits.session_requests_per_window, 7);
            assert_eq!(limits.authentication_failures_per_window, 13);
        }
    }

    fn config_with_target(target: &str) -> String {
        format!(
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
{target}
"#
        )
    }

    fn minimal_pty(name: &str) -> Target {
        Target::Pty(PtyTarget {
            name: name.into(),
            executable: PathBuf::from("/bin/sh"),
            argv: vec![],
            read_only: false,
        })
    }

    #[test]
    fn parses_minimal_pty_and_ssh_targets() {
        let pty = parse(&config_with_target(
            r#"[[targets]]
name = "shell"
type = "pty"
command = ["/bin/sh"]"#,
        ))
        .unwrap();
        assert!(matches!(&pty.targets[0], Target::Pty(target) if target.argv.is_empty()));

        let ssh = parse(&config_with_target(
            r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "/etc/ttygate/known_hosts"
user_policy = "same-as-auth-user""#,
        ))
        .unwrap();
        assert!(matches!(&ssh.targets[0], Target::Ssh(_)));
    }

    #[test]
    fn parses_and_resolves_all_ssh_user_policies() {
        let cases = [
            (
                r#"user_policy = "fixed"
user = "operator""#,
                "alice",
                Some("operator"),
            ),
            (
                r#"user_policy = "same-as-auth-user""#,
                "alice",
                Some("alice"),
            ),
            (
                r#"user_policy = "mapping"
user_mapping = { alice = "remote-alice" }"#,
                "alice",
                Some("remote-alice"),
            ),
            (
                r#"user_policy = "mapping"
user_mapping = { alice = "remote-alice" }"#,
                "bob",
                None,
            ),
        ];

        for (policy, identity, expected) in cases {
            let source = config_with_target(&format!(
                r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
{policy}"#
            ));
            let config = parse(&source).unwrap();
            let Target::Ssh(target) = &config.targets[0] else {
                panic!("expected ssh target");
            };
            assert_eq!(target.user_policy.resolve(identity).ok(), expected);
        }
    }

    #[test]
    fn rejects_invalid_target_shapes_and_policy_fields() {
        let cases = [
            (
                r#"name = "shell"
type = "pty"
command = []"#,
                "targets[0].command",
            ),
            (
                r#"name = "shell"
type = "pty"
command = [""]"#,
                "targets[0].command[0]",
            ),
            (
                r#"name = "host"
type = "ssh"
host = ""
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "same-as-auth-user""#,
                "targets[0].host",
            ),
            (
                r#"name = "host"
type = "ssh"
host = "example.test"
port = 0
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "same-as-auth-user""#,
                "targets[0].port",
            ),
            (
                r#"name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "fixed""#,
                "targets[0].user",
            ),
            (
                r#"name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "mapping""#,
                "targets[0].user_mapping",
            ),
            (
                r#"name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "mapping"
user_mapping = {}"#,
                "targets[0].user_mapping",
            ),
            (
                r#"name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "same-as-auth-user"
user = "stray""#,
                "targets[0].user",
            ),
        ];

        for (target, field) in cases {
            let source = config_with_target(&format!("[[targets]]\n{target}"));
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(field), "{error:?} did not contain {field:?}");
        }
    }

    #[test]
    fn rejects_unknown_schema_values_and_fields() {
        let cases = [
            config_with_target(
                r#"[[targets]]
name = "bad"
type = "container"
image = "nope""#,
            ),
            config_with_target(
                r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "browser-chooses""#,
            ),
            config_with_target(
                r#"[[targets]]
name = "shell"
type = "pty"
command = ["/bin/sh"]
commnad = ["/bin/bash"]"#,
            ),
        ];
        for source in cases {
            assert!(matches!(parse(&source), Err(ConfigError::Parse { .. })));
        }
    }

    #[test]
    fn rejects_invalid_and_duplicate_target_names() {
        for name in [
            "",
            "two words",
            "../shell",
            "-option",
            "café",
            "a/b",
            "line\nbreak",
        ] {
            let source = config_with_target(&format!(
                "[[targets]]\nname = {name:?}\ntype = \"pty\"\ncommand = [\"/bin/sh\"]"
            ));
            assert!(
                parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("targets[0].name")
            );
        }
        let long_name = "a".repeat(129);
        let source = config_with_target(&format!(
            "[[targets]]\nname = \"{long_name}\"\ntype = \"pty\"\ncommand = [\"/bin/sh\"]"
        ));
        assert!(parse(&source).is_err());

        let duplicate = config_with_target(
            r#"[[targets]]
name = "shell"
type = "pty"
command = ["/bin/sh"]
[[targets]]
name = "shell"
type = "pty"
command = ["/bin/bash"]"#,
        );
        assert!(
            parse(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("targets[1].name")
        );
    }

    #[test]
    fn preserves_literal_paths_and_rejects_expansion_syntax() {
        for path in ["./known_hosts", "/etc/ttygate/known hosts"] {
            let source = config_with_target(&format!(
                r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = {path:?}
user_policy = "same-as-auth-user""#
            ));
            let config = parse(&source).unwrap();
            let Target::Ssh(target) = &config.targets[0] else {
                unreachable!()
            };
            assert_eq!(target.known_hosts, PathBuf::from(path));
        }

        for path in [
            "",
            "~/known_hosts",
            "$HOME/known_hosts",
            "./known_*",
            "./known?hosts",
            "./known[12]",
            "`pwd`/hosts",
            "${HOME}/hosts",
            "./{a,b}",
        ] {
            let source = config_with_target(&format!(
                r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = {path:?}
user_policy = "same-as-auth-user""#
            ));
            assert!(
                parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("targets[0].known_hosts")
            );
        }
    }

    #[test]
    fn validates_limits() {
        let replacements = [
            (
                "max_sessions = 8",
                "max_sessions = 0",
                "limits.max_sessions",
            ),
            (
                "max_sessions_per_user = 2",
                "max_sessions_per_user = 0",
                "limits.max_sessions_per_user",
            ),
            (
                "idle_timeout_seconds = 900",
                "idle_timeout_seconds = 0",
                "limits.idle_timeout_seconds",
            ),
            (
                "absolute_timeout_seconds = 14400",
                "absolute_timeout_seconds = 0",
                "limits.absolute_timeout_seconds",
            ),
            (
                "max_sessions_per_user = 2",
                "max_sessions_per_user = 9",
                "limits.max_sessions_per_user",
            ),
            (
                "idle_timeout_seconds = 900",
                "idle_timeout_seconds = 14401",
                "limits.idle_timeout_seconds",
            ),
        ];
        for (from, to, field) in replacements {
            let source = COMPLETE_CONFIG.replace(from, to);
            assert!(parse(&source).unwrap_err().to_string().contains(field));
        }
        let config = parse(COMPLETE_CONFIG).unwrap();
        assert_eq!(config.limits.idle_timeout, Duration::from_secs(900));
    }

    #[test]
    fn required_sections_fields_and_duplicate_mapping_keys_fail_with_context() {
        for required in ["server", "auth", "audit", "limits", "targets"] {
            let source = match required {
                "server" => COMPLETE_CONFIG.replace("[server]", "[missing_server]"),
                "auth" => COMPLETE_CONFIG.replace("[auth]", "[missing_auth]"),
                "audit" => COMPLETE_CONFIG.replace("[audit]", "[missing_audit]"),
                "limits" => COMPLETE_CONFIG.replace("[limits]", "[missing_limits]"),
                "targets" => COMPLETE_CONFIG.replace("[[targets]]", "[[not_targets]]"),
                _ => unreachable!(),
            };
            assert!(parse(&source).unwrap_err().to_string().contains(required));
        }
        let duplicate = config_with_target(
            r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "mapping"
user_mapping = { alice = "one", alice = "two" }"#,
        );
        assert!(matches!(parse(&duplicate), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn every_required_field_is_rejected_individually() {
        let required_fields = [
            ("bind = \"127.0.0.1:7681\"", "bind"),
            ("mode = \"dev\"", "mode"),
            ("public_url = \"http://127.0.0.1:7681\"", "public_url"),
            ("provider = \"dev\"", "provider"),
            ("user = \"local\"", "user"),
            ("format = \"json\"", "format"),
            ("path = \"./ttygate-audit.jsonl\"", "path"),
            ("recording = false", "recording"),
            ("max_sessions = 8", "max_sessions"),
            ("max_sessions_per_user = 2", "max_sessions_per_user"),
            ("idle_timeout_seconds = 900", "idle_timeout_seconds"),
            (
                "absolute_timeout_seconds = 14400",
                "absolute_timeout_seconds",
            ),
            ("name = \"local-shell\"", "name"),
            ("command = [\"/bin/bash\", \"-l\"]", "command"),
            ("host = \"lab.example.internal\"", "host"),
            ("port = 22", "port"),
            ("ssh_executable = \"/usr/bin/ssh\"", "ssh_executable"),
            ("identity_file = \"./id_ed25519\"", "identity_file"),
            ("known_hosts = \"./known_hosts\"", "known_hosts"),
            ("user_policy = \"same-as-auth-user\"", "user_policy"),
        ];

        for (line, field) in required_fields {
            let source = COMPLETE_CONFIG.replacen(line, "", 1);
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(field), "{error:?} did not contain {field:?}");
        }
    }

    #[test]
    fn unknown_fields_fail_closed_in_every_section() {
        for anchor in ["[server]", "[auth]", "[audit]", "[limits]"] {
            let source = COMPLETE_CONFIG.replacen(anchor, &format!("{anchor}\ntypo = true"), 1);
            assert!(matches!(parse(&source), Err(ConfigError::Parse { .. })));
        }
        let source = format!("top_level_typo = true\n{COMPLETE_CONFIG}");
        assert!(matches!(parse(&source), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn audit_path_uses_the_literal_path_policy() {
        for path in [
            "",
            "~/audit",
            "$HOME/audit",
            "./audit*.jsonl",
            "`pwd`/audit",
        ] {
            let source = COMPLETE_CONFIG.replace(
                "path = \"./ttygate-audit.jsonl\"",
                &format!("path = {path:?}"),
            );
            assert!(
                parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("audit.path")
            );
        }
    }

    #[test]
    fn allowlist_lookup_is_independent_of_toml_parsing() {
        let allowlist = TargetAllowlist::new(vec![minimal_pty("shell")]).unwrap();
        assert_eq!(allowlist.resolve("shell").unwrap().name(), "shell");
        let error = allowlist.resolve("browser-command").unwrap_err();
        assert_eq!(error.name(), "browser-command");
    }

    #[test]
    fn allowlist_rejects_duplicate_typed_targets() {
        assert!(TargetAllowlist::new(vec![minimal_pty("shell"), minimal_pty("shell")]).is_err());
    }

    #[test]
    fn allowlist_rejects_invalid_typed_targets() {
        let invalid_pty = Target::Pty(PtyTarget {
            name: "shell".into(),
            executable: PathBuf::new(),
            argv: vec![],
            read_only: false,
        });
        assert!(
            TargetAllowlist::new(vec![invalid_pty])
                .unwrap_err()
                .to_string()
                .contains("targets[0].command[0]")
        );

        let invalid_ssh = Target::Ssh(SshTarget {
            name: "host".into(),
            host: "example.test".into(),
            port: 0,
            ssh_executable: "/usr/bin/ssh".into(),
            identity_file: "./id_ed25519".into(),
            known_hosts: "./known_hosts".into(),
            user_policy: SshUserPolicy::SameAsAuthenticatedUser,
            read_only: false,
        });
        assert!(
            TargetAllowlist::new(vec![invalid_ssh])
                .unwrap_err()
                .to_string()
                .contains("targets[0].port")
        );
    }

    #[test]
    fn file_loading_has_typed_safe_errors_and_never_executes_targets() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("literal-$HOME-config.toml");
        let marker = directory.path().join("must-not-exist");
        let source = config_with_target(&format!(
            "[[targets]]\nname = \"shell\"\ntype = \"pty\"\ncommand = [\"/usr/bin/touch\", {:?}]",
            marker.to_string_lossy()
        ));
        fs::write(&config_path, source).unwrap();

        let config = load(&config_path).unwrap();
        assert_eq!(config.targets[0].name(), "shell");
        assert!(!marker.exists());

        let missing = directory.path().join("missing.toml");
        assert!(matches!(load(&missing), Err(ConfigError::Read { .. })));
        fs::write(&config_path, "secret_token = 'do-not-display'\nnot toml =").unwrap();
        let message = load(&config_path).unwrap_err().to_string();
        assert!(!message.contains("do-not-display"));
    }

    #[test]
    fn parses_typed_plaintext_direct_tls_and_trusted_proxy_contracts() {
        let plaintext = parse(COMPLETE_CONFIG).unwrap();
        assert_eq!(plaintext.server.transport, ServerTransport::Plaintext);

        let direct_tls = COMPLETE_CONFIG.replace(
            "public_url = \"http://127.0.0.1:7681\"",
            r#"public_url = "https://127.0.0.1:7681"

[server.tls]
certificate = "/etc/ttygate/tls/certificate.pem"
private_key = "/etc/ttygate/tls/private-key.pem""#,
        );
        let direct_tls = parse(&direct_tls).unwrap();
        assert!(matches!(
            direct_tls.server.transport,
            ServerTransport::DirectTls(ref tls)
                if tls.certificate == Path::new("/etc/ttygate/tls/certificate.pem")
                    && tls.private_key == Path::new("/etc/ttygate/tls/private-key.pem")
        ));

        let trusted_proxy = COMPLETE_CONFIG
            .replace("mode = \"dev\"", "mode = \"production\"")
            .replace(
                "public_url = \"http://127.0.0.1:7681\"",
                r#"public_url = "https://terminal.example.test"

[server.trusted_proxy]
trusted_sources = ["127.0.0.1/32", "::1/128"]"#,
            )
            .replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"",
            );
        let trusted_proxy = parse(&trusted_proxy).unwrap();
        assert!(matches!(
            trusted_proxy.auth,
            AuthConfig::TrustedProxy { ref identity_header }
                if identity_header.as_str() == "x-authenticated-user"
        ));
        assert!(matches!(
            trusted_proxy.server.transport,
            ServerTransport::TrustedProxy(ref proxy)
                if proxy.trusted_sources.iter().map(ToString::to_string).collect::<Vec<_>>()
                    == ["127.0.0.1/32", "::1/128"]
        ));
    }

    #[test]
    fn provider_specific_missing_and_stray_fields_fail_closed() {
        let cases = [
            COMPLETE_CONFIG.replace("user = \"local\"\n", ""),
            COMPLETE_CONFIG.replace(
                "user = \"local\"",
                "user = \"local\"\nidentity_header = \"x-user\"",
            ),
            COMPLETE_CONFIG.replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"",
            ),
            COMPLETE_CONFIG.replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"x-user\"\nuser = \"stray\"",
            ),
        ];
        for source in cases {
            assert!(parse(&source).is_err(), "provider-specific fields accepted");
        }
    }

    #[test]
    fn partial_tls_and_proxy_sections_have_actionable_field_errors() {
        let cases = [
            (
                COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/cert.pem\"",
                ),
                "server.tls.private_key",
            ),
            (
                COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://127.0.0.1:7681\"\n[server.trusted_proxy]\ntrusted_sources = []",
                ),
                "server.trusted_proxy.trusted_sources",
            ),
        ];
        for (source, field) in cases {
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(field), "{error:?} did not contain {field:?}");
        }
    }

    #[test]
    fn trusted_proxy_cidrs_and_identity_header_are_typed_and_canonical() {
        let source = COMPLETE_CONFIG
            .replace("mode = \"dev\"", "mode = \"production\"")
            .replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"10.0.0.0/8\"]",
            )
            .replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"X-Authenticated-User\"",
            );
        let config = parse(&source).unwrap();
        assert!(matches!(
            config.auth,
            AuthConfig::TrustedProxy { ref identity_header }
                if identity_header.as_str() == "x-authenticated-user"
        ));
        assert!(matches!(
            config.server.transport,
            ServerTransport::TrustedProxy(ref proxy)
                if proxy.trusted_sources[0].to_string() == "10.0.0.0/8"
        ));
    }

    #[test]
    fn production_validation_matrix_fails_closed() {
        struct Case {
            name: &'static str,
            source: String,
            error_field: Option<&'static str>,
        }

        let tls_server = r#"public_url = "https://127.0.0.1:7681"

[server.tls]
certificate = "/etc/ttygate/tls/certificate.pem"
private_key = "/etc/ttygate/tls/private-key.pem""#;
        let proxy_server = r#"public_url = "https://terminal.example.test"

[server.trusted_proxy]
trusted_sources = ["127.0.0.1/32"]"#;
        let proxy_auth = "provider = \"trusted-proxy\"\nidentity_header = \"x-authenticated-user\"";

        let cases = [
            Case {
                name: "valid loopback plaintext development",
                source: COMPLETE_CONFIG.to_owned(),
                error_field: None,
            },
            Case {
                name: "valid loopback direct TLS development",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    tls_server,
                ),
                error_field: None,
            },
            Case {
                name: "valid production trusted proxy contract",
                source: COMPLETE_CONFIG
                    .replace("mode = \"dev\"", "mode = \"production\"")
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        proxy_server,
                    )
                    .replace("provider = \"dev\"\nuser = \"local\"", proxy_auth),
                error_field: None,
            },
            Case {
                name: "production plaintext development identity",
                source: COMPLETE_CONFIG.replace("mode = \"dev\"", "mode = \"production\""),
                error_field: Some("auth.provider"),
            },
            Case {
                name: "production direct TLS development identity",
                source: COMPLETE_CONFIG
                    .replace("mode = \"dev\"", "mode = \"production\"")
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        tls_server,
                    ),
                error_field: Some("auth.provider"),
            },
            Case {
                name: "production proxy development identity",
                source: COMPLETE_CONFIG
                    .replace("mode = \"dev\"", "mode = \"production\"")
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        proxy_server,
                    ),
                error_field: Some("auth.provider"),
            },
            Case {
                name: "development identity on IPv4 wildcard",
                source: COMPLETE_CONFIG.replace("127.0.0.1:7681", "0.0.0.0:7681"),
                error_field: Some("server.bind"),
            },
            Case {
                name: "development identity on IPv6 wildcard with TLS",
                source: COMPLETE_CONFIG
                    .replace("bind = \"127.0.0.1:7681\"", "bind = \"[::]:7681\"")
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        tls_server,
                    ),
                error_field: Some("server.bind"),
            },
            Case {
                name: "public production plaintext",
                source: COMPLETE_CONFIG
                    .replace("mode = \"dev\"", "mode = \"production\"")
                    .replace("bind = \"127.0.0.1:7681\"", "bind = \"0.0.0.0:7681\"")
                    .replace("provider = \"dev\"\nuser = \"local\"", proxy_auth),
                error_field: Some("server.transport"),
            },
            Case {
                name: "plaintext with HTTPS public URL",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "https://127.0.0.1:7681",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "direct TLS with HTTP public URL",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"http://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/cert.pem\"\nprivate_key = \"/key.pem\"",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "trusted proxy with HTTP public URL",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"http://127.0.0.1:7681\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "simultaneous direct TLS and trusted proxy transports",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://terminal.example.test\"\n[server.tls]\ncertificate = \"/cert.pem\"\nprivate_key = \"/key.pem\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\"]",
                ),
                error_field: Some("server.transport"),
            },
            Case {
                name: "TLS section with certificate only",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/cert.pem\"",
                ),
                error_field: Some("server.tls.private_key"),
            },
            Case {
                name: "TLS section with private key only",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\nprivate_key = \"/key.pem\"",
                ),
                error_field: Some("server.tls.certificate"),
            },
            Case {
                name: "trusted proxy auth without proxy transport",
                source: COMPLETE_CONFIG.replace(
                    "provider = \"dev\"\nuser = \"local\"",
                    proxy_auth,
                ),
                error_field: Some("auth.provider"),
            },
            Case {
                name: "proxy transport without trusted proxy auth",
                source: COMPLETE_CONFIG.replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    proxy_server,
                ),
                error_field: Some("auth.provider"),
            },
            Case {
                name: "duplicate trusted proxy CIDRs",
                source: COMPLETE_CONFIG
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.1/32\", \"127.0.0.1/32\"]",
                    )
                    .replace("provider = \"dev\"\nuser = \"local\"", proxy_auth),
                error_field: Some("server.trusted_proxy.trusted_sources"),
            },
            Case {
                name: "noncanonical trusted proxy CIDR",
                source: COMPLETE_CONFIG
                    .replace(
                        "public_url = \"http://127.0.0.1:7681\"",
                        "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"127.0.0.42/8\"]",
                    )
                    .replace("provider = \"dev\"\nuser = \"local\"", proxy_auth),
                error_field: Some("server.trusted_proxy.trusted_sources"),
            },
            Case {
                name: "public URL credentials",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "http://operator:secret@127.0.0.1:7681",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "public URL path",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "http://127.0.0.1:7681/terminal",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "public URL query",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "http://127.0.0.1:7681/?secret=value",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "public URL fragment",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "http://127.0.0.1:7681/#fragment",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "unsupported public URL scheme",
                source: COMPLETE_CONFIG.replace(
                    "http://127.0.0.1:7681",
                    "ftp://127.0.0.1:7681",
                ),
                error_field: Some("server.public_url"),
            },
            Case {
                name: "missing public URL host",
                source: COMPLETE_CONFIG
                    .replace("http://127.0.0.1:7681", "http://"),
                error_field: Some("server.public_url"),
            },
        ];

        for case in cases {
            match case.error_field {
                None => {
                    parse(&case.source).unwrap_or_else(|error| panic!("{}: {error}", case.name));
                }
                Some(field) => {
                    let error = match parse(&case.source) {
                        Ok(_) => panic!("{} unexpectedly validated", case.name),
                        Err(error) => error.to_string(),
                    };
                    assert!(
                        error.contains(field),
                        "{}: {error:?} did not contain {field:?}",
                        case.name
                    );
                }
            }
        }
    }

    #[test]
    fn development_identity_never_validates_for_non_loopback_exposure_even_with_tls() {
        for bind in ["0.0.0.0:7681", "192.0.2.10:7681", "[::]:7681"] {
            let source = COMPLETE_CONFIG
                .replace("bind = \"127.0.0.1:7681\"", &format!("bind = \"{bind}\""))
                .replace(
                    "public_url = \"http://127.0.0.1:7681\"",
                    "public_url = \"https://terminal.example.test\"\n[server.tls]\ncertificate = \"/cert.pem\"\nprivate_key = \"/key.pem\"",
                );
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains("server.bind"), "{bind}: {error}");
        }
    }

    #[test]
    fn startup_contract_errors_do_not_reflect_hostile_values() {
        let sentinels = [
            "operator-secret",
            "private-path-sentinel",
            "hostile-header-sentinel",
            "cidr-sentinel",
        ];
        let cases = [
            COMPLETE_CONFIG.replace(
                "http://127.0.0.1:7681",
                "http://operator-secret@127.0.0.1:7681",
            ),
            COMPLETE_CONFIG.replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://127.0.0.1:7681\"\n[server.tls]\ncertificate = \"/private-path-sentinel/cert.pem\"",
            ),
            COMPLETE_CONFIG.replace(
                "provider = \"dev\"\nuser = \"local\"",
                "provider = \"trusted-proxy\"\nidentity_header = \"hostile header sentinel\"",
            ),
            COMPLETE_CONFIG.replace(
                "public_url = \"http://127.0.0.1:7681\"",
                "public_url = \"https://terminal.example.test\"\n[server.trusted_proxy]\ntrusted_sources = [\"cidr-sentinel\"]",
            ),
        ];
        for source in cases {
            let message = parse(&source).unwrap_err().to_string();
            for sentinel in sentinels {
                assert!(
                    !message.contains(sentinel),
                    "{message:?} reflected {sentinel}"
                );
            }
        }
    }

    #[test]
    fn mapping_policy_rejects_invalid_identity_and_username_entries() {
        let invalid_maps = [
            r#"user_mapping = { "" = "remote" }"#,
            r#"user_mapping = { alice = "" }"#,
            r#"user_mapping = { "bad identity" = "remote" }"#,
            r#"user_mapping = { alice = "-oProxyCommand=bad" }"#,
        ];
        for mapping in invalid_maps {
            let source = config_with_target(&format!(
                r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "mapping"
{mapping}"#
            ));
            assert!(
                parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("user_mapping")
            );
        }
    }

    #[test]
    fn fixed_policy_rejects_option_like_username() {
        let target = SshTarget {
            name: "host".into(),
            host: "example.test".into(),
            port: 22,
            ssh_executable: "/usr/bin/ssh".into(),
            identity_file: "./id_ed25519".into(),
            known_hosts: "./known_hosts".into(),
            user_policy: SshUserPolicy::Fixed("operator".into()),
            read_only: false,
        };
        assert_eq!(target.user_policy.resolve("ignored").unwrap(), "operator");

        let source = config_with_target(
            r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "./id_ed25519"
known_hosts = "./known_hosts"
user_policy = "fixed"
user = "-oProxyCommand=bad""#,
        );
        assert!(
            parse(&source)
                .unwrap_err()
                .to_string()
                .contains("targets[0].user")
        );
    }

    #[test]
    fn mapping_policy_is_typed() {
        let policy = SshUserPolicy::Mapping(BTreeMap::from([("alice".into(), "remote".into())]));
        assert_eq!(policy.resolve("alice").unwrap(), "remote");
    }

    fn ssh_target(policy: &str) -> String {
        config_with_target(&format!(
            r#"[[targets]]
name = "host"
type = "ssh"
host = "example.test"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "/etc/ttygate/id_ed25519"
known_hosts = "/etc/ttygate/known_hosts"
{policy}"#
        ))
    }

    fn parsed_ssh(policy: &str) -> SshTarget {
        let config = parse(&ssh_target(policy)).expect("SSH target should parse");
        let Target::Ssh(target) = config.targets.into_iter().next().unwrap() else {
            panic!("expected SSH target");
        };
        target
    }

    #[test]
    fn ssh_target_requires_literal_executable_and_identity_paths() {
        let target = parsed_ssh(r#"user_policy = "same-as-auth-user""#);
        assert_eq!(target.ssh_executable, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(
            target.identity_file,
            PathBuf::from("/etc/ttygate/id_ed25519")
        );

        for (line, field) in [
            ("ssh_executable = \"/usr/bin/ssh\"\n", "ssh_executable"),
            (
                "identity_file = \"/etc/ttygate/id_ed25519\"\n",
                "identity_file",
            ),
        ] {
            let source = ssh_target(r#"user_policy = "same-as-auth-user""#).replace(line, "");
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(field), "{error:?} did not contain {field:?}");
        }
    }

    #[test]
    fn ssh_target_rejects_unknown_duplicate_and_stray_credential_fields() {
        let cases = [
            ssh_target(
                r#"user_policy = "same-as-auth-user"
ssh_executible = "/usr/bin/ssh""#,
            ),
            ssh_target(
                r#"user_policy = "same-as-auth-user"
ssh_executable = "/bin/ssh""#,
            ),
            config_with_target(
                r#"[[targets]]
name = "shell"
type = "pty"
command = ["/bin/sh"]
identity_file = "/etc/ttygate/id_ed25519""#,
            ),
        ];

        for source in cases {
            assert!(matches!(parse(&source), Err(ConfigError::Parse { .. })));
        }
    }

    #[test]
    fn fixed_user_policy_resolves_exactly() {
        let target = parsed_ssh(
            r#"user_policy = "fixed"
user = "operator_1""#,
        );
        assert_eq!(target.user_policy.resolve("alice").unwrap(), "operator_1");
    }

    #[test]
    fn same_as_authenticated_user_policy_resolves_exactly() {
        let target = parsed_ssh(r#"user_policy = "same-as-auth-user""#);
        assert_eq!(target.user_policy.resolve("alice.1").unwrap(), "alice.1");
    }

    #[test]
    fn mapping_user_policy_resolves_exactly_and_rejects_missing_mapping() {
        let target = parsed_ssh(
            r#"user_policy = "mapping"
user_mapping = { alice = "remote-alice" }"#,
        );
        assert_eq!(target.user_policy.resolve("alice").unwrap(), "remote-alice");
        assert!(matches!(
            target.user_policy.resolve("bob"),
            Err(super::UserPolicyError::NotMapped(user)) if user == "bob"
        ));
    }

    #[test]
    fn ssh_usernames_reject_option_control_whitespace_confusable_unicode_and_oversize() {
        for username in [
            "",
            "-operator",
            "operator-",
            "_operator",
            ".operator",
            "operator name",
            "operator\nname",
            "operаtor",
            "operator/name",
            "operator@example",
        ] {
            let source = ssh_target(&format!("user_policy = \"fixed\"\nuser = {username:?}"));
            assert!(
                parse(&source)
                    .unwrap_err()
                    .to_string()
                    .contains("targets[0].user"),
                "accepted invalid SSH username {username:?}"
            );
        }
        assert!(matches!(
            SshUserPolicy::Fixed("oper\u{0000}ator".into()).resolve("ignored"),
            Err(super::UserPolicyError::InvalidResolvedUser)
        ));

        let oversize = "a".repeat(129);
        assert!(
            parse(&ssh_target(&format!(
                "user_policy = \"fixed\"\nuser = {oversize:?}"
            )))
            .is_err()
        );

        for username in ["a", "A1", "operator.name", "operator_name", "operator-name"] {
            let target = parsed_ssh(&format!("user_policy = \"fixed\"\nuser = {username:?}"));
            assert_eq!(target.user_policy.resolve("ignored").unwrap(), username);
        }
    }

    #[test]
    fn ssh_literal_paths_preserve_bytes_without_tilde_or_environment_expansion() {
        let source = ssh_target(r#"user_policy = "same-as-auth-user""#)
            .replace("/usr/bin/ssh", "./bin/ssh with spaces")
            .replace(
                "/etc/ttygate/id_ed25519",
                "./credentials/id_ed25519.literal",
            );
        let config = parse(&source).unwrap();
        let Target::Ssh(target) = &config.targets[0] else {
            panic!("expected SSH target");
        };
        assert_eq!(
            target.ssh_executable,
            PathBuf::from("./bin/ssh with spaces")
        );
        assert_eq!(
            target.identity_file,
            PathBuf::from("./credentials/id_ed25519.literal")
        );

        for (field, path) in [
            ("ssh_executable", "~/bin/ssh"),
            ("ssh_executable", "$HOME/bin/ssh"),
            ("identity_file", "~/id_ed25519"),
            ("identity_file", "${HOME}/id_ed25519"),
        ] {
            let source = ssh_target(r#"user_policy = "same-as-auth-user""#).replace(
                &format!(
                    "{field} = {:?}",
                    if field == "ssh_executable" {
                        "/usr/bin/ssh"
                    } else {
                        "/etc/ttygate/id_ed25519"
                    }
                ),
                &format!("{field} = {path:?}"),
            );
            let error = parse(&source).unwrap_err().to_string();
            assert!(error.contains(field), "{error:?} did not contain {field:?}");
        }
    }

    #[test]
    fn unknown_target_fails_before_ssh_construction() {
        let target = parsed_ssh(r#"user_policy = "same-as-auth-user""#);
        assert_eq!(target.ssh_executable, PathBuf::from("/usr/bin/ssh"));
        let allowlist = TargetAllowlist::new(vec![Target::Ssh(target)]).unwrap();

        let error = allowlist.resolve("not-configured").unwrap_err();
        assert_eq!(error.name(), "not-configured");
    }
}
