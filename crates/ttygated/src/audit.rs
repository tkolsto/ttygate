use std::{fmt, net::SocketAddr, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::ticket::Identity;

pub const AUDIT_SCHEMA_VERSION: u8 = 1;
const OPAQUE_ID_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AuditTimestamp(String);

impl AuditTimestamp {
    pub fn now() -> Result<Self, AuditValueError> {
        Self::from_system_time(SystemTime::now())
    }

    pub fn from_system_time(value: SystemTime) -> Result<Self, AuditValueError> {
        OffsetDateTime::from(value)
            .format(&Rfc3339)
            .map(Self)
            .map_err(|_| AuditValueError)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Result<Self, AuditValueError> {
                let mut bytes = [0_u8; OPAQUE_ID_BYTES];
                getrandom::fill(&mut bytes).map_err(|_| AuditValueError)?;
                Ok(Self::from_bytes(bytes))
            }

            pub fn from_bytes(bytes: [u8; OPAQUE_ID_BYTES]) -> Self {
                Self(URL_SAFE_NO_PAD.encode(bytes))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(SessionId);
opaque_id!(CorrelationId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialCategory {
    Authentication,
    RateLimit,
    Capacity,
    Target,
    Ticket,
    Origin,
    HostKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialReason {
    IdentityRequired,
    IdentityUnavailable,
    AuthenticationRateLimited,
    SessionRateLimited,
    GlobalSessionLimit,
    IdentitySessionLimit,
    TargetNotFound,
    TargetUnavailable,
    TicketMalformed,
    TicketUnknown,
    TicketExpired,
    TicketWrongIdentity,
    TicketCapacity,
    TicketGeneration,
    OriginDenied,
    HostKeyVerificationFailed,
    SessionUnavailable,
    AuditUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditCloseReason {
    ChildExited,
    Explicit,
    WebsocketDisconnect,
    ManagerShutdown,
    IdleTimeout,
    AbsoluteTimeout,
    SpawnFailure,
    Cancellation,
    SupervisorUnwind,
    BackendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum AuditOutcome {
    Code(u8),
    Signal(u8),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    schema_version: u8,
    #[serde(flatten)]
    event: AuditEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event_type", rename_all = "kebab-case")]
enum AuditEventKind {
    AuthenticationSucceeded {
        identity: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        occurred_at: AuditTimestamp,
    },
    SessionStarted {
        session_id: SessionId,
        identity: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        started_at: AuditTimestamp,
    },
    SessionEnded {
        session_id: SessionId,
        identity: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        started_at: AuditTimestamp,
        ended_at: AuditTimestamp,
        close_reason: AuditCloseReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<AuditOutcome>,
    },
    AccessDenied {
        correlation_id: CorrelationId,
        category: DenialCategory,
        reason: DenialReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        identity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        occurred_at: AuditTimestamp,
    },
}

impl AuditEvent {
    pub fn authentication_succeeded(
        identity: &Identity,
        remote_address: Option<SocketAddr>,
        occurred_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::AuthenticationSucceeded {
            identity: identity.as_str().to_owned(),
            remote_address: format_address(remote_address),
            occurred_at,
        })
    }

    pub fn session_started(
        session_id: SessionId,
        identity: &Identity,
        target: &str,
        remote_address: Option<SocketAddr>,
        started_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::SessionStarted {
            session_id,
            identity: identity.as_str().to_owned(),
            target: target.to_owned(),
            remote_address: format_address(remote_address),
            started_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn session_ended(
        session_id: SessionId,
        identity: &Identity,
        target: &str,
        remote_address: Option<SocketAddr>,
        started_at: AuditTimestamp,
        ended_at: AuditTimestamp,
        close_reason: AuditCloseReason,
        outcome: Option<AuditOutcome>,
    ) -> Self {
        Self::new(AuditEventKind::SessionEnded {
            session_id,
            identity: identity.as_str().to_owned(),
            target: target.to_owned(),
            remote_address: format_address(remote_address),
            started_at,
            ended_at,
            close_reason,
            outcome,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn access_denied(
        correlation_id: CorrelationId,
        category: DenialCategory,
        reason: DenialReason,
        identity: Option<&Identity>,
        target: Option<&str>,
        remote_address: Option<SocketAddr>,
        occurred_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::AccessDenied {
            correlation_id,
            category,
            reason,
            identity: identity.map(|identity| identity.as_str().to_owned()),
            target: target.map(str::to_owned),
            remote_address: format_address(remote_address),
            occurred_at,
        })
    }

    fn new(event: AuditEventKind) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            event,
        }
    }
}

fn format_address(address: Option<SocketAddr>) -> Option<String> {
    address.map(|address| address.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("audit value could not be constructed")]
pub struct AuditValueError;

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
