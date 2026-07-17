use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Instant};

use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

use crate::ticket::{Identity, IdentityError};

pub const SESSION_COOKIE_NAME: &str = "ttgate_session";
const SESSION_BYTES: usize = 32;
const SESSION_LENGTH: usize = 43;
const MAX_SESSIONS: usize = 1024;

pub struct AuthContext<'a> {
    headers: &'a HeaderMap,
    peer_addr: Option<SocketAddr>,
}

impl<'a> AuthContext<'a> {
    pub fn new(headers: &'a HeaderMap, peer_addr: Option<SocketAddr>) -> Self {
        Self { headers, peer_addr }
    }

    pub fn headers(&self) -> &HeaderMap {
        self.headers
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}

pub trait AuthProvider: Send + Sync {
    fn establish(&self, context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError>;
    fn authenticate(
        &self,
        context: &AuthContext<'_>,
        cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedIdentity {
    pub identity: Identity,
    pub cookie: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("identity cookie is missing")]
    Missing,
    #[error("identity cookie is malformed")]
    Malformed,
    #[error("identity session is unknown")]
    Unknown,
    #[error("identity session capacity is exhausted")]
    AtCapacity,
    #[error("identity session generation failed")]
    Generation,
    #[error("configured identity is invalid")]
    InvalidIdentity,
}

#[derive(Debug)]
pub struct DevAuthProvider {
    identity: Identity,
    sessions: Mutex<HashMap<String, DevSession>>,
}

#[derive(Debug)]
struct DevSession {
    identity: Identity,
    created_at: Instant,
}

impl DevAuthProvider {
    pub fn new(user: impl Into<String>) -> Result<Self, IdentityError> {
        Ok(Self {
            identity: Identity::new(user)?,
            sessions: Mutex::new(HashMap::new()),
        })
    }
}

impl AuthProvider for DevAuthProvider {
    fn establish(&self, _context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.created_at)
                .map(|(token, _)| token.clone())
        {
            sessions.remove(&oldest);
        }
        for _ in 0..4 {
            let mut bytes = [0_u8; SESSION_BYTES];
            getrandom::fill(&mut bytes).map_err(|_| AuthError::Generation)?;
            let token = URL_SAFE_NO_PAD.encode(bytes);
            if !sessions.contains_key(&token) {
                sessions.insert(
                    token.clone(),
                    DevSession {
                        identity: self.identity.clone(),
                        created_at: Instant::now(),
                    },
                );
                return Ok(ProvisionedIdentity {
                    identity: self.identity.clone(),
                    cookie: format!(
                        "{SESSION_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"
                    ),
                });
            }
        }
        Err(AuthError::Generation)
    }

    fn authenticate(
        &self,
        _context: &AuthContext<'_>,
        cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError> {
        let header = cookie_header.ok_or(AuthError::Missing)?;
        if header.len() > 4096 {
            return Err(AuthError::Malformed);
        }
        let mut found = None;
        for pair in header.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                return Err(AuthError::Malformed);
            };
            if name == SESSION_COOKIE_NAME {
                if found.is_some()
                    || value.len() != SESSION_LENGTH
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(AuthError::Malformed);
                }
                found = Some(value);
            }
        }
        let token = found.ok_or(AuthError::Missing)?;
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(token)
            .map(|session| session.identity.clone())
            .ok_or(AuthError::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{
        AuthContext, AuthError, AuthProvider, DevAuthProvider, MAX_SESSIONS, SESSION_COOKIE_NAME,
    };

    fn context(headers: &HeaderMap) -> AuthContext<'_> {
        AuthContext::new(
            headers,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43210)),
        )
    }

    #[test]
    fn development_provider_provisions_and_authenticates_opaque_cookie_session() {
        let provider = DevAuthProvider::new("developer").unwrap();
        let headers = HeaderMap::new();
        let provisioned = provider.establish(&context(&headers)).unwrap();
        assert_eq!(provisioned.identity.as_str(), "developer");
        assert!(!provisioned.cookie.contains("developer"));
        assert!(
            provisioned
                .cookie
                .starts_with(&format!("{SESSION_COOKIE_NAME}="))
        );
        for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
            assert!(provisioned.cookie.contains(attribute));
        }
        let pair = provisioned.cookie.split(';').next().unwrap();
        assert_eq!(
            provider
                .authenticate(&context(&headers), Some(pair))
                .unwrap()
                .as_str(),
            "developer"
        );
    }

    #[test]
    fn authentication_context_exposes_borrowed_headers_and_peer_address() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-user", HeaderValue::from_static("alice"));
        headers.insert(header::USER_AGENT, HeaderValue::from_static("test-client"));
        let context = context(&headers);
        assert_eq!(context.headers()["x-auth-user"], "alice");
        assert_eq!(
            context.peer_addr().unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43210)
        );
    }

    #[test]
    fn development_provider_rejects_missing_malformed_and_unknown_cookies() {
        let provider = DevAuthProvider::new("developer").unwrap();
        let headers = HeaderMap::new();
        let context = context(&headers);
        assert_eq!(
            provider.authenticate(&context, None),
            Err(AuthError::Missing)
        );
        assert_eq!(
            provider.authenticate(&context, Some("broken")),
            Err(AuthError::Malformed)
        );
        assert_eq!(
            provider.authenticate(
                &context,
                Some(&format!("ttgate_session={}", "A".repeat(43)))
            ),
            Err(AuthError::Unknown)
        );
        assert_eq!(
            provider.authenticate(
                &context,
                Some(&format!("ttgate_session={}", "x".repeat(10_000)))
            ),
            Err(AuthError::Malformed)
        );
    }

    #[test]
    fn development_sessions_recover_from_capacity_pressure() {
        let provider = DevAuthProvider::new("developer").unwrap();
        let headers = HeaderMap::new();
        let context = context(&headers);
        let first = provider.establish(&context).unwrap().cookie;
        for _ in 0..MAX_SESSIONS {
            provider.establish(&context).unwrap();
        }
        let first_pair = first.split(';').next().unwrap();
        assert_eq!(
            provider.authenticate(&context, Some(first_pair)),
            Err(AuthError::Unknown)
        );
        assert!(provider.establish(&context).is_ok());
    }
}
