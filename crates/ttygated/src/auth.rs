use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Instant,
};

use axum::http::{HeaderMap, HeaderName};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
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
    #[error("connection peer address is unavailable")]
    MissingPeer,
    #[error("connection peer is not trusted")]
    UntrustedPeer,
    #[error("configured identity header is missing")]
    MissingIdentityHeader,
    #[error("configured identity header is duplicated")]
    DuplicateIdentityHeader,
    #[error("configured identity header is invalid")]
    InvalidIdentityHeader,
}

#[derive(Debug)]
pub struct DevAuthProvider {
    identity: Identity,
    sessions: BrowserSessionStore,
}

#[derive(Debug)]
struct BrowserSessionStore {
    sessions: Mutex<HashMap<String, BrowserSession>>,
}

#[derive(Debug)]
struct BrowserSession {
    identity: Identity,
    created_at: Instant,
}

impl BrowserSessionStore {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn establish(&self, identity: Identity) -> Result<ProvisionedIdentity, AuthError> {
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
                    BrowserSession {
                        identity: identity.clone(),
                        created_at: Instant::now(),
                    },
                );
                return Ok(ProvisionedIdentity {
                    identity,
                    cookie: format!(
                        "{SESSION_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"
                    ),
                });
            }
        }
        Err(AuthError::Generation)
    }

    fn authenticate(&self, cookie_header: Option<&str>) -> Result<Identity, AuthError> {
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

impl DevAuthProvider {
    pub fn new(user: impl Into<String>) -> Result<Self, IdentityError> {
        Ok(Self {
            identity: Identity::new(user)?,
            sessions: BrowserSessionStore::new(),
        })
    }
}

impl AuthProvider for DevAuthProvider {
    fn establish(&self, _context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError> {
        self.sessions.establish(self.identity.clone())
    }

    fn authenticate(
        &self,
        _context: &AuthContext<'_>,
        cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError> {
        self.sessions.authenticate(cookie_header)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("trusted proxy authentication configuration is invalid")]
pub struct AuthProviderBuildError;

#[derive(Debug)]
pub struct TrustedProxyAuthProvider {
    identity_header: HeaderName,
    trusted_sources: Vec<IpNet>,
    sessions: BrowserSessionStore,
}

impl TrustedProxyAuthProvider {
    pub fn new(
        identity_header: HeaderName,
        trusted_sources: Vec<IpNet>,
    ) -> Result<Self, AuthProviderBuildError> {
        if trusted_sources.is_empty() {
            return Err(AuthProviderBuildError);
        }
        Ok(Self {
            identity_header,
            trusted_sources,
            sessions: BrowserSessionStore::new(),
        })
    }

    fn trusted_peer(&self, context: &AuthContext<'_>) -> Result<IpAddr, AuthError> {
        let peer = context.peer_addr().ok_or(AuthError::MissingPeer)?.ip();
        if self
            .trusted_sources
            .iter()
            .any(|network| network.contains(&peer))
        {
            Ok(peer)
        } else {
            Err(AuthError::UntrustedPeer)
        }
    }

    fn identity_from_header(&self, headers: &HeaderMap) -> Result<Identity, AuthError> {
        let mut values = headers.get_all(&self.identity_header).iter();
        let value = values.next().ok_or(AuthError::MissingIdentityHeader)?;
        if values.next().is_some() {
            return Err(AuthError::DuplicateIdentityHeader);
        }
        let value =
            std::str::from_utf8(value.as_bytes()).map_err(|_| AuthError::InvalidIdentityHeader)?;
        if value.is_empty()
            || value.len() > 128
            || value.chars().any(char::is_whitespace)
            || value.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidIdentityHeader);
        }
        Identity::new(value).map_err(|_| AuthError::InvalidIdentityHeader)
    }
}

impl AuthProvider for TrustedProxyAuthProvider {
    fn establish(&self, context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError> {
        self.trusted_peer(context)?;
        let identity = self.identity_from_header(context.headers())?;
        self.sessions.establish(identity)
    }

    fn authenticate(
        &self,
        context: &AuthContext<'_>,
        cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError> {
        self.trusted_peer(context)?;
        self.sessions.authenticate(cookie_header)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderValue, header};
    use http::HeaderName;
    use ipnet::IpNet;

    use super::{
        AuthContext, AuthError, AuthProvider, DevAuthProvider, MAX_SESSIONS, SESSION_COOKIE_NAME,
        TrustedProxyAuthProvider,
    };

    fn context(headers: &HeaderMap) -> AuthContext<'_> {
        AuthContext::new(
            headers,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43210)),
        )
    }

    fn proxy(sources: &[&str]) -> TrustedProxyAuthProvider {
        TrustedProxyAuthProvider::new(
            HeaderName::from_static("x-authenticated-user"),
            sources
                .iter()
                .map(|source| source.parse::<IpNet>().unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn peer_context(headers: &HeaderMap, peer: IpAddr) -> AuthContext<'_> {
        AuthContext::new(headers, Some(SocketAddr::new(peer, 43210)))
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

    #[test]
    fn trusted_proxy_accepts_ipv4_network_and_broadcast_boundaries() {
        let provider = proxy(&["192.0.2.0/30"]);
        let headers = HeaderMap::new();

        for peer in [Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 3)] {
            assert_eq!(
                provider.trusted_peer(&peer_context(&headers, peer.into())),
                Ok(IpAddr::V4(peer))
            );
        }
    }

    #[test]
    fn trusted_proxy_rejects_ipv4_peer_immediately_outside_cidr() {
        let provider = proxy(&["192.0.2.0/30"]);
        let headers = HeaderMap::new();

        assert_eq!(
            provider.trusted_peer(&peer_context(
                &headers,
                Ipv4Addr::new(192, 0, 2, 4).into()
            )),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn trusted_proxy_accepts_ipv6_last_inside_and_rejects_first_outside() {
        let provider = proxy(&["2001:db8::/126"]);
        let headers = HeaderMap::new();
        let inside = "2001:db8::3".parse::<Ipv6Addr>().unwrap();
        let outside = "2001:db8::4".parse::<Ipv6Addr>().unwrap();

        assert_eq!(
            provider.trusted_peer(&peer_context(&headers, inside.into())),
            Ok(IpAddr::V6(inside))
        );
        assert_eq!(
            provider.trusted_peer(&peer_context(&headers, outside.into())),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn trusted_proxy_accepts_any_of_multiple_canonical_cidrs() {
        let provider = proxy(&["192.0.2.0/24", "2001:db8:1::/48"]);
        let headers = HeaderMap::new();

        for peer in [
            "192.0.2.99".parse::<IpAddr>().unwrap(),
            "2001:db8:1::99".parse::<IpAddr>().unwrap(),
        ] {
            assert_eq!(
                provider.trusted_peer(&peer_context(&headers, peer)),
                Ok(peer)
            );
        }
    }

    #[test]
    fn trusted_proxy_requires_listener_supplied_peer_address() {
        let provider = proxy(&["127.0.0.1/32"]);
        let headers = HeaderMap::new();

        assert_eq!(
            provider.trusted_peer(&AuthContext::new(&headers, None)),
            Err(AuthError::MissingPeer)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_not_silently_matched_as_ipv4() {
        let provider = proxy(&["192.0.2.0/24"]);
        let headers = HeaderMap::new();
        let mapped = "::ffff:192.0.2.1".parse::<IpAddr>().unwrap();

        assert_eq!(
            provider.trusted_peer(&peer_context(&headers, mapped)),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn forwarded_address_headers_never_change_peer_trust() {
        let provider = proxy(&["192.0.2.0/24"]);
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", HeaderValue::from_static("for=192.0.2.1"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));

        assert_eq!(
            provider.trusted_peer(&peer_context(
                &headers,
                Ipv4Addr::new(198, 51, 100, 1).into()
            )),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn loopback_proxy_contract_matches_only_the_configured_loopback_source() {
        let provider = proxy(&["127.0.0.1/32", "::1/128"]);
        let headers = HeaderMap::new();

        for peer in [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)] {
            assert_eq!(
                provider.trusted_peer(&peer_context(&headers, peer)),
                Ok(peer)
            );
        }
        assert_eq!(
            provider.trusted_peer(&peer_context(
                &headers,
                Ipv4Addr::new(127, 0, 0, 2).into()
            )),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn trusted_proxy_rejects_missing_identity_header() {
        let provider = proxy(&["127.0.0.1/32"]);
        let headers = HeaderMap::new();

        assert_eq!(
            provider.identity_from_header(&headers),
            Err(AuthError::MissingIdentityHeader)
        );
    }

    #[test]
    fn trusted_proxy_rejects_duplicate_identity_headers_even_when_equal() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        headers.append(
            "x-authenticated-user",
            HeaderValue::from_static("alice"),
        );
        headers.append(
            "x-authenticated-user",
            HeaderValue::from_static("alice"),
        );

        assert_eq!(
            provider.identity_from_header(&headers),
            Err(AuthError::DuplicateIdentityHeader)
        );
    }

    #[test]
    fn trusted_proxy_rejects_empty_and_whitespace_only_identity() {
        let provider = proxy(&["127.0.0.1/32"]);
        for value in ["", " ", "\t", "  \t  "] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-authenticated-user",
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
            assert_eq!(
                provider.identity_from_header(&headers),
                Err(AuthError::InvalidIdentityHeader),
                "{value:?}"
            );
        }
    }

    #[test]
    fn trusted_proxy_rejects_leading_trailing_and_embedded_whitespace() {
        let provider = proxy(&["127.0.0.1/32"]);
        for value in [" alice", "alice ", "ali ce", "ali\tce", "ali\u{a0}ce"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-authenticated-user",
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
            assert_eq!(
                provider.identity_from_header(&headers),
                Err(AuthError::InvalidIdentityHeader),
                "{value:?}"
            );
        }
    }

    #[test]
    fn trusted_proxy_rejects_non_utf8_identity_header() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );

        assert_eq!(
            provider.identity_from_header(&headers),
            Err(AuthError::InvalidIdentityHeader)
        );
    }

    #[test]
    fn trusted_proxy_rejects_ascii_and_unicode_control_characters() {
        let provider = proxy(&["127.0.0.1/32"]);
        for value in ["ali\tce", "ali\u{85}ce"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-authenticated-user",
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
            assert_eq!(
                provider.identity_from_header(&headers),
                Err(AuthError::InvalidIdentityHeader),
                "{value:?}"
            );
        }
    }

    #[test]
    fn trusted_proxy_accepts_exact_128_byte_identity() {
        let provider = proxy(&["127.0.0.1/32"]);
        let value = "a".repeat(128);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );

        assert_eq!(
            provider
                .identity_from_header(&headers)
                .unwrap()
                .as_str(),
            value
        );
    }

    #[test]
    fn trusted_proxy_rejects_129_byte_identity() {
        let provider = proxy(&["127.0.0.1/32"]);
        let value = "a".repeat(129);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );

        assert_eq!(
            provider.identity_from_header(&headers),
            Err(AuthError::InvalidIdentityHeader)
        );
    }

    #[test]
    fn trusted_proxy_preserves_case_and_valid_unicode_bytes_without_normalization() {
        let provider = proxy(&["127.0.0.1/32"]);
        let values = ["Alice", "alice", "\u{e9}", "e\u{301}"];

        let parsed = values.map(|value| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-authenticated-user",
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
            provider.identity_from_header(&headers).unwrap()
        });

        for (identity, expected) in parsed.iter().zip(values) {
            assert_eq!(identity.as_str().as_bytes(), expected.as_bytes());
        }
        assert_ne!(parsed[0], parsed[1]);
        assert_ne!(parsed[2], parsed[3]);
    }

    #[test]
    fn trusted_proxy_reads_only_the_configured_identity_header() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-auth-user", "alice"),
            ("x-forwarded-user", "alice"),
            ("forwarded", "for=alice"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }

        assert_eq!(
            provider.identity_from_header(&headers),
            Err(AuthError::MissingIdentityHeader)
        );
    }

    #[test]
    fn trusted_proxy_header_errors_never_reflect_identity_peer_or_parser_text() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_static("hostile identity sentinel"),
        );

        let error = provider.identity_from_header(&headers).unwrap_err().to_string();
        for sentinel in ["hostile", "identity sentinel", "127.0.0.1"] {
            assert!(!error.contains(sentinel), "{error:?} reflected {sentinel:?}");
        }
    }

    #[test]
    fn untrusted_peer_with_valid_identity_is_rejected_before_header_parsing() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_static("valid-looking"),
        );
        let context = peer_context(&headers, Ipv4Addr::new(127, 0, 0, 2).into());

        assert_eq!(provider.establish(&context), Err(AuthError::UntrustedPeer));
    }

    fn proxy_identity_context<'a>(
        headers: &'a mut HeaderMap,
        identity: &'static str,
    ) -> AuthContext<'a> {
        headers.insert(
            "x-authenticated-user",
            HeaderValue::from_static(identity),
        );
        peer_context(headers, IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn trusted_proxy_establishes_existing_secure_cookie_attributes() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        let provisioned = provider
            .establish(&proxy_identity_context(&mut headers, "alice"))
            .unwrap();

        assert_eq!(provisioned.identity.as_str(), "alice");
        assert!(!provisioned.cookie.contains("alice"));
        for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
            assert!(provisioned.cookie.contains(attribute));
        }
        let pair = provisioned.cookie.split(';').next().unwrap();
        assert_eq!(
            provider
                .authenticate(
                    &peer_context(&HeaderMap::new(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    Some(pair),
                )
                .unwrap()
                .as_str(),
            "alice"
        );
    }

    #[test]
    fn trusted_proxy_cookie_authentication_does_not_reread_identity_header() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        let provisioned = provider
            .establish(&proxy_identity_context(&mut headers, "alice"))
            .unwrap();
        let pair = provisioned.cookie.split(';').next().unwrap();

        let identity = provider
            .authenticate(
                &peer_context(&HeaderMap::new(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(pair),
            )
            .unwrap();

        assert_eq!(identity.as_str(), "alice");
    }

    #[test]
    fn trusted_proxy_changed_header_cannot_replace_existing_cookie_identity() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut alice_headers = HeaderMap::new();
        let provisioned = provider
            .establish(&proxy_identity_context(&mut alice_headers, "alice"))
            .unwrap();
        let pair = provisioned.cookie.split(';').next().unwrap();
        let mut changed_headers = HeaderMap::new();
        changed_headers.insert(
            "x-authenticated-user",
            HeaderValue::from_static("mallory"),
        );

        let identity = provider
            .authenticate(
                &peer_context(&changed_headers, IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(pair),
            )
            .unwrap();

        assert_eq!(identity.as_str(), "alice");
    }

    #[test]
    fn trusted_proxy_cookie_still_requires_a_trusted_peer() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        let provisioned = provider
            .establish(&proxy_identity_context(&mut headers, "alice"))
            .unwrap();
        let pair = provisioned.cookie.split(';').next().unwrap();

        assert_eq!(
            provider.authenticate(
                &peer_context(
                    &HeaderMap::new(),
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
                ),
                Some(pair),
            ),
            Err(AuthError::UntrustedPeer)
        );
    }

    #[test]
    fn trusted_proxy_rejects_missing_malformed_unknown_and_duplicate_cookies() {
        let provider = proxy(&["127.0.0.1/32"]);
        let headers = HeaderMap::new();
        let context = peer_context(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST));

        assert_eq!(provider.authenticate(&context, None), Err(AuthError::Missing));
        assert_eq!(
            provider.authenticate(&context, Some("broken")),
            Err(AuthError::Malformed)
        );
        assert_eq!(
            provider.authenticate(
                &context,
                Some(&format!("{SESSION_COOKIE_NAME}={}", "A".repeat(43)))
            ),
            Err(AuthError::Unknown)
        );
        assert_eq!(
            provider.authenticate(
                &context,
                Some(&format!(
                    "{SESSION_COOKIE_NAME}={}; {SESSION_COOKIE_NAME}={}",
                    "A".repeat(43),
                    "B".repeat(43)
                ))
            ),
            Err(AuthError::Malformed)
        );
    }

    #[test]
    fn trusted_proxy_session_capacity_remains_bounded() {
        let provider = proxy(&["127.0.0.1/32"]);
        let mut headers = HeaderMap::new();
        let first = provider
            .establish(&proxy_identity_context(&mut headers, "alice"))
            .unwrap()
            .cookie;
        for _ in 0..MAX_SESSIONS {
            let mut headers = HeaderMap::new();
            provider
                .establish(&proxy_identity_context(&mut headers, "alice"))
                .unwrap();
        }
        let empty_headers = HeaderMap::new();
        let context = peer_context(&empty_headers, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            provider.authenticate(&context, Some(first.split(';').next().unwrap())),
            Err(AuthError::Unknown)
        );
    }
}
