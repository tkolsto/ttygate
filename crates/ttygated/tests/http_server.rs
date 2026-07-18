use std::{
    io::{Read, Write},
    net::SocketAddr,
    net::TcpStream,
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use http::{HeaderName, HeaderValue};
use http_body_util::BodyExt;
use ipnet::IpNet;
use tokio::net::TcpListener;
use tower::ServiceExt;
use ttygated::{
    auth::{
        AuthContext, AuthError, AuthProvider, DevAuthProvider, ProvisionedIdentity,
        SESSION_COOKIE_NAME, TrustedProxyAuthProvider,
    },
    config::{Limits, PtyTarget, Target, TargetAllowlist},
    origin::OriginPolicy,
    server::{AppState, build_router, serve},
    ticket::{Identity, TicketStore},
};

const ORIGIN: &str = "https://ttygate.local:7681";

fn limits() -> Limits {
    Limits {
        max_sessions: 8,
        max_sessions_per_user: 4,
        idle_timeout: std::time::Duration::from_secs(5),
        absolute_timeout: std::time::Duration::from_secs(10),
    }
}

struct PeerRecordingAuthProvider {
    peer_addr: Mutex<Option<SocketAddr>>,
}

impl AuthProvider for PeerRecordingAuthProvider {
    fn establish(&self, context: &AuthContext<'_>) -> Result<ProvisionedIdentity, AuthError> {
        *self.peer_addr.lock().unwrap() = context.peer_addr();
        Ok(ProvisionedIdentity {
            identity: Identity::new("developer").unwrap(),
            cookie: format!(
                "{SESSION_COOKIE_NAME}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
                "A".repeat(43)
            ),
        })
    }

    fn authenticate(
        &self,
        _context: &AuthContext<'_>,
        _cookie_header: Option<&str>,
    ) -> Result<Identity, AuthError> {
        Err(AuthError::Missing)
    }
}

fn app() -> axum::Router {
    let target = Target::Pty(PtyTarget {
        name: "shell".into(),
        executable: "/bin/sh".into(),
        argv: Vec::new(),
        read_only: false,
    });
    let auth: Arc<dyn AuthProvider> = Arc::new(DevAuthProvider::new("developer").unwrap());
    build_router(AppState::new(
        OriginPolicy::new(ORIGIN).unwrap(),
        auth,
        TargetAllowlist::new(vec![target]).unwrap(),
        TicketStore::new(std::time::Duration::from_secs(10), 32),
        limits(),
    ))
}

fn trusted_proxy_app() -> axum::Router {
    let target = Target::Pty(PtyTarget {
        name: "shell".into(),
        executable: "/bin/sh".into(),
        argv: Vec::new(),
        read_only: false,
    });
    let auth: Arc<dyn AuthProvider> = Arc::new(
        TrustedProxyAuthProvider::new(
            HeaderName::from_static("x-authenticated-user"),
            vec!["127.0.0.1/32".parse::<IpNet>().unwrap()],
        )
        .unwrap(),
    );
    build_router(AppState::new(
        OriginPolicy::new(ORIGIN).unwrap(),
        auth,
        TargetAllowlist::new(vec![target]).unwrap(),
        TicketStore::new(std::time::Duration::from_secs(10), 32),
        limits(),
    ))
}

async fn response(
    app: &axum::Router,
    method: &str,
    uri: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    body: &str,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn proxy_response(
    app: &axum::Router,
    method: &str,
    uri: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    identities: &[HeaderValue],
    peer: &str,
    forwarded_for: Option<&str>,
    body: &str,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(forwarded_for) = forwarded_for {
        builder = builder.header("x-forwarded-for", forwarded_for);
    }
    for identity in identities {
        builder = builder.header("x-authenticated-user", identity);
    }
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    app.clone().oneshot(request).await.unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn provision_cookie(app: &axum::Router) -> String {
    let response = response(app, "POST", "/api/identity", Some(ORIGIN), None, "").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn healthz_is_deterministic_without_browser_credentials() {
    let app = app();
    let response = response(&app, "GET", "/healthz", None, None, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok\n"
    );
}

#[tokio::test]
async fn static_frontend_is_origin_checked_when_present_and_side_effect_free() {
    let app = app();
    for origin in [Some("https://attacker.test"), Some("not an origin")] {
        assert_eq!(
            response(&app, "GET", "/", origin, None, "").await.status(),
            StatusCode::FORBIDDEN
        );
    }
    let index_response = response(&app, "GET", "/", None, None, "").await;
    assert_eq!(index_response.status(), StatusCode::OK);
    assert!(!index_response.headers().contains_key(header::SET_COOKIE));
    let body = index_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(
        body.windows(b"<!doctype html>".len())
            .any(|window| window == b"<!doctype html>")
    );
    let script = response(&app, "GET", "/app.js", Some(ORIGIN), None, "").await;
    assert_eq!(script.status(), StatusCode::OK);
    assert_eq!(
        script.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    let stylesheet = response(&app, "GET", "/app.css", Some(ORIGIN), None, "").await;
    assert_eq!(stylesheet.status(), StatusCode::OK);
    assert_eq!(
        stylesheet.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
}

#[tokio::test]
async fn identity_establishment_requires_one_allowed_origin() {
    let app = app();
    for origin in [None, Some("https://attacker.test"), Some("not an origin")] {
        assert_eq!(
            response(&app, "POST", "/api/identity", origin, None, "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    let duplicate = Request::builder()
        .method("POST")
        .uri("/api/identity")
        .header(header::ORIGIN, ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn allowed_origin_establishes_secure_development_identity() {
    let app = app();
    let response = response(&app, "POST", "/api/identity", Some(ORIGIN), None, "").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute));
    }
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn valid_development_identity_establishment_is_idempotent() {
    let app = app();
    let cookie = provision_cookie(&app).await;
    let identity_response = response(
        &app,
        "POST",
        "/api/identity",
        Some(ORIGIN),
        Some(&cookie),
        "",
    )
    .await;
    assert_eq!(identity_response.status(), StatusCode::NO_CONTENT);
    assert!(!identity_response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        response(
            &app,
            "POST",
            "/api/sessions",
            Some(ORIGIN),
            Some(&cookie),
            r#"{"target":"shell"}"#,
        )
        .await
        .status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn originless_static_requests_cannot_evict_a_development_identity() {
    let app = app();
    let cookie = provision_cookie(&app).await;
    for _ in 0..1_100 {
        let response = response(&app, "GET", "/", None, None, "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    assert_eq!(
        response(
            &app,
            "POST",
            "/api/sessions",
            Some(ORIGIN),
            Some(&cookie),
            r#"{"target":"shell"}"#,
        )
        .await
        .status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn session_creation_rejects_duplicate_cookie_headers_and_wrong_content_type() {
    let app = app();
    let cookie = provision_cookie(&app).await;
    let duplicate = Request::builder()
        .method("POST")
        .uri("/api/sessions")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"target":"shell"}"#))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let wrong_type = Request::builder()
        .method("POST")
        .uri("/api/sessions")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"target":"shell"}"#))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_type).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[tokio::test]
async fn session_creation_rejects_origin_identity_target_and_bad_bodies_safely() {
    let app = app();
    assert_eq!(
        response(
            &app,
            "POST",
            "/api/sessions",
            None,
            None,
            r#"{"target":"shell"}"#
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response(
            &app,
            "POST",
            "/api/sessions",
            Some(ORIGIN),
            None,
            r#"{"target":"shell"}"#
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let cookie = provision_cookie(&app).await;
    for (body, expected) in [
        ("not json".to_owned(), StatusCode::BAD_REQUEST),
        (r#"{"target":"missing"}"#.to_owned(), StatusCode::NOT_FOUND),
        (
            r#"{"target":"shell","extra":true}"#.to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(r#"{{"target":"{}"}}"#, "x".repeat(20_000)),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = response(
            &app,
            "POST",
            "/api/sessions",
            Some(ORIGIN),
            Some(&cookie),
            &body,
        )
        .await;
        assert_eq!(response.status(), expected);
        let error = json(response).await;
        assert!(error["error"]["code"].as_str().is_some());
        assert!(!error.to_string().contains(&body));
    }
}

#[tokio::test]
async fn target_catalog_exposes_only_configured_presentation_metadata() {
    let app = app();
    let cookie = provision_cookie(&app).await;
    let response = response(
        &app,
        "POST",
        "/api/targets",
        Some(ORIGIN),
        Some(&cookie),
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = json(response).await;
    assert_eq!(
        value,
        serde_json::json!({
            "targets": [
                {
                    "name": "shell",
                    "readOnly": false
                }
            ]
        })
    );
    let serialized = value.to_string();
    for forbidden in [
        "/bin/sh",
        "argv",
        "executable",
        "credential",
        "cookie",
        "identity",
        "known_hosts",
        "host",
        "ticket",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden} leaked");
    }
}

#[tokio::test]
async fn target_catalog_rejects_unauthorized_and_nonempty_requests() {
    let app = app();
    assert_eq!(
        response(&app, "POST", "/api/targets", None, None, "",)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        response(&app, "POST", "/api/targets", Some(ORIGIN), None, "",)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let cookie = provision_cookie(&app).await;
    assert_eq!(
        response(
            &app,
            "POST",
            "/api/targets",
            Some(ORIGIN),
            Some(&cookie),
            r#"{"authority":"browser-controlled"}"#,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn successful_session_creation_returns_only_ticket_bound_presentation_metadata() {
    let app = app();
    let cookie = provision_cookie(&app).await;
    let response = response(
        &app,
        "POST",
        "/api/sessions",
        Some(ORIGIN),
        Some(&cookie),
        r#"{"target":"shell"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let value = json(response).await;
    assert_eq!(
        value.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["target", "ticket"]
    );
    assert_eq!(value["ticket"].as_str().unwrap().len(), 43);
    assert_eq!(
        value["target"],
        serde_json::json!({
            "name": "shell",
            "readOnly": false
        })
    );
    let serialized = value.to_string();
    for forbidden in [
        "/bin/sh",
        "argv",
        "executable",
        "credential",
        "cookie",
        "identity",
        "known_hosts",
        "host",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden} leaked");
    }
}

#[tokio::test]
async fn listener_injects_the_actual_peer_into_authentication_context() {
    let target = Target::Pty(PtyTarget {
        name: "shell".into(),
        executable: "/bin/sh".into(),
        argv: Vec::new(),
        read_only: false,
    });
    let auth = Arc::new(PeerRecordingAuthProvider {
        peer_addr: Mutex::new(None),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(
        listener,
        AppState::new(
            OriginPolicy::new(ORIGIN).unwrap(),
            auth.clone(),
            TargetAllowlist::new(vec![target]).unwrap(),
            TicketStore::new(std::time::Duration::from_secs(10), 32),
            limits(),
        ),
    ));

    let (client_addr, response) = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .write_all(
            format!(
                "POST /api/identity HTTP/1.1\r\nHost: {server_addr}\r\nOrigin: {ORIGIN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        (client_addr, response)
    })
    .await
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204"));
    assert_eq!(*auth.peer_addr.lock().unwrap(), Some(client_addr));
    server.abort();
}

#[tokio::test]
async fn trusted_proxy_auth_failures_return_stable_non_reflecting_errors() {
    let app = trusted_proxy_app();
    let hostile = HeaderValue::from_static("hostile identity sentinel");

    let response = proxy_response(
        &app,
        "POST",
        "/api/identity",
        Some(ORIGIN),
        None,
        &[hostile],
        "127.0.0.1:41000",
        None,
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error = json(response).await;
    assert_eq!(error["error"]["code"], "identity-unavailable");
    assert_eq!(
        error["error"]["message"],
        "Identity is unavailable."
    );
    let rendered = error.to_string();
    for sentinel in ["hostile", "identity sentinel", "127.0.0.1"] {
        assert!(!rendered.contains(sentinel));
    }
}

#[tokio::test]
async fn untrusted_or_malformed_identity_sets_no_cookie_or_ticket() {
    let app = trusted_proxy_app();
    for (peer, identity) in [
        ("127.0.0.2:41001", HeaderValue::from_static("alice")),
        (
            "127.0.0.1:41002",
            HeaderValue::from_static("malformed identity"),
        ),
    ] {
        let response = proxy_response(
            &app,
            "POST",
            "/api/identity",
            Some(ORIGIN),
            None,
            &[identity],
            peer,
            None,
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            proxy_response(
                &app,
                "POST",
                "/api/sessions",
                Some(ORIGIN),
                None,
                &[],
                peer,
                None,
                r#"{"target":"shell"}"#,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn forwarded_headers_cannot_authorize_session_creation() {
    let app = trusted_proxy_app();

    let response = proxy_response(
        &app,
        "POST",
        "/api/identity",
        Some(ORIGIN),
        None,
        &[HeaderValue::from_static("alice")],
        "127.0.0.2:41003",
        Some("127.0.0.1"),
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn wrong_origin_precedes_proxy_identity_establishment() {
    let app = trusted_proxy_app();

    let response = proxy_response(
        &app,
        "POST",
        "/api/identity",
        Some("https://attacker.invalid"),
        None,
        &[HeaderValue::from_static("alice")],
        "127.0.0.1:41004",
        None,
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn secure_cookie_attributes_are_provider_independent() {
    let app = trusted_proxy_app();

    let response = proxy_response(
        &app,
        "POST",
        "/api/identity",
        Some(ORIGIN),
        None,
        &[HeaderValue::from_static("alice")],
        "127.0.0.1:41005",
        None,
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute));
    }
    assert!(!cookie.contains("alice"));
}
