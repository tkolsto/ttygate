use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use ttygated::{
    auth::{AuthProvider, DevAuthProvider},
    config::{PtyTarget, Target, TargetAllowlist},
    origin::OriginPolicy,
    server::{AppState, build_router},
    ticket::TicketStore,
};

const ORIGIN: &str = "https://ttygate.local:7681";

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

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
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
async fn static_frontend_requires_allowed_origin_and_provisions_dev_identity() {
    let app = app();
    for origin in [Some("https://attacker.test"), Some("not an origin")] {
        assert_eq!(
            response(&app, "GET", "/", origin, None, "").await.status(),
            StatusCode::FORBIDDEN
        );
    }
    let index_response = response(&app, "GET", "/", None, None, "").await;
    assert_eq!(index_response.status(), StatusCode::OK);
    assert!(
        index_response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure")
    );
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
async fn session_creation_rejects_duplicate_cookie_headers_and_wrong_content_type() {
    let app = app();
    let provision = response(&app, "GET", "/", None, None, "").await;
    let cookie = provision.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let duplicate = Request::builder()
        .method("POST")
        .uri("/api/sessions")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, cookie)
        .header(header::COOKIE, cookie)
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
        .header(header::COOKIE, cookie)
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

    let provision = response(&app, "GET", "/", Some(ORIGIN), None, "").await;
    let cookie = provision.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
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
async fn successful_session_creation_returns_only_an_opaque_ticket() {
    let app = app();
    let provision = response(&app, "GET", "/", Some(ORIGIN), None, "").await;
    let cookie = provision.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
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
        vec!["ticket"]
    );
    assert_eq!(value["ticket"].as_str().unwrap().len(), 43);
}
