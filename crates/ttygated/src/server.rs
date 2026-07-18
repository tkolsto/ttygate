use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::{
    auth::{AuthContext, AuthProvider, DevAuthProvider, TrustedProxyAuthProvider},
    config::{AuthConfig, Config, Limits, ServerTransport, TargetAllowlist},
    origin::OriginPolicy,
    protocol::MAX_BINARY_BYTES,
    rate_limit::{Attempt, FixedWindowLimiter, LimitError},
    session::SessionManager,
    ticket::{TicketError, TicketStore},
    websocket,
};

const MAX_SESSION_BODY: usize = 1024;
const TICKET_TTL: Duration = Duration::from_secs(10);
const TICKET_CAPACITY: usize = 1024;
const LIMITER_KEY_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerKey {
    Address(IpAddr),
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthHttpError {
    Required,
    Limited(Duration),
}

#[derive(Clone)]
pub struct AppState {
    origin: Arc<OriginPolicy>,
    auth: Arc<dyn AuthProvider>,
    targets: Arc<TargetAllowlist>,
    tickets: Arc<TicketStore>,
    sessions: Arc<SessionManager>,
    authentication_failures: Arc<FixedWindowLimiter<PeerKey>>,
    session_requests: Arc<FixedWindowLimiter<crate::ticket::Identity>>,
}

impl AppState {
    pub fn new(
        origin: OriginPolicy,
        auth: Arc<dyn AuthProvider>,
        targets: TargetAllowlist,
        tickets: TicketStore,
        limits: Limits,
    ) -> Self {
        let authentication_failures = Arc::new(FixedWindowLimiter::new(
            limits.authentication_failures_per_window,
            limits.authentication_failure_window,
            LIMITER_KEY_CAPACITY,
        ));
        let session_requests = Arc::new(FixedWindowLimiter::new(
            limits.session_requests_per_window,
            limits.session_request_window,
            LIMITER_KEY_CAPACITY,
        ));
        let sessions = SessionManager::new(limits, targets.clone());
        Self {
            origin: Arc::new(origin),
            auth,
            targets: Arc::new(targets),
            tickets: Arc::new(tickets),
            sessions: Arc::new(sessions),
            authentication_failures,
            session_requests,
        }
    }

    pub fn from_config(config: &Config) -> Result<Self, ServerBuildError> {
        let origin =
            OriginPolicy::new(&config.server.public_url).map_err(|_| ServerBuildError::Origin)?;
        let auth = match &config.auth {
            AuthConfig::Dev { user } => Arc::new(
                DevAuthProvider::new(user.clone()).map_err(|_| ServerBuildError::Identity)?,
            ) as Arc<dyn AuthProvider>,
            AuthConfig::TrustedProxy { identity_header } => {
                let ServerTransport::TrustedProxy(proxy) = &config.server.transport else {
                    return Err(ServerBuildError::Authentication);
                };
                Arc::new(
                    TrustedProxyAuthProvider::new(
                        identity_header.clone(),
                        proxy.trusted_sources.clone(),
                    )
                    .map_err(|_| ServerBuildError::Authentication)?,
                ) as Arc<dyn AuthProvider>
            }
        };
        let targets =
            TargetAllowlist::new(config.targets.clone()).map_err(|_| ServerBuildError::Targets)?;
        Ok(Self::new(
            origin,
            auth,
            targets,
            TicketStore::new(TICKET_TTL, TICKET_CAPACITY),
            config.limits.clone(),
        ))
    }

    pub fn tickets(&self) -> Arc<TicketStore> {
        Arc::clone(&self.tickets)
    }

    pub fn sessions(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ServerBuildError {
    #[error("server public URL does not define a valid allowed origin")]
    Origin,
    #[error("development identity is invalid")]
    Identity,
    #[error("configured target allowlist is invalid")]
    Targets,
    #[error("configured authentication provider could not be constructed")]
    Authentication,
}

pub fn build_router(state: AppState) -> Router {
    let static_routes = Router::new()
        .route("/", get(frontend))
        .route("/app.js", get(frontend_script))
        .route("/app.css", get(frontend_stylesheet))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state.origin),
            enforce_origin_if_present,
        ));
    let authority_api = Router::new()
        .route("/api/identity", post(establish_identity))
        .route("/api/targets", post(list_targets))
        .route("/api/sessions", post(create_session))
        .route("/api/ws", get(upgrade_websocket))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state.origin),
            enforce_origin,
        ));
    Router::new()
        .route("/healthz", get(|| async { (StatusCode::OK, "ok\n") }))
        .merge(static_routes)
        .merge(authority_api)
        .with_state(state)
}

async fn upgrade_websocket(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    request: Request,
) -> Response {
    if request.uri().query().is_some()
        || request
            .headers()
            .contains_key(header::SEC_WEBSOCKET_PROTOCOL)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid-websocket-request",
            "The WebSocket request is invalid.",
        );
    }
    let context = auth_context(&request);
    let identity =
        match authenticate_limited(&state, &context, single_cookie_header(request.headers())) {
            Ok(identity) => identity,
            Err(error) => return auth_error_response(error),
        };
    let tickets = Arc::clone(&state.tickets);
    let sessions = Arc::clone(&state.sessions);
    ws.max_message_size(MAX_BINARY_BYTES)
        .max_frame_size(MAX_BINARY_BYTES)
        .on_upgrade(move |socket| websocket::accept_upgrade(socket, identity, tickets, sessions))
}

async fn enforce_origin_if_present(
    State(policy): State<Arc<OriginPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    if request
        .headers()
        .get_all(header::ORIGIN)
        .iter()
        .next()
        .is_none()
    {
        return next.run(request).await;
    }
    enforce_origin(State(policy), request, next).await
}

async fn frontend_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../frontend/dist/app.js"),
    )
}

async fn frontend_stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../frontend/dist/app.css"),
    )
}

pub async fn serve(listener: TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

pub async fn serve_tls_on(
    listener: std::net::TcpListener,
    state: AppState,
    tls: axum_server::tls_rustls::RustlsConfig,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    axum_server::from_tcp_rustls(listener, tls)?
        .serve(build_router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
}

async fn enforce_origin(
    State(policy): State<Arc<OriginPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let values: Vec<&[u8]> = request
        .headers()
        .get_all(header::ORIGIN)
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    if policy.validate_header_values(&values).is_err() {
        return api_error(
            StatusCode::FORBIDDEN,
            "origin-denied",
            "The request origin is not allowed.",
        );
    }
    next.run(request).await
}

async fn frontend() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../frontend/src/index.html"),
    )
}

async fn establish_identity(State(state): State<AppState>, request: Request) -> Response {
    let context = auth_context(&request);
    let attempt = match begin_authentication_attempt(&state, &context) {
        Ok(attempt) => attempt,
        Err(error) => return auth_error_response(error),
    };
    match single_cookie_header(request.headers()) {
        Ok(cookie) if state.auth.authenticate(&context, cookie).is_ok() => {
            attempt.rollback();
            return StatusCode::NO_CONTENT.into_response();
        }
        Ok(_) => {}
        Err(()) => {
            attempt.commit();
            return api_error(
                StatusCode::UNAUTHORIZED,
                "identity-required",
                "A valid identity session is required.",
            );
        }
    }
    let provisioned = match state.auth.establish(&context) {
        Ok(provisioned) => {
            attempt.rollback();
            provisioned
        }
        Err(_) => {
            attempt.commit();
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity-unavailable",
                "Identity is unavailable.",
            );
        }
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    let Ok(cookie) = provisioned.cookie.parse() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "The request could not be completed.",
        );
    };
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSession {
    target: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetPresentation {
    name: String,
    read_only: bool,
}

impl From<&crate::config::Target> for TargetPresentation {
    fn from(target: &crate::config::Target) -> Self {
        Self {
            name: target.name().to_owned(),
            read_only: target.read_only(),
        }
    }
}

#[derive(Serialize)]
struct TargetCatalog {
    targets: Vec<TargetPresentation>,
}

async fn list_targets(State(state): State<AppState>, request: Request) -> Response {
    let context = auth_context(&request);
    if let Err(error) =
        authenticate_limited(&state, &context, single_cookie_header(request.headers()))
    {
        return auth_error_response(error);
    }
    if to_bytes(request.into_body(), 0).await.is_err() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "The request body must be empty.",
        );
    }
    axum::Json(TargetCatalog {
        targets: state.targets.iter().map(TargetPresentation::from).collect(),
    })
    .into_response()
}

#[derive(Serialize)]
struct TicketResponse<'a> {
    ticket: &'a str,
    target: TargetPresentation,
}

async fn create_session(State(state): State<AppState>, request: Request) -> Response {
    let context = auth_context(&request);
    let identity =
        match authenticate_limited(&state, &context, single_cookie_header(request.headers())) {
            Ok(identity) => identity,
            Err(error) => return auth_error_response(error),
        };
    let session_request = match state.session_requests.begin(identity.clone()) {
        Ok(attempt) => attempt,
        Err(LimitError::Exhausted { retry_after }) => {
            return rate_error(
                "session-rate-limited",
                "Session requests are temporarily limited.",
                retry_after,
            );
        }
    };
    session_request.commit();
    let is_json = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "The request body must be JSON.",
        );
    }
    let body = match to_bytes(request.into_body(), MAX_SESSION_BODY).await {
        Ok(body) => body,
        Err(_) => {
            return api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request-too-large",
                "The request body is too large.",
            );
        }
    };
    let payload: CreateSession = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "The request body is invalid.",
            );
        }
    };
    if payload.target.len() > 128 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "The request body is invalid.",
        );
    }
    let target = match state.targets.resolve(&payload.target) {
        Ok(target) => target.clone(),
        Err(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "target-not-found",
                "The requested target is not available.",
            );
        }
    };
    let presentation = TargetPresentation::from(&target);
    match state.tickets.issue(identity, target) {
        Ok(ticket) => (
            StatusCode::CREATED,
            axum::Json(TicketResponse {
                ticket: ticket.as_str(),
                target: presentation,
            }),
        )
            .into_response(),
        Err(TicketError::AtCapacity) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ticket-capacity",
            "Session authorization is temporarily unavailable.",
        ),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "The request could not be completed.",
        ),
    }
}

fn auth_context(request: &Request) -> AuthContext<'_> {
    let peer_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    AuthContext::new(request.headers(), peer_addr)
}

fn begin_authentication_attempt(
    state: &AppState,
    context: &AuthContext<'_>,
) -> Result<Attempt<PeerKey>, AuthHttpError> {
    let key = context
        .peer_addr()
        .map(|address| PeerKey::Address(address.ip()))
        .unwrap_or(PeerKey::Missing);
    state
        .authentication_failures
        .begin(key)
        .map_err(|LimitError::Exhausted { retry_after }| AuthHttpError::Limited(retry_after))
}

fn authenticate_limited(
    state: &AppState,
    context: &AuthContext<'_>,
    cookie: Result<Option<&str>, ()>,
) -> Result<crate::ticket::Identity, AuthHttpError> {
    let attempt = begin_authentication_attempt(state, context)?;
    let cookie = match cookie {
        Ok(cookie) => cookie,
        Err(()) => {
            attempt.commit();
            return Err(AuthHttpError::Required);
        }
    };
    match state.auth.authenticate(context, cookie) {
        Ok(identity) => {
            attempt.rollback();
            Ok(identity)
        }
        Err(_) => {
            attempt.commit();
            Err(AuthHttpError::Required)
        }
    }
}

fn auth_error_response(error: AuthHttpError) -> Response {
    match error {
        AuthHttpError::Required => api_error(
            StatusCode::UNAUTHORIZED,
            "identity-required",
            "A valid identity session is required.",
        ),
        AuthHttpError::Limited(retry_after) => rate_error(
            "authentication-rate-limited",
            "Authentication is temporarily limited.",
            retry_after,
        ),
    }
}

fn rate_error(code: &'static str, message: &'static str, retry_after: Duration) -> Response {
    let seconds = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() > 0))
        .max(1);
    let mut response = api_error(StatusCode::TOO_MANY_REQUESTS, code, message);
    response.headers_mut().insert(
        header::RETRY_AFTER,
        seconds
            .to_string()
            .parse()
            .expect("integer retry-after is a valid header value"),
    );
    response
}

fn single_cookie_header(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(header::COOKIE).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        axum::Json(ErrorEnvelope {
            error: ErrorBody { code, message },
        }),
    )
        .into_response()
}
