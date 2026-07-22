#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic))]
#![recursion_limit = "256"]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use smcv_app::{
    AuthenticatedOwner, AuthorizedVaultError, BrowserSessionSecrets, IdempotencyInput,
    InitializedVault, LocalSetupCapability, MetadataInput, PasskeyService, PolicyMetadata,
    RequestPrincipal, ServiceIdentityMetadata, initialize_vault,
};
use smcv_core::{
    Action, CeremonyId, GrantSpec, NamespaceId, ObjectId, PolicyId, PrincipalId, ProtectedBytes,
    ProtectedString, RequestId, ResourceKind, SecretId, SecretSchedule,
};
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

mod backup_jobs;
pub mod operations;
mod web;

const SESSION_COOKIE: &str = "__Host-smcv_session";
const REQUEST_BODY_LIMIT: usize = 1024 * 1024;
const ARCHIVE_UPLOAD_BODY_LIMIT: usize = 8 * 1024 * 1024 * 1024;
const LOGIN_WINDOW_MS: i64 = 60_000;
const LOGIN_ATTEMPTS_PER_WINDOW: u16 = 10;
const PASSKEY_ATTEMPTS_PER_WINDOW: u16 = 20;
const BEARER_ATTEMPTS_PER_WINDOW: u16 = 120;
const MAX_LOGIN_SOURCES: usize = 4_096;

#[derive(Clone, Copy)]
struct LoginWindow {
    started_at_unix_ms: i64,
    attempts: u16,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum AuthenticationRateKey {
    Peer(IpAddr),
    ApplicationCredential([u8; 12]),
}

impl From<IpAddr> for AuthenticationRateKey {
    fn from(value: IpAddr) -> Self {
        Self::Peer(value)
    }
}

#[derive(Default)]
struct LoginRateLimiter {
    sources: Mutex<HashMap<AuthenticationRateKey, LoginWindow>>,
}

impl LoginRateLimiter {
    fn allow(
        &self,
        source: impl Into<AuthenticationRateKey>,
        now_unix_ms: i64,
        limit: u16,
    ) -> bool {
        let source = source.into();
        let Ok(mut sources) = self.sources.lock() else {
            return false;
        };
        sources.retain(|_, window| {
            now_unix_ms.saturating_sub(window.started_at_unix_ms) < LOGIN_WINDOW_MS
        });
        if let Some(window) = sources.get_mut(&source) {
            if now_unix_ms.saturating_sub(window.started_at_unix_ms) >= LOGIN_WINDOW_MS {
                *window = LoginWindow {
                    started_at_unix_ms: now_unix_ms,
                    attempts: 1,
                };
                return true;
            }
            if window.attempts >= limit {
                return false;
            }
            window.attempts = window.attempts.saturating_add(1);
            return true;
        }
        if sources.len() >= MAX_LOGIN_SOURCES {
            return false;
        }
        sources.insert(
            source,
            LoginWindow {
                started_at_unix_ms: now_unix_ms,
                attempts: 1,
            },
        );
        true
    }
}

/// Shared HTTP adapter state with bounded expensive-authentication work.
#[derive(Clone)]
pub struct ApiState {
    vault: Arc<InitializedVault>,
    passkeys: Arc<PasskeyService>,
    password_slots: Arc<Semaphore>,
    login_rate_limiter: Arc<LoginRateLimiter>,
    passkey_rate_limiter: Arc<LoginRateLimiter>,
    bearer_rate_limiter: Arc<LoginRateLimiter>,
    backup_jobs: Arc<backup_jobs::BackupJobRegistry>,
    metrics: Arc<OperationalMetrics>,
}

#[derive(Default)]
struct OperationalMetrics {
    requests: AtomicU64,
    responses_success: AtomicU64,
    responses_client_error: AtomicU64,
    responses_server_error: AtomicU64,
    timeouts: AtomicU64,
    rate_limited: AtomicU64,
    readiness_checks: AtomicU64,
    readiness_failures: AtomicU64,
}

impl ApiState {
    /// Opens one initialized vault and pins passkeys to the configured origin.
    ///
    /// # Errors
    ///
    /// Returns a safe string when local custody, vault initialization, or
    /// relying-party configuration cannot be validated.
    pub fn open(
        database_path: &Path,
        root_key_path: &Path,
        rp_id: &str,
        origin: &str,
    ) -> Result<Self, String> {
        let vault = initialize_vault(database_path, root_key_path, now_unix_ms())
            .map_err(|error| error.to_string())?;
        let passkeys = PasskeyService::new(rp_id, origin).map_err(|error| error.to_string())?;
        let backup_directory = database_path
            .parent()
            .ok_or_else(|| "backup artifact directory is invalid".to_owned())?
            .join("backup-artifacts");
        let backup_jobs = backup_jobs::BackupJobRegistry::open(&backup_directory)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            vault: Arc::new(vault),
            passkeys: Arc::new(passkeys),
            password_slots: Arc::new(Semaphore::new(4)),
            login_rate_limiter: Arc::new(LoginRateLimiter::default()),
            passkey_rate_limiter: Arc::new(LoginRateLimiter::default()),
            bearer_rate_limiter: Arc::new(LoginRateLimiter::default()),
            backup_jobs: Arc::new(backup_jobs),
            metrics: Arc::new(OperationalMetrics::default()),
        })
    }

    /// Returns the vault for local integration tests and process diagnostics.
    #[must_use]
    pub fn vault(&self) -> &InitializedVault {
        &self.vault
    }
}

/// Builds the bounded same-origin `/api/v1` router.
#[allow(
    clippy::too_many_lines,
    reason = "the closed versioned route catalog remains explicit in one composition root"
)]
pub fn router(state: ApiState) -> Router {
    let request_id_header = axum::http::HeaderName::from_static("x-request-id");
    Router::new()
        .route("/", get(web::index))
        .route("/assets/styles.css", get(web::styles))
        .route("/assets/app.js", get(web::app))
        .route("/assets/api.js", get(web::api))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/session/password", post(password_login))
        .route("/api/v1/session", get(session_status).delete(logout))
        .route(
            "/api/v1/session/passkeys/registration/options",
            post(start_passkey_registration),
        )
        .route(
            "/api/v1/session/passkeys/registration/verify",
            post(finish_passkey_registration),
        )
        .route(
            "/api/v1/session/passkeys/authentication/options",
            post(start_passkey_authentication),
        )
        .route(
            "/api/v1/session/passkeys/authentication/verify",
            post(finish_passkey_authentication),
        )
        .route(
            "/api/v1/namespaces",
            get(list_namespaces).post(create_namespace),
        )
        .route(
            "/api/v1/namespaces/{id}/move-impact",
            post(preview_namespace_move),
        )
        .route("/api/v1/namespaces/{id}/move", post(move_namespace))
        .route("/api/v1/secrets", get(list_secrets).post(create_secret))
        .route(
            "/api/v1/secrets/{id}",
            get(read_secret_metadata).put(update_secret),
        )
        .route("/api/v1/secrets/{id}/value", get(reveal_secret))
        .route("/api/v1/secrets/{id}/versions", get(secret_versions))
        .route(
            "/api/v1/secrets/{id}/versions/{version}/value",
            get(reveal_secret_version),
        )
        .route("/api/v1/secrets/{id}/archive", post(archive_secret))
        .route("/api/v1/secrets/{id}/restore", post(restore_secret))
        .route("/api/v1/secrets/lifecycle", get(list_secret_lifecycle))
        .route("/api/v1/secrets/{id}/delete", post(delete_secret))
        .route("/api/v1/secrets/{id}/purge", post(purge_secret))
        .route(
            "/api/v1/service-identities",
            get(list_service_identities).post(create_service_identity),
        )
        .route(
            "/api/v1/service-identities/{id}",
            get(read_service_identity),
        )
        .route(
            "/api/v1/service-identities/{id}/effective-access",
            get(effective_access),
        )
        .route(
            "/api/v1/service-identities/{id}/credentials",
            get(list_credentials).post(issue_credential),
        )
        .route(
            "/api/v1/service-identities/{id}/credentials/{credential_id}/revoke",
            post(revoke_credential),
        )
        .route("/api/v1/policies", get(list_policies).post(create_policy))
        .route("/api/v1/policies/{id}", get(read_policy))
        .route("/api/v1/policies/{id}/rules", get(policy_rules))
        .route("/api/v1/policies/{id}/archive", post(archive_policy))
        .route("/api/v1/policies/{id}/grants", post(add_grant))
        .route("/api/v1/policies/{id}/bindings", post(bind_policy))
        .route("/api/v1/audit-events", get(audit_events))
        .route(
            "/api/v1/backups",
            get(backup_jobs::list_backups).post(backup_jobs::create_backup),
        )
        .route(
            "/api/v1/backups/{id}",
            get(backup_jobs::backup_status).delete(backup_jobs::delete_backup),
        )
        .route(
            "/api/v1/backups/{id}/download",
            get(backup_jobs::download_backup),
        )
        .route(
            "/api/v1/backup-verifications",
            post(backup_jobs::verify_uploaded_backup)
                .layer(DefaultBodyLimit::max(ARCHIVE_UPLOAD_BODY_LIMIT)),
        )
        .route("/api/v1/openapi.json", get(openapi))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            record_operational_metrics,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_request_timeout,
        ))
        .layer(ConcurrencyLimitLayer::new(128))
        .layer(middleware::from_fn(enforce_header_limits))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_bearer_rate_limit,
        ))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<axum::body::Body>| {
                let route = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map_or("unmatched", MatchedPath::as_str);
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    route = route
                )
            }),
        )
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .with_state(state)
}

/// Builds the optional loopback-only operational telemetry router.
pub fn operational_router(state: ApiState) -> Router {
    Router::new()
        .route("/metrics", get(operations::metrics))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .layer(middleware::from_fn(enforce_header_limits))
        .with_state(state)
}

async fn record_operational_metrics(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    match response.status().as_u16() / 100 {
        2 | 3 => &state.metrics.responses_success,
        4 => &state.metrics.responses_client_error,
        _ => &state.metrics.responses_server_error,
    }
    .fetch_add(1, Ordering::Relaxed);
    response
}

async fn enforce_request_timeout(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let duration = if request.uri().path() == "/api/v1/backup-verifications" {
        Duration::from_secs(15 * 60)
    } else {
        Duration::from_secs(15)
    };
    if let Ok(response) = tokio::time::timeout(duration, next.run(request)).await {
        response
    } else {
        state.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
        StatusCode::REQUEST_TIMEOUT.into_response()
    }
}

async fn enforce_bearer_rate_limit(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer "))
    {
        let source = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |peer| peer.0.ip());
        let rate_key = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .and_then(|token| state.vault.known_application_credential_lookup(token))
            .map_or(AuthenticationRateKey::Peer(source), |lookup| {
                AuthenticationRateKey::ApplicationCredential(lookup)
            });
        if !state
            .bearer_rate_limiter
            .allow(rate_key, now_unix_ms(), BEARER_ATTEMPTS_PER_WINDOW)
        {
            state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return ApiError::rate_limited(request_id(request.headers())).into_response();
        }
    }
    next.run(request).await
}

async fn enforce_header_limits(request: Request<axum::body::Body>, next: Next) -> Response {
    let headers = request.headers();
    let total = headers.iter().fold(0_usize, |sum, (name, value)| {
        sum.saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    });
    if headers.len() > 64 || total > 32 * 1024 {
        return ApiError::invalid(request_id(headers)).into_response();
    }
    let mut response = next.run(request).await;
    apply_security_headers(response.headers_mut());
    response
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
}

async fn live() -> Json<StatusResponse> {
    Json(StatusResponse { status: "ok" })
}

async fn ready(State(state): State<ApiState>) -> Result<Json<StatusResponse>, ApiError> {
    state
        .metrics
        .readiness_checks
        .fetch_add(1, Ordering::Relaxed);
    if state.vault.store.quick_integrity_check().unwrap_or(false) {
        Ok(Json(StatusResponse { status: "ready" }))
    } else {
        state
            .metrics
            .readiness_failures
            .fetch_add(1, Ordering::Relaxed);
        Err(ApiError::unavailable(RequestId::random()))
    }
}

#[derive(Deserialize)]
struct PasswordLoginRequest {
    password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    csrf_token: String,
    absolute_expires_at_unix_ms: i64,
}

async fn password_login(
    State(state): State<ApiState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasswordLoginRequest>,
) -> Result<Response, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let source = peer.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |peer| peer.0.0.ip());
    if !state
        .login_rate_limiter
        .allow(source, now, LOGIN_ATTEMPTS_PER_WINDOW)
    {
        state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::rate_limited(request_id));
    }
    let permit = Arc::clone(&state.password_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::rate_limited(request_id))?;
    let vault = Arc::clone(&state.vault);
    let password = ProtectedString::new(input.password);
    let issued = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        vault.login_with_password(&password, request_id, now)
    })
    .await
    .map_err(|_| ApiError::unavailable(request_id))?
    .map_err(|_| ApiError::authentication(request_id))?;
    Ok(session_response(issued))
}

#[derive(Serialize)]
struct SessionStatusResponse {
    authenticated: bool,
    recent: bool,
}

async fn session_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<SessionStatusResponse>, ApiError> {
    let now = now_unix_ms();
    let owner = authenticate_owner(&state, &headers, false, now)?;
    Ok(Json(SessionStatusResponse {
        authenticated: true,
        recent: owner.is_recent_at(now),
    }))
}

async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    if headers
        .get("x-smcv-session-lock")
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return Err(ApiError::authentication(request_id));
    }
    let owner = authenticate_owner(&state, &headers, false, now)?;
    state
        .vault
        .logout_browser_session(owner, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-smcv_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    apply_security_headers(response.headers_mut());
    Ok(response)
}

#[derive(Serialize)]
struct ChallengeResponse {
    ceremony_id: String,
    expires_at_unix_ms: i64,
    options: serde_json::Value,
}

async fn start_passkey_registration(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let challenge = state
        .passkeys
        .start_registration(&state.vault, owner, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?;
    Ok(Json(ChallengeResponse {
        ceremony_id: challenge.ceremony_id.to_string(),
        expires_at_unix_ms: challenge.expires_at_unix_ms,
        options: serde_json::to_value(challenge.options)
            .map_err(|_| ApiError::unavailable(request_id))?,
    }))
}

#[derive(Deserialize)]
struct FinishRegistrationRequest {
    ceremony_id: String,
    response: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct IdResponse {
    id: String,
}

async fn finish_passkey_registration(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<FinishRegistrationRequest>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let id = state
        .passkeys
        .finish_registration(
            &state.vault,
            owner,
            ceremony_id(&input.ceremony_id).ok_or_else(|| ApiError::invalid(request_id))?,
            &input.response,
            request_id,
            now,
        )
        .map_err(|_| ApiError::authentication(request_id))?;
    Ok((StatusCode::CREATED, Json(IdResponse { id: id.to_string() })))
}

async fn start_passkey_authentication(
    State(state): State<ApiState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let source = peer.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |peer| peer.0.0.ip());
    if !state
        .passkey_rate_limiter
        .allow(source, now, PASSKEY_ATTEMPTS_PER_WINDOW)
    {
        state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::rate_limited(request_id));
    }
    let challenge = state
        .passkeys
        .start_authentication(&state.vault, now)
        .map_err(|_| ApiError::authentication(request_id))?;
    Ok(Json(ChallengeResponse {
        ceremony_id: challenge.ceremony_id.to_string(),
        expires_at_unix_ms: challenge.expires_at_unix_ms,
        options: serde_json::to_value(challenge.options)
            .map_err(|_| ApiError::unavailable(request_id))?,
    }))
}

#[derive(Deserialize)]
struct FinishAuthenticationRequest {
    ceremony_id: String,
    response: PublicKeyCredential,
}

async fn finish_passkey_authentication(
    State(state): State<ApiState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<FinishAuthenticationRequest>,
) -> Result<Response, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let source = peer.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |peer| peer.0.0.ip());
    if !state
        .passkey_rate_limiter
        .allow(source, now, PASSKEY_ATTEMPTS_PER_WINDOW)
    {
        state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::rate_limited(request_id));
    }
    let issued = state
        .passkeys
        .finish_authentication(
            &state.vault,
            ceremony_id(&input.ceremony_id).ok_or_else(|| ApiError::invalid(request_id))?,
            &input.response,
            request_id,
            now,
        )
        .map_err(|_| ApiError::authentication(request_id))?;
    Ok(session_response(issued))
}

#[derive(Deserialize, Serialize)]
struct MetadataRequest {
    name: String,
    description: Option<String>,
    username: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl MetadataRequest {
    fn protect(self) -> MetadataInput {
        MetadataInput {
            name: ProtectedString::new(self.name),
            description: self.description.map(ProtectedString::new),
            username: self.username.map(ProtectedString::new),
            tags: self.tags.into_iter().map(ProtectedString::new).collect(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct CreateNamespaceRequest {
    parent_namespace_id: Option<String>,
    metadata: MetadataRequest,
}

#[derive(Deserialize)]
struct NamespacePageQuery {
    parent_namespace_id: Option<String>,
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

#[derive(Serialize)]
struct NamespaceListEntryResponse {
    id: String,
    metadata: MetadataResponse,
    revision: u64,
}

#[derive(Serialize)]
struct NamespacePageResponse {
    namespaces: Vec<NamespaceListEntryResponse>,
    next_after: Option<String>,
}

async fn list_namespaces(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<NamespacePageQuery>,
) -> Result<Json<NamespacePageResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let records = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .list_namespaces(
            query
                .parent_namespace_id
                .as_deref()
                .map(namespace_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query
                .after
                .as_deref()
                .map(namespace_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.namespace_id.to_string()))
        .flatten();
    Ok(Json(NamespacePageResponse {
        namespaces: records
            .into_iter()
            .map(|record| NamespaceListEntryResponse {
                id: record.namespace_id.to_string(),
                metadata: metadata_response(&record.metadata),
                revision: record.revision,
            })
            .collect(),
        next_after,
    }))
}

async fn create_namespace(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let canonical = serde_json::to_vec(&input).map_err(|_| ApiError::invalid(request_id))?;
    let idempotency = idempotency_input(&headers, canonical, request_id)?;
    let parent = input
        .parent_namespace_id
        .as_deref()
        .map(namespace_id)
        .transpose()
        .map_err(|()| ApiError::invalid(request_id))?;
    let id = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .create_namespace_idempotent(parent, &input.metadata.protect(), &idempotency)
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok((StatusCode::CREATED, Json(IdResponse { id: id.to_string() })))
}

#[derive(Deserialize)]
struct MovePreviewRequest {
    new_parent_namespace_id: Option<String>,
}

#[derive(Serialize)]
struct AccessDeltaResponse {
    service_principal_id: String,
    action: &'static str,
}

async fn preview_namespace_move(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<MovePreviewRequest>,
) -> Result<Json<Vec<AccessDeltaResponse>>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let new_parent = input
        .new_parent_namespace_id
        .as_deref()
        .map(namespace_id)
        .transpose()
        .map_err(|()| ApiError::invalid(request_id))?;
    let delta = state
        .vault
        .preview_namespace_move(
            owner,
            namespace_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            new_parent,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(
        delta
            .into_iter()
            .map(|item| AccessDeltaResponse {
                service_principal_id: item.principal_id.to_string(),
                action: item.action.as_str(),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct ConfirmedDeltaRequest {
    service_principal_id: String,
    action: String,
}

#[derive(Deserialize)]
struct MoveNamespaceRequest {
    expected_revision: u64,
    new_parent_namespace_id: Option<String>,
    confirmed_delta: Vec<ConfirmedDeltaRequest>,
}

#[derive(Serialize)]
struct RevisionResponse {
    revision: u64,
}

async fn move_namespace(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<MoveNamespaceRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    use core::str::FromStr as _;

    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let new_parent = input
        .new_parent_namespace_id
        .as_deref()
        .map(namespace_id)
        .transpose()
        .map_err(|()| ApiError::invalid(request_id))?;
    let confirmed = input
        .confirmed_delta
        .into_iter()
        .map(|item| {
            Ok(smcv_app::EffectiveAccessDelta {
                principal_id: principal_id(&item.service_principal_id)?,
                action: Action::from_str(&item.action)?,
            })
        })
        .collect::<Result<Vec<_>, ()>>()
        .map_err(|()| ApiError::invalid(request_id))?;
    let revision = state
        .vault
        .move_namespace(
            owner,
            namespace_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
            new_parent,
            &confirmed,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

#[derive(Deserialize, Serialize)]
struct CreateSecretRequest {
    namespace_id: String,
    metadata: MetadataRequest,
    value_base64: String,
    expires_at_unix_ms: Option<i64>,
    rotation_due_at_unix_ms: Option<i64>,
}

#[derive(Deserialize)]
struct SecretPageQuery {
    namespace_id: String,
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

#[derive(Serialize)]
struct SecretListEntryResponse {
    id: String,
    metadata: MetadataResponse,
    current_version: u64,
    revision: u64,
    lifecycle_state: String,
    deleted_at_unix_ms: Option<i64>,
}

#[derive(Serialize)]
struct SecretPageResponse {
    secrets: Vec<SecretListEntryResponse>,
    next_after: Option<String>,
}

async fn list_secrets(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SecretPageQuery>,
) -> Result<Json<SecretPageResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let records = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .list_secrets(
            namespace_id(&query.namespace_id).map_err(|()| ApiError::invalid(request_id))?,
            query
                .after
                .as_deref()
                .map(secret_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.secret_id.to_string()))
        .flatten();
    Ok(Json(SecretPageResponse {
        secrets: records
            .into_iter()
            .map(|record| SecretListEntryResponse {
                id: record.secret_id.to_string(),
                metadata: metadata_response(&record.metadata),
                current_version: record.current_version,
                revision: record.revision,
                lifecycle_state: record.lifecycle_state,
                deleted_at_unix_ms: record.deleted_at_unix_ms,
            })
            .collect(),
        next_after,
    }))
}

#[derive(Deserialize)]
struct SecretLifecyclePageQuery {
    namespace_id: String,
    state: String,
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

async fn list_secret_lifecycle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SecretLifecyclePageQuery>,
) -> Result<Json<SecretPageResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let records = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .list_secrets_in_lifecycle(
            namespace_id(&query.namespace_id).map_err(|()| ApiError::invalid(request_id))?,
            &query.state,
            query
                .after
                .as_deref()
                .map(secret_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.secret_id.to_string()))
        .flatten();
    Ok(Json(SecretPageResponse {
        secrets: records
            .into_iter()
            .map(|record| SecretListEntryResponse {
                id: record.secret_id.to_string(),
                metadata: metadata_response(&record.metadata),
                current_version: record.current_version,
                revision: record.revision,
                lifecycle_state: record.lifecycle_state,
                deleted_at_unix_ms: record.deleted_at_unix_ms,
            })
            .collect(),
        next_after,
    }))
}

#[derive(Serialize)]
struct SecretCreatedResponse {
    id: String,
    version: u64,
    revision: u64,
}

async fn create_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<SecretCreatedResponse>), ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let canonical = serde_json::to_vec(&input).map_err(|_| ApiError::invalid(request_id))?;
    let idempotency = idempotency_input(&headers, canonical, request_id)?;
    let namespace =
        namespace_id(&input.namespace_id).map_err(|()| ApiError::invalid(request_id))?;
    let value = STANDARD
        .decode(input.value_base64)
        .map_err(|_| ApiError::invalid(request_id))?;
    let created = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .create_secret_idempotent(
            namespace,
            &input.metadata.protect(),
            ProtectedBytes::new(value),
            SecretSchedule {
                expires_at_unix_ms: input.expires_at_unix_ms,
                rotation_due_at_unix_ms: input.rotation_due_at_unix_ms,
            },
            &idempotency,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok((
        StatusCode::CREATED,
        Json(SecretCreatedResponse {
            id: created.secret_id.to_string(),
            version: created.version,
            revision: created.revision,
        }),
    ))
}

#[derive(Deserialize)]
struct UpdateSecretRequest {
    expected_current_version: u64,
    expected_revision: u64,
    value_base64: String,
    expires_at_unix_ms: Option<i64>,
    rotation_due_at_unix_ms: Option<i64>,
}

#[derive(Serialize)]
struct VersionResponse {
    version: u64,
}

async fn update_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<UpdateSecretRequest>,
) -> Result<Json<VersionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let value = STANDARD
        .decode(input.value_base64)
        .map_err(|_| ApiError::invalid(request_id))?;
    let version = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .update_secret(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_current_version,
            input.expected_revision,
            ProtectedBytes::new(value),
            SecretSchedule {
                expires_at_unix_ms: input.expires_at_unix_ms,
                rotation_due_at_unix_ms: input.rotation_due_at_unix_ms,
            },
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(VersionResponse { version }))
}

#[derive(Deserialize)]
struct LifecycleRequest {
    expected_revision: u64,
}

async fn archive_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<LifecycleRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let revision = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .archive_secret(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

async fn restore_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<LifecycleRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let revision = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .restore_archived_secret(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

async fn delete_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<LifecycleRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let principal = authenticate_principal(&state, &headers, true, now)?;
    let revision = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .delete_secret(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

#[derive(Deserialize)]
struct PurgeSecretRequest {
    expected_revision: u64,
    retention_cutoff_unix_ms: i64,
}

async fn purge_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<PurgeSecretRequest>,
) -> Result<StatusCode, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let principal = authenticate_principal(&state, &headers, true, now)?;
    state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .purge_secret(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
            input.retention_cutoff_unix_ms,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct MetadataResponse {
    name: String,
    description: Option<String>,
    username: Option<String>,
    tags: Vec<String>,
}

fn metadata_response(metadata: &smcv_app::DecryptedMetadata) -> MetadataResponse {
    MetadataResponse {
        name: String::from(metadata.name.expose()),
        description: metadata
            .description
            .as_ref()
            .map(|value| String::from(value.expose())),
        username: metadata
            .username
            .as_ref()
            .map(|value| String::from(value.expose())),
        tags: metadata
            .tags
            .iter()
            .map(|value| String::from(value.expose()))
            .collect(),
    }
}

async fn read_secret_metadata(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<MetadataResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let metadata = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .read_secret_metadata(secret_id(&id).map_err(|()| ApiError::not_found(request_id))?)
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(metadata_response(&metadata)))
}

#[derive(Serialize)]
struct SecretValueResponse {
    value_base64: String,
}

async fn reveal_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let value = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .reveal_current_secret(secret_id(&id).map_err(|()| ApiError::not_found(request_id))?)
        .map_err(|error| map_vault_error(error, request_id))?;
    let mut response = Json(SecretValueResponse {
        value_base64: STANDARD.encode(value.expose()),
    })
    .into_response();
    apply_security_headers(response.headers_mut());
    Ok(response)
}

#[derive(Deserialize)]
struct VersionPageQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_page_size")]
    limit: u16,
}

const fn default_page_size() -> u16 {
    50
}

#[derive(Serialize)]
struct SecretVersionMetadataResponse {
    version: u64,
    expires_at_unix_ms: Option<i64>,
    rotation_due_at_unix_ms: Option<i64>,
    created_by_principal_id: Option<String>,
    created_at_unix_ms: i64,
}

#[derive(Serialize)]
struct SecretVersionPageResponse {
    versions: Vec<SecretVersionMetadataResponse>,
    next_after_version: Option<u64>,
}

async fn secret_versions(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<VersionPageQuery>,
) -> Result<Json<SecretVersionPageResponse>, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let records = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .secret_version_history(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            query.after,
            query.limit,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    let next_after_version = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.version))
        .flatten();
    Ok(Json(SecretVersionPageResponse {
        versions: records
            .into_iter()
            .map(|record| SecretVersionMetadataResponse {
                version: record.version,
                expires_at_unix_ms: record.schedule.expires_at_unix_ms,
                rotation_due_at_unix_ms: record.schedule.rotation_due_at_unix_ms,
                created_by_principal_id: record
                    .created_by_principal_id
                    .map(|principal_id| principal_id.to_string()),
                created_at_unix_ms: record.created_at_unix_ms,
            })
            .collect(),
        next_after_version,
    }))
}

async fn reveal_secret_version(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath((id, version)): AxumPath<(String, u64)>,
) -> Result<Response, ApiError> {
    let request_id = request_id(&headers);
    let now = now_unix_ms();
    let principal = authenticate_principal(&state, &headers, false, now)?;
    let value = state
        .vault
        .authorized(principal, request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .reveal_secret_version(
            secret_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            version,
        )
        .map_err(|error| map_vault_error(error, request_id))?;
    Ok(Json(SecretValueResponse {
        value_base64: STANDARD.encode(value.expose()),
    })
    .into_response())
}

#[derive(Deserialize)]
struct CreateServiceIdentityRequest {
    label: String,
    description: Option<String>,
}

#[derive(Deserialize)]
struct ServiceIdentityPageQuery {
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

#[derive(Serialize)]
struct ServiceIdentityListEntryResponse {
    id: String,
    label: String,
    description: Option<String>,
    state: String,
    revision: u64,
}

#[derive(Serialize)]
struct ServiceIdentityPageResponse {
    applications: Vec<ServiceIdentityListEntryResponse>,
    next_after: Option<String>,
}

async fn list_service_identities(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ServiceIdentityPageQuery>,
) -> Result<Json<ServiceIdentityPageResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let records = state
        .vault
        .service_identities(
            owner,
            query
                .after
                .as_deref()
                .map(principal_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.principal_id.to_string()))
        .flatten();
    Ok(Json(ServiceIdentityPageResponse {
        applications: records
            .into_iter()
            .map(|record| ServiceIdentityListEntryResponse {
                id: record.principal_id.to_string(),
                label: String::from(record.metadata.label.expose()),
                description: record
                    .metadata
                    .description
                    .as_ref()
                    .map(|value| String::from(value.expose())),
                state: record.state,
                revision: record.revision,
            })
            .collect(),
        next_after,
    }))
}

async fn create_service_identity(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreateServiceIdentityRequest>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let id = state
        .vault
        .create_service_identity(
            owner,
            &ServiceIdentityMetadata {
                label: ProtectedString::new(input.label),
                description: input.description.map(ProtectedString::new),
            },
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok((StatusCode::CREATED, Json(IdResponse { id: id.to_string() })))
}

#[derive(Serialize)]
struct ServiceIdentityResponse {
    id: String,
    label: String,
    description: Option<String>,
}

async fn read_service_identity(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ServiceIdentityResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let principal_id = principal_id(&id).map_err(|()| ApiError::not_found(request_id))?;
    let metadata = state
        .vault
        .read_service_identity_metadata(owner, principal_id, request_id, now)
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(ServiceIdentityResponse {
        id,
        label: String::from(metadata.label.expose()),
        description: metadata
            .description
            .as_ref()
            .map(|value| String::from(value.expose())),
    }))
}

#[derive(Deserialize)]
struct EffectiveAccessQuery {
    resource_kind: String,
    resource_id: String,
}

#[derive(Serialize)]
struct EffectiveAccessResponse {
    service_principal_id: String,
    resource_kind: String,
    resource_id: String,
    actions: Vec<&'static str>,
}

async fn effective_access(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<EffectiveAccessQuery>,
) -> Result<Json<EffectiveAccessResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let service_principal_id = principal_id(&id).map_err(|()| ApiError::not_found(request_id))?;
    let resource_kind = match query.resource_kind.as_str() {
        "namespace" => ResourceKind::Namespace,
        "secret" => ResourceKind::Secret,
        _ => return Err(ApiError::invalid(request_id)),
    };
    let resource_id =
        object_id(&query.resource_id).map_err(|()| ApiError::not_found(request_id))?;
    let actions = state
        .vault
        .effective_service_actions(
            owner,
            service_principal_id,
            resource_kind,
            resource_id,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(EffectiveAccessResponse {
        service_principal_id: id,
        resource_kind: query.resource_kind,
        resource_id: query.resource_id,
        actions: actions.into_iter().map(Action::as_str).collect(),
    }))
}

#[derive(Deserialize)]
struct IssueCredentialRequest {
    expires_at_unix_ms: Option<i64>,
}

#[derive(Deserialize)]
struct CredentialPageQuery {
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

#[derive(Serialize)]
struct CredentialSummaryResponse {
    id: String,
    created_at_unix_ms: i64,
    expires_at_unix_ms: Option<i64>,
    last_used_at_unix_ms: Option<i64>,
    revoked_at_unix_ms: Option<i64>,
    revision: u64,
}

#[derive(Serialize)]
struct CredentialPageResponse {
    credentials: Vec<CredentialSummaryResponse>,
    next_after: Option<String>,
}

async fn list_credentials(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<CredentialPageQuery>,
) -> Result<Json<CredentialPageResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let records = state
        .vault
        .application_credentials(
            owner,
            principal_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            query
                .after
                .as_deref()
                .map(credential_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| {
            records
                .last()
                .map(|record| record.credential_id.to_string())
        })
        .flatten();
    Ok(Json(CredentialPageResponse {
        credentials: records
            .into_iter()
            .map(|record| CredentialSummaryResponse {
                id: record.credential_id.to_string(),
                created_at_unix_ms: record.created_at_unix_ms,
                expires_at_unix_ms: record.expires_at_unix_ms,
                last_used_at_unix_ms: record.last_used_at_unix_ms,
                revoked_at_unix_ms: record.revoked_at_unix_ms,
                revision: record.revision,
            })
            .collect(),
        next_after,
    }))
}

#[derive(Serialize)]
struct IssuedCredentialResponse {
    id: String,
    credential: String,
    expires_at_unix_ms: Option<i64>,
}

async fn issue_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<IssueCredentialRequest>,
) -> Result<(StatusCode, Json<IssuedCredentialResponse>), ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let issued = state
        .vault
        .issue_application_credential(
            owner,
            principal_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expires_at_unix_ms,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok((
        StatusCode::CREATED,
        Json(IssuedCredentialResponse {
            id: issued.credential_id.to_string(),
            credential: String::from(issued.plaintext.expose()),
            expires_at_unix_ms: issued.expires_at_unix_ms,
        }),
    ))
}

#[derive(Deserialize)]
struct RevokeCredentialRequest {
    expected_revision: u64,
}

async fn revoke_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath((service_id_value, credential_id_value)): AxumPath<(String, String)>,
    Json(input): Json<RevokeCredentialRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let revision = state
        .vault
        .revoke_application_credential(
            owner,
            principal_id(&service_id_value).map_err(|()| ApiError::not_found(request_id))?,
            credential_id(&credential_id_value).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

#[derive(Deserialize)]
struct CreatePolicyRequest {
    label: String,
}

#[derive(Deserialize)]
struct PolicyPageQuery {
    after: Option<String>,
    #[serde(default = "default_page_size")]
    limit: u16,
}

#[derive(Serialize)]
struct PolicyPageResponse {
    policies: Vec<PolicyResponse>,
    next_after: Option<String>,
}

async fn list_policies(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<PolicyPageQuery>,
) -> Result<Json<PolicyPageResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let records = state
        .vault
        .policies(
            owner,
            query
                .after
                .as_deref()
                .map(policy_id)
                .transpose()
                .map_err(|()| ApiError::invalid(request_id))?,
            query.limit,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    let next_after = (records.len() == usize::from(query.limit))
        .then(|| records.last().map(|record| record.policy_id.to_string()))
        .flatten();
    Ok(Json(PolicyPageResponse {
        policies: records
            .into_iter()
            .map(|record| PolicyResponse {
                id: record.policy_id.to_string(),
                label: String::from(record.label.expose()),
                state: record.state,
                revision: record.revision,
            })
            .collect(),
        next_after,
    }))
}

async fn create_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let id = state
        .vault
        .create_policy(
            owner,
            &PolicyMetadata {
                label: ProtectedString::new(input.label),
            },
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok((StatusCode::CREATED, Json(IdResponse { id: id.to_string() })))
}

#[derive(Serialize)]
struct PolicyResponse {
    id: String,
    label: String,
    state: String,
    revision: u64,
}

#[derive(Serialize)]
struct PolicyGrantResponse {
    id: String,
    action: &'static str,
    resource_kind: &'static str,
    resource_id: String,
    include_descendants: bool,
}

#[derive(Serialize)]
struct PolicyRulesResponse {
    authorization_revision: u64,
    grants: Vec<PolicyGrantResponse>,
    bound_service_principal_ids: Vec<String>,
}

async fn policy_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PolicyRulesResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let rules = state
        .vault
        .policy_rules(
            owner,
            policy_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(PolicyRulesResponse {
        authorization_revision: rules.authorization_revision,
        grants: rules
            .grants
            .into_iter()
            .map(|grant| PolicyGrantResponse {
                id: grant.grant_id.to_string(),
                action: grant.action.as_str(),
                resource_kind: grant.resource_kind.as_str(),
                resource_id: grant.resource_id.to_string(),
                include_descendants: grant.include_descendants,
            })
            .collect(),
        bound_service_principal_ids: rules
            .bindings
            .into_iter()
            .map(|binding| binding.principal_id.to_string())
            .collect(),
    }))
}

async fn read_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let details = state
        .vault
        .read_policy(
            owner,
            policy_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(PolicyResponse {
        id,
        label: String::from(details.label.expose()),
        state: details.state,
        revision: details.revision,
    }))
}

async fn archive_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<LifecycleRequest>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let revision = state
        .vault
        .archive_policy(
            owner,
            policy_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            input.expected_revision,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(Json(RevisionResponse { revision }))
}

#[derive(Deserialize)]
struct AddGrantRequest {
    action: String,
    resource_kind: String,
    resource_id: String,
    include_descendants: bool,
}

async fn add_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<AddGrantRequest>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    use core::str::FromStr as _;

    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    let kind = match input.resource_kind.as_str() {
        "namespace" => ResourceKind::Namespace,
        "secret" => ResourceKind::Secret,
        _ => return Err(ApiError::invalid(request_id)),
    };
    let grant = state
        .vault
        .add_policy_grant(
            owner,
            GrantSpec {
                policy_id: policy_id(&id).map_err(|()| ApiError::not_found(request_id))?,
                action: Action::from_str(&input.action)
                    .map_err(|()| ApiError::invalid(request_id))?,
                resource_kind: kind,
                resource_id: object_id(&input.resource_id)
                    .map_err(|()| ApiError::not_found(request_id))?,
                include_descendants: input.include_descendants,
            },
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok((
        StatusCode::CREATED,
        Json(IdResponse {
            id: grant.to_string(),
        }),
    ))
}

#[derive(Deserialize)]
struct BindPolicyRequest {
    service_principal_id: String,
}

async fn bind_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<BindPolicyRequest>,
) -> Result<StatusCode, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    state
        .vault
        .bind_policy_to_service(
            owner,
            principal_id(&input.service_principal_id)
                .map_err(|()| ApiError::not_found(request_id))?,
            policy_id(&id).map_err(|()| ApiError::not_found(request_id))?,
            request_id,
            now,
        )
        .map_err(|_| ApiError::not_found(request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct AuditEventResponse {
    sequence: u64,
    event_id: String,
    occurred_at_unix_ms: i64,
    request_id: String,
    actor_principal_id: Option<String>,
    credential_kind: Option<String>,
    credential_id: Option<String>,
    action: String,
    target_kind: String,
    target_id: Option<String>,
    outcome: String,
}

#[derive(Serialize)]
struct AuditPageResponse {
    events: Vec<AuditEventResponse>,
    next_after_sequence: Option<u64>,
}

async fn audit_events(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<AuditPageResponse>, ApiError> {
    let now = now_unix_ms();
    let request_id = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, false, now)?;
    let after = headers
        .get("x-smcv-after-sequence")
        .and_then(|value| value.to_str().ok())
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| ApiError::invalid(request_id))?
        .unwrap_or(0);
    let limit = headers
        .get("x-smcv-page-size")
        .and_then(|value| value.to_str().ok())
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|_| ApiError::invalid(request_id))?
        .unwrap_or(100);
    let records = state
        .vault
        .authorized(RequestPrincipal::Owner(owner), request_id, now)
        .map_err(|_| ApiError::authentication(request_id))?
        .audit_events(after, limit)
        .map_err(|error| map_vault_error(error, request_id))?;
    let next_after_sequence = (records.len() == usize::from(limit))
        .then(|| records.last().map(|record| record.sequence))
        .flatten();
    Ok(Json(AuditPageResponse {
        events: records
            .into_iter()
            .map(|record| AuditEventResponse {
                sequence: record.sequence,
                event_id: record.event_id.to_string(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
                request_id: record.request_id.to_string(),
                actor_principal_id: record.actor_principal_id.map(|value| value.to_string()),
                credential_kind: record.credential_kind,
                credential_id: record.credential_id.map(|value| value.to_string()),
                action: record.action,
                target_kind: record.target_kind,
                target_id: record.target_id.map(|value| value.to_string()),
                outcome: record.outcome,
            })
            .collect(),
        next_after_sequence,
    }))
}

async fn openapi() -> Json<serde_json::Value> {
    Json(openapi_document())
}

fn openapi_document() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "SMCV API",
            "version": "1.0.0",
            "description": "Same-origin, non-enumerating API for one encrypted SMCV vault. Secret-bearing responses are never cacheable."
        },
        "servers": [{"url": "/api/v1"}],
        "security": [{"sessionCookie": []}, {"bearerAuth": []}],
        "paths": {
            "/session/password": {"post": {"operationId": "passwordLogin", "summary": "Create owner session", "security": [], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PasswordLogin"}}}}, "responses": {"200": {"$ref": "#/components/responses/Session"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/session": {
                "get": {"operationId": "sessionStatus", "summary": "Inspect owner session", "responses": {"200": {"description": "Current session state"}, "default": {"$ref": "#/components/responses/Error"}}},
                "delete": {"operationId": "logout", "summary": "Revoke owner session", "responses": {"204": {"description": "Session revoked"}, "default": {"$ref": "#/components/responses/Error"}}}
            },
            "/session/passkeys/registration/options": {"post": {"operationId": "startPasskeyRegistration", "summary": "Start owner passkey registration", "responses": {"200": {"description": "One-use registration options"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/session/passkeys/registration/verify": {"post": {"operationId": "finishPasskeyRegistration", "summary": "Verify owner passkey registration", "responses": {"204": {"description": "Passkey registered"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/session/passkeys/authentication/options": {"post": {"operationId": "startPasskeyAuthentication", "summary": "Start owner passkey authentication", "security": [], "responses": {"200": {"description": "One-use authentication options"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/session/passkeys/authentication/verify": {"post": {"operationId": "finishPasskeyAuthentication", "summary": "Verify passkey and create session", "security": [], "responses": {"200": {"$ref": "#/components/responses/Session"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/namespaces": {"get": {"operationId": "listNamespaces", "summary": "List protected child namespace metadata", "parameters": [{"$ref": "#/components/parameters/ParentNamespaceId"}, {"$ref": "#/components/parameters/ObjectAfter"}, {"$ref": "#/components/parameters/Limit"}], "responses": {"200": {"description": "Bounded namespace page"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "createNamespace", "summary": "Create namespace", "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}], "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"$ref": "#/components/responses/Id"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/namespaces/{id}/move-impact": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "previewNamespaceMove", "summary": "Preview exact access broadening", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"200": {"description": "Service/action access delta"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/namespaces/{id}/move": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "moveNamespace", "summary": "Move namespace with confirmed access delta", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets": {"get": {"operationId": "listSecrets", "summary": "List protected secret metadata", "parameters": [{"$ref": "#/components/parameters/NamespaceIdQuery"}, {"$ref": "#/components/parameters/ObjectAfter"}, {"$ref": "#/components/parameters/Limit"}], "responses": {"200": {"description": "Bounded metadata-only secret page"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "createSecret", "summary": "Create encrypted secret", "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}], "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"description": "Secret identifier and version preconditions"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/lifecycle": {"get": {"operationId": "listSecretLifecycle", "summary": "List owner-visible secrets in one lifecycle state", "parameters": [{"$ref": "#/components/parameters/NamespaceIdQuery"}, {"name": "state", "in": "query", "required": true, "schema": {"type": "string", "enum": ["active", "archived", "deleted"]}}, {"$ref": "#/components/parameters/ObjectAfter"}, {"$ref": "#/components/parameters/Limit"}], "responses": {"200": {"description": "Bounded lifecycle inventory without values"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "readSecretMetadata", "summary": "Read protected metadata", "responses": {"200": {"description": "Decrypted metadata"}, "default": {"$ref": "#/components/responses/Error"}}}, "put": {"operationId": "updateSecret", "summary": "Append immutable secret version", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"200": {"description": "New immutable version"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/value": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "revealCurrentSecret", "summary": "Explicitly reveal current value", "responses": {"200": {"$ref": "#/components/responses/SecretValue"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/versions": {"parameters": [{"$ref": "#/components/parameters/Id"}, {"$ref": "#/components/parameters/After"}, {"$ref": "#/components/parameters/Limit"}], "get": {"operationId": "listSecretVersions", "summary": "List immutable version metadata", "responses": {"200": {"description": "Bounded version page"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/versions/{version}/value": {"parameters": [{"$ref": "#/components/parameters/Id"}, {"$ref": "#/components/parameters/Version"}], "get": {"operationId": "revealSecretVersion", "summary": "Explicitly reveal historical value", "responses": {"200": {"$ref": "#/components/responses/SecretValue"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/archive": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "archiveSecret", "summary": "Archive secret", "requestBody": {"$ref": "#/components/requestBodies/Lifecycle"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/restore": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "restoreSecret", "summary": "Restore archived secret", "requestBody": {"$ref": "#/components/requestBodies/Lifecycle"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/delete": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "deleteSecret", "summary": "Owner-tombstone a secret while retaining encrypted history", "requestBody": {"$ref": "#/components/requestBodies/Lifecycle"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/secrets/{id}/purge": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "purgeSecret", "summary": "Owner-purge current-vault ciphertext after retention approval", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"204": {"description": "Current-vault ciphertext purged; tombstone and audit retained"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/service-identities": {"get": {"operationId": "listServiceIdentities", "summary": "List protected service-identity metadata", "responses": {"200": {"description": "Bounded application identity page"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "createServiceIdentity", "summary": "Create service identity", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"$ref": "#/components/responses/Id"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/service-identities/{id}": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "readServiceIdentity", "summary": "Read service identity", "responses": {"200": {"description": "Protected identity metadata"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/service-identities/{id}/effective-access": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "effectiveAccess", "summary": "Compute current effective access", "responses": {"200": {"description": "Closed effective action set"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/service-identities/{id}/credentials": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "listCredentials", "summary": "List safe credential lifecycle metadata", "parameters": [{"$ref": "#/components/parameters/CredentialAfter"}, {"$ref": "#/components/parameters/Limit"}], "responses": {"200": {"description": "Bounded credential page without bearer values"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "issueCredential", "summary": "Issue display-once application credential", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"description": "Display-once credential"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/service-identities/{id}/credentials/{credential_id}/revoke": {"parameters": [{"$ref": "#/components/parameters/Id"}, {"$ref": "#/components/parameters/CredentialId"}], "post": {"operationId": "revokeCredential", "summary": "Revoke application credential", "requestBody": {"$ref": "#/components/requestBodies/Lifecycle"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies": {"get": {"operationId": "listPolicies", "summary": "List protected policy metadata", "responses": {"200": {"description": "Bounded policy page"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "createPolicy", "summary": "Create allow-only policy", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"$ref": "#/components/responses/Id"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies/{id}": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "readPolicy", "summary": "Read policy", "responses": {"200": {"description": "Policy metadata and state"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies/{id}/rules": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "readPolicyRules", "summary": "Read exact policy grants and bindings", "responses": {"200": {"description": "Policy rules and authorization revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies/{id}/archive": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "archivePolicy", "summary": "Archive policy", "requestBody": {"$ref": "#/components/requestBodies/Lifecycle"}, "responses": {"200": {"description": "New revision"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies/{id}/grants": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "addPolicyGrant", "summary": "Add closed allow-only grant", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"201": {"$ref": "#/components/responses/Id"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/policies/{id}/bindings": {"parameters": [{"$ref": "#/components/parameters/Id"}], "post": {"operationId": "bindPolicy", "summary": "Bind policy to service identity", "requestBody": {"$ref": "#/components/requestBodies/JsonObject"}, "responses": {"204": {"description": "Policy bound"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/audit-events": {"get": {"operationId": "auditEvents", "summary": "Read bounded audit page", "parameters": [{"$ref": "#/components/parameters/AuditAfter"}, {"$ref": "#/components/parameters/AuditLimit"}], "responses": {"200": {"description": "Authenticated audit records"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/backups": {"get": {"operationId": "listBackupJobs", "summary": "List safe durable backup job status", "responses": {"200": {"description": "Unexpired backup jobs without recovery material"}, "default": {"$ref": "#/components/responses/Error"}}}, "post": {"operationId": "createBackupJob", "summary": "Start a durable portable-backup job", "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BackupCreate"}}}}, "responses": {"202": {"description": "Opaque job and optional display-once recovery key"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/backups/{id}": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "backupJobStatus", "summary": "Read safe durable backup status", "responses": {"200": {"description": "Safe job status without key material"}, "default": {"$ref": "#/components/responses/Error"}}}, "delete": {"operationId": "deleteBackupArtifact", "summary": "Delete an encrypted server artifact and status", "responses": {"204": {"description": "Artifact removed"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/backups/{id}/download": {"parameters": [{"$ref": "#/components/parameters/Id"}], "get": {"operationId": "downloadBackupArtifact", "summary": "Download a verified encrypted archive", "responses": {"200": {"description": "Portable .smcvault stream", "content": {"application/octet-stream": {}}}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/backup-verifications": {"post": {"operationId": "verifyUploadedBackup", "summary": "Fully verify and clean-restore-test an uploaded portable archive", "requestBody": {"required": true, "content": {"multipart/form-data": {"schema": {"type": "object", "required": ["key_mode", "key", "archive"], "properties": {"key_mode": {"type": "string", "enum": ["generated_recovery", "recovery_key", "passphrase"]}, "key": {"type": "string", "format": "password", "writeOnly": true}, "archive": {"type": "string", "format": "binary"}}}}}}, "responses": {"200": {"description": "Authenticated metadata and successful clean restore drill"}, "default": {"$ref": "#/components/responses/Error"}}}},
            "/openapi.json": {"get": {"operationId": "openApiDocument", "summary": "Read this API contract", "security": [], "responses": {"200": {"description": "OpenAPI 3.1 document"}}}}
        },
        "components": {
            "securitySchemes": {
                "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "__Host-smcv_session"},
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "SMCV application credential"}
            },
            "parameters": {
                "Id": {"name": "id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}},
                "CredentialId": {"name": "credential_id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}},
                "CredentialAfter": {"name": "after", "in": "query", "schema": {"type": "string", "format": "uuid"}},
                "ObjectAfter": {"name": "after", "in": "query", "schema": {"type": "string", "format": "uuid"}},
                "ParentNamespaceId": {"name": "parent_namespace_id", "in": "query", "schema": {"type": "string", "format": "uuid"}},
                "NamespaceIdQuery": {"name": "namespace_id", "in": "query", "required": true, "schema": {"type": "string", "format": "uuid"}},
                "Version": {"name": "version", "in": "path", "required": true, "schema": {"type": "integer", "minimum": 1}},
                "After": {"name": "after", "in": "query", "schema": {"type": "integer", "minimum": 0, "default": 0}},
                "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}},
                "IdempotencyKey": {"name": "Idempotency-Key", "in": "header", "required": true, "schema": {"type": "string", "minLength": 1, "maxLength": 128}},
                "AuditAfter": {"name": "X-SMCV-After-Sequence", "in": "header", "schema": {"type": "integer", "minimum": 0}},
                "AuditLimit": {"name": "X-SMCV-Page-Size", "in": "header", "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}}
            },
            "schemas": {
                "PasswordLogin": {"type": "object", "additionalProperties": false, "required": ["password"], "properties": {"password": {"type": "string", "minLength": 12, "maxLength": 1024, "writeOnly": true}}},
                "BackupCreate": {"type": "object", "additionalProperties": false, "required": ["key_mode"], "properties": {"key_mode": {"type": "string", "enum": ["generated_recovery", "passphrase"]}, "passphrase": {"type": "string", "minLength": 16, "maxLength": 1024, "writeOnly": true}}},
                "Error": {"type": "object", "additionalProperties": false, "required": ["code", "message", "request_id"], "properties": {"code": {"type": "string"}, "message": {"type": "string"}, "request_id": {"type": "string", "format": "uuid"}}, "example": {"code": "resource_unavailable", "message": "The requested resource is unavailable.", "request_id": "00000000-0000-4000-8000-000000000001"}},
                "Id": {"type": "object", "additionalProperties": false, "required": ["id"], "properties": {"id": {"type": "string", "format": "uuid"}}},
                "SecretValue": {"type": "object", "additionalProperties": false, "required": ["value_base64"], "properties": {"value_base64": {"type": "string", "contentEncoding": "base64", "readOnly": true}}, "example": {"value_base64": "c3ludGhldGlj"}},
                "Lifecycle": {"type": "object", "additionalProperties": false, "required": ["expected_revision"], "properties": {"expected_revision": {"type": "integer", "minimum": 1}}}
            },
            "requestBodies": {
                "JsonObject": {"required": true, "content": {"application/json": {"schema": {"type": "object"}}}},
                "Lifecycle": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Lifecycle"}}}}
            },
            "responses": {
                "Error": {"description": "Bounded non-enumerating error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Id": {"description": "Created stable identifier", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Id"}}}},
                "Session": {"description": "Display-once CSRF token and secure session cookie"},
                "SecretValue": {"description": "Explicit secret-bearing response", "headers": {"Cache-Control": {"schema": {"type": "string", "const": "no-store"}}}, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SecretValue"}}}}
            }
        }
    })
}

async fn not_found(headers: HeaderMap) -> ApiError {
    ApiError::not_found(request_id(&headers))
}

fn authenticate_principal(
    state: &ApiState,
    headers: &HeaderMap,
    state_changing: bool,
    now: i64,
) -> Result<RequestPrincipal, ApiError> {
    let request_id = request_id(headers);
    if let Some(bearer) = bearer(headers) {
        let service = state
            .vault
            .authenticate_application_credential(&ProtectedString::new(bearer), request_id, now)
            .map_err(|_| ApiError::authentication(request_id))?;
        return Ok(RequestPrincipal::Service(service));
    }
    authenticate_owner(state, headers, state_changing, now).map(RequestPrincipal::Owner)
}

fn authenticate_owner(
    state: &ApiState,
    headers: &HeaderMap,
    require_csrf: bool,
    now: i64,
) -> Result<AuthenticatedOwner, ApiError> {
    let request_id = request_id(headers);
    let session =
        cookie(headers, SESSION_COOKIE).ok_or_else(|| ApiError::authentication(request_id))?;
    let csrf = headers
        .get("x-smcv-csrf")
        .and_then(|value| value.to_str().ok())
        .map(|value| ProtectedString::new(String::from(value)));
    state
        .vault
        .authenticate_browser_session(
            &ProtectedString::new(session),
            csrf.as_ref(),
            require_csrf,
            now,
        )
        .map_err(|_| ApiError::authentication(request_id))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming display-once secrets bounds and zeroizes their lifetime"
)]
fn session_response(issued: BrowserSessionSecrets) -> Response {
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        issued.session_token.expose()
    );
    let mut response = Json(SessionResponse {
        csrf_token: String::from(issued.csrf_token.expose()),
        absolute_expires_at_unix_ms: issued.absolute_expires_at_unix_ms,
    })
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    apply_security_headers(response.headers_mut());
    response
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    if value.len() > 4_096 {
        return None;
    }
    value.split(';').find_map(|field| {
        let (candidate, value) = field.trim().split_once('=')?;
        (candidate == name && !value.is_empty() && value.len() <= 128).then(|| String::from(value))
    })
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (!token.is_empty() && token.len() <= 128).then(|| String::from(token))
}

fn idempotency_input(
    headers: &HeaderMap,
    canonical_request: Vec<u8>,
    request_id: RequestId,
) -> Result<IdempotencyInput, ApiError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| ApiError::invalid(request_id))?;
    Ok(IdempotencyInput {
        key: ProtectedString::new(String::from(key)),
        canonical_request: ProtectedBytes::new(canonical_request),
    })
}

fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        );
    }
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: String,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    request_id: RequestId,
}

impl ApiError {
    const fn authentication(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication_failed",
            message: "Authentication failed.",
            request_id,
        }
    }

    const fn not_found(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "resource_unavailable",
            message: "The requested resource is unavailable.",
            request_id,
        }
    }

    const fn invalid(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "The request is invalid.",
            request_id,
        }
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            message: "The service is temporarily unavailable.",
            request_id,
        }
    }

    const fn rate_limited(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "Try again later.",
            request_id,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                code: self.code,
                message: self.message,
                request_id: self.request_id.to_string(),
            }),
        )
            .into_response();
        apply_security_headers(response.headers_mut());
        response
    }
}

fn map_vault_error(_error: AuthorizedVaultError, request_id: RequestId) -> ApiError {
    ApiError::not_found(request_id)
}

fn request_id(headers: &HeaderMap) -> RequestId {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .map_or_else(RequestId::random, RequestId::from_uuid)
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn parse_uuid(value: &str) -> Result<Uuid, ()> {
    Uuid::parse_str(value).map_err(|_| ())
}

fn namespace_id(value: &str) -> Result<NamespaceId, ()> {
    parse_uuid(value).map(NamespaceId::from_uuid)
}

fn secret_id(value: &str) -> Result<SecretId, ()> {
    parse_uuid(value).map(SecretId::from_uuid)
}

fn principal_id(value: &str) -> Result<PrincipalId, ()> {
    parse_uuid(value).map(PrincipalId::from_uuid)
}

fn credential_id(value: &str) -> Result<smcv_core::CredentialId, ()> {
    parse_uuid(value).map(smcv_core::CredentialId::from_uuid)
}

fn policy_id(value: &str) -> Result<PolicyId, ()> {
    parse_uuid(value).map(PolicyId::from_uuid)
}

fn object_id(value: &str) -> Result<ObjectId, ()> {
    parse_uuid(value).map(ObjectId::from_uuid)
}

fn ceremony_id(value: &str) -> Option<CeremonyId> {
    Uuid::parse_str(value).ok().map(CeremonyId::from_uuid)
}

/// Performs local-only owner enrollment for the CLI without an HTTP route.
///
/// # Errors
///
/// Returns a safe string if enrollment fails or was already completed.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming the password ensures its zeroizing wrapper is not retained"
)]
pub fn enroll_local_owner(
    state: &ApiState,
    password: ProtectedString,
) -> Result<PrincipalId, String> {
    state
        .vault
        .enroll_local_owner(
            LocalSetupCapability::for_local_cli(),
            &password,
            RequestId::random(),
            now_unix_ms(),
        )
        .map_err(|error| error.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{collections::BTreeMap, fs};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use smcv_app::{MetadataInput, RequestPrincipal};
    use smcv_core::{ProtectedBytes, ProtectedString, RequestId, SecretSchedule};
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    use super::{ApiState, REQUEST_BODY_LIMIT, enroll_local_owner, operational_router, router};

    fn state() -> (TempDir, ApiState) {
        let root =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic root must create: {error}"));
        let state = ApiState::open(
            &root.path().join("data/vault.sqlite"),
            &root.path().join("keys/root.key"),
            "localhost",
            "http://localhost:8080",
        )
        .unwrap_or_else(|error| panic!("synthetic API state must open: {error}"));
        (root, state)
    }

    async fn login_owner(state: &ApiState) -> (String, String) {
        let login = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"synthetic long password"}"#))
            .unwrap_or_else(|error| panic!("login request must build: {error}"));
        let login = router(state.clone())
            .oneshot(login)
            .await
            .unwrap_or_else(|error| panic!("login must respond: {error}"));
        let cookie = login
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map_or_else(|| panic!("session cookie must exist"), str::to_owned);
        let login_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(login.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("login body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("login body must parse: {error}"));
        let csrf = login_body["csrf_token"]
            .as_str()
            .map_or_else(|| panic!("CSRF token must exist"), str::to_owned);
        (cookie, csrf)
    }

    #[tokio::test]
    async fn same_origin_web_shell_has_distinct_strict_document_policy() {
        let (_root, state) = state();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("web request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("web request must respond: {error}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let policy = response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("document CSP must exist"));
        assert!(policy.contains("script-src 'self'"));
        assert!(policy.contains("connect-src 'self'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        assert_eq!(
            response
                .headers()
                .get("permissions-policy")
                .and_then(|value| value.to_str().ok()),
            Some("camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-opener-policy")
                .and_then(|value| value.to_str().ok()),
            Some("same-origin")
        );
        assert_eq!(
            response
                .headers()
                .get("strict-transport-security")
                .and_then(|value| value.to_str().ok()),
            Some("max-age=31536000")
        );
        let body = to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|error| panic!("web body must read: {error}"));
        let text = std::str::from_utf8(&body)
            .unwrap_or_else(|error| panic!("web body must be UTF-8: {error}"));
        assert!(text.contains("id=\"skip-link\""));
        assert!(text.contains("Skip to authentication"));
        assert!(text.contains("id=\"main-content\""));
        assert!(text.contains("autocomplete=\"current-password\""));
    }

    #[tokio::test]
    async fn password_session_cookie_is_secure_and_state_change_requires_csrf() {
        let (_root, state) = state();
        enroll_local_owner(
            &state,
            ProtectedString::new(String::from("synthetic long password")),
        )
        .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"synthetic long password"}"#))
            .unwrap_or_else(|error| panic!("synthetic request must build: {error}"));
        let response = router(state.clone())
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("synthetic login must respond: {error}"));
        assert_eq!(response.status(), 200);
        let cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("session cookie must be present"));
        assert!(cookie.starts_with("__Host-smcv_session="));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces")
            .header("content-type", "application/json")
            .header("cookie", cookie.split(';').next().unwrap_or_default())
            .body(Body::from(
                r#"{"parent_namespace_id":null,"metadata":{"name":"blocked","description":null,"username":null,"tags":[]}}"#,
            ))
            .unwrap_or_else(|error| panic!("synthetic request must build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("synthetic request must respond: {error}"));
        assert_eq!(response.status(), 401);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|error| panic!("synthetic response body must read: {error}"));
        assert!(!String::from_utf8_lossy(&body).contains("synthetic long password"));
    }

    #[tokio::test]
    async fn custom_header_lock_revokes_a_reloaded_session_without_csrf() {
        let (_root, state) = state();
        enroll_local_owner(
            &state,
            ProtectedString::new(String::from("synthetic long password")),
        )
        .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let (cookie, _csrf) = login_owner(&state).await;

        let missing_header = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/session")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("lock request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("lock request must respond: {error}"));
        assert_eq!(missing_header.status(), StatusCode::UNAUTHORIZED);

        let locked = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/session")
                    .header("cookie", &cookie)
                    .header("x-smcv-session-lock", "1")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("lock request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("lock request must respond: {error}"));
        assert_eq!(locked.status(), StatusCode::NO_CONTENT);
        assert!(
            locked
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("Max-Age=0"))
        );

        let rejected = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/session")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("status request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("status request must respond: {error}"));
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_and_missing_routes_have_bounded_safe_errors() {
        let (_root, state) = state();
        let request = Request::builder()
            .uri("/api/v1/secrets/not-a-uuid")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("synthetic request must build: {error}"));
        let response = router(state.clone())
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("synthetic request must respond: {error}"));
        assert_eq!(response.status(), 401);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        let request = Request::builder()
            .uri("/api/v1/unknown")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("synthetic request must build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("synthetic request must respond: {error}"));
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn denied_existing_and_absent_resources_share_one_external_contract() {
        let (_root, state) = state();
        let password = ProtectedString::new(String::from("synthetic long password"));
        enroll_local_owner(
            &state,
            ProtectedString::new(String::from(password.expose())),
        )
        .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let now = super::now_unix_ms();
        let session = state
            .vault()
            .login_with_password(&password, RequestId::random(), now)
            .unwrap_or_else(|error| panic!("synthetic owner must login: {error}"));
        let owner = state
            .vault()
            .authenticate_browser_session(
                &session.session_token,
                Some(&session.csrf_token),
                true,
                now + 1,
            )
            .unwrap_or_else(|error| panic!("synthetic session must authenticate: {error}"));
        let owner_vault = state
            .vault()
            .authorized(RequestPrincipal::Owner(owner), RequestId::random(), now + 2)
            .unwrap_or_else(|error| panic!("synthetic owner must authorize: {error}"));
        let metadata = |name: &str| MetadataInput {
            name: ProtectedString::new(String::from(name)),
            description: None,
            username: None,
            tags: Vec::new(),
        };
        let namespace = owner_vault
            .create_namespace(None, &metadata("synthetic namespace"))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        let secret = owner_vault
            .create_secret(
                namespace,
                &metadata("synthetic secret"),
                ProtectedBytes::new(b"synthetic protected value".to_vec()),
                SecretSchedule::default(),
            )
            .unwrap_or_else(|error| panic!("synthetic secret must create: {error}"));
        drop(owner_vault);
        let service = state
            .vault()
            .create_service_identity(
                owner,
                &smcv_app::ServiceIdentityMetadata {
                    label: ProtectedString::new(String::from("synthetic denied service")),
                    description: None,
                },
                RequestId::random(),
                now + 3,
            )
            .unwrap_or_else(|error| panic!("synthetic service must create: {error}"));
        let credential = state
            .vault()
            .issue_application_credential(owner, service, None, RequestId::random(), now + 4)
            .unwrap_or_else(|error| panic!("synthetic credential must issue: {error}"));

        let probe = |id: String| {
            Request::builder()
                .uri(format!("/api/v1/secrets/{id}"))
                .header(
                    "authorization",
                    format!("Bearer {}", credential.plaintext.expose()),
                )
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("probe request must build: {error}"))
        };
        let existing = router(state.clone())
            .oneshot(probe(secret.secret_id.to_string()))
            .await
            .unwrap_or_else(|error| panic!("existing probe must respond: {error}"));
        let absent = router(state)
            .oneshot(probe(uuid::Uuid::new_v4().to_string()))
            .await
            .unwrap_or_else(|error| panic!("absent probe must respond: {error}"));
        assert_eq!(existing.status(), absent.status());
        let existing_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(existing.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("existing error must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("existing error must parse: {error}"));
        let absent_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(absent.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("absent error must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("absent error must parse: {error}"));
        assert_eq!(existing_body["code"], absent_body["code"]);
        assert_eq!(existing_body["message"], absent_body["message"]);
        assert_eq!(
            existing_body["request_id"].as_str().map(str::len),
            absent_body["request_id"].as_str().map(str::len)
        );
    }

    #[tokio::test]
    async fn openapi_paths_and_methods_match_the_runtime_router() {
        let (_root, state) = state();
        let request = Request::builder()
            .uri("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("OpenAPI request must build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("OpenAPI request must respond: {error}"));
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|error| panic!("OpenAPI response must read: {error}"));
        let document: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|error| panic!("OpenAPI response must parse: {error}"));
        let expected: BTreeMap<&str, &[&str]> = BTreeMap::from([
            ("/session/password", &["post"][..]),
            ("/session", &["delete", "get"][..]),
            ("/session/passkeys/registration/options", &["post"][..]),
            ("/session/passkeys/registration/verify", &["post"][..]),
            ("/session/passkeys/authentication/options", &["post"][..]),
            ("/session/passkeys/authentication/verify", &["post"][..]),
            ("/namespaces", &["get", "post"][..]),
            ("/namespaces/{id}/move-impact", &["post"][..]),
            ("/namespaces/{id}/move", &["post"][..]),
            ("/secrets", &["get", "post"][..]),
            ("/secrets/lifecycle", &["get"][..]),
            ("/secrets/{id}", &["get", "put"][..]),
            ("/secrets/{id}/value", &["get"][..]),
            ("/secrets/{id}/versions", &["get"][..]),
            ("/secrets/{id}/versions/{version}/value", &["get"][..]),
            ("/secrets/{id}/archive", &["post"][..]),
            ("/secrets/{id}/restore", &["post"][..]),
            ("/secrets/{id}/delete", &["post"][..]),
            ("/secrets/{id}/purge", &["post"][..]),
            ("/service-identities", &["get", "post"][..]),
            ("/service-identities/{id}", &["get"][..]),
            ("/service-identities/{id}/effective-access", &["get"][..]),
            ("/service-identities/{id}/credentials", &["get", "post"][..]),
            (
                "/service-identities/{id}/credentials/{credential_id}/revoke",
                &["post"][..],
            ),
            ("/policies", &["get", "post"][..]),
            ("/policies/{id}", &["get"][..]),
            ("/policies/{id}/rules", &["get"][..]),
            ("/policies/{id}/archive", &["post"][..]),
            ("/policies/{id}/grants", &["post"][..]),
            ("/policies/{id}/bindings", &["post"][..]),
            ("/audit-events", &["get"][..]),
            ("/backups", &["get", "post"][..]),
            ("/backups/{id}", &["delete", "get"][..]),
            ("/backups/{id}/download", &["get"][..]),
            ("/backup-verifications", &["post"][..]),
            ("/openapi.json", &["get"][..]),
        ]);
        let paths = document["paths"]
            .as_object()
            .unwrap_or_else(|| panic!("OpenAPI paths must be an object"));
        assert_eq!(paths.len(), expected.len());
        let mut operation_ids = std::collections::BTreeSet::new();
        for (path, methods) in expected {
            let item = paths
                .get(path)
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| panic!("OpenAPI path must exist: {path}"));
            for method in methods {
                let operation = item
                    .get(*method)
                    .unwrap_or_else(|| panic!("OpenAPI operation must exist: {method} {path}"));
                let operation_id = operation["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("operationId must exist: {method} {path}"));
                assert!(operation_ids.insert(operation_id));
            }
        }
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the HTTP lifecycle proof keeps archive inventory, restore, tombstone inventory, and purge in one ordered scenario"
    )]
    async fn owner_can_administer_distinct_secret_lifecycle_inventories() {
        let (_root, state) = state();
        enroll_local_owner(
            &state,
            ProtectedString::new(String::from("synthetic long password")),
        )
        .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let (cookie, csrf) = login_owner(&state).await;
        let namespace_request = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-smcv-csrf", &csrf)
            .header("idempotency-key", "synthetic-lifecycle-namespace")
            .body(Body::from(r#"{"parent_namespace_id":null,"metadata":{"name":"synthetic lifecycle namespace","description":null,"username":null,"tags":[]}}"#))
            .unwrap_or_else(|error| panic!("namespace request must build: {error}"));
        let namespace_response = router(state.clone())
            .oneshot(namespace_request)
            .await
            .unwrap_or_else(|error| panic!("namespace must respond: {error}"));
        assert_eq!(namespace_response.status(), StatusCode::CREATED);
        let namespace_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(namespace_response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("namespace body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("namespace body must parse: {error}"));
        let namespace = namespace_body["id"]
            .as_str()
            .map_or_else(|| panic!("namespace id must exist"), str::to_owned);
        let secret_request = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-smcv-csrf", &csrf)
            .header("idempotency-key", "synthetic-lifecycle-secret")
            .body(Body::from(format!(r#"{{"namespace_id":"{namespace}","metadata":{{"name":"synthetic lifecycle secret","description":null,"username":null,"tags":[]}},"value_base64":"dmFsdWU=","expires_at_unix_ms":null,"rotation_due_at_unix_ms":null}}"#)))
            .unwrap_or_else(|error| panic!("secret request must build: {error}"));
        let secret_response = router(state.clone())
            .oneshot(secret_request)
            .await
            .unwrap_or_else(|error| panic!("secret must respond: {error}"));
        assert_eq!(secret_response.status(), StatusCode::CREATED);
        let secret_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(secret_response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("secret body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("secret body must parse: {error}"));
        let secret = secret_body["id"]
            .as_str()
            .map_or_else(|| panic!("secret id must exist"), str::to_owned);

        let mutation = |path: String, body: String| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-smcv-csrf", &csrf)
                .body(Body::from(body))
                .unwrap_or_else(|error| panic!("lifecycle request must build: {error}"))
        };
        let archive = router(state.clone())
            .oneshot(mutation(
                format!("/api/v1/secrets/{secret}/archive"),
                r#"{"expected_revision":1}"#.to_owned(),
            ))
            .await
            .unwrap_or_else(|error| panic!("archive must respond: {error}"));
        assert_eq!(archive.status(), StatusCode::OK);

        let archived = Request::builder()
            .uri(format!(
                "/api/v1/secrets/lifecycle?namespace_id={namespace}&state=archived&limit=10"
            ))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("inventory request must build: {error}"));
        let archived = router(state.clone())
            .oneshot(archived)
            .await
            .unwrap_or_else(|error| panic!("inventory must respond: {error}"));
        let archived_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(archived.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("inventory body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("inventory body must parse: {error}"));
        assert_eq!(archived_body["secrets"][0]["lifecycle_state"], "archived");

        let restore = router(state.clone())
            .oneshot(mutation(
                format!("/api/v1/secrets/{secret}/restore"),
                r#"{"expected_revision":2}"#.to_owned(),
            ))
            .await
            .unwrap_or_else(|error| panic!("restore must respond: {error}"));
        assert_eq!(restore.status(), StatusCode::OK);
        let delete = router(state.clone())
            .oneshot(mutation(
                format!("/api/v1/secrets/{secret}/delete"),
                r#"{"expected_revision":3}"#.to_owned(),
            ))
            .await
            .unwrap_or_else(|error| panic!("delete must respond: {error}"));
        assert_eq!(delete.status(), StatusCode::OK);

        let deleted = Request::builder()
            .uri(format!(
                "/api/v1/secrets/lifecycle?namespace_id={namespace}&state=deleted&limit=10"
            ))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("deleted request must build: {error}"));
        let deleted = router(state.clone())
            .oneshot(deleted)
            .await
            .unwrap_or_else(|error| panic!("deleted inventory must respond: {error}"));
        let deleted_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(deleted.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("deleted body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("deleted body must parse: {error}"));
        assert!(deleted_body["secrets"][0]["deleted_at_unix_ms"].is_number());

        let purge = router(state.clone())
            .oneshot(mutation(
                format!("/api/v1/secrets/{secret}/purge"),
                format!(
                    r#"{{"expected_revision":4,"retention_cutoff_unix_ms":{}}}"#,
                    i64::MAX
                ),
            ))
            .await
            .unwrap_or_else(|error| panic!("purge must respond: {error}"));
        assert_eq!(purge.status(), StatusCode::NO_CONTENT);
        assert!(
            state
                .vault
                .store
                .secret(
                    super::secret_id(&secret).unwrap_or_else(|()| panic!("secret id must parse"))
                )
                .is_err()
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the durable-job test covers creation, polling, key non-persistence, and download"
    )]
    async fn backup_job_survives_request_and_downloads_only_after_verification() {
        let (root, state) = state();
        enroll_local_owner(
            &state,
            ProtectedString::new(String::from("synthetic long password")),
        )
        .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let login = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"synthetic long password"}"#))
            .unwrap_or_else(|error| panic!("login request must build: {error}"));
        let login = router(state.clone())
            .oneshot(login)
            .await
            .unwrap_or_else(|error| panic!("login must respond: {error}"));
        let cookie = login
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map_or_else(|| panic!("session cookie must exist"), str::to_owned);
        let login_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(login.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("login body must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("login body must parse: {error}"));
        let csrf = login_body["csrf_token"]
            .as_str()
            .unwrap_or_else(|| panic!("CSRF token must exist"));
        let create = Request::builder()
            .method("POST")
            .uri("/api/v1/backups")
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .header("x-smcv-csrf", csrf)
            .body(Body::from(r#"{"key_mode":"generated_recovery"}"#))
            .unwrap_or_else(|error| panic!("backup request must build: {error}"));
        let create = router(state.clone())
            .oneshot(create)
            .await
            .unwrap_or_else(|error| panic!("backup create must respond: {error}"));
        assert_eq!(create.status(), StatusCode::ACCEPTED);
        let create_body: serde_json::Value = serde_json::from_slice(
            &to_bytes(create.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|error| panic!("backup response must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("backup response must parse: {error}"));
        let job_id = create_body["job_id"]
            .as_str()
            .unwrap_or_else(|| panic!("job id must exist"));
        let recovery_key = create_body["recovery_key"]
            .as_str()
            .unwrap_or_else(|| panic!("display-once recovery key must exist"));

        let mut completed = false;
        for _attempt in 0..1_000 {
            let status = Request::builder()
                .uri(format!("/api/v1/backups/{job_id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("status request must build: {error}"));
            let status = router(state.clone())
                .oneshot(status)
                .await
                .unwrap_or_else(|error| panic!("status must respond: {error}"));
            assert_eq!(status.status(), StatusCode::OK);
            let value: serde_json::Value = serde_json::from_slice(
                &to_bytes(status.into_body(), 16 * 1024)
                    .await
                    .unwrap_or_else(|error| panic!("status body must read: {error}")),
            )
            .unwrap_or_else(|error| panic!("status body must parse: {error}"));
            assert!(value.get("recovery_key").is_none());
            if value["state"] == "completed" {
                completed = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(completed);
        let status_path = root
            .path()
            .join(format!("data/backup-artifacts/{job_id}.json"));
        let status_text = fs::read_to_string(status_path)
            .unwrap_or_else(|error| panic!("durable status must read: {error}"));
        assert!(!status_text.contains(recovery_key));

        let download = Request::builder()
            .uri(format!("/api/v1/backups/{job_id}/download"))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("download request must build: {error}"));
        let download = router(state.clone())
            .oneshot(download)
            .await
            .unwrap_or_else(|error| panic!("download must respond: {error}"));
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(
            download
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        let archive = to_bytes(download.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("archive download must read: {error}"));
        assert!(archive.starts_with(b"SMCVLT01"));

        let boundary = "smcv-synthetic-verification-boundary";
        let mut multipart = Vec::new();
        multipart.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"key_mode\"\r\n\r\ngenerated_recovery\r\n"
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{recovery_key}\r\n"
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"synthetic.smcvault\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(&archive);
        multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let verification = Request::builder()
            .method("POST")
            .uri("/api/v1/backup-verifications")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("cookie", &cookie)
            .header("x-smcv-csrf", csrf)
            .body(Body::from(multipart))
            .unwrap_or_else(|error| panic!("verification request must build: {error}"));
        let verification = router(state)
            .oneshot(verification)
            .await
            .unwrap_or_else(|error| panic!("verification must respond: {error}"));
        assert_eq!(verification.status(), StatusCode::OK);
        let report: serde_json::Value = serde_json::from_slice(
            &to_bytes(verification.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("verification report must read: {error}")),
        )
        .unwrap_or_else(|error| panic!("verification report must parse: {error}"));
        assert_eq!(report["integrity_verified"], true);
        assert_eq!(report["restore_tested"], true);
        let leftovers: Vec<_> = fs::read_dir(root.path().join("data/backup-artifacts"))
            .unwrap_or_else(|error| panic!("artifact directory must read: {error}"))
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[tokio::test]
    async fn body_header_and_password_work_are_bounded_before_processing() {
        let (_root, state) = state();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("content-type", "application/json")
            .body(Body::from(vec![b'x'; REQUEST_BODY_LIMIT + 1]))
            .unwrap_or_else(|error| panic!("oversize request must build: {error}"));
        let response = router(state.clone())
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("oversize request must respond: {error}"));
        assert_eq!(response.status(), 413);

        let mut builder = Request::builder().uri("/api/v1/openapi.json");
        for index in 0..65 {
            builder = builder.header(format!("x-synthetic-{index}"), "bounded");
        }
        let response = router(state.clone())
            .oneshot(
                builder
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("header request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("header request must respond: {error}"));
        assert_eq!(response.status(), 400);

        let mut permits = Vec::new();
        for _ in 0..4 {
            permits.push(
                state
                    .password_slots
                    .clone()
                    .try_acquire_owned()
                    .unwrap_or_else(|error| panic!("synthetic slot must acquire: {error}")),
            );
        }
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"synthetic long password"}"#))
            .unwrap_or_else(|error| panic!("saturation request must build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("saturation request must respond: {error}"));
        assert_eq!(response.status(), 429);
        drop(permits);
    }

    #[tokio::test]
    async fn operational_metrics_are_fixed_cardinality_and_contain_no_input() {
        let (_root, state) = state();
        let sentinel = "synthetic-metric-sentinel";
        let request = Request::builder()
            .uri(format!("/missing/{sentinel}"))
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("synthetic request must build: {error}"));
        let response = router(state.clone())
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("synthetic request must respond: {error}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let metrics = operational_router(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("metrics request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("metrics request must respond: {error}"));
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = to_bytes(metrics.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|error| panic!("metrics body must read: {error}"));
        let body = String::from_utf8(body.to_vec())
            .unwrap_or_else(|error| panic!("metrics body must be text: {error}"));
        assert!(body.contains("smcv_http_requests_total 1"));
        assert!(body.contains("class=\"client_error\""));
        assert!(!body.contains(sentinel));
        assert!(!body.contains("route="));
        assert!(!body.contains("vault_id"));
    }

    #[test]
    fn login_rate_limit_is_per_peer_bounded_and_recovers_after_window() {
        let limiter = super::LoginRateLimiter::default();
        let first = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
        let second = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 11));
        for _ in 0..super::LOGIN_ATTEMPTS_PER_WINDOW {
            assert!(limiter.allow(first, 1_800_000_000_000, super::LOGIN_ATTEMPTS_PER_WINDOW));
        }
        assert!(!limiter.allow(first, 1_800_000_000_001, super::LOGIN_ATTEMPTS_PER_WINDOW));
        assert!(limiter.allow(second, 1_800_000_000_001, super::LOGIN_ATTEMPTS_PER_WINDOW));
        assert!(limiter.allow(
            first,
            1_800_000_000_000 + super::LOGIN_WINDOW_MS,
            super::LOGIN_ATTEMPTS_PER_WINDOW
        ));

        let first_credential = super::AuthenticationRateKey::ApplicationCredential([0x11; 12]);
        let second_credential = super::AuthenticationRateKey::ApplicationCredential([0x22; 12]);
        for _ in 0..super::BEARER_ATTEMPTS_PER_WINDOW {
            assert!(limiter.allow(
                first_credential,
                1_800_000_100_000,
                super::BEARER_ATTEMPTS_PER_WINDOW
            ));
        }
        assert!(!limiter.allow(
            first_credential,
            1_800_000_100_001,
            super::BEARER_ATTEMPTS_PER_WINDOW
        ));
        assert!(limiter.allow(
            second_credential,
            1_800_000_100_001,
            super::BEARER_ATTEMPTS_PER_WINDOW
        ));
    }

    #[tokio::test]
    async fn unauthenticated_passkey_ceremonies_have_an_independent_rate_limit() {
        let (_root, state) = state();
        for _ in 0..super::PASSKEY_ATTEMPTS_PER_WINDOW {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/session/passkeys/authentication/options")
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("passkey request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("passkey request must respond: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let limited = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session/passkeys/authentication/options")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("limited request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("limited request must respond: {error}"));
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let password = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session/password")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"synthetic long password"}"#))
                    .unwrap_or_else(|error| panic!("password request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("password request must respond: {error}"));
        assert_eq!(password.status(), StatusCode::UNAUTHORIZED);
    }
}
