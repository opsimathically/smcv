use std::{
    error::Error,
    fs::{self, OpenOptions},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, RequestExt as _, Router,
    extract::{DefaultBodyLimit, Multipart, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use smcv_app::{CredentialRestoreMode, InitializedVault};
use smcv_backup::{ArchiveKey, KeyMode, RecoveryKey, VerifiedArchive};
use subtle::ConstantTimeEq as _;
use tokio::{io::AsyncWriteExt as _, net::TcpListener, sync::Notify};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CHANNEL_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 4 * 1024;

const INDEX: &str = include_str!("../recovery_web/index.html");
const STYLES: &str = include_str!("../recovery_web/styles.css");
const SCRIPT: &str = include_str!("../recovery_web/app.js");

enum OwnedArchiveKey {
    Passphrase(Zeroizing<String>),
    Recovery(RecoveryKey),
}

impl OwnedArchiveKey {
    fn borrowed(&self) -> ArchiveKey<'_> {
        match self {
            Self::Passphrase(value) => ArchiveKey::Passphrase(value.as_bytes()),
            Self::Recovery(value) => ArchiveKey::Recovery(value),
        }
    }
}

struct PendingRestore {
    archive_path: PathBuf,
    key: OwnedArchiveKey,
    verified: VerifiedArchive,
}

struct RecoveryState {
    claim_digest: [u8; 32],
    session_digest: Mutex<Option<[u8; 32]>>,
    origin: String,
    expires_at_unix_ms: i64,
    database_path: PathBuf,
    root_key_path: PathBuf,
    workspace: PathBuf,
    claimed: AtomicBool,
    reserved: AtomicBool,
    consumed: AtomicBool,
    pending: Mutex<Option<PendingRestore>>,
    shutdown: Notify,
}

#[derive(Serialize)]
struct VerificationResponse {
    archive_id: Uuid,
    format_version: u16,
    logical_vault_id: Uuid,
    source_recovery_epoch: u64,
    created_at_unix_ms: i64,
    record_count: u64,
    logical_bytes: u64,
    expires_at_unix_ms: i64,
}

#[derive(Deserialize)]
struct ActivateRequest {
    archive_id: Uuid,
    credential_mode: String,
}

#[derive(Serialize)]
struct ActivationResponse {
    archive_id: Uuid,
    vault_id: String,
    installation_id: String,
    recovery_epoch: u64,
    imported_records: u64,
    imported_audit_events: u64,
    revoked_application_credentials: u64,
    disabled_source_bound_authenticators: u64,
    status: &'static str,
}

#[derive(Serialize)]
struct LocalProblem {
    message: &'static str,
}

#[derive(Deserialize)]
struct ClaimRequest {
    authorization_code: Zeroizing<String>,
}

#[derive(Serialize)]
struct ClaimResponse {
    claimed: bool,
}

struct RecoveryError(StatusCode, &'static str);

impl IntoResponse for RecoveryError {
    fn into_response(self) -> Response {
        (self.0, Json(LocalProblem { message: self.1 })).into_response()
    }
}

pub(super) async fn run(database: PathBuf, root_key: PathBuf) -> Result<(), Box<dyn Error>> {
    if database.exists() || root_key.exists() || database == root_key {
        return Err("recovery destinations must be distinct brand-new paths".into());
    }
    let database_parent = database
        .parent()
        .ok_or("database destination must have a parent directory")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(database_parent)?;
    let workspace = database_parent.join(format!(".smcv-recovery-{}", Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&workspace)?;

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let address = listener.local_addr()?;
    let origin = format!("http://127.0.0.1:{}", address.port());
    let token = generate_token()?;
    let expires_at_unix_ms = now_unix_ms().saturating_add(
        i64::try_from(CHANNEL_TTL.as_millis()).map_err(|_| "channel lifetime is invalid")?,
    );
    let state = Arc::new(RecoveryState {
        claim_digest: digest(token.as_bytes()),
        session_digest: Mutex::new(None),
        origin: origin.clone(),
        expires_at_unix_ms,
        database_path: database,
        root_key_path: root_key,
        workspace: workspace.clone(),
        claimed: AtomicBool::new(false),
        reserved: AtomicBool::new(false),
        consumed: AtomicBool::new(false),
        pending: Mutex::new(None),
        shutdown: Notify::new(),
    });
    let app = recovery_router(Arc::clone(&state));

    println!("Open this local single-use recovery URL in a browser:");
    println!("{origin}/");
    println!("Local recovery authorization code: {}", token.as_str());
    println!("The channel expires in 10 minutes and stops after one activation attempt.");
    let shutdown_state = Arc::clone(&state);
    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                () = shutdown_state.shutdown.notified() => {},
                () = tokio::time::sleep(CHANNEL_TTL) => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        })
        .await;
    let _cleanup = fs::remove_dir_all(&workspace);
    server_result?;
    if state.consumed.load(Ordering::Acquire) {
        println!("recovery_channel=consumed");
    } else {
        println!("recovery_channel=closed_without_activation");
    }
    Ok(())
}

fn recovery_router(state: Arc<RecoveryState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/recovery/claim", post(claim_channel))
        .route(
            "/api/recovery/verify",
            post(verify_archive).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .route("/api/recovery/activate", post(activate_restore))
        .fallback(StatusCode::NOT_FOUND)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn generate_token() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes)?;
    Ok(Zeroizing::new(hex::encode(*bytes)))
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn styles() -> Response {
    static_asset(STYLES, "text/css; charset=utf-8")
}

async fn script() -> Response {
    static_asset(SCRIPT, "text/javascript; charset=utf-8")
}

fn static_asset(body: &'static str, content_type: &'static str) -> Response {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
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
    response
}

fn validate_origin(state: &RecoveryState, headers: &HeaderMap) -> Result<(), RecoveryError> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        != Some(state.origin.as_str())
    {
        return Err(RecoveryError(
            StatusCode::FORBIDDEN,
            "Recovery request rejected.",
        ));
    }
    Ok(())
}

fn authorize(state: &RecoveryState, headers: &HeaderMap) -> Result<(), RecoveryError> {
    if now_unix_ms() >= state.expires_at_unix_ms || state.consumed.load(Ordering::Acquire) {
        return Err(RecoveryError(
            StatusCode::GONE,
            "The recovery channel is no longer available.",
        ));
    }
    validate_origin(state, headers)?;
    let supplied = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == "smcv_recovery_session").then_some(value)
            })
        })
        .ok_or(RecoveryError(
            StatusCode::UNAUTHORIZED,
            "Recovery authorization is missing.",
        ))?;
    let expected = state
        .session_digest
        .lock()
        .map_err(|_| {
            RecoveryError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Recovery state is unavailable.",
            )
        })?
        .ok_or(RecoveryError(
            StatusCode::UNAUTHORIZED,
            "Recovery authorization is missing.",
        ))?;
    if !bool::from(digest(supplied.as_bytes()).ct_eq(&expected)) {
        return Err(RecoveryError(
            StatusCode::UNAUTHORIZED,
            "Recovery authorization is invalid.",
        ));
    }
    Ok(())
}

async fn claim_channel(
    State(state): State<Arc<RecoveryState>>,
    request: axum::extract::Request,
) -> Result<Response, RecoveryError> {
    if now_unix_ms() >= state.expires_at_unix_ms || state.claimed.load(Ordering::Acquire) {
        return Err(RecoveryError(
            StatusCode::GONE,
            "The recovery channel is no longer available.",
        ));
    }
    validate_origin(&state, request.headers())?;
    let body = axum::body::to_bytes(request.into_body(), 4 * 1024)
        .await
        .map_err(|_| {
            RecoveryError(
                StatusCode::BAD_REQUEST,
                "Recovery authorization is invalid.",
            )
        })?;
    let claim: ClaimRequest = serde_json::from_slice(&body).map_err(|_| {
        RecoveryError(
            StatusCode::BAD_REQUEST,
            "Recovery authorization is invalid.",
        )
    })?;
    if !bool::from(digest(claim.authorization_code.trim().as_bytes()).ct_eq(&state.claim_digest))
        || state
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(RecoveryError(
            StatusCode::UNAUTHORIZED,
            "Recovery authorization is invalid.",
        ));
    }
    let session = generate_token().map_err(|_| {
        RecoveryError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery authorization is unavailable.",
        )
    })?;
    *state.session_digest.lock().map_err(|_| {
        RecoveryError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery state is unavailable.",
        )
    })? = Some(digest(session.as_bytes()));
    let mut response = Json(ClaimResponse { claimed: true }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "smcv_recovery_session={}; Path=/; HttpOnly; SameSite=Strict",
            session.as_str()
        ))
        .map_err(|_| {
            RecoveryError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Recovery authorization is unavailable.",
            )
        })?,
    );
    Ok(response)
}

async fn verify_archive(
    State(state): State<Arc<RecoveryState>>,
    request: axum::extract::Request,
) -> Result<Json<VerificationResponse>, RecoveryError> {
    authorize(&state, request.headers())?;
    if state
        .reserved
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(RecoveryError(
            StatusCode::CONFLICT,
            "A recovery archive is already staged.",
        ));
    }
    let archive_path = state.workspace.join(format!("{}.smcvault", Uuid::new_v4()));
    let mut multipart = request
        .extract_with_state::<Multipart, _, _>(&state)
        .await
        .map_err(|_| RecoveryError(StatusCode::BAD_REQUEST, "The recovery upload is invalid."))?;
    let received = receive_upload(&mut multipart, &archive_path).await;
    let (mode, supplied_key) = match received {
        Ok(received) => received,
        Err(error) => {
            state.reserved.store(false, Ordering::Release);
            let _cleanup = fs::remove_file(&archive_path);
            return Err(error);
        }
    };
    let verify_path = archive_path.clone();
    let verified = tokio::task::spawn_blocking(move || {
        prepare_key_and_verify(&verify_path, &mode, supplied_key)
    })
    .await;
    let Ok(verified) = verified else {
        state.reserved.store(false, Ordering::Release);
        let _cleanup = fs::remove_file(&archive_path);
        return Err(RecoveryError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery verification is unavailable.",
        ));
    };
    let Ok((verified, key)) = verified else {
        state.reserved.store(false, Ordering::Release);
        let _cleanup = fs::remove_file(&archive_path);
        return Err(RecoveryError(
            StatusCode::BAD_REQUEST,
            "The archive or separate key could not be verified.",
        ));
    };
    let response = VerificationResponse {
        archive_id: verified.header.archive_id,
        format_version: smcv_backup::FORMAT_VERSION,
        logical_vault_id: verified.metadata.logical_vault_id,
        source_recovery_epoch: verified.metadata.source_recovery_epoch,
        created_at_unix_ms: verified.metadata.created_at_unix_ms,
        record_count: verified.record_count,
        logical_bytes: verified.logical_bytes,
        expires_at_unix_ms: state.expires_at_unix_ms,
    };
    *state.pending.lock().map_err(|_| {
        RecoveryError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery state is unavailable.",
        )
    })? = Some(PendingRestore {
        archive_path,
        key,
        verified,
    });
    Ok(Json(response))
}

#[allow(
    clippy::too_many_lines,
    reason = "the hostile multipart parser keeps all field-count, key-size, file-size, and restrictive-write checks visible"
)]
async fn receive_upload(
    multipart: &mut Multipart,
    archive_path: &Path,
) -> Result<(String, Zeroizing<String>), RecoveryError> {
    let mut key_mode = None;
    let mut key = None;
    let mut archive_seen = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| RecoveryError(StatusCode::BAD_REQUEST, "The recovery upload is invalid."))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "key_mode" | "key" => {
                let mut value = Zeroizing::new(Vec::new());
                while let Some(chunk) = field.chunk().await.map_err(|_| {
                    RecoveryError(StatusCode::BAD_REQUEST, "The recovery upload is invalid.")
                })? {
                    if value.len().saturating_add(chunk.len()) > MAX_KEY_BYTES {
                        return Err(RecoveryError(
                            StatusCode::BAD_REQUEST,
                            "A recovery field is too large.",
                        ));
                    }
                    value.extend_from_slice(&chunk);
                }
                if name == "key_mode" {
                    let value = String::from_utf8(value.to_vec()).map_err(|_| {
                        RecoveryError(StatusCode::BAD_REQUEST, "A recovery field is invalid.")
                    })?;
                    if key_mode.replace(value).is_some() {
                        return Err(RecoveryError(
                            StatusCode::BAD_REQUEST,
                            "A recovery field was repeated.",
                        ));
                    }
                } else if key
                    .replace(protected_utf8(value).map_err(|()| {
                        RecoveryError(StatusCode::BAD_REQUEST, "A recovery field is invalid.")
                    })?)
                    .is_some()
                {
                    return Err(RecoveryError(
                        StatusCode::BAD_REQUEST,
                        "A recovery field was repeated.",
                    ));
                }
            }
            "archive" if !archive_seen => {
                archive_seen = true;
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(archive_path)
                    .map_err(|_| {
                        RecoveryError(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Temporary recovery storage is unavailable.",
                        )
                    })?;
                let mut file = tokio::fs::File::from_std(file);
                let mut total = 0_u64;
                while let Some(chunk) = field.chunk().await.map_err(|_| {
                    RecoveryError(StatusCode::BAD_REQUEST, "The recovery upload is invalid.")
                })? {
                    total = total
                        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                            RecoveryError(StatusCode::BAD_REQUEST, "The archive is too large.")
                        })?)
                        .ok_or(RecoveryError(
                            StatusCode::BAD_REQUEST,
                            "The archive is too large.",
                        ))?;
                    if total > MAX_ARCHIVE_BYTES {
                        return Err(RecoveryError(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "The archive is too large.",
                        ));
                    }
                    file.write_all(&chunk).await.map_err(|_| {
                        RecoveryError(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Temporary recovery storage is unavailable.",
                        )
                    })?;
                }
                file.sync_all().await.map_err(|_| {
                    RecoveryError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Temporary recovery storage is unavailable.",
                    )
                })?;
                if total == 0 {
                    return Err(RecoveryError(
                        StatusCode::BAD_REQUEST,
                        "The archive is empty.",
                    ));
                }
            }
            _ => {
                return Err(RecoveryError(
                    StatusCode::BAD_REQUEST,
                    "The recovery upload contains an unsupported field.",
                ));
            }
        }
    }
    match (key_mode, key, archive_seen) {
        (Some(mode), Some(key), true) => Ok((mode, key)),
        _ => Err(RecoveryError(
            StatusCode::BAD_REQUEST,
            "The recovery upload is incomplete.",
        )),
    }
}

fn protected_utf8(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, ()> {
    match String::from_utf8(std::mem::take(bytes.as_mut())) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut rejected = error.into_bytes();
            rejected.zeroize();
            Err(())
        }
    }
}

fn prepare_key_and_verify(
    archive_path: &Path,
    mode: &str,
    supplied_key: Zeroizing<String>,
) -> Result<(VerifiedArchive, OwnedArchiveKey), ()> {
    let header = InitializedVault::inspect_backup_file(archive_path).map_err(|_| ())?;
    let key = match (header.key_mode, mode) {
        (KeyMode::PassphraseArgon2id, "passphrase") => OwnedArchiveKey::Passphrase(supplied_key),
        (KeyMode::RecoveryKey, "generated_recovery" | "recovery_key") => {
            OwnedArchiveKey::Recovery(RecoveryKey::parse(supplied_key.trim()).map_err(|_| ())?)
        }
        _ => return Err(()),
    };
    let verified =
        InitializedVault::verify_backup_file(archive_path, key.borrowed()).map_err(|_| ())?;
    Ok((verified, key))
}

#[allow(
    clippy::too_many_lines,
    reason = "the single-use activation handler keeps authorization, exact confirmation, consumption, restore, cleanup, and shutdown ordering visible"
)]
async fn activate_restore(
    State(state): State<Arc<RecoveryState>>,
    request: axum::extract::Request,
) -> Result<Response, RecoveryError> {
    authorize(&state, request.headers())?;
    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|_| {
            RecoveryError(
                StatusCode::BAD_REQUEST,
                "Activation confirmation is invalid.",
            )
        })?;
    let input: ActivateRequest = serde_json::from_slice(&body).map_err(|_| {
        RecoveryError(
            StatusCode::BAD_REQUEST,
            "Activation confirmation is invalid.",
        )
    })?;
    let credential_mode = match input.credential_mode.as_str() {
        "preserve" => CredentialRestoreMode::Preserve,
        "revoke" => CredentialRestoreMode::Revoke,
        _ => {
            return Err(RecoveryError(
                StatusCode::BAD_REQUEST,
                "Select an application credential recovery mode.",
            ));
        }
    };
    let pending = {
        let mut pending_guard = state.pending.lock().map_err(|_| {
            RecoveryError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Recovery state is unavailable.",
            )
        })?;
        let staged_archive_id = pending_guard
            .as_ref()
            .map(|pending| pending.verified.header.archive_id)
            .ok_or(RecoveryError(
                StatusCode::CONFLICT,
                "No verified archive is staged.",
            ))?;
        if staged_archive_id != input.archive_id {
            return Err(RecoveryError(
                StatusCode::CONFLICT,
                "The staged archive confirmation does not match.",
            ));
        }
        if state.consumed.swap(true, Ordering::AcqRel) {
            return Err(RecoveryError(
                StatusCode::GONE,
                "The recovery channel is no longer available.",
            ));
        }
        pending_guard.take().ok_or(RecoveryError(
            StatusCode::CONFLICT,
            "No verified archive is staged.",
        ))?
    };
    let database = state.database_path.clone();
    let root_key = state.root_key_path.clone();
    let archive_path = pending.archive_path.clone();
    let report = tokio::task::spawn_blocking(move || {
        let report = InitializedVault::restore_backup_file(
            &pending.archive_path,
            &database,
            &root_key,
            pending.key.borrowed(),
            credential_mode,
            now_unix_ms(),
        );
        let _cleanup = fs::remove_file(&pending.archive_path);
        report
    })
    .await;
    let shutdown = Arc::clone(&state);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.shutdown.notify_waiters();
    });
    let report = report
        .map_err(|_| {
            RecoveryError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Recovery activation is unavailable.",
            )
        })?
        .map_err(|_| {
            RecoveryError(
                StatusCode::BAD_REQUEST,
                "Recovery activation failed without making a ready partial vault.",
            )
        })?;
    let response = ActivationResponse {
        archive_id: report.archive_id,
        vault_id: report.vault_id.to_string(),
        installation_id: report.installation_id.to_string(),
        recovery_epoch: report.recovery_epoch,
        imported_records: report.imported_records,
        imported_audit_events: report.imported_audit_events,
        revoked_application_credentials: report.revoked_application_credentials,
        disabled_source_bound_authenticators: report.disabled_source_bound_authenticators,
        status: "ready",
    };
    let _cleanup = fs::remove_file(archive_path);
    let mut response = Json(response).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "smcv_recovery_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Mutex, atomic::AtomicBool},
    };

    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use smcv_app::{LocalSetupCapability, initialize_vault};
    use smcv_backup::RecoveryKey;
    use smcv_core::{ProtectedString, RequestId};
    use tempfile::TempDir;
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    use super::{INDEX, RecoveryState, SCRIPT, STYLES, digest, now_unix_ms, recovery_router};

    #[test]
    fn recovery_assets_are_self_contained_and_do_not_persist_authority() {
        for asset in [INDEX, STYLES, SCRIPT] {
            assert!(!asset.contains("https://"));
            assert!(!asset.contains("http://"));
        }
        assert!(!INDEX.contains("<script>"));
        assert!(!INDEX.contains(" style="));
        assert!(!SCRIPT.contains("localStorage"));
        assert!(!SCRIPT.contains("sessionStorage"));
        assert!(!SCRIPT.contains("innerHTML"));
        assert!(!SCRIPT.contains("location.hash"));
        assert!(!SCRIPT.contains("history."));
    }

    #[tokio::test]
    async fn recovery_document_has_isolation_and_capability_headers() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let state = Arc::new(RecoveryState {
            claim_digest: digest(b"synthetic-claim"),
            session_digest: Mutex::new(None),
            origin: "http://127.0.0.1:12345".to_owned(),
            expires_at_unix_ms: now_unix_ms().saturating_add(60_000),
            database_path: root.path().join("data/vault.sqlite"),
            root_key_path: root.path().join("provider/root.key"),
            workspace: root.path().join("workspace"),
            claimed: AtomicBool::new(false),
            reserved: AtomicBool::new(false),
            consumed: AtomicBool::new(false),
            pending: Mutex::new(None),
            shutdown: Notify::new(),
        });
        let response = recovery_router(state)
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("recovery request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("recovery request must respond: {error}"));
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
                .get("cross-origin-resource-policy")
                .and_then(|value| value.to_str().ok()),
            Some("same-origin")
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the recovery-channel test keeps claim, archive authentication, activation, and replay rejection in one ordered proof"
    )]
    async fn loopback_channel_authenticates_then_activates_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let source_database = root.path().join("source/data/vault.sqlite");
        let source_root = root.path().join("source/provider/root.key");
        let source = initialize_vault(&source_database, &source_root, now_unix_ms())?;
        source.enroll_local_owner(
            LocalSetupCapability::for_local_cli(),
            &ProtectedString::new("synthetic long owner password".to_owned()),
            RequestId::random(),
            now_unix_ms(),
        )?;
        let recovery_key = RecoveryKey::generate()?;
        let exposed_key = recovery_key.expose_once();
        let archive_path = root.path().join("source/portable.smcvault");
        source.create_backup_file(
            &archive_path,
            smcv_backup::ArchiveKey::Recovery(&recovery_key),
            now_unix_ms(),
        )?;
        let archive = fs::read(&archive_path)?;

        let workspace = root.path().join("channel");
        fs::create_dir(&workspace)?;
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let origin = "http://127.0.0.1:43123";
        let state = Arc::new(RecoveryState {
            claim_digest: digest(token.as_bytes()),
            session_digest: None.into(),
            origin: origin.to_owned(),
            expires_at_unix_ms: now_unix_ms() + 60_000,
            database_path: root.path().join("destination/data/vault.sqlite"),
            root_key_path: root.path().join("destination/provider/root.key"),
            workspace,
            claimed: false.into(),
            reserved: false.into(),
            consumed: false.into(),
            pending: None.into(),
            shutdown: tokio::sync::Notify::new(),
        });
        let rejected_claim = Request::builder()
            .method("POST")
            .uri("/api/recovery/claim")
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"authorization_code":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}"#,
            ))?;
        let rejected_claim = recovery_router(Arc::clone(&state))
            .oneshot(rejected_claim)
            .await?;
        assert_eq!(rejected_claim.status(), 401);
        let claim = Request::builder()
            .method("POST")
            .uri("/api/recovery/claim")
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"authorization_code":"{token}"}}"#)))?;
        let claim = recovery_router(Arc::clone(&state)).oneshot(claim).await?;
        assert_eq!(claim.status(), 200);
        let cookie = claim
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .ok_or("recovery cookie")?
            .to_owned();
        let replayed_claim = Request::builder()
            .method("POST")
            .uri("/api/recovery/claim")
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"authorization_code":"{token}"}}"#)))?;
        let replayed_claim = recovery_router(Arc::clone(&state))
            .oneshot(replayed_claim)
            .await?;
        assert_eq!(replayed_claim.status(), 410);
        let boundary = "synthetic-recovery-boundary";
        let mut multipart = Vec::new();
        multipart.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"key_mode\"\r\n\r\ngenerated_recovery\r\n").as_bytes());
        multipart.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{exposed_key}\r\n").as_bytes());
        multipart.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"portable.smcvault\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        multipart.extend_from_slice(&archive);
        multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let verify = Request::builder()
            .method("POST")
            .uri("/api/recovery/verify")
            .header("origin", origin)
            .header("cookie", &cookie)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(multipart))?;
        let verify = recovery_router(Arc::clone(&state)).oneshot(verify).await?;
        assert_eq!(verify.status(), 200);
        let verified: serde_json::Value =
            serde_json::from_slice(&to_bytes(verify.into_body(), 64 * 1024).await?)?;
        let archive_id = verified["archive_id"].as_str().ok_or("archive id")?;

        let activate = Request::builder()
            .method("POST")
            .uri("/api/recovery/activate")
            .header("origin", origin)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"archive_id":"{archive_id}","credential_mode":"preserve"}}"#
            )))?;
        let activate = recovery_router(Arc::clone(&state))
            .oneshot(activate)
            .await?;
        assert_eq!(activate.status(), 200);
        let report: serde_json::Value =
            serde_json::from_slice(&to_bytes(activate.into_body(), 64 * 1024).await?)?;
        assert_eq!(report["status"], "ready");
        assert!(state.database_path.exists());
        assert!(state.root_key_path.exists());

        let replay = Request::builder()
            .method("POST")
            .uri("/api/recovery/activate")
            .header("origin", origin)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from("{}"))?;
        let replay = recovery_router(state).oneshot(replay).await?;
        assert_eq!(replay.status(), 410);
        Ok(())
    }
}
