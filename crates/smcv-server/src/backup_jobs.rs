use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use axum::{
    Json,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use smcv_app::RequestPrincipal;
use smcv_backup::{ArchiveKey, RecoveryKey};
use tower::ServiceExt as _;
use tower_http::services::ServeFile;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ApiError, ApiState, authenticate_owner, map_vault_error, now_unix_ms, request_id};

const MAX_JOBS: usize = 32;
const JOB_TTL_MS: i64 = 15 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JobState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BackupJobRecord {
    job_id: Uuid,
    state: JobState,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    archive_id: Option<Uuid>,
    archive_bytes: Option<u64>,
    record_count: Option<u64>,
    downloaded: bool,
    error_code: Option<String>,
}

/// Durable safe-status registry for ephemeral encrypted server artifacts.
pub(super) struct BackupJobRegistry {
    directory: PathBuf,
    jobs: Mutex<HashMap<Uuid, BackupJobRecord>>,
}

impl BackupJobRegistry {
    #[cfg(unix)]
    pub(super) fn open(directory: &Path) -> Result<Self, std::io::Error> {
        if !directory.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "backup artifact directory is not restrictive",
            ));
        }
        let registry = Self {
            directory: directory.to_path_buf(),
            jobs: Mutex::new(HashMap::new()),
        };
        registry.load_statuses()?;
        Ok(registry)
    }

    fn load_statuses(&self) -> Result<(), std::io::Error> {
        let mut loaded = HashMap::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json")
                || entry.metadata()?.len() > 64 * 1024
            {
                continue;
            }
            let mut record: BackupJobRecord =
                serde_json::from_reader(BufReader::new(File::open(entry.path())?))
                    .map_err(std::io::Error::other)?;
            if matches!(record.state, JobState::Pending | JobState::Running) {
                record.state = JobState::Failed;
                record.error_code = Some("interrupted".to_owned());
                record.updated_at_unix_ms = now_unix_ms();
                self.persist(&record)?;
            }
            loaded.insert(record.job_id, record);
        }
        *self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))? = loaded;
        Ok(())
    }

    fn create(&self, now: i64) -> Result<BackupJobRecord, std::io::Error> {
        self.cleanup_expired(now)?;
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))?;
        if jobs.len() >= MAX_JOBS {
            return Err(std::io::Error::other("backup job quota reached"));
        }
        let record = BackupJobRecord {
            job_id: Uuid::new_v4(),
            state: JobState::Pending,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(JOB_TTL_MS),
            archive_id: None,
            archive_bytes: None,
            record_count: None,
            downloaded: false,
            error_code: None,
        };
        self.persist(&record)?;
        jobs.insert(record.job_id, record.clone());
        Ok(record)
    }

    fn update(
        &self,
        job_id: Uuid,
        update: impl FnOnce(&mut BackupJobRecord),
    ) -> Result<(), std::io::Error> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))?;
        let record = jobs
            .get_mut(&job_id)
            .ok_or_else(|| std::io::Error::other("backup job missing"))?;
        update(record);
        record.updated_at_unix_ms = now_unix_ms();
        self.persist(record)
    }

    fn get(&self, job_id: Uuid) -> Option<BackupJobRecord> {
        self.jobs.lock().ok()?.get(&job_id).cloned()
    }

    fn cleanup_expired(&self, now: i64) -> Result<(), std::io::Error> {
        let expired = {
            let mut jobs = self
                .jobs
                .lock()
                .map_err(|_| std::io::Error::other("job registry unavailable"))?;
            let expired: Vec<Uuid> = jobs
                .iter()
                .filter_map(|(id, job)| (job.expires_at_unix_ms <= now).then_some(*id))
                .collect();
            for id in &expired {
                jobs.remove(id);
            }
            expired
        };
        for id in expired {
            remove_if_exists(&self.artifact_path(id))?;
            remove_if_exists(&self.status_path(id))?;
        }
        Ok(())
    }

    fn remove(&self, job_id: Uuid) -> Result<(), std::io::Error> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))?;
        let _removed = jobs.remove(&job_id);
        remove_if_exists(&self.artifact_path(job_id))?;
        remove_if_exists(&self.status_path(job_id))?;
        Ok(())
    }

    fn persist(&self, record: &BackupJobRecord) -> Result<(), std::io::Error> {
        let temporary = self
            .directory
            .join(format!(".status-{}.tmp", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, record).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, self.status_path(record.job_id))?;
        File::open(&self.directory)?.sync_all()
    }

    fn artifact_path(&self, job_id: Uuid) -> PathBuf {
        self.directory.join(format!("{job_id}.smcvault"))
    }
    fn status_path(&self, job_id: Uuid) -> PathBuf {
        self.directory.join(format!("{job_id}.json"))
    }
}

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

#[derive(Deserialize)]
pub(super) struct CreateBackupRequest {
    key_mode: String,
    passphrase: Option<Zeroizing<String>>,
}

#[derive(Serialize)]
pub(super) struct CreateBackupResponse {
    job_id: Uuid,
    recovery_key: Option<String>,
    expires_at_unix_ms: i64,
}

#[derive(Serialize)]
pub(super) struct BackupStatusResponse {
    job_id: Uuid,
    state: JobState,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    archive_id: Option<Uuid>,
    archive_bytes: Option<u64>,
    record_count: Option<u64>,
    downloaded: bool,
    error_code: Option<String>,
}

pub(super) async fn create_backup(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(mut input): Json<CreateBackupRequest>,
) -> Result<(StatusCode, Json<CreateBackupResponse>), ApiError> {
    let now = now_unix_ms();
    let request = request_id(&headers);
    let owner = authenticate_owner(&state, &headers, true, now)?;
    state
        .vault
        .authorized(RequestPrincipal::Owner(owner), request, now)
        .map_err(|_| ApiError::authentication(request))?
        .authorize_backup_create()
        .map_err(|error| map_vault_error(error, request))?;
    let (key, recovery_key) = match input.key_mode.as_str() {
        "generated_recovery" if input.passphrase.is_none() => {
            let recovery = RecoveryKey::generate().map_err(|_| ApiError::unavailable(request))?;
            let exposed = recovery.expose_once();
            (OwnedArchiveKey::Recovery(recovery), Some(exposed))
        }
        "passphrase" => {
            let passphrase = input
                .passphrase
                .take()
                .ok_or_else(|| ApiError::invalid(request))?;
            if passphrase.len() < 16 {
                return Err(ApiError::invalid(request));
            }
            (OwnedArchiveKey::Passphrase(passphrase), None)
        }
        _ => return Err(ApiError::invalid(request)),
    };
    let job = state
        .backup_jobs
        .create(now)
        .map_err(|_| ApiError::unavailable(request))?;
    let jobs = Arc::clone(&state.backup_jobs);
    let vault = Arc::clone(&state.vault);
    let artifact = jobs.artifact_path(job.job_id);
    let job_id = job.job_id;
    tokio::task::spawn_blocking(move || {
        let _running = jobs.update(job_id, |record| record.state = JobState::Running);
        if let Ok(report) = vault.create_backup_file(&artifact, key.borrowed(), now_unix_ms()) {
            let _completed = jobs.update(job_id, |record| {
                record.state = JobState::Completed;
                record.archive_id = Some(report.archive_id);
                record.archive_bytes = Some(report.archive_bytes);
                record.record_count = Some(report.record_count);
            });
        } else {
            let _cleanup = remove_if_exists(&artifact);
            let _failed = jobs.update(job_id, |record| {
                record.state = JobState::Failed;
                record.error_code = Some("backup_failed".to_owned());
            });
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(CreateBackupResponse {
            job_id,
            recovery_key,
            expires_at_unix_ms: job.expires_at_unix_ms,
        }),
    ))
}

pub(super) async fn backup_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<BackupStatusResponse>, ApiError> {
    let request = request_id(&headers);
    authorize_inspect(&state, &headers, request)?;
    state
        .backup_jobs
        .cleanup_expired(now_unix_ms())
        .map_err(|_| ApiError::unavailable(request))?;
    let job_id = parse_job_id(&id, request)?;
    let job = state
        .backup_jobs
        .get(job_id)
        .filter(|job| job.expires_at_unix_ms > now_unix_ms())
        .ok_or_else(|| ApiError::not_found(request))?;
    Ok(Json(status_response(job)))
}

pub(super) async fn download_backup(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let request_id_value = request_id(&headers);
    authorize_inspect(&state, &headers, request_id_value)?;
    state
        .backup_jobs
        .cleanup_expired(now_unix_ms())
        .map_err(|_| ApiError::unavailable(request_id_value))?;
    let job_id = parse_job_id(&id, request_id_value)?;
    let job = state
        .backup_jobs
        .get(job_id)
        .filter(|job| job.expires_at_unix_ms > now_unix_ms())
        .ok_or_else(|| ApiError::not_found(request_id_value))?;
    if job.state != JobState::Completed {
        return Err(ApiError::not_found(request_id_value));
    }
    let request = Request::builder()
        .body(Body::empty())
        .map_err(|_| ApiError::unavailable(request_id_value))?;
    let served = ServeFile::new(state.backup_jobs.artifact_path(job_id))
        .oneshot(request)
        .await
        .map_err(|_| ApiError::unavailable(request_id_value))?;
    if served.status() != StatusCode::OK {
        return Err(ApiError::not_found(request_id_value));
    }
    let _updated = state
        .backup_jobs
        .update(job_id, |record| record.downloaded = true);
    let (parts, body) = served.into_parts();
    let mut response = Response::from_parts(parts, Body::new(body));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{job_id}.smcvault\""))
            .map_err(|_| ApiError::unavailable(request_id_value))?,
    );
    Ok(response)
}

pub(super) async fn delete_backup(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, ApiError> {
    let request = request_id(&headers);
    authorize_inspect(&state, &headers, request)?;
    let job_id = parse_job_id(&id, request)?;
    let job = state
        .backup_jobs
        .get(job_id)
        .ok_or_else(|| ApiError::not_found(request))?;
    if matches!(job.state, JobState::Pending | JobState::Running) {
        return Err(ApiError::invalid(request));
    }
    state
        .backup_jobs
        .remove(job_id)
        .map_err(|_| ApiError::unavailable(request))?;
    Ok(StatusCode::NO_CONTENT)
}

fn authorize_inspect(
    state: &ApiState,
    headers: &HeaderMap,
    request: smcv_core::RequestId,
) -> Result<(), ApiError> {
    let now = now_unix_ms();
    let owner = authenticate_owner(state, headers, false, now)?;
    state
        .vault
        .authorized(RequestPrincipal::Owner(owner), request, now)
        .map_err(|_| ApiError::authentication(request))?
        .authorize_backup_inspect()
        .map_err(|error| map_vault_error(error, request))
}

fn parse_job_id(value: &str, request: smcv_core::RequestId) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::not_found(request))
}

fn status_response(job: BackupJobRecord) -> BackupStatusResponse {
    BackupStatusResponse {
        job_id: job.job_id,
        state: job.state,
        created_at_unix_ms: job.created_at_unix_ms,
        updated_at_unix_ms: job.updated_at_unix_ms,
        expires_at_unix_ms: job.expires_at_unix_ms,
        archive_id: job.archive_id,
        archive_bytes: job.archive_bytes,
        record_count: job.record_count,
        downloaded: job.downloaded,
        error_code: job.error_code,
    }
}

fn remove_if_exists(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use tempfile::TempDir;

    use super::{BackupJobRegistry, JobState};

    #[test]
    fn process_restart_durably_fails_an_interrupted_job() -> Result<(), std::io::Error> {
        let root = TempDir::new()?;
        let directory = root.path().join("jobs");
        let registry = BackupJobRegistry::open(&directory)?;
        let job = registry.create(1_800_000_300_000)?;
        registry.update(job.job_id, |record| record.state = JobState::Running)?;
        drop(registry);

        let reopened = BackupJobRegistry::open(&directory)?;
        let recovered = reopened
            .get(job.job_id)
            .ok_or_else(|| std::io::Error::other("recovered job missing"))?;
        assert_eq!(recovered.state, JobState::Failed);
        assert_eq!(recovered.error_code.as_deref(), Some("interrupted"));
        Ok(())
    }
}
