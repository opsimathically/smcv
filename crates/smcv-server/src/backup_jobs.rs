use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use axum::{
    Json, RequestExt as _,
    body::Body,
    extract::{Multipart, Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use smcv_app::{CredentialRestoreMode, InitializedVault, RequestPrincipal};
use smcv_backup::{ArchiveKey, KeyMode, RecoveryKey};
use tokio::io::AsyncWriteExt as _;
use tower::ServiceExt as _;
use tower_http::services::ServeFile;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{ApiError, ApiState, authenticate_owner, map_vault_error, now_unix_ms, request_id};

const MAX_JOBS: usize = 32;
const JOB_TTL_MS: i64 = 15 * 60 * 1_000;
const MAX_VERIFICATION_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_KEY_FIELD_BYTES: usize = 4 * 1024;

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
    #[serde(default)]
    format_version: Option<u16>,
    #[serde(default)]
    logical_vault_id: Option<Uuid>,
    #[serde(default)]
    source_recovery_epoch: Option<u64>,
    archive_bytes: Option<u64>,
    record_count: Option<u64>,
    #[serde(default, alias = "downloaded")]
    download_started: bool,
    error_code: Option<String>,
}

/// Durable safe-status registry for ephemeral encrypted server artifacts.
pub(super) struct BackupJobRegistry {
    directory: PathBuf,
    jobs: Mutex<HashMap<Uuid, BackupJobRecord>>,
}

struct RemoveFileOnDrop(PathBuf);

impl RemoveFileOnDrop {
    fn new(path: PathBuf) -> Self {
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _cleanup = remove_if_exists(&self.0);
    }
}

impl BackupJobRegistry {
    #[cfg(unix)]
    pub(super) fn open(directory: &Path) -> Result<Self, std::io::Error> {
        match directory.symlink_metadata() {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(directory)?;
            }
            Err(error) => return Err(error),
        }
        let metadata = directory.symlink_metadata()?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != current_effective_uid()?
        {
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
        let now = now_unix_ms();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with(".verify-") && name.ends_with(".smcvault"))
                || (name.starts_with(".status-") && name.ends_with(".tmp"))
            {
                remove_if_exists(&entry.path())?;
                continue;
            }
            if name.starts_with(".restore-drill-") && entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
                continue;
            }
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let file_type = entry.file_type()?;
            let metadata = entry.metadata()?;
            if !file_type.is_file() || metadata.len() > 64 * 1024 {
                return Err(std::io::Error::other("backup status file is invalid"));
            }
            let mut record: BackupJobRecord =
                serde_json::from_reader(BufReader::new(File::open(entry.path())?))
                    .map_err(std::io::Error::other)?;
            if name != format!("{}.json", record.job_id)
                || record.created_at_unix_ms < 0
                || record.updated_at_unix_ms < record.created_at_unix_ms
                || record.expires_at_unix_ms <= record.created_at_unix_ms
            {
                return Err(std::io::Error::other("backup status record is invalid"));
            }
            if matches!(record.state, JobState::Completed | JobState::Failed)
                && record.expires_at_unix_ms <= now
            {
                remove_if_exists(&self.artifact_path(record.job_id))?;
                remove_if_exists(&entry.path())?;
                continue;
            }
            if matches!(record.state, JobState::Pending | JobState::Running) {
                record.state = JobState::Failed;
                record.error_code = Some("interrupted".to_owned());
                record.updated_at_unix_ms = record.updated_at_unix_ms.max(now);
                record.expires_at_unix_ms = record
                    .updated_at_unix_ms
                    .saturating_add(JOB_TTL_MS)
                    .max(record.created_at_unix_ms.saturating_add(1));
                remove_if_exists(&self.artifact_path(record.job_id))?;
                self.persist(&record)?;
            }
            if loaded.len() >= MAX_JOBS {
                return Err(std::io::Error::other("backup job quota exceeded on disk"));
            }
            loaded.insert(record.job_id, record);
        }
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(job_id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".smcvault"))
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            if !loaded
                .get(&job_id)
                .is_some_and(|record| record.state == JobState::Completed)
            {
                remove_if_exists(&entry.path())?;
            }
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
            format_version: None,
            logical_vault_id: None,
            source_recovery_epoch: None,
            archive_bytes: None,
            record_count: None,
            download_started: false,
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
        let mut candidate = jobs
            .get(&job_id)
            .cloned()
            .ok_or_else(|| std::io::Error::other("backup job missing"))?;
        update(&mut candidate);
        candidate.updated_at_unix_ms = candidate.updated_at_unix_ms.max(now_unix_ms());
        self.persist(&candidate)?;
        jobs.insert(job_id, candidate);
        Ok(())
    }

    fn get(&self, job_id: Uuid) -> Option<BackupJobRecord> {
        self.jobs.lock().ok()?.get(&job_id).cloned()
    }

    fn list(&self) -> Vec<BackupJobRecord> {
        let Ok(jobs) = self.jobs.lock() else {
            return Vec::new();
        };
        let mut records: Vec<_> = jobs.values().cloned().collect();
        records.sort_by(|left, right| {
            right
                .created_at_unix_ms
                .cmp(&left.created_at_unix_ms)
                .then_with(|| right.job_id.cmp(&left.job_id))
        });
        records
    }

    fn cleanup_expired(&self, now: i64) -> Result<(), std::io::Error> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))?;
        let expired: Vec<Uuid> = jobs
            .iter()
            .filter_map(|(id, job)| {
                (matches!(job.state, JobState::Completed | JobState::Failed)
                    && job.expires_at_unix_ms <= now)
                    .then_some(*id)
            })
            .collect();
        for id in &expired {
            remove_if_exists(&self.artifact_path(*id))?;
            remove_if_exists(&self.status_path(*id))?;
        }
        for id in expired {
            jobs.remove(&id);
        }
        Ok(())
    }

    fn remove(&self, job_id: Uuid) -> Result<(), std::io::Error> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| std::io::Error::other("job registry unavailable"))?;
        remove_if_exists(&self.artifact_path(job_id))?;
        remove_if_exists(&self.status_path(job_id))?;
        let _removed = jobs.remove(&job_id);
        Ok(())
    }

    fn persist(&self, record: &BackupJobRecord) -> Result<(), std::io::Error> {
        let temporary = self
            .directory
            .join(format!(".status-{}.tmp", Uuid::new_v4()));
        let _cleanup = RemoveFileOnDrop::new(temporary.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, record).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, self.status_path(record.job_id))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn artifact_path(&self, job_id: Uuid) -> PathBuf {
        self.directory.join(format!("{job_id}.smcvault"))
    }
    fn status_path(&self, job_id: Uuid) -> PathBuf {
        self.directory.join(format!("{job_id}.json"))
    }
}

#[cfg(unix)]
fn current_effective_uid() -> Result<u32, std::io::Error> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| std::io::Error::other("effective user identity is unavailable"))
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
    recovery_key: Option<Zeroizing<String>>,
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
    format_version: Option<u16>,
    logical_vault_id: Option<Uuid>,
    source_recovery_epoch: Option<u64>,
    archive_bytes: Option<u64>,
    record_count: Option<u64>,
    download_started: bool,
    error_code: Option<String>,
}

#[derive(Serialize)]
pub(super) struct BackupPageResponse {
    backups: Vec<BackupStatusResponse>,
}

pub(super) async fn list_backups(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<BackupPageResponse>, ApiError> {
    let request = request_id(&headers);
    authorize_inspect(&state, &headers, request)?;
    state
        .backup_jobs
        .cleanup_expired(now_unix_ms())
        .map_err(|_| ApiError::unavailable(request))?;
    Ok(Json(BackupPageResponse {
        backups: state
            .backup_jobs
            .list()
            .into_iter()
            .map(status_response)
            .collect(),
    }))
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
            (
                OwnedArchiveKey::Recovery(recovery),
                Some(Zeroizing::new(exposed)),
            )
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
    let vault = Arc::clone(&state.vault);
    let logical_vault_id = Uuid::from_bytes(*vault.vault_id.as_bytes());
    let source_recovery_epoch = vault
        .store
        .installation()
        .map_err(|_| ApiError::unavailable(request))?
        .ok_or_else(|| ApiError::unavailable(request))?
        .recovery_epoch;
    let expensive_slot = Arc::clone(&state.archive_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::rate_limited(request))?;
    let job = state
        .backup_jobs
        .create(now)
        .map_err(|_| ApiError::unavailable(request))?;
    state
        .backup_jobs
        .update(job.job_id, |record| record.state = JobState::Running)
        .map_err(|_| ApiError::unavailable(request))?;
    let jobs = Arc::clone(&state.backup_jobs);
    let artifact = jobs.artifact_path(job.job_id);
    let job_id = job.job_id;
    tokio::task::spawn_blocking(move || {
        let _expensive_slot = expensive_slot;
        if let Ok(report) = vault.create_backup_file(&artifact, key.borrowed(), now_unix_ms()) {
            let completed = jobs.update(job_id, |record| {
                record.state = JobState::Completed;
                record.expires_at_unix_ms = now_unix_ms()
                    .max(record.created_at_unix_ms)
                    .saturating_add(JOB_TTL_MS);
                record.archive_id = Some(report.archive_id);
                record.format_version = Some(smcv_backup::FORMAT_VERSION);
                record.logical_vault_id = Some(logical_vault_id);
                record.source_recovery_epoch = Some(source_recovery_epoch);
                record.archive_bytes = Some(report.archive_bytes);
                record.record_count = Some(report.record_count);
            });
            if completed.is_err() {
                let _cleanup = remove_if_exists(&artifact);
                let _failed = jobs.update(job_id, |record| {
                    record.state = JobState::Failed;
                    record.expires_at_unix_ms = now_unix_ms()
                        .max(record.created_at_unix_ms)
                        .saturating_add(JOB_TTL_MS);
                    record.error_code = Some("status_persistence_failed".to_owned());
                });
            }
        } else {
            let _cleanup = remove_if_exists(&artifact);
            let _failed = jobs.update(job_id, |record| {
                record.state = JobState::Failed;
                record.expires_at_unix_ms = now_unix_ms()
                    .max(record.created_at_unix_ms)
                    .saturating_add(JOB_TTL_MS);
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
    state
        .backup_jobs
        .update(job_id, |record| record.download_started = true)
        .map_err(|_| ApiError::unavailable(request_id_value))?;
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

#[derive(Serialize)]
pub(super) struct BackupVerificationResponse {
    archive_id: Uuid,
    format_version: u16,
    logical_vault_id: Uuid,
    source_recovery_epoch: u64,
    created_at_unix_ms: i64,
    archive_bytes: u64,
    record_count: u64,
    logical_bytes: u64,
    integrity_verified: bool,
    restore_tested: bool,
    staged_recovery_epoch: u64,
}

/// Streams an owner-supplied archive to a restrictive temporary file, fully
/// verifies it, and performs a clean staging restore exercise before cleanup.
pub(super) async fn verify_uploaded_backup(
    State(state): State<ApiState>,
    request: axum::extract::Request,
) -> Result<Json<BackupVerificationResponse>, ApiError> {
    let headers = request.headers().clone();
    let request_id_value = request_id(&headers);
    let now = now_unix_ms();
    let owner = authenticate_owner(&state, &headers, true, now)?;
    state
        .vault
        .authorized(RequestPrincipal::Owner(owner), request_id_value, now)
        .map_err(|_| ApiError::authentication(request_id_value))?
        .authorize_backup_inspect()
        .map_err(|error| map_vault_error(error, request_id_value))?;
    let expensive_slot = Arc::clone(&state.archive_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::rate_limited(request_id_value))?;

    let upload_id = Uuid::new_v4();
    let archive_file = RemoveFileOnDrop::new(
        state
            .backup_jobs
            .directory
            .join(format!(".verify-{upload_id}.smcvault")),
    );
    let mut multipart = request
        .extract_with_state::<Multipart, _, _>(&state)
        .await
        .map_err(|_| ApiError::invalid(request_id_value))?;
    let received =
        receive_verification_upload(&mut multipart, archive_file.path(), request_id_value).await;
    let (supplied_mode, supplied_key, archive_bytes) = match received {
        Ok(received) => received,
        Err(error) => return Err(error),
    };
    let drill_directory = state
        .backup_jobs
        .directory
        .join(format!(".restore-drill-{upload_id}"));
    let cleanup_drill = drill_directory.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _expensive_slot = expensive_slot;
        let result = verify_and_restore_test(
            archive_file.path(),
            &drill_directory,
            &supplied_mode,
            supplied_key,
            archive_bytes,
        );
        let _drill_cleanup = fs::remove_dir_all(&drill_directory);
        result
    })
    .await
    .map_err(|_| ApiError::unavailable(request_id_value));
    if result.is_err() {
        let _drill_cleanup = fs::remove_dir_all(&cleanup_drill);
    }
    result?
        .map(Json)
        .map_err(|()| ApiError::invalid(request_id_value))
}

async fn receive_verification_upload(
    multipart: &mut Multipart,
    archive_path: &Path,
    request: smcv_core::RequestId,
) -> Result<(String, Zeroizing<String>, u64), ApiError> {
    let mut key_mode = None;
    let mut key = None;
    let mut archive_bytes = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::invalid(request))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "key_mode" | "key" => {
                let mut value = Zeroizing::new(Vec::new());
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| ApiError::invalid(request))?
                {
                    if value.len().saturating_add(chunk.len()) > MAX_KEY_FIELD_BYTES {
                        return Err(ApiError::invalid(request));
                    }
                    value.extend_from_slice(&chunk);
                }
                if name == "key_mode" {
                    let value = String::from_utf8(value.to_vec())
                        .map_err(|_| ApiError::invalid(request))?;
                    if key_mode.replace(value).is_some() {
                        return Err(ApiError::invalid(request));
                    }
                } else if key
                    .replace(protected_utf8(value).map_err(|()| ApiError::invalid(request))?)
                    .is_some()
                {
                    return Err(ApiError::invalid(request));
                }
            }
            "archive" => {
                if archive_bytes.is_some() {
                    return Err(ApiError::invalid(request));
                }
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(archive_path)
                    .map_err(|_| ApiError::unavailable(request))?;
                let mut file = tokio::fs::File::from_std(file);
                let mut total = 0_u64;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| ApiError::invalid(request))?
                {
                    total = total
                        .checked_add(
                            u64::try_from(chunk.len()).map_err(|_| ApiError::invalid(request))?,
                        )
                        .ok_or_else(|| ApiError::invalid(request))?;
                    if total > MAX_VERIFICATION_ARCHIVE_BYTES {
                        return Err(ApiError::invalid(request));
                    }
                    file.write_all(&chunk)
                        .await
                        .map_err(|_| ApiError::unavailable(request))?;
                }
                file.sync_all()
                    .await
                    .map_err(|_| ApiError::unavailable(request))?;
                archive_bytes = Some(total);
            }
            _ => return Err(ApiError::invalid(request)),
        }
    }
    match (key_mode, key, archive_bytes) {
        (Some(mode), Some(key), Some(bytes)) if bytes > 0 => Ok((mode, key, bytes)),
        _ => Err(ApiError::invalid(request)),
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

#[cfg(unix)]
fn verify_and_restore_test(
    archive_path: &Path,
    drill_directory: &Path,
    supplied_mode: &str,
    supplied_key: Zeroizing<String>,
    archive_bytes: u64,
) -> Result<BackupVerificationResponse, ()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(drill_directory)
        .map_err(|_| ())?;
    let header = InitializedVault::inspect_backup_file(archive_path).map_err(|_| ())?;
    let key = match (header.key_mode, supplied_mode) {
        (KeyMode::PassphraseArgon2id, "passphrase") => OwnedArchiveKey::Passphrase(supplied_key),
        (KeyMode::RecoveryKey, "generated_recovery" | "recovery_key") => {
            OwnedArchiveKey::Recovery(RecoveryKey::parse(supplied_key.trim()).map_err(|_| ())?)
        }
        _ => return Err(()),
    };
    let verified =
        InitializedVault::verify_backup_file(archive_path, key.borrowed()).map_err(|_| ())?;
    let database = drill_directory.join("data/vault.sqlite");
    let root_key = drill_directory.join("provider/root.key");
    let restored = InitializedVault::restore_backup_file(
        archive_path,
        &database,
        &root_key,
        key.borrowed(),
        CredentialRestoreMode::Preserve,
        now_unix_ms(),
    )
    .map_err(|_| ())?;
    Ok(BackupVerificationResponse {
        archive_id: verified.header.archive_id,
        format_version: smcv_backup::FORMAT_VERSION,
        logical_vault_id: verified.metadata.logical_vault_id,
        source_recovery_epoch: verified.metadata.source_recovery_epoch,
        created_at_unix_ms: verified.metadata.created_at_unix_ms,
        archive_bytes,
        record_count: verified.record_count,
        logical_bytes: verified.logical_bytes,
        integrity_verified: true,
        restore_tested: true,
        staged_recovery_epoch: restored.recovery_epoch,
    })
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
        format_version: job.format_version,
        logical_vault_id: job.logical_vault_id,
        source_recovery_epoch: job.source_recovery_epoch,
        archive_bytes: job.archive_bytes,
        record_count: job.record_count,
        download_started: job.download_started,
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
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use tempfile::TempDir;

    use super::{BackupJobRegistry, JobState};

    #[test]
    fn process_restart_durably_fails_an_interrupted_job() -> Result<(), std::io::Error> {
        let root = TempDir::new()?;
        let directory = root.path().join("jobs");
        let registry = BackupJobRegistry::open(&directory)?;
        let job = registry.create(1_800_000_300_000)?;
        registry.update(job.job_id, |record| record.state = JobState::Running)?;
        fs::write(
            registry.artifact_path(job.job_id),
            b"encrypted interrupted artifact",
        )?;
        drop(registry);
        let orphan_archive = directory.join(".verify-test.smcvault");
        let orphan_status = directory.join(".status-test.tmp");
        let orphan_drill = directory.join(".restore-drill-test");
        fs::write(&orphan_archive, b"encrypted synthetic partial")?;
        fs::write(&orphan_status, b"partial status")?;
        fs::create_dir(&orphan_drill)?;

        let reopened = BackupJobRegistry::open(&directory)?;
        assert!(!orphan_archive.exists());
        assert!(!orphan_status.exists());
        assert!(!orphan_drill.exists());
        let recovered = reopened
            .get(job.job_id)
            .ok_or_else(|| std::io::Error::other("recovered job missing"))?;
        assert_eq!(recovered.state, JobState::Failed);
        assert_eq!(recovered.error_code.as_deref(), Some("interrupted"));
        assert!(!reopened.artifact_path(job.job_id).exists());
        Ok(())
    }

    #[test]
    fn artifact_registry_rejects_a_symlinked_custody_directory() -> Result<(), std::io::Error> {
        let root = TempDir::new()?;
        let actual = root.path().join("actual");
        fs::create_dir(&actual)?;
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700))?;
        let linked = root.path().join("linked");
        symlink(&actual, &linked)?;
        assert!(BackupJobRegistry::open(&linked).is_err());
        Ok(())
    }

    #[test]
    fn failed_status_publication_preserves_memory_and_removes_its_partial()
    -> Result<(), std::io::Error> {
        let root = TempDir::new()?;
        let directory = root.path().join("jobs");
        let registry = BackupJobRegistry::open(&directory)?;
        let job = registry.create(1_800_000_300_000)?;
        fs::remove_file(registry.status_path(job.job_id))?;
        fs::create_dir(registry.status_path(job.job_id))?;

        assert!(
            registry
                .update(job.job_id, |record| record.state = JobState::Running)
                .is_err()
        );
        assert_eq!(
            registry
                .get(job.job_id)
                .ok_or_else(|| std::io::Error::other("job missing"))?
                .state,
            JobState::Pending
        );
        assert!(fs::read_dir(&directory)?.all(|entry| {
            entry
                .ok()
                .is_none_or(|entry| !entry.file_name().to_string_lossy().starts_with(".status-"))
        }));
        Ok(())
    }

    #[test]
    fn running_jobs_do_not_expire_before_terminal_artifact_retention() -> Result<(), std::io::Error>
    {
        let root = TempDir::new()?;
        let directory = root.path().join("jobs");
        let registry = BackupJobRegistry::open(&directory)?;
        let job = registry.create(1_800_000_300_000)?;
        registry.update(job.job_id, |record| record.state = JobState::Running)?;
        registry.cleanup_expired(job.expires_at_unix_ms + 1)?;
        assert_eq!(
            registry
                .get(job.job_id)
                .ok_or_else(|| std::io::Error::other("running job expired"))?
                .state,
            JobState::Running
        );

        registry.update(job.job_id, |record| record.state = JobState::Completed)?;
        registry.cleanup_expired(job.expires_at_unix_ms + 1)?;
        assert!(registry.get(job.job_id).is_none());
        assert!(!registry.status_path(job.job_id).exists());
        Ok(())
    }
}
