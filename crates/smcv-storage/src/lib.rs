#![forbid(unsafe_code)]
#![doc = "`SQLite` persistence adapter for SMCV."]
#![cfg_attr(test, allow(clippy::panic))]

use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use rusqlite::{Connection, OpenFlags, OptionalExtension, backup::Backup, limits::Limit, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod authorization;
mod idempotency;
mod identity;
mod portable;
mod records;
mod rotation;
mod vault;

pub use authorization::{
    AuthorizationSnapshot, AuthorizationState, PolicyBindingRecord, PolicyGrantRecord,
    PolicyInsert, PolicyRecord,
};
pub use idempotency::IdempotencyReservation;
pub use identity::{
    ApplicationCredentialInsert, ApplicationCredentialRecord, AuthenticatorKind,
    OwnerAuthenticatorInsert, OwnerAuthenticatorRecord, PrincipalKind, PrincipalRecord,
    ServiceIdentityInsert, ServiceIdentityRecord, SessionInsert, SessionRecord,
};
pub use portable::{
    PortableApplicationCredential, PortableAuthenticator, PortableNamespace, PortablePolicy,
    PortablePrincipal, PortableSecret, PortableSecretVersion, PortableServiceIdentity,
    PortableSnapshot, PortableTombstone,
};
pub use records::{
    AuditHead, AuditRecord, EncryptedRecord, NamespaceInsert, NamespaceRecord, ScheduledSecret,
    SecretInsert, SecretLifecycleChange, SecretPurge, SecretRecord, SecretVersionInsert,
    SecretVersionRecord, StoredAuditRecord,
};
pub use rotation::{
    KekRotationJob, RewrapItem, RewrapKind, RewrappedItem, RootRewrappedKey, RotationStage,
};
pub use vault::{
    ActivationState, BootstrapRecord, InitializationDisposition, InstallationRecord, KeyKind,
    KeyState, RegisteredKey, WrappedKeyRecord,
};

const APPLICATION_ID: i32 = 0x534d_4356;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SQL_VALUE_BYTES: i32 = 16 * 1024 * 1024;

/// Persistence failures with redacted external formatting.
#[derive(Debug, Error)]
pub enum StorageError {
    /// `SQLite` rejected or could not complete an operation.
    #[error("database operation failed")]
    Sqlite(#[source] rusqlite::Error),
    /// Another thread panicked while holding the connection.
    #[error("database connection unavailable")]
    Poisoned,
    /// The destination would overwrite an existing path.
    #[error("backup destination already exists")]
    DestinationExists,
    /// An applied migration has different content than this binary expects.
    #[error("database migration history does not match this build")]
    MigrationMismatch,
    /// Durable state conflicts with the requested state-machine transition.
    #[error("vault state conflicts with the requested operation")]
    StateConflict,
    /// A required durable record is absent.
    #[error("vault is not initialized")]
    NotInitialized,
    /// Durable data violates an internal fixed-width invariant.
    #[error("database contains invalid protected metadata")]
    InvalidData,
    /// A database or snapshot path is not a restrictive regular file.
    #[error("database path permissions are invalid")]
    UnsafePath,
    /// An optimistic concurrency or uniqueness precondition failed.
    #[error("database write conflicts with current state")]
    Conflict,
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Result returned by the `SQLite` adapter.
pub type StorageResult<T> = Result<T, StorageError>;

/// Safe `SQLite` runtime settings observed after initialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteSettings {
    /// Active journal mode.
    pub journal_mode: String,
    /// Active synchronous level (`2` is FULL).
    pub synchronous: i32,
    /// Whether foreign keys are enforced.
    pub foreign_keys: bool,
    /// Application identifier in the database header.
    pub application_id: i32,
}

/// Single-process `SQLite` adapter with explicit serialized connection access.
pub struct SqliteStore {
    connection: Mutex<Connection>,
    path: PathBuf,
}

impl SqliteStore {
    /// Opens or creates a local SMCV `SQLite` database.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened, configured, or
    /// migrated.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();
        prepare_database_file(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let connection = Connection::open_with_flags(path, flags)?;
        configure(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            path: path.to_path_buf(),
        })
    }

    /// Returns the database path without including it in debug output.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns security-relevant `SQLite` settings for readiness checks.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection is unavailable or a setting cannot
    /// be read.
    pub fn settings(&self) -> StorageResult<SqliteSettings> {
        let connection = self.lock()?;
        read_settings(&connection)
    }

    /// Runs `SQLite`'s quick integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection is unavailable or the integrity
    /// query cannot be executed.
    pub fn quick_integrity_check(&self) -> StorageResult<bool> {
        let connection = self.lock()?;
        let result: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        Ok(result == "ok")
    }

    /// Creates a consistent online `SQLite` snapshot at a new destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination exists or the snapshot cannot be
    /// completed.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> StorageResult<()> {
        let destination = destination.as_ref();
        create_restrictive_file(destination, true)?;

        let source = self.lock()?;
        let mut target = Connection::open_with_flags(
            destination,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(32, Duration::from_millis(10), None)?;
        Ok(())
    }

    fn lock(&self) -> StorageResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StorageError::Poisoned)
    }
}

#[cfg(unix)]
fn prepare_database_file(path: &Path) -> StorageResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::UnsafePath);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_restrictive_file(path, false)
        }
        Err(error) => Err(StorageError::Sqlite(
            rusqlite::Error::ToSqlConversionFailure(error.into()),
        )),
    }
}

#[cfg(not(unix))]
fn prepare_database_file(path: &Path) -> StorageResult<()> {
    create_restrictive_file(path, false)
}

#[cfg(unix)]
fn create_restrictive_file(path: &Path, destination_semantics: bool) -> StorageResult<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).mode(0o600);
    match options.open(path) {
        Ok(file) => sync_new_file_and_parent(&file, path),
        Err(error)
            if destination_semantics && error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            Err(StorageError::DestinationExists)
        }
        Err(error) => Err(io_as_storage(error)),
    }
}

#[cfg(not(unix))]
fn create_restrictive_file(path: &Path, destination_semantics: bool) -> StorageResult<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    match options.open(path) {
        Ok(file) => sync_new_file_and_parent(&file, path),
        Err(error)
            if destination_semantics && error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            Err(StorageError::DestinationExists)
        }
        Err(error) => Err(io_as_storage(error)),
    }
}

fn sync_new_file_and_parent(file: &fs::File, path: &Path) -> StorageResult<()> {
    file.sync_all().map_err(io_as_storage)?;
    let parent = path.parent().ok_or(StorageError::UnsafePath)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_as_storage)
}

fn io_as_storage(error: std::io::Error) -> StorageError {
    StorageError::Sqlite(rusqlite::Error::ToSqlConversionFailure(error.into()))
}

fn configure(connection: &Connection) -> StorageResult<()> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    let _previous_limit = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQL_VALUE_BYTES);
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS smcv_schema_migrations (
             version INTEGER PRIMARY KEY,
             checksum TEXT NOT NULL,
             applied_at_unix_ms INTEGER NOT NULL
         ) STRICT;",
    )?;
    apply_migrations(connection)?;
    Ok(())
}

struct Migration {
    version: i64,
    checksum: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        checksum: "sha256:e279f6be347da07e482e11884680b3e7f249acb9e9c1a4a5b8244c11e2c8ff44",
        sql: "CREATE TABLE smcv_installation_state (\
                  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
                  logical_vault_id BLOB NOT NULL CHECK (length(logical_vault_id) = 16),\
                  installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),\
                  recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),\
                  initialized_at_unix_ms INTEGER NOT NULL\
              ) STRICT;",
    },
    Migration {
        version: 2,
        checksum: "sha256:5f5638c43abb9744e53871ea50587c580186bcc7e3e96076eb4c537b2e5986da",
        sql: r"
ALTER TABLE smcv_installation_state
    ADD COLUMN activation_state TEXT NOT NULL DEFAULT 'initializing'
    CHECK (activation_state IN ('initializing', 'ready', 'maintenance', 'failed'));
ALTER TABLE smcv_installation_state
    ADD COLUMN active_kek_version INTEGER CHECK (active_kek_version > 0);
ALTER TABLE smcv_installation_state
    ADD COLUMN security_semantics_version INTEGER NOT NULL DEFAULT 1
    CHECK (security_semantics_version = 1);

CREATE TABLE smcv_key_registry (
    key_kind TEXT NOT NULL CHECK (key_kind IN ('kek', 'blind_index', 'audit', 'token_verifier')),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    wrapping_kek_version INTEGER CHECK (wrapping_kek_version > 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    wrapped_key BLOB NOT NULL CHECK (length(wrapped_key) = 48),
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (key_kind, key_version)
) STRICT;
CREATE UNIQUE INDEX smcv_one_active_key_per_kind
    ON smcv_key_registry(key_kind) WHERE state = 'active';

CREATE TABLE smcv_namespaces (
    namespace_id BLOB PRIMARY KEY CHECK (length(namespace_id) = 16),
    parent_namespace_id BLOB REFERENCES smcv_namespaces(namespace_id) ON DELETE RESTRICT,
    name_index BLOB NOT NULL CHECK (length(name_index) = 32),
    metadata_version INTEGER NOT NULL CHECK (metadata_version > 0),
    metadata_nonce BLOB NOT NULL CHECK (length(metadata_nonce) = 24),
    metadata_ciphertext BLOB NOT NULL CHECK (length(metadata_ciphertext) BETWEEN 16 AND 1048592),
    dek_nonce BLOB NOT NULL CHECK (length(dek_nonce) = 24),
    wrapped_dek BLOB NOT NULL CHECK (length(wrapped_dek) = 48),
    kek_version INTEGER NOT NULL CHECK (kek_version > 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('active', 'archived', 'deleted')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (parent_namespace_id, name_index)
) STRICT;
CREATE UNIQUE INDEX smcv_namespaces_unique_root_name
    ON smcv_namespaces(name_index) WHERE parent_namespace_id IS NULL;

CREATE TABLE smcv_secrets (
    secret_id BLOB PRIMARY KEY CHECK (length(secret_id) = 16),
    namespace_id BLOB NOT NULL REFERENCES smcv_namespaces(namespace_id) ON DELETE RESTRICT,
    name_index BLOB NOT NULL CHECK (length(name_index) = 32),
    metadata_version INTEGER NOT NULL CHECK (metadata_version > 0),
    metadata_nonce BLOB NOT NULL CHECK (length(metadata_nonce) = 24),
    metadata_ciphertext BLOB NOT NULL CHECK (length(metadata_ciphertext) BETWEEN 16 AND 1048592),
    metadata_dek_nonce BLOB NOT NULL CHECK (length(metadata_dek_nonce) = 24),
    metadata_wrapped_dek BLOB NOT NULL CHECK (length(metadata_wrapped_dek) = 48),
    metadata_kek_version INTEGER NOT NULL CHECK (metadata_kek_version > 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('active', 'archived', 'deleted', 'purged')),
    current_version INTEGER NOT NULL CHECK (current_version > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    deleted_at_unix_ms INTEGER,
    UNIQUE (namespace_id, name_index),
    FOREIGN KEY (secret_id, current_version)
        REFERENCES smcv_secret_versions(secret_id, version)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE smcv_secret_versions (
    secret_id BLOB NOT NULL REFERENCES smcv_secrets(secret_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    envelope_version INTEGER NOT NULL CHECK (envelope_version = 1),
    algorithm_suite INTEGER NOT NULL CHECK (algorithm_suite = 1),
    kek_version INTEGER NOT NULL CHECK (kek_version > 0),
    payload_nonce BLOB NOT NULL CHECK (length(payload_nonce) = 24),
    payload_ciphertext BLOB NOT NULL CHECK (length(payload_ciphertext) BETWEEN 16 AND 16777216),
    dek_nonce BLOB NOT NULL CHECK (length(dek_nonce) = 24),
    wrapped_dek BLOB NOT NULL CHECK (length(wrapped_dek) = 48),
    expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms >= 0),
    rotation_due_at_unix_ms INTEGER CHECK (rotation_due_at_unix_ms IS NULL OR rotation_due_at_unix_ms >= 0),
    created_by_principal_id BLOB CHECK (created_by_principal_id IS NULL OR length(created_by_principal_id) = 16),
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (secret_id, version)
) STRICT;
CREATE INDEX smcv_secret_versions_expiration_due
    ON smcv_secret_versions(expires_at_unix_ms)
    WHERE expires_at_unix_ms IS NOT NULL;
CREATE INDEX smcv_secret_versions_rotation_due
    ON smcv_secret_versions(rotation_due_at_unix_ms)
    WHERE rotation_due_at_unix_ms IS NOT NULL;

CREATE TABLE smcv_secret_tombstones (
    secret_id BLOB PRIMARY KEY CHECK (length(secret_id) = 16),
    namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
    name_index BLOB NOT NULL CHECK (length(name_index) = 32),
    last_version INTEGER NOT NULL CHECK (last_version > 0),
    purged_at_unix_ms INTEGER NOT NULL,
    retention_cutoff_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE smcv_audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    occurred_at_unix_ms INTEGER NOT NULL,
    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
    actor_principal_id BLOB CHECK (actor_principal_id IS NULL OR length(actor_principal_id) = 16),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    target_kind TEXT NOT NULL CHECK (length(target_kind) BETWEEN 1 AND 32),
    target_id BLOB CHECK (target_id IS NULL OR length(target_id) = 16),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'failed')),
    previous_commitment BLOB NOT NULL CHECK (length(previous_commitment) = 32),
    commitment BLOB NOT NULL CHECK (length(commitment) = 32)
) STRICT;

CREATE TABLE smcv_maintenance_jobs (
    job_id BLOB PRIMARY KEY CHECK (length(job_id) = 16),
    job_kind TEXT NOT NULL CHECK (job_kind IN ('kek_rotation', 'root_rotation', 'audit_verify')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'paused', 'completed', 'failed')),
    source_key_version INTEGER,
    target_key_version INTEGER,
    stage TEXT CHECK (stage IS NULL OR stage IN ('auxiliary', 'namespace_metadata', 'secret_metadata', 'secret_versions', 'finalize')),
    last_row_id INTEGER NOT NULL DEFAULT 0 CHECK (last_row_id >= 0),
    last_object_id BLOB CHECK (last_object_id IS NULL OR length(last_object_id) = 16),
    lease_owner BLOB CHECK (lease_owner IS NULL OR length(lease_owner) = 16),
    lease_expires_at_unix_ms INTEGER,
    updated_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE smcv_mutation_guard (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    purge_enabled INTEGER NOT NULL CHECK (purge_enabled IN (0, 1))
) STRICT;
INSERT INTO smcv_mutation_guard(singleton, purge_enabled) VALUES (1, 0);

CREATE TRIGGER smcv_secret_versions_protect_update
BEFORE UPDATE ON smcv_secret_versions
WHEN OLD.secret_id != NEW.secret_id
  OR OLD.version != NEW.version
  OR OLD.envelope_version != NEW.envelope_version
  OR OLD.algorithm_suite != NEW.algorithm_suite
  OR OLD.payload_nonce != NEW.payload_nonce
  OR OLD.payload_ciphertext != NEW.payload_ciphertext
  OR OLD.expires_at_unix_ms IS NOT NEW.expires_at_unix_ms
  OR OLD.rotation_due_at_unix_ms IS NOT NEW.rotation_due_at_unix_ms
  OR OLD.created_by_principal_id IS NOT NEW.created_by_principal_id
  OR OLD.created_at_unix_ms != NEW.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'immutable secret version');
END;

CREATE TRIGGER smcv_secret_versions_protect_delete
BEFORE DELETE ON smcv_secret_versions
WHEN (SELECT purge_enabled FROM smcv_mutation_guard WHERE singleton = 1) != 1
BEGIN
    SELECT RAISE(ABORT, 'explicit purge required');
END;

CREATE TRIGGER smcv_secrets_protect_delete
BEFORE DELETE ON smcv_secrets
WHEN (SELECT purge_enabled FROM smcv_mutation_guard WHERE singleton = 1) != 1
BEGIN
    SELECT RAISE(ABORT, 'explicit purge required');
END;

CREATE TRIGGER smcv_secrets_monotonic_versions
BEFORE UPDATE ON smcv_secrets
WHEN NEW.current_version < OLD.current_version
  OR NEW.metadata_version < OLD.metadata_version
  OR (
      NEW.revision <= OLD.revision
      AND (
          NEW.namespace_id != OLD.namespace_id
          OR NEW.name_index != OLD.name_index
          OR NEW.metadata_version != OLD.metadata_version
          OR NEW.metadata_nonce != OLD.metadata_nonce
          OR NEW.metadata_ciphertext != OLD.metadata_ciphertext
          OR NEW.lifecycle_state != OLD.lifecycle_state
          OR NEW.current_version != OLD.current_version
          OR NEW.updated_at_unix_ms != OLD.updated_at_unix_ms
          OR NEW.deleted_at_unix_ms IS NOT OLD.deleted_at_unix_ms
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'secret versions and revision must advance');
END;

CREATE TRIGGER smcv_audit_events_protect_update
BEFORE UPDATE ON smcv_audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER smcv_audit_events_protect_delete
BEFORE DELETE ON smcv_audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
",
    },
    Migration {
        version: 3,
        checksum: "sha256:5e944e456736d5c0c6b478b92b5915b12b327db8a5e8f67fc66d8dd973a927a1",
        sql: r"
ALTER TABLE smcv_audit_events ADD COLUMN commitment_version INTEGER NOT NULL DEFAULT 1 CHECK (commitment_version IN (1, 2));
ALTER TABLE smcv_audit_events ADD COLUMN credential_kind TEXT CHECK (credential_kind IS NULL OR credential_kind IN ('session', 'application'));
ALTER TABLE smcv_audit_events ADD COLUMN credential_id BLOB CHECK (credential_id IS NULL OR length(credential_id) = 16);

CREATE TABLE smcv_principals (
    principal_id BLOB PRIMARY KEY CHECK (length(principal_id) = 16),
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('owner', 'service')),
    state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX smcv_one_owner
    ON smcv_principals(principal_kind) WHERE principal_kind = 'owner';

CREATE TABLE smcv_owner_authenticators (
    authenticator_id BLOB PRIMARY KEY CHECK (length(authenticator_id) = 16),
    principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    authenticator_kind TEXT NOT NULL CHECK (authenticator_kind IN ('password', 'passkey', 'recovery')),
    credential_lookup BLOB UNIQUE CHECK (credential_lookup IS NULL OR length(credential_lookup) BETWEEN 1 AND 1024),
    credential_data BLOB CHECK (credential_data IS NULL OR length(credential_data) BETWEEN 1 AND 65536),
    password_phc TEXT CHECK (password_phc IS NULL OR length(password_phc) BETWEEN 32 AND 1024),
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    created_at_unix_ms INTEGER NOT NULL,
    last_used_at_unix_ms INTEGER,
    revoked_at_unix_ms INTEGER,
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    CHECK (
        (authenticator_kind = 'passkey' AND credential_lookup IS NOT NULL AND credential_data IS NOT NULL AND password_phc IS NULL)
        OR (authenticator_kind IN ('password', 'recovery') AND credential_lookup IS NULL AND credential_data IS NULL AND password_phc IS NOT NULL)
    )
) STRICT;

CREATE TABLE smcv_sessions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 16),
    lookup_id BLOB NOT NULL UNIQUE CHECK (length(lookup_id) = 16),
    verifier BLOB NOT NULL CHECK (length(verifier) = 32),
    csrf_verifier BLOB NOT NULL CHECK (length(csrf_verifier) = 32),
    principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    authenticator_id BLOB NOT NULL REFERENCES smcv_owner_authenticators(authenticator_id) ON DELETE RESTRICT,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('password', 'passkey', 'recovery')),
    created_at_unix_ms INTEGER NOT NULL,
    last_used_at_unix_ms INTEGER NOT NULL,
    idle_expires_at_unix_ms INTEGER NOT NULL,
    absolute_expires_at_unix_ms INTEGER NOT NULL,
    recent_auth_at_unix_ms INTEGER NOT NULL,
    revoked_at_unix_ms INTEGER,
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    CHECK (idle_expires_at_unix_ms <= absolute_expires_at_unix_ms)
) STRICT;
CREATE INDEX smcv_sessions_principal_active
    ON smcv_sessions(principal_id, absolute_expires_at_unix_ms)
    WHERE revoked_at_unix_ms IS NULL;

CREATE TABLE smcv_service_identities (
    principal_id BLOB PRIMARY KEY REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    metadata_version INTEGER NOT NULL CHECK (metadata_version > 0),
    metadata_nonce BLOB NOT NULL CHECK (length(metadata_nonce) = 24),
    metadata_ciphertext BLOB NOT NULL CHECK (length(metadata_ciphertext) BETWEEN 16 AND 1048592),
    metadata_dek_nonce BLOB NOT NULL CHECK (length(metadata_dek_nonce) = 24),
    metadata_wrapped_dek BLOB NOT NULL CHECK (length(metadata_wrapped_dek) = 48),
    metadata_kek_version INTEGER NOT NULL CHECK (metadata_kek_version > 0)
) STRICT;

CREATE TABLE smcv_application_credentials (
    credential_id BLOB PRIMARY KEY CHECK (length(credential_id) = 16),
    principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    lookup_id BLOB NOT NULL UNIQUE CHECK (length(lookup_id) = 12),
    verifier BLOB NOT NULL CHECK (length(verifier) = 32),
    created_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER,
    last_used_at_unix_ms INTEGER,
    revoked_at_unix_ms INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms >= created_at_unix_ms)
) STRICT;
CREATE INDEX smcv_application_credentials_principal
    ON smcv_application_credentials(principal_id, revoked_at_unix_ms);

CREATE TABLE smcv_policies (
    policy_id BLOB PRIMARY KEY CHECK (length(policy_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'archived')),
    metadata_version INTEGER NOT NULL CHECK (metadata_version > 0),
    metadata_nonce BLOB NOT NULL CHECK (length(metadata_nonce) = 24),
    metadata_ciphertext BLOB NOT NULL CHECK (length(metadata_ciphertext) BETWEEN 16 AND 1048592),
    metadata_dek_nonce BLOB NOT NULL CHECK (length(metadata_dek_nonce) = 24),
    metadata_wrapped_dek BLOB NOT NULL CHECK (length(metadata_wrapped_dek) = 48),
    metadata_kek_version INTEGER NOT NULL CHECK (metadata_kek_version > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE smcv_policy_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    policy_id BLOB NOT NULL REFERENCES smcv_policies(policy_id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('namespace', 'secret')),
    resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
    include_descendants INTEGER NOT NULL CHECK (include_descendants IN (0, 1)),
    created_by_principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    created_at_unix_ms INTEGER NOT NULL,
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    CHECK (include_descendants = 0 OR resource_kind = 'namespace'),
    UNIQUE(policy_id, action, resource_kind, resource_id, include_descendants)
) STRICT;

CREATE TABLE smcv_policy_bindings (
    principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    policy_id BLOB NOT NULL REFERENCES smcv_policies(policy_id) ON DELETE RESTRICT,
    created_by_principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    created_at_unix_ms INTEGER NOT NULL,
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32),
    PRIMARY KEY(principal_id, policy_id)
) STRICT;

CREATE TABLE smcv_authorization_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state_commitment BLOB NOT NULL CHECK (length(state_commitment) = 32)
) STRICT;
INSERT INTO smcv_authorization_state(singleton, revision, state_commitment)
    VALUES (1, 1, zeroblob(32));

CREATE TABLE smcv_idempotency_records (
    principal_id BLOB NOT NULL REFERENCES smcv_principals(principal_id) ON DELETE RESTRICT,
    key_verifier BLOB NOT NULL CHECK (length(key_verifier) = 32),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    response_kind TEXT NOT NULL CHECK (length(response_kind) BETWEEN 1 AND 32),
    response_id BLOB CHECK (response_id IS NULL OR length(response_id) = 16),
    created_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(principal_id, key_verifier),
    CHECK (expires_at_unix_ms > created_at_unix_ms)
) STRICT;
CREATE INDEX smcv_idempotency_expiry ON smcv_idempotency_records(expires_at_unix_ms);
",
    },
];

fn apply_migrations(connection: &Connection) -> StorageResult<()> {
    for migration in MIGRATIONS {
        if migration_checksum(migration.sql) != migration.checksum {
            return Err(StorageError::MigrationMismatch);
        }
        let applied_checksum: Option<String> = connection
            .query_row(
                "SELECT checksum FROM smcv_schema_migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(checksum) = applied_checksum {
            if checksum != migration.checksum {
                return Err(StorageError::MigrationMismatch);
            }
            continue;
        }

        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO smcv_schema_migrations (version, checksum, applied_at_unix_ms)\
             VALUES (?1, ?2, unixepoch('subsec') * 1000)",
            params![migration.version, migration.checksum],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
    }
    Ok(())
}

fn migration_checksum(sql: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(sql.as_bytes())))
}

fn read_settings(connection: &Connection) -> StorageResult<SqliteSettings> {
    Ok(SqliteSettings {
        journal_mode: connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?,
        synchronous: connection.pragma_query_value(None, "synchronous", |row| row.get(0))?,
        foreign_keys: connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?,
        application_id: connection.pragma_query_value(None, "application_id", |row| row.get(0))?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::{Seek, SeekFrom, Write},
        sync::Arc,
        thread,
        time::Duration,
    };

    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use rusqlite::{Connection, ErrorCode};
    use tempfile::TempDir;

    use super::{APPLICATION_ID, MIGRATIONS, SqliteStore, StorageError, migration_checksum};

    #[test]
    fn applies_durability_and_integrity_settings() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let store = SqliteStore::open(directory.path().join("vault.sqlite"))
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        let settings = store
            .settings()
            .unwrap_or_else(|error| panic!("settings must be readable: {error}"));

        assert_eq!(settings.journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(settings.synchronous, 2);
        assert!(settings.foreign_keys);
        assert_eq!(settings.application_id, APPLICATION_ID);
        assert!(
            store
                .quick_integrity_check()
                .unwrap_or_else(|error| panic!("integrity check must run: {error}"))
        );
    }

    #[test]
    fn migrates_the_frozen_phase_zero_schema_fixture_forward() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let path = directory.path().join("phase-zero.sqlite");
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("fixture database must open: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE smcv_schema_migrations (
                     version INTEGER PRIMARY KEY,
                     checksum TEXT NOT NULL,
                     applied_at_unix_ms INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap_or_else(|error| panic!("fixture migration table must create: {error}"));
        connection
            .execute_batch(MIGRATIONS[0].sql)
            .unwrap_or_else(|error| panic!("frozen v1 schema must apply: {error}"));
        connection
            .execute(
                "INSERT INTO smcv_schema_migrations VALUES (1, ?1, 0)",
                [MIGRATIONS[0].checksum],
            )
            .unwrap_or_else(|error| panic!("fixture history must record: {error}"));
        connection
            .pragma_update(None, "user_version", 1)
            .unwrap_or_else(|error| panic!("fixture version must record: {error}"));
        drop(connection);
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("fixture permissions must restrict: {error}"));

        let store = SqliteStore::open(&path)
            .unwrap_or_else(|error| panic!("fixture must migrate: {error}"));
        let connection = store
            .lock()
            .unwrap_or_else(|error| panic!("migrated fixture must lock: {error}"));
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap_or_else(|error| panic!("migrated version must read: {error}"));
        let tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name IN ('smcv_key_registry', 'smcv_secrets', 'smcv_audit_events', 'smcv_principals', 'smcv_sessions')",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("migrated tables must inspect: {error}"));
        assert_eq!(version, 3);
        assert_eq!(tables, 5);
    }

    #[test]
    fn busy_writer_waits_within_bound_and_then_commits() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let path = directory.path().join("busy.sqlite");
        let store = Arc::new(
            SqliteStore::open(&path)
                .unwrap_or_else(|error| panic!("synthetic database must open: {error}")),
        );
        store
            .lock()
            .unwrap_or_else(|error| panic!("database must lock: {error}"))
            .execute("CREATE TABLE smcv_busy_probe(value INTEGER) STRICT", [])
            .unwrap_or_else(|error| panic!("probe table must create: {error}"));
        let blocker = Connection::open(&path)
            .unwrap_or_else(|error| panic!("blocking connection must open: {error}"));
        blocker
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO smcv_busy_probe VALUES (1);")
            .unwrap_or_else(|error| panic!("blocking write must begin: {error}"));
        let writer = Arc::clone(&store);
        let handle = thread::spawn(move || {
            writer.lock().is_ok_and(|connection| {
                connection
                    .execute("INSERT INTO smcv_busy_probe VALUES (2)", [])
                    .is_ok()
            })
        });
        thread::sleep(Duration::from_millis(50));
        blocker
            .execute_batch("COMMIT")
            .unwrap_or_else(|error| panic!("blocking write must commit: {error}"));
        assert!(
            handle
                .join()
                .unwrap_or_else(|_| panic!("bounded writer thread must join"))
        );
        let count: i64 = store
            .lock()
            .unwrap_or_else(|error| panic!("database must relock: {error}"))
            .query_row("SELECT count(*) FROM smcv_busy_probe", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("probe rows must count: {error}"));
        assert_eq!(count, 2);
    }

    #[test]
    fn disk_full_rolls_back_the_entire_transaction() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let store = SqliteStore::open(directory.path().join("full.sqlite"))
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        let connection = store
            .lock()
            .unwrap_or_else(|error| panic!("database must lock: {error}"));
        connection
            .execute("CREATE TABLE smcv_full_probe(value BLOB) STRICT", [])
            .unwrap_or_else(|error| panic!("probe table must create: {error}"));
        let page_count: i64 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap_or_else(|error| panic!("page count must read: {error}"));
        connection
            .pragma_update(None, "max_page_count", page_count.saturating_add(1))
            .unwrap_or_else(|error| panic!("page cap must set: {error}"));
        let transaction = connection
            .unchecked_transaction()
            .unwrap_or_else(|error| panic!("probe transaction must begin: {error}"));
        let Err(error) =
            transaction.execute("INSERT INTO smcv_full_probe VALUES (zeroblob(1048576))", [])
        else {
            panic!("bounded database must report full");
        };
        assert!(matches!(
            error,
            rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::DiskFull
        ));
        drop(transaction);
        let count: i64 = connection
            .query_row("SELECT count(*) FROM smcv_full_probe", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("rolled-back rows must count: {error}"));
        assert_eq!(count, 0);
    }

    #[test]
    fn database_page_corruption_never_reports_healthy() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let path = directory.path().join("corrupt.sqlite");
        let store = SqliteStore::open(&path)
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        drop(store);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("synthetic database bytes must open: {error}"));
        file.seek(SeekFrom::Start(100))
            .and_then(|_| file.write_all(&[0xff; 32]))
            .and_then(|()| file.sync_all())
            .unwrap_or_else(|error| panic!("synthetic corruption must persist: {error}"));
        drop(file);

        let rejected = match SqliteStore::open(&path) {
            Ok(store) => !store.quick_integrity_check().unwrap_or(false),
            Err(error) => {
                assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
                true
            }
        };
        assert!(rejected);
    }

    #[cfg(unix)]
    #[test]
    fn database_and_snapshot_files_are_restrictive_and_unsafe_files_fail_closed() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let database = directory.path().join("restricted.sqlite");
        let snapshot = directory.path().join("restricted.snapshot.sqlite");
        let store = SqliteStore::open(&database)
            .unwrap_or_else(|error| panic!("restricted database must open: {error}"));
        assert_eq!(
            std::fs::metadata(&database)
                .unwrap_or_else(|error| panic!("database metadata must read: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        store
            .backup_to(&snapshot)
            .unwrap_or_else(|error| panic!("restricted snapshot must create: {error}"));
        assert_eq!(
            std::fs::metadata(&snapshot)
                .unwrap_or_else(|error| panic!("snapshot metadata must read: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let unsafe_path = directory.path().join("unsafe.sqlite");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&unsafe_path)
            .unwrap_or_else(|error| panic!("unsafe fixture must create: {error}"));
        assert!(matches!(
            SqliteStore::open(&unsafe_path),
            Err(StorageError::UnsafePath)
        ));
    }

    #[test]
    fn online_backup_creates_readable_snapshot_without_overwrite() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let source_path = directory.path().join("vault.sqlite");
        let backup_path = directory.path().join("snapshot.sqlite");
        let store = SqliteStore::open(&source_path)
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));

        store
            .backup_to(&backup_path)
            .unwrap_or_else(|error| panic!("online backup must succeed: {error}"));
        let snapshot = Connection::open(&backup_path)
            .unwrap_or_else(|error| panic!("snapshot must open: {error}"));
        let application_id: i32 = snapshot
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap_or_else(|error| panic!("snapshot metadata must read: {error}"));

        assert_eq!(application_id, APPLICATION_ID);
        assert!(matches!(
            store.backup_to(&backup_path),
            Err(StorageError::DestinationExists)
        ));
    }

    #[test]
    fn committed_wal_data_recovers_and_uncommitted_data_rolls_back() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let database_path = directory.path().join("vault.sqlite");
        {
            let store = SqliteStore::open(&database_path)
                .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
            let mut connection = store
                .connection
                .lock()
                .unwrap_or_else(|error| panic!("synthetic database lock must open: {error}"));
            connection
                .execute_batch(
                    "CREATE TABLE recovery_probe (value INTEGER NOT NULL) STRICT;\
                     INSERT INTO recovery_probe VALUES (1);",
                )
                .unwrap_or_else(|error| panic!("committed WAL write must succeed: {error}"));
            let transaction = connection
                .transaction()
                .unwrap_or_else(|error| panic!("transaction must start: {error}"));
            transaction
                .execute("INSERT INTO recovery_probe VALUES (2)", [])
                .unwrap_or_else(|error| panic!("uncommitted write must execute: {error}"));
        }

        let reopened = Connection::open(&database_path)
            .unwrap_or_else(|error| panic!("synthetic database must reopen: {error}"));
        let values: i64 = reopened
            .query_row("SELECT sum(value) FROM recovery_probe", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("recovered values must read: {error}"));
        assert_eq!(values, 1);
    }

    #[test]
    fn migration_checksum_drift_fails_closed() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let database_path = directory.path().join("vault.sqlite");
        let store = SqliteStore::open(&database_path)
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        {
            let connection = store
                .connection
                .lock()
                .unwrap_or_else(|error| panic!("synthetic database lock must open: {error}"));
            connection
                .execute(
                    "UPDATE smcv_schema_migrations SET checksum = 'changed' WHERE version = 1",
                    [],
                )
                .unwrap_or_else(|error| panic!("synthetic migration drift must write: {error}"));
        }
        drop(store);

        assert!(matches!(
            SqliteStore::open(&database_path),
            Err(StorageError::MigrationMismatch)
        ));
    }

    #[test]
    fn compiled_migration_checksum_is_current() {
        for migration in MIGRATIONS {
            assert_eq!(migration_checksum(migration.sql), migration.checksum);
        }
    }
}
