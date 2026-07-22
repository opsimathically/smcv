#![forbid(unsafe_code)]
#![doc = "`SQLite` persistence adapter for SMCV."]
#![cfg_attr(test, allow(clippy::panic))]

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, backup::Backup, limits::Limit, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
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
        if destination.exists() {
            return Err(StorageError::DestinationExists);
        }

        let source = self.lock()?;
        let mut target = Connection::open(destination)?;
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(32, Duration::from_millis(10), None)?;
        Ok(())
    }

    fn lock(&self) -> StorageResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StorageError::Poisoned)
    }
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

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    checksum: "sha256:e279f6be347da07e482e11884680b3e7f249acb9e9c1a4a5b8244c11e2c8ff44",
    sql: "CREATE TABLE smcv_installation_state (\
              singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
              logical_vault_id BLOB NOT NULL CHECK (length(logical_vault_id) = 16),\
              installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),\
              recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),\
              initialized_at_unix_ms INTEGER NOT NULL\
          ) STRICT;",
}];

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
    use rusqlite::Connection;
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
        assert_eq!(
            migration_checksum(MIGRATIONS[0].sql),
            MIGRATIONS[0].checksum
        );
    }
}
