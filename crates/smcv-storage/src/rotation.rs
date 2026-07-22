use rusqlite::{OptionalExtension, Transaction, params};
use smcv_core::{MaintenanceJobId, ObjectId};

use crate::{
    AuditRecord, KeyKind, SqliteStore, StorageError, StorageResult, WrappedKeyRecord,
    records::{insert_audit, require_audit_head},
    vault::insert_key,
};

/// Ordered KEK-rotation stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationStage {
    /// Rewrap vault-scoped auxiliary keys.
    Auxiliary,
    /// Rewrap namespace metadata DEKs.
    NamespaceMetadata,
    /// Rewrap secret metadata DEKs.
    SecretMetadata,
    /// Rewrap immutable secret-version DEKs.
    SecretVersions,
    /// Verify inventory and retire the prior KEK.
    Finalize,
}

impl RotationStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auxiliary => "auxiliary",
            Self::NamespaceMetadata => "namespace_metadata",
            Self::SecretMetadata => "secret_metadata",
            Self::SecretVersions => "secret_versions",
            Self::Finalize => "finalize",
        }
    }

    fn parse(value: &str) -> StorageResult<Self> {
        match value {
            "auxiliary" => Ok(Self::Auxiliary),
            "namespace_metadata" => Ok(Self::NamespaceMetadata),
            "secret_metadata" => Ok(Self::SecretMetadata),
            "secret_versions" => Ok(Self::SecretVersions),
            "finalize" => Ok(Self::Finalize),
            _ => Err(StorageError::InvalidData),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Auxiliary => Some(Self::NamespaceMetadata),
            Self::NamespaceMetadata => Some(Self::SecretMetadata),
            Self::SecretMetadata => Some(Self::SecretVersions),
            Self::SecretVersions => Some(Self::Finalize),
            Self::Finalize => None,
        }
    }
}

/// Durable in-progress KEK rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KekRotationJob {
    /// Stable maintenance job identity.
    pub job_id: MaintenanceJobId,
    /// Prior key version still needed for unprocessed records.
    pub source_key_version: u32,
    /// Active key version used for new writes.
    pub target_key_version: u32,
    /// Current ordered scan stage.
    pub stage: RotationStage,
    /// Last committed `SQLite` row ID in this stage.
    pub last_row_id: i64,
}

/// Record category whose wrapped key is being changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewrapKind {
    /// Blind-index key.
    BlindIndexKey,
    /// Audit commitment key.
    AuditKey,
    /// Application-token verifier key.
    TokenVerifierKey,
    /// Namespace metadata DEK.
    NamespaceMetadata,
    /// Secret metadata DEK.
    SecretMetadata,
    /// Immutable secret payload DEK.
    SecretVersion,
}

/// One source-wrapped key fetched outside the write transaction.
pub struct RewrapItem {
    /// Internal row locator used only for the checkpointed update.
    pub row_id: i64,
    /// Record category and cryptographic domain.
    pub kind: RewrapKind,
    /// Owning opaque object identity.
    pub object_id: ObjectId,
    /// Owning immutable/metadata/key version.
    pub object_version: u64,
    /// Existing public wrapping nonce.
    pub nonce: [u8; 24],
    /// Existing wrapped 256-bit key and tag.
    pub wrapped_key: [u8; 48],
}

/// Rewrapped output ready for an optimistic atomic batch update.
pub struct RewrappedItem {
    /// Source item authenticated under the retiring key.
    pub source: RewrapItem,
    /// Fresh public nonce under the target key.
    pub nonce: [u8; 24],
    /// Wrapped key under the target KEK.
    pub wrapped_key: [u8; 48],
}

/// One root-wrapped KEK replacement with an optimistic source precondition.
pub struct RootRewrappedKey {
    /// KEK version whose key material is unchanged.
    pub version: u32,
    /// Stable object identity bound into the wrapping context.
    pub object_id: ObjectId,
    /// Existing provider-wrapped nonce.
    pub source_nonce: [u8; 24],
    /// Existing provider-wrapped ciphertext.
    pub source_wrapped_key: [u8; 48],
    /// Fresh nonce under the replacement provider key.
    pub target_nonce: [u8; 24],
    /// Authenticated ciphertext under the replacement provider key.
    pub target_wrapped_key: [u8; 48],
}

impl SqliteStore {
    /// Atomically replaces every non-retired provider-wrapped KEK after the
    /// application has created and verified the replacement provider.
    ///
    /// # Errors
    ///
    /// Returns a conflict if the installation is not ready, another
    /// maintenance operation exists, or the complete source inventory changed.
    pub fn replace_root_wrappings(
        &self,
        job_id: MaintenanceJobId,
        keys: &[RootRewrappedKey],
        now_unix_ms: i64,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        if keys.is_empty() {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let ready: i64 = transaction.query_row(
            "SELECT count(*) FROM smcv_installation_state WHERE singleton = 1 AND activation_state = 'ready'",
            [],
            |row| row.get(0),
        )?;
        let maintenance: i64 = transaction.query_row(
            "SELECT count(*) FROM smcv_maintenance_jobs WHERE state IN ('pending', 'running', 'paused')",
            [],
            |row| row.get(0),
        )?;
        let inventory: i64 = transaction.query_row(
            "SELECT count(*) FROM smcv_key_registry WHERE key_kind = 'kek' AND state != 'retired' AND wrapping_kek_version IS NULL",
            [],
            |row| row.get(0),
        )?;
        if ready != 1
            || maintenance != 0
            || inventory != i64::try_from(keys.len()).map_err(|_| StorageError::Conflict)?
        {
            return Err(StorageError::StateConflict);
        }
        for key in keys {
            let changed = transaction.execute(
                r"UPDATE smcv_key_registry SET nonce = ?1, wrapped_key = ?2
                   WHERE key_kind = 'kek' AND key_version = ?3 AND object_id = ?4
                     AND wrapping_kek_version IS NULL AND state != 'retired'
                     AND nonce = ?5 AND wrapped_key = ?6",
                params![
                    key.target_nonce.as_slice(),
                    key.target_wrapped_key.as_slice(),
                    key.version,
                    key.object_id.as_bytes(),
                    key.source_nonce.as_slice(),
                    key.source_wrapped_key.as_slice(),
                ],
            )?;
            if changed != 1 {
                return Err(StorageError::Conflict);
            }
        }
        transaction.execute(
            r"INSERT INTO smcv_maintenance_jobs (
                   job_id, job_kind, state, stage, last_row_id, updated_at_unix_ms
               ) VALUES (?1, 'root_rotation', 'completed', NULL, 0, ?2)",
            params![job_id.as_bytes(), now_unix_ms],
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Installs a new active KEK and starts a resumable rotation atomically.
    ///
    /// # Errors
    ///
    /// Returns a conflict for non-ready/stale state, an existing rotation, or
    /// malformed new key material.
    pub fn begin_kek_rotation(
        &self,
        job_id: MaintenanceJobId,
        source_key_version: u32,
        new_key: &WrappedKeyRecord,
        now_unix_ms: i64,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<KekRotationJob> {
        if new_key.kind != KeyKind::KeyEncryption
            || new_key.version != source_key_version.saturating_add(1)
            || new_key.wrapping_kek_version.is_some()
        {
            return Err(StorageError::StateConflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let active: Option<i64> = transaction
            .query_row(
                "SELECT active_kek_version FROM smcv_installation_state WHERE singleton = 1 AND activation_state = 'ready'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if active != Some(i64::from(source_key_version)) {
            return Err(StorageError::StateConflict);
        }
        let running: i64 = transaction.query_row(
            "SELECT count(*) FROM smcv_maintenance_jobs WHERE job_kind = 'kek_rotation' AND state IN ('pending', 'running', 'paused')",
            [],
            |row| row.get(0),
        )?;
        if running != 0 {
            return Err(StorageError::StateConflict);
        }
        let changed = transaction.execute(
            "UPDATE smcv_key_registry SET state = 'retiring' WHERE key_kind = 'kek' AND key_version = ?1 AND state = 'active'",
            [source_key_version],
        )?;
        if changed != 1 {
            return Err(StorageError::StateConflict);
        }
        insert_key(&transaction, new_key, now_unix_ms)?;
        transaction.execute(
            "UPDATE smcv_installation_state SET activation_state = 'maintenance', active_kek_version = ?1 WHERE singleton = 1",
            [new_key.version],
        )?;
        transaction.execute(
            r"INSERT INTO smcv_maintenance_jobs (
                   job_id, job_kind, state, source_key_version, target_key_version,
                   stage, last_row_id, updated_at_unix_ms
               ) VALUES (?1, 'kek_rotation', 'running', ?2, ?3, 'auxiliary', 0, ?4)",
            params![
                job_id.as_bytes(),
                source_key_version,
                new_key.version,
                now_unix_ms,
            ],
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(KekRotationJob {
            job_id,
            source_key_version,
            target_key_version: new_key.version,
            stage: RotationStage::Auxiliary,
            last_row_id: 0,
        })
    }

    /// Loads the one unfinished KEK rotation, if any.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid durable state or storage failure.
    pub fn active_kek_rotation(&self) -> StorageResult<Option<KekRotationJob>> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT job_id, source_key_version, target_key_version, stage, last_row_id
                   FROM smcv_maintenance_jobs
                   WHERE job_kind = 'kek_rotation' AND state IN ('pending', 'running', 'paused')",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        row.as_ref().map(parse_job).transpose()
    }

    /// Fetches the next bounded source-key batch for the durable stage.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, stale job state, or corrupt widths.
    pub fn next_rewrap_batch(
        &self,
        job: &KekRotationJob,
        limit: u16,
    ) -> StorageResult<Vec<RewrapItem>> {
        if limit == 0 || limit > 256 {
            return Err(StorageError::Conflict);
        }
        let current = self
            .active_kek_rotation()?
            .ok_or(StorageError::StateConflict)?;
        if current != *job || job.stage == RotationStage::Finalize {
            return Err(StorageError::StateConflict);
        }
        let connection = self.lock()?;
        let (sql, kind) = stage_query(job.stage);
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map(
            params![job.source_key_version, job.last_row_id, limit],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let mut items = Vec::with_capacity(usize::from(limit));
        for row in rows {
            let (row_id, subtype, object_id, version, nonce, wrapped) = row?;
            items.push(RewrapItem {
                row_id,
                kind: kind(&subtype)?,
                object_id: ObjectId::from_uuid(
                    uuid::Uuid::from_slice(&object_id).map_err(|_| StorageError::InvalidData)?,
                ),
                object_version: u64::try_from(version).map_err(|_| StorageError::InvalidData)?,
                nonce: nonce.try_into().map_err(|_| StorageError::InvalidData)?,
                wrapped_key: wrapped.try_into().map_err(|_| StorageError::InvalidData)?,
            });
        }
        Ok(items)
    }

    /// Applies one rewrap batch and advances its checkpoint atomically.
    ///
    /// # Errors
    ///
    /// Returns a conflict if any source row or job checkpoint changed.
    pub fn apply_rewrap_batch(
        &self,
        job: &KekRotationJob,
        items: &[RewrappedItem],
        now_unix_ms: i64,
    ) -> StorageResult<KekRotationJob> {
        if items.is_empty() || items.len() > 256 {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_job(&transaction, job)?;
        let mut last = job.last_row_id;
        for item in items {
            if item.source.row_id <= last || update_rewrap(&transaction, job, item)? != 1 {
                return Err(StorageError::Conflict);
            }
            last = item.source.row_id;
        }
        let changed = transaction.execute(
            "UPDATE smcv_maintenance_jobs SET last_row_id = ?1, updated_at_unix_ms = ?2 WHERE job_id = ?3 AND stage = ?4 AND last_row_id = ?5",
            params![
                last,
                now_unix_ms,
                job.job_id.as_bytes(),
                job.stage.as_str(),
                job.last_row_id,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        transaction.commit()?;
        Ok(KekRotationJob {
            last_row_id: last,
            ..*job
        })
    }

    /// Advances an exhausted scan stage with an atomic checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a conflict if rows remain or the job changed.
    pub fn advance_rotation_stage(
        &self,
        job: &KekRotationJob,
        now_unix_ms: i64,
    ) -> StorageResult<KekRotationJob> {
        let next = job.stage.next().ok_or(StorageError::StateConflict)?;
        if !self.next_rewrap_batch(job, 1)?.is_empty() {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE smcv_maintenance_jobs SET stage = ?1, last_row_id = 0, updated_at_unix_ms = ?2 WHERE job_id = ?3 AND stage = ?4 AND last_row_id = ?5",
            params![
                next.as_str(),
                now_unix_ms,
                job.job_id.as_bytes(),
                job.stage.as_str(),
                job.last_row_id,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        Ok(KekRotationJob {
            stage: next,
            last_row_id: 0,
            ..*job
        })
    }

    /// Retires the old KEK only after inventory is empty and appends audit.
    ///
    /// # Errors
    ///
    /// Returns a conflict if inventory, job, active key, or audit head changed.
    pub fn finish_kek_rotation(
        &self,
        job: &KekRotationJob,
        now_unix_ms: i64,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        if job.stage != RotationStage::Finalize {
            return Err(StorageError::StateConflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_job(&transaction, job)?;
        require_audit_head(&transaction, audit)?;
        if source_inventory(&transaction, job.source_key_version)? != 0 {
            return Err(StorageError::Conflict);
        }
        if transaction.execute(
            "UPDATE smcv_key_registry SET state = 'retired' WHERE key_kind = 'kek' AND key_version = ?1 AND state = 'retiring'",
            [job.source_key_version],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        transaction.execute(
            "UPDATE smcv_maintenance_jobs SET state = 'completed', updated_at_unix_ms = ?1 WHERE job_id = ?2",
            params![now_unix_ms, job.job_id.as_bytes()],
        )?;
        if transaction.execute(
            "UPDATE smcv_installation_state SET activation_state = 'ready' WHERE singleton = 1 AND activation_state = 'maintenance' AND active_kek_version = ?1",
            [job.target_key_version],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }
}

type KindParser = fn(&str) -> StorageResult<RewrapKind>;

fn stage_query(stage: RotationStage) -> (&'static str, KindParser) {
    match stage {
        RotationStage::Auxiliary => (
            r"SELECT rowid, key_kind, object_id, key_version, nonce, wrapped_key
               FROM smcv_key_registry
               WHERE wrapping_kek_version = ?1 AND rowid > ?2 AND key_kind != 'kek'
               ORDER BY rowid LIMIT ?3",
            parse_auxiliary_kind,
        ),
        RotationStage::NamespaceMetadata => (
            r"SELECT rowid, 'namespace_metadata', namespace_id, metadata_version, dek_nonce, wrapped_dek
               FROM smcv_namespaces WHERE kek_version = ?1 AND rowid > ?2 ORDER BY rowid LIMIT ?3",
            |_| Ok(RewrapKind::NamespaceMetadata),
        ),
        RotationStage::SecretMetadata => (
            r"SELECT rowid, 'secret_metadata', secret_id, metadata_version, metadata_dek_nonce, metadata_wrapped_dek
               FROM smcv_secrets WHERE metadata_kek_version = ?1 AND rowid > ?2 ORDER BY rowid LIMIT ?3",
            |_| Ok(RewrapKind::SecretMetadata),
        ),
        RotationStage::SecretVersions => (
            r"SELECT rowid, 'secret_version', secret_id, version, dek_nonce, wrapped_dek
               FROM smcv_secret_versions WHERE kek_version = ?1 AND rowid > ?2 ORDER BY rowid LIMIT ?3",
            |_| Ok(RewrapKind::SecretVersion),
        ),
        RotationStage::Finalize => (
            "SELECT 0, '', zeroblob(16), 0, zeroblob(24), zeroblob(48) WHERE 0",
            |_| Err(StorageError::StateConflict),
        ),
    }
}

fn parse_auxiliary_kind(value: &str) -> StorageResult<RewrapKind> {
    match value {
        "blind_index" => Ok(RewrapKind::BlindIndexKey),
        "audit" => Ok(RewrapKind::AuditKey),
        "token_verifier" => Ok(RewrapKind::TokenVerifierKey),
        _ => Err(StorageError::InvalidData),
    }
}

fn require_job(transaction: &Transaction<'_>, job: &KekRotationJob) -> StorageResult<()> {
    let count: i64 = transaction.query_row(
        r"SELECT count(*) FROM smcv_maintenance_jobs
           WHERE job_id = ?1 AND state = 'running' AND source_key_version = ?2
             AND target_key_version = ?3 AND stage = ?4 AND last_row_id = ?5",
        params![
            job.job_id.as_bytes(),
            job.source_key_version,
            job.target_key_version,
            job.stage.as_str(),
            job.last_row_id,
        ],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

fn update_rewrap(
    transaction: &Transaction<'_>,
    job: &KekRotationJob,
    item: &RewrappedItem,
) -> StorageResult<usize> {
    let sql = match item.source.kind {
        RewrapKind::BlindIndexKey | RewrapKind::AuditKey | RewrapKind::TokenVerifierKey => {
            "UPDATE smcv_key_registry SET nonce = ?1, wrapped_key = ?2, wrapping_kek_version = ?3 WHERE rowid = ?4 AND wrapping_kek_version = ?5"
        }
        RewrapKind::NamespaceMetadata => {
            "UPDATE smcv_namespaces SET dek_nonce = ?1, wrapped_dek = ?2, kek_version = ?3 WHERE rowid = ?4 AND kek_version = ?5"
        }
        RewrapKind::SecretMetadata => {
            "UPDATE smcv_secrets SET metadata_dek_nonce = ?1, metadata_wrapped_dek = ?2, metadata_kek_version = ?3 WHERE rowid = ?4 AND metadata_kek_version = ?5"
        }
        RewrapKind::SecretVersion => {
            "UPDATE smcv_secret_versions SET dek_nonce = ?1, wrapped_dek = ?2, kek_version = ?3 WHERE rowid = ?4 AND kek_version = ?5"
        }
    };
    transaction
        .execute(
            sql,
            params![
                item.nonce.as_slice(),
                item.wrapped_key.as_slice(),
                job.target_key_version,
                item.source.row_id,
                job.source_key_version,
            ],
        )
        .map_err(Into::into)
}

fn source_inventory(transaction: &Transaction<'_>, version: u32) -> StorageResult<i64> {
    transaction
        .query_row(
            r"SELECT
                 (SELECT count(*) FROM smcv_key_registry WHERE wrapping_kek_version = ?1) +
                 (SELECT count(*) FROM smcv_namespaces WHERE kek_version = ?1) +
                 (SELECT count(*) FROM smcv_secrets WHERE metadata_kek_version = ?1) +
                 (SELECT count(*) FROM smcv_secret_versions WHERE kek_version = ?1)",
            [version],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

type RawJob = (Vec<u8>, i64, i64, String, i64);

fn parse_job(row: &RawJob) -> StorageResult<KekRotationJob> {
    Ok(KekRotationJob {
        job_id: MaintenanceJobId::from_uuid(
            uuid::Uuid::from_slice(&row.0).map_err(|_| StorageError::InvalidData)?,
        ),
        source_key_version: u32::try_from(row.1).map_err(|_| StorageError::InvalidData)?,
        target_key_version: u32::try_from(row.2).map_err(|_| StorageError::InvalidData)?,
        stage: RotationStage::parse(&row.3)?,
        last_row_id: row.4,
    })
}
