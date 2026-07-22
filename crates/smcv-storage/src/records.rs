use core::fmt;

use rusqlite::{OptionalExtension, Transaction, params};
use smcv_core::{
    AuditEventId, InstallationId, NamespaceId, ObjectId, PrincipalId, RequestId, SecretId,
    SecretSchedule,
};
use uuid::Uuid;

use crate::{SqliteStore, StorageError, StorageResult};

/// Ciphertext envelope stored without plaintext accessors.
pub struct EncryptedRecord {
    /// Public payload nonce.
    pub nonce: [u8; 24],
    /// Authenticated payload ciphertext and tag.
    pub ciphertext: Vec<u8>,
    /// Public nonce used to wrap this record's DEK.
    pub dek_nonce: [u8; 24],
    /// Wrapped 256-bit DEK and authentication tag.
    pub wrapped_dek: [u8; 48],
    /// KEK version that wraps the DEK.
    pub kek_version: u32,
}

impl fmt::Debug for EncryptedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedRecord")
            .field("nonce", &"[PUBLIC NONCE]")
            .field("ciphertext", &"[CIPHERTEXT]")
            .field("dek_nonce", &"[PUBLIC NONCE]")
            .field("wrapped_dek", &"[WRAPPED KEY]")
            .field("kek_version", &self.kek_version)
            .finish()
    }
}

/// Safe append-chain head used to construct the next audit commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditHead {
    /// Last committed sequence, zero for a new installation.
    pub sequence: u64,
    /// Last commitment, zeros for a new installation.
    pub commitment: [u8; 32],
}

/// Complete safe audit row with its precomputed keyed commitment.
pub struct AuditRecord<'a> {
    /// Expected next local sequence.
    pub sequence: u64,
    /// Random event identity.
    pub event_id: AuditEventId,
    /// Installation producing the event.
    pub installation_id: InstallationId,
    /// Recovery epoch producing the event.
    pub recovery_epoch: u64,
    /// Event timestamp.
    pub occurred_at_unix_ms: i64,
    /// Correlated request.
    pub request_id: RequestId,
    /// Acting principal when known.
    pub actor_principal_id: Option<PrincipalId>,
    /// Closed action.
    pub action: &'a str,
    /// Closed target kind.
    pub target_kind: &'a str,
    /// Opaque target.
    pub target_id: Option<ObjectId>,
    /// Closed outcome.
    pub outcome: &'a str,
    /// Expected predecessor commitment.
    pub previous_commitment: [u8; 32],
    /// Keyed commitment over this event and predecessor.
    pub commitment: [u8; 32],
}

impl fmt::Debug for AuditRecord<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditRecord")
            .field("sequence", &self.sequence)
            .field("event_id", &self.event_id)
            .field("action", &self.action)
            .field("target_kind", &self.target_kind)
            .field("target_id", &self.target_id)
            .field("outcome", &self.outcome)
            .field("commitment", &"[COMMITMENT]")
            .finish_non_exhaustive()
    }
}

/// Owned audit record used by the verification service.
pub struct StoredAuditRecord {
    /// Monotonic sequence.
    pub sequence: u64,
    /// Random event identity.
    pub event_id: AuditEventId,
    /// Installation segment identity.
    pub installation_id: InstallationId,
    /// Recovery epoch.
    pub recovery_epoch: u64,
    /// Event timestamp.
    pub occurred_at_unix_ms: i64,
    /// Correlated request.
    pub request_id: RequestId,
    /// Acting principal when known.
    pub actor_principal_id: Option<PrincipalId>,
    /// Closed action.
    pub action: String,
    /// Closed target kind.
    pub target_kind: String,
    /// Opaque target.
    pub target_id: Option<ObjectId>,
    /// Closed outcome.
    pub outcome: String,
    /// Stored predecessor commitment.
    pub previous_commitment: [u8; 32],
    /// Stored event commitment.
    pub commitment: [u8; 32],
}

impl fmt::Debug for StoredAuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAuditRecord")
            .field("sequence", &self.sequence)
            .field("event_id", &self.event_id)
            .field("action", &self.action)
            .field("target_kind", &self.target_kind)
            .field("target_id", &self.target_id)
            .field("outcome", &self.outcome)
            .field("commitment", &"[COMMITMENT]")
            .finish_non_exhaustive()
    }
}

/// Encrypted namespace row ready for atomic persistence.
pub struct NamespaceInsert {
    /// Stable namespace identity.
    pub namespace_id: NamespaceId,
    /// Parent namespace, or none for a top-level namespace.
    pub parent_namespace_id: Option<NamespaceId>,
    /// Keyed exact-match index over its protected name.
    pub name_index: [u8; 32],
    /// Encrypted metadata document.
    pub metadata: EncryptedRecord,
    /// Keyed commitment over integrity-sensitive clear namespace state.
    pub state_commitment: [u8; 32],
    /// Creation timestamp.
    pub created_at_unix_ms: i64,
}

/// Safe namespace state plus encrypted metadata returned by the repository.
pub struct NamespaceRecord {
    /// Stable namespace identity.
    pub namespace_id: NamespaceId,
    /// Parent namespace, or none at the root.
    pub parent_namespace_id: Option<NamespaceId>,
    /// Keyed exact-name index included in the state commitment.
    pub name_index: [u8; 32],
    /// Clear lifecycle state.
    pub lifecycle_state: String,
    /// Optimistic revision.
    pub revision: u64,
    /// Metadata envelope version.
    pub metadata_version: u64,
    /// Encrypted namespace metadata.
    pub metadata: EncryptedRecord,
    /// Stored keyed commitment over integrity-sensitive clear state.
    pub state_commitment: [u8; 32],
}

/// Encrypted secret and initial version ready for atomic persistence.
pub struct SecretInsert {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Owning namespace.
    pub namespace_id: NamespaceId,
    /// Keyed exact-match index over its protected name.
    pub name_index: [u8; 32],
    /// Encrypted metadata document.
    pub metadata: EncryptedRecord,
    /// Encrypted immutable version 1 payload.
    pub payload: EncryptedRecord,
    /// Expiration and upstream-credential rotation schedule for version 1.
    pub schedule: SecretSchedule,
    /// Keyed commitment over integrity-sensitive clear secret state.
    pub state_commitment: [u8; 32],
    /// Creating principal when known.
    pub created_by_principal_id: Option<PrincipalId>,
    /// Creation timestamp.
    pub created_at_unix_ms: i64,
}

/// Next encrypted immutable version for an existing secret.
pub struct SecretVersionInsert {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Required current version before append.
    pub expected_current_version: u64,
    /// Required current revision before append.
    pub expected_revision: u64,
    /// New encrypted payload.
    pub payload: EncryptedRecord,
    /// Expiration and upstream-credential rotation schedule for the new value.
    pub schedule: SecretSchedule,
    /// Commitment for the next current-version/revision state.
    pub next_state_commitment: [u8; 32],
    /// Updating principal when known.
    pub created_by_principal_id: Option<PrincipalId>,
    /// Update timestamp.
    pub created_at_unix_ms: i64,
}

/// Optimistically guarded lifecycle transition.
pub struct SecretLifecycleChange {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Required current revision.
    pub expected_revision: u64,
    /// Required current lifecycle value.
    pub from_state: &'static str,
    /// New lifecycle value.
    pub to_state: &'static str,
    /// Transition timestamp.
    pub changed_at_unix_ms: i64,
    /// Commitment for the next lifecycle/revision state.
    pub next_state_commitment: [u8; 32],
}

/// Explicit retention-checked purge request.
pub struct SecretPurge {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Required current revision.
    pub expected_revision: u64,
    /// A deleted record must be no newer than this cutoff.
    pub retention_cutoff_unix_ms: i64,
    /// Purge timestamp.
    pub purged_at_unix_ms: i64,
}

/// Safe secret state plus encrypted metadata returned by the repository.
pub struct SecretRecord {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Owning namespace.
    pub namespace_id: NamespaceId,
    /// Keyed exact-name index included in the state commitment.
    pub name_index: [u8; 32],
    /// Lifecycle state without human-readable metadata.
    pub lifecycle_state: String,
    /// Current immutable version.
    pub current_version: u64,
    /// Optimistic concurrency revision.
    pub revision: u64,
    /// Metadata envelope version.
    pub metadata_version: u64,
    /// Encrypted metadata.
    pub metadata: EncryptedRecord,
    /// Current immutable version's advisory schedule.
    pub schedule: SecretSchedule,
    /// Stored keyed commitment over integrity-sensitive clear state.
    pub state_commitment: [u8; 32],
}

/// Opaque current-version schedule returned by the due-work query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledSecret {
    /// Stable secret identity; no protected display metadata is exposed.
    pub secret_id: SecretId,
    /// Current immutable version represented by this schedule.
    pub version: u64,
    /// Clear bounded operational timestamps.
    pub schedule: SecretSchedule,
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("secret_id", &self.secret_id)
            .field("namespace_id", &self.namespace_id)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("current_version", &self.current_version)
            .field("revision", &self.revision)
            .field("metadata", &"[ENCRYPTED]")
            .finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Loads safe state and encrypted metadata for one namespace.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent namespace or invalid durable widths.
    pub fn namespace(&self, namespace_id: NamespaceId) -> StorageResult<NamespaceRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT parent_namespace_id, name_index, lifecycle_state, revision,
                          metadata_version, metadata_nonce, metadata_ciphertext,
                          dek_nonce, wrapped_dek, kek_version, state_commitment
                   FROM smcv_namespaces WHERE namespace_id = ?1",
                [namespace_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        let parent_namespace_id = row
            .0
            .map(|bytes| parse_uuid(&bytes).map(NamespaceId::from_uuid))
            .transpose()?;
        Ok(NamespaceRecord {
            namespace_id,
            parent_namespace_id,
            name_index: row.1.try_into().map_err(|_| StorageError::InvalidData)?,
            lifecycle_state: row.2,
            revision: u64::try_from(row.3).map_err(|_| StorageError::InvalidData)?,
            metadata_version: u64::try_from(row.4).map_err(|_| StorageError::InvalidData)?,
            metadata: parse_encrypted((row.5, row.6, row.7, row.8, row.9))?,
            state_commitment: row.10.try_into().map_err(|_| StorageError::InvalidData)?,
        })
    }

    /// Returns the one-based depth of an existing namespace.
    ///
    /// The walk is bounded at 33 rows so corrupt or unsupported hierarchy
    /// depth cannot consume unbounded work.
    ///
    /// # Errors
    ///
    /// Returns not-initialized for an absent namespace and an error for invalid
    /// or unavailable durable state.
    pub fn namespace_depth(&self, namespace_id: NamespaceId) -> StorageResult<u16> {
        let connection = self.lock()?;
        let depth: Option<i64> = connection.query_row(
            r"WITH RECURSIVE ancestors(namespace_id, parent_namespace_id, depth) AS (
                   SELECT namespace_id, parent_namespace_id, 1
                     FROM smcv_namespaces WHERE namespace_id = ?1
                   UNION ALL
                   SELECT parent.namespace_id, parent.parent_namespace_id, child.depth + 1
                     FROM smcv_namespaces AS parent
                     JOIN ancestors AS child ON parent.namespace_id = child.parent_namespace_id
                    WHERE child.depth <= 32
               )
               SELECT max(depth) FROM ancestors",
            [namespace_id.as_bytes()],
            |row| row.get(0),
        )?;
        depth
            .ok_or(StorageError::NotInitialized)
            .and_then(|value| u16::try_from(value).map_err(|_| StorageError::InvalidData))
    }

    /// Returns the current local audit-chain head.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable storage or invalid fixed-width data.
    pub fn audit_head(&self) -> StorageResult<AuditHead> {
        let connection = self.lock()?;
        audit_head_on(&connection)
    }

    /// Appends one audit event after verifying its chain precondition.
    ///
    /// # Errors
    ///
    /// Returns a conflict for a stale chain head and fails closed for any
    /// persistence error.
    pub fn append_audit(&self, audit: &AuditRecord<'_>) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Reads a bounded ordered page for audit-chain verification.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page limit, unavailable storage, or
    /// invalid fixed-width durable data.
    pub fn audit_records_after(
        &self,
        after_sequence: u64,
        limit: u16,
    ) -> StorageResult<Vec<StoredAuditRecord>> {
        if limit == 0 || limit > 1000 {
            return Err(StorageError::Conflict);
        }
        let after_sequence = sql_i64(after_sequence)?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r"SELECT sequence, event_id, installation_id, recovery_epoch,
                     occurred_at_unix_ms, request_id, actor_principal_id, action,
                     target_kind, target_id, outcome, previous_commitment, commitment
              FROM smcv_audit_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_sequence, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
            ))
        })?;
        let mut records = Vec::with_capacity(usize::from(limit));
        for row in rows {
            records.push(parse_audit(row?)?);
        }
        Ok(records)
    }

    /// Atomically creates an encrypted namespace and its audit event.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate namespace/index, stale audit head, or
    /// failed transaction.
    pub fn create_namespace(
        &self,
        namespace: &NamespaceInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let parent = namespace
            .parent_namespace_id
            .map(|identifier| identifier.as_bytes().to_vec());
        let changed = transaction.execute(
            r"INSERT OR IGNORE INTO smcv_namespaces (
                   namespace_id, parent_namespace_id, name_index, metadata_version,
                   metadata_nonce, metadata_ciphertext, dek_nonce, wrapped_dek,
                   kek_version, lifecycle_state, revision, state_commitment, created_at_unix_ms,
                   updated_at_unix_ms
               ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 'active', 1, ?9, ?10, ?10)",
            params![
                namespace.namespace_id.as_bytes(),
                parent,
                namespace.name_index.as_slice(),
                namespace.metadata.nonce.as_slice(),
                namespace.metadata.ciphertext.as_slice(),
                namespace.metadata.dek_nonce.as_slice(),
                namespace.metadata.wrapped_dek.as_slice(),
                namespace.metadata.kek_version,
                namespace.state_commitment.as_slice(),
                namespace.created_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically creates an encrypted secret, immutable version 1, and audit.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent namespace, duplicate secret/index, stale
    /// audit head, or failed transaction.
    pub fn create_secret(
        &self,
        secret: &SecretInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let changed = transaction.execute(
            r"INSERT OR IGNORE INTO smcv_secrets (
                   secret_id, namespace_id, name_index, metadata_version,
                   metadata_nonce, metadata_ciphertext, metadata_dek_nonce,
                   metadata_wrapped_dek, metadata_kek_version, lifecycle_state,
                   current_version, revision, state_commitment, created_at_unix_ms, updated_at_unix_ms
               ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 'active', 1, 1, ?9, ?10, ?10)",
            params![
                secret.secret_id.as_bytes(),
                secret.namespace_id.as_bytes(),
                secret.name_index.as_slice(),
                secret.metadata.nonce.as_slice(),
                secret.metadata.ciphertext.as_slice(),
                secret.metadata.dek_nonce.as_slice(),
                secret.metadata.wrapped_dek.as_slice(),
                secret.metadata.kek_version,
                secret.state_commitment.as_slice(),
                secret.created_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_version(
            &transaction,
            secret.secret_id,
            1,
            &secret.payload,
            secret.schedule,
            secret.created_by_principal_id,
            secret.created_at_unix_ms,
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically appends a new immutable payload, advances the pointer, and
    /// records audit under optimistic concurrency preconditions.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale version/revision or audit preconditions.
    pub fn append_secret_version(
        &self,
        version: &SecretVersionInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let next_version = version
            .expected_current_version
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let next_version_sql = sql_i64(next_version)?;
        let expected_current_sql = sql_i64(version.expected_current_version)?;
        let expected_revision_sql = sql_i64(version.expected_revision)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let current: Option<(i64, i64, String)> = transaction
            .query_row(
                "SELECT current_version, revision, lifecycle_state FROM smcv_secrets WHERE secret_id = ?1",
                [version.secret_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((current_version, current_revision, lifecycle_state)) = current else {
            return Err(StorageError::Conflict);
        };
        if current_version != expected_current_sql
            || current_revision != expected_revision_sql
            || lifecycle_state != "active"
        {
            return Err(StorageError::Conflict);
        }
        insert_version(
            &transaction,
            version.secret_id,
            next_version,
            &version.payload,
            version.schedule,
            version.created_by_principal_id,
            version.created_at_unix_ms,
        )?;
        let changed = transaction.execute(
            r"UPDATE smcv_secrets
               SET current_version = ?1, revision = revision + 1,
                   state_commitment = ?2, updated_at_unix_ms = ?3
               WHERE secret_id = ?4 AND current_version = ?5 AND revision = ?6
                 AND lifecycle_state = 'active'",
            params![
                next_version_sql,
                version.next_state_commitment.as_slice(),
                version.created_at_unix_ms,
                version.secret_id.as_bytes(),
                expected_current_sql,
                expected_revision_sql,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_version)
    }

    /// Loads safe state and encrypted metadata for one exact secret.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent secret or invalid durable widths.
    pub fn secret(&self, secret_id: SecretId) -> StorageResult<SecretRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT namespace_id, name_index, lifecycle_state, current_version, revision,
                          metadata_version, metadata_nonce, metadata_ciphertext,
                          metadata_dek_nonce, metadata_wrapped_dek, metadata_kek_version,
                          state_commitment,
                          (SELECT expires_at_unix_ms FROM smcv_secret_versions
                            WHERE secret_id = smcv_secrets.secret_id AND version = current_version),
                          (SELECT rotation_due_at_unix_ms FROM smcv_secret_versions
                            WHERE secret_id = smcv_secrets.secret_id AND version = current_version)
                   FROM smcv_secrets WHERE secret_id = ?1",
                [secret_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, Vec<u8>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_secret(secret_id, row)
    }

    /// Returns the encrypted candidate for one namespace-scoped keyed index.
    ///
    /// Callers must decrypt and compare the canonical name to handle the
    /// theoretical keyed-index collision case.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable storage or invalid durable widths.
    pub fn secret_by_name_index(
        &self,
        namespace_id: NamespaceId,
        name_index: &[u8; 32],
    ) -> StorageResult<Option<SecretRecord>> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT secret_id, name_index, lifecycle_state, current_version, revision,
                          metadata_version, metadata_nonce, metadata_ciphertext,
                          metadata_dek_nonce, metadata_wrapped_dek, metadata_kek_version,
                          state_commitment,
                          (SELECT expires_at_unix_ms FROM smcv_secret_versions
                            WHERE secret_id = smcv_secrets.secret_id AND version = current_version),
                          (SELECT rotation_due_at_unix_ms FROM smcv_secret_versions
                            WHERE secret_id = smcv_secrets.secret_id AND version = current_version)
                   FROM smcv_secrets WHERE namespace_id = ?1 AND name_index = ?2",
                params![namespace_id.as_bytes(), name_index.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, Vec<u8>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                    ))
                },
            )
            .optional()?;
        row.map(|row| {
            let secret_id = SecretId::from_uuid(parse_uuid(&row.0)?);
            let raw = (
                namespace_id.as_bytes().to_vec(),
                row.1,
                row.2,
                row.3,
                row.4,
                row.5,
                row.6,
                row.7,
                row.8,
                row.9,
                row.10,
                row.11,
                row.12,
                row.13,
            );
            parse_secret(secret_id, raw)
        })
        .transpose()
    }

    /// Loads one encrypted immutable secret version.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent version or invalid durable widths.
    pub fn encrypted_secret_version(
        &self,
        secret_id: SecretId,
        version: u64,
    ) -> StorageResult<EncryptedRecord> {
        let version = sql_i64(version)?;
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT payload_nonce, payload_ciphertext, dek_nonce, wrapped_dek, kek_version
                   FROM smcv_secret_versions WHERE secret_id = ?1 AND version = ?2",
                params![secret_id.as_bytes(), version],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_encrypted(row)
    }

    /// Returns active current versions whose expiration or upstream rotation
    /// schedule is due, ordered deterministically and bounded by `limit`.
    ///
    /// # Errors
    ///
    /// Returns a conflict for invalid bounds and an error for unavailable or
    /// invalid durable state.
    pub fn scheduled_secrets_due(
        &self,
        now_unix_ms: i64,
        limit: u16,
    ) -> StorageResult<Vec<ScheduledSecret>> {
        if now_unix_ms < 0 || limit == 0 || limit > 1000 {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r"SELECT s.secret_id, v.version, v.expires_at_unix_ms, v.rotation_due_at_unix_ms
               FROM smcv_secrets AS s
               JOIN smcv_secret_versions AS v
                 ON v.secret_id = s.secret_id AND v.version = s.current_version
               WHERE s.lifecycle_state = 'active'
                 AND (v.expires_at_unix_ms <= ?1 OR v.rotation_due_at_unix_ms <= ?1)
               ORDER BY min(
                   coalesce(v.expires_at_unix_ms, 9223372036854775807),
                   coalesce(v.rotation_due_at_unix_ms, 9223372036854775807)
               ), s.secret_id
               LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_unix_ms, limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut scheduled = Vec::new();
        for row in rows {
            let (secret_id, version, expires, rotation) = row?;
            scheduled.push(ScheduledSecret {
                secret_id: SecretId::from_uuid(parse_uuid(&secret_id)?),
                version: u64::try_from(version).map_err(|_| StorageError::InvalidData)?,
                schedule: SecretSchedule {
                    expires_at_unix_ms: expires,
                    rotation_due_at_unix_ms: rotation,
                },
            });
        }
        Ok(scheduled)
    }

    /// Atomically changes lifecycle state and appends its audit event.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale revision/state or audit preconditions.
    pub fn change_secret_lifecycle(
        &self,
        change: &SecretLifecycleChange,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let expected_revision = sql_i64(change.expected_revision)?;
        let next_revision = change
            .expected_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let next_revision_sql = sql_i64(next_revision)?;
        let deleted_at = if change.to_state == "deleted" {
            Some(change.changed_at_unix_ms)
        } else {
            None
        };
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let changed = transaction.execute(
            r"UPDATE smcv_secrets
               SET lifecycle_state = ?1, revision = ?2, updated_at_unix_ms = ?3,
                   deleted_at_unix_ms = ?4, state_commitment = ?5
               WHERE secret_id = ?6 AND revision = ?7 AND lifecycle_state = ?8",
            params![
                change.to_state,
                next_revision_sql,
                change.changed_at_unix_ms,
                deleted_at,
                change.next_state_commitment.as_slice(),
                change.secret_id.as_bytes(),
                expected_revision,
                change.from_state,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_revision)
    }

    /// Physically removes current-vault encrypted rows only after explicit
    /// deleted-state retention checks, while retaining an opaque tombstone and
    /// append-only audit history.
    ///
    /// # Errors
    ///
    /// Returns a conflict unless the exact revision is deleted and old enough,
    /// or if the audit head changed.
    pub fn purge_secret(&self, purge: &SecretPurge, audit: &AuditRecord<'_>) -> StorageResult<()> {
        let expected_revision = sql_i64(purge.expected_revision)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.pragma_update(None, "defer_foreign_keys", true)?;
        require_audit_head(&transaction, audit)?;
        let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = transaction
            .query_row(
                r"SELECT namespace_id, name_index, current_version, deleted_at_unix_ms
                   FROM smcv_secrets
                   WHERE secret_id = ?1 AND revision = ?2 AND lifecycle_state = 'deleted'",
                params![purge.secret_id.as_bytes(), expected_revision],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((namespace_id, name_index, last_version, deleted_at)) = row else {
            return Err(StorageError::Conflict);
        };
        if deleted_at > purge.retention_cutoff_unix_ms {
            return Err(StorageError::Conflict);
        }
        transaction.execute(
            "UPDATE smcv_mutation_guard SET purge_enabled = 1 WHERE singleton = 1",
            [],
        )?;
        transaction.execute(
            r"INSERT INTO smcv_secret_tombstones (
                   secret_id, namespace_id, name_index, last_version,
                   purged_at_unix_ms, retention_cutoff_unix_ms
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                purge.secret_id.as_bytes(),
                namespace_id,
                name_index,
                last_version,
                purge.purged_at_unix_ms,
                purge.retention_cutoff_unix_ms,
            ],
        )?;
        transaction.execute(
            "DELETE FROM smcv_secret_versions WHERE secret_id = ?1",
            [purge.secret_id.as_bytes()],
        )?;
        transaction.execute(
            "DELETE FROM smcv_secrets WHERE secret_id = ?1",
            [purge.secret_id.as_bytes()],
        )?;
        transaction.execute(
            "UPDATE smcv_mutation_guard SET purge_enabled = 0 WHERE singleton = 1",
            [],
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }
}

fn audit_head_on(connection: &rusqlite::Connection) -> StorageResult<AuditHead> {
    let row: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT sequence, commitment FROM smcv_audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((sequence, commitment)) = row {
        Ok(AuditHead {
            sequence: u64::try_from(sequence).map_err(|_| StorageError::InvalidData)?,
            commitment: commitment
                .try_into()
                .map_err(|_| StorageError::InvalidData)?,
        })
    } else {
        Ok(AuditHead {
            sequence: 0,
            commitment: [0; 32],
        })
    }
}

pub(super) fn require_audit_head(
    transaction: &Transaction<'_>,
    audit: &AuditRecord<'_>,
) -> StorageResult<()> {
    let head = audit_head_on(transaction)?;
    if audit.sequence != head.sequence + 1 || audit.previous_commitment != head.commitment {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub(super) fn insert_audit(
    transaction: &Transaction<'_>,
    audit: &AuditRecord<'_>,
) -> StorageResult<()> {
    let sequence = sql_i64(audit.sequence)?;
    let recovery_epoch = sql_i64(audit.recovery_epoch)?;
    let actor = audit
        .actor_principal_id
        .map(|identifier| identifier.as_bytes().to_vec());
    let target = audit
        .target_id
        .map(|identifier| identifier.as_bytes().to_vec());
    transaction.execute(
        r"INSERT INTO smcv_audit_events (
               sequence, event_id, installation_id, recovery_epoch, occurred_at_unix_ms,
               request_id, actor_principal_id, action, target_kind, target_id,
               outcome, previous_commitment, commitment
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            sequence,
            audit.event_id.as_bytes(),
            audit.installation_id.as_bytes(),
            recovery_epoch,
            audit.occurred_at_unix_ms,
            audit.request_id.as_bytes(),
            actor,
            audit.action,
            audit.target_kind,
            target,
            audit.outcome,
            audit.previous_commitment.as_slice(),
            audit.commitment.as_slice(),
        ],
    )?;
    Ok(())
}

fn insert_version(
    transaction: &Transaction<'_>,
    secret_id: SecretId,
    version: u64,
    payload: &EncryptedRecord,
    schedule: SecretSchedule,
    actor: Option<PrincipalId>,
    created_at_unix_ms: i64,
) -> StorageResult<()> {
    let version = sql_i64(version)?;
    let actor = actor.map(|identifier| identifier.as_bytes().to_vec());
    transaction.execute(
        r"INSERT INTO smcv_secret_versions (
               secret_id, version, envelope_version, algorithm_suite, kek_version,
               payload_nonce, payload_ciphertext, dek_nonce, wrapped_dek,
               expires_at_unix_ms, rotation_due_at_unix_ms,
               created_by_principal_id, created_at_unix_ms
           ) VALUES (?1, ?2, 1, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            secret_id.as_bytes(),
            version,
            payload.kek_version,
            payload.nonce.as_slice(),
            payload.ciphertext.as_slice(),
            payload.dek_nonce.as_slice(),
            payload.wrapped_dek.as_slice(),
            schedule.expires_at_unix_ms,
            schedule.rotation_due_at_unix_ms,
            actor,
            created_at_unix_ms,
        ],
    )?;
    Ok(())
}

type RawEncrypted = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
type RawAudit = (
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    String,
    Option<Vec<u8>>,
    String,
    Vec<u8>,
    Vec<u8>,
);
type RawSecret = (
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<i64>,
    Option<i64>,
);

fn parse_secret(secret_id: SecretId, row: RawSecret) -> StorageResult<SecretRecord> {
    let (
        namespace,
        name_index,
        state,
        current,
        revision,
        metadata_version,
        nonce,
        cipher,
        dek_nonce,
        wrapped,
        kek,
        state_commitment,
        expires_at_unix_ms,
        rotation_due_at_unix_ms,
    ) = row;
    Ok(SecretRecord {
        secret_id,
        namespace_id: NamespaceId::from_uuid(parse_uuid(&namespace)?),
        name_index: name_index
            .try_into()
            .map_err(|_| StorageError::InvalidData)?,
        lifecycle_state: state,
        current_version: u64::try_from(current).map_err(|_| StorageError::InvalidData)?,
        revision: u64::try_from(revision).map_err(|_| StorageError::InvalidData)?,
        metadata_version: u64::try_from(metadata_version).map_err(|_| StorageError::InvalidData)?,
        metadata: parse_encrypted((nonce, cipher, dek_nonce, wrapped, kek))?,
        schedule: SecretSchedule {
            expires_at_unix_ms,
            rotation_due_at_unix_ms,
        },
        state_commitment: state_commitment
            .try_into()
            .map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_encrypted(row: RawEncrypted) -> StorageResult<EncryptedRecord> {
    let (nonce, ciphertext, dek_nonce, wrapped_dek, kek_version) = row;
    if !(16..=16 * 1024 * 1024).contains(&ciphertext.len()) {
        return Err(StorageError::InvalidData);
    }
    Ok(EncryptedRecord {
        nonce: nonce.try_into().map_err(|_| StorageError::InvalidData)?,
        ciphertext,
        dek_nonce: dek_nonce
            .try_into()
            .map_err(|_| StorageError::InvalidData)?,
        wrapped_dek: wrapped_dek
            .try_into()
            .map_err(|_| StorageError::InvalidData)?,
        kek_version: u32::try_from(kek_version).map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_audit(row: RawAudit) -> StorageResult<StoredAuditRecord> {
    let (
        sequence,
        event_id,
        installation_id,
        recovery_epoch,
        occurred_at_unix_ms,
        request_id,
        actor,
        action,
        target_kind,
        target,
        outcome,
        previous,
        commitment,
    ) = row;
    Ok(StoredAuditRecord {
        sequence: u64::try_from(sequence).map_err(|_| StorageError::InvalidData)?,
        event_id: AuditEventId::from_uuid(parse_uuid(&event_id)?),
        installation_id: InstallationId::from_uuid(parse_uuid(&installation_id)?),
        recovery_epoch: u64::try_from(recovery_epoch).map_err(|_| StorageError::InvalidData)?,
        occurred_at_unix_ms,
        request_id: RequestId::from_uuid(parse_uuid(&request_id)?),
        actor_principal_id: actor
            .map(|bytes| parse_uuid(&bytes).map(PrincipalId::from_uuid))
            .transpose()?,
        action,
        target_kind,
        target_id: target
            .map(|bytes| parse_uuid(&bytes).map(ObjectId::from_uuid))
            .transpose()?,
        outcome,
        previous_commitment: previous.try_into().map_err(|_| StorageError::InvalidData)?,
        commitment: commitment
            .try_into()
            .map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_uuid(bytes: &[u8]) -> StorageResult<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| StorageError::InvalidData)
}

fn sql_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| StorageError::Conflict)
}
