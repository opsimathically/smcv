use rusqlite::{OptionalExtension, Row, Transaction, params};
use smcv_core::{
    AuditEventId, AuthenticatorId, CredentialId, GrantId, InstallationId, NamespaceId, ObjectId,
    PolicyId, PrincipalId, RequestId, ResourceKind, SecretId, SecretSchedule, VaultId,
};
use uuid::Uuid;

use crate::{
    AuthenticatorKind, AuthorizationState, EncryptedRecord, PolicyBindingRecord, PolicyGrantRecord,
    PrincipalKind, SqliteStore, StorageError, StorageResult, StoredAuditRecord,
};

/// Complete consistent logical snapshot containing ciphertext but no root or KEK material.
pub struct PortableSnapshot {
    pub vault_id: VaultId,
    pub source_installation_id: InstallationId,
    pub source_recovery_epoch: u64,
    pub security_semantics_version: u32,
    pub namespaces: Vec<PortableNamespace>,
    pub secrets: Vec<PortableSecret>,
    pub secret_versions: Vec<PortableSecretVersion>,
    pub tombstones: Vec<PortableTombstone>,
    pub principals: Vec<PortablePrincipal>,
    pub authenticators: Vec<PortableAuthenticator>,
    pub service_identities: Vec<PortableServiceIdentity>,
    pub application_credentials: Vec<PortableApplicationCredential>,
    pub authorization_state: AuthorizationState,
    pub policies: Vec<PortablePolicy>,
    pub grants: Vec<PolicyGrantRecord>,
    pub bindings: Vec<PolicyBindingRecord>,
    pub audit_records: Vec<StoredAuditRecord>,
}

pub struct PortableNamespace {
    pub namespace_id: NamespaceId,
    pub parent_namespace_id: Option<NamespaceId>,
    pub name_index: [u8; 32],
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
    pub lifecycle_state: String,
    pub revision: u64,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

pub struct PortableSecret {
    pub secret_id: SecretId,
    pub namespace_id: NamespaceId,
    pub name_index: [u8; 32],
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
    pub lifecycle_state: String,
    pub current_version: u64,
    pub revision: u64,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
    pub deleted_at_unix_ms: Option<i64>,
}

pub struct PortableSecretVersion {
    pub secret_id: SecretId,
    pub version: u64,
    pub payload: EncryptedRecord,
    pub schedule: SecretSchedule,
    pub created_by_principal_id: Option<PrincipalId>,
    pub created_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableTombstone {
    pub secret_id: SecretId,
    pub namespace_id: NamespaceId,
    pub name_index: [u8; 32],
    pub last_version: u64,
    pub purged_at_unix_ms: i64,
    pub retention_cutoff_unix_ms: i64,
}

pub struct PortablePrincipal {
    pub principal_id: PrincipalId,
    pub kind: PrincipalKind,
    pub state: String,
    pub revision: u64,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

pub struct PortableAuthenticator {
    pub authenticator_id: AuthenticatorId,
    pub principal_id: PrincipalId,
    pub kind: AuthenticatorKind,
    pub credential_lookup: Option<Vec<u8>>,
    pub credential_data: Option<Vec<u8>>,
    pub password_phc: Option<String>,
    pub state: String,
    pub created_at_unix_ms: i64,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub state_commitment: [u8; 32],
}

pub struct PortableServiceIdentity {
    pub principal_id: PrincipalId,
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableApplicationCredential {
    pub credential_id: CredentialId,
    pub principal_id: PrincipalId,
    pub lookup_id: [u8; 12],
    pub verifier: [u8; 32],
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub revision: u64,
    pub state_commitment: [u8; 32],
}

pub struct PortablePolicy {
    pub policy_id: PolicyId,
    pub revision: u64,
    pub state: String,
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

impl SqliteStore {
    /// Captures every portable durable row under one `SQLite` read snapshot.
    /// Sessions, idempotency state, maintenance jobs, and key registry rows are
    /// deliberately excluded.
    ///
    /// # Errors
    ///
    /// Returns an error when the ready-state precondition, a durable invariant,
    /// or the consistent database read fails.
    pub fn portable_snapshot(&self) -> StorageResult<PortableSnapshot> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let installation = transaction.query_row(
            r"SELECT logical_vault_id, installation_id, recovery_epoch,
                     security_semantics_version
                FROM smcv_installation_state
               WHERE singleton = 1 AND activation_state = 'ready'",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let snapshot = PortableSnapshot {
            vault_id: VaultId::from_uuid(parse_uuid(&installation.0)?),
            source_installation_id: InstallationId::from_uuid(parse_uuid(&installation.1)?),
            source_recovery_epoch: parse_u64(installation.2)?,
            security_semantics_version: parse_u32(installation.3)?,
            namespaces: read_namespaces(&transaction)?,
            secrets: read_secrets(&transaction)?,
            secret_versions: read_secret_versions(&transaction)?,
            tombstones: read_tombstones(&transaction)?,
            principals: read_principals(&transaction)?,
            authenticators: read_authenticators(&transaction)?,
            service_identities: read_service_identities(&transaction)?,
            application_credentials: read_application_credentials(&transaction)?,
            authorization_state: read_authorization_state(&transaction)?,
            policies: read_policies(&transaction)?,
            grants: read_grants(&transaction)?,
            bindings: read_bindings(&transaction)?,
            audit_records: read_audit(&transaction)?,
        };
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Atomically imports a fully transformed logical snapshot into an
    /// initializing destination. The installation remains non-ready after this
    /// call so the application can perform complete verification first.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-empty or non-initializing destination,
    /// identity mismatch, invalid references, duplicate rows, or database
    /// failure. No partial logical import is committed.
    pub fn import_portable_snapshot(
        &self,
        snapshot: &PortableSnapshot,
        destination_recovery_epoch: u64,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let state = transaction.query_row(
            "SELECT logical_vault_id, activation_state FROM smcv_installation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )?;
        if state.1 != "initializing" || parse_uuid(&state.0)? != snapshot.vault_id.as_uuid() {
            return Err(StorageError::StateConflict);
        }
        let existing: i64 = transaction.query_row(
            r"SELECT
                (SELECT count(*) FROM smcv_namespaces) +
                (SELECT count(*) FROM smcv_secrets) +
                (SELECT count(*) FROM smcv_principals) +
                (SELECT count(*) FROM smcv_audit_events) +
                (SELECT count(*) FROM smcv_policies)",
            [],
            |row| row.get(0),
        )?;
        if existing != 0 {
            return Err(StorageError::StateConflict);
        }
        transaction.execute(
            r"UPDATE smcv_installation_state
                  SET recovery_epoch = ?1, security_semantics_version = ?2
                WHERE singleton = 1 AND activation_state = 'initializing'",
            params![
                sql_u64(destination_recovery_epoch)?,
                i64::from(snapshot.security_semantics_version)
            ],
        )?;

        insert_principals(&transaction, &snapshot.principals)?;
        insert_authenticators(&transaction, &snapshot.authenticators)?;
        insert_service_identities(&transaction, &snapshot.service_identities)?;
        insert_application_credentials(&transaction, &snapshot.application_credentials)?;
        insert_namespaces(&transaction, &snapshot.namespaces)?;
        insert_secrets(&transaction, &snapshot.secrets)?;
        insert_secret_versions(&transaction, &snapshot.secret_versions)?;
        insert_tombstones(&transaction, &snapshot.tombstones)?;
        insert_policies(&transaction, &snapshot.policies)?;
        insert_grants(&transaction, &snapshot.grants)?;
        insert_bindings(&transaction, &snapshot.bindings)?;
        transaction.execute(
            "UPDATE smcv_authorization_state SET revision = ?1, state_commitment = ?2 WHERE singleton = 1",
            params![
                sql_u64(snapshot.authorization_state.revision)?,
                snapshot.authorization_state.state_commitment.as_slice()
            ],
        )?;
        insert_audit_records(&transaction, &snapshot.audit_records)?;

        let violation: Option<String> = transaction
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .optional()?;
        if violation.is_some() {
            return Err(StorageError::InvalidData);
        }
        transaction.commit()?;
        Ok(())
    }
}

fn insert_principals(
    transaction: &Transaction<'_>,
    records: &[PortablePrincipal],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            "INSERT INTO smcv_principals VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.principal_id.as_bytes(),
                principal_kind_str(record.kind),
                record.state,
                sql_u64(record.revision)?,
                record.state_commitment.as_slice(),
                record.created_at_unix_ms,
                record.updated_at_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_authenticators(
    transaction: &Transaction<'_>,
    records: &[PortableAuthenticator],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_owner_authenticators VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.authenticator_id.as_bytes(),
                record.principal_id.as_bytes(),
                authenticator_kind_str(record.kind),
                record.credential_lookup,
                record.credential_data,
                record.password_phc,
                record.state,
                record.created_at_unix_ms,
                record.last_used_at_unix_ms,
                record.revoked_at_unix_ms,
                record.state_commitment.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn insert_service_identities(
    transaction: &Transaction<'_>,
    records: &[PortableServiceIdentity],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            "INSERT INTO smcv_service_identities VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.principal_id.as_bytes(),
                sql_u64(record.metadata_version)?,
                record.metadata.nonce.as_slice(),
                record.metadata.ciphertext,
                record.metadata.dek_nonce.as_slice(),
                record.metadata.wrapped_dek.as_slice(),
                i64::from(record.metadata.kek_version),
            ],
        )?;
    }
    Ok(())
}

fn insert_application_credentials(
    transaction: &Transaction<'_>,
    records: &[PortableApplicationCredential],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_application_credentials VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.credential_id.as_bytes(),
                record.principal_id.as_bytes(),
                record.lookup_id.as_slice(),
                record.verifier.as_slice(),
                record.created_at_unix_ms,
                record.expires_at_unix_ms,
                record.last_used_at_unix_ms,
                record.revoked_at_unix_ms,
                sql_u64(record.revision)?,
                record.state_commitment.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn insert_namespaces(
    transaction: &Transaction<'_>,
    records: &[PortableNamespace],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_namespaces VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                record.namespace_id.as_bytes(),
                record
                    .parent_namespace_id
                    .map(|value| value.as_bytes().to_vec()),
                record.name_index.as_slice(),
                sql_u64(record.metadata_version)?,
                record.metadata.nonce.as_slice(),
                record.metadata.ciphertext,
                record.metadata.dek_nonce.as_slice(),
                record.metadata.wrapped_dek.as_slice(),
                i64::from(record.metadata.kek_version),
                record.lifecycle_state,
                sql_u64(record.revision)?,
                record.state_commitment.as_slice(),
                record.created_at_unix_ms,
                record.updated_at_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_secrets(transaction: &Transaction<'_>, records: &[PortableSecret]) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_secrets VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                record.secret_id.as_bytes(),
                record.namespace_id.as_bytes(),
                record.name_index.as_slice(),
                sql_u64(record.metadata_version)?,
                record.metadata.nonce.as_slice(),
                record.metadata.ciphertext,
                record.metadata.dek_nonce.as_slice(),
                record.metadata.wrapped_dek.as_slice(),
                i64::from(record.metadata.kek_version),
                record.lifecycle_state,
                sql_u64(record.current_version)?,
                sql_u64(record.revision)?,
                record.state_commitment.as_slice(),
                record.created_at_unix_ms,
                record.updated_at_unix_ms,
                record.deleted_at_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_secret_versions(
    transaction: &Transaction<'_>,
    records: &[PortableSecretVersion],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_secret_versions VALUES
               (?1, ?2, 1, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.secret_id.as_bytes(),
                sql_u64(record.version)?,
                i64::from(record.payload.kek_version),
                record.payload.nonce.as_slice(),
                record.payload.ciphertext,
                record.payload.dek_nonce.as_slice(),
                record.payload.wrapped_dek.as_slice(),
                record.schedule.expires_at_unix_ms,
                record.schedule.rotation_due_at_unix_ms,
                record
                    .created_by_principal_id
                    .map(|value| value.as_bytes().to_vec()),
                record.created_at_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_tombstones(
    transaction: &Transaction<'_>,
    records: &[PortableTombstone],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            "INSERT INTO smcv_secret_tombstones VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.secret_id.as_bytes(),
                record.namespace_id.as_bytes(),
                record.name_index.as_slice(),
                sql_u64(record.last_version)?,
                record.purged_at_unix_ms,
                record.retention_cutoff_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_policies(transaction: &Transaction<'_>, records: &[PortablePolicy]) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_policies VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                record.policy_id.as_bytes(),
                sql_u64(record.revision)?,
                record.state,
                sql_u64(record.metadata_version)?,
                record.metadata.nonce.as_slice(),
                record.metadata.ciphertext,
                record.metadata.dek_nonce.as_slice(),
                record.metadata.wrapped_dek.as_slice(),
                i64::from(record.metadata.kek_version),
                record.state_commitment.as_slice(),
                record.created_at_unix_ms,
                record.updated_at_unix_ms,
            ],
        )?;
    }
    Ok(())
}

fn insert_grants(
    transaction: &Transaction<'_>,
    records: &[PolicyGrantRecord],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            "INSERT INTO smcv_policy_grants VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.grant_id.as_bytes(),
                record.policy_id.as_bytes(),
                record.action.as_str(),
                record.resource_kind.as_str(),
                record.resource_id.as_bytes(),
                i64::from(record.include_descendants),
                record.created_by_principal_id.as_bytes(),
                record.created_at_unix_ms,
                record.state_commitment.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn insert_bindings(
    transaction: &Transaction<'_>,
    records: &[PolicyBindingRecord],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            "INSERT INTO smcv_policy_bindings VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.principal_id.as_bytes(),
                record.policy_id.as_bytes(),
                record.created_by_principal_id.as_bytes(),
                record.created_at_unix_ms,
                record.state_commitment.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn insert_audit_records(
    transaction: &Transaction<'_>,
    records: &[StoredAuditRecord],
) -> StorageResult<()> {
    for record in records {
        transaction.execute(
            r"INSERT INTO smcv_audit_events (
                 sequence, event_id, installation_id, recovery_epoch, occurred_at_unix_ms,
                 request_id, actor_principal_id, action, target_kind, target_id, outcome,
                 previous_commitment, commitment, commitment_version, credential_kind, credential_id
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                sql_u64(record.sequence)?,
                record.event_id.as_bytes(),
                record.installation_id.as_bytes(),
                sql_u64(record.recovery_epoch)?,
                record.occurred_at_unix_ms,
                record.request_id.as_bytes(),
                record
                    .actor_principal_id
                    .map(|value| value.as_bytes().to_vec()),
                record.action,
                record.target_kind,
                record.target_id.map(|value| value.as_bytes().to_vec()),
                record.outcome,
                record.previous_commitment.as_slice(),
                record.commitment.as_slice(),
                i64::from(record.commitment_version),
                record.credential_kind,
                record.credential_id.map(|value| value.as_bytes().to_vec()),
            ],
        )?;
    }
    Ok(())
}

fn read_namespaces(transaction: &Transaction<'_>) -> StorageResult<Vec<PortableNamespace>> {
    let mut statement = transaction.prepare(
        r"WITH RECURSIVE tree(namespace_id, depth) AS (
               SELECT namespace_id, 0 FROM smcv_namespaces WHERE parent_namespace_id IS NULL
               UNION ALL
               SELECT child.namespace_id, tree.depth + 1
                 FROM smcv_namespaces AS child JOIN tree
                   ON child.parent_namespace_id = tree.namespace_id
           )
           SELECT n.namespace_id, n.parent_namespace_id, n.name_index, n.metadata_version,
                  n.metadata_nonce, n.metadata_ciphertext, n.dek_nonce, n.wrapped_dek,
                  n.kek_version, n.lifecycle_state, n.revision, n.state_commitment,
                  n.created_at_unix_ms, n.updated_at_unix_ms
             FROM smcv_namespaces AS n JOIN tree ON tree.namespace_id = n.namespace_id
            ORDER BY tree.depth, n.namespace_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, Vec<u8>>(11)?,
            row.get::<_, i64>(12)?,
            row.get::<_, i64>(13)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableNamespace {
            namespace_id: NamespaceId::from_uuid(parse_uuid(&row.0)?),
            parent_namespace_id: row
                .1
                .as_deref()
                .map(parse_uuid)
                .transpose()?
                .map(NamespaceId::from_uuid),
            name_index: fixed(&row.2)?,
            metadata_version: parse_u64(row.3)?,
            metadata: encrypted(row.4, row.5, row.6, row.7, row.8)?,
            lifecycle_state: row.9,
            revision: parse_u64(row.10)?,
            state_commitment: fixed(&row.11)?,
            created_at_unix_ms: row.12,
            updated_at_unix_ms: row.13,
        });
    }
    Ok(output)
}

fn read_secrets(transaction: &Transaction<'_>) -> StorageResult<Vec<PortableSecret>> {
    let mut statement = transaction.prepare(
        r"SELECT secret_id, namespace_id, name_index, metadata_version, metadata_nonce,
                  metadata_ciphertext, metadata_dek_nonce, metadata_wrapped_dek,
                  metadata_kek_version, lifecycle_state, current_version, revision,
                  state_commitment, created_at_unix_ms, updated_at_unix_ms, deleted_at_unix_ms
             FROM smcv_secrets ORDER BY secret_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, i64>(11)?,
            row.get::<_, Vec<u8>>(12)?,
            row.get::<_, i64>(13)?,
            row.get::<_, i64>(14)?,
            row.get::<_, Option<i64>>(15)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableSecret {
            secret_id: SecretId::from_uuid(parse_uuid(&row.0)?),
            namespace_id: NamespaceId::from_uuid(parse_uuid(&row.1)?),
            name_index: fixed(&row.2)?,
            metadata_version: parse_u64(row.3)?,
            metadata: encrypted(row.4, row.5, row.6, row.7, row.8)?,
            lifecycle_state: row.9,
            current_version: parse_u64(row.10)?,
            revision: parse_u64(row.11)?,
            state_commitment: fixed(&row.12)?,
            created_at_unix_ms: row.13,
            updated_at_unix_ms: row.14,
            deleted_at_unix_ms: row.15,
        });
    }
    Ok(output)
}

fn read_secret_versions(
    transaction: &Transaction<'_>,
) -> StorageResult<Vec<PortableSecretVersion>> {
    let mut statement = transaction.prepare(
        r"SELECT secret_id, version, payload_nonce, payload_ciphertext, dek_nonce, wrapped_dek,
                  kek_version, expires_at_unix_ms, rotation_due_at_unix_ms,
                  created_by_principal_id, created_at_unix_ms
             FROM smcv_secret_versions ORDER BY secret_id, version",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?,
            row.get::<_, i64>(10)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableSecretVersion {
            secret_id: SecretId::from_uuid(parse_uuid(&row.0)?),
            version: parse_u64(row.1)?,
            payload: encrypted(row.2, row.3, row.4, row.5, row.6)?,
            schedule: SecretSchedule {
                expires_at_unix_ms: row.7,
                rotation_due_at_unix_ms: row.8,
            },
            created_by_principal_id: row
                .9
                .as_deref()
                .map(parse_uuid)
                .transpose()?
                .map(PrincipalId::from_uuid),
            created_at_unix_ms: row.10,
        });
    }
    Ok(output)
}

fn read_tombstones(transaction: &Transaction<'_>) -> StorageResult<Vec<PortableTombstone>> {
    let mut statement = transaction.prepare(
        "SELECT secret_id, namespace_id, name_index, last_version, purged_at_unix_ms, retention_cutoff_unix_ms FROM smcv_secret_tombstones ORDER BY secret_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableTombstone {
            secret_id: SecretId::from_uuid(parse_uuid(&row.0)?),
            namespace_id: NamespaceId::from_uuid(parse_uuid(&row.1)?),
            name_index: fixed(&row.2)?,
            last_version: parse_u64(row.3)?,
            purged_at_unix_ms: row.4,
            retention_cutoff_unix_ms: row.5,
        });
    }
    Ok(output)
}

fn read_principals(transaction: &Transaction<'_>) -> StorageResult<Vec<PortablePrincipal>> {
    let mut statement = transaction.prepare("SELECT principal_id, principal_kind, state, revision, state_commitment, created_at_unix_ms, updated_at_unix_ms FROM smcv_principals ORDER BY principal_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortablePrincipal {
            principal_id: PrincipalId::from_uuid(parse_uuid(&row.0)?),
            kind: parse_principal_kind(&row.1)?,
            state: row.2,
            revision: parse_u64(row.3)?,
            state_commitment: fixed(&row.4)?,
            created_at_unix_ms: row.5,
            updated_at_unix_ms: row.6,
        });
    }
    Ok(output)
}

fn read_authenticators(transaction: &Transaction<'_>) -> StorageResult<Vec<PortableAuthenticator>> {
    let mut statement = transaction.prepare("SELECT authenticator_id, principal_id, authenticator_kind, credential_lookup, credential_data, password_phc, state, created_at_unix_ms, last_used_at_unix_ms, revoked_at_unix_ms, state_commitment FROM smcv_owner_authenticators ORDER BY authenticator_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Option<Vec<u8>>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<i64>>(9)?,
            row.get::<_, Vec<u8>>(10)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableAuthenticator {
            authenticator_id: AuthenticatorId::from_uuid(parse_uuid(&row.0)?),
            principal_id: PrincipalId::from_uuid(parse_uuid(&row.1)?),
            kind: parse_authenticator_kind(&row.2)?,
            credential_lookup: row.3,
            credential_data: row.4,
            password_phc: row.5,
            state: row.6,
            created_at_unix_ms: row.7,
            last_used_at_unix_ms: row.8,
            revoked_at_unix_ms: row.9,
            state_commitment: fixed(&row.10)?,
        });
    }
    Ok(output)
}

fn read_service_identities(
    transaction: &Transaction<'_>,
) -> StorageResult<Vec<PortableServiceIdentity>> {
    let mut statement = transaction.prepare("SELECT principal_id, metadata_version, metadata_nonce, metadata_ciphertext, metadata_dek_nonce, metadata_wrapped_dek, metadata_kek_version FROM smcv_service_identities ORDER BY principal_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableServiceIdentity {
            principal_id: PrincipalId::from_uuid(parse_uuid(&row.0)?),
            metadata_version: parse_u64(row.1)?,
            metadata: encrypted(row.2, row.3, row.4, row.5, row.6)?,
        });
    }
    Ok(output)
}

fn read_application_credentials(
    transaction: &Transaction<'_>,
) -> StorageResult<Vec<PortableApplicationCredential>> {
    let mut statement = transaction.prepare("SELECT credential_id, principal_id, lookup_id, verifier, created_at_unix_ms, expires_at_unix_ms, last_used_at_unix_ms, revoked_at_unix_ms, revision, state_commitment FROM smcv_application_credentials ORDER BY credential_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Vec<u8>>(9)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortableApplicationCredential {
            credential_id: CredentialId::from_uuid(parse_uuid(&row.0)?),
            principal_id: PrincipalId::from_uuid(parse_uuid(&row.1)?),
            lookup_id: fixed(&row.2)?,
            verifier: fixed(&row.3)?,
            created_at_unix_ms: row.4,
            expires_at_unix_ms: row.5,
            last_used_at_unix_ms: row.6,
            revoked_at_unix_ms: row.7,
            revision: parse_u64(row.8)?,
            state_commitment: fixed(&row.9)?,
        });
    }
    Ok(output)
}

fn read_authorization_state(transaction: &Transaction<'_>) -> StorageResult<AuthorizationState> {
    let row = transaction.query_row(
        "SELECT revision, state_commitment FROM smcv_authorization_state WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    Ok(AuthorizationState {
        revision: parse_u64(row.0)?,
        state_commitment: fixed(&row.1)?,
    })
}

fn read_policies(transaction: &Transaction<'_>) -> StorageResult<Vec<PortablePolicy>> {
    let mut statement = transaction.prepare("SELECT policy_id, revision, state, metadata_version, metadata_nonce, metadata_ciphertext, metadata_dek_nonce, metadata_wrapped_dek, metadata_kek_version, state_commitment, created_at_unix_ms, updated_at_unix_ms FROM smcv_policies ORDER BY policy_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, i64>(11)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PortablePolicy {
            policy_id: PolicyId::from_uuid(parse_uuid(&row.0)?),
            revision: parse_u64(row.1)?,
            state: row.2,
            metadata_version: parse_u64(row.3)?,
            metadata: encrypted(row.4, row.5, row.6, row.7, row.8)?,
            state_commitment: fixed(&row.9)?,
            created_at_unix_ms: row.10,
            updated_at_unix_ms: row.11,
        });
    }
    Ok(output)
}

fn read_grants(transaction: &Transaction<'_>) -> StorageResult<Vec<PolicyGrantRecord>> {
    let mut statement = transaction.prepare("SELECT grant_id, policy_id, action, resource_kind, resource_id, include_descendants, created_by_principal_id, created_at_unix_ms, state_commitment FROM smcv_policy_grants ORDER BY grant_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Vec<u8>>(8)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PolicyGrantRecord {
            grant_id: GrantId::from_uuid(parse_uuid(&row.0)?),
            policy_id: PolicyId::from_uuid(parse_uuid(&row.1)?),
            action: row.2.parse().map_err(|()| StorageError::InvalidData)?,
            resource_kind: parse_resource_kind(&row.3)?,
            resource_id: ObjectId::from_uuid(parse_uuid(&row.4)?),
            include_descendants: row.5 == 1,
            created_by_principal_id: PrincipalId::from_uuid(parse_uuid(&row.6)?),
            created_at_unix_ms: row.7,
            state_commitment: fixed(&row.8)?,
        });
    }
    Ok(output)
}

fn read_bindings(transaction: &Transaction<'_>) -> StorageResult<Vec<PolicyBindingRecord>> {
    let mut statement = transaction.prepare("SELECT principal_id, policy_id, created_by_principal_id, created_at_unix_ms, state_commitment FROM smcv_policy_bindings ORDER BY principal_id, policy_id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    let mut output = Vec::new();
    for row in rows {
        let row = row?;
        output.push(PolicyBindingRecord {
            principal_id: PrincipalId::from_uuid(parse_uuid(&row.0)?),
            policy_id: PolicyId::from_uuid(parse_uuid(&row.1)?),
            created_by_principal_id: PrincipalId::from_uuid(parse_uuid(&row.2)?),
            created_at_unix_ms: row.3,
            state_commitment: fixed(&row.4)?,
        });
    }
    Ok(output)
}

fn read_audit(transaction: &Transaction<'_>) -> StorageResult<Vec<StoredAuditRecord>> {
    let mut statement = transaction.prepare("SELECT sequence, event_id, installation_id, recovery_epoch, occurred_at_unix_ms, request_id, actor_principal_id, commitment_version, credential_kind, credential_id, action, target_kind, target_id, outcome, previous_commitment, commitment FROM smcv_audit_events ORDER BY sequence")?;
    let rows = statement.query_map([], read_audit_row)?;
    let mut output = Vec::new();
    for row in rows {
        output.push(parse_audit(row?)?);
    }
    Ok(output)
}

type RawAudit = (
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    i64,
    Option<String>,
    Option<Vec<u8>>,
    String,
    String,
    Option<Vec<u8>>,
    String,
    Vec<u8>,
    Vec<u8>,
);

fn read_audit_row(row: &Row<'_>) -> rusqlite::Result<RawAudit> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
    ))
}

fn parse_audit(row: RawAudit) -> StorageResult<StoredAuditRecord> {
    Ok(StoredAuditRecord {
        sequence: parse_u64(row.0)?,
        event_id: AuditEventId::from_uuid(parse_uuid(&row.1)?),
        installation_id: InstallationId::from_uuid(parse_uuid(&row.2)?),
        recovery_epoch: parse_u64(row.3)?,
        occurred_at_unix_ms: row.4,
        request_id: RequestId::from_uuid(parse_uuid(&row.5)?),
        actor_principal_id: row
            .6
            .as_deref()
            .map(parse_uuid)
            .transpose()?
            .map(PrincipalId::from_uuid),
        commitment_version: u8::try_from(row.7).map_err(|_| StorageError::InvalidData)?,
        credential_kind: row.8,
        credential_id: row
            .9
            .as_deref()
            .map(parse_uuid)
            .transpose()?
            .map(ObjectId::from_uuid),
        action: row.10,
        target_kind: row.11,
        target_id: row
            .12
            .as_deref()
            .map(parse_uuid)
            .transpose()?
            .map(ObjectId::from_uuid),
        outcome: row.13,
        previous_commitment: fixed(&row.14)?,
        commitment: fixed(&row.15)?,
    })
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the parser consumes a destructured owned SQLite row while retaining its ciphertext"
)]
fn encrypted(
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    dek_nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    kek_version: i64,
) -> StorageResult<EncryptedRecord> {
    Ok(EncryptedRecord {
        nonce: fixed(&nonce)?,
        ciphertext,
        dek_nonce: fixed(&dek_nonce)?,
        wrapped_dek: fixed(&wrapped_dek)?,
        kek_version: parse_u32(kek_version)?,
    })
}

fn fixed<const N: usize>(bytes: &[u8]) -> StorageResult<[u8; N]> {
    bytes.try_into().map_err(|_| StorageError::InvalidData)
}
fn parse_uuid(bytes: &[u8]) -> StorageResult<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| StorageError::InvalidData)
}
fn parse_u64(value: i64) -> StorageResult<u64> {
    u64::try_from(value).map_err(|_| StorageError::InvalidData)
}
fn parse_u32(value: i64) -> StorageResult<u32> {
    u32::try_from(value).map_err(|_| StorageError::InvalidData)
}
fn parse_principal_kind(value: &str) -> StorageResult<PrincipalKind> {
    match value {
        "owner" => Ok(PrincipalKind::Owner),
        "service" => Ok(PrincipalKind::Service),
        _ => Err(StorageError::InvalidData),
    }
}
fn parse_authenticator_kind(value: &str) -> StorageResult<AuthenticatorKind> {
    match value {
        "password" => Ok(AuthenticatorKind::Password),
        "passkey" => Ok(AuthenticatorKind::Passkey),
        "recovery" => Ok(AuthenticatorKind::Recovery),
        _ => Err(StorageError::InvalidData),
    }
}

fn parse_resource_kind(value: &str) -> StorageResult<ResourceKind> {
    match value {
        "namespace" => Ok(ResourceKind::Namespace),
        "secret" => Ok(ResourceKind::Secret),
        _ => Err(StorageError::InvalidData),
    }
}

fn principal_kind_str(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Owner => "owner",
        PrincipalKind::Service => "service",
    }
}

fn authenticator_kind_str(kind: AuthenticatorKind) -> &'static str {
    match kind {
        AuthenticatorKind::Password => "password",
        AuthenticatorKind::Passkey => "passkey",
        AuthenticatorKind::Recovery => "recovery",
    }
}

fn sql_u64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| StorageError::InvalidData)
}
