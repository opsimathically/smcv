use core::str::FromStr;

use rusqlite::params;
use smcv_core::{Action, GrantId, ObjectId, PolicyId, PrincipalId, ResourceKind};
use uuid::Uuid;

use crate::{
    AuditRecord, EncryptedRecord, SqliteStore, StorageError, StorageResult,
    records::{insert_audit, require_audit_head},
};

/// Stored policy and its protected display metadata.
pub struct PolicyRecord {
    pub policy_id: PolicyId,
    pub revision: u64,
    pub state: String,
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

/// New allow-only policy.
pub struct PolicyInsert {
    pub policy_id: PolicyId,
    pub metadata: EncryptedRecord,
    pub state_commitment: [u8; 32],
    pub created_at_unix_ms: i64,
}

/// One durable allow grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGrantRecord {
    pub grant_id: GrantId,
    pub policy_id: PolicyId,
    pub action: Action,
    pub resource_kind: ResourceKind,
    pub resource_id: ObjectId,
    pub include_descendants: bool,
    pub created_by_principal_id: PrincipalId,
    pub created_at_unix_ms: i64,
    pub state_commitment: [u8; 32],
}

/// One service-principal policy binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBindingRecord {
    pub principal_id: PrincipalId,
    pub policy_id: PolicyId,
    pub created_by_principal_id: PrincipalId,
    pub created_at_unix_ms: i64,
    pub state_commitment: [u8; 32],
}

/// Authenticated revision for the complete authorization graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationState {
    pub revision: u64,
    pub state_commitment: [u8; 32],
}

/// Deterministically ordered durable authorization graph.
pub struct AuthorizationSnapshot {
    pub state: AuthorizationState,
    pub policies: Vec<PolicyRecord>,
    pub grants: Vec<PolicyGrantRecord>,
    pub bindings: Vec<PolicyBindingRecord>,
}

#[allow(
    clippy::missing_errors_doc,
    reason = "each adapter operation returns the shared redacted storage contract"
)]
impl SqliteStore {
    /// Loads the full bounded v1 authorization graph in deterministic order.
    pub fn authorization_snapshot(&self) -> StorageResult<AuthorizationSnapshot> {
        let connection = self.lock()?;
        let state_raw = connection.query_row(
            "SELECT revision, state_commitment FROM smcv_authorization_state WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let state = AuthorizationState {
            revision: u64::try_from(state_raw.0).map_err(|_| StorageError::InvalidData)?,
            state_commitment: state_raw
                .1
                .try_into()
                .map_err(|_| StorageError::InvalidData)?,
        };

        let mut policy_statement = connection.prepare(
            r"SELECT policy_id, revision, state, metadata_version, metadata_nonce,
                      metadata_ciphertext, metadata_dek_nonce, metadata_wrapped_dek,
                      metadata_kek_version, state_commitment, created_at_unix_ms,
                      updated_at_unix_ms
               FROM smcv_policies ORDER BY policy_id",
        )?;
        let policy_rows = policy_statement.query_map([], parse_policy_row)?;
        let mut policies = Vec::new();
        for row in policy_rows {
            policies.push(parse_policy(row?)?);
        }

        let mut grant_statement = connection.prepare(
            r"SELECT grant_id, policy_id, action, resource_kind, resource_id,
                      include_descendants, created_by_principal_id, created_at_unix_ms,
                      state_commitment
               FROM smcv_policy_grants ORDER BY grant_id",
        )?;
        let grant_rows = grant_statement.query_map([], parse_grant_row)?;
        let mut grants = Vec::new();
        for row in grant_rows {
            grants.push(parse_grant(row?)?);
        }

        let mut binding_statement = connection.prepare(
            r"SELECT principal_id, policy_id, created_by_principal_id,
                      created_at_unix_ms, state_commitment
               FROM smcv_policy_bindings ORDER BY principal_id, policy_id",
        )?;
        let binding_rows = binding_statement.query_map([], parse_binding_row)?;
        let mut bindings = Vec::new();
        for row in binding_rows {
            bindings.push(parse_binding(row?)?);
        }
        Ok(AuthorizationSnapshot {
            state,
            policies,
            grants,
            bindings,
        })
    }

    /// Creates a policy and advances the authenticated graph revision atomically.
    pub fn create_policy(
        &self,
        policy: &PolicyInsert,
        expected_authorization_revision: u64,
        authorization_state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let next_revision = expected_authorization_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        transaction.execute(
            r"INSERT INTO smcv_policies (
                   policy_id, revision, state, metadata_version, metadata_nonce,
                   metadata_ciphertext, metadata_dek_nonce, metadata_wrapped_dek,
                   metadata_kek_version, state_commitment, created_at_unix_ms,
                   updated_at_unix_ms
               ) VALUES (?1, 1, 'active', 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                policy.policy_id.as_bytes(),
                policy.metadata.nonce.as_slice(),
                policy.metadata.ciphertext.as_slice(),
                policy.metadata.dek_nonce.as_slice(),
                policy.metadata.wrapped_dek.as_slice(),
                i64::from(policy.metadata.kek_version),
                policy.state_commitment.as_slice(),
                policy.created_at_unix_ms,
            ],
        )?;
        advance_authorization_state(
            &transaction,
            expected_authorization_revision,
            next_revision,
            authorization_state_commitment,
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_revision)
    }

    /// Adds one validated grant and advances graph state atomically.
    pub fn add_policy_grant(
        &self,
        grant: &PolicyGrantRecord,
        expected_authorization_revision: u64,
        authorization_state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let next_revision = expected_authorization_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        if transaction.query_row(
            "SELECT count(*) FROM smcv_policies WHERE policy_id = ?1 AND state = 'active'",
            [grant.policy_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        )? != 1
        {
            return Err(StorageError::StateConflict);
        }
        transaction.execute(
            r"INSERT INTO smcv_policy_grants VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                grant.grant_id.as_bytes(),
                grant.policy_id.as_bytes(),
                grant.action.as_str(),
                grant.resource_kind.as_str(),
                grant.resource_id.as_bytes(),
                i64::from(grant.include_descendants),
                grant.created_by_principal_id.as_bytes(),
                grant.created_at_unix_ms,
                grant.state_commitment.as_slice(),
            ],
        )?;
        advance_authorization_state(
            &transaction,
            expected_authorization_revision,
            next_revision,
            authorization_state_commitment,
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_revision)
    }

    /// Archives a policy and advances the authorization graph atomically.
    #[allow(
        clippy::too_many_arguments,
        reason = "two optimistic revisions advance atomically"
    )]
    pub fn archive_policy(
        &self,
        policy_id: PolicyId,
        expected_policy_revision: u64,
        policy_state_commitment: &[u8; 32],
        updated_at_unix_ms: i64,
        expected_authorization_revision: u64,
        authorization_state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<(u64, u64)> {
        let next_policy_revision = expected_policy_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let next_authorization_revision = expected_authorization_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let changed = transaction.execute(
            r"UPDATE smcv_policies
               SET state = 'archived', revision = ?1, state_commitment = ?2,
                   updated_at_unix_ms = ?3
               WHERE policy_id = ?4 AND revision = ?5 AND state = 'active'",
            params![
                i64::try_from(next_policy_revision).map_err(|_| StorageError::Conflict)?,
                policy_state_commitment.as_slice(),
                updated_at_unix_ms,
                policy_id.as_bytes(),
                i64::try_from(expected_policy_revision).map_err(|_| StorageError::Conflict)?,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        advance_authorization_state(
            &transaction,
            expected_authorization_revision,
            next_authorization_revision,
            authorization_state_commitment,
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok((next_policy_revision, next_authorization_revision))
    }

    /// Binds one policy to one active service identity atomically.
    pub fn bind_policy(
        &self,
        binding: &PolicyBindingRecord,
        expected_authorization_revision: u64,
        authorization_state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let next_revision = expected_authorization_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        if transaction.query_row(
            "SELECT count(*) FROM smcv_principals WHERE principal_id = ?1 AND principal_kind = 'service' AND state = 'active'",
            [binding.principal_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        )? != 1
        {
            return Err(StorageError::StateConflict);
        }
        transaction.execute(
            "INSERT INTO smcv_policy_bindings VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                binding.principal_id.as_bytes(),
                binding.policy_id.as_bytes(),
                binding.created_by_principal_id.as_bytes(),
                binding.created_at_unix_ms,
                binding.state_commitment.as_slice(),
            ],
        )?;
        advance_authorization_state(
            &transaction,
            expected_authorization_revision,
            next_revision,
            authorization_state_commitment,
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_revision)
    }
}

fn advance_authorization_state(
    transaction: &rusqlite::Transaction<'_>,
    expected_revision: u64,
    next_revision: u64,
    commitment: &[u8; 32],
) -> StorageResult<()> {
    let changed = transaction.execute(
        r"UPDATE smcv_authorization_state SET revision = ?1, state_commitment = ?2
           WHERE singleton = 1 AND revision = ?3",
        params![
            i64::try_from(next_revision).map_err(|_| StorageError::Conflict)?,
            commitment.as_slice(),
            i64::try_from(expected_revision).map_err(|_| StorageError::Conflict)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

type RawPolicy = (
    Vec<u8>,
    i64,
    String,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    i64,
);
type RawGrant = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
);
type RawBinding = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

fn parse_policy_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawPolicy> {
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
    ))
}

fn parse_policy(row: RawPolicy) -> StorageResult<PolicyRecord> {
    Ok(PolicyRecord {
        policy_id: PolicyId::from_uuid(parse_uuid(&row.0)?),
        revision: u64::try_from(row.1).map_err(|_| StorageError::InvalidData)?,
        state: row.2,
        metadata_version: u64::try_from(row.3).map_err(|_| StorageError::InvalidData)?,
        metadata: EncryptedRecord {
            nonce: row.4.try_into().map_err(|_| StorageError::InvalidData)?,
            ciphertext: row.5,
            dek_nonce: row.6.try_into().map_err(|_| StorageError::InvalidData)?,
            wrapped_dek: row.7.try_into().map_err(|_| StorageError::InvalidData)?,
            kek_version: u32::try_from(row.8).map_err(|_| StorageError::InvalidData)?,
        },
        state_commitment: row.9.try_into().map_err(|_| StorageError::InvalidData)?,
        created_at_unix_ms: row.10,
        updated_at_unix_ms: row.11,
    })
}

fn parse_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawGrant> {
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
    ))
}

fn parse_grant(row: RawGrant) -> StorageResult<PolicyGrantRecord> {
    Ok(PolicyGrantRecord {
        grant_id: GrantId::from_uuid(parse_uuid(&row.0)?),
        policy_id: PolicyId::from_uuid(parse_uuid(&row.1)?),
        action: Action::from_str(&row.2).map_err(|()| StorageError::InvalidData)?,
        resource_kind: match row.3.as_str() {
            "namespace" => ResourceKind::Namespace,
            "secret" => ResourceKind::Secret,
            _ => return Err(StorageError::InvalidData),
        },
        resource_id: ObjectId::from_uuid(parse_uuid(&row.4)?),
        include_descendants: match row.5 {
            0 => false,
            1 => true,
            _ => return Err(StorageError::InvalidData),
        },
        created_by_principal_id: PrincipalId::from_uuid(parse_uuid(&row.6)?),
        created_at_unix_ms: row.7,
        state_commitment: row.8.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_binding_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBinding> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn parse_binding(row: RawBinding) -> StorageResult<PolicyBindingRecord> {
    Ok(PolicyBindingRecord {
        principal_id: PrincipalId::from_uuid(parse_uuid(&row.0)?),
        policy_id: PolicyId::from_uuid(parse_uuid(&row.1)?),
        created_by_principal_id: PrincipalId::from_uuid(parse_uuid(&row.2)?),
        created_at_unix_ms: row.3,
        state_commitment: row.4.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_uuid(bytes: &[u8]) -> StorageResult<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| StorageError::InvalidData)
}
