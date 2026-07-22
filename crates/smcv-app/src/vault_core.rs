use core::fmt;

use smcv_core::{
    AuditEventId, NamespaceId, ObjectId, PrincipalId, ProtectedBytes, ProtectedString, RequestId,
    SecretId, SecretSchedule,
};
use smcv_crypto::{
    AuditCommitmentInput, CryptoError, KeyMaterial, ObjectKind, RecordContext, SealedRecord,
    audit_commitment, exact_name_index, open, seal, state_commitment,
};
use smcv_storage::{
    AuditRecord, EncryptedRecord, NamespaceInsert, SecretInsert, SecretLifecycleChange,
    SecretPurge, SecretVersionInsert, StorageError,
};
use thiserror::Error;

use crate::InitializedVault;

const METADATA_MAGIC: &[u8; 8] = b"SMCVMD02";
const MAX_NAME_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 4096;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_TAG_BYTES: usize = 64;
const MAX_TAGS: usize = 32;
const MAX_NAMESPACE_DEPTH: u16 = 32;
const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;

/// Protected human-readable metadata accepted by vault operations.
pub struct MetadataInput {
    /// Human-readable name, encrypted before persistence.
    pub name: ProtectedString,
    /// Optional human-readable description, encrypted before persistence.
    pub description: Option<ProtectedString>,
    /// Optional encrypted username or account label.
    pub username: Option<ProtectedString>,
    /// Encrypted human-readable classification tags.
    pub tags: Vec<ProtectedString>,
}

/// Decrypted metadata returned only by an explicit vault-domain call.
pub struct DecryptedMetadata {
    /// Protected human-readable name.
    pub name: ProtectedString,
    /// Protected optional description.
    pub description: Option<ProtectedString>,
    /// Protected optional username or account label.
    pub username: Option<ProtectedString>,
    /// Protected classification tags in their stored order.
    pub tags: Vec<ProtectedString>,
}

impl fmt::Debug for DecryptedMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecryptedMetadata([REDACTED])")
    }
}

impl fmt::Debug for MetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataInput([REDACTED])")
    }
}

/// Authentication-independent operation context for audit attribution.
///
/// Phase 2 constructs this only after authentication and authorization.
#[derive(Clone, Copy, Debug)]
pub struct VaultOperationContext {
    /// Correlated request identity.
    pub request_id: RequestId,
    /// Acting principal when known during local initialization work.
    pub actor_principal_id: Option<PrincipalId>,
    /// Authentication context category when the operation is remote.
    pub(crate) credential_kind: Option<&'static str>,
    /// Exact session or application credential used for attribution.
    pub(crate) credential_id: Option<ObjectId>,
    /// Wall-clock timestamp supplied by the application boundary.
    pub now_unix_ms: i64,
}

/// Safe result of creating a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretCreated {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Initial immutable version.
    pub version: u64,
    /// Initial optimistic concurrency revision.
    pub revision: u64,
}

/// Safe, non-value metadata for one immutable secret version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretVersionSummary {
    /// Monotonic version number.
    pub version: u64,
    /// Advisory schedule attached to this version.
    pub schedule: SecretSchedule,
    /// Principal that created the version, when attributed.
    pub created_by_principal_id: Option<PrincipalId>,
    /// Creation timestamp.
    pub created_at_unix_ms: i64,
}

/// One protected namespace-list entry.
pub struct NamespaceListItem {
    /// Stable namespace identity.
    pub namespace_id: NamespaceId,
    /// Decrypted protected metadata.
    pub metadata: DecryptedMetadata,
    /// Optimistic revision.
    pub revision: u64,
}

/// One protected secret-list entry without its value.
pub struct SecretListItem {
    /// Stable secret identity.
    pub secret_id: SecretId,
    /// Decrypted protected metadata.
    pub metadata: DecryptedMetadata,
    /// Current immutable version.
    pub current_version: u64,
    /// Optimistic revision.
    pub revision: u64,
}

/// Safe due-state for one active current secret version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueSecret {
    /// Stable secret identity; protected names are not exposed by this query.
    pub secret_id: SecretId,
    /// Current immutable version represented by the schedule.
    pub version: u64,
    /// Stored advisory schedule.
    pub schedule: SecretSchedule,
    /// Whether the upstream credential is expected to be expired now.
    pub expired: bool,
    /// Whether owner action to rotate the upstream credential is due now.
    pub upstream_rotation_due: bool,
}

/// Result of streaming local audit-chain verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    /// Number of events authenticated from the segment origin.
    pub events_verified: u64,
    /// Final verified sequence.
    pub final_sequence: u64,
    /// Final verified commitment.
    pub final_commitment: [u8; 32],
}

/// Capability produced only after owner authorization, recent authentication,
/// retention evaluation, and explicit destructive confirmation.
pub struct OwnerPurgeApproval {
    retention_cutoff_unix_ms: i64,
}

impl fmt::Debug for OwnerPurgeApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnerPurgeApproval([CONFIRMED])")
    }
}

impl OwnerPurgeApproval {
    /// Creates a purge capability inside the Phase 2 authorization service.
    #[allow(dead_code, reason = "used by the Phase 2 owner authorization slice")]
    pub(crate) const fn authorized(retention_cutoff_unix_ms: i64) -> Self {
        Self {
            retention_cutoff_unix_ms,
        }
    }
}

/// Safe vault-domain failures.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Protected input violates a documented bound or encoding.
    #[error("vault input is invalid")]
    InvalidInput,
    /// The resource is absent or unavailable in its lifecycle state.
    #[error("vault resource is unavailable")]
    NotFound,
    /// An optimistic concurrency or uniqueness precondition failed.
    #[error("vault operation conflicts with current state")]
    Conflict,
    /// Protected data or its bound context did not authenticate.
    #[error("protected data integrity check failed")]
    Integrity,
    /// A required storage or cryptographic dependency failed.
    #[error("vault dependency is unavailable")]
    Unavailable,
}

impl InitializedVault {
    /// Returns a bounded list of active current versions with an expiration or
    /// upstream credential-rotation timestamp at or before `now_unix_ms`.
    ///
    /// This query reports owner work; it does not state that SMCV rotated an
    /// upstream credential.
    ///
    /// # Errors
    ///
    /// Returns invalid input for negative time or an unsupported bound, and a
    /// safe dependency error for storage failure.
    pub(crate) fn secrets_due(
        &self,
        now_unix_ms: i64,
        limit: u16,
    ) -> Result<Vec<DueSecret>, VaultError> {
        if now_unix_ms < 0 || limit == 0 || limit > 1000 {
            return Err(VaultError::InvalidInput);
        }
        let records = self
            .store
            .scheduled_secrets_due(now_unix_ms, limit)
            .map_err(map_storage)?;
        let mut due = Vec::with_capacity(records.len());
        for record in records {
            let current = self.store.secret(record.secret_id).map_err(map_storage)?;
            self.verify_secret_state(&current)?;
            if current.current_version != record.version {
                return Err(VaultError::Integrity);
            }
            due.push(DueSecret {
                secret_id: record.secret_id,
                version: record.version,
                schedule: record.schedule,
                expired: record
                    .schedule
                    .expires_at_unix_ms
                    .is_some_and(|timestamp| timestamp <= now_unix_ms),
                upstream_rotation_due: record
                    .schedule
                    .rotation_due_at_unix_ms
                    .is_some_and(|timestamp| timestamp <= now_unix_ms),
            });
        }
        Ok(due)
    }

    /// Creates an encrypted namespace and an atomic audit event.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, duplicate identity/name, missing
    /// parent, cryptographic failure, or audit/storage failure.
    pub(crate) fn create_namespace(
        &self,
        parent_namespace_id: Option<NamespaceId>,
        metadata: &MetadataInput,
        operation: VaultOperationContext,
    ) -> Result<NamespaceId, VaultError> {
        self.create_namespace_with_id(
            NamespaceId::random(),
            parent_namespace_id,
            metadata,
            operation,
        )
    }

    pub(crate) fn create_namespace_with_id(
        &self,
        namespace_id: NamespaceId,
        parent_namespace_id: Option<NamespaceId>,
        metadata: &MetadataInput,
        operation: VaultOperationContext,
    ) -> Result<NamespaceId, VaultError> {
        validate_metadata(metadata)?;
        if let Some(parent) = parent_namespace_id {
            let parent_state = self.store.namespace(parent).map_err(map_storage)?;
            self.verify_namespace_state(&parent_state)?;
            if parent_state.lifecycle_state != "active" {
                return Err(VaultError::NotFound);
            }
            let depth = self.store.namespace_depth(parent).map_err(map_storage)?;
            if depth >= MAX_NAMESPACE_DEPTH {
                return Err(VaultError::InvalidInput);
            }
        }
        let index_scope =
            parent_namespace_id.unwrap_or_else(|| NamespaceId::from_uuid(self.vault_id.as_uuid()));
        let name_index = exact_name_index(self.blind_index_key(), index_scope, &metadata.name)
            .map_err(map_crypto)?;
        let object_id = ObjectId::from_uuid(namespace_id.as_uuid());
        let plaintext = encode_metadata(metadata, 1)?;
        let encrypted = self.encrypt_record(
            plaintext,
            ObjectKind::NamespaceMetadata,
            ObjectKind::WrappedNamespaceMetadataKey,
            object_id,
            1,
        )?;
        let state_commitment = self.namespace_state_commitment(
            namespace_id,
            parent_namespace_id,
            name_index.as_bytes(),
            "active",
            1,
            1,
        )?;
        let audit =
            self.build_audit("namespace:create", "namespace", Some(object_id), operation)?;
        self.store
            .create_namespace(
                &NamespaceInsert {
                    namespace_id,
                    parent_namespace_id,
                    name_index: *name_index.as_bytes(),
                    metadata: encrypted,
                    state_commitment,
                    created_at_unix_ms: operation.now_unix_ms,
                },
                &audit,
            )
            .map_err(map_storage)?;
        Ok(namespace_id)
    }

    /// Moves an active namespace after the authorization layer has confirmed
    /// its effective-access impact.
    pub(crate) fn move_namespace_core(
        &self,
        namespace_id: NamespaceId,
        expected_revision: u64,
        new_parent_namespace_id: Option<NamespaceId>,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        let current = self.store.namespace(namespace_id).map_err(map_storage)?;
        self.verify_namespace_state(&current)?;
        if current.revision != expected_revision || current.lifecycle_state != "active" {
            return Err(VaultError::Conflict);
        }
        if let Some(parent) = new_parent_namespace_id {
            if parent == namespace_id {
                return Err(VaultError::InvalidInput);
            }
            let parent_state = self.store.namespace(parent).map_err(map_storage)?;
            self.verify_namespace_state(&parent_state)?;
            if parent_state.lifecycle_state != "active"
                || self.store.namespace_depth(parent).map_err(map_storage)? >= MAX_NAMESPACE_DEPTH
                || self
                    .store
                    .namespace_ancestors_inclusive(parent)
                    .map_err(map_storage)?
                    .contains(&namespace_id)
            {
                return Err(VaultError::InvalidInput);
            }
        }
        let plaintext = self.decrypt_record(
            &current.metadata,
            ObjectKind::NamespaceMetadata,
            ObjectKind::WrappedNamespaceMetadataKey,
            ObjectId::from_uuid(namespace_id.as_uuid()),
            current.metadata_version,
        )?;
        let metadata = decode_metadata(plaintext, 1)?;
        let scope = new_parent_namespace_id
            .unwrap_or_else(|| NamespaceId::from_uuid(self.vault_id.as_uuid()));
        let name_index =
            exact_name_index(self.blind_index_key(), scope, &metadata.name).map_err(map_crypto)?;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::Conflict)?;
        let commitment = self.namespace_state_commitment(
            namespace_id,
            new_parent_namespace_id,
            name_index.as_bytes(),
            "active",
            next_revision,
            current.metadata_version,
        )?;
        let audit = self.build_audit(
            "namespace:move",
            "namespace",
            Some(ObjectId::from_uuid(namespace_id.as_uuid())),
            operation,
        )?;
        self.store
            .move_namespace(
                namespace_id,
                expected_revision,
                new_parent_namespace_id,
                name_index.as_bytes(),
                &commitment,
                operation.now_unix_ms,
                &audit,
            )
            .map_err(map_storage)
    }

    /// Creates an encrypted secret and immutable version 1 with atomic audit.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, missing namespace, duplicate name,
    /// cryptographic failure, or audit/storage failure.
    #[cfg_attr(not(test), allow(dead_code, reason = "scheduled facade is canonical"))]
    pub(crate) fn create_secret(
        &self,
        namespace_id: NamespaceId,
        metadata: &MetadataInput,
        value: ProtectedBytes,
        operation: VaultOperationContext,
    ) -> Result<SecretCreated, VaultError> {
        self.create_secret_with_schedule(
            namespace_id,
            metadata,
            value,
            SecretSchedule::default(),
            operation,
        )
    }

    /// Creates an encrypted secret with explicit expiration and upstream
    /// credential-rotation timestamps.
    ///
    /// The schedule is advisory metadata. Reaching a due time never claims or
    /// triggers rotation in the upstream system.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid schedule/metadata/value bounds, duplicate
    /// identity/name, cryptographic failure, or audit/storage failure.
    pub(crate) fn create_secret_with_schedule(
        &self,
        namespace_id: NamespaceId,
        metadata: &MetadataInput,
        value: ProtectedBytes,
        schedule: SecretSchedule,
        operation: VaultOperationContext,
    ) -> Result<SecretCreated, VaultError> {
        self.create_secret_with_id_and_schedule(
            SecretId::random(),
            namespace_id,
            metadata,
            value,
            schedule,
            operation,
        )
    }

    pub(crate) fn create_secret_with_id_and_schedule(
        &self,
        secret_id: SecretId,
        namespace_id: NamespaceId,
        metadata: &MetadataInput,
        value: ProtectedBytes,
        schedule: SecretSchedule,
        operation: VaultOperationContext,
    ) -> Result<SecretCreated, VaultError> {
        validate_metadata(metadata)?;
        validate_secret(&value)?;
        if !schedule.is_valid() {
            return Err(VaultError::InvalidInput);
        }
        let object_id = ObjectId::from_uuid(secret_id.as_uuid());
        let name_index = exact_name_index(self.blind_index_key(), namespace_id, &metadata.name)
            .map_err(map_crypto)?;
        let encrypted_metadata = self.encrypt_record(
            encode_metadata(metadata, 2)?,
            ObjectKind::SecretMetadata,
            ObjectKind::WrappedMetadataKey,
            object_id,
            1,
        )?;
        let encrypted_payload = self.encrypt_record(
            value,
            ObjectKind::SecretVersion,
            ObjectKind::WrappedDataKey,
            object_id,
            1,
        )?;
        let state_commitment = self.secret_state_commitment(
            secret_id,
            namespace_id,
            name_index.as_bytes(),
            "active",
            1,
            1,
            1,
            schedule,
        )?;
        let audit = self.build_audit("secret:create", "secret", Some(object_id), operation)?;
        self.store
            .create_secret(
                &SecretInsert {
                    secret_id,
                    namespace_id,
                    name_index: *name_index.as_bytes(),
                    metadata: encrypted_metadata,
                    payload: encrypted_payload,
                    schedule,
                    state_commitment,
                    created_by_principal_id: operation.actor_principal_id,
                    created_at_unix_ms: operation.now_unix_ms,
                },
                &audit,
            )
            .map_err(map_storage)?;
        Ok(SecretCreated {
            secret_id,
            version: 1,
            revision: 1,
        })
    }

    /// Appends a new immutable value under explicit version and revision
    /// preconditions.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale preconditions and fails closed for any
    /// cryptographic, audit, or storage error.
    #[cfg_attr(not(test), allow(dead_code, reason = "scheduled facade is canonical"))]
    pub(crate) fn update_secret(
        &self,
        secret_id: SecretId,
        expected_current_version: u64,
        expected_revision: u64,
        value: ProtectedBytes,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        self.update_secret_with_schedule(
            secret_id,
            expected_current_version,
            expected_revision,
            value,
            SecretSchedule::default(),
            operation,
        )
    }

    /// Appends a scheduled immutable value version under explicit version and
    /// revision preconditions.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale preconditions, invalid input for an invalid
    /// schedule, and fails closed for cryptographic, audit, or storage errors.
    pub(crate) fn update_secret_with_schedule(
        &self,
        secret_id: SecretId,
        expected_current_version: u64,
        expected_revision: u64,
        value: ProtectedBytes,
        schedule: SecretSchedule,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        validate_secret(&value)?;
        if !schedule.is_valid() {
            return Err(VaultError::InvalidInput);
        }
        let next_version = expected_current_version
            .checked_add(1)
            .ok_or(VaultError::Conflict)?;
        let current_state = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&current_state)?;
        if current_state.current_version != expected_current_version
            || current_state.revision != expected_revision
            || current_state.lifecycle_state != "active"
        {
            return Err(VaultError::Conflict);
        }
        let next_state_commitment = self.secret_state_commitment(
            secret_id,
            current_state.namespace_id,
            &current_state.name_index,
            "active",
            next_version,
            expected_revision
                .checked_add(1)
                .ok_or(VaultError::Conflict)?,
            current_state.metadata_version,
            schedule,
        )?;
        let object_id = ObjectId::from_uuid(secret_id.as_uuid());
        let encrypted = self.encrypt_record(
            value,
            ObjectKind::SecretVersion,
            ObjectKind::WrappedDataKey,
            object_id,
            next_version,
        )?;

        for _attempt in 0..2 {
            let audit = self.build_audit("secret:update", "secret", Some(object_id), operation)?;
            let result = self.store.append_secret_version(
                &SecretVersionInsert {
                    secret_id,
                    expected_current_version,
                    expected_revision,
                    payload: clone_encrypted(&encrypted),
                    schedule,
                    next_state_commitment,
                    created_by_principal_id: operation.actor_principal_id,
                    created_at_unix_ms: operation.now_unix_ms,
                },
                &audit,
            );
            match result {
                Ok(version) => return Ok(version),
                Err(StorageError::Conflict) => {
                    let current = self.store.secret(secret_id).map_err(map_storage)?;
                    if current.current_version != expected_current_version
                        || current.revision != expected_revision
                    {
                        return Err(VaultError::Conflict);
                    }
                }
                Err(error) => return Err(map_storage(error)),
            }
        }
        Err(VaultError::Conflict)
    }

    /// Explicitly decrypts and audits the current secret value.
    ///
    /// This is the sole policy-independent plaintext-returning domain call;
    /// Phase 2 wraps it with `secret:value-read` authorization and recent-auth
    /// requirements. Audit must commit before plaintext is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for absent/inactive state, cryptographic integrity
    /// failure, or audit persistence failure.
    pub(crate) fn reveal_current_secret(
        &self,
        secret_id: SecretId,
        operation: VaultOperationContext,
    ) -> Result<ProtectedBytes, VaultError> {
        let state = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&state)?;
        if state.lifecycle_state != "active" {
            return Err(VaultError::NotFound);
        }
        let encrypted = self
            .store
            .encrypted_secret_version(secret_id, state.current_version)
            .map_err(map_storage)?;
        let plaintext = self.decrypt_record(
            &encrypted,
            ObjectKind::SecretVersion,
            ObjectKind::WrappedDataKey,
            ObjectId::from_uuid(secret_id.as_uuid()),
            state.current_version,
        )?;
        let audit = self.build_audit(
            "secret:value-read",
            "secret",
            Some(ObjectId::from_uuid(secret_id.as_uuid())),
            operation,
        )?;
        self.store.append_audit(&audit).map_err(map_storage)?;
        Ok(plaintext)
    }

    /// Returns a bounded page of immutable version metadata.
    ///
    /// # Errors
    ///
    /// Returns not found for an absent or deleted secret, invalid input for an
    /// unsupported page size, and integrity/unavailable on protected failure.
    pub(crate) fn secret_version_history(
        &self,
        secret_id: SecretId,
        after_version: u64,
        limit: u16,
    ) -> Result<Vec<SecretVersionSummary>, VaultError> {
        if !(1..=100).contains(&limit) {
            return Err(VaultError::InvalidInput);
        }
        let state = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&state)?;
        if state.lifecycle_state == "deleted" {
            return Err(VaultError::NotFound);
        }
        self.store
            .secret_versions_after(secret_id, after_version, limit)
            .map_err(map_storage)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| SecretVersionSummary {
                        version: record.version,
                        schedule: record.schedule,
                        created_by_principal_id: record.created_by_principal_id,
                        created_at_unix_ms: record.created_at_unix_ms,
                    })
                    .collect()
            })
    }

    /// Decrypts and audits one exact immutable historical value.
    ///
    /// # Errors
    ///
    /// Returns not found without distinguishing an absent secret or version,
    /// and fails closed on integrity or audit-persistence errors.
    pub(crate) fn reveal_secret_version(
        &self,
        secret_id: SecretId,
        version: u64,
        operation: VaultOperationContext,
    ) -> Result<ProtectedBytes, VaultError> {
        if version == 0 {
            return Err(VaultError::InvalidInput);
        }
        let state = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&state)?;
        if state.lifecycle_state == "deleted" || version > state.current_version {
            return Err(VaultError::NotFound);
        }
        let encrypted = self
            .store
            .encrypted_secret_version(secret_id, version)
            .map_err(map_storage)?;
        let plaintext = self.decrypt_record(
            &encrypted,
            ObjectKind::SecretVersion,
            ObjectKind::WrappedDataKey,
            ObjectId::from_uuid(secret_id.as_uuid()),
            version,
        )?;
        let audit = self.build_audit(
            "secret:version-read",
            "secret",
            Some(ObjectId::from_uuid(secret_id.as_uuid())),
            operation,
        )?;
        self.store.append_audit(&audit).map_err(map_storage)?;
        Ok(plaintext)
    }

    /// Looks up a secret by an exact protected name and verifies the decrypted
    /// canonical name before returning its stable identity.
    ///
    /// # Errors
    ///
    /// Returns not-found for no candidate, collision, or inactive candidate;
    /// fails closed for metadata integrity/storage errors.
    pub(crate) fn find_secret_by_exact_name(
        &self,
        namespace_id: NamespaceId,
        name: &ProtectedString,
    ) -> Result<SecretId, VaultError> {
        use unicode_normalization::UnicodeNormalization;

        let index =
            exact_name_index(self.blind_index_key(), namespace_id, name).map_err(map_crypto)?;
        let candidate = self
            .store
            .secret_by_name_index(namespace_id, index.as_bytes())
            .map_err(map_storage)?
            .ok_or(VaultError::NotFound)?;
        self.verify_secret_state(&candidate)?;
        if candidate.lifecycle_state != "active" {
            return Err(VaultError::NotFound);
        }
        let metadata = self.decrypt_metadata(&candidate)?;
        let expected = name.expose().nfc().collect::<String>();
        let actual = metadata.name.expose().nfc().collect::<String>();
        if expected != actual {
            return Err(VaultError::NotFound);
        }
        Ok(candidate.secret_id)
    }

    /// Explicitly decrypts protected secret metadata.
    ///
    /// Phase 2 wraps this call with `secret:metadata-read` authorization.
    ///
    /// # Errors
    ///
    /// Returns not-found for inactive state and integrity for malformed or
    /// unauthenticated metadata.
    pub(crate) fn read_secret_metadata(
        &self,
        secret_id: SecretId,
    ) -> Result<DecryptedMetadata, VaultError> {
        let candidate = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&candidate)?;
        if candidate.lifecycle_state != "active" {
            return Err(VaultError::NotFound);
        }
        self.decrypt_metadata(&candidate)
    }

    /// Loads and decrypts a bounded page of active child namespaces.
    pub(crate) fn list_namespaces(
        &self,
        parent_namespace_id: Option<NamespaceId>,
        after_namespace_id: Option<NamespaceId>,
        limit: u16,
    ) -> Result<Vec<NamespaceListItem>, VaultError> {
        if !(1..=100).contains(&limit) {
            return Err(VaultError::InvalidInput);
        }
        let records = self
            .store
            .namespaces_after(parent_namespace_id, after_namespace_id, limit)
            .map_err(map_storage)?;
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            self.verify_namespace_state(&record)?;
            let plaintext = self.decrypt_record(
                &record.metadata,
                ObjectKind::NamespaceMetadata,
                ObjectKind::WrappedNamespaceMetadataKey,
                ObjectId::from_uuid(record.namespace_id.as_uuid()),
                record.metadata_version,
            )?;
            items.push(NamespaceListItem {
                namespace_id: record.namespace_id,
                metadata: decode_metadata(plaintext, 1)?,
                revision: record.revision,
            });
        }
        Ok(items)
    }

    /// Loads and decrypts a bounded metadata-only page of active secrets.
    pub(crate) fn list_secrets(
        &self,
        namespace_id: NamespaceId,
        after_secret_id: Option<SecretId>,
        limit: u16,
    ) -> Result<Vec<SecretListItem>, VaultError> {
        if !(1..=100).contains(&limit) {
            return Err(VaultError::InvalidInput);
        }
        let namespace = self.store.namespace(namespace_id).map_err(map_storage)?;
        self.verify_namespace_state(&namespace)?;
        if namespace.lifecycle_state != "active" {
            return Err(VaultError::NotFound);
        }
        let records = self
            .store
            .secrets_after(namespace_id, after_secret_id, limit)
            .map_err(map_storage)?;
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            self.verify_secret_state(&record)?;
            items.push(SecretListItem {
                secret_id: record.secret_id,
                metadata: self.decrypt_metadata(&record)?,
                current_version: record.current_version,
                revision: record.revision,
            });
        }
        Ok(items)
    }

    /// Archives an active secret without deleting immutable versions.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale revision/state and fails closed if audit
    /// cannot commit atomically.
    pub(crate) fn archive_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        self.change_lifecycle(
            secret_id,
            expected_revision,
            "active",
            "archived",
            "secret:archive",
            operation,
        )
    }

    /// Restores an archived secret to ordinary active use.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale revision/state and fails closed if audit
    /// cannot commit atomically.
    pub(crate) fn restore_archived_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        self.change_lifecycle(
            secret_id,
            expected_revision,
            "archived",
            "active",
            "secret:restore",
            operation,
        )
    }

    /// Tombstones a secret while retaining its encrypted immutable history.
    ///
    /// # Errors
    ///
    /// Returns a conflict for stale revision/state and fails closed if audit
    /// cannot commit atomically.
    pub(crate) fn delete_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        self.change_lifecycle(
            secret_id,
            expected_revision,
            "active",
            "deleted",
            "secret:delete",
            operation,
        )
    }

    /// Purges encrypted rows from the current vault after an unforgeable owner
    /// approval capability and retention check.
    ///
    /// This does not claim erasure from prior backups, filesystem snapshots,
    /// storage media, or replicas. Opaque tombstone and audit history remain.
    ///
    /// # Errors
    ///
    /// Returns a conflict unless the exact revision is deleted and older than
    /// the approved retention cutoff, or if audit cannot commit.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "single-use authorization capability is consumed by the operation"
    )]
    pub(crate) fn purge_secret_after_owner_approval(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        approval: OwnerPurgeApproval,
        operation: VaultOperationContext,
    ) -> Result<(), VaultError> {
        let OwnerPurgeApproval {
            retention_cutoff_unix_ms,
        } = approval;
        let current = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&current)?;
        if current.revision != expected_revision || current.lifecycle_state != "deleted" {
            return Err(VaultError::Conflict);
        }
        let audit = self.build_audit(
            "secret:purge",
            "secret",
            Some(ObjectId::from_uuid(secret_id.as_uuid())),
            operation,
        )?;
        self.store
            .purge_secret(
                &SecretPurge {
                    secret_id,
                    expected_revision,
                    retention_cutoff_unix_ms,
                    purged_at_unix_ms: operation.now_unix_ms,
                },
                &audit,
            )
            .map_err(map_storage)
    }

    /// Streams and authenticates the complete local audit chain.
    ///
    /// This detects modification, insertion, reordering, and internal
    /// truncation. Without an external anchor it cannot prove that a valid
    /// suffix was not removed together with the database's recorded head.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for any sequence, predecessor, or keyed
    /// commitment mismatch, and unavailable for storage failure.
    pub(crate) fn verify_audit_chain(&self) -> Result<AuditVerification, VaultError> {
        let mut previous = [0_u8; 32];
        let mut sequence = 0_u64;
        loop {
            let page = self
                .store
                .audit_records_after(sequence, 1000)
                .map_err(map_storage)?;
            if page.is_empty() {
                break;
            }
            let page_length = page.len();
            for record in page {
                let expected_sequence = sequence.checked_add(1).ok_or(VaultError::Integrity)?;
                if record.sequence != expected_sequence || record.previous_commitment != previous {
                    return Err(VaultError::Integrity);
                }
                let input = AuditCommitmentInput {
                    commitment_version: record.commitment_version,
                    previous,
                    sequence: record.sequence,
                    event_id: record.event_id,
                    installation_id: record.installation_id,
                    recovery_epoch: record.recovery_epoch,
                    occurred_at_unix_ms: record.occurred_at_unix_ms,
                    request_id: record.request_id,
                    actor_principal_id: record.actor_principal_id,
                    credential_kind: record.credential_kind.as_deref(),
                    credential_id: record.credential_id,
                    action: &record.action,
                    target_kind: &record.target_kind,
                    target_id: record.target_id,
                    outcome: &record.outcome,
                };
                let expected = audit_commitment(self.audit_key(), &input).map_err(map_crypto)?;
                if expected.as_bytes() != &record.commitment {
                    return Err(VaultError::Integrity);
                }
                sequence = record.sequence;
                previous = record.commitment;
            }
            if page_length < 1000 {
                break;
            }
        }
        let head = self.store.audit_head().map_err(map_storage)?;
        if head.sequence != sequence || head.commitment != previous {
            return Err(VaultError::Conflict);
        }
        Ok(AuditVerification {
            events_verified: sequence,
            final_sequence: sequence,
            final_commitment: previous,
        })
    }

    fn change_lifecycle(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        from_state: &'static str,
        to_state: &'static str,
        action: &'static str,
        operation: VaultOperationContext,
    ) -> Result<u64, VaultError> {
        let current = self.store.secret(secret_id).map_err(map_storage)?;
        self.verify_secret_state(&current)?;
        if current.revision != expected_revision || current.lifecycle_state != from_state {
            return Err(VaultError::Conflict);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::Conflict)?;
        let next_state_commitment = self.secret_state_commitment(
            secret_id,
            current.namespace_id,
            &current.name_index,
            to_state,
            current.current_version,
            next_revision,
            current.metadata_version,
            current.schedule,
        )?;
        let audit = self.build_audit(
            action,
            "secret",
            Some(ObjectId::from_uuid(secret_id.as_uuid())),
            operation,
        )?;
        self.store
            .change_secret_lifecycle(
                &SecretLifecycleChange {
                    secret_id,
                    expected_revision,
                    from_state,
                    to_state,
                    changed_at_unix_ms: operation.now_unix_ms,
                    next_state_commitment,
                },
                &audit,
            )
            .map_err(map_storage)
    }

    fn namespace_state_commitment(
        &self,
        namespace_id: NamespaceId,
        parent_namespace_id: Option<NamespaceId>,
        name_index: &[u8; 32],
        lifecycle_state: &str,
        revision: u64,
        metadata_version: u64,
    ) -> Result<[u8; 32], VaultError> {
        let mut canonical = Vec::with_capacity(124);
        canonical.extend_from_slice(b"SMCV-NS-STATE\0v1\0");
        canonical.extend_from_slice(self.vault_id.as_bytes());
        canonical.extend_from_slice(self.installation_id.as_bytes());
        canonical.extend_from_slice(namespace_id.as_bytes());
        if let Some(parent) = parent_namespace_id {
            canonical.push(1);
            canonical.extend_from_slice(parent.as_bytes());
        } else {
            canonical.push(0);
            canonical.extend_from_slice(&[0; 16]);
        }
        canonical.extend_from_slice(name_index);
        canonical.push(lifecycle_code(lifecycle_state)?);
        canonical.extend_from_slice(&revision.to_be_bytes());
        canonical.extend_from_slice(&metadata_version.to_be_bytes());
        state_commitment(self.audit_key(), &canonical)
            .map(|commitment| *commitment.as_bytes())
            .map_err(map_crypto)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "explicit canonical state fields avoid an ambiguous or partially committed input"
    )]
    fn secret_state_commitment(
        &self,
        secret_id: SecretId,
        namespace_id: NamespaceId,
        name_index: &[u8; 32],
        lifecycle_state: &str,
        current_version: u64,
        revision: u64,
        metadata_version: u64,
        schedule: SecretSchedule,
    ) -> Result<[u8; 32], VaultError> {
        let mut canonical = Vec::with_capacity(121);
        canonical.extend_from_slice(b"SMCV-SECRET-STATE\0v1\0");
        canonical.extend_from_slice(self.vault_id.as_bytes());
        canonical.extend_from_slice(self.installation_id.as_bytes());
        canonical.extend_from_slice(secret_id.as_bytes());
        canonical.extend_from_slice(namespace_id.as_bytes());
        canonical.extend_from_slice(name_index);
        canonical.push(lifecycle_code(lifecycle_state)?);
        canonical.extend_from_slice(&current_version.to_be_bytes());
        canonical.extend_from_slice(&revision.to_be_bytes());
        canonical.extend_from_slice(&metadata_version.to_be_bytes());
        append_optional_timestamp(&mut canonical, schedule.expires_at_unix_ms);
        append_optional_timestamp(&mut canonical, schedule.rotation_due_at_unix_ms);
        state_commitment(self.audit_key(), &canonical)
            .map(|commitment| *commitment.as_bytes())
            .map_err(map_crypto)
    }

    pub(crate) fn verify_secret_state(
        &self,
        secret: &smcv_storage::SecretRecord,
    ) -> Result<(), VaultError> {
        let expected = self.secret_state_commitment(
            secret.secret_id,
            secret.namespace_id,
            &secret.name_index,
            &secret.lifecycle_state,
            secret.current_version,
            secret.revision,
            secret.metadata_version,
            secret.schedule,
        )?;
        if expected != secret.state_commitment {
            return Err(VaultError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn verify_namespace_state(
        &self,
        namespace: &smcv_storage::NamespaceRecord,
    ) -> Result<(), VaultError> {
        let expected = self.namespace_state_commitment(
            namespace.namespace_id,
            namespace.parent_namespace_id,
            &namespace.name_index,
            &namespace.lifecycle_state,
            namespace.revision,
            namespace.metadata_version,
        )?;
        if expected != namespace.state_commitment {
            return Err(VaultError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn encrypt_record(
        &self,
        plaintext: ProtectedBytes,
        object_kind: ObjectKind,
        wrapped_kind: ObjectKind,
        object_id: ObjectId,
        object_version: u64,
    ) -> Result<EncryptedRecord, VaultError> {
        let context = RecordContext {
            vault_id: self.vault_id,
            installation_id: self.installation_id,
            object_kind,
            object_id,
            object_version,
        };
        let dek = KeyMaterial::generate().map_err(map_crypto)?;
        let payload = seal(&dek, context, &plaintext).map_err(map_crypto)?;
        drop(plaintext);
        let wrapped_context = RecordContext {
            object_kind: wrapped_kind,
            ..context
        };
        let (kek_version, wrapped) = self
            .with_active_kek(|kek| seal(kek, wrapped_context, &dek.to_protected_bytes()))
            .ok_or(VaultError::Unavailable)?;
        let wrapped = wrapped.map_err(map_crypto)?;
        Ok(EncryptedRecord {
            nonce: payload.nonce,
            ciphertext: payload.ciphertext,
            dek_nonce: wrapped.nonce,
            wrapped_dek: wrapped
                .ciphertext
                .try_into()
                .map_err(|_| VaultError::Integrity)?,
            kek_version,
        })
    }

    pub(crate) fn decrypt_record(
        &self,
        encrypted: &EncryptedRecord,
        object_kind: ObjectKind,
        wrapped_kind: ObjectKind,
        object_id: ObjectId,
        object_version: u64,
    ) -> Result<ProtectedBytes, VaultError> {
        let base_context = RecordContext {
            vault_id: self.vault_id,
            installation_id: self.installation_id,
            object_kind,
            object_id,
            object_version,
        };
        let wrapped_context = RecordContext {
            object_kind: wrapped_kind,
            ..base_context
        };
        let dek_plaintext = self
            .with_kek(encrypted.kek_version, |kek| {
                open(
                    kek,
                    wrapped_context,
                    &SealedRecord {
                        nonce: encrypted.dek_nonce,
                        ciphertext: encrypted.wrapped_dek.to_vec(),
                    },
                )
            })
            .ok_or(VaultError::Integrity)?
            .map_err(map_crypto)?;
        let dek = KeyMaterial::from_protected(dek_plaintext).map_err(map_crypto)?;
        open(
            &dek,
            base_context,
            &SealedRecord {
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext.clone(),
            },
        )
        .map_err(map_crypto)
    }

    fn decrypt_metadata(
        &self,
        secret: &smcv_storage::SecretRecord,
    ) -> Result<DecryptedMetadata, VaultError> {
        let plaintext = self.decrypt_record(
            &secret.metadata,
            ObjectKind::SecretMetadata,
            ObjectKind::WrappedMetadataKey,
            ObjectId::from_uuid(secret.secret_id.as_uuid()),
            secret.metadata_version,
        )?;
        decode_metadata(plaintext, 2)
    }

    pub(crate) fn build_audit(
        &self,
        action: &'static str,
        target_kind: &'static str,
        target_id: Option<ObjectId>,
        operation: VaultOperationContext,
    ) -> Result<AuditRecord<'static>, VaultError> {
        self.build_audit_outcome(action, target_kind, target_id, "allowed", operation)
    }

    pub(crate) fn build_audit_outcome(
        &self,
        action: &'static str,
        target_kind: &'static str,
        target_id: Option<ObjectId>,
        outcome: &'static str,
        operation: VaultOperationContext,
    ) -> Result<AuditRecord<'static>, VaultError> {
        let head = self.store.audit_head().map_err(map_storage)?;
        let sequence = head.sequence.checked_add(1).ok_or(VaultError::Conflict)?;
        let installation = self
            .store
            .installation()
            .map_err(map_storage)?
            .ok_or(VaultError::Unavailable)?;
        let event_id = AuditEventId::random();
        let input = AuditCommitmentInput {
            commitment_version: 2,
            previous: head.commitment,
            sequence,
            event_id,
            installation_id: self.installation_id,
            recovery_epoch: installation.recovery_epoch,
            occurred_at_unix_ms: operation.now_unix_ms,
            request_id: operation.request_id,
            actor_principal_id: operation.actor_principal_id,
            credential_kind: operation.credential_kind,
            credential_id: operation.credential_id,
            action,
            target_kind,
            target_id,
            outcome,
        };
        let commitment = audit_commitment(self.audit_key(), &input).map_err(map_crypto)?;
        Ok(AuditRecord {
            commitment_version: 2,
            sequence,
            event_id,
            installation_id: self.installation_id,
            recovery_epoch: installation.recovery_epoch,
            occurred_at_unix_ms: operation.now_unix_ms,
            request_id: operation.request_id,
            actor_principal_id: operation.actor_principal_id,
            credential_kind: operation.credential_kind,
            credential_id: operation.credential_id,
            action,
            target_kind,
            target_id,
            outcome,
            previous_commitment: head.commitment,
            commitment: *commitment.as_bytes(),
        })
    }
}

fn validate_metadata(metadata: &MetadataInput) -> Result<(), VaultError> {
    let name = metadata.name.expose();
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(char::is_control)
        || metadata
            .description
            .as_ref()
            .is_some_and(|description| description.expose().len() > MAX_DESCRIPTION_BYTES)
        || metadata.username.as_ref().is_some_and(|username| {
            username.expose().len() > MAX_USERNAME_BYTES
                || username.expose().chars().any(char::is_control)
        })
        || metadata.tags.len() > MAX_TAGS
        || metadata.tags.iter().any(|tag| {
            tag.expose().is_empty()
                || tag.expose().len() > MAX_TAG_BYTES
                || tag.expose().chars().any(char::is_control)
        })
    {
        return Err(VaultError::InvalidInput);
    }
    Ok(())
}

fn lifecycle_code(value: &str) -> Result<u8, VaultError> {
    match value {
        "active" => Ok(1),
        "archived" => Ok(2),
        "deleted" => Ok(3),
        "purged" => Ok(4),
        _ => Err(VaultError::Integrity),
    }
}

fn append_optional_timestamp(canonical: &mut Vec<u8>, value: Option<i64>) {
    if let Some(value) = value {
        canonical.push(1);
        canonical.extend_from_slice(&value.to_be_bytes());
    } else {
        canonical.push(0);
        canonical.extend_from_slice(&[0; 8]);
    }
}

fn validate_secret(secret: &ProtectedBytes) -> Result<(), VaultError> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(VaultError::InvalidInput);
    }
    Ok(())
}

fn encode_metadata(metadata: &MetadataInput, kind: u8) -> Result<ProtectedBytes, VaultError> {
    let name = metadata.name.expose().as_bytes();
    let name_length = u16::try_from(name.len()).map_err(|_| VaultError::InvalidInput)?;
    let description = metadata.description.as_ref().map(ProtectedString::expose);
    let description_length = description
        .map(str::len)
        .map(u32::try_from)
        .transpose()
        .map_err(|_| VaultError::InvalidInput)?
        .unwrap_or(u32::MAX);
    let username = metadata.username.as_ref().map(ProtectedString::expose);
    let username_length = username
        .map(str::len)
        .map(u16::try_from)
        .transpose()
        .map_err(|_| VaultError::InvalidInput)?
        .unwrap_or(u16::MAX);
    let tag_count = u8::try_from(metadata.tags.len()).map_err(|_| VaultError::InvalidInput)?;
    let tag_bytes = metadata.tags.iter().try_fold(0_usize, |total, tag| {
        total
            .checked_add(2)
            .and_then(|size| size.checked_add(tag.expose().len()))
            .ok_or(VaultError::InvalidInput)
    })?;
    let capacity = 18_usize
        .checked_add(name.len())
        .and_then(|size| size.checked_add(description.map_or(0, str::len)))
        .and_then(|size| size.checked_add(username.map_or(0, str::len)))
        .and_then(|size| size.checked_add(tag_bytes))
        .ok_or(VaultError::InvalidInput)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(METADATA_MAGIC);
    encoded.push(kind);
    encoded.extend_from_slice(&name_length.to_be_bytes());
    encoded.extend_from_slice(&description_length.to_be_bytes());
    encoded.extend_from_slice(&username_length.to_be_bytes());
    encoded.push(tag_count);
    encoded.extend_from_slice(name);
    if let Some(description) = description {
        encoded.extend_from_slice(description.as_bytes());
    }
    if let Some(username) = username {
        encoded.extend_from_slice(username.as_bytes());
    }
    for tag in &metadata.tags {
        let bytes = tag.expose().as_bytes();
        let length = u16::try_from(bytes.len()).map_err(|_| VaultError::InvalidInput)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(bytes);
    }
    Ok(ProtectedBytes::new(encoded))
}

fn decode_metadata(
    plaintext: ProtectedBytes,
    expected_kind: u8,
) -> Result<DecryptedMetadata, VaultError> {
    let bytes = plaintext.expose();
    if bytes.len() < 18 || &bytes[0..8] != METADATA_MAGIC || bytes[8] != expected_kind {
        return Err(VaultError::Integrity);
    }
    let name_length = usize::from(u16::from_be_bytes([bytes[9], bytes[10]]));
    let description_raw = u32::from_be_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
    let description_length = if description_raw == u32::MAX {
        None
    } else {
        Some(usize::try_from(description_raw).map_err(|_| VaultError::Integrity)?)
    };
    let username_raw = u16::from_be_bytes([bytes[15], bytes[16]]);
    let username_length = (username_raw != u16::MAX).then_some(usize::from(username_raw));
    let tag_count = usize::from(bytes[17]);
    if description_length.is_some_and(|length| length > MAX_DESCRIPTION_BYTES)
        || username_length.is_some_and(|length| length > MAX_USERNAME_BYTES)
        || tag_count > MAX_TAGS
    {
        return Err(VaultError::Integrity);
    }
    let mut cursor = 18;
    let name = read_metadata_string(bytes, &mut cursor, name_length, MAX_NAME_BYTES, true)?;
    let description = description_length
        .map(|length| {
            read_metadata_string(bytes, &mut cursor, length, MAX_DESCRIPTION_BYTES, false)
        })
        .transpose()?;
    let username = username_length
        .map(|length| read_metadata_string(bytes, &mut cursor, length, MAX_USERNAME_BYTES, false))
        .transpose()?;
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        let length_end = cursor.checked_add(2).ok_or(VaultError::Integrity)?;
        let length_bytes = bytes.get(cursor..length_end).ok_or(VaultError::Integrity)?;
        let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        cursor = length_end;
        tags.push(read_metadata_string(
            bytes,
            &mut cursor,
            length,
            MAX_TAG_BYTES,
            true,
        )?);
    }
    if cursor != bytes.len()
        || name.chars().any(char::is_control)
        || username
            .as_ref()
            .is_some_and(|value| value.chars().any(char::is_control))
        || tags.iter().any(|value| value.chars().any(char::is_control))
    {
        return Err(VaultError::Integrity);
    }
    drop(plaintext);
    Ok(DecryptedMetadata {
        name: ProtectedString::new(name),
        description: description.map(ProtectedString::new),
        username: username.map(ProtectedString::new),
        tags: tags.into_iter().map(ProtectedString::new).collect(),
    })
}

fn read_metadata_string(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    maximum: usize,
    require_nonempty: bool,
) -> Result<String, VaultError> {
    if length > maximum || (require_nonempty && length == 0) {
        return Err(VaultError::Integrity);
    }
    let end = cursor.checked_add(length).ok_or(VaultError::Integrity)?;
    let value = bytes.get(*cursor..end).ok_or(VaultError::Integrity)?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| VaultError::Integrity)
}

fn clone_encrypted(record: &EncryptedRecord) -> EncryptedRecord {
    EncryptedRecord {
        nonce: record.nonce,
        ciphertext: record.ciphertext.clone(),
        dek_nonce: record.dek_nonce,
        wrapped_dek: record.wrapped_dek,
        kek_version: record.kek_version,
    }
}

pub(crate) fn map_crypto(error: CryptoError) -> VaultError {
    match error {
        CryptoError::Integrity => VaultError::Integrity,
        CryptoError::InvalidProtectedInput | CryptoError::InvalidCredential => {
            VaultError::InvalidInput
        }
        CryptoError::Randomness | CryptoError::KeyProvider => VaultError::Unavailable,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as an owned Result::map_err adapter"
)]
pub(crate) fn map_storage(error: StorageError) -> VaultError {
    match error {
        StorageError::Conflict | StorageError::StateConflict => VaultError::Conflict,
        StorageError::NotInitialized => VaultError::NotFound,
        StorageError::InvalidData => VaultError::Integrity,
        StorageError::Sqlite(_)
        | StorageError::Poisoned
        | StorageError::DestinationExists
        | StorageError::UnsafePath
        | StorageError::MigrationMismatch => VaultError::Unavailable,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use rusqlite::Connection;
    use smcv_core::{ProtectedBytes, ProtectedString, RequestId, SecretSchedule};
    use tempfile::TempDir;

    use super::{MetadataInput, VaultError, VaultOperationContext};
    use crate::initialize_vault;

    fn operation(now_unix_ms: i64) -> VaultOperationContext {
        VaultOperationContext {
            request_id: RequestId::random(),
            actor_principal_id: None,
            credential_kind: None,
            credential_id: None,
            now_unix_ms,
        }
    }

    fn metadata(name: &str, description: &str) -> MetadataInput {
        MetadataInput {
            name: ProtectedString::new(String::from(name)),
            description: Some(ProtectedString::new(String::from(description))),
            username: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn metadata_v2_encoding_is_a_frozen_compatibility_fixture() {
        let input = MetadataInput {
            name: ProtectedString::new(String::from("n")),
            description: Some(ProtectedString::new(String::from("d"))),
            username: Some(ProtectedString::new(String::from("u"))),
            tags: vec![
                ProtectedString::new(String::from("x")),
                ProtectedString::new(String::from("yz")),
            ],
        };
        let encoded = super::encode_metadata(&input, 2)
            .unwrap_or_else(|error| panic!("fixture metadata must encode: {error}"));
        let mut expected = b"SMCVMD02\x02\x00\x01\x00\x00\x00\x01\x00\x01\x02ndu".to_vec();
        expected.extend_from_slice(b"\x00\x01x\x00\x02yz");
        assert_eq!(encoded.expose(), expected);
        let decoded = super::decode_metadata(encoded, 2)
            .unwrap_or_else(|error| panic!("fixture metadata must decode: {error}"));
        assert_eq!(decoded.name.expose(), "n");
        assert_eq!(
            decoded.username.as_ref().map(ProtectedString::expose),
            Some("u")
        );
        assert_eq!(decoded.tags[1].expose(), "yz");
    }

    #[test]
    fn audit_insert_failure_rolls_back_the_domain_mutation() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let injector = Connection::open(&database)
            .unwrap_or_else(|error| panic!("failure injector must open: {error}"));
        injector
            .execute_batch(
                "CREATE TRIGGER smcv_test_reject_namespace_audit
                 BEFORE INSERT ON smcv_audit_events
                 WHEN NEW.action = 'namespace:create'
                 BEGIN
                     SELECT RAISE(ABORT, 'synthetic audit failure');
                 END;",
            )
            .unwrap_or_else(|error| panic!("failure trigger must install: {error}"));
        drop(injector);

        assert!(matches!(
            vault.create_namespace(
                None,
                &metadata("must-not-commit", "synthetic"),
                operation(1_800_000_000_001),
            ),
            Err(VaultError::Unavailable)
        ));
        let inspector = Connection::open(&database)
            .unwrap_or_else(|error| panic!("rollback inspector must open: {error}"));
        let namespaces: i64 = inspector
            .query_row("SELECT count(*) FROM smcv_namespaces", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("namespace count must read: {error}"));
        let audit: i64 = inspector
            .query_row("SELECT count(*) FROM smcv_audit_events", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("audit count must read: {error}"));
        assert_eq!(namespaces, 0);
        assert_eq!(audit, 0);
    }

    #[test]
    fn namespace_names_are_unique_at_root_and_hierarchy_depth_is_bounded() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let top = vault
            .create_namespace(None, &metadata("unique-root", ""), operation(1))
            .unwrap_or_else(|error| panic!("root namespace must create: {error}"));
        assert!(matches!(
            vault.create_namespace(None, &metadata("unique-root", ""), operation(2)),
            Err(VaultError::Conflict)
        ));

        let mut parent = top;
        for depth in 2..=super::MAX_NAMESPACE_DEPTH {
            parent = vault
                .create_namespace(
                    Some(parent),
                    &metadata(&format!("depth-{depth}"), ""),
                    operation(i64::from(depth)),
                )
                .unwrap_or_else(|error| panic!("bounded namespace must create: {error}"));
        }
        assert!(matches!(
            vault.create_namespace(Some(parent), &metadata("too-deep", ""), operation(100),),
            Err(VaultError::InvalidInput)
        ));
    }

    #[test]
    fn expiration_and_upstream_rotation_due_are_current_version_advisories() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(
                None,
                &metadata("schedules", ""),
                operation(1_800_000_000_001),
            )
            .unwrap_or_else(|error| panic!("namespace must create: {error}"));
        let expired = vault
            .create_secret_with_schedule(
                namespace,
                &metadata("expired", ""),
                ProtectedBytes::new(b"expired-value".to_vec()),
                SecretSchedule {
                    expires_at_unix_ms: Some(1_800_000_000_005),
                    rotation_due_at_unix_ms: Some(1_800_000_000_100),
                },
                operation(1_800_000_000_002),
            )
            .unwrap_or_else(|error| panic!("scheduled secret must create: {error}"));
        let rotation_due = vault
            .create_secret_with_schedule(
                namespace,
                &metadata("rotation-due", ""),
                ProtectedBytes::new(b"rotation-value".to_vec()),
                SecretSchedule {
                    expires_at_unix_ms: None,
                    rotation_due_at_unix_ms: Some(1_800_000_000_006),
                },
                operation(1_800_000_000_003),
            )
            .unwrap_or_else(|error| panic!("rotation schedule must create: {error}"));
        let due = vault
            .secrets_due(1_800_000_000_010, 10)
            .unwrap_or_else(|error| panic!("due schedules must query: {error}"));
        assert_eq!(due.len(), 2);
        assert!(due.iter().any(|item| {
            item.secret_id == expired.secret_id && item.expired && !item.upstream_rotation_due
        }));
        assert!(due.iter().any(|item| {
            item.secret_id == rotation_due.secret_id && !item.expired && item.upstream_rotation_due
        }));

        vault
            .update_secret_with_schedule(
                expired.secret_id,
                1,
                1,
                ProtectedBytes::new(b"replacement-upstream-value".to_vec()),
                SecretSchedule {
                    expires_at_unix_ms: Some(1_800_000_001_000),
                    rotation_due_at_unix_ms: Some(1_800_000_001_000),
                },
                operation(1_800_000_000_011),
            )
            .unwrap_or_else(|error| panic!("replacement version must append: {error}"));
        let due = vault
            .secrets_due(1_800_000_000_012, 10)
            .unwrap_or_else(|error| panic!("current schedules must query: {error}"));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].secret_id, rotation_due.secret_id);
        assert!(matches!(
            vault.create_secret_with_schedule(
                namespace,
                &metadata("invalid", ""),
                ProtectedBytes::new(b"invalid-schedule".to_vec()),
                SecretSchedule {
                    expires_at_unix_ms: Some(-1),
                    rotation_due_at_unix_ms: None,
                },
                operation(1_800_000_000_013),
            ),
            Err(VaultError::InvalidInput)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "single end-to-end test keeps encryption, append, audit, and artifact scan linked"
    )]
    fn encrypted_create_update_reveal_is_append_only_and_audited() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let sentinel = "SYNTHETIC-PROTECTED-PHASE1-7f61d0a4";
        let username_sentinel = "SYNTHETIC-USERNAME-3e19c4";
        let tag_sentinel = "SYNTHETIC-TAG-70bcd2";
        let namespace = vault
            .create_namespace(
                None,
                &metadata(sentinel, "SYNTHETIC-NAMESPACE-DESCRIPTION"),
                operation(1_800_000_000_001),
            )
            .unwrap_or_else(|error| panic!("encrypted namespace must create: {error}"));
        let created = vault
            .create_secret(
                namespace,
                &MetadataInput {
                    name: ProtectedString::new(String::from(sentinel)),
                    description: Some(ProtectedString::new(String::from(
                        "SYNTHETIC-SECRET-DESCRIPTION",
                    ))),
                    username: Some(ProtectedString::new(String::from(username_sentinel))),
                    tags: vec![ProtectedString::new(String::from(tag_sentinel))],
                },
                ProtectedBytes::new(sentinel.as_bytes().to_vec()),
                operation(1_800_000_000_002),
            )
            .unwrap_or_else(|error| panic!("encrypted secret must create: {error}"));

        let next_value = "SYNTHETIC-PROTECTED-PHASE1-NEXT-8a23d19b";
        assert_eq!(
            vault
                .update_secret(
                    created.secret_id,
                    1,
                    1,
                    ProtectedBytes::new(next_value.as_bytes().to_vec()),
                    operation(1_800_000_000_003),
                )
                .unwrap_or_else(|error| panic!("new version must append: {error}")),
            2
        );
        assert!(matches!(
            vault.update_secret(
                created.secret_id,
                1,
                1,
                ProtectedBytes::new(b"stale-synthetic-value".to_vec()),
                operation(1_800_000_000_004),
            ),
            Err(VaultError::Conflict)
        ));

        let revealed = vault
            .reveal_current_secret(created.secret_id, operation(1_800_000_000_005))
            .unwrap_or_else(|error| panic!("current version must reveal: {error}"));
        assert_eq!(revealed.expose(), next_value.as_bytes());
        let state = vault
            .store
            .secret(created.secret_id)
            .unwrap_or_else(|error| panic!("safe secret state must load: {error}"));
        assert_eq!(state.current_version, 2);
        assert_eq!(state.revision, 2);
        let protected_metadata = vault
            .read_secret_metadata(created.secret_id)
            .unwrap_or_else(|error| panic!("protected metadata must decrypt: {error}"));
        assert_eq!(
            protected_metadata
                .username
                .as_ref()
                .map(ProtectedString::expose),
            Some(username_sentinel)
        );
        assert_eq!(protected_metadata.tags[0].expose(), tag_sentinel);
        assert!(
            vault
                .store
                .encrypted_secret_version(created.secret_id, 1)
                .is_ok()
        );
        assert_eq!(
            vault
                .store
                .audit_head()
                .unwrap_or_else(|error| panic!("audit head must load: {error}"))
                .sequence,
            4
        );
        assert_eq!(
            vault
                .verify_audit_chain()
                .unwrap_or_else(|error| panic!("audit chain must verify: {error}"))
                .events_verified,
            4
        );

        for entry in fs::read_dir(
            database
                .parent()
                .unwrap_or_else(|| panic!("synthetic database must have a parent")),
        )
        .unwrap_or_else(|error| panic!("database directory must read: {error}"))
        {
            let entry = entry.unwrap_or_else(|error| panic!("database entry must read: {error}"));
            if entry
                .file_type()
                .unwrap_or_else(|error| panic!("database entry type must read: {error}"))
                .is_file()
            {
                let bytes = fs::read(entry.path())
                    .unwrap_or_else(|error| panic!("database artifact must read: {error}"));
                assert!(!contains(&bytes, sentinel.as_bytes()));
                assert!(!contains(&bytes, next_value.as_bytes()));
                assert!(!contains(&bytes, username_sentinel.as_bytes()));
                assert!(!contains(&bytes, tag_sentinel.as_bytes()));
            }
        }
    }

    #[test]
    fn every_record_envelope_component_and_substitution_fails_closed() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("scope", "scope"), operation(1))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        let first = vault
            .create_secret(
                namespace,
                &metadata("first", "first"),
                ProtectedBytes::new(b"synthetic-first-value".to_vec()),
                operation(2),
            )
            .unwrap_or_else(|error| panic!("first synthetic secret must create: {error}"));
        let second = vault
            .create_secret(
                namespace,
                &metadata("second", "second"),
                ProtectedBytes::new(b"synthetic-second-value".to_vec()),
                operation(3),
            )
            .unwrap_or_else(|error| panic!("second synthetic secret must create: {error}"));
        let record = vault
            .store
            .encrypted_secret_version(first.secret_id, 1)
            .unwrap_or_else(|error| panic!("encrypted synthetic version must load: {error}"));

        let mut changed = super::clone_encrypted(&record);
        changed.nonce[0] ^= 1;
        assert_integrity(&vault, first.secret_id, 1, &changed);
        let mut changed = super::clone_encrypted(&record);
        changed.ciphertext[0] ^= 1;
        assert_integrity(&vault, first.secret_id, 1, &changed);
        let mut changed = super::clone_encrypted(&record);
        changed.dek_nonce[0] ^= 1;
        assert_integrity(&vault, first.secret_id, 1, &changed);
        let mut changed = super::clone_encrypted(&record);
        changed.wrapped_dek[0] ^= 1;
        assert_integrity(&vault, first.secret_id, 1, &changed);
        let mut changed = super::clone_encrypted(&record);
        changed.kek_version = 2;
        assert_integrity(&vault, first.secret_id, 1, &changed);
        assert_integrity(&vault, first.secret_id, 2, &record);
        assert_integrity(&vault, second.secret_id, 1, &record);
    }

    #[test]
    fn lifecycle_and_purge_require_revision_retention_and_explicit_capability() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("scope", "scope"), operation(1))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        let created = vault
            .create_secret(
                namespace,
                &metadata("lifecycle", "lifecycle"),
                ProtectedBytes::new(b"synthetic-lifecycle-value".to_vec()),
                operation(2),
            )
            .unwrap_or_else(|error| panic!("synthetic secret must create: {error}"));

        assert_eq!(
            vault
                .archive_secret(created.secret_id, 1, operation(3))
                .unwrap_or_else(|error| panic!("synthetic secret must archive: {error}")),
            2
        );
        assert!(matches!(
            vault.reveal_current_secret(created.secret_id, operation(4)),
            Err(VaultError::NotFound)
        ));
        assert_eq!(
            vault
                .restore_archived_secret(created.secret_id, 2, operation(5))
                .unwrap_or_else(|error| panic!("synthetic secret must restore: {error}")),
            3
        );
        assert_eq!(
            vault
                .delete_secret(created.secret_id, 3, operation(100))
                .unwrap_or_else(|error| panic!("synthetic secret must delete: {error}")),
            4
        );
        assert!(matches!(
            vault.purge_secret_after_owner_approval(
                created.secret_id,
                4,
                super::OwnerPurgeApproval {
                    retention_cutoff_unix_ms: 99,
                },
                operation(101),
            ),
            Err(VaultError::Conflict)
        ));
        vault
            .purge_secret_after_owner_approval(
                created.secret_id,
                4,
                super::OwnerPurgeApproval {
                    retention_cutoff_unix_ms: 100,
                },
                operation(102),
            )
            .unwrap_or_else(|error| panic!("retained synthetic secret must purge: {error}"));

        assert!(vault.store.secret(created.secret_id).is_err());
        assert!(
            vault
                .store
                .encrypted_secret_version(created.secret_id, 1)
                .is_err()
        );
        assert_eq!(
            vault
                .store
                .audit_head()
                .unwrap_or_else(|error| panic!("purge audit must remain: {error}"))
                .sequence,
            6
        );
    }

    #[test]
    fn offline_audit_modification_is_detected_after_restart() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        vault
            .create_namespace(None, &metadata("audit", "audit"), operation(1))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        assert!(vault.verify_audit_chain().is_ok());
        drop(vault);

        let connection = rusqlite::Connection::open(&database)
            .unwrap_or_else(|error| panic!("offline database must open: {error}"));
        connection
            .execute_batch(
                "DROP TRIGGER smcv_audit_events_protect_update;\
                 UPDATE smcv_audit_events SET action = 'secret:create' WHERE sequence = 1;",
            )
            .unwrap_or_else(|error| panic!("offline adversarial edit must apply: {error}"));
        drop(connection);

        let reopened =
            initialize_vault(&database, &root, 1_800_000_000_001).unwrap_or_else(|error| {
                panic!("modified vault must still unlock for diagnosis: {error}")
            });
        assert!(matches!(
            reopened.verify_audit_chain(),
            Err(VaultError::Integrity)
        ));
    }

    #[test]
    fn offline_current_version_and_lifecycle_rollback_fails_state_authentication() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("state", "state"), operation(1))
            .unwrap_or_else(|error| panic!("namespace must create: {error}"));
        let secret = vault
            .create_secret(
                namespace,
                &metadata("rollback", "rollback"),
                ProtectedBytes::new(b"version-one".to_vec()),
                operation(2),
            )
            .unwrap_or_else(|error| panic!("secret must create: {error}"));
        vault
            .update_secret(
                secret.secret_id,
                1,
                1,
                ProtectedBytes::new(b"version-two".to_vec()),
                operation(3),
            )
            .unwrap_or_else(|error| panic!("second version must append: {error}"));
        drop(vault);

        let connection = Connection::open(&database)
            .unwrap_or_else(|error| panic!("offline database must open: {error}"));
        connection
            .execute_batch(
                "DROP TRIGGER smcv_secrets_monotonic_versions;
                 UPDATE smcv_secrets
                    SET current_version = 1, revision = 1, lifecycle_state = 'archived';",
            )
            .unwrap_or_else(|error| panic!("synthetic state rollback must persist: {error}"));
        drop(connection);

        let reopened = initialize_vault(&database, &root, 4)
            .unwrap_or_else(|error| panic!("vault key state must still reopen: {error}"));
        assert!(matches!(
            reopened.reveal_current_secret(secret.secret_id, operation(5)),
            Err(VaultError::Integrity)
        ));
        assert!(matches!(
            reopened.read_secret_metadata(secret.secret_id),
            Err(VaultError::Integrity)
        ));
    }

    #[test]
    fn exact_lookup_is_nfc_case_sensitive_and_confirms_decrypted_metadata() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("scope", "scope"), operation(1))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        let created = vault
            .create_secret(
                namespace,
                &metadata("Caf\u{e9}", "protected description"),
                ProtectedBytes::new(b"synthetic-value".to_vec()),
                operation(2),
            )
            .unwrap_or_else(|error| panic!("synthetic secret must create: {error}"));

        let canonical_variant = ProtectedString::new(String::from("Cafe\u{301}"));
        assert_eq!(
            vault
                .find_secret_by_exact_name(namespace, &canonical_variant)
                .unwrap_or_else(|error| panic!("canonical name must resolve: {error}")),
            created.secret_id
        );
        assert!(matches!(
            vault.find_secret_by_exact_name(
                namespace,
                &ProtectedString::new(String::from("CAF\u{c9}"))
            ),
            Err(VaultError::NotFound)
        ));
        let decrypted = vault
            .read_secret_metadata(created.secret_id)
            .unwrap_or_else(|error| panic!("protected metadata must decrypt: {error}"));
        assert_eq!(decrypted.name.expose(), "Caf\u{e9}");
        assert_eq!(
            decrypted
                .description
                .as_ref()
                .unwrap_or_else(|| panic!("description must exist"))
                .expose(),
            "protected description"
        );
        assert!(!format!("{decrypted:?}").contains("protected description"));
    }

    fn assert_integrity(
        vault: &crate::InitializedVault,
        secret_id: smcv_core::SecretId,
        version: u64,
        encrypted: &smcv_storage::EncryptedRecord,
    ) {
        assert!(matches!(
            vault.decrypt_record(
                encrypted,
                smcv_crypto::ObjectKind::SecretVersion,
                smcv_crypto::ObjectKind::WrappedDataKey,
                smcv_core::ObjectId::from_uuid(secret_id.as_uuid()),
                version,
            ),
            Err(VaultError::Integrity)
        ));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
