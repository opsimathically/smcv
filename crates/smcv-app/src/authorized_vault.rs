use smcv_core::{
    Action, NamespaceId, ObjectId, ProtectedBytes, ProtectedString, RequestId, ResourceKind,
    SecretId, SecretSchedule,
};
use smcv_crypto::idempotency_verifiers;
use std::sync::RwLockReadGuard;
use thiserror::Error;

use crate::{
    AuditVerification, AuthorizationError, DecryptedMetadata, DueSecret, InitializedVault,
    MetadataInput, NamespaceListItem, OwnerPurgeApproval, RequestPrincipal, SecretCreated,
    SecretListItem, SecretVersionSummary, VaultError, VaultOperationContext,
};

/// Per-request vault facade that cannot be constructed without authentication.
pub struct AuthorizedVault<'a> {
    vault: &'a InitializedVault,
    principal: RequestPrincipal,
    request_id: RequestId,
    now_unix_ms: i64,
    _authorization_guard: RwLockReadGuard<'a, ()>,
}

/// Protected principal-scoped idempotency input for retryable creates.
pub struct IdempotencyInput {
    /// Raw client key, stored only through a keyed verifier.
    pub key: ProtectedString,
    /// Canonical protected request bytes, stored only through a keyed digest.
    pub canonical_request: ProtectedBytes,
}

impl core::fmt::Debug for IdempotencyInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("IdempotencyInput([REDACTED])")
    }
}

/// Combined safe authorization/domain failure from the protected facade.
#[derive(Debug, Error)]
pub enum AuthorizedVaultError {
    /// Authentication succeeded but current policy does not allow the action.
    #[error("resource is unavailable")]
    Authorization(#[source] AuthorizationError),
    /// The authorized vault operation failed safely.
    #[error("vault operation failed")]
    Vault(#[source] VaultError),
}

impl From<AuthorizationError> for AuthorizedVaultError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}

impl From<VaultError> for AuthorizedVaultError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl InitializedVault {
    /// Creates the only public entry point to protected vault operations.
    ///
    /// # Errors
    ///
    /// Returns denied if the session/credential changed after authentication,
    /// and unavailable if the process authorization gate was poisoned.
    pub fn authorized(
        &self,
        principal: RequestPrincipal,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<AuthorizedVault<'_>, AuthorizationError> {
        let guard = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        match principal {
            RequestPrincipal::Owner(owner) => {
                crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
                    .map_err(|_| AuthorizationError::Denied)?;
            }
            RequestPrincipal::Service(service) => {
                crate::service_identity::verify_service_context_active(self, service, now_unix_ms)
                    .map_err(|_| AuthorizationError::Denied)?;
            }
        }
        Ok(AuthorizedVault {
            vault: self,
            principal,
            request_id,
            now_unix_ms,
            _authorization_guard: guard,
        })
    }
}

impl AuthorizedVault<'_> {
    /// Lists a bounded page of child namespaces after independent list access.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn list_namespaces(
        &self,
        parent_namespace_id: Option<NamespaceId>,
        after_namespace_id: Option<NamespaceId>,
        limit: u16,
    ) -> Result<Vec<NamespaceListItem>, AuthorizedVaultError> {
        let target = parent_namespace_id.map_or_else(
            || ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
            |id| ObjectId::from_uuid(id.as_uuid()),
        );
        self.authorize(Action::NamespaceList, ResourceKind::Namespace, target)?;
        self.vault
            .list_namespaces(parent_namespace_id, after_namespace_id, limit)
            .map_err(Into::into)
    }

    /// Lists a bounded metadata-only secret page after independent list access.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn list_secrets(
        &self,
        namespace_id: NamespaceId,
        after_secret_id: Option<SecretId>,
        limit: u16,
    ) -> Result<Vec<SecretListItem>, AuthorizedVaultError> {
        self.authorize(
            Action::SecretList,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
        )?;
        self.vault
            .list_secrets(namespace_id, after_secret_id, limit)
            .map_err(Into::into)
    }

    /// Lists archived or deleted secrets for owner lifecycle administration.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn list_secrets_in_lifecycle(
        &self,
        namespace_id: NamespaceId,
        lifecycle_state: &str,
        after_secret_id: Option<SecretId>,
        limit: u16,
    ) -> Result<Vec<SecretListItem>, AuthorizedVaultError> {
        self.authorize(
            Action::SecretList,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
        )?;
        if !matches!(self.principal, RequestPrincipal::Owner(_)) {
            return Err(AuthorizationError::Denied.into());
        }
        self.vault
            .list_secrets_in_lifecycle(namespace_id, lifecycle_state, after_secret_id, limit)
            .map_err(Into::into)
    }

    /// Creates a namespace after owner-only centralized authorization.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn create_namespace(
        &self,
        parent_namespace_id: Option<NamespaceId>,
        metadata: &MetadataInput,
    ) -> Result<NamespaceId, AuthorizedVaultError> {
        let target = parent_namespace_id.map_or_else(
            || ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
            |id| ObjectId::from_uuid(id.as_uuid()),
        );
        self.authorize(Action::NamespaceCreate, ResourceKind::Namespace, target)?;
        self.vault
            .create_namespace(parent_namespace_id, metadata, self.operation())
            .map_err(Into::into)
    }

    /// Retry-safely creates one namespace under a durable idempotency key.
    ///
    /// # Errors
    /// Returns conflict for key reuse with different input and otherwise the
    /// same safe errors as ordinary namespace creation.
    pub fn create_namespace_idempotent(
        &self,
        parent_namespace_id: Option<NamespaceId>,
        metadata: &MetadataInput,
        idempotency: &IdempotencyInput,
    ) -> Result<NamespaceId, AuthorizedVaultError> {
        let target = parent_namespace_id.map_or_else(
            || ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
            |id| ObjectId::from_uuid(id.as_uuid()),
        );
        self.authorize(Action::NamespaceCreate, ResourceKind::Namespace, target)?;
        let reserved = self.reserve_idempotency(idempotency, "namespace")?;
        let namespace_id = NamespaceId::from_uuid(reserved.response_id.as_uuid());
        if reserved.reused && self.vault.store.namespace(namespace_id).is_ok() {
            return Ok(namespace_id);
        }
        match self.vault.create_namespace_with_id(
            namespace_id,
            parent_namespace_id,
            metadata,
            self.operation(),
        ) {
            Ok(id) => Ok(id),
            Err(VaultError::Conflict)
                if reserved.reused && self.vault.store.namespace(namespace_id).is_ok() =>
            {
                Ok(namespace_id)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Creates an encrypted secret in an authorized namespace.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn create_secret(
        &self,
        namespace_id: NamespaceId,
        metadata: &MetadataInput,
        value: ProtectedBytes,
        schedule: SecretSchedule,
    ) -> Result<SecretCreated, AuthorizedVaultError> {
        self.authorize(
            Action::SecretCreate,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
        )?;
        self.vault
            .create_secret_with_schedule(namespace_id, metadata, value, schedule, self.operation())
            .map_err(Into::into)
    }

    /// Retry-safely creates one secret under a durable idempotency key.
    ///
    /// # Errors
    /// Returns conflict for key reuse with different input and otherwise the
    /// same safe errors as ordinary secret creation.
    pub fn create_secret_idempotent(
        &self,
        namespace_id: NamespaceId,
        metadata: &MetadataInput,
        value: ProtectedBytes,
        schedule: SecretSchedule,
        idempotency: &IdempotencyInput,
    ) -> Result<SecretCreated, AuthorizedVaultError> {
        self.authorize(
            Action::SecretCreate,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
        )?;
        let reserved = self.reserve_idempotency(idempotency, "secret")?;
        let secret_id = SecretId::from_uuid(reserved.response_id.as_uuid());
        if reserved.reused && self.vault.store.secret(secret_id).is_ok() {
            return Ok(SecretCreated {
                secret_id,
                version: 1,
                revision: 1,
            });
        }
        match self.vault.create_secret_with_id_and_schedule(
            secret_id,
            namespace_id,
            metadata,
            value,
            schedule,
            self.operation(),
        ) {
            Ok(created) => Ok(created),
            Err(VaultError::Conflict)
                if reserved.reused && self.vault.store.secret(secret_id).is_ok() =>
            {
                Ok(SecretCreated {
                    secret_id,
                    version: 1,
                    revision: 1,
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Appends an immutable secret version under explicit preconditions.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn update_secret(
        &self,
        secret_id: SecretId,
        expected_current_version: u64,
        expected_revision: u64,
        value: ProtectedBytes,
        schedule: SecretSchedule,
    ) -> Result<u64, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretUpdate, secret_id)?;
        self.vault
            .update_secret_with_schedule(
                secret_id,
                expected_current_version,
                expected_revision,
                value,
                schedule,
                self.operation(),
            )
            .map_err(Into::into)
    }

    /// Reveals and audits the current value only after value-read permission.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn reveal_current_secret(
        &self,
        secret_id: SecretId,
    ) -> Result<ProtectedBytes, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretValueRead, secret_id)?;
        self.vault
            .reveal_current_secret(secret_id, self.operation())
            .map_err(Into::into)
    }

    /// Lists a bounded immutable version-history page.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn secret_version_history(
        &self,
        secret_id: SecretId,
        after_version: u64,
        limit: u16,
    ) -> Result<Vec<SecretVersionSummary>, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretHistoryRead, secret_id)?;
        self.vault
            .secret_version_history(secret_id, after_version, limit)
            .map_err(Into::into)
    }

    /// Reveals one exact immutable version after its distinct permission.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn reveal_secret_version(
        &self,
        secret_id: SecretId,
        version: u64,
    ) -> Result<ProtectedBytes, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretVersionRead, secret_id)?;
        self.vault
            .reveal_secret_version(secret_id, version, self.operation())
            .map_err(Into::into)
    }

    /// Reads protected metadata only after the distinct metadata permission.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn read_secret_metadata(
        &self,
        secret_id: SecretId,
    ) -> Result<DecryptedMetadata, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretMetadataRead, secret_id)?;
        self.vault
            .read_secret_metadata(secret_id)
            .map_err(Into::into)
    }

    /// Resolves one exact protected name only with namespace listing access.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn find_secret_by_exact_name(
        &self,
        namespace_id: NamespaceId,
        name: &ProtectedString,
    ) -> Result<SecretId, AuthorizedVaultError> {
        self.authorize(
            Action::SecretList,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
        )?;
        self.vault
            .find_secret_by_exact_name(namespace_id, name)
            .map_err(Into::into)
    }

    /// Archives a secret under optimistic concurrency.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn archive_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
    ) -> Result<u64, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretArchive, secret_id)?;
        self.vault
            .archive_secret(secret_id, expected_revision, self.operation())
            .map_err(Into::into)
    }

    /// Restores an archived secret under optimistic concurrency.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn restore_archived_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
    ) -> Result<u64, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretRestore, secret_id)?;
        self.vault
            .restore_archived_secret(secret_id, expected_revision, self.operation())
            .map_err(Into::into)
    }

    /// Owner-only tombstones a secret while retaining encrypted history.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn delete_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
    ) -> Result<u64, AuthorizedVaultError> {
        self.authorize_secret(Action::SecretPurge, secret_id)?;
        self.vault
            .delete_secret(secret_id, expected_revision, self.operation())
            .map_err(Into::into)
    }

    /// Owner-only purges ciphertext after retention and confirmation.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn purge_secret(
        &self,
        secret_id: SecretId,
        expected_revision: u64,
        retention_cutoff_unix_ms: i64,
    ) -> Result<(), AuthorizedVaultError> {
        self.authorize_secret(Action::SecretPurge, secret_id)?;
        self.vault
            .purge_secret_after_owner_approval(
                secret_id,
                expected_revision,
                OwnerPurgeApproval::authorized(retention_cutoff_unix_ms),
                self.operation(),
            )
            .map_err(Into::into)
    }

    /// Returns bounded owner due-work after administration authorization.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn secrets_due(&self, limit: u16) -> Result<Vec<DueSecret>, AuthorizedVaultError> {
        self.authorize(
            Action::VaultConfigure,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
        )?;
        self.vault
            .secrets_due(self.now_unix_ms, limit)
            .map_err(Into::into)
    }

    /// Verifies the audit chain after owner-only audit access.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe domain error.
    pub fn verify_audit_chain(&self) -> Result<AuditVerification, AuthorizedVaultError> {
        self.authorize(
            Action::AuditRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
        )?;
        self.vault.verify_audit_chain().map_err(Into::into)
    }

    /// Reads one bounded audit page after owner-only audit authorization.
    ///
    /// # Errors
    /// Returns a uniform authorization or safe storage error.
    pub fn audit_events(
        &self,
        after_sequence: u64,
        limit: u16,
    ) -> Result<Vec<smcv_storage::StoredAuditRecord>, AuthorizedVaultError> {
        self.authorize(
            Action::AuditRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
        )?;
        self.vault
            .store
            .audit_records_after(after_sequence, limit)
            .map_err(|error| match error {
                smcv_storage::StorageError::InvalidData => VaultError::Integrity,
                smcv_storage::StorageError::Conflict => VaultError::InvalidInput,
                _ => VaultError::Unavailable,
            })
            .map_err(Into::into)
    }

    /// Confirms current owner authorization for creating a portable backup.
    ///
    /// # Errors
    /// Returns a uniform authorization error when recent owner authority is
    /// absent or changed before the decision point.
    pub fn authorize_backup_create(&self) -> Result<(), AuthorizedVaultError> {
        self.authorize(
            Action::BackupCreate,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
        )
    }

    /// Confirms current owner authorization for inspecting or downloading a
    /// generated backup artifact.
    ///
    /// # Errors
    /// Returns a uniform authorization error when owner authority is absent.
    pub fn authorize_backup_inspect(&self) -> Result<(), AuthorizedVaultError> {
        self.authorize(
            Action::BackupInspect,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault.vault_id.as_uuid()),
        )
    }

    fn authorize_secret(
        &self,
        action: Action,
        secret_id: SecretId,
    ) -> Result<(), AuthorizedVaultError> {
        self.authorize(
            action,
            ResourceKind::Secret,
            ObjectId::from_uuid(secret_id.as_uuid()),
        )
    }

    fn authorize(
        &self,
        action: Action,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
    ) -> Result<(), AuthorizedVaultError> {
        self.vault
            .authorize(
                self.principal,
                action,
                resource_kind,
                resource_id,
                self.request_id,
                self.now_unix_ms,
            )
            .map_err(Into::into)
    }

    fn reserve_idempotency(
        &self,
        input: &IdempotencyInput,
        response_kind: &str,
    ) -> Result<smcv_storage::IdempotencyReservation, AuthorizedVaultError> {
        let (key_verifier, request_fingerprint) = idempotency_verifiers(
            self.vault.token_verifier_key(),
            &input.key,
            &input.canonical_request,
        )
        .map_err(|_| VaultError::InvalidInput)?;
        let expires_at = self
            .now_unix_ms
            .checked_add(24 * 60 * 60 * 1_000)
            .ok_or(VaultError::InvalidInput)?;
        self.vault
            .store
            .reserve_idempotency(
                self.principal.principal_id(),
                &key_verifier,
                &request_fingerprint,
                response_kind,
                ObjectId::random(),
                self.now_unix_ms,
                expires_at,
            )
            .map_err(|error| match error {
                smcv_storage::StorageError::Conflict => VaultError::Conflict,
                smcv_storage::StorageError::InvalidData => VaultError::Integrity,
                _ => VaultError::Unavailable,
            })
            .map_err(Into::into)
    }

    const fn operation(&self) -> VaultOperationContext {
        let (credential_kind, credential_id) = self.principal.credential_attribution();
        VaultOperationContext {
            request_id: self.request_id,
            actor_principal_id: Some(self.principal.principal_id()),
            credential_kind: Some(credential_kind),
            credential_id: Some(credential_id),
            now_unix_ms: self.now_unix_ms,
        }
    }
}
