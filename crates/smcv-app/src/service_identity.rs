use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use smcv_core::{
    Action, CredentialId, ObjectId, PrincipalId, ProtectedBytes, ProtectedString, RequestId,
    ResourceKind,
};
use smcv_crypto::{
    ObjectKind, TokenVerifier, issue_token, state_commitment, token_lookup_id, verify_token,
};
use smcv_storage::{
    ApplicationCredentialInsert, ApplicationCredentialRecord, ServiceIdentityInsert,
};

use crate::{
    AuthenticatedOwner, AuthenticationError, AuthorizationError, InitializedVault,
    RequestPrincipal, VaultOperationContext,
    authentication::{map_storage, principal_commitment, verify_principal_commitment},
};

const MAX_LABEL_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 2_048;

/// Protected display metadata for one workload identity.
pub struct ServiceIdentityMetadata {
    /// Owner-facing label encrypted at rest.
    pub label: ProtectedString,
    /// Optional owner-facing description encrypted at rest.
    pub description: Option<ProtectedString>,
}

impl core::fmt::Debug for ServiceIdentityMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ServiceIdentityMetadata([REDACTED])")
    }
}

/// Display-once application credential issued for one service identity.
pub struct IssuedApplicationCredential {
    /// Stable credential record reference.
    pub credential_id: CredentialId,
    /// Raw bearer credential shown exactly once.
    pub plaintext: ProtectedString,
    /// Optional enforced expiration.
    pub expires_at_unix_ms: Option<i64>,
}

/// Owner-visible application credential lifecycle metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationCredentialSummary {
    /// Stable credential record identifier; never the bearer value.
    pub credential_id: CredentialId,
    /// Creation timestamp.
    pub created_at_unix_ms: i64,
    /// Optional enforced expiration.
    pub expires_at_unix_ms: Option<i64>,
    /// Safe most-recent successful-use timestamp.
    pub last_used_at_unix_ms: Option<i64>,
    /// Revocation timestamp when inactive.
    pub revoked_at_unix_ms: Option<i64>,
    /// Optimistic lifecycle revision.
    pub revision: u64,
}

/// Owner-visible service identity inventory entry with protected metadata.
pub struct ServiceIdentitySummary {
    /// Stable workload identity.
    pub principal_id: PrincipalId,
    /// Decrypted owner-facing label and optional description.
    pub metadata: ServiceIdentityMetadata,
    /// Durable principal lifecycle state.
    pub state: String,
    /// Optimistic principal revision.
    pub revision: u64,
}

impl core::fmt::Debug for IssuedApplicationCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssuedApplicationCredential")
            .field("credential_id", &self.credential_id)
            .field("plaintext", &"[REDACTED]")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

/// Verified service authentication context consumed by authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedService {
    principal_id: PrincipalId,
    credential_id: CredentialId,
}

impl AuthenticatedService {
    /// Returns the authenticated service principal.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the exact application credential used for attribution.
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }
}

impl InitializedVault {
    /// Creates a service identity with encrypted owner-facing metadata.
    ///
    /// # Errors
    ///
    /// Returns rejected without recent owner authentication, invalid input for
    /// metadata bounds, and safe integrity/unavailable failures otherwise.
    pub fn create_service_identity(
        &self,
        owner: AuthenticatedOwner,
        metadata: &ServiceIdentityMetadata,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PrincipalId, AuthenticationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        if !owner.is_recent_at(now_unix_ms) {
            return Err(AuthenticationError::Rejected);
        }
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::IdentityManage,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let plaintext = encode_service_metadata(metadata)?;
        let principal_id = PrincipalId::random();
        let object_id = ObjectId::from_uuid(principal_id.as_uuid());
        let encrypted = self
            .encrypt_record(
                plaintext,
                ObjectKind::ServiceIdentityMetadata,
                ObjectKind::WrappedServiceIdentityMetadataKey,
                object_id,
                1,
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        let commitment = principal_commitment(self, principal_id, "service", "active", 1)?;
        let audit = self
            .build_audit(
                "identity:create",
                "principal",
                Some(object_id),
                VaultOperationContext {
                    request_id,
                    actor_principal_id: Some(owner.principal_id()),
                    credential_kind: Some("session"),
                    credential_id: Some(ObjectId::from_uuid(owner.session_id().as_uuid())),
                    now_unix_ms,
                },
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .create_service_identity(
                &ServiceIdentityInsert {
                    principal_id,
                    principal_state_commitment: commitment,
                    metadata: encrypted,
                    created_at_unix_ms: now_unix_ms,
                },
                &audit,
            )
            .map_err(map_storage)?;
        Ok(principal_id)
    }

    /// Opens protected service-identity display metadata for the owner UI.
    ///
    /// # Errors
    ///
    /// Returns rejected for non-owner callers and integrity/unavailable for an
    /// invalid protected envelope or committed service state.
    pub fn read_service_identity_metadata(
        &self,
        owner: AuthenticatedOwner,
        principal_id: PrincipalId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<ServiceIdentityMetadata, AuthenticationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::IdentityRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let record = self
            .store
            .service_identity(principal_id)
            .map_err(map_storage)?;
        verify_principal_commitment(self, &record.principal)?;
        let plaintext = self
            .decrypt_record(
                &record.metadata,
                ObjectKind::ServiceIdentityMetadata,
                ObjectKind::WrappedServiceIdentityMetadataKey,
                ObjectId::from_uuid(principal_id.as_uuid()),
                record.metadata_version,
            )
            .map_err(|_| AuthenticationError::Integrity)?;
        decode_service_metadata(&plaintext)
    }

    /// Lists a bounded stable page of protected service-identity metadata.
    ///
    /// # Errors
    ///
    /// Returns rejected for stale owner authority, invalid bounds, or any
    /// principal/envelope integrity failure.
    pub fn service_identities(
        &self,
        owner: AuthenticatedOwner,
        after_principal_id: Option<PrincipalId>,
        limit: u16,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<Vec<ServiceIdentitySummary>, AuthenticationError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthenticationError::InvalidInput);
        }
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::IdentityRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let records = self
            .store
            .service_identities_after(after_principal_id, limit)
            .map_err(map_storage)?;
        let mut summaries = Vec::with_capacity(records.len());
        for record in records {
            verify_principal_commitment(self, &record.principal)?;
            let plaintext = self
                .decrypt_record(
                    &record.metadata,
                    ObjectKind::ServiceIdentityMetadata,
                    ObjectKind::WrappedServiceIdentityMetadataKey,
                    ObjectId::from_uuid(record.principal.principal_id.as_uuid()),
                    record.metadata_version,
                )
                .map_err(|_| AuthenticationError::Integrity)?;
            summaries.push(ServiceIdentitySummary {
                principal_id: record.principal.principal_id,
                metadata: decode_service_metadata(&plaintext)?,
                state: record.principal.state,
                revision: record.principal.revision,
            });
        }
        Ok(summaries)
    }

    /// Issues a random display-once application credential after recent auth.
    ///
    /// # Errors
    ///
    /// Returns rejected without recent authentication or for inactive service
    /// state and unavailable/integrity for verifier persistence failures.
    pub fn issue_application_credential(
        &self,
        owner: AuthenticatedOwner,
        service_principal_id: PrincipalId,
        expires_at_unix_ms: Option<i64>,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<IssuedApplicationCredential, AuthenticationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        if !owner.is_recent_at(now_unix_ms)
            || expires_at_unix_ms.is_some_and(|expiry| expiry <= now_unix_ms)
        {
            return Err(AuthenticationError::Rejected);
        }
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::CredentialIssue,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let principal = self
            .store
            .principal(service_principal_id)
            .map_err(map_storage)?;
        verify_principal_commitment(self, &principal)?;
        if principal.kind != smcv_storage::PrincipalKind::Service || principal.state != "active" {
            return Err(AuthenticationError::Rejected);
        }
        let issued =
            issue_token(self.token_verifier_key()).map_err(|_| AuthenticationError::Unavailable)?;
        let lookup: [u8; 12] = URL_SAFE_NO_PAD
            .decode(&issued.lookup_id)
            .map_err(|_| AuthenticationError::Integrity)?
            .try_into()
            .map_err(|_| AuthenticationError::Integrity)?;
        let credential_id = CredentialId::random();
        let verifier = *issued.verifier.as_bytes();
        let commitment = application_credential_commitment(
            self,
            credential_id,
            service_principal_id,
            &lookup,
            &verifier,
            now_unix_ms,
            expires_at_unix_ms,
            None,
            None,
            1,
        )?;
        let audit = self
            .build_audit(
                "credential:issue",
                "credential",
                Some(ObjectId::from_uuid(credential_id.as_uuid())),
                VaultOperationContext {
                    request_id,
                    actor_principal_id: Some(owner.principal_id()),
                    credential_kind: Some("session"),
                    credential_id: Some(ObjectId::from_uuid(owner.session_id().as_uuid())),
                    now_unix_ms,
                },
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .create_application_credential(
                &ApplicationCredentialInsert {
                    credential_id,
                    principal_id: service_principal_id,
                    lookup_id: lookup,
                    verifier,
                    created_at_unix_ms: now_unix_ms,
                    expires_at_unix_ms,
                    state_commitment: commitment,
                },
                &audit,
            )
            .map_err(map_storage)?;
        Ok(IssuedApplicationCredential {
            credential_id,
            plaintext: issued.plaintext,
            expires_at_unix_ms,
        })
    }

    /// Lists bounded non-secret application credential lifecycle metadata.
    ///
    /// # Errors
    ///
    /// Returns rejected for stale owner or cursor context and fails closed on
    /// credential commitment or durable-state integrity errors.
    pub fn application_credentials(
        &self,
        owner: AuthenticatedOwner,
        service_principal_id: PrincipalId,
        after_credential_id: Option<CredentialId>,
        limit: u16,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<Vec<ApplicationCredentialSummary>, AuthenticationError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthenticationError::InvalidInput);
        }
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::IdentityRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let after = after_credential_id
            .map(|credential_id| {
                let record = self.store.application_credential(credential_id)?;
                if record.principal_id != service_principal_id {
                    return Err(smcv_storage::StorageError::NotInitialized);
                }
                verify_application_credential_commitment(self, &record)
                    .map_err(|_| smcv_storage::StorageError::InvalidData)?;
                Ok((record.created_at_unix_ms, credential_id))
            })
            .transpose()
            .map_err(map_storage)?;
        let records = self
            .store
            .application_credentials_after(service_principal_id, after, limit)
            .map_err(map_storage)?;
        let mut summaries = Vec::with_capacity(records.len());
        for record in records {
            verify_application_credential_commitment(self, &record)?;
            summaries.push(ApplicationCredentialSummary {
                credential_id: record.credential_id,
                created_at_unix_ms: record.created_at_unix_ms,
                expires_at_unix_ms: record.expires_at_unix_ms,
                last_used_at_unix_ms: record.last_used_at_unix_ms,
                revoked_at_unix_ms: record.revoked_at_unix_ms,
                revision: record.revision,
            });
        }
        Ok(summaries)
    }

    /// Verifies a bearer credential and rechecks revocation at its use update.
    ///
    /// # Errors
    ///
    /// Returns one rejected category for malformed, unknown, expired, revoked,
    /// raced, or disabled credentials.
    pub fn authenticate_application_credential(
        &self,
        presented: &ProtectedString,
        now_unix_ms: i64,
    ) -> Result<AuthenticatedService, AuthenticationError> {
        let lookup = token_lookup_id(presented.expose()).ok_or(AuthenticationError::Rejected)?;
        let candidate = self
            .store
            .application_credential_by_lookup(&lookup)
            .map_err(map_storage)?;
        let expected_lookup = URL_SAFE_NO_PAD.encode(lookup);
        let expected =
            TokenVerifier::from_bytes(candidate.as_ref().map_or([0; 32], |record| record.verifier));
        let matches = verify_token(
            self.token_verifier_key(),
            presented.expose(),
            &expected_lookup,
            &expected,
        )
        .map_err(|_| AuthenticationError::Unavailable)?;
        let record = candidate.ok_or(AuthenticationError::Rejected)?;
        verify_application_credential_commitment(self, &record)?;
        if !matches
            || record.revoked_at_unix_ms.is_some()
            || record
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry < now_unix_ms)
        {
            return Err(AuthenticationError::Rejected);
        }
        let principal = self
            .store
            .principal(record.principal_id)
            .map_err(map_storage)?;
        verify_principal_commitment(self, &principal)?;
        if principal.state != "active" || principal.kind != smcv_storage::PrincipalKind::Service {
            return Err(AuthenticationError::Rejected);
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(AuthenticationError::Rejected)?;
        let next_commitment = application_credential_commitment(
            self,
            record.credential_id,
            record.principal_id,
            &record.lookup_id,
            &record.verifier,
            record.created_at_unix_ms,
            record.expires_at_unix_ms,
            Some(now_unix_ms),
            None,
            next_revision,
        )?;
        self.store
            .mark_application_credential_used(
                record.credential_id,
                record.revision,
                now_unix_ms,
                &next_commitment,
            )
            .map_err(|_| AuthenticationError::Rejected)?;
        Ok(AuthenticatedService {
            principal_id: record.principal_id,
            credential_id: record.credential_id,
        })
    }

    /// Revokes one application credential effective on its next checked use.
    ///
    /// # Errors
    ///
    /// Returns rejected without recent owner authentication or on a stale
    /// revision and integrity/unavailable for protected-state failure.
    pub fn revoke_application_credential(
        &self,
        owner: AuthenticatedOwner,
        credential_id: CredentialId,
        expected_revision: u64,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<u64, AuthenticationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)?;
        if !owner.is_recent_at(now_unix_ms) {
            return Err(AuthenticationError::Rejected);
        }
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::CredentialRevoke,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )
        .map_err(map_authorization)?;
        let record = self
            .store
            .application_credential(credential_id)
            .map_err(map_storage)?;
        verify_application_credential_commitment(self, &record)?;
        if record.revision != expected_revision || record.revoked_at_unix_ms.is_some() {
            return Err(AuthenticationError::Rejected);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(AuthenticationError::Rejected)?;
        let next_commitment = application_credential_commitment(
            self,
            record.credential_id,
            record.principal_id,
            &record.lookup_id,
            &record.verifier,
            record.created_at_unix_ms,
            record.expires_at_unix_ms,
            record.last_used_at_unix_ms,
            Some(now_unix_ms),
            next_revision,
        )?;
        let audit = self
            .build_audit(
                "credential:revoke",
                "credential",
                Some(ObjectId::from_uuid(credential_id.as_uuid())),
                VaultOperationContext {
                    request_id,
                    actor_principal_id: Some(owner.principal_id()),
                    credential_kind: Some("session"),
                    credential_id: Some(ObjectId::from_uuid(owner.session_id().as_uuid())),
                    now_unix_ms,
                },
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .revoke_application_credential(
                credential_id,
                expected_revision,
                now_unix_ms,
                &next_commitment,
                &audit,
            )
            .map_err(map_storage)
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "this mapper is passed directly to Result::map_err"
)]
fn map_authorization(error: AuthorizationError) -> AuthenticationError {
    match error {
        AuthorizationError::Denied | AuthorizationError::RecentAuthenticationRequired => {
            AuthenticationError::Rejected
        }
        AuthorizationError::InvalidInput => AuthenticationError::InvalidInput,
        AuthorizationError::Integrity => AuthenticationError::Integrity,
        AuthorizationError::Unavailable => AuthenticationError::Unavailable,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the commitment authenticates each persisted credential field explicitly"
)]
pub(crate) fn application_credential_commitment(
    vault: &InitializedVault,
    credential_id: CredentialId,
    principal_id: PrincipalId,
    lookup_id: &[u8; 12],
    verifier: &[u8; 32],
    created_at_unix_ms: i64,
    expires_at_unix_ms: Option<i64>,
    last_used_at_unix_ms: Option<i64>,
    revoked_at_unix_ms: Option<i64>,
    revision: u64,
) -> Result<[u8; 32], AuthenticationError> {
    let canonical = format!(
        "application-credential\0{credential_id}\0{principal_id}\0{}\0{}\0{created_at_unix_ms}\0{expires_at_unix_ms:?}\0{last_used_at_unix_ms:?}\0{revoked_at_unix_ms:?}\0{revision}",
        hex::encode(lookup_id),
        hex::encode(verifier),
    );
    state_commitment(vault.audit_key(), canonical.as_bytes())
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthenticationError::Integrity)
}

pub(crate) fn verify_application_credential_commitment(
    vault: &InitializedVault,
    record: &ApplicationCredentialRecord,
) -> Result<(), AuthenticationError> {
    if application_credential_commitment(
        vault,
        record.credential_id,
        record.principal_id,
        &record.lookup_id,
        &record.verifier,
        record.created_at_unix_ms,
        record.expires_at_unix_ms,
        record.last_used_at_unix_ms,
        record.revoked_at_unix_ms,
        record.revision,
    )? != record.state_commitment
    {
        return Err(AuthenticationError::Integrity);
    }
    Ok(())
}

pub(crate) fn verify_service_context_active(
    vault: &InitializedVault,
    service: AuthenticatedService,
    now_unix_ms: i64,
) -> Result<(), AuthenticationError> {
    let record = vault
        .store
        .application_credential(service.credential_id())
        .map_err(map_storage)?;
    verify_application_credential_commitment(vault, &record)?;
    if record.principal_id != service.principal_id()
        || record.revoked_at_unix_ms.is_some()
        || record
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry < now_unix_ms)
    {
        return Err(AuthenticationError::Rejected);
    }
    let principal = vault
        .store
        .principal(record.principal_id)
        .map_err(map_storage)?;
    verify_principal_commitment(vault, &principal)?;
    if principal.state != "active" {
        return Err(AuthenticationError::Rejected);
    }
    Ok(())
}

fn encode_service_metadata(
    metadata: &ServiceIdentityMetadata,
) -> Result<ProtectedBytes, AuthenticationError> {
    let label = metadata.label.expose().as_bytes();
    let description = metadata
        .description
        .as_ref()
        .map(|value| value.expose().as_bytes());
    if label.is_empty()
        || label.len() > MAX_LABEL_BYTES
        || description.is_some_and(|value| value.len() > MAX_DESCRIPTION_BYTES)
    {
        return Err(AuthenticationError::InvalidInput);
    }
    let mut encoded = Vec::with_capacity(
        8_usize
            .saturating_add(label.len())
            .saturating_add(description.map_or(0, <[u8]>::len)),
    );
    encoded.extend_from_slice(b"SMCVSI01");
    append_field(&mut encoded, label)?;
    append_field(&mut encoded, description.unwrap_or_default())?;
    Ok(ProtectedBytes::new(encoded))
}

fn decode_service_metadata(
    plaintext: &ProtectedBytes,
) -> Result<ServiceIdentityMetadata, AuthenticationError> {
    let bytes = plaintext.expose();
    if !bytes.starts_with(b"SMCVSI01") {
        return Err(AuthenticationError::Integrity);
    }
    let mut offset = 8;
    let label = read_field(bytes, &mut offset)?;
    let description = read_field(bytes, &mut offset)?;
    if offset != bytes.len() || label.is_empty() {
        return Err(AuthenticationError::Integrity);
    }
    let label = String::from_utf8(label.to_vec()).map_err(|_| AuthenticationError::Integrity)?;
    let description = if description.is_empty() {
        None
    } else {
        Some(ProtectedString::new(
            String::from_utf8(description.to_vec()).map_err(|_| AuthenticationError::Integrity)?,
        ))
    };
    Ok(ServiceIdentityMetadata {
        label: ProtectedString::new(label),
        description,
    })
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), AuthenticationError> {
    let length = u16::try_from(field.len()).map_err(|_| AuthenticationError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn read_field<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], AuthenticationError> {
    let length_bytes = input
        .get(*offset..offset.saturating_add(2))
        .ok_or(AuthenticationError::Integrity)?;
    let length = usize::from(u16::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| AuthenticationError::Integrity)?,
    ));
    *offset = offset.saturating_add(2);
    let value = input
        .get(*offset..offset.saturating_add(length))
        .ok_or(AuthenticationError::Integrity)?;
    *offset = offset.saturating_add(length);
    Ok(value)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, mpsc},
        time::Duration,
    };

    use smcv_core::{ProtectedString, RequestId};
    use tempfile::TempDir;

    use crate::{
        LocalSetupCapability, RequestPrincipal, ServiceIdentityMetadata, initialize_vault,
    };

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "end-to-end credential lifecycle and revocation-race fixture"
    )]
    fn display_once_service_credential_authenticates_and_revokes_immediately() {
        let root = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic directory must create: {error}"));
        let database_directory = root.path().join("database");
        let key_directory = root.path().join("key");
        fs::create_dir_all(&database_directory)
            .unwrap_or_else(|error| panic!("database directory must create: {error}"));
        fs::create_dir_all(&key_directory)
            .unwrap_or_else(|error| panic!("key directory must create: {error}"));
        fs::set_permissions(&database_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("database directory must restrict: {error}"));
        fs::set_permissions(&key_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("key directory must restrict: {error}"));
        let vault = Arc::new(
            initialize_vault(
                &database_directory.join("vault.sqlite"),
                &key_directory.join("root.key"),
                1_800_000_000_000,
            )
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}")),
        );
        let password = ProtectedString::new(String::from("synthetic long password"));
        vault
            .enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &password,
                RequestId::random(),
                1_800_000_001_000,
            )
            .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let session = vault
            .login_with_password(&password, RequestId::random(), 1_800_000_002_000)
            .unwrap_or_else(|error| panic!("synthetic owner must login: {error}"));
        let owner = vault
            .authenticate_browser_session(
                &session.session_token,
                Some(&session.csrf_token),
                true,
                1_800_000_003_000,
            )
            .unwrap_or_else(|error| panic!("synthetic session must authenticate: {error}"));
        let service_id = vault
            .create_service_identity(
                owner,
                &ServiceIdentityMetadata {
                    label: ProtectedString::new(String::from("synthetic workload")),
                    description: None,
                },
                RequestId::random(),
                1_800_000_004_000,
            )
            .unwrap_or_else(|error| panic!("synthetic service must create: {error}"));
        let inventory = vault
            .service_identities(owner, None, 100, RequestId::random(), 1_800_000_003_500)
            .unwrap_or_else(|error| panic!("service inventory must read: {error}"));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].principal_id, service_id);
        assert_eq!(inventory[0].metadata.label.expose(), "synthetic workload");
        let owner = vault
            .authenticate_browser_session(
                &session.session_token,
                Some(&session.csrf_token),
                true,
                1_800_000_005_000,
            )
            .unwrap_or_else(|error| panic!("synthetic session must reauthenticate: {error}"));
        let issued = vault
            .issue_application_credential(
                owner,
                service_id,
                Some(1_900_000_000_000),
                RequestId::random(),
                1_800_000_006_000,
            )
            .unwrap_or_else(|error| panic!("synthetic credential must issue: {error}"));
        let authenticated = vault
            .authenticate_application_credential(&issued.plaintext, 1_800_000_007_000)
            .unwrap_or_else(|error| panic!("synthetic credential must authenticate: {error}"));
        assert_eq!(authenticated.principal_id(), service_id);
        assert!(!format!("{issued:?}").contains(issued.plaintext.expose()));

        let owner = vault
            .authenticate_browser_session(
                &session.session_token,
                Some(&session.csrf_token),
                true,
                1_800_000_008_000,
            )
            .unwrap_or_else(|error| panic!("synthetic session must remain active: {error}"));
        let credential_page = vault
            .application_credentials(
                owner,
                service_id,
                None,
                100,
                RequestId::random(),
                1_800_000_008_100,
            )
            .unwrap_or_else(|error| panic!("credential metadata must list: {error}"));
        assert_eq!(credential_page.len(), 1);
        assert_eq!(credential_page[0].credential_id, issued.credential_id);
        assert_eq!(
            credential_page[0].last_used_at_unix_ms,
            Some(1_800_000_007_000)
        );
        assert_eq!(credential_page[0].revision, 2);
        let guarded_request = vault
            .authorized(
                RequestPrincipal::Service(authenticated),
                RequestId::random(),
                1_800_000_008_500,
            )
            .unwrap_or_else(|error| panic!("request must authorize before revoke: {error}"));
        let (started_sender, started_receiver) = mpsc::channel();
        let (result_sender, result_receiver) = mpsc::channel();
        let revoking_vault = Arc::clone(&vault);
        let credential_id = issued.credential_id;
        let revoker = std::thread::spawn(move || {
            started_sender
                .send(())
                .unwrap_or_else(|error| panic!("start signal must send: {error}"));
            let result = revoking_vault.revoke_application_credential(
                owner,
                credential_id,
                2,
                RequestId::random(),
                1_800_000_009_000,
            );
            result_sender
                .send(result)
                .unwrap_or_else(|error| panic!("revoke result must send: {error}"));
        });
        started_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("revoker must start: {error}"));
        assert!(
            result_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(guarded_request);
        result_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("revoker must finish: {error}"))
            .unwrap_or_else(|error| panic!("synthetic credential must revoke: {error}"));
        revoker
            .join()
            .unwrap_or_else(|_| panic!("revoker must not panic"));
        assert!(
            vault
                .authenticate_application_credential(&issued.plaintext, 1_800_000_010_000)
                .is_err()
        );
        assert!(
            vault
                .authorized(
                    RequestPrincipal::Service(authenticated),
                    RequestId::random(),
                    1_800_000_010_000,
                )
                .is_err()
        );
        drop(vault);
        let restarted = initialize_vault(
            &database_directory.join("vault.sqlite"),
            &key_directory.join("root.key"),
            1_800_000_011_000,
        )
        .unwrap_or_else(|error| panic!("revoked vault must restart: {error}"));
        assert!(
            restarted
                .authenticate_application_credential(&issued.plaintext, 1_800_000_011_001)
                .is_err()
        );
        for entry in fs::read_dir(&database_directory)
            .unwrap_or_else(|error| panic!("database artifacts must list: {error}"))
        {
            let path = entry
                .unwrap_or_else(|error| panic!("database artifact must resolve: {error}"))
                .path();
            if path.is_file() {
                let bytes = fs::read(&path)
                    .unwrap_or_else(|error| panic!("database artifact must read: {error}"));
                assert!(
                    !bytes
                        .windows(issued.plaintext.expose().len())
                        .any(|window| { window == issued.plaintext.expose().as_bytes() })
                );
                assert!(
                    !bytes
                        .windows(password.expose().len())
                        .any(|window| { window == password.expose().as_bytes() })
                );
            }
        }
    }
}
