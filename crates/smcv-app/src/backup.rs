use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use smcv_backup::{
    ArchiveError, ArchiveKey, ArchiveMetadata, ArchiveOptions, ArchiveSummary, PublicHeader,
    VerifiedArchive, decode_archive, parse_public_header, verify_archive, write_archive,
};
use smcv_core::{
    Action, AuditEventId, AuthenticatorId, CredentialId, GrantId, InstallationId, NamespaceId,
    ObjectId, PolicyId, PrincipalId, ProtectedBytes, RequestId, ResourceKind, SecretId,
    SecretSchedule, VaultId,
};
use smcv_crypto::{KeyMaterial, ObjectKind};
use smcv_storage::{
    AuthenticatorKind, AuthorizationState, EncryptedRecord, PolicyBindingRecord, PolicyGrantRecord,
    PortableApplicationCredential, PortableAuthenticator, PortableNamespace, PortablePolicy,
    PortablePrincipal, PortableSecret, PortableSecretVersion, PortableServiceIdentity,
    PortableSnapshot, PortableTombstone, PrincipalKind, StorageError, StoredAuditRecord,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    InitializedVault, VaultError, VaultOperationContext,
    authentication::{authenticator_commitment, verify_principal_commitment},
    authorization::{policy_commitment, portable_authorization_commitment},
    initialization::{PortableVaultKeys, initialize_restore_staging},
    service_identity::{
        application_credential_commitment, verify_application_credential_commitment,
    },
};

const SCHEMA_VERSION: u32 = 3;
const SECURITY_SEMANTICS_VERSION: u32 = 1;
const MAX_LOGICAL_STREAM_BYTES: usize = 1024 * 1024 * 1024;
const MAX_PORTABLE_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const RECORD_FLAG_CRITICAL: u16 = 1;
const RECORD_KEYS: u16 = 1;
const RECORD_NAMESPACE: u16 = 10;
const RECORD_SECRET: u16 = 11;
const RECORD_SECRET_VERSION: u16 = 12;
const RECORD_TOMBSTONE: u16 = 13;
const RECORD_PRINCIPAL: u16 = 20;
const RECORD_AUTHENTICATOR: u16 = 21;
const RECORD_SERVICE_IDENTITY: u16 = 22;
const RECORD_APPLICATION_CREDENTIAL: u16 = 23;
const RECORD_AUTHORIZATION_STATE: u16 = 30;
const RECORD_POLICY: u16 = 31;
const RECORD_GRANT: u16 = 32;
const RECORD_BINDING: u16 = 33;
const RECORD_AUDIT: u16 = 40;

/// Imported application-credential disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRestoreMode {
    /// Preserve verifier-only credentials exactly for disaster recovery.
    Preserve,
    /// Revoke all imported credentials before destination activation.
    Revoke,
}

/// Safe result of a reopened and verified portable backup file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupFileReport {
    pub archive_id: Uuid,
    pub archive_bytes: u64,
    pub record_count: u64,
    pub logical_bytes: u64,
    pub destination: PathBuf,
}

/// Safe result of a clean logical restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReport {
    pub archive_id: Uuid,
    pub vault_id: VaultId,
    pub installation_id: InstallationId,
    pub recovery_epoch: u64,
    pub imported_records: u64,
    pub imported_audit_events: u64,
    pub revoked_application_credentials: u64,
    pub disabled_source_bound_authenticators: u64,
}

/// Redacted backup/recovery service failures.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup archive is invalid or unavailable")]
    Archive(#[source] ArchiveError),
    #[error("vault backup state is invalid or unavailable")]
    Storage(#[source] StorageError),
    #[error("protected vault data failed verification")]
    Vault(#[source] VaultError),
    #[error("backup destination or protected input is invalid")]
    InvalidInput,
    #[error("backup file operation failed")]
    Io(#[source] std::io::Error),
    #[error("backup logical format is unsupported or corrupt")]
    Integrity,
}

impl From<ArchiveError> for BackupError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}
impl From<StorageError> for BackupError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
impl From<VaultError> for BackupError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}
impl From<std::io::Error> for BackupError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Serialize, Deserialize)]
struct LogicalKeys {
    blind_index: Zeroizing<String>,
    audit: Zeroizing<String>,
    token_verifier: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
struct LogicalNamespace {
    namespace_id: NamespaceId,
    parent_namespace_id: Option<NamespaceId>,
    name_index: [u8; 32],
    metadata_version: u64,
    metadata: Zeroizing<String>,
    lifecycle_state: String,
    revision: u64,
    state_commitment: [u8; 32],
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct LogicalSecret {
    secret_id: SecretId,
    namespace_id: NamespaceId,
    name_index: [u8; 32],
    metadata_version: u64,
    metadata: Zeroizing<String>,
    lifecycle_state: String,
    current_version: u64,
    revision: u64,
    state_commitment: [u8; 32],
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    deleted_at_unix_ms: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct LogicalSecretVersion {
    secret_id: SecretId,
    version: u64,
    payload: Zeroizing<String>,
    schedule: SecretSchedule,
    created_by_principal_id: Option<PrincipalId>,
    created_at_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct LogicalTombstone {
    secret_id: SecretId,
    namespace_id: NamespaceId,
    name_index: [u8; 32],
    last_version: u64,
    purged_at_unix_ms: i64,
    retention_cutoff_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct LogicalPrincipal {
    principal_id: PrincipalId,
    kind: String,
    state: String,
    revision: u64,
    state_commitment: [u8; 32],
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct LogicalAuthenticator {
    authenticator_id: AuthenticatorId,
    principal_id: PrincipalId,
    kind: String,
    credential_lookup: Option<Vec<u8>>,
    credential_data: Option<Vec<u8>>,
    password_phc: Option<String>,
    state: String,
    created_at_unix_ms: i64,
    last_used_at_unix_ms: Option<i64>,
    revoked_at_unix_ms: Option<i64>,
    state_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LogicalServiceIdentity {
    principal_id: PrincipalId,
    metadata_version: u64,
    metadata: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
struct LogicalApplicationCredential {
    credential_id: CredentialId,
    principal_id: PrincipalId,
    lookup_id: [u8; 12],
    verifier: [u8; 32],
    created_at_unix_ms: i64,
    expires_at_unix_ms: Option<i64>,
    last_used_at_unix_ms: Option<i64>,
    revoked_at_unix_ms: Option<i64>,
    revision: u64,
    state_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LogicalAuthorizationState {
    revision: u64,
    state_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LogicalPolicy {
    policy_id: PolicyId,
    revision: u64,
    state: String,
    metadata_version: u64,
    metadata: Zeroizing<String>,
    state_commitment: [u8; 32],
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct LogicalGrant {
    grant_id: GrantId,
    policy_id: PolicyId,
    action: Action,
    resource_kind: ResourceKind,
    resource_id: ObjectId,
    include_descendants: bool,
    created_by_principal_id: PrincipalId,
    created_at_unix_ms: i64,
    state_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LogicalBinding {
    principal_id: PrincipalId,
    policy_id: PolicyId,
    created_by_principal_id: PrincipalId,
    created_at_unix_ms: i64,
    state_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LogicalAudit {
    commitment_version: u8,
    sequence: u64,
    event_id: AuditEventId,
    installation_id: InstallationId,
    recovery_epoch: u64,
    occurred_at_unix_ms: i64,
    request_id: RequestId,
    actor_principal_id: Option<PrincipalId>,
    credential_kind: Option<String>,
    credential_id: Option<ObjectId>,
    action: String,
    target_kind: String,
    target_id: Option<ObjectId>,
    outcome: String,
    previous_commitment: [u8; 32],
    commitment: [u8; 32],
}

struct DecodedLogical {
    keys: Option<LogicalKeys>,
    namespaces: Vec<LogicalNamespace>,
    secrets: Vec<LogicalSecret>,
    secret_versions: Vec<LogicalSecretVersion>,
    tombstones: Vec<LogicalTombstone>,
    principals: Vec<LogicalPrincipal>,
    authenticators: Vec<LogicalAuthenticator>,
    service_identities: Vec<LogicalServiceIdentity>,
    application_credentials: Vec<LogicalApplicationCredential>,
    authorization_state: Option<LogicalAuthorizationState>,
    policies: Vec<LogicalPolicy>,
    grants: Vec<LogicalGrant>,
    bindings: Vec<LogicalBinding>,
    audit: Vec<LogicalAudit>,
    records: u64,
}

impl DecodedLogical {
    fn new() -> Self {
        Self {
            keys: None,
            namespaces: Vec::new(),
            secrets: Vec::new(),
            secret_versions: Vec::new(),
            tombstones: Vec::new(),
            principals: Vec::new(),
            authenticators: Vec::new(),
            service_identities: Vec::new(),
            application_credentials: Vec::new(),
            authorization_state: None,
            policies: Vec::new(),
            grants: Vec::new(),
            bindings: Vec::new(),
            audit: Vec::new(),
            records: 0,
        }
    }
}

impl InitializedVault {
    /// Safely reads only the bounded public archive header without a key.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an unsafe file or invalid bounded header.
    pub fn inspect_backup_file(source: &Path) -> Result<PublicHeader, BackupError> {
        let (mut file, metadata) = open_safe_source(source)?;
        let mut header = vec![0_u8; smcv_backup::MAX_HEADER_BYTES];
        let read = file.read(&mut header)?;
        header.truncate(read);
        parse_public_header(&header, metadata.len())
            .map_err(|error| BackupError::Archive(error.into()))
    }

    /// Performs complete authenticated, non-mutating archive verification.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an unsafe file, wrong key, corruption, or
    /// unsupported archive semantics.
    pub fn verify_backup_file(
        source: &Path,
        key: ArchiveKey<'_>,
    ) -> Result<VerifiedArchive, BackupError> {
        let (file, metadata) = open_safe_source(source)?;
        verify_archive(file, metadata.len(), key).map_err(BackupError::from)
    }

    /// Writes a portable archive to a new restrictive file, reopens it for
    /// complete verification, and publishes it without overwriting.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for invalid custody paths, protected source
    /// integrity failure, archive failure, or a conflicting destination.
    #[cfg(unix)]
    pub fn create_backup_file(
        &self,
        destination: &Path,
        key: ArchiveKey<'_>,
        now_unix_ms: i64,
    ) -> Result<BackupFileReport, BackupError> {
        if now_unix_ms < 0
            || destination.extension().and_then(|value| value.to_str()) != Some("smcvault")
        {
            return Err(BackupError::InvalidInput);
        }
        crate::initialization::prepare_parent(destination)
            .map_err(|_| BackupError::InvalidInput)?;
        if destination.exists() {
            return Err(BackupError::InvalidInput);
        }
        let parent = destination.parent().ok_or(BackupError::InvalidInput)?;
        let temporary = parent.join(format!(".smcvault-{}.partial", Uuid::new_v4()));
        let result = self.write_and_verify_backup(&temporary, key, now_unix_ms);
        let verified = match result {
            Ok(value) => value,
            Err(error) => {
                let _cleanup = fs::remove_file(&temporary);
                return Err(error);
            }
        };
        fs::hard_link(&temporary, destination)?;
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        let audit = self.build_audit(
            "backup:create",
            "archive",
            Some(ObjectId::from_uuid(verified.header.archive_id)),
            VaultOperationContext {
                request_id: RequestId::random(),
                actor_principal_id: None,
                credential_kind: None,
                credential_id: None,
                now_unix_ms,
            },
        )?;
        if let Err(error) = self.store.append_audit(&audit) {
            let _cleanup = fs::remove_file(destination);
            return Err(error.into());
        }
        Ok(BackupFileReport {
            archive_id: verified.header.archive_id,
            archive_bytes: fs::metadata(destination)?.len(),
            record_count: verified.record_count,
            logical_bytes: verified.logical_bytes,
            destination: destination.to_path_buf(),
        })
    }

    #[cfg(unix)]
    fn write_and_verify_backup(
        &self,
        temporary: &Path,
        key: ArchiveKey<'_>,
        now_unix_ms: i64,
    ) -> Result<VerifiedArchive, BackupError> {
        let snapshot = self.store.portable_snapshot()?;
        let logical = self.encode_logical_snapshot(&snapshot)?;
        let metadata = ArchiveMetadata {
            logical_vault_id: snapshot.vault_id.as_uuid(),
            source_installation_id: snapshot.source_installation_id.as_uuid(),
            source_recovery_epoch: snapshot.source_recovery_epoch,
            source_schema_version: SCHEMA_VERSION,
            security_semantics_version: snapshot.security_semantics_version,
            created_at_unix_ms: now_unix_ms,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temporary)?;
        let _summary: ArchiveSummary = write_archive(
            Cursor::new(logical.as_slice()),
            &mut file,
            key,
            &metadata,
            ArchiveOptions::default(),
        )?;
        file.sync_all()?;
        drop(file);
        let file = File::open(temporary)?;
        let length = file.metadata()?.len();
        verify_archive(file, length, key).map_err(BackupError::from)
    }

    fn encode_logical_snapshot(
        &self,
        snapshot: &PortableSnapshot,
    ) -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let mut output = Zeroizing::new(Vec::new());
        let mut keys = LogicalKeys {
            blind_index: encode_key(self.blind_index_key()),
            audit: encode_key(self.audit_key()),
            token_verifier: encode_key(self.token_verifier_key()),
        };
        append_record(&mut output, RECORD_KEYS, &keys)?;
        keys.blind_index.zeroize();
        keys.audit.zeroize();
        keys.token_verifier.zeroize();
        for row in &snapshot.namespaces {
            self.encode_namespace(&mut output, row)?;
        }
        for row in &snapshot.secrets {
            self.encode_secret(&mut output, row)?;
        }
        for row in &snapshot.secret_versions {
            self.encode_secret_version(&mut output, row)?;
        }
        for row in &snapshot.tombstones {
            append_record(&mut output, RECORD_TOMBSTONE, &LogicalTombstone::from(row))?;
        }
        for row in &snapshot.principals {
            append_record(&mut output, RECORD_PRINCIPAL, &LogicalPrincipal::from(row))?;
        }
        for row in &snapshot.authenticators {
            append_record(
                &mut output,
                RECORD_AUTHENTICATOR,
                &LogicalAuthenticator::from(row),
            )?;
        }
        for row in &snapshot.service_identities {
            self.encode_service_identity(&mut output, row)?;
        }
        for row in &snapshot.application_credentials {
            append_record(
                &mut output,
                RECORD_APPLICATION_CREDENTIAL,
                &LogicalApplicationCredential::from(row),
            )?;
        }
        append_record(
            &mut output,
            RECORD_AUTHORIZATION_STATE,
            &LogicalAuthorizationState {
                revision: snapshot.authorization_state.revision,
                state_commitment: snapshot.authorization_state.state_commitment,
            },
        )?;
        for row in &snapshot.policies {
            self.encode_policy(&mut output, row)?;
        }
        for row in &snapshot.grants {
            append_record(&mut output, RECORD_GRANT, &LogicalGrant::from(row))?;
        }
        for row in &snapshot.bindings {
            append_record(&mut output, RECORD_BINDING, &LogicalBinding::from(row))?;
        }
        for row in &snapshot.audit_records {
            append_record(&mut output, RECORD_AUDIT, &LogicalAudit::from(row))?;
        }
        Ok(output)
    }

    fn encode_namespace(
        &self,
        output: &mut Vec<u8>,
        row: &PortableNamespace,
    ) -> Result<(), BackupError> {
        let mut value = LogicalNamespace::from(row);
        value.metadata = self.decrypt_b64(
            &row.metadata,
            ObjectKind::NamespaceMetadata,
            ObjectKind::WrappedNamespaceMetadataKey,
            ObjectId::from_uuid(row.namespace_id.as_uuid()),
            row.metadata_version,
        )?;
        append_record(output, RECORD_NAMESPACE, &value)?;
        value.metadata.zeroize();
        Ok(())
    }
    fn encode_secret(&self, output: &mut Vec<u8>, row: &PortableSecret) -> Result<(), BackupError> {
        let mut value = LogicalSecret::from(row);
        value.metadata = self.decrypt_b64(
            &row.metadata,
            ObjectKind::SecretMetadata,
            ObjectKind::WrappedMetadataKey,
            ObjectId::from_uuid(row.secret_id.as_uuid()),
            row.metadata_version,
        )?;
        append_record(output, RECORD_SECRET, &value)?;
        value.metadata.zeroize();
        Ok(())
    }
    fn encode_secret_version(
        &self,
        output: &mut Vec<u8>,
        row: &PortableSecretVersion,
    ) -> Result<(), BackupError> {
        let mut value = LogicalSecretVersion::from(row);
        value.payload = self.decrypt_b64(
            &row.payload,
            ObjectKind::SecretVersion,
            ObjectKind::WrappedDataKey,
            ObjectId::from_uuid(row.secret_id.as_uuid()),
            row.version,
        )?;
        append_record(output, RECORD_SECRET_VERSION, &value)?;
        value.payload.zeroize();
        Ok(())
    }
    fn encode_service_identity(
        &self,
        output: &mut Vec<u8>,
        row: &PortableServiceIdentity,
    ) -> Result<(), BackupError> {
        let mut value = LogicalServiceIdentity::from(row);
        value.metadata = self.decrypt_b64(
            &row.metadata,
            ObjectKind::ServiceIdentityMetadata,
            ObjectKind::WrappedServiceIdentityMetadataKey,
            ObjectId::from_uuid(row.principal_id.as_uuid()),
            row.metadata_version,
        )?;
        append_record(output, RECORD_SERVICE_IDENTITY, &value)?;
        value.metadata.zeroize();
        Ok(())
    }
    fn encode_policy(&self, output: &mut Vec<u8>, row: &PortablePolicy) -> Result<(), BackupError> {
        let mut value = LogicalPolicy::from(row);
        value.metadata = self.decrypt_b64(
            &row.metadata,
            ObjectKind::PolicyMetadata,
            ObjectKind::WrappedPolicyMetadataKey,
            ObjectId::from_uuid(row.policy_id.as_uuid()),
            row.metadata_version,
        )?;
        append_record(output, RECORD_POLICY, &value)?;
        value.metadata.zeroize();
        Ok(())
    }
    fn decrypt_b64(
        &self,
        encrypted: &EncryptedRecord,
        object_kind: ObjectKind,
        wrapped_kind: ObjectKind,
        object_id: ObjectId,
        version: u64,
    ) -> Result<Zeroizing<String>, BackupError> {
        let plaintext =
            self.decrypt_record(encrypted, object_kind, wrapped_kind, object_id, version)?;
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(plaintext.expose())))
    }

    /// Restores a fully verified archive into brand-new database and root-key
    /// paths. The destination activation marker is committed last.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for invalid input, wrong key, archive or
    /// logical corruption, a non-empty destination, or failed verification.
    #[cfg(unix)]
    pub fn restore_backup_file(
        source: &Path,
        database_path: &Path,
        root_key_path: &Path,
        key: ArchiveKey<'_>,
        credential_mode: CredentialRestoreMode,
        now_unix_ms: i64,
    ) -> Result<RestoreReport, BackupError> {
        if now_unix_ms < 0 || database_path.exists() || root_key_path.exists() {
            return Err(BackupError::InvalidInput);
        }
        let (source_file, source_metadata) = open_safe_source(source)?;
        let mut canonical = Zeroizing::new(Vec::new());
        let verified = decode_archive(source_file, source_metadata.len(), key, |chunk| {
            let next = canonical
                .len()
                .checked_add(chunk.len())
                .ok_or(ArchiveError::InvalidBound)?;
            if next > MAX_LOGICAL_STREAM_BYTES {
                return Err(ArchiveError::InvalidBound);
            }
            canonical.extend_from_slice(chunk);
            Ok(())
        })?;
        if verified.metadata.source_schema_version != SCHEMA_VERSION
            || verified.metadata.security_semantics_version != SECURITY_SEMANTICS_VERSION
        {
            return Err(BackupError::Integrity);
        }
        let mut decoded = decode_logical_stream(&canonical, verified.record_count)?;
        let keys = decode_vault_keys(decoded.keys.take().ok_or(BackupError::Integrity)?)?;
        let destination_epoch = verified
            .metadata
            .source_recovery_epoch
            .checked_add(1)
            .ok_or(BackupError::Integrity)?;
        let destination = initialize_restore_staging(
            database_path,
            root_key_path,
            VaultId::from_uuid(verified.metadata.logical_vault_id),
            keys,
            now_unix_ms,
        )
        .map_err(|_| BackupError::InvalidInput)?;
        let (snapshot, revoked_credentials, disabled_authenticators) = destination
            .transform_logical_snapshot(decoded, &verified, credential_mode, now_unix_ms)?;
        let imported_audit_events =
            u64::try_from(snapshot.audit_records.len()).map_err(|_| BackupError::Integrity)?;
        destination
            .store
            .import_portable_snapshot(&snapshot, destination_epoch)?;
        let audit = destination.build_audit(
            "backup:restore",
            "vault",
            Some(ObjectId::from_uuid(destination.vault_id.as_uuid())),
            VaultOperationContext {
                request_id: RequestId::random(),
                actor_principal_id: None,
                credential_kind: None,
                credential_id: None,
                now_unix_ms,
            },
        )?;
        destination.store.append_audit(&audit)?;
        destination.verify_restored_snapshot(&snapshot)?;
        destination.store.activate_restored_initialization(1)?;

        let reopened = crate::initialize_vault(database_path, root_key_path, now_unix_ms)
            .map_err(|_| BackupError::Integrity)?;
        let _audit_verification = reopened.verify_audit_chain()?;
        Ok(RestoreReport {
            archive_id: verified.header.archive_id,
            vault_id: reopened.vault_id,
            installation_id: reopened.installation_id,
            recovery_epoch: destination_epoch,
            imported_records: verified.record_count,
            imported_audit_events,
            revoked_application_credentials: revoked_credentials,
            disabled_source_bound_authenticators: disabled_authenticators,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed portable record mapping is kept together for exhaustive review"
    )]
    fn transform_logical_snapshot(
        &self,
        mut decoded: DecodedLogical,
        verified: &VerifiedArchive,
        credential_mode: CredentialRestoreMode,
        now_unix_ms: i64,
    ) -> Result<(PortableSnapshot, u64, u64), BackupError> {
        let schedules: BTreeMap<(SecretId, u64), SecretSchedule> = decoded
            .secret_versions
            .iter()
            .map(|row| ((row.secret_id, row.version), row.schedule))
            .collect();
        let mut namespaces = Vec::with_capacity(decoded.namespaces.len());
        for mut row in decoded.namespaces.drain(..) {
            let metadata = self.encrypt_b64(
                &mut row.metadata,
                ObjectKind::NamespaceMetadata,
                ObjectKind::WrappedNamespaceMetadataKey,
                ObjectId::from_uuid(row.namespace_id.as_uuid()),
                row.metadata_version,
            )?;
            let state_commitment = self.namespace_state_commitment(
                row.namespace_id,
                row.parent_namespace_id,
                &row.name_index,
                &row.lifecycle_state,
                row.revision,
                row.metadata_version,
            )?;
            namespaces.push(PortableNamespace {
                namespace_id: row.namespace_id,
                parent_namespace_id: row.parent_namespace_id,
                name_index: row.name_index,
                metadata_version: row.metadata_version,
                metadata,
                lifecycle_state: row.lifecycle_state,
                revision: row.revision,
                state_commitment,
                created_at_unix_ms: row.created_at_unix_ms,
                updated_at_unix_ms: row.updated_at_unix_ms,
            });
        }
        let mut secrets = Vec::with_capacity(decoded.secrets.len());
        for mut row in decoded.secrets.drain(..) {
            let metadata = self.encrypt_b64(
                &mut row.metadata,
                ObjectKind::SecretMetadata,
                ObjectKind::WrappedMetadataKey,
                ObjectId::from_uuid(row.secret_id.as_uuid()),
                row.metadata_version,
            )?;
            let schedule = schedules
                .get(&(row.secret_id, row.current_version))
                .copied()
                .ok_or(BackupError::Integrity)?;
            let state_commitment = self.secret_state_commitment(
                row.secret_id,
                row.namespace_id,
                &row.name_index,
                &row.lifecycle_state,
                row.current_version,
                row.revision,
                row.metadata_version,
                schedule,
            )?;
            secrets.push(PortableSecret {
                secret_id: row.secret_id,
                namespace_id: row.namespace_id,
                name_index: row.name_index,
                metadata_version: row.metadata_version,
                metadata,
                lifecycle_state: row.lifecycle_state,
                current_version: row.current_version,
                revision: row.revision,
                state_commitment,
                created_at_unix_ms: row.created_at_unix_ms,
                updated_at_unix_ms: row.updated_at_unix_ms,
                deleted_at_unix_ms: row.deleted_at_unix_ms,
            });
        }
        let mut secret_versions = Vec::with_capacity(decoded.secret_versions.len());
        for mut row in decoded.secret_versions.drain(..) {
            let payload = self.encrypt_b64(
                &mut row.payload,
                ObjectKind::SecretVersion,
                ObjectKind::WrappedDataKey,
                ObjectId::from_uuid(row.secret_id.as_uuid()),
                row.version,
            )?;
            secret_versions.push(PortableSecretVersion {
                secret_id: row.secret_id,
                version: row.version,
                payload,
                schedule: row.schedule,
                created_by_principal_id: row.created_by_principal_id,
                created_at_unix_ms: row.created_at_unix_ms,
            });
        }
        let tombstones = decoded
            .tombstones
            .drain(..)
            .map(|row| PortableTombstone {
                secret_id: row.secret_id,
                namespace_id: row.namespace_id,
                name_index: row.name_index,
                last_version: row.last_version,
                purged_at_unix_ms: row.purged_at_unix_ms,
                retention_cutoff_unix_ms: row.retention_cutoff_unix_ms,
            })
            .collect();
        let principals = decoded
            .principals
            .drain(..)
            .map(|row| {
                Ok(PortablePrincipal {
                    principal_id: row.principal_id,
                    kind: parse_principal_kind(&row.kind)?,
                    state: row.state,
                    revision: row.revision,
                    state_commitment: row.state_commitment,
                    created_at_unix_ms: row.created_at_unix_ms,
                    updated_at_unix_ms: row.updated_at_unix_ms,
                })
            })
            .collect::<Result<Vec<_>, BackupError>>()?;

        let mut disabled_authenticators = 0_u64;
        let mut authenticators = Vec::with_capacity(decoded.authenticators.len());
        for row in decoded.authenticators.drain(..) {
            let kind = parse_authenticator_kind(&row.kind)?;
            let mut restored = PortableAuthenticator {
                authenticator_id: row.authenticator_id,
                principal_id: row.principal_id,
                kind,
                credential_lookup: row.credential_lookup,
                credential_data: row.credential_data,
                password_phc: row.password_phc,
                state: row.state,
                created_at_unix_ms: row.created_at_unix_ms,
                last_used_at_unix_ms: row.last_used_at_unix_ms,
                revoked_at_unix_ms: row.revoked_at_unix_ms,
                state_commitment: row.state_commitment,
            };
            if kind == AuthenticatorKind::Passkey && restored.state == "active" {
                "revoked".clone_into(&mut restored.state);
                restored.revoked_at_unix_ms = Some(now_unix_ms);
                restored.state_commitment = authenticator_commitment(
                    self,
                    restored.authenticator_id,
                    restored.principal_id,
                    restored.kind,
                    restored.credential_lookup.as_deref(),
                    restored.credential_data.as_deref(),
                    restored.password_phc.as_deref(),
                    &restored.state,
                    restored.created_at_unix_ms,
                    restored.last_used_at_unix_ms,
                    restored.revoked_at_unix_ms,
                )
                .map_err(|_| BackupError::Integrity)?;
                disabled_authenticators = disabled_authenticators
                    .checked_add(1)
                    .ok_or(BackupError::Integrity)?;
            }
            authenticators.push(restored);
        }
        let mut service_identities = Vec::with_capacity(decoded.service_identities.len());
        for mut row in decoded.service_identities.drain(..) {
            let metadata = self.encrypt_b64(
                &mut row.metadata,
                ObjectKind::ServiceIdentityMetadata,
                ObjectKind::WrappedServiceIdentityMetadataKey,
                ObjectId::from_uuid(row.principal_id.as_uuid()),
                row.metadata_version,
            )?;
            service_identities.push(PortableServiceIdentity {
                principal_id: row.principal_id,
                metadata_version: row.metadata_version,
                metadata,
            });
        }
        let mut revoked_credentials = 0_u64;
        let mut application_credentials = Vec::with_capacity(decoded.application_credentials.len());
        for row in decoded.application_credentials.drain(..) {
            let mut restored = PortableApplicationCredential {
                credential_id: row.credential_id,
                principal_id: row.principal_id,
                lookup_id: row.lookup_id,
                verifier: row.verifier,
                created_at_unix_ms: row.created_at_unix_ms,
                expires_at_unix_ms: row.expires_at_unix_ms,
                last_used_at_unix_ms: row.last_used_at_unix_ms,
                revoked_at_unix_ms: row.revoked_at_unix_ms,
                revision: row.revision,
                state_commitment: row.state_commitment,
            };
            if credential_mode == CredentialRestoreMode::Revoke
                && restored.revoked_at_unix_ms.is_none()
            {
                restored.revoked_at_unix_ms = Some(now_unix_ms);
                restored.revision = restored
                    .revision
                    .checked_add(1)
                    .ok_or(BackupError::Integrity)?;
                restored.state_commitment = application_credential_commitment(
                    self,
                    restored.credential_id,
                    restored.principal_id,
                    &restored.lookup_id,
                    &restored.verifier,
                    restored.created_at_unix_ms,
                    restored.expires_at_unix_ms,
                    restored.last_used_at_unix_ms,
                    restored.revoked_at_unix_ms,
                    restored.revision,
                )
                .map_err(|_| BackupError::Integrity)?;
                revoked_credentials = revoked_credentials
                    .checked_add(1)
                    .ok_or(BackupError::Integrity)?;
            }
            application_credentials.push(restored);
        }
        let authorization = decoded
            .authorization_state
            .take()
            .ok_or(BackupError::Integrity)?;
        let mut policies = Vec::with_capacity(decoded.policies.len());
        for mut row in decoded.policies.drain(..) {
            let metadata = self.encrypt_b64(
                &mut row.metadata,
                ObjectKind::PolicyMetadata,
                ObjectKind::WrappedPolicyMetadataKey,
                ObjectId::from_uuid(row.policy_id.as_uuid()),
                row.metadata_version,
            )?;
            let state_commitment = policy_commitment(
                self,
                row.policy_id,
                row.revision,
                &row.state,
                row.metadata_version,
                &metadata,
                row.created_at_unix_ms,
                row.updated_at_unix_ms,
            )
            .map_err(|_| BackupError::Integrity)?;
            policies.push(PortablePolicy {
                policy_id: row.policy_id,
                revision: row.revision,
                state: row.state,
                metadata_version: row.metadata_version,
                metadata,
                state_commitment,
                created_at_unix_ms: row.created_at_unix_ms,
                updated_at_unix_ms: row.updated_at_unix_ms,
            });
        }
        let grants: Vec<PolicyGrantRecord> = decoded
            .grants
            .drain(..)
            .map(|row| PolicyGrantRecord {
                grant_id: row.grant_id,
                policy_id: row.policy_id,
                action: row.action,
                resource_kind: row.resource_kind,
                resource_id: row.resource_id,
                include_descendants: row.include_descendants,
                created_by_principal_id: row.created_by_principal_id,
                created_at_unix_ms: row.created_at_unix_ms,
                state_commitment: row.state_commitment,
            })
            .collect();
        let bindings: Vec<PolicyBindingRecord> = decoded
            .bindings
            .drain(..)
            .map(|row| PolicyBindingRecord {
                principal_id: row.principal_id,
                policy_id: row.policy_id,
                created_by_principal_id: row.created_by_principal_id,
                created_at_unix_ms: row.created_at_unix_ms,
                state_commitment: row.state_commitment,
            })
            .collect();
        let audit_records = decoded
            .audit
            .drain(..)
            .map(|row| StoredAuditRecord {
                commitment_version: row.commitment_version,
                sequence: row.sequence,
                event_id: row.event_id,
                installation_id: row.installation_id,
                recovery_epoch: row.recovery_epoch,
                occurred_at_unix_ms: row.occurred_at_unix_ms,
                request_id: row.request_id,
                actor_principal_id: row.actor_principal_id,
                credential_kind: row.credential_kind,
                credential_id: row.credential_id,
                action: row.action,
                target_kind: row.target_kind,
                target_id: row.target_id,
                outcome: row.outcome,
                previous_commitment: row.previous_commitment,
                commitment: row.commitment,
            })
            .collect();
        let authorization_state_commitment = portable_authorization_commitment(
            self,
            &policies,
            &grants,
            &bindings,
            authorization.revision,
        )
        .map_err(|_| BackupError::Integrity)?;
        Ok((
            PortableSnapshot {
                vault_id: VaultId::from_uuid(verified.metadata.logical_vault_id),
                source_installation_id: InstallationId::from_uuid(
                    verified.metadata.source_installation_id,
                ),
                source_recovery_epoch: verified.metadata.source_recovery_epoch,
                security_semantics_version: verified.metadata.security_semantics_version,
                namespaces,
                secrets,
                secret_versions,
                tombstones,
                principals,
                authenticators,
                service_identities,
                application_credentials,
                authorization_state: AuthorizationState {
                    revision: authorization.revision,
                    state_commitment: authorization_state_commitment,
                },
                policies,
                grants,
                bindings,
                audit_records,
            },
            revoked_credentials,
            disabled_authenticators,
        ))
    }

    fn encrypt_b64(
        &self,
        encoded: &mut String,
        object_kind: ObjectKind,
        wrapped_kind: ObjectKind,
        object_id: ObjectId,
        version: u64,
    ) -> Result<EncryptedRecord, BackupError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(encoded.len()));
        let decoded = URL_SAFE_NO_PAD.decode_vec(encoded.as_bytes(), bytes.as_mut());
        encoded.zeroize();
        decoded.map_err(|_| BackupError::Integrity)?;
        self.encrypt_record(
            ProtectedBytes::new(std::mem::take(bytes.as_mut())),
            object_kind,
            wrapped_kind,
            object_id,
            version,
        )
        .map_err(BackupError::from)
    }

    fn verify_restored_snapshot(&self, snapshot: &PortableSnapshot) -> Result<(), BackupError> {
        if !self.store.quick_integrity_check()? {
            return Err(BackupError::Integrity);
        }
        self.verify_restored_relationships(snapshot)?;
        for namespace in &snapshot.namespaces {
            let durable = self.store.namespace(namespace.namespace_id)?;
            self.verify_namespace_state(&durable)?;
            let _plaintext = self.decrypt_record(
                &durable.metadata,
                ObjectKind::NamespaceMetadata,
                ObjectKind::WrappedNamespaceMetadataKey,
                ObjectId::from_uuid(namespace.namespace_id.as_uuid()),
                namespace.metadata_version,
            )?;
        }
        for secret in &snapshot.secrets {
            let durable = self.store.secret(secret.secret_id)?;
            self.verify_secret_state(&durable)?;
            let _plaintext = self.decrypt_record(
                &durable.metadata,
                ObjectKind::SecretMetadata,
                ObjectKind::WrappedMetadataKey,
                ObjectId::from_uuid(secret.secret_id.as_uuid()),
                secret.metadata_version,
            )?;
        }
        for version in &snapshot.secret_versions {
            let _plaintext = self.decrypt_record(
                &version.payload,
                ObjectKind::SecretVersion,
                ObjectKind::WrappedDataKey,
                ObjectId::from_uuid(version.secret_id.as_uuid()),
                version.version,
            )?;
        }
        for principal in &snapshot.principals {
            let durable = self.store.principal(principal.principal_id)?;
            verify_principal_commitment(self, &durable).map_err(|_| BackupError::Integrity)?;
        }
        for authenticator in &snapshot.authenticators {
            let expected = authenticator_commitment(
                self,
                authenticator.authenticator_id,
                authenticator.principal_id,
                authenticator.kind,
                authenticator.credential_lookup.as_deref(),
                authenticator.credential_data.as_deref(),
                authenticator.password_phc.as_deref(),
                &authenticator.state,
                authenticator.created_at_unix_ms,
                authenticator.last_used_at_unix_ms,
                authenticator.revoked_at_unix_ms,
            )
            .map_err(|_| BackupError::Integrity)?;
            if expected != authenticator.state_commitment {
                return Err(BackupError::Integrity);
            }
        }
        for credential in &snapshot.application_credentials {
            let durable = self
                .store
                .application_credential(credential.credential_id)?;
            verify_application_credential_commitment(self, &durable)
                .map_err(|_| BackupError::Integrity)?;
        }
        let empty_initial_authorization = snapshot.policies.is_empty()
            && snapshot.grants.is_empty()
            && snapshot.bindings.is_empty()
            && snapshot.authorization_state.revision == 1
            && snapshot.authorization_state.state_commitment == [0_u8; 32];
        if !empty_initial_authorization {
            let _authorization = self
                .verified_authorization_snapshot()
                .map_err(|_| BackupError::Integrity)?;
        }
        let _audit = self.verify_audit_chain()?;
        Ok(())
    }

    fn verify_restored_relationships(
        &self,
        snapshot: &PortableSnapshot,
    ) -> Result<(), BackupError> {
        let namespace_ids: BTreeSet<_> = snapshot
            .namespaces
            .iter()
            .map(|row| row.namespace_id)
            .collect();
        let secret_ids: BTreeSet<_> = snapshot.secrets.iter().map(|row| row.secret_id).collect();
        let principal_kinds: BTreeMap<_, _> = snapshot
            .principals
            .iter()
            .map(|row| (row.principal_id, row.kind))
            .collect();
        if namespace_ids.len() != snapshot.namespaces.len()
            || secret_ids.len() != snapshot.secrets.len()
            || principal_kinds.len() != snapshot.principals.len()
        {
            return Err(BackupError::Integrity);
        }

        for namespace in &snapshot.namespaces {
            let ancestors = self
                .store
                .namespace_ancestors_inclusive(namespace.namespace_id)?;
            let unique: BTreeSet<_> = ancestors.iter().copied().collect();
            let root = ancestors.last().ok_or(BackupError::Integrity)?;
            if ancestors.len() > 33
                || ancestors.len() != unique.len()
                || self.store.namespace(*root)?.parent_namespace_id.is_some()
            {
                return Err(BackupError::Integrity);
            }
        }

        let mut versions: BTreeMap<SecretId, BTreeSet<u64>> = BTreeMap::new();
        for version in &snapshot.secret_versions {
            versions
                .entry(version.secret_id)
                .or_default()
                .insert(version.version);
        }
        for secret in &snapshot.secrets {
            let actual = versions.get(&secret.secret_id);
            let actual_count = actual.map_or(0, BTreeSet::len);
            let expected_count =
                usize::try_from(secret.current_version).map_err(|_| BackupError::Integrity)?;
            if actual_count != expected_count
                || !(1..=secret.current_version)
                    .all(|version| actual.is_some_and(|values| values.contains(&version)))
            {
                return Err(BackupError::Integrity);
            }
        }
        if versions
            .keys()
            .any(|secret_id| !secret_ids.contains(secret_id))
            || snapshot
                .tombstones
                .iter()
                .any(|row| secret_ids.contains(&row.secret_id))
        {
            return Err(BackupError::Integrity);
        }

        for authenticator in &snapshot.authenticators {
            if principal_kinds.get(&authenticator.principal_id) != Some(&PrincipalKind::Owner) {
                return Err(BackupError::Integrity);
            }
        }
        for service in &snapshot.service_identities {
            if principal_kinds.get(&service.principal_id) != Some(&PrincipalKind::Service) {
                return Err(BackupError::Integrity);
            }
        }
        for credential in &snapshot.application_credentials {
            if principal_kinds.get(&credential.principal_id) != Some(&PrincipalKind::Service) {
                return Err(BackupError::Integrity);
            }
        }
        for grant in &snapshot.grants {
            let target_exists = match grant.resource_kind {
                ResourceKind::Namespace => {
                    namespace_ids.contains(&NamespaceId::from_uuid(grant.resource_id.as_uuid()))
                }
                ResourceKind::Secret => {
                    secret_ids.contains(&SecretId::from_uuid(grant.resource_id.as_uuid()))
                }
            };
            if !target_exists
                || principal_kinds.get(&grant.created_by_principal_id)
                    != Some(&PrincipalKind::Owner)
            {
                return Err(BackupError::Integrity);
            }
        }
        for binding in &snapshot.bindings {
            if principal_kinds.get(&binding.principal_id) != Some(&PrincipalKind::Service)
                || principal_kinds.get(&binding.created_by_principal_id)
                    != Some(&PrincipalKind::Owner)
            {
                return Err(BackupError::Integrity);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn open_safe_source(source: &Path) -> Result<(File, fs::Metadata), BackupError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PORTABLE_FILE_BYTES {
        return Err(BackupError::InvalidInput);
    }
    Ok((file, metadata))
}

#[cfg(not(unix))]
fn open_safe_source(source: &Path) -> Result<(File, fs::Metadata), BackupError> {
    let file = File::open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PORTABLE_FILE_BYTES {
        return Err(BackupError::InvalidInput);
    }
    Ok((file, metadata))
}

fn decode_vault_keys(mut keys: LogicalKeys) -> Result<PortableVaultKeys, BackupError> {
    let blind_index = decode_key(&mut keys.blind_index)?;
    let audit = decode_key(&mut keys.audit)?;
    let token_verifier = decode_key(&mut keys.token_verifier)?;
    Ok(PortableVaultKeys {
        blind_index,
        audit,
        token_verifier,
    })
}

fn decode_key(encoded: &mut String) -> Result<KeyMaterial, BackupError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    let decoded = URL_SAFE_NO_PAD.decode_slice(encoded.as_bytes(), bytes.as_mut());
    encoded.zeroize();
    let length = decoded.map_err(|_| BackupError::Integrity)?;
    if length != bytes.len() {
        return Err(BackupError::Integrity);
    }
    KeyMaterial::from_protected(ProtectedBytes::new(bytes.to_vec()))
        .map_err(|_| BackupError::Integrity)
}

fn decode_logical_stream(
    bytes: &[u8],
    expected_records: u64,
) -> Result<DecodedLogical, BackupError> {
    let mut decoded = DecodedLogical::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor.checked_add(8).ok_or(BackupError::Integrity)?)
            .ok_or(BackupError::Integrity)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::try_from(u32::from_be_bytes([
            header[4], header[5], header[6], header[7],
        ]))
        .map_err(|_| BackupError::Integrity)?;
        if flags != RECORD_FLAG_CRITICAL {
            return Err(BackupError::Integrity);
        }
        cursor = cursor.checked_add(8).ok_or(BackupError::Integrity)?;
        let end = cursor.checked_add(length).ok_or(BackupError::Integrity)?;
        let payload = bytes.get(cursor..end).ok_or(BackupError::Integrity)?;
        match kind {
            RECORD_KEYS => {
                if decoded.keys.is_some() || decoded.records != 0 {
                    return Err(BackupError::Integrity);
                }
                decoded.keys = Some(parse_record(payload)?);
            }
            RECORD_NAMESPACE => decoded.namespaces.push(parse_record(payload)?),
            RECORD_SECRET => decoded.secrets.push(parse_record(payload)?),
            RECORD_SECRET_VERSION => decoded.secret_versions.push(parse_record(payload)?),
            RECORD_TOMBSTONE => decoded.tombstones.push(parse_record(payload)?),
            RECORD_PRINCIPAL => decoded.principals.push(parse_record(payload)?),
            RECORD_AUTHENTICATOR => decoded.authenticators.push(parse_record(payload)?),
            RECORD_SERVICE_IDENTITY => decoded.service_identities.push(parse_record(payload)?),
            RECORD_APPLICATION_CREDENTIAL => {
                decoded.application_credentials.push(parse_record(payload)?);
            }
            RECORD_AUTHORIZATION_STATE => {
                if decoded.authorization_state.is_some() {
                    return Err(BackupError::Integrity);
                }
                decoded.authorization_state = Some(parse_record(payload)?);
            }
            RECORD_POLICY => decoded.policies.push(parse_record(payload)?),
            RECORD_GRANT => decoded.grants.push(parse_record(payload)?),
            RECORD_BINDING => decoded.bindings.push(parse_record(payload)?),
            RECORD_AUDIT => decoded.audit.push(parse_record(payload)?),
            _ => return Err(BackupError::Integrity),
        }
        decoded.records = decoded
            .records
            .checked_add(1)
            .ok_or(BackupError::Integrity)?;
        cursor = end;
    }
    if decoded.records != expected_records
        || decoded.keys.is_none()
        || decoded.authorization_state.is_none()
    {
        return Err(BackupError::Integrity);
    }
    Ok(decoded)
}

fn parse_record<'de, T: Deserialize<'de>>(payload: &'de [u8]) -> Result<T, BackupError> {
    serde_json::from_slice(payload).map_err(|_| BackupError::Integrity)
}

fn parse_principal_kind(value: &str) -> Result<PrincipalKind, BackupError> {
    match value {
        "owner" => Ok(PrincipalKind::Owner),
        "service" => Ok(PrincipalKind::Service),
        _ => Err(BackupError::Integrity),
    }
}

fn parse_authenticator_kind(value: &str) -> Result<AuthenticatorKind, BackupError> {
    match value {
        "password" => Ok(AuthenticatorKind::Password),
        "passkey" => Ok(AuthenticatorKind::Passkey),
        "recovery" => Ok(AuthenticatorKind::Recovery),
        _ => Err(BackupError::Integrity),
    }
}

fn append_record(
    output: &mut Vec<u8>,
    kind: u16,
    value: &impl Serialize,
) -> Result<(), BackupError> {
    let mut payload = serde_json::to_vec(value).map_err(|_| BackupError::Integrity)?;
    let length = u32::try_from(payload.len()).map_err(|_| BackupError::InvalidInput)?;
    let next_length = output
        .len()
        .checked_add(8)
        .and_then(|size| size.checked_add(payload.len()))
        .ok_or(BackupError::InvalidInput)?;
    if next_length > MAX_LOGICAL_STREAM_BYTES {
        payload.zeroize();
        return Err(BackupError::InvalidInput);
    }
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&RECORD_FLAG_CRITICAL.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&payload);
    payload.zeroize();
    Ok(())
}

fn encode_key(key: &KeyMaterial) -> Zeroizing<String> {
    let protected = key.to_protected_bytes();
    Zeroizing::new(URL_SAFE_NO_PAD.encode(protected.expose()))
}

fn principal_kind(value: PrincipalKind) -> &'static str {
    match value {
        PrincipalKind::Owner => "owner",
        PrincipalKind::Service => "service",
    }
}
fn authenticator_kind(value: AuthenticatorKind) -> &'static str {
    match value {
        AuthenticatorKind::Password => "password",
        AuthenticatorKind::Passkey => "passkey",
        AuthenticatorKind::Recovery => "recovery",
    }
}

impl From<&PortableNamespace> for LogicalNamespace {
    fn from(row: &PortableNamespace) -> Self {
        Self {
            namespace_id: row.namespace_id,
            parent_namespace_id: row.parent_namespace_id,
            name_index: row.name_index,
            metadata_version: row.metadata_version,
            metadata: Zeroizing::new(String::new()),
            lifecycle_state: row.lifecycle_state.clone(),
            revision: row.revision,
            state_commitment: row.state_commitment,
            created_at_unix_ms: row.created_at_unix_ms,
            updated_at_unix_ms: row.updated_at_unix_ms,
        }
    }
}
impl From<&PortableSecret> for LogicalSecret {
    fn from(row: &PortableSecret) -> Self {
        Self {
            secret_id: row.secret_id,
            namespace_id: row.namespace_id,
            name_index: row.name_index,
            metadata_version: row.metadata_version,
            metadata: Zeroizing::new(String::new()),
            lifecycle_state: row.lifecycle_state.clone(),
            current_version: row.current_version,
            revision: row.revision,
            state_commitment: row.state_commitment,
            created_at_unix_ms: row.created_at_unix_ms,
            updated_at_unix_ms: row.updated_at_unix_ms,
            deleted_at_unix_ms: row.deleted_at_unix_ms,
        }
    }
}
impl From<&PortableSecretVersion> for LogicalSecretVersion {
    fn from(row: &PortableSecretVersion) -> Self {
        Self {
            secret_id: row.secret_id,
            version: row.version,
            payload: Zeroizing::new(String::new()),
            schedule: row.schedule,
            created_by_principal_id: row.created_by_principal_id,
            created_at_unix_ms: row.created_at_unix_ms,
        }
    }
}
impl From<&PortableTombstone> for LogicalTombstone {
    fn from(row: &PortableTombstone) -> Self {
        Self {
            secret_id: row.secret_id,
            namespace_id: row.namespace_id,
            name_index: row.name_index,
            last_version: row.last_version,
            purged_at_unix_ms: row.purged_at_unix_ms,
            retention_cutoff_unix_ms: row.retention_cutoff_unix_ms,
        }
    }
}
impl From<&PortablePrincipal> for LogicalPrincipal {
    fn from(row: &PortablePrincipal) -> Self {
        Self {
            principal_id: row.principal_id,
            kind: principal_kind(row.kind).to_owned(),
            state: row.state.clone(),
            revision: row.revision,
            state_commitment: row.state_commitment,
            created_at_unix_ms: row.created_at_unix_ms,
            updated_at_unix_ms: row.updated_at_unix_ms,
        }
    }
}
impl From<&PortableAuthenticator> for LogicalAuthenticator {
    fn from(row: &PortableAuthenticator) -> Self {
        Self {
            authenticator_id: row.authenticator_id,
            principal_id: row.principal_id,
            kind: authenticator_kind(row.kind).to_owned(),
            credential_lookup: row.credential_lookup.clone(),
            credential_data: row.credential_data.clone(),
            password_phc: row.password_phc.clone(),
            state: row.state.clone(),
            created_at_unix_ms: row.created_at_unix_ms,
            last_used_at_unix_ms: row.last_used_at_unix_ms,
            revoked_at_unix_ms: row.revoked_at_unix_ms,
            state_commitment: row.state_commitment,
        }
    }
}
impl From<&PortableServiceIdentity> for LogicalServiceIdentity {
    fn from(row: &PortableServiceIdentity) -> Self {
        Self {
            principal_id: row.principal_id,
            metadata_version: row.metadata_version,
            metadata: Zeroizing::new(String::new()),
        }
    }
}
impl From<&PortableApplicationCredential> for LogicalApplicationCredential {
    fn from(row: &PortableApplicationCredential) -> Self {
        Self {
            credential_id: row.credential_id,
            principal_id: row.principal_id,
            lookup_id: row.lookup_id,
            verifier: row.verifier,
            created_at_unix_ms: row.created_at_unix_ms,
            expires_at_unix_ms: row.expires_at_unix_ms,
            last_used_at_unix_ms: row.last_used_at_unix_ms,
            revoked_at_unix_ms: row.revoked_at_unix_ms,
            revision: row.revision,
            state_commitment: row.state_commitment,
        }
    }
}
impl From<&PortablePolicy> for LogicalPolicy {
    fn from(row: &PortablePolicy) -> Self {
        Self {
            policy_id: row.policy_id,
            revision: row.revision,
            state: row.state.clone(),
            metadata_version: row.metadata_version,
            metadata: Zeroizing::new(String::new()),
            state_commitment: row.state_commitment,
            created_at_unix_ms: row.created_at_unix_ms,
            updated_at_unix_ms: row.updated_at_unix_ms,
        }
    }
}
impl From<&PolicyGrantRecord> for LogicalGrant {
    fn from(row: &PolicyGrantRecord) -> Self {
        Self {
            grant_id: row.grant_id,
            policy_id: row.policy_id,
            action: row.action,
            resource_kind: row.resource_kind,
            resource_id: row.resource_id,
            include_descendants: row.include_descendants,
            created_by_principal_id: row.created_by_principal_id,
            created_at_unix_ms: row.created_at_unix_ms,
            state_commitment: row.state_commitment,
        }
    }
}
impl From<&PolicyBindingRecord> for LogicalBinding {
    fn from(row: &PolicyBindingRecord) -> Self {
        Self {
            principal_id: row.principal_id,
            policy_id: row.policy_id,
            created_by_principal_id: row.created_by_principal_id,
            created_at_unix_ms: row.created_at_unix_ms,
            state_commitment: row.state_commitment,
        }
    }
}
impl From<&StoredAuditRecord> for LogicalAudit {
    fn from(row: &StoredAuditRecord) -> Self {
        Self {
            commitment_version: row.commitment_version,
            sequence: row.sequence,
            event_id: row.event_id,
            installation_id: row.installation_id,
            recovery_epoch: row.recovery_epoch,
            occurred_at_unix_ms: row.occurred_at_unix_ms,
            request_id: row.request_id,
            actor_principal_id: row.actor_principal_id,
            credential_kind: row.credential_kind.clone(),
            credential_id: row.credential_id,
            action: row.action.clone(),
            target_kind: row.target_kind.clone(),
            target_id: row.target_id,
            outcome: row.outcome.clone(),
            previous_commitment: row.previous_commitment,
            commitment: row.commitment,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, symlink},
    };

    use smcv_backup::{ArchiveKey, RecoveryKey};
    use smcv_core::{ProtectedBytes, ProtectedString, RequestId, VaultId};
    use smcv_crypto::KeyMaterial;
    use smcv_storage::{ActivationState, StorageError};
    use tempfile::TempDir;

    use super::{CredentialRestoreMode, InitializedVault};
    use crate::{
        LocalSetupCapability, MetadataInput, ServiceIdentityMetadata, VaultOperationContext,
        initialization::{PortableVaultKeys, initialize_restore_staging},
        initialize_vault,
    };

    fn make_directory(path: &std::path::Path) -> std::io::Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the clean-host drill keeps source, preserve, and revoke assertions in one fixture"
    )]
    fn clean_environment_backup_restore_reencrypts_and_preserves_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let source_database = directory.path().join("source/database/vault.sqlite");
        let source_root = directory.path().join("source/provider/root.key");
        make_directory(source_database.parent().ok_or("database parent")?)?;
        make_directory(source_root.parent().ok_or("root parent")?)?;
        let source = initialize_vault(&source_database, &source_root, 1_800_000_000_000)?;
        let operation = |time| VaultOperationContext {
            request_id: RequestId::random(),
            actor_principal_id: None,
            credential_kind: None,
            credential_id: None,
            now_unix_ms: time,
        };
        let namespace_id = source.create_namespace(
            None,
            &MetadataInput {
                name: ProtectedString::new("production".to_owned()),
                description: None,
                username: None,
                tags: Vec::new(),
            },
            operation(1_800_000_000_001),
        )?;
        let created = source.create_secret(
            namespace_id,
            &MetadataInput {
                name: ProtectedString::new("database-password".to_owned()),
                description: Some(ProtectedString::new("synthetic".to_owned())),
                username: None,
                tags: Vec::new(),
            },
            ProtectedBytes::new(b"first-version".to_vec()),
            operation(1_800_000_000_002),
        )?;
        source.update_secret(
            created.secret_id,
            1,
            1,
            ProtectedBytes::new(b"second-version".to_vec()),
            operation(1_800_000_000_003),
        )?;
        let owner_password = ProtectedString::new("synthetic long owner password".to_owned());
        source.enroll_local_owner(
            LocalSetupCapability::for_local_cli(),
            &owner_password,
            RequestId::random(),
            1_800_000_000_004,
        )?;
        let session =
            source.login_with_password(&owner_password, RequestId::random(), 1_800_000_000_005)?;
        let owner = source.authenticate_browser_session(
            &session.session_token,
            Some(&session.csrf_token),
            true,
            1_800_000_000_006,
        )?;
        let service_id = source.create_service_identity(
            owner,
            &ServiceIdentityMetadata {
                label: ProtectedString::new("synthetic workload".to_owned()),
                description: None,
            },
            RequestId::random(),
            1_800_000_000_007,
        )?;
        let owner = source.authenticate_browser_session(
            &session.session_token,
            Some(&session.csrf_token),
            true,
            1_800_000_000_008,
        )?;
        let application_credential = source.issue_application_credential(
            owner,
            service_id,
            None,
            RequestId::random(),
            1_800_000_000_009,
        )?;

        let backup_directory = directory.path().join("backups");
        make_directory(&backup_directory)?;
        let archive_path = backup_directory.join("vault.smcvault");
        let recovery_key = RecoveryKey::generate()?;
        let report = source.create_backup_file(
            &archive_path,
            ArchiveKey::Recovery(&recovery_key),
            1_800_000_000_010,
        )?;
        assert!(report.archive_bytes > 0);
        let header = InitializedVault::inspect_backup_file(&archive_path)?;
        assert_eq!(header.archive_id, report.archive_id);
        let verified = InitializedVault::verify_backup_file(
            &archive_path,
            ArchiveKey::Recovery(&recovery_key),
        )?;
        assert_eq!(verified.record_count, report.record_count);
        let archive_link = backup_directory.join("linked.smcvault");
        symlink(&archive_path, &archive_link)?;
        assert!(InitializedVault::inspect_backup_file(&archive_link).is_err());
        assert!(
            InitializedVault::verify_backup_file(
                &archive_link,
                ArchiveKey::Recovery(&recovery_key)
            )
            .is_err()
        );
        let archive_bytes = fs::read(&archive_path)?;
        assert!(
            !archive_bytes
                .windows(b"database-password".len())
                .any(|window| window == b"database-password")
        );
        assert!(
            !archive_bytes
                .windows(b"second-version".len())
                .any(|window| window == b"second-version")
        );
        let source_root_bytes = fs::read(&source_root)?;
        assert!(
            !archive_bytes
                .windows(32)
                .any(|window| window == &source_root_bytes[40..72])
        );

        let wrong_key = RecoveryKey::generate()?;
        let rejected_database = directory.path().join("rejected/database/vault.sqlite");
        let rejected_root = directory.path().join("rejected/provider/root.key");
        assert!(
            InitializedVault::restore_backup_file(
                &archive_path,
                &rejected_database,
                &rejected_root,
                ArchiveKey::Recovery(&wrong_key),
                CredentialRestoreMode::Preserve,
                1_800_000_000_010,
            )
            .is_err()
        );
        assert!(!rejected_database.exists());
        assert!(!rejected_root.exists());

        let destination_database = directory.path().join("restored/database/vault.sqlite");
        let destination_root = directory.path().join("restored/provider/root.key");
        let restore = InitializedVault::restore_backup_file(
            &archive_path,
            &destination_database,
            &destination_root,
            ArchiveKey::Recovery(&recovery_key),
            CredentialRestoreMode::Preserve,
            1_800_000_000_011,
        )?;
        assert_eq!(restore.vault_id, source.vault_id);
        assert_ne!(restore.installation_id, source.installation_id);
        assert_eq!(restore.recovery_epoch, 1);

        let restored =
            initialize_vault(&destination_database, &destination_root, 1_800_000_000_012)?;
        let value =
            restored.reveal_current_secret(created.secret_id, operation(1_800_000_000_013))?;
        assert_eq!(value.expose(), b"second-version");
        assert_eq!(
            restored
                .secret_version_history(created.secret_id, 0, 10)?
                .len(),
            2
        );
        let restored_service = restored.authenticate_application_credential(
            &application_credential.plaintext,
            RequestId::random(),
            1_800_000_000_014,
        )?;
        assert_eq!(restored_service.principal_id(), service_id);
        let _owner_session = restored.login_with_password(
            &owner_password,
            RequestId::random(),
            1_800_000_000_015,
        )?;
        assert!(restored.verify_audit_chain()?.events_verified >= 4);

        let revoked_database = directory.path().join("revoked/database/vault.sqlite");
        let revoked_root = directory.path().join("revoked/provider/root.key");
        let revoked_report = InitializedVault::restore_backup_file(
            &archive_path,
            &revoked_database,
            &revoked_root,
            ArchiveKey::Recovery(&recovery_key),
            CredentialRestoreMode::Revoke,
            1_800_000_000_016,
        )?;
        assert_eq!(revoked_report.revoked_application_credentials, 1);
        let revoked = initialize_vault(&revoked_database, &revoked_root, 1_800_000_000_017)?;
        assert!(
            revoked
                .authenticate_application_credential(
                    &application_credential.plaintext,
                    RequestId::random(),
                    1_800_000_000_018,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn committed_v1_fixture_restores_to_a_clean_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let archive = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../smcv-backup/fixtures/v1-minimal.smcvault");
        let key =
            RecoveryKey::parse("smcvbrk_v1.M6_qs6hHm50zrqXxU3vlWWCdK8FWcnIhAkiuqMnITp0.83d973d9")?;
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let report = InitializedVault::restore_backup_file(
            &archive,
            &database,
            &root,
            ArchiveKey::Recovery(&key),
            CredentialRestoreMode::Preserve,
            1_800_000_100_000,
        )?;
        assert_eq!(report.imported_records, 2);
        assert_eq!(report.recovery_epoch, 1);
        let restored = initialize_vault(&database, &root, 1_800_000_100_001)?;
        assert_eq!(restored.vault_id, report.vault_id);
        assert_eq!(restored.verify_audit_chain()?.events_verified, 1);
        let backup_directory = directory.path().join("current-backup");
        make_directory(&backup_directory)?;
        let current_archive = backup_directory.join("current.smcvault");
        let current_key = RecoveryKey::generate()?;
        let _current = restored.create_backup_file(
            &current_archive,
            ArchiveKey::Recovery(&current_key),
            1_800_000_100_002,
        )?;
        let second_database = directory.path().join("second/database/vault.sqlite");
        let second_root = directory.path().join("second/provider/root.key");
        let second = InitializedVault::restore_backup_file(
            &current_archive,
            &second_database,
            &second_root,
            ArchiveKey::Recovery(&current_key),
            CredentialRestoreMode::Preserve,
            1_800_000_100_003,
        )?;
        assert_eq!(second.vault_id, report.vault_id);
        assert_eq!(second.recovery_epoch, 2);
        Ok(())
    }

    #[test]
    fn interrupted_restore_cannot_be_activated_by_generic_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        make_directory(database.parent().ok_or("database parent")?)?;
        make_directory(root.parent().ok_or("root parent")?)?;
        let staging = initialize_restore_staging(
            &database,
            &root,
            VaultId::random(),
            PortableVaultKeys {
                blind_index: KeyMaterial::generate()?,
                audit: KeyMaterial::generate()?,
                token_verifier: KeyMaterial::generate()?,
            },
            1_800_000_200_000,
        )?;
        assert_eq!(
            staging
                .store
                .installation()?
                .ok_or("missing installation")?
                .activation_state,
            ActivationState::Initializing
        );
        assert!(staging.store.activate_restored_initialization(2).is_err());
        assert_eq!(
            staging
                .store
                .installation()?
                .ok_or("missing installation")?
                .activation_state,
            ActivationState::Initializing
        );

        let startup = initialize_vault(&database, &root, 1_800_000_200_001);
        assert!(matches!(
            startup,
            Err(crate::InitializationError::Storage(
                StorageError::StateConflict
            ))
        ));
        assert_eq!(
            staging
                .store
                .installation()?
                .ok_or("missing installation")?
                .activation_state,
            ActivationState::Initializing
        );
        Ok(())
    }
}
