use std::path::Path;

use smcv_core::{MaintenanceJobId, ObjectId, ProtectedBytes};
use smcv_crypto::{
    KeyMaterial, ObjectKind, RecordContext, SealedRecord, create_root_key_file, open, seal,
};
use smcv_storage::{
    KekRotationJob, KeyKind, KeyState, RewrapItem, RewrapKind, RewrappedItem, RootRewrappedKey,
    RotationStage, WrappedKeyRecord,
};

use crate::{InitializedVault, VaultError, VaultOperationContext};

/// Bounded progress from resuming a durable KEK rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationProgress {
    /// Number of record batches committed in this invocation.
    pub batches_committed: u32,
    /// Whether the old KEK has been retired and normal service restored.
    pub completed: bool,
}

/// Successful root-provider replacement result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRotationOutcome {
    /// The replacement provider authenticated every live KEK after commit.
    pub replacement_verified: bool,
    /// The prior provider file was deliberately retained for owner custody.
    pub previous_provider_retained: bool,
}

impl InitializedVault {
    /// Installs a newly generated KEK as the active write key and creates a
    /// durable, resumable rewrap job.
    ///
    /// # Errors
    ///
    /// Returns a conflict when another maintenance rotation is active and
    /// fails closed for key-generation, audit, or storage errors.
    pub fn start_kek_rotation(
        &self,
        operation: VaultOperationContext,
    ) -> Result<KekRotationJob, VaultError> {
        if self
            .store
            .active_kek_rotation()
            .map_err(super::vault_core::map_storage)?
            .is_some()
        {
            return Err(VaultError::Conflict);
        }
        let (source_version, ()) = self
            .with_active_kek(|_| ())
            .ok_or(VaultError::Unavailable)?;
        let target_version = source_version.checked_add(1).ok_or(VaultError::Conflict)?;
        let target_key = KeyMaterial::generate().map_err(super::vault_core::map_crypto)?;
        let key_object_id = ObjectId::random();
        let context = RecordContext {
            vault_id: self.vault_id,
            installation_id: self.installation_id,
            object_kind: ObjectKind::WrappedKeyEncryptionKey,
            object_id: key_object_id,
            object_version: u64::from(target_version),
        };
        let wrapped = self
            .with_root_key(|root_key| seal(root_key, context, &target_key.to_protected_bytes()))
            .ok_or(VaultError::Unavailable)?
            .map_err(super::vault_core::map_crypto)?;
        let ciphertext: [u8; 48] = wrapped
            .ciphertext
            .try_into()
            .map_err(|_| VaultError::Integrity)?;
        let audit = self.build_audit("key:rotate-start", "key", Some(key_object_id), operation)?;
        let job = self
            .store
            .begin_kek_rotation(
                MaintenanceJobId::random(),
                source_version,
                &WrappedKeyRecord {
                    kind: KeyKind::KeyEncryption,
                    version: target_version,
                    object_id: key_object_id,
                    wrapping_kek_version: None,
                    nonce: wrapped.nonce,
                    ciphertext,
                },
                operation.now_unix_ms,
                &audit,
            )
            .map_err(super::vault_core::map_storage)?;
        self.install_active_kek(target_version, target_key)
            .map_err(|_| VaultError::Unavailable)?;
        Ok(job)
    }

    /// Performs at most `max_batches` rewrap batches, persisting a checkpoint
    /// after each batch so process interruption never requires starting over.
    /// Stage transitions do not consume the batch allowance.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid bounds, stale job state, authenticated
    /// decryption failure, or an atomic storage failure.
    pub fn resume_kek_rotation(
        &self,
        max_batches: u32,
        batch_size: u16,
        operation: VaultOperationContext,
    ) -> Result<RotationProgress, VaultError> {
        if max_batches == 0 || batch_size == 0 || batch_size > 256 {
            return Err(VaultError::InvalidInput);
        }
        let mut job = self
            .store
            .active_kek_rotation()
            .map_err(super::vault_core::map_storage)?
            .ok_or(VaultError::NotFound)?;
        let mut batches_committed = 0;
        loop {
            if job.stage == RotationStage::Finalize {
                let audit = self.build_audit("key:rotate-complete", "key", None, operation)?;
                self.store
                    .finish_kek_rotation(&job, operation.now_unix_ms, &audit)
                    .map_err(super::vault_core::map_storage)?;
                self.retire_kek(job.source_key_version)
                    .map_err(|_| VaultError::Unavailable)?;
                return Ok(RotationProgress {
                    batches_committed,
                    completed: true,
                });
            }
            if batches_committed == max_batches {
                return Ok(RotationProgress {
                    batches_committed,
                    completed: false,
                });
            }
            let source = self
                .store
                .next_rewrap_batch(&job, batch_size)
                .map_err(super::vault_core::map_storage)?;
            if source.is_empty() {
                job = self
                    .store
                    .advance_rotation_stage(&job, operation.now_unix_ms)
                    .map_err(super::vault_core::map_storage)?;
                continue;
            }
            let mut rewrapped = Vec::with_capacity(source.len());
            for item in source {
                rewrapped.push(self.rewrap_item(&job, item)?);
            }
            job = self
                .store
                .apply_rewrap_batch(&job, &rewrapped, operation.now_unix_ms)
                .map_err(super::vault_core::map_storage)?;
            batches_committed += 1;
        }
    }

    /// Starts and completes a KEK rotation with bounded durable batches.
    ///
    /// # Errors
    ///
    /// Returns an error if start, authentication, checkpointing, or final
    /// retirement fails.
    pub fn rotate_kek_to_completion(
        &self,
        operation: VaultOperationContext,
    ) -> Result<(), VaultError> {
        self.start_kek_rotation(operation)?;
        while !self.resume_kek_rotation(64, 64, operation)?.completed {}
        Ok(())
    }

    /// Creates a replacement local root provider, atomically reprotects every
    /// live KEK, verifies the replacement, and retains the prior provider file.
    ///
    /// The destination must not already exist and must be outside the database
    /// directory. If interruption occurs before the database commit, the old
    /// provider remains authoritative; after commit, the already durable new
    /// provider is authoritative. Neither provider file is removed.
    ///
    /// # Errors
    ///
    /// Returns a safe error for an unsafe/existing destination, concurrent
    /// maintenance, provider failure, failed authentication, or storage error.
    #[cfg(unix)]
    pub fn rotate_root_provider(
        &self,
        replacement_path: &Path,
        operation: VaultOperationContext,
    ) -> Result<RootRotationOutcome, VaultError> {
        super::initialization::prepare_parent(replacement_path)
            .map_err(|_| VaultError::Unavailable)?;
        super::initialization::ensure_separate_parents(self.store.path(), replacement_path)
            .map_err(|_| VaultError::Unavailable)?;
        if self
            .store
            .active_kek_rotation()
            .map_err(super::vault_core::map_storage)?
            .is_some()
        {
            return Err(VaultError::Conflict);
        }
        let replacement =
            create_root_key_file(replacement_path, self.vault_id, self.installation_id)
                .map_err(super::vault_core::map_crypto)?;
        let registry = self
            .store
            .registered_keys(KeyKind::KeyEncryption)
            .map_err(super::vault_core::map_storage)?;
        let mut updates = Vec::new();
        for registered in registry
            .iter()
            .filter(|registered| registered.state != KeyState::Retired)
        {
            updates.push(self.rewrap_root_key(&replacement, &registered.wrapped)?);
        }
        let audit = self.build_audit("root-provider:rotate", "vault", None, operation)?;
        self.store
            .replace_root_wrappings(
                MaintenanceJobId::random(),
                &updates,
                operation.now_unix_ms,
                &audit,
            )
            .map_err(super::vault_core::map_storage)?;
        verify_root_wrappings(self, &replacement)?;
        self.replace_root_key(replacement)
            .map_err(|_| VaultError::Unavailable)?;
        Ok(RootRotationOutcome {
            replacement_verified: true,
            previous_provider_retained: true,
        })
    }

    fn rewrap_root_key(
        &self,
        replacement: &KeyMaterial,
        source: &WrappedKeyRecord,
    ) -> Result<RootRewrappedKey, VaultError> {
        let context = RecordContext {
            vault_id: self.vault_id,
            installation_id: self.installation_id,
            object_kind: ObjectKind::WrappedKeyEncryptionKey,
            object_id: source.object_id,
            object_version: u64::from(source.version),
        };
        let wrapped = self
            .with_kek(source.version, |key| {
                seal(replacement, context, &key.to_protected_bytes())
            })
            .ok_or(VaultError::Integrity)?
            .map_err(super::vault_core::map_crypto)?;
        let target_wrapped_key: [u8; 48] = wrapped
            .ciphertext
            .try_into()
            .map_err(|_| VaultError::Integrity)?;
        let verified = open(
            replacement,
            context,
            &SealedRecord {
                nonce: wrapped.nonce,
                ciphertext: target_wrapped_key.to_vec(),
            },
        )
        .map_err(super::vault_core::map_crypto)?;
        ensure_key_width(&verified)?;
        Ok(RootRewrappedKey {
            version: source.version,
            object_id: source.object_id,
            source_nonce: source.nonce,
            source_wrapped_key: source.ciphertext,
            target_nonce: wrapped.nonce,
            target_wrapped_key,
        })
    }

    fn rewrap_item(
        &self,
        job: &KekRotationJob,
        source: RewrapItem,
    ) -> Result<RewrappedItem, VaultError> {
        let context = RecordContext {
            vault_id: self.vault_id,
            installation_id: self.installation_id,
            object_kind: wrapping_object_kind(source.kind),
            object_id: source.object_id,
            object_version: source.object_version,
        };
        let plaintext = self
            .with_kek(job.source_key_version, |source_key| {
                open(
                    source_key,
                    context,
                    &SealedRecord {
                        nonce: source.nonce,
                        ciphertext: source.wrapped_key.to_vec(),
                    },
                )
            })
            .ok_or(VaultError::Integrity)?
            .map_err(super::vault_core::map_crypto)?;
        ensure_key_width(&plaintext)?;
        let sealed = self
            .with_kek(job.target_key_version, |target_key| {
                seal(target_key, context, &plaintext)
            })
            .ok_or(VaultError::Integrity)?
            .map_err(super::vault_core::map_crypto)?;
        let wrapped_key = sealed
            .ciphertext
            .try_into()
            .map_err(|_| VaultError::Integrity)?;
        Ok(RewrappedItem {
            source,
            nonce: sealed.nonce,
            wrapped_key,
        })
    }
}

fn verify_root_wrappings(
    vault: &InitializedVault,
    replacement: &KeyMaterial,
) -> Result<(), VaultError> {
    let registry = vault
        .store
        .registered_keys(KeyKind::KeyEncryption)
        .map_err(super::vault_core::map_storage)?;
    for registered in registry
        .iter()
        .filter(|registered| registered.state != KeyState::Retired)
    {
        let record = &registered.wrapped;
        let plaintext = open(
            replacement,
            RecordContext {
                vault_id: vault.vault_id,
                installation_id: vault.installation_id,
                object_kind: ObjectKind::WrappedKeyEncryptionKey,
                object_id: record.object_id,
                object_version: u64::from(record.version),
            },
            &SealedRecord {
                nonce: record.nonce,
                ciphertext: record.ciphertext.to_vec(),
            },
        )
        .map_err(super::vault_core::map_crypto)?;
        ensure_key_width(&plaintext)?;
    }
    Ok(())
}

fn wrapping_object_kind(kind: RewrapKind) -> ObjectKind {
    match kind {
        RewrapKind::BlindIndexKey => ObjectKind::BlindIndexKey,
        RewrapKind::AuditKey => ObjectKind::AuditKey,
        RewrapKind::TokenVerifierKey => ObjectKind::VerifierKey,
        RewrapKind::NamespaceMetadata => ObjectKind::WrappedNamespaceMetadataKey,
        RewrapKind::SecretMetadata => ObjectKind::WrappedMetadataKey,
        RewrapKind::SecretVersion => ObjectKind::WrappedDataKey,
    }
}

fn ensure_key_width(value: &ProtectedBytes) -> Result<(), VaultError> {
    if value.len() != 32 {
        return Err(VaultError::Integrity);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use smcv_core::{ProtectedBytes, ProtectedString, RequestId};
    use smcv_crypto::CryptoError;
    use smcv_storage::{ActivationState, KeyKind, KeyState};
    use tempfile::TempDir;

    use crate::{InitializationError, MetadataInput, VaultOperationContext, initialize_vault};

    fn operation(now_unix_ms: i64) -> VaultOperationContext {
        VaultOperationContext {
            request_id: RequestId::random(),
            actor_principal_id: None,
            now_unix_ms,
        }
    }

    fn metadata(name: &str) -> MetadataInput {
        MetadataInput {
            name: ProtectedString::new(String::from(name)),
            description: None,
            username: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn root_provider_rotation_verifies_new_custody_and_retains_old_file() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let original = directory.path().join("provider-a/root.key");
        let replacement = directory.path().join("provider-b/root.key");
        let vault = initialize_vault(&database, &original, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("custody"), operation(1_800_000_000_001))
            .unwrap_or_else(|error| panic!("namespace must create: {error}"));
        let secret = vault
            .create_secret(
                namespace,
                &metadata("survives"),
                ProtectedBytes::new(b"root-rotation-value".to_vec()),
                operation(1_800_000_000_002),
            )
            .unwrap_or_else(|error| panic!("secret must create: {error}"));
        let outcome = vault
            .rotate_root_provider(&replacement, operation(1_800_000_000_003))
            .unwrap_or_else(|error| panic!("provider rotation must complete: {error}"));
        assert!(outcome.replacement_verified);
        assert!(outcome.previous_provider_retained);
        assert!(original.exists());
        assert!(replacement.exists());
        drop(vault);

        assert!(matches!(
            initialize_vault(&database, &original, 1_800_000_000_004),
            Err(InitializationError::Cryptography(CryptoError::Integrity))
        ));
        let reopened = initialize_vault(&database, &replacement, 1_800_000_000_005)
            .unwrap_or_else(|error| panic!("replacement provider must unlock: {error}"));
        assert_eq!(
            reopened
                .reveal_current_secret(secret.secret_id, operation(1_800_000_000_006))
                .unwrap_or_else(|error| panic!("secret must survive provider rotation: {error}"))
                .expose(),
            b"root-rotation-value"
        );
        reopened
            .verify_audit_chain()
            .unwrap_or_else(|error| panic!("provider rotation audit must authenticate: {error}"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "single end-to-end restart test keeps the rotation timeline explicit"
    )]
    fn rotation_resumes_across_restarts_and_supports_mixed_key_versions() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let root = directory.path().join("provider/root.key");
        let vault = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let namespace = vault
            .create_namespace(None, &metadata("rotation"), operation(1_800_000_000_001))
            .unwrap_or_else(|error| panic!("namespace must create: {error}"));
        let before = vault
            .create_secret(
                namespace,
                &metadata("before"),
                ProtectedBytes::new(b"old-version-one".to_vec()),
                operation(1_800_000_000_002),
            )
            .unwrap_or_else(|error| panic!("pre-rotation secret must create: {error}"));
        vault
            .update_secret(
                before.secret_id,
                1,
                1,
                ProtectedBytes::new(b"old-version-two".to_vec()),
                operation(1_800_000_000_003),
            )
            .unwrap_or_else(|error| panic!("pre-rotation version must append: {error}"));

        let job = vault
            .start_kek_rotation(operation(1_800_000_000_004))
            .unwrap_or_else(|error| panic!("rotation must start: {error}"));
        assert_eq!(job.source_key_version, 1);
        assert_eq!(job.target_key_version, 2);
        let during = vault
            .create_secret(
                namespace,
                &metadata("during"),
                ProtectedBytes::new(b"new-key-write".to_vec()),
                operation(1_800_000_000_005),
            )
            .unwrap_or_else(|error| panic!("mixed-version write must succeed: {error}"));
        assert_eq!(
            vault
                .store
                .encrypted_secret_version(during.secret_id, 1)
                .unwrap_or_else(|error| panic!("new record must load: {error}"))
                .kek_version,
            2
        );
        drop(vault);

        for attempt in 0..32_i64 {
            let vault = initialize_vault(
                &database,
                &root,
                1_800_000_000_010_i64.saturating_add(attempt),
            )
            .unwrap_or_else(|error| panic!("maintenance restart must recover: {error}"));
            let installation = vault
                .store
                .installation()
                .unwrap_or_else(|error| panic!("installation must load: {error}"))
                .unwrap_or_else(|| panic!("installation must exist"));
            if vault
                .store
                .active_kek_rotation()
                .unwrap_or_else(|error| panic!("job state must load: {error}"))
                .is_none()
            {
                assert_eq!(installation.activation_state, ActivationState::Ready);
                break;
            }
            assert_eq!(installation.activation_state, ActivationState::Maintenance);
            let old = vault
                .reveal_current_secret(
                    before.secret_id,
                    operation(1_800_000_001_000_i64.saturating_add(attempt)),
                )
                .unwrap_or_else(|error| panic!("old-key record must remain readable: {error}"));
            assert_eq!(old.expose(), b"old-version-two");
            vault
                .resume_kek_rotation(
                    1,
                    1,
                    operation(1_800_000_002_000_i64.saturating_add(attempt)),
                )
                .unwrap_or_else(|error| panic!("bounded rotation must resume: {error}"));
        }

        let vault = initialize_vault(&database, &root, 1_800_000_003_000)
            .unwrap_or_else(|error| panic!("completed vault must reopen: {error}"));
        assert!(
            vault
                .store
                .active_kek_rotation()
                .unwrap_or_else(|error| panic!("job state must load: {error}"))
                .is_none()
        );
        let keys = vault
            .store
            .registered_keys(KeyKind::KeyEncryption)
            .unwrap_or_else(|error| panic!("KEK registry must load: {error}"));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].state, KeyState::Retired);
        assert_eq!(keys[1].state, KeyState::Active);
        let state = vault
            .store
            .secret(before.secret_id)
            .unwrap_or_else(|error| panic!("secret must load: {error}"));
        assert_eq!(state.metadata.kek_version, 2);
        assert_eq!(
            vault
                .store
                .encrypted_secret_version(before.secret_id, 1)
                .unwrap_or_else(|error| panic!("first version must load: {error}"))
                .kek_version,
            2
        );
        assert_eq!(
            vault
                .store
                .encrypted_secret_version(before.secret_id, 2)
                .unwrap_or_else(|error| panic!("second version must load: {error}"))
                .kek_version,
            2
        );
        assert_eq!(
            vault
                .reveal_current_secret(before.secret_id, operation(1_800_000_003_001))
                .unwrap_or_else(|error| panic!("rotated secret must decrypt: {error}"))
                .expose(),
            b"old-version-two"
        );
        vault
            .verify_audit_chain()
            .unwrap_or_else(|error| panic!("rotation audit must authenticate: {error}"));
    }
}
