use core::fmt;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{Mutex, RwLock},
};

#[cfg(unix)]
use std::os::unix::{fs::DirBuilderExt, fs::PermissionsExt};

use smcv_core::{InstallationId, ObjectId, VaultId};
use smcv_crypto::{
    KeyMaterial, ObjectKind, RecordContext, SealedRecord, create_root_key_file, load_root_key_file,
    open, seal,
};
use smcv_storage::{
    ActivationState, BootstrapRecord, InstallationRecord, KeyKind, KeyState, RegisteredKey,
    SqliteStore, StorageError, WrappedKeyRecord,
};
use thiserror::Error;

/// Fully verified local vault state held only by the application layer.
pub struct InitializedVault {
    /// Persistence adapter containing ciphertext and operational metadata only.
    pub store: SqliteStore,
    /// Logical vault identity.
    pub vault_id: VaultId,
    /// Local installation identity.
    pub installation_id: InstallationId,
    root_key: RwLock<KeyMaterial>,
    key_ring: RwLock<KeyRing>,
    blind_index_key: KeyMaterial,
    audit_key: KeyMaterial,
    token_verifier_key: KeyMaterial,
    pub(crate) audit_gate: Mutex<()>,
    pub(crate) authorization_gate: RwLock<()>,
}

struct KeyRing {
    active_version: u32,
    keys: BTreeMap<u32, KeyMaterial>,
}

/// Vault-scoped security keys carried only inside authenticated portable
/// archive encryption. Source root keys and KEKs are intentionally absent.
pub(crate) struct PortableVaultKeys {
    pub(crate) blind_index: KeyMaterial,
    pub(crate) audit: KeyMaterial,
    pub(crate) token_verifier: KeyMaterial,
}

impl InitializedVault {
    pub(crate) fn with_active_kek<T>(
        &self,
        operation: impl FnOnce(&KeyMaterial) -> T,
    ) -> Option<(u32, T)> {
        let ring = self.key_ring.read().ok()?;
        let key = ring.keys.get(&ring.active_version)?;
        Some((ring.active_version, operation(key)))
    }

    pub(crate) fn with_kek<T>(
        &self,
        version: u32,
        operation: impl FnOnce(&KeyMaterial) -> T,
    ) -> Option<T> {
        let ring = self.key_ring.read().ok()?;
        ring.keys.get(&version).map(operation)
    }

    pub(crate) fn install_active_kek(
        &self,
        version: u32,
        key: KeyMaterial,
    ) -> Result<(), InitializationError> {
        let mut ring = self
            .key_ring
            .write()
            .map_err(|_| InitializationError::UnsafePath)?;
        if ring.keys.contains_key(&version) || version <= ring.active_version {
            return Err(StorageError::StateConflict.into());
        }
        ring.keys.insert(version, key);
        ring.active_version = version;
        Ok(())
    }

    pub(crate) fn retire_kek(&self, version: u32) -> Result<(), InitializationError> {
        let mut ring = self
            .key_ring
            .write()
            .map_err(|_| InitializationError::UnsafePath)?;
        if version == ring.active_version || ring.keys.remove(&version).is_none() {
            return Err(StorageError::StateConflict.into());
        }
        Ok(())
    }

    /// Returns the domain-separated blind-index key to the vault service.
    #[must_use]
    pub(crate) fn blind_index_key(&self) -> &KeyMaterial {
        &self.blind_index_key
    }

    /// Returns the audit commitment key to the audit service.
    #[must_use]
    pub(crate) fn audit_key(&self) -> &KeyMaterial {
        &self.audit_key
    }

    /// Returns the token verifier key to the identity service.
    #[must_use]
    #[allow(dead_code, reason = "used by the Phase 2 identity slice")]
    pub(crate) fn token_verifier_key(&self) -> &KeyMaterial {
        &self.token_verifier_key
    }

    pub(crate) fn with_root_key<T>(&self, operation: impl FnOnce(&KeyMaterial) -> T) -> Option<T> {
        let key = self.root_key.read().ok()?;
        Some(operation(&key))
    }

    pub(crate) fn replace_root_key(&self, key: KeyMaterial) -> Result<(), InitializationError> {
        let mut current = self
            .root_key
            .write()
            .map_err(|_| InitializationError::UnsafePath)?;
        *current = key;
        Ok(())
    }
}

impl fmt::Debug for InitializedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitializedVault")
            .field("store", &"[DATABASE]")
            .field("vault_id", &self.vault_id)
            .field("installation_id", &self.installation_id)
            .field("key_ring", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Safe initialization failures.
#[derive(Debug, Error)]
pub enum InitializationError {
    /// Data and root-key paths do not satisfy local custody requirements.
    #[error("vault paths or permissions are invalid")]
    UnsafePath,
    /// A database exists without its matching external root provider.
    #[error("vault root key is missing; explicit recovery or cleanup is required")]
    MissingRootKey,
    /// Cryptographic initialization or verification failed.
    #[error("vault key verification failed")]
    Cryptography(#[source] smcv_crypto::CryptoError),
    /// Durable initialization state could not be read or advanced.
    #[error("vault initialization storage operation failed")]
    Storage(#[source] StorageError),
}

impl From<smcv_crypto::CryptoError> for InitializationError {
    fn from(error: smcv_crypto::CryptoError) -> Self {
        Self::Cryptography(error)
    }
}

impl From<StorageError> for InitializationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Initializes or idempotently resumes a local vault and marks it ready only
/// after every wrapped key authenticates.
///
/// The root-key file and database must live in distinct restrictive
/// directories. An orphan root file from interruption before the database
/// bootstrap is safely reused; a database without its root key requires an
/// explicit recovery decision.
///
/// # Errors
///
/// Returns a safe error for insecure paths, missing custody, cryptographic
/// verification failure, or a durable state conflict.
#[cfg(unix)]
pub fn initialize_vault(
    database_path: &Path,
    root_key_path: &Path,
    now_unix_ms: i64,
) -> Result<InitializedVault, InitializationError> {
    prepare_parent(database_path)?;
    prepare_parent(root_key_path)?;
    ensure_separate_parents(database_path, root_key_path)?;

    let store = SqliteStore::open(database_path)?;
    let installation = store.installation()?;
    if installation.is_some() && !root_key_path.exists() {
        return Err(InitializationError::MissingRootKey);
    }

    let (vault_id, installation_id, root_key) = if root_key_path.exists() {
        let root = load_root_key_file(root_key_path)?;
        if let Some(existing) = installation
            && (existing.vault_id != root.vault_id
                || existing.installation_id != root.installation_id)
        {
            return Err(StorageError::StateConflict.into());
        }
        (root.vault_id, root.installation_id, root.key)
    } else {
        let vault_id = VaultId::random();
        let installation_id = InstallationId::random();
        let root_key = create_root_key_file(root_key_path, vault_id, installation_id)?;
        (vault_id, installation_id, root_key)
    };

    if store.installation()?.is_none() {
        let bootstrap = create_bootstrap(vault_id, installation_id, &root_key, now_unix_ms)?;
        let _disposition = store.begin_initialization(&bootstrap)?;
    }

    let mut state = store.installation()?.ok_or(StorageError::NotInitialized)?;
    let active_version = state.active_kek_version.unwrap_or(1);
    let mut key_encryption_keys = BTreeMap::new();
    let registered_keks = store.registered_keys(KeyKind::KeyEncryption)?;
    validate_kek_registry_state(&store, &state, &registered_keks)?;
    for registered in registered_keks {
        if registered.state != KeyState::Retired {
            let key = unwrap_key(
                &root_key,
                vault_id,
                installation_id,
                ObjectKind::WrappedKeyEncryptionKey,
                &registered.wrapped,
            )?;
            key_encryption_keys.insert(registered.wrapped.version, key);
        }
    }
    if !key_encryption_keys.contains_key(&active_version) {
        return Err(StorageError::StateConflict.into());
    }
    let blind_index_key = unwrap_registry_key(
        &store,
        &key_encryption_keys,
        vault_id,
        installation_id,
        KeyKind::BlindIndex,
        ObjectKind::BlindIndexKey,
    )?;
    let audit_key = unwrap_registry_key(
        &store,
        &key_encryption_keys,
        vault_id,
        installation_id,
        KeyKind::Audit,
        ObjectKind::AuditKey,
    )?;
    let token_verifier_key = unwrap_registry_key(
        &store,
        &key_encryption_keys,
        vault_id,
        installation_id,
        KeyKind::TokenVerifier,
        ObjectKind::VerifierKey,
    )?;

    if state.activation_state == ActivationState::Initializing {
        store.activate_initialization(1)?;
        state = store.installation()?.ok_or(StorageError::NotInitialized)?;
    }
    if !matches!(
        state.activation_state,
        ActivationState::Ready | ActivationState::Maintenance
    ) || state.active_kek_version != Some(active_version)
    {
        return Err(StorageError::StateConflict.into());
    }

    Ok(InitializedVault {
        store,
        vault_id,
        installation_id,
        root_key: RwLock::new(root_key),
        key_ring: RwLock::new(KeyRing {
            active_version,
            keys: key_encryption_keys,
        }),
        blind_index_key,
        audit_key,
        token_verifier_key,
        audit_gate: Mutex::new(()),
        authorization_gate: RwLock::new(()),
    })
}

/// Creates a fresh, non-ready destination installation around imported
/// vault-scoped keys. Logical rows must be imported and fully verified before
/// the caller activates the installation.
#[cfg(unix)]
pub(crate) fn initialize_restore_staging(
    database_path: &Path,
    root_key_path: &Path,
    vault_id: VaultId,
    keys: PortableVaultKeys,
    now_unix_ms: i64,
) -> Result<InitializedVault, InitializationError> {
    prepare_parent(database_path)?;
    prepare_parent(root_key_path)?;
    ensure_separate_parents(database_path, root_key_path)?;
    if database_path.exists() || root_key_path.exists() {
        return Err(StorageError::StateConflict.into());
    }

    let installation_id = InstallationId::random();
    let root_key = create_root_key_file(root_key_path, vault_id, installation_id)?;
    let kek = KeyMaterial::generate()?;
    let store = SqliteStore::open(database_path)?;
    let bootstrap = create_bootstrap_with_keys(
        vault_id,
        installation_id,
        &root_key,
        &kek,
        &keys,
        now_unix_ms,
    )?;
    let disposition = store.begin_restore_initialization(&bootstrap)?;
    if disposition != smcv_storage::InitializationDisposition::Begun {
        return Err(StorageError::StateConflict.into());
    }

    let mut key_encryption_keys = BTreeMap::new();
    key_encryption_keys.insert(1, kek);
    Ok(InitializedVault {
        store,
        vault_id,
        installation_id,
        root_key: RwLock::new(root_key),
        key_ring: RwLock::new(KeyRing {
            active_version: 1,
            keys: key_encryption_keys,
        }),
        blind_index_key: keys.blind_index,
        audit_key: keys.audit,
        token_verifier_key: keys.token_verifier,
        audit_gate: Mutex::new(()),
        authorization_gate: RwLock::new(()),
    })
}

fn validate_kek_registry_state(
    store: &SqliteStore,
    installation: &InstallationRecord,
    keys: &[RegisteredKey],
) -> Result<(), InitializationError> {
    let active_version = installation.active_kek_version.unwrap_or(1);
    let nonretired: Vec<&RegisteredKey> = keys
        .iter()
        .filter(|key| key.state != KeyState::Retired)
        .collect();
    match installation.activation_state {
        ActivationState::Initializing => {
            if installation.active_kek_version.is_some()
                || nonretired.len() != 1
                || nonretired[0].state != KeyState::Active
                || nonretired[0].wrapped.version != 1
            {
                return Err(StorageError::StateConflict.into());
            }
        }
        ActivationState::Ready => {
            if nonretired.len() != 1
                || nonretired[0].state != KeyState::Active
                || nonretired[0].wrapped.version != active_version
                || store.active_kek_rotation()?.is_some()
            {
                return Err(StorageError::StateConflict.into());
            }
        }
        ActivationState::Maintenance => {
            let job = store
                .active_kek_rotation()?
                .ok_or(StorageError::StateConflict)?;
            let active = nonretired.iter().any(|key| {
                key.state == KeyState::Active && key.wrapped.version == job.target_key_version
            });
            let retiring = nonretired.iter().any(|key| {
                key.state == KeyState::Retiring && key.wrapped.version == job.source_key_version
            });
            if nonretired.len() != 2
                || !active
                || !retiring
                || active_version != job.target_key_version
            {
                return Err(StorageError::StateConflict.into());
            }
        }
        ActivationState::Failed => return Err(StorageError::StateConflict.into()),
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn prepare_parent(path: &Path) -> Result<(), InitializationError> {
    let parent = path.parent().ok_or(InitializationError::UnsafePath)?;
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(parent)
            .map_err(|_| InitializationError::UnsafePath)?;
    }
    let metadata = parent
        .symlink_metadata()
        .map_err(|_| InitializationError::UnsafePath)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(InitializationError::UnsafePath);
    }
    Ok(())
}

pub(crate) fn ensure_separate_parents(
    database_path: &Path,
    root_key_path: &Path,
) -> Result<(), InitializationError> {
    let database_parent = database_path
        .parent()
        .ok_or(InitializationError::UnsafePath)?
        .canonicalize()
        .map_err(|_| InitializationError::UnsafePath)?;
    let key_parent = root_key_path
        .parent()
        .ok_or(InitializationError::UnsafePath)?
        .canonicalize()
        .map_err(|_| InitializationError::UnsafePath)?;
    if database_parent == key_parent || database_path == root_key_path {
        return Err(InitializationError::UnsafePath);
    }
    Ok(())
}

fn create_bootstrap(
    vault_id: VaultId,
    installation_id: InstallationId,
    root_key: &KeyMaterial,
    now_unix_ms: i64,
) -> Result<BootstrapRecord, InitializationError> {
    let kek = KeyMaterial::generate()?;
    let keys = PortableVaultKeys {
        blind_index: KeyMaterial::generate()?,
        audit: KeyMaterial::generate()?,
        token_verifier: KeyMaterial::generate()?,
    };
    create_bootstrap_with_keys(
        vault_id,
        installation_id,
        root_key,
        &kek,
        &keys,
        now_unix_ms,
    )
}

fn create_bootstrap_with_keys(
    vault_id: VaultId,
    installation_id: InstallationId,
    root_key: &KeyMaterial,
    kek: &KeyMaterial,
    keys: &PortableVaultKeys,
    now_unix_ms: i64,
) -> Result<BootstrapRecord, InitializationError> {
    Ok(BootstrapRecord {
        vault_id,
        installation_id,
        initialized_at_unix_ms: now_unix_ms,
        key_encryption_key: wrap_key(
            root_key,
            kek,
            vault_id,
            installation_id,
            KeyKind::KeyEncryption,
            ObjectKind::WrappedKeyEncryptionKey,
            None,
        )?,
        blind_index_key: wrap_key(
            kek,
            &keys.blind_index,
            vault_id,
            installation_id,
            KeyKind::BlindIndex,
            ObjectKind::BlindIndexKey,
            Some(1),
        )?,
        audit_key: wrap_key(
            kek,
            &keys.audit,
            vault_id,
            installation_id,
            KeyKind::Audit,
            ObjectKind::AuditKey,
            Some(1),
        )?,
        token_verifier_key: wrap_key(
            kek,
            &keys.token_verifier,
            vault_id,
            installation_id,
            KeyKind::TokenVerifier,
            ObjectKind::VerifierKey,
            Some(1),
        )?,
    })
}

fn wrap_key(
    wrapping_key: &KeyMaterial,
    plaintext_key: &KeyMaterial,
    vault_id: VaultId,
    installation_id: InstallationId,
    kind: KeyKind,
    object_kind: ObjectKind,
    wrapping_kek_version: Option<u32>,
) -> Result<WrappedKeyRecord, InitializationError> {
    let object_id = ObjectId::random();
    let context = RecordContext {
        vault_id,
        installation_id,
        object_kind,
        object_id,
        object_version: 1,
    };
    let plaintext = plaintext_key.to_protected_bytes();
    let sealed = seal(wrapping_key, context, &plaintext)?;
    let ciphertext: [u8; 48] = sealed
        .ciphertext
        .try_into()
        .map_err(|_| smcv_crypto::CryptoError::Integrity)?;
    Ok(WrappedKeyRecord {
        kind,
        version: 1,
        object_id,
        wrapping_kek_version,
        nonce: sealed.nonce,
        ciphertext,
    })
}

fn unwrap_registry_key(
    store: &SqliteStore,
    key_encryption_keys: &BTreeMap<u32, KeyMaterial>,
    vault_id: VaultId,
    installation_id: InstallationId,
    key_kind: KeyKind,
    object_kind: ObjectKind,
) -> Result<KeyMaterial, InitializationError> {
    let record = store.wrapped_key(key_kind, 1)?;
    let wrapping_version = record
        .wrapping_kek_version
        .ok_or(StorageError::StateConflict)?;
    let kek = key_encryption_keys
        .get(&wrapping_version)
        .ok_or(StorageError::StateConflict)?;
    unwrap_key(kek, vault_id, installation_id, object_kind, &record)
}

fn unwrap_key(
    wrapping_key: &KeyMaterial,
    vault_id: VaultId,
    installation_id: InstallationId,
    object_kind: ObjectKind,
    record: &WrappedKeyRecord,
) -> Result<KeyMaterial, InitializationError> {
    let context = RecordContext {
        vault_id,
        installation_id,
        object_kind,
        object_id: record.object_id,
        object_version: u64::from(record.version),
    };
    let sealed = SealedRecord {
        nonce: record.nonce,
        ciphertext: record.ciphertext.to_vec(),
    };
    Ok(KeyMaterial::from_protected(open(
        wrapping_key,
        context,
        &sealed,
    )?)?)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, symlink},
    };

    use smcv_core::{InstallationId, VaultId};
    use smcv_crypto::create_root_key_file;
    use smcv_storage::{ActivationState, SqliteStore};
    use tempfile::TempDir;

    use super::{InitializationError, create_bootstrap, initialize_vault};

    fn paths(directory: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
        (
            directory.path().join("database/vault.sqlite"),
            directory.path().join("provider/root.key"),
        )
    }

    #[test]
    fn complete_initialization_is_ready_and_restart_idempotent() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let (database, root) = paths(&directory);
        let first = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        let first_vault_id = first.vault_id;
        let first_installation_id = first.installation_id;
        let debug = format!("{first:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(root.to_string_lossy().as_ref()));
        drop(first);

        let reopened = initialize_vault(&database, &root, 1_800_000_000_001)
            .unwrap_or_else(|error| panic!("synthetic vault must reopen: {error}"));
        assert_eq!(reopened.vault_id, first_vault_id);
        assert_eq!(reopened.installation_id, first_installation_id);
        let installation = reopened
            .store
            .installation()
            .unwrap_or_else(|error| panic!("installation must load: {error}"))
            .unwrap_or_else(|| panic!("installation must exist"));
        assert_eq!(installation.activation_state, ActivationState::Ready);
    }

    #[test]
    fn root_only_interruption_resumes_without_replacing_identity() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let (database, root) = paths(&directory);
        let provider_directory = root
            .parent()
            .unwrap_or_else(|| panic!("provider path must have a parent"));
        let mut builder = fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(provider_directory)
            .unwrap_or_else(|error| panic!("provider directory must create: {error}"));
        let vault_id = VaultId::random();
        let installation_id = InstallationId::random();
        create_root_key_file(&root, vault_id, installation_id)
            .unwrap_or_else(|error| panic!("orphan synthetic root must create: {error}"));

        let resumed = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("root-only state must resume: {error}"));
        assert_eq!(resumed.vault_id, vault_id);
        assert_eq!(resumed.installation_id, installation_id);
    }

    #[test]
    fn unready_database_interruption_authenticates_keys_before_activation() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let (database, root) = paths(&directory);
        for parent in [database.parent(), root.parent()] {
            let parent = parent.unwrap_or_else(|| panic!("synthetic path must have parent"));
            let mut builder = fs::DirBuilder::new();
            builder
                .mode(0o700)
                .create(parent)
                .unwrap_or_else(|error| panic!("synthetic directory must create: {error}"));
        }
        let vault_id = VaultId::random();
        let installation_id = InstallationId::random();
        let root_key = create_root_key_file(&root, vault_id, installation_id)
            .unwrap_or_else(|error| panic!("synthetic root must create: {error}"));
        let bootstrap = create_bootstrap(vault_id, installation_id, &root_key, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic bootstrap must build: {error}"));
        let store = SqliteStore::open(&database)
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        store
            .begin_initialization(&bootstrap)
            .unwrap_or_else(|error| panic!("synthetic bootstrap must persist: {error}"));
        drop(store);
        drop(root_key);

        let resumed = initialize_vault(&database, &root, 1_800_000_000_001)
            .unwrap_or_else(|error| panic!("unready database must resume: {error}"));
        let installation = resumed
            .store
            .installation()
            .unwrap_or_else(|error| panic!("installation must load: {error}"))
            .unwrap_or_else(|| panic!("installation must exist"));
        assert_eq!(installation.activation_state, ActivationState::Ready);
    }

    #[test]
    fn initialized_database_without_provider_requires_recovery() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let (database, root) = paths(&directory);
        let initialized = initialize_vault(&database, &root, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        drop(initialized);
        fs::remove_file(&root)
            .unwrap_or_else(|error| panic!("synthetic provider must remove: {error}"));

        assert!(matches!(
            initialize_vault(&database, &root, 1_800_000_000_001),
            Err(InitializationError::MissingRootKey)
        ));
    }

    #[test]
    fn initialization_rejects_a_symlinked_custody_parent() {
        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("synthetic directory must open: {error}"));
        let database = directory.path().join("database/vault.sqlite");
        let actual_provider = directory.path().join("actual-provider");
        let mut builder = fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(&actual_provider)
            .unwrap_or_else(|error| panic!("provider directory must create: {error}"));
        let linked_provider = directory.path().join("provider");
        symlink(&actual_provider, &linked_provider)
            .unwrap_or_else(|error| panic!("provider symlink must create: {error}"));

        assert!(matches!(
            initialize_vault(
                &database,
                &linked_provider.join("root.key"),
                1_800_000_000_000
            ),
            Err(InitializationError::UnsafePath)
        ));
    }
}
