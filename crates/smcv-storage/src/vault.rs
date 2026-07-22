use core::fmt;

use rusqlite::{OptionalExtension, params};
use smcv_core::{InstallationId, ObjectId, VaultId};
use uuid::Uuid;

use crate::{SqliteStore, StorageError, StorageResult};

/// Durable installation activation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationState {
    /// Key and schema material is being assembled and verified.
    Initializing,
    /// All startup invariants were verified and protected services may open.
    Ready,
    /// A key or schema maintenance operation owns the vault.
    Maintenance,
    /// Initialization cannot safely resume without explicit cleanup.
    Failed,
}

impl ActivationState {
    fn parse(value: &str) -> StorageResult<Self> {
        match value {
            "initializing" => Ok(Self::Initializing),
            "ready" => Ok(Self::Ready),
            "maintenance" => Ok(Self::Maintenance),
            "failed" => Ok(Self::Failed),
            _ => Err(StorageError::InvalidData),
        }
    }
}

/// Safe installation state loaded without protected key bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallationRecord {
    /// Logical vault identity retained through disaster recovery.
    pub vault_id: VaultId,
    /// Concrete local installation identity.
    pub installation_id: InstallationId,
    /// Current recovery lineage epoch.
    pub recovery_epoch: u64,
    /// Current activation state.
    pub activation_state: ActivationState,
    /// Key version used for new writes once ready.
    pub active_kek_version: Option<u32>,
    /// Portable authorization/security semantics version.
    pub security_semantics_version: u32,
}

/// Closed key categories stored in the encrypted key registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyKind {
    /// Vault key-encryption key protected by the external root provider.
    KeyEncryption,
    /// Vault-scoped keyed exact-lookup key.
    BlindIndex,
    /// Vault-scoped audit commitment key.
    Audit,
    /// Vault-scoped application-token verifier key.
    TokenVerifier,
}

/// Lifecycle of one registered key version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    /// Used for new writes.
    Active,
    /// Still required for reads while rewrap is in progress.
    Retiring,
    /// No live record may require this key.
    Retired,
}

impl KeyState {
    fn parse(value: &str) -> StorageResult<Self> {
        match value {
            "active" => Ok(Self::Active),
            "retiring" => Ok(Self::Retiring),
            "retired" => Ok(Self::Retired),
            _ => Err(StorageError::InvalidData),
        }
    }
}

impl KeyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::KeyEncryption => "kek",
            Self::BlindIndex => "blind_index",
            Self::Audit => "audit",
            Self::TokenVerifier => "token_verifier",
        }
    }
}

/// Wrapped fixed-width key material safe for persistence adapters to transport.
pub struct WrappedKeyRecord {
    /// Key purpose.
    pub kind: KeyKind,
    /// Version within the key purpose.
    pub version: u32,
    /// Stable object identity bound into AEAD context.
    pub object_id: ObjectId,
    /// KEK version wrapping this record, or `None` when the root provider wraps it.
    pub wrapping_kek_version: Option<u32>,
    /// Public AEAD nonce.
    pub nonce: [u8; 24],
    /// Authenticated ciphertext containing exactly 32 key bytes and a tag.
    pub ciphertext: [u8; 48],
}

impl fmt::Debug for WrappedKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedKeyRecord")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("object_id", &self.object_id)
            .field("wrapping_kek_version", &self.wrapping_kek_version)
            .field("nonce", &"[PUBLIC NONCE]")
            .field("ciphertext", &"[CIPHERTEXT]")
            .finish()
    }
}

/// Registered wrapped key and lifecycle state.
pub struct RegisteredKey {
    /// Wrapped key material and context identifiers.
    pub wrapped: WrappedKeyRecord,
    /// Durable lifecycle state.
    pub state: KeyState,
}

/// All key records committed before an installation may become ready.
pub struct BootstrapRecord {
    /// Logical vault identity.
    pub vault_id: VaultId,
    /// Concrete installation identity.
    pub installation_id: InstallationId,
    /// Millisecond creation time supplied by an injectable application clock.
    pub initialized_at_unix_ms: i64,
    /// Version 1 KEK wrapped by the external root key.
    pub key_encryption_key: WrappedKeyRecord,
    /// Blind-index key wrapped by version 1 KEK.
    pub blind_index_key: WrappedKeyRecord,
    /// Audit commitment key wrapped by version 1 KEK.
    pub audit_key: WrappedKeyRecord,
    /// Token-verifier key wrapped by version 1 KEK.
    pub token_verifier_key: WrappedKeyRecord,
}

/// Idempotent result of beginning initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationDisposition {
    /// New installation and key records were committed.
    Begun,
    /// Matching initialization records already existed and remain resumable.
    Resumed,
    /// The matching installation was already ready.
    AlreadyReady,
}

impl SqliteStore {
    /// Loads safe installation state when a bootstrap row exists.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable storage or invalid durable field widths.
    pub fn installation(&self) -> StorageResult<Option<InstallationRecord>> {
        let connection = self.lock()?;
        connection
            .query_row(
                r"SELECT logical_vault_id, installation_id, recovery_epoch,
                          activation_state, active_kek_version, security_semantics_version
                   FROM smcv_installation_state WHERE singleton = 1",
                [],
                |row| {
                    let vault: Vec<u8> = row.get(0)?;
                    let installation: Vec<u8> = row.get(1)?;
                    let epoch: i64 = row.get(2)?;
                    let state: String = row.get(3)?;
                    let active: Option<i64> = row.get(4)?;
                    let semantics: i64 = row.get(5)?;
                    Ok((vault, installation, epoch, state, active, semantics))
                },
            )
            .optional()?
            .map(parse_installation)
            .transpose()
    }

    /// Atomically records all initialization material in an unready state.
    ///
    /// Matching retries are idempotent. Different identities or key material
    /// fail closed rather than replacing the existing bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error for a conflicting state or failed transaction.
    pub fn begin_initialization(
        &self,
        bootstrap: &BootstrapRecord,
    ) -> StorageResult<InitializationDisposition> {
        validate_bootstrap(bootstrap)?;
        if let Some(existing) = self.installation()? {
            if existing.vault_id != bootstrap.vault_id
                || existing.installation_id != bootstrap.installation_id
                || !self.bootstrap_matches(bootstrap)?
            {
                return Err(StorageError::StateConflict);
            }
            return match existing.activation_state {
                ActivationState::Initializing => Ok(InitializationDisposition::Resumed),
                ActivationState::Ready => Ok(InitializationDisposition::AlreadyReady),
                ActivationState::Maintenance | ActivationState::Failed => {
                    Err(StorageError::StateConflict)
                }
            };
        }

        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            r"INSERT INTO smcv_installation_state (
                   singleton, logical_vault_id, installation_id, recovery_epoch,
                   initialized_at_unix_ms, activation_state, active_kek_version,
                   security_semantics_version
               ) VALUES (1, ?1, ?2, 0, ?3, 'initializing', NULL, 1)",
            params![
                bootstrap.vault_id.as_bytes(),
                bootstrap.installation_id.as_bytes(),
                bootstrap.initialized_at_unix_ms,
            ],
        )?;
        for key in [
            &bootstrap.key_encryption_key,
            &bootstrap.blind_index_key,
            &bootstrap.audit_key,
            &bootstrap.token_verifier_key,
        ] {
            insert_key(&transaction, key, bootstrap.initialized_at_unix_ms)?;
        }
        transaction.commit()?;
        Ok(InitializationDisposition::Begun)
    }

    fn bootstrap_matches(&self, bootstrap: &BootstrapRecord) -> StorageResult<bool> {
        for expected in [
            &bootstrap.key_encryption_key,
            &bootstrap.blind_index_key,
            &bootstrap.audit_key,
            &bootstrap.token_verifier_key,
        ] {
            let actual = self.wrapped_key(expected.kind, expected.version)?;
            if actual.object_id != expected.object_id
                || actual.wrapping_kek_version != expected.wrapping_kek_version
                || actual.nonce != expected.nonce
                || actual.ciphertext != expected.ciphertext
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Loads one wrapped key record by exact kind and version.
    ///
    /// # Errors
    ///
    /// Returns an error when storage is unavailable, the record is absent, or
    /// fixed-width protected fields are invalid.
    pub fn wrapped_key(&self, kind: KeyKind, version: u32) -> StorageResult<WrappedKeyRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT object_id, wrapping_kek_version, nonce, wrapped_key
                   FROM smcv_key_registry WHERE key_kind = ?1 AND key_version = ?2",
                params![kind.as_str(), version],
                |row| {
                    let object_id: Vec<u8> = row.get(0)?;
                    let wrapping_version: Option<i64> = row.get(1)?;
                    let nonce: Vec<u8> = row.get(2)?;
                    let ciphertext: Vec<u8> = row.get(3)?;
                    Ok((object_id, wrapping_version, nonce, ciphertext))
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_wrapped_key(kind, version, row)
    }

    /// Lists registered versions of one key kind in ascending order.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable storage or invalid fixed-width data.
    pub fn registered_keys(&self, kind: KeyKind) -> StorageResult<Vec<RegisteredKey>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r"SELECT key_version, object_id, wrapping_kek_version, nonce, wrapped_key, state
               FROM smcv_key_registry WHERE key_kind = ?1 ORDER BY key_version",
        )?;
        let rows = statement.query_map([kind.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut keys = Vec::new();
        for row in rows {
            let (version, object_id, wrapping, nonce, ciphertext, state) = row?;
            let version = u32::try_from(version).map_err(|_| StorageError::InvalidData)?;
            keys.push(RegisteredKey {
                wrapped: parse_wrapped_key(
                    kind,
                    version,
                    (object_id, wrapping, nonce, ciphertext),
                )?,
                state: KeyState::parse(&state)?,
            });
        }
        Ok(keys)
    }

    /// Marks a fully verified initialization ready as its last durable step.
    ///
    /// # Errors
    ///
    /// Returns an error unless all required active key records exist and the
    /// installation is initializing (or already ready at the same version).
    pub fn activate_initialization(&self, kek_version: u32) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let state: Option<String> = transaction
            .query_row(
                "SELECT activation_state FROM smcv_installation_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let state = state.ok_or(StorageError::NotInitialized)?;
        if state == "ready" {
            let active: i64 = transaction.query_row(
                "SELECT active_kek_version FROM smcv_installation_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            return if active == i64::from(kek_version) {
                Ok(())
            } else {
                Err(StorageError::StateConflict)
            };
        }
        if state != "initializing" {
            return Err(StorageError::StateConflict);
        }
        let required: i64 = transaction.query_row(
            r"SELECT count(*) FROM smcv_key_registry
               WHERE state = 'active' AND (
                   (key_kind = 'kek' AND key_version = ?1) OR
                   (key_kind IN ('blind_index', 'audit', 'token_verifier')
                    AND wrapping_kek_version = ?1)
               )",
            [kek_version],
            |row| row.get(0),
        )?;
        if required != 4 {
            return Err(StorageError::StateConflict);
        }
        let changed = transaction.execute(
            r"UPDATE smcv_installation_state
               SET activation_state = 'ready', active_kek_version = ?1
               WHERE singleton = 1 AND activation_state = 'initializing'",
            [kek_version],
        )?;
        if changed != 1 {
            return Err(StorageError::StateConflict);
        }
        transaction.commit()?;
        Ok(())
    }
}

fn validate_bootstrap(bootstrap: &BootstrapRecord) -> StorageResult<()> {
    if bootstrap.key_encryption_key.kind != KeyKind::KeyEncryption
        || bootstrap.key_encryption_key.version != 1
        || bootstrap.key_encryption_key.wrapping_kek_version.is_some()
        || bootstrap.blind_index_key.kind != KeyKind::BlindIndex
        || bootstrap.audit_key.kind != KeyKind::Audit
        || bootstrap.token_verifier_key.kind != KeyKind::TokenVerifier
    {
        return Err(StorageError::StateConflict);
    }
    for key in [
        &bootstrap.blind_index_key,
        &bootstrap.audit_key,
        &bootstrap.token_verifier_key,
    ] {
        if key.version != 1 || key.wrapping_kek_version != Some(1) {
            return Err(StorageError::StateConflict);
        }
    }
    Ok(())
}

pub(super) fn insert_key(
    transaction: &rusqlite::Transaction<'_>,
    key: &WrappedKeyRecord,
    created_at_unix_ms: i64,
) -> StorageResult<()> {
    transaction.execute(
        r"INSERT INTO smcv_key_registry (
               key_kind, key_version, object_id, wrapping_kek_version, nonce,
               wrapped_key, state, created_at_unix_ms
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7)",
        params![
            key.kind.as_str(),
            key.version,
            key.object_id.as_bytes(),
            key.wrapping_kek_version,
            key.nonce.as_slice(),
            key.ciphertext.as_slice(),
            created_at_unix_ms,
        ],
    )?;
    Ok(())
}

type RawWrappedKey = (Vec<u8>, Option<i64>, Vec<u8>, Vec<u8>);

fn parse_wrapped_key(
    kind: KeyKind,
    version: u32,
    row: RawWrappedKey,
) -> StorageResult<WrappedKeyRecord> {
    let (object_id, wrapping_version, nonce, ciphertext) = row;
    let object_id = parse_uuid(&object_id)?;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| StorageError::InvalidData)?;
    let ciphertext: [u8; 48] = ciphertext
        .try_into()
        .map_err(|_| StorageError::InvalidData)?;
    let wrapping_kek_version = wrapping_version
        .map(|value| u32::try_from(value).map_err(|_| StorageError::InvalidData))
        .transpose()?;
    Ok(WrappedKeyRecord {
        kind,
        version,
        object_id: ObjectId::from_uuid(object_id),
        wrapping_kek_version,
        nonce,
        ciphertext,
    })
}

type RawInstallation = (Vec<u8>, Vec<u8>, i64, String, Option<i64>, i64);

fn parse_installation(row: RawInstallation) -> StorageResult<InstallationRecord> {
    let (vault, installation, epoch, state, active, semantics) = row;
    Ok(InstallationRecord {
        vault_id: VaultId::from_uuid(parse_uuid(&vault)?),
        installation_id: InstallationId::from_uuid(parse_uuid(&installation)?),
        recovery_epoch: u64::try_from(epoch).map_err(|_| StorageError::InvalidData)?,
        activation_state: ActivationState::parse(&state)?,
        active_kek_version: active
            .map(|value| u32::try_from(value).map_err(|_| StorageError::InvalidData))
            .transpose()?,
        security_semantics_version: u32::try_from(semantics)
            .map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_uuid(bytes: &[u8]) -> StorageResult<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| StorageError::InvalidData)
}

#[cfg(test)]
mod tests {
    use smcv_core::{InstallationId, ObjectId, VaultId};
    use tempfile::TempDir;

    use super::{
        ActivationState, BootstrapRecord, InitializationDisposition, KeyKind, WrappedKeyRecord,
    };
    use crate::{SqliteStore, StorageError};

    fn key(kind: KeyKind, byte: u8, wrapping: Option<u32>) -> WrappedKeyRecord {
        WrappedKeyRecord {
            kind,
            version: 1,
            object_id: ObjectId::random(),
            wrapping_kek_version: wrapping,
            nonce: [byte; 24],
            ciphertext: [byte; 48],
        }
    }

    fn bootstrap() -> BootstrapRecord {
        BootstrapRecord {
            vault_id: VaultId::random(),
            installation_id: InstallationId::random(),
            initialized_at_unix_ms: 1_800_000_000_000,
            key_encryption_key: key(KeyKind::KeyEncryption, 1, None),
            blind_index_key: key(KeyKind::BlindIndex, 2, Some(1)),
            audit_key: key(KeyKind::Audit, 3, Some(1)),
            token_verifier_key: key(KeyKind::TokenVerifier, 4, Some(1)),
        }
    }

    #[test]
    fn initialization_is_unready_idempotent_and_activates_last() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let store = SqliteStore::open(directory.path().join("vault.sqlite"))
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        let bootstrap = bootstrap();

        assert_eq!(
            store
                .begin_initialization(&bootstrap)
                .unwrap_or_else(|error| panic!("bootstrap must begin: {error:?}")),
            InitializationDisposition::Begun
        );
        let installation = store
            .installation()
            .unwrap_or_else(|error| panic!("installation must load: {error}"))
            .unwrap_or_else(|| panic!("installation must exist"));
        assert_eq!(installation.activation_state, ActivationState::Initializing);
        assert_eq!(installation.active_kek_version, None);
        assert_eq!(
            store
                .begin_initialization(&bootstrap)
                .unwrap_or_else(|error| panic!("matching bootstrap must resume: {error}")),
            InitializationDisposition::Resumed
        );

        store
            .activate_initialization(1)
            .unwrap_or_else(|error| panic!("verified bootstrap must activate: {error}"));
        let ready = store
            .installation()
            .unwrap_or_else(|error| panic!("ready installation must load: {error}"))
            .unwrap_or_else(|| panic!("ready installation must exist"));
        assert_eq!(ready.activation_state, ActivationState::Ready);
        assert_eq!(ready.active_kek_version, Some(1));
        assert_eq!(
            store
                .begin_initialization(&bootstrap)
                .unwrap_or_else(|error| panic!("ready bootstrap retry must work: {error}")),
            InitializationDisposition::AlreadyReady
        );
    }

    #[test]
    fn initialization_rejects_identity_or_key_substitution() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic temp directory must open: {error}"));
        let store = SqliteStore::open(directory.path().join("vault.sqlite"))
            .unwrap_or_else(|error| panic!("synthetic database must open: {error}"));
        let mut bootstrap = bootstrap();
        store
            .begin_initialization(&bootstrap)
            .unwrap_or_else(|error| panic!("bootstrap must begin: {error:?}"));

        bootstrap.audit_key.ciphertext[0] ^= 1;
        assert!(matches!(
            store.begin_initialization(&bootstrap),
            Err(StorageError::StateConflict)
        ));
        bootstrap.audit_key.ciphertext[0] ^= 1;
        bootstrap.installation_id = InstallationId::random();
        assert!(matches!(
            store.begin_initialization(&bootstrap),
            Err(StorageError::StateConflict)
        ));
    }
}
