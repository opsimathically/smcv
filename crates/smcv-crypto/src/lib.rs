#![forbid(unsafe_code)]
#![doc = "Cryptographic adapters and canonical envelope context for SMCV."]
#![cfg_attr(test, allow(clippy::panic))]

use core::fmt;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Key, KeyInit, Payload},
};
use smcv_core::{
    AuditEventId, InstallationId, NamespaceId, ObjectId, PrincipalId, ProtectedBytes,
    ProtectedString, RequestId, VaultId,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Size of an SMCV symmetric key in bytes.
pub const KEY_LENGTH: usize = 32;
/// Size of an XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LENGTH: usize = 24;
/// Current record-envelope version.
pub const ENVELOPE_VERSION: u16 = 1;
/// Random secret material in an application credential.
pub const TOKEN_SECRET_LENGTH: usize = 32;
/// Non-secret lookup material in an application credential.
pub const TOKEN_LOOKUP_LENGTH: usize = 12;
/// Non-secret lookup material in a browser session token.
pub const SESSION_LOOKUP_LENGTH: usize = 16;
/// Random secret material in browser session and CSRF tokens.
pub const SESSION_SECRET_LENGTH: usize = 32;
/// Length of a version 1 local root-key file.
pub const ROOT_KEY_FILE_LENGTH: usize = 72;

const AAD_DOMAIN: &[u8; 8] = b"SMCV-AAD";
const ROOT_KEY_MAGIC: &[u8; 8] = b"SMCVKEY1";

/// Cryptographic failures with no protected diagnostic material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CryptoError {
    /// The operating system did not provide random bytes.
    #[error("cryptographic randomness unavailable")]
    Randomness,
    /// Ciphertext or its bound context did not authenticate.
    #[error("protected data integrity check failed")]
    Integrity,
    /// A credential does not have the supported bounded encoding.
    #[error("credential is invalid")]
    InvalidCredential,
    /// A key provider is absent, insecure, corrupt, or unavailable.
    #[error("root key provider is unavailable")]
    KeyProvider,
    /// Protected input violates a cryptographic boundary limit.
    #[error("protected input is invalid")]
    InvalidProtectedInput,
}

/// A result from the cryptographic adapter.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Identifies the domain object type bound into associated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectKind {
    /// An immutable secret version.
    SecretVersion = 1,
    /// Protected secret metadata.
    SecretMetadata = 2,
    /// A wrapped data-encryption key.
    WrappedDataKey = 3,
    /// A protected vault-scoped verifier key.
    VerifierKey = 4,
    /// A metadata-specific DEK wrapped by a vault KEK.
    WrappedMetadataKey = 5,
    /// A vault KEK wrapped by an external root key.
    WrappedKeyEncryptionKey = 6,
    /// A vault-scoped blind-index key wrapped by a KEK.
    BlindIndexKey = 7,
    /// A vault-scoped audit commitment key wrapped by a KEK.
    AuditKey = 8,
    /// Protected namespace metadata.
    NamespaceMetadata = 9,
    /// A namespace metadata DEK wrapped by a vault KEK.
    WrappedNamespaceMetadataKey = 10,
    /// Protected service-identity metadata.
    ServiceIdentityMetadata = 11,
    /// Service-identity metadata DEK wrapped by a vault KEK.
    WrappedServiceIdentityMetadataKey = 12,
    /// Protected policy display metadata.
    PolicyMetadata = 13,
    /// Policy metadata DEK wrapped by a vault KEK.
    WrappedPolicyMetadataKey = 14,
}

/// Stable context authenticated with an encrypted record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordContext {
    /// Logical vault identity.
    pub vault_id: VaultId,
    /// Concrete installation identity.
    pub installation_id: InstallationId,
    /// Domain object kind.
    pub object_kind: ObjectKind,
    /// Opaque object identity.
    pub object_id: ObjectId,
    /// Immutable object version.
    pub object_version: u64,
}

impl RecordContext {
    /// Encodes unambiguous, fixed-width associated data.
    #[must_use]
    pub fn encode_aad(self) -> [u8; 67] {
        let mut aad = [0_u8; 67];
        aad[0..8].copy_from_slice(AAD_DOMAIN);
        aad[8..10].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        aad[10..26].copy_from_slice(self.vault_id.as_bytes());
        aad[26..42].copy_from_slice(self.installation_id.as_bytes());
        aad[42] = self.object_kind as u8;
        aad[43..59].copy_from_slice(self.object_id.as_bytes());
        aad[59..67].copy_from_slice(&self.object_version.to_be_bytes());
        aad
    }
}

/// Zeroizing 256-bit symmetric key material.
pub struct KeyMaterial(Zeroizing<[u8; KEY_LENGTH]>);

impl KeyMaterial {
    /// Takes ownership of an existing key.
    #[must_use]
    pub fn new(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generates a new key using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system cannot provide random bytes.
    pub fn generate() -> CryptoResult<Self> {
        let mut bytes = [0_u8; KEY_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::Randomness)?;
        Ok(Self::new(bytes))
    }

    /// Converts a protected fixed-width plaintext into key material.
    ///
    /// # Errors
    ///
    /// Returns an integrity error when the protected value is not exactly one
    /// 256-bit key.
    pub fn from_protected(bytes: ProtectedBytes) -> CryptoResult<Self> {
        let key: [u8; KEY_LENGTH] = bytes
            .expose()
            .try_into()
            .map_err(|_| CryptoError::Integrity)?;
        drop(bytes);
        Ok(Self::new(key))
    }

    /// Copies the key into an explicitly protected, zeroizing transport value.
    ///
    /// This is intended only for wrapping or provider persistence boundaries.
    #[must_use]
    pub fn to_protected_bytes(&self) -> ProtectedBytes {
        ProtectedBytes::new(self.expose().to_vec())
    }

    fn expose(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyMaterial([REDACTED])")
    }
}

/// Root-key material loaded with its bound vault and installation identities.
pub struct RootKeyRecord {
    /// Logical vault identity embedded in the provider file.
    pub vault_id: VaultId,
    /// Installation identity embedded in the provider file.
    pub installation_id: InstallationId,
    /// Root key material, zeroized when dropped.
    pub key: KeyMaterial,
}

impl fmt::Debug for RootKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootKeyRecord")
            .field("vault_id", &self.vault_id)
            .field("installation_id", &self.installation_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Creates a new restrictive root-key file without replacing an existing path.
///
/// The file binds its key to one logical vault and concrete installation.
/// Callers must store it outside the database directory and exclude it from
/// portable archives.
///
/// # Errors
///
/// Returns an error if randomness, restrictive creation, writing, or durable
/// synchronization fails, or if the destination already exists.
#[cfg(unix)]
pub fn create_root_key_file(
    path: &Path,
    vault_id: VaultId,
    installation_id: InstallationId,
) -> CryptoResult<KeyMaterial> {
    let key = KeyMaterial::generate()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).map_err(|_| CryptoError::KeyProvider)?;
    file.write_all(ROOT_KEY_MAGIC)
        .and_then(|()| file.write_all(vault_id.as_bytes()))
        .and_then(|()| file.write_all(installation_id.as_bytes()))
        .and_then(|()| file.write_all(key.expose()))
        .and_then(|()| file.sync_all())
        .map_err(|_| CryptoError::KeyProvider)?;
    sync_parent(path)?;
    Ok(key)
}

/// Loads a restrictive root-key file and validates its fixed framing.
///
/// # Errors
///
/// Returns an error when the file is not regular, has group/other permission
/// bits, has invalid framing, cannot be read, or cannot be bound to UUIDs.
#[cfg(unix)]
pub fn load_root_key_file(path: &Path) -> CryptoResult<RootKeyRecord> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| CryptoError::KeyProvider)?;
    if !metadata.file_type().is_file()
        || metadata.len() != ROOT_KEY_FILE_LENGTH as u64
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CryptoError::KeyProvider);
    }
    let mut bytes = Zeroizing::new([0_u8; ROOT_KEY_FILE_LENGTH]);
    File::open(path)
        .and_then(|mut file| file.read_exact(bytes.as_mut()))
        .map_err(|_| CryptoError::KeyProvider)?;
    if &bytes[0..8] != ROOT_KEY_MAGIC {
        return Err(CryptoError::KeyProvider);
    }
    let vault_uuid = uuid::Uuid::from_slice(&bytes[8..24]).map_err(|_| CryptoError::KeyProvider)?;
    let installation_uuid =
        uuid::Uuid::from_slice(&bytes[24..40]).map_err(|_| CryptoError::KeyProvider)?;
    let mut key = [0_u8; KEY_LENGTH];
    key.copy_from_slice(&bytes[40..72]);
    Ok(RootKeyRecord {
        vault_id: VaultId::from_uuid(vault_uuid),
        installation_id: InstallationId::from_uuid(installation_uuid),
        key: KeyMaterial::new(key),
    })
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> CryptoResult<()> {
    let parent = path.parent().ok_or(CryptoError::KeyProvider)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CryptoError::KeyProvider)
}

/// AEAD output containing public nonce and authenticated ciphertext.
pub struct SealedRecord {
    /// Fresh nonce used once under the supplied key.
    pub nonce: [u8; NONCE_LENGTH],
    /// Ciphertext with the authentication tag appended by the AEAD.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedRecord")
            .field("nonce", &"[PUBLIC NONCE]")
            .field("ciphertext", &"[CIPHERTEXT]")
            .finish()
    }
}

/// Constant-time application credential verifier stored by the server.
pub struct TokenVerifier([u8; 32]);

impl TokenVerifier {
    /// Imports a verifier from its fixed-width durable representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width durable verifier representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Constant-time browser session or CSRF verifier stored by the server.
pub struct SessionVerifier([u8; 32]);

impl SessionVerifier {
    /// Imports a verifier from its fixed-width durable representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width durable verifier representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionVerifier([REDACTED])")
    }
}

/// Keyed exact-match index that reveals no human-readable name.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlindIndex([u8; 32]);

impl BlindIndex {
    /// Imports an index from its durable fixed-width representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width durable representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical safe fields committed into one append-oriented audit event.
pub struct AuditCommitmentInput<'a> {
    /// Canonical audit commitment format version.
    pub commitment_version: u8,
    /// Previous event commitment, or zeros for the first local event.
    pub previous: [u8; 32],
    /// Monotonic local event sequence.
    pub sequence: u64,
    /// Random event identifier.
    pub event_id: AuditEventId,
    /// Installation producing this segment.
    pub installation_id: InstallationId,
    /// Recovery epoch producing this segment.
    pub recovery_epoch: u64,
    /// Event wall-clock timestamp.
    pub occurred_at_unix_ms: i64,
    /// Correlated request identifier.
    pub request_id: RequestId,
    /// Acting principal when one exists.
    pub actor_principal_id: Option<PrincipalId>,
    /// Authentication context category for version 2 events.
    pub credential_kind: Option<&'a str>,
    /// Session or application-credential reference for version 2 events.
    pub credential_id: Option<ObjectId>,
    /// Closed action vocabulary.
    pub action: &'a str,
    /// Closed target-kind vocabulary.
    pub target_kind: &'a str,
    /// Opaque target when one exists.
    pub target_id: Option<ObjectId>,
    /// Closed outcome vocabulary.
    pub outcome: &'a str,
}

/// Keyed commitment linking one durable audit event to its predecessor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuditCommitment([u8; 32]);

impl AuditCommitment {
    /// Imports a fixed-width durable commitment.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width durable representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuditCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditCommitment([COMMITMENT])")
    }
}

/// Keyed commitment over a canonical integrity-sensitive database state.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StateCommitment([u8; 32]);

impl StateCommitment {
    /// Returns the fixed-width durable representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StateCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateCommitment([COMMITMENT])")
    }
}

/// Commits a bounded canonical encoding of clear database state using a
/// separate domain from audit chaining and exact indexes.
///
/// # Errors
///
/// Returns invalid input for an empty encoding, an encoding larger than 4 KiB,
/// or key initialization failure.
pub fn state_commitment(
    commitment_key: &KeyMaterial,
    canonical_state: &[u8],
) -> CryptoResult<StateCommitment> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    if canonical_state.is_empty() || canonical_state.len() > 4096 {
        return Err(CryptoError::InvalidProtectedInput);
    }
    let length =
        u16::try_from(canonical_state.len()).map_err(|_| CryptoError::InvalidProtectedInput)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(commitment_key.expose())
        .map_err(|_| CryptoError::InvalidProtectedInput)?;
    mac.update(b"SMCV-STATE-COMMITMENT\0v1\0");
    mac.update(&length.to_be_bytes());
    mac.update(canonical_state);
    let mut commitment = [0_u8; 32];
    commitment.copy_from_slice(&mac.finalize().into_bytes());
    Ok(StateCommitment(commitment))
}

/// Computes the domain-separated commitment for one audit event.
///
/// # Errors
///
/// Returns an error if a string field is empty, exceeds its fixed limit, or
/// the commitment key cannot initialize.
pub fn audit_commitment(
    audit_key: &KeyMaterial,
    input: &AuditCommitmentInput<'_>,
) -> CryptoResult<AuditCommitment> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let action_length = bounded_audit_text(input.action, 64)?;
    let kind_length = bounded_audit_text(input.target_kind, 32)?;
    let outcome_length = bounded_audit_text(input.outcome, 16)?;
    if !matches!(input.commitment_version, 1 | 2)
        || (input.commitment_version == 1
            && (input.credential_kind.is_some() || input.credential_id.is_some()))
        || input.credential_kind.is_some() != input.credential_id.is_some()
    {
        return Err(CryptoError::InvalidProtectedInput);
    }
    let credential_kind_length = input
        .credential_kind
        .map(|value| bounded_audit_text(value, 16))
        .transpose()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(audit_key.expose())
        .map_err(|_| CryptoError::InvalidProtectedInput)?;
    if input.commitment_version == 1 {
        mac.update(b"SMCV-AUDIT-COMMITMENT\0v1\0");
    } else {
        mac.update(b"SMCV-AUDIT-COMMITMENT\0v2\0");
    }
    mac.update(&input.previous);
    mac.update(&input.sequence.to_be_bytes());
    mac.update(input.event_id.as_bytes());
    mac.update(input.installation_id.as_bytes());
    mac.update(&input.recovery_epoch.to_be_bytes());
    mac.update(&input.occurred_at_unix_ms.to_be_bytes());
    mac.update(input.request_id.as_bytes());
    update_optional_id(&mut mac, input.actor_principal_id.map(PrincipalId::as_uuid));
    if input.commitment_version == 2 {
        if let (Some(kind), Some(length)) = (input.credential_kind, credential_kind_length) {
            mac.update(&[1]);
            mac.update(&length.to_be_bytes());
            mac.update(kind.as_bytes());
            update_optional_id(&mut mac, input.credential_id.map(ObjectId::as_uuid));
        } else {
            mac.update(&[0]);
        }
    }
    mac.update(&action_length.to_be_bytes());
    mac.update(input.action.as_bytes());
    mac.update(&kind_length.to_be_bytes());
    mac.update(input.target_kind.as_bytes());
    update_optional_id(&mut mac, input.target_id.map(ObjectId::as_uuid));
    mac.update(&outcome_length.to_be_bytes());
    mac.update(input.outcome.as_bytes());
    let mut commitment = [0_u8; 32];
    commitment.copy_from_slice(&mac.finalize().into_bytes());
    Ok(AuditCommitment(commitment))
}

fn bounded_audit_text(value: &str, max: usize) -> CryptoResult<u16> {
    if value.is_empty() || value.len() > max || !value.is_ascii() {
        return Err(CryptoError::InvalidProtectedInput);
    }
    u16::try_from(value.len()).map_err(|_| CryptoError::InvalidProtectedInput)
}

fn update_optional_id(mac: &mut hmac::Hmac<sha2::Sha256>, value: Option<uuid::Uuid>) {
    use hmac::Mac as _;

    if let Some(value) = value {
        mac.update(&[1]);
        mac.update(value.as_bytes());
    } else {
        mac.update(&[0]);
    }
}

impl fmt::Debug for BlindIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlindIndex([KEYED INDEX])")
    }
}

/// Computes a case-sensitive NFC exact-match index scoped to one namespace.
///
/// # Errors
///
/// Returns an error for an empty name, more than 256 UTF-8 bytes after NFC
/// normalization, control characters, or a verifier-key initialization error.
pub fn exact_name_index(
    blind_index_key: &KeyMaterial,
    namespace_id: NamespaceId,
    name: &ProtectedString,
) -> CryptoResult<BlindIndex> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use unicode_normalization::UnicodeNormalization;

    let normalized = Zeroizing::new(name.expose().nfc().collect::<String>());
    if normalized.is_empty() || normalized.len() > 256 || normalized.chars().any(char::is_control) {
        return Err(CryptoError::InvalidProtectedInput);
    }
    let length = u16::try_from(normalized.len()).map_err(|_| CryptoError::InvalidProtectedInput)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(blind_index_key.expose())
        .map_err(|_| CryptoError::InvalidProtectedInput)?;
    mac.update(b"SMCV-BLIND-INDEX\0v1\0secret-name\0");
    mac.update(namespace_id.as_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(normalized.as_bytes());
    let mut index = [0_u8; 32];
    index.copy_from_slice(&mac.finalize().into_bytes());
    Ok(BlindIndex(index))
}

impl fmt::Debug for TokenVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenVerifier([REDACTED])")
    }
}

/// Newly generated application credential and its safe storage components.
pub struct IssuedToken {
    /// Complete credential shown once to the operator.
    pub plaintext: smcv_core::ProtectedString,
    /// Public lookup identifier used to select a candidate verifier.
    pub lookup_id: String,
    /// Keyed verifier stored instead of the random token secret.
    pub verifier: TokenVerifier,
}

/// Newly generated browser session secrets and their durable verifiers.
pub struct IssuedSession {
    /// Complete session cookie value returned only to the browser.
    pub session_token: ProtectedString,
    /// Complete double-submit value returned only to the browser.
    pub csrf_token: ProtectedString,
    /// Public random lookup used to select the server-side session.
    pub lookup_id: [u8; SESSION_LOOKUP_LENGTH],
    /// Keyed session-token verifier.
    pub session_verifier: SessionVerifier,
    /// Keyed CSRF-token verifier.
    pub csrf_verifier: SessionVerifier,
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSession")
            .field("session_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .field("lookup_id", &"[PUBLIC RANDOM LOOKUP]")
            .field("session_verifier", &self.session_verifier)
            .field("csrf_verifier", &self.csrf_verifier)
            .finish()
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("plaintext", &"[REDACTED]")
            .field("lookup_id", &self.lookup_id)
            .field("verifier", &self.verifier)
            .finish()
    }
}

/// Creates a uniformly random self-identifying application credential.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn issue_token(verifier_key: &KeyMaterial) -> CryptoResult<IssuedToken> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut lookup = [0_u8; TOKEN_LOOKUP_LENGTH];
    let mut secret = Zeroizing::new([0_u8; TOKEN_SECRET_LENGTH]);
    getrandom::fill(&mut lookup).map_err(|_| CryptoError::Randomness)?;
    getrandom::fill(secret.as_mut()).map_err(|_| CryptoError::Randomness)?;
    let lookup_id = URL_SAFE_NO_PAD.encode(lookup);
    let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
    let plaintext =
        smcv_core::ProtectedString::new(format!("smcv_v1.{lookup_id}.{}", encoded_secret.as_str()));
    let verifier = token_verifier(verifier_key, &lookup, secret.as_slice())?;
    Ok(IssuedToken {
        plaintext,
        lookup_id,
        verifier,
    })
}

/// Extracts the bounded public lookup from a candidate application token.
#[must_use]
pub fn token_lookup_id(presented: &str) -> Option<[u8; TOKEN_LOOKUP_LENGTH]> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    if presented.len() > 128 {
        return None;
    }
    let encoded = presented.strip_prefix("smcv_v1.")?;
    let mut fields = encoded.split('.');
    let lookup = URL_SAFE_NO_PAD.decode(fields.next()?).ok()?;
    let secret = URL_SAFE_NO_PAD.decode(fields.next()?).ok()?;
    if fields.next().is_some()
        || lookup.len() != TOKEN_LOOKUP_LENGTH
        || secret.len() != TOKEN_SECRET_LENGTH
    {
        return None;
    }
    lookup.try_into().ok()
}

/// Produces keyed, non-reversible idempotency-key and request verifiers.
///
/// # Errors
///
/// Returns invalid input for an empty/oversized key or request and unavailable
/// verifier construction failure.
pub fn idempotency_verifiers(
    verifier_key: &KeyMaterial,
    key: &ProtectedString,
    request: &ProtectedBytes,
) -> CryptoResult<([u8; 32], [u8; 32])> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    if key.expose().is_empty()
        || key.expose().len() > 128
        || request.is_empty()
        || request.len() > 1024 * 1024
    {
        return Err(CryptoError::InvalidProtectedInput);
    }
    let calculate = |domain: &[u8], value: &[u8]| -> CryptoResult<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(verifier_key.expose())
            .map_err(|_| CryptoError::InvalidProtectedInput)?;
        mac.update(domain);
        mac.update(value);
        let mut output = [0; 32];
        output.copy_from_slice(&mac.finalize().into_bytes());
        Ok(output)
    };
    Ok((
        calculate(b"SMCV-IDEMPOTENCY-KEY\0v1\0", key.expose().as_bytes())?,
        calculate(b"SMCV-IDEMPOTENCY-REQUEST\0v1\0", request.expose())?,
    ))
}

/// Creates a fresh server-side browser session and CSRF token pair.
///
/// The vault verifier key is used as key-derivation input with independent
/// domains for application credentials, sessions, and CSRF. Only the keyed
/// verifiers and public lookup are durable.
///
/// # Errors
///
/// Returns an error if operating-system randomness or verifier construction
/// is unavailable.
pub fn issue_session(verifier_key: &KeyMaterial) -> CryptoResult<IssuedSession> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut lookup = [0_u8; SESSION_LOOKUP_LENGTH];
    let mut session_secret = Zeroizing::new([0_u8; SESSION_SECRET_LENGTH]);
    let mut csrf_secret = Zeroizing::new([0_u8; SESSION_SECRET_LENGTH]);
    getrandom::fill(&mut lookup).map_err(|_| CryptoError::Randomness)?;
    getrandom::fill(session_secret.as_mut()).map_err(|_| CryptoError::Randomness)?;
    getrandom::fill(csrf_secret.as_mut()).map_err(|_| CryptoError::Randomness)?;

    let lookup_text = URL_SAFE_NO_PAD.encode(lookup);
    let session_text = Zeroizing::new(URL_SAFE_NO_PAD.encode(session_secret.as_slice()));
    let csrf_text = Zeroizing::new(URL_SAFE_NO_PAD.encode(csrf_secret.as_slice()));
    let durable_session_verifier = session_verifier(
        verifier_key,
        b"SMCV-SESSION-VERIFIER\0v1\0",
        &lookup,
        session_secret.as_slice(),
    )?;
    let durable_csrf_verifier = session_verifier(
        verifier_key,
        b"SMCV-CSRF-VERIFIER\0v1\0",
        &lookup,
        csrf_secret.as_slice(),
    )?;
    Ok(IssuedSession {
        session_token: ProtectedString::new(format!(
            "smcvs_v1.{lookup_text}.{}",
            session_text.as_str()
        )),
        csrf_token: ProtectedString::new(format!("smcvc_v1.{}", csrf_text.as_str())),
        lookup_id: lookup,
        session_verifier: durable_session_verifier,
        csrf_verifier: durable_csrf_verifier,
    })
}

/// Extracts the bounded public lookup from a candidate browser-session token.
#[must_use]
pub fn session_lookup_id(presented: &str) -> Option<[u8; SESSION_LOOKUP_LENGTH]> {
    let (lookup, _secret) = decode_session_token(presented)?;
    lookup.try_into().ok()
}

/// Verifies a browser-session token against its selected durable verifier.
///
/// # Errors
///
/// Returns an error only if keyed verifier construction fails. Malformed and
/// non-matching credentials return `false`.
pub fn verify_session(
    verifier_key: &KeyMaterial,
    presented: &str,
    expected_lookup: &[u8; SESSION_LOOKUP_LENGTH],
    expected_verifier: &SessionVerifier,
) -> CryptoResult<bool> {
    use subtle::ConstantTimeEq;

    let Some((lookup, secret)) = decode_session_token(presented) else {
        return Ok(false);
    };
    if lookup.as_slice().ct_eq(expected_lookup).unwrap_u8() != 1 {
        return Ok(false);
    }
    let actual = session_verifier(
        verifier_key,
        b"SMCV-SESSION-VERIFIER\0v1\0",
        &lookup,
        &secret,
    )?;
    Ok(actual.0.ct_eq(&expected_verifier.0).into())
}

/// Verifies a CSRF token bound to the selected browser session lookup.
///
/// # Errors
///
/// Returns an error only if keyed verifier construction fails. Malformed and
/// non-matching credentials return `false`.
pub fn verify_csrf(
    verifier_key: &KeyMaterial,
    presented: &str,
    expected_lookup: &[u8; SESSION_LOOKUP_LENGTH],
    expected_verifier: &SessionVerifier,
) -> CryptoResult<bool> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use subtle::ConstantTimeEq;

    if presented.len() > 64 {
        return Ok(false);
    }
    let Some(encoded) = presented.strip_prefix("smcvc_v1.") else {
        return Ok(false);
    };
    let Ok(secret) = URL_SAFE_NO_PAD.decode(encoded) else {
        return Ok(false);
    };
    if secret.len() != SESSION_SECRET_LENGTH {
        return Ok(false);
    }
    let actual = session_verifier(
        verifier_key,
        b"SMCV-CSRF-VERIFIER\0v1\0",
        expected_lookup,
        &secret,
    )?;
    Ok(actual.0.ct_eq(&expected_verifier.0).into())
}

fn decode_session_token(presented: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    if presented.len() > 96 {
        return None;
    }
    let encoded = presented.strip_prefix("smcvs_v1.")?;
    let mut fields = encoded.split('.');
    let lookup = URL_SAFE_NO_PAD.decode(fields.next()?).ok()?;
    let secret = URL_SAFE_NO_PAD.decode(fields.next()?).ok()?;
    if fields.next().is_some()
        || lookup.len() != SESSION_LOOKUP_LENGTH
        || secret.len() != SESSION_SECRET_LENGTH
    {
        return None;
    }
    Some((lookup, secret))
}

fn session_verifier(
    verifier_key: &KeyMaterial,
    domain: &[u8],
    lookup: &[u8],
    secret: &[u8],
) -> CryptoResult<SessionVerifier> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(verifier_key.expose())
        .map_err(|_| CryptoError::InvalidCredential)?;
    mac.update(domain);
    mac.update(lookup);
    mac.update(secret);
    let mut verifier = [0_u8; 32];
    verifier.copy_from_slice(&mac.finalize().into_bytes());
    Ok(SessionVerifier(verifier))
}

/// Verifies one bounded application credential against its candidate record.
///
/// Unknown lookup identifiers should still be checked against a synthetic
/// verifier by the authentication service to reduce enumeration timing.
///
/// # Errors
///
/// Returns an error only when the verifier key cannot initialize; malformed or
/// non-matching credentials return `false`.
pub fn verify_token(
    verifier_key: &KeyMaterial,
    presented: &str,
    expected_lookup_id: &str,
    expected_verifier: &TokenVerifier,
) -> CryptoResult<bool> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use subtle::ConstantTimeEq;

    if presented.len() > 128 {
        return Ok(false);
    }
    let Some(encoded) = presented.strip_prefix("smcv_v1.") else {
        return Ok(false);
    };
    let mut fields = encoded.split('.');
    let Some(lookup_text) = fields.next() else {
        return Ok(false);
    };
    let Some(secret_text) = fields.next() else {
        return Ok(false);
    };
    if fields.next().is_some() {
        return Ok(false);
    }
    let Ok(lookup) = URL_SAFE_NO_PAD.decode(lookup_text) else {
        return Ok(false);
    };
    let Ok(secret) = URL_SAFE_NO_PAD.decode(secret_text) else {
        return Ok(false);
    };
    if lookup.len() != TOKEN_LOOKUP_LENGTH || secret.len() != TOKEN_SECRET_LENGTH {
        return Ok(false);
    }
    if lookup_text
        .as_bytes()
        .ct_eq(expected_lookup_id.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Ok(false);
    }
    let actual = token_verifier(verifier_key, &lookup, &secret)?;
    Ok(actual.0.ct_eq(&expected_verifier.0).into())
}

fn token_verifier(
    verifier_key: &KeyMaterial,
    lookup: &[u8],
    secret: &[u8],
) -> CryptoResult<TokenVerifier> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(verifier_key.expose())
        .map_err(|_| CryptoError::InvalidCredential)?;
    mac.update(b"SMCV-TOKEN-VERIFIER\0v1\0");
    mac.update(lookup);
    mac.update(secret);
    let mut verifier = [0_u8; 32];
    verifier.copy_from_slice(&mac.finalize().into_bytes());
    Ok(TokenVerifier(verifier))
}

/// Seals plaintext under a fresh random nonce and context-bound AAD.
///
/// # Errors
///
/// Returns an error if randomness is unavailable or encryption cannot be
/// completed.
pub fn seal(
    key: &KeyMaterial,
    context: RecordContext,
    plaintext: &ProtectedBytes,
) -> CryptoResult<SealedRecord> {
    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    seal_with_nonce(key, context, plaintext, nonce)
}

fn seal_with_nonce(
    key: &KeyMaterial,
    context: RecordContext,
    plaintext: &ProtectedBytes,
    nonce: [u8; NONCE_LENGTH],
) -> CryptoResult<SealedRecord> {
    let key_array: &Key<XChaCha20Poly1305> = key.expose().into();
    let cipher = XChaCha20Poly1305::new(key_array);
    let aad = context.encode_aad();
    let nonce_array = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: plaintext.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Integrity)?;

    Ok(SealedRecord { nonce, ciphertext })
}

/// Authenticates and opens a context-bound sealed record.
///
/// # Errors
///
/// Returns an integrity error when the key, context, nonce, authentication tag,
/// or ciphertext does not authenticate.
pub fn open(
    key: &KeyMaterial,
    context: RecordContext,
    record: &SealedRecord,
) -> CryptoResult<ProtectedBytes> {
    let key_array: &Key<XChaCha20Poly1305> = key.expose().into();
    let cipher = XChaCha20Poly1305::new(key_array);
    let aad = context.encode_aad();
    let nonce_array = XNonce::from(record.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce_array,
            Payload {
                msg: &record.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Integrity)?;

    Ok(ProtectedBytes::new(plaintext))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use proptest::prelude::*;
    use smcv_core::{
        AuditEventId, InstallationId, NamespaceId, ObjectId, ProtectedBytes, ProtectedString,
        RequestId, VaultId,
    };
    #[cfg(unix)]
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::{
        AuditCommitmentInput, CryptoError, KeyMaterial, ObjectKind, RecordContext, SealedRecord,
        audit_commitment, exact_name_index, issue_session, issue_token, open, seal_with_nonce,
        session_lookup_id, state_commitment, token_lookup_id, verify_csrf, verify_session,
        verify_token,
    };
    #[cfg(unix)]
    use super::{create_root_key_file, load_root_key_file};

    fn context(version: u64) -> RecordContext {
        RecordContext {
            vault_id: VaultId::from_uuid(Uuid::from_u128(
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            )),
            installation_id: InstallationId::from_uuid(Uuid::from_u128(
                0x1021_3243_5465_7687_98a9_bacb_dced_fe0f,
            )),
            object_kind: ObjectKind::SecretVersion,
            object_id: ObjectId::from_uuid(Uuid::from_u128(
                0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
            )),
            object_version: version,
        }
    }

    proptest! {
        #[test]
        fn arbitrary_encoded_credentials_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let candidate = String::from_utf8_lossy(&bytes);
            let key = KeyMaterial::new([0x51; 32]);
            let expected_lookup = [0x52; super::SESSION_LOOKUP_LENGTH];
            let session_verifier = super::SessionVerifier([0x53; 32]);
            let token_verifier = super::TokenVerifier([0x54; 32]);

            let _ = token_lookup_id(&candidate);
            let _ = session_lookup_id(&candidate);
            let _ = verify_session(&key, &candidate, &expected_lookup, &session_verifier);
            let _ = verify_csrf(&key, &candidate, &expected_lookup, &session_verifier);
            let _ = verify_token(&key, &candidate, "synthetic-lookup", &token_verifier);
        }
    }

    #[test]
    fn aad_encoding_is_stable() {
        let encoded = context(7).encode_aad();
        assert_eq!(
            hex::encode(encoded),
            "534d43562d414144000100112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f010123456789abcdeffedcba98765432100000000000000007"
        );
    }

    #[test]
    fn known_answer_round_trip_and_context_binding() {
        let key = KeyMaterial::new([0x42; 32]);
        let plaintext = ProtectedBytes::new(b"synthetic-value".to_vec());
        let sealed = seal_with_nonce(&key, context(7), &plaintext, [0x24; 24])
            .unwrap_or_else(|error| panic!("synthetic vector must seal: {error}"));

        assert_eq!(
            hex::encode(&sealed.ciphertext),
            "d627b911064138cfc102495b62fd680494e696feb5ca0902cd5a648dbf8f9f"
        );
        let opened = open(&key, context(7), &sealed)
            .unwrap_or_else(|error| panic!("synthetic vector must open: {error}"));
        assert_eq!(opened.expose(), b"synthetic-value");
        assert!(matches!(
            open(&key, context(8), &sealed),
            Err(CryptoError::Integrity)
        ));
    }

    #[test]
    fn corrupted_ciphertext_fails_closed() {
        let key = KeyMaterial::new([0x11; 32]);
        let plaintext = ProtectedBytes::new(b"synthetic-value".to_vec());
        let sealed = seal_with_nonce(&key, context(1), &plaintext, [0x22; 24])
            .unwrap_or_else(|error| panic!("synthetic vector must seal: {error}"));
        let mut ciphertext = sealed.ciphertext;
        ciphertext[0] ^= 1;
        let corrupted = SealedRecord {
            nonce: sealed.nonce,
            ciphertext,
        };

        assert!(matches!(
            open(&key, context(1), &corrupted),
            Err(CryptoError::Integrity)
        ));
    }

    #[test]
    fn application_token_is_one_time_material_with_keyed_verifier() {
        let key = KeyMaterial::new([0x71; 32]);
        let issued =
            issue_token(&key).unwrap_or_else(|error| panic!("synthetic token must issue: {error}"));

        assert!(
            verify_token(
                &key,
                issued.plaintext.expose(),
                &issued.lookup_id,
                &issued.verifier,
            )
            .unwrap_or_else(|error| panic!("synthetic token must verify: {error}"))
        );
        assert!(
            !verify_token(
                &KeyMaterial::new([0x72; 32]),
                issued.plaintext.expose(),
                &issued.lookup_id,
                &issued.verifier,
            )
            .unwrap_or_else(|error| panic!("wrong-key token check must complete: {error}"))
        );
        assert!(!format!("{issued:?}").contains(issued.plaintext.expose()));
    }

    #[test]
    fn browser_session_and_csrf_are_independent_verifier_only_secrets() {
        let key = KeyMaterial::new([0x73; 32]);
        let issued = issue_session(&key)
            .unwrap_or_else(|error| panic!("synthetic session must issue: {error}"));

        assert_eq!(
            session_lookup_id(issued.session_token.expose()),
            Some(issued.lookup_id)
        );
        assert!(
            verify_session(
                &key,
                issued.session_token.expose(),
                &issued.lookup_id,
                &issued.session_verifier,
            )
            .unwrap_or_else(|error| panic!("synthetic session must verify: {error}"))
        );
        assert!(
            verify_csrf(
                &key,
                issued.csrf_token.expose(),
                &issued.lookup_id,
                &issued.csrf_verifier,
            )
            .unwrap_or_else(|error| panic!("synthetic csrf must verify: {error}"))
        );
        assert!(
            !verify_csrf(
                &key,
                issued.session_token.expose(),
                &issued.lookup_id,
                &issued.csrf_verifier,
            )
            .unwrap_or_else(|error| panic!("cross-domain check must complete: {error}"))
        );
        assert!(!format!("{issued:?}").contains(issued.session_token.expose()));
        assert!(!format!("{issued:?}").contains(issued.csrf_token.expose()));
    }

    #[test]
    fn blind_index_is_nfc_canonical_case_sensitive_and_namespace_scoped() {
        let key = KeyMaterial::new([0x31; 32]);
        let namespace = NamespaceId::random();
        let composed = ProtectedString::new(String::from("Caf\u{e9}"));
        let decomposed = ProtectedString::new(String::from("Cafe\u{301}"));
        let uppercase = ProtectedString::new(String::from("CAF\u{c9}"));

        let first = exact_name_index(&key, namespace, &composed)
            .unwrap_or_else(|error| panic!("synthetic name must index: {error}"));
        let equivalent = exact_name_index(&key, namespace, &decomposed)
            .unwrap_or_else(|error| panic!("canonical synthetic name must index: {error}"));
        let different_case = exact_name_index(&key, namespace, &uppercase)
            .unwrap_or_else(|error| panic!("case variant must index: {error}"));
        let different_namespace = exact_name_index(&key, NamespaceId::random(), &composed)
            .unwrap_or_else(|error| panic!("namespace variant must index: {error}"));

        assert_eq!(first, equivalent);
        assert_ne!(first, different_case);
        assert_ne!(first, different_namespace);
        assert!(!format!("{first:?}").contains("Caf"));
    }

    #[test]
    fn audit_commitment_links_every_canonical_field() {
        let key = KeyMaterial::new([0x51; 32]);
        let mut input = AuditCommitmentInput {
            commitment_version: 2,
            previous: [0x11; 32],
            sequence: 7,
            event_id: AuditEventId::random(),
            installation_id: InstallationId::random(),
            recovery_epoch: 2,
            occurred_at_unix_ms: 1_800_000_000_000,
            request_id: RequestId::random(),
            actor_principal_id: None,
            credential_kind: Some("session"),
            credential_id: Some(ObjectId::random()),
            action: "secret:create",
            target_kind: "secret",
            target_id: Some(ObjectId::random()),
            outcome: "allowed",
        };
        let first = audit_commitment(&key, &input)
            .unwrap_or_else(|error| panic!("synthetic audit event must commit: {error}"));
        input.sequence += 1;
        let changed = audit_commitment(&key, &input)
            .unwrap_or_else(|error| panic!("changed synthetic event must commit: {error}"));

        assert_ne!(first, changed);
        assert!(!format!("{first:?}").contains("secret:create"));
    }

    #[test]
    fn state_commitment_authenticates_every_canonical_byte() {
        let key = KeyMaterial::new([0x61; 32]);
        let first = state_commitment(&key, b"canonical-clear-state")
            .unwrap_or_else(|error| panic!("synthetic state must commit: {error}"));
        let changed = state_commitment(&key, b"canonical-clear-statf")
            .unwrap_or_else(|error| panic!("changed state must commit: {error}"));
        assert_ne!(first, changed);
        assert!(format!("{first:?}").contains("[COMMITMENT]"));
        assert!(!format!("{first:?}").contains("canonical"));
    }

    #[cfg(unix)]
    #[test]
    fn root_key_file_is_bound_restrictive_and_never_overwritten() {
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic key directory must open: {error}"));
        let path = directory.path().join("root.key");
        let expected = context(1);
        create_root_key_file(&path, expected.vault_id, expected.installation_id)
            .unwrap_or_else(|error| panic!("synthetic root key must create: {error}"));

        let mode = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("synthetic key metadata must read: {error}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        let loaded = load_root_key_file(&path)
            .unwrap_or_else(|error| panic!("synthetic root key must load: {error}"));
        assert_eq!(loaded.vault_id, expected.vault_id);
        assert_eq!(loaded.installation_id, expected.installation_id);
        assert!(format!("{loaded:?}").contains("[REDACTED]"));
        assert!(matches!(
            create_root_key_file(&path, expected.vault_id, expected.installation_id),
            Err(CryptoError::KeyProvider)
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("synthetic permissions must change: {error}"));
        assert!(matches!(
            load_root_key_file(&path),
            Err(CryptoError::KeyProvider)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("synthetic permissions must restore: {error}"));
        let link = directory.path().join("root-link.key");
        symlink(&path, &link)
            .unwrap_or_else(|error| panic!("synthetic provider symlink must create: {error}"));
        assert!(matches!(
            load_root_key_file(&link),
            Err(CryptoError::KeyProvider)
        ));
    }
}
