#![forbid(unsafe_code)]
#![doc = "Cryptographic adapters and canonical envelope context for SMCV."]
#![cfg_attr(test, allow(clippy::panic))]

use core::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Key, KeyInit, Payload},
};
use smcv_core::{InstallationId, ObjectId, ProtectedBytes, VaultId};
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

const AAD_DOMAIN: &[u8; 8] = b"SMCV-AAD";

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

    fn expose(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyMaterial([REDACTED])")
    }
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
    use smcv_core::{InstallationId, ObjectId, ProtectedBytes, VaultId};
    use uuid::Uuid;

    use super::{
        CryptoError, KeyMaterial, ObjectKind, RecordContext, SealedRecord, issue_token, open,
        seal_with_nonce, verify_token,
    };

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
}
