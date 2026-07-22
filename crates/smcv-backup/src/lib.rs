#![forbid(unsafe_code)]
#![doc = "Bounded framing primitives for portable SMCV backup archives."]

use std::io::{Read, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// On-disk archive magic for format version 1.
pub const MAGIC: [u8; 8] = *b"SMCVLT01";
/// The only archive format accepted by this reader.
pub const FORMAT_VERSION: u16 = 1;
/// The version 1 algorithm suite (XChaCha20-Poly1305 and SHA-256).
pub const ALGORITHM_SUITE: u16 = 1;
/// Largest public header accepted before any KDF work.
pub const MAX_HEADER_BYTES: usize = 256;
/// Maximum accepted encrypted archive size.
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Smallest encrypted stream chunk.
pub const MIN_CHUNK_BYTES: u32 = 16 * 1024;
/// Largest encrypted stream chunk.
pub const MAX_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum logical records in one archive.
pub const MAX_RECORDS: u64 = 10_000_000;
/// Minimum Argon2 memory cost accepted for passphrase archives.
pub const MIN_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Maximum Argon2 memory cost accepted from an archive.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1024 * 1024;
/// Maximum Argon2 iteration count accepted from an archive.
pub const MAX_ARGON2_ITERATIONS: u32 = 10;
/// Maximum Argon2 lanes accepted from an archive.
pub const MAX_ARGON2_LANES: u8 = 4;

const FIXED_HEADER_BYTES: usize = 54;
const WRAP_NONCE_BYTES: usize = 24;
const WRAPPED_DEK_BYTES: usize = 48;
const MIN_HEADER_BYTES: usize = FIXED_HEADER_BYTES + WRAP_NONCE_BYTES + WRAPPED_DEK_BYTES;
const MIN_SALT_BYTES: usize = 16;
const MAX_SALT_BYTES: usize = 32;
const FRAME_HEADER_BYTES: usize = 38;
const AEAD_TAG_BYTES: usize = 16;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_LOGICAL_RECORD_BYTES: u32 = 32 * 1024 * 1024;

/// Backup key derivation mode selected by the bounded public header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyMode {
    /// An archive wrapping key derived with bounded Argon2id parameters.
    PassphraseArgon2id = 1,
    /// A uniformly random recovery key supplied directly by the operator.
    RecoveryKey = 2,
}

/// Validated Argon2id parameters safe to pass to the KDF layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Parameters {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallel lane count.
    pub lanes: u8,
}

/// Public metadata that is fully bounded before expensive processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicHeader {
    /// Unique non-secret archive identity.
    pub archive_id: Uuid,
    /// Selected key derivation mode.
    pub key_mode: KeyMode,
    /// Salt used only by passphrase mode.
    pub salt: Vec<u8>,
    /// Validated parameters used only by passphrase mode.
    pub argon2: Option<Argon2Parameters>,
    /// Ciphertext chunk size.
    pub chunk_bytes: u32,
    /// Declared upper bound on logical records.
    pub record_limit: u64,
    /// Non-secret nonce protecting the random archive DEK.
    pub wrap_nonce: [u8; WRAP_NONCE_BYTES],
    /// Random archive DEK encrypted by the selected wrapping key.
    pub wrapped_dek: [u8; WRAPPED_DEK_BYTES],
}

/// Failure returned before archive authentication begins.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HeaderError {
    /// The containing file is larger than the reader limit.
    #[error("archive exceeds the supported size limit")]
    ArchiveTooLarge,
    /// Too few bytes exist for the declared header.
    #[error("archive header is truncated")]
    Truncated,
    /// The archive magic is not recognized.
    #[error("archive format is not recognized")]
    BadMagic,
    /// The version or algorithm suite is not in the compiled allowlist.
    #[error("archive version or algorithm suite is unsupported")]
    Unsupported,
    /// A length or count is outside a safe bound.
    #[error("archive header contains an invalid bound")]
    InvalidBound,
    /// Key-mode and KDF fields are inconsistent.
    #[error("archive key parameters are invalid")]
    InvalidKdf,
}

/// Parses and validates the public header without running a KDF or allocating
/// based on an untrusted length.
///
/// The caller supplies the total file length so the global archive bound is
/// enforced before any further I/O.
///
/// # Errors
///
/// Returns a safe format error for unsupported, truncated, or out-of-bounds
/// input.
pub fn parse_public_header(
    bytes: &[u8],
    total_archive_bytes: u64,
) -> Result<PublicHeader, HeaderError> {
    if total_archive_bytes > MAX_ARCHIVE_BYTES {
        return Err(HeaderError::ArchiveTooLarge);
    }
    if bytes.len() < FIXED_HEADER_BYTES {
        return Err(HeaderError::Truncated);
    }
    if bytes[0..8] != MAGIC {
        return Err(HeaderError::BadMagic);
    }
    let version = read_u16(bytes, 8)?;
    let suite = read_u16(bytes, 10)?;
    if version != FORMAT_VERSION || suite != ALGORITHM_SUITE {
        return Err(HeaderError::Unsupported);
    }

    let mode = match bytes[12] {
        1 => KeyMode::PassphraseArgon2id,
        2 => KeyMode::RecoveryKey,
        _ => return Err(HeaderError::Unsupported),
    };
    if bytes[13] != 0 {
        return Err(HeaderError::Unsupported);
    }
    let header_len = usize::from(read_u16(bytes, 14)?);
    if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&header_len) || bytes.len() < header_len {
        return Err(HeaderError::InvalidBound);
    }

    let archive_id = Uuid::from_slice(&bytes[16..32]).map_err(|_| HeaderError::InvalidBound)?;
    let salt_len = usize::from(bytes[32]);
    let expected_len = MIN_HEADER_BYTES
        .checked_add(salt_len)
        .ok_or(HeaderError::InvalidBound)?;
    if header_len != expected_len {
        return Err(HeaderError::InvalidBound);
    }

    let memory_kib = read_u32(bytes, 33)?;
    let iterations = read_u32(bytes, 37)?;
    let lanes = bytes[41];
    let chunk_bytes = read_u32(bytes, 42)?;
    let record_limit = read_u64(bytes, 46)?;
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
        || record_limit == 0
        || record_limit > MAX_RECORDS
    {
        return Err(HeaderError::InvalidBound);
    }

    let (salt, argon2) = match mode {
        KeyMode::PassphraseArgon2id => {
            if !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&salt_len)
                || !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&memory_kib)
                || !(1..=MAX_ARGON2_ITERATIONS).contains(&iterations)
                || !(1..=MAX_ARGON2_LANES).contains(&lanes)
            {
                return Err(HeaderError::InvalidKdf);
            }
            (
                bytes[FIXED_HEADER_BYTES..FIXED_HEADER_BYTES + salt_len].to_vec(),
                Some(Argon2Parameters {
                    memory_kib,
                    iterations,
                    lanes,
                }),
            )
        }
        KeyMode::RecoveryKey => {
            if salt_len != 0 || memory_kib != 0 || iterations != 0 || lanes != 0 {
                return Err(HeaderError::InvalidKdf);
            }
            (Vec::new(), None)
        }
    };

    let wrap_nonce_offset = FIXED_HEADER_BYTES + salt_len;
    let wrapped_dek_offset = wrap_nonce_offset + WRAP_NONCE_BYTES;
    Ok(PublicHeader {
        archive_id,
        key_mode: mode,
        salt,
        argon2,
        chunk_bytes,
        record_limit,
        wrap_nonce: bytes[wrap_nonce_offset..wrapped_dek_offset]
            .try_into()
            .map_err(|_| HeaderError::InvalidBound)?,
        wrapped_dek: bytes[wrapped_dek_offset..header_len]
            .try_into()
            .map_err(|_| HeaderError::InvalidBound)?,
    })
}

/// A generated uniformly random backup recovery key.
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    /// Generates a new key from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns unavailable when the operating system cannot provide random
    /// bytes.
    pub fn generate() -> Result<Self, ArchiveError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| ArchiveError::Unavailable)?;
        Ok(Self(key))
    }

    /// Parses the checksummed display-once textual representation.
    ///
    /// # Errors
    ///
    /// Returns invalid key for any malformed length, encoding, or checksum.
    pub fn parse(encoded: &str) -> Result<Self, ArchiveError> {
        let mut fields = encoded.split('.');
        if fields.next() != Some("smcvbrk_v1") {
            return Err(ArchiveError::InvalidKey);
        }
        let body = fields.next().ok_or(ArchiveError::InvalidKey)?;
        let checksum = fields.next().ok_or(ArchiveError::InvalidKey)?;
        if fields.next().is_some() || checksum.len() != 8 {
            return Err(ArchiveError::InvalidKey);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        let decoded = URL_SAFE_NO_PAD
            .decode_slice(body, key.as_mut())
            .map_err(|_| ArchiveError::InvalidKey)?;
        if decoded != key.len() {
            return Err(ArchiveError::InvalidKey);
        }
        if recovery_checksum(&key) != checksum {
            return Err(ArchiveError::InvalidKey);
        }
        Ok(Self(key))
    }

    /// Returns the display-once representation with a transcription checksum.
    #[must_use]
    pub fn expose_once(&self) -> String {
        format!(
            "smcvbrk_v1.{}.{}",
            URL_SAFE_NO_PAD.encode(self.0.as_ref()),
            recovery_checksum(&self.0)
        )
    }
}

/// Protected key material supplied to archive creation or verification.
#[derive(Clone, Copy)]
pub enum ArchiveKey<'a> {
    /// Human passphrase processed by the bounded public-header Argon2id profile.
    Passphrase(&'a [u8]),
    /// Uniform recovery or automation key.
    Recovery(&'a RecoveryKey),
}

impl core::fmt::Debug for ArchiveKey<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArchiveKey([REDACTED])")
    }
}

/// Authenticated safe archive metadata; protected labels never occur here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchiveMetadata {
    /// Logical vault identity preserved by disaster recovery.
    pub logical_vault_id: Uuid,
    /// Source installation identity used only for recovery provenance.
    pub source_installation_id: Uuid,
    /// Source recovery epoch.
    pub source_recovery_epoch: u64,
    /// Source schema version required by the logical reader.
    pub source_schema_version: u32,
    /// Portable security-semantics version.
    pub security_semantics_version: u32,
    /// Backup creation time.
    pub created_at_unix_ms: i64,
}

/// Bounded archive writer configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveOptions {
    /// Plaintext bytes per encrypted data frame.
    pub chunk_bytes: u32,
    /// Maximum logical record count accepted from the source stream.
    pub record_limit: u64,
    /// Argon2id profile for passphrase mode.
    pub argon2: Argon2Parameters,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            chunk_bytes: 1024 * 1024,
            record_limit: MAX_RECORDS,
            argon2: Argon2Parameters {
                memory_kib: 64 * 1024,
                iterations: 3,
                lanes: 1,
            },
        }
    }
}

/// Result returned only after the archive stream has been fully written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSummary {
    /// Random archive identity.
    pub archive_id: Uuid,
    /// Exact bytes written.
    pub archive_bytes: u64,
    /// Logical framed records observed.
    pub record_count: u64,
    /// Logical plaintext stream bytes encrypted.
    pub logical_bytes: u64,
}

/// Result of full authenticated non-mutating verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArchive {
    /// Validated public header.
    pub header: PublicHeader,
    /// Authenticated safe manifest metadata.
    pub metadata: ArchiveMetadata,
    /// Exact authenticated logical record count.
    pub record_count: u64,
    /// Exact authenticated logical byte count.
    pub logical_bytes: u64,
    /// SHA-256 digest of the canonical logical stream.
    pub logical_digest: [u8; 32],
}

/// Safe portable archive failure categories.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// Public framing is unsupported or violates a bound.
    #[error("archive header is invalid")]
    Header(#[source] HeaderError),
    /// Archive I/O did not complete.
    #[error("archive I/O failed")]
    Io(#[source] std::io::Error),
    /// The supplied passphrase or recovery key is invalid.
    #[error("archive key or authentication is invalid")]
    InvalidKey,
    /// Encrypted framing, sequence, manifest, or logical records are invalid.
    #[error("archive integrity verification failed")]
    Integrity,
    /// A configured or observed resource bound is invalid.
    #[error("archive exceeds a supported resource bound")]
    InvalidBound,
    /// Randomness or cryptographic setup is unavailable.
    #[error("archive service is unavailable")]
    Unavailable,
}

impl From<std::io::Error> for ArchiveError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HeaderError> for ArchiveError {
    fn from(error: HeaderError) -> Self {
        Self::Header(error)
    }
}

#[derive(Deserialize, Serialize)]
struct FinalManifest {
    record_count: u64,
    logical_bytes: u64,
    logical_digest: [u8; 32],
    data_frames: u64,
}

/// Encrypts one canonical framed logical stream into archive format v1.
///
/// The logical stream consists of repeated big-endian
/// `(kind:u16, flags:u16, length:u32, payload:length)` records. This function
/// validates boundaries and counts while streaming and never writes plaintext
/// temporary data.
///
/// # Errors
///
/// Returns a safe error for invalid options/key/record framing, failed
/// randomness, cryptographic failure, or incomplete output.
#[allow(
    clippy::too_many_lines,
    reason = "the archive writer keeps the authenticated sequence visible in one protocol operation"
)]
pub fn write_archive<R: Read, W: Write>(
    mut logical_stream: R,
    mut destination: W,
    key: ArchiveKey<'_>,
    metadata: &ArchiveMetadata,
    options: ArchiveOptions,
) -> Result<ArchiveSummary, ArchiveError> {
    validate_options(options)?;
    let archive_id = Uuid::new_v4();
    let mut salt = Vec::new();
    let (key_mode, argon2) = match key {
        ArchiveKey::Passphrase(passphrase) => {
            if !(16..=1024).contains(&passphrase.len()) {
                return Err(ArchiveError::InvalidKey);
            }
            salt.resize(MIN_SALT_BYTES, 0);
            getrandom::fill(&mut salt).map_err(|_| ArchiveError::Unavailable)?;
            (KeyMode::PassphraseArgon2id, Some(options.argon2))
        }
        ArchiveKey::Recovery(_) => (KeyMode::RecoveryKey, None),
    };
    let mut wrap_nonce = [0_u8; WRAP_NONCE_BYTES];
    let mut archive_dek = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut wrap_nonce).map_err(|_| ArchiveError::Unavailable)?;
    getrandom::fill(archive_dek.as_mut()).map_err(|_| ArchiveError::Unavailable)?;
    let mut header = PublicHeader {
        archive_id,
        key_mode,
        salt,
        argon2,
        chunk_bytes: options.chunk_bytes,
        record_limit: options.record_limit,
        wrap_nonce,
        wrapped_dek: [0_u8; WRAPPED_DEK_BYTES],
    };
    let wrapping_key = derive_wrapping_key(key, &header)?;
    let header_prefix = encode_header_prefix(&header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| ArchiveError::Unavailable)?;
    let wrap_nonce = XNonce::from(header.wrap_nonce);
    let wrapped = cipher
        .encrypt(
            &wrap_nonce,
            Payload {
                msg: archive_dek.as_ref(),
                aad: &header_prefix,
            },
        )
        .map_err(|_| ArchiveError::Unavailable)?;
    header.wrapped_dek = wrapped.try_into().map_err(|_| ArchiveError::Unavailable)?;
    let encoded_header = encode_public_header(&header)?;
    destination.write_all(&encoded_header)?;
    let mut bytes_written =
        u64::try_from(encoded_header.len()).map_err(|_| ArchiveError::InvalidBound)?;

    let manifest = serde_json::to_vec(metadata).map_err(|_| ArchiveError::InvalidBound)?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(ArchiveError::InvalidBound);
    }
    bytes_written = bytes_written
        .checked_add(write_frame(
            &mut destination,
            &archive_dek,
            archive_id,
            0,
            1,
            &manifest,
        )?)
        .ok_or(ArchiveError::InvalidBound)?;

    let mut sequence = 1_u64;
    let mut data_frames = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut digest = Sha256::new();
    let mut counter = RecordCounter::new(options.record_limit);
    let chunk_bytes =
        usize::try_from(options.chunk_bytes).map_err(|_| ArchiveError::InvalidBound)?;
    let mut chunk = Zeroizing::new(vec![0_u8; chunk_bytes]);
    loop {
        let read = logical_stream.read(chunk.as_mut())?;
        if read == 0 {
            break;
        }
        let data = &chunk[..read];
        counter.update(data)?;
        digest.update(data);
        logical_bytes = logical_bytes
            .checked_add(u64::try_from(read).map_err(|_| ArchiveError::InvalidBound)?)
            .ok_or(ArchiveError::InvalidBound)?;
        bytes_written = bytes_written
            .checked_add(write_frame(
                &mut destination,
                &archive_dek,
                archive_id,
                sequence,
                2,
                data,
            )?)
            .ok_or(ArchiveError::InvalidBound)?;
        sequence = sequence.checked_add(1).ok_or(ArchiveError::InvalidBound)?;
        data_frames = data_frames
            .checked_add(1)
            .ok_or(ArchiveError::InvalidBound)?;
    }
    let record_count = counter.finish()?;
    let final_manifest = FinalManifest {
        record_count,
        logical_bytes,
        logical_digest: digest.finalize().into(),
        data_frames,
    };
    let final_bytes = serde_json::to_vec(&final_manifest).map_err(|_| ArchiveError::Integrity)?;
    bytes_written = bytes_written
        .checked_add(write_frame(
            &mut destination,
            &archive_dek,
            archive_id,
            sequence,
            3,
            &final_bytes,
        )?)
        .ok_or(ArchiveError::InvalidBound)?;
    destination.flush()?;
    Ok(ArchiveSummary {
        archive_id,
        archive_bytes: bytes_written,
        record_count,
        logical_bytes,
    })
}

/// Fully verifies an archive without exposing its logical plaintext.
///
/// # Errors
///
/// Returns a safe error for wrong keys, corruption, truncation, extension,
/// sequence changes, invalid logical framing, or resource-limit violations.
pub fn verify_archive<R: Read>(
    source: R,
    total_archive_bytes: u64,
    key: ArchiveKey<'_>,
) -> Result<VerifiedArchive, ArchiveError> {
    decode_archive(source, total_archive_bytes, key, |_| Ok(()))
}

/// Authenticates and streams canonical logical chunks to a staging consumer.
///
/// The consumer may observe plaintext before the final manifest authenticates,
/// so it must write only to non-ready staging state and discard it on any
/// returned error.
///
/// # Errors
///
/// Returns the same safe failures as [`verify_archive`] plus consumer errors.
#[allow(
    clippy::too_many_lines,
    reason = "the archive reader keeps the authenticated sequence visible in one protocol operation"
)]
pub fn decode_archive<R: Read, F: FnMut(&[u8]) -> Result<(), ArchiveError>>(
    mut source: R,
    total_archive_bytes: u64,
    key: ArchiveKey<'_>,
    mut consume: F,
) -> Result<VerifiedArchive, ArchiveError> {
    if total_archive_bytes > MAX_ARCHIVE_BYTES {
        return Err(HeaderError::ArchiveTooLarge.into());
    }
    let mut first = [0_u8; 16];
    source.read_exact(&mut first)?;
    let header_len = usize::from(u16::from_be_bytes([first[14], first[15]]));
    if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&header_len) {
        return Err(HeaderError::InvalidBound.into());
    }
    let mut encoded_header = vec![0_u8; header_len];
    encoded_header[..16].copy_from_slice(&first);
    source.read_exact(&mut encoded_header[16..])?;
    let header = parse_public_header(&encoded_header, total_archive_bytes)?;
    let wrapping_key = derive_wrapping_key(key, &header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| ArchiveError::Unavailable)?;
    let header_prefix = encode_header_prefix(&header)?;
    let wrap_nonce = XNonce::from(header.wrap_nonce);
    let archive_dek: Zeroizing<[u8; 32]> = Zeroizing::new(
        cipher
            .decrypt(
                &wrap_nonce,
                Payload {
                    msg: &header.wrapped_dek,
                    aad: &header_prefix,
                },
            )
            .map_err(|_| ArchiveError::InvalidKey)?
            .try_into()
            .map_err(|_| ArchiveError::InvalidKey)?,
    );
    let mut consumed_bytes = u64::try_from(header_len).map_err(|_| ArchiveError::InvalidBound)?;
    let (kind, manifest_bytes, frame_size) = read_frame(
        &mut source,
        &archive_dek,
        header.archive_id,
        0,
        header.chunk_bytes,
    )?;
    if kind != 1 || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ArchiveError::Integrity);
    }
    consumed_bytes = consumed_bytes
        .checked_add(frame_size)
        .ok_or(ArchiveError::InvalidBound)?;
    let metadata: ArchiveMetadata =
        serde_json::from_slice(&manifest_bytes).map_err(|_| ArchiveError::Integrity)?;

    let mut sequence = 1_u64;
    let mut data_frames = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut digest = Sha256::new();
    let mut counter = RecordCounter::new(header.record_limit);
    let final_manifest = loop {
        let (kind, plaintext, frame_size) = read_frame(
            &mut source,
            &archive_dek,
            header.archive_id,
            sequence,
            header.chunk_bytes,
        )?;
        consumed_bytes = consumed_bytes
            .checked_add(frame_size)
            .ok_or(ArchiveError::InvalidBound)?;
        sequence = sequence.checked_add(1).ok_or(ArchiveError::InvalidBound)?;
        match kind {
            2 => {
                counter.update(&plaintext)?;
                digest.update(&plaintext);
                logical_bytes = logical_bytes
                    .checked_add(
                        u64::try_from(plaintext.len()).map_err(|_| ArchiveError::InvalidBound)?,
                    )
                    .ok_or(ArchiveError::InvalidBound)?;
                data_frames = data_frames
                    .checked_add(1)
                    .ok_or(ArchiveError::InvalidBound)?;
                consume(&plaintext)?;
            }
            3 => {
                if plaintext.len() > MAX_MANIFEST_BYTES {
                    return Err(ArchiveError::Integrity);
                }
                break serde_json::from_slice::<FinalManifest>(&plaintext)
                    .map_err(|_| ArchiveError::Integrity)?;
            }
            _ => return Err(ArchiveError::Integrity),
        }
    };
    if consumed_bytes != total_archive_bytes {
        return Err(ArchiveError::Integrity);
    }
    let mut extra = [0_u8; 1];
    if source.read(&mut extra)? != 0 {
        return Err(ArchiveError::Integrity);
    }
    let record_count = counter.finish()?;
    let logical_digest: [u8; 32] = digest.finalize().into();
    if final_manifest.record_count != record_count
        || final_manifest.logical_bytes != logical_bytes
        || final_manifest.logical_digest != logical_digest
        || final_manifest.data_frames != data_frames
    {
        return Err(ArchiveError::Integrity);
    }
    Ok(VerifiedArchive {
        header,
        metadata,
        record_count,
        logical_bytes,
        logical_digest,
    })
}

fn validate_options(options: ArchiveOptions) -> Result<(), ArchiveError> {
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&options.chunk_bytes)
        || options.record_limit == 0
        || options.record_limit > MAX_RECORDS
        || !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&options.argon2.memory_kib)
        || !(1..=MAX_ARGON2_ITERATIONS).contains(&options.argon2.iterations)
        || !(1..=MAX_ARGON2_LANES).contains(&options.argon2.lanes)
    {
        return Err(ArchiveError::InvalidBound);
    }
    Ok(())
}

fn derive_wrapping_key(
    key: ArchiveKey<'_>,
    header: &PublicHeader,
) -> Result<Zeroizing<[u8; 32]>, ArchiveError> {
    match (key, header.key_mode) {
        (ArchiveKey::Passphrase(passphrase), KeyMode::PassphraseArgon2id) => {
            if passphrase.is_empty() || passphrase.len() > 1024 {
                return Err(ArchiveError::InvalidKey);
            }
            let parameters = header.argon2.ok_or(ArchiveError::InvalidKey)?;
            let params = Params::new(
                parameters.memory_kib,
                parameters.iterations,
                u32::from(parameters.lanes),
                Some(32),
            )
            .map_err(|_| ArchiveError::InvalidKey)?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut output = Zeroizing::new([0_u8; 32]);
            argon2
                .hash_password_into(passphrase, &header.salt, output.as_mut())
                .map_err(|_| ArchiveError::InvalidKey)?;
            Ok(output)
        }
        (ArchiveKey::Recovery(recovery), KeyMode::RecoveryKey) => {
            let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(recovery.0.as_ref())
                .map_err(|_| ArchiveError::Unavailable)?;
            mac.update(b"SMCV-BACKUP-WRAP-v1");
            mac.update(header.archive_id.as_bytes());
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }
        _ => Err(ArchiveError::InvalidKey),
    }
}

fn encode_header_prefix(header: &PublicHeader) -> Result<Vec<u8>, ArchiveError> {
    let header_len = MIN_HEADER_BYTES
        .checked_add(header.salt.len())
        .ok_or(ArchiveError::InvalidBound)?;
    let header_len = u16::try_from(header_len).map_err(|_| ArchiveError::InvalidBound)?;
    let mut bytes = Vec::with_capacity(usize::from(header_len) - WRAPPED_DEK_BYTES);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&ALGORITHM_SUITE.to_be_bytes());
    bytes.push(header.key_mode as u8);
    bytes.push(0);
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(header.archive_id.as_bytes());
    bytes.push(u8::try_from(header.salt.len()).map_err(|_| ArchiveError::InvalidBound)?);
    let parameters = header.argon2.unwrap_or(Argon2Parameters {
        memory_kib: 0,
        iterations: 0,
        lanes: 0,
    });
    bytes.extend_from_slice(&parameters.memory_kib.to_be_bytes());
    bytes.extend_from_slice(&parameters.iterations.to_be_bytes());
    bytes.push(parameters.lanes);
    bytes.extend_from_slice(&header.chunk_bytes.to_be_bytes());
    bytes.extend_from_slice(&header.record_limit.to_be_bytes());
    bytes.extend_from_slice(&header.salt);
    bytes.extend_from_slice(&header.wrap_nonce);
    Ok(bytes)
}

fn encode_public_header(header: &PublicHeader) -> Result<Vec<u8>, ArchiveError> {
    let mut bytes = encode_header_prefix(header)?;
    bytes.extend_from_slice(&header.wrapped_dek);
    Ok(bytes)
}

fn write_frame<W: Write>(
    destination: &mut W,
    key: &[u8; 32],
    archive_id: Uuid,
    sequence: u64,
    kind: u8,
    plaintext: &[u8],
) -> Result<u64, ArchiveError> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| ArchiveError::Unavailable)?;
    let ciphertext_len = plaintext
        .len()
        .checked_add(AEAD_TAG_BYTES)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ArchiveError::InvalidBound)?;
    let aad = frame_aad(archive_id, sequence, kind, ciphertext_len);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ArchiveError::Unavailable)?;
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ArchiveError::Unavailable)?;
    destination.write_all(&ciphertext_len.to_be_bytes())?;
    destination.write_all(&sequence.to_be_bytes())?;
    destination.write_all(&[kind, 0])?;
    destination.write_all(&nonce)?;
    destination.write_all(&ciphertext)?;
    u64::try_from(FRAME_HEADER_BYTES + ciphertext.len()).map_err(|_| ArchiveError::InvalidBound)
}

fn read_frame<R: Read>(
    source: &mut R,
    key: &[u8; 32],
    archive_id: Uuid,
    expected_sequence: u64,
    chunk_bytes: u32,
) -> Result<(u8, Zeroizing<Vec<u8>>, u64), ArchiveError> {
    let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
    source.read_exact(&mut frame_header)?;
    let ciphertext_len = u32::from_be_bytes(
        frame_header[0..4]
            .try_into()
            .map_err(|_| ArchiveError::Integrity)?,
    );
    let sequence = u64::from_be_bytes(
        frame_header[4..12]
            .try_into()
            .map_err(|_| ArchiveError::Integrity)?,
    );
    let kind = frame_header[12];
    if sequence != expected_sequence || frame_header[13] != 0 {
        return Err(ArchiveError::Integrity);
    }
    let max_plaintext = if kind == 2 {
        chunk_bytes as usize
    } else {
        MAX_MANIFEST_BYTES
    };
    let ciphertext_len_usize =
        usize::try_from(ciphertext_len).map_err(|_| ArchiveError::InvalidBound)?;
    if ciphertext_len_usize < AEAD_TAG_BYTES
        || ciphertext_len_usize > max_plaintext + AEAD_TAG_BYTES
    {
        return Err(ArchiveError::InvalidBound);
    }
    let mut ciphertext = vec![0_u8; ciphertext_len_usize];
    source.read_exact(&mut ciphertext)?;
    let nonce_bytes: [u8; 24] = frame_header[14..38]
        .try_into()
        .map_err(|_| ArchiveError::Integrity)?;
    let nonce = XNonce::from(nonce_bytes);
    let aad = frame_aad(archive_id, sequence, kind, ciphertext_len);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ArchiveError::Unavailable)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArchiveError::Integrity)?,
    );
    let size = u64::try_from(FRAME_HEADER_BYTES + ciphertext_len_usize)
        .map_err(|_| ArchiveError::InvalidBound)?;
    Ok((kind, plaintext, size))
}

fn frame_aad(archive_id: Uuid, sequence: u64, kind: u8, ciphertext_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 8 + 1 + 4);
    aad.extend_from_slice(b"SMCV-FRAME-v1\0");
    aad.extend_from_slice(archive_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.push(kind);
    aad.extend_from_slice(&ciphertext_len.to_be_bytes());
    aad
}

struct RecordCounter {
    header: [u8; 8],
    header_used: usize,
    remaining_payload: u32,
    records: u64,
    limit: u64,
}

impl RecordCounter {
    const fn new(limit: u64) -> Self {
        Self {
            header: [0; 8],
            header_used: 0,
            remaining_payload: 0,
            records: 0,
            limit,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) -> Result<(), ArchiveError> {
        while !bytes.is_empty() {
            if self.remaining_payload > 0 {
                let remaining_payload = usize::try_from(self.remaining_payload)
                    .map_err(|_| ArchiveError::InvalidBound)?;
                let consumed = bytes.len().min(remaining_payload);
                self.remaining_payload = self
                    .remaining_payload
                    .checked_sub(u32::try_from(consumed).map_err(|_| ArchiveError::InvalidBound)?)
                    .ok_or(ArchiveError::Integrity)?;
                bytes = &bytes[consumed..];
                continue;
            }
            let needed = 8 - self.header_used;
            let consumed = needed.min(bytes.len());
            self.header[self.header_used..self.header_used + consumed]
                .copy_from_slice(&bytes[..consumed]);
            self.header_used += consumed;
            bytes = &bytes[consumed..];
            if self.header_used == 8 {
                let flags = u16::from_be_bytes([self.header[2], self.header[3]]);
                let length = u32::from_be_bytes([
                    self.header[4],
                    self.header[5],
                    self.header[6],
                    self.header[7],
                ]);
                if flags & !1 != 0 || length > MAX_LOGICAL_RECORD_BYTES {
                    return Err(ArchiveError::Integrity);
                }
                self.records = self
                    .records
                    .checked_add(1)
                    .ok_or(ArchiveError::InvalidBound)?;
                if self.records > self.limit {
                    return Err(ArchiveError::InvalidBound);
                }
                self.remaining_payload = length;
                self.header_used = 0;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<u64, ArchiveError> {
        if self.header_used != 0 || self.remaining_payload != 0 {
            return Err(ArchiveError::Integrity);
        }
        Ok(self.records)
    }
}

fn recovery_checksum(key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"SMCV-BACKUP-RECOVERY-CHECK-v1");
    digest.update(key);
    hex_lower(&digest.finalize()[..4])
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, HeaderError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(HeaderError::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HeaderError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(HeaderError::Truncated)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, HeaderError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(HeaderError::Truncated)?;
    Ok(u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use proptest::prelude::*;
    use uuid::Uuid;

    use super::{
        ALGORITHM_SUITE, ArchiveError, ArchiveKey, ArchiveMetadata, ArchiveOptions, FORMAT_VERSION,
        FRAME_HEADER_BYTES, HeaderError, KeyMode, MAGIC, MAX_ARCHIVE_BYTES, MIN_CHUNK_BYTES,
        RecoveryKey, decode_archive, parse_public_header, verify_archive, write_archive,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct FailAfter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for FailAfter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() >= self.limit {
                return Err(std::io::Error::other("injected capacity exhaustion"));
            }
            let accepted = input.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&input[..accepted]);
            Ok(accepted)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn valid_header() -> Vec<u8> {
        let salt = [0x55_u8; 16];
        let header_len = 142_u16;
        let mut bytes = Vec::with_capacity(usize::from(header_len));
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&ALGORITHM_SUITE.to_be_bytes());
        bytes.push(KeyMode::PassphraseArgon2id as u8);
        bytes.push(0);
        bytes.extend_from_slice(&header_len.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.push(16);
        bytes.extend_from_slice(&(64_u32 * 1024).to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&(1024_u32 * 1024).to_be_bytes());
        bytes.extend_from_slice(&1000_u64.to_be_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&[0x22; 24]);
        bytes.extend_from_slice(&[0x33; 48]);
        bytes
    }

    #[test]
    fn valid_header_is_bounded_before_kdf() -> Result<(), HeaderError> {
        let bytes = valid_header();
        let parsed = parse_public_header(&bytes, 4096)?;

        assert_eq!(parsed.key_mode, KeyMode::PassphraseArgon2id);
        assert_eq!(parsed.salt.len(), 16);
        assert_eq!(parsed.chunk_bytes, 1024 * 1024);
        Ok(())
    }

    #[test]
    fn rejects_hostile_lengths_and_kdf_costs() {
        let mut oversized_header = valid_header();
        oversized_header[14..16].copy_from_slice(&257_u16.to_be_bytes());
        assert_eq!(
            parse_public_header(&oversized_header, 4096),
            Err(HeaderError::InvalidBound)
        );

        let mut expensive_kdf = valid_header();
        expensive_kdf[33..37].copy_from_slice(&(2_u32 * 1024 * 1024).to_be_bytes());
        assert_eq!(
            parse_public_header(&expensive_kdf, 4096),
            Err(HeaderError::InvalidKdf)
        );
        assert_eq!(
            parse_public_header(&valid_header(), MAX_ARCHIVE_BYTES + 1),
            Err(HeaderError::ArchiveTooLarge)
        );
    }

    fn logical_stream(payloads: &[&[u8]]) -> TestResult<Vec<u8>> {
        let mut stream = Vec::new();
        for (index, payload) in payloads.iter().enumerate() {
            let kind = u16::try_from(index + 1)?;
            let length = u32::try_from(payload.len())?;
            stream.extend_from_slice(&kind.to_be_bytes());
            stream.extend_from_slice(&0_u16.to_be_bytes());
            stream.extend_from_slice(&length.to_be_bytes());
            stream.extend_from_slice(payload);
        }
        Ok(stream)
    }

    fn metadata() -> ArchiveMetadata {
        ArchiveMetadata {
            logical_vault_id: Uuid::from_u128(1),
            source_installation_id: Uuid::from_u128(2),
            source_recovery_epoch: 3,
            source_schema_version: 4,
            security_semantics_version: 1,
            created_at_unix_ms: 5,
        }
    }

    fn recovery_archive() -> TestResult<(Vec<u8>, RecoveryKey, Vec<u8>)> {
        let key = RecoveryKey::generate()?;
        let logical = logical_stream(&[b"protected-label", b"protected-secret"])?;
        let mut archive = Vec::new();
        let summary = write_archive(
            Cursor::new(&logical),
            &mut archive,
            ArchiveKey::Recovery(&key),
            &metadata(),
            ArchiveOptions::default(),
        )?;
        assert_eq!(summary.archive_bytes, u64::try_from(archive.len())?);
        assert_eq!(summary.record_count, 2);
        Ok((archive, key, logical))
    }

    #[test]
    fn recovery_key_is_checksummed_and_redacted() -> TestResult {
        let key = RecoveryKey::generate()?;
        let exposed = key.expose_once();
        let parsed = RecoveryKey::parse(&exposed)?;
        assert_eq!(parsed.expose_once(), exposed);
        assert_eq!(format!("{key:?}"), "RecoveryKey([REDACTED])");

        let mut damaged = exposed.into_bytes();
        if let Some(last) = damaged.last_mut() {
            *last = if *last == b'a' { b'b' } else { b'a' };
        }
        assert!(RecoveryKey::parse(std::str::from_utf8(&damaged)?).is_err());
        Ok(())
    }

    #[test]
    fn archive_round_trip_hides_plaintext_from_public_header() -> TestResult {
        let (archive, key, logical) = recovery_archive()?;
        let header_len = usize::from(u16::from_be_bytes([archive[14], archive[15]]));
        assert!(
            !archive[..header_len]
                .windows(b"protected-label".len())
                .any(|window| window == b"protected-label")
        );
        assert!(
            !archive
                .windows(b"protected-secret".len())
                .any(|window| window == b"protected-secret")
        );

        let mut restored = Vec::new();
        let verified = decode_archive(
            Cursor::new(&archive),
            u64::try_from(archive.len())?,
            ArchiveKey::Recovery(&key),
            |chunk| {
                restored.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        assert_eq!(restored, logical);
        assert_eq!(verified.metadata, metadata());
        assert_eq!(verified.record_count, 2);
        Ok(())
    }

    #[test]
    fn passphrase_archive_round_trips() -> TestResult {
        let logical = logical_stream(&[b"one"])?;
        let mut archive = Vec::new();
        write_archive(
            Cursor::new(logical),
            &mut archive,
            ArchiveKey::Passphrase(b"a sufficiently long backup passphrase"),
            &metadata(),
            ArchiveOptions::default(),
        )?;
        let verified = verify_archive(
            Cursor::new(&archive),
            u64::try_from(archive.len())?,
            ArchiveKey::Passphrase(b"a sufficiently long backup passphrase"),
        )?;
        assert_eq!(verified.record_count, 1);
        Ok(())
    }

    #[test]
    fn wrong_key_corruption_truncation_and_extension_fail_closed() -> TestResult {
        let (archive, key, _) = recovery_archive()?;
        let wrong_key = RecoveryKey::generate()?;
        assert!(matches!(
            verify_archive(
                Cursor::new(&archive),
                u64::try_from(archive.len())?,
                ArchiveKey::Recovery(&wrong_key)
            ),
            Err(ArchiveError::InvalidKey)
        ));

        let mut corrupted = archive.clone();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 1;
        }
        assert!(
            verify_archive(
                Cursor::new(&corrupted),
                u64::try_from(corrupted.len())?,
                ArchiveKey::Recovery(&key)
            )
            .is_err()
        );

        let truncated = &archive[..archive.len() - 1];
        assert!(
            verify_archive(
                Cursor::new(truncated),
                u64::try_from(truncated.len())?,
                ArchiveKey::Recovery(&key)
            )
            .is_err()
        );

        let mut extended = archive;
        extended.push(0);
        assert!(matches!(
            verify_archive(
                Cursor::new(&extended),
                u64::try_from(extended.len())?,
                ArchiveKey::Recovery(&key)
            ),
            Err(ArchiveError::Integrity)
        ));
        Ok(())
    }

    #[test]
    fn capacity_exhaustion_returns_failure_with_only_encrypted_partial_bytes() -> TestResult {
        let key = RecoveryKey::generate()?;
        let sentinel = b"synthetic-capacity-sentinel";
        let filler = vec![0x5a; 32 * 1024];
        let logical = logical_stream(&[sentinel, &filler])?;
        for limit in [0, 64, 160, 1024, 8192] {
            let mut destination = FailAfter {
                bytes: Vec::new(),
                limit,
            };
            assert!(
                write_archive(
                    Cursor::new(&logical),
                    &mut destination,
                    ArchiveKey::Recovery(&key),
                    &metadata(),
                    ArchiveOptions::default(),
                )
                .is_err()
            );
            assert!(
                !destination
                    .bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            );
        }
        Ok(())
    }

    fn frame_ranges(archive: &[u8]) -> TestResult<Vec<std::ops::Range<usize>>> {
        let mut offset = usize::from(u16::from_be_bytes([archive[14], archive[15]]));
        let mut ranges = Vec::new();
        while offset < archive.len() {
            let length_bytes: [u8; 4] = archive
                .get(offset..offset + 4)
                .ok_or("truncated test frame")?
                .try_into()?;
            let ciphertext_len = usize::try_from(u32::from_be_bytes(length_bytes))?;
            let end = offset
                .checked_add(FRAME_HEADER_BYTES)
                .and_then(|value| value.checked_add(ciphertext_len))
                .ok_or("test frame overflow")?;
            if end > archive.len() {
                return Err("truncated test frame".into());
            }
            ranges.push(offset..end);
            offset = end;
        }
        Ok(ranges)
    }

    #[test]
    fn reordered_duplicate_and_downgraded_frames_fail_closed() -> TestResult {
        let key = RecoveryKey::generate()?;
        let payload = vec![0x5a_u8; 40 * 1024];
        let logical = logical_stream(&[&payload])?;
        let mut archive = Vec::new();
        write_archive(
            Cursor::new(logical),
            &mut archive,
            ArchiveKey::Recovery(&key),
            &metadata(),
            ArchiveOptions {
                chunk_bytes: MIN_CHUNK_BYTES,
                ..ArchiveOptions::default()
            },
        )?;
        let ranges = frame_ranges(&archive)?;
        assert!(ranges.len() >= 5);

        let mut reordered = Vec::with_capacity(archive.len());
        reordered.extend_from_slice(&archive[..ranges[1].start]);
        reordered.extend_from_slice(&archive[ranges[2].clone()]);
        reordered.extend_from_slice(&archive[ranges[1].clone()]);
        reordered.extend_from_slice(&archive[ranges[2].end..]);
        assert!(
            verify_archive(
                Cursor::new(&reordered),
                u64::try_from(reordered.len())?,
                ArchiveKey::Recovery(&key),
            )
            .is_err()
        );

        let final_start = ranges.last().ok_or("missing final frame")?.start;
        let mut duplicated = Vec::with_capacity(archive.len() + ranges[1].len());
        duplicated.extend_from_slice(&archive[..final_start]);
        duplicated.extend_from_slice(&archive[ranges[1].clone()]);
        duplicated.extend_from_slice(&archive[final_start..]);
        assert!(
            verify_archive(
                Cursor::new(&duplicated),
                u64::try_from(duplicated.len())?,
                ArchiveKey::Recovery(&key),
            )
            .is_err()
        );

        let mut downgraded = archive;
        downgraded[8..10].copy_from_slice(&0_u16.to_be_bytes());
        assert!(matches!(
            verify_archive(
                Cursor::new(&downgraded),
                u64::try_from(downgraded.len())?,
                ArchiveKey::Recovery(&key),
            ),
            Err(ArchiveError::Header(HeaderError::Unsupported))
        ));
        Ok(())
    }

    #[test]
    fn representative_large_archive_crosses_many_bounded_frames() -> TestResult {
        let key = RecoveryKey::generate()?;
        let payload = vec![0x6b_u8; 16 * 1024 * 1024];
        let logical = logical_stream(&[&payload])?;
        let mut archive = Vec::new();
        let summary = write_archive(
            Cursor::new(&logical),
            &mut archive,
            ArchiveKey::Recovery(&key),
            &metadata(),
            ArchiveOptions {
                chunk_bytes: 256 * 1024,
                ..ArchiveOptions::default()
            },
        )?;
        assert_eq!(summary.record_count, 1);
        assert!(frame_ranges(&archive)?.len() >= 66);
        let verified = verify_archive(
            Cursor::new(&archive),
            u64::try_from(archive.len())?,
            ArchiveKey::Recovery(&key),
        )?;
        assert_eq!(verified.logical_bytes, u64::try_from(logical.len())?);
        Ok(())
    }

    #[test]
    fn committed_v1_fixture_remains_fully_readable() -> TestResult {
        let archive = include_bytes!("../fixtures/v1-minimal.smcvault");
        let key =
            RecoveryKey::parse("smcvbrk_v1.M6_qs6hHm50zrqXxU3vlWWCdK8FWcnIhAkiuqMnITp0.83d973d9")?;
        let verified = verify_archive(
            Cursor::new(archive),
            u64::try_from(archive.len())?,
            ArchiveKey::Recovery(&key),
        )?;
        assert_eq!(verified.header.key_mode, KeyMode::RecoveryKey);
        assert_eq!(verified.record_count, 2);
        assert_eq!(verified.metadata.source_schema_version, 3);
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_headers_never_panic(input in prop::collection::vec(any::<u8>(), 0..600)) {
            let _result = parse_public_header(&input, input.len() as u64);
        }

        #[test]
        fn arbitrary_complete_archives_never_panic(
            input in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let key = RecoveryKey([0x42; 32].into());
            let _result = verify_archive(
                Cursor::new(&input),
                input.len() as u64,
                ArchiveKey::Recovery(&key),
            );
        }
    }
}
