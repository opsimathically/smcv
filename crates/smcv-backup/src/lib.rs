#![forbid(unsafe_code)]
#![doc = "Bounded framing primitives for portable SMCV backup archives."]

use thiserror::Error;
use uuid::Uuid;

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
const MIN_SALT_BYTES: usize = 16;
const MAX_SALT_BYTES: usize = 32;

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
    if !(FIXED_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&header_len) || bytes.len() < header_len {
        return Err(HeaderError::InvalidBound);
    }

    let archive_id = Uuid::from_slice(&bytes[16..32]).map_err(|_| HeaderError::InvalidBound)?;
    let salt_len = usize::from(bytes[32]);
    let expected_len = FIXED_HEADER_BYTES
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
                bytes[FIXED_HEADER_BYTES..header_len].to_vec(),
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

    Ok(PublicHeader {
        archive_id,
        key_mode: mode,
        salt,
        argon2,
        chunk_bytes,
        record_limit,
    })
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
    use proptest::prelude::*;

    use super::{
        ALGORITHM_SUITE, FORMAT_VERSION, HeaderError, KeyMode, MAGIC, MAX_ARCHIVE_BYTES,
        parse_public_header,
    };

    fn valid_header() -> Vec<u8> {
        let salt = [0x55_u8; 16];
        let mut bytes = Vec::with_capacity(70);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&ALGORITHM_SUITE.to_be_bytes());
        bytes.push(KeyMode::PassphraseArgon2id as u8);
        bytes.push(0);
        bytes.extend_from_slice(&70_u16.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.push(16);
        bytes.extend_from_slice(&(64_u32 * 1024).to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&(1024_u32 * 1024).to_be_bytes());
        bytes.extend_from_slice(&1000_u64.to_be_bytes());
        bytes.extend_from_slice(&salt);
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

    proptest! {
        #[test]
        fn arbitrary_headers_never_panic(input in prop::collection::vec(any::<u8>(), 0..600)) {
            let _result = parse_public_header(&input, input.len() as u64);
        }
    }
}
