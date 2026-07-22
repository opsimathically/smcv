# Portable archive format version 1

Status: **Committed by D-108**
Last reviewed: 2026-07-21

This is the non-secret interoperability and hostile-reader specification for
`.smcvault` format version 1. Writers emit only this version. Readers reject
every other version and algorithm suite before running a KDF.

All integers are unsigned big-endian. Archive and object identifiers are the
16-byte UUID representation. Reserved bytes and bits must be zero. The file is
complete only when its final authenticated manifest is present and the next
read reaches exact EOF.

## Public header

| Offset | Bytes | Meaning and v1 bound |
|---:|---:|---|
| 0 | 8 | ASCII magic `SMCVLT01` |
| 8 | 2 | Format version, exactly `1` |
| 10 | 2 | Algorithm suite, exactly `1` |
| 12 | 1 | Key mode: `1` Argon2id passphrase, `2` recovery key |
| 13 | 1 | Reserved zero |
| 14 | 2 | Total header bytes, 126–256 |
| 16 | 16 | Random archive ID |
| 32 | 1 | Salt bytes, 16–32 for passphrase or zero for recovery |
| 33 | 4 | Argon2 memory KiB, 65,536–262,144 in passphrase mode |
| 37 | 4 | Argon2 iterations, 1–10 in passphrase mode |
| 41 | 1 | Argon2 lanes, 1–4 in passphrase mode |
| 42 | 4 | Plaintext chunk bytes, 16 KiB–4 MiB |
| 46 | 8 | Logical-record limit, 1–10,000,000 |
| 54 | variable | Salt |
| after salt | 24 | XChaCha20-Poly1305 nonce wrapping the archive DEK |
| after nonce | 48 | Encrypted 32-byte random archive DEK plus tag |

The prefix from byte 0 through the wrapping nonce is AAD for the wrapped DEK.
Passphrase mode derives a 32-byte wrapping key with Argon2id v1.3 and the exact
bounded header parameters. Recovery mode derives a wrapping key with
HMAC-SHA-256 over domain `SMCV-BACKUP-WRAP-v1` and the archive ID, keyed by the
uniform 256-bit recovery key. The textual recovery-key form is
`smcvbrk_v1.<base64url-no-pad>.<8 lowercase hex checksum>`; it is key material,
not archive metadata.

The header intentionally contains no vault ID, installation ID, protected
label, record timestamp, path, count by record type, or recovery key. Header
authentication occurs when the wrapped archive DEK is opened.

## Encrypted frames

Every frame is:

| Bytes | Meaning |
|---:|---|
| 4 | Ciphertext bytes including the 16-byte tag |
| 8 | Sequence, starting at zero with no gaps |
| 1 | Kind: `1` initial manifest, `2` logical data, `3` final manifest |
| 1 | Reserved zero |
| 24 | Fresh XChaCha20-Poly1305 nonce |
| variable | Ciphertext and tag |

Frame AAD is the domain `SMCV-FRAME-v1\0`, archive ID, sequence, kind, and
ciphertext length. The initial manifest must be sequence zero. One or more
kind-2 frames may follow; a zero-record archive may have none. Exactly one
kind-3 final manifest terminates the stream. Any unknown kind, sequence gap,
duplicate, reorder, bytes after the final frame, or missing final frame fails.

The authenticated initial manifest is canonical JSON containing logical vault
ID, source installation ID and recovery epoch, source schema version, portable
security-semantics version, and creation time. These are safe only after key
authentication and are not a signature of source identity.

The final manifest is canonical JSON containing logical-record count, logical
byte count, SHA-256 of the exact canonical logical stream, and data-frame
count. Reader-observed values must equal every committed value.

## Canonical logical stream

Each record is `kind:u16, flags:u16, payload_length:u32, payload`. V1 accepts
only critical flag bit zero and rejects every other bit. A reader that does not
understand a critical record kind rejects the archive before activation.
Individual v1 logical records are limited to 32 MiB; the application currently
sets a 256 MiB total logical-stream limit and 8 GiB archive-file
limit below the framing layer's absolute 64 GiB ceiling.

Closed v1 kinds are:

| Kind | Logical content |
|---:|---|
| 1 | Vault-scoped blind-index, audit-commitment, and token-verifier keys |
| 10–13 | Namespace, secret metadata, immutable secret version, tombstone |
| 20–23 | Principal, owner authenticator, service identity, application credential |
| 30–33 | Authorization state, policy, grant, binding |
| 40 | Historical audit event |

Record payloads are canonical JSON. Protected metadata/value bytes and the
three portable vault-scoped keys use base64url without padding inside archive
encryption. Browser sessions, CSRF state, idempotency records, maintenance
jobs, rate limits, source root keys, source KEKs, raw credentials, and host
configuration have no record kind and are rejected if represented as an
unknown critical extension.

## Restore invariants

The complete archive is authenticated and logically parsed before destination
creation. Restore preserves the logical vault ID, creates a random installation
ID, increments the recovery epoch, creates a new external root and KEK, and
re-encrypts every protected envelope with destination-bound AAD. It recomputes
installation- or envelope-bound state commitments. The imported audit/index/
token-verifier keys remain protected inside archive encryption so historical
commitments, exact indexes, and optionally preserved credential verifiers keep
their intended meaning.

The destination stays `initializing` during one atomic logical import.
Foreign-key, database-integrity, envelope, state-commitment, authorization,
and audit-chain checks run before the ready marker is committed. A new audit
segment then records the restore under the new installation and epoch.

## Compatibility

The supported reader set is currently exactly `{1}`. Unknown versions,
algorithm suites, key modes, frame kinds, critical record kinds, and semantics
versions fail without partial import. A supported v1 fixture is retained under
`crates/smcv-backup/fixtures/`; release gates must continue to verify it and
must perform v1 restore → current backup → second restore.
