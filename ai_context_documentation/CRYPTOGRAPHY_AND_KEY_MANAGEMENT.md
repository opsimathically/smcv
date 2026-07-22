# Cryptography and key management

Status: **Committed construction requirements; primitive selection proposed**
Last reviewed: 2026-07-21

## Rules

- Use standard reviewed primitives from maintained Rust libraries.
- No custom cipher, mode, padding, KDF, random generator, or key-wrapping
  construction.
- Stored envelopes identify format, algorithm suite, key version, and required
  parameters so safe migration is possible.
- Cryptographic agility does not mean accepting arbitrary algorithms from
  untrusted input; readers use a small compiled allowlist.
- Authentication failure and decryption failure do not release partial
  plaintext.

## Vault key hierarchy

The proposed hierarchy is:

```text
external root key material
        │ protects
versioned vault key-encryption key (KEK)
        │ wraps
random data-encryption key (DEK) per secret version
        │ encrypts
protected payload + protected metadata
```

The root-key provider is configured outside SQLite. SQLite may store a
provider locator, salt, wrapped KEK, key version, and verification metadata,
but never the root material needed to unwrap the KEK.

A random DEK per version confines nonce accounting and permits inexpensive KEK
rotation. The Phase 0 cryptographic decision record must select the exact AEAD,
wrapping construction, nonce generation rule, tag size, and maintained crate,
with test vectors and misuse analysis.

## Record envelope

Each encrypted record includes:

- Envelope and algorithm-suite version.
- Vault key version and wrapped DEK.
- Nonce or synthetic-IV material required by the selected suite.
- Ciphertext and authentication tag.
- An authenticated encoding of stable associated data.

Associated data includes at minimum a domain-separation label, logical vault
ID, installation ID, object type, object ID, immutable version, and envelope
version. Import re-encrypts envelopes for the destination installation.
Encoding is canonical and length-delimited; ambiguous string concatenation is
prohibited.

Ciphertext size limits are checked before allocation. Decryption first
validates fixed-width and bounded metadata, selects an allowed reader, and
authenticates the entire value.

## Protected metadata and lookup

Human-readable secret metadata is encrypted with the payload or under a
separate domain-separated key. Exact lookup may use a keyed, domain-separated
blind index over a canonical name and namespace identifier. The design must:

- Use a key distinct from encryption and token-verifier keys.
- Define Unicode normalization and case behavior once.
- Compare candidate decrypted values to handle theoretical collisions.
- Avoid supporting prefix or substring search by leaking progressively more
  information in v1.

## Root-key providers

The provider interface returns or performs a narrowly defined unwrap operation
for one expected logical vault and installation identity. Proposed v1 providers
are:

1. A protected local key file or operating-system service credential for
   unattended self-hosting.
2. An interactive manual-unlock provider for deployments that accept downtime
   after restart.

External KMS/HSM providers are deferred but the interface must not assume raw
root-key exportability. Environment variables and command arguments are not
recommended key sources because they are easily exposed by configuration,
diagnostic, shell-history, or process tooling.

Initialization generates root and vault key material from the operating
system's cryptographically secure random source, writes files with restrictive
creation semantics, and never prints a key unless the selected explicit
recovery workflow requires a display-once recovery value.

## Human password verification

Passwords are authentication material, not vault encryption keys. Store a
salted Argon2id verifier with parameters on each record. Phase 2 calibrates the
work factor on minimum supported hardware, applies upper bounds to imported or
stored parameters, and supports increasing cost after successful login.

V1 does not use a non-portable external password pepper because losing it would
violate the `.smcvault` plus archive-key recovery promise. A future pepper or
verifier key must either be a portable vault-scoped secret reprotected by the
archive workflow or become an explicit additional recovery dependency approved
through a product decision.

## Application credential verification

Application credentials contain a non-secret lookup identifier and at least
256 bits of random secret material in a self-identifying textual form. The raw
credential is shown once. Store a domain-separated keyed verifier and compare
it in constant time.

The domain-separated token-verifier key is vault-scoped secret material. It is
wrapped under the vault key hierarchy in normal storage and included only
inside the encrypted logical payload of a portable backup. Restore rewraps it
under destination keys. This preserves existing random-token verification
without exporting raw tokens or source root/KEK material. Revoke-credentials
restore mode discards imported credential records before activation.

Because tokens are uniformly random rather than human-selected, verification
does not need an intentionally expensive password KDF. Authentication performs
a dummy verification path for unknown lookup IDs to reduce enumeration
signals. Credential prefixes identify SMCV tokens for handling and leak
prevention without encoding authorization.

## Backup encryption

Portable archives use a fresh random archive DEK. That DEK is protected by
either:

- A key derived from a user passphrase using bounded Argon2id parameters and a
  random salt, or
- A uniformly random display-once recovery key.

The archive header authenticates the format version, vault export identity,
KDF selection and parameters, salt, algorithm suite, and chunking rules.
Payload chunks authenticate their sequence number, final/non-final status, and
archive identity. The final authenticated manifest commits to record counts
and a digest of the logical stream so truncation, extension, duplication, and
reordering fail.

The archive never contains its decryption key or the source root key. Import
decrypts bounded records in memory and re-encrypts them under destination vault
keys. More detail is in `BACKUP_AND_RECOVERY.md`.

## Rotation

### Vault KEK rotation

1. Create and durably record a new active KEK version.
2. New writes use the new version.
3. Rewrap existing DEKs in bounded resumable batches.
4. Verify every live record has an allowed key version.
5. Retire the old KEK only after a verified backup and explicit checkpoint.

Interruption leaves both required KEKs available and resumes idempotently.

### Root-provider rotation

Reprotect vault KEKs with the new provider/root material, verify an unlock
before removing the prior provider, and produce a fresh recovery artifact as
needed.

### Secret rotation

Secret rotation changes an upstream credential value and creates a new secret
version. It is not implied by KEK rotation. SMCV must use precise language for
these different events.

## Memory and side channels

- Secret-bearing types avoid `Debug`, `Display`, serialization defaults, and
  implicit cloning.
- Plaintext buffers are scoped narrowly and zeroized where the library and
  ownership model permit.
- Core dumps and swap exposure are deployment concerns documented for
  operators; memory locking may be offered best-effort.
- Authentication and verifier comparisons are constant-time where secrets are
  compared.
- Error categories and timing should not expose record existence or whether a
  particular cryptographic field failed.

Rust and operating systems may copy or retain memory beyond reliable
application control. Documentation must say "best-effort memory exposure
reduction," never "plaintext is guaranteed erased."

## Validation gate

Before Phase 1 storage implementation, the cryptographic proposal needs:

- Primitive and crate selection with maintenance and security history.
- A concise construction proof/rationale and threat mapping.
- Cross-language or independent known-answer vectors where available.
- Nonce and key uniqueness analysis.
- Corrupt-field and record-substitution test matrix.
- Rotation, interruption, backup, and restore compatibility tests.
- A fresh adversarial second-pass review of the decision record, with an
  external-review-ready handoff retained for post-development assurance.
