# Phase 1 exit report

Phase: 1 — encrypted vault and storage core
Date: 2026-07-21
Status: **Passed; Phase 2 active**
Phase boundary: the local commit containing this report

## Environment and scope

- Linux x86_64 development host
- `rustc 1.94.0 (4a4ef493e 2026-03-02)` and Cargo 1.94.0
- Bundled SQLite through locked `rusqlite 0.39.0`
- Synthetic temporary vaults and fresh ephemeral keys only

Delivered scope includes restrictive local initialization, external root-key
custody, versioned KEK/DEK hierarchy, encrypted metadata and values, immutable
versions, advisory expiration/rotation schedules, lifecycle and purge rules,
keyed clear-state and audit commitments, resumable KEK rotation, root-provider
replacement, checksummed migrations, and bounded operational snapshots.

## Acceptance and requirements evidence

| Requirements / criterion | Evidence and result |
|---|---|
| VAULT-001 | Root key is a separate fixed-format mode-`0600` provider file bound to vault and installation IDs. Missing, substituted, permissive, corrupt, or symlink providers fail closed. Initialization interruption resumes and activates only after all keys authenticate. |
| VAULT-002–004 | Domain tests create, reveal, append immutable versions, archive, restore, delete, and retention-gated purge opaque byte values. Stale version/revision writes conflict without overwrite. Purge consumes an internal owner-approval capability, retains tombstone/audit state, and makes no backup/media erasure claim. |
| VAULT-005–006 | XChaCha20-Poly1305 protects values plus names, descriptions, usernames, and tags. Raw SQLite, WAL, and related files contain none of the synthetic protected sentinels. Every envelope records suite, envelope, nonce, object/version context, and wrapping-key version. Every nonce/ciphertext/wrapped-key/key-version/object/version substitution tested fails authentication. |
| VAULT-007 | Immutable versions store optional expiration and explicitly named upstream-credential-rotation timestamps. A bounded current-version due query distinguishes expired from rotation-due and replacement versions supersede old schedules. |
| AUDIT-001/AUDIT-004 persistence | Every successful domain mutation and explicit reveal appends an atomic domain-separated HMAC chain event. Audit rejection rolls back the mutation. Offline event modification fails verification. The local full-database rollback/tail-removal limit is documented. |
| OPS-001/OPS-002 database behavior | Database and snapshots are atomic mode-`0600` creations; unsafe files fail closed. WAL, FULL sync, foreign keys, secure deletion, trusted-schema off, a five-second busy bound, 16 MiB SQL value limit, quick integrity check, and no-overwrite online backup are executable tests. |
| Rotation interruption | New writes switch to KEK v2 immediately. One-record rewrap batches repeatedly drop and reopen the application across all durable stages while old and new records remain readable. Source inventory reaches zero before v1 retires. Root replacement verifies every live KEK, retains the old file, and only the new provider reopens afterward. |
| Failure behavior | Database-page corruption never reports healthy; disk full rolls back a transaction; a second writer waits within the busy bound then commits; stale audit heads and forced audit insert failure roll back; committed WAL survives and an uncommitted transaction disappears. Errors do not include protected values or filesystem paths. |
| Migration compatibility | Frozen migration v1/checksum upgrades to current schema v2; current compiled checksum is tested; applied-checksum drift prevents open. Metadata `SMCVMD02`, AAD/envelope v1, root provider `SMCVKEY1`, and migration v1/v2 are compatibility anchors. |

## Reproducible validation

```text
./scripts/check.sh
  PASS: rustfmt and strict all-feature Clippy
  PASS: 42 unit/property/failure tests and all doc tests
  PASS: rustdoc warnings denied
  PASS: RustSec advisory scan and cargo-deny license/source policy
  PASS: exact application-token/private-key secret scan
  PASS: every relative Markdown link resolves
```

Focused tests exercise 18 application-domain cases, 12 SQLite/storage cases, 8
cryptographic cases, 3 hostile archive-header properties, and the protected
core type. The only dependency-policy warnings remain the documented `syn` 2/3
macro-stack duplicate and unused allowed license categories.

## Crash, recovery, and rotation observations

- A root-file-only interruption reuses the same bound identity; a database
  without its provider requires explicit recovery rather than silent reset.
- An initializing database authenticates every registry key before its final
  ready transition. Ready and maintenance startup validate the exact active and
  retiring KEK inventory against the durable job.
- KEK rotation checkpoints stage plus last committed row ID. Restart loads both
  required keys, resumes without duplicate effects, and retires the source only
  after inventory verification.
- Root replacement writes and synchronizes the replacement provider before one
  atomic database rewrap commit. Therefore interruption leaves either the old
  provider authoritative or the already durable new provider authoritative;
  neither file is deleted automatically.
- SQLite page corruption, WAL recovery, dropped transactions, busy locking,
  disk exhaustion, and audit failure all produced defined fail-closed results.

## Adversarial review

The focused [Phase 1 adversarial
review](../ai_context_documentation/reviews/PHASE_1_ADVERSARIAL_REVIEW.md)
recorded five high and four medium findings. All were corrected and regression
tested. Material corrections added restrictive atomic file creation, root-name
uniqueness, rewrap-compatible monotonic triggers, authenticated clear-state
commitments, exact startup key-state validation, symlink rejection, complete
protected metadata, and advisory due-state behavior.

No open critical or high finding remains.

## Compatibility and design decisions

- D-103 is committed: protected human metadata uses the frozen encrypted
  `SMCVMD02` document and namespace-scoped, case-sensitive NFC HMAC indexes with
  decrypted collision confirmation.
- State commitments share the audit key only through a separate cryptographic
  domain; they do not turn local storage into an external freshness oracle.
- Operational SQLite snapshots remain maintenance artifacts. They are not
  `.smcvault` portable backups and do not satisfy BACKUP requirements.
- Encryption-key rotation, root-provider rotation, application-credential
  rotation, and upstream secret rotation remain distinct terms.

## Unsafe, dependency, accessibility, and residual risk

- Workspace source continues to forbid unsafe Rust. The locked dependency
  graph passed current RustSec, license, and source checks.
- Phase 1 exposes no HTTP or browser workflow, so WCAG workflow validation is
  not applicable yet. Phase 4 retains executable accessibility ownership.
- A valid whole-database rollback cannot be distinguished without an external
  freshness anchor; the UI and recovery designs must not call the local chain
  tamper-proof.
- The root provider is a local file provider. OS keyrings/KMS/HSM integrations
  remain optional future adapters and are not development prerequisites.
- External assurance and personal recovery custody remain post-development
  owner actions under D-015/D-016 and do not block the continuous goal.

## Phase transition

No human task, external account, or new authority is required. Phase 2 may use
the frozen encrypted core and must place all plaintext-capable operations behind
authenticated, centralized, deny-by-default authorization before any protected
API route is enabled.
