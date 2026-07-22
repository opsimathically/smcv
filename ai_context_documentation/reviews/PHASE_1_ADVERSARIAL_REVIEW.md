# Phase 1 cryptography and storage adversarial review

Status: **Complete; all findings closed**
Date: 2026-07-21
Scope: encrypted vault domain, SQLite persistence, key providers, state and
audit commitments, lifecycle, migrations, rotation, and failure behavior

## Review method

The implementation was reviewed against the Phase 1 adversarial prompts, the
threat model's stolen-database and failure adversaries, and every Phase 1
acceptance criterion. Review included source inspection, mutation of protected
and clear database fields, interruption at one-record rotation checkpoints,
unsafe filesystem modes, corrupt database pages, stale writes, disk-full and
busy injection, audit rejection, migration drift, and raw database/WAL scans.

No real vault data, credential, recovery material, or production path was used.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P1-A01 | High | Database and online-snapshot file creation inherited the process umask, and snapshot destination checking was race-prone. A permissive host could create broadly readable ciphertext or replace a checked destination. | Files are now atomically created with `create_new` at mode `0600`, parent creation is synchronized, unsafe existing database files and symlinks fail closed, and snapshots never overwrite. Unix mode and rejection tests pass. |
| P1-A02 | High | SQLite uniqueness over `(parent_namespace_id, name_index)` did not constrain duplicate root names because `NULL` values are distinct. | Added a partial unique root-name index and a domain regression test. Child uniqueness remains enforced by the non-null parent composite constraint. |
| P1-A03 | High | The first monotonic-secret trigger rejected cryptographic metadata-DEK rewraps because a rewrap intentionally preserves logical revision. Rotation could stall on secret metadata. | The trigger now distinguishes logical-field changes from wrapping-only changes. One-record batches traverse auxiliary, namespace, secret-metadata, and secret-version stages across repeated restarts. |
| P1-A04 | High | Clear lifecycle, current-version, revision, namespace, name-index, and schedule fields were transactionally constrained but not cryptographically authenticated. An offline editor could select an older valid ciphertext without forging its AEAD tag. | Added domain-separated HMAC state commitments for secret and namespace integrity-sensitive clear state. Reads, writes, due queries, lifecycle actions, and hierarchy use verify before acting. Offline pointer/lifecycle rollback now returns integrity failure. |
| P1-A05 | High | Startup loaded non-retired KEKs without proving that ready/maintenance state, active version, retiring version, and maintenance job formed one valid state machine. Corrupt mixed state could be accepted. | Startup now requires exactly one active KEK in ready state, or the exact active/retiring pair named by the unfinished rotation in maintenance state. Every wrapped key authenticates before readiness. |
| P1-A06 | Medium | Root-provider reads followed symlinks, weakening the explicit provider-location trust boundary. | Provider loading uses symlink metadata and accepts only a restrictive regular file. A symlink regression test fails closed. |
| P1-A07 | Medium | The initial protected metadata document represented name and description but omitted committed sensitive username and tag fields. | Frozen metadata format `SMCVMD02` now bounds and encrypts name, description, username, and tags. Round-trip fixture and database/WAL sentinel scans cover the added fields. |
| P1-A08 | Medium | VAULT-007 had no executable expiration/rotation-due model, and wording could blur encryption-key rotation with upstream credential rotation. | Immutable versions now carry bounded advisory expiration and upstream-rotation timestamps with a current-version due query. Tests prove both conditions independently and prove a replacement version changes the due state. |
| P1-A09 | Medium | The broad source secret scanner treated long internal `smcv_*` SQLite identifiers as credentials, making the complete gate fail after schema expansion. | Scanner now matches the exact versioned application-token shape while retaining private-key and cloud-key patterns. The repository check passes without excluding source files. |

## Residual limits

- Local audit and state commitments detect modification when the attacker lacks
  the vault key, but they cannot prove that an entire valid database was not
  rolled back. External anchoring remains optional and newest-instance claims
  remain explicitly limited.
- Local operational SQLite snapshots are not portable backups and do not
  satisfy owner recovery custody. Phase 3 implements `.smcvault` portability.
- Root-provider replacement deliberately retains the prior file. The operation
  never claims secure erasure; custody and later removal are operator actions.
- Phase 1 has no network authorization surface. Phase 2 must make operation
  contexts unforgeable outside the centralized authenticated authorization
  boundary before exposing any plaintext-capable domain method.

## Conclusion

All critical/high findings were repaired and retested inside Phase 1. No open
finding prevents Phase 2 entry. This review does not claim independent external
assurance; that remains a post-development handoff under D-015.
