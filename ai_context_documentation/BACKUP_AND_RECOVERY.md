# Backup and recovery

Status: **Delivered core and Phase 4 browser workflows**
Last reviewed: 2026-07-21

## Recovery promise

A supported SMCV installation can use a valid `.smcvault` archive plus its
separate passphrase or recovery key to restore the durable vault into a new or
empty destination without the source machine or source root key.

This promise is verified by clean-environment restore tests. A file that has
never been verified and restored is not treated as a proven backup.

## Backup types

### Portable encrypted vault backup

The primary owner-facing backup. It is logically exported and re-encrypted
under an archive key, supports safe inspection and verification, and is
portable across compatible installations.

### Local SQLite operational snapshot

An optional operator mechanism for fast same-installation rollback. It uses
SQLite's supported online backup behavior and still requires the source key
provider. It does not satisfy the portability promise and must not be labeled a
portable vault backup.

### Plaintext export

Not part of v1. If introduced later, it is a separate high-risk capability with
recent authentication, explicit destination warnings, minimal scope, and
audit. It must never share the safe-sounding "backup" label.

## Portable archive contents

Included:

- Vault format and portable vault-security semantics needed for interpretation.
- Namespace structure and encrypted display metadata.
- Secrets, all retained immutable versions, tombstones, and lifecycle metadata.
- Owner identity and durable authenticators/recovery verifiers needed by the
  approved recovery model.
- Service identities, credential verifiers, revocation state, policy bindings,
  and the distinct vault-scoped token-verifier key reprotected inside archive
  encryption.
- Audit history and chain/commitment state.
- Safe migration and key-version history needed for provenance.

Excluded:

- Source root keys, vault KEKs, unwrapped DEKs, and source-provider credentials.
- Archive passphrase or recovery key.
- Raw application credentials, passwords, sessions, CSRF state, and recovery
  codes already issued display-once.
- Rate-limit state, in-progress HTTP requests, telemetry, caches, and host paths.
- Uncommitted SQLite pages or partial maintenance effects.
- Host paths, bind addresses, TLS private keys, trusted-proxy configuration,
  runtime limits, source key-provider locations, and other installation-bound
  configuration. Restore reports the destination settings that require setup.

Because application credentials are stored as verifiers, an exact disaster
recovery restore allows existing applications to continue authenticating. A
migration restore can revoke all imported application credentials before
activation and returns a report of identities requiring new credentials.

Owner passkeys may be bound to the source relying-party ID. Restore retains
their public records for provenance but enables them only after validating the
destination RP binding. A local single-use recovery ceremony establishes or
reenrolls the destination owner; no remotely claimable bootstrap route exists.

## Logical identity and recovery epochs

Disaster recovery preserves the logical vault ID and stable object IDs so
policies, client references, and history remain coherent. Every restore creates
a new installation ID and increments a recovery epoch. New record envelopes
bind the destination installation ID, and new audit events begin a destination
segment referencing the imported archive.

This design makes a fork visible but cannot prevent two restored clones from
running. The workflow warns the operator to decommission the old installation.
Migration and uncertain-compromise runbooks rotate or revoke credentials so
two installations do not remain equally authoritative.

## Committed archive structure

```text
fixed magic + format version
bounded public header
encrypted authenticated manifest
ordered encrypted authenticated chunks
encrypted authenticated final manifest/commitment
```

The public header reveals only what is needed to select a supported reader and
derive/locate the archive key: format version, archive ID, algorithm suite, KDF
type and bounded parameters, random salt, and chunk framing. It does not expose
vault name, secret names, identity labels, policy names, or record timestamps.

The encrypted manifest commits to source version, creation time, logical record
types and counts, compatibility requirements, and stream digest. Each chunk
authenticates archive ID, monotonically increasing sequence, record framing,
and final status. The final commitment prevents accepting a valid prefix as a
complete archive.

The exact version 1 byte layout, logical record registry, bounds, and
compatibility behavior are specified in
[Portable archive format version 1](PORTABLE_ARCHIVE_FORMAT_V1.md).

Compression is disabled initially. If later introduced, it occurs before
encryption and enforces strict decompressed-size and ratio limits.

## Backup key modes

### Passphrase mode

The UI or CLI obtains a passphrase through a protected input, derives a wrapping
key with a bounded memory-hard KDF and random salt, and confirms the passphrase
before beginning a large export. The passphrase is not an argument, log field,
filename, saved preference, or archive field.

Generated recovery-key mode is recommended. Passphrase mode enforces a minimum
length and checks compromised/common values without arbitrary composition
rules. It explains that archive theft permits offline guessing and that the KDF
only raises guessing cost; it cannot make a weak passphrase strong.

### Generated recovery-key mode

SMCV generates uniformly random recovery material and displays it once in an
unambiguous encoded form with checksum. The operator confirms custody before
the backup is considered complete. SMCV does not retain the raw recovery key.

During implementation and Phase 6, this workflow is exercised with synthetic
recovery material. The owner's personal real-key custody exercise is scheduled
after complete development under D-016 and is not a phase gate.

### Automated mode

Scheduled CLI jobs obtain a random backup wrapping key from an explicit
protected file descriptor, OS credential, or future external key provider.
They never accept it in process arguments. Automation records verification and
supports retention without deleting the last known-good backup.

## Create workflow

1. Require owner authorization and recent authentication.
2. Acquire a consistent logical snapshot and record its audit boundary.
3. Select and confirm backup key mode.
4. Write to a newly created restrictive temporary destination in the target
   directory; the temporary file contains only encrypted archive bytes.
5. Stream logical records through bounded plaintext buffers, encrypting before
   write.
6. Finalize and authenticate the manifest and stream commitment.
7. Reopen and verify the completed archive with the supplied key.
8. Commit the chained authorization/result event while the verified archive
   still has only its opaque partial name.
9. Publish without overwrite to the chosen `.smcvault` destination and sync the
   containing directory. Any audit or publication failure removes the partial;
   a final name is never exposed before required audit state commits.
10. Return safe archive ID, size, format, creation time, and
   counts.

Failure removes or clearly marks only the incomplete encrypted temporary file.
It never overwrites an existing destination by default.

For web creation, the verified encrypted artifact uses an opaque randomized
server filename, restrictive permissions, per-owner size/count quotas, and a
short explicit expiry. Durable job status survives a browser disconnect.
Completed status includes the encrypted artifact's byte count and SHA-256;
download validates both plus same-owner restrictive regular-file custody, then
streams from the already-validated no-follow descriptor. Corruption or an
unsafe path transitions the job to `failed/artifact_integrity_failed` and
removes the suspect file.
Downloading does not prove the owner retained an off-host copy; the UI records
download status separately and removes the server artifact after configured
download/expiry behavior.

Phase 5 scheduled operation uses `smcv-cli backup-maintain` with a protected
recovery-key descriptor. It creates and verifies the new archive first, never
places that new archive in the deletion set, deletes only older files that
fully authenticate under the supplied key, and fails the service invocation if
any candidate is unverifiable. `backup-restore-drill` performs a real clean
restore/reopen/integrity check under a restrictive temporary workspace and
removes the destination before reporting success.

## Inspect and verify

`inspect` without a key reports only public format and KDF information needed
for diagnosis. Authenticated inspect/verify reports safe encrypted-manifest
metadata, compatibility, counts, and integrity result without revealing secret
names or values.

Verification performs all framing, authenticated-integrity, stream commitment,
referential, count, and bounded cryptographic checks that do not require a
destination. It does not mutate the current vault. A fast header check is never
labeled full verification.

This proves integrity under the supplied backup key, not the identity of the
source installation. Source-origin authenticity requires a future signature or
external anchor.

## Restore workflow

1. Require a new/empty destination and protected staging directory. Fresh-host
   authority comes from the local CLI or a CLI-created single-use local channel.
2. Validate file type, ownership/permissions where applicable, total size,
   magic, supported version, and bounded header before expensive KDF work.
3. Obtain backup key through protected input and authenticate the encrypted
   manifest.
4. Create fresh destination root-provider material and initialize a non-ready
   restore state. Stream all records into its staging vault, re-encrypting
   protected fields under fresh destination vault keys and installation ID.
5. Reject unknown critical record types, duplicate identifiers, broken
   references, version gaps, invalid policy targets, audit discontinuity,
   excessive fields, and any cryptographic failure.
6. Apply the explicit preserve-or-revoke application credential choice.
7. Run destination schema, cryptographic sampling/full checks as specified,
   referential integrity, counts, and audit verification.
8. Validate or reenroll the destination owner through the local single-use
   recovery ceremony; disable restored authenticators whose RP binding is not
   valid for the destination.
9. Produce a safe restore report and require final confirmation where the UI
   workflow has not already committed intent.
10. Reopen the guarded non-ready destination through a new database connection,
    reload the external root provider, and unwrap every required key. Commit the
    installation activation marker only after that fresh-unlock proof; no
    fallible verification follows activation. An ordinary returned failure
    removes the newly created database, WAL/SHM, and root-provider files. A
    process crash may leave an explicitly non-ready guarded destination for
    identity-checked cleanup, but never a generically activatable partial vault.
11. Begin a new installation/recovery-epoch audit segment that references but
    does not rewrite imported history.

Import never trusts archive-supplied KDF values, paths, allocation sizes,
timestamps, IDs, or counts before bounds and structural validation.
Imported password and recovery-verifier PHC strings must use the exact supported
Argon2id profile before any password verification can allocate KDF memory.

## Rollback awareness

A valid old backup can intentionally reintroduce old secret versions, policy,
and credential verifiers. SMCV therefore shows backup creation time and a clear
rollback warning before activation. After recovery from an uncertain incident,
the runbook recommends revoking application credentials and rotating upstream
secrets based on exposure analysis.

An external audit anchor can reveal that a restored history is older than the
last externally observed event. Without an external anchor, SMCV cannot prove
that an internally consistent archive is the newest archive ever created.

## Restore authority and owner recovery

The local CLI is the root of fresh-host recovery authority because it already
requires operating-system access to the destination and key-provider setup.
It may perform the complete restore or mint a short-lived, single-use,
loopback/local-socket recovery channel for an accessible browser flow. That
channel is never logged, never exposed on a non-loopback listener, expires
quickly, and is consumed atomically.

The delivered browser ceremony is started with:

```sh
smcv backup-restore-browser \
  --database /new/data/vault.sqlite \
  --root-key /separate/provider/root.key
```

The CLI displays—not logs—a clean one-use URL and a separate random
authorization code. Browser code submits the code once in a protected request
body, clears the field, and receives an HttpOnly, SameSite-strict loopback
session cookie; neither value enters a URL, browser storage, or history. The
local process stores only their digests, accepts only the exact loopback
origin, keeps uploaded encrypted bytes in a restrictive random workspace,
holds supplied recovery material only in zeroizing process memory between
authenticated review and activation, and closes after one activation attempt
or ten minutes. Activation retains the source owner password verifier,
disables source-bound passkeys, reports their reenrollment count, and offers
explicit preserve-or-revoke handling for application credentials.

Possession of an archive and its key is necessary but does not by itself open a
public remote bootstrap endpoint. The destination ceremony establishes the
owner and verifies unlock before readiness.

## Compatibility policy

- Readers support a documented bounded set of prior archive versions.
- Writers produce only the current version unless an explicit tested
  compatibility option exists.
- Unknown non-critical fields may be ignored; unknown critical semantics fail.
- A newer incompatible archive never triggers a partial import.
- Release tests restore fixtures from every supported archive version.
- Format migration happens during staged import, never by modifying the source
  archive in place.

## Required recovery exercises

- Full restore to a clean machine-equivalent environment.
- Wrong key and subtly corrupted key.
- Every byte-region corruption, truncation, extension, chunk reordering, and
  duplicate chunk.
- Extreme allowed record count/size and one-over-limit rejection.
- Disk full and process termination at every restore phase.
- Source vault containing retired key versions and tombstones.
- Preserve-credentials and revoke-credentials modes.
- Restore from every supported old format, followed by new backup and restore.
- Comparison of logical IDs, versions, policies, audit counts, and sampled or
  complete protected payloads without writing plaintext evidence.
- Small and representative large bounded fixtures with peak time, memory, disk,
  and temporary-space results; Phase 3 sets provisional limits and Phase 5
  turns them into supported capacity and recovery objectives.

## Operator rule

Maintain at least one off-host verified portable backup and its separate key
material. Backup automation should use retention such as multiple recent and
periodic copies, but exact policy remains deployment-specific. Periodic restore
drills are mandatory for claiming recoverability.
