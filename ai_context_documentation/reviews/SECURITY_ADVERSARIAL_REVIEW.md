# Security and abuse adversarial review

Review date: 2026-07-21
Review target: pre-implementation documentation draft
Status: **Complete — findings applied and verified in documentation**

## Method

The review assumed control of a service credential, theft of database/backup
artifacts, a malicious archive author, a hostile website, operational mistakes,
and a clean-host disaster recovery. It traced secret, key, identity, policy,
and audit state across initialization, use, rotation, backup, restore, and
failure. It also searched for security claims stronger than their mechanism.

## Findings

### SEC-AR-001 — Keyed application verifiers were not portable

Severity: **High**
Affected: AUTHN-004, BACKUP-003, BACKUP-010, D-105, D-109

The draft required keyed application-token verifiers while excluding all
source keys from a portable archive. A raw token cannot be reconstructed, so a
restore could not preserve authentication unless its verifier key were
portably reprotected. That contradicted the disaster-recovery promise.

Required correction: define a vault-scoped, domain-separated verifier key that
is protected under the vault hierarchy, logically included inside archive
encryption, and reprotected under destination keys. It is not a root key. Test
both preserve and revoke modes.

### SEC-AR-002 — Restored owner authenticators might be unusable or unsafe

Severity: **High**
Affected: AUTHN-002, BACKUP-003, BACKUP-007

Passkeys/WebAuthn credentials are scoped to an RP identity and may not work on
a fresh destination hostname. The draft said durable authenticators were
included but did not define how the owner regains control without creating an
unauthenticated remote bootstrap route.

Required correction: make restore authority local, require possession of the
archive key and destination root-key setup, create a single-use destination
owner recovery ceremony, preserve compatible authenticators only after RP-ID
validation, and disable incompatible ones pending reenrollment.

### SEC-AR-003 — Portable restore created an undocumented vault clone/fork

Severity: **High**
Affected: BACKUP-007, BACKUP-010, AUDIT-004

A portable archive can start a second valid instance with the same service
credentials and historical identity. Without a logical-vault/installation
distinction, operators could run both, split audit history, or mistake an old
clone for the current authority.

Required correction: preserve a logical vault ID for disaster recovery, create
a new installation ID and recovery epoch on restore, mark audit segments, warn
against concurrent clones, and require decommission/rotation guidance for
migration or uncertain recovery. Do not claim local detection of the newest
clone without an external anchor.

### SEC-AR-004 — “Authenticity” overclaimed archive provenance

Severity: **Medium**
Affected: BACKUP-006 and backup language

AEAD under a supplied passphrase/key proves integrity and possession of that
key, not that a named source installation created the archive. A malicious
party with the backup key could create another internally valid archive.

Required correction: use “authenticated integrity under the supplied backup
key” and reserve origin authenticity for a future signature/externally anchored
mechanism.

### SEC-AR-005 — Staging activation did not bind key-provider creation

Severity: **Medium**
Affected: VAULT-001, BACKUP-007, OPS-003

The draft described atomic database activation but not the ordering and cleanup
of fresh destination root/provider material. A crash could orphan keys, expose
a ready marker too early, or leave ambiguous initialization state.

Required correction: define restore as an initialization state machine that
creates destination provider material, re-encrypts staging, verifies unlock,
commits an activation marker last, and handles orphan cleanup explicitly.

### SEC-AR-006 — Weak backup passphrases could undermine archive security

Severity: **Medium**
Affected: BACKUP-002, backup key modes

A memory-hard KDF does not rescue a weak passphrase. The draft did not prefer
generated recovery keys or require a passphrase strength policy and confirmation.

Required correction: recommend generated recovery keys, enforce a length and
compromised/common-value policy without arbitrary composition rules, confirm
input, and explain offline guessing risk. Keep archive-supplied KDF parameters
strictly bounded.

### SEC-AR-007 — Optional non-portable password pepper broke recovery

Severity: **Medium**
Affected: AUTHN-002, recovery promise

An optional password pepper stored only outside SQLite would make restored
password verifiers unusable if it were not separately recovered, contradicting
the two-item `.smcvault` plus archive-key promise.

Required correction: do not use a non-portable external pepper in v1. Any
future verifier key must be a documented portable vault-scoped secret or an
explicit additional recovery dependency that changes the product promise.

### SEC-AR-008 — Namespace moves could silently broaden effective access

Severity: **Medium**
Affected: AUTHZ-002, WEB-003

Moving a secret into a namespace with descendant grants changes effective
access even though stable IDs correctly preserve exact grants. Treating move as
ordinary metadata editing could expose the secret without a clear permission
change.

Required correction: model namespace moves as policy-impacting actions,
calculate before/after effective access, require recent owner authentication
when access broadens, and audit the delta.

### SEC-AR-009 — Server-created download artifacts lacked lifecycle controls

Severity: **Medium**
Affected: BACKUP-001, BACKUP-005, OPS-004

Web backup creation may leave encrypted downloadable artifacts on server disk.
Although encrypted, indefinite retention increases attack and disk-exhaustion
surface and could lead the UI to confuse server retention with owner custody.

Required correction: define restrictive storage, randomized opaque names,
expiration/deletion, quota, explicit download status, and language that server
job retention is not the owner's off-host backup.

### SEC-AR-010 — Local audit chaining cannot prove completeness

Severity: **Low, already substantially addressed**
Affected: AUDIT-004

An attacker controlling the local database can truncate events and recompute
or restore an older self-consistent state if all anchoring is local.

Required correction: retain the existing limitation, add recovery epochs, and
require external signed/append-only anchoring before using stronger provenance
language.

### SEC-AR-011 — Administrative actions were accidentally service-grantable

Severity: **High, found during resolution verification**
Affected: AUTHZ-002, BACKUP-001, key and policy administration

The initial closed action vocabulary placed backup, restore, key, policy,
identity, audit, and vault administration beside secret actions without a
service-grantable allowlist. An owner could accidentally create an application
policy capable of exporting the whole vault or increasing authority, defeating
compartmentalization.

Required correction: define and schema-enforce a service-grantable action
allowlist. Backup, restore, keys, vault configuration, identity/credential,
policy, audit administration, namespace administration, and purge remain
owner-only in v1 even though the central boundary evaluates and audits them.

## Positive observations

- The draft consistently separates at-rest protection from unlocked-host
  compromise.
- Authorization is centralized, action-specific, and deny-by-default.
- Hostile archive parsing, partial restore, and KDF/resource exhaustion already
  have strong baseline requirements.
- Secret non-disclosure in telemetry, URLs, browser storage, and audit is
  addressed across layers.

## Verification plan

Each correction is tracked in `REVIEW_RESOLUTION_LOG.md`. After edits, search
for conflicting claims, trace the revised restore flow end-to-end, and update
the implementation-readiness gate.

## Verification result

All eleven findings are closed in the documentation. The revised trace now
preserves application verification through a portable vault-scoped verifier
key, establishes owner recovery locally, separates logical vault from
installation/recovery epoch, limits archive claims to key-authenticated
integrity, orders restore activation last, strengthens backup-key guidance,
removes non-portable password pepper, treats namespace moves as access changes,
bounds server artifacts, preserves the audit-anchor limitation, and prevents
service policies from containing owner-only administrative actions.
