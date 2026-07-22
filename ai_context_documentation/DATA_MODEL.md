# Data model

Status: **Committed logical model; Phases 1–2 schema implemented**
Last reviewed: 2026-07-21

This is a logical model, not a migration. Exact columns and indexes are decided
and evidenced during implementation.

## Classification

### Always encrypted

- Secret values, structured credential fields, binary payloads.
- Secret names, descriptions, tags, usernames, private-key labels, and notes.
- Human recovery-code material where retained.
- Backup contents other than the deliberately minimal public header.

### Stored only as verifiers

- Human passwords.
- Application credential secret portions.
- Active session secret portions.
- Recovery codes after issuance.

### Clear operational metadata

- Random identifiers and foreign keys.
- Schema, envelope, algorithm, and key versions.
- Version numbers, lifecycle state, and bounded timestamps.
- Ciphertext sizes and safe record counts.
- Permission actions and opaque target identifiers.
- Audit action, decision, opaque actor/target references, and safe source data.

Clear metadata is not assumed public. Database and backup access still requires
filesystem and operational controls.

## Logical entities

### Vault configuration

One row identifies the logical vault, schema version, initialization state,
active key version, portable security-semantics version, and creation time. A
separate installation record contains a newly generated installation ID,
recovery epoch, predecessor/archive reference, activation state, and local
creation time. Initialization and restore are explicit state machines so a
crash cannot produce a seemingly ready partial vault.

### Owner identities and authenticators

Separates owner identity from password, passkey, recovery-code, and session
records. Authenticators have creation, last-use, revocation, and safe display
metadata. Active session tokens are represented by a lookup ID and verifier,
not a raw bearer value.

### Service identities and credentials

A service identity is the authorization principal. It may have several
application credential records for overlap during rotation. Revoking one
credential does not delete the identity or its policy bindings.

A vault-scoped token-verifier key is stored only wrapped under the vault key
hierarchy. It is distinct from encryption, blind-index, session, and audit
keys. Portable export re-protects it inside archive encryption so preserved
credential verifiers remain usable after disaster recovery.

### Namespaces

Namespaces form a bounded acyclic tree through stable IDs. Display names are
protected. Moves and renames do not change resource identity. The database
enforces one parent and domain code enforces maximum depth and cycle absence.

### Secrets

A secret row contains stable ID, namespace ID, lifecycle state, current version
number, optimistic concurrency value, encrypted metadata envelope, creation
time, and tombstone information.

### Secret versions

An append-only row keyed by secret ID and monotonically increasing version. It
contains the encrypted record envelope, content type or protected type data,
creator principal reference, created time, and optional expiration/rotation
metadata. A committed version is never updated in place except for a narrowly
defined cryptographic rewrap that preserves authenticated plaintext identity
and records key-maintenance history.

### Policies, grants, and bindings

Policies contain explicit allow grants: action, target kind, stable target ID,
and whether namespace descendants are included. Bindings connect policies to
service identities. V1 has no wildcard string grammar, script evaluation, or
explicit deny rules.

### Audit events

Append-oriented events use a monotonic sequence, event ID, timestamp, actor and
credential references, action, opaque target, allow/deny result, request ID,
safe source context, previous event commitment, and current commitment.
Phase 2's safe source context is the authenticated channel (`session` or
`application`) plus an opaque credential-record reference; raw bearer/session
values and network addresses are not persisted. Phase 5 may add a coarse or
keyed network-source field after retention and privacy review.
Security events are not cascaded away when principals or resources are deleted.
Events also identify installation ID and recovery epoch. A restore closes the
imported segment and begins a new destination segment referencing the archive;
it does not pretend the two installations are one uninterrupted process.

### Idempotency records

Bounded-lifetime records bind a principal, operation, idempotency-key verifier,
request fingerprint, and safe response reference. Reuse with a different
request is rejected. Raw attacker-controlled idempotency keys are not logged.

### Key registry and maintenance jobs

Key rows contain versions and wrapped material, never root keys. Durable
maintenance rows checkpoint key rewrap, audit verification, and other
resumable operations. Ownership uses a bounded lease even in a single process
to make restart behavior explicit.

### Backup and restore history

Records safe archive ID, creation/import time, actor, format version, counts,
result, destination vault identity, and whether application credentials were
preserved or revoked. It does not store the archive passphrase, recovery key,
or protected contents.

## Core invariants

1. A secret's current version points to an existing committed version of the
   same secret.
2. Version numbers increase without reuse; deletion does not reset them.
3. A protected envelope's associated data matches its owning vault, entity,
   and version.
4. One credential belongs to exactly one principal and has no embedded grants.
5. Revoked or expired credentials cannot create sessions or authorize calls.
6. Grants refer to existing stable resources or durable tombstones.
7. A policy change and its audit event commit atomically.
8. Secret-value access creates an audit event before a successful response is
   considered complete.
9. Root and backup decryption keys are absent from all schema tables.
10. Cascading deletion cannot erase audit or immutable secret history.
11. Restored identifiers cannot silently collide with existing live objects.
12. Size, count, and nesting limits are checked before allocation or commit.
13. One ready installation has one current recovery epoch; restore activation
    appends a new epoch rather than rewriting imported history.
14. Host-bound configuration and root-provider locators are not treated as
    portable logical vault state.

## Secret update transaction

1. Authenticate and authorize `secret:update`.
2. Read current version and compare the required precondition.
3. Validate and encrypt the new bounded payload outside the write lock where
   safe.
4. Begin transaction and recheck the version.
5. Insert next immutable version, advance the secret pointer, and append audit.
6. Commit; on any error none of the three durable effects remain.

## Deletion and purge

Archive hides an object from default use but is reversible. Delete creates a
tombstone and disables ordinary reads while retaining encrypted history. Purge
is a separately authorized, recently reauthenticated operation with explicit
retention rules. Physical deletion cannot promise forensic erasure from prior
backups or storage media; user language must state that limitation.

V1 retains immutable versions and audit history until an explicit authorized
retention/purge action exists. It never performs silent age-based deletion.
Capacity warnings and published limits prevent this rule from becoming an
unobserved disk-exhaustion hazard.

## SQLite requirements

- Foreign-key enforcement is enabled and verified per connection.
- Durability, WAL, checkpoint, busy-timeout, and integrity-check settings are
  explicit rather than inherited from ambient defaults.
- Database, WAL, journal, and temporary files live only in the protected vault
  directory.
- Long reads do not indefinitely prevent checkpoints.
- Migrations have an application ID, schema version, checksums, and backup gate.
- Raw SQL access is confined to the persistence adapter.

## Import staging

Portable import writes to a newly created protected staging database. It
validates referential, version, policy, audit, cryptographic, and count
invariants before that database can become a vault. V1 never merges the staging
database into a populated destination.
