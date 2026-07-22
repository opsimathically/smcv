# Operations and security

Status: **Committed Phase 5 Linux operational baseline**
Last reviewed: 2026-07-21

## Supported environment

- One SMCV server per vault.
- The v1 release candidate supports x86-64 Linux with systemd and local ext4 or
  XFS. Other platforms and supervisors require their own evidence.
- SQLite and its WAL/journal files reside on a local filesystem with reliable
  locking and durability semantics.
- SMCV runs as a dedicated unprivileged OS account with no interactive shell
  where the platform supports it.
- The vault directory is inaccessible to other ordinary users.

Containers may be supported only with documented persistent-volume, ownership,
key-provider, backup, signal, and core-dump behavior. A container image alone
is not the operational design.

## Directory and permission model

The runtime separates:

- Read-only executable and web assets.
- Protected configuration.
- Root-key provider material.
- Vault database, WAL, journal, and staging files.
- Encrypted backup destination when local.
- Non-secret logs and runtime sockets.

Files are created with restrictive permissions from the first open operation;
creating broadly readable files and chmodding later is not acceptable. Startup
checks ownership and obvious unsafe modes, failing closed when policy says the
condition is unsafe.

## Initialization

Initialization is a local, explicit state machine:

1. Validate empty destination, permissions, randomness, and key-provider
   availability.
2. Generate vault ID and key hierarchy.
3. Create schema and initialization audit state transactionally.
4. Enroll the owner through a short-lived single-use local setup flow.
5. Verify unlock and owner authentication.
6. Create and verify the first portable backup before initialization is marked
   operationally complete, unless the owner explicitly records deferral.

The complete first-backup owner journey becomes available when Phases 3 and 4
integrate with initialization. Phase 1 may prove the cryptographic initialization
state machine but must not claim this release-level journey is complete.

No default password, default API credential, or silently reusable setup token
exists. Bootstrap values do not enter process lists or durable logs.

## Configuration

- Configuration has a closed environment schema, explicit development
  defaults, and unknown-`SMCV_*` errors.
- Security-sensitive settings state whether they are static, reloadable, or
  require maintenance mode.
- Secret configuration values use files/file descriptors or key providers, not
  ordinary checked-in configuration.
- Startup prints effective safe configuration without protected values.
- Production refuses non-loopback plaintext binding.
- Database open checks the SMCV application ID and an exact checksummed
  migration prefix before changing persistent SQLite configuration. A foreign,
  future, gapped, or version-inconsistent database fails closed without being
  adopted by the running binary.
- Trusted forwarding-header mode is not supported in v1 and any configured
  proxy trust is rejected. The same-host ingress clears `Forwarded` and
  `X-Forwarded-*`; unauthenticated password, passkey, and unknown-bearer limits
  use the direct peer. Valid application credentials use independent bounded
  buckets keyed by their public random lookup component.

## TLS and network

TLS 1.3 is preferred; TLS 1.2 exists only for documented compatibility. API
plaintext requests fail rather than redirect. HSTS is enabled when SMCV owns
the public HTTPS origin and deployment guarantees are compatible.

Request timeouts, header count/size, body size, connection count, and expensive
worker queues are bounded. Administrative and secret-value routes may have
stricter limits. Health endpoints expose no version, path, vault identity, or
dependency detail to unauthenticated networks.

## Database operation

Phase 1 selects and tests explicit settings for:

- WAL or rollback-journal mode.
- Full durability and checkpoint behavior.
- Foreign key enforcement.
- Busy timeout and bounded retry.
- Secure temporary-file location.
- Page size and maximum database size.
- Integrity and foreign-key checks.

WAL mode permits concurrent readers but only one writer and requires all
participants on one host. Long-running readers and checkpoint growth are
observable. A file copy of a live database is not an approved backup workflow;
use the SQLite backup interface or SMCV portable backup.

## Telemetry

Logs and traces use an allowlist of fields. They never include request or
response bodies, raw URLs/query strings, secret names, user-submitted labels,
authentication headers, cookies, key material, ciphertext, or decrypted data.
Potentially attacker-controlled safe fields are length-bounded and sanitized.

The delivered optional metrics listener is independently loopback-only and uses
fixed labels. It exposes readiness and aggregate request response-class,
timeout, rate-limit, and readiness-check counters. Host/systemd monitoring owns
filesystem, WAL, scheduled backup age, and service signals. The broader useful
signal catalog includes:

- Authentication and authorization outcomes by safe category.
- Credential revocation/expiration attempts.
- Integrity failures and audit-write failures.
- Database busy duration, WAL size, checkpoint age, and disk-space thresholds.
- Backup age, last full verification, and last restore-drill result.
- Key versions remaining during rotation.
- Worker-queue saturation and rate limiting.

Liveness means the process loop responds. Readiness additionally requires an
unlocked valid key provider, compatible schema, usable database, and ability to
write required audit state.

## Backup operations

- Manual UI and CLI backup are supported.
- Scheduled CLI backup supports a protected non-interactive key source.
- A completed backup is immediately verified before success is reported.
- Portable archives and local SQLite snapshots publish from restrictive
  same-directory partial files without overwrite and sync the directory before
  success. Required backup audit state commits before the portable final name
  becomes visible.
- Retention never deletes the final known-good verified copy.
- Server-generated encrypted download artifacts use opaque names, quotas,
  restrictive permissions, and short expiry; their presence is not described as
  off-host owner custody.
- Failed restore staging directories and orphaned destination key material are
  recognized by explicit non-ready state and cleaned only after target identity
  validation.
- A returned restore error removes files created by that attempt. Successful
  restore freshly reloads the external root provider and all wrapped keys while
  still guarded/non-ready, then commits readiness as the final fallible step.
- Backup artifact registries reject a symlinked, permissive, or foreign-owned
  custody directory.
- Off-host movement and destination access are operator responsibilities with
  documented examples.
- Recovery keys are stored separately from backup files.
- Restore drills use isolated destinations and produce safe evidence.
- A restore preserves logical vault ID but creates a new installation ID and
  recovery epoch. Runbooks prevent old and restored installations from
  remaining active with the same credentials.

Development and release-candidate evidence uses synthetic recovery material
and isolated clean environments. The owner's personal recovery-key custody
exercise occurs after Phase 6 under D-016 and does not delay implementation.

## Upgrade and rollback

1. Read release notes and compatibility range.
2. Create and verify a portable backup and local snapshot where applicable.
3. Confirm separate key custody and available disk space.
4. Stop or enter maintenance mode.
5. Run preflight and forward migration.
6. Start, verify readiness, inspect audit continuity, and exercise safe probes.
7. Create a new-format backup after success.

Rollback restores a verified pre-upgrade snapshot with the matching binary; it
does not attempt undocumented down-migrations. Any secret or policy changes
after the pre-upgrade backup are explicitly at risk during rollback.

## Incident runbooks required before release

- Lost or suspected-leaked application credential.
- Suspected owner account/session compromise.
- Suspected root-key or host compromise.
- Secret value disclosed to an unauthorized client.
- Audit discontinuity or ciphertext integrity failure.
- Corrupt database, disk-full crash, or unusable WAL.
- Lost backup passphrase/recovery key.
- Restore of an old backup after uncertain compromise.
- Vulnerable or compromised dependency/release artifact.

Runbooks identify containment, evidence preservation, credential/secret
rotation, restoration, notification, and post-incident decision ownership.

## Host hardening guidance

- Dedicated patched host or strongly isolated workload.
- Least filesystem and network privileges.
- Core dumps disabled; debugging access restricted.
- Swap disabled or encrypted where the operator's threat model requires it.
- Backups and key material on separate protected media or services.
- Process supervision with graceful stop and bounded restart.
- Time synchronization and monitoring because audit ordering depends on it.

Host guidance is defense in depth and does not change the threat-model limit
for an attacker controlling an unlocked host.

## Capacity and availability

V1 publishes measured limits for database size, secret size, record count,
concurrent connections, backup size, and recovery time. SQLite remains the
choice until evidence shows an unmet requirement. High availability is achieved
initially through fast verified restore and documented recovery objectives, not
multiple active database writers.

Immutable versions and audit history are retained until an explicit authorized
policy/action removes eligible data; v1 never silently age-purges them. Disk
threshold alerts account for database, WAL, verified backup jobs, and restore
staging. Ephemeral encrypted artifacts have deterministic expiry and cleanup,
while durable history requires an owner-visible retention decision.

The reference small-vault target is a 24-hour RPO and 15-minute RTO for up to 16
MiB total protected payload on the measured reference hardware. The daily timer
and isolated restore drill meet that target. Larger deployments must measure
their own RTO rather than treating parser ceilings as a latency promise. Exact
limits and dated results are in
[`docs/operations/TELEMETRY_AND_CAPACITY.md`](../docs/operations/TELEMETRY_AND_CAPACITY.md).
