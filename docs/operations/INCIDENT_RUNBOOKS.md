# Incident runbooks

Status: **Committed v1 containment baseline**

For every incident, open a private record, establish an incident lead and UTC
timeline, preserve safe evidence before repair, avoid copying protected values
into tickets, and declare who owns notification and return-to-service. Assume an
unlocked-host compromise can expose plaintext and keys; local audit chaining is
tamper-evident within its documented boundary, not proof against root.

## Application credential lost or leaked

Revoke the exact credential immediately, inspect its safe last-use/audit
records, issue a replacement with no broader grants, rotate any secret it could
read, and verify denied reuse. Escalate to host compromise if the token source
is unknown.

## Owner account or session compromise

Stop public ingress if control is uncertain, terminate active sessions by
restarting into the documented maintenance window, recover owner access locally
if necessary, reenroll authenticators, rotate exposed secrets/credentials, and
review all owner-only audit actions since the earliest suspected access.

## Root key or unlocked host compromise

Isolate the host without destroying volatile evidence, treat every vault secret
and verifier as exposed, create no new backup on an untrusted process, restore a
known-good pre-compromise archive on a clean host with imported credentials
revoked, reenroll the owner, rotate upstream secrets, and permanently
decommission the old installation.

## Secret disclosed to an unauthorized client

Revoke the responsible application credential and grant, rotate the secret at
its upstream authority, write the new immutable vault version, identify every
authorized disclosure after the compromised version, and follow notification
policy. Purge does not erase backups, snapshots, logs outside SMCV, or client
copies.

## Audit discontinuity or ciphertext integrity failure

Set the service unavailable, preserve database/WAL/root files and release
checksums without broadening access, run no repair that rewrites evidence,
compare the last external operational record if present, and restore a verified
archive to a clean isolated host. Treat affected secrets as exposed when cause
cannot be proven benign.

## Corrupt database, disk-full crash, or unusable WAL

Stop writes, preserve all SQLite companion files together, free space outside
the vault directories, run preflight/integrity checks on a copy, and prefer a
verified portable restore over ad-hoc SQL repair. Never copy only the live main
database while WAL mode is active.

## Lost archive passphrase or recovery key

Do not brute-force through SMCV or weaken KDF limits. Locate a separately held
valid key or another verified backup/key pair. If the live vault remains
healthy, generate a new key and backup immediately. If both live vault and all
keys are lost, recovery is impossible by design.

## Restore of an old backup after uncertain compromise

Authenticate and drill the archive first, note its creation time and recovery
epoch, select revoke-imported-credentials unless continuity is essential and
trusted, disable the old installation, rotate owner/application/upstream
credentials, and reconcile explicitly accepted post-backup data loss.

## Vulnerable dependency or release artifact

Stop distribution, verify artifact/checksum/SBOM/provenance against the build
commit, determine reachable use of the component, preserve suspect binaries,
rotate release credentials if applicable, rebuild from a reviewed locked tree,
and publish a replacement plus coordinated advisory through the owner-selected
private channel.

## Return-to-service gate

Require correct release verification, production preflight, readiness,
integrity and audit continuity, owner authentication, least-privilege
application probes, a new verified off-host backup, a clean restore drill, and
a written residual-risk decision. Keep the compromised installation offline.
