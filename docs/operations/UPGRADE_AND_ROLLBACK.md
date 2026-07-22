# Upgrade and rollback

Status: **Committed v1 procedure**

## Upgrade

1. Verify the new release tarball, internal checksums, CycloneDX SBOM, and local
   provenance. Review compatibility notes before stopping the old binary.
2. Run the current binary's scheduled backup once, fully verify it, copy it off
   host, and confirm separate key custody.
3. Stop writes and record the current binary checksum, schema version, archive
   format, installation ID, recovery epoch, and audit-chain verification result.
4. Preserve a filesystem snapshot only as a matching-binary rollback aid; it is
   not the portable recovery artifact.
5. Install the new binaries without deleting the old version. Run the new
   `smcv-server preflight` under the exact production environment. Startup
   applies only the forward migrations compiled into that release and rejects
   checksum drift or an unsupported database.
6. Start SMCV, require readiness, inspect structured error counters, log in,
   perform a masked metadata read, verify audit continuity, and create a new
   post-upgrade portable backup.

The test suite migrates the frozen Phase 0 schema fixture through every current
migration and authenticates the committed `.smcvault` v1 fixture. Removing a
reader or migration requires an explicit compatibility decision and fixture
retirement record.

## Rollback

SMCV has no down-migrations. Stop the failed release and restore the exact
pre-upgrade database snapshot and matching root-provider file with the exact
old binary. Alternatively, perform a clean portable restore, which creates a
new installation and recovery epoch. Never run an old binary against a schema
it did not create or support.

Any mutation accepted after the pre-upgrade checkpoint is outside that
checkpoint and may be lost. State this window before rollback, preserve the
failed database for analysis, and ensure only one installation remains active.
After rollback, require readiness, integrity, audit-chain verification, owner
login, application credential checks, and a fresh verified backup.
