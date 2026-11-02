# Scheduled backup and restore operations

Status: **Committed v1 procedure**

The packaged daily timer creates a portable archive with a recovery key loaded
through an inherited descriptor. `backup-maintain` reopens and fully verifies
the new archive before any deletion. It inventories at most 4,096 archive files,
retains unverifiable files for investigation, and deletes only the oldest
copies verified by the supplied key. Retention is 1–365; even a retain count of
one cannot delete the newly verified copy.

The default schedule and retention create a target RPO of 24 hours and seven
local verified copies. The timer's successful exit is not off-host custody.
After every success, transfer the archive through an authenticated operator
channel and monitor that the newest separately held copy is no older than 26
hours. Alert critically at 48 hours, on any timer failure, on an unverifiable
file count above zero, or when filesystem use reaches 90% (warn at 80%).

Run a weekly isolated drill against the exact off-host copy and separately held
key:

```text
install -d -m 0700 /var/lib/smcv-drills
smcv-cli backup-restore-drill --archive COPY.smcvault \
  --workspace /var/lib/smcv-drills --key-fd 3 3</protected/backup.key
```

Success means the archive authenticated, restored into a brand-new vault,
reopened with its fresh root provider, passed SQLite integrity, and the drill
directory was removed. It does not mean the current running installation was
modified. Record archive ID, check time, safe copy location identifier, and
result—never its key or host path.

For an actual host-loss restore, use `backup-restore` or
`backup-restore-browser` against brand-new paths. Preserve application
credentials for disaster recovery or explicitly revoke them for migration.
Disable the old installation before the restored clone accepts traffic, review
the new recovery epoch, reenroll passkeys, and rotate credentials after an
uncertain compromise. Never merge or replace a populated vault.

If the archive key is lost, encrypted backups are not recoverable. If the most
recent archive fails verification, preserve it and its logs, test earlier
copies newest-first, investigate current-vault integrity, and do not let
retention delete any evidence.
