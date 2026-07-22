# Supported deployment and clean-host procedure

Status: **Committed v1 release-candidate procedure**
Last tested: 2026-07-21

## Support boundary

SMCV v1 supports one x86-64 Linux process under systemd, with SQLite, WAL, and
root-provider files on local ext4 or XFS. A same-host TLS reverse proxy exposes
the product listener. NFS, SMB, distributed filesystems, containers,
active-active replicas, non-systemd supervision, and other CPU/OS targets are
not part of the v1 support claim.

The host needs a stable clock, at least 2 GiB RAM plus archive working headroom,
and enough local space for the database, WAL, temporary encrypted artifacts,
and one verified backup. Recovery media and its key must also exist off host.

## Install and initialize

1. Verify the downloaded tarball with `scripts/verify-release.sh` or the same
   commands shipped in [release verification](RELEASES.md).
2. Install `smcv-server` and `smcv-cli` mode 0755 below
   `/usr/local/lib/smcv`.
3. Create a static `smcv` user with no login shell. Create `/var/lib/smcv`,
   `/var/lib/smcv-key`, and `/var/backups/smcv` owned by that user and mode
   0700.
4. Install [the environment template](../../packaging/smcv.env.example) as
   `/etc/smcv/smcv.env`, mode 0640, and replace the example RP ID and HTTPS
   origin. Unknown `SMCV_*` settings fail startup.
5. As the service user, run:

   ```text
   smcv-cli init --database /var/lib/smcv/vault.sqlite \
     --root-key /var/lib/smcv-key/root.key
   smcv-cli enroll-owner --database /var/lib/smcv/vault.sqlite \
     --root-key /var/lib/smcv-key/root.key
   ```

6. Generate a dedicated backup key through protected redirection, store a
   separate copy, and create the first verified backup:

   ```text
   umask 077
   smcv-cli backup-key-generate > /protected/backup.key
   smcv-cli backup-maintain --database /var/lib/smcv/vault.sqlite \
     --root-key /var/lib/smcv-key/root.key \
     --output-directory /var/backups/smcv --key-fd 3 --retain 7 \
     3</protected/backup.key
   ```

7. Configure the TLS proxy to clear `Forwarded` and all `X-Forwarded-*`
   headers. Do not proxy the loopback metrics port. SMCV deliberately rejects
   trusted-proxy header mode in v1.
8. Run `smcv-server preflight` under the exact service environment. It must
   report `status=ready` before enabling the unit.
9. Enable `smcv.service` and `smcv-backup.timer`, then check the public liveness
   and readiness endpoints through TLS and local metrics directly on loopback.

Production preflight requires existing regular mode-0600 database/root files,
distinct mode-0700 custody directories, an HTTPS origin, protected transport,
JSON logs, a loopback metrics listener, recognized settings, compatible schema,
matching root identity, and a passing SQLite quick integrity check. It refuses
to initialize missing production custody.

## TLS and ingress

The packaged nginx fragment is an example, not certificate automation. Permit
TLS 1.3 and, when compatibility requires, TLS 1.2; redirect port 80 at the
proxy, never inside the plaintext SMCV hop. Set HSTS only after every subdomain
and recovery route is ready for it. The proxy must preserve the original Host
used by the configured origin and enforce its own connection/header/time
bounds.

## Shutdown and support bundle

Systemd sends SIGTERM. SMCV stops accepting work, drains for at most the
configured 1–120 second grace, and exits nonzero if the deadline is exceeded.
For a support bundle, collect only release checksums, `smcv-cli diagnostics`,
systemd unit status, the fixed-label metrics snapshot, and filtered structured
events. Never include the environment file, paths, database/WAL, root provider,
backup files, cookies, request bodies, or core dumps.
