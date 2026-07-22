# Linux production packaging

Status: **Supported v1 packaging baseline**

The supported release-candidate platform is x86-64 Linux with systemd, a local
ext4 or XFS filesystem, and a same-host TLS reverse proxy. SMCV runs under a
static unprivileged `smcv` user. The database and root provider use distinct
mode-0700 directories; the product listener is loopback behind the proxy, and
the optional metrics listener is independently loopback-only.

Install the two release binaries in `/usr/local/lib/smcv`, copy
`smcv.env.example` to `/etc/smcv/smcv.env`, and install the systemd units. Create
the service identity and directories before initialization:

```text
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin smcv
install -d -o smcv -g smcv -m 0700 /var/lib/smcv /var/lib/smcv-key /var/backups/smcv
install -d -o root -g smcv -m 0750 /etc/smcv
```

Run `smcv-cli init` and `smcv-cli enroll-owner` locally as the service user,
then create and separately retain the first verified portable backup. Production
startup never creates missing custody: `smcv-server preflight` must pass before
the listener opens.

The nginx example is illustrative because certificate paths and issuance are
operator-owned. It terminates TLS, clears forwarding headers rather than asking
SMCV to trust client-controlled values, and does not proxy the metrics listener.
SMCV rejects a configured `SMCV_TRUSTED_PROXY`; forwarded-client identity is not
a v1 trust input.

For scheduled backups, provision `/etc/smcv/backup.key` as root-owned mode 0600,
separately protect a second copy of that recovery key, and enable
`smcv-backup.timer`. Prefer systemd encrypted credentials where available by
replacing `LoadCredential=` with the locally provisioned
`LoadCredentialEncrypted=` form. Success means the new archive was reopened and
fully verified before old verified copies were deleted. Unverifiable files are
retained for investigation and never count as recoverable copies.
