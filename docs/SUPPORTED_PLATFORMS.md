# Supported v1 platform and configuration

Status: **Committed for release candidate 0.1.0**
Last reviewed: 2026-07-21

## Production support envelope

SMCV 0.1.0 supports one self-hosted instance on x86-64 Linux, built for
`x86_64-unknown-linux-gnu`, with local SQLite storage and a separate local
root-key provider directory. The packaged service assumes systemd, `/proc`, a
same-host TLS reverse proxy, and a filesystem that implements ordinary Linux
ownership, mode, rename, fsync, and file-lock behavior. Release construction
rejects every other Rust host target.

The reference candidate was built and exercised on Linux 6.17, glibc 2.39,
OpenSSL 3 (`libssl.so.3`/`libcrypto.so.3`), systemd 257, and ext4. The server is
dynamically linked to those OpenSSL 3 libraries; both binaries require glibc
2.39 or newer. Other Linux distributions are compatible only when they provide
these interfaces and the packaged units pass `systemd-analyze verify`; they are
not independently certified combinations.

Production traffic terminates HTTPS at the packaged same-host proxy pattern.
The SMCV product and optional metrics listeners remain loopback-only. V1 does
not trust forwarded client identity/address headers and does not support direct
public binding, containers, Kubernetes, multi-node operation, network
filesystems, Windows, macOS, non-x86 CPUs, external databases, or external
KMS/HSM providers.

## Browser and accessibility support

The owner interface uses standards-based HTML, CSS, JavaScript, WebAuthn, and
Fetch APIs. Release evidence covers Firefox 152 on Linux and Chromium at 320
CSS pixels, 2x device scale, forced colors, reduced motion, keyboard operation,
and empty persistent web storage. Other current browsers may work but are not
part of the verified v1 matrix. Passkeys require an HTTPS origin, except for
the explicit loopback `localhost` development allowance.

The local recovery browser binds only to loopback and is an administrative
ceremony, not a remotely exposed recovery service.

## Frozen compatibility promises

- Application API prefix: `/api/v1`; checked contract: `api/openapi.yaml`.
- Portable archive writer/reader: `.smcvault` format version 1 only.
- Database migrations: every committed migration from the frozen Phase 0
  fixture forward; no down-migrations.
- Metadata envelope: frozen v2 fixture.
- Recovery preserves logical vault identity, creates a new installation ID and
  recovery epoch, and disables source-bound passkeys pending reenrollment.
- Rollback uses a stopped pre-upgrade snapshot plus its matching old binary;
  an old binary is never run against a newer schema.

Expanding this matrix requires a new compatibility decision and evidence; it
is not implied by successful compilation elsewhere.
