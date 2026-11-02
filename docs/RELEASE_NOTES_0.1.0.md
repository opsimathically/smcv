# SMCV 0.1.0 release-candidate notes

Status: **Production-ready local candidate; not publicly published**
Candidate date: 2026-07-22

SMCV 0.1.0 is the first complete release candidate of the self-hosted Secret
Manager and Credentials Vault. It includes the encrypted vault, owner and
application authentication, deny-by-default authorization, versioned JSON API,
accessible owner web interface, portable encrypted backup and clean-host
recovery, selective physical-safe copy preparation, operational packaging, and
release-assurance materials.

## Native local-lab HTTPS

An optional second product listener provides direct HTTPS on one explicit
loopback, private/unique-local, or link-local address while preserving the
loopback HTTP path for ForwardDynamic or another same-host proxy. With two
settings it creates and reuses a restrictive self-signed exact-SAN identity;
operators may instead provide a bounded, current, matching CA-issued PEM
chain/key pair.

Preflight reports the safe direct origin, leaf SHA-256 fingerprint, and expiry.
It rejects partial, unsafe, symlinked, oversized, expired, wrong-SAN, or
mismatched material rather than silently regenerating it. Self-signed traffic
is not authenticated until the operator independently verifies the fingerprint
or installs the intended trust anchor. See [Native local-lab
HTTPS](operations/LAB_HTTPS.md) for firewall, systemd, trust, renewal, and
canonical WebAuthn-origin guidance.

## Selective physical-safe copies

The owner web interface includes a metadata-only searchable, paginated table
for explicitly selecting up to 50 active current secrets. Selection survives
search and page changes, followed by a complete value-free review and recent
password reauthentication. One bounded `no-store` response then creates a
transient print document containing exactly the reviewed current records.

SMCV does not generate a server-side PDF or plaintext file. It clears the print
tree after the print lifecycle, visibility loss, navigation, lock, discard, or
five minutes. Printer drivers, spools, previews, saved files, paper inventory,
copy freshness, and secure destruction are owner custody; see
[Physical-safe copies](operations/PHYSICAL_SAFE_COPIES.md).

## Security and trust boundary

Sensitive metadata and values are encrypted at the application layer with
XChaCha20-Poly1305. The SQLite database and `.smcvault` files are assumed
stealable. Root material is kept separately from SQLite, and portable backups
require a separate generated recovery key or strong passphrase. Application
credentials are verifier-only, display-once, explicitly scoped, expirable, and
revocable. Browser sessions are server controlled and secret responses are
non-cacheable.

SMCV cannot protect plaintext from root/kernel control, arbitrary code running
as the unlocked service user, authorized clients, or a compromised display
endpoint. Local audit chaining detects many edits but cannot independently
prove that the newest history was not truncated or rolled back. Read the
included threat model and residual-risk register before deployment.

## Installation and operation

The supported target is `x86_64-unknown-linux-gnu` under the exact constraints
in [Supported platforms](SUPPORTED_PLATFORMS.md). Production preferably uses a
loopback SMCV listener behind a same-host HTTPS reverse proxy. A separately
scoped native HTTPS lab listener is optional. Both require restrictive owned
data/key directories and the closed environment schema. Run
`smcv-server preflight` under the exact service environment before launch.

The operator owns host security, TLS/domain custody, off-host backup transfer,
separate backup-key custody, restore drills, capacity alerts, and keeping only
one restored clone active. The reference objective is a 24-hour RPO and
15-minute RTO for the documented small-vault class; those are operational
targets, not guarantees for maximum parser bounds.

## Backup, upgrade, and rollback

Archive version 1 is the only supported portable format. Verification proves
integrity under the supplied recovery material, not who created the archive.
Restore requires empty destinations and activates only after full validation.
Preserved application credentials must be rotated or revoked when source
custody is uncertain.

There are no down-migrations. Before upgrading, create and verify an off-host
portable backup and preserve a stopped database/key-provider snapshot with the
matching old binary. Rollback loses writes after that checkpoint. Candidate
evidence proves preflight, mutation after checkpoint, stopped-state rollback,
total-loss restore, owner login, and secret recovery using packaged binaries.

## Artifact verification

The tarball contains binaries, internal SHA-256 checksums, seven CycloneDX
SBOMs, `Cargo.lock`, toolchain and dependency policy, local provenance, API and
archive specifications, operational documentation, phase evidence, and the
external-assurance handoff. Local provenance is not a third-party attestation.
Official signing and publication remain post-development owner activities.

Use the included verifier:

```text
scripts/verify-release.sh smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

## Assurance state

Independent security assurance and personal testing with real recovery-key
custody remain separate activities. Local verification uses synthetic records
and does not certify a production deployment or an operator's custody practice.
