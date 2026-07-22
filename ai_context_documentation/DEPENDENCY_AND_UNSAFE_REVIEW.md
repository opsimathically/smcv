# Release-candidate dependency and unsafe review

Status: **Complete for 0.1.0 candidate**
Review date: 2026-07-22

The exact graph is pinned by `Cargo.lock`, checked by `cargo audit` and `cargo
deny`, and emitted as seven CycloneDX SBOMs. Workspace crates all declare
`#![forbid(unsafe_code)]`; source search and strict Clippy found no project-owned
unsafe block or exception. Upstream unsafe is risk-assessed by exposure rather
than represented as absent.

## Security-critical dependency groups

| Boundary | Locked direct dependencies | Why retained | Incident/replacement posture |
|---|---|---|---|
| AEAD and key derivation | `chacha20poly1305 0.11.0`, `argon2 0.5.3`, `hmac 0.13.0`, `sha2 0.11.0`, `subtle 2.6.1`, `zeroize 1.9.0` | Maintained RustCrypto constructions; XChaCha nonce space, Argon2id, domain-separated MACs, constant-time equality, bounded secret cleanup. | Stop affected operation/release, assess advisory reachability and feature use, upgrade with known-answer/corruption/compatibility campaigns; change formats only through an explicit version decision. |
| Randomness | `getrandom 0.4.3` | Direct OS CSPRNG with fallible API; failure closes initialization/issuance. | Treat platform RNG failure as unavailable; do not add a fallback PRNG. |
| OS custody flags | `libc 0.2.189` | Constants only for `O_NOFOLLOW`/`O_CLOEXEC` on root-provider descriptors; all calls remain through safe `std::fs::OpenOptions`, and project-owned unsafe code remains forbidden. | Preserve opened-descriptor metadata checks and symlink regressions; replace with stable standard-library flags if they become available. |
| Persistence | `rusqlite 0.39.0` with bundled SQLite | Transactional local store with fixed SQLite version and tested backup/limits. | Preserve migration fixtures, WAL/crash/disk-full tests, and pin until a newer stable-compatible binding passes the same matrix. |
| Authentication | `webauthn-rs 0.5.4`, `argon2 0.5.3` | Standards-based phishing-resistant owner auth and bounded password fallback. Default WebAuthn features are disabled. | Patch certificate/WebAuthn advisories promptly; disable affected authenticator mode if safe upgrade is unavailable; retain local owner recovery. |
| HTTP/runtime | `axum 0.8.9`, `tower 0.5.3`, `tower-http 0.7.0`, `tokio 1.53.1` | Narrow HTTP/1, JSON, multipart, static-file, request-ID, trace, signal, and bounded runtime features. Application timeout policy is explicit rather than enabling the unused tower-http timeout feature. | Re-run route-contract, parser limits, auth, shutdown, telemetry, browser, and artifact campaigns after upgrades. |
| Parsing/serialization | `serde 1.0.229`, `serde_json 1.0.151`, `base64 0.22.1`, `uuid 1.24.0` | Bounded DTOs and canonical encodings; protected domain types do not derive general serialization. | Reject unknown/oversized inputs and retain arbitrary-input campaigns; format changes require compatibility fixtures. |

Build-time proc macros and build scripts remain represented in the SBOM and
source policy. Release builds are locked and deterministic but are not claimed
to be hermetic: Cargo's already-resolved local cache and the trusted build host
remain in the build trust boundary. The local provenance says this explicitly
and does not claim an external attestation.

The ten-pass review re-ran RustSec against 1,167 current advisories, cargo-deny
license/source policy, exact build-script inventory, direct/transitive feature
inspection, native linkage inspection, and upstream commit resolution for all
four GitHub Actions. CI now pins the Ubuntu 24.04 baseline, each action commit,
and exact cargo-audit/cyclonedx/deny versions. All validation builds use the
lockfile; SBOM construction proves it did not alter that graph. Unused UUID v7
and tower-http timeout features were removed. The server's expected OpenSSL 3
dynamic dependency and glibc 2.39 baseline are documented and carried in
verified provenance.
