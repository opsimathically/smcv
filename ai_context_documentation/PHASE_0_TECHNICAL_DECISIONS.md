# Phase 0 technical decisions

Status: **Committed for implementation**
Last reviewed: 2026-07-21

## Toolchain and workspace

- Rust 2024 is the language edition. The declared MSRV is Rust 1.88 and the
  reproducible developer/CI toolchain is pinned to Rust 1.94.0.
- The MSRV advanced from 1.85 to 1.88 during Phase 2 so the WebAuthn certificate
  parser can select patched `time 0.3.47`; retaining the former MSRV would have
  required accepting RUSTSEC-2026-0009.
- The deployable shape remains one server and one administrative CLI. Crate
  boundaries enforce inward dependencies: `smcv-core` has no HTTP, SQLite, or
  cryptographic implementation dependency; adapters depend on the core.
- `unsafe` is forbidden in workspace source. Formatting, Clippy, unit/property
  tests, docs, RustSec advisories, source/license policy, local documentation
  links, and secret-pattern checks run through `./scripts/check.sh`.
- Release and test profiles retain integer overflow checks. Release panic mode
  aborts rather than attempting to continue after uncertain cryptographic
  state.
- The repository is all-rights-reserved unless the owner later selects a
  distribution license. Third-party licenses are allowlisted and checked.

```text
smcv-core  <── smcv-crypto
    ▲
    └──────── smcv-app <── smcv-cli

smcv-backup   smcv-storage   smcv-server
  bounded       SQLite         HTTP
  framing       adapter        adapter
```

The temporary independence of the three adapters is intentional. Phase 1 and
Phase 2 application services connect them only through authorization-aware
ports; no adapter receives a convenience entry point that exposes plaintext.

## Direct dependency review

Review date: 2026-07-21. Versions are locked by `Cargo.lock`; features are kept
explicit for the largest adapters. Maintenance was assessed from current crate
metadata, repository activity, advisory results, and compatibility tests. The
full transitive license/source inventory is enforced by `cargo deny` and the
SBOM command.

| Dependency | Selected use and features | License | Security criticality / rationale |
|---|---|---|---|
| axum 0.8.9; tower-http 0.7 | HTTP/1, JSON, Tokio, tracing, request IDs | MIT | High ingress boundary; narrow features, same-origin design, hard limits added before protected routes. |
| tokio 1.53.1 | Multi-thread runtime, net, signal, macros | MIT | High availability boundary; maintained runtime with explicit blocking separation planned. |
| rusqlite 0.39.0 / bundled SQLite | `backup`, `bundled`, `limits`; no default cache | MIT | High persistence boundary. 0.40.1 is temporarily excluded because its bundled build invokes unstable `std::cfg_select!` on stable Rust. Bundling prevents host SQLite drift. |
| chacha20poly1305 0.11.0 | XChaCha20-Poly1305 with zeroization support | Apache-2.0 OR MIT | Critical; maintained RustCrypto AEAD, 192-bit nonces, 128-bit tags, no custom primitive. |
| argon2 0.5.3 | Argon2id, PHC encoding, zeroization | Apache-2.0 OR MIT | Critical authentication/archive KDF. Stable 0.5 line selected instead of a release candidate. |
| hmac 0.13 / sha2 0.11 / subtle 2.6 | HMAC-SHA-256 verifier and constant-time equality | MIT/Apache-2.0; BSD-3-Clause | Critical token/cursor/blind-index foundation with domain separation. |
| getrandom 0.4.3 | Operating-system CSPRNG | MIT OR Apache-2.0 | Critical; randomness failures return errors and fail closed. |
| zeroize 1.9.0 | Owned protected buffer cleanup | Apache-2.0 OR MIT | Defense in depth; does not create a guarantee that all memory copies disappear. |
| serde 1.0.229 / serde_json 1.0 | Bounded wire DTOs | MIT OR Apache-2.0 | High parsing boundary; domain secret types do not derive serialization. |
| uuid 1.24.0 | Opaque v4/v7 identifiers | Apache-2.0 OR MIT | IDs are non-authoritative and never replace authorization. |
| clap 4.6.4 | Administrative CLI parsing | MIT OR Apache-2.0 | Secret inputs will use protected prompts/file descriptors, never arguments. |
| thiserror 2.0.19 | Typed internal errors | MIT OR Apache-2.0 | External adapters map these to stable redacted categories. |
| proptest 1.11 / tempfile 3.27 | Hostile parser and persistence tests | MIT OR Apache-2.0 | Development-only; synthetic data and bounded strategies. |

`cargo audit` reported no known vulnerability in the locked graph on the review
date. `cargo deny` accepts the graph with one reviewed duplicate of `syn`
(versions 2 and 3 through independent macro stacks); no duplicate
security-critical runtime primitive is present.

## Cryptographic construction

Decisions D-101 and D-102 are committed with algorithm suite 1:

- Each immutable secret version receives an independent random 256-bit DEK.
- XChaCha20-Poly1305 encrypts record plaintext and wraps DEKs. These operations
  use domain-separated object kinds and independent fresh 192-bit random
  nonces. A nonce must never be intentionally reused with a key.
- The record tag is 128 bits. Authentication failure releases no plaintext.
- Canonical AAD is exactly 67 bytes: ASCII domain `SMCV-AAD`, big-endian
  envelope version, 16-byte logical vault ID, 16-byte installation ID, one-byte
  object kind, 16-byte object ID, and big-endian 64-bit immutable version.
- Every ciphertext stores its suite/envelope version, key version, and nonce.
  Readers use a compiled allowlist and reject unknown versions before decrypting.
- A random per-version DEK limits a record-encryption key to its one envelope;
  random 192-bit nonces also make accidental collisions negligible. KEK
  wrapping spans records, so the same fresh-nonce rule remains mandatory.
- Application tokens contain 256 random secret bits plus a 96-bit public lookup
  ID. The stored verifier is HMAC-SHA-256 under a distinct vault-scoped key over
  a domain label, lookup bytes, and secret bytes. Comparisons are constant-time.

The committed known-answer fixture uses key byte `42`, nonce byte `24`, and
synthetic plaintext. Its AAD and ciphertext were independently reproduced with
libsodium/PyNaCl, not merely round-tripped through the Rust implementation.

### Corrupt-input and substitution matrix

| Mutation | Required result | Phase 0 evidence |
|---|---|---|
| Ciphertext or tag bit | Generic integrity failure; no plaintext | Automated bit-corruption test |
| Nonce bit | Generic integrity failure | Construction/library behavior; expanded exhaustive matrix in Phase 1 |
| Vault, installation, object kind, object ID, or version substitution | Generic integrity failure | Version substitution automated; all fields scheduled in Phase 1 matrix |
| Unsupported envelope/suite/key version | Reject before decrypt | Envelope reader is completed with Phase 1 durable schema |
| Truncated/oversized ciphertext | Reject before allocation/decrypt | Durable envelope parser completed in Phase 1 |
| Wrong token verifier key or malformed token | Uniform false result | Automated token-verifier tests |

## Password and archive KDF bounds

Argon2id is the only initial password/passphrase KDF. Stored parameters are
allowlisted and bounded before work begins. The Phase 0 archive reader accepts
64 MiB through 1 GiB, one through ten iterations, and one through four lanes.
Archive creation begins with 64 MiB, three iterations, and one lane; Phase 2
calibrates human password defaults on the minimum supported host without
raising the compiled import ceiling. All expensive work uses a bounded worker
queue and concurrency cap.

## SQLite and migrations

Decision D-107 is committed:

- SQLite uses WAL, `synchronous=FULL`, foreign keys, secure deletion, trusted
  schema off, a five-second busy timeout, a 16 MiB SQL value ceiling, and a
  fixed application ID.
- Schema migrations are ordered, transactional, append-only, and carry a
  compiled SHA-256 checksum. An altered applied checksum prevents startup.
- The phase fixture proves committed WAL data survives reopen, an uncommitted
  transaction rolls back, and the online backup API creates a readable
  consistent snapshot without overwriting a destination.
- Phase 1 adds schema-specific migration/down-level fixtures and a process-kill
  crash matrix; migrations themselves are never automatically reversed.

## Archive framing prototype

The `smcv-backup` reader proves the defensive portion of D-108 without claiming
that backup behavior ships. Before any KDF work it checks a 64 GiB total-file
ceiling, 256-byte header ceiling, exact magic/version/suite allowlist, fixed
field offsets, 16–32-byte passphrase salt, KDF bounds, 16 KiB–4 MiB chunk bound,
and ten-million-record ceiling. Length arithmetic is checked and the parser
allocates only the already-bounded salt. Property tests feed arbitrary byte
strings and the negative fixtures cover oversized header, file, and KDF cost.

Chunk AEAD, authenticated manifests, stream commitments, staging, and atomic
activation remain Phase 3 implementation work.

## API and WebAuthn feasibility

The checked OpenAPI 3.1 skeleton commits `/api/v1`, the safe problem shape, and
session no-store behavior. Phase 2 grows it from the same file.

WebAuthn is feasible under these deployment rules:

- Production uses HTTPS and an exact configured origin allowlist. RP ID is a
  stable domain equal to, or a registrable suffix of, that origin's effective
  domain; it contains no scheme or port.
- Development passkey ceremonies use `http://localhost:<port>`, which the
  WebAuthn specification explicitly permits. The listener remains loopback.
- Registration stores the RP ID/origin binding. Restore to a different RP
  binding disables affected authenticators and requires local owner recovery.
- SMCV verifies the exact expected origin, RP ID hash, user-presence flag, and
  required user-verification flag. No untrusted sibling origin is accepted.
- No third-party script runs on the credential origin; CSP and same-origin
  assets reduce injection risk.

Authoritative references reviewed on 2026-07-21:

- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [Secure Contexts](https://www.w3.org/TR/secure-contexts/)

## Residual Phase 0 findings

No high-severity Phase 0 finding remains. The rusqlite pin is a documented
compatibility constraint, property tests are not a substitute for continuous
fuzzing, and process-kill SQLite experiments remain required in Phase 1. These
are next-phase work, not blockers.
