# Phase 0 exit report

Phase: 0 — engineering and security foundations
Date: 2026-07-21
Status: **Passed; Phase 1 entry recommended**
Documentation baseline commit: `6d533bd`
Phase boundary: the local commit containing this report

## Environment

- Linux x86_64 development host
- `rustc 1.94.0 (4a4ef493e 2026-03-02)`
- `cargo 1.94.0 (85eff7c80 2026-01-15)`
- `cargo-audit 0.22.2`
- `cargo-deny 0.20.2`
- `cargo-cyclonedx 0.5.9`
- bundled SQLite through `libsqlite3-sys 0.37.0`; host diagnostic CLI 3.45.1

No real key, credential, vault value, personal record, or production data was
used. All fixtures are deterministic synthetic values or fresh temporary data.

## Acceptance evidence

| Acceptance criterion | Evidence and result |
|---|---|
| One pre-commit command | `./scripts/check.sh` passed formatting, strict Clippy, all-feature tests, rustdoc warnings, RustSec audit, source/license policy, secret patterns, and local Markdown links. |
| Overflow checks | Root `Cargo.toml` enables overflow checks for dev, test, and release. |
| Domain independence | `cargo tree -p smcv-core` contains no HTTP, SQLite, or concrete crypto adapter. Workspace builds all inward-facing boundaries. |
| Redacted protected types | Core/app/crypto tests prove protected bytes, strings, runtime paths, token plaintext, keys, verifiers, nonces, and ciphertext are absent from `Debug`. |
| Dependency record | `PHASE_0_TECHNICAL_DECISIONS.md`, `Cargo.lock`, `deny.toml`, and current advisory scan record rationale, features, licenses, maintenance posture, and criticality. |
| Crypto decision and independent vector | D-101/D-102 are committed. The XChaCha20-Poly1305 AAD/ciphertext fixture was reproduced using libsodium/PyNaCl; corruption, substitution, wrong-key token, and redaction tests pass. |
| SQLite behavior | Tests observe foreign keys, WAL, FULL sync, application ID, committed-WAL reopen, uncommitted rollback, online snapshot readability/no-overwrite, and migration checksum drift fail-closed. |
| Bounded archive prototype | Unit and property tests reject oversized file/header/KDF/chunk/count input before expensive work and never panic for arbitrary inputs up to 599 bytes. |
| Secret sentinel absence | Repository scanner passed over source, manifests, Markdown, JSON, and YAML. |

The Phase 0 work owns SEC-002/SEC-003 baseline controls and establishes the
technical prerequisites for SEC-004–SEC-014, VAULT-001–VAULT-010,
AUD-001–AUD-005, and BAK-001–BAK-018. Product requirement completion remains
with the delivery/final-verification phases in the traceability matrix.

## Reproducible commands and summarized results

```text
./scripts/check.sh
  PASS: 15 unit/property tests; all doc tests; no compiler/rustdoc warning
  PASS: RustSec advisory scan, source policy, license policy
  REVIEWED WARNING: syn 2 and 3 occur through separate macro dependency stacks

SMCV_LISTEN_ADDR=127.0.0.1:18080 cargo run -p smcv-server
curl --fail-with-body http://127.0.0.1:18080/health/live
  PASS: 200, application/json, random x-request-id, {"status":"ok"}

SMCV_LISTEN_ADDR=0.0.0.0:18081 cargo run -p smcv-server
  PASS: startup refused unprotected non-loopback binding

SOURCE_DATE_EPOCH=1784620800 cargo cyclonedx \
  --manifest-path crates/smcv-server/Cargo.toml \
  --format json --spec-version 1.5 \
  --override-filename phase0-server-sbom
  PASS: seven CycloneDX 1.5 workspace-component documents parsed with jq
```

The generated SBOM sample was intentionally not committed because it is a
derived build artifact. Its generation command is reproducible from the locked
tree. Representative server document SHA-256 in this run:
`90a28ec3c0e871a2f11dd40808332b300a6eae5957e996b7ae0bf31e0579aeee`.

## Architecture and unsafe review

- Workspace code uses `#![forbid(unsafe_code)]`; `rg` finds no unsafe block in
  project source. Third-party crates are governed by lock, advisory, source,
  and license checks; their internal unsafe code has not received a line audit.
- The domain crate owns opaque identifiers, redacted values, and ports only.
  It cannot open SQLite, receive HTTP requests, or instantiate cipher adapters.
- Crypto and storage adapters have no authorization API. Phase 1 connects them
  behind application services so an ingress adapter cannot request plaintext
  without an explicit authorization result.
- Health endpoints contain no build version, database detail, key state, host
  path, or protected diagnostic material.

## Failure and recovery observations

- The newest rusqlite/libsqlite3-sys pair failed to compile on stable Rust due
  to an upstream unstable macro. The graph was pinned to rusqlite 0.39.0 and
  bundled libsqlite3-sys 0.37.0; all durability behavior then passed. This pin
  remains explicit until a compatible upstream release is verified.
- A committed WAL write survived close/reopen. A dropped transaction did not
  expose its uncommitted row. Online backup produced a readable, application-ID
  preserving snapshot and refused overwrite.
- Changing an applied migration checksum prevented database open.
- Server startup safely failed on an occupied port and on a non-loopback
  plaintext address; neither case created persistent state.

## Adversarial second-pass findings

| ID | Severity | Finding | Resolution and verification |
|---|---|---|---|
| P0-A01 | Medium | Initial health shape exposed a build version to unauthenticated callers. | Removed version; smoke response contains only `status`. |
| P0-A02 | High | First archive prototype used an incorrect fixed-header offset, which could misparse record-limit bytes as salt. | Corrected fixed width from 47 to 54 and total fixture width to 70; bounds and property tests pass. No archive was shipped or persisted. |
| P0-A03 | Medium | Underscore-delimited token components were ambiguous because base64url may contain underscore. | Changed to a dot delimiter excluded from base64url and verified generated-token round trip plus wrong-key failure. |
| P0-A04 | Medium | Secret scanner initially contained its own full sentinel expression and would self-trigger. | Built the prefix separately and corrected glob ordering; the complete repository check passes. |
| P0-A05 | Medium | Latest bundled SQLite binding claimed compatible resolution but used unstable compiler functionality. | Exact compatible pin, lockfile, rationale, and full retest. |

No open critical or high finding remains. P0-A02 was repaired before any phase
boundary and its negative tests are retained.

## Security, dependency, accessibility, and compatibility

- Security: strict lints, generic errors, CSPRNG failure paths, AEAD context
  binding, keyed token verifier, bounded archive input, restrictive SQLite
  settings, startup network refusal, and secret scan passed.
- Dependency: advisory/source/license gates passed. The reviewed `syn` duplicate
  is build/macro-only and does not duplicate a cryptographic implementation.
- Accessibility: no user workflow ships in Phase 0. The future same-origin UI
  remains bound to WCAG 2.2 AA; Phase 4 owns executable accessibility evidence.
- Compatibility fixtures: AAD version 1 and its known-answer ciphertext,
  migration version 1/checksum, archive public-header version 1, and OpenAPI
  version 1 skeleton are now compatibility anchors.

## Known limitations and residual risks

- The server is a health-only architecture skeleton and is explicitly not a
  usable vault.
- Process-kill/power-loss matrices, durable encrypted schemas, key-provider
  permissions, full corrupt-field permutations, and rotation interruption are
  Phase 1 work.
- Archive chunks and manifests are not implemented until Phase 3; the Phase 0
  crate proves only bounded public framing.
- WebAuthn was validated against current W3C constraints but is implemented and
  browser-tested in Phase 2/4.
- Automated tests reduce but do not eliminate implementation or supply-chain
  risk. External assurance remains post-development under D-015.

## Human decisions and next-phase recommendation

No human task or new authority was required. D-101, D-102, and D-107 moved from
proposed to committed based on the evidence above. D-108 remains proposed until
the complete authenticated streaming format passes Phase 3.

Phase 1 should begin immediately under the active long-running goal.
