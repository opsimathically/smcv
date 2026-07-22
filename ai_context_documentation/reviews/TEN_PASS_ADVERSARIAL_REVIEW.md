# Ten-pass adversarial project review

Status: **In progress**
Started: 2026-07-22
Scope: complete SMCV repository and 0.1.0 release-candidate behavior

This campaign performs ten consecutive reviews from different failure
perspectives. Each pass challenges the repository after all preceding repairs.
A pass is complete only after concrete findings are fixed, regression evidence
passes, documentation matches, and the fix boundary is committed locally.

## Pass 1 — repository integrity, configuration, and release envelope

Perspective: a hostile release publisher, artifact supplier, CI dependency,
local path adversary, and new operator. Result: **six findings repaired and
retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R1-001 | Critical | `verify-release.sh` extracted the archive and executed its bundled CLI before checking an optional detached signature. Supplying a public key therefore did not prevent pre-authentication code execution. | Signature verification now authenticates a restrictive private archive copy before listing or extraction. Artifact verification never executes bundled code. A synthetic signed archive containing an executable marker script verifies without creating its marker; a wrong public key fails. |
| A10-R1-002 | High | Verification repeatedly reopened the caller-controlled archive path, parsed human-formatted tar listings, rejected only links rather than every special type, and allowed files omitted from `SHA256SUMS`. A path replacement or self-consistent unlisted payload could evade the claimed whole-bundle check. | The verifier copies once, requires the adjacent checksum for that copy, accepts only the exact safe bundle root/portable member vocabulary/regular-file-or-directory types, extracts the same copy, and compares the checksum manifest one-to-one with all files. Automated tests reject an unlisted file and symlink. Candidate smoke likewise verifies and extracts one stable copy. |
| A10-R1-003 | High | All four GitHub Actions dependencies used mutable major or branch references, including `dtolnay/rust-toolchain@master`. Compromise or retagging could silently alter the trusted CI/release environment. | Checkout, Rust toolchain, cache, and installer actions are pinned to full reviewed commit hashes, with release/version comments. The installer action's own security guidance recommends hash pinning. |
| A10-R1-004 | Medium | Outer checksum files embedded an absolute build-host path, reducing portability; an unsigned rebuild could leave a stale `.sig`; and the final archive was overwritten directly rather than published from a completed temporary file. | Checksums now contain the archive basename, unsigned builds remove stale signatures, and the archive is completed in a same-directory temporary file then atomically renamed. Signed/wrong-key and normal candidate verification pass. |
| A10-R1-005 | Medium | Local provenance omitted the Rust, Cargo, and CycloneDX versions and did not cryptographically bind its `Cargo.lock` claim to the included lockfile. | Provenance now records all three tool versions and the lockfile SHA-256. Verification checks types, commit shape, target/version, clean state, and exact bundled lock hash. |
| A10-R1-006 | Low | Architecture status stopped at Phase 5 and allowed an in-server TLS interpretation even though v1 production is unconditionally loopback-only behind the same-host proxy. | Architecture status and deployment wording now match the completed Phase 6 implementation and supported TLS boundary. |

Validation:

```text
./scripts/release-verifier-smoke.sh
  signed_archive_not_executed=passed
  wrong_signature_key=passed
  unlisted_file=passed
  link_member=passed
  missing_outer_checksum=passed
  malformed_outer_checksum=passed

SMCV_ALLOW_DIRTY_BUILD=1 ./scripts/build-release.sh
SMCV_ALLOW_DIRTY_VERIFY=1 ./scripts/verify-release.sh dist/smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
SMCV_ALLOW_DIRTY_VERIFY=1 ./scripts/release-candidate-smoke.sh dist/smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
  PASS: complete expanded bundle verification and artifact install/preflight/
        rollback/restore campaign
```

No Pass 1 critical/high finding remains open. The next pass begins from these
repairs and reviews cryptography, key lifecycle, plaintext handling, and memory
exposure without relying on prior assurance conclusions.

## Pass 2 — cryptography, key lifecycle, and plaintext exposure

Perspective: a local path adversary, memory-forensics observer after buffer
release, hostile archive/token supplier, and interrupted key custodian. Result:
**four findings repaired and retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R2-001 | High | Root-provider loading checked metadata by pathname and then reopened the path. A replacement between those operations could make the validated object differ from the key bytes read; immediate custody-directory symlinks were also accepted. | Root providers now open once with `O_NOFOLLOW` and `O_CLOEXEC`, validate type/length/mode on that descriptor, and read from it. Creation also uses no-follow/close-on-exec, and initialization rejects a symlinked immediate custody parent. Existing provider symlink rejection plus a new parent-symlink regression pass. |
| A10-R2-002 | Medium | Key-generation temporaries and decoded application/session/CSRF token secrets used ordinary stack arrays or vectors on some success and rejection paths. | Generated key buffers and every decoded bearer-secret component now enter a zeroizing owner before fallible work and remain there through verification. Public lookup components remain ordinary data by design. |
| A10-R2-003 | Medium | Backup recovery keys, plaintext archive read/write chunks, base64-decoded restore values, and decrypted logical key/metadata fields could be freed without zeroization, particularly after malformed input or a later restore error. | Recovery keys and archive plaintext frames/chunks now use zeroizing storage. Protected logical fields deserialize into zeroizing strings, base64 decoders use zeroizing destinations, and malformed key inputs are cleared before returning. The committed v1 fixture and complete clean-environment re-encryption restore still pass. |
| A10-R2-004 | Medium | Protected descriptor and multipart inputs first occupied ordinary `String`/`Vec` allocations; descriptor trimming also copied secret text and could silently alter a passphrase ending in whitespace. | CLI descriptor reads and browser/server recovery-key fields now accumulate directly into zeroizing owners, explicitly clear invalid UTF-8, and remove only transport CR/LF in place without a plaintext copy. |

Validation includes the complete crypto, backup, application, CLI, and server
test suites, the frozen AEAD/metadata/archive compatibility fixtures, hostile
credential properties, wrong-key/corruption checks, rotation restart tests,
and the new custody-parent symlink rejection. No Pass 2 critical/high finding
remains open.
