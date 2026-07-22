# Phase 0: engineering and security foundations

Status: **Planned — next implementation phase**

## Objective

Create the smallest executable Rust foundation that proves architecture,
toolchain, dependency, cryptographic, persistence, and verification choices
before product behavior is built.

## Entry criteria

- Documentation-readiness index is satisfied.
- Adversarial documentation findings are resolved or explicitly accepted.
- Decisions D-012 through D-016 are in force; no owner approval, pilot, external
  account, or external reviewer is an entry prerequisite.

## In scope

- Rust workspace and pinned supported toolchain policy.
- Domain/adapters module boundaries and dependency checks.
- Error/redaction and secret-bearing value conventions.
- Configuration schema and safe development defaults.
- CI commands for format, lint, tests, docs, advisory/license checks, secret
  scanning, and an initial SBOM.
- Dependency selection records for web, async/runtime, SQLite, serialization,
  cryptography, password hashing, secrecy/zeroization, CLI, and testing.
- Cryptographic construction decision record resolving D-101 and D-102.
- SQLite configuration and migration strategy decision resolving D-107.
- API contract and passkey/browser deployment feasibility spike.
- Archive-format framing prototype sufficient to validate D-108, without
  shipping backup behavior.
- Synthetic test-data and phase-evidence harness.

## Out of scope

- Production secret storage, authentication, authorization, backup, or UI.
- A deployable server advertised as usable.
- Multiple database backends, KMS implementations, or distributed processes.

## Work slices

1. **Repository baseline:** workspace, license/security policy placeholders,
   deterministic commands, CI, dependency and unsafe-code inventories.
2. **Architecture skeleton:** domain ports with fake adapters; compile-time or
   review-enforced dependency direction.
3. **Security primitives decision:** exact algorithms/crates, canonical
   encodings, nonce/key rules, Argon2 bounds, token verifier, test vectors.
4. **Storage decision:** SQLite library, pooling/blocking boundary, pragmas,
   transaction and migration harness, crash-test approach.
5. **Protocol spikes:** OpenAPI shape, same-origin session mechanism, WebAuthn
   deployment constraints, archive parser/framing limits.

## Acceptance criteria

- One documented command runs every required local pre-commit check.
- Release profile explicitly enables overflow checks unless a reviewed
  alternative proves equivalent safety.
- The domain crate/module compiles and tests without HTTP or SQLite adapters.
- Secret-bearing wrapper tests demonstrate redacted debug/error behavior.
- Selected dependencies have recorded rationale, features, maintenance state,
  licenses, and security-criticality.
- Crypto decision includes independent test vectors and corrupt-input matrix.
- SQLite spike demonstrates foreign keys, selected durability mode, WAL or
  journal recovery, busy handling, and online snapshot behavior.
- Archive framing prototype rejects oversized header/KDF/chunk/count inputs
  before large allocation or expensive unbounded work.
- No committed example or artifact contains a value matching the secret
  scanning sentinel rules.

## Required evidence

- Toolchain and command transcript.
- Dependency review and SBOM sample.
- Architecture dependency diagram checked against code.
- Crypto decision and review notes.
- SQLite crash/durability experiment.
- Archive/parser bound experiment.
- Updated decision register marking validated proposals committed or revised.

## Adversarial review prompts

- Can an adapter decrypt or query secrets without authorization once later
  connected?
- Can debug formatting or generic errors expose protected values?
- Did a crate default silently choose weak durability, algorithms, cookies, or
  parser limits?
- Can imported cryptographic parameters force memory/CPU exhaustion?
- Does the test setup pass while release settings disable important checks?

## Exit gate

All technical proposals needed by Phase 1 are resolved, no high-severity
finding remains, and the skeleton demonstrates the intended dependency and
verification model without claiming usable vault behavior.
