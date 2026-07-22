# Security assurance

Status: **Committed process baseline**
Last reviewed: 2026-07-21

## Assurance strategy

SMCV is security-sensitive infrastructure. Assurance combines small auditable
design, explicit invariants, automated negative tests, dependency controls,
manual review, and demonstrated recovery. Passing a scanner alone is not a
security claim.

## Required automated checks

- Rust formatting and compiler warnings treated as errors.
- Linting with project-approved security and correctness lints.
- Unit tests for domain invariants and error redaction.
- Integration tests across HTTP, authorization, encryption, SQLite, and audit.
- Permission-matrix tests generated from the closed action/resource vocabulary.
- Known-answer and corruption tests for cryptographic envelopes.
- Property tests for parsers, canonical encodings, version transitions, and
  policy evaluation.
- Fuzzing for unauthenticated parsers, archive framing, encoded credentials,
  pagination cursors, and cryptographic envelope metadata.
- Migration tests from every supported schema and archive fixture.
- Crash/failure injection for transactions, key rotation, backup, and restore.
- Browser security and accessibility tests for critical owner workflows.
- Dependency advisory, license, source-policy, and lockfile checks.
- Secret-scanning of source, fixtures, generated docs, and release artifacts.
- SBOM generation tied to the exact release artifact.

## Test-data rules

Fixtures use unmistakably synthetic values. No production-shaped real
credential is copied into an issue, fixture, screenshot, recording, or evidence
file. Tests assert that synthetic sentinel secrets never occur in logs, traces,
audit rows, metrics, panic text, URLs, filenames, or backup public headers.

Encrypted fixtures document their non-secret test keys. Production must reject
well-known development keys and initialization fixtures.

## Cryptography review

The Phase 0 decision record and Phase 1 implementation receive focused review
covering primitive suitability, key separation, domain separation, canonical
associated data, randomness, nonce rules, key/provider failure, rotation,
format compatibility, and error behavior. Cryptographic dependencies receive
manual source/API review for the exact features used.

## Authorization review

Every protected application service declares its required action. Review
searches for persistence or decryption calls reachable without a policy check.
Tests use principals with near-miss permissions, not only all-powerful owner
fixtures. Policy-cache invalidation and revoked-credential behavior are tested
under concurrency and restart.

## Backup and parser review

Backup import is treated as a hostile file parser and expensive cryptographic
endpoint. Review covers integer overflow, allocation before validation,
path/file attacks, KDF parameter abuse, compression bombs, duplicate records,
record-order assumptions, partial authentication, truncation, rollback, schema
migration, and atomic activation.

## Web review

Critical flows receive checks for XSS, CSRF, session fixation, clickjacking,
cache leakage, browser history/referrer leakage, unsafe clipboard assumptions,
third-party assets, CSP, reauthentication, and accessible error/focus behavior.
Secret reveal is tested against DOM persistence and client telemetry.

## Supply-chain controls

- Minimize direct and transitive dependencies, especially crypto, parser, web,
  and templating code.
- Commit `Cargo.lock` for applications and use locked builds.
- Record why each security-critical dependency is needed, its maintainer and
  security posture, enabled features, and replacement/incident plan.
- Automate RustSec/advisory checks and manually triage applicability.
- Restrict build scripts, proc macros, native dependencies, and network access
  during reproducible release builds where practical.
- Produce CycloneDX or SPDX SBOM, checksums, and provenance for the release
  candidate. Official external signing identity/custody may be added during
  post-development publication.

## Unsafe code policy

Project code avoids `unsafe`. An exception must include:

- Why a safe alternative is insufficient.
- The exact safety invariant and ownership/lifetime assumptions.
- A minimal encapsulated surface.
- Targeted tests, platform analysis, and a fresh adversarial review pass by a
  context separated from the implementation where available.
- A repository-visible inventory checked in CI.

Dependencies containing unsafe code are assessed according to criticality and
exposure rather than treated as automatically equivalent to project-owned
unsafe code.

## Manual adversarial reviews

At minimum:

1. Documentation readiness: security/abuse and operability/scope/recovery.
2. End of Phase 1: cryptography, storage, migrations, and crash consistency.
3. End of Phase 2: identity, authorization, API, and enumeration.
4. End of Phase 3: archive format, hostile import, and disaster recovery.
5. End of Phase 4: browser, content, and accessibility.
6. Release candidate: full threat model, supply chain, operations, and residual
   risks.

Reviews record finding ID, severity, evidence, affected requirements, decision,
owner, correction, and verification. A critical/high finding prevents an
incorrect phase-close claim but does not pause the implementation goal: it
becomes active repair work and is retested before advancing.

## Release security gate

- Threat model and authoritative guidance have current review dates.
- No unresolved critical/high finding.
- Medium findings have fixes or explicit owner risk acceptance and expiry.
- Dependency advisories are triaged and recorded.
- All cryptographic and archive compatibility vectors pass.
- Restore drill and incident tabletop evidence exists.
- Reproducible release command, SBOM, checksums, and provenance are available.
- The final internal assurance report and external-review handoff package are
  complete. D-015 records the owner's 2026-07-21 acceptance of reaching the
  release candidate before independent external assurance.

Independent external assurance occurs after complete development. Its findings
create subsequent remediation goals and do not delay Phase 6 completion.

## Vulnerability handling

Before public release or deployment, publish a private reporting channel, supported-version
policy, expected acknowledgement window, coordinated disclosure approach, and
release-key compromise procedure. Security reports and artifacts must not
contain live secrets.

Public release is an owner-controlled post-development action, so this section
does not gate completion of the release candidate.
