# External-assurance handoff

Status: **Self-contained post-development handoff for SMCV 0.1.0**
Prepared: 2026-07-21

This package lets an independent reviewer understand and reproduce the
candidate without reconstructing project intent. External review is deliberately
post-development under D-015; this handoff does not claim that review occurred.

## Start here

1. Read `docs/RELEASE_NOTES_0.1.0.md` and `docs/SUPPORTED_PLATFORMS.md`.
2. Read `ai_context_documentation/SYSTEM_ARCHITECTURE.md`,
   `THREAT_AND_TRUST_MODEL.md`, `CRYPTOGRAPHY_AND_KEY_MANAGEMENT.md`,
   `AUTHORIZATION_MODEL.md`, and `PORTABLE_ARCHIVE_FORMAT_V1.md`.
3. Inspect `ai_context_documentation/RESIDUAL_RISK_REGISTER.md` and
   `DEPENDENCY_AND_UNSAFE_REVIEW.md` before assessing claims.
4. Use `ai_phase_evidence/FINAL_REQUIREMENTS_TRACEABILITY.md` to sample a claim
   back to tests, phase reports, compatibility fixtures, and negative behavior.
5. Read `ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md` for the
   final finding log and `ai_phase_evidence/PHASE_6_EXIT_REPORT.md` for exact
   candidate commands/results.

## Artifact verification and reproduction

From beside the release tarball:

```text
scripts/verify-release.sh smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

From a clean source checkout at the provenance commit with Rust 1.94.0,
`cargo-audit`, `cargo-deny`, `cargo-cyclonedx`, `jq`, `openssl`, `systemd-analyze`,
`curl`, Node/Playwright, Firefox, and Chromium available:

```text
./scripts/check.sh
./scripts/final-release-gate.sh
```

The final gate builds twice and requires identical SHA-256, verifies all
internal hashes/seven SBOMs/provenance, runs the artifact-only binary campaign,
simulates rollback and total loss, restores with separately held synthetic
material, scans operational/release artifacts for sentinels, checks packaging,
and confirms DELIVERY-001 through DELIVERY-005 remain represented.

## High-value review targets

- Root-provider substitution, permissions, initialization/activation ordering,
  key rotation interruption, envelope AAD, and zeroization limits.
- Owner password/passkey sessions, recent-auth, CSRF, application token lookup
  timing, revocation races, and near-miss authorization policies.
- SQLite migration checksums, WAL/crash behavior, encrypted metadata/indexes,
  audit commitments, and whole-database rollback limits.
- Archive integer/KDF/count bounds, chunk/manifests, exact EOF, duplicate/order
  rejection, staging failure, credential modes, passkey RP rebinding, and clone
  consequences.
- Browser reveal lifetime, CSP, cache/history/storage behavior, focus/errors,
  accessibility, and recovery ceremony origin/code binding.
- Production environment closure, proxy assumptions, listener isolation,
  telemetry labels, graceful drain, retention, release extraction, and build
  trust boundary.

## Fixtures and evidence inventory

- Frozen `.smcvault` v1 fixture: `crates/smcv-backup/fixtures/` in source; its
  test and results are linked from Phase 3 evidence.
- Frozen schema/migration and metadata fixtures are code-owned tests linked from
  the final matrix.
- Browser/accessibility JSON and synthetic screenshots are under
  `ai_phase_evidence/phase_4_browser/`.
- Permission matrix, operational measurements, tabletop, release campaign,
  final reports, all adversarial reviews, and resolution log are under
  `ai_phase_evidence/` and `ai_context_documentation/reviews/`.
- Exact dependencies/features are in `Cargo.lock`, crate manifests, and the
  seven `sbom/*.cdx.json` files.

Use only synthetic data. Report vulnerabilities through `SECURITY.md`; do not
place sensitive details in public issues.
