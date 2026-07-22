# Phase 6 exit report

Phase: 6 — release candidate and assurance handoff
Date: 2026-07-21
Status: **Passed; development complete**
Phase boundary: the local commit containing this report

## Delivered scope

Phase 6 freezes the x86-64 GNU/Linux production matrix and compatibility
anchors; adds hostile credential and metadata property campaigns; refreshes the
threat and residual-risk model; closes a fresh full-product adversarial review;
repeats browser, accessibility, operational, dependency, and recovery gates;
hardens and expands the deterministic release bundle; proves stopped-snapshot
rollback and synthetic total-loss recovery using packaged binaries; completes
requirements traceability; and supplies release notes plus a self-contained
external-assurance handoff.

## Acceptance and evidence

| Criterion | Evidence and result |
|---|---|
| Complete traceability | [Final matrix](FINAL_REQUIREMENTS_TRACEABILITY.md) links every requirement group to phase evidence and final review sampling. DELIVERY-001 through DELIVERY-005 are checked by the release gate. |
| Internal assurance | [Fresh review](../ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md) closed three high and five medium findings. No critical/high internal finding remains. |
| Threat and residual risk | [Threat model](../ai_context_documentation/THREAT_AND_TRUST_MODEL.md) now matches rejected proxy trust and unsigned-local-provenance semantics. [RR-001–010](../ai_context_documentation/RESIDUAL_RISK_REGISTER.md) distinguish boundaries, medium/low risk, mitigations, and post-development work. |
| Recovery promise | `release-candidate-smoke.sh` verifies the candidate then uses only bundled CLI/server binaries. It passes production preflight, creates and separately stores a backup key/archive, performs a clean drill, snapshots stopped state, mutates after checkpoint, proves rollback value, removes the source, restores cleanly, logs in, and recovers the expected secret. |
| Compatibility | Migration Phase 0→current, metadata v2, audit commitment v1/v2 reading, action vocabulary v1, `/api/v1`, committed archive v1, and v1→current→second-restore tests remain frozen and passing. No fixture retired. |
| Accessibility | [Final conformance](FINAL_ACCESSIBILITY_CONFORMANCE.md), refreshed JSON/screenshots, ordinary browser and active-Orca campaigns pass DOM lifetime, persistent storage, names, keyboard, focus, narrow/scale reflow, reduced motion, and forced-colors checks. Spoken-output assertion remains honestly not tested. |
| Supply chain/release | [Dependency review](../ai_context_documentation/DEPENDENCY_AND_UNSAFE_REVIEW.md), clean RustSec/license/source gates, project unsafe prohibition, seven structurally verified CycloneDX SBOMs, `Cargo.lock`, internal/outer checksums, safe extraction, clean provenance, exact-platform rejection, secret scan, and two-build equality satisfy the candidate envelope. |
| Operator/integrator handoff | [Release notes](../docs/RELEASE_NOTES_0.1.0.md), [support matrix](../docs/SUPPORTED_PLATFORMS.md), full operational docs, API/format specs, phase evidence, and [reviewer index](../external_assurance/README.md) ship together. |

## Reproducible validation

```text
./scripts/check.sh
  PASS: format; strict all-target/all-feature Clippy; 81 Rust tests; rustdoc
  PASS: RustSec advisory and cargo-deny license/source policy
  PASS: secret-pattern scan, shell syntax, and relative documentation links

node scripts/browser-smoke.mjs
SMCV_SCREEN_READER=1 node scripts/browser-smoke.mjs
  PASS: ordinary and active-Orca critical owner workflows

./scripts/operations-smoke.sh
  preflight=passed; load_requests=2048; load_milliseconds=516
  shutdown_seconds=0; verified_retained=2; verification_alert=passed
  restore_drill=passed-and-cleaned; telemetry_sentinel=absent

./scripts/final-release-gate.sh
  Runs from the clean phase-boundary commit and must pass repository validation,
  packaging verification, artifact-only candidate exercise, two-build SHA-256
  equality, release secret scan, and delivery-continuity assertions.
```

The final clean artifact command occurs immediately after the phase-boundary
commit because clean provenance intentionally refuses the uncommitted report.
Its SHA-256 is printed by the gate and its outer `.sha256` file, avoiding a
self-referential hash inside the artifact being hashed.

## Failure, recovery, and adversarial observations

The final review corrected incomplete rollback snapshotting, an incomplete
reviewer bundle, unsupported-host release construction, partial SBOM structure
checking, missing arbitrary credential/metadata campaigns, two inaccurate trust
claims, and a browser-harness environment/cleanup regression. All corrections
have regression checks. The artifact campaign's plaintext sentinels were absent
from log/JSON/text/Markdown operational artifacts and from the release scan.

## Residual limits and post-development work

The candidate does not claim protection from a compromised unlocked host,
external proof of local audit freshness, multi-node availability, automatic
off-host custody, official publication authentication, or speech verification
across every assistive-technology combination. It also does not claim that
independent security assurance, the owner's real recovery-custody exercise,
official signing/publication, or production deployment occurred.

Those owner-controlled activities are recorded as non-blocking post-development
tasks under `human_tasks/`. D-015 and D-016 preserve the accepted sequencing;
future findings create new remediation goals rather than reopening this phase's
honest evidence.

## Completion

All Phase 6 acceptance criteria pass without a pilot, owner approval checkpoint,
external account/reviewer, real custody material, signing identity, domain,
certificate, publication, or deployment. Phases 0–6 are complete and the
continuous development goal can close after the clean boundary gate passes.
