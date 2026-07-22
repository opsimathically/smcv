# Phase 5: operational hardening

Status: **Planned**

## Objective

Make SMCV deployable, observable, upgradeable, recoverable, and diagnosable by
an operator without weakening its trust boundaries.

## Entry criteria

- Phase 4 exit evidence passes.
- Supported deployment platforms selected.
- Representative capacity/recovery objectives proposed.

## In scope

- Production packaging and service supervision examples.
- TLS/reverse-proxy, permissions, key-provider, and trusted-proxy validation.
- Safe configuration reference and production preflight.
- Health/readiness, redacted telemetry, alerting guidance, and capacity limits.
- Scheduled backup, retention safety, verification, and restore-drill tooling.
- Upgrade/rollback and schema/archive compatibility procedures.
- Required incident runbooks and security reporting process.
- Release SBOM, checksums, provenance, and artifact verification.
- Load, saturation, soak, disk-full, time-skew, and shutdown tests.

## Out of scope

- Active-active HA, automatic cloud orchestration, managed hosting, and every
  possible OS/distribution.
- External accounts, production infrastructure, official signing identity,
  public domain/certificate issuance, and personal real-key custody testing.

## Work slices

1. Supported platform packaging, service identity, filesystem, and key-provider
   setup.
2. TLS/reverse-proxy and production configuration preflight.
3. Health, telemetry, alerting, capacity, and saturation behavior.
4. Scheduled backup, retention, restore drills, and formal RPO/RTO.
5. Upgrade/rollback and schema/archive compatibility operations.
6. Incident runbooks, vulnerability handling, and synthetic tabletop exercises.
7. Release artifact, SBOM, checksum, provenance, optional local test signing,
   and verification.

## Acceptance criteria

- A clean supported host can install, initialize, harden, back up, upgrade,
  diagnose, and restore using documentation alone.
- Production preflight rejects insecure plaintext binding, unsafe permissions,
  missing key material, incompatible schema, and invalid proxy trust.
- Logs/metrics/traces pass sentinel and cardinality review under success and
  failure load.
- Scheduled backup cannot delete the last verified copy and alerts on age or
  verification failure.
- Published capacity and recovery objectives are met in representative tests.
- Formal RPO/RTO builds on Phase 3 provisional archive and restore measurements
  rather than selecting an untested target late in release preparation.
- Release artifact, SBOM, checksum, and provenance verification is documented
  and tested.
- Every required incident runbook completes a synthetic tabletop exercise that
  requires no production account or owner participation.

## Required evidence

- Clean-host deployment and upgrade transcripts.
- Backup retention and restore-drill evidence.
- Load/saturation/disk-full/shutdown results.
- Telemetry disclosure review.
- Incident tabletop reports.
- Artifact/SBOM/provenance verification.

## Adversarial review prompts

- Can unsafe permissions, proxy headers, plaintext binding, or missing keys pass
  production preflight?
- Can logs, labels, support bundles, crash output, or health endpoints reveal
  protected or host-sensitive data?
- Can retention delete the final verified backup or fill disk with history,
  WAL, failed staging, or expired job artifacts?
- Can an upgrade leave no tested rollback/recovery path or accept a mismatched
  artifact/SBOM/provenance chain?

## Exit gate

OPS, OBS, supply-chain, upgrade, and incident requirements pass with no
unresolved high finding and documented residual operational risks. A failed
check stays inside the active goal as repair/retest work; no owner approval is
required to proceed to Phase 6 after evidence passes.
