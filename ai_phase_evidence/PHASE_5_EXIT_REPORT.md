# Phase 5 exit report

Phase: 5 — operational hardening
Date: 2026-07-21
Status: **Passed; Phase 6 active**
Phase boundary: the local commit containing this report

## Delivered scope

Phase 5 delivers an x86-64 Linux/systemd support boundary; production preflight;
same-host TLS-proxy contract; separate loopback fixed-label metrics; structured
redacted logs; bounded SIGTERM drain; verify-before-delete scheduled backup and
retention; isolated restore drills; upgrade/rollback, telemetry/capacity,
deployment, backup, incident, and tabletop guides; and deterministic release
construction with per-crate SBOMs, checksums, local provenance, and optional
test signing.

## Acceptance and requirements evidence

| Requirements / criterion | Evidence and result |
|---|---|
| OPS-001–003 | [Deployment procedure](../docs/operations/DEPLOYMENT.md), packaged systemd/nginx configuration, and startup tests enforce one unprivileged Linux instance, local SQLite, existing separate custody, effective-UID ownership, safe modes, loopback-only product/metrics listeners, HTTPS origin intent, known config, matching root/schema, and integrity readiness. |
| OPS-004 | Initialization, backup/restore, upgrade/rollback, and all nine required incidents have executable procedures and a [synthetic tabletop](../docs/operations/TABLETOP_EXERCISES.md). |
| OPS-005 | Frozen Phase 0 schema migration and committed `.smcvault` v1 fixture pass; rollback retains the matching old binary/snapshot and never attempts a down-migration. |
| OPS-006 | Published bounds cover secret, request, archive, logical stream, records, concurrency, KDF queues, jobs, and retention inventory. Disk-full, WAL, capacity, and explicit-history behavior are tested. |
| OBS-001 | Product health reveals status only; metrics are independently loopback-only and fixed-cardinality. Unit and process campaigns prove an attacker-controlled sentinel and dynamic labels absent. Logs use method plus matched route, not raw URI/body/header/user labels. |
| BACKUP-007–015 | Daily protected-FD maintenance creates/verifies before deletion, protects the new/final verified copy, alerts without deleting corrupt candidates, and runs an isolated clean restore/reopen/integrity/cleanup drill. |
| SEC-002–003 | Locked dependency policy passes; release bundle contains seven CycloneDX SBOMs, normalized local provenance, internal and outer SHA-256, dirty-tree protection, safe extraction, reproducibility, and optional verified local signature. |
| PERF-001–003 | [Capacity evidence](PHASE_5_OPERATIONS_REPORT.md) records the reference host, 2,048-request campaign, 16 MiB multi-frame measurement, resource bounds, Argon2id parameters, 24-hour RPO, and small-vault 15-minute RTO. |

## Reproducible validation

```text
./scripts/check.sh
./scripts/operations-smoke.sh
SMCV_ALLOW_DIRTY_BUILD=1 ./scripts/build-release.sh
SMCV_ALLOW_DIRTY_VERIFY=1 ./scripts/verify-release.sh dist/ARTIFACT.tar.gz
systemd-analyze verify packaging/systemd/*.service packaging/systemd/*.timer
systemd-analyze security --offline=yes packaging/systemd/smcv.service
systemd-analyze security --offline=yes packaging/systemd/smcv-backup.service
```

The repository-wide gate passes formatting, strict all-feature Clippy, 79 Rust
tests, rustdoc, RustSec, license/source policy, expanded source/asset secret
scan, shell syntax, and Markdown links. The clean-tree release build and normal
verification run immediately after the phase boundary commit.

## Adversarial review and residual risk

The [Phase 5 adversarial
review](../ai_context_documentation/reviews/PHASE_5_ADVERSARIAL_REVIEW.md)
closed four high and four medium findings. No critical or high finding remains.
Off-host transfer, public certificate/domain, official signing identity,
production deployment, personal key-custody test, and independent assurance
remain owner-controlled post-development actions and are not represented as
completed.

## Phase transition

The operational, observability, supply-chain, upgrade, recovery-objective, and
incident gates pass without an external dependency or human task. Phase 6 may
perform final integrated assurance and release-candidate handoff under the same
continuous goal.
