# Final requirements-to-evidence traceability

Status: **Complete for SMCV 0.1.0 candidate**
Date: 2026-07-21

Every committed requirement group is implemented and linked to reproducible
evidence. Phase reports state environment, commands, positive/negative behavior,
and residual limits; the [final internal review](../ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md)
adversarially sampled these links rather than accepting phase status alone.

| Requirements | Final result and primary evidence |
|---|---|
| VAULT-001 | Separate bound restrictive root provider; initialization interruption/substitution fails closed. [Phase 1](PHASE_1_EXIT_REPORT.md). |
| VAULT-002–004 | Complete namespace/secret lifecycle, opaque values, immutable versions, optimistic conflict behavior, explicit purge. [Phase 1](PHASE_1_EXIT_REPORT.md), [Phase 4](PHASE_4_EXIT_REPORT.md). |
| VAULT-005–006 | Protected metadata/value encryption, SQLite/WAL sentinel absence, versioned context-bound envelopes, exhaustive substitutions, rotation compatibility. [Phase 1](PHASE_1_EXIT_REPORT.md). |
| VAULT-007 | Expiration and upstream rotation-due schedules are distinct current-version advisories. [Phase 1](PHASE_1_EXIT_REPORT.md). |
| AUTHN-001–005 | Separate human/application auth; password/passkey, bounded server-side ceremonies, session/CSRF expiry, display-once verifier-only credentials, overlap/revoke/restart behavior. [Phase 2](PHASE_2_EXIT_REPORT.md). |
| AUTHN-006 | Local single-use clean-host owner recovery, RP-binding/passkey disable and reenrollment consequences. [Phase 3](PHASE_3_EXIT_REPORT.md), [Phase 4](PHASE_4_EXIT_REPORT.md). |
| AUTHZ-001–008 | Central deny-by-default request-scoped policy, independent grants, no self-escalation, immediate invalidation, move delta/recent auth, complete owner-only action rejection. [Permission matrix](PHASE_2_PERMISSION_MATRIX.md), [Phase 2](PHASE_2_EXIT_REPORT.md). |
| API-001–004 | Checked `/api/v1` router/OpenAPI parity, bounded requests/work, safe errors, no secret URLs, idempotency/version preconditions, universal private/no-store response policy. [Phase 2](PHASE_2_EXIT_REPORT.md), [OpenAPI](../api/openapi.yaml). |
| WEB-001–005 | Complete owner workflows, explicit ephemeral reveal, recent-auth consequences, self-contained same-origin assets, CSP, browser security and WCAG workflow evidence. [Phase 4](PHASE_4_EXIT_REPORT.md), [final accessibility](FINAL_ACCESSIBILITY_CONFORMANCE.md). |
| BACKUP-001–006 | CLI/web creation/download/import, separate passphrase/generated key modes, complete portable state/exclusions, no plaintext file, safe inspect and full authenticated verify. [Phase 3](PHASE_3_EXIT_REPORT.md), [Phase 4](PHASE_4_EXIT_REPORT.md). |
| BACKUP-007–015 | Transactional clean-only restore, preserve/revoke modes, versioned hostile reader, local authority, new installation/epoch, guarded activation, bounded durable job lifecycle and cleanup. [Phase 3](PHASE_3_EXIT_REPORT.md), [Phase 4](PHASE_4_EXIT_REPORT.md), [Phase 5](PHASE_5_EXIT_REPORT.md). |
| AUDIT-001–004 | Atomic domain event coverage, no protected values, exact actor/credential attribution, commitment versions/segments/epochs, documented local freshness limit. [Phase 1](PHASE_1_EXIT_REPORT.md), [Phase 2](PHASE_2_EXIT_REPORT.md), [Phase 3](PHASE_3_EXIT_REPORT.md). |
| OBS-001 | Status-only health, separate fixed-cardinality loopback metrics, allowlisted JSON logs, readiness integrity, sentinel/cardinality campaigns. [Phase 5](PHASE_5_EXIT_REPORT.md), [operations results](PHASE_5_OPERATIONS_REPORT.md). |
| OPS-001–003 | Frozen one-node x86-64 Linux/SQLite topology, same-host TLS loopback boundary, restrictive custody and closed fail-fast production preflight. [Phase 5](PHASE_5_EXIT_REPORT.md), [supported platform](../docs/SUPPORTED_PLATFORMS.md). |
| OPS-004–006 | Initialization/backup/restore/upgrade/incidents runbooks, migration/archive fixtures, explicit no-down-migration rollback, bounded growth/retention/disk tests. [Phase 5](PHASE_5_EXIT_REPORT.md), [tabletop](../docs/operations/TABLETOP_EXERCISES.md). |
| SEC-001 | Negative/failure/property/parser/accessibility campaigns and six adversarial repair passes; arbitrary archives, credentials, and metadata cannot panic. [Final review](../ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md). |
| SEC-002–003 | Locked reviewed graph, clean advisory/license/source checks, no project unsafe, seven SBOMs, reproducible candidate, checksums, safe extraction and local provenance. [Dependency review](../ai_context_documentation/DEPENDENCY_AND_UNSAFE_REVIEW.md), [Phase 5](PHASE_5_EXIT_REPORT.md). |
| SEC-004 | Final threat refresh, no open critical/high internal finding, residual register, D-015 acceptance, and self-contained external handoff. [Final review](../ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md), [risks](../ai_context_documentation/RESIDUAL_RISK_REGISTER.md), [handoff](../external_assurance/README.md). |
| DELIVERY-001 | No pilot/beta/adoption/external-user program is an implementation or completion gate. [Continuous amendment](CONTINUOUS_IMPLEMENTATION_AMENDMENT.md), [Phase 6 plan](../ai_phased_plans/PHASE_06_RELEASE_READINESS.md). |
| DELIVERY-002 | Phases 0–6 executed under one continuous goal with dependency-ordered boundary commits and no owner phase approval. [Phase evidence index](README.md). |
| DELIVERY-003 | Failed checks/findings became repair/retest work inside the active phase; each adversarial report records closure. [Final review](../ai_context_documentation/reviews/FINAL_INTERNAL_ASSURANCE.md), [review log](../ai_context_documentation/reviews/REVIEW_RESOLUTION_LOG.md). |
| DELIVERY-004 | Synthetic/local substitutes avoided accounts, domain/certificate, KMS/HSM, official signing, production system, and reviewer prerequisites. [Phase 5](PHASE_5_EXIT_REPORT.md), [Phase 6](PHASE_6_EXIT_REPORT.md). |
| DELIVERY-005 | External assurance, personal custody, official publication/signing, and deployment remain explicit post-development tasks. [Human tasks](../human_tasks/README.md), [release notes](../docs/RELEASE_NOTES_0.1.0.md). |
| PERF-001–002 | Reference-host load, bounded concurrency/queues/timeouts, Argon2id calibration and non-lowered security settings are recorded. [Operations results](PHASE_5_OPERATIONS_REPORT.md). |
| PERF-003 | Bounded frames/records/files/streams plus 16 MiB timing/RSS evidence and stated small-vault RPO/RTO. [Phase 3](PHASE_3_EXIT_REPORT.md), [operations results](PHASE_5_OPERATIONS_REPORT.md). |

Compatibility anchors retained by the final gate are migration v1 through the
current schema, metadata envelope v2, audit commitment readers v1/v2,
authorization vocabulary v1, `.smcvault` format v1, and `/api/v1`. No fixture
was retired for this candidate.
