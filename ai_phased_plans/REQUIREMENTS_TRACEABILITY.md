# Requirements traceability

Status: **Planned ownership baseline**
Last reviewed: 2026-07-21

This matrix assigns implementation and final-verification ownership. It does not
replace the full acceptance language in `PRODUCT_REQUIREMENTS.md` or phase
plans. A requirement may span phases; the final owner cannot close it until all
earlier evidence is linked.

| Requirements | Primary implementation phase | Final verification | Expected evidence |
|---|---|---|---|
| VAULT-001 | 1 | 6 | Initialization/unlock state-machine failure matrix; external key absence |
| VAULT-002–004 | 1, API in 2, UI in 4 | 6 | Lifecycle/version/concurrency tests and critical-flow evidence |
| VAULT-005–006 | 1 | 6 | DB/WAL sentinel scan, envelope vectors, algorithm/key-version migration |
| VAULT-007 | 1, API in 2, UI in 4 | 6 | Expiration/rotation-due behavior and language review |
| AUTHN-001–005 | 2, UI completion in 4 | 6 | Session/passkey/password/token lifecycle, revocation, browser tests |
| AUTHN-006 | 3, UI completion in 4 | 6 | Fresh-host local recovery and RP-binding/reenrollment evidence |
| AUTHZ-001–006 | 2 | 6 | Generated permission matrix, revocation/invalidation concurrency tests |
| AUTHZ-007 | 2, UI in 4 | 6 | Namespace-move access delta, recent auth, and audit evidence |
| AUTHZ-008 | 2, UI in 4 | 6 | Service-policy rejection of every owner-only action |
| API-001–004 | 2 | 6 | OpenAPI conformance, bounds, errors, cache, retry/concurrency tests |
| WEB-001–005 | 4 | 6 | Critical-flow, DOM/storage/network, CSP, third-party, WCAG evidence |
| BACKUP-001 | 3 CLI/API; 4 web | 6 | CLI and web create/download on clean supported build |
| BACKUP-002–006 | 3 | 6 | Key modes, public-header scan, corrupt/key/compatibility verification |
| BACKUP-007–015 | 3, UI in 4, operations in 5 | 6 | Local-authority staged restore, epochs, credential modes, job cleanup |
| AUDIT-001–004 | 1 persistence; 2–4 domain/UI | 6 | Event coverage, sentinel scan, chain/epoch and external-limit review |
| OBS-001 | 2 baseline; 5 production | 6 | Log/trace/metrics allowlist and sentinel/cardinality tests |
| OPS-001–003 | 0 decisions; 1/2 behavior; 5 packaging | 6 | Platform, SQLite, preflight, TLS, permissions, readiness evidence |
| OPS-004–006 | 3 recovery; 5 operations | 6 | Runbooks/tabletops, compatibility, retention/capacity/disk tests |
| SEC-001 | Every phase | 6 | Negative, property, fuzz, failure, accessibility, and review reports |
| SEC-002–003 | 0 baseline; 5 release | 6 | Lock/advisory/license checks, SBOM, artifact provenance verification |
| SEC-004 | 6 | 6 | Final internal assurance report, residual-risk register, recorded 2026-07-21 owner acceptance, and external-assurance handoff package |
| DELIVERY-001–005 | Every phase | 6 | Continuous phase advancement, repair/retest records, no external prerequisite, and post-development handoff separation |
| PERF-001–002 | 0 baseline; 1/2 measurement | 5 and 6 | Benchmarks, authentication calibration, saturation/queue results |
| PERF-003 | 3 provisional; 5 supported limits | 6 | Small/large streaming backup/restore time, memory, and disk evidence |

## Traceability rules

- Phase exit reports link requirement IDs to specific evidence locations.
- A test name alone is not evidence; include result, environment, and failure
  behavior.
- Later phases may discover that a requirement needs an earlier architectural
  change. Reopen the owning phase decision instead of adding a UI workaround.
- Any new committed requirement must be assigned here and to a phase before
  implementation.
- Deferred decisions must not acquire requirement coverage accidentally.
