# Phase 2 identity, authorization, and API adversarial review

Status: **Complete; all high findings closed**
Date: 2026-07-21
Scope: owner and service authentication, sessions, passkeys, policy evaluation,
request authorization, API ingress, audit attribution, and observable errors

## Review method

The review traced every plaintext-capable domain call from HTTP ingress through
authentication, the closed action vocabulary, current policy state, encrypted
storage, audit commit, and response headers. It exercised exact, sibling,
namespace, descendant, write-only, read-only, stale-session, revoked-credential,
archived-policy, moved-namespace, malformed-input, saturation, and restart
cases. Source review covered token persistence, tracing fields, OpenAPI/runtime
drift, ceremony bounds, locking, and all service-grantable actions.

All fixtures use synthetic temporary vaults and credentials.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P2-A01 | High | The encrypted core initially exposed plaintext-capable methods without a type-level authenticated boundary, allowing a future adapter to bypass policy evaluation. | Core vault methods are crate-private. Public protected operations require a request-scoped `AuthorizedVault`, which records one explicit action before domain access. Direct authorization is crate-private. |
| P2-A02 | High | A credential or policy could be revoked after authentication/authorization but before the protected operation, allowing one request after the revocation commit. | A process read/write authorization gate now spans current credential/session recheck, policy evaluation, and the operation. Logout, credential revoke, policy mutation, and access-affecting namespace moves take the write gate. A concurrent revoke blocks behind an executing request, then the next request and restart both reject the credential. |
| P2-A03 | High | Owner-only service, passkey, credential, and policy administration accepted a time-valid `AuthenticatedOwner` value without reloading durable session revocation state. | Every owner administrative entry point now reloads and authenticates the current session under the gate, performs centralized owner-action authorization, and then mutates. Logout therefore invalidates stale copied contexts. |
| P2-A04 | High | A policy parser that accepted arbitrary action strings could grant identity, backup, key, audit, policy, or purge authority to a service. | `Action::ALL` is a closed 28-action vocabulary and `is_service_grantable` is an explicit narrow allowlist. The complete-set test rejects every owner-only action; invalid descendant shape also fails before persistence. |
| P2-A05 | Medium | The initial API omitted immutable history/value and list operations even though they were distinct committed permissions. | Added bounded `namespace:list`, `secret:list`, `secret:history-read`, and `secret:version-read` operations, routes, positive grants, and cross-permission denial tests. Historical values use exact version-bound AEAD context and audit before return. |
| P2-A06 | Medium | Login concurrency alone did not prevent repeated per-source attempts or invalid-bearer traffic from consuming bounded work. | TCP-peer-derived, forwarding-header-independent fixed-window limits now bound password attempts, all bearer requests, and tracked source cardinality. Argon2id jobs, total HTTP concurrency, headers, body size, and request duration also have independent bounds and saturation tests. |
| P2-A07 | Medium | A hand-maintained partial OpenAPI document could silently diverge from runtime routes. | The OpenAPI 3.1 document now includes every `/api/v1` path and method, security schemes, common limits, and synthetic examples. A runtime test compares the exact route/method set and enforces unique operation IDs. |
| P2-A08 | Medium | Credential rotation had display-once issuance and revoke but no safe last-use inventory, encouraging operators to retain raw credentials elsewhere just to identify activity. | Added bounded owner-only credential metadata pages containing only opaque record ID, timestamps, revision, expiry, and revocation. Database/WAL scans prove raw credential and password sentinels are absent. |
| P2-A09 | Medium | The locked WebAuthn certificate stack selected `time 0.3.45`, affected by RUSTSEC-2026-0009. Keeping the prior Rust 1.85 MSRV prevented the patched release. | Updated to `time 0.3.47`, advanced the documented MSRV to Rust 1.88, reran all-feature compilation/tests/docs, and obtained a clean RustSec result. |
| P2-A10 | Medium | Default HTTP tracing could include raw URI paths and query strings containing opaque identifiers or attacker-controlled filters. | Trace spans now allowlist only HTTP method and Axum's matched route template. Headers, raw URI, query, request/response bodies, protected labels, and credential fragments are not recorded. |

## Residual limits assigned forward

- The authorization gate is intentionally process-local and is sound only for
  the committed single-instance topology. Multi-process support requires a new
  cross-instance revision/lease design and is deferred under D-202.
- Phase 2 records authenticated channel and opaque credential reference as safe
  audit source context; it deliberately does not retain network addresses.
  Phase 5 owns any coarse/keyed network-source field and its privacy/retention
  review.
- Common denied-existing and absent probes have identical status, code,
  message, and response shape. Perfect timing equivalence is not claimed;
  Phase 5 load calibration and Phase 6 adversarial measurement retain that
  residual traffic-analysis review.
- Password hashing is isolated on bounded blocking workers. General SQLite
  blocking isolation and supported-hardware saturation calibration remain
  Phase 5 work before release readiness.
- Real browser/authenticator WebAuthn interaction and browser-storage inspection
  require the Phase 4 same-origin UI harness. Phase 2 validates RP/origin
  binding, user-verification policy, one-use state, expiration, persistence
  bounds, and API ceremony shape without claiming a hardware ceremony.

## Conclusion

All critical/high findings were repaired and retested within Phase 2. No open
finding blocks Phase 3. The review is internal engineering assurance, not the
post-development independent review described by D-015.
