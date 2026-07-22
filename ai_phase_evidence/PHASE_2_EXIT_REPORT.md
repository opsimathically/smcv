# Phase 2 exit report

Phase: 2 — identity, authorization, and API
Date: 2026-07-21
Status: **Passed; Phase 3 active**
Phase boundary: the local commit containing this report

## Environment and scope

- Linux x86_64 development host
- `rustc 1.94.0 (4a4ef493e 2026-03-02)` and Cargo 1.94.0
- Declared MSRV Rust 1.88 after the patched `time 0.3.47` selection
- Bundled SQLite through locked `rusqlite 0.39.0`
- `webauthn-rs 0.5.4`, exact RP/origin binding, user verification required
- Synthetic temporary vaults, identities, credentials, and secret values only

Delivered scope includes local-only owner enrollment, Argon2id password login,
passkey registration/authentication ceremonies, verifier-only browser sessions
and CSRF, service identities, rotating application credentials, a revisioned
allow-only policy graph, request-scoped centralized authorization, list/value/
history/lifecycle APIs, namespace move-impact confirmation, effective-access
inspection, bounded audit reads, peer-derived rate limits, and checked OpenAPI.

## Acceptance and requirements evidence

| Requirements / criterion | Evidence and result |
|---|---|
| AUTHN-001–002 | Owner sessions and service bearer credentials have separate formats, records, and lifecycles. Passwords use salted Argon2id (64 MiB, t=3, p=1); WebAuthn is pinned to RP/origin and requires user verification. Pending ceremony state is server-side, one-use, five-minute, capped at 32, and separately peer-rate-limited. Session creation compare-and-swaps the verified authenticator commitment so concurrent passkey counter updates or revocation cannot be overwritten. |
| AUTHN-003 | Session and CSRF tokens use independent verifier domains. Sessions have 30-minute sliding idle and 12-hour absolute expiry, five-minute recent authentication, secure host-only cookies, CSRF on browser mutations, and durable logout. Stale recent auth, stale copied context, stale authenticator state, and backward-clock authentication fail closed. |
| AUTHN-004–005 | Application credentials contain random display-once material and only keyed verifiers persist. Multiple credentials may overlap, optionally expire, expose safe bounded last-use metadata, and revoke individually. Concurrent revocation waits for an executing request, rejects the next request, and remains rejected after restart. A copied service context cannot move before committed last use; known wrong-secret/revoked/expired attempts create attributed denial events without claiming an authenticated actor. Raw credential/password scans cover SQLite and WAL artifacts. |
| AUTHZ-001–003 | Every exposed protected operation enters `AuthorizedVault` or an owner administration entry point that reloads session state and calls the centralized closed-action boundary. Allowed and denied decisions are audit-attributed to request, principal, credential kind, and opaque credential ID. |
| AUTHZ-004 | The matrix fixture proves a pure write-only service can create but cannot reveal, while separately granted metadata, value, namespace-list, secret-list, history, and historical-value actions remain independent. |
| AUTHZ-005–006 | Credentials contain no grants and services cannot call policy management. Policies are evaluated from the authenticated current graph without a cache. Archive invalidates the next request; credential revocation is linearized under concurrency and survives restart. |
| AUTHZ-007 | Namespace moves calculate exact newly inherited service/action pairs. Preview enters the centralized `effective-access:read` boundary and authenticates every ancestor used in the delta. Stale or incomplete confirmation fails; broadened access requires recent auth; the confirmed move changes descendant access and is audited. |
| AUTHZ-008 | The generated [permission matrix](PHASE_2_PERMISSION_MATRIX.md) covers all 28 actions. The complete-set executable test rejects backup, restore, key, vault, identity, credential, policy, audit, namespace administration, and purge actions from every service policy. |
| API-001 | `/api/v1` enforces 1 MiB bodies, 64 headers/32 KiB total headers, 15-second timeout, 128 concurrent requests, bounded pages, stable errors, UUID request correlation, local-only plaintext HTTP, and protected non-loopback opt-in. The checked OpenAPI document has exact runtime path/method parity and unique operation IDs. |
| API-002/API-004 | Credentials and values occur only in protected headers, cookies, request bodies, or explicit value responses—never URLs. All responses receive `no-store`, `no-cache`, `nosniff`, no-referrer, and restrictive CSP; no response compression is configured. |
| API-003 | Namespace and secret creates use principal-bound HMAC idempotency-key verifiers plus canonical request fingerprints; matching retries recover the deterministic response ID and mismatched reuse conflicts. Updates, moves, archive, restore, policy archive, and revoke require explicit version/revision preconditions. |
| AUDIT-001–004 | Authorization allow/deny—including absent-target denials—reveal, lifecycle, identity, credential, policy, session, and owner enrollment events use audit commitment v2 with exact credential attribution. Known rejected application credentials are audited without authenticating the claimant as actor. Sensitive bodies and raw tokens are absent. Method/route-template-only trace spans avoid URI/header/body leakage. The Phase 1 tamper-limit language remains unchanged. |
| OBS-001 | Liveness and readiness are distinct; readiness performs a bounded SQLite integrity check. Errors and startup summaries are redacted. Trace fields are allowlisted to method and matched route template. |
| OPS-001–003 | The server rejects unprotected non-loopback binding, uses one process/SQLite vault, and fails startup on key/schema/path problems. Unauthenticated source limits derive from the TCP peer rather than untrusted forwarding headers; known application credentials have independent bounded rate buckets so the supported same-host proxy does not couple workload limits. |
| SEC-001–003 | Strict all-feature Clippy, tests, docs, RustSec, source/license policy, secret scanning, and link checks pass. RUSTSEC-2026-0009 found during the gate was fixed by selecting `time 0.3.47`; no advisory waiver remains. |

## Reproducible validation

```text
./scripts/check.sh
  PASS: rustfmt and strict all-feature Clippy
  PASS: 54 unit/property/integration/failure tests and all doc tests
  PASS: rustdoc warnings denied
  PASS: RustSec advisory scan and cargo-deny license/source policy
  PASS: exact application-token/private-key repository scan
  PASS: every relative Markdown link resolves
```

Focused evidence includes:

- `exact_and_descendant_grants_do_not_leak_to_siblings_or_owner_actions`:
  exact/sibling, list/read/write/history, owner-only action, namespace move, and
  policy invalidation matrix.
- `display_once_service_credential_authenticates_and_revokes_immediately`:
  verifier-only issuance, last-use metadata, concurrent gate ordering,
  next-request/restart rejection, and SQLite/WAL leakage scan.
- `local_enrollment_password_login_session_and_csrf_round_trip`: password,
  independent CSRF, stale recent authentication, logout, and stale-context
  rejection.
- Server integration tests: secure cookie/CSRF behavior, denied-versus-absent
  external equivalence, body/header/Argon saturation, per-peer rate windows,
  safe malformed errors, and OpenAPI/runtime parity.

## Adversarial review

The [Phase 2 adversarial
review](../ai_context_documentation/reviews/PHASE_2_ADVERSARIAL_REVIEW.md)
recorded four high and six medium findings. All high findings and all actionable
Phase 2 medium findings were corrected and regression tested. Corrections added
the type-level protected facade, revocation/policy gate, durable owner-context
rechecks, closed service action allowlist, missing list/history routes, peer
limits, checked OpenAPI, credential inventory, patched dependency, and safe
route-template tracing.

No critical or high finding remains.

## Compatibility anchors introduced

- SQLite migration v3/checksum adds principals, authenticators, sessions,
  service identities, application credentials, policies/grants/bindings,
  authorization revision state, idempotency records, and audit attribution.
- Audit commitment v2 adds credential kind and opaque credential record ID;
  the reader retains v1 verification compatibility.
- Closed authorization vocabulary v1 contains 28 stable action spellings.
- Password PHC records use Argon2id; application, session, and CSRF token shapes
  and their verifier domains are versioned and distinct.
- Encrypted service metadata `SMCVSI01` and policy label `SMCVPL01` are bounded
  durable compatibility formats.

## Residual risk and forward ownership

- The process authorization gate relies on the committed single-instance
  topology. D-202 prohibits treating it as multi-instance synchronization.
- Real browser/hardware WebAuthn, DOM/storage inspection, CSP navigation, and
  WCAG workflow evidence remain Phase 4.
- General SQLite blocking isolation, production rate calibration, coarse timing
  measurement, proxy source rules, and optional network-source audit context
  remain Phase 5.
- Namespace deletion/vault lock and secret relocation are closed owner-only
  capabilities without Phase 2 public routes. Later workflow work must use the
  existing actions and central boundary rather than inventing shortcuts.
- Independent external assurance remains the post-development handoff accepted
  under D-015; it is not claimed here.

## Phase transition

No human task, external account, public certificate, hardware authenticator, or
new authority is required. Phase 3 may build portable `.smcvault` creation,
verification, and clean-host restore on the authenticated vault and API. The
same long-running goal continues without an approval pause.
