# API design

Status: **Committed protocol properties; proposed resource shape**
Last reviewed: 2026-07-21

## General contract

- Base path: `/api/v1`.
- HTTPS is mandatory outside explicit loopback development.
- JSON is the default structured representation; binary secret values use a
  bounded base64 field or a separately specified octet-stream endpoint.
- Requests and responses use UTF-8 and explicit media types.
- All limits are documented and enforced before expensive processing.
- API documentation and an OpenAPI description are generated or checked from
  the same committed contract.

The browser uses the same origin. Owner endpoints authenticate through a
server-side session cookie plus CSRF protection. Application endpoints use an
`Authorization: Bearer` credential. Bearer credentials are never accepted in
query parameters or request paths.

## Proposed resource endpoints

Exact route names are validated during Phase 2, but the contract must support:

| Capability | Proposed route family |
|---|---|
| Namespaces | `/api/v1/namespaces` |
| Secret metadata and versions | `/api/v1/secrets`, `/api/v1/secrets/{id}/versions` |
| Explicit plaintext reveal | `/api/v1/secrets/{id}/value` |
| Service identities | `/api/v1/service-identities` |
| Application credentials | `/api/v1/service-identities/{id}/credentials` |
| Policies and effective access | `/api/v1/policies`, `/api/v1/effective-access` |
| Audit events | `/api/v1/audit-events` |
| Backup creation and safe metadata | `/api/v1/backups` |
| Restore staging/status | `/api/v1/restores` |
| Session and recent authentication | `/api/v1/session` |

High-risk operations use action-shaped subresources when ordinary CRUD would
hide important semantics, such as reveal, revoke, verify, or restore.

Fresh-host restore is authorized locally by the CLI. Network restore routes are
available only after a local single-use recovery channel or an authenticated
owner session exists; there is no remote first-claim endpoint.

## Secret representation

Metadata responses never include plaintext value fields. A value is returned
only by the explicit value endpoint after `secret:value-read` authorization.
Secret writes use one canonical bounded payload representation and an expected
version on update.

Secret-bearing requests and responses set or receive protections including:

- `Cache-Control: no-store`
- `Pragma: no-cache` where compatibility warrants it
- `X-Content-Type-Options: nosniff`
- A restrictive `Content-Security-Policy` for browser routes
- No response compression until a phase-specific side-channel review approves
  it for authenticated secret-bearing content

## Errors

Every error has:

- Stable machine-readable code.
- Safe human message.
- Request ID.
- Optional field errors that echo field names, not submitted secret values.

No SQL, stack trace, key-provider detail, ciphertext, policy internals, or
credential fragment is returned. Authentication failure is uniform.
Authorization and not-found behavior avoid resource enumeration. Integrity
errors are generic externally and detailed only through safe internal event
codes.

## Concurrency and retry

- Updates and destructive actions require an expected version through an ETag
  or explicit precondition field.
- A stale precondition returns a conflict without the current secret value.
- Create operations that clients may retry accept an idempotency key in a
  header, bound to principal and request digest.
- Reusing a key for different input is rejected.
- Idempotency keys are bounded and stored/logged only as verifiers.
- Reads are safe to retry; high-risk streaming operations state whether retry
  creates a new audit event.

## Pagination and filtering

Cursor pagination uses opaque, authenticated cursors with bounded page sizes.
Cursors include policy or query context so they cannot be replayed to broaden
access. Filters use an allowlist and never become raw SQL fragments. Protected
metadata search is limited by the blind-index leakage decision in the crypto
document.

## Rate and resource limits

Separate limits apply to:

- Login and recent-authentication attempts.
- Invalid application credentials.
- Ordinary metadata operations.
- Secret-value reads.
- Password hashing and archive KDF work.
- Backup/import size, record count, chunk size, and concurrent jobs.

Limits combine per-source and per-principal controls without trusting proxy
headers unless the proxy boundary is configured. Expensive work uses bounded
queues and returns a safe unavailable/rate-limit response when saturated.

## Browser security

- Session cookies use the `__Host-` prefix, `Secure`, `HttpOnly`, `Path=/`, and
  `SameSite=Strict` in production.
- State-changing browser requests require a CSRF token bound to the session.
- CORS is disabled by default; an allowlist is not a substitute for CSRF.
- Session IDs rotate after login and privilege/recent-auth changes.
- Logout invalidates server state and clears site data where safe.
- Sensitive content is not placed in URLs, browser storage, service-worker
  caches, or referrer-bearing navigation.

## Audit semantics

Each request has one correlation ID. Domain operations may generate multiple
audit events, but every protected decision is attributable to the request,
principal, and credential. Access logs record route templates and status—not
raw paths where user-controlled identifiers, headers, query strings, or bodies
could leak data.

## Compatibility

Additive fields are documented as ignorable by clients. Removing or changing
semantics requires a new API version or explicit deprecation window. Backup
format versions and API versions are independent.

## Long-running backup and restore jobs

Job state is durable but bounded. It records safe stage, result, expiry, and
opaque artifact reference so disconnecting the browser does not cancel or
misreport work. Cancellation states whether server work was stopped or only the
client detached. Encrypted download artifacts use opaque randomized names,
restrictive creation permissions, per-owner quotas, short expiry, and explicit
deletion after download/expiry. The UI never treats server retention as proof
that the owner has an off-host backup.
