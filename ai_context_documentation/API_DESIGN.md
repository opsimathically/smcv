# API design

Status: **Committed Phase 2 API, Phase 3 backup jobs, and Phase 4 browser adapters**
Last reviewed: 2026-07-22

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

## Committed Phase 2 resource endpoints

The checked OpenAPI 3.1 document at `/api/v1/openapi.json` and its runtime
conformance test commit these route families:

| Capability | Proposed route family |
|---|---|
| Namespaces | `/api/v1/namespaces` |
| Secret metadata and versions | `/api/v1/secrets`, `/api/v1/secrets/{id}/versions` |
| Explicit plaintext reveal | `/api/v1/secrets/{id}/value` |
| Service identities | `/api/v1/service-identities` |
| Application credentials | `/api/v1/service-identities/{id}/credentials` |
| Policies and effective access | `/api/v1/policies`, `/api/v1/service-identities/{id}/effective-access` |
| Audit events | `/api/v1/audit-events` |
| Backup creation and safe metadata | `/api/v1/backups` |
| Existing-backup verification and clean restore drill | `/api/v1/backup-verifications` |
| Session and recent authentication | `/api/v1/session` |

Phase 2 also commits namespace move-impact and confirmed-move, immutable
historical value, passkey ceremony, credential revocation, and OpenAPI
subresources. Phase 3 adds owner-authorized backup create/status/download/delete
routes after their format and job semantics pass the portable-recovery gate.
Phase 4 adds a recent-owner-authorized streaming multipart verification route.
It stores the encrypted upload restrictively, runs full verification plus a
clean staging restore exercise, and removes both temporary archive and staging
vault before responding.

Fresh-host browser restore is deliberately outside the normal server router.
`smcv backup-restore-browser` creates an ephemeral `/api/recovery/*` adapter on
a random loopback port. The CLI displays a clean URL and a separate 256-bit
authorization code. The browser submits that code once in a protected body,
clears its input, and receives an HttpOnly, SameSite-strict loopback session
cookie. The process holds only code and session digests; the channel expires
after ten minutes and is consumed by one activation attempt. The next request
streams and authenticates the archive; the final request confirms its
authenticated ID and preserve-or-revoke credential choice before atomic
activation. There is no network first-claim route.

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
- A browser create form keeps the same key after a transport or server failure
  whose commit outcome is unknown. It rotates the key only after a definitive
  client rejection. The UI requires a state reload before retrying any other
  mutation with an ambiguous outcome.
- Reads are safe to retry; high-risk streaming operations state whether retry
  creates a new audit event.

## Pagination and filtering

Phase 2 uses stable exclusive opaque record IDs or monotonic safe sequence
numbers as bounded cursors. Cursor use is authorized again against the current
principal and resource, so a cursor never carries authority. Future compound
filter cursors must be authenticated and include policy/query context. Filters
use an allowlist and never become raw SQL fragments. Protected metadata search
is limited by the blind-index leakage decision in the crypto document.

## Rate and resource limits

Separate limits apply to:

- Login and recent-authentication attempts.
- Invalid application credentials.
- Ordinary metadata operations.
- Secret-value reads.
- Password hashing and archive KDF work.
- Backup/import size, record count, chunk size, and concurrent jobs.

Phase 2 derives unauthenticated source limits from the TCP peer rather than
forwarding headers: password attempts are limited to 10 per peer per minute
and passkey authentication ceremony requests to 20 in a separate bucket.
Known application credentials receive independent 120-request-per-minute
buckets so one workload behind the same-host ingress cannot throttle another;
malformed and unknown bearer tokens remain in the bounded peer bucket. Each
limiter tracks at most 4,096 keys. Password work is limited to four concurrent
Argon2id jobs, all requests to 128 concurrent operations, headers to 64/32 KiB,
bodies to 1 MiB, and request time to 15 seconds. The authenticated archive
verification and local recovery upload routes explicitly override those body
and time bounds up to the documented 8 GiB web-import limit and 15-minute
operation window; archive framing enforces its own tighter structural bounds.
Expensive online backup and verification work shares a four-slot semaphore.
Phase 5 calibrates production limits and proxy deployment rules. Saturation
returns a safe rate-limit or timeout response.

Operational metrics are not part of `/api/v1` and are never served by the
product listener. When enabled, a separate loopback-only listener exposes a
fixed vocabulary of aggregate counters without route, actor, source, object,
vault, installation, or user-controlled labels. Production product binding is
also loopback-only behind the documented TLS ingress; forwarding headers are
cleared and never trusted.

## Browser security

- Session cookies use the `__Host-` prefix, `Secure`, `HttpOnly`, `Path=/`, and
  `SameSite=Strict` in production.
- State-changing browser requests require a CSRF token bound to the session.
- Session lock/logout is the narrow exception needed to revoke a cookie after
  page reload has discarded the display-once CSRF value. It requires the
  session cookie plus the non-simple `X-SMCV-Session-Lock: 1` header; ordinary
  cross-origin form requests cannot supply that header, and CORS remains off.
- CORS is disabled by default; an allowlist is not a substitute for CSRF.
- Session IDs rotate after login and privilege/recent-auth changes.
- Session, authenticator, credential, and ceremony timestamps fail closed when
  the wall clock moves earlier than already committed authentication state.
- Session creation atomically compares the authenticator state observed during
  verification, preventing concurrent assertions or revocation from being
  overwritten by stale successful-login state.
- Logout invalidates server state and clears site data where safe.
- Browser documents deny framing and unnecessary device capabilities, isolate
  opener/resource contexts, and emit HSTS for the production HTTPS boundary.
- Sensitive content is not placed in URLs, browser storage, service-worker
  caches, or referrer-bearing navigation.

## Audit semantics

Each request has one correlation ID. Domain operations may generate multiple
audit events, but every protected decision is attributable to the request,
principal, and credential. Phase 2 access spans record method plus matched route
template only—not raw paths, identifiers, headers, query strings, or bodies.

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
