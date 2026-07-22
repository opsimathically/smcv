# Phase 2: identity, authorization, and API

Status: **Planned**

## Objective

Expose the encrypted core through a versioned API with strong owner and service
authentication, centralized least-privilege authorization, non-enumerating
errors, and complete security auditing.

## Entry criteria

- Phase 1 exit evidence passes.
- Stored formats and vault-domain interfaces frozen for the phase.
- D-104, D-105, and D-106 reviewed for final implementation.

## In scope

- Local owner enrollment and recovery path.
- Preferred phishing-resistant authentication and approved fallback.
- Server-side browser sessions, CSRF, recent authentication, and logout.
- Service identities and display-once application credentials.
- Allow-only policies, bindings, effective-access calculation, and revisioned
  invalidation.
- `/api/v1` OpenAPI contract for vault, identity, policy, and audit operations.
- TLS/development binding controls, request bounds, rate limits, safe errors,
  pagination, idempotency, and concurrency preconditions.
- API-level audit and telemetry redaction.
- A minimal same-origin functional authentication/recent-auth harness needed to
  validate passkeys, cookies, and CSRF; polished administration UI remains
  Phase 4 scope.

## Out of scope

- Portable backup endpoints, completed web administration UI, multi-user roles,
  OIDC, explicit deny rules, and arbitrary policy expressions.

## Work slices

1. Owner authenticator and session lifecycle.
2. Service identity and credential lifecycle.
3. Policy engine and generated permission matrix.
4. Bounded API ingress and error contract.
5. Secret/namespace/version endpoints.
6. Identity/policy/audit endpoints.
7. Enumeration, revocation, CSRF, and saturation adversarial campaign.

## Acceptance criteria

- Every protected domain call has a declared action and denial audit path.
- Write-only, read-only, exact-secret, namespace, sibling, and descendant tests
  match the authorization model.
- Service policy validation rejects every owner-only administrative action,
  including backup, restore, key, identity, policy, audit administration,
  namespace administration, and purge.
- Credential revocation blocks the next request under concurrency, cache, and
  restart tests.
- Raw credentials are returned only once and never occur in database, logs,
  traces, metrics, audit, or error fixtures.
- Session fixation, cross-origin state change, stale recent-auth state, and
  browser token-storage tests fail safely.
- Unauthorized versus nonexistent probes have equivalent external contract
  within documented limits.
- Expensive authentication and request paths remain bounded under saturation.
- OpenAPI examples contain only synthetic non-sensitive data and match runtime.

## Required evidence

- Generated permission matrix and coverage map.
- Credential/session lifecycle transcripts.
- Sentinel leakage scans across all observability outputs.
- API conformance and malformed-request/fuzz results.
- Revocation race and policy-invalidation results.
- Namespace-move effective-access delta and broadened-access reauthentication
  results.
- Identity/authz/API adversarial review and resolutions.

## Adversarial review prompts

- Can any HTTP, repository, owner shortcut, or policy cache reach decryption
  without the central authorization decision?
- Can a service policy encode an owner-only action or increase its own authority?
- Can status, body shape, pagination, conflict, timing, or audit access reveal a
  resource the principal cannot list/read?
- Can credential/session revocation race a cached successful decision?
- Can authentication work, headers, JSON, or idempotency state exhaust bounded
  resources before rejection?

## Exit gate

AUTHN, AUTHZ, API, and relevant AUDIT requirements pass; no high finding remains;
application clients can perform narrowly authorized operations over TLS.
