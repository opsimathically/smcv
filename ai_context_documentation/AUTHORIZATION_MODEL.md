# Identity and authorization model

Status: **Committed and implemented for the Phase 2 API**
Last reviewed: 2026-07-22

## Identity types

### Owner

The v1 owner is the sole human administrative principal. Owner status permits
administrative workflows but does not remove recent-authentication,
maintenance-lock, audit, or other safety requirements. "Owner" is not encoded
as an application token scope.

### Service identity

One service identity represents one workload or application security boundary.
It holds policy bindings and may have multiple independently managed
application credentials. Credentials authenticate the identity; they do not
contain or snapshot its grants.

Applications with different compromise boundaries use different identities,
even if maintained by the same person.

### Session and credential

A session or application credential is authentication context, not a
principal. Audit records reference both principal and credential so one leaked
credential can be identified and revoked without deleting the identity.

## Resources

- Vault administration domain.
- Namespace and its optionally included descendants.
- Exact secret.
- Exact secret version or history of a secret.
- Service identity and individual application credential.
- Policy and binding.
- Audit stream.
- Backup, restore, and key-maintenance operation.

Resources use opaque stable IDs internally. Human-readable names do not define
authorization identity and cannot change effective access through a rename.

## Actions

The v1 action vocabulary is explicit and closed:

- `namespace:list`, `namespace:create`, `namespace:update`, `namespace:delete`
- `secret:list`, `secret:metadata-read`, `secret:value-read`
- `secret:create`, `secret:update`, `secret:archive`, `secret:restore`
- `secret:history-read`, `secret:version-read`, `secret:purge`
- `identity:read`, `identity:manage`, `credential:issue`, `credential:revoke`
- `policy:read`, `policy:manage`, `effective-access:read`
- `audit:read`, `backup:create`, `backup:inspect`, `backup:restore`
- `key:rotate`, `vault:configure`, `vault:lock`

Phase implementation may split an action to prevent overbroad access but must
not combine distinct committed permissions merely for convenience.

### Service-grantable actions

V1 policies may grant service identities only the explicitly approved secret
and safe namespace-discovery subset: namespace/secret listing where required,
metadata read, value read, create, update, history/version read, archive, and
restore. Phase 2 may narrow this set further after abuse testing.

### Owner-only actions

Namespace creation/move/delete, secret purge, identity/credential management,
policy/effective-access administration, audit administration, backup/restore,
key rotation, vault configuration, and vault lock are owner-only. They are
still evaluated and audited at the central authorization boundary, but they
cannot appear in a service policy. Unknown or owner-only actions in a service
grant fail validation rather than being ignored.

## V1 grant model

A grant contains:

- One or more explicit actions from the closed vocabulary.
- One resource type and stable resource ID.
- For a namespace, an explicit `include_descendants` boolean.
- Creation actor and timestamp.

Policies are named collections of grants. Bindings attach policies to service
identities. V1 grants only allow; absence is denial. There are no glob paths,
regular expressions, user-authored code, explicit deny precedence, or
conditions based on attacker-controlled metadata.

The policy schema validates actions against the service-grantable allowlist.
This prevents even an authorized owner from accidentally turning a service
credential into a whole-vault backup, key-management, or policy-management
credential.

Credential expiration and revocation are authentication checks. They are not
policy conditions.

The implemented representation is an authenticated, monotonically revisioned
allow-only graph of policies, grants, and service bindings. Policy labels are
encrypted. Each graph item and the aggregate graph have keyed commitments;
archive, grant, bind, and namespace-move transactions advance the graph
revision atomically with audit. No authorization cache is used.

## Evaluation algorithm

1. Require an authenticated, active principal and credential/session context.
2. Resolve the requested resource to a stable ID without disclosing it to an
   unauthorized caller.
3. Reject credential revocation, expiration, disabled identity, or locked vault.
4. Apply operation safety requirements such as recent human authentication.
5. Load the principal's current policy bindings.
6. Allow only if an exact action grant matches the resource or an ancestor
   namespace grant explicitly includes descendants.
7. Emit one audit decision with the closed action, opaque target, outcome,
   principal/credential attribution, and request correlation. Denials caused
   by an absent target follow the same audited path as no-grant denials.

The only public plaintext-capable application entry point is a request-scoped
`AuthorizedVault`. Construction reacquires the current session or application
credential under a process authorization read gate. Credential revocation,
logout, policy changes, and access-affecting namespace moves take the write
gate. An operation already executing finishes under its prior decision;
revocation then commits and the next request must reauthenticate and
reauthorize. This synchronization is valid only for the committed one-process
v1 topology.

The domain returns only allow/deny plus internal decision metadata. It does not
return secret data or user-facing error text.

Move-impact preview is itself an `effective-access:read` decision. It verifies
the keyed state commitment of the moved namespace, the proposed parent, and
every ancestor used in the calculation before returning a delta; the eventual
move independently recalculates the same delta under the write gate.

## Existence confidentiality

An unauthorized caller should not learn whether an exact secret exists.
Resource lookup and permission evaluation therefore use uniform external
not-found behavior where practical. Write-only creation requires a client
chosen idempotency key and explicit create-only semantics; it must not reveal
whether a guessed secret name already exists through different error bodies or
obvious timing.

Listing is independently granted. Possession of `secret:value-read` for one
secret does not imply namespace listing. Metadata read is distinct from value
read because names and tags are protected information.

Perfect resistance to traffic analysis is not claimed. Negative tests compare
observable status, body shape, and coarse timing for common existence probes.

## Permission-management safety

- Only the owner may manage policies in v1.
- Policy editing requires recent authentication.
- UI and API show the exact effective-access delta before confirmation.
- A policy may not reference a deleted resource without making its tombstone
  state visible to the owner.
- Removing a binding takes effect on the next authorization evaluation.
- Caches, if added, have a bounded short lifetime and a monotonic policy
  revision that invalidates immediately after changes.
- Policy changes and audit events commit together.
- Moving a secret or namespace computes the effective-access delta caused by
  old and new ancestor grants. Any broadened access is shown explicitly,
  requires recent owner authentication, and is audited as a policy-impacting
  change even though exact-resource grants follow stable IDs.

## Credential lifecycle

1. Owner creates a service identity and grants only required access.
2. Owner issues a labeled credential with an explicit expiration or explicit
   acceptance of no expiration.
3. The secret portion is shown once; only its verifier is retained.
4. For rotation, issue a second credential, deploy it, observe successful use,
   then revoke the first.
5. Revocation immediately blocks new calls and is audited.
6. Attempted use of a known wrong-secret, revoked, expired, or backward-time
   credential is rate-limited and audited without treating the claimant as an
   authenticated actor or placing raw material in the event. Unknown random
   lookups remain uniform authentication failures and are not durable audit
   cardinality keys.

Credential values cannot be retrieved after issuance. "Reveal credential"
means create or rotate, never decrypt a stored token.

## Recent authentication

The following owner actions require a fresh phishing-resistant authentication
or another approved strong factor within a short configured window:

- Reveal or export secret values.
- Read historical values.
- Issue credentials or change policy.
- Create backup recovery material or restore a vault.
- Rotate root/KEK material or change key providers.
- Purge data or disable security controls.

The initial login time alone is insufficient for a long-lived session.

Phase 2 uses a five-minute recent-authentication window, 30-minute sliding idle
session expiry, and 12-hour absolute expiry. Session and CSRF tokens use
independent HMAC domains and only their verifiers are durable. High-risk owner
actions are rejected after the recent window even while the underlying session
remains valid.

## Required test matrix

For each action test: unauthenticated, expired credential, revoked credential,
disabled identity, no grant, exact grant, sibling resource, parent namespace
without descendants, ancestor with descendants, renamed/moved resource,
archived/deleted target, and policy changed during request. Tests assert both
the response and audit event.
