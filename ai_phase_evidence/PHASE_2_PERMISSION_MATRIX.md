# Phase 2 permission matrix

Date: 2026-07-21
Status: **Passed executable and source review**

The closed action set is defined once by `smcv_core::Action::ALL`. Unknown
spellings fail parsing. A service grant is accepted only when
`Action::is_service_grantable` returns true and descendant scope targets a
namespace. The core test `owner_only_actions_never_validate_for_service_grants`
iterates the complete set so a newly added owner-only action cannot silently
become service-grantable.

| Action | Owner | Service grant | Recent owner auth | Protected operation / evidence |
|---|---|---|---|---|
| `namespace:list` | Allow | Exact namespace; descendants only when explicit | No | Bounded namespace list; positive grant and empty-child result tested |
| `namespace:create` | Allow | Never | No | Idempotent create through `AuthorizedVault` and API |
| `namespace:update` | Allow | Never | On broadened move | Exact access-delta preview, stale confirmation rejection, confirmed move |
| `namespace:delete` | Allow | Never | No | Reserved closed action; no Phase 2 HTTP deletion route |
| `secret:list` | Allow | Exact namespace; descendants only when explicit | No | Bounded metadata-only list; positive separate grant tested |
| `secret:metadata-read` | Allow | Exact secret or inherited namespace | No | Exact/inherited allow and sibling denial tested |
| `secret:value-read` | Allow | Exact secret or inherited namespace | Yes | Explicit reveal, sibling denial, audit attribution tested |
| `secret:create` | Allow | Exact/inherited namespace | No | Pure write-only service creates and cannot reveal |
| `secret:update` | Allow | Exact secret or inherited namespace | No | Immutable append with current-version and revision preconditions |
| `secret:archive` | Allow | Exact secret or inherited namespace | No | Revisioned lifecycle endpoint |
| `secret:restore` | Allow | Exact secret or inherited namespace | No | Revisioned lifecycle endpoint |
| `secret:history-read` | Allow | Exact secret or inherited namespace | Yes | Bounded version metadata page; distinct denial tested |
| `secret:version-read` | Allow | Exact secret or inherited namespace | Yes | Exact immutable historical reveal; distinct denial and audit tested |
| `secret:purge` | Allow | Never | Yes | Internal retention/confirmation capability; never service-grantable |
| `identity:read` | Allow | Never | No | Owner service-identity and safe credential metadata reads |
| `identity:manage` | Allow | Never | Yes for Phase 2 mutations | Service identity and passkey administration |
| `credential:issue` | Allow | Never | Yes | Display-once issuance and verifier-only persistence |
| `credential:revoke` | Allow | Never | Yes | Revisioned revoke, concurrency gate, next request and restart denial |
| `policy:read` | Allow | Never | No | Owner policy metadata/state read |
| `policy:manage` | Allow | Never | Yes | Create, grant, bind, archive; graph revision invalidation |
| `effective-access:read` | Allow | Never | No | Closed effective action set for service/resource |
| `audit:read` | Allow | Never | No | Owner-only bounded audit page and chain verification |
| `backup:create` | Allow | Never | Yes | Closed owner-only action; implemented in Phase 3 |
| `backup:inspect` | Allow | Never | No | Closed owner-only action; implemented in Phase 3 |
| `backup:restore` | Allow | Never | Yes | Closed owner-only action; implemented in Phase 3 |
| `key:rotate` | Allow | Never | Yes | Closed owner-only action; local key service implemented, API deferred |
| `vault:configure` | Allow | Never | Yes | Owner due-state administration; never service-grantable |
| `vault:lock` | Allow | Never | Yes | Closed owner-only action; operational route deferred |

## Matrix observations

- Owner status does not bypass session activity, recent-authentication, audit,
  optimistic concurrency, retention, or confirmation checks.
- Metadata read, value read, list, history, version read, create, and update are
  independent service grants.
- Exact-secret grants do not reach sibling secrets. Namespace grants inherit
  only with `include_descendants=true`; moves recalculate the broadened
  service/action pairs before commit.
- Credential and policy records contain no embedded authority. Every protected
  request loads current credential/session state and the current authenticated
  policy graph.
- Reserved owner-only actions stay in the closed vocabulary before their later
  phase route exists so future adapters cannot invent an unreviewed spelling.
