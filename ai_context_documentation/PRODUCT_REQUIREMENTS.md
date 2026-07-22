# Product requirements

Status: **Committed** unless a requirement says otherwise
Last reviewed: 2026-07-21

Requirement identifiers are durable. Tests, phase plans, and evidence should
refer to them rather than duplicating their meaning.

## Vault and secret lifecycle

- **VAULT-001:** The owner can initialize and unlock a vault without placing
  root key material in SQLite.
- **VAULT-002:** The owner can create, view, update, archive, restore, and
  intentionally purge a secret through supported workflows.
- **VAULT-003:** Every update creates an immutable secret version; concurrent
  writes cannot silently overwrite one another.
- **VAULT-004:** SMCV supports opaque text or bytes as the canonical secret
  payload while allowing UI templates for common credential shapes.
- **VAULT-005:** Secret value, display name, description, tags, usernames,
  private key material, and similarly sensitive content are encrypted at rest.
- **VAULT-006:** Every ciphertext records enough non-secret algorithm and key
  version metadata for safe migration and rotation.
- **VAULT-007:** Secret expiration and rotation-due metadata are visible and
  queryable without pretending SMCV has rotated an upstream credential.

## Identity, authentication, and authorization

- **AUTHN-001:** Human and application identities use separate authentication
  mechanisms and lifecycles.
- **AUTHN-002:** Human authentication supports a phishing-resistant method;
  any stored password verifier uses a memory-hard password hashing function.
- **AUTHN-003:** Browser sessions are server-controlled, expire by idle and
  absolute lifetime, rotate after privilege changes, and are never stored in
  browser local storage.
- **AUTHN-004:** Application credentials contain cryptographically random
  secret material, are displayed once, and are stored only as non-reversible
  verifiers.
- **AUTHN-005:** Application credentials can expire, rotate with overlap, be
  individually revoked, and expose safe last-use metadata.
- **AUTHN-006:** Recovery on a new installation uses a local, single-use owner
  recovery ceremony. Restored phishing-resistant authenticators are enabled
  only when their relying-party binding is valid for the destination.
- **AUTHZ-001:** Authorization is deny-by-default and evaluated for every
  protected action at a centralized domain boundary.
- **AUTHZ-002:** A service identity receives only explicit action grants over
  exact secrets or namespaces.
- **AUTHZ-003:** Read, list, create, update, delete, history access, policy
  management, and audit access are distinct permissions.
- **AUTHZ-004:** Write-only and read-only service identities are supported.
- **AUTHZ-005:** No credential can grant itself or its identity additional
  authority.
- **AUTHZ-006:** Revocation takes effect without waiting for a long-lived token
  to expire or for an unbounded authorization cache.
- **AUTHZ-007:** Moving a secret or namespace shows the before/after effective
  access; a move that broadens access requires recent owner authentication.
- **AUTHZ-008:** Backup, restore, key, vault configuration, identity, credential,
  policy, audit-administration, namespace-administration, and purge capabilities
  are owner-only in v1 and cannot be granted to service identities.

## API and web product

- **API-001:** SMCV exposes a versioned HTTPS JSON API with bounded request and
  response sizes, stable machine-readable errors, and request correlation IDs.
- **API-002:** Secrets, credentials, session identifiers, and recovery material
  never appear in URLs.
- **API-003:** Mutating operations support concurrency protection and safe retry
  semantics where retry is meaningful.
- **API-004:** Secret-bearing responses prohibit storage by shared or browser
  caches.
- **WEB-001:** The owner can perform the supported vault, identity, policy,
  audit, backup, and restore workflows through a polished web interface.
- **WEB-002:** Secret material is masked by default and fetched only after an
  explicit reveal action.
- **WEB-003:** High-risk actions require recent authentication and state their
  consequences before execution.
- **WEB-004:** The product meets WCAG 2.2 AA for supported owner workflows.
- **WEB-005:** Production pages contain no third-party analytics, remote fonts,
  advertising, or remotely hosted executable assets.

## Backup, restore, and portability

- **BACKUP-001:** The owner can create a portable encrypted `.smcvault` file
  through the web UI and CLI.
- **BACKUP-002:** A backup is protected by a separate passphrase-derived or
  randomly generated backup key; the decryption key is never embedded in the
  archive.
- **BACKUP-003:** A backup contains all portable durable vault state needed for
  disaster recovery, including encrypted secret history, policies, service
  identities, application credential verifiers and their portable vault-scoped
  verification key, portable vault semantics, and audit history.
- **BACKUP-004:** Active sessions, CSRF state, rate-limit counters, plaintext
  credentials, root keys, and other ephemeral or host-bound state are excluded.
- **BACKUP-005:** Backup creation and restore do not write plaintext secret
  content to temporary files.
- **BACKUP-006:** SMCV can inspect safe archive metadata and verify complete
  authenticated integrity under the supplied archive key, compatibility, and
  key correctness without changing a vault. It does not claim source-origin
  authenticity without a separate signature or external anchor.
- **BACKUP-007:** Restore into a new or empty vault is transactional: success is
  complete, and failure leaves no partially usable vault.
- **BACKUP-008:** Destructive replacement of a populated vault is not part of
  the first release. A later replacement workflow must create and verify a
  safety backup before changing the destination.
- **BACKUP-009:** Merge import between populated vaults is deferred until an
  identity, policy, version, audit, and conflict model is approved.
- **BACKUP-010:** Restored application verifiers and grants remain valid for
  disaster recovery, with an explicit option to revoke imported application
  credentials for migration scenarios.
- **BACKUP-011:** Automated CLI backup accepts protected key-provider input and
  never requires a passphrase in process arguments.
- **BACKUP-012:** The archive has a versioned, documented format with downgrade,
  truncation, reordering, corruption, and resource-exhaustion defenses.
- **BACKUP-013:** Fresh-host restore authority is established locally through
  the CLI or a CLI-created single-use local channel; no unauthenticated remote
  restore/bootstrap endpoint exists.
- **BACKUP-014:** Disaster recovery preserves the logical vault ID but creates a
  new installation ID and recovery epoch so restored history and future audit
  events cannot be mistaken for one continuous running instance.
- **BACKUP-015:** Server-side encrypted backup artifacts and restore staging
  data have restrictive permissions, quotas, explicit expiry/cleanup, and are
  never presented as the owner's off-host retained copy.

## Audit and observability

- **AUDIT-001:** Authentication, authorization decisions, secret lifecycle,
  reveal, policy, credential, key, backup, restore, and administrative events
  are audited.
- **AUDIT-002:** Audit events never contain secret values, raw credentials,
  session IDs, root keys, recovery keys, or sensitive request bodies.
- **AUDIT-003:** Audit records contain actor, credential reference when
  applicable, action, target identifier, decision, time, request ID, and safe
  source context.
- **AUDIT-004:** Local audit tampering is detectable within documented limits;
  the product does not describe local hash chaining as tamper-proof.
- **OBS-001:** Health, metrics, logs, and traces reveal no protected values or
  sensitive labels and distinguish readiness from liveness.

## Operation and assurance

- **OPS-001:** The supported v1 deployment is a single SMCV instance using
  SQLite on a local filesystem under a dedicated operating-system identity.
- **OPS-002:** Plain HTTP is limited to an explicit loopback development mode;
  production API traffic requires TLS.
- **OPS-003:** Startup fails closed on missing key material, unsafe file
  permissions where detectable, unsupported schema, or invalid security
  configuration.
- **OPS-004:** Operators have documented procedures for initialization, key
  custody, backup, restore, upgrade, rollback, credential compromise, and
  database corruption.
- **OPS-005:** Database migrations and backup-format readers are compatibility
  tested across every supported upgrade path.
- **OPS-006:** V1 never silently purges secret versions or audit history;
  operators receive capacity limits, disk warnings, and explicit retention or
  purge behavior.
- **SEC-001:** Security-sensitive code has negative tests, permission-matrix
  tests, malformed-input tests, and failure-injection tests proportional to
  risk.
- **SEC-002:** Dependencies are locked, reviewed, vulnerability-scanned, and
  represented in a release SBOM.
- **SEC-003:** Release artifacts and their provenance can be verified.
- **SEC-004:** Development completion requires a final internal adversarial
  assurance report and documented residual risks. The owner's 2026-07-21 risk
  acceptance satisfies the independent-review precondition for the initial
  production-ready release candidate; external assurance follows development.

## Delivery continuity

- **DELIVERY-001:** No pilot, beta cohort, early-access, field-trial, adoption,
  or external-user-validation program is required to complete v1 development.
- **DELIVERY-002:** Phases 0–6 can execute under one continuous goal without
  owner approval between phases; phase evidence is sufficient to advance.
- **DELIVERY-003:** A failed acceptance, security, accessibility, compatibility,
  or recovery check creates repair/retest work within the active goal and does
  not terminate or pause development for permission.
- **DELIVERY-004:** External accounts, domains, public certificates, KMS/HSM,
  signing identities, production infrastructure, and external reviewers are not
  prerequisites for a production-ready release candidate when local or
  synthetic substitutes can prove the requirement.
- **DELIVERY-005:** Personal recovery-custody testing, independent external
  security assurance, public publication, and production deployment are
  post-development owner activities and do not block Phase 6 completion.

## Performance requirements

- **PERF-001:** Performance targets are established from representative
  benchmarks during implementation rather than weakening durability or
  security for speculative throughput.
- **PERF-002:** Authentication work factors are calibrated on supported
  hardware and bounded to prevent trivial denial of service.
- **PERF-003:** Backup and import use bounded streaming or bounded-size records
  and publish progress without exposing record contents.
