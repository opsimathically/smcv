# SMCV contributor instructions

This file governs work in this repository.

## Read before changing the project

Start with:

1. `README.md`
2. `ai_context_documentation/PROJECT_CHARTER.md`
3. `ai_context_documentation/SYSTEM_ARCHITECTURE.md`
4. `ai_context_documentation/THREAT_AND_TRUST_MODEL.md`
5. The active phase plan in `ai_phased_plans/`

For user-facing changes, also read:

- `ai_design_guidelines/PRODUCT_DESIGN_SYSTEM.md`
- `ai_design_guidelines/CONTENT_AND_TRUST_LANGUAGE.md`
- `ai_design_guidelines/ACCESSIBILITY.md`
- `ai_design_guidelines/CRITICAL_USER_FLOWS.md`

## Non-negotiable product constraints

- Never commit or log plaintext secrets, credentials, session material, root
  keys, archive keys, real recovery material, or production vault data.
- Keep root-provider material separate from the SQLite vault database.
- Preserve immutable secret versions and audit history. Never silently replace
  history with a newer value or lifecycle state.
- Route every protected operation through authentication, explicit
  authorization, bounded input handling, and safe audit semantics.
- Owner-only actions must never become service-policy grant actions.
- Treat archive creation, full verification, download, off-host custody,
  restore testing, and activation as distinct states.
- Fresh-host browser recovery must originate from explicit local CLI authority;
  never add a remotely claimable empty-vault bootstrap route.
- Never place secret or recovery material in URLs, browser storage, telemetry,
  filenames, process arguments, or unredacted errors.
- Production browser assets must be same-origin and self-contained, with no
  third-party executable assets, analytics, remote fonts, or service worker.

## Engineering posture

- The implementation language is Rust; use the workspace MSRV and pinned
  dependency policy documented in the decision register.
- Begin and remain a single-node modular monolith unless a later committed
  decision changes that boundary.
- SQLite is the v1 source of truth; application-level authenticated encryption
  protects sensitive records before persistence.
- Keep identity/session, authorization, vault, backup/recovery, audit,
  persistence, HTTP, web, and local CLI recovery responsibilities explicit.
- All mutations use concurrency preconditions or idempotency where retry could
  otherwise duplicate or overwrite effects.
- Bound attacker-controlled work before expensive password, KDF, archive,
  allocation, database, or WebAuthn processing.
- Avoid distributed-system complexity until a measured requirement and a
  committed architecture change warrant it.

## Change workflow

- Work from the current phase plan and keep changes within its acceptance
  scope while continuing automatically across non-blocking phase boundaries.
- Use `human_tasks/` only for an account, key, external authority, policy
  decision, or owner action that cannot safely be performed with synthetic
  material.
- Add reproducible phase evidence to `ai_phase_evidence/` and never include
  real protected material in it.
- Update durable context and the decision register when product intent,
  security boundaries, architecture, or compatibility behavior changes.
- Preserve unrelated user changes in a dirty worktree.
- Run formatting, strict linting, tests, documentation checks, dependency
  policy checks, secret scans, and relevant browser checks before declaring a
  phase complete.
- Make local commits at completed phase boundaries; do not push unless the
  owner explicitly requests it.

## Definition of done

A phase or slice is not complete merely because code exists. Completion needs:

- Acceptance criteria satisfied and requirement coverage recorded.
- Automated tests proportional to risk, including negative and interruption
  behavior.
- Operational behavior observed, including retry, restart, cleanup, and
  recovery paths.
- Plaintext/ciphertext, authorization, browser storage/DOM/cache, and audit
  invariants demonstrated with synthetic records.
- Accessibility checks for every supported user-facing workflow.
- Security, dependency, and secret-handling review with adversarial findings
  resolved or explicitly accepted under the project rules.
- Evidence recorded according to `ai_phase_evidence/README.md`.
- Documentation updated to match delivered behavior.

## Documentation conventions

- State whether a choice is **committed**, **proposed**, or **deferred**.
- Use calendar dates for time-sensitive reviews.
- Use the exact trust-language distinctions in
  `ai_design_guidelines/CONTENT_AND_TRUST_LANGUAGE.md`.
- Never call a backup successful before post-write verification, and never
  imply that current-vault purge erases prior backups or storage remnants.
- Keep human task status and credential metadata current, but never include a
  credential or recovery value.
