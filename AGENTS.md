# SMCV contributor instructions

This file governs work in this repository.

## Read before changing the project

Read, in order:

1. `README.md`
2. `ai_context_documentation/PROJECT_CHARTER.md`
3. `ai_context_documentation/PRODUCT_REQUIREMENTS.md`
4. `ai_context_documentation/DECISION_REGISTER.md`
5. `ai_context_documentation/THREAT_AND_TRUST_MODEL.md`
6. `ai_context_documentation/SYSTEM_ARCHITECTURE.md`
7. The active phase plan identified by `ai_phased_plans/README.md`

For security-sensitive changes, also read:

- `ai_context_documentation/CRYPTOGRAPHY_AND_KEY_MANAGEMENT.md`
- `ai_context_documentation/AUTHORIZATION_MODEL.md`
- `ai_context_documentation/BACKUP_AND_RECOVERY.md`
- `ai_context_documentation/SECURITY_ASSURANCE.md`

For user-facing changes, also read every document in
`ai_design_guidelines/`.

## Decision language

- **Committed** decisions are requirements. Do not contradict them without an
  explicit owner decision recorded in `DECISION_REGISTER.md`.
- **Proposed** decisions are the default direction but must be validated at the
  phase gate named in the decision.
- **Deferred** work is out of the current implementation scope.

Do not silently convert proposed or deferred items into committed scope.

## Non-negotiable security constraints

- Never commit real secrets, credentials, recovery keys, private production
  data, or plaintext vault backups.
- Never write plaintext secret values to logs, traces, metrics, panic messages,
  URLs, filenames, audit records, or temporary files.
- Do not invent cryptographic algorithms or protocols. Use reviewed primitives
  through maintained libraries and preserve algorithm agility in stored data.
- Keep root key material outside SQLite and outside portable backup files.
- Treat authorization as deny-by-default. Every protected operation must pass
  through the central policy boundary.
- Keep authentication, authorization, encryption, persistence, backup, and
  audit responsibilities explicit even within the modular monolith.
- API credentials are display-once, stored only as verifiers, independently
  revocable, expirable, and unable to increase their own authority.
- Secret updates create immutable versions. Never silently overwrite history.
- Backup import must authenticate and validate the complete input before
  committing effects, and must not partially replace a live vault.
- Do not claim protection against a fully compromised, unlocked host. Maintain
  the documented trust boundaries.
- Avoid unsafe Rust. Any required `unsafe` block needs a documented invariant,
  focused tests, and security review.

## Engineering posture

- Begin as a single-node, self-hosted Rust modular monolith with SQLite on a
  local filesystem.
- Prefer correctness, recoverability, and simple operation over speculative
  distributed-system complexity.
- Keep domain logic independent of HTTP, UI, SQLite, and concrete key-provider
  adapters.
- Use stable Rust, a committed lockfile, reproducible commands, and the
  smallest practical dependency set.
- Bound inputs, concurrency, memory use, and transaction duration.
- Make migrations forward-moving, transactional where SQLite permits, and
  tested from every supported prior schema.
- Use structured errors externally and preserve useful internal context without
  including sensitive material.

## Change workflow

- Work only within the active phase acceptance scope.
- Preserve unrelated user changes in a dirty worktree.
- Put optional or post-development owner actions in `human_tasks/`; never put
  credential values there and never use a human task as a Phase 0–6 gate.
- Do not create pilot, beta, early-access, external-user-validation, adoption,
  or owner-approval gates. Phases 0–6 are one continuous implementation goal.
- Treat phase gates as self-verified evidence checkpoints. If a criterion or
  review fails, keep the goal active, repair the defect, retest, and continue.
- Prefer local and synthetic substitutes over waiting for an external account,
  domain, certificate, KMS/HSM, signing identity, production infrastructure, or
  reviewer. Those items cannot block the v1 release candidate unless the owner
  explicitly changes D-012 through D-016.
- Record verification evidence in `ai_phase_evidence/` using its README.
- Update durable documentation when a decision, invariant, data format, threat,
  or operational behavior changes.
- Run formatting, linting, unit and integration tests, migration checks,
  dependency review, documentation link checks, and security checks relevant
  to the changed area.

## Definition of done

Code existence is insufficient. A phase or slice is complete only when:

- Its acceptance criteria and negative cases pass.
- Tests are proportional to security and recovery risk.
- Failure, restart, and rollback behavior has been exercised.
- Authorization denials and secret non-disclosure are verified.
- Backup or migration compatibility is demonstrated when applicable.
- Accessibility is checked for user-facing changes.
- Security-sensitive dependencies and `unsafe` usage are reviewed.
- Evidence and durable documentation match the delivered behavior.
- The phase-close evidence passes and the active phase pointer advances without
  requiring owner approval.
