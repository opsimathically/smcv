# SMCV implementation phases

Status: **Phase 1 active; Phase 0 passed**
Last reviewed: 2026-07-21

## Active phase

The active phase is [Phase 1: encrypted vault core](PHASE_01_CRYPTO_STORAGE.md).
[Phase 0](PHASE_00_FOUNDATIONS.md) passed its evidence gate on 2026-07-21.
Requirement ownership is tracked in the
[requirements traceability matrix](REQUIREMENTS_TRACEABILITY.md).

## Phase sequence

| Phase | Outcome | Depends on |
|---|---|---|
| 0 | Reviewed technical decisions, Rust workspace, secure engineering baseline, and executable architecture skeleton | Documentation readiness |
| 1 | Encrypted SQLite vault core, immutable versions, migrations, key lifecycle, and audit persistence | Phase 0 |
| 2 | Owner/service authentication, centralized authorization, and versioned API | Phase 1 |
| 3 | Portable encrypted backup, verification, clean restore, and recovery tooling | Phase 2 |
| 4 | Accessible polished web UI for all committed owner workflows | Phase 3 |
| 5 | Deployment, telemetry, upgrades, incident runbooks, and operational hardening | Phase 4 |
| 6 | Final internal adversarial assurance, release-candidate hardening, and post-development assurance handoff | Phase 5 |

Phases are sequential engineering checkpoints inside one continuous long-running
implementation goal, not approval pauses or release branches. Small vertical
slices inside a phase are preferred. Work from a later phase may be prototyped
only when it does not create unsupported public or persisted behavior.

## Gate rules

- Entry criteria are verified before phase work begins.
- Scope exclusions are binding unless the decision register changes.
- Every acceptance criterion receives evidence under `ai_phase_evidence/`.
- A critical/high security or recovery finding prevents a false phase-close
  claim but does not halt the goal: repair it, retest it, and continue.
- Persisted formats require compatibility fixtures before phase exit.
- A phase plan is updated when evidence changes the approach; the evidence is
  not rewritten to fit an obsolete plan.
- The implementing agent writes the phase-close report and advances the active
  phase pointer when evidence passes; no owner approval is required.

## Continuity and non-blocking policy

- No pilot, beta cohort, early-access program, field trial, adoption threshold,
  or external-user validation is part of v1 development.
- No external account, domain, public certificate, KMS/HSM, signing identity,
  production infrastructure, or reviewer is required when a local or synthetic
  substitute can prove the committed behavior.
- Test/review failures create repair work within the same active goal.
- External security assurance and the owner's personal recovery-custody test
  occur after Phase 6 and may create later improvement goals.
- Public publication and production deployment are owner-controlled actions
  outside the implementation completion gate.

Use [the phase template](PHASE_TEMPLATE.md) for later phases or substantial
replans.
