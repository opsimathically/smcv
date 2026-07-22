# SMCV

SMCV (Secret Manager and Credentials Vault) is a security-first, self-hosted
vault written in Rust. It gives people a polished web interface for managing
encrypted secrets and gives applications narrowly scoped, revocable API
access to only the secrets and operations they require.

The project is currently in documentation and implementation-planning. No
production implementation exists yet.

## Committed product direction

- Rust implementation with a web UI and versioned application API.
- SQLite as the initial single-node source of truth.
- Application-level authenticated encryption for sensitive vault data.
- Root encryption material stored separately from the database.
- Deny-by-default, fine-grained permissions for application identities.
- Immutable secret versions, lifecycle controls, and security auditing.
- Easy creation, verification, and restoration of portable encrypted vault
  backup files.
- Accessible, calm, and trustworthy product design.

## Documentation

- [Project documentation index](ai_context_documentation/README.md)
- [Project charter](ai_context_documentation/PROJECT_CHARTER.md)
- [Product requirements](ai_context_documentation/PRODUCT_REQUIREMENTS.md)
- [System architecture](ai_context_documentation/SYSTEM_ARCHITECTURE.md)
- [Threat and trust model](ai_context_documentation/THREAT_AND_TRUST_MODEL.md)
- [Design guidelines](ai_design_guidelines/README.md)
- [Implementation phases](ai_phased_plans/README.md)
- [Human task workflow](human_tasks/README.md)

## Current status

The documentation foundation was completed and adversarially reviewed on
2026-07-21. The project is ready to begin
[Phase 0](ai_phased_plans/PHASE_00_FOUNDATIONS.md); implementation has not yet
started. See the
[implementation-readiness index](ai_phased_plans/IMPLEMENTATION_READINESS.md)
and [documentation evidence](ai_phase_evidence/DOCUMENTATION_FOUNDATION.md).

Phases 0–6 are designed to run continuously under one implementation goal.
There is no pilot, beta, external-user, adoption, owner-approval, or external
review gate. Failed checks create repair/retest work inside the same goal.
Phase 6 produces a production-ready release candidate and post-development
security-assurance handoff; public deployment and personal recovery-key custody
testing remain later owner-controlled activities.
