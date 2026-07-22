# SMCV

SMCV (Secret Manager and Credentials Vault) is a security-first, self-hosted
vault written in Rust. It gives people a polished web interface for managing
encrypted secrets and gives applications narrowly scoped, revocable API
access to only the secrets and operations they require.

The project is under active implementation. The encrypted local vault core is
complete, but the server does not yet expose protected vault workflows and is
not production-ready.

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

The documentation foundation, [Phase 0 engineering
baseline](ai_phase_evidence/PHASE_0_EXIT_REPORT.md), and [Phase 1 encrypted
vault core](ai_phase_evidence/PHASE_1_EXIT_REPORT.md) passed their adversarial
evidence gates on 2026-07-21. [Phase 2 identity, authorization, and
API](ai_phased_plans/PHASE_02_IDENTITY_AUTHZ_API.md) is active. Run the complete
local verification gate with:

```sh
./scripts/check.sh
```

Phases 0–6 are designed to run continuously under one implementation goal.
There is no pilot, beta, external-user, adoption, owner-approval, or external
review gate. Failed checks create repair/retest work inside the same goal.
Phase 6 produces a production-ready release candidate and post-development
security-assurance handoff; public deployment and personal recovery-key custody
testing remain later owner-controlled activities.
