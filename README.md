# SMCV

SMCV (Secret Manager and Credentials Vault) is a security-first, self-hosted
vault written in Rust. It gives people a polished web interface for managing
encrypted secrets and gives applications narrowly scoped, revocable API
access to only the secrets and operations they require.

Development of the local SMCV 0.1.0 release candidate is complete. The
encrypted vault core, authenticated `/api/v1` surface, portable backup/recovery
tooling, owner web interface, Linux operational packaging, and final integrated
assurance have passed their internal evidence gates. Public publication,
production deployment, independent assurance, and the owner's real custody
exercise remain post-development activities.

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
- [Linux deployment guide](docs/operations/DEPLOYMENT.md)
- [Backup operations](docs/operations/BACKUP_AND_RECOVERY_OPERATIONS.md)
- [Upgrade and rollback](docs/operations/UPGRADE_AND_ROLLBACK.md)
- [Incident runbooks](docs/operations/INCIDENT_RUNBOOKS.md)
- [Supported platform](docs/SUPPORTED_PLATFORMS.md)
- [Release notes](docs/RELEASE_NOTES_0.1.0.md)
- [External-assurance handoff](external_assurance/README.md)

## Current status

The documentation foundation, [Phase 0 engineering
baseline](ai_phase_evidence/PHASE_0_EXIT_REPORT.md), [Phase 1 encrypted vault
core](ai_phase_evidence/PHASE_1_EXIT_REPORT.md), [Phase 2 authenticated
API](ai_phase_evidence/PHASE_2_EXIT_REPORT.md), [Phase 3 portable backup and
recovery](ai_phase_evidence/PHASE_3_EXIT_REPORT.md), and [Phase 4 web product
and accessibility](ai_phase_evidence/PHASE_4_EXIT_REPORT.md), and [Phase 5
operational hardening](ai_phase_evidence/PHASE_5_EXIT_REPORT.md), and [Phase 6
release readiness](ai_phase_evidence/PHASE_6_EXIT_REPORT.md) passed their
adversarial evidence gates on 2026-07-21. Run the complete repository gate with:

```sh
./scripts/check.sh
```

The clean candidate boundary additionally runs `./scripts/final-release-gate.sh`.

Phases 0–6 are designed to run continuously under one implementation goal.
There is no pilot, beta, external-user, adoption, owner-approval, or external
review gate. Failed checks create repair/retest work inside the same goal.
Phase 6 produced a production-ready local release candidate and
post-development security-assurance handoff; public deployment and personal
recovery-key custody testing remain later owner-controlled activities.
