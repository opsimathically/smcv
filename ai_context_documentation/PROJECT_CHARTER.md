# Project charter

Status: **Committed**
Last reviewed: 2026-07-21

## Mission

SMCV will make it straightforward for a person to control sensitive
credentials while allowing their applications to retrieve or update only the
specific secrets they need. It will combine strong default security with a
small operational footprint and an interface that makes authority, exposure,
rotation, backup, and recovery understandable.

## Product promise

If an operator retains a valid portable backup and its separate backup
passphrase or recovery key, they can restore the vault on a fresh compatible
SMCV installation without the original machine. If an application credential
is compromised, its blast radius is limited to its explicitly granted actions
and resources, and it can be revoked without rotating unrelated credentials.

## Primary users

1. **Owner/operator:** installs SMCV, unlocks and administers the vault,
   manages policies, examines audit history, and performs recovery.
2. **Application developer:** creates service identities and integrates
   applications through a stable API.
3. **Application workload:** authenticates non-interactively and performs only
   its granted secret operations.

The first release serves one administrative owner and multiple service
identities. The internal model may allow later human-user expansion without
making multi-user administration a v1 requirement.

## Product principles

1. **Least authority is visible.** Effective access must be inspectable before
   it is granted and after it is used.
2. **Ciphertext and keys are separated.** A database or backup file alone is
   insufficient to recover secrets.
3. **History is not silently rewritten.** Secret values, permissions, and
   security events retain meaningful version or audit history.
4. **Recovery is a product feature.** Backup verification and restore drills
   are designed and tested, not left to filesystem folklore.
5. **Safe behavior is the easy behavior.** Secure defaults require fewer steps
   than insecure exceptions.
6. **Claims match trust boundaries.** Documentation and UI never imply that
   encryption at rest defeats a fully compromised unlocked host.
7. **Simple deployment wins first.** SQLite and a modular monolith are retained
   until measured needs justify additional operational complexity.
8. **Performance is measured.** Optimization must not weaken cryptography,
   durability, isolation, or clarity.

## Success indicators

- An owner can initialize a vault, store a secret, grant an application
  read-only access, observe the access, revoke it, and confirm denial.
- Write-only, read-only, and narrowly scoped identities behave correctly under
  both normal and adversarial tests.
- A backup can be created, verified, moved to a clean installation, restored,
  and compared with the source without plaintext intermediate files.
- Loss of a database file alone does not disclose protected fields.
- Security-sensitive actions are understandable and accessible in the web UI.
- A new operator can deploy, back up, upgrade, diagnose, and restore SMCV from
  maintained documentation.

## Non-goals for the first release

- A multi-tenant hosted secrets platform.
- Distributed consensus, active-active clustering, or network-filesystem
  SQLite.
- A general-purpose identity provider.
- Dynamic database account issuance, SSH certificate authority, or full PKI.
- Automatic rotation connectors for third-party services.
- A general policy programming language.
- Protection after arbitrary code execution as the SMCV operating-system user
  or administrative control of an unlocked host.

## Governance

Product-owner decisions are recorded in `DECISION_REGISTER.md`. Implementation
may refine proposed mechanisms but cannot weaken committed outcomes without an
explicit decision and a threat-model update.

## Continuous implementation policy

Phases 0–6 are one continuous implementation path. They do not require a pilot,
beta cohort, early-access program, external user feedback, adoption threshold,
external service account, domain, public certificate, reviewer appointment, or
owner approval between phases. Local and synthetic substitutes are used when an
external integration is unnecessary to prove the product.

Entry and exit gates are engineering evidence checkpoints. When a test,
security review, accessibility check, recovery exercise, or acceptance
criterion fails, the active goal remains active: correct the defect, update the
plan if needed, rerun the evidence, and continue. A gate is not a permission
pause.

Development concludes with a production-ready release candidate and a package
for post-development external assurance. The owner accepted on 2026-07-21 the
residual risk of reaching that point before independent external security
review. Public deployment, external review, and personal recovery-key custody
testing occur afterward and may generate later iterations.
