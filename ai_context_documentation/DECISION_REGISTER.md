# Decision register

Last reviewed: 2026-07-21

## Committed

| ID | Decision | Rationale |
|---|---|---|
| D-001 | SMCV is written in Rust and exposes a web UI and application API. | Owner requirement. |
| D-002 | SQLite on a local filesystem is the v1 source of truth. | Small operational footprint and expected single-node workload. |
| D-003 | V1 is a self-hosted, single-node modular monolith. | Keeps security and recovery understandable while preserving internal boundaries. |
| D-004 | Sensitive vault fields use application-level authenticated encryption and root key material is stored outside SQLite. | A stolen database must not be self-decrypting; rotation and portability need explicit key hierarchy. |
| D-005 | Authorization is deny-by-default with separate permissions for actions and exact resources or namespaces. | Limits compromised-credential blast radius. |
| D-006 | Secret updates create immutable versions. | Prevents silent loss and supports audit and recovery. |
| D-007 | Portable encrypted backup, verification, and restore are v1 product features available in UI and CLI. | Owner requires durable, easy recovery independent of the original machine. |
| D-008 | Portable backups use encryption independent from the destination vault key and never embed their decryption key. | Enables migration while preserving separation of key and ciphertext. |
| D-009 | Initial restore targets a new or empty vault; populated-vault merge is deferred. | Avoids unsafe, ambiguous conflict semantics in v1. |
| D-010 | V1 supports one human owner and multiple service identities. | Meets initial use without premature multi-user administration. |
| D-011 | The web product targets WCAG 2.2 AA and uses no production third-party executable assets. | Accessibility and reduced client-side supply-chain exposure. |
| D-012 | V1 development has no pilot, beta cohort, early-access, field-trial, adoption, or external-user-validation gate. | Owner requires uninterrupted start-to-finish development rather than staged market validation. |
| D-013 | Phases 0–6 may execute continuously under one long-running implementation goal. Phase gates are self-verified evidence checkpoints; a failed criterion creates repair and retest work inside the same goal rather than an approval pause. | Owner sign-off on 2026-07-21. |
| D-014 | Phase 6 completes with a production-ready release candidate, assurance report, recovery evidence, and external-review handoff package. Public deployment or publication is a separate owner action and is not an implementation completion gate. | Separates a complete product from external release authority. |
| D-015 | The owner accepts the residual risk of completing development without a prior independent external security review. External assurance occurs after the application is complete and may drive later iterations. | Explicit owner risk acceptance on 2026-07-21. |
| D-016 | Personal recovery-key custody testing occurs after complete development. Implementation still proves backup/restore and custody UX using synthetic material and automated clean-environment exercises. | Keeps personal key custody off the implementation critical path without weakening recovery engineering. |
| D-101 | Use a random 256-bit DEK per immutable secret version, wrapped by a versioned KEK. | Limits key/nonce scope and permits KEK rotation by rewrapping rather than re-encrypting values. Validated in Phase 0. |
| D-102 | Algorithm suite 1 uses XChaCha20-Poly1305 with fresh random 192-bit nonces, 128-bit tags, and fixed-width canonical AAD binding vault, installation, object type, object ID, and version. | Maintained RustCrypto construction, independently checked known-answer vector, and substitution/corruption failure tests. Validated in Phase 0. |
| D-103 | Encrypt human-readable secret metadata and use namespace-scoped HMAC-SHA-256 exact-match indexes with decrypted collision confirmation. | Phase 1 database/WAL sentinel scans, NFC/case/scope tests, and authenticated metadata format fixture passed. |
| D-107 | SQLite uses WAL, `synchronous=FULL`, foreign keys, bounded busy handling, trusted schema off, transactional checksummed migrations, and the online backup API. | Phase 0 recovery, rollback, configuration, checksum-drift, and snapshot tests validated the durability baseline. |

## Proposed: validate in Phase 0 or named phase

| ID | Proposal | Validation gate |
|---|---|---|
| D-104 | Use passkeys/WebAuthn as the preferred human authenticator with an Argon2id-protected password recovery or fallback path. | Phase 2 owner-flow and deployment review. |
| D-105 | Use opaque random application tokens with a public lookup prefix and a keyed verifier stored server-side; the domain-separated vault verifier key is portably reprotected during backup restore. | Phase 2 credential and Phase 3 portability review. |
| D-106 | Serve the UI and API from one origin and use server-side sessions in secure HTTP-only cookies. | Phase 2 and Phase 4 web threat review. |
| D-108 | Use chunked authenticated encryption for `.smcvault` payloads with a small authenticated public header. | Phase 3 format review and adversarial parser tests. |
| D-109 | Preserve imported application credential verifiers and their portable vault-scoped verifier key by default for disaster recovery; offer explicit revocation for migration. | Phase 3 UX and threat review. |
| D-110 | Preserve logical vault identity across disaster recovery while generating a new installation ID and recovery epoch. | Phase 3 clone, audit, and restore review. |

## Deferred

| ID | Item | Revisit trigger |
|---|---|---|
| D-201 | Multi-user and multi-tenant administration. | Validated demand and a new identity/recovery threat review. |
| D-202 | Active-active clustering or PostgreSQL. | Measured availability or write-concurrency requirement that SQLite cannot meet. |
| D-203 | Populated-vault merge import. | Approved deterministic conflict and audit semantics. |
| D-204 | Automatic third-party secret rotation and dynamic credentials. | Stable static-secret core and source-specific security designs. |
| D-205 | OIDC federation, SSH CA, PKI, agents, and browser extensions. | Separate chartered phases after v1. |
| D-206 | General policy language and explicit deny rules. | Allow-only policy model proves insufficient with representative cases. |

## Changing a decision

A change records the date, owner decision, impacted requirements, threat-model
delta, migration or compatibility effect, and the phase that will implement
it. Superseded entries remain visible rather than being silently rewritten.
