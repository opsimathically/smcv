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
| D-017 | The declared MSRV is Rust 1.88; the reproducible development toolchain remains Rust 1.94.0. | Phase 2 selected patched `time 0.3.47` for the WebAuthn certificate stack rather than accept RUSTSEC-2026-0009 under the former Rust 1.85 floor. |
| D-101 | Use a random 256-bit DEK per immutable secret version, wrapped by a versioned KEK. | Limits key/nonce scope and permits KEK rotation by rewrapping rather than re-encrypting values. Validated in Phase 0. |
| D-102 | Algorithm suite 1 uses XChaCha20-Poly1305 with fresh random 192-bit nonces, 128-bit tags, and fixed-width canonical AAD binding vault, installation, object type, object ID, and version. | Maintained RustCrypto construction, independently checked known-answer vector, and substitution/corruption failure tests. Validated in Phase 0. |
| D-103 | Encrypt human-readable secret metadata and use namespace-scoped HMAC-SHA-256 exact-match indexes with decrypted collision confirmation. | Phase 1 database/WAL sentinel scans, NFC/case/scope tests, and authenticated metadata format fixture passed. |
| D-104 | Use passkeys/WebAuthn with required user verification as the preferred owner authenticator, with an Argon2id password fallback. | Phase 2 pins the exact RP ID/origin, keeps one-use ceremony state server-side, bounds pending ceremonies, and uses a 64 MiB, three-iteration Argon2id verifier. |
| D-105 | Use opaque random application credentials with a public lookup component and keyed verifier stored server-side. | Phase 2 proves display-once issuance, verifier-only persistence, independent expiry/revocation/last-use state, concurrent next-request revocation, and restart persistence. |
| D-106 | Serve UI and API from one origin with server-side owner sessions in secure HTTP-only cookies and session-bound CSRF tokens. | Phase 2 enforces `__Host-`, Secure, HttpOnly, SameSite=Strict, CSRF on state changes, idle/absolute expiry, recent authentication, and logout revocation. |
| D-107 | SQLite uses WAL, `synchronous=FULL`, foreign keys, bounded busy handling, trusted schema off, transactional checksummed migrations, and the online backup API. | Phase 0 recovery, rollback, configuration, checksum-drift, and snapshot tests validated the durability baseline. |
| D-108 | `.smcvault` v1 uses a bounded public header, a random wrapped archive DEK, ordered XChaCha20-Poly1305 frames, and an authenticated final logical-stream commitment. | Phase 3 parser properties and wrong-key, corruption, prefix, extension, duplicate, reorder, and downgrade tests fail closed; the byte format is published. |
| D-109 | Preserve imported application credential verifiers and their portable vault-scoped verifier key by default for disaster recovery; offer explicit revocation for migration. | Phase 3 clean-host tests prove preserved credentials authenticate and revoke mode invalidates them before activation without exporting raw tokens. |
| D-110 | Preserve logical vault identity across disaster recovery while generating a new installation ID and incremented recovery epoch. | Phase 3 restore re-encrypts destination-bound envelopes, begins a new audit segment, and exposes the clone/decommission warning. |
| D-111 | Ship the owner UI as embedded, no-build, same-origin semantic HTML/CSS/ES modules with no third-party runtime assets or browser persistence. | Phase 4 keeps the Rust API as the authority boundary, permits a strict nonce-free CSP, and reduces client supply-chain and secret-retention surface. |
| D-112 | Fresh-host browser recovery exists only as a CLI-minted, loopback-only, ten-minute, single-use channel. The CLI displays a clean URL plus a separate body-submitted authorization code; the process retains only code/session digests. | Phase 4 provides accessible local recovery without putting authority in a URL or introducing a remotely claimable empty-vault bootstrap endpoint. |
| D-113 | Support x86-64 Linux/systemd on local ext4 or XFS for v1; production product and metrics listeners remain loopback behind a same-host TLS proxy that clears forwarding headers. | Phase 5 can fail closed on direct plaintext exposure and avoids trusting client-supplied proxy identity while retaining a small reproducible deployment surface. |
| D-114 | Scheduled retention always creates and fully verifies a new archive before deleting only older verified copies; the new copy is ineligible for the deletion set and unverifiable files cause an alerting failure. | Phase 5 makes daily backup automation retry-safe and prevents timestamp ties, wrong keys, or corrupt files from deleting the last demonstrated recovery copy. |
| D-115 | Release bundles require a clean tree by default and contain per-crate CycloneDX SBOMs, internal/outer SHA-256 checksums, deterministic local provenance, and optional detached local test signatures. | Phase 5 makes the release candidate independently inspectable without pretending local provenance or test signing is an external publication identity. |

## Proposed: validate in Phase 0 or named phase

No implementation decisions are currently awaiting validation.

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
