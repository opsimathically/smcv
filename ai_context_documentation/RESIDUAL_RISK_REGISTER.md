# Residual-risk register

Status: **Committed release-candidate register**
Last reviewed: 2026-07-21
Owner acceptance: D-015, recorded 2026-07-21

No unresolved critical or high internal assurance finding remains. The items
below are bounded residual risks, explicit trust-boundary conditions, or
post-development controls. D-015 accepts reaching the candidate before an
independent review; it does not waive later remediation.

| ID | Rating | Residual condition | Existing mitigation and required follow-up |
|---|---|---|---|
| RR-001 | Boundary | Root/kernel control, process inspection, or code execution as the unlocked service user can obtain plaintext. | Harden and patch the dedicated host, use the packaged sandbox, restrict administrative access, and treat host compromise as vault compromise requiring rotation. This is outside the confidentiality guarantee. |
| RR-002 | Medium | Local audit commitments cannot independently prove newest-history completeness against whole-database rollback or truncation. | Recovery epochs, segment commitments, backup times, clone warnings, and operator records expose many discontinuities. Add an external audit anchor only in a later explicitly designed feature. |
| RR-003 | Medium | Two restored installations can accept preserved application credentials and diverge. | Restore increments the epoch and warns; decommission the source and rotate/revoke credentials after uncertain recovery. Never operate concurrent clones. |
| RR-004 | Medium | A guessed archive passphrase permits offline attempts, and loss of separate recovery material makes a valid archive unrecoverable. | Prefer generated 256-bit backup keys, enforce Argon2id bounds and passphrase policy, maintain separate custody, and perform the owner's real custody exercise after development. |
| RR-005 | Medium | Successful local scheduled backup does not prove off-host custody; the 24-hour RPO depends on timer health and transfer practice. | Monitoring exposes failures, retention verifies before delete, and isolated drills prove local restorability. Operator must transfer and inventory verified archives off host. |
| RR-006 | Medium | Local provenance and hashes can detect corruption but do not authenticate an untrusted publication channel by themselves. | Reproducible bytes, SBOMs, internal/outer checksums, and optional detached signing are supplied. Establish official signing identity and trusted distribution before public release. |
| RR-007 | Medium | V1 is a single-node vault; host or disk outage makes it unavailable until repair or restore. | SQLite durability, bounded shutdown, verified backups, documented rollback, and a small-vault 15-minute RTO limit impact. Multi-node availability is deliberately deferred. |
| RR-008 | Low | Automated accessibility evidence did not assert Orca's spoken text because the available debug stream exposed no names. | Firefox's accessibility tree names, semantic DOM, keyboard flow, reflow, scale, forced-color, and active-Orca campaigns passed. Perform human spoken-output review after development if required for deployment. |
| RR-009 | Low | The supported binary is dynamically linked and the distribution matrix is narrow. | Candidate construction is locked to x86-64 GNU/Linux and documents glibc/systemd/filesystem assumptions. Reject unsupported hosts instead of implying support. |
| RR-010 | Low | Cryptographic and other dependencies may contain reviewed upstream `unsafe` even though project code forbids it. | Exact versions/features are locked, advisory/source/license checks pass, SBOMs inventory the graph, and security-critical dependencies are documented. Reassess advisories for every release. |

## Expiry and review

Revisit every item before public publication, after independent assurance, on
any trust-boundary or cryptographic change, and at every release. A newly found
critical/high defect becomes repair work and is not converted into acceptance
by this register.
