# Final internal assurance review

Status: **Complete; all high and medium findings closed**
Date: 2026-07-21
Scope: full 0.1.0 candidate as attacker, owner, operator, integrator, recovery
custodian, accessibility reviewer, and release consumer

## Fresh-review method

The review began from the threat boundaries and release claims rather than the
phase completion summaries. It traced every plaintext-capable path, every
authority-bearing credential, the central policy boundary, SQLite/keys through
backup and restore, browser state, production configuration, telemetry,
shutdown, upgrade/rollback, dependency provenance, and tar extraction. It then
sampled every requirements group back to executable failure evidence and ran
the candidate only from packaged binaries against separately held synthetic
recovery material.

The review also searched workspace code for unsafe blocks, panic-prone lint
exceptions, unresolved markers, secrets, unsupported release assumptions, and
claims stronger than the implementation. No production data or real custody
material was used.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P6-REC-001 | High | The first release-candidate rollback harness copied only `vault.sqlite` and assumed clean shutdown eliminated every SQLite companion file. That made the assurance procedure weaker than the documented stopped-directory snapshot rule. | The harness now copies the complete stopped data and provider directory contents. It mutates after the checkpoint, boots the snapshot, logs in, and proves the old value—not the post-checkpoint value—is present. |
| P6-REL-001 | High | The Phase 5 artifact omitted `Cargo.lock`, the API contract, complete assurance evidence, and the promised external-review package, forcing a reviewer to reconstruct source context. | The candidate now includes the lock/toolchain/policy, API, design/context/phase/evidence/operations trees, reviewer index, and verification/reproduction scripts. The verifier requires the key handoff files. |
| P6-PLAT-001 | High | Release construction used the build host triple in the filename but did not reject an undeclared platform, so a seemingly official candidate could be emitted outside the tested support matrix. | Construction now accepts exactly `x86_64-unknown-linux-gnu`; supported glibc/systemd/filesystem/browser assumptions and exclusions are frozen in the candidate. |
| P6-FUZ-001 | Medium | Archive framing had property campaigns, but the encoded credential and decrypted metadata parsers named by the assurance baseline lacked arbitrary-input regression campaigns. | Added bounded Proptest campaigns over arbitrary byte sequences for application/session/CSRF credential paths and metadata envelopes. Both return safe results without panic and run in the repository gate. |
| P6-SBOM-001 | Medium | The artifact verifier structurally inspected only the CLI/server SBOMs even though checksums covered all seven. A malformed internal-library SBOM could pass structural verification. | Verification now validates CycloneDX structure and nonempty components for every workspace crate and continues to hash every artifact file. |
| P6-TRUST-001 | Medium | The threat table said “signed provenance,” while the actual candidate intentionally provides unsigned local provenance and only optional detached signing; proxy text also suggested a trusted-proxy mode that production rejects. | Claims now distinguish checksums/local provenance/optional publication signing and state that v1 rejects forwarded-client trust. Release notes and the residual register carry the same boundary. |
| P6-ACC-001 | Medium | The screen-reader harness passed its `SMCV_SCREEN_READER` control flag through to the server. Phase 5's closed production schema then correctly rejected the unknown variable, preventing the final accessibility rerun; an unbounded WebDriver cleanup request could also hang after evidence was written. | The harness removes its own control variable from the server environment and bounds every WebDriver call. Both ordinary and active-Orca browser campaigns run through the hardened configuration. |
| P6-HAR-001 | Medium | The first dirty-envelope artifact exercise inherited `SMCV_ALLOW_DIRTY_VERIFY` into its packaged server, whose closed schema correctly refused to start. Ambient test controls could therefore perturb the assurance target. | Candidate development and production server launches now use an explicit empty environment plus `PATH` and the exact declared SMCV keys. Dirty-envelope and clean-boundary modes exercise identical server configuration. |

No critical finding was identified. All three high and five medium findings are
corrected and retested; no unresolved critical/high internal finding remains.

## Required abuse-case disposition

| Threat-model case | Final evidence/result |
|---|---|
| 1. Read-only identity attempts writes/history/policy/cross-namespace access | Phase 2 generated permission matrix, exact/sibling/near-miss policy test, and uniform API denial pass. |
| 2. Write-only identity attempts existence inference | Pure writer creates but cannot reveal; denied existing/absent resources share status/body contract; bounded timing remains a coarse-network limitation, not an identity oracle claim. |
| 3. Revoked credential reuse | Concurrent use/revoke is linearized; next use and restart fail. Policy archival invalidates the next request without a cache window. |
| 4. Cross-origin owner mutation | Host-only secure SameSite cookie, CSRF token, Origin policy, and CSP tests reject the request; state change requires current session plus CSRF. |
| 5. Control/markup/log-delimiter secret propagation | Redacted secret types, route-template-only tracing, no body/header/user labels, repository/SQLite/WAL/telemetry/release sentinel scans pass. |
| 6. Envelope component substitution | Exhaustive record component/context substitution, state commitment, audit commitment, corruption, and wrong-key tests fail closed without plaintext. |
| 7. Hostile archive mutations/costs | Bounds-before-KDF, arbitrary inputs, corruption/truncation/extension/reorder/duplicate/downgrade/count/digest/EOF tests fail before activation. |
| 8. Interrupted import and disk exhaustion | Pre-decode failures create no destination; every post-creation point remains under the durable activation guard; wrong activation and generic restart fail; import/activation transactions are atomic; injected disk-full/short writes roll back or clean partial output. |
| 9. Stale backup restores revoked access | Preserve behavior is explicit; revoke mode invalidates all imported application credentials before activation; UI/CLI warn and the incident guide requires rotation after uncertain recovery. |
| 10. Secret enumeration | Existing/absent denial responses are identical; list/read grants are independent; peer throttling and synthetic-verifier work bound unauthenticated probing. |
| 11. Secret in nominal metadata | Metadata is bounded/encrypted, telemetry uses opaque/fixed fields, raw URI/body/header/user-agent values are absent, and sentinel scans pass. |
| 12. Interrupted key rotation | Restart campaign traverses mixed KEK versions, resumes checkpointed batches, verifies source inventory zero, and retains the old root file until explicit custody action. |
| 13. Concurrent restored clones | Recovery epoch and installation ID change, credentials have explicit preserve/revoke modes, clone warnings require decommission/rotation, and RR-003 states the lack of an external freshness oracle. |

## Cross-domain conclusions

- Security/privacy: protected values remain limited to explicit in-memory/API/UI
  reveal paths. Release and observability artifacts contain no detected
  sentinel. Trust exclusions and metadata leakage are stated without claiming
  host-compromise protection.
- Recovery/operations: packaged binaries prove production preflight, rollback
  window, isolated drill cleanup, simulated total loss, owner login, and value
  recovery. Local backup success still cannot prove off-host custody.
- Accessibility: critical workflows retain the Phase 4 WCAG evidence. Spoken
  Orca output was not asserted and is carried as RR-008, not silently passed.
- Supply chain: locked graph, advisories, licenses/sources, seven SBOMs,
  reproducible bytes, checksums, and local provenance pass. The build is not
  described as hermetic or externally attested.
- Delivery: no pilot, external account/reviewer, real custody ceremony, signing
  identity, domain/certificate, publication, or production deployment entered
  the completion path.

Independent security assurance remains the explicit post-development task in
`human_tasks/HT-001-independent-security-assurance.md`.
