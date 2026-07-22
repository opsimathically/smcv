# Adversarial review resolution log

Status: **Complete**
Last updated: 2026-07-21

| Finding | Resolution evidence | Status |
|---|---|---|
| SEC-AR-001 | Vault-scoped token-verifier key added to crypto, data, backup requirements, and Phase 3 preserve/revoke tests. | Closed |
| SEC-AR-002 | Local restore ceremony and destination RP-binding validation added to requirements, backup, flows, and phases. | Closed |
| SEC-AR-003 | Logical vault ID, installation ID, recovery epoch, audit segments, clone warning, and runbook requirements added. | Closed |
| SEC-AR-004 | Backup verification language now claims authenticated integrity under the key, not source-origin authenticity. | Closed |
| SEC-AR-005 | Restore is an initialization state machine with fresh provider material, verified unlock, and activation marker last. | Closed |
| SEC-AR-006 | Generated keys recommended; passphrase length/common-value policy and offline-guessing warning added. | Closed |
| SEC-AR-007 | Non-portable external password pepper prohibited in v1 unless the recovery promise explicitly changes. | Closed |
| SEC-AR-008 | Namespace moves compute access delta, require recent auth when broadening, and receive Phase 2 evidence. | Closed |
| SEC-AR-009 | Durable bounded jobs, restrictive opaque artifacts, quota, expiry, cleanup, and custody language added. | Closed |
| SEC-AR-010 | Recovery epochs added; external-anchor limitation retained in threat, audit, backup, and language. | Closed |
| SEC-AR-011 | Service-grantable action allowlist added; owner-only administration rejected by schema and tested. | Closed |
| OPS-AR-001 | Phase 3 owns backend/CLI/API; Phase 4 explicitly closes web backup requirements. | Closed |
| OPS-AR-002 | Local CLI/single-use local channel is the only fresh-host restore authority. | Closed |
| OPS-AR-003 | Portable vault semantics included; host/network/TLS/proxy/provider paths excluded and reported for setup. | Closed |
| OPS-AR-004 | Logical vault identity is preserved while installation identity and recovery epoch are renewed. | Closed |
| OPS-AR-005 | No silent history purge; capacity alerts and deterministic ephemeral cleanup added. | Closed |
| OPS-AR-006 | Phase 3 provisional recovery measurements feed Phase 5 supported RPO/RTO. | Closed |
| OPS-AR-007 | Durable job state, disconnect/cancellation semantics, artifact quota, expiry, and download status added. | Closed |
| OPS-AR-008 | Phase 1 initialization explicitly cannot claim the later first-backup owner journey. | Closed |
| OPS-AR-009 | Exact implementation technologies remain proposed for Phase 0 evidence. | Accepted |
| OPS-AR-010 | Small and representative large fixtures with time/memory/disk results added to Phase 3. | Closed |

Closure here means the planning defect is corrected. Implementation phases
must still prove the revised requirement with the evidence assigned in
`../../ai_phased_plans/REQUIREMENTS_TRACEABILITY.md`.
