# Phase 5 synthetic incident tabletops

Date: 2026-07-21
Data class: synthetic only
Result: **All required runbooks reached a deterministic containment and
recovery decision without an external account**

| Exercise | Inject | Actions exercised | Pass condition |
|---|---|---|---|
| T5-01 application token | One synthetic credential appears in an untrusted paste | Exact revoke, denied reuse, least-privilege replacement, readable-secret rotation list | Revoked verifier fails immediately and no broader policy is issued |
| T5-02 owner session | Browser session may have been copied | Ingress containment, session invalidation/restart, local owner recovery, audit review | No remote first-claim route and owner control is reestablished locally |
| T5-03 host/root compromise | Root access occurred while unlocked | Host isolation, clean restore, revoke-imported mode, upstream rotation plan | Old installation remains offline; new epoch and passkey reenrollment are explicit |
| T5-04 secret disclosure | Read-only application received one wrong secret | Credential/grant revoke, upstream rotate, immutable new version, notification owner | Current secret changes without rewriting historical evidence |
| T5-05 integrity failure | One encrypted field and one audit row are modified | Readiness failure, evidence preservation, isolated verified restore | No ad-hoc repair or claim that local chaining is tamper-proof |
| T5-06 disk/WAL failure | Storage fills during a write and WAL cannot checkpoint | Stop writes, preserve companions, use portable restore, run preflight | Transaction rolls back or vault stays unavailable; verified backup remains |
| T5-07 lost backup key | Newest archive key cannot be located | Test other key/archive pairs; create new pair only from healthy vault | No bypass exists; dual loss is declared unrecoverable |
| T5-08 stale restore | Only a pre-revocation backup is trusted | Drill, restore with imported credentials revoked, rotate, reconcile RPO window | Stale credential cannot authenticate on activated destination |
| T5-09 supply chain | SBOM names a newly vulnerable reachable crate | Stop distribution, verify provenance, triage reachability, rebuild/replace | Suspect artifact is not deployed and exact replacement evidence exists |

The disk-full rollback, corrupt database readiness, stale credential revoke,
wrong-key restore, interrupted activation, and artifact-verification mechanics
are automated in the Rust and operational suites. Notification and public
disclosure remain explicit owner decisions because the synthetic exercise has
no real affected party.
