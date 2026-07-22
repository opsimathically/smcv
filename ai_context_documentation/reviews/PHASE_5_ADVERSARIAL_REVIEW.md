# Phase 5 operational hardening adversarial review

Status: **Complete; all high findings closed**
Date: 2026-07-21
Scope: production preflight, Linux/systemd packaging, telemetry, scheduled
backup, restore drills, upgrades, incident response, and release artifacts

## Review method

The review followed a clean synthetic installation through production preflight,
live operation, bounded load, structured logs, metrics, SIGTERM, scheduled
backup retention, isolated restore, release construction, SBOM/checksum/
provenance verification, and optional local signing. It separately challenged
filesystem modes and ownership, direct binding, unknown settings/arguments,
proxy trust, equal timestamps, corrupt backup inventories, dirty source trees,
nondeterministic SBOM fields, tar traversal, and archive links.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P5-RET-001 | High | Retention originally sorted all verified files by modification time and path. When timestamps tied, the newly created archive could sort among old files and be selected for deletion, violating create-verify-before-delete safety. | The new archive is now explicitly removed from the deletion candidate set. Only older verified files can satisfy the bounded removal count. The test confirms the returned new archive ID still exists after retention. |
| P5-NET-001 | High | A `SMCV_PROTECTED_TRANSPORT=1` assertion allowed a production listener on a non-loopback address even though SMCV does not terminate TLS itself; a mistaken deployment could expose plaintext directly. | The supported v1 production listener is unconditionally loopback-only behind the same-host TLS proxy. Preflight rejects non-loopback product/metrics binds and any trusted-forwarding-header mode. |
| P5-SC-001 | High | Release provenance named the current commit without recording that uncommitted or untracked source could have changed the binaries. | Normal release construction now refuses a dirty tree. Explicit envelope testing marks `working_tree_dirty=true`, and normal verification rejects that artifact. Clean boundary builds are required for the release candidate. |
| P5-REL-001 | High | The first release verifier checked obvious `../` names but did not reject every absolute member or symlink/hardlink that could redirect extraction. | Verification walks every member name, rejects absolute/parent traversal, rejects all links before extraction, then verifies a single root and every internal checksum. Synthetic traversal and link archives are rejected. |
| P5-SBOM-001 | Medium | CycloneDX generation inserted random serial numbers and wall-clock timestamps, so two otherwise identical bundles had different hashes. | The builder removes the optional random serial and normalizes timestamps to the source epoch. Two consecutive same-source builds produced identical SHA-256. |
| P5-FS-001 | Medium | Equality-only data/key separation allowed nested custody directories, and restrictive modes alone did not prove the files belonged to the running service identity. | Preflight now rejects nested paths and requires Linux effective-UID ownership plus regular non-symlink mode-0700 directories and mode-0600 files. |
| P5-CLI-001 | Medium | A misspelled `preflight` argument could be ignored and start the server, turning an operator validation typo into an unintended launch. | Server arguments are closed to either none or exactly `preflight`; every other argument fails before configuration or vault open. |
| P5-BACK-001 | Medium | Scheduled maintenance retained corrupt/unverifiable archive files but returned success, so systemd would not alert even though the inventory needed investigation. | The safe count is printed and files remain untouched, but the CLI exits nonzero. The operational campaign injects a corrupt candidate and verifies the alerting failure. |

## Residual operational limits

- Local provenance and optional test signing establish reproducible internal
  evidence, not an official external publication identity.
- The default RPO relies on the systemd timer and operator off-host transfer;
  SMCV cannot prove external custody from a local successful exit.
- The 15-minute reference RTO is measured for the documented small-vault class.
  Parser ceilings are not latency promises for larger installations.
- Linux effective UID validation uses the supported `/proc/self/status`
  interface and therefore does not extend the production support claim to
  non-Linux Unix systems.

## Conclusion

All four high and four medium findings were repaired and retested. No critical
or high Phase 5 finding remains. Phase 6 can repeat the complete release gate,
threat-model review, dependency/unsafe inventory, and residual-risk handoff.
