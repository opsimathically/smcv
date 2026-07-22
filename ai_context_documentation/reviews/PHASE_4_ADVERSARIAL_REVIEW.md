# Phase 4 web product and recovery UX adversarial review

Status: **Complete; all high findings closed**
Date: 2026-07-21
Scope: same-origin web UI, secret rendering, owner workflows, backup browser
adapters, and fresh-host local recovery

## Review method

The review traced secret and recovery authority across the Rust handlers,
embedded assets, browser DOM and storage, multipart staging, cancellation,
temporary files, and the local recovery channel. It exercised synthetic secret
reveal/hide/navigation, lifecycle transitions, authenticated backup download and
re-upload, clean staging restore, claim replay, session replay, keyboard use,
responsive layouts, 2x rendering, reduced motion, forced colors, Firefox
accessibility names, and Firefox while Orca was active.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P4-REC-001 | High | The first local-recovery design put the one-time bootstrap capability in the URL fragment. Although fragments are not sent as HTTP referrers, browser history, crash recovery, screenshots, or copied URLs could retain authority. | The CLI now displays a clean loopback URL and separate 256-bit authorization code. The code is submitted once in a JSON body, the server stores only its digest, and successful claim returns a distinct digest-only, `HttpOnly`, `SameSite=Strict` loopback session cookie. Wrong, repeated, and post-activation claims fail in regression tests. |
| P4-PROC-001 | High | The inherited repository instructions described an unrelated public-data system and required PostgreSQL/object storage, creating a serious risk of implementing against the wrong trust model. | `AGENTS.md` now governs SMCV, names its SQLite/browser/recovery invariants, and points contributors to the active security and phase documents. Repository behavior and documentation were rechecked against the corrected instructions. |
| P4-REC-002 | Medium | A cancelled or timed-out multipart verification could leave an encrypted upload or clean-restore staging artifact behind. | Restrictive temporary artifacts use removal-on-drop guards, successful paths remove them explicitly, and startup removes only exact SMCV verification/status/restore-drill orphan patterns. The integration test checks that no such artifact remains. |
| P4-RES-001 | Medium | Backup creation and verification both perform expensive Argon2/archive work; independent unbounded request concurrency could exhaust CPU or memory. | Both operations share a four-slot semaphore, route-specific 8 GiB body limit, and 15-minute timeout. Global body and password-work bounds remain in force. |
| P4-A11Y-001 | Medium | The skip link initially targeted the authenticated application main region even while the login view was active. | Routing now points the skip link at the currently visible main region. Browser evidence verifies its label and the login and backup controls' computed accessibility names. |
| P4-DATA-001 | Medium | Active-secret listing alone could not support honest archived/deleted inventories or an explicit purge flow. | Owner-only lifecycle inventory and archive, restore, soft-delete, and purge handlers were added with ordered integration coverage. The UI distinguishes each state and warns that purge cannot remove copies already present in backups. |
| P4-TRUST-001 | Medium | A single “backup complete” state could imply off-host custody or recovery readiness without evidence. | The UI distinguishes created, server-verified, downloaded, off-host custody unproven, and browser restore-test results. It shows archive format, logical vault ID, recovery epoch, expiry, and passkey reenrollment consequences. |

## Browser and recovery conclusions

- The production shell has no inline script, remote asset, analytics, browser
  persistence, or third-party runtime dependency. Its document CSP disallows
  object, frame, base, and form escape paths.
- The synthetic sentinel is absent before reveal, present only after reveal,
  and absent after hide and navigation. No local or session storage entry is
  created.
- Fresh-host browser recovery binds only to loopback, requires exact origin,
  expires after ten minutes, activates at most once, and never accepts a
  populated destination. Archive keys stay in request bodies.
- Browser verification authenticates the complete archive and performs a real
  restore into clean temporary paths; it reports this test without claiming
  that the owner's off-host copy has been tested.

## Accessibility limits

Firefox computed names, semantic headings, keyboard focus, reduced motion,
forced-colors rendering, narrow reflow, and 2x device-scale overflow checks
pass. Orca 46.1 was active with Firefox during the complete synthetic flow and
produced diagnostic output, but that non-speech debug format did not expose the
spoken accessible names. This is recorded as a tooling limitation, not a claim
that an automated spoken-output assertion passed; the same critical names were
asserted through Firefox's accessibility interface.

## Conclusion

Both high findings and all actionable Phase 4 findings were repaired and
retested. No critical or high finding remains. Phase 5 owns production
packaging, capacity/fault calibration, upgrades, telemetry, and operational
runbooks; independent assurance remains the accepted post-development handoff.
