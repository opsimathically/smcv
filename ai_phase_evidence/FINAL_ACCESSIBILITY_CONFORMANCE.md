# Final accessibility conformance and known limitations

Date: 2026-07-21
Candidate: SMCV 0.1.0
Result: **Supported critical owner workflows meet the project's WCAG 2.2 AA acceptance evidence, with the spoken-output limit below**

No Phase 5 or Phase 6 implementation changed the owner or recovery UI after the
Phase 4 browser campaign. The release gate re-runs the full Rust/asset contract
tests; the final browser campaign repeats `node scripts/browser-smoke.mjs` and
its `SMCV_SCREEN_READER=1` variant against synthetic vaults.

Evidence in [the Phase 4 report](PHASE_4_ACCESSIBILITY_REPORT.md) covers semantic
landmarks/headings, native labels, focus and skip navigation, keyboard entry,
error/status regions, masked reveal state, empty local/session storage, 320 CSS
pixel reflow, 2x scale, reduced motion, forced colors, Firefox accessibility
tree names, and an active Orca/Firefox exercise. The critical owner workflows
include login, navigation, secret creation/reveal/hide, and backup/recovery.

Known limitation RR-008 remains: the available Orca debug stream did not expose
spoken accessible names, so automated spoken-output assertion was not tested.
The accessibility-tree names and active screen-reader path passed, but this is
not certification of every assistive technology, operating system, browser, or
user configuration. A human spoken-output review is recommended before a
deployment that depends on that exact combination; it is not a development
completion blocker.
