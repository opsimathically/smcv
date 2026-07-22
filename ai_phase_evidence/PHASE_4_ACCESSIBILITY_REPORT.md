# Phase 4 accessibility report

Date: 2026-07-22
Scope: supported owner web workflows and local fresh-host recovery UI
Result: **Passed with one explicitly bounded assistive-technology tooling limit**

## Automated browser campaign

Run from the repository root:

```text
node scripts/browser-smoke.mjs
SMCV_SCREEN_READER=1 node scripts/browser-smoke.mjs
```

Both commands create isolated synthetic vaults and exercise login, navigation,
namespace and secret creation, masked/revealed/hidden secret handling, and the
backup/recovery page. The committed machine-readable results are
[browser-smoke.json](phase_4_browser/browser-smoke.json) and
[screen-reader-smoke.json](phase_4_browser/screen-reader-smoke.json). Each mode
replaces only its own report, so rerunning one campaign preserves the other's
independent evidence.

| Check | Result |
|---|---|
| Keyboard reaches the visible page's primary action from the main region | Pass |
| Visible form controls and buttons have names; one visible `h1` | Pass |
| Firefox exposes expected names for owner-password, login, heading, create-backup, and verify-backup controls | Pass |
| Skip link targets and names the currently visible authentication region | Pass |
| 500 CSS-pixel Firefox layout and 320 CSS-pixel Chromium capture reflow without horizontal overflow | Pass |
| Firefox at 2x device scale has no horizontal overflow | Pass |
| Reduced-motion preference removes navigation transition duration | Pass |
| Chromium forced-colors/high-contrast rendering remains legible | Pass by screenshot inspection |
| Synthetic plaintext is absent before reveal and after hide/navigation | Pass |
| Local storage and session storage remain empty | Pass |
| Orca 46.1 remains active with Firefox through the synthetic flow | Pass |
| Automated assertion of Orca spoken output | Not tested: speech was disabled and Orca's debug stream did not expose accessible names |

## Visual evidence

- [Forced-colors login](phase_4_browser/00-login-forced-colors.png)
- [Narrow login](phase_4_browser/01-login-narrow.png)
- [Narrow overview](phase_4_browser/02-overview-narrow.png)
- [Masked secret detail](phase_4_browser/03-secret-hidden-narrow.png)
- [Narrow backup and recovery](phase_4_browser/04-backup-recovery-narrow.png)
- [Wide backup and recovery](phase_4_browser/05-backup-recovery-wide.png)
- [320 CSS-pixel 2x Chromium login](phase_4_browser/06-login-2x-scale-320csspx.png)
- [2x Firefox login](phase_4_browser/07-login-firefox-2x-scale.png)

The screenshots contain synthetic labels only and no revealed secret value,
credential, recovery code, key, host-sensitive path, or production data.

## WCAG-oriented review

The shell uses landmarks, semantic headings, native labeled controls, visible
focus, skip navigation, status/error regions, restrained contrast-safe tokens,
and no information encoded solely by color. Dialog-like high-risk actions state
their consequence before confirmation. Error summaries receive focus, stale
updates provide a reload path, and loss of page visibility clears revealed
secret material.

The browser campaign is reproducible accessibility evidence, not a claim that
every operating-system, browser, magnifier, or screen-reader combination has
been certified. Phase 6 repeats the release-candidate review; independent
external accessibility or security assurance is post-development work.
