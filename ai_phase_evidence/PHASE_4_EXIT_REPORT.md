# Phase 4 exit report

Phase: 4 — web product and accessibility
Date: 2026-07-21
Status: **Passed; Phase 5 active**
Phase boundary: the local commit containing this report

## Environment and delivered scope

- Linux x86_64 development host
- `rustc 1.94.0 (4a4ef493e 2026-03-02)` and Cargo 1.94.0
- Firefox 152.0.6, geckodriver, Orca 46.1, Chromium 150.0.7871.114
- Node.js 20.19.4 for the dependency-free browser harness
- Synthetic temporary vaults, credentials, recovery keys, and sentinels only

Delivered scope includes the embedded same-origin owner UI, password/passkey
login, secret and namespace lifecycle, service credentials, policies and
effective-access previews, activity, settings/passkeys, durable backup jobs,
browser archive verification with a real clean restore drill, and a loopback
fresh-host browser recovery channel.

## Acceptance and requirements evidence

| Requirements / criterion | Evidence and result |
|---|---|
| WEB-001 | All committed owner workflows are available in the semantic responsive shell, including empty, loading, denial, conflict, archive/delete/purge, and recovery states. |
| WEB-002 | Reveal is explicit; the browser test proves the synthetic value absent before reveal and after hide/navigation. Visibility loss and a one-minute maximum timer clear revealed state; browser persistence stays empty. |
| WEB-003 | Existing recent-owner API enforcement protects high-risk actions. The UI states purge, credential, backup custody, rollback, and passkey consequences before action. |
| WEB-004 | The [accessibility report](PHASE_4_ACCESSIBILITY_REPORT.md), machine-readable Firefox results, and screenshots cover keyboard, names, focus, 320 px capture, 2x scale, forced colors, reduced motion, and responsive layouts. |
| WEB-005 | Embedded asset tests reject remote runtime dependencies and inline script; production documents use a restrictive same-origin CSP, private/no-store policies, frame/capability denial, opener/resource isolation, and HSTS. |
| BACKUP-001 / BACKUP-006 | The owner can create, list, download, delete, and upload a portable archive. Browser upload runs full authenticated verification and an actual clean temporary restore test. |
| BACKUP-007–015 | The local CLI recovery browser requires a clean destination, separate one-time body code, exact loopback origin, digest-only state, short expiry, and single activation. It displays logical-vault/epoch/credential/passkey effects and supports preserve/revoke credential modes. |
| AUDIT-001–004 | Activity renders safe actor/action/resource/result records; lifecycle, authorization, backup, and recovery coverage remains enforced by the lower-layer tests. No raw protected values enter UI event text. |
| SEC-001–003 | Strict workspace formatting, Clippy, tests, docs, advisory/source/license policy, secret-pattern scan, and Markdown-link checks pass. Both Phase 4 high findings are closed. |

## Reproducible validation

```text
./scripts/check.sh
  PASS: rustfmt and strict all-feature Clippy
  PASS: workspace unit, integration, failure, browser-asset, and doc tests
  PASS: rustdoc warnings denied
  PASS: RustSec advisory scan and cargo-deny license/source policy
  PASS: exact application-token/private-key repository scan
  PASS: every relative Markdown link resolves

node scripts/browser-smoke.mjs
  PASS: secret DOM lifecycle, storage, names, keyboard, reflow, reduced motion,
        2x scale, forced-colors capture, and critical-flow screenshots

SMCV_SCREEN_READER=1 node scripts/browser-smoke.mjs
  PASS: the same flow with Orca active; see the documented debug-output limit
```

The two browser modes publish separate reports without deleting one another's
evidence. A 2026-07-22 adversarial rerun also verified reload-triggered server
session revocation and ambiguity-safe create retries.

Focused Rust evidence includes:

- owner lifecycle inventories and ordered active/archive/restore/delete/purge;
- authenticated backup creation, verified download, browser re-upload, clean
  restore drill, and temporary-artifact cleanup;
- wrong and replayed recovery claim rejection, cookie-bound upload and
  activation, single-use shutdown, and clean destination activation;
- asset checks for no remote runtime dependency, inline script, browser
  persistence, URL authority, or history authority.

## Adversarial review and residual risk

The [Phase 4 adversarial
review](../ai_context_documentation/reviews/PHASE_4_ADVERSARIAL_REVIEW.md)
closed two high and five medium findings. No critical or high finding remains.
The recovery claim is no longer placed in a URL; cancellation-safe cleanup and
bounded expensive work are regression covered.

The non-speech Orca debug output did not expose accessible names. Firefox's
accessibility API did expose and verify the critical names while Orca was also
run through the flow. This bounded automation limitation is retained honestly
for the Phase 6 release-candidate review and is not an external-review gate.

## Compatibility, interruption, and recovery observations

No archive compatibility format changed. Phase 3's committed v1 fixture remains
the compatibility baseline. Multipart cancellation cleanup is enforced by drop
guards and exact startup orphan cleanup. Server jobs retain restart semantics;
fresh-host activation is last, clean-only, and cannot be replayed.

## Phase transition

Phase 4 satisfies the web-owned requirements and backup/recovery UI gate. No
human task, pilot, deployment, or external dependency is required. Phase 5 may
package and operate the completed product surfaces, and the continuous goal
advances without an approval pause.
