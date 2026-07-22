# Phase 4: web product and accessibility

Status: **Planned**

## Objective

Deliver the polished, accessible owner interface for every committed v1
workflow without increasing secret exposure in the browser.

## Entry criteria

- Phase 3 exit evidence passes.
- API and job semantics stable for the planned UI.
- Design tokens and critical-flow prototypes reviewed.

## In scope

- Same-origin authenticated shell and responsive navigation.
- Overview, secrets, applications, access, activity, backup/recovery, settings.
- Explicit secret reveal/hide/copy behavior.
- Credential issue/rotation/revocation and effective-access previews.
- Secret versioning, stale-update recovery, archive/delete/purge distinctions.
- Backup create/download, verify, and empty-vault restore flows.
- Locked, loading, empty, denial, conflict, integrity, timeout, and long-job
  states.
- CSP, cache, DOM/storage leakage checks and WCAG 2.2 AA work.

## Out of scope

- Browser extension, offline secret access, remote analytics/assets, arbitrary
  visual dashboards, and deferred backend capabilities.

## Work slices

1. Tokens, semantic components, shell, and all interaction states.
2. Authentication/session/recent-auth flows.
3. Secret and version workflows.
4. Application, credential, and policy workflows.
5. Audit/activity workflows.
6. Backup/recovery workflows.
7. Browser security, content, responsive, and accessibility campaign.

## Acceptance criteria

- All critical flows in the design guide complete with keyboard and supported
  screen reader.
- Automated checks plus manual WCAG 2.2 AA evidence exist for every critical
  page/state.
- No plaintext secret exists in DOM, client storage, cache, URL, referrer,
  telemetry, or error before reveal or after hide/navigation/session lock.
- Permissions are previewed as effective actor/action/resource sentences before
  grant.
- Owner-only actions never appear in service-policy controls, and purge states
  its retention and backup limitations before recent-auth confirmation.
- Created, verified, and restore-tested backup states remain distinct.
- 320 px reflow, 200% zoom, forced colors/high contrast, and reduced motion work.
- Production bundle makes no third-party runtime network request.
- Web backup creation/download, full verification, and locally authorized
  restore complete the UI portion of BACKUP-001 and show artifact expiry,
  off-host custody, logical-vault/recovery-epoch, and passkey reenrollment state
  accurately.

## Required evidence

- Critical-flow recordings/screenshots using synthetic data.
- Browser storage/network/DOM leakage checks.
- CSP and cache-header verification.
- Keyboard, screen-reader, contrast, zoom/reflow, and reduced-motion results.
- Content/trust-language review.
- Browser/adversarial UX review and resolutions.

## Adversarial review prompts

- Can plaintext survive in DOM, accessibility tree, clipboard promise, cache,
  browser storage, history, referrer, screenshot helper, or client telemetry?
- Can XSS/CSRF/clickjacking or a stale recent-auth state perform a high-risk
  action?
- Can visual design hide inherited access, owner-only scope, rollback risk, or
  backup custody requirements?
- Can a keyboard/screen-reader user complete recovery and integrity-failure
  paths without losing context or disclosing a secret?

## Exit gate

WEB requirements and the web-owned portions of backup requirements pass, no
serious accessibility or high security finding remains, and the UI accurately
communicates the underlying trust model.
