# Product design system

Status: **Committed principles; proposed visual tokens**
Last reviewed: 2026-07-21

## Experience principles

1. **Reveal progressively.** Show safe metadata first; fetch and display a
   secret only after explicit intent and authorization.
2. **Authority before identity.** A service's effective access is more important
   than its decorative name or icon.
3. **Consequences near controls.** Rotation, revocation, restore, and purge
   consequences appear beside the action, not only in documentation.
4. **Calm hierarchy.** Color supports structure and state; alarm colors are
   reserved for states requiring attention.
5. **Recovery is ordinary.** Backup status and restore readiness are routine
   navigation, not hidden emergency tools.
6. **No false certainty.** The UI distinguishes encrypted, verified, backed up,
   restored, rotated, expired, and revoked rather than collapsing them into a
   generic "secure" badge.

## Information architecture

Primary navigation:

- Overview
- Secrets
- Applications
- Access policies
- Activity
- Backup and recovery
- Settings

The overview prioritizes actionable state: expiring secrets, credentials due
for rotation, denied-access anomalies, backup freshness, last verification,
last restore drill, and key-maintenance status. It does not show vanity charts.

Secret detail separates metadata, current value reveal, versions, access, and
activity. Application detail separates identity, effective access, credentials,
and recent activity. Backup and recovery separates create, verify, restore, and
recovery guidance.

## Layout

- Desktop uses a restrained navigation rail, readable content column, and
  contextual detail panel only when it prevents navigation churn.
- Mobile and narrow layouts remain complete, but high-risk bulk administration
  may state a supported minimum width if a safe accessible design cannot fit.
- Primary reading width targets 65–85 characters for prose.
- Tables switch to labeled cards or horizontal regions without hiding actions.
- Persistent headers do not obscure focused content.

Use an 8 px spacing base with 4 px for compact internal relationships. Large
empty areas should communicate grouping, not waste screen space.

## Proposed visual foundation

Exact tokens are validated against WCAG and representative displays in Phase 4.

- Neutral surfaces use slightly cool charcoal/slate in dark mode and soft
  off-white/slate in light mode.
- The primary accent is a restrained blue or blue-violet associated with
  control and focus, not neon.
- Success uses green only for completed verified outcomes.
- Warning uses amber for recoverable attention.
- Danger uses red for disclosure, revocation, destructive change, and integrity
  failure.
- Secret values use a readable system monospace stack; ordinary UI remains a
  high-legibility system sans stack.

Do not encode state only with color. Every state has text and, where helpful,
an icon whose meaning remains clear without color.

## Core components

### Secret value

- Masked placeholder contains no real value in the DOM.
- Reveal is an explicit labeled button, not an eye icon alone.
- The client fetches plaintext only after activation.
- Revealed state shows an always-visible hide control and a short exposure
  notice.
- Copy provides a non-intrusive confirmation but never promises clipboard
  erasure; optional clearing is described as best effort.
- Page navigation, loss of visibility, session lock, and a one-minute maximum
  reveal timer remove rendered plaintext.

### Effective-access summary

Shows principal, actions, exact resources/namespaces, descendant behavior,
credential state, and last evaluated policy revision. Changes display a before
and after diff in plain language.

### Credential issue panel

Shows raw credential once after successful creation. It requires acknowledgement
that SMCV cannot show it again. Label, expiration, scope link, copy action, and
rotation guidance remain visible. Download-to-file is not the default.

### Status and badges

Badges use precise states such as `Encrypted`, `Backup verified`, `Restore drill
overdue`, `Credential revoked`, or `Rotation due`. Avoid `Safe`, `Protected`, or
`Healthy` when the underlying claim is narrower.

### Confirmation

Ordinary reversible changes use inline confirmation or undo. High-risk changes
use a focused dialog that states object, scope, immediate effect, recovery
route, and required recent authentication. Typed phrases are reserved for rare
irreversible actions and are never the only protection.

### Audit timeline

Uses consistent actor/action/target/decision/time structure, with filters whose
active state is apparent. It never reconstructs secret values or displays raw
request data. Denials are visible without sensational language.

### Backup card

Displays archive ID, creation time, format, size, safe counts, verification
result/time, and custody reminder. It distinguishes "created" from "verified"
and "restore tested."

Temporary server artifacts show download status and an absolute expiry. They
do not count as off-host custody, and disconnecting the browser does not change
the durable job result.

## Interaction states

Every interactive surface designs and tests:

- Initial, loading, empty, success, warning, error, unauthorized, locked,
  offline/retrying where supported, stale-version conflict, and integrity
  failure.
- Skeletons never mimic actual secret lengths.
- Errors preserve entered non-secret form data but clear secret fields.
- Retry does not silently duplicate a mutation.
- A network or server failure never claims that a mutation was not committed.
  Preserve a create request's idempotency key and require a current-state
  reload before retrying when the final outcome is unknown.
- Long operations show bounded progress, current safe stage, cancellation
  semantics, and what happens if the browser closes.

## Motion

Motion explains spatial or state change and respects `prefers-reduced-motion`.
No pulsing security badges, animated backgrounds, or countdown pressure.
Critical information never exists only during animation.

## Iconography and illustration

Use a small locally bundled icon set with accessible labels. Avoid ubiquitous
padlocks as decoration. A lock icon represents actual locked/unlocked state,
not general security. Decorative illustration is minimal and never consumes
attention needed for recovery or permission information.

## Responsive and offline behavior

SMCV is an online control surface. The service worker, if any, must not cache
authenticated HTML, API responses, secret values, or session-dependent assets.
An offline screen may explain loss of connection but cannot display previously
revealed data from application storage.

## Design acceptance

Phase 4 requires reviewed prototypes for every critical flow, contrast and
keyboard checks, reduced-motion behavior, 200% zoom/reflow, responsive states,
safe error recovery, and tests showing that secret plaintext is absent before
reveal and removed after hide/navigation/session lock.
