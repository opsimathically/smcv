# Accessibility standard

Status: **Committed: WCAG 2.2 AA target**
Last reviewed: 2026-07-21

## Scope

Every supported owner workflow, authentication screen, error path, help panel,
and generated document targets WCAG 2.2 Level AA. Accessibility is an
acceptance criterion in each user-facing slice, not a final polish phase.

## Keyboard and focus

- All actions work with keyboard alone and have visible focus.
- Focus order follows the visual and semantic sequence.
- Dialogs move focus to their heading or first appropriate field, trap focus
  while modal, close with documented behavior, and return focus to the trigger.
- After navigation or asynchronous state change, focus moves only when needed
  and to a meaningful target.
- Skip links and landmarks support quick navigation.
- No single-key shortcut activates while typing unless it can be disabled or
  remapped.

## Semantics

- Use native HTML controls before custom widgets.
- Every input has a persistent label; placeholder text is not a label.
- Tables have captions and associated headers.
- Status messages use appropriate live regions without reading secret values.
- Icon-only controls have accessible names, though high-risk actions should
  normally include visible text.
- Validation connects errors to fields and provides a summary.

## Visual access

- Normal text contrast is at least 4.5:1 and large text at least 3:1.
- UI components, focus indicators, and meaningful graphics meet applicable 3:1
  non-text contrast.
- Content reflows at 320 CSS px and remains usable at 200% zoom.
- Text spacing overrides do not clip or hide content.
- State and chart meaning never depend on color alone.
- Secret masks do not reveal actual value length visually or to assistive
  technology.

## Motion and time

- Respect reduced-motion preferences.
- Avoid flashing content.
- Session and recent-authentication timeouts warn the user with an accessible
  extension flow where security permits.
- Clipboard clearing and auto-hide are not communicated only through a visual
  countdown.
- Long backup/restore progress has text stage and determinate/indeterminate
  semantics without excessive announcements.

## Authentication

- Password managers and paste are allowed in password and recovery fields.
- Passkey workflows have a usable fallback and clear platform/browser errors.
- CAPTCHA is not a planned control.
- Recovery codes are available in accessible text and print formats without
  requiring visual interpretation of a QR code.
- TOTP setup, if supported, provides the textual seed through a protected
  accessible route as well as any QR representation.

## Secret reveal

The reveal control announces state without reading the secret automatically.
Plaintext is reachable by the intended assistive technology only after explicit
reveal. Hide removes the plaintext node. Copy results announce success without
repeating content.

## Testing

Each critical flow requires:

- Automated accessibility checks with documented limitations.
- Keyboard-only walkthrough.
- Screen-reader smoke test on supported browser/platform combinations.
- Contrast, forced-colors/high-contrast, reduced-motion, 200% zoom, and 320 px
  reflow checks.
- Error, loading, timeout, locked, unauthorized, and integrity-failure states.

Phase evidence records tool/browser versions, results, and remediation. A
waiver names the affected success criterion, user impact, workaround, owner,
and expiration. A serious issue creates remediation work within the same goal
and cannot be hidden by a phase-close report.
