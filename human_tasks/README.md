# Human tasks

Phases 0–6 are designed to complete without human-task dependencies. Use this
directory only to record an optional owner activity, a post-development action,
or a genuinely new product decision that would change committed scope.

Human tasks do not become implementation phase prerequisites under D-012
through D-016. During the continuous v1 goal:

- Use local and synthetic substitutes instead of waiting for an account,
  domain, public certificate, signing identity, KMS/HSM, production system,
  reviewer, or real recovery key.
- Resolve technical choices from the committed requirements, current evidence,
  and safest in-scope default.
- If a newly discovered question would materially expand product scope, keep it
  proposed or deferred and continue the committed v1 path.
- Never pause for a pilot, external-user feedback, adoption result, owner phase
  approval, external security review, or personal key-custody exercise.

Never place a credential value, private key, recovery code, passphrase,
production record, or other secret in a task file.

## File and status convention

Use `HT-NNN-short-title.md` with one of:

- **Requested:** optional owner input that does not pause development.
- **Post-development:** action intentionally scheduled after Phase 6.
- **In progress:** owner has acknowledged it.
- **Complete:** result and date recorded without secret material.
- **Cancelled:** no longer needed, with reason.

Each task includes purpose, safe instructions, expected non-secret evidence,
timing, impact if deferred, and result. No task uses a `Blocked` state.

## Current status

There are no human tasks on the v1 implementation critical path. The owner has
already signed off on continuous execution and accepted the residual risk of
completing development before independent external security assurance.

The following are explicitly post-development and non-blocking:

- Owner custody testing with real recovery material.
- Independent external security assurance and resulting iterations.
- Official release-signing identity custody.
- Public publication and production deployment decisions.
