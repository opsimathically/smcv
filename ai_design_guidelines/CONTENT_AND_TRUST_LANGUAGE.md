# Content and trust language

Status: **Committed**
Last reviewed: 2026-07-21

## Voice

SMCV speaks plainly, calmly, and directly. It explains what happened, what is
protected, what remains at risk, and what the owner can do next. It does not use
fear, blame, jokes about breaches, or unexplained security jargon.

Use active voice and concrete nouns:

- Prefer: "SMCV encrypted this backup and verified its integrity."
- Avoid: "Your data is totally safe."
- Prefer: "This application can read 3 secrets in Production."
- Avoid: "Broad access" without enumerating what broad means.

## Required distinctions

### Authentication and authorization

`Authenticated` means an identity was verified. `Authorized` means that
identity may perform this action on this resource. Never use `authenticated` to
imply permission.

### Encryption states

- `Encrypted at rest` means protected fields are ciphertext in storage.
- `Unlocked` means the running service can decrypt authorized values.
- `Revealed` means plaintext was delivered to and displayed by a client.

Do not imply that encryption at rest protects plaintext on a compromised
unlocked server or client.

### Key and secret rotation

- `Encryption key rotation` changes how stored data keys are protected.
- `Credential rotation` replaces an SMCV login/API credential.
- `Secret rotation` replaces the value used by an upstream system.

Never claim an upstream secret was rotated merely because SMCV re-encrypted it.

### Backup states

- `Created`: archive writing completed.
- `Verified`: complete authenticated-integrity and structural checks passed
  under the supplied archive key. This does not prove which installation
  created the archive.
- `Restore tested`: the archive completed a clean staging restore exercise.
- `Portable`: restore does not require the source host/root key, but does
  require the separate archive passphrase or recovery key.

Do not call a backup successful before post-write verification.

### Deletion

Use `Archive` for reversible hiding, `Delete` for tombstoning according to
retention behavior, and `Purge` for physical removal from the current vault.
State that prior backups or storage remnants may still contain encrypted data.
Avoid `permanently erased everywhere`.

## Secret language

Never echo a secret value to identify it in text, toast, error, activity, or
confirmation. Use protected display name after authorization or an opaque short
ID. Do not reveal actual secret length through masking; use a fixed mask.

Copy confirmation says `Copied to clipboard` and, if clearing is attempted,
`SMCV will try to clear this clipboard entry in 30 seconds. Other applications
or clipboard managers may retain it.`

## Permission language

State effective access as an actor, verb, and resource:

- `Billing deployer can read API token in Billing / Production.`
- `Metrics collector can create new versions but cannot read stored values.`

Avoid unexplained `read/write` when the actual action is reveal, list, create,
update, archive, or manage policy. A permission preview includes inherited
namespace access explicitly.

## Errors

A safe error contains:

1. What SMCV could not complete.
2. Whether any change was committed.
3. A safe next step.
4. A request ID for diagnosis.

Example: `The backup could not be verified. The vault was not changed. Check
that you selected the correct file and recovery key. Request ID: …`

Do not distinguish unknown account from wrong password, unknown secret from
unauthorized secret, or individual cryptographic field failures to an
unauthorized client.

## Warnings and destructive actions

Warnings are proportional:

- Information: expected behavior or setup guidance.
- Warning: recoverable risk requiring attention.
- Danger: likely disclosure, access loss, or irreversible current-vault change.
- Integrity failure: SMCV cannot trust data and has stopped the operation.

Do not use `Are you sure?` alone. Name the action and consequence: `Revoke this
credential now. Requests using it will be denied immediately.`

## Recovery language

Recovery instructions always name both required items: the `.smcvault` file and
its separate passphrase or recovery key. State clearly that losing the only
copy of either makes restoration impossible.

When importing an old backup: `This backup may restore credentials or policies
that were later revoked. Review the creation date and choose whether to revoke
all imported application credentials before activation.`

When a web-created artifact remains temporarily on the server, call it
`Available for download until …`, not `Stored backup`. Explain that the owner
still needs an off-host copy and separate recovery material.

## Dates, identity, and audit

Show absolute dates with timezone for security events and backups. Relative
time may supplement but never replace it. Distinguish service identity from the
specific credential used. Use `SMCV could not determine` instead of inventing a
principal or cause.

## Documentation claims

Security claims identify scope, mechanism, and limitation. Avoid `military
grade`, `zero knowledge`, `unhackable`, `tamper-proof`, `guaranteed erased`, and
`fully secure`. Use algorithm names in technical details, not as marketing.
