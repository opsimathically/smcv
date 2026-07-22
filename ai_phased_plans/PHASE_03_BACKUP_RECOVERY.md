# Phase 3: portable backup and recovery

Status: **Active implementation phase**

## Objective

Fulfill the recovery promise with a hostile-input-resistant portable archive,
easy UI-ready/API and CLI workflows, and proven clean-environment restore.

## Entry criteria

- Phase 2 exit evidence passes.
- Archive cryptography/framing decision D-108 resolved.
- Authentication and authorization exist for backup operations.

## In scope

- Versioned `.smcvault` writer and bounded reader.
- Passphrase, generated recovery key, and protected automation key modes.
- Backup create, safe inspect, full verify, and new/empty-vault restore.
- Server job/API and CLI workflows with safe progress.
- Staging database, complete validation, re-encryption, and atomic activation.
- Local CLI fresh-restore authority and single-use local recovery channel.
- Logical vault identity preservation with new installation ID/recovery epoch.
- Preserve-versus-revoke imported application credential choice.
- Compatibility fixtures and restore of every supported archive version.
- Post-write verification and clean-environment recovery drill.

## Out of scope

- Populated-vault merge, destructive in-place replacement, plaintext export,
  cloud storage connectors, compression, and automatic upstream secret
  rotation.

## Work slices

1. Canonical logical export and archive format.
2. Bounded hostile reader and authenticated verification.
3. Staging restore and destination re-encryption.
4. CLI protected input and automation modes.
5. API/job lifecycle and safe progress/status.
6. Compatibility, corruption, interruption, and recovery-drill campaign.

## Acceptance criteria

- The source root key is absent from the archive and destination restore does
  not require it.
- No protected-field sentinel appears in archive public headers, process
  arguments, logs, temporary filenames, or plaintext temporary files.
- Wrong key, corrupt header/manifest/chunk, truncation, extension, reorder,
  duplicate, downgrade, and extreme parameters fail before activation.
- Every interruption and disk-full point leaves the destination non-ready and
  the existing installation unchanged.
- Full verification is non-mutating and clearly distinct from header inspect.
- Clean restore preserves logical secret versions, policies, audit counts, and
  credential behavior according to the selected preserve/revoke mode.
- Preserved credential verification works through the portably reprotected
  vault-scoped verifier key; raw credentials and source root/KEK material are
  absent.
- Source-bound owner authenticators are enabled only when destination RP
  binding is valid; local recovery enrollment remains possible without a remote
  first-claim route.
- Backup completion is reported only after reopening and verifying the archive.
- Old supported fixture restore followed by current backup and second restore
  succeeds.
- Representative small and large bounded fixtures establish provisional
  archive-size/count, peak-memory/disk, and restore-time limits.

## Required evidence

- Published non-secret archive specification and fixtures.
- Parser fuzzing and resource-bound results.
- Corruption/interruption matrix.
- Clean-environment restore report with safe comparison.
- Process/log/temp sentinel scan.
- Recovery usability walkthrough.
- Backup/recovery adversarial review and resolutions.

## Adversarial review prompts

- Can a valid prefix, reordered stream, duplicate ID, extreme KDF value, or
  unknown critical record reach a ready destination?
- Can restore preserve credentials without preserving the secret verifier key,
  or accidentally preserve them in revoke mode?
- Can an unauthenticated network client win fresh-host ownership?
- Can two clones appear to be one continuous installation/audit history?
- Can a disconnect, cancellation, quota, disk-full event, or cleanup target
  alter another vault or report an unverified archive as complete?

## Exit gate

The domain, CLI, API/job, and non-web portions of BACKUP-001 through BACKUP-015
pass; no high finding remains; and the product recovery promise is demonstrated
without the source host or root key. Phase 4 owns the web portions of BACKUP-001
and the browser workflows without reopening archive semantics.
