# Critical user flows

Status: **Committed outcomes; interaction details proposed**
Last reviewed: 2026-07-21

## Initialize and establish recovery

1. Operator starts local initialization and sees the key-provider choice and
   loss consequences.
2. SMCV generates the vault and enrolls the owner without a default credential.
3. Owner authenticates and creates the first portable backup.
4. Owner confirms custody of the separate passphrase/recovery key.
5. SMCV verifies the written archive.
6. Overview shows backup as created and verified, but not restore tested.

Success means the operator can explain what files/keys are needed after total
host loss.

## Create and reveal a secret

1. Owner selects namespace and enters protected metadata and value.
2. UI explains that save creates version 1 and shows which applications will
   gain access from existing namespace policies.
3. Save clears secret fields and records an audit event.
4. Detail page shows metadata but not value.
5. Reveal requests recent authentication if needed, fetches plaintext only
   after authorization, and exposes hide/copy controls.
6. Hide/navigation/session lock removes rendered plaintext.

## Create a least-privilege application identity

1. Owner creates a service identity for one workload boundary.
2. Owner selects exact actions and resources/namespaces.
3. UI previews effective access in sentences and flags read-plus-write breadth.
4. Owner confirms through recent authentication.
5. Owner issues a labeled, expiring credential.
6. Raw credential appears once; owner acknowledges non-recoverability.
7. Activity distinguishes identity from the individual credential used.

## Rotate and revoke an application credential

1. Owner issues an overlapping credential with the same identity/policies.
2. Application deploys it and owner observes successful last-use.
3. Owner revokes the old credential.
4. UI states that requests using it will fail immediately.
5. Attempted reuse is visible without exposing the credential.

## Update a secret safely

1. Owner opens version N and begins editing.
2. Another update that creates N+1 causes the first save to fail as stale.
3. UI preserves safe metadata input, clears or protects secret input, and asks
   the owner to compare without revealing values unnecessarily.
4. Successful retry creates N+2; it never overwrites N+1.

## Create and verify a backup

1. Owner selects the recommended generated recovery-key mode or a strong
   passphrase mode and reauthenticates.
2. UI states included durable state and excluded sessions/root keys.
3. Owner confirms key custody.
4. Progress names safe stages: snapshot, encrypt, finalize, verify.
5. Download becomes available only after server-side archive finalization and
   verification; browser response is not cached and the encrypted server
   artifact has a visible expiry.
6. Result shows archive ID, absolute creation time, format, size, counts, and
   verified state.

Closing the browser does not turn an ambiguous partial job into a reported
success. The owner can safely inspect job status later.

## Verify an existing backup

1. Owner selects a `.smcvault` file and supplies its key through protected input.
2. SMCV performs full non-mutating verification.
3. Result states compatible/incompatible, creation time, safe counts, and
   whether complete integrity and structural checks passed.
4. Failure says the current vault was not changed and provides a safe next step.

## Restore after total host loss

1. Operator installs compatible SMCV and starts restore locally through the CLI,
   which may create a short-lived single-use local browser flow.
2. Operator selects archive and enters separate recovery material.
3. UI authenticates metadata and shows backup creation time plus rollback risk.
4. Operator chooses preserve application credentials for disaster recovery or
   revoke them for migration.
5. SMCV stages, validates, re-encrypts under a new installation ID/recovery
   epoch, and reports results before activation.
6. Activation is atomic; failure leaves no ready partial vault.
7. Owner completes local destination enrollment; source-bound passkeys are
   enabled only if the RP identity matches, otherwise they are reenrolled.
8. Owner reviews audit epochs, decommissions the old installation, creates a new
   backup, and follows post-incident rotation guidance.

## Respond to compromised application credential

1. Owner finds identity/credential by safe prefix, label, or activity.
2. Effective access explains possible blast radius.
3. Revoke takes effect immediately and is audited.
4. Owner reviews accessed targets and denied attempts.
5. UI recommends upstream secret rotation based on actual read authority; it
   does not claim revocation rotates exposed secrets.

## Integrity failure

1. SMCV stops the affected operation without partial plaintext or mutation.
2. UI states that data integrity could not be verified and avoids speculative
   cause.
3. Owner receives safe record/request references and recovery guidance.
4. The system does not offer a one-click "ignore and continue" path.
