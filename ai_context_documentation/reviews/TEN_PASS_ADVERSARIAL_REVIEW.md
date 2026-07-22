# Ten-pass adversarial project review

Status: **In progress**
Started: 2026-07-22
Scope: complete SMCV repository and 0.1.0 release-candidate behavior

This campaign performs ten consecutive reviews from different failure
perspectives. Each pass challenges the repository after all preceding repairs.
A pass is complete only after concrete findings are fixed, regression evidence
passes, documentation matches, and the fix boundary is committed locally.

## Pass 1 — repository integrity, configuration, and release envelope

Perspective: a hostile release publisher, artifact supplier, CI dependency,
local path adversary, and new operator. Result: **six findings repaired and
retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R1-001 | Critical | `verify-release.sh` extracted the archive and executed its bundled CLI before checking an optional detached signature. Supplying a public key therefore did not prevent pre-authentication code execution. | Signature verification now authenticates a restrictive private archive copy before listing or extraction. Artifact verification never executes bundled code. A synthetic signed archive containing an executable marker script verifies without creating its marker; a wrong public key fails. |
| A10-R1-002 | High | Verification repeatedly reopened the caller-controlled archive path, parsed human-formatted tar listings, rejected only links rather than every special type, and allowed files omitted from `SHA256SUMS`. A path replacement or self-consistent unlisted payload could evade the claimed whole-bundle check. | The verifier copies once, requires the adjacent checksum for that copy, accepts only the exact safe bundle root/portable member vocabulary/regular-file-or-directory types, extracts the same copy, and compares the checksum manifest one-to-one with all files. Automated tests reject an unlisted file and symlink. Candidate smoke likewise verifies and extracts one stable copy. |
| A10-R1-003 | High | All four GitHub Actions dependencies used mutable major or branch references, including `dtolnay/rust-toolchain@master`. Compromise or retagging could silently alter the trusted CI/release environment. | Checkout, Rust toolchain, cache, and installer actions are pinned to full reviewed commit hashes, with release/version comments. The installer action's own security guidance recommends hash pinning. |
| A10-R1-004 | Medium | Outer checksum files embedded an absolute build-host path, reducing portability; an unsigned rebuild could leave a stale `.sig`; and the final archive was overwritten directly rather than published from a completed temporary file. | Checksums now contain the archive basename, unsigned builds remove stale signatures, and the archive is completed in a same-directory temporary file then atomically renamed. Signed/wrong-key and normal candidate verification pass. |
| A10-R1-005 | Medium | Local provenance omitted the Rust, Cargo, and CycloneDX versions and did not cryptographically bind its `Cargo.lock` claim to the included lockfile. | Provenance now records all three tool versions and the lockfile SHA-256. Verification checks types, commit shape, target/version, clean state, and exact bundled lock hash. |
| A10-R1-006 | Low | Architecture status stopped at Phase 5 and allowed an in-server TLS interpretation even though v1 production is unconditionally loopback-only behind the same-host proxy. | Architecture status and deployment wording now match the completed Phase 6 implementation and supported TLS boundary. |

Validation:

```text
./scripts/release-verifier-smoke.sh
  signed_archive_not_executed=passed
  wrong_signature_key=passed
  unlisted_file=passed
  link_member=passed
  missing_outer_checksum=passed
  malformed_outer_checksum=passed

SMCV_ALLOW_DIRTY_BUILD=1 ./scripts/build-release.sh
SMCV_ALLOW_DIRTY_VERIFY=1 ./scripts/verify-release.sh dist/smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
SMCV_ALLOW_DIRTY_VERIFY=1 ./scripts/release-candidate-smoke.sh dist/smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
  PASS: complete expanded bundle verification and artifact install/preflight/
        rollback/restore campaign
```

No Pass 1 critical/high finding remains open. The next pass begins from these
repairs and reviews cryptography, key lifecycle, plaintext handling, and memory
exposure without relying on prior assurance conclusions.

## Pass 2 — cryptography, key lifecycle, and plaintext exposure

Perspective: a local path adversary, memory-forensics observer after buffer
release, hostile archive/token supplier, and interrupted key custodian. Result:
**four findings repaired and retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R2-001 | High | Root-provider loading checked metadata by pathname and then reopened the path. A replacement between those operations could make the validated object differ from the key bytes read; immediate custody-directory symlinks were also accepted. | Root providers now open once with `O_NOFOLLOW` and `O_CLOEXEC`, validate type/length/mode on that descriptor, and read from it. Creation also uses no-follow/close-on-exec, and initialization rejects a symlinked immediate custody parent. Existing provider symlink rejection plus a new parent-symlink regression pass. |
| A10-R2-002 | Medium | Key-generation temporaries and decoded application/session/CSRF token secrets used ordinary stack arrays or vectors on some success and rejection paths. | Generated key buffers and every decoded bearer-secret component now enter a zeroizing owner before fallible work and remain there through verification. Public lookup components remain ordinary data by design. |
| A10-R2-003 | Medium | Backup recovery keys, plaintext archive read/write chunks, base64-decoded restore values, and decrypted logical key/metadata fields could be freed without zeroization, particularly after malformed input or a later restore error. | Recovery keys and archive plaintext frames/chunks now use zeroizing storage. Protected logical fields deserialize into zeroizing strings, base64 decoders use zeroizing destinations, and malformed key inputs are cleared before returning. The committed v1 fixture and complete clean-environment re-encryption restore still pass. |
| A10-R2-004 | Medium | Protected descriptor and multipart inputs first occupied ordinary `String`/`Vec` allocations; descriptor trimming also copied secret text and could silently alter a passphrase ending in whitespace. | CLI descriptor reads and browser/server recovery-key fields now accumulate directly into zeroizing owners, explicitly clear invalid UTF-8, and remove only transport CR/LF in place without a plaintext copy. |

Validation includes the complete crypto, backup, application, CLI, and server
test suites, the frozen AEAD/metadata/archive compatibility fixtures, hostile
credential properties, wrong-key/corruption checks, rotation restart tests,
and the new custody-parent symlink rejection. No Pass 2 critical/high finding
remains open.

## Pass 3 — authentication, sessions, CSRF, WebAuthn, and credentials

Perspective: a credential holder racing revocation, a hostile unauthenticated
client, multiple services behind the supported same-host ingress, a path-ID
confusion attacker, and a host clock that moves backward. Result: **five
findings repaired and retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R3-001 | High | Successful session creation updated an authenticator by ID without comparing the state that had actually been verified. Concurrent WebAuthn assertions could overwrite one another's authenticator data/counter, and a stale successful authentication could race later authenticator state. | Session creation now atomically compares the verified authenticator commitment while inserting the session, advancing last use, and persisting new WebAuthn state. Any stale observation rolls back the entire transaction. A deterministic stale-password-authenticator regression proves that a second session cannot be created from the old observation. |
| A10-R3-002 | Medium | The unauthenticated passkey authentication options and verification routes could repeatedly allocate/consume the bounded in-process ceremony store without a source limit. | Both routes now share a dedicated 20-request-per-peer/minute passkey bucket, independent from the 10-attempt password bucket, and increment the aggregate rate-limit metric. Integration coverage exhausts passkey capacity, receives `429`, and proves password authentication remains in its separate bucket. |
| A10-R3-003 | Medium | Bearer requests were limited only by direct peer IP. Under the required same-host proxy, one noisy or compromised service could therefore consume the 120-request bucket for every other service. Naively accepting attacker-selected token lookups as limiter keys would also permit bounded-map exhaustion. | Durable application credentials now receive independent buckets keyed by their public random lookup. Malformed, well-formed-but-unknown, and storage-error lookups use the peer bucket and cannot allocate arbitrary credential keys. Unit/domain tests prove credential isolation and reject an attacker-selected valid token as a durable key. |
| A10-R3-004 | Medium | Session, owner-context, authenticator, application-credential, and passkey-ceremony checks enforced upper expiry bounds but did not reject times earlier than already observed durable/process state. A backward clock could therefore reuse an older validity position or mutate last-use state backward. | Every affected authentication boundary now rejects a time before creation or committed last use; request-scoped owner contexts also carry a lower validity bound, and ceremony cleanup removes rollback-invalid entries. Session regression coverage exercises the backward-clock rejection. |
| A10-R3-005 | Medium | `POST /service-identities/{service}/credentials/{credential}/revoke` parsed only the credential ID and ignored the parent service ID, so a valid credential could be revoked through a false resource hierarchy. | The application boundary now requires the parent service principal and compares it to the credential owner before mutation. Regression coverage proves a mismatched parent fails without revoking and the correct parent retains the existing linearized revoke behavior. |

Validation includes focused authentication/service-identity regressions, the
complete server integration suite, strict all-feature Clippy, and the full
repository gate. No Pass 3 critical/high finding remains open.

## Pass 4 — authorization, enumeration resistance, and audit integrity

Perspective: a service probing unknown object IDs, a revoked credential
holder, an offline hierarchy editor, a stale request-context holder, and an
auditor relying on the decision trail. Result: **four findings repaired and
retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R4-001 | High | Namespace move-impact preview validated the owner session but bypassed the centralized authorization/audit decision. Its delta calculation also consumed namespace ancestry without authenticating the keyed state of the moved namespace, proposed parent, or intervening ancestors. An offline hierarchy edit could therefore make the preview report an untrusted access delta even though final mutation later failed. | Preview now enters `effective-access:read` with request correlation and resolves both old and proposed ancestry through the commitment-verifying resource boundary. A regression corrupts the proposed parent's state commitment and proves preview fails; the valid preview is audited and the final move still recalculates under the write gate. |
| A10-R4-002 | Medium | Service authorization used `?` while resolving a target. An absent target returned `Denied` before the common audit append, so unknown-object probes escaped the denial trail even though no-grant denials were recorded. | Expected absent-target `Denied` is now normalized into the common decision result before audit construction; integrity and infrastructure errors still fail closed without being mislabeled. Regression coverage correlates the absent opaque target and request ID to a committed denied event. |
| A10-R4-003 | Medium | Authentication rejected a known wrong-secret, revoked, expired, or backward-time application credential without an audit event, contradicting the credential-compromise and audit requirements. | Application authentication now accepts request correlation and appends a `credential:authenticate` denial for durable known credentials. The event carries the opaque credential reference but no actor principal, because a rejected claimant is not authenticated. Unknown random lookups remain unaudited to avoid attacker-controlled durable cardinality. Revoked-attempt coverage verifies the exact event. |
| A10-R4-004 | Medium | Revalidation of a copied `AuthenticatedService` checked revocation and upper expiry but not credential creation/last-use lower bounds. Code using the application facade could therefore authorize that context at a time earlier than durable authentication state. | Service-context revalidation now rejects time before credential creation or committed last use. The authorization matrix regression attempts the rollback and fails before constructing `AuthorizedVault`. |

Validation includes offline hierarchy corruption, absent-resource denial
attribution, revoked-credential denial attribution, service-context rollback,
the complete application/server suites, strict all-feature Clippy, and the
full repository gate. No Pass 4 critical/high finding remains open.

## Pass 5 — persistence, migrations, concurrency, and crash consistency

Perspective: an operator selecting the wrong database, an older binary opening
future state, a local path replacer, concurrent audited requests, and a crash
between durable state-machine steps. Result: **four findings repaired and
retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R5-001 | Critical | Database configuration unconditionally set the SMCV application ID and enabled WAL before proving file identity. Pointing SMCV at another restrictive SQLite database could therefore persistently modify it and then add SMCV migration state. | Open now reads identity before every persistent pragma. A zero-ID database must be empty, except for the exact checksummed two-table Phase 0 legacy fixture; a different application ID or any unrelated object fails closed. A regression creates an unrelated database, attempts open, and proves its bytes are unchanged. |
| A10-R5-002 | High | Migration startup verified only known rows encountered in its loop. It did not reject extra future migration rows or a `user_version` newer/inconsistent with recorded history, allowing an older binary to open unsupported state. | Startup now requires the applied rows to be an exact ordered prefix of compiled migrations and requires `user_version` to equal that prefix head before applying anything. Tests reject an added version 99 row and an independently inconsistent version while the frozen forward-migration fixture still passes. |
| A10-R5-003 | High | Audit commitment construction read the chain head before the later append/mutation transaction, while concurrent request paths held only shared authorization guards. Two requests could build the same next sequence; one then failed spuriously at commit, including read requests whose authorization decision itself is audited. | Each initialized vault now holds a narrow audit mutex from head observation and HMAC construction through the consuming append or domain transaction. A deterministic two-thread regression holds the first pending event, proves the second builder cannot pass, commits the first, and observes the exact next sequence for the second. Domain mutation/audit atomicity remains inside SQLite. |
| A10-R5-004 | Medium | SQLite database and online-snapshot connections reopened previously validated paths without requesting SQLite's no-follow protection, leaving a final-component symlink substitution window between metadata validation/creation and SQLite open. | Every database and snapshot connection now includes `SQLITE_OPEN_NOFOLLOW` in addition to the existing restrictive-file checks, full mutex mode, protected-parent policy, and non-overwrite snapshot behavior. |

Validation includes the expanded storage suite, frozen migration fixture,
foreign-database byte comparison, unknown/inconsistent-version rejection,
deterministic audit concurrency ordering, strict all-feature Clippy, and the
full repository gate. No Pass 5 critical/high finding remains open.

## Pass 6 — backup, import, restore, and recovery custody

Perspective: a crash at every publication/activation edge, a malicious archive
holder controlling authenticated logical fields, a local path replacer, and an
operator relying on retryable recovery. Result: **five findings repaired and
retested**.

| ID | Severity | Finding | Repair and verification |
|---|---|---|---|
| A10-R6-001 | Critical | Restore committed the ready marker and only then performed its fresh reopen/audit check. A failure there returned an error while leaving a ready destination; failures after staging also stranded database and root-provider files that blocked a clean retry. | Restore now completes protected-state verification, then freshly reopens the still-guarded database, reloads the external root provider, and unwraps every required key before activation. Activation is the final fallible step. An attempt-owned cleanup guard removes database, WAL/SHM, and root-provider files on every ordinary post-staging error. A deliberately authenticated but invalid logical archive proves cleanup. |
| A10-R6-002 | High | Imported password/recovery PHC strings were commitment-authenticated but their Argon2 parameters were not bounded. An archive/key holder could create a valid archive whose later login requested extreme memory or iteration work. | Password verification and restore transformation now structurally require the exact supported Argon2id v1.3 profile, output length, and required fields before invoking the KDF. Regressions reject maximum-width memory and iteration values without performing their work. |
| A10-R6-003 | High | Portable backup exposed the final archive name before its required audit append. Audit rejection attempted best-effort deletion, so a failed call could leave an untracked final artifact; build-audit failure also leaked the encrypted partial. | The fully verified archive remains under its random partial name until the chained backup event commits. Publication then uses no-overwrite hard-link semantics and a directory sync; guarded cleanup removes partial/final paths on every reported failure. An injected audit trigger proves neither name remains. |
| A10-R6-004 | Medium | The SQLite operational snapshot API wrote directly to the final path and returned without explicit file/directory durability. A crash or backup error could leave a partial file that looked complete. | Snapshots now write through a restrictive random same-directory partial using `SQLITE_OPEN_NOFOLLOW`, sync the complete inode, publish without overwrite, remove the partial, and sync the directory. Tests prove readability, no-overwrite behavior, mode, and absence of residual partial names. |
| A10-R6-005 | Medium | The server backup-artifact registry followed an existing final directory symlink and checked only its target mode, weakening the documented custody boundary. | Registry open now uses symlink metadata and requires a real mode-0700 directory owned by the effective service user. A regression rejects a symlink to an otherwise restrictive directory. |

Validation includes clean-host preserve/revoke restore, the committed v1 fixture
and second restore, injected post-staging/audit failures, exact PHC work-factor
bounds, snapshot publication, artifact-custody symlink rejection, strict
all-feature Clippy, and focused application/storage/server suites. No Pass 6
critical/high finding remains open.
