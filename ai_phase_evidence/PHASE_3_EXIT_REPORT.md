# Phase 3 exit report

Phase: 3 — portable backup and recovery
Date: 2026-07-21
Status: **Passed; Phase 4 active**
Phase boundary: the local commit containing this report

## Environment and delivered scope

- Linux x86_64 development host
- `rustc 1.94.0 (4a4ef493e 2026-03-02)` and Cargo 1.94.0
- Declared MSRV Rust 1.88
- Bundled SQLite through locked `rusqlite 0.39.0`
- Synthetic temporary vaults, credentials, recovery keys, and sentinels only

Delivered scope includes the documented `.smcvault` v1 format, recovery-key
and Argon2id passphrase modes, protected-FD automation input, safe inspect,
full verification, consistent logical snapshots, clean-host restore with fresh
root/KEK/installation identity, preserve/revoke credential modes, passkey
disable-on-unknown-RP behavior, CLI recovery, durable server jobs, compatibility
fixtures, and guarded final activation.

## Acceptance and requirements evidence

| Requirements / criterion | Evidence and result |
|---|---|
| BACKUP-001–002 | CLI creates a restrictive `.smcvault` using a confirmed terminal passphrase, a checksummed 256-bit generated key, or key bytes from an inherited FD. Server jobs support passphrase and display-once generated-key modes. Key material is absent from headers and durable job status. Phase 4 owns the browser interaction. |
| BACKUP-003–005 | One SQLite read transaction exports namespaces, all secret versions, tombstones, principals/authenticators, services, credential verifiers, policy graph, portable vault-scoped keys, and audit history. Sessions, CSRF, idempotency, maintenance state, source root/KEKs, and raw credentials are excluded. Logical plaintext exists only in zeroizing bounded memory and is written to files only after archive encryption. |
| BACKUP-006 | Public inspect parses only bounded framing. Full verify authenticates the wrapped DEK, every ordered frame, exact EOF, logical framing/counts, digest, and final manifest without opening or mutating a vault. The API and documentation do not claim source-origin authenticity. |
| BACKUP-007–010 | Restore requires absent database/root paths, creates a fresh installation and recovery epoch, atomically imports into guarded staging, re-encrypts every protected envelope, validates graph/commitments/audit, freshly reopens the root provider and all wrapped keys while still non-ready, and activates as the final fallible step. Returned post-staging failures remove database/WAL/SHM/root files. Preserved credentials authenticate; revoke mode invalidates them before activation. |
| BACKUP-011 | `--key-fd` reads at most 4,096 protected bytes from an inherited descriptor. Passphrases and recovery keys have no command-line value option. |
| BACKUP-012 | The published [v1 format](../ai_context_documentation/PORTABLE_ARCHIVE_FORMAT_V1.md), committed fixture, property parser campaign, and negative tests cover hostile lengths/KDFs, wrong key, corruption, truncation, extension, reorder, duplicate, downgrade, and arbitrary complete input. |
| BACKUP-013–014 / AUTHN-006 | Fresh-host restore and owner recovery are local CLI actions; no unauthenticated network restore or ownership route exists. Logical vault ID is preserved while installation ID and epoch change. Source-bound passkeys are revoked pending destination reenrollment. |
| BACKUP-015 | Server artifacts use opaque UUID names, a non-symlink same-owner mode-0700 directory, mode-0600 files, 32-job quota, terminal-artifact 15-minute expiry, explicit delete, and durable download-started/status state. Completion binds size and SHA-256; download revalidates custody and digest on one no-follow descriptor, while a mismatch durably fails/removes the artifact. Pending/running work becomes failed/interrupted on process restart. The operational review renamed the transport observation because an HTTP response cannot prove client-side completion or custody. |
| AUDIT-001–004 | Backup authorization, completed creation, and restoration are chained events. Imported audit history verifies under the portably reprotected audit key; the new restore event uses the destination installation and incremented epoch. |
| SEC-001–003 | Strict all-feature formatting, lint, tests, docs, RustSec, source/license policy, secret scanning, and link checks pass. The Phase 3 adversarial review closed both high findings. |
| PERF-003 | Framing uses 16 KiB–4 MiB chunks, 32 MiB record bounds, 10 million record ceiling, a 256 MiB application logical-stream ceiling (reduced from the provisional Phase 3 ceiling by the ten-pass operational review), an 8 GiB application file ceiling, and a 64 GiB absolute framing ceiling. The 16 MiB/256 KiB multi-frame test completed in 5.16 s wall with a conservative whole-test-process peak RSS of 266,732 KiB in the debug harness. |

## Reproducible validation

```text
./scripts/check.sh
  PASS: rustfmt and strict all-feature Clippy
  PASS: workspace unit, property, integration, failure, and doc tests
  PASS: rustdoc warnings denied
  PASS: RustSec advisory scan and cargo-deny license/source policy
  PASS: exact application-token/private-key repository scan
  PASS: every relative Markdown link resolves

/usr/bin/time -v cargo test -p smcv-backup \
  representative_large_archive_crosses_many_bounded_frames -- --nocapture
  PASS: 16 MiB logical payload, at least 66 total frames
  wall: 5.16 s; maximum RSS: 266,732 KiB (debug test-process upper bound)
```

Focused evidence includes:

- `clean_environment_backup_restore_reencrypts_and_preserves_history`: source
  root/sentinel absence, wrong-key no-destination behavior, logical/version
  equality, new installation/epoch, preserved credential authentication,
  revoke mode, owner password recovery, and audit continuity.
- `interrupted_restore_cannot_be_activated_by_generic_startup`: durable guard,
  wrong activation version, generic-startup rejection, and persistent non-ready
  state.
- `failed_post_staging_restore_removes_all_destination_files`: authenticated but
  semantically invalid input reaches staging and fails without leaving its
  database, WAL/SHM, or root provider.
- `failed_backup_audit_never_publishes_or_leaves_a_partial`: injected audit
  rejection leaves neither a final archive nor an opaque partial.
- `wrong_key_corruption_truncation_and_extension_fail_closed` and
  `reordered_duplicate_and_downgraded_frames_fail_closed`: exact archive
  framing failures.
- `capacity_exhaustion_returns_failure_with_only_encrypted_partial_bytes`:
  injected capacity failures at five output offsets with no plaintext sentinel.
- `arbitrary_headers_never_panic` and `arbitrary_complete_archives_never_panic`:
  property-generated hostile input remains bounded and panic-free.
- `backup_job_survives_request_and_downloads_only_after_verification` and
  `process_restart_durably_fails_an_interrupted_job`: disconnect, status/key
  separation, verified download, and restart behavior.

## Compatibility and recovery drill

The committed `crates/smcv-backup/fixtures/v1-minimal.smcvault` archive has a
synthetic documented recovery key. Both the framing reader and application
restore it. The application then creates a current archive and restores it a
second time, preserving logical vault identity and advancing to recovery epoch
2. Wrong keys create no destination files; post-staging interruption remains
durably non-ready.

CLI recovery walkthrough:

```text
smcv backup-inspect --archive vault.smcvault
smcv backup-verify --archive vault.smcvault
smcv backup-restore --archive vault.smcvault \
  --database NEW_DATA/vault.sqlite --root-key NEW_PROVIDER/root.key
smcv recover-owner --database NEW_DATA/vault.sqlite \
  --root-key NEW_PROVIDER/root.key
```

Prompts and inherited descriptors carry protected input; examples intentionally
contain no real key value. Operators must decommission an old clone and retain
the archive separately from its key.

## Adversarial review and residual ownership

The [Phase 3 adversarial
review](../ai_context_documentation/reviews/PHASE_3_ADVERSARIAL_REVIEW.md)
recorded two high and four medium findings. All high findings and all actionable
Phase 3 medium findings were corrected and regression tested. No critical or
high finding remains.

Phase 4 owns browser custody confirmation, created/downloaded/verified/
restore-tested state language, browser-safe verification and locally authorized
restore interaction, and recovery accessibility. Phase 5 owns supported
capacity/RPO/RTO calibration and platform-specific disk-full/power-loss tests.
Independent external assurance and the owner's personal real-key custody drill
remain the accepted post-development handoff, not a development gate.

## Phase transition

Phase 3 satisfies its backend, CLI, API/job, archive, and clean-recovery gate.
No human task or external dependency is required. Phase 4 may build the complete
same-origin owner interface on these stable archive and job semantics, and the
same long-running goal continues without an approval pause.
