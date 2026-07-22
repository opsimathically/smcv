# Phase 3 portable backup and recovery adversarial review

Status: **Complete; all high findings closed**
Date: 2026-07-21
Scope: archive framing and keys, logical export/import, clean-host authority,
activation, credential behavior, compatibility, CLI input, and server jobs

## Review method

The review traced protected records from one consistent SQLite snapshot through
logical decryption, archive encryption, authenticated parsing, fresh-host key
creation, destination re-encryption, relational and cryptographic verification,
and the final ready marker. It separately reviewed path races, partial writes,
job restart/expiry, key exposure, credential modes, old-format compatibility,
and the absence of a network first-claim route.

Synthetic property inputs, corrupt archives, injected writer exhaustion,
interrupted restore state, a committed v1 fixture, and isolated source and
destination vaults were used. No production key or data was involved.

## Findings and resolutions

| ID | Severity | Finding and failure narrative | Resolution and verification |
|---|---|---|---|
| P3-A01 | High | Generic startup could see a restore-created `initializing` database and activate it after a process interruption, before logical import and verification completed. | Restore bootstrap now creates a durable activation guard in the same transaction. Only the restore-specific final transaction can clear it and mark ready. A regression test proves generic startup and an incorrect activation version both leave the installation `initializing`. |
| P3-A02 | High | Authenticated framing and foreign keys alone did not reject every hostile logical graph. A holder of an archive key could construct namespace cycles, secret-version gaps, invalid policy targets, or owner/service type mismatches and recompute portable commitments. | Pre-activation verification now checks bounded acyclic namespace ancestry, complete version sequences, tombstone conflicts, policy target existence, and owner/service relationships in addition to envelope, state, authorization, audit, and database checks. |
| P3-A03 | Medium | Header inspection and verification checked path metadata before reopening the path, permitting a local replace/symlink race between validation and parsing. | Unix archive reads now open once with `O_NOFOLLOW`, validate metadata from that descriptor, and parse the same descriptor. A symlink rejection regression covers both inspect and full verify. |
| P3-A04 | Medium | An in-flight server backup job needed deterministic process-restart semantics rather than remaining indefinitely `running`. | Safe job status is persisted with restrictive permissions. Startup converts pending/running jobs to durable `failed/interrupted`; the display-once recovery key is never persisted. Restart and browser-disconnect/download tests pass. |
| P3-A05 | Medium | Backup publication and restore audit ordering could otherwise leave success visible before its durable audit or mark a restored vault ready before its new recovery event. | Backup publication is removed if the required audit append fails. Restore imports and appends its new recovery audit before full verification and the guarded activation transaction. |
| P3-A06 | Medium | A source archive path or failed-capacity write could expose a plaintext temporary artifact if lower layers wrote logical bytes before encryption. | The writer accepts only logical input and emits encrypted frames directly to a restrictive new partial file. Injected capacity failures at five offsets contain no sentinel plaintext; failed creation removes the named partial artifact. |

## Corruption and interruption conclusions

- Wrong key, header bounds, KDF extremes, corruption, truncation, extension,
  sequence reorder, duplicate frame, downgrade, unknown frame/critical record,
  count mismatch, and final-manifest mismatch all fail before readiness.
- A valid prefix cannot be accepted because exact EOF, observed frame counts,
  logical digest, byte count, and record count must match the final manifest.
- Failures before authenticated logical decode create no destination. Failures
  after destination creation leave a guarded non-ready installation that
  requires identity-checked cleanup; generic startup cannot claim it.
- The final ready transition and guard removal share one SQLite transaction, so
  interruption cannot commit only one side.
- Server disconnect does not cancel the job. Process interruption is recovered
  as a durable safe failure, and expiry/deletion target only an opaque job UUID.

## Residual limits assigned forward

- The Phase 3 application encoder/decoder uses a zeroizing, bounded logical
  stream buffer with a provisional 1 GiB ceiling. Phase 5 owns supported-size
  calibration and may replace this with incremental record streaming before
  publishing production capacity claims.
- The generated-key API returns key material once and the UI must distinguish
  archive completion, download, custody confirmation, and restore testing.
  Phase 4 owns that state language and browser workflow.
- Real filesystem exhaustion, power-loss, and platform durability campaigns are
  repeated in Phase 5 packaging on each supported filesystem. Phase 3 covers
  injected short writes, SQLite transactional rollback, guarded interruption,
  and exact activation ordering.
- Source-origin signatures are not a v1 promise. Archive-key authentication
  proves integrity and key correctness, not who created the source archive.

## Conclusion

Both high findings were repaired and retested inside Phase 3. No critical or
high finding remains. Browser custody and restore interaction remain Phase 4;
production capacity and platform fault calibration remain Phase 5.
