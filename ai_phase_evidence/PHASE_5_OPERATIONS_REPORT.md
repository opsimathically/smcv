# Phase 5 operational campaign

Date: 2026-07-21
Environment: Linux 6.17 x86-64; Intel Core i7-14700KF; 32 GiB RAM; systemd
257; ext4 development workspace
Data: isolated synthetic vaults, credentials, archives, and signing key only

## Production process campaign

```text
/usr/bin/time -v ./scripts/operations-smoke.sh
  preflight=passed
  load_requests=2048
  load_milliseconds=522
  shutdown_seconds=0
  verified_retained=2
  verification_alert=passed
  restore_drill=passed-and-cleaned
  telemetry_sentinel=absent
  elapsed=2.87 s
  maximum resident set=597,332 KiB (debug multi-process upper bound)
```

The same campaign rejected a mode-0644 root provider, unknown `SMCV_*` key,
trusted-proxy setting, HTTP production origin, and misspelled server argument.
It exercised the exact production schema, separate loopback metrics listener,
16-way request load, SIGTERM drain, protected-FD scheduled key, three retention
passes, corrupt-candidate alert, and an isolated restore/reopen/integrity/cleanup
cycle.

`systemd-analyze verify` parsed the service, backup, and timer units; its only
message was the expected absence of the not-yet-installed release binary at
`/usr/local/lib/smcv/smcv-server`. Offline security analysis rated the main
unit 2.7 “OK” and the filesystem-only backup unit 3.0 “OK”.

## Capacity and failure evidence

```text
/usr/bin/time -v cargo test -p smcv-backup \
  representative_large_archive_crosses_many_bounded_frames -- --nocapture
  PASS: 16 MiB payload across at least 66 frames
  elapsed=5.15 s; maximum resident set=236,660 KiB
```

Workspace tests additionally pass injected SQLite disk-full rollback, database
page corruption readiness failure, WAL commit/recovery, busy-writer bounds,
archive short-write cleanup, KDF/header bounds, password-slot saturation,
process restart of interrupted jobs, and backward wall-clock audit sequencing.

## Release envelope

With explicit dirty-envelope test flags, two consecutive builds produced the
same SHA-256. Normal build refused the dirty tree and normal verification
refused dirty provenance. The verifier passed every internal checksum and seven
CycloneDX SBOMs, and an ephemeral RSA test key produced a detached signature
that verified successfully. Synthetic link and traversal tarballs were rejected
before extraction.

After the Phase 5 boundary commit, the same builder/verifier is rerun without
dirty overrides. That clean-commit artifact is the release input; generated
`dist/` output is intentionally ignored and is not a publication action.
