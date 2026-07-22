# Operability, scope, and recovery adversarial review

Review date: 2026-07-21
Review target: pre-implementation documentation draft
Status: **Complete — findings applied and verified in documentation**

## Method

The review adopted four skeptical perspectives: a new operator with only the
docs, an implementer optimizing for phase completion, an owner after total host
loss, and a maintainer supporting upgrades for years. It looked for ambiguous
ownership, impossible phase gates, hidden configuration, unbounded retention,
and features whose dependencies occur in later phases.

## Findings

### OPS-AR-001 — Phase 3 claimed a web requirement before the web phase

Severity: **High**
Affected: BACKUP-001, Phase 3, Phase 4

Phase 3 excludes the completed web UI but its exit gate claimed all of
BACKUP-001 through BACKUP-012. BACKUP-001 requires both UI and CLI. An
implementer could either violate scope or falsely close the requirement.

Required correction: Phase 3 completes archive/domain/CLI/API portions and
Phase 4 completes the web portion. Split evidence explicitly without splitting
the durable requirement ID.

### OPS-AR-002 — Fresh restore authority was unclear

Severity: **High**
Affected: BACKUP-007, Phase 3 critical flow

A new empty installation has no authenticated owner session, so an
“authenticated restore API” cannot safely authorize total-loss recovery. A
network bootstrap route would create a severe takeover race.

Required correction: make the local CLI the authoritative fresh-restore entry,
or use a local-only single-use setup channel created by it. The later web flow
may guide a locally authorized restore but cannot create unauthenticated remote
authority.

### OPS-AR-003 — “Configuration” in portable backup was ambiguous

Severity: **Medium**
Affected: BACKUP-003, archive contents

Including configuration could mean either portable vault semantics or
host-bound TLS paths, proxy trust, bind addresses, and key-provider locations.
Restoring host configuration blindly is unsafe and non-portable.

Required correction: include only portable vault policy/security semantics;
exclude host paths, network/TLS/proxy, runtime limits, and source key-provider
locations. Produce a safe report of settings requiring destination setup.

### OPS-AR-004 — Logical identity across recovery was undefined

Severity: **Medium**
Affected: backup comparison, audit, operational recovery

It was unclear whether restore preserves or changes the vault ID. Either choice
affects associated data, credential continuity, external client configuration,
and audit provenance.

Required correction: preserve logical vault ID for recovery, generate new
installation ID/recovery epoch, and re-encrypt destination envelopes with the
preserved logical ID plus new cryptographic key versions.

### OPS-AR-005 — Retention and growth were underdefined

Severity: **Medium**
Affected: immutable versions, audit, local jobs, SQLite capacity

Immutable versions and audit events can grow indefinitely; downloadable
backups and failed staging areas add more disk pressure. Automatic deletion
would violate history expectations, but ignoring growth harms availability.

Required correction: v1 retains versions/audit until explicit policy/action,
never silently purges, publishes capacity limits and disk alerts, and defines
cleanup for ephemeral encrypted artifacts and failed staging directories.

### OPS-AR-006 — Recovery performance appears only near release

Severity: **Medium**
Affected: PERF-003, Phase 3, Phase 5

Waiting until Phase 5 to establish all recovery objectives could reveal too
late that archive framing or import transactions cannot meet usable recovery
times.

Required correction: Phase 3 sets representative archive-size/count and
provisional restore-time/memory targets; Phase 5 validates production capacity
and formal RPO/RTO.

### OPS-AR-007 — Browser-close and job-retention semantics needed completion

Severity: **Medium**
Affected: web backup flow, API jobs, operations

The draft noted ambiguity but did not specify whether server jobs survive
browser disconnect, how the owner retrieves results, or when encrypted
artifacts expire.

Required correction: durable bounded job state survives disconnect, exposes
safe resume/status, uses quotas and expiry, and reports success only after
verification. Cancellation semantics state whether work stops or merely
detaches the client.

### OPS-AR-008 — First-backup initialization spans later phases

Severity: **Low**
Affected: initialization operations, phase sequencing

Phase 1 builds initialization before portable backup exists in Phase 3. The
draft allows explicit deferral but could confuse intermediate phase evidence.

Required correction: state that "initialization operationally complete" is a
release behavior assembled in Phase 3/4; Phase 1 proves cryptographic readiness
without claiming the complete owner journey.

### OPS-AR-009 — Technology choices were appropriately not frozen

Severity: **Informational**

The draft correctly defers exact crates, AEAD, web framework, and UI technology
to Phase 0 evidence. Freezing them in planning would create false confidence.

### OPS-AR-010 — Restore verification needed a usable representative scale

Severity: **Medium**
Affected: Phase 3 acceptance

Clean restore correctness at tiny fixture scale does not demonstrate a useful
product. Conversely, unbounded goals would prevent delivery.

Required correction: define bounded representative small and large fixtures in
Phase 3, record peak memory/disk/time, and carry measured limits into Phase 5.

## Positive observations

- Deferred scope is unusually explicit and protects the single-node design.
- Merge import is correctly excluded rather than underspecified.
- Phase gates demand failure/restart and compatibility evidence.
- Backup is treated as a user workflow and recovery promise, not a database-copy
  footnote.

## Verification plan

Resolve findings across requirements, backup, data, operations, user flows, and
phase gates; then validate phase ownership and requirement coverage again.

## Verification result

All actionable findings are closed in the documentation. Backup ownership is
now split honestly between Phase 3 backend/CLI/API and Phase 4 web work; fresh
restore is locally authorized; host configuration is excluded from portable
state; vault/installation/epoch identity is explicit; history retention and
ephemeral cleanup are defined; Phase 3 records provisional recovery capacity;
job disconnect/expiry behavior is specified; and the initialization phase note
prevents premature completion claims. The traceability matrix assigns final
verification ownership for all 63 requirements.
