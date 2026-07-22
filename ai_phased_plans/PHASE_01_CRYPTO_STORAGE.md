# Phase 1: encrypted vault and storage core

Status: **Active implementation phase**

## Objective

Deliver a tested domain and SQLite core that stores only protected secret data,
preserves immutable history, manages key versions safely, and survives expected
failure/restart cases without an external API.

## Entry criteria

- Phase 0 exit evidence passes.
- D-101, D-102, D-103, and D-107 resolved.
- Exact cryptographic and SQLite decisions reviewed.

## In scope

- Vault initialization state machine and v1 root-key providers.
- Schema, forward migrations, explicit SQLite settings, and repositories.
- Vault/KEK/DEK hierarchy and authenticated record envelopes.
- Encrypted protected metadata and exact lookup strategy.
- Namespace, secret, immutable version, archive/delete/tombstone, and explicit
  owner-only purge/retention domain model.
- Optimistic concurrency and bounded idempotent writes.
- Append-oriented audit persistence and documented local tamper-evidence limit.
- Resumable KEK/root-provider rotation.
- Local operational SQLite snapshots for maintenance only.

This phase proves initialization mechanics but does not claim the complete
first-backup owner journey, which is assembled after portable backup and web
work in Phases 3 and 4.

## Out of scope

- Network API, owner login, service credentials, policy engine, portable
  `.smcvault` backup, and web UI.

## Work slices

1. Schema/migration harness and SQLite configuration.
2. Key-provider and initialization state machine.
3. Record envelope, protected metadata, and corruption tests.
4. Namespace/secret/version repositories and domain services.
5. Audit transaction integration.
6. Key rotation with checkpoint/restart.
7. Crash, corruption, and migration compatibility campaign.

## Acceptance criteria

- A stolen database/WAL fixture contains no synthetic protected-field sentinel.
- Swapping or modifying every envelope component fails authentication without
  partial plaintext.
- Secret updates are append-only and stale concurrent updates cannot overwrite.
- Purge follows explicit retention and audit rules and never presents physical
  current-vault deletion as erasure from backups or storage media.
- Policy-independent repository APIs cannot return plaintext without an
  explicit vault-domain decrypt call suitable for later authorization wrapping.
- Initialization interruption at each durable step safely resumes or clearly
  requires cleanup; it never reports ready early.
- Key rotation interrupted at any checkpoint resumes with all records readable
  under allowed key versions and new writes using the active version.
- Database corruption, busy, disk-full, and audit failure produce defined
  rollback behavior and redacted diagnostics.
- Migrations are tested from every Phase 1 schema fixture.

## Required evidence

- Known-answer and record-substitution results.
- Database/WAL sentinel scan.
- Concurrency and append-only tests.
- Crash/failure injection matrix.
- Key-rotation restart transcript and inventory.
- Migration and SQLite integrity results.
- Focused cryptography/storage adversarial review and resolutions.

## Adversarial review prompts

- Can any protected sentinel enter SQLite, WAL, journals, indexes, or migration
  scratch state as plaintext?
- Can record/key/metadata substitution authenticate under another identity?
- Can interruption select the wrong active key or make initialization ready
  before all invariants hold?
- Can purge, migration, or cascade silently remove immutable/audit history?

## Exit gate

VAULT-001 through VAULT-007 and applicable audit/storage requirements pass at
the domain/storage boundary; no high finding remains; persisted fixtures are
frozen for compatibility testing.
