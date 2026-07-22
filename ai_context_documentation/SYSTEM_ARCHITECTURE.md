# System architecture

Status: **Committed architecture; proposed component details**
Last reviewed: 2026-07-21

## Architecture summary

SMCV begins as one deployable Rust service and one administrative CLI. The
service is a modular monolith: modules share a process but interact through
explicit domain interfaces so security decisions are not scattered among HTTP
handlers, SQL queries, or UI code.

```text
Browser ─ HTTPS ─┐
                 ├─ Ingress adapters ─ Application services ─ Domain core
Workload ─ HTTPS ┘       │                       │                │
Admin CLI ─ local/API ───┘                       │                │
                                                 ├─ Policy engine │
                                                 ├─ Audit service │
                                                 └─ Vault crypto ─┤
                                                                  │
                                     SQLite adapter ──────────────┤
                                     Key-provider adapter ────────┤
                                     Clock/randomness ─────────────┘
```

## Domain boundaries

### Identity and session

Authenticates owners and service identities, manages server-side sessions and
application credential verifiers, and returns a principal plus authentication
context. It does not decide resource access.

### Authorization

Evaluates principal, action, resource, and request context against durable
grants. All protected application services call this boundary before reading
or mutating protected state. Adapters cannot bypass it with direct repository
access.

### Vault

Owns secret identity, immutable versions, lifecycle metadata, encryption and
decryption requests, concurrency rules, and redacted return types. Plaintext
types must not implement accidental debug or display formatting.

### Backup and recovery

Owns archive format, safe inspection, authentication, compatibility checks,
streaming export/import, transactional staging, and restore reports. It calls
the vault boundary for cryptographic transformations rather than reaching into
key-provider internals.

Fresh-host restore authority originates only from the local CLI or a
CLI-created single-use local channel. No unauthenticated network route may turn
an empty installation into a remotely claimable vault.

### Audit

Receives structured security events from application services and writes them
in the same transaction as the state change when atomic accountability is
required. Audit failure fails closed for protected mutations and value access.

### Persistence

Implements repositories and transaction orchestration over SQLite. SQL rows
contain ciphertext and safe indexing metadata, never domain plaintext objects.

### Operations

Owns configuration validation, readiness, migrations, maintenance locks,
backup scheduling hooks, telemetry redaction, and graceful shutdown.

## Dependency direction

The domain core depends on interfaces for persistence, cryptography, clock,
randomness, and audit output. Concrete web, SQLite, and key-provider adapters
depend inward on those interfaces. The domain must be testable with in-memory
fakes without starting HTTP or opening SQLite.

Circular dependencies are prohibited. Shared crates or modules may contain
opaque identifiers, error categories, secrecy-preserving value wrappers, and
bounded input types, but not convenience access that bypasses authorization.

## Deployable processes

### SMCV server

- Serves same-origin web assets and `/api/v1`.
- Holds the unlocked vault KEK only while running and ready.
- Uses a bounded database connection pool and bounded blocking workers for
  SQLite, password hashing, archive encryption, and other CPU/blocking work.
- Supports one active instance per SQLite vault in v1.
- Gives long-running backup/restore jobs durable bounded state so a browser
  disconnect does not change completion semantics; encrypted download artifacts
  have quotas and expiry.

### SMCV CLI

- Initializes and diagnoses a local installation.
- Creates, verifies, inspects, and restores backups.
- Performs explicit maintenance and key operations.
- Prompts for secrets using protected terminal input; secret inputs are not
  accepted in command arguments.

The CLI may use local files during pre-start recovery or authenticate through
the API for online operations. Each command documents which mode applies.

## Principal request flow

1. Ingress assigns a random request ID and enforces connection, header, body,
   and timeout bounds.
2. Authentication produces a principal and safe credential reference or
   rejects uniformly.
3. Input is parsed into bounded domain types.
4. The application service asks authorization for one explicit action and
   resource.
5. The service performs its transaction, including the audit event where
   required.
6. Secret-bearing responses receive cache-prevention headers and are excluded
   from response-body logging.
7. Plaintext objects are dropped and zeroized on a best-effort basis as soon as
   the response has been produced.

## Write and concurrency model

- SQLite remains the sole durable writer in v1.
- Mutations use short explicit transactions.
- Secret updates require an expected current version or ETag.
- Idempotency records protect retried create operations where duplicate effects
  would be harmful.
- Long cryptographic work happens outside a write transaction when safe; the
  final commit rechecks preconditions.
- Administrative maintenance uses a durable maintenance mode or lease so
  backup restore, migration, and key rotation cannot interleave unsafely.

## Deployment model

The supported production topology is:

- One server process under a dedicated unprivileged OS account.
- SQLite, WAL, and key-provider material on local protected storage.
- TLS in the server or a carefully configured same-host reverse proxy.
- No shared network filesystem and no multiple active servers against one DB.
- Off-host encrypted backups and, optionally, an external append-only audit
  sink.

Loopback HTTP may be enabled explicitly for development. Binding plaintext HTTP
to a non-loopback address is rejected by default.

## Failure posture

- Missing or invalid root key: remain unready; do not serve protected routes.
- Unsupported schema or archive version: stop before mutation.
- Database busy: bounded retry with jitter, then a safe unavailable response.
- Audit write failure: fail protected value access or state mutation.
- Randomness failure: fail closed.
- Corrupt ciphertext or associated data: return a generic integrity error,
  audit it, and never return partial plaintext.
- Disk full: roll back the active transaction and surface actionable safe
  diagnostics.
- Panic: prevent secret-bearing panic formatting, terminate the affected
  process, and rely on the supervisor to restart; never continue with uncertain
  cryptographic state.

## Evolution

Adapters and domain ports permit a future PostgreSQL repository, external KMS,
OIDC identity provider, remote audit sink, or separated backup worker. None of
those abstractions authorize building distributed behavior during v1.
