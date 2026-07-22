# Threat and trust model

Status: **Committed baseline**
Last reviewed: 2026-07-22
Required review: every release and any architecture or cryptographic change

## Protected assets

1. Secret values and sensitive metadata.
2. Root keys, KEKs, DEKs, backup keys, recovery material, and application
   credentials.
3. Human authenticators and active sessions.
4. Authorization policies and identity bindings.
5. Secret and policy history.
6. Audit event integrity and availability.
7. Backup confidentiality, integrity, completeness, and restorability.
8. SMCV release and update integrity.

## Adversaries in scope

- An attacker who steals SQLite, WAL, journal, or portable backup files.
- A network attacker who can observe, modify, replay, or redirect traffic.
- An attacker holding one application credential.
- A remote unauthenticated attacker sending malformed or expensive requests.
- A malicious website targeting an authenticated owner's browser.
- An authenticated principal attempting horizontal or vertical privilege
  escalation.
- An operator making an accidental destructive or recovery mistake.
- A compromised dependency, build job, or release channel.
- An attacker with read access to ordinary application logs or metrics.
- A crash, power loss, disk-full event, truncated backup, or corrupt record.

## Adversaries outside the guaranteed protection boundary

SMCV does not promise secret confidentiality against:

- Root or kernel control of the unlocked SMCV host.
- Arbitrary code execution as the SMCV OS user while the vault is unlocked.
- Runtime process inspection with permission to read SMCV memory.
- A malicious authorized client after SMCV legitimately returns plaintext.
- A compromised browser or endpoint displaying a revealed secret.
- Loss of both all valid backups and the required separate recovery material.

The product should still reduce exposure under these conditions through short
plaintext lifetime, least privilege, audit, host hardening, and recovery
practice, but must not describe those controls as complete protection.

## Trust boundaries

### Client to ingress

All client input is untrusted. TLS authenticates the server and protects
transport; it does not make request contents safe. V1 does not trust forwarded
identity or source-address headers. The supported same-host proxy overwrites
forwarding headers, while SMCV derives enforcement identity from its direct
loopback peer and rejects trusted-proxy mode.

### Ingress to domain

Parsed input remains untrusted until it is converted to bounded domain types.
HTTP authentication is not authorization. A handler cannot infer permission
from route possession or UI visibility.

### Domain to SQLite

SQLite is trusted for transactional persistence, not for confidentiality of
protected fields. Database files, indexes, WAL, journals, and backups are
assumed stealable. Integrity-sensitive clear metadata is bound to ciphertext
or checked through domain invariants.

### Domain to key provider

The configured key provider is a high-trust component. It may release or use
root material only for the intended vault identity. Provider configuration and
vault identity must prevent substituting one vault's root key for another.

### Server to browser

The browser is trusted only to display data to the authenticated owner for the
duration requested. No secret or session is placed in persistent browser
storage. Third-party script execution is excluded.

### Server to backup file

The destination filesystem and transport are untrusted for confidentiality.
The archive must authenticate header choices, chunk order, completeness, and
payload before records become usable.

## Primary threats and required controls

| Threat | Required controls |
|---|---|
| Database theft | Application-level AEAD; external root key; encrypted protected metadata; no raw application tokens. |
| Backup theft | Independent archive encryption; memory-hard passphrase KDF or random backup key; no embedded key; opaque public metadata. |
| Ciphertext substitution | Associated data binds vault, record, type, version, and algorithm; integrity failure is fatal for that operation. |
| Compromised app key | Random display-once token; verifier-only storage; exact scopes/actions; expiration; immediate revocation; rate limits; audit. |
| Authorization bypass | Central policy boundary; repository encapsulation; permission-matrix and negative tests; deny by default. |
| Administrative capability granted to service | Closed service-grantable action allowlist; owner-only backup/key/policy/audit/identity/purge actions rejected in service policy schema. |
| Owner-session theft | Secure HTTP-only same-site cookies; CSRF defense; session rotation; idle/absolute expiration; recent-auth checks. |
| XSS and supply-chain script | Contextual output encoding; strict CSP; no third-party runtime assets; dependency review; no secret in persistent web storage. |
| Secret leakage through observability | Non-debuggable secret types; log-field allowlist; redaction tests; no bodies or secret names in telemetry. |
| Brute-force authentication | Argon2id calibration; per-principal and source throttling; bounded work queue; alerts without account enumeration. |
| Replay or duplicate write | TLS; short sessions; idempotency keys where appropriate; expected-version preconditions; nonce uniqueness. |
| Rollback to old DB/backup | Audit restored origin and backup creation time; surface rollback clearly; optional external audit anchor; revoke or rotate after uncertain recovery. |
| Restored clone/split history | Preserve logical vault ID but generate installation ID and recovery epoch; warn against concurrent clones; require decommission/rotation guidance; external anchor for newest-instance claims. |
| Malformed archive DoS | Size/count/depth limits; streaming parser; authenticated manifest; bounded KDF choices; reject duplicate IDs and chunks. |
| Partial restore | Stage into a new database; validate all invariants; atomic activation only after verification; retain failure report without secrets. |
| Disk-full/power loss | Short transactions; durability settings; crash testing; SQLite integrity checks; verified backup/restore drills. |
| Dependency compromise | Minimal dependencies; lockfile; source review for critical crypto/auth/parser crates; vulnerability scanning; SBOM, checksums, and local provenance; optional detached publication signing. |

## Abuse cases that must be tested

1. A read-only identity attempts create, update, history, delete, policy, and
   cross-namespace operations.
2. A write-only identity attempts to infer an existing secret through errors,
   timing, list results, or conditional update behavior.
3. A revoked credential is reused during and after cache windows and server
   restart.
4. An owner is lured into a cross-origin state-changing request.
5. Secret text containing control characters, markup, format strings, and log
   delimiters reaches every error and observability path.
6. Ciphertext, nonce, key version, associated metadata, or wrapped DEK is
   swapped between records.
7. A backup is truncated, extended, reordered, duplicated, downgraded, given
   extreme KDF parameters, or decompressed beyond bounds.
8. Import is interrupted at every stage, including disk full immediately
   before activation.
9. A stale backup restores valid but formerly revoked application access.
10. An attacker enumerates secret existence using status codes, response sizes,
    or timing.
11. A malicious service attempts to place a secret into its name, tags,
    idempotency key, user agent, or other nominal metadata to reach logs.
12. A key rotation is interrupted and resumed with records under multiple key
    versions.
13. Two installations restored from one backup continue accepting the same
    application credential and produce divergent audit epochs.

## Privacy and metadata

Even when secret values are encrypted, names such as `production-payroll` and
access patterns may be sensitive. Protected fields are encrypted; audit and
telemetry use opaque IDs. The system documents unavoidable leakage such as
record counts, approximate ciphertext sizes, timestamps needed for operation,
and access timing. Padding is deferred unless a concrete traffic or size
analysis requirement is established.

## Residual-risk ownership

Every phase evidence report lists newly discovered threats, accepted residual
risks, and decisions. Critical/high unresolved findings remain active repair
work until retested; they do not terminate or pause the long-running goal.
Technical choices follow the safest in-scope documented default without owner
approval. SEC-004 is satisfied for the initial release candidate by final
internal assurance and the owner's recorded D-015 risk acceptance; independent
external assurance follows development.
