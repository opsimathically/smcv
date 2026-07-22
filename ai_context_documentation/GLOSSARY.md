# Glossary

- **AEAD:** Authenticated encryption with associated data; provides
  confidentiality and detects unauthorized ciphertext or associated-metadata
  changes.
- **Application credential:** Display-once secret material used by a workload to
  authenticate as a service identity.
- **Backup key:** Key derived from a backup passphrase or generated recovery
  material that protects a portable `.smcvault` archive.
- **DEK:** Data-encryption key used to encrypt one secret version or archive
  payload unit.
- **Effective access:** The actions a principal can actually perform on a
  resource after policy evaluation.
- **KEK:** Key-encryption key used to wrap DEKs.
- **Owner:** The initial human administrator with authority over the vault.
- **Principal:** A human or service identity subject to authorization.
- **Protected field:** Data classified for encryption at rest, including secret
  payload and sensitive human-readable metadata.
- **Root key material:** Highest-level secret used by a configured key provider
  to protect vault KEKs; it is not stored in SQLite.
- **Secret:** Stable logical identity containing metadata and one or more
  immutable versions.
- **Secret version:** Immutable encrypted payload plus integrity-bound metadata.
- **Service identity:** Non-human principal representing one application or
  workload; it can have multiple application credentials.
- **Tombstone:** Durable record that a logical object was deleted, retained to
  prevent silent history loss and identifier reuse.
- **Vault:** One SMCV security and data domain managed by an owner.
