# SMCV

SMCV (Secret Manager and Credentials Vault) is a security-first, self-hosted
vault written in Rust. It gives people a polished web interface for managing
encrypted secrets and gives applications narrowly scoped, revocable API
access to only the secrets and operations they require.

The current code contains the encrypted vault core, authenticated `/api/v1` surface, portable backup/recovery tooling, owner web interface, selective physical-safe printing, native local-lab HTTPS and Linux operational packaging. Public publication, production deployment, independent security assurance and real recovery-key custody exercises remain separate activities.

## Committed product direction

- Rust implementation with a web UI and versioned application API.
- SQLite as the initial single-node source of truth.
- Application-level authenticated encryption for sensitive vault data.
- Root encryption material stored separately from the database.
- Deny-by-default, fine-grained permissions for application identities.
- Immutable secret versions, lifecycle controls, and security auditing.
- Easy creation, verification, and restoration of portable encrypted vault
  backup files.
- Selective owner-only preparation of transient printable physical-safe copies.
- Optional direct local-lab HTTPS with a persistent generated self-signed
  identity or operator-supplied CA certificate.
- Accessible, calm, and trustworthy product design.

## Documentation

- [Linux deployment guide](docs/operations/DEPLOYMENT.md)
- [Native local-lab HTTPS](docs/operations/LAB_HTTPS.md)
- [Backup operations](docs/operations/BACKUP_AND_RECOVERY_OPERATIONS.md)
- [Physical-safe copies](docs/operations/PHYSICAL_SAFE_COPIES.md)
- [Upgrade and rollback](docs/operations/UPGRADE_AND_ROLLBACK.md)
- [Incident runbooks](docs/operations/INCIDENT_RUNBOOKS.md)
- [Supported platform](docs/SUPPORTED_PLATFORMS.md)
- [Release notes](docs/RELEASE_NOTES_0.1.0.md)


## Local verification

Run the repository checks with:

```sh
./scripts/check.sh
```

The clean candidate boundary also runs `./scripts/final-release-gate.sh`, which checks the local release artifact. These commands do not publish or deploy the application. Use synthetic data for all local verification.
