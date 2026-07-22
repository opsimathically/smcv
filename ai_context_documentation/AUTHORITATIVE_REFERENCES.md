# Authoritative references

Status: **Reference baseline**
Last source review: 2026-07-21

Links are preferred over copied guidance. Time-sensitive implementation choices
must recheck current versions at their phase gate.

## Secrets, cryptography, and keys

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [RFC 9106: Argon2](https://datatracker.ietf.org/doc/rfc9106/)

## Authentication, sessions, web, and API

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/B/4/final)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

## Storage and accessibility

- [SQLite write-ahead logging](https://www.sqlite.org/wal.html)
- [SQLite Online Backup API](https://www.sqlite.org/backup.html)
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)

## Supply chain and Rust

- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP Dependency Graph and SBOM Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
- [The Cargo Book](https://doc.rust-lang.org/cargo/)
- [RustSec Advisory Database](https://rustsec.org/)

## Review policy

Phase 0 records exact versions or revisions used for cryptography,
authentication, accessibility, and release assurance. Connector, framework,
crate, and deployment guidance is reverified when selected, not assumed from
this planning snapshot.
