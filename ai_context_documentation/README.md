# SMCV durable context index

These documents define product intent and the implementation constraints that
survive individual work sessions. Decision status is governed by
`DECISION_REGISTER.md`.

## Product and decisions

- [Project charter](PROJECT_CHARTER.md)
- [Product requirements](PRODUCT_REQUIREMENTS.md)
- [Decision register](DECISION_REGISTER.md)
- [Glossary](GLOSSARY.md)

## Architecture and security

- [System architecture](SYSTEM_ARCHITECTURE.md)
- [Threat and trust model](THREAT_AND_TRUST_MODEL.md)
- [Cryptography and key management](CRYPTOGRAPHY_AND_KEY_MANAGEMENT.md)
- [Data model](DATA_MODEL.md)
- [Identity and authorization model](AUTHORIZATION_MODEL.md)
- [API design](API_DESIGN.md)
- [Backup and recovery](BACKUP_AND_RECOVERY.md)
- [Operations and security](OPERATIONS_AND_SECURITY.md)
- [Security assurance](SECURITY_ASSURANCE.md)

## Reviews and references

- [Security adversarial review](reviews/SECURITY_ADVERSARIAL_REVIEW.md)
- [Operability, scope, and recovery review](reviews/OPERABILITY_SCOPE_RECOVERY_REVIEW.md)
- [Review resolution log](reviews/REVIEW_RESOLUTION_LOG.md)
- [Authoritative references](AUTHORITATIVE_REFERENCES.md)

## Update rules

Update these documents in the same change when implementation alters an
invariant, public behavior, threat, persisted format, recovery procedure, or
committed decision. Time-sensitive recommendations include a review date.
