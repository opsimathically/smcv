# HT-003: signing, publication, and deployment

Status: **Post-development**

Purpose: establish official signing identity custody, trusted distribution,
production domain/certificate, private reporting address, and deployment
approval.

Safe instructions: verify the candidate and independent-review disposition;
create signing material outside the repository; publish only public keys and
checksums; configure the exact supported environment and same-host TLS proxy;
complete preflight and the real recovery exercise. Never store private keys or
credential values in this file.

Expected non-secret evidence: artifact SHA-256, public signing-key fingerprint,
publication location/date, supported-version statement, reporting channel,
preflight result, and deployment decision.

Timing: after development and any owner-required external assurance. Impact if
deferred: no public or production release occurs; the local candidate remains
complete and verifiable.
