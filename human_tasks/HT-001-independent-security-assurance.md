# HT-001: independent security assurance

Status: **Post-development**

Purpose: commission an independent review of the complete candidate and turn
its findings into later remediation goals.

Safe instructions: provide the exact candidate artifact and the bundled
`external_assurance/README.md`; use synthetic data and a private reporting
channel. Never place credentials or private findings here.

Expected non-secret evidence: reviewer identity/engagement date, tested commit
and artifact SHA-256, report date, finding IDs/severities, and remediation
tracking references.

Timing: after Phase 6, before a production deployment handling real secrets.
Impact if deferred: the internally assured candidate remains complete but lacks
independent validation; D-015 records the owner's accepted sequencing risk.
