# Security policy

SMCV is under active development and is not yet released for real secrets.

Do not place vulnerability details, live credentials, private keys, recovery
material, or production records in public issues, logs, fixtures, or evidence.
Until the owner publishes a dedicated reporting address, retain a minimal
synthetic reproduction locally and notify the repository owner through an
already trusted private channel. Do not open a public issue for a suspected
vulnerability. The owner should acknowledge a private report within three
business days, provide an initial severity assessment within seven, and
coordinate disclosure only after a fix or explicit risk decision.

Only the newest release candidate is supported before public v1 publication.
After publication, the owner must name supported versions and the private
reporting address before accepting production deployments. A compromised
release key or artifact triggers immediate distribution suspension, SBOM and
provenance comparison, credential rotation, and replacement build under the
[incident runbook](docs/operations/INCIDENT_RUNBOOKS.md).

Security findings remain active implementation work until fixed and retested.
