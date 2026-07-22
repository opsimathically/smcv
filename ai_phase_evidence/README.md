# Phase evidence

This directory stores concise, reproducible proof that phase acceptance
criteria were met. Evidence is committed only when it contains no real secret,
credential, private production data, host-sensitive path, or protected
recovery material.

## Required phase-close report

Name reports `PHASE_N_EXIT_REPORT.md`. Include:

1. Phase, date, commit, environment, and tool versions.
2. Acceptance criteria mapped to requirement IDs.
3. Commands or procedures and summarized result.
4. Links to non-sensitive fixtures, test reports, screenshots, or recordings.
5. Failure/restart/recovery observations.
6. Security, accessibility, dependency, and `unsafe` review results.
7. Adversarial findings and resolution references.
8. Compatibility fixtures introduced or retired.
9. Known limitations and residual risks.
10. Human decisions and the next-phase entry recommendation.

## Evidence quality

- Reproducible beats descriptive: name the exact command and input class.
- Include negative and failure behavior, not only successful output.
- Use synthetic sentinel secrets and report presence/absence; never paste
  plaintext sentinel into large public logs unnecessarily.
- Redact by construction. Do not commit an unsafe artifact and rely on manual
  visual redaction.
- Date time-sensitive source and platform checks with calendar dates.
- State `not tested` rather than inferring success.
- A screenshot is evidence of appearance, not authorization or storage safety.

## Review finding format

Use stable IDs and record severity, affected requirement/invariant, exploit or
failure narrative, evidence, disposition, correction, verification, owner, and
date. Critical/high findings must be repaired and retested before phase close;
the same implementation goal remains active throughout that work.

## Documentation-foundation evidence

The pre-implementation documentation goal is recorded separately in
`DOCUMENTATION_FOUNDATION.md` once adversarial reviews and validation finish.
The owner's continuous, non-blocking implementation decisions and the
repository-wide revalidation are recorded in
`CONTINUOUS_IMPLEMENTATION_AMENDMENT.md`.
