# Phase 6: release candidate and assurance handoff

Status: **Passed 2026-07-21**

## Objective

Challenge the complete product as an attacker, operator, integrator, and owner;
repair findings; freeze compatibility promises; and produce a production-ready
release candidate with evidence sufficient for post-development external
security assurance and later owner-controlled deployment.

Phase 6 completes development. It does not wait for a pilot, external reviewer,
owner sign-off, public publication, production infrastructure, or the owner's
personal recovery-key custody exercise.

## Entry criteria

- Phase 5 exit evidence passes.
- All committed v1 requirements have evidence links.
- Release candidate and supported-platform matrix exist.
- Owner residual-risk acceptance D-015 is recorded.

## In scope

- Full threat-model refresh and abuse-case campaign.
- Final internal adversarial security, privacy, accessibility, operability, and
  recovery assurance.
- End-to-end permission, credential-compromise, browser, hostile-parser, and
  recovery testing.
- Upgrade/rollback and every supported archive/schema compatibility test.
- Clean-host install, total-loss synthetic restore, and incident simulations.
- Performance/capacity verification without lowered security settings.
- Release documentation, security-reporting guidance, support/versioning
  policy, SBOM, provenance, checksums, artifacts, and reproducible commands.
- A self-contained external-assurance handoff package for use after development.

## Out of scope

- Deferred features D-201 through D-206.
- Pilot, beta, early-access, field-trial, adoption, or external-user-validation
  programs.
- Waiting for an independent external reviewer or external review results.
- The owner's personal recovery-key custody exercise.
- Public publication, production deployment, production accounts/domains,
  public certificates, external KMS/HSM, or official signing-identity custody.
- Expanding supported platforms or deployment topologies during candidate
  freeze.

## Work slices

1. Freeze the candidate, compatibility fixtures, toolchains, dependency graph,
   and supported-environment matrix.
2. Execute internal adversarial security, privacy, accessibility, operability,
   and recovery reviews from a fresh-review perspective.
3. Repair and retest findings; refresh the threat model and residual-risk
   register. Critical/high findings remain active work, never accepted merely to
   finish on schedule.
4. Run clean install, upgrade, rollback, synthetic total-loss restore, and
   incident simulations from release artifacts.
5. Complete requirement-to-evidence sampling and verify that public claims do
   not exceed evidence.
6. Produce final artifacts, SBOM, provenance, checksums, release notes, and
   reproducible verification instructions. Use local/synthetic signing where
   useful; official signing identity is a post-development deployment concern.
7. Assemble the external-assurance handoff: architecture, threat model,
   cryptographic decisions, test/fuzz results, dependency inventory, residual
   risks, supported configuration, fixtures, and reviewer reproduction steps.

## Must-fix conditions

The following conditions create repair and retest work inside Phase 6. They do
not halt the long-running goal or require owner permission:

- Any unresolved critical/high security or recovery finding.
- Any committed requirement without evidence.
- Inability to restore a current verified synthetic backup on a clean supported
  host.
- Secret exposure in storage, observability, browser persistence, or artifacts.
- Serious accessibility barrier in a critical owner workflow.
- Untriaged security advisory in a shipped dependency.
- Undocumented key-loss, upgrade, rollback, or incident behavior.

## Acceptance criteria

- Requirements-to-evidence traceability is complete and adversarially sampled.
- All critical/high internal findings are fixed and retested; medium/lower
  residual risks are documented with mitigation and follow-up guidance.
- Archive and schema compatibility fixtures are frozen and reproducible.
- The recovery promise passes from release artifacts using synthetic recovery
  material, not a development checkout or the owner's real custody material.
- WCAG evidence and known limitations are accurate.
- SBOM, provenance, checksums, and verification instructions match the exact
  candidate artifacts without requiring an external signing account.
- Release notes state threat boundaries, supported environments, backup/key
  responsibilities, upgrade compatibility, and D-015 risk acceptance.
- The external-assurance handoff can be used after development without reverse
  engineering the repository or reconstructing missing evidence.
- No phase transition or completion criterion requires owner sign-off, pilot
  results, external review results, or production deployment.

## Required evidence

- Complete requirements traceability matrix with phase-exit links.
- Final internal assurance report and finding-resolution verification.
- Final threat model and residual-risk register.
- Accessibility conformance report and known-limitations statement.
- Release-artifact clean install/upgrade/rollback/synthetic-restore transcripts.
- Incident simulation, performance/capacity, and restore-objective results.
- Artifact/SBOM/provenance/checksum verification bundle.
- External-assurance handoff package.
- Automated confirmation that DELIVERY-001 through DELIVERY-005 remain true.

## Adversarial review prompts

- Which documented security or recovery claim is stronger than the evidence?
- Can an attacker combine individually medium findings into whole-vault access?
- Can a new operator install and recover using only shipped artifacts/docs and
  synthetic separately held keys, without development knowledge?
- Does any compatibility, accessibility, or operational failure become hidden
  by the checklist rather than repaired?
- Did any pilot, owner approval, external account, reviewer, signing identity,
  domain/certificate, or personal custody exercise reenter the critical path?

## Exit gate

Phase 6 closes when its acceptance criteria and evidence pass and all must-fix
conditions have been repaired and retested. The implementing agent records the
phase-close report and marks development complete without further owner
approval. External security assurance, personal recovery custody, publication,
and production deployment occur afterward and may create new iteration goals.
