# HT-002: real recovery-custody exercise

Status: **Post-development**

Purpose: validate the owner's actual off-host archive and separate recovery-key
custody process using the completed application.

Safe instructions: follow the bundled backup operations guide on an isolated
supported host. Do not record the archive, key, passphrase, secret values, or
private paths here. Destroy the temporary restored vault after verification.

Expected non-secret evidence: exercise date, candidate SHA-256, archive age
class, restore duration, credential mode, success/failure, cleanup confirmation,
and corrective-action references.

Timing: after Phase 6 and before relying on SMCV for real secrets; repeat on the
operator's recovery schedule. Impact if deferred: automated synthetic recovery
is proven, but the owner's real custody chain is not. D-016 explicitly keeps
this personal activity outside development completion.
