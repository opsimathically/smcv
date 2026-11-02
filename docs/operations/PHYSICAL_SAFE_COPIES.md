# Physical-safe copies

Status: **Owner workflow**
Last reviewed: 2026-07-22

## Purpose and boundary

`Physical copies` prepares a selected set of active current secret values for
the browser print dialog. The resulting pages are plaintext custody material
for an owner-controlled physical safe. They are not a complete vault backup,
may omit records intentionally, and become stale when a printed secret changes.

Use a portable encrypted `.smcvault` archive plus its separately retained key
for complete disaster recovery. Do not substitute selective paper for the
documented backup and restore process.

SMCV controls selection, recent authentication, server response lifetime, and
the in-page plaintext lifetime. It cannot erase or verify copies retained by:

- Paper, labels, photographs, or scans.
- A printer, print server, spooler, or device storage.
- Browser print preview or operating-system preview services.
- A user-selected `Save as PDF` or other file destination.
- Endpoint screenshots, accessibility tooling, malware, or a compromised
  unlocked host.

## Prepare a printout

1. Sign in to the owner web interface and open `Physical copies`.
2. Search protected metadata or move through the paginated active-secret
   inventory. Search does not inspect secret values.
3. Select individual rows. Selection remains visible in the count when a
   record is hidden by another page or search. At most 50 records may be
   prepared in one request.
4. Choose `Review selected secrets`. Confirm the exact names, namespace paths,
   and current versions. Remove anything that should not leave encrypted vault
   custody.
5. Acknowledge the plaintext warning and enter the owner password. SMCV rotates
   this browser session, revokes the previous session, then validates every
   secret and its full namespace revision path.
6. Review the transient output and choose `Open print dialog`. Select the
   intended physical printer and inspect the browser preview for page breaks,
   long values, and the expected record count before committing the job.
7. Collect every page immediately, check the printer and spool policy, and put
   the pages in the intended safe. Destroy superseded physical copies using an
   appropriate sensitive-document process.

SMCV removes its rendered plaintext when the print dialog closes or is
cancelled, when the page loses visibility or navigates, when the session is
locked, when `Discard plaintext` is selected, or after five minutes. This
clearing does not reach downstream printer or file systems.

## Accuracy and limits

- Only active current versions are eligible; archived, deleted, and historical
  versions are excluded.
- The request contains 1–50 unique opaque IDs in its JSON body and is limited
  to 2 MiB of decrypted values plus protected identifying metadata.
- A secret version/revision or any root-to-leaf namespace ID/revision mismatch
  rejects the whole response. Reload, search, select, and review again.
- A successful response preserves the reviewed request order and identifies
  each record with authenticated namespace path, name, current version,
  optional metadata, value encoding, and an absolute preparation time.
- Every selected opaque secret ID receives correlated audit evidence. Values,
  protected names, namespace paths, and search text are not written to audit.
- SMCV can only state that plaintext was prepared. It cannot prove that a
  printer completed a job or that the pages reached a safe.

## Custody incident

If pages, a saved PDF, printer storage, or spool custody may be compromised,
treat every included value as disclosed. Identify the printed records from the
physical copy and correlated activity time, rotate each secret in its upstream
system, append the replacement value to SMCV, revoke affected application or
owner credentials when relevant, and record the incident through the operator's
normal process. Re-encrypting or deleting an SMCV record does not revoke the
credential in its upstream system or erase downstream physical copies.
