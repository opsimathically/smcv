# Telemetry, alerts, and supported capacity

Status: **Committed v1 baseline; measurements dated 2026-07-21**

## Disclosure boundary

Production emits structured JSON events from an allowlist. HTTP spans contain
method and matched route template, never raw URI, query, headers, bodies,
cookies, submitted names, or values. Startup summaries redact both custody
directories. Request IDs are returned for correlation but are not protected
material.

The optional metrics server binds independently to loopback. Its vocabulary is
fixed: readiness gauge; aggregate request count; success/client/server response
classes; timeout; rate-limit; readiness check; and readiness failure counters.
It has no vault, installation, actor, credential, object, route, method, source
address, or user-supplied label. The product proxy must not expose this port.

Alert on any readiness failure or integrity error, repeated server-error growth,
request saturation/timeouts, sustained rate limiting, backup timer failure,
verified backup age, restore-drill failure, WAL growth, and disk thresholds.
The backup timer and filesystem monitor supply backup-age and disk signals in
v1; SMCV does not fabricate metrics it cannot observe safely.

## Hard limits

| Resource | V1 bound |
|---|---:|
| Secret payload | 16 MiB |
| Normal JSON request | 1 MiB |
| Browser archive upload / application archive | 8 GiB |
| Absolute framing input | 64 GiB |
| Logical portable stream | 1 GiB |
| Logical archive records | 10,000,000 |
| Archive frame | 16 KiB–4 MiB |
| Concurrent HTTP requests | 128 |
| Concurrent password/KDF jobs | 4 |
| Password attempts per direct peer/minute | 10 |
| Bearer attempts per direct peer/minute | 120 |
| Durable browser backup jobs | 32 |
| Scheduled archive inventory | 4,096 files |

These are rejection bounds, not throughput promises. The reference host was
Linux 6.17 x86-64, Intel Core i7-14700KF, 28 logical CPUs, and 32 GiB RAM. The
16 MiB multi-frame debug test completed in 5.15 seconds with a conservative
whole-test-process peak of 236,660 KiB. A 2,048-request, 16-way liveness campaign
completed in 522 ms without failure, dynamic metric labels, sentinel
disclosure, or a shutdown delay. The complete debug operational workflow took
2.87 seconds with a conservative multi-process peak RSS of 597,332 KiB. Exact
current transcripts are retained in the Phase 5 evidence.

The reference small-vault objective is a daily RPO of 24 hours and a 15-minute
RTO for a verified archive with up to 16 MiB total protected payload on equal or
better hardware. The automated drill is far below that target. Larger vaults up
to parser bounds require operator-specific measurement before making an RTO
claim; the 1 GiB logical ceiling is not a promise that every supported host
restores it within 15 minutes.

Argon2id password and passphrase work uses 64 MiB, three iterations, and one
lane, with four process-wide password slots. Operators must not lower it to
solve saturation; scale ingress/rate limits or hardware after measurement.
