# Release construction and verification

Status: **Committed local release-candidate process**

Run `scripts/build-release.sh` from a clean reviewed commit. It refuses a dirty
tree by default so provenance cannot silently attribute uncommitted code to
`HEAD`. `SMCV_ALLOW_DIRTY_BUILD=1` exists only to test the release envelope and
marks that fact in provenance; normal verification rejects such an artifact.
The builder performs a
locked optimized workspace build, collects the CLI/server, lockfile/toolchain,
API, complete documentation/evidence, and external-assurance handoff, creates
one CycloneDX JSON SBOM per crate, normalizes generated SBOM
time/serial fields to the source epoch, writes local provenance, hashes every
internal file, and creates a sorted owner-normalized gzip tarball. Repeated
builds from the same checkout and source epoch must have the same SHA-256.

The local provenance records version, target, commit, source epoch, Rust/Cargo/
CycloneDX tool versions, exact glibc baseline, OpenSSL builder version, the
bundled lockfile hash, locked Cargo builder, and the fact that no external
signing identity was used. Construction rejects a host other than x86-64 GNU/
Linux with glibc 2.39, and verification rejects missing or different runtime
baseline claims. It is useful evidence,
not a third-party attestation. If `SMCV_TEST_SIGNING_KEY_FILE` names a locally
controlled PEM private key, the builder emits an optional detached test
signature without copying that key into the artifact. A later unsigned build
removes any stale detached signature.

Verify with:

```text
scripts/verify-release.sh dist/smcv-VERSION-TARGET.tar.gz
scripts/verify-release.sh dist/smcv-VERSION-TARGET.tar.gz PUBLIC_KEY.pem
```

Verification requires the adjacent outer checksum and validates a private copy
so a concurrent path replacement cannot change the bytes between checks. When
a public key is supplied, it authenticates that copy before archive parsing or
extraction. The verifier accepts only one expected safe root, regular files and
directories with portable names, complete one-to-one internal checksums, the
locked provenance fields, and all seven SBOM structures. It deliberately does
not execute a binary from the archive. An official publication identity and
public release channel remain owner-controlled post-development work.
