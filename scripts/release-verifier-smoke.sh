#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
marker="$temporary/executed-untrusted-binary"

make_fixture() {
  version=$1
  root="$temporary/smcv-$version-x86_64-unknown-linux-gnu"
  mkdir -p "$root/bin" "$root/docs" "$root/external_assurance" \
    "$root/ai_phase_evidence" "$root/sbom"
  printf '#!/bin/sh\ntouch %s\n' "$marker" > "$root/bin/smcv-cli"
  chmod 0755 "$root/bin/smcv-cli"
  printf 'synthetic locked graph\n' > "$root/Cargo.lock"
  printf '# Synthetic release notes\n' > "$root/docs/RELEASE_NOTES_0.1.0.md"
  printf '# Synthetic handoff\n' > "$root/external_assurance/README.md"
  printf '# Synthetic traceability\n' > "$root/ai_phase_evidence/FINAL_REQUIREMENTS_TRACEABILITY.md"
  for crate in smcv-app smcv-backup smcv-cli smcv-core smcv-crypto smcv-server smcv-storage; do
    jq -n '{bomFormat:"CycloneDX",components:[{name:"synthetic"}]}' > "$root/sbom/$crate.cdx.json"
  done
  lock_sha=$(sha256sum "$root/Cargo.lock" | awk '{print $1}')
  jq -n --arg version "$version" --arg lock "$lock_sha" \
    '{schema:"smcv.local-provenance.v1",version:$version,target:"x86_64-unknown-linux-gnu",commit:"0000000000000000000000000000000000000000",source_date_epoch:1,builder:"local-cargo-locked",rustc_version:"synthetic",cargo_version:"synthetic",cyclonedx_version:"synthetic",glibc_version:"glibc 2.39",openssl_version:"OpenSSL 3.synthetic",cargo_lock_sha256:$lock,working_tree_dirty:false,external_signing:false}' \
    > "$root/PROVENANCE.json"
  (
    cd "$root"
    find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
      sha256sum "$file"
    done > SHA256SUMS
  )
}

pack_fixture() {
  version=$1
  archive="$temporary/smcv-$version-x86_64-unknown-linux-gnu.tar.gz"
  tar -C "$temporary" -czf "$archive" "smcv-$version-x86_64-unknown-linux-gnu"
  (
    cd "$temporary"
    sha256sum "$(basename -- "$archive")" > "$(basename -- "$archive.sha256")"
  )
}

make_fixture 9.9.9
pack_fixture 9.9.9
private_key="$temporary/signing-private.pem"
public_key="$temporary/signing-public.pem"
wrong_private_key="$temporary/wrong-private.pem"
wrong_public_key="$temporary/wrong-public.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$private_key" 2>/dev/null
openssl pkey -in "$private_key" -pubout -out "$public_key" 2>/dev/null
openssl dgst -sha256 -sign "$private_key" \
  -out "$temporary/smcv-9.9.9-x86_64-unknown-linux-gnu.tar.gz.sig" \
  "$temporary/smcv-9.9.9-x86_64-unknown-linux-gnu.tar.gz"
"$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.9-x86_64-unknown-linux-gnu.tar.gz" "$public_key" >/dev/null
[ ! -e "$marker" ]

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$wrong_private_key" 2>/dev/null
openssl pkey -in "$wrong_private_key" -pubout -out "$wrong_public_key" 2>/dev/null
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.9-x86_64-unknown-linux-gnu.tar.gz" "$wrong_public_key" >/dev/null 2>&1; then
  echo "release verifier accepted the wrong signature key" >&2
  exit 1
fi
[ ! -e "$marker" ]

make_fixture 9.9.8
printf 'unlisted payload\n' > "$temporary/smcv-9.9.8-x86_64-unknown-linux-gnu/unlisted"
pack_fixture 9.9.8
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.8-x86_64-unknown-linux-gnu.tar.gz" >/dev/null 2>&1; then
  echo "release verifier accepted an unlisted file" >&2
  exit 1
fi

make_fixture 9.9.7
ln -s Cargo.lock "$temporary/smcv-9.9.7-x86_64-unknown-linux-gnu/link"
pack_fixture 9.9.7
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.7-x86_64-unknown-linux-gnu.tar.gz" >/dev/null 2>&1; then
  echo "release verifier accepted a link" >&2
  exit 1
fi

make_fixture 9.9.6
pack_fixture 9.9.6
rm "$temporary/smcv-9.9.6-x86_64-unknown-linux-gnu.tar.gz.sha256"
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.6-x86_64-unknown-linux-gnu.tar.gz" >/dev/null 2>&1; then
  echo "release verifier accepted a missing outer checksum" >&2
  exit 1
fi

make_fixture 9.9.5
pack_fixture 9.9.5
printf 'unexpected checksum content\n' >> \
  "$temporary/smcv-9.9.5-x86_64-unknown-linux-gnu.tar.gz.sha256"
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.5-x86_64-unknown-linux-gnu.tar.gz" >/dev/null 2>&1; then
  echo "release verifier accepted malformed outer checksum content" >&2
  exit 1
fi

make_fixture 9.9.4
jq '.glibc_version = "glibc 2.40"' \
  "$temporary/smcv-9.9.4-x86_64-unknown-linux-gnu/PROVENANCE.json" \
  > "$temporary/provenance-wrong-baseline.json"
mv "$temporary/provenance-wrong-baseline.json" \
  "$temporary/smcv-9.9.4-x86_64-unknown-linux-gnu/PROVENANCE.json"
(
  cd "$temporary/smcv-9.9.4-x86_64-unknown-linux-gnu"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
    sha256sum "$file"
  done > SHA256SUMS
)
pack_fixture 9.9.4
if "$repository/scripts/verify-release.sh" \
  "$temporary/smcv-9.9.4-x86_64-unknown-linux-gnu.tar.gz" >/dev/null 2>&1; then
  echo "release verifier accepted an unsupported glibc baseline" >&2
  exit 1
fi

printf 'signed_archive_not_executed=passed\nwrong_signature_key=passed\nunlisted_file=passed\nlink_member=passed\nmissing_outer_checksum=passed\nmalformed_outer_checksum=passed\nwrong_glibc_baseline=passed\n'
