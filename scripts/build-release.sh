#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repository/Cargo.toml" | head -n 1)
target=$(rustc -vV | sed -n 's/^host: //p')
required_target=x86_64-unknown-linux-gnu
[ "$target" = "$required_target" ] || {
  echo "v1 release construction supports only $required_target (found $target)" >&2
  exit 1
}
glibc_version=$(getconf GNU_LIBC_VERSION)
[ "$glibc_version" = "glibc 2.39" ] || {
  echo "v1 release construction requires the glibc 2.39 baseline (found $glibc_version)" >&2
  exit 1
}
openssl_version=$(openssl version)
commit=$(git -C "$repository" rev-parse HEAD)
working_tree_dirty=false
if [ -n "$(git -C "$repository" status --porcelain --untracked-files=normal)" ]; then
  working_tree_dirty=true
  if [ "${SMCV_ALLOW_DIRTY_BUILD:-0}" != 1 ]; then
    echo "release builds require a clean working tree; set SMCV_ALLOW_DIRTY_BUILD=1 only for envelope testing" >&2
    exit 1
  fi
fi
source_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repository" log -1 --format=%ct)}
source_timestamp=$(date -u -d "@$source_epoch" '+%Y-%m-%dT%H:%M:%SZ')
rustc_version=$(rustc --version)
cargo_version=$(cargo --version)
cyclonedx_version=$(cargo cyclonedx --version)
cargo_lock_sha256=$(sha256sum "$repository/Cargo.lock" | awk '{print $1}')
temporary=$(mktemp -d)
archive_partial=
cleanup() {
  rm -f -- "$repository"/crates/*/smcv-release.json
  if [ -n "$archive_partial" ]; then
    rm -f -- "$archive_partial"
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

bundle="smcv-${version}-${target}"
stage="$temporary/$bundle"
mkdir -p "$stage/bin" "$stage/packaging" "$stage/sbom" "$stage/scripts"

cd "$repository"
SOURCE_DATE_EPOCH=$source_epoch cargo build --locked --release --workspace
install -m 0755 target/release/smcv-cli "$stage/bin/smcv-cli"
install -m 0755 target/release/smcv-server "$stage/bin/smcv-server"
cp Cargo.lock Cargo.toml CONTRIBUTING.md deny.toml LICENSE README.md SECURITY.md rust-toolchain.toml "$stage/"
cp -R ai_context_documentation ai_design_guidelines ai_phase_evidence ai_phased_plans api docs external_assurance "$stage/"
cp -R packaging/. "$stage/packaging/"
cp scripts/build-release.sh scripts/release-candidate-smoke.sh scripts/verify-release.sh "$stage/scripts/"
cargo cyclonedx --quiet --manifest-path Cargo.toml --format json --all --override-filename smcv-release
[ "$(sha256sum "$repository/Cargo.lock" | awk '{print $1}')" = "$cargo_lock_sha256" ] || {
  echo "SBOM generation changed the locked dependency graph" >&2
  exit 1
}
for crate in smcv-app smcv-backup smcv-cli smcv-core smcv-crypto smcv-server smcv-storage; do
  cp "crates/$crate/smcv-release.json" "$stage/sbom/$crate.cdx.json"
  jq --arg timestamp "$source_timestamp" 'del(.serialNumber) | .metadata.timestamp = $timestamp' \
    "$stage/sbom/$crate.cdx.json" > "$stage/sbom/$crate.cdx.json.normalized"
  mv "$stage/sbom/$crate.cdx.json.normalized" "$stage/sbom/$crate.cdx.json"
done

jq -n \
  --arg schema "smcv.local-provenance.v1" \
  --arg version "$version" \
  --arg target "$target" \
  --arg commit "$commit" \
  --arg rustc_version "$rustc_version" \
  --arg cargo_version "$cargo_version" \
  --arg cyclonedx_version "$cyclonedx_version" \
  --arg glibc_version "$glibc_version" \
  --arg openssl_version "$openssl_version" \
  --arg cargo_lock_sha256 "$cargo_lock_sha256" \
  --argjson source_date_epoch "$source_epoch" \
  --argjson working_tree_dirty "$working_tree_dirty" \
  '{schema:$schema,version:$version,target:$target,commit:$commit,source_date_epoch:$source_date_epoch,builder:"local-cargo-locked",rustc_version:$rustc_version,cargo_version:$cargo_version,cyclonedx_version:$cyclonedx_version,glibc_version:$glibc_version,openssl_version:$openssl_version,cargo_lock_sha256:$cargo_lock_sha256,working_tree_dirty:$working_tree_dirty,external_signing:false}' \
  > "$stage/PROVENANCE.json"

(
  cd "$stage"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
    sha256sum "$file"
  done > SHA256SUMS
)

find "$stage" -exec touch -h -d "@$source_epoch" {} +
mkdir -p "$repository/dist"
archive="$repository/dist/$bundle.tar.gz"
archive_partial=$(mktemp "$repository/dist/.$bundle.tar.gz.XXXXXX")
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$source_epoch" -C "$temporary" -cf - "$bundle" | gzip -n > "$archive_partial"
chmod 0644 "$archive_partial"
mv -f -- "$archive_partial" "$archive"
archive_partial=
(
  cd "$(dirname -- "$archive")"
  sha256sum "$(basename -- "$archive")" > "$(basename -- "$archive.sha256")"
)

if [ -n "${SMCV_TEST_SIGNING_KEY_FILE:-}" ]; then
  openssl dgst -sha256 -sign "$SMCV_TEST_SIGNING_KEY_FILE" -out "$archive.sig" "$archive"
else
  rm -f -- "$archive.sig"
fi

printf '%s\n' "$archive"
