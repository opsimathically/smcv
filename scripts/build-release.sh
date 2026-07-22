#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repository/Cargo.toml" | head -n 1)
target=$(rustc -vV | sed -n 's/^host: //p')
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
temporary=$(mktemp -d)
cleanup() {
  rm -f -- "$repository"/crates/*/smcv-release.json
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

bundle="smcv-${version}-${target}"
stage="$temporary/$bundle"
mkdir -p "$stage/bin" "$stage/docs" "$stage/packaging" "$stage/sbom"

cd "$repository"
SOURCE_DATE_EPOCH=$source_epoch cargo build --locked --release --workspace
install -m 0755 target/release/smcv-cli "$stage/bin/smcv-cli"
install -m 0755 target/release/smcv-server "$stage/bin/smcv-server"
cp LICENSE README.md SECURITY.md "$stage/"
cp ai_context_documentation/BACKUP_AND_RECOVERY.md "$stage/docs/"
cp ai_context_documentation/OPERATIONS_AND_SECURITY.md "$stage/docs/"
cp -R packaging/. "$stage/packaging/"
cargo cyclonedx --quiet --manifest-path Cargo.toml --format json --all --override-filename smcv-release
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
  --argjson source_date_epoch "$source_epoch" \
  --argjson working_tree_dirty "$working_tree_dirty" \
  '{schema:$schema,version:$version,target:$target,commit:$commit,source_date_epoch:$source_date_epoch,builder:"local-cargo-locked",working_tree_dirty:$working_tree_dirty,external_signing:false}' \
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
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$source_epoch" -C "$temporary" -cf - "$bundle" | gzip -n > "$archive"
sha256sum "$archive" > "$archive.sha256"

if [ -n "${SMCV_TEST_SIGNING_KEY_FILE:-}" ]; then
  openssl dgst -sha256 -sign "$SMCV_TEST_SIGNING_KEY_FILE" -out "$archive.sig" "$archive"
fi

printf '%s\n' "$archive"
