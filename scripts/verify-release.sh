#!/bin/sh
set -eu

archive=${1:?usage: verify-release.sh ARCHIVE [PUBLIC_KEY]}
public_key=${2:-}
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

if [ -f "$archive.sha256" ]; then
  (cd "$(dirname -- "$archive")" && sha256sum -c "$(basename -- "$archive.sha256")")
fi

tar -tzf "$archive" | while IFS= read -r member; do
  case "$member" in
    /*|..|../*|*/../*|*/..) echo "unsafe archive member" >&2; exit 1 ;;
  esac
done
if tar -tvzf "$archive" | awk '$1 ~ /^[lh]/ { found=1 } END { exit found ? 0 : 1 }'; then
  echo "release archive must not contain links" >&2
  exit 1
fi
tar -xzf "$archive" --no-same-owner -C "$temporary"
root=$(find "$temporary" -mindepth 1 -maxdepth 1 -type d)
[ -n "$root" ] && [ "$(printf '%s\n' "$root" | wc -l)" -eq 1 ]
(
  cd "$root"
  sha256sum -c SHA256SUMS
  if [ "${SMCV_ALLOW_DIRTY_VERIFY:-0}" = 1 ]; then
    jq -e '.schema == "smcv.local-provenance.v1" and .builder == "local-cargo-locked" and (.external_signing == false)' PROVENANCE.json >/dev/null
  else
    jq -e '.schema == "smcv.local-provenance.v1" and .builder == "local-cargo-locked" and (.working_tree_dirty == false) and (.external_signing == false)' PROVENANCE.json >/dev/null
  fi
  jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' sbom/smcv-cli.cdx.json >/dev/null
  jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' sbom/smcv-server.cdx.json >/dev/null
  bin/smcv-cli --version >/dev/null
)

if [ -n "$public_key" ]; then
  openssl dgst -sha256 -verify "$public_key" -signature "$archive.sig" "$archive"
fi

printf '%s\n' "release_artifact=verified"
