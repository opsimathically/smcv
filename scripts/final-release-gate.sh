#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

[ -z "$(git status --porcelain --untracked-files=normal)" ] || {
  echo "final release gate requires a clean reviewed commit" >&2
  exit 1
}

./scripts/check.sh
if ! systemd_output=$(systemd-analyze verify packaging/systemd/*.service packaging/systemd/*.timer 2>&1); then
  unexpected=$(printf '%s\n' "$systemd_output" \
    | sed '\|^smcv.service: Command /usr/local/lib/smcv/smcv-server is not executable: No such file or directory$|d')
  [ -z "$unexpected" ] || {
    printf '%s\n' "$systemd_output" >&2
    exit 1
  }
fi
./scripts/build-release.sh >"$temporary/release-path"
archive=$(cat "$temporary/release-path")
first_hash=$(sha256sum "$archive" | awk '{print $1}')
./scripts/verify-release.sh "$archive"
./scripts/release-candidate-smoke.sh "$archive"
./scripts/build-release.sh >"$temporary/release-path-second"
second_archive=$(cat "$temporary/release-path-second")
second_hash=$(sha256sum "$second_archive" | awk '{print $1}')
[ "$first_hash" = "$second_hash" ]

mkdir "$temporary/extracted"
tar -xzf "$archive" --no-same-owner -C "$temporary/extracted"
token_prefix='smcv_v1\.'
secret_pattern="-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|${token_prefix}[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}"
if rg -n -- "$secret_pattern" "$temporary/extracted"; then
  echo "possible secret pattern in release artifact" >&2
  exit 1
fi

for id in DELIVERY-001 DELIVERY-002 DELIVERY-003 DELIVERY-004 DELIVERY-005; do
  rg -q "$id" ai_context_documentation/PRODUCT_REQUIREMENTS.md
  rg -q "$id" ai_phase_evidence/FINAL_REQUIREMENTS_TRACEABILITY.md
done

printf 'repository_gate=passed\nsystemd_units=parsed-with-uninstalled-binary-warning\nartifact_verify=passed\nartifact_candidate_campaign=passed\nreproducible_sha256=%s\nrelease_secret_scan=passed\ndelivery_continuity=passed\n' "$first_hash"
