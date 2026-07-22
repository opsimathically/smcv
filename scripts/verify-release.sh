#!/bin/sh
set -eu

archive=${1:?usage: verify-release.sh ARCHIVE [PUBLIC_KEY]}
public_key=${2:-}
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
archive_name=$(basename -- "$archive")
archive_copy="$temporary/$archive_name"
checksum="$archive.sha256"
case "$archive_name" in
  smcv-*-x86_64-unknown-linux-gnu.tar.gz) ;;
  *) echo "release archive name is invalid" >&2; exit 1 ;;
esac
case "$archive_name" in
  *[!A-Za-z0-9._-]*) echo "release archive name is invalid" >&2; exit 1 ;;
esac

[ -f "$archive" ] && [ ! -L "$archive" ]
[ -f "$checksum" ] && [ ! -L "$checksum" ]
cp -- "$archive" "$archive_copy"
expected=$(awk -v name="$archive_name" '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ || $2 != name { bad=1 }
  !bad { found++; value=$1 }
  END {
    if (bad || found != 1) exit 1
    print value
  }
' "$checksum")
[ -n "$expected" ]
actual=$(sha256sum "$archive_copy" | awk '{print $1}')
[ "$actual" = "$expected" ] || {
  echo "$archive_name: checksum mismatch" >&2
  exit 1
}
printf '%s\n' "$archive_name: OK"

if [ -n "$public_key" ]; then
  signature="$archive.sig"
  [ -f "$signature" ] && [ ! -L "$signature" ]
  cp -- "$signature" "$temporary/archive.sig"
  openssl dgst -sha256 -verify "$public_key" -signature "$temporary/archive.sig" "$archive_copy"
fi

members="$temporary/members"
LC_ALL=C tar -tzf "$archive_copy" --quoting-style=escape > "$members"
[ -s "$members" ]
expected_root=${archive_name%.tar.gz}
bundle_version=${expected_root#smcv-}
bundle_version=${bundle_version%-x86_64-unknown-linux-gnu}
[ -n "$bundle_version" ] || {
  echo "release archive version is empty" >&2
  exit 1
}
while IFS= read -r member; do
  case "$member" in
    ''|*[!A-Za-z0-9_./-]*|/*|./*|..|../*|*/../*|*/..|*/./*|*/.|*//* )
      echo "unsafe archive member" >&2
      exit 1
      ;;
    "$expected_root"/|"$expected_root"/*) ;;
    *) echo "unexpected release archive root" >&2; exit 1 ;;
  esac
done < "$members"
if LC_ALL=C tar -tvzf "$archive_copy" --quoting-style=escape \
  | awk '$1 !~ /^[-d]/ { bad=1 } END { exit bad ? 0 : 1 }'; then
  echo "release archive must contain only regular files and directories" >&2
  exit 1
fi
extracted="$temporary/extracted"
mkdir "$extracted"
tar -xzf "$archive_copy" --no-same-owner -C "$extracted"
root="$extracted/$expected_root"
[ -d "$root" ] && [ ! -L "$root" ]
[ "$(find "$extracted" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ]
(
  cd "$root"
  awk '
    {
      path=$2
      sub(/^\.\//, "", path)
      if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ ||
          $2 !~ /^\.\/[A-Za-z0-9_./-]+$/ || path ~ /(^|\/)\.\.?(\/|$)/)
        bad=1
      print $2
    }
    END { if (bad) exit 1 }
  ' SHA256SUMS > "$temporary/manifest-files-unsorted"
  LC_ALL=C sort "$temporary/manifest-files-unsorted" > "$temporary/manifest-files"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort > "$temporary/actual-files"
  cmp "$temporary/manifest-files" "$temporary/actual-files"
  sha256sum -c SHA256SUMS
  lock_sha256=$(sha256sum Cargo.lock | awk '{print $1}')
  if [ "${SMCV_ALLOW_DIRTY_VERIFY:-0}" = 1 ]; then
    jq -e --arg version "$bundle_version" --arg lock "$lock_sha256" '
      .schema == "smcv.local-provenance.v1" and
      .version == $version and .target == "x86_64-unknown-linux-gnu" and
      .builder == "local-cargo-locked" and
      (.commit | type == "string" and test("^[0-9a-f]{40}$")) and
      (.source_date_epoch | type == "number" and . >= 0) and
      (.rustc_version | type == "string" and length > 0) and
      (.cargo_version | type == "string" and length > 0) and
      (.cyclonedx_version | type == "string" and length > 0) and
      (.glibc_version == "glibc 2.39") and
      (.openssl_version | type == "string" and startswith("OpenSSL 3.")) and
      .cargo_lock_sha256 == $lock and
      (.working_tree_dirty | type == "boolean") and
      (.external_signing == false)
    ' PROVENANCE.json >/dev/null
  else
    jq -e --arg version "$bundle_version" --arg lock "$lock_sha256" '
      .schema == "smcv.local-provenance.v1" and
      .version == $version and .target == "x86_64-unknown-linux-gnu" and
      .builder == "local-cargo-locked" and
      (.commit | type == "string" and test("^[0-9a-f]{40}$")) and
      (.source_date_epoch | type == "number" and . >= 0) and
      (.rustc_version | type == "string" and length > 0) and
      (.cargo_version | type == "string" and length > 0) and
      (.cyclonedx_version | type == "string" and length > 0) and
      (.glibc_version == "glibc 2.39") and
      (.openssl_version | type == "string" and startswith("OpenSSL 3.")) and
      .cargo_lock_sha256 == $lock and
      (.working_tree_dirty == false) and (.external_signing == false)
    ' PROVENANCE.json >/dev/null
  fi
  for crate in smcv-app smcv-backup smcv-cli smcv-core smcv-crypto smcv-server smcv-storage; do
    jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' "sbom/$crate.cdx.json" >/dev/null
  done
  test -f Cargo.lock
  test -f external_assurance/README.md
  test -f docs/RELEASE_NOTES_0.1.0.md
  test -f ai_phase_evidence/FINAL_REQUIREMENTS_TRACEABILITY.md
)

printf '%s\n' "release_artifact=verified"
