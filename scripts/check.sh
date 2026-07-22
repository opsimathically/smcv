#!/bin/sh
set -eu

cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo audit
cargo deny check
sh -n scripts/*.sh

if ! grep -Fq 'runs-on: ubuntu-24.04' .github/workflows/ci.yml; then
  echo "CI runner baseline is not pinned to Ubuntu 24.04" >&2
  exit 1
fi
if ! awk '
  /uses:/ {
    if ($0 !~ /@[0-9a-f]{40}([[:space:]]|$)/) bad=1
  }
  END { exit bad }
' .github/workflows/*.yml; then
  echo "GitHub Actions dependencies must use full commit pins" >&2
  exit 1
fi
if ! grep -Fq 'tool: cargo-audit@0.22.2,cargo-cyclonedx@0.5.9,cargo-deny@0.20.2' .github/workflows/ci.yml; then
  echo "CI verification tools are not exactly version-pinned" >&2
  exit 1
fi

token_prefix='smcv_v1\.'
secret_pattern="-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|${token_prefix}[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}"
if rg -n -g '*.{rs,toml,md,json,yaml,yml,js,html,css,sh,service,timer,conf,example}' -g '!target/**' -g '!dist/**' -g '!scripts/check.sh' -- \
  "$secret_pattern" .; then
  echo "possible committed secret pattern detected" >&2
  exit 1
fi

perl -MFile::Spec -e '
  $bad=0;
  for $f (@ARGV) {
    open $h, "<", $f or die $!;
    local $/;
    $s=<$h>;
    while ($s =~ /\[[^\]]*\]\(([^)]+)\)/g) {
      $u=$1;
      next if $u =~ m{^(?:https?://|#)};
      ($p)=split /#/, $u, 2;
      next unless length $p;
      ($vol,$dir,$file)=File::Spec->splitpath($f);
      $t=File::Spec->canonpath(File::Spec->catfile($dir,$p));
      if (!-e $t) { print "$f: $u -> $t\n"; $bad=1; }
    }
  }
  exit $bad;
' $(find . -type f -name '*.md' -not -path './.git/*' -not -path './target/*' -print | sort)
