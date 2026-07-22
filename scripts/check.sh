#!/bin/sh
set -eu

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo audit
cargo deny check

secret_prefix='smcv_'
secret_pattern="-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|${secret_prefix}[A-Za-z0-9_-]{20,}"
if rg -n -g '*.{rs,toml,md,json,yaml,yml}' -g '!target/**' -- \
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
