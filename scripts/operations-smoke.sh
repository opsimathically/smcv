#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

available_port() {
  node -e 'const n=require("net");const s=n.createServer();s.listen(0,"127.0.0.1",()=>{process.stdout.write(String(s.address().port));s.close();});'
}

product_port=$(available_port)
metrics_port=$(available_port)
database="$temporary/data/vault.sqlite"
root_key="$temporary/provider/root.key"
password_input="$temporary/password-input"
backup_key="$temporary/backup-key"
backups="$temporary/backups"
drills="$temporary/drills"
logs="$temporary/server.log"

cd "$repository"
nginx_example=packaging/nginx-smcv.conf.example
for required in \
  'client_max_body_size 8193m;' \
  'proxy_request_buffering off;' \
  'proxy_buffering off;' \
  'proxy_max_temp_file_size 0;' \
  'proxy_read_timeout 930s;' \
  'proxy_set_header X-Forwarded-For "";' \
  'proxy_set_header X-Real-IP "";' \
  'proxy_set_header Forwarded "";'
do
  grep -Fq "$required" "$nginx_example" || {
    echo "nginx security/streaming boundary is missing: $required" >&2
    exit 1
  }
done
cargo build --locked --workspace >/dev/null
target/debug/smcv-cli init --database "$database" --root-key "$root_key" >/dev/null
printf '%s\n' 'synthetic operations owner password' > "$password_input"
chmod 0600 "$password_input"
target/debug/smcv-cli enroll-owner --database "$database" --root-key "$root_key" --password-fd 3 3<"$password_input" >/dev/null
rm "$password_input"

production_environment() {
  env \
    SMCV_ENVIRONMENT=production \
    SMCV_LISTEN_ADDR="127.0.0.1:$product_port" \
    SMCV_METRICS_ADDR="127.0.0.1:$metrics_port" \
    SMCV_DATA_DIR="$temporary/data" \
    SMCV_KEY_DIR="$temporary/provider" \
    SMCV_RP_ID=vault.example.test \
    SMCV_ORIGIN=https://vault.example.test \
    SMCV_PROTECTED_TRANSPORT=1 \
    SMCV_LOG_FORMAT=json \
    SMCV_SHUTDOWN_GRACE_SECONDS=5 \
    "$@"
}

production_environment target/debug/smcv-server preflight > "$temporary/preflight.log"
if target/debug/smcv-server misspelled-preflight >/dev/null 2>&1; then
  echo "unknown server argument started successfully" >&2
  exit 1
fi

chmod 0644 "$root_key"
if production_environment target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "unsafe root-key permissions passed preflight" >&2
  exit 1
fi
chmod 0600 "$root_key"

if env SMCV_UNKNOWN_OPTION=1 SMCV_ENVIRONMENT=production target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "unknown configuration passed preflight" >&2
  exit 1
fi
if SMCV_TRUSTED_PROXY=127.0.0.1 production_environment target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "unsupported trusted-proxy configuration passed preflight" >&2
  exit 1
fi
if env \
  SMCV_ENVIRONMENT=production \
  SMCV_DATA_DIR="$temporary/data" \
  SMCV_KEY_DIR="$temporary/provider" \
  SMCV_ORIGIN=http://vault.example.test \
  SMCV_RP_ID=vault.example.test \
  SMCV_PROTECTED_TRANSPORT=1 \
  SMCV_LOG_FORMAT=json \
  target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "plaintext production origin passed preflight" >&2
  exit 1
fi

env \
  SMCV_ENVIRONMENT=production \
  SMCV_LISTEN_ADDR="127.0.0.1:$product_port" \
  SMCV_METRICS_ADDR="127.0.0.1:$metrics_port" \
  SMCV_DATA_DIR="$temporary/data" \
  SMCV_KEY_DIR="$temporary/provider" \
  SMCV_RP_ID=vault.example.test \
  SMCV_ORIGIN=https://vault.example.test \
  SMCV_PROTECTED_TRANSPORT=1 \
  SMCV_LOG_FORMAT=json \
  SMCV_SHUTDOWN_GRACE_SECONDS=5 \
  target/debug/smcv-server > "$logs" 2>&1 &
server_pid=$!
attempt=0
until curl --fail --silent "http://127.0.0.1:$product_port/health/ready" >/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || { echo "server readiness timeout" >&2; exit 1; }
  sleep 0.05
done

load_start=$(date +%s%N)
seq 1 2048 | xargs -P16 -I '{}' curl --fail --silent "http://127.0.0.1:$product_port/health/live" >/dev/null
load_milliseconds=$((($(date +%s%N) - load_start) / 1000000))
sentinel='synthetic-operations-sentinel'
curl --silent "http://127.0.0.1:$product_port/missing/$sentinel" >/dev/null
curl --fail --silent "http://127.0.0.1:$metrics_port/metrics" > "$temporary/metrics.txt"
grep -q '^smcv_process_ready 1$' "$temporary/metrics.txt"
grep -q '^smcv_http_requests_total ' "$temporary/metrics.txt"
if grep -q "$sentinel" "$logs" "$temporary/metrics.txt"; then
  echo "attacker-controlled sentinel reached operational output" >&2
  exit 1
fi
if grep -Eq 'route=|vault_id|installation_id|request\.uri|secret' "$temporary/metrics.txt"; then
  echo "metrics contain dynamic or protected labels" >&2
  exit 1
fi

shutdown_start=$(date +%s)
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
shutdown_seconds=$(($(date +%s) - shutdown_start))
[ "$shutdown_seconds" -le 5 ]

umask 077
target/debug/smcv-cli backup-key-generate > "$backup_key"
mkdir -m 0700 "$backups" "$drills"
target/debug/smcv-cli backup-maintain --database "$database" --root-key "$root_key" --output-directory "$backups" --key-fd 3 --retain 2 3<"$backup_key" >/dev/null
target/debug/smcv-cli backup-maintain --database "$database" --root-key "$root_key" --output-directory "$backups" --key-fd 3 --retain 2 3<"$backup_key" >/dev/null
target/debug/smcv-cli backup-maintain --database "$database" --root-key "$root_key" --output-directory "$backups" --key-fd 3 --retain 2 3<"$backup_key" >/dev/null
[ "$(find "$backups" -maxdepth 1 -type f -name '*.smcvault' | wc -l)" -eq 2 ]
cp LICENSE "$backups/corrupt.smcvault"
if target/debug/smcv-cli backup-maintain --database "$database" --root-key "$root_key" --output-directory "$backups" --key-fd 3 --retain 2 3<"$backup_key" >/dev/null 2>&1; then
  echo "unverifiable backup inventory did not alert" >&2
  exit 1
fi
rm "$backups/corrupt.smcvault"
archive=$(find "$backups" -maxdepth 1 -type f -name '*.smcvault' | sort | head -n 1)
target/debug/smcv-cli backup-restore-drill --archive "$archive" --workspace "$drills" --key-fd 3 3<"$backup_key" >/dev/null
[ -z "$(find "$drills" -mindepth 1 -maxdepth 1 -print -quit)" ]

printf 'preflight=passed\nload_requests=2048\nload_milliseconds=%s\nshutdown_seconds=%s\nverified_retained=2\nverification_alert=passed\nrestore_drill=passed-and-cleaned\ntelemetry_sentinel=absent\n' "$load_milliseconds" "$shutdown_seconds"
