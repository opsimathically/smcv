#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive=${1:?usage: release-candidate-smoke.sh RELEASE_TARBALL}
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

mkdir "$temporary/artifact"
stable_archive="$temporary/artifact/$(basename -- "$archive")"
cp -- "$archive" "$stable_archive"
cp -- "$archive.sha256" "$stable_archive.sha256"
archive="$stable_archive"
"$repository/scripts/verify-release.sh" "$archive" >/dev/null
mkdir "$temporary/extracted"
tar -xzf "$archive" --no-same-owner -C "$temporary/extracted"
bundle=$(find "$temporary/extracted" -mindepth 1 -maxdepth 1 -type d)
cli="$bundle/bin/smcv-cli"
server="$bundle/bin/smcv-server"
source_data="$temporary/source/data"
source_keys="$temporary/source/provider"
source_database="$source_data/vault.sqlite"
source_root="$source_keys/root.key"
rollback_data="$temporary/rollback/data"
rollback_keys="$temporary/rollback/provider"
restored_data="$temporary/restored/data"
restored_keys="$temporary/restored/provider"
off_host="$temporary/off-host"
drills="$temporary/drills"
password_file="$temporary/owner-password"
backup_key="$temporary/backup-key"
password='synthetic candidate owner password'
first_secret='synthetic-candidate-secret-before-upgrade'
second_secret='synthetic-candidate-secret-after-upgrade'
umask 077

printf '%s\n' "$password" > "$password_file"
"$cli" init --database "$source_database" --root-key "$source_root" >/dev/null
"$cli" enroll-owner --database "$source_database" --root-key "$source_root" --password-fd 3 3<"$password_file" >/dev/null
"$cli" backup-key-generate > "$backup_key"
mkdir -m 0700 "$off_host" "$drills"

run_server() {
  data=$1
  keys=$2
  port=$3
  env -i \
    PATH="$PATH" \
    SMCV_ENVIRONMENT=development \
    SMCV_LISTEN_ADDR="127.0.0.1:$port" \
    SMCV_DATA_DIR="$data" \
    SMCV_KEY_DIR="$keys" \
    SMCV_RP_ID=localhost \
    SMCV_ORIGIN="http://localhost:$port" \
    RUST_LOG=warn \
    "$server" > "$temporary/server-$port.log" 2>&1 &
  server_pid=$!
  attempt=0
  until curl --fail --silent "http://127.0.0.1:$port/health/ready" >/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || { echo "release server readiness timeout" >&2; exit 1; }
    sleep 0.05
  done
}

stop_server() {
  kill -TERM "$server_pid"
  wait "$server_pid"
  server_pid=
}

login() {
  port=$1
  cookie_file=$2
  jq -n --arg password "$password" '{password:$password}' \
    | curl --fail --silent --cookie-jar "$cookie_file" \
        --header 'Content-Type: application/json' --data-binary @- \
        "http://127.0.0.1:$port/api/v1/session/password"
}

source_port=$(available_port)
source_cookie="$temporary/source-cookie"
run_server "$source_data" "$source_keys" "$source_port"
login_response=$(login "$source_port" "$source_cookie")
csrf=$(printf '%s' "$login_response" | jq -er '.csrf_token')
namespace_response=$(jq -n '{parent_namespace_id:null,metadata:{name:"Synthetic candidate",description:"Release artifact fixture",username:null,tags:[]}}' \
  | curl --fail --silent --cookie "$source_cookie" \
      --header "X-SMCV-CSRF: $csrf" --header 'Idempotency-Key: 10000000-0000-4000-8000-000000000001' \
      --header 'Content-Type: application/json' --data-binary @- \
      "http://127.0.0.1:$source_port/api/v1/namespaces")
namespace_id=$(printf '%s' "$namespace_response" | jq -er '.id')
encoded_first=$(printf '%s' "$first_secret" | base64 -w0)
secret_response=$(jq -n --arg namespace "$namespace_id" --arg value "$encoded_first" \
  '{namespace_id:$namespace,metadata:{name:"Synthetic release credential",description:"Release artifact fixture",username:"synthetic-service",tags:[]},value_base64:$value,expires_at_unix_ms:null,rotation_due_at_unix_ms:null}' \
  | curl --fail --silent --cookie "$source_cookie" \
      --header "X-SMCV-CSRF: $csrf" --header 'Idempotency-Key: 10000000-0000-4000-8000-000000000002' \
      --header 'Content-Type: application/json' --data-binary @- \
      "http://127.0.0.1:$source_port/api/v1/secrets")
secret_id=$(printf '%s' "$secret_response" | jq -er '.id')
stop_server

"$cli" backup-maintain --database "$source_database" --root-key "$source_root" \
  --output-directory "$off_host" --key-fd 3 --retain 2 3<"$backup_key" >/dev/null
portable_archive=$(find "$off_host" -maxdepth 1 -type f -name '*.smcvault' -print -quit)
"$cli" backup-restore-drill --archive "$portable_archive" --workspace "$drills" \
  --key-fd 3 3<"$backup_key" >/dev/null
mkdir -p -m 0700 "$rollback_data" "$rollback_keys"
cp -a "$source_data/." "$rollback_data/"
cp -a "$source_keys/." "$rollback_keys/"

production_port=$(available_port)
env -i \
  PATH="$PATH" \
  SMCV_ENVIRONMENT=production \
  SMCV_LISTEN_ADDR="127.0.0.1:$production_port" \
  SMCV_DATA_DIR="$source_data" \
  SMCV_KEY_DIR="$source_keys" \
  SMCV_RP_ID=vault.example.test \
  SMCV_ORIGIN=https://vault.example.test \
  SMCV_PROTECTED_TRANSPORT=1 \
  SMCV_LOG_FORMAT=json \
  "$server" preflight >/dev/null

source_port=$(available_port)
source_cookie="$temporary/source-cookie-after-upgrade"
run_server "$source_data" "$source_keys" "$source_port"
login_response=$(login "$source_port" "$source_cookie")
csrf=$(printf '%s' "$login_response" | jq -er '.csrf_token')
encoded_second=$(printf '%s' "$second_secret" | base64 -w0)
jq -n --arg value "$encoded_second" \
  '{expected_current_version:1,expected_revision:1,value_base64:$value,expires_at_unix_ms:null,rotation_due_at_unix_ms:null}' \
  | curl --fail --silent --request PUT --cookie "$source_cookie" \
      --header "X-SMCV-CSRF: $csrf" --header 'Content-Type: application/json' \
      --data-binary @- "http://127.0.0.1:$source_port/api/v1/secrets/$secret_id" >/dev/null
stop_server

rollback_port=$(available_port)
rollback_cookie="$temporary/rollback-cookie"
run_server "$rollback_data" "$rollback_keys" "$rollback_port"
login_response=$(login "$rollback_port" "$rollback_cookie")
rollback_value=$(curl --fail --silent --cookie "$rollback_cookie" \
  "http://127.0.0.1:$rollback_port/api/v1/secrets/$secret_id/value" | jq -er '.value_base64' | base64 -d)
[ "$rollback_value" = "$first_secret" ]
[ "$rollback_value" != "$second_secret" ]
stop_server

mv "$source_data" "$temporary/lost-source-data"
mv "$source_keys" "$temporary/lost-source-provider"
"$cli" backup-restore --archive "$portable_archive" \
  --database "$restored_data/vault.sqlite" --root-key "$restored_keys/root.key" \
  --key-fd 3 3<"$backup_key" >/dev/null
restored_port=$(available_port)
restored_cookie="$temporary/restored-cookie"
run_server "$restored_data" "$restored_keys" "$restored_port"
login_response=$(login "$restored_port" "$restored_cookie")
restored_value=$(curl --fail --silent --cookie "$restored_cookie" \
  "http://127.0.0.1:$restored_port/api/v1/secrets/$secret_id/value" | jq -er '.value_base64' | base64 -d)
[ "$restored_value" = "$first_secret" ]
stop_server

if rg -n 'synthetic-candidate-secret-(before|after)-upgrade' "$temporary" \
  -g '*.log' -g '*.json' -g '*.txt' -g '*.md' >/dev/null; then
  echo "synthetic secret reached release-candidate operational artifacts" >&2
  exit 1
fi

rm "$password_file" "$backup_key"
printf 'artifact_install=passed\nproduction_preflight=passed\nupgrade_probe=passed\nrollback=passed-with-documented-data-window\nrestore_drill=passed-and-cleaned\ntotal_loss_restore=passed\nowner_login_after_restore=passed\nsecret_value_after_restore=matched\n'
