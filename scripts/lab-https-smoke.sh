#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
server_pid=
occupier_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ -n "$occupier_pid" ]; then
    kill -TERM "$occupier_pid" 2>/dev/null || true
    wait "$occupier_pid" 2>/dev/null || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

available_port() {
  node -e 'const n=require("net");const s=n.createServer();s.listen(0,"127.0.0.1",()=>{process.stdout.write(String(s.address().port));s.close();});'
}

product_port=$(available_port)
tls_port=$(available_port)
database="$temporary/data/vault.sqlite"
root_key="$temporary/provider/root.key"
password_input="$temporary/password-input"
generated_certificate="$temporary/provider/lab-https-cert.pem"
generated_key="$temporary/provider/lab-https-key.pem"
server_log="$temporary/server.log"

cd "$repository"
cargo build --locked -p smcv-server -p smcv-cli >/dev/null
target/debug/smcv-cli init --database "$database" --root-key "$root_key" >/dev/null
printf '%s\n' 'synthetic native HTTPS owner password' >"$password_input"
chmod 0600 "$password_input"
target/debug/smcv-cli enroll-owner \
  --database "$database" --root-key "$root_key" --password-fd 3 \
  3<"$password_input" >/dev/null
rm "$password_input"

lab_environment() {
  env \
    SMCV_ENVIRONMENT=production \
    SMCV_LISTEN_ADDR="127.0.0.1:$product_port" \
    SMCV_LAB_HTTPS_ADDR="127.0.0.1:$tls_port" \
    SMCV_LAB_HTTPS_SERVER_NAME=localhost \
    SMCV_DATA_DIR="$temporary/data" \
    SMCV_KEY_DIR="$temporary/provider" \
    SMCV_PROTECTED_TRANSPORT=1 \
    SMCV_LOG_FORMAT=json \
    SMCV_SHUTDOWN_GRACE_SECONDS=5 \
    "$@"
}

lab_environment target/debug/smcv-server preflight >"$temporary/generated-preflight"
grep -q '^status=ready$' "$temporary/generated-preflight"
grep -q "^lab_https_origin=https://localhost:$tls_port$" "$temporary/generated-preflight"
grep -Eq '^lab_https_certificate_fingerprint_sha256=([0-9A-F]{2}:){31}[0-9A-F]{2}$' \
  "$temporary/generated-preflight"
[ "$(stat -c '%a' "$generated_certificate")" = 600 ]
[ "$(stat -c '%a' "$generated_key")" = 600 ]
generated_hash_before=$(sha256sum "$generated_certificate" | awk '{print $1}')

env \
  SMCV_ENVIRONMENT=production \
  SMCV_LISTEN_ADDR="127.0.0.1:$product_port" \
  SMCV_LAB_HTTPS_ADDR="127.0.0.1:$tls_port" \
  SMCV_LAB_HTTPS_SERVER_NAME=localhost \
  SMCV_DATA_DIR="$temporary/data" \
  SMCV_KEY_DIR="$temporary/provider" \
  SMCV_PROTECTED_TRANSPORT=1 \
  SMCV_LOG_FORMAT=json \
  SMCV_SHUTDOWN_GRACE_SECONDS=5 \
  target/debug/smcv-server >"$server_log" 2>&1 &
server_pid=$!
attempt=0
until curl --fail --silent --cacert "$generated_certificate" \
  "https://localhost:$tls_port/health/ready" >/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || {
    echo "generated-certificate HTTPS readiness timeout" >&2
    sed -n '1,120p' "$server_log" >&2
    exit 1
  }
  sleep 0.05
done
curl --fail --silent "http://127.0.0.1:$product_port/health/live" >/dev/null
curl --fail --silent --cacert "$generated_certificate" \
  -H 'content-type: application/json' \
  -c "$temporary/session-cookies" \
  -d '{"password":"synthetic native HTTPS owner password"}' \
  "https://localhost:$tls_port/api/v1/session/password" \
  >"$temporary/session.json"
curl --fail --silent --cacert "$generated_certificate" \
  -b "$temporary/session-cookies" \
  "https://localhost:$tls_port/api/v1/session" >/dev/null
curl --fail --silent --tlsv1.2 --tls-max 1.2 \
  --cacert "$generated_certificate" \
  "https://localhost:$tls_port/health/live" >/dev/null
curl --fail --silent --tlsv1.3 \
  --cacert "$generated_certificate" \
  "https://localhost:$tls_port/health/live" >/dev/null
if openssl s_client -tls1_1 -connect "127.0.0.1:$tls_port" \
  -servername localhost </dev/null >/dev/null 2>&1; then
  echo "native HTTPS listener negotiated obsolete TLS 1.1" >&2
  exit 1
fi
if curl --fail --silent --max-time 2 "http://127.0.0.1:$tls_port/health/live" >/dev/null 2>&1; then
  echo "native HTTPS listener accepted plaintext HTTP" >&2
  exit 1
fi
if curl --fail --silent --cacert "$generated_certificate" \
  "https://localhost:$tls_port/metrics" >/dev/null 2>&1; then
  echo "native HTTPS product listener exposed operational metrics" >&2
  exit 1
fi
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

lab_environment target/debug/smcv-server preflight >"$temporary/restart-preflight"
generated_hash_after=$(sha256sum "$generated_certificate" | awk '{print $1}')
[ "$generated_hash_before" = "$generated_hash_after" ]
cmp -s "$temporary/generated-preflight" "$temporary/restart-preflight"

umask 077
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj '/CN=SMCV synthetic lab CA' \
  -keyout "$temporary/ca.key" -out "$temporary/ca.crt" -days 2 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj '/CN=localhost' \
  -keyout "$temporary/leaf.key" -out "$temporary/leaf.csr" \
  -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' \
  >"$temporary/leaf.ext"
openssl x509 -req -in "$temporary/leaf.csr" \
  -CA "$temporary/ca.crt" -CAkey "$temporary/ca.key" -CAcreateserial \
  -out "$temporary/leaf.crt" -days 2 -extfile "$temporary/leaf.ext" >/dev/null 2>&1

supplied_environment() {
  SMCV_LAB_HTTPS_CERT_FILE="$temporary/leaf.crt" \
  SMCV_LAB_HTTPS_KEY_FILE="$temporary/leaf.key" \
  lab_environment "$@"
}

supplied_environment target/debug/smcv-server preflight >"$temporary/supplied-preflight"
env \
  SMCV_ENVIRONMENT=production \
  SMCV_LISTEN_ADDR="127.0.0.1:$product_port" \
  SMCV_LAB_HTTPS_ADDR="127.0.0.1:$tls_port" \
  SMCV_LAB_HTTPS_SERVER_NAME=localhost \
  SMCV_LAB_HTTPS_CERT_FILE="$temporary/leaf.crt" \
  SMCV_LAB_HTTPS_KEY_FILE="$temporary/leaf.key" \
  SMCV_DATA_DIR="$temporary/data" \
  SMCV_KEY_DIR="$temporary/provider" \
  SMCV_PROTECTED_TRANSPORT=1 \
  SMCV_LOG_FORMAT=json \
  SMCV_SHUTDOWN_GRACE_SECONDS=5 \
  target/debug/smcv-server >"$server_log" 2>&1 &
server_pid=$!
attempt=0
until curl --fail --silent --cacert "$temporary/ca.crt" \
  "https://localhost:$tls_port/health/ready" >/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || {
    echo "CA-issued HTTPS readiness timeout" >&2
    sed -n '1,120p' "$server_log" >&2
    exit 1
  }
  sleep 0.05
done
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

if SMCV_LAB_HTTPS_KEY_FILE="$temporary/ca.key" \
  SMCV_LAB_HTTPS_CERT_FILE="$temporary/leaf.crt" \
  lab_environment target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "mismatched certificate/private key passed preflight" >&2
  exit 1
fi
chmod 0644 "$temporary/leaf.key"
if supplied_environment target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "permissive private-key custody passed preflight" >&2
  exit 1
fi
chmod 0600 "$temporary/leaf.key"
if SMCV_LAB_HTTPS_CERT_FILE="$temporary/leaf.crt" \
  lab_environment target/debug/smcv-server preflight >/dev/null 2>&1; then
  echo "one-sided supplied certificate configuration passed preflight" >&2
  exit 1
fi

node -e 'const n=require("net");const s=n.createServer();s.listen(Number(process.argv[1]),"127.0.0.1");setInterval(()=>{},1000);' \
  "$tls_port" >/dev/null 2>&1 &
occupier_pid=$!
sleep 0.1
if lab_environment target/debug/smcv-server >/dev/null 2>&1; then
  echo "native HTTPS bind collision did not fail the process" >&2
  exit 1
fi
kill -TERM "$occupier_pid"
wait "$occupier_pid" 2>/dev/null || true
occupier_pid=

if grep -Eq 'BEGIN (RSA |EC )?PRIVATE KEY|PRIVATE KEY-----' \
  "$server_log" "$temporary/"*preflight; then
  echo "TLS private key reached operational output" >&2
  exit 1
fi

printf '%s\n' \
  'generated_self_signed=passed' \
  'generated_identity_restart_stability=passed' \
  'password_session_over_https=passed' \
  'ca_issued_certificate=passed' \
  'tls_12_and_13=passed' \
  'tls_11=rejected' \
  'plaintext_tls_probe=rejected' \
  'mismatched_key=rejected' \
  'unsafe_custody=rejected' \
  'one_sided_configuration=rejected' \
  'bind_collision=rejected' \
  'metrics_exposure=rejected' \
  'temporary_workspace=cleanup-armed'
