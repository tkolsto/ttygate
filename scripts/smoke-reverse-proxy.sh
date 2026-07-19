#!/bin/sh

set -eu

proxy_kind=${1:-}
case "$proxy_kind" in
  caddy | nginx) ;;
  *)
    printf 'usage: %s caddy|nginx\n' "$0" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
run_id="ttygate-chunk42-$proxy_kind-$$"
runtime=$(mktemp -d "$repo_root/.$run_id.XXXXXX")
runtime=$(CDPATH='' cd -- "$runtime" && pwd -P)
tls_dir="$runtime/tls"
image="$run_id:ttygate"
backend_network="$run_id-backend"
auth_network="$run_id-auth"
frontend_network="$run_id-frontend"
audit_volume="$run_id-audit"
backend="$run_id-ttygated"
auth="$run_id-auth"
proxy="$run_id-proxy"
validator="$run_id-validator"
client="$run_id-client"
attacker="$run_id-untrusted"
invalid="$run_id-invalid"

CADDY_IMAGE="caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
NGINX_IMAGE="nginx:1.29.8-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de"
NODE_IMAGE="node:22.21.1-bookworm-slim@sha256:25b3eb23a00590b7499f2a2ce939322727fcce1b15fdd69754fcd09536a3ae2c"

redact() {
  sed -E \
    -e 's/chunk42-fixture-only/[redacted]/g' \
    -e 's/TTYGATE_PROXY_FLOW_OK/[redacted]/g' \
    -e 's/ttgate_session=[A-Za-z0-9_-]+/ttgate_session=[redacted]/g' \
    -e 's/[A-Za-z0-9_-]{32,}/[redacted]/g'
}

fail() {
  printf 'reverse-proxy smoke failed (%s): %s\n' "$proxy_kind" "$1" >&2
  for name in "$backend" "$auth" "$proxy" "$client" "$invalid"; do
    if docker inspect "$name" >/dev/null 2>&1; then
      docker inspect --format 'name={{.Name}} state={{json .State}}' "$name" |
        redact >&2 || true
      docker logs --tail 40 "$name" 2>&1 | redact >&2 || true
    fi
  done
  exit 1
}

cleanup() {
  exit_code=$?
  trap - EXIT HUP INT TERM
  docker rm -f \
    "$client" "$attacker" "$invalid" "$validator" "$proxy" "$auth" "$backend" \
    >/dev/null 2>&1 || true
  docker network rm "$frontend_network" "$auth_network" "$backend_network" \
    >/dev/null 2>&1 || true
  docker volume rm -f "$audit_volume" >/dev/null 2>&1 || true
  docker image rm -f "$image" >/dev/null 2>&1 || true
  rm -rf "$runtime"

  residue=
  for object in \
    "$client" "$attacker" "$invalid" "$validator" "$proxy" "$auth" "$backend"; do
    if docker inspect "$object" >/dev/null 2>&1; then
      residue="$residue container:$object"
    fi
  done
  for network in "$frontend_network" "$auth_network" "$backend_network"; do
    if docker network inspect "$network" >/dev/null 2>&1; then
      residue="$residue network:$network"
    fi
  done
  if docker volume inspect "$audit_volume" >/dev/null 2>&1; then
    residue="$residue volume:$audit_volume"
  fi
  if docker image inspect "$image" >/dev/null 2>&1; then
    residue="$residue image:$image"
  fi
  if [ -e "$runtime" ]; then
    residue="$residue fixture-directory"
  fi
  if [ -n "$residue" ]; then
    printf 'reverse-proxy cleanup left disposable residue:%s\n' "$residue" >&2
    exit_code=1
  fi
  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for command in docker openssl sed grep mktemp; do
  command -v "$command" >/dev/null 2>&1 ||
    fail "required command is unavailable: $command"
done
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

mkdir -p "$tls_dir"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=terminal.example.invalid" \
  -addext "subjectAltName=DNS:terminal.example.invalid" \
  -keyout "$tls_dir/private-key.pem" \
  -out "$tls_dir/certificate.pem" >/dev/null 2>&1
chmod 0600 "$tls_dir/private-key.pem"
chmod 0644 "$tls_dir/certificate.pem"

docker build --tag "$image" "$repo_root" >/dev/null

sed \
  's#public_url = "https://terminal.example.invalid:8443"#public_url = "http://terminal.example.invalid:8080"#' \
  "$repo_root/packaging/reverse-proxy/ttygate.toml" \
  >"$runtime/plaintext-production.toml"
sed \
  -e 's/provider = "trusted-proxy"/provider = "dev"/' \
  -e 's/identity_header = "x-authenticated-user"/user = "local"/' \
  "$repo_root/packaging/reverse-proxy/ttygate.toml" \
  >"$runtime/development-auth.toml"
sed \
  '/identity_header = "x-authenticated-user"/d' \
  "$repo_root/packaging/reverse-proxy/ttygate.toml" \
  >"$runtime/incomplete-proxy.toml"

expect_config_failure() {
  label=$1
  config=$2
  docker create \
    --name "$invalid" \
    --network none \
    --mount "type=bind,src=$config,dst=/tmp/invalid.toml,readonly" \
    "$image" /tmp/invalid.toml >/dev/null
  docker start "$invalid" >/dev/null
  attempt=0
  while [ "$attempt" -lt 50 ]; do
    running=$(docker inspect --format '{{.State.Running}}' "$invalid")
    [ "$running" = false ] && break
    attempt=$((attempt + 1))
    sleep 0.1
  done
  [ "${running:-true}" = false ] ||
    fail "$label did not fail before listening"
  [ "$(docker inspect --format '{{.State.ExitCode}}' "$invalid")" -ne 0 ] ||
    fail "$label returned success"
  invalid_log=$(docker logs "$invalid" 2>&1)
  printf '%s' "$invalid_log" | grep -Eq 'Validation \{|invalid configuration field' ||
    fail "$label lacked a stable configuration error"
  printf '%s' "$invalid_log" |
    grep -Eq 'chunk42-fixture-only|TTYGATE_PROXY_FLOW_OK|BEGIN .*PRIVATE KEY' &&
    fail "$label diagnostics exposed test secrets"
  docker rm "$invalid" >/dev/null
}

expect_config_failure "plaintext production exposure" "$runtime/plaintext-production.toml"
expect_config_failure "development authentication" "$runtime/development-auth.toml"
expect_config_failure "incomplete trusted-proxy configuration" "$runtime/incomplete-proxy.toml"

docker network create --internal --subnet 192.0.2.0/24 "$backend_network" >/dev/null
docker network create --internal --subnet 203.0.113.0/24 "$auth_network" >/dev/null
docker network create --internal --subnet 198.51.100.0/24 "$frontend_network" >/dev/null
docker volume create "$audit_volume" >/dev/null

docker create \
  --name "$backend" \
  --network "$backend_network" \
  --ip 192.0.2.20 \
  --network-alias ttygated \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$repo_root/packaging/reverse-proxy/ttygate.toml,dst=/etc/ttygate/ttygate.toml,readonly" \
  --mount "type=volume,src=$audit_volume,dst=/var/log/ttygate" \
  "$image" >/dev/null
docker start "$backend" >/dev/null

docker create \
  --name "$auth" \
  --network "$auth_network" \
  --ip 203.0.113.30 \
  --network-alias auth-gateway \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$repo_root/scripts/fixtures/reverse-proxy-auth.mjs,dst=/fixture-auth.mjs,readonly" \
  --entrypoint node \
  "$NODE_IMAGE" /fixture-auth.mjs >/dev/null
docker start "$auth" >/dev/null

attempt=0
while [ "$attempt" -lt 50 ]; do
  docker logs "$auth" 2>&1 | grep -q '^AUTH_READY$' && break
  [ "$(docker inspect --format '{{.State.Running}}' "$auth")" = true ] ||
    fail "authentication fixture exited before readiness"
  attempt=$((attempt + 1))
  sleep 0.1
done
docker logs "$auth" 2>&1 | grep -q '^AUTH_READY$' ||
  fail "authentication fixture did not become ready"
[ "$(docker inspect --format '{{.State.Running}}' "$backend")" = true ] ||
  fail "ttygate failed to start"

create_proxy_container() {
  name=$1
  mode=$2
  # Native validation equivalents: caddy validate --config and nginx -t -c.
  case "$proxy_kind:$mode" in
    caddy:validate)
      docker create \
        --name "$name" --network "$frontend_network" --read-only \
        --ip 198.51.100.10 --network-alias terminal.example.invalid \
        --cap-drop ALL --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
        --tmpfs /data:rw,noexec,nosuid,nodev,mode=0700 \
        --tmpfs /config:rw,noexec,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$repo_root/packaging/reverse-proxy/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
        --mount "type=bind,src=$tls_dir,dst=/etc/ttygate-proxy/tls,readonly" \
        --entrypoint caddy "$CADDY_IMAGE" \
        validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
      ;;
    caddy:run)
      docker create \
        --name "$name" --network "$frontend_network" --read-only \
        --ip 198.51.100.10 --network-alias terminal.example.invalid \
        --cap-drop ALL --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
        --tmpfs /data:rw,noexec,nosuid,nodev,mode=0700 \
        --tmpfs /config:rw,noexec,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$repo_root/packaging/reverse-proxy/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
        --mount "type=bind,src=$tls_dir,dst=/etc/ttygate-proxy/tls,readonly" \
        --entrypoint caddy "$CADDY_IMAGE" \
        run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
      ;;
    nginx:validate)
      docker create \
        --name "$name" --network "$frontend_network" --read-only \
        --ip 198.51.100.10 --network-alias terminal.example.invalid \
        --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
        --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$repo_root/packaging/reverse-proxy/nginx.conf,dst=/etc/nginx/nginx.conf,readonly" \
        --mount "type=bind,src=$tls_dir,dst=/etc/ttygate-proxy/tls,readonly" \
        --entrypoint nginx "$NGINX_IMAGE" \
        -t -c /etc/nginx/nginx.conf >/dev/null
      ;;
    nginx:run)
      docker create \
        --name "$name" --network "$frontend_network" --read-only \
        --ip 198.51.100.10 --network-alias terminal.example.invalid \
        --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
        --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$repo_root/packaging/reverse-proxy/nginx.conf,dst=/etc/nginx/nginx.conf,readonly" \
        --mount "type=bind,src=$tls_dir,dst=/etc/ttygate-proxy/tls,readonly" \
        --entrypoint nginx "$NGINX_IMAGE" \
        -c /etc/nginx/nginx.conf -g 'daemon off;' >/dev/null
      ;;
  esac
}

connect_proxy_networks() {
  name=$1
  docker network connect --ip 192.0.2.10 "$backend_network" "$name"
  docker network connect --ip 203.0.113.10 "$auth_network" "$name"
}

create_proxy_container "$validator" validate
connect_proxy_networks "$validator"
docker start -a "$validator" >/dev/null ||
  fail "the exact committed proxy configuration failed its native validation"
[ "$(docker inspect --format '{{.State.ExitCode}}' "$validator")" -eq 0 ] ||
  fail "proxy validation returned failure"
docker rm "$validator" >/dev/null

create_proxy_container "$proxy" run
connect_proxy_networks "$proxy"
docker start "$proxy" >/dev/null
sleep 1
[ "$(docker inspect --format '{{.State.Running}}' "$proxy")" = true ] ||
  fail "proxy failed to start"

backend_bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$backend")
case "$backend_bindings" in
  '{}' | null) ;;
  *) fail "ttygate backend was published as a client endpoint" ;;
esac
[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$backend")" -eq 1 ] ||
  fail "ttygate was attached outside its private backend network"
[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$auth")" -eq 1 ] ||
  fail "auth fixture was attached outside its private auth network"
[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$proxy")" -eq 3 ] ||
  fail "proxy did not exclusively bridge frontend, auth, and backend networks"

docker run --rm \
  --name "$attacker" \
  --network "$backend_network" \
  --ip 192.0.2.30 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint node \
  "$NODE_IMAGE" \
  -e '
    const http = require("node:http");
    const request = http.request({
      hostname: "ttygated",
      port: 7681,
      path: "/api/identity",
      method: "POST",
      headers: {
        Host: "terminal.example.invalid:8443",
        Origin: "https://terminal.example.invalid:8443",
        "X-Authenticated-User": "untrusted-user",
        "X-Forwarded-For": "192.0.2.10",
        "Content-Length": "0"
      },
      timeout: 3000
    }, (response) => process.exit(response.statusCode === 503 ? 0 : 1));
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", () => process.exit(2));
    request.end();
  ' || fail "untrusted socket peer could establish identity"

run_client() {
  secret_name=$1
  hold=${2:-0}
  docker rm -f "$client" >/dev/null 2>&1 || true
  docker create \
    --name "$client" \
    --network "$frontend_network" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
    --mount "type=bind,src=$repo_root/scripts/fixtures,dst=/fixtures,readonly" \
    --mount "type=bind,src=$runtime,dst=/runtime" \
    --env "TTYGATE_FIXTURE_HOLD=$hold" \
    --entrypoint node \
    "$NODE_IMAGE" \
    /fixtures/reverse-proxy-session.mjs \
    /runtime/tls/certificate.pem \
    "/runtime/$secret_name" >/dev/null
  docker start "$client" >/dev/null
}

wait_for_client_log() {
  marker=$1
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    docker logs "$client" 2>&1 | grep -q "^$marker" && return 0
    [ "$(docker inspect --format '{{.State.Running}}' "$client")" = true ] ||
      return 1
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 1
}

wait_for_client_exit() {
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    [ "$(docker inspect --format '{{.State.Running}}' "$client")" = false ] &&
      return 0
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 1
}

scan_audit() {
  secret_name=$1
  docker run --rm \
    --network none \
    --user 65532:65532 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=volume,src=$audit_volume,dst=/audit,readonly" \
    --mount "type=bind,src=$repo_root/scripts/fixtures,dst=/fixtures,readonly" \
    --mount "type=bind,src=$runtime,dst=/runtime,readonly" \
    --entrypoint node \
    "$NODE_IMAGE" \
    /fixtures/reverse-proxy-session.mjs \
    --scan-audit /audit/audit.jsonl "/runtime/$secret_name" |
    grep -Eq '^AUDIT_SCAN_OK records=[1-9][0-9]*$' ||
    fail "complete audit scan rejected lifecycle or found secret content"
}

run_client runtime-secrets-main.json
wait_for_client_exit || fail "complete HTTPS/WSS client lifecycle did not finish"
[ "$(docker inspect --format '{{.State.ExitCode}}' "$client")" -eq 0 ] ||
  fail "complete HTTPS/WSS client lifecycle failed"
docker logs "$client" 2>&1 |
  grep -q "^REVERSE_PROXY_SESSION_OK identity=synthetic-user$" ||
  fail "client did not complete the canonical identity-to-PTY chain"
scan_audit runtime-secrets-main.json

run_client runtime-secrets-proxy-stop.json 1
wait_for_client_log REVERSE_PROXY_SESSION_HOLD_READY ||
  fail "live proxy-stop fixture did not become ready"
docker top "$backend" -eo pid,ppid,comm,args | grep -Eq '[[:space:]]sh[[:space:]]' ||
  fail "live proxy-stop fixture had no PTY child"
docker stop --time 10 "$proxy" >/dev/null
wait_for_client_exit || fail "proxy stop did not end the client transport"
attempt=0
while [ "$attempt" -lt 50 ]; do
  if ! docker top "$backend" -eo pid,ppid,comm,args |
    grep -Eq '[[:space:]]sh[[:space:]]'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
[ "$attempt" -lt 50 ] || fail "proxy stop left a PTY child"
scan_audit runtime-secrets-proxy-stop.json

docker start "$proxy" >/dev/null
sleep 1
run_client runtime-secrets-backend-stop.json 1
wait_for_client_log REVERSE_PROXY_SESSION_HOLD_READY ||
  fail "live ttygate-stop fixture did not become ready"
docker top "$backend" -eo pid,ppid,comm,args | grep -Eq '[[:space:]]sh[[:space:]]' ||
  fail "live ttygate-stop fixture had no PTY child"
docker stop --time 10 "$backend" >/dev/null
wait_for_client_exit || fail "ttygate stop did not end the client transport"
scan_audit runtime-secrets-backend-stop.json

docker stop --time 10 "$proxy" "$auth" >/dev/null

printf '%s reverse-proxy deployment smoke tests passed.\n' "$proxy_kind"
