#!/bin/sh

set -eu

run_id="ttygate-packaging-$$"
image_one="$run_id:runtime"
archive_one="/tmp/$run_id-first.oci.tar"
archive_two="/tmp/$run_id-second.oci.tar"
container="$run_id-daemon"
client="$run_id-client"
unsafe="$run_id-unsafe"
network="$run_id-network"
audit_volume="$run_id-audit"
node_image="node:22.21.1-bookworm-slim@sha256:25b3eb23a00590b7499f2a2ce939322727fcce1b15fdd69754fcd09536a3ae2c"

fail() {
  printf 'Docker smoke failed: %s\n' "$1" >&2
  if docker inspect "$container" >/dev/null 2>&1; then
    docker inspect --format 'daemon state={{json .State}} health={{json .State.Health}}' "$container" >&2 || true
    docker logs --tail 40 "$container" 2>&1 | sed -E 's/[A-Za-z0-9_-]{32,}/[redacted]/g' >&2 || true
  fi
  if docker inspect "$unsafe" >/dev/null 2>&1; then
    docker logs --tail 40 "$unsafe" 2>&1 | sed -E 's/[A-Za-z0-9_-]{32,}/[redacted]/g' >&2 || true
  fi
  exit 1
}

cleanup() {
  docker rm -f "$client" "$unsafe" "$container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm -f "$audit_volume" >/dev/null 2>&1 || true
  docker image rm -f "$image_one" >/dev/null 2>&1 || true
  rm -f "$archive_one" "$archive_two"
}
trap cleanup EXIT HUP INT TERM

docker buildx build \
  --build-arg "CACHE_SCOPE=$run_id" \
  --build-arg SOURCE_DATE_EPOCH=1769990400 \
  --no-cache \
  --provenance=false \
  --output "type=oci,dest=$archive_one,rewrite-timestamp=true" \
  --tag "$image_one" \
  .
first_index=$(tar -xOf "$archive_one" index.json)

docker buildx build \
  --build-arg "CACHE_SCOPE=$run_id" \
  --build-arg SOURCE_DATE_EPOCH=1769990400 \
  --no-cache \
  --provenance=false \
  --output "type=oci,dest=$archive_two,rewrite-timestamp=true" \
  --tag "$image_one" \
  .
second_index=$(tar -xOf "$archive_two" index.json)
[ "$first_index" = "$second_index" ] ||
  fail "clean repeated builds produced different image identities"
docker buildx build \
  --build-arg "CACHE_SCOPE=$run_id" \
  --build-arg SOURCE_DATE_EPOCH=1769990400 \
  --provenance=false \
  --load \
  --tag "$image_one" \
  . >/dev/null

[ "$(docker image inspect --format '{{.Config.User}}' "$image_one")" = "ttygate:ttygate" ] ||
  fail "runtime image user is not ttygate:ttygate"
health_command=$(docker image inspect --format '{{json .Config.Healthcheck.Test}}' "$image_one")
[ "$health_command" = '["CMD","/usr/local/bin/ttygated","--health-check","127.0.0.1:7681"]' ] ||
  fail "image health command does not use the daemon /healthz checker"

docker run --rm --entrypoint /bin/sh "$image_one" -ec '
  test "$(id -u ttygate)" = 65532
  test "$(id -g ttygate)" = 65532
  test -x /usr/local/bin/ttygated
  test -x /usr/bin/ssh
  test -x /bin/sh
  test ! -e /build
  test ! -e /workspace
  test ! -e /usr/local/cargo
  test ! -e /root/.npm
  test ! -e /var/lib/apt/lists/lock
  test -z "$(find /var/lib/apt/lists /var/cache/apt -mindepth 1 -print -quit)"
  ! command -v cargo >/dev/null 2>&1
  ! command -v rustc >/dev/null 2>&1
  ! command -v node >/dev/null 2>&1
  ! command -v npm >/dev/null 2>&1
  ! command -v gcc >/dev/null 2>&1
'

docker network create --internal "$network" >/dev/null
docker volume create "$audit_volume" >/dev/null
docker run --detach \
  --name "$container" \
  --network "$network" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
  --mount "type=volume,src=$audit_volume,dst=/var/log/ttygate" \
  "$image_one" >/dev/null

attempt=0
while [ "$attempt" -lt 30 ]; do
  state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")
  [ "$state" = "healthy" ] && break
  [ "$state" = "unhealthy" ] && fail "container health state became unhealthy"
  attempt=$((attempt + 1))
  sleep 1
done
[ "${state:-}" = "healthy" ] || fail "container did not become healthy"

[ "$(docker exec "$container" id -u)" = "65532" ] ||
  fail "running container is not the dedicated non-root UID"
[ "$(docker exec "$container" id -g)" = "65532" ] ||
  fail "running container is not the dedicated non-root GID"
[ "$(docker exec "$container" sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/1/status')" = "0000000000000000" ] ||
  fail "running container retained effective Linux capabilities"
docker exec "$container" /usr/local/bin/ttygated --health-check 127.0.0.1:7681 ||
  fail "internal /healthz command failed"
if docker exec "$container" sh -c 'touch /must-not-write' >/dev/null 2>&1; then
  fail "read-only root filesystem accepted a write"
fi
docker exec "$container" sh -c 'touch /var/log/ttygate/smoke-write && rm /var/log/ttygate/smoke-write' ||
  fail "explicit audit path was not writable"

port_bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container")
case "$port_bindings" in
  '{}' | null) ;;
  *) fail "default container unexpectedly published a host port" ;;
esac
[ -z "$(docker port "$container" 7681/tcp 2>/dev/null)" ] ||
  fail "default container exposed its loopback listener on the host"

docker run --detach \
  --name "$client" \
  --network "container:$container" \
  --mount "type=bind,src=$PWD/scripts/fixtures/docker-session.mjs,dst=/fixture.mjs,readonly" \
  --entrypoint node \
  "$node_image" /fixture.mjs >/dev/null
attempt=0
while [ "$attempt" -lt 20 ]; do
  docker logs "$client" 2>&1 | grep -q '^SESSION_READY$' && break
  client_state=$(docker inspect --format '{{.State.Status}}' "$client")
  [ "$client_state" = "exited" ] && fail "session fixture exited before readiness"
  attempt=$((attempt + 1))
  sleep 1
done
docker logs "$client" 2>&1 | grep -q '^SESSION_READY$' ||
  fail "session fixture did not create a live PTY child"
docker top "$container" -eo pid,ppid,comm,args | grep -Eq '[[:space:]](sh|sleep)[[:space:]]' ||
  fail "live daemon session had no observable child process"

docker stop --time 10 "$container" >/dev/null
[ "$(docker inspect --format '{{.State.Status}}' "$container")" = "exited" ] ||
  fail "container did not stop"
[ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0 ] ||
  fail "container did not complete graceful SIGTERM shutdown"
docker rm "$container" >/dev/null
if docker inspect "$container" >/dev/null 2>&1; then
  fail "stopped daemon container survived removal"
fi
docker rm -f "$client" >/dev/null 2>&1 || true

docker run --rm --user 0:0 \
  --mount "type=volume,src=$audit_volume,dst=/var/log/ttygate" \
  --entrypoint /bin/sh "$image_one" \
  -ec 'chmod 0644 /var/log/ttygate/audit.jsonl'
docker run --name "$unsafe" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
  --mount "type=volume,src=$audit_volume,dst=/var/log/ttygate" \
  "$image_one" >/dev/null 2>&1 &&
  fail "unsafe audit permissions did not fail closed"
[ "$(docker inspect --format '{{.State.ExitCode}}' "$unsafe")" -ne 0 ] ||
  fail "unsafe audit container returned success"
unsafe_log=$(docker logs "$unsafe" 2>&1)
printf '%s' "$unsafe_log" | grep -q 'Audit(UnsafeDestination)' ||
  fail "unsafe permission failure lacked useful stable diagnostics"
printf '%s' "$unsafe_log" | grep -Eq '/var/log|audit\.jsonl|ttygate\.toml|[A-Za-z0-9_-]{32,}' &&
  fail "unsafe permission diagnostics exposed a path or secret-like value"

docker rm "$unsafe" >/dev/null
docker network inspect "$network" >/dev/null ||
  fail "smoke network disappeared before cleanup verification"
docker volume inspect "$audit_volume" >/dev/null ||
  fail "smoke audit volume disappeared before cleanup verification"

printf 'Docker packaging smoke tests passed.\n'
