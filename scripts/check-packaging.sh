#!/bin/sh

set -eu

fail() {
  printf 'packaging check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "$1 is missing"
}

require_text() {
  file=$1
  pattern=$2
  description=$3
  grep -Eq "$pattern" "$file" || fail "$file lacks $description"
}

reject_text() {
  file=$1
  pattern=$2
  description=$3
  if grep -Eq "$pattern" "$file"; then
    fail "$file contains $description"
  fi
}

DOCKERFILE=Dockerfile
DOCKERIGNORE=.dockerignore
DOCKER_CONFIG=packaging/docker/ttygate.toml
DOCKER_README=packaging/docker/README.md
SYSTEMD_UNIT=packaging/systemd/ttygated.service
SYSTEMD_SYSUSERS=packaging/systemd/ttygate.sysusers
SYSTEMD_TMPFILES=packaging/systemd/ttygate.tmpfiles
SYSTEMD_CONFIG=packaging/systemd/ttygate.toml
SYSTEMD_README=packaging/systemd/README.md
CI_WORKFLOW=.github/workflows/ci.yml

for file in \
  "$DOCKERFILE" \
  "$DOCKERIGNORE" \
  "$DOCKER_CONFIG" \
  "$DOCKER_README" \
  "$SYSTEMD_UNIT" \
  "$SYSTEMD_SYSUSERS" \
  "$SYSTEMD_TMPFILES" \
  "$SYSTEMD_CONFIG" \
  "$SYSTEMD_README"; do
  require_file "$file"
done

stage_count=$(grep -Ec '^FROM [^ ]+@sha256:[0-9a-f]{64}( AS [a-z][a-z0-9-]*)?$' "$DOCKERFILE")
[ "$stage_count" -eq 3 ] ||
  fail "$DOCKERFILE must contain exactly three digest-pinned stages"
require_text "$DOCKERFILE" '^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$' 'a digest-pinned Dockerfile frontend'
require_text "$DOCKERFILE" '^FROM .* AS frontend$' 'a frontend builder stage'
require_text "$DOCKERFILE" '^FROM .* AS builder$' 'a Rust builder stage'
require_text "$DOCKERFILE" '^FROM .* AS runtime$' 'a minimal runtime stage'
require_text "$DOCKERFILE" '^FROM rust:[0-9]+\.[0-9]+\.[0-9]+-[^@]+@sha256:' 'an exact digest-pinned Rust toolchain'
reject_text "$DOCKERFILE" '^COPY .*rust-toolchain\.toml' 'a floating stable toolchain input'
require_text "$DOCKERFILE" 'npm ci' 'a locked frontend dependency install'
require_text "$DOCKERFILE" 'cargo build .*--locked.*--release|cargo build .*--release.*--locked' 'a locked release build'
require_text "$DOCKERFILE" 'snapshot\.debian\.org/archive/debian/[0-9]{8}T[0-9]{6}Z' 'an immutable Debian package snapshot'
require_text "$DOCKERFILE" '^ARG SOURCE_DATE_EPOCH=1769990400$' 'the pinned Debian snapshot epoch'
require_text "$DOCKERFILE" 'touch --no-dereference --date="@\$\{SOURCE_DATE_EPOCH\}"' 'generated-file timestamp normalization'
require_text scripts/smoke-docker.sh 'rewrite-timestamp=true' 'layer timestamp normalization during OCI export'
require_text scripts/smoke-docker.sh 'docker buildx build' 'portable BuildKit exporter invocation'
require_text scripts/smoke-docker.sh '[[:space:]]--load' 'portable runtime image load through Buildx'
reject_text scripts/smoke-docker.sh 'docker load[[:space:]]+--input' 'direct OCI archive loading into the classic Docker image store'
require_text "$CI_WORKFLOW" 'docker/setup-buildx-action@[0-9a-f]{40}' 'a digest-pinned portable BuildKit builder'
require_text "$DOCKERFILE" 'rm -f /etc/apt/sources\.list\.d/debian\.sources' 'removal of mutable Debian package sources'
require_text "$DOCKERFILE" 'groupadd .*ttygate|addgroup .*ttygate' 'a dedicated runtime group'
require_text "$DOCKERFILE" 'useradd .*ttygate|adduser .*ttygate' 'a dedicated runtime user'
require_text "$DOCKERFILE" '^USER ttygate:ttygate$|^USER [0-9]+:[0-9]+$' 'a non-root runtime user'
require_text "$DOCKERFILE" '^ENTRYPOINT \["/usr/local/bin/ttygated"\]$' 'direct daemon entrypoint'
require_text "$DOCKERFILE" '^CMD \["/etc/ttygate/ttygate.toml"\]$' 'explicit config path'
require_text "$DOCKERFILE" '^HEALTHCHECK .*CMD \["/usr/local/bin/ttygated", "--health-check"' 'daemon /healthz health check'
require_text "$DOCKERFILE" '/var/log/ttygate' 'the explicit audit path'
require_text "$DOCKERFILE" '/etc/ttygate/ssh' 'the explicit SSH material path'
reject_text "$DOCKERFILE" '(curl|wget)[[:space:]]+.*healthz' 'a shell/external HTTP health check'
reject_text "$DOCKERFILE" 'COPY --from=(frontend|builder) /(root|usr/local/cargo|workspace|src|app)(/| )' 'a builder source or toolchain copy'

for pattern in \
  '^\.git$' \
  '^\.worktrees$' \
  '^target$' \
  '^frontend/node_modules$' \
  '^frontend/playwright-report$' \
  '^frontend/test-results$' \
  '^crates/ttygated/tests$' \
  '^spikes$' \
  '^\*\*/\*\.key$' \
  '^\*\*/known_hosts\*$'; do
  require_text "$DOCKERIGNORE" "$pattern" "build-context exclusion $pattern"
done

for config in "$DOCKER_CONFIG" "$SYSTEMD_CONFIG"; do
  require_text "$config" '^bind = "127\.0\.0\.1:7681"$' 'localhost-only listener'
  require_text "$config" '^mode = "dev"$' 'safe development mode default'
  require_text "$config" '^public_url = "http://127\.0\.0\.1:7681"$' 'matching loopback public URL'
  require_text "$config" '^recording = false$' 'disabled recording'
done
require_text "$DOCKER_CONFIG" '^path = "/var/log/ttygate/audit\.jsonl"$' 'container audit destination'
require_text "$SYSTEMD_CONFIG" '^path = "/var/log/ttygate/audit\.jsonl"$' 'systemd audit destination'

for directive in \
  '^Type=notify$' \
  '^NotifyAccess=main$' \
  '^WatchdogSec=[1-9][0-9]*s$' \
  '^User=ttygate$' \
  '^Group=ttygate$' \
  '^NoNewPrivileges=yes$' \
  '^ProtectSystem=strict$' \
  '^ProtectHome=yes$' \
  '^PrivateDevices=yes$' \
  '^PrivateTmp=yes$' \
  '^PrivateMounts=yes$' \
  '^ProtectKernelTunables=yes$' \
  '^ProtectKernelModules=yes$' \
  '^ProtectKernelLogs=yes$' \
  '^ProtectControlGroups=yes$' \
  '^ProtectClock=yes$' \
  '^ProtectHostname=yes$' \
  '^RestrictNamespaces=yes$' \
  '^RestrictRealtime=yes$' \
  '^RestrictSUIDSGID=yes$' \
  '^LockPersonality=yes$' \
  '^MemoryDenyWriteExecute=yes$' \
  '^CapabilityBoundingSet=$' \
  '^AmbientCapabilities=$' \
  '^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6$' \
  '^SystemCallArchitectures=native$' \
  '^SystemCallFilter=@system-service$' \
  '^UMask=0077$' \
  '^KillMode=control-group$' \
  '^Restart=on-failure$' \
  '^StateDirectory=ttygate$' \
  '^LogsDirectory=ttygate$'; do
  require_text "$SYSTEMD_UNIT" "$directive" "hardening directive $directive"
done

require_text "$SYSTEMD_UNIT" '^ExecStart=/usr/local/bin/ttygated /etc/ttygate/ttygate\.toml$' 'literal daemon/config argv'
reject_text "$SYSTEMD_UNIT" '^Environment=.*(PASSWORD|TOKEN|SECRET|KEY)=' 'inline secret environment'
reject_text "$SYSTEMD_UNIT" '^PrivateNetwork=no$|^PrivateUsers=no$' 'silent explicit sandbox weakening'
require_text "$SYSTEMD_SYSUSERS" '^u ttygate - "ttygate daemon" /var/lib/ttygate /usr/sbin/nologin$' 'dedicated system account'
require_text "$SYSTEMD_TMPFILES" '^d /var/lib/ttygate 0700 ttygate ttygate - -$' 'private state directory'
require_text "$SYSTEMD_TMPFILES" '^d /var/log/ttygate 0700 ttygate ttygate - -$' 'private audit directory'

require_text "$DOCKER_README" 'root-owned.*configuration|configuration.*root-owned' 'root-owned container configuration guidance'
require_text "$DOCKER_README" 'UID.*GID|uid.*gid' 'stable container identity guidance'
require_text "$DOCKER_README" 'loopback|localhost' 'container loopback boundary'
require_text "$DOCKER_README" 'read-only' 'read-only root filesystem guidance'
require_text "$SYSTEMD_README" 'PrivateNetwork' 'network namespace exception'
require_text "$SYSTEMD_README" 'PrivateUsers' 'user namespace exception'
require_text "$SYSTEMD_README" 'owner|ownership' 'SSH and audit ownership contract'
require_text "$SYSTEMD_README" 'systemd-analyze' 'unit verification command'
# shellcheck disable=SC2016 # The dollar sign is literal script text in this regex.
require_text scripts/smoke-systemd.sh '/sys/fs/cgroup\$control_group/cgroup\.procs' 'runtime service-cgroup PID capture'
require_text scripts/smoke-systemd.sh 'service control-group process survived stop' 'runtime service-cgroup teardown assertion'
require_text scripts/smoke-systemd.sh 'wait_for_health' 'bounded restarted-daemon readiness verification'

printf 'All packaging contract checks passed.\n'
