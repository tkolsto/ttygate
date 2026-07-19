#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
unit_source="$repo_root/packaging/systemd/ttygated.service"
config_source="$repo_root/packaging/systemd/ttygate.toml"
sysusers_source="$repo_root/packaging/systemd/ttygate.sysusers"
tmpfiles_source="$repo_root/packaging/systemd/ttygate.tmpfiles"
binary_source="$repo_root/target/release/ttygated"
unit_name=ttygated-chunk41.service
unit_target="/etc/systemd/system/$unit_name"
config_target=/etc/ttygate/ttygate.toml
binary_target=/usr/local/bin/ttygated
fixture_log=
fixture_pid=
created_user=no

fail() {
  printf 'systemd smoke failed: %s\n' "$1" >&2
  if command -v journalctl >/dev/null 2>&1; then
    sudo journalctl --unit "$unit_name" --no-pager --lines 40 2>/dev/null |
      sed -E 's/[A-Za-z0-9_-]{32,}/[redacted]/g' >&2 || true
  fi
  exit 1
}

cleanup() {
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
    wait "$fixture_pid" >/dev/null 2>&1 || true
  fi
  if [ "${TTYGATE_SYSTEMD_SMOKE:-0}" = 1 ]; then
    sudo systemctl stop "$unit_name" >/dev/null 2>&1 || true
    sudo rm -f "$unit_target" "$config_target" "$binary_target"
    sudo rm -rf "/etc/systemd/system/$unit_name.d"
    sudo rm -rf /etc/ttygate /var/lib/ttygate /var/log/ttygate
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "$created_user" = yes ]; then
      sudo userdel ttygate >/dev/null 2>&1 || true
    fi
  fi
  [ -z "$fixture_log" ] || rm -f "$fixture_log"
}
trap cleanup EXIT HUP INT TERM

if [ "${TTYGATE_SYSTEMD_SMOKE:-0}" != 1 ]; then
  if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify "$unit_source"
    printf 'systemd unit verification passed; set TTYGATE_SYSTEMD_SMOKE=1 on a disposable Linux host for runtime tests.\n'
  else
    printf 'SKIP: systemd-analyze is unavailable; CI performs Linux unit verification and runtime smoke tests.\n'
  fi
  exit 0
fi

[ "$(uname -s)" = Linux ] || fail "runtime smoke requires Linux"
[ "$(ps -p 1 -o comm= | tr -d ' ')" = systemd ] ||
  fail "runtime smoke requires systemd as PID 1"
command -v systemd-analyze >/dev/null 2>&1 ||
  fail "systemd-analyze is unavailable"
command -v systemctl >/dev/null 2>&1 ||
  fail "systemctl is unavailable"
command -v node >/dev/null 2>&1 ||
  fail "Node.js is unavailable for the WebSocket session fixture"
[ -x "$binary_source" ] ||
  fail "build target/release/ttygated before running the runtime smoke"

for path in /etc/ttygate /var/lib/ttygate /var/log/ttygate "$unit_target"; do
  [ ! -e "$path" ] || fail "$path already exists; use a disposable test host"
done
[ ! -e "$binary_target" ] ||
  fail "$binary_target already exists; use a disposable test host"

if ! getent passwd ttygate >/dev/null 2>&1; then
  sudo systemd-sysusers "$sysusers_source"
  created_user=yes
fi

sudo install -D -o root -g root -m 0755 "$binary_source" "$binary_target"
sudo install -D -o root -g ttygate -m 0640 "$config_source" "$config_target"
sudo install -D -o root -g root -m 0644 "$unit_source" "$unit_target"
sudo systemd-tmpfiles --create "$tmpfiles_source"
sudo systemd-analyze verify "$unit_target"
sudo systemctl daemon-reload
sudo systemctl start "$unit_name"

attempt=0
while [ "$attempt" -lt 20 ]; do
  [ "$(sudo systemctl show "$unit_name" --property ActiveState --value)" = active ] &&
    break
  attempt=$((attempt + 1))
  sleep 1
done
[ "$(sudo systemctl show "$unit_name" --property ActiveState --value)" = active ] ||
  fail "service did not reach active state"
[ "$(sudo systemctl show "$unit_name" --property Type --value)" = notify ] ||
  fail "installed service is not Type=notify"
[ "$(sudo systemctl show "$unit_name" --property NotifyAccess --value)" = main ] ||
  fail "installed service does not restrict notifications to the main process"
[ "$(sudo systemctl show "$unit_name" --property WatchdogUSec --value)" = 6s ] ||
  fail "installed watchdog interval differs from the unit"
"$binary_target" --health-check 127.0.0.1:7681 ||
  fail "daemon health check failed"

fixture_log=$(mktemp)
node "$repo_root/scripts/fixtures/docker-session.mjs" >"$fixture_log" 2>&1 &
fixture_pid=$!
attempt=0
while [ "$attempt" -lt 20 ]; do
  grep -q '^SESSION_READY$' "$fixture_log" && break
  kill -0 "$fixture_pid" >/dev/null 2>&1 ||
    fail "session fixture exited before readiness"
  attempt=$((attempt + 1))
  sleep 1
done
grep -q '^SESSION_READY$' "$fixture_log" ||
  fail "session fixture did not create a PTY child"
main_pid=$(sudo systemctl show "$unit_name" --property MainPID --value)
pgrep -P "$main_pid" >/dev/null ||
  fail "live service had no observable PTY child"
control_group=$(sudo systemctl show "$unit_name" --property ControlGroup --value)
[ -n "$control_group" ] || fail "active service has no control group"
service_pids=$(sudo cat "/sys/fs/cgroup$control_group/cgroup.procs")
[ "$(printf '%s\n' "$service_pids" | wc -w | tr -d ' ')" -ge 2 ] ||
  fail "service control group did not contain the daemon and PTY child"
sudo systemctl stop "$unit_name"
for service_pid in $service_pids; do
  if sudo kill -0 "$service_pid" >/dev/null 2>&1; then
    fail "service control-group process survived stop"
  fi
done
kill "$fixture_pid"
wait "$fixture_pid" >/dev/null 2>&1 || true
fixture_pid=

sudo systemctl start "$unit_name"
old_pid=$(sudo systemctl show "$unit_name" --property MainPID --value)
old_watchdog=$(sudo systemctl show "$unit_name" --property WatchdogTimestampMonotonic --value)
sleep 4
new_watchdog=$(sudo systemctl show "$unit_name" --property WatchdogTimestampMonotonic --value)
[ "$new_watchdog" -gt "$old_watchdog" ] ||
  fail "watchdog keepalive timestamp did not advance"
sudo kill -STOP "$old_pid"
attempt=0
new_pid=$old_pid
while [ "$attempt" -lt 20 ]; do
  new_pid=$(sudo systemctl show "$unit_name" --property MainPID --value)
  [ "$new_pid" -gt 0 ] && [ "$new_pid" != "$old_pid" ] && break
  attempt=$((attempt + 1))
  sleep 1
done
[ "$new_pid" -gt 0 ] && [ "$new_pid" != "$old_pid" ] ||
  fail "systemd did not restart a watchdog-stalled daemon"
"$binary_target" --health-check 127.0.0.1:7681 ||
  fail "restarted daemon did not become healthy"

sudo systemctl stop "$unit_name"
sudo install -o ttygate -g ttygate -m 0644 /dev/null /var/log/ttygate/audit.jsonl
sudo mkdir -p "/etc/systemd/system/$unit_name.d"
printf '[Service]\nRestart=no\n' |
  sudo tee "/etc/systemd/system/$unit_name.d/smoke.conf" >/dev/null
sudo systemctl daemon-reload
if sudo systemctl start "$unit_name"; then
  fail "unsafe audit permissions did not fail closed"
fi
unsafe_log=$(sudo journalctl --unit "$unit_name" --since '-10 seconds' \
  --output cat --no-pager 2>&1)
printf '%s' "$unsafe_log" | grep -q 'Audit(UnsafeDestination)' ||
  fail "unsafe permission failure lacked useful stable diagnostics"
printf '%s' "$unsafe_log" | grep -Eq '/var/log|audit\.jsonl|[A-Za-z0-9_-]{32,}' &&
  fail "unsafe permission diagnostics exposed a path or secret-like value"

printf 'systemd packaging smoke tests passed.\n'
