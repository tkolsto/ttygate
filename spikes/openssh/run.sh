#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cargo_bin="${CARGO:-$(rustup which cargo)}"
export PATH="$(dirname "${cargo_bin}"):${PATH}"
mkdir -p "${repo_root}/spikes/openssh/.tmp"
tmp="$(mktemp -d "${repo_root}/spikes/openssh/.tmp/run.XXXXXX")"
container="ttygate-openssh-spike-$$"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}
trap cleanup EXIT INT TERM

chmod 0700 "${tmp}"
ssh-keygen -q -t ed25519 -N '' -f "${tmp}/client_key"
ssh-keygen -q -t ed25519 -N '' -f "${tmp}/ssh_host_ed25519_key"
ssh-keygen -q -t ed25519 -N '' -f "${tmp}/wrong_host_key"

docker build -q -t ttygate-openssh-spike:local "${repo_root}/spikes/openssh/sshd" >/dev/null
docker run -d --name "${container}" \
  -p 127.0.0.1::2222 \
  -v "${tmp}:/fixture:ro" \
  ttygate-openssh-spike:local >/dev/null

for _ in $(seq 1 50); do
  mapping="$(docker port "${container}" 2222/tcp 2>/dev/null || true)"
  if [[ -n "${mapping}" ]]; then break; fi
  sleep 0.1
done
if [[ -z "${mapping:-}" ]]; then
  echo "sshd port was not published" >&2
  docker logs "${container}" >&2 || true
  exit 1
fi
port="${mapping##*:}"

host_type="$(awk '{print $1}' "${tmp}/ssh_host_ed25519_key.pub")"
host_data="$(awk '{print $2}' "${tmp}/ssh_host_ed25519_key.pub")"
wrong_type="$(awk '{print $1}' "${tmp}/wrong_host_key.pub")"
wrong_data="$(awk '{print $2}' "${tmp}/wrong_host_key.pub")"
printf '[127.0.0.1]:%s %s %s\n' "${port}" "${host_type}" "${host_data}" >"${tmp}/known_hosts"
: >"${tmp}/empty_known_hosts"
printf '[127.0.0.1]:%s %s %s\n' "${port}" "${wrong_type}" "${wrong_data}" >"${tmp}/mismatch_known_hosts"

refused_port=1
"${cargo_bin}" run --quiet --manifest-path "${repo_root}/spikes/openssh/Cargo.toml" -- \
  "${port}" "${tmp}/client_key" "${tmp}/known_hosts" \
  "${tmp}/empty_known_hosts" "${tmp}/mismatch_known_hosts" "${refused_port}"

sleep 0.2
session_children="$(docker exec "${container}" sh -c "pgrep -a sshd | grep -v 'listener' || true")"
[[ -z "${session_children}" ]] || {
  echo "orphan sshd session child remains: ${session_children}" >&2
  exit 1
}
echo "PASS OpenSSH server: no lingering sshd session child; cleanup armed"
