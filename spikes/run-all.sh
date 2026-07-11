#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for spike in web-stack pty openssh; do
  echo "==> ${spike} spike"
  "${repo_root}/spikes/${spike}/run.sh"
done
