#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cargo_bin="${CARGO:-$(rustup which cargo)}"
export PATH="$(dirname "${cargo_bin}"):${PATH}"

"${cargo_bin}" run --quiet --manifest-path "${repo_root}/spikes/pty/Cargo.toml"
