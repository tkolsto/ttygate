# 0001: License — MIT OR Apache-2.0

- Date: 2026-07-11
- Status: accepted

## Context

The rewrite plan recommended a permissive license unless something forced GPL
separation. Nothing does: ttygate is a clean-room reimplementation and shares
no code with the GPL-2.0 shellinabox codebase.

## Decision

Dual-license the repository `MIT OR Apache-2.0`, the Rust ecosystem
convention (Apache-2.0 provides an explicit patent grant; MIT maximizes
compatibility).

## Consequences

- `LICENSE-MIT` and `LICENSE-APACHE` at the repo root; workspace manifest
  declares `license = "MIT OR Apache-2.0"`.
- The clean-room rule in CONTRIBUTING.md is mandatory: no code from
  shellinabox or its forks may enter this repository.
- Dependencies must be permissive-compatible; enforced by `cargo deny`
  (see `deny.toml`).
