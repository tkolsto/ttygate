# Contributing to ttygate

Thanks for contributing. Two rules are non-negotiable; everything else is
ordinary open-source hygiene.

## Clean-Room Rule (non-negotiable)

ttygate is dual-licensed `MIT OR Apache-2.0`. Shell In A Box is GPL-2.0.

No code of any kind — Rust, C, JavaScript, TypeScript, CSS, HTML, shell,
build scripts, or configuration — may be copied or adapted from the
`shellinabox/shellinabox` repository or any of its forks into this
repository. ttygate is inspired by Shell In A Box's *idea*; it must contain
none of its *expression*. If you have studied the shellinabox source closely,
describe behavior in an issue instead of writing the corresponding ttygate
code yourself.

By submitting a contribution you certify it is your own work (or compatibly
licensed) under the terms of both LICENSE-MIT and LICENSE-APACHE.

## Security-Sensitive Changes (non-negotiable)

This project is a browser terminal gateway; most of it is attack surface.
Changes touching authentication, session/ticket handling, Origin checks,
process spawning, SSH options, or config validation must:

- state the threat-model impact in the PR description, and
- include tests for the rejection/negative paths, not just the happy path.

Suspected vulnerabilities go to the process in SECURITY.md, not the public
issue tracker.

## Practical Notes

- CI must be green: `cargo fmt --all --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --workspace`, `cargo deny check`, and the frontend
  `npm run check && npm run build`.
- Fix warnings; do not suppress them without a comment explaining why.
- No `TODO`/`FIXME` comments — use `NOTE` or open an issue.
- Architecture decisions are recorded in `docs/decisions/`.
