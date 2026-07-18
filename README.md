# ttygate

ttygate is a security-first browser terminal gateway inspired by Shell In A Box.

> [!WARNING]
> Browser terminals are security-sensitive: they expose shell-equivalent authority to a web application. Binding a service to localhost is not a complete security boundary—malicious websites can reach local services from a user's browser, and DNS rebinding can defeat host-based assumptions. Do not expose an unfinished or development build to another machine or an untrusted network.

## Current status

ttygate is pre-release software. Milestone M1, completed by issue #7, provides an accessible xterm.js browser terminal over the Rust HTTP daemon, explicit browser Origin checks, a development identity cookie, bounded single-use session tickets, an authenticated ticket-bound WebSocket bridge, safe configured-target discovery, and an allowlisted PTY session backend with bounded I/O and guaranteed process-group teardown. SSH execution, production authentication and transport gating, audit persistence, and deployment controls are still planned.

Follow the [roadmap](docs/roadmap.md) for implementation status. Until the roadmap says otherwise, do not deploy ttygate or rely on it to protect terminal access.

## Repository quickstart

The current quickstart verifies and builds the repository. The browser smoke suite launches an isolated loopback daemon and disposable PTY fixtures; it does not make the pre-release build production-safe.

Prerequisites:

- A stable Rust toolchain with `rustfmt` and Clippy
- Node.js 22 or later with npm

From the repository root:

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings

npm --prefix frontend ci
npm --prefix frontend run check
npm --prefix frontend run build
npm --prefix frontend test
npm --prefix frontend run test:e2e
```

These commands test the HTTP/config/protocol foundations, authenticated WebSocket bridge, PTY session lifecycle, frontend state machine, and a real Chromium-to-PTY terminal flow, then build the static frontend into `frontend/dist/`.

## Planned v0.1 posture

The daemon defaults to `127.0.0.1`, but localhost-only binding is only one layer. Local development requires Origin validation, a real browser session cookie, and a short-lived single-use ticket presented as the first WebSocket message. The frontend lists only safe presentation metadata for server-configured targets; executable paths, arguments, SSH options, credentials, and tickets never become target-selection authority. Terminal output uses bounded server and browser queues, and a dropped WebSocket ends the session without automatic reconnect.

The PTY session manager already enforces configured global/per-identity concurrency, idle/absolute deadlines, server-side read-only behavior, and bounded output backpressure. Production mode is planned to fail closed unless real authentication and either direct TLS or an explicitly trusted reverse proxy are configured. It will add request rate limits and structured session-lifecycle audit persistence. These production controls are not implemented yet; see the [rewrite plan](docs/ttygate-rewrite-plan.md) for the intended architecture and release checklist.

## Security model and non-goals

The [threat model](docs/threat-model.md) documents the trust boundaries, attacker capabilities, planned controls, and residual risks. Important v0.1 non-goals include:

- no `/bin/login`-style host authentication or default browser-exposed host login;
- no arbitrary commands supplied by browser requests;
- no session sharing, collaboration, or reconnect after a dropped WebSocket;
- no built-in enterprise identity platform;
- no drop-in compatibility with `shellinaboxd`;
- no OS-level separation between authenticated users of local PTY targets.

For local PTY targets, every child process will run as the daemon's dedicated non-root Unix user. Application policy and audit attribution do not create an OS security boundary between authenticated users. SSH or a future container backend is the intended route to stronger per-user isolation.

## Relationship to Shell In A Box

ttygate is inspired by Shell In A Box, not a fork and not a drop-in replacement. It retains the useful product idea while pursuing a new Rust backend, a current xterm.js frontend, standard WebSockets, and an explicit security model.

This is a clean-room project. No code or prose is copied or adapted from Shell In A Box or its forks. Contributors must follow the non-negotiable [clean-room rule](CONTRIBUTING.md#clean-room-rule-non-negotiable).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes, especially the requirements for security-sensitive work and negative-path tests.

If you believe you found a vulnerability, do not open a public issue. Follow the private process in [SECURITY.md](SECURITY.md).

## License

ttygate is dual-licensed under your choice of the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), expressed as `MIT OR Apache-2.0`.
