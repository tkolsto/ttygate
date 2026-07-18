# ttygate

ttygate is a security-first browser terminal gateway inspired by Shell In A Box.

> [!WARNING]
> Browser terminals are security-sensitive: they expose shell-equivalent authority to a web application. Binding a service to localhost is not a complete security boundary—malicious websites can reach local services from a user's browser, and DNS rebinding can defeat host-based assumptions. Do not expose an unfinished or development build to another machine or an untrusted network.

## Current status

ttygate is pre-release software. Milestone M1, completed by issue #7, provides an accessible xterm.js browser terminal over the Rust daemon, explicit browser Origin checks, a development identity cookie, bounded single-use session tickets, an authenticated ticket-bound WebSocket bridge, safe configured-target discovery, and an allowlisted PTY session backend with bounded I/O and guaranteed process-group teardown.

Roadmap Chunk 2.1 (Refs #8) adds typed `dev`/`production` mode gating,
restricts the development identity to loopback binds, rejects unsafe production
configuration before application construction or listener binding, and
implements one direct rustls listener for HTTPS and WSS. Roadmap Chunk 2.2 is complete (Refs #9): production trusted-proxy authentication now verifies the actual
socket peer against configured CIDRs, consumes one configured identity header,
and binds that identity through the secure browser cookie, session ticket, WSS
upgrade, and PTY session. Rate limiting, audit persistence, SSH, recording,
reconnect, packaging, and release hardening remain future work, so the current
build is still not production-safe.

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

## Direct TLS development configuration

Direct TLS is available for loopback development. Its certificate and private-key configuration belongs in the relevant server and authentication sections:

```toml
[server]
bind = "127.0.0.1:7681"
mode = "dev"
public_url = "https://localhost:7681"

[server.tls]
certificate = "/absolute/path/to/certificate-chain.pem"
private_key = "/absolute/path/to/private-key.pem"

[auth]
provider = "dev"
user = "local"
```

Both TLS paths must be absolute regular files rather than symlinks. Certificate
and key reads are bounded; the PEM must contain one matching key, and on Unix the
private key must not grant group or other permissions. Startup failures use
stable, secret-safe diagnostics that never include certificate/key paths, PEM
contents, or parser source errors.

The TLS listener serves the frontend, API, health endpoint, and WebSocket on the
same authority. HTTPS/WSS Origin checks still use the exact `public_url`, secure
cookie attributes are unchanged, and TLS failure never falls back to plaintext
HTTP. Self-signed certificates are used only inside isolated integration tests;
they are not production-safe.

## Trusted reverse-proxy authentication

The implemented production trusted-proxy configuration has this exact shape:

```toml
[server]
bind = "127.0.0.1:7681"
mode = "production"
public_url = "https://terminal.example.com"

[server.trusted_proxy]
trusted_sources = ["127.0.0.1/32"]

[auth]
provider = "trusted-proxy"
identity_header = "x-auth-request-user"
```

The listener is plaintext inside the protected proxy-to-daemon network boundary;
the proxy terminates TLS for the public HTTPS/WSS authority. ttygate treats only
the actual socket peer address supplied by the listener as authoritative. It
ignores `Forwarded`, `X-Forwarded-For`, and similar client-controlled address
claims, and it accepts a request only when that peer belongs to one of
`trusted_sources`. IPv4 and IPv6 CIDRs are matched in their original address
families; an IPv4-mapped IPv6 peer is not converted into IPv4 for matching.

After the peer check, ttygate requires exactly one occurrence of
`identity_header`. The semantic HTTP field value exposed by the HTTP parser must
be valid UTF-8, contain 1 through 128 bytes, and contain no Unicode whitespace
or control character. HTTP field-line optional whitespace is framing and is
removed by the parser before ttygate receives the semantic value. ttygate does
not trim, case-fold, Unicode-normalize, split, or otherwise transform that
semantic value, so accepted identity bytes remain case-sensitive and distinct.

The trusted proxy must authenticate the upstream user, reject or normalize
ambiguous upstream surrounding whitespace before injection, strip every
client-supplied instance of the configured identity header, and inject exactly
one canonical identity header. It must also be the only component able to reach
the backend from a trusted CIDR; direct public access to the backend must be
blocked. A compromised trusted proxy can impersonate any user, and CIDR checks
do not reduce that residual risk. This is the application contract, not a
ready-to-copy deployment example; concrete hardened proxy examples remain
future work.

On `POST /api/identity`, the verified header identity is stored behind the same
opaque secure, HTTP-only, SameSite browser cookie used in development. Later
session and WSS requests authenticate that cookie after rechecking the socket
peer; they never reread an identity header to replace the cookie-bound
identity. Tickets remain short-lived, single-use, target-bound, and
identity-bound.

## Planned v0.1 posture

The daemon defaults to `127.0.0.1`, but localhost-only binding is only one layer. Local development requires Origin validation, a real browser session cookie, and a short-lived single-use ticket presented as the first WebSocket message. The frontend lists only safe presentation metadata for server-configured targets; executable paths, arguments, SSH options, credentials, and tickets never become target-selection authority. Terminal output uses bounded server and browser queues, and a dropped WebSocket ends the session without automatic reconnect.

The PTY session manager already enforces configured global/per-identity concurrency, idle/absolute deadlines, server-side read-only behavior, and bounded output backpressure. Production mode fails closed unless its typed authentication and transport contracts are structurally complete, rejects development authentication and public plaintext binds, and enforces the configured trusted-proxy socket-peer and identity-header boundary. Request rate limits and structured session-lifecycle audit persistence remain planned; see the [rewrite plan](docs/ttygate-rewrite-plan.md) for the intended architecture and release checklist.

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
