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
upgrade, and PTY session. Roadmap Chunk 2.3 is complete (Refs #24):
authenticated session requests and authentication failures are rate-limited,
and configured global/per-identity capacity is reserved when a ticket is issued
and transferred exactly once to the live session. Roadmap Chunk 2.4 is complete (Refs #10):
both modes require a restrictive structured lifecycle audit sink
before application construction or listener binding, and new authority fails
closed if that sink becomes unavailable. Milestone M2 is complete.
Roadmap Chunk 3.1 (Refs #11) implements strict-host-key SSH targets: the
daemon spawns the configured system OpenSSH client inside the existing PTY
machinery with a pinned, non-negotiable option policy, validates SSH
credential material and client capability before binding, and surfaces only
curated failure states. Milestone M3 is complete. Recording, reconnect,
packaging, deployment examples, and release hardening
remain future work, so the current build is still not production-safe.

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

## Rate and concurrency limits

Chunk 2.3 uses first-request-anchored fixed windows measured with monotonic time.
Defaults are 10 session requests per 60 seconds for each authenticated identity
and 20 authentication failures per 60 seconds for each listener-supplied peer
IP. Development and production use the same defaults:

```toml
[limits]
session_requests_per_window = 10
session_request_window_seconds = 60
authentication_failures_per_window = 20
authentication_failure_window_seconds = 60
```

The first and last configured attempts are admitted; the next is rejected
without consuming or extending the window, and capacity recovers at the exact
window boundary. Authentication-failure keys use only the actual listener peer
IP. Session-request keys use the authenticated cookie identity. `Forwarded`,
`X-Forwarded-For`, `X-Real-IP`, Host, query parameters, and WebSocket
subprotocols cannot select either key.

Global and per-identity session capacity is reserved atomically before a ticket
is returned. The opaque ticket owns that reservation until expiry or
correct-identity redemption, which transfers rather than duplicates it into the
live session. Expiry, abandonment, failed spawn, disconnect, close, timeout, and
shutdown release the same reservation. Rate exhaustion returns HTTP 429 with a
positive `Retry-After`; concurrency exhaustion returns HTTP 503 with
`global-session-limit` or `identity-session-limit`. These application limits
bound local state but do not prevent distributed denial of service or host,
socket, proxy, or allowlisted-command exhaustion.

## Lifecycle audit log

Chunk 2.4 implements this audit configuration in development and production:

```toml
[audit]
format = "json"
path = "./ttygate-audit.jsonl"
recording = false
```

The path is literal: ttygate does not expand environment variables or `~`.
Every existing parent must be a real directory rather than a symlink. ttygate
walks those parents through anchored non-following directory descriptors, so a
concurrent parent rename cannot redirect the final open; a raced special file
is opened nonblocking and rejected. The destination must be a regular
non-symlink file. A missing destination is
created owner-only (`0600` on Unix); ttygate rejects an existing file with
group/other permissions or an owner other than the daemon's effective Unix
user, and never weakens it with an automatic `chmod`.
Existing content must end at a complete newline-delimited record.

The sink writes schema-versioned JSONL in append mode. One process-owned mutex
keeps each bounded event on one complete line. Events cover authentication
success, stable access denials, and one correlated start/end pair for every
admitted PTY session, including normal exit, WebSocket disconnect, timeouts,
manager shutdown, caller cancellation, supervisor unwind, and resistant-child
cleanup. Attribution uses only the listener-supplied socket peer; forwarding
headers, Host, query strings, WebSocket subprotocols, and hostile request values
are not audit authority and are not reflected into denial records.

Lifecycle records include identity, configured target name, peer address,
timestamps, stable reasons, and exit outcome where available. They never
include cookies, tickets, credentials, executable paths, arguments,
environment, raw terminal input, or routine terminal output. Recording is a
separate future feature; `recording = false` is currently the only supported
value.
Terminal input and output never appear in lifecycle audit records.

Startup refuses to construct the application or bind a listener if the audit
destination cannot be opened safely. A runtime write or flush failure
permanently marks the process sink unavailable and denies subsequent identity,
ticket, and session authority with stable errors. The JSONL writer flushes the
language-level buffer but does not call `fsync` per event, so recent records can
still be lost on kernel, storage, or power failure.

ttygate does not rotate, retain, ship, back up, or delete audit files.
Operators own rotation and retention and must coordinate them without replacing
the live path behind the daemon. The containing filesystem is a trust boundary;
administrators able to write or truncate the opened inode or underlying storage
remain trusted even though pathname redirects are resisted. Audit metadata is
sensitive even though terminal contents and credentials are excluded.

## Strict OpenSSH targets

Chunk 3.1 (Refs #11) implements `type = "ssh"` targets. The daemon spawns the
configured system OpenSSH client inside the existing PTY, session,
concurrency, audit, and WebSocket machinery:

```toml
[[targets]]
name = "lab-host"
type = "ssh"
host = "lab.example.internal"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "/etc/ttygate/lab_host_ed25519"
known_hosts = "/etc/ttygate/lab_host_known_hosts"
user_policy = "same-as-auth-user"
read_only = false
```

`user_policy` accepts `fixed` (with `user`), `same-as-auth-user`, and `mapping` (with `user_mapping`);
every resolved username must satisfy the same
strict grammar as configured usernames, and an unmapped or invalid resolution
is denied before any process is spawned. `host` uses a closed host-only
grammar: ASCII DNS names or plain IPv4/IPv6 literals; user-qualified
destinations, SSH URIs, brackets, and option-like values are rejected.

All paths are literal: no environment variables, no `~`, no globs. Because
OpenSSH re-parses `-o` option values with its own option lexer,
`identity_file` and `known_hosts` additionally reject whitespace, control
characters, `%`, quotes, backslashes, and `$`, so an accepted path always
reaches OpenSSH byte-identically.

Provisioning: `identity_file` must be one unencrypted OpenSSH-format Ed25519
private key, newline-terminated, owned by the daemon user with owner-only
permissions. `known_hosts` must be a newline-terminated file owned by the
daemon user; its entries are the only host-key trust source. Startup validates
executable safety, material ownership, permissions, size bounds, and identity
structure, and probes the client (`ssh -G`) for the complete pinned option
vocabulary; any gap fails closed before bind, with no weaker runtime fallback.
Material is snapshotted at startup and rechecked before every spawn; a changed
file denies the session instead of trusting new content.

Every session runs with a pinned argv: `StrictHostKeyChecking=yes`, the
configured `UserKnownHostsFile`, `IdentitiesOnly=yes` with the configured
`IdentityFile`, `CertificateFile=/dev/null` (so OpenSSH never implicitly
loads a sibling `<identity>-cert.pub`), `BatchMode=yes`,
`UpdateHostKeys=no` (ttygate never modifies the known-hosts file), disabled
password/keyboard-interactive/hostbased/GSSAPI authentication, no agent, no
X11/port forwarding, no ProxyCommand/ProxyJump, no local command, no escape
character, and a cleared environment with a fixed locale. No browser or
protocol input reaches the argument vector.

Failures surface only as curated states: `ssh-host-key-failed` (unknown and
mismatched host keys intentionally share it), `ssh-connection-failed`,
`ssh-authentication-failed`, `ssh-policy-denied`, and `ssh-failed`. Errors and
audit records never contain hosts, usernames, paths, argv, or OpenSSH
diagnostics.

Compatibility: the pinned vocabulary requires an OpenSSH 9.2 or newer client
(`EnableEscapeCommandline` sets the floor); the suite is exercised against
OpenSSH 10.x. Cleanup guarantees cover the local client only: the daemon
tears down the local SSH process group, but remote commands may outlive the
session if the remote side detaches them from the connection. Deferred scope
includes SSH agent forwarding, certificate authentication, ProxyJump/bastion
chains, password authentication, host-key learning, per-target extra options,
session re-attach, and a native SSH library backend.

## Planned v0.1 posture

The daemon defaults to `127.0.0.1`, but localhost-only binding is only one layer. Local development requires Origin validation, a real browser session cookie, and a short-lived single-use ticket presented as the first WebSocket message. The frontend lists only safe presentation metadata for server-configured targets; executable paths, arguments, SSH options, credentials, and tickets never become target-selection authority. Terminal output uses bounded server and browser queues, and a dropped WebSocket ends the session without automatic reconnect.

The PTY session manager already enforces configured ticket-time global/per-identity concurrency, idle/absolute deadlines, server-side read-only behavior, and bounded output backpressure. Production mode fails closed unless its typed authentication and transport contracts are structurally complete, rejects development authentication and public plaintext binds, and enforces the configured trusted-proxy socket-peer and identity-header boundary. Request rate limits, structured session-lifecycle audit persistence, and strict-host-key OpenSSH targets are implemented. Recording, packaging, deployment examples, and release work remain planned. See the [rewrite plan](docs/ttygate-rewrite-plan.md) for the intended architecture and release checklist.

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
