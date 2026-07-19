# ttygate Rewrite Plan

## Purpose

Build `ttygate`, a security-first browser terminal gateway inspired by Shell In A Box. The project should use the visibility of a `shellinabox` fork for discovery and historical context, but the production direction is a clean reimplementation rather than a long-term revival of the legacy C daemon.

The first public artifact should make the security posture obvious: small backend, modern terminal frontend, localhost-only default that is itself hardened against browser-based attacks, explicit production configuration, structured audit logs, and a documented threat model.

## Recommendation

Proceed with a split architecture:

- Keep a GitHub fork of `shellinabox/shellinabox` for visibility, issue triage, and an audit/migration note.
- Build the successor as a new repo named `ttygate`.
- Implement the backend in Rust unless schedule pressure strongly favors Go. Rust is the better default for Linux/security/systems credibility and memory-safety positioning.
- Use xterm.js for terminal rendering instead of maintaining terminal emulation code.
- Use standard RFC 6455 WebSocket transport instead of legacy AJAX polling or old WebSocket drafts.
- Implement the SSH backend by driving the system OpenSSH client in a PTY, not by embedding an SSH library. This inherits battle-tested crypto, strict host-key verification, and agent support, and keeps security-sensitive surface out of our code.

Do not try to make the C daemon production-modern as the primary path. The old code has too much security-sensitive custom surface: HTTP parsing, WebSocket framing, TLS loading, privilege handling, PAM/login integration, PTY management, command parsing, and terminal frontend code.

## Product Positioning

README positioning:

> ttygate is a security-first browser terminal gateway inspired by Shell In A Box. It is not a drop-in fork: it keeps the useful idea, replaces the legacy C/AJAX stack with a memory-safe backend and xterm.js frontend, and defaults to localhost-only until authentication, transport security, and audit controls are configured.

Primary audience:

- Developers who need a local browser terminal for containers, labs, appliances, or demos.
- Operators who want controlled browser access to specific shells or SSH targets.
- Security-minded users who will not accept `/bin/login` exposed over HTTP-like defaults.

Non-goals for v0.1:

- Drop-in compatibility with `shellinaboxd` command syntax.
- Browser-exposed host login as the default mode.
- Full terminal sharing/collaboration.
- Full enterprise identity product.
- Broad OS portability beyond Linux and macOS dev support.
- Session re-attach: a dropped WebSocket ends the session. Resumable sessions (buffering, scrollback replay, re-auth binding) are a deliberate deferral, not an oversight.
- OS-level per-user separation for local PTY targets (see Process and User Model).

## Architecture

### Components

1. `ttygated` backend daemon
   - Rust binary.
   - Serves static frontend assets and `/healthz`.
   - Exposes session-creation API and WebSocket endpoint for terminal streams.
   - Owns session lifecycle, auth checks, audit logging, PTY/SSH execution, and policy.

2. Frontend
   - xterm.js terminal.
   - WebSocket transport.
   - Resize, paste handling, connection error/closed states.
   - Read-only mode (input suppressed client-side and enforced server-side).
   - No inline secrets or tickets in URLs.
   - No terminal escape interpretation outside xterm.js.

3. Session manager
   - Creates sessions only after auth/policy checks, via one-time tickets (see Session Establishment).
   - Tracks session id, user identity, command target, remote address, start/end time, exit status.
   - Enforces idle timeout, absolute session lifetime, and max concurrent sessions.
   - Defines idle activity as a successful non-empty PTY input write, a successful non-empty PTY output enqueue, or a successful resize. Empty I/O and rejected, dropped, or failed operations do not reset the idle deadline. Absolute lifetime never resets.
   - WebSocket drop terminates the session and its child process. No re-attach in v0.1.

4. Execution backends
   - Local PTY backend for allowlisted commands.
   - SSH backend: spawns the system OpenSSH client (`ssh`) in a PTY with pinned, non-negotiable options (`StrictHostKeyChecking=yes`, explicit `UserKnownHostsFile`, `BatchMode` where applicable). A native SSH-library implementation is a possible later change, not v0.1.
   - Container/namespace backend deferred until after v0.1 unless needed for a demo.

5. Audit subsystem
   - JSON lifecycle logs by default.
   - Optional terminal recording in asciinema-compatible format. Recordings capture terminal output, which routinely contains secrets — they are sensitive artifacts, written with restrictive permissions, off by default.
   - No password/secret logging in lifecycle logs.

### Process and User Model

The daemon runs as a dedicated non-root user. In v0.1, all local PTY targets run as the daemon's own Unix user; there is no privilege switching and no `/bin/login`-style user substitution. Authenticated identity is used for authorization decisions and audit attribution only, not OS-level separation. This is a deliberate design statement and belongs in the threat model: two authenticated users of the same ttygate instance share an OS security domain for local PTY targets. Per-user OS separation, if ever added, arrives via the SSH backend (connect as yourself) or a future container backend — not via daemon privileges.

### Session Establishment and WebSocket Binding

WebSocket upgrades are never accepted bare. The flow:

1. Browser holds an authenticated session (secure, httpOnly, sameSite cookie) — even in dev mode, where the identity is auto-provisioned but the cookie is still real.
2. Browser calls `POST /api/sessions` with the target name. The backend validates identity, Origin, target policy, and rate limits, then returns a single-use ticket with a short TTL (~10 seconds).
3. Browser opens the WebSocket and presents the ticket in the first message — never in the URL.
4. Backend redeems the ticket (single use, TTL enforced, bound to the issuing identity), starts the PTY/SSH child, and begins streaming.

### Wire Protocol

Terminal I/O uses binary WebSocket frames; control messages (resize, close, exit status, error) use JSON text frames. The exact framing is specified in `docs/protocol.md` before implementation begins — it is the contract between backend and frontend work, and the surface later fuzz targets are written against. Output streaming uses bounded buffers with backpressure: a target that produces output faster than the client drains it gets throttled, not buffered without limit.

### Data Flow

1. Browser loads `/` from `ttygated` or from a reverse proxy.
2. User identity is established through dev mode, trusted reverse-proxy headers, or later OIDC. All modes result in a real browser session cookie.
3. Browser requests a session ticket for a configured target via `POST /api/sessions`.
4. Backend validates identity, target policy, Origin, CSRF/session binding, and rate limits, then issues a one-time ticket.
5. Browser opens the WebSocket and redeems the ticket; backend starts the PTY or SSH child process.
6. WebSocket carries terminal input/output and resize events under the wire protocol, with backpressure on output.
7. Backend records lifecycle events and optional terminal output recording.
8. Session ends on process exit, timeout, WebSocket drop, user close, or admin policy termination.

## MVP Scope: v0.1

Must have:

- Rust workspace with one `ttygated` binary.
- Static frontend using xterm.js.
- Wire protocol specified in `docs/protocol.md`; binary data + JSON control framing.
- WebSocket terminal channel bound to authenticated sessions via one-time tickets — in all modes, including dev.
- Origin checks on session-creation and WebSocket endpoints — in all modes, including dev.
- Local PTY execution for explicitly allowlisted commands, with bounded output buffering/backpressure.
- SSH backend via OpenSSH client subprocess with strict known-hosts verification.
- Read-only target flag (server-enforced input drop).
- Localhost-only binding by default.
- Production mode refuses to start unless auth and TLS/reverse-proxy trust are explicitly configured.
- Trusted reverse-proxy auth header mode for Tailscale, Cloudflare Access, oauth2-proxy, or similar deployments.
- Structured JSON audit logs for session lifecycle.
- Config file with schema validation and clear startup errors.
- `/healthz` endpoint for Docker healthchecks and systemd watchdog.
- Dockerfile and systemd unit.
- CI for build, tests, formatting, linting, and dependency audit.
- Security policy and threat model in `docs/`.

Should have if time permits:

- Asciinema-compatible session recording.
- Basic admin CLI: list active sessions, terminate session.
- Fuzz targets for config parsing and wire-protocol control message parsing.
- Resource limits (rlimits) for local PTY child processes.

Defer:

- Native ACME/Let's Encrypt.
- Native OIDC login flow.
- WebAuthn/passkeys.
- Multi-user collaboration/share links.
- Session re-attach after WebSocket drop.
- Native SSH library backend (replacing the OpenSSH subprocess).
- Full container/namespace profile management.
- PAM/local password auth.
- Drop-in Shell In A Box config migration.

## Security Requirements

### Localhost Is Not a Security Boundary

Binding to `127.0.0.1` protects against remote network clients, not against browsers. Any website the user visits can attempt WebSocket connections to `127.0.0.1:7681` (cross-site WebSocket hijacking), and DNS rebinding defeats host-based assumptions. A browser terminal gateway that is exploitable by a malicious webpage in dev mode has failed its entire premise. Therefore Origin checks, session cookies, and ticket-bound WebSocket upgrades are part of the first working build — not hardening added later.

### Threat Model

Assume these attackers exist:

- Unauthenticated internet clients probing the service.
- Malicious websites running in the browser of a legitimate (even localhost dev) user: cross-site WebSocket hijacking, DNS rebinding, CSRF.
- Authenticated but malicious users trying to escape policy or access other sessions.
- Compromised or misconfigured reverse proxies.
- Malicious terminal output from remote hosts or commands.
- Local unprivileged users trying to abuse the daemon or child processes.
- Network attackers when TLS/reverse-proxy boundaries are misconfigured.
- Resource-exhaustion attackers: session-creation floods, output floods from targets, unbounded buffers.
- Administrators who choose unsafe config unless the tool blocks or warns clearly.

Documented residual risks (v0.1):

- Local PTY targets share the daemon's OS user; authenticated users are separated by policy and audit, not by OS boundaries.
- Session recordings, when enabled, capture terminal output and therefore potentially secrets; they must be handled as sensitive artifacts.

### Dangerous Anti-Features To Avoid

- No `/bin/login` default.
- No password auth to host accounts through ttygate v0.1.
- No HTTP fallback in production.
- No self-signed TLS presented as production-safe.
- No SSH mode with `StrictHostKeyChecking=no`, and no client-influenced SSH options.
- No session ids or tickets in URLs.
- No unauthenticated or unticketed WebSocket endpoint — in any mode.
- No arbitrary shell command string from request parameters.
- No root daemon requirement for normal operation.
- No `X-Forwarded-*` or identity headers trusted unless configured with trusted proxy CIDRs or local listener constraints.

### Minimum Controls in All Modes (Including Dev)

- Bind `127.0.0.1` by default.
- Enforce Origin checks for browser endpoints.
- Secure, httpOnly, sameSite session cookies.
- WebSocket upgrades bound to authenticated sessions via single-use, short-TTL tickets.
- Validate target names against config, never raw commands from clients.
- Bounded output buffers with backpressure.

### Additional Production Controls

- Require explicit `--mode=production` or config equivalent for non-local deployments.
- In production, require one of:
  - TLS enabled directly, or
  - trusted reverse proxy mode with documented headers and trusted source restrictions.
- Require real authentication in production (`auth.provider = "dev"` refuses to start).
- Rate limit session creation and auth failures.
- Enforce per-user/session concurrency limits.
- Log session start/end/target/user/source/exit status.
- Avoid logging terminal input by default; make recording explicit.

## Configuration Shape

Example v0.1 config:

```toml
# All paths are literal. No environment variable or tilde expansion in v0.1.

[server]
bind = "127.0.0.1:7681"
mode = "dev"
public_url = "http://127.0.0.1:7681"

[auth]
provider = "dev"
user = "local"

[audit]
format = "json"
path = "./ttygate-audit.jsonl"
recording = false

[limits]
max_sessions = 8
max_sessions_per_user = 2
idle_timeout_seconds = 900
absolute_timeout_seconds = 14400

[[targets]]
name = "local-shell"
type = "pty"
command = ["/bin/bash", "-l"]
read_only = false

[[targets]]
name = "lab-host"
type = "ssh"
host = "lab.example.internal"
port = 22
ssh_executable = "/usr/bin/ssh"
identity_file = "/etc/ttygate/lab_host_ed25519"
known_hosts = "/etc/ttygate/lab_host_known_hosts"
user_policy = "same-as-auth-user"
```

Production config should fail startup if `auth.provider = "dev"` or if `bind` is public without explicit production controls.

Chunk 2.1 (Refs #8) implements this configuration gate and direct TLS. A
loopback development listener may add `[server.tls]` with absolute
`certificate` and `private_key` paths and an `https://` `public_url`. TLS
startup validates bounded regular non-symlink files, restrictive Unix private
key permissions, PEM shape, and certificate/key agreement. Its stable
diagnostics do not expose paths or PEM contents, and a TLS failure never falls
back to HTTP.

Chunk 2.2 (Refs #9) implements `[server.trusted_proxy] trusted_sources = [...]`
with `auth.provider = "trusted-proxy"` and `identity_header`. The listener's
actual socket peer is authoritative and must match a configured CIDR before
exactly one configured identity header is considered. Forwarded address headers
are ignored, and IPv4-mapped IPv6 peers are not converted across address
families. The semantic HTTP field value exposed by the HTTP parser must be valid
UTF-8, contain 1 through 128 bytes, and contain no Unicode whitespace or control
character. HTTP field-line optional whitespace is parser framing rather than
part of that semantic value; the proxy must reject or normalize ambiguous
upstream surrounding whitespace, strip all client instances, and inject exactly
one canonical header. ttygate performs no further trimming, case folding, or
Unicode normalization. Chunk 2.3 implements rate and concurrency limits.

Chunk 2.4 (Refs #10) implements `[audit]` for both modes. `path` is literal and
must resolve through existing non-symlink directories to a regular,
non-symlink destination; a new file is created owner-only (`0600` on Unix).
The process appends bounded schema-versioned JSONL records for authentication,
stable denials, and one correlated start/end pair per admitted session. Only
the actual listener socket peer supplies source attribution. Cookies, tickets,
request values, executable paths, arguments, environment, and terminal input
or output are excluded. Audit opening precedes application construction and
binding, and runtime sink failure permanently denies new authority.

This is append persistence, not a transactional journal: the writer flushes but
does not `fsync` each record. Operators own rotation, retention, shipping,
backup, and deletion. The containing filesystem remains trusted against
privileged or concurrent namespace mutation. Recording, reconnect,
packaging, deployment examples, and release hardening remain future phases.

## Implementation Phases

Each phase's tests are part of its exit criteria — there is no separate testing phase. Continuous checks run in CI from Phase 0 onward: `cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny` (or `cargo audit`), CodeQL, dependency review, `cargo fmt --check`, frontend build.

### Phase 0: Repo Foundation and Decisions

- Create Rust workspace and frontend package structure.
- Choose license: permissive (Apache-2.0 OR MIT recommended). Record the decision.
- Establish the clean-room rule in CONTRIBUTING: no code — including frontend JS — copied from the GPL-2 Shell In A Box fork.
- Add README, security policy, threat model stub, contributing guide.
- Add GitHub Actions for formatting, linting, tests, dependency audit, CodeQL, frontend build.
- Add issue templates for security-sensitive changes.
- Run decision spikes, each producing a short record in `docs/decisions/`:
  - Web stack: confirm `axum` + `tokio` after checking WebSocket/PTY ergonomics.
  - PTY crate: evaluate maintenance status and unsafe surface (e.g. `portable-pty`, `pty-process`, direct `nix`/`rustix`).
  - SSH subprocess: validate the pinned OpenSSH option set (strict host keys, known-hosts file, no user-controlled options) against real servers.

Exit criteria:

- `cargo test`, `cargo fmt --check`, `cargo clippy`, dependency audit, CodeQL, and frontend build run in CI.
- License chosen and clean-room rule documented.
- All three decision records written; no open architecture questions block Phase 1.
- README clearly says this is inspired by Shell In A Box but not a drop-in fork.

### Phase 1: Secure Local Terminal

**Status:** complete through the frontend work tracked in issue #7. Detailed RED/GREEN, browser-QA, review, and verification evidence is retained in the [Chunk 1.6 implementation plan](plans/2026-07-18-chunk-1.6-browser-frontend.md).

The first working build already resists browser-based attacks. Scope:

- Config loading, schema validation, target allowlist, clear startup errors.
- `docs/protocol.md` and the message codec (binary data frames, JSON control frames).
- HTTP server: static frontend, `/healthz`, dev identity provider issuing a real session cookie, `POST /api/sessions` issuing single-use short-TTL tickets, Origin checks on all browser endpoints.
- PTY spawn for allowlisted targets; resize handling; bounded output buffering with backpressure; child teardown on WebSocket/session close.
- Session lifecycle state machine; WebSocket drop ends the session.
- WebSocket endpoint: ticket redemption, then PTY↔WS bridging via the codec.
- xterm.js frontend: connect flow, resize, paste, error/closed states, read-only rendering.

Exit criteria (tests):

- Local browser can open a terminal at `127.0.0.1`.
- Only configured targets can launch; unknown target names rejected.
- Unit tests: config schema, target allowlist parsing, ticket issue/redeem (single-use, TTL, identity binding), codec round-trip, session limit enforcement.
- Integration tests: PTY echo over WebSocket; resize event reaches the PTY; session close kills the child process; WebSocket rejected without a valid ticket; Origin mismatch rejected on both `POST /api/sessions` and the WebSocket upgrade; read-only target drops input server-side.

### Phase 2: Production Gating and Audit

- **Implemented in Chunk 2.1 (Refs #8):** dev vs production startup checks; rejection of development identity outside loopback and in production; rejection of public production plaintext and contradictory/incomplete transport contracts; fail-before-build/bind ordering; and one direct TLS listener with no HTTP fallback.
- **Implemented in Chunk 2.2 (Refs #9):** trusted reverse-proxy authentication enforces actual socket-peer CIDRs, the single-header identity grammar, opaque secure browser sessions, ticket binding, and WSS-to-PTY identity propagation. The proxy remains responsible for upstream authentication, client-header stripping, canonical injection, TLS termination, and exclusive backend reachability.
- **Implemented in Chunk 2.3 (Refs #24):** bounded monotonic fixed-window rate limits protect session creation by authenticated identity and authentication failures by actual listener peer IP. Ticket issuance atomically reserves global/per-user concurrency, and ticket redemption transfers the reservation exactly once to the live session. HTTP 503 responses distinguish `global-session-limit` from `identity-session-limit`; HTTP 429 responses include a positive `Retry-After`.
- **Implemented in Chunk 2.4 (Refs #10):** restrictive append-only
  schema-versioned JSONL audit records cover authentication, access denials, and
  exactly-once correlated session lifecycle outcomes. Audit availability gates
  startup and subsequent authority; listener-peer provenance and whole-file
  secret/terminal exclusion are integration-tested.

Exit criteria (tests):

- Unit tests: unsafe production config rejection (table-driven over bad configs), identity header validation (missing/spoofed/untrusted source), rate and concurrency limit enforcement, audit event serialization.
- Integration tests: requests from outside trusted CIDRs cannot inject identity headers; audit log reconstructs who opened which target and when.
- Security docs describe remaining limitations (shared-OS-user model, recording sensitivity).

**Status:** Phase 2 / M2 complete.

### Phase 3: SSH Backend

- Implement SSH target type by spawning the system OpenSSH client in a PTY with pinned options; reuse the Phase 1 PTY/session machinery.
- Enforce known-hosts verification via explicit `UserKnownHostsFile`; never `StrictHostKeyChecking=no`.
- Support configured user policy: fixed user, same-as-auth-user, or mapping table.
- Surface connection errors and host-key failures distinctly in the frontend and audit logs.

Exit criteria (tests):

- SSH works against a real server without disabling host-key verification.
- Integration tests: host-key mismatch is rejected and audit-logged; unknown SSH target rejected; user policy mapping applied correctly; no client input can alter the ssh argument vector.

**Status:** Phase 3 / M3 complete. Implemented in Chunk 3.1 (Refs #11): `type = "ssh"` targets require literal `ssh_executable`, `identity_file`, and `known_hosts` paths whose option values additionally reject the OpenSSH option lexer and expansion syntax; startup validates material ownership, permissions, and structure and probes the client for the complete pinned option vocabulary (including `CertificateFile=/dev/null`) before bind; sessions run with a fully server-constructed argv, cleared environment, and curated non-reflecting failure states; real containerized-sshd tests cover the exit criteria above. The remaining roadmap begins with packaging; completion so far does not make this pre-release build production-safe.

### Phase 4: Packaging and Release

- Dockerfile with non-root runtime user and `/healthz`-based healthcheck.
- systemd unit with hardening options and watchdog integration.
- Example reverse-proxy configs for Caddy/Nginx and Cloudflare Access/Tailscale style headers.
- Release workflow with checksums and SBOM if practical.
- Complete the README checklist below.

Exit criteria (manual pre-release checks):

- Install/run path documented and verified for Docker and systemd; default package starts localhost-only.
- Verified behind a Caddy or Nginx reverse proxy, and with a Cloudflare Access/Tailscale-style identity header config.
- Unsafe configs verified to fail closed.
- Logs verified to contain no terminal input unless recording is explicitly enabled.

## High-Signal GitHub Issues

Create these as public issues early, grouped by milestone:

Phase 0:

1. `docs: publish threat model and security goals`
2. `repo: scaffold Rust backend and frontend workspace with CI`
3. `decisions: spike PTY crate, web stack, and OpenSSH subprocess option set`

Phase 1:

4. `protocol: specify and implement the WebSocket wire protocol`
5. `backend: implement allowlisted PTY session lifecycle with backpressure`
6. `security: ticket-bound WebSocket auth and Origin checks in all modes`
7. `frontend: integrate xterm.js with resize, paste, and error states`

Phase 2:

8. `security: production-mode config guard and fail-closed startup checks`
9. `auth: add trusted reverse-proxy identity header provider`
10. `audit: add structured JSON session lifecycle logs`

Phase 3:

11. `ssh: strict known-hosts SSH backend via OpenSSH subprocess`

Phase 4:

12. `packaging: Dockerfile, systemd hardening, reverse-proxy examples, release workflow`

Should-have: `hardening: fuzz targets for config and protocol parsers`, `audit: asciinema-compatible recording`, `admin: session list/terminate CLI`.

## Shell In A Box Fork Plan

Use the fork for credibility and migration, not as the main codebase.

Immediately:

- Add `SECURITY.md` explaining legacy status and responsible disclosure.
- Add `docs/security-review.md` summarizing known architectural risks.
- Triage high-risk open issues with labels, but avoid promising long-term C maintenance.
- Optionally add CI for building the legacy project to show due diligence.

After ttygate v0.1 is tagged (not before — never point public traffic at vaporware):

- Add `docs/successor.md` pointing to `ttygate` and explaining the rewrite rationale.
- Update the fork README to reference the successor.

Do not spend early effort on broad C refactors unless a specific advisory or build blocker must be addressed for credibility.

## README Checklist For v0.1

The README should include:

- One-sentence positioning.
- Clear warning that browser terminals are security-sensitive.
- Safe quickstart bound to localhost.
- Production deployment checklist.
- Auth provider matrix: dev, trusted reverse proxy, planned OIDC.
- Target examples: local PTY and SSH.
- Audit log example.
- Comparison with Shell In A Box.
- Explicit non-goals, including the shared-OS-user model for local PTY targets.
- Security reporting link.

## Decision Log

Resolved in this plan:

- SSH backend approach: OpenSSH client subprocess in a PTY for v0.1; native library deferred.
- WebSocket auth binding: single-use short-TTL tickets issued by authenticated `POST /api/sessions`, presented in the first WS message.
- Reconnect semantics: WebSocket drop ends the session; re-attach deferred.
- Process/user model: all local PTY targets run as the daemon's non-root user in v0.1.
- Fork pointer timing: successor references go up only after v0.1 is tagged.
- Config paths: literal only, no expansion in v0.1.

Open — to be closed by Phase 0 spikes with records in `docs/decisions/`:

- Rust web stack: likely `axum` + `tokio`; confirm WebSocket/PTY ergonomics.
- PTY crate: evaluate maintenance and unsafe surface before committing.
- License: permissive recommended (Apache-2.0 OR MIT); confirm and record.
