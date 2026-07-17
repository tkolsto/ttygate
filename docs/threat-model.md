# ttygate Threat Model

## Scope and status

This document describes the intended security boundaries for ttygate v0.1, a browser gateway to allowlisted local PTY commands and SSH targets. It covers the browser frontend, HTTP and WebSocket service, authentication boundary, session manager, child processes, reverse-proxy integration, configuration, audit logs, and optional recordings.

ttygate is currently pre-release. Chunks 1.3 through 1.5 implement the localhost HTTP foundation, explicit browser Origin policy, development identity cookie, bounded single-use session tickets, an authenticated first-message WebSocket bridge, allowlisted PTY execution, bounded session and bridge I/O, concurrency/deadline enforcement, and process-group teardown on transport loss. Frontend terminal integration, production authentication/transport gating, and the remaining mitigations below are still planned. This model is a design contract for later chunks, not a claim that the current binary is safe to deploy. The [roadmap](roadmap.md) identifies when each control is expected to land.

The model assumes the host operating system, browser, configured identity provider, and administrators are not already fully compromised. Protecting a compromised endpoint, making untrusted commands safe to run, defending third-party infrastructure, and providing per-user OS isolation for local PTY targets are out of scope. Those limitations are non-goals, not security properties.

## Security objectives

ttygate aims to:

- start terminal sessions only for authenticated users and explicitly configured targets;
- bind each WebSocket to the user and policy decision that authorized it;
- prevent browser cross-origin attacks even when the daemon listens only on localhost;
- keep browser input from changing server-controlled commands, SSH options, or target policy;
- contain sessions within a dedicated non-root daemon account and reliably terminate child processes;
- preserve confidentiality and integrity across correctly configured transport and reverse-proxy boundaries;
- keep terminal data and secrets out of lifecycle logs by default;
- remain available under reasonable hostile input through rate limits, concurrency limits, timeouts, and backpressure; and
- fail closed when a production deployment omits required authentication or transport controls.

Availability under unlimited traffic, protection after host or browser compromise, and safe execution of a malicious allowlisted command are not guaranteed.

## Assets

| Asset | Why it matters |
|---|---|
| Host and daemon authority | A terminal session can read, change, and execute anything available to the daemon's Unix account. |
| Authenticated identity and session cookies | They determine authorization and audit attribution. Theft or confusion can impersonate a user. |
| One-time session tickets | A ticket authorizes creation of a particular terminal session during its short lifetime. |
| Terminal input, output, and scrollback | They routinely contain commands, credentials, personal data, and operational secrets. |
| Target allowlist and SSH policy | Target commands, user mapping, pinned SSH options, and known-hosts data define where and how code executes. |
| Configuration and TLS private keys | They define trust, network exposure, limits, and cryptographic identity. |
| Audit logs | They provide accountability but expose identities, targets, addresses, timing, and failure metadata. |
| Session recordings | Output recordings can contain secrets even when keyboard input is not explicitly recorded. |
| Service and host availability | Output floods, connection floods, and orphaned children can exhaust memory, file descriptors, CPU, or process capacity. |
| Build and dependency integrity | A compromised Rust crate, npm package, build action, or release artifact can bypass every runtime control. |

## Trust boundaries

1. **Browser to ttygate.** Untrusted HTTP requests, cookies, Origin values, WebSocket frames, terminal input, and control messages cross into the service. A page loaded from another origin can still attempt to contact localhost.
2. **Session API to WebSocket redemption.** Authorization occurs on `POST /api/sessions`; the later WebSocket must prove it owns the resulting short-lived, identity-bound ticket before a child starts.
3. **Reverse proxy to daemon.** TLS termination and identity headers are trustworthy only when the daemon can authenticate the proxy connection or restrict it to configured source CIDRs or a local listener.
4. **Daemon to PTY or OpenSSH child.** The daemon converts policy into an argument vector and gains control over a child process. Child output is hostile data; child authority is bounded only by the daemon's OS account and target environment.
5. **Authenticated identities to the shared OS user.** Distinct application identities may select different targets, but all local PTY children run as the same Unix user in v0.1. Policy separation is not kernel-enforced isolation.
6. **Terminal output to browser renderer.** Remote systems and local commands control escape sequences and arbitrary byte streams consumed by xterm.js. Output must never be treated as application HTML or script.
7. **Daemon to audit and recording storage.** Lifecycle metadata and optional output leave process memory and become durable sensitive artifacts subject to filesystem access, retention, and backup policy.
8. **Administrator and configuration to runtime.** Operators choose network binding, authentication, targets, proxy trust, logging, and resource limits. Production validation must reject combinations known to be unsafe rather than trusting warnings alone.
9. **Source and dependencies to build artifacts.** CI actions, registries, lockfiles, and release tooling cross a supply-chain boundary before code reaches an operator.

## Attacker capabilities

The design assumes attempts by:

- unauthenticated remote clients scanning, fuzzing, and flooding an exposed service;
- malicious websites running in a legitimate user's browser and attempting CSRF, cross-site WebSocket hijacking, localhost access, or DNS rebinding;
- authenticated malicious users trying to select undeclared commands, reuse tickets, cross session boundaries, evade limits, or gain another user's authority;
- a compromised or misconfigured reverse proxy that forwards spoofed identities, exposes plaintext traffic, or admits untrusted source addresses;
- local unprivileged users probing daemon files, sockets, child processes, logs, and recordings;
- commands and remote SSH hosts producing malicious terminal output or unbounded output;
- network attackers observing or changing traffic where TLS or proxy trust is absent or misconfigured;
- resource-exhaustion attackers creating sessions, failing authentication, flooding frames, or causing targets to emit data faster than a browser consumes it; and
- administrators selecting unsafe configurations, whether accidentally or without understanding the browser threat model.

An attacker may control all browser request fields and protocol frames but must not be able to control server-side target definitions or SSH options through them. The model does not assume that binding to `127.0.0.1` makes hostile browser requests impossible.

## Threats and planned mitigations

All mitigations in this table are planned unless a later roadmap chunk records them as implemented and tested.

| Threat | Security consequence | Required mitigation and validation |
|---|---|---|
| Cross-site WebSocket hijacking, CSRF, and DNS rebinding | A malicious site creates or drives a terminal using a victim's browser, including against localhost. | Enforce an explicit Origin policy on the session API and WebSocket upgrade in every mode. Use a secure, HTTP-only, SameSite session cookie and require a short-lived ticket bound to the authenticated identity. Integration tests must reject wrong origins at both endpoints. |
| Ticket theft or replay | An attacker starts a session authorized for somebody else or redeems the same authorization twice. | Issue tickets only after identity, Origin, target, and limit checks. Keep them single-use, short-lived, identity- and target-bound, and out of URLs and logs. Unit tests cover expiry, reuse, and identity mismatch. |
| Reverse-proxy header spoofing | A direct client asserts another identity through a trusted-looking header. | Read identity headers only in an explicit provider mode and only from configured trusted CIDRs or a constrained local listener. Production startup rejects incomplete trust configuration; integration tests send spoofed headers from an untrusted peer. |
| Target, command, or SSH argument injection | Browser input changes the executable, arguments, SSH destination, user, known-hosts file, or security options. | Resolve an opaque target name against validated server configuration. Construct argument arrays entirely on the server, allow only literal configured paths, and never accept a command string or SSH option from protocol input. Test unknown targets and property-test the SSH argument boundary. |
| Session crossover or unauthorized observation | One user reads, writes, resizes, closes, or attaches to another user's terminal. | Bind ticket, WebSocket, session handle, and audit identity; use unguessable identifiers only as references, never as authorization. Do not support re-attachment in v0.1. Enforce read-only input suppression on the server. |
| Privilege escalation through the daemon or child | A child gains root or another user's OS authority. | Run the daemon and local PTY targets as a dedicated non-root user without `/bin/login`, PAM, setuid switching, or a normal root requirement. Keep process spawning narrow and add OS hardening in packaging. |
| Malicious terminal output | Escape sequences or bytes trigger script execution, corrupt application UI, manipulate trusted text, or overwhelm parsing. | Send terminal bytes only to xterm.js, never to HTML/template interpretation. Keep application errors outside terminal parsing, use a versioned bounded protocol, and test malformed control frames. Browser and terminal-emulator vulnerabilities remain a dependency risk. |
| SSH machine-in-the-middle attack | A fake host captures credentials or commands. | Spawn the system OpenSSH client with `StrictHostKeyChecking=yes`, an explicit server-configured `UserKnownHostsFile`, and no client-influenced options. Surface and audit host-key failure without offering an insecure bypass. Test a real mismatch. |
| Transport interception or modification | Credentials, cookies, tickets, terminal data, or identity headers are exposed or altered. | Default to loopback. Production requires direct TLS or a deliberately configured trusted proxy boundary; use secure cookies and refuse unsafe combinations at startup. Do not describe self-signed TLS as production-safe. |
| Secret leakage through URLs or logs | Tickets, commands, passwords, or terminal contents persist in histories, proxies, analytics, or lifecycle logs. | Keep tickets out of query strings; avoid terminal input and output in lifecycle audit events; redact authentication failures; make output recording explicit and off by default. Add tests proving typed input does not enter audit logs. |
| Sensitive or overexposed recordings | Output recordings reveal tokens, command output, personal data, or typed characters echoed by a program. | Treat recordings as sensitive even when nominally output-only. Keep them disabled by default, use restrictive permissions, document retention and access controls, and warn that shell echo makes input/output distinctions incomplete. |
| Session floods, authentication floods, output floods, or orphan children | Memory, CPU, processes, file descriptors, or disk are exhausted. | Rate-limit session creation and auth failures; enforce global and per-user concurrency, idle and absolute timeouts, frame limits, and bounded output buffers with backpressure. Terminate and reap children on every close path. Test output floods and dropped WebSockets. |
| Unsafe administrator configuration | A public unauthenticated plaintext terminal is exposed unintentionally. | Make loopback and development identity the development defaults, but block unsafe combinations in production. Validate configuration schema and paths, require explicit production mode, and return actionable startup errors. |
| Dependency or CI compromise | Malicious code enters the browser, daemon, or release artifacts. | Pin dependency resolution, review updates, run `cargo deny`, CodeQL, dependency review, Rust lint/tests, frontend type checks/builds, and least-privilege CI. Release provenance and SBOM work belongs to the packaging milestone. |

## Minimum controls in every mode

The first functional build is required to include these controls even in development:

- loopback binding by default;
- Origin validation on every browser session endpoint and WebSocket upgrade;
- a real secure, HTTP-only, SameSite browser session cookie;
- an authenticated `POST /api/sessions` flow issuing a single-use, short-TTL ticket;
- ticket redemption in the first WebSocket message, never the URL;
- server-side target-name lookup with no request-supplied command strings;
- server-side enforcement of read-only targets; and
- bounded output buffering with backpressure and guaranteed child teardown.

Localhost binding is defense in depth, not a substitute for these browser-facing controls.

## Production-only controls

Production mode must additionally:

- reject the development identity provider;
- require direct TLS or an explicitly configured trusted reverse proxy with source restrictions;
- reject public binding without the required transport and authentication boundary;
- rate-limit authentication failures and session creation;
- enforce global and per-user concurrency limits;
- produce structured lifecycle events containing user, target, source, start, end, outcome, and denial reason; and
- avoid terminal input and output in lifecycle logs unless an administrator separately enables sensitive recording.

Configuration errors must stop startup. A warning followed by insecure operation is not an acceptable production control.

## Audit and recording rules

Lifecycle audit logs should make it possible to reconstruct who attempted or opened which target, from where, when, and with what outcome. They must not contain passwords, session cookies, tickets, private keys, raw terminal input, or routine terminal output. Log files remain sensitive because identity, address, target, timing, and denial metadata can reveal operational details.

Optional asciinema-compatible recording is distinct from lifecycle audit. It is planned to capture terminal output, be disabled by default, and write files with restrictive permissions. Programs frequently echo typed input, display access tokens, or print private data; therefore recordings are sensitive regardless of an “output-only” label. Operators remain responsible for access control, retention, backups, deletion, and legal notice.

## Dangerous anti-features

The following are intentionally prohibited for v0.1:

- a `/bin/login` default, host-password authentication, or routine root daemon;
- an HTTP fallback or self-signed certificate presented as production protection;
- `StrictHostKeyChecking=no`, an insecure host-key bypass, or browser-controlled SSH options;
- session identifiers or tickets in URLs;
- an unauthenticated or unticketed WebSocket in any mode;
- arbitrary command strings supplied through requests;
- trusting `X-Forwarded-*` or identity headers from an unverified source; and
- treating localhost, a Host header, or DNS alone as browser authorization.

## Validation strategy

Security claims require rejection-path evidence. Unit tests cover configuration rejection, allowlist resolution, ticket expiry/reuse/identity binding, protocol parsing, state transitions, read-only input handling, and limit enforcement. Integration tests cover wrong-Origin requests, unticketed WebSockets, spoofed proxy headers, PTY lifecycle and resize, child teardown, bounded output, audit exclusion of terminal input, and strict SSH host-key mismatch behavior.

CI runs formatting, warning-free linting, tests, dependency policy, frontend checks, CodeQL, and dependency review. Manual release checks cover localhost-only defaults, reverse-proxy examples, fail-closed unsafe configurations, logs, packaging, and rendered public documentation. Passing one layer does not substitute for testing the others.

## Residual risks

Even after the planned controls are implemented, v0.1 retains important risks:

- **Shared OS user.** All local PTY children run as the same dedicated daemon Unix user. Authenticated users are separated by application policy and audit attribution, not by an OS boundary. A command that can inspect or influence another same-user process may cross that policy boundary. Use SSH identities or a future container backend when kernel-enforced separation is required.
- **Sensitive recordings and output.** Terminal output and scrollback routinely expose secrets. Output-only recordings may contain echoed input. Restrictive permissions reduce exposure but do not make recordings safe to share.
- **Authorized terminal power.** A correctly authorized user can exercise everything the selected target permits. ttygate cannot make an overly broad target harmless.
- **Trusted proxy concentration.** A compromised trusted proxy can impersonate users or weaken transport guarantees. Source restrictions prevent arbitrary direct spoofing, not compromise of the trusted component itself.
- **Endpoint or host compromise.** Malware in the browser, a vulnerable terminal emulator, or compromise of the daemon host can bypass application-level controls.
- **Denial of service.** Limits and backpressure bound individual paths but cannot guarantee availability under host exhaustion, distributed traffic, or expensive allowlisted commands.
- **Audit metadata.** Lifecycle logs exclude terminal contents by default but still reveal identities, targets, addresses, timing, and outcomes.
- **Pre-release immaturity.** Interfaces and assumptions may change, and security controls are incomplete until their roadmap chunks and tests land. The current scaffold must not be deployed as a terminal gateway.

## Maintaining this model

Every change to authentication, session establishment, browser endpoints, proxy trust, protocol framing, target selection, process execution, SSH options, user separation, transport, logging, recording, packaging, or deployment assumptions must review this document. Pull requests for security-sensitive changes must identify affected assets and trust boundaries, describe abuse cases and negative tests, and update the model when a threat, mitigation, or residual risk changes.

Security fixes that would reveal an unpatched vulnerability belong in the private process described in [SECURITY.md](../SECURITY.md), not in a public issue or pull request.
