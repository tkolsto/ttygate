# ttygate Threat Model

## Scope and status

This document describes the intended security boundaries for ttygate v0.1, a browser gateway to allowlisted local PTY commands and SSH targets. It covers the browser frontend, HTTP and WebSocket service, authentication boundary, session manager, child processes, reverse-proxy integration, configuration, audit logs, and optional recordings.

ttygate is currently pre-release. Milestone M1, completed through the frontend work tracked in issue #7, implements the localhost HTTP foundation, explicit browser Origin policy, development identity cookie, bounded single-use session tickets, authenticated first-message WebSocket bridge, allowlisted PTY execution, bounded session and bridge I/O, concurrency/deadline enforcement, process-group teardown, and an xterm.js frontend with bounded input/output handling and stale-connection cleanup. Chunk 2.1 (Refs #8) implements mode/transport gating, loopback-only development identity, fail-before-bind startup phases, secret-safe TLS material validation, and a direct rustls HTTPS/WSS listener with no HTTP fallback. Chunk 2.2 (Refs #9) implements trusted reverse-proxy production authentication; Chunk 2.3 (Refs #24) implements bounded rate and ticket-time concurrency enforcement; and Chunk 2.4 (Refs #10) implements required fail-closed structured audit persistence. Milestone M2 is complete. Chunk 3.1 (Refs #11) implements strict-host-key OpenSSH targets through the same PTY, concurrency, and audit machinery, with startup capability probing, validated credential material, a pinned non-negotiable option vocabulary, and curated failure states; Milestone M3 is complete. Chunk 4.1 (Refs #12) implements non-root Docker and hardened systemd packaging. Chunk 4.2 (Refs #12) implements verified Caddy and Nginx reverse-proxy deployments with documented Cloudflare Access and Tailscale Serve identity boundaries. Recording, reconnect, and Chunk 4.3 release work remain planned. This model is not a claim that the current binary is safe to deploy. The [roadmap](roadmap.md) identifies when each remaining control is expected to land.

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

Mitigations remain planned unless this document or a completed roadmap chunk
records them as implemented and tested. Chunk 2.1 implements transport and
startup gating. Chunk 2.2 implements the trusted reverse-proxy authentication
boundary (Refs #9). Chunk 2.3 implements bounded rate and ticket-time
concurrency enforcement (Refs #24). Chunk 2.4 implements fail-closed audit
persistence (Refs #10), and Chunk 3.1 implements the strict OpenSSH backend
(Refs #11). Chunk 4.1 implements non-root Docker and hardened systemd
packaging (Refs #12). Chunk 4.2 implements verified reverse-proxy examples
(Refs #12), but recording, reconnect, and Chunk 4.3 release controls remain
incomplete.

| Threat | Security consequence | Required mitigation and validation |
|---|---|---|
| Cross-site WebSocket hijacking, CSRF, and DNS rebinding | A malicious site creates or drives a terminal using a victim's browser, including against localhost. | Enforce an explicit Origin policy on the session API and WebSocket upgrade in every mode. Use a secure, HTTP-only, SameSite session cookie and require a short-lived ticket bound to the authenticated identity. Integration tests must reject wrong origins at both endpoints. |
| Ticket theft or replay | An attacker starts a session authorized for somebody else or redeems the same authorization twice. | Issue tickets only after identity, Origin, target, and limit checks. Keep them single-use, short-lived, identity- and target-bound, and out of URLs and logs. Unit tests cover expiry, reuse, and identity mismatch. |
| Reverse-proxy header spoofing | A direct client asserts another identity through a trusted-looking header. | Chunk 2.2 checks the actual socket peer supplied by the listener against configured IPv4/IPv6 CIDRs before reading exactly one configured identity header. `Forwarded`, `X-Forwarded-For`, Host, query, and WebSocket subprotocol data are never peer or identity authority. IPv4-mapped IPv6 peers are not converted to IPv4. Chunk 4.2's Caddy and Nginx deployments replace duplicate client identity headers with one authenticated value, remove credentials, isolate the backend, reject an untrusted real socket peer, and exercise the complete HTTPS/WSS lifecycle. |
| Target, command, or SSH argument injection | Browser input changes the executable, arguments, SSH destination, user, known-hosts file, or security options. | Chunk 3.1 resolves an opaque target name against validated server configuration and constructs the argument vector entirely on the server. Configured paths are literal, and because OpenSSH re-parses option values with its own option lexer, `identity_file` and `known_hosts` reject whitespace, control characters, `%`, quotes, backslashes, `$`, and expansion syntax so accepted paths reach OpenSSH byte-identically. No command string or SSH option is ever accepted from protocol input; hostile protocol and identity values are tested against the exact argv. |
| Session crossover or unauthorized observation | One user reads, writes, resizes, closes, or attaches to another user's terminal. | Bind ticket, WebSocket, session handle, and audit identity; use unguessable identifiers only as references, never as authorization. Do not support re-attachment in v0.1. Enforce read-only input suppression on the server. |
| Privilege escalation through the daemon or child | A child gains root or another user's OS authority. | Chunk 4.1 runs the Docker daemon as fixed UID/GID 65532 and the systemd daemon as the dedicated `ttygate` account, without `/bin/login`, PAM, setuid switching, capabilities, or a root process. The systemd unit adds `NoNewPrivileges`, a strict filesystem view, private devices and temporary storage, namespace and syscall restrictions, and control-group teardown. |
| Malicious terminal output | Escape sequences or bytes trigger script execution, corrupt application UI, manipulate trusted text, or overwhelm parsing. | Send terminal bytes only to xterm.js, never to HTML/template interpretation. Keep application errors outside terminal parsing, use a versioned bounded protocol, and test malformed control frames. Browser and terminal-emulator vulnerabilities remain a dependency risk. |
| SSH machine-in-the-middle attack | A fake host captures credentials or commands. | Chunk 3.1 spawns the system OpenSSH client with `StrictHostKeyChecking=yes`, the server-configured `UserKnownHostsFile`, `UpdateHostKeys=no`, `IdentitiesOnly=yes`, `CertificateFile=/dev/null` (no implicit sibling certificate), disabled fallback authentication, forwarding, proxying, and local commands, and no client-influenced options. Unknown and mismatched host keys share one curated audited failure with no insecure bypass; a real mismatch is tested against a live sshd. |
| Transport interception or modification | Credentials, cookies, tickets, terminal data, or identity headers are exposed or altered. | Chunk 2.1 defaults development identity to loopback, refuses unsafe production combinations, preserves secure cookies and exact HTTPS/WSS Origin checks, and serves direct rustls without plaintext fallback. Chunk 2.2 supports a mutually exclusive trusted-proxy mode where the proxy terminates public TLS and the protected backend listener is plaintext. The proxy must be the only component able to reach the backend from a trusted CIDR. |
| Secret leakage through URLs or logs | Tickets, commands, passwords, or terminal contents persist in histories, proxies, analytics, browser storage, DOM attributes, or lifecycle logs. | Keep tickets in a short-lived closure until the first WebSocket message, then overwrite them; use a fixed same-origin WebSocket URL with no query, fragment, credential, or subprotocol authority; avoid terminal input and output in lifecycle audit events; redact authentication failures; make output recording explicit and off by default. Test URL/DOM/storage/error exclusion and prove typed input does not enter audit logs. |
| Sensitive or overexposed recordings | Output recordings reveal tokens, command output, personal data, or typed characters echoed by a program. | Treat recordings as sensitive even when nominally output-only. Keep them disabled by default, use restrictive permissions, document retention and access controls, and warn that shell echo makes input/output distinctions incomplete. |
| Session floods, authentication floods, output floods, or orphan children | Memory, CPU, processes, file descriptors, or disk are exhausted. | Chunk 2.3 rate-limits session creation by authenticated identity and authentication failures by the actual listener peer IP using bounded monotonic fixed windows. `Forwarded`, `X-Forwarded-For`, and `X-Real-IP` are never rate-limit authority. It atomically reserves global and per-user concurrency at ticket issuance and transfers one reservation into the live session. Existing idle/absolute timeouts, frame limits, backpressure, and process teardown remain enforced. Distributed sources and upstream/host exhaustion remain residual risks. |
| Unsafe administrator configuration | A public unauthenticated plaintext terminal is exposed unintentionally. | Chunk 2.1 makes loopback and development identity the development boundary, blocks public development identity even with TLS, rejects public production plaintext and contradictory transport/provider contracts, and returns stable startup errors before application construction or listener binding. Chunk 2.2 constructs the real trusted-proxy provider only from the paired typed auth/transport configuration and fails closed on peer or header violations. |
| Dependency or CI compromise | Malicious code enters the browser, daemon, or release artifacts. | Pin dependency resolution, review updates, run `cargo deny`, CodeQL, dependency review, Rust lint/tests, frontend type checks/builds, and least-privilege CI. Chunk 4.1 pins Docker base manifests, Debian package snapshots, and the action revisions used by its packaging CI. Release provenance and SBOM work remains in Chunk 4.3. |

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

- reject the development identity provider (implemented in Chunk 2.1);
- require direct TLS or an explicitly configured trusted reverse proxy (structural gating implemented in Chunk 2.1; actual socket-peer and identity enforcement implemented in Chunk 2.2);
- reject public binding without the required transport and authentication boundary (implemented in Chunk 2.1);
- rate-limit authentication failures and session creation (implemented in Chunk 2.3);
- enforce global and per-user concurrency limits at ticket issuance (implemented in Chunk 2.3);
- produce structured lifecycle events containing user, target, source, start, end, outcome, and denial reason (implemented in Chunk 2.4); and
- exclude terminal input and output from lifecycle logs (implemented in Chunk 2.4; sensitive recording remains a separate planned feature).

Chunk 2.1 enforces its configuration and TLS errors before application
construction or listener binding. A warning followed by insecure operation, or
an HTTP fallback after TLS failure, is not an acceptable production control.
Chunk 2.2 enforces the actual listener socket peer before examining identity,
then requires exactly one configured identity header. The semantic HTTP field
value exposed by the HTTP parser must be valid UTF-8, contain 1 through 128
bytes, and contain no Unicode whitespace or control character. HTTP field-line
optional whitespace is removed by the parser and is not part of that semantic
value; the proxy must reject or normalize ambiguous upstream surrounding
whitespace, strip every client instance, and inject exactly one canonical
header. ttygate does no trimming, case folding, or Unicode normalization.
Chunk 2.4 opens the configured audit sink before application construction or
listener binding and permanently denies new authority after a runtime audit
failure. Audit attribution uses the actual socket peer, never forwarding
headers.

## Audit and recording rules

Lifecycle audit logs make it possible to reconstruct who attempted or opened
which configured target, from which listener peer, when, and with what outcome.
Chunk 2.4 writes bounded schema-versioned append JSONL records to the literal
configured path. An anchored non-following directory-descriptor walk prevents
parent rename redirection, and nonblocking final open rejects raced special
files. It rejects symlink parents/destinations, non-regular destinations,
unsafe existing permissions, and incomplete existing tails; a new file is
owner-only (`0600` on Unix), and an existing file must be owned by the daemon's
effective Unix user. Authentication success, stable denials,
and admitted-session starts and completions are closed event variants with
opaque correlation identifiers.

Lifecycle events must not contain passwords, session cookies, tickets, private
keys, request-supplied target strings, executable paths, arguments,
environment, raw terminal input, or routine terminal output. Tests scan a
complete direct-TLS lifecycle log for all of those sentinel classes. Log files
remain sensitive because identity, address, configured target, timing, and
denial metadata reveal operational details.

The append sink flushes each complete record but does not `fsync` on every
event. Kernel, storage, or power failure can therefore lose recent records.
ttygate does not implement rotation, retention, remote shipping, backup, or
deletion; operators own those policies. The filesystem namespace and
administrators able to mutate it remain a trust boundary. Path and permission
validation cannot protect against a privileged actor writing or truncating the
opened inode or replacing underlying storage outside the daemon's control.

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

Security claims require rejection-path evidence. Unit tests cover configuration rejection, TLS path/permission/PEM validation, fail-before-bind startup ordering, allowlist resolution, ticket expiry/reuse/identity binding, trusted-proxy CIDR and semantic identity grammar, protocol parsing, frontend stale-event and ticket lifecycle, bounded UTF-8 input chunking, state transitions, read-only input handling, bounded atomic rate/concurrency enforcement, exact audit serialization, and injected audit/supervisor failures. Integration tests cover verified direct HTTPS/WSS, wrong-Origin requests, plaintext and invalid-certificate rejection, unticketed WebSockets, real-browser identity/ticket/WebSocket/PTY flow, secret-free URLs, PTY lifecycle and resize, child teardown, bounded output, trusted and untrusted real proxy peers, cookie and ticket identity binding, proxy WSS-to-PTY propagation, rate floods, ticket-time capacity, expiry, abandonment, wrong-identity redemption, recovery, restrictive append behavior, exactly-once lifecycle completion, listener-peer audit provenance, and complete-log secret/terminal exclusion. SSH validation adds startup capability probing, option-path grammar rejection, hostile identity/protocol argv immutability, live classification of setup diagnostics, and containerized real-sshd integration tests covering strict success, unknown and mismatched host keys, wrong identities, sibling certificates, user policy, cancellation, and local process-group cleanup. Chunk 4.1 packaging validation adds reproducible clean Docker builds, minimal non-root/read-only runtime inspection, localhost health and network checks, fail-closed permissions, service readiness/watchdog recovery, and container/cgroup child teardown. Chunk 4.2 deployment validation adds native Caddy/Nginx checks, disposable isolated networks, ephemeral TLS, missing-auth and identity-spoof rejection, complete HTTPS/WSS/PTY and audit lifecycles, proxy/backend stop cleanup, and a whole-log secret scan. Recording, reconnect, and Chunk 4.3 release hardening remain future work with their own negative tests.

CI runs formatting, warning-free linting, tests, dependency policy, frontend checks, CodeQL, and dependency review. Manual release checks cover localhost-only defaults, reverse-proxy examples, fail-closed unsafe configurations, logs, packaging, and rendered public documentation. Passing one layer does not substitute for testing the others.

## Residual risks

Even after the planned controls are implemented, v0.1 retains important risks:

- **Shared OS user.** All local PTY children run as the same dedicated daemon Unix user. Authenticated users are separated by application policy and audit attribution, not by an OS boundary. A command that can inspect or influence another same-user process may cross that policy boundary. Use SSH targets with per-user policies or a future container backend when kernel-enforced separation is required.
- **Sensitive recordings and output.** Terminal output and scrollback routinely expose secrets. Output-only recordings may contain echoed input. Restrictive permissions reduce exposure but do not make recordings safe to share.
- **Authorized terminal power.** A correctly authorized user can exercise everything the selected target permits. ttygate cannot make an overly broad target harmless.
- **Trusted proxy concentration.** A compromised trusted proxy can impersonate users or weaken transport guarantees. Source restrictions prevent arbitrary direct spoofing, not compromise of the trusted component itself.
- **Endpoint or host compromise.** Malware in the browser, a vulnerable terminal emulator, or compromise of the daemon host can bypass application-level controls.
- **Denial of service.** Limits and backpressure bound individual paths but cannot guarantee availability under host exhaustion, distributed traffic, or expensive allowlisted commands.
- **Audit metadata.** Lifecycle logs exclude terminal contents by default but still reveal identities, targets, addresses, timing, and outcomes.
- **Audit durability and filesystem trust.** Per-event `fsync`, rotation, retention, and remote shipping are not implemented. Recent records can be lost on abrupt storage failure, and a privileged actor controlling the filesystem namespace can subvert local persistence.
- **Daemon-readable SSH credentials.** Each SSH target uses one unencrypted Ed25519 identity readable by the daemon user. Anything able to run code or read files as that user can authenticate to the configured targets. Ownership, permission, and structural checks bound accidents, not a compromised daemon account.
- **Operator known-hosts accuracy.** Strict host-key verification is only as good as the provisioned `known_hosts` content. ttygate never learns or updates host keys (`UpdateHostKeys=no`), so key rotation requires operator action, and a wrongly provisioned key denies or misdirects trust. The SSH material files share the audit log's filesystem trust boundary.
- **Remote-side cleanup.** Ending a session tears down the local OpenSSH process group, but remote commands may outlive the session if the remote side detaches them from the connection. Remote process lifecycle belongs to the remote host.
- **Pre-release immaturity.** Interfaces and assumptions may change. M1's local terminal controls, M2's transport, authentication, rate/concurrency, and audit controls, M3's strict OpenSSH backend, Chunk 4.1's Docker/systemd packaging, and Chunk 4.2's verified reverse-proxy deployments are implemented, but recording, reconnect, and Chunk 4.3 release hardening remain incomplete. The current build must not be deployed as a terminal gateway.

## Maintaining this model

Every change to authentication, session establishment, browser endpoints, proxy trust, protocol framing, target selection, process execution, SSH options, user separation, transport, logging, recording, packaging, or deployment assumptions must review this document. Pull requests for security-sensitive changes must identify affected assets and trust boundaries, describe abuse cases and negative tests, and update the model when a threat, mitigation, or residual risk changes.

Security fixes that would reveal an unpatched vulnerability belong in the private process described in [SECURITY.md](../SECURITY.md), not in a public issue or pull request.
