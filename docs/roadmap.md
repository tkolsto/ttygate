# ttygate Roadmap

Source spec: [ttygate-rewrite-plan.md](ttygate-rewrite-plan.md). This roadmap slices the plan into milestones and chunks. A **chunk** is the unit of execution: small enough to hold in one head, ends in an independently testable deliverable, and gets its own detailed TDD implementation plan (in `docs/plans/`) when picked up. Chunks list what they consume and produce so they can be planned and reviewed in isolation.

Milestones M0–M4 are strictly ordered. Chunks within a milestone can be parallel where dependencies allow. The fork track (F) is independent of everything.

## Milestone Overview

| Milestone | Theme | Outcome |
|---|---|---|
| M0 | Foundation & decisions | CI-green empty workspace, license, all architecture decisions recorded |
| M1 | Secure local terminal | Browser terminal on localhost that already resists cross-site attacks |
| M2 | Production gating & audit | Fail-closed production mode, reverse-proxy auth, TLS, audit logs |
| M3 | SSH backend | Strict-host-key SSH targets via OpenSSH subprocess |
| M4 | Packaging & release | Docker, systemd, deployment docs, tagged v0.1 |
| M5 | Should-haves | Recording, admin CLI, fuzzing, rlimits — as time permits |
| F | Fork track | shellinabox fork stewardship, independent of M0–M5 |

---

## M0 — Foundation & Decisions

### Chunk 0.1 — Repo scaffold and CI

- **Deliverables:** git repo; Cargo workspace with `ttygated` binary crate; frontend package skeleton (xterm.js via npm, bundled to static assets); GitHub Actions running `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo deny`, CodeQL, dependency review, frontend build; license files (Apache-2.0 OR MIT per spike confirmation); CONTRIBUTING with the clean-room rule (no code copied from the GPL-2 fork).
- **Depends on:** nothing.
- **Done when:** CI is green on an empty-but-real workspace; license and clean-room rule committed.

### Chunk 0.2 — Public docs baseline

- **Deliverables:** README with positioning, security warning, and "inspired by, not a fork" statement; `SECURITY.md` with reporting process; `docs/threat-model.md` (full write-up from the plan's Security Requirements section, including residual risks: shared OS user, recording sensitivity); issue templates for security-sensitive changes; the 12 milestone-grouped GitHub issues from the plan.
- **Depends on:** 0.1 (repo exists).
- **Done when:** docs render correctly on GitHub; issues filed.

### Chunk 0.3 — Decision spikes

- **Deliverables:** three throwaway spike programs and three records in `docs/decisions/`: (a) web stack — confirm `axum`+`tokio` WebSocket ergonomics; (b) PTY crate — compare `portable-pty` / `pty-process` / direct `nix`-`rustix` on maintenance, unsafe surface, resize + reap behavior; (c) OpenSSH subprocess — validate the pinned option set (`StrictHostKeyChecking=yes`, explicit `UserKnownHostsFile`, no user-controllable options) against a real server, including host-key-mismatch behavior worth surfacing in M3.
- **Depends on:** 0.1. Parallel with 0.2.
- **Done when:** each record states the choice, alternatives, and rationale; no open architecture questions remain for M1.

---

## M1 — Secure Local Terminal

The first running build already enforces Origin checks and ticket-bound WebSockets — dev mode is not exempt (see plan: "Localhost Is Not a Security Boundary").

### Chunk 1.1 — Config and target allowlist

- **Deliverables:** TOML config loading matching the plan's Configuration Shape; schema validation with actionable startup errors; typed `Target` enum (pty/ssh) with allowlist lookup by name; literal-paths-only rule enforced; `limits` section parsed.
- **Consumes:** decision records (0.3).
- **Produces:** `Config`, `Target`, `Limits` types the server and session manager consume.
- **Done when:** table-driven unit tests cover valid configs, each rejection case, and unknown-target lookup failure. Pure logic, no I/O beyond reading a file.

### Chunk 1.2 — Wire protocol spec and codec

- **Deliverables:** `docs/protocol.md` specifying framing (binary frames for terminal I/O; JSON text frames for resize/close/exit-status/error), limits, and version tag; Rust codec module encoding/decoding both frame kinds; TypeScript counterpart for the frontend.
- **Consumes:** nothing from 1.1 — parallel.
- **Produces:** the backend↔frontend contract; codec API used by 1.4 and 1.5; the surface M5 fuzzing targets.
- **Done when:** codec round-trip unit tests pass on both sides; malformed-frame rejection tested; doc reviewed against both implementations.

### Chunk 1.3 — HTTP server, dev identity, tickets

- **Deliverables:** axum server binding `127.0.0.1:7681` by default; static asset serving; `/healthz`; dev auth provider auto-provisioning an identity behind a real secure/httpOnly/sameSite cookie; `POST /api/sessions` validating identity + Origin + target name and issuing single-use ~10 s tickets bound to the identity; Origin enforcement on all browser endpoints.
- **Consumes:** `Config`/`Target` (1.1).
- **Produces:** ticket store with `issue(identity, target)` / `redeem(ticket) -> (identity, target)` semantics consumed by 1.5; session-cookie middleware consumed by M2 auth providers.
- **Done when:** unit tests cover ticket single-use, TTL expiry, identity binding, and Origin rejection; integration test shows a cookie-less or wrong-Origin `POST /api/sessions` fails.

### Chunk 1.4 — PTY backend and session lifecycle

- **Status:** implemented by the work tracked in issue #5.
- **Deliverables:** PTY spawn of allowlisted commands (chosen crate from 0.3); session state machine (created → running → closed with exit status/reason); idle and absolute timeouts; max-session and per-user limits from config; resize; bounded output buffer with backpressure; guaranteed child teardown on close; read-only flag dropping input server-side.
- **Consumes:** `Target`/`Limits` (1.1), control-message types (1.2).
- **Produces:** `Session` handle with async read/write/resize/close consumed by 1.5; lifecycle events consumed by M2 audit.
- **Done when:** unit tests cover state transitions, limit enforcement, timeout firing, read-only input drop; integration test proves child process death on session close (no orphans) and bounded memory under an output flood (e.g. `yes`).

### Chunk 1.5 — WebSocket bridge

- **Deliverables:** WS upgrade endpoint that accepts a connection, requires a valid ticket in the first message (never URL), redeems it, starts the session via 1.4, then bridges PTY↔WS using the 1.2 codec; WS drop terminates the session.
- **Consumes:** ticket store (1.3), `Session` (1.4), codec (1.2).
- **Produces:** the complete backend path the frontend connects to.
- **Done when:** integration tests: echo through a real PTY over a real WS; resize reaches the PTY; missing/expired/reused ticket rejected; wrong Origin rejected at upgrade; WS drop kills the child.

### Chunk 1.6 — Frontend

- **Deliverables:** xterm.js terminal page; session flow (fetch ticket → open WS → attach); resize propagation; paste handling; distinct error/closed/denied states; read-only rendering; no secrets in URLs; bundled into the static assets 1.3 serves.
- **Consumes:** protocol + TS codec (1.2), endpoints (1.3, 1.5).
- **Produces:** the v0.1 UI.
- **Done when:** manual browser check passes the M1 exit criteria (open terminal, resize, paste, close behavior); a headless smoke test (Playwright or similar) exercises connect/echo/close if practical.

**M1 exit:** all plan Phase 1 exit criteria green; a malicious third-party webpage cannot open a session against a running dev instance (verified by an Origin-mismatch integration test).

---

## M2 — Production Gating & Audit

### Chunk 2.1 — Mode gating and fail-closed startup

- **Deliverables:** `mode = "dev" | "production"`; production startup refuses `auth.provider = "dev"`, public bind without TLS or trusted-proxy config, and other unsafe combinations, with actionable error messages; direct TLS listener (rustls) with cert/key config.
- **Consumes:** config (1.1), server (1.3).
- **Done when:** table-driven tests over unsafe configs all fail closed; TLS listener serves the frontend in an integration test.

### Chunk 2.2 — Trusted reverse-proxy auth provider

- **Deliverables:** auth provider reading configured identity headers only when the peer is within trusted CIDRs (or a local listener constraint); documented header contract for oauth2-proxy / Cloudflare Access / Tailscale-style deployments; plugs into the 1.3 cookie/session layer.
- **Consumes:** session middleware (1.3), mode gating (2.1).
- **Done when:** tests cover missing header, spoofed header from untrusted source, and correct identity propagation into session creation and tickets.

### Chunk 2.3 — Rate and concurrency limits

- **Deliverables:** rate limiting on `POST /api/sessions` and on auth failures; enforcement of global and per-user concurrency limits at ticket issue time (limits themselves defined in 1.4).
- **Consumes:** ticket path (1.3), session manager (1.4).
- **Done when:** tests prove limits trigger, return distinguishable errors, and recover after the window passes.

### Chunk 2.4 — Audit subsystem

- **Deliverables:** structured JSON lifecycle log (session id, user, target, remote address, start/end, exit status, denial reasons including host-key failures later); append-only JSONL file per config; no terminal input in logs; audit event serialization tests.
- **Consumes:** lifecycle events (1.4), auth outcomes (2.2, 2.3).
- **Produces:** audit event API that M3 (host-key failures) and M5 (recording) extend.
- **Done when:** an integration test reconstructs "who opened which target and when" purely from the log; a grep-style test asserts typed terminal input never appears.

**M2 exit:** plan Phase 2 exit criteria green; security docs updated with residual limitations.

---

## M3 — SSH Backend

### Chunk 3.1 — OpenSSH subprocess target

- **Deliverables:** `type = "ssh"` targets spawn the system `ssh` client inside the existing PTY machinery with the pinned option set from the 0.3 spike; user policy (fixed / same-as-auth-user / mapping table); argument vector fully server-constructed — no client input reaches it; host-key failures and connection errors surfaced distinctly in the frontend and recorded as audit events.
- **Consumes:** PTY/session machinery (1.4), config (1.1), audit API (2.4), spike record (0.3c).
- **Done when:** integration tests (against a containerized sshd): successful session with strict host keys; host-key mismatch rejected and audit-logged; user policy mapping applied; property-style test that no protocol input can alter the argv.

**M3 exit:** plan Phase 3 exit criteria green.

---

## M4 — Packaging & Release

### Chunk 4.1 — Docker and systemd

- **Deliverables:** Dockerfile (multi-stage, non-root runtime user, `/healthz` healthcheck); systemd unit with hardening (`DynamicUser` or dedicated user, `NoNewPrivileges`, `ProtectSystem`, watchdog wired to `/healthz` or sd_notify).
- **Consumes:** working binary (M1–M3).
- **Done when:** both start localhost-only by default and pass a scripted smoke test.

### Chunk 4.2 — Deployment docs and reverse-proxy examples

- **Deliverables:** example configs for Caddy and Nginx; Cloudflare Access / Tailscale-style identity-header walkthroughs; production deployment checklist in README; auth provider matrix; audit log example; Shell In A Box comparison; non-goals including the shared-OS-user model.
- **Consumes:** 2.1, 2.2 behavior; 4.1 artifacts.
- **Done when:** each example verified by actually running it (plan Phase 4 manual checks).

### Chunk 4.3 — Release v0.1

- **Deliverables:** release workflow building artifacts with checksums (SBOM if practical); version tagging; final pass of the plan's README checklist; manual pre-release checklist executed and recorded (unsafe configs fail closed; no terminal input in logs without recording).
- **Consumes:** everything.
- **Done when:** v0.1 tagged; then and only then trigger fork chunk F.2.

---

## M5 — Should-Haves (post-v0.1 or slack time)

Ordered by value; each is one chunk, planned when picked up:

- **5.1 Fuzz targets** — config parser and protocol control-frame parser (`cargo-fuzz`), wired into scheduled CI.
- **5.2 Asciinema recording** — output-only cast files, restrictive permissions, off by default, documented as sensitive.
- **5.3 Admin CLI** — list active sessions, terminate session (local control socket).
- **5.4 Child rlimits** — resource limits for local PTY children.

Deferred beyond v0.x (tracked as icebox issues, no chunks yet): OIDC, ACME, WebAuthn, session re-attach, native SSH library, container backend, PAM, shellinabox config migration.

---

## F — Fork Track (independent)

- **F.1 Now:** `SECURITY.md` (legacy status, disclosure process); `docs/security-review.md` (architectural risk summary); label-based triage of high-risk issues; optional build CI. No C refactors without a concrete advisory.
- **F.2 After v0.1 tag only:** `docs/successor.md` and README pointer to ttygate.

---

## Suggested execution order

0.1 → (0.2 ∥ 0.3) → (1.1 ∥ 1.2) → 1.3 → 1.4 → 1.5 → 1.6 → 2.1 → 2.2 → (2.3 ∥ 2.4) → 3.1 → 4.1 → 4.2 → 4.3. F.1 anytime; F.2 gated on 4.3.

The critical path runs through 1.3 → 1.4 → 1.5; 1.2 and 1.6 are the natural chunks to interleave. When starting a chunk, write its implementation plan in `docs/plans/YYYY-MM-DD-<chunk>.md` with full TDD steps, using the chunk's Consumes/Produces block as the interface contract.
