# 0002: Web stack — axum and Tokio

- Date: 2026-07-11
- Status: accepted

## Context

ttygate needs ordinary HTTP routing and a WebSocket bridge whose binary
terminal data, text control messages, backpressure, cancellation, and close
semantics compose with an asynchronous session/PTY layer. Chunk 0.3 must settle
the stack without shipping a server.

## Decision

Use axum on Tokio for the v0.1 HTTP and WebSocket server. Split each upgraded
socket into input/output tasks around bounded Tokio channels. Give the session
an explicit cancellation/completion path: a WebSocket drop ends the session,
all bridge tasks are joined or aborted, and child teardown is awaited.

## Alternatives

- **actix-web:** credible and mature, with actor-oriented WebSocket support,
  but introduces a second concurrency model without improving ttygate's small
  Tokio session bridge.
- **warp or salvo:** both can serve WebSockets, but neither supplied a material
  ergonomic or safety advantage over axum's typed extractors and direct Tokio,
  Tower, and Hyper composition for this design.
- **Custom Hyper/Tungstenite wiring:** offers control ttygate does not need and
  increases HTTP/upgrade surface owned by the project.

## Evidence

The disposable program in `spikes/web-stack/` exercised HTTP routing, RFC 6455
upgrade, distinct text/binary frames, capacity-one backpressure, peer close,
task cancellation, and graceful listener teardown. It passed ten consecutive
iterations. Exact versions, command, red/green teardown finding, and limitations
are in `spikes/evidence/web-stack.md`.

axum 0.8.9 exposes WebSocket upgrade and typed `Message` variants directly;
its `ws` feature uses tokio-tungstenite. Tokio 1.52.3 provides bounded MPSC,
task cancellation, blocking adapters, and timeouts needed by the later PTY
bridge. Metadata was checked from crates.io/docs.rs and the Tokio-owned axum
repository on the decision date.

## Risks and mitigations

- A split socket does not automatically own session teardown. Chunk 1.5 must
  make cancellation explicit and test transport drop, not only close frames.
- Awaiting a bounded send propagates backpressure but can stall teardown.
  Cancellation must remain selectable and every bridge operation bounded.
- WebSocket availability is not authorization. Origin validation and first-
  message ticket redemption remain mandatory in all modes.
- Framework upgrades can change message types or close behavior. Pin through
  `Cargo.lock` and keep real loopback integration tests.

## Consequences

Chunks 1.3 and 1.5 can proceed with axum + Tokio. The spike does not select a
wire encoding, implement authentication, or become production code.
