# Web stack spike evidence

- Checked: 2026-07-11
- Host: macOS 26.5 arm64
- Rust: 1.97.0
- Resolved: axum 0.8.9, tokio 1.52.3, tokio-tungstenite 0.29.0
- Command: `./spikes/web-stack/run.sh`
- Result: `PASS web-stack: HTTP routing, typed WS frames, bounded bridge, teardown (10/10)`

The program bound an ephemeral loopback listener, served `/healthz`, upgraded
`/ws`, round-tripped a JSON-like text control message and arbitrary binary
terminal bytes without conflating frame types, and completed bridge teardown
after a close frame. A capacity-one Tokio channel demonstrated real
backpressure: its second send remained pending until the receiver drained the
first item. Ten fresh server/connection cycles completed within bounded
timeouts.

The first test run failed at the teardown assertion because sender drop and
graceful completion had been conflated. The corrected experiment gives each
connection an explicit completion notification and shuts the listener down
gracefully. This red/green result was useful evidence that teardown needs an
owned lifecycle signal rather than inference from channel closure.

Primary metadata: [axum 0.8.9](https://crates.io/crates/axum/0.8.9),
[axum WebSocket API](https://docs.rs/axum/0.8.9/axum/extract/ws/index.html),
[Tokio 1.52.3](https://crates.io/crates/tokio/1.52.3), and the
[axum repository](https://github.com/tokio-rs/axum).

Limitations: the bridge transports representative frames through a bounded
session channel; it does not spawn a PTY or define ttygate's eventual protocol.
Those belong to Chunks 1.2, 1.4, and 1.5.
