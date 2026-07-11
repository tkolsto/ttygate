# PTY spike evidence

- Checked: 2026-07-11
- Host: macOS 26.5 arm64; Rust 1.97.0
- Command: `./spikes/pty/run.sh`
- Result: `PASS PTY: portable-pty, direct-nix-libc, pty-process resize/kill/reap/orphan-free (20/20)`

All three implementations spawned a real controlling-terminal child, observed
`stty size` at 24×80, resized to 41×132, and observed the new size inside the
child. Each child started a long-lived descendant. The runner signalled the PTY
session process group, applied a kill fallback, called `wait`, and then proved
both recorded PIDs absent. The selected pty-process path passed 20 consecutive
spawn/resize/disconnect/kill/reap cycles.

| Criterion | portable-pty 0.9.0 | pty-process 0.5.3 | direct nix 0.30.1 / rustix 1.1.4 |
|---|---|---|---|
| Maintenance signal | Current crates.io release; PTY-specific WezTerm commit observed 2026-06-07 | Current crates.io release; upstream `main` is ahead of v0.5.3, but a full clone returned an object-level HTTP 503 during review | Current releases; nix and rustix upstream activity observed 2026-05-19 and 2026-06-15; ttygate would still own the PTY layer |
| Platforms | Unix plus Windows ConPTY | Unix | Unix; conditional code required per OS |
| Direct dependency surface in lockfile | 8 direct children, including older nix 0.28 and serial support | rustix + optional Tokio | nix/libc or rustix plus ttygate-owned glue |
| Unsafe surface | PTY spawn implementation contains platform unsafe/syscall code | Focused wrapper uses rustix plus required pre-exec/syscall code | ttygate must own pre-exec, controlling-terminal, dup/close, and ioctl invariants |
| Resize | Synchronous `MasterPty::resize` | `Pty::resize`, including owned async halves | Explicit `TIOCSWINSZ`; caller owns notification semantics |
| Async integration | Blocking reader adapted through a bounded worker channel | Native Tokio AsyncRead/AsyncWrite and Tokio Child | Must implement nonblocking registration and async wrappers |
| Teardown/reap | Child kill/wait exists; still needs process-group policy | Tokio Child kill/wait/kill-on-drop; still needs process-group policy | Entire close/signal/wait policy is application code |
| Testability | Trait abstraction helps fakes, but lifecycle is blocking | Small concrete async API worked with real PTYs and timeouts | Maximum control, maximum test and maintenance burden |

The textual `unsafe` searches used during review are only a source-audit aid,
not a security metric: comments, tests, platform modules, and transitive code
make raw counts incomparable. The stronger finding is ownership: the direct
experiment necessarily placed unsafe `pre_exec` and ioctl contracts in ttygate
code, while pty-process confines them behind its rustix-based API.

Primary metadata/source: [portable-pty](https://crates.io/crates/portable-pty/0.9.0)
and [WezTerm source](https://github.com/wezterm/wezterm/tree/main/pty),
[pty-process](https://crates.io/crates/pty-process/0.5.3),
[nix](https://crates.io/crates/nix/0.30.1), and
[rustix](https://crates.io/crates/rustix/1.1.4).

Maintenance checks used upstream refs/APIs as primary sources. `git ls-remote`
for pty-process succeeded and showed `main` at `2728909` versus v0.5.3 at
`9d4ab45`; the subsequent repository clone failed while fetching an older tag
object with HTTP 503. That does not invalidate the published crate experiment,
but it is a real continuity/availability risk and weighs against exposing the
dependency broadly.

Limitations: behavior was observed on macOS. Linux is the production priority,
and Chunk 1.4 must repeat the integration lifecycle test on Linux CI. Windows
portability is not a v0.1 goal.
