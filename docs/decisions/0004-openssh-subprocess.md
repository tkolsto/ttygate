# 0004: SSH backend — system OpenSSH subprocess

- Date: 2026-07-11
- Status: accepted

## Context

ttygate needs strict host identity, mature SSH cryptography, PTY resize, useful
failure reporting, and a narrow policy boundary. The rewrite plan recommends a
system OpenSSH subprocess, but Chunk 0.3 must prove the pinned option set against
a real server and show that browser input cannot alter it.

## Decision

Use the system `ssh` client inside the PTY/session machinery selected in ADR
0003. Build argv exclusively from validated server configuration and typed user
policy. The browser supplies only an opaque target name and terminal bytes after
authorization; it supplies no executable, destination, username, path, command,
environment setting, or SSH option.

For key-authenticated targets, pin at least:

- `-F /dev/null`;
- `-o StrictHostKeyChecking=yes`;
- `-o UserKnownHostsFile=<literal configured path>`;
- `-o GlobalKnownHostsFile=/dev/null`;
- `-o BatchMode=yes`;
- `-o IdentitiesOnly=yes` with an explicit identity policy; and
- explicit host, port, and resolved username.

Disable password and keyboard-interactive fallback when BatchMode/key policy is
used. Allocate a TTY for interactive targets. Never add an insecure bypass or
learn a host key from the same connection whose identity is being decided.

Classify unknown host, host-key mismatch, transport connection failure, and
normal child exit separately. Host-key mismatch must become a distinct M3 UI
error and audit denial reason.

## Alternatives

- **Native SSH library:** keeps everything in-process but makes ttygate choose
  and track crypto/protocol/agent behavior. Deferred unless subprocess limits
  become a demonstrated problem.
- **Shell command invocation:** rejected. Quoting is not a security boundary and
  would create an argument-injection surface. Spawn `ssh` directly with argv.
- **TOFU or `StrictHostKeyChecking=accept-new/no`:** rejected. ttygate targets
  are administrator configured and require pre-provisioned host identity.

## Evidence

`spikes/openssh/` built and ran an Alpine OpenSSH 10.0p2 sshd on a random
loopback port and drove it with the macOS OpenSSH 10.2p1 client. With the fully
server-constructed argv, strict success and remote exit-status propagation
worked. An empty host file, deliberately wrong key, and refused port all failed
closed and produced classifiable errors.

The OpenSSH process ran inside a real PTY. Remote dimensions changed from 24×80
to 41×132 after resize. Disconnect killed and reaped local ssh; the disposable
server had no lingering sshd session child. Argv unit tests covered every pinned
option and the absence of a protocol-controlled option path. Detailed versions,
commands, observations, cleanup, and limitations are in
`spikes/evidence/openssh.md`.

## Risks and mitigations

- OpenSSH stderr wording varies by version and locale. Classify with exit
  context plus narrowly tested patterns, retain a safe generic failure, and do
  not expose raw sensitive diagnostics by default.
- Local ssh config could weaken policy. `-F /dev/null` and explicit options
  minimize ambient configuration; review environment and token/agent policy in
  Chunk 3.1.
- Known-host files and private keys are sensitive policy material. Require
  literal server-configured paths and restrictive filesystem permissions.
  `O_NOFOLLOW` protects only the final path component; administrator-controlled
  parent namespaces remain part of the trust boundary.
- A local PTY target running as the daemon UID can read identities readable by
  that UID. PTY supervision is not OS-level credential isolation; use separate
  UIDs or a stronger sandbox for less-trusted local commands.
- Killing only ssh may leave remote work running after network loss. Local
  teardown must kill/reap ssh; remote command termination depends on sshd and
  remote process behavior and remains a documented distributed-systems limit.
- OpenSSH options evolve. Integration-test the supported system versions against
  real sshd and fail startup clearly if required capabilities are unavailable.

## Consequences

No SSH architecture question blocks Phase 3. Chunk 3.1 can reuse the Phase 1
PTY lifecycle and implement a typed argv builder plus stable error/audit
taxonomy; the disposable spike is not production code.
