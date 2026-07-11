# OpenSSH subprocess spike evidence

- Checked: 2026-07-11
- Client: OpenSSH_10.2p1, LibreSSL 3.3.6 (macOS arm64)
- Server: OpenSSH_10.0p2, OpenSSL 3.5.1 (Alpine 3.22.1 container)
- Docker: client 29.1.5, server 29.2.0
- Command: `./spikes/openssh/run.sh`
- Result: strict success, unknown host, mismatched host key, refused
  connection, remote exit 7, PTY resize, local reap, and remote-session cleanup
  all passed.

The runner generated a client key, server host key, and deliberately wrong host
key in a private project-local temporary directory. The real sshd container was
bound to a random loopback port. Its known-host entry came directly from the
generated server public key, outside the connection under test; no `ssh-keyscan`
or trust-on-first-use shortcut was used.

The Rust program built every argument from a typed server-owned target. Its
argv included `-F /dev/null`, `StrictHostKeyChecking=yes`, an explicit
`UserKnownHostsFile`, `BatchMode=yes`, `IdentitiesOnly=yes`, an explicit
identity, public-key-only authentication, and fixed host/user/port. Unit tests
proved the pinned options and that representative hostile protocol bytes had no
argv input path.

Observed classifications:

| Case | Observation | Required later classification |
|---|---|---|
| Correct pinned key | command output exactly matched; exit 0 | success |
| Empty known-hosts file | non-zero; host-key verification failure/no known ED25519 key | `unknown_host_key` |
| Wrong pinned key | non-zero; changed-identification/verification failure | `host_key_mismatch` (distinct UI/audit event) |
| Refused loopback port | non-zero; connection refused/connect failure | `connection_failed` |
| Remote `exit 7` | local ssh exit status 7 | remote/process exit status |

For the interactive case, system ssh ran inside pty-process. Remote `stty size`
observed 24×80 then 41×132 after local resize. Disconnect signalled the local
ssh process group and awaited it; a container-side process listing found no
remaining sshd session child. Cleanup was registered before container start and
removed the container and all temporary keys on success and failure.

Primary reference: the [OpenSSH `ssh` manual](https://man.openbsd.org/ssh),
[`ssh_config` option reference](https://man.openbsd.org/ssh_config), and
[OpenSSH portable source](https://github.com/openssh/openssh-portable).

Limitations: the server fixture uses public-key authentication and therefore
`BatchMode=yes` is appropriate. A future target deliberately supporting an
interactive authentication method would need a separately reviewed option
policy; the browser may never supply or override SSH options.
