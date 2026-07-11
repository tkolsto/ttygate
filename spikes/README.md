# Chunk 0.3 decision spikes

These programs are disposable evidence for architecture decisions, not
production ttygate code. They deliberately live outside the root Cargo
workspace and must not be imported by `ttygated`.

Run all spikes from the repository root:

```sh
./spikes/run-all.sh
```

Prerequisites are Rust stable, a system OpenSSH client, Docker, `ssh-keygen`,
and standard Unix process tools. Each runner builds in its own ignored target
directory. The OpenSSH runner creates keys, known-hosts data, and logs in a
private temporary directory and registers cleanup before starting a container.

Only dated, sanitized summaries belong in `spikes/evidence/`. Never commit raw
logs, private keys, generated host files, temporary paths, or credentials.
