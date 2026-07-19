# Docker package contract

This image is a pre-release, localhost-only package for Chunk 4.1. Its default
configuration listens only on `127.0.0.1` inside the container, and the image
does not publish a host port. A later deployment configuration may select
another validated bind and production transport; Chunk 4.2 owns those proxy
examples.

The process runs as the fixed non-root `ttygate` identity with UID and GID
65532. `/etc/ttygate/ttygate.toml` is root-owned and read-only to the process.
The image-created `/var/log/ttygate` audit directory is owned by UID/GID 65532.
Static assets are embedded in `/usr/local/bin/ttygated`; there is no runtime
asset directory.

For an operator configuration, mount a root-owned file at
`/etc/ttygate/ttygate.toml`. Mount SSH identities and known-host files beneath
`/etc/ttygate/ssh`. The daemon requires each SSH material file to be owned by
its effective UID 65532 and applies its existing restrictive permission and
structure checks before binding. Do not pass credentials in environment
variables or command-line arguments.

The supported hardened invocation uses a read-only root filesystem and an
explicit audit volume:

```sh
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700 \
  --mount type=volume,src=ttygate-audit,dst=/var/log/ttygate \
  ttygate:local
```

The image health check executes the daemon's bounded loopback-only
`--health-check` command. That command requests `/healthz`, accepts only the
exact healthy response, and prints no response body, address, configuration,
or credential on failure.

The image contains the system OpenSSH client because SSH targets are an
implemented daemon feature. It does not contain compilers, Node/npm, Cargo,
source trees, repository tests, fixture keys, package-manager indexes, or
package-manager caches. The Debian package snapshot and all three base-image
manifest lists are immutable pins in the Dockerfile.

Refs #12.
