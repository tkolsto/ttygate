# systemd package contract

This pre-release unit runs `ttygated` as the dedicated static `ttygate`
account. Install the binary root-owned and mode 0755 at
`/usr/local/bin/ttygated`, the configuration root-owned and mode 0640 at
`/etc/ttygate/ttygate.toml`, and the unit root-owned and mode 0644 at
`/etc/systemd/system/ttygated.service`. Install the sysusers and tmpfiles
fragments using the distribution's normal package locations.

The supplied configuration is intentionally localhost-only and uses
development authentication. Replace it before any non-local deployment.
Never place credentials in the unit, process arguments, or environment.

The service manager creates `/var/lib/ttygate` and `/var/log/ttygate` with
mode 0700 and ownership `ttygate:ttygate`. Keep the configuration root-owned.
SSH identity and known-host files belong under `/etc/ttygate/ssh`; because the
daemon validates ownership against its effective identity, operator-provided
SSH material must be owned by `ttygate:ttygate` with restrictive permissions.

`PrivateNetwork` is deliberately absent: the gateway must accept its configured
listener and reach SSH targets. Restrict exposure with the loopback default,
firewall policy, and a later reviewed reverse-proxy configuration.
`PrivateUsers` is deliberately absent because a remapped user namespace would
break the daemon's fail-closed audit and SSH-file ownership checks. The unit
instead removes capabilities, restricts namespaces, and uses a dedicated
unprivileged account.

Verify the installed unit on Linux before enabling it:

```sh
systemd-analyze verify /etc/systemd/system/ttygated.service
systemd-analyze security ttygated.service
systemctl daemon-reload
systemctl enable --now ttygated.service
systemctl status ttygated.service
/usr/local/bin/ttygated --health-check 127.0.0.1:7681
```

`Type=notify` prevents systemd from considering the service ready before its
listener is bound. `WatchdogSec=6s` supervises a stalled process, and
`KillMode=control-group` ensures terminal children are stopped with the daemon.

Refs #12.
