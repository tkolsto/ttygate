#!/bin/sh
set -eu

install -o spike -g spike -m 0600 /fixture/client_key.pub /home/spike/.ssh/authorized_keys

exec /usr/sbin/sshd -D -e \
  -p 2222 \
  -h /fixture/ssh_host_ed25519_key \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o PermitRootLogin=no \
  -o AllowUsers=spike \
  -o UsePAM=no \
  -o PrintMotd=no
