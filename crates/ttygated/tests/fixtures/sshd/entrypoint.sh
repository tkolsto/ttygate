#!/bin/sh
set -eu

install -o ttygate -g ttygate -m 0600 \
  /fixture/client_key.pub /home/ttygate/.ssh/authorized_keys

exec /usr/sbin/sshd -D -e \
  -p 2222 \
  -h /fixture/ssh_host_ed25519_key \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o PermitRootLogin=no \
  -o AllowUsers=ttygate \
  -o UsePAM=no \
  -o PrintMotd=no \
  -o Banner=/fixture/banner
