#!/bin/sh
set -eu

cp /fixture/accepted_client_key.pub /home/ttygate/.ssh/authorized_keys
chmod 0600 /home/ttygate/.ssh/authorized_keys
chown ttygate:ttygate /home/ttygate/.ssh/authorized_keys
chown ttygate:ttygate /home/ttygate/.ssh

exec /usr/sbin/sshd -D -e \
  -p 2222 \
  -h /fixture/ssh_host_ed25519_key \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o TrustedUserCAKeys=/fixture/user_ca.pub \
  -o PermitRootLogin=no \
  -o AllowUsers=ttygate \
  -o PrintMotd=no \
  -o Banner=/fixture/banner
