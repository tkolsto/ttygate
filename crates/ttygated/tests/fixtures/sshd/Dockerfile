FROM alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

RUN apk add --no-cache \
      openssh-server=10.0_p1-r10 \
      procps-ng=4.0.4-r3 \
      socat=1.8.1.3-r0 \
    && adduser -D -s /bin/sh ttygate \
    && echo 'ttygate:password-auth-is-disabled' | chpasswd \
    && mkdir -p /run/sshd /home/ttygate/.ssh \
    && chown -R ttygate:ttygate /home/ttygate/.ssh \
    && chmod 0700 /home/ttygate/.ssh

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 2222
ENTRYPOINT ["/entrypoint.sh"]
