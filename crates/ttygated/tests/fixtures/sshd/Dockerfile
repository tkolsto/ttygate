FROM alpine:3.22.1

RUN apk add --no-cache openssh-server procps \
    && adduser -D -s /bin/sh ttygate \
    && echo 'ttygate:password-auth-is-disabled' | chpasswd \
    && mkdir -p /run/sshd /home/ttygate/.ssh \
    && chown -R ttygate:ttygate /home/ttygate/.ssh \
    && chmod 0700 /home/ttygate/.ssh

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 2222
ENTRYPOINT ["/entrypoint.sh"]
