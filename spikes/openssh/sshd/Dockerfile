FROM alpine:3.22.1

RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/sh spike \
    && echo 'spike:disabled-password-auth' | chpasswd \
    && mkdir -p /run/sshd /home/spike/.ssh \
    && chown -R spike:spike /home/spike/.ssh \
    && chmod 0700 /home/spike/.ssh

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 2222
ENTRYPOINT ["/entrypoint.sh"]
