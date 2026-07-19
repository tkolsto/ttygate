# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1769990400

FROM node:22.21.1-bookworm-slim@sha256:25b3eb23a00590b7499f2a2ce939322727fcce1b15fdd69754fcd09536a3ae2c AS frontend
ARG SOURCE_DATE_EPOCH
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci
COPY frontend/ ./
RUN npm run check && npm run build

FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS builder
ARG SOURCE_DATE_EPOCH
ARG CACHE_SCOPE=default
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=frontend /build/frontend/dist/ frontend/dist/
COPY --from=frontend /build/frontend/src/index.html frontend/src/index.html
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=ttygate-target-${CACHE_SCOPE},target=/build/target,sharing=locked \
    cargo build --locked --release --bin ttygated && \
    cp /build/target/release/ttygated /tmp/ttygated && \
    strip /tmp/ttygated

FROM debian:bookworm-20260202-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe AS runtime
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260202T000000Z bookworm main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260202T000000Z bookworm-security main' \
      > /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install --no-install-recommends --yes ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/ldconfig \
      /var/log/apt/* /var/log/dpkg.log && \
    groupadd --gid 65532 ttygate && \
    useradd --uid 65532 --gid ttygate --home-dir /var/lib/ttygate \
      --shell /usr/sbin/nologin --no-create-home ttygate && \
    install -d -o root -g ttygate -m 0750 /etc/ttygate /etc/ttygate/ssh && \
    install -d -o ttygate -g ttygate -m 0700 /var/lib/ttygate /var/log/ttygate && \
    find /bin /boot /etc /home /lib /media /mnt /opt /root /run /sbin /srv \
      /tmp /usr /var -xdev \
      ! -path /etc/hostname ! -path /etc/hosts ! -path /etc/resolv.conf \
      -newermt "@${SOURCE_DATE_EPOCH}" \
      -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

COPY --from=builder --chown=root:root --chmod=0755 /tmp/ttygated /usr/local/bin/ttygated
COPY --chown=root:ttygate --chmod=0640 packaging/docker/ttygate.toml /etc/ttygate/ttygate.toml

WORKDIR /var/lib/ttygate
USER ttygate:ttygate
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["/usr/local/bin/ttygated", "--health-check", "127.0.0.1:7681"]
ENTRYPOINT ["/usr/local/bin/ttygated"]
CMD ["/etc/ttygate/ttygate.toml"]
