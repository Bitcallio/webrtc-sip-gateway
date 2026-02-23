FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG S6_OVERLAY_VERSION=3.2.0.2
ARG TARGETARCH

ENV S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    S6_VERBOSITY=1 \
    RTPENGINE_MIN_PORT=10000 \
    RTPENGINE_MAX_PORT=10100

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        software-properties-common \
        xz-utils \
    && add-apt-repository --yes universe \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.kamailio.org/kamailiodebkey.gpg \
      | gpg --dearmor -o /usr/share/keyrings/kamailio.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/kamailio57 noble main" \
      > /etc/apt/sources.list.d/kamailio.list

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        kamailio \
        kamailio-modules \
        python3 \
        rtpengine-daemon \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) S6_ARCH="x86_64" ;; \
      arm64) S6_ARCH="aarch64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
      | tar -C / -Jxpf -; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
      | tar -C / -Jxpf -

COPY kamailio/kamailio.cfg /etc/kamailio/kamailio.cfg
COPY healthcheck/healthcheck_server.py /opt/bitcall/healthcheck_server.py
COPY rootfs/ /

RUN chmod +x /etc/cont-init.d/* /etc/services.d/*/run

EXPOSE 80/tcp 5060/tcp 5060/udp 2223/udp 10000-10100/udp

HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD curl -fsS http://127.0.0.1/.well-known/acme-challenge/healthcheck || exit 1

ENTRYPOINT ["/init"]
