FROM debian:13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && useradd --create-home --shell /bin/sh bootstrap \
    && echo 'bootstrap:integration-secret' | chpasswd \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

HEALTHCHECK --interval=2s --timeout=2s --retries=15 \
    CMD ssh-keyscan -T 1 localhost >/dev/null 2>&1 || exit 1

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
