FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
    && { id -u ubuntu >/dev/null 2>&1 || useradd --create-home --shell /bin/bash ubuntu; } \
    && echo 'ubuntu:ubuntu' | chpasswd \
    && chage --lastday 0 ubuntu \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
