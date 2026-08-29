FROM debian:13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && echo 'root:1234' | chpasswd \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

COPY first-login.sh /usr/local/sbin/armbian-first-login
COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0755 /usr/local/sbin/armbian-first-login

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
