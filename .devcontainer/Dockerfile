FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash-completion \
        ca-certificates \
        curl \
        dnsutils \
        expect \
        git \
        iproute2 \
        iputils-ping \
        jq \
        less \
        lsof \
        make \
        netcat-openbsd \
        openssh-client \
        procps \
        qemu-system-x86 \
        qemu-utils \
        rsync \
        shellcheck \
        socat \
        sshpass \
        strace \
        tcpdump \
        tree \
        unzip \
        vim \
        wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-dev.txt /tmp/ssh-bootstrap-requirements-dev.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/ssh-bootstrap-requirements-dev.txt \
    && rm /tmp/ssh-bootstrap-requirements-dev.txt
