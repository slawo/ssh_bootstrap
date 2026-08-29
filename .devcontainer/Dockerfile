FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN printf '%s\n' \
        'Acquire::Retries "5";' \
        'Acquire::http::Timeout "30";' \
        'Acquire::https::Timeout "30";' \
        'APT::Update::Error-Mode "any";' \
        > /etc/apt/apt.conf.d/80-ssh-bootstrap-retries

RUN apt-get update --no-list-cleanup \
    && apt-get install --yes --no-install-recommends --no-install-suggests \
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
