FROM mcr.microsoft.com/devcontainers/base:trixie

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/opt/ssh-bootstrap-venv/bin:${PATH}

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
        python3 \
        python3-venv \
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
RUN python3 -m venv /opt/ssh-bootstrap-venv \
    && /opt/ssh-bootstrap-venv/bin/python -m pip install --no-cache-dir \
        --requirement /tmp/ssh-bootstrap-requirements-dev.txt \
    && rm /tmp/ssh-bootstrap-requirements-dev.txt
