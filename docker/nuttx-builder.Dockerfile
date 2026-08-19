FROM mbed-os:latest

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bison \
        flex \
        gperf \
        kconfig-frontends \
        libncurses-dev \
        make \
        patch \
        unzip \
    && rm -rf /var/lib/apt/lists/*
