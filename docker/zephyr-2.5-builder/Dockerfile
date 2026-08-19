FROM coppertrace-nuttx-builder:13.0.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        device-tree-compiler \
        gperf \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
        "west>=0.7.2,<1.0" \
        "pyelftools>=0.26" \
        "PyYAML>=5.1,<6" \
        pykwalify \
        canopen \
        packaging \
        progress \
        psutil \
        anytree \
        intelhex

ENV ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
ENV GNUARMEMB_TOOLCHAIN_PATH=/opt/mbed-os-toolchain/gcc-arm-none-eabi-10.3-2021.07
