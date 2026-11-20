# grub-mkrescue doesn't run on macOS; this image provides the i386-pc
# platform files + xorriso so xtask can build BIOS-bootable ISOs.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        grub-common \
        grub-pc-bin \
        xorriso \
        mtools \
        dosfstools \
    && rm -rf /var/lib/apt/lists/*
