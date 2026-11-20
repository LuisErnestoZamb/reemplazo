# Toolchain image: GRUB bootable-ISO builder + x86 QEMU.
#
# Why containerized (see AGENTS.md):
#  - grub-mkrescue/xorriso do not run on macOS.
#  - Homebrew can't build QEMU on macOS 13 (Tier 3, no bottles → source
#    build fails on current clang). If a host qemu-system-x86_64 ever
#    exists, xtask prefers it; otherwise this image is the fallback.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        grub-common \
        grub-pc-bin \
        xorriso \
        mtools \
        dosfstools \
        qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/*
