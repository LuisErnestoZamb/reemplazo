# Toolchain image: GRUB bootable-ISO builder + x86 QEMU.
#
# Why containerized (see AGENTS.md):
#  - grub-mkrescue/xorriso do not run on macOS.
#  - Homebrew can't build QEMU on macOS 13 (Tier 3, no bottles → source
#    build fails on current clang). If a host qemu-system-x86_64 ever
#    exists, xtask prefers it; otherwise this image is the fallback.
#
# openssh-client is not a build tool: it is the *interop peer* of
# `cargo xtask smoke-ssh` — a real OpenSSH client runs inside the
# container (its loopback is where VM1 publishes guest :2222) against
# our sshd. ssh-keygen ships with it and is what generates the per-run
# keypair's OpenSSH-format private key on the host.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        grub-common \
        grub-pc-bin \
        xorriso \
        mtools \
        dosfstools \
        qemu-system-x86 \
        netcat-openbsd \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*
