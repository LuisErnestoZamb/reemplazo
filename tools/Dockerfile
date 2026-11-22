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
# Pin the base image by digest (audit-boot H3): the moving
# `trixie-slim` tag lets an upstream change swap QEMU/GRUB/OpenSSH in
# the toolchain without any commit here. This is the multi-arch index
# digest of `debian:trixie-slim` resolved on 2026-11-22; it still
# selects the amd64 layer. Re-resolve deliberately when upgrading.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392

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
