#!/usr/bin/env bash
# Build the eBPF object for the EDR Linux agent.
#
# Output: agent-linux/ebpf/edr.bpf.o (BTF-relocatable, loaded at runtime
# by aya in agent-linux). The user-mode crate's build.rs invokes this.
#
# Prerequisites:
#   - clang (>= 14, tested with 18)
#   - bpftool (in linux-tools-* on Ubuntu 24.04 — install if missing)
#   - /sys/kernel/btf/vmlinux (default-on for Ubuntu 22.04+)
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR"

# Locate bpftool: prefer the matching linux-tools-$KREL variant.
BPFTOOL=""
KREL=$(uname -r)
for candidate in \
    "/usr/lib/linux-tools-$KREL/bpftool" \
    "/usr/lib/linux-tools/$KREL/bpftool" \
    "/usr/sbin/bpftool" \
    "$(command -v bpftool 2>/dev/null || true)"; do
    if [ -x "$candidate" ]; then BPFTOOL="$candidate"; break; fi
done
if [ -z "$BPFTOOL" ]; then
    echo "ERROR: bpftool not found. apt install linux-tools-$KREL" >&2
    exit 1
fi

# Generate vmlinux.h from BTF (fast — skips if already up-to-date).
if [ ! -f vmlinux.h ] || [ vmlinux.h -ot /sys/kernel/btf/vmlinux ]; then
    echo "[ebpf] generating vmlinux.h via bpftool"
    "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h.tmp
    mv vmlinux.h.tmp vmlinux.h
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET_ARCH=x86 ;;
    aarch64) TARGET_ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

echo "[ebpf] compiling edr.bpf.c (target=bpf, __TARGET_ARCH_${TARGET_ARCH})"
clang \
    -target bpf \
    -O2 -g \
    -Wall -Wextra -Werror \
    -Wno-unused-parameter \
    -D__TARGET_ARCH_${TARGET_ARCH} \
    -I. \
    -c edr.bpf.c \
    -o edr.bpf.o

# Strip DWARF debug sections; keep BTF (required for CO-RE relocations).
# Only `llvm-strip` understands the BPF ELF format reliably; GNU strip
# rejects it with "Unable to recognise the format". We skip silently if
# neither is available — DWARF in .bpf.o doesn't break aya, just bloats
# the binary.
if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip --strip-debug edr.bpf.o
fi

echo "[ebpf] OK -> $DIR/edr.bpf.o"
ls -la edr.bpf.o
