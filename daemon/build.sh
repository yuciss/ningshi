#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 1/2 compile BPF"
clang -target bpf -O2 -g -c bpf/gate.bpf.c -o bpf/gate.bpf.o

echo "==> 2/2 cross compile daemon (aarch64 musl static)"
cargo zigbuild --release --target aarch64-unknown-linux-musl

echo "==> output: target/aarch64-unknown-linux-musl/release/ningshi"
