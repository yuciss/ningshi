#!/usr/bin/env bash
# Build the daemon, place it into the module, and package a flashable zip.
set -euo pipefail
cd "$(dirname "$0")/.."

bash scripts/sync_version.sh

(cd daemon && bash build.sh)

mkdir -p module/bin
cp daemon/target/aarch64-unknown-linux-musl/release/ningshi module/bin/ningshi

version=$(grep -m1 '^version=' module/module.prop | cut -d= -f2)
(cd module && zip -r9 "../ningshi-v${version}.zip" *)
echo "packaged ningshi-v${version}.zip"
