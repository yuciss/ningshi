#!/usr/bin/env bash
# Single source of truth: module/module.prop "version".
# Derive versionCode (major*10000 + minor*100 + patch) and sync Cargo.toml + READMEs.
set -euo pipefail
cd "$(dirname "$0")/.."

v=$(grep -m1 '^version=' module/module.prop | cut -d= -f2)
[ -n "$v" ] || { echo "module.prop has no version" >&2; exit 1; }

major=$(echo "$v" | cut -d. -f1)
minor=$(echo "$v" | cut -d. -f2)
patch=$(echo "$v" | cut -d. -f3)
code=$((major * 10000 + minor * 100 + patch))

sed -i "s/^versionCode=.*/versionCode=${code}/" module/module.prop
sed -i "s/^version = \".*\"/version = \"${v}\"/" daemon/Cargo.toml
sed -i "s/\*\*Version [0-9.]*\*\*/\*\*Version ${v}\*\*/" README.md
sed -i "s/\*\*版本 [0-9.]*\*\*/\*\*版本 ${v}\*\*/" README.zh.md

echo "synced version ${v} (versionCode ${code})"
