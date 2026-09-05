#!/system/bin/sh

[ "$(uname -m)" = "aarch64" ] || abort "Ningshi supports arm64 only, current: $(uname -m)"

grep -qE "[[:space:]]binder_transaction$" /proc/kallsyms 2>/dev/null \
  || abort "kernel lacks the binder_transaction symbol, interception unavailable"

mkdir -p /data/adb/ningshi
set_perm /data/adb/ningshi 0 0 0700

set_perm "$MODPATH/bin/ningshi" 0 0 0755
