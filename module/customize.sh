#!/system/bin/sh

[ "$(uname -m)" = "aarch64" ] || abort "Ningshi supports arm64 only, current: $(uname -m)"

# The gate has two independent kernel anchors and needs at least one of them:
#   * binder_transaction    - precise: the first non-zero-handle transaction of a
#                             new process is attachApplication;
#   * __arm64_sys_setresuid - independent of binder: a process just swapped to a
#                             blocked uid (zygote's child does this before any
#                             app code runs).
# Having both is best, so a missing symbol degrades instead of refusing to
# install; a clear message beats a module that silently does nothing.
anchor_binder=0
anchor_uid=0

grep -qE "[[:space:]]binder_transaction$" /proc/kallsyms 2>/dev/null && anchor_binder=1
grep -qE "[[:space:]]__arm64_sys_setresuid$" /proc/kallsyms 2>/dev/null && anchor_uid=1

if [ "$anchor_binder" = 0 ] && [ "$anchor_uid" = 0 ]; then
  abort "kernel exposes neither binder_transaction nor __arm64_sys_setresuid, interception unavailable"
fi
ui_print "- gate anchors: binder_transaction=$anchor_binder uid_switch=$anchor_uid"

mkdir -p /data/adb/ningshi
set_perm /data/adb/ningshi 0 0 0700

# First install only: detect device timezone/language and write initial rules.
if [ ! -f /data/adb/ningshi/rules.json ]; then
  tz="UTC"
  off=$(date +%z 2>/dev/null | tr -d ' ')
  if [ "${#off}" -eq 5 ]; then
    sign=${off%????}
    hh=$(echo "$off" | cut -c2-3 | sed 's/^0*//')
    [ -z "$hh" ] && hh=0
    if [ "$hh" != "0" ]; then
      tz="UTC${sign}${hh}"
    fi
  fi
  lang="en"
  case "$(getprop persist.sys.locale 2>/dev/null)" in
    zh*) lang="zh" ;;
  esac
  cat > /data/adb/ningshi/rules.json <<EOF
{
  "version": 1,
  "settings": {
    "timezone": "$tz",
    "language": "$lang",
    "clear_log_on_boot": false
  },
  "apps": {},
  "groups": {}
}
EOF
  chmod 600 /data/adb/ningshi/rules.json
fi

set_perm "$MODPATH/bin/ningshi" 0 0 0755
