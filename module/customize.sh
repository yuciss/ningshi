#!/system/bin/sh

[ "$(uname -m)" = "aarch64" ] || abort "Ningshi supports arm64 only, current: $(uname -m)"

grep -qE "[[:space:]]binder_transaction$" /proc/kallsyms 2>/dev/null \
  || abort "kernel lacks the binder_transaction symbol, interception unavailable"

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
