#!/system/bin/sh

for p in $(pidof ningshi); do
  kill -9 "$p" 2>/dev/null
done

# Keep /data/adb/ningshi/rules.json: it is hand-tuned user configuration, and
# reinstalling the module should not silently lose it. Only the runtime state
# (today's usage/cooldown counters) is meaningless after removal.
rm -f /data/adb/ningshi/state.json
# Full wipe, if you really want it:
#   rm -rf /data/adb/ningshi
