#!/system/bin/sh

for p in $(pidof ningshi); do
  kill -9 "$p" 2>/dev/null
done

rm -rf /data/adb/ningshi
