#!/system/bin/sh

MODDIR=${0%/*}

while true; do
  "$MODDIR/bin/ningshi" >>"$MODDIR/ningshi.log" 2>&1
  sleep 5
done &
