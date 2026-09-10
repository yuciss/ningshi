#!/system/bin/sh

MODDIR=${0%/*}

# The daemon writes as root: keep what it creates out of reach of other uids
# (the boot shell's umask is 000, so the log used to be created 0666).
umask 077

while true; do
  # One daemon only. The daemon itself also holds an flock; this check just
  # avoids pointless restarts (and log noise) while it is already running.
  if [ -z "$(pidof ningshi)" ]; then
    "$MODDIR/bin/ningshi" >>"$MODDIR/ningshi.log" 2>&1
  fi
  sleep 5
done &
