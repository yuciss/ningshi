#!/system/bin/sh

MODDIR=${0%/*}

# The daemon writes as root: keep what it creates out of reach of other uids
# (the boot shell's umask is 000, so the log used to be created 0666).
umask 077

# One daemon only. The daemon itself also holds an flock; this check just avoids
# pointless restarts (and log noise) while it is already running.
#
# A daemon that cannot start (e.g. the kernel has no usable probe at all) would
# otherwise be respawned every 5 seconds forever; back off instead, but never so
# far that a transient failure costs minutes.
fail=0
while true; do
  if [ -z "$(pidof ningshi)" ]; then
    started=$(date +%s)
    "$MODDIR/bin/ningshi" >>"$MODDIR/ningshi.log" 2>&1
    ran=$(( $(date +%s) - started ))
    if [ "$ran" -lt 3 ]; then
      fail=$((fail + 1))
    else
      fail=0
    fi
  fi
  if [ "$fail" -ge 3 ]; then
    sleep 60
  elif [ "$fail" -ge 1 ]; then
    sleep 15
  else
    sleep 5
  fi
done &
