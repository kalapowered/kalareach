#!/bin/bash
# stop-unit.sh --name NAME --log-dir DIR [--prefix P]
#
# Ends a unit that run-unit.sh started with --no-wait, waits until its control group is gone,
# and prints its output (after it has ended) the way run-unit.sh does. Exits 1 when the unit is
# still there after 30 seconds. A unit that has already ended is not an error.
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
name='' logdir='' prefix=''
while [ "$#" -gt 0 ]; do
  case $1 in
    --name) name=${2:-}; shift 2 ;;
    --log-dir) logdir=${2:-}; shift 2 ;;
    --prefix) prefix=${2:-}; shift 2 ;;
    *) echo "stop-unit: unknown option $1" >&2; exit 2 ;;
  esac
done
case $name in '' | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*) echo "stop-unit: bad --name" >&2; exit 2 ;; esac
[ -d "$logdir" ] || { echo "stop-unit: --log-dir is not a folder" >&2; exit 2; }
[ -n "$prefix" ] || prefix=$name

sudo -n systemctl stop "$name.service" 2>/dev/null || true
gone=0
for _ in $(seq 1 30); do
  if ! sudo -n systemctl cat "$name.service" >/dev/null 2>&1; then gone=1; break; fi
  state=$(sudo -n systemctl show -p ActiveState --value "$name.service" 2>/dev/null)
  if [ "$state" = inactive ] || [ "$state" = failed ]; then gone=1; break; fi
  sleep 1
done
# After the stop no process of the unit's group remains: its group folder is gone or empty.
cg="/sys/fs/cgroup/system.slice/$name.service"
if [ -d "$cg" ] && [ -n "$(cat "$cg/cgroup.procs" 2>/dev/null)" ]; then gone=0; fi

"$here/replay-log.sh" "$logdir/$name.systemd" "$prefix.systemd" "$logdir/$name.log" "$prefix"
if [ "$gone" -eq 1 ]; then
  echo "stop-unit: $name ended"
  exit 0
fi
echo "stop-unit: $name is still there after 30 seconds" >&2
exit 1
