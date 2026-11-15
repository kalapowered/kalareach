#!/bin/bash
# stop-unit.sh --name NAME --log-dir DIR [--prefix P]
#
# Ends a unit that run-unit.sh started with --no-wait, waits until its control group is gone,
# and prints its output (after it has ended) the way run-unit.sh does. Exits 1 when the unit is
# still there after 30 seconds. A unit that has already ended is not an error.
set -u

dir=$(dirname "${BASH_SOURCE[0]}") || { echo "stop-unit: cannot find its own folder" >&2; exit 2; }
here=$(cd "$dir" && pwd) || { echo "stop-unit: cannot find its own folder" >&2; exit 2; }
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

# A stop of a unit that is not loaded fails too, so the stop's status says nothing about the
# unit: the questions below do. A question that cannot be asked is not the answer "gone": the
# script then ends with 1 (asked=0).
sudo -n systemctl stop "$name.service" 2>/dev/null
gone=0
asked=1
tries=0
while [ "$tries" -lt 30 ]; do
  tries=$((tries + 1))
  if props=$(sudo -n systemctl show -p LoadState -p ActiveState "$name.service" 2>/dev/null); then
    case $props in
      *LoadState=not-found* | *ActiveState=inactive* | *ActiveState=failed*) gone=1; break ;;
    esac
  else
    asked=0
    break
  fi
  sleep 1
done
# After the stop no process of the unit's group remains: its group folder is gone or empty.
cg="/sys/fs/cgroup/system.slice/$name.service"
if [ -e "$cg/cgroup.procs" ]; then
  if procs=$(cat "$cg/cgroup.procs" 2>/dev/null); then
    [ -z "$procs" ] || gone=0
  elif [ -e "$cg/cgroup.procs" ]; then
    gone=0
    asked=0
  fi
fi

"$here/replay-log.sh" "$logdir/$name.systemd" "$prefix.systemd" "$logdir/$name.log" "$prefix"
if [ "$gone" -eq 1 ]; then
  echo "stop-unit: $name ended"
  exit 0
fi
if [ "$asked" -eq 0 ]; then
  echo "stop-unit: cannot ask about $name" >&2
  exit 1
fi
echo "stop-unit: $name is still there after 30 seconds" >&2
exit 1
