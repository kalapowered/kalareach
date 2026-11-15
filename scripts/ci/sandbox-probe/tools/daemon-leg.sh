#!/bin/bash
# daemon-leg.sh
# Runs as the build account in a legs unit, after the builds: starts core's control daemon with
# the file secret store, the way the end-to-end harness does, as a process of its own session;
# asks it `kr list --json` and `kr doctor`; prints the account's processes; and exits while the
# daemon is still running, so that the unit's end is what must end it. Every fact is one
# `DAEMON <name> <value>` line for the runner to read.
set -u
bin=/opt/kr-legs/target/debug
run=/home/kr-legs/tmp/daemon-leg-run
for f in kr kr-controller kr-worker; do
  [ -x "$bin/$f" ] || { echo "DAEMON missing $f"; exit 1; }
done
rm -rf -- "$run"
mkdir -p "$run/runtime" "$run/state" "$run/home"
chmod 0700 "$run" "$run/runtime" "$run/state" "$run/home"

export HOME="$run/home" KR_RUNTIME_DIR="$run/runtime" KR_STATE_DIR="$run/state" PATH=/usr/bin:/bin
echo "DAEMON resolv-conf-target $(readlink /etc/resolv.conf) exists=$([ -e /etc/resolv.conf ] && echo yes || echo no)"

setsid "$bin/kr-controller" --runtime-dir "$run/runtime" --state-dir "$run/state" \
  --secret-store file --worker "$bin/kr-worker" >"$run/daemon.log" 2>&1 </dev/null &

up=0
out=''
for i in $(seq 1 90); do
  if out=$("$bin/kr" list --json 2>&1); then up=1; break; fi
  sleep 1
done
echo "DAEMON list answered=$up after=${i}s bytes=${#out}"
if printf '%s' "$out" | /usr/bin/python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  echo "DAEMON list json=yes"
else
  echo "DAEMON list json=no"
fi

doc=$("$bin/kr" doctor 2>&1)
rc=$?
echo "DAEMON doctor exit=$rc bytes=${#doc}"
echo "DAEMON doctor detached-lines=$(printf '%s\n' "$doc" | grep -c -i 'detached process')"
printf '%s\n' "$doc" | grep -i -E 'supervis|detached' | head -4 | cut -c1-220 | sed -e 's/^/DAEMON-DOCTOR /'

echo "DAEMON log warn-lines=$(grep -c -i -E 'resolv|dns|nameserver' "$run/daemon.log")"
grep -i -E 'resolv|dns|nameserver' "$run/daemon.log" | head -3 | cut -c1-220 | sed -e 's/^/DAEMON-LOG /'
echo "DAEMON log panics=$(grep -c -i -E 'panicked|fatal' "$run/daemon.log")"

echo "DAEMON controller-running=$(pgrep -c -x kr-controller)"
echo "DAEMON processes-before-end:"
ps -u "$(id -u)" -o pid=,ppid=,pgid=,sid=,stat=,comm= | sed -e 's/^/DAEMON-PS /'
[ "$up" -eq 1 ]
