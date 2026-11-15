#!/bin/bash
# Group G: lifetime. A double-forked child and a child that ignores the end signal are gone when
# the launcher returns and stay gone; the time limit ends a unit that ignores the end signal;
# what happens when systemd-run itself receives SIGTERM; a helper-like unit stays active until
# it is stopped (three service types); a crash does not reach a host helper program.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "G lifetime"
LIFE="/usr/bin/python3 $TOOLS/life.py"
tmpdir=/home/kr-legs/tmp
alive() { [ -d "/proc/$1" ]; }
readpid() { sudo -n cat "$tmpdir/$1" 2>/dev/null; }
clean_pids() { sudo -n /usr/bin/find "$tmpdir" -maxdepth 1 -name '*.pid' -delete; }

# G.1: after the main process exits, the whole control group ends, at once and for good.
clean_pids
UNIT_MAX=60 unit_legs sbx-g1 -- $LIFE spawn "$tmpdir"
rc=$?
grand=$(readpid grand.pid)
ign=$(readpid ignore.pid)
if [ -n "$grand" ] && [ -n "$ign" ]; then
  if ! alive "$grand" && ! alive "$ign"; then
    ok G.1 "when the launcher returned (exit $rc) the double-forked child ($grand) and the SIGTERM-ignoring child ($ign) were gone"
  else
    fail G.1 "survivors at return: grand alive=$(alive "$grand" && echo yes || echo no) ignorer alive=$(alive "$ign" && echo yes || echo no)"
  fi
  sleep 30
  if ! alive "$grand" && ! alive "$ign"; then ok G.2 "both are still gone 30 s later"; else fail G.2 "a child came back or lived on"; fi
else
  fail G.1 "the fixture did not record its pids (grand='$grand' ignorer='$ign')"
fi

# G.3: a time limit ends a unit whose main process ignores SIGTERM (killed after TimeoutStopSec).
start=$(date +%s)
UNIT_MAX=3 unit_legs sbx-g3 -- $LIFE ignore
rc=$?
took=$(( $(date +%s) - start ))
if [ "$rc" -ne 0 ] && grep -q 'timeout' "$SBX_LOGS/sbx-g3.systemd" && [ "$took" -le 30 ]; then
  ok G.3 "RuntimeMaxSec=3 ended a SIGTERM-ignoring unit with result timeout after $took s (exit $rc)"
else
  fail G.3 "time limit on a SIGTERM-ignorer: exit $rc after $took s: $(tr '\n' ';' <"$SBX_LOGS/sbx-g3.systemd" | cut -c1-200)"
fi

# G.4: systemd-run receiving SIGTERM (recorded, not asserted): is the unit stopped?
UNIT_MAX=120 unit_legs sbx-g4 -- /bin/sleep 100 &
sleep 4
srpid=$(pgrep -f '^systemd-run --unit=sbx-g4 ' | head -1)
if [ -n "$srpid" ]; then
  sudo -n kill -TERM "$srpid"
  sleep 3
  state=$(sudo -n systemctl show -p ActiveState --value sbx-g4.service 2>/dev/null || echo gone)
  ok G.4 "recorded: after SIGTERM to systemd-run --wait the unit is: ${state:-gone}"
else
  ok G.4 "recorded: no systemd-run process was found to signal"
fi
sudo -n systemctl stop sbx-g4.service 2>/dev/null
wait

# G.5: a helper-like unit (a starter that leaves a detached child and exits) in three service types.
helper_case() { # helper_case ID NAME TYPE_OPTIONS...
  local id=$1 name=$2
  shift 2
  clean_pids
  UNIT_MAX=300 unit_legs "$name" --no-wait "$@" -- $LIFE helper "$tmpdir"
  sleep 6
  local state sub child
  state=$(sudo -n systemctl show -p ActiveState --value "$name.service" 2>/dev/null || echo gone)
  sub=$(sudo -n systemctl show -p SubState --value "$name.service" 2>/dev/null || echo gone)
  child=$(readpid helper.pid)
  local childalive=no
  [ -n "$child" ] && alive "$child" && childalive=yes
  if [ "$state" = active ] && [ "$childalive" = yes ]; then
    ok "$id" "helper-like unit ($*): stays $state/$sub with its detached child alive after its starter exited"
  else
    fail "$id" "helper-like unit ($*): state $state/$sub, detached child alive=$childalive"
  fi
  bash "$SBX_DIR/stop-unit.sh" --name "$name" --log-dir "$SBX_LOGS" >/dev/null
  sleep 1
  if [ -n "$child" ] && ! alive "$child"; then ok "$id.stop" "after the stop the detached child is gone ($name)"; else fail "$id.stop" "the detached child survived the stop ($name)"; fi
}
helper_case G.5a sbx-g5a --type exec --exit-type cgroup
helper_case G.5b sbx-g5b --type forking --prop GuessMainPID=no
helper_case G.5c sbx-g5c --type oneshot --prop RemainAfterExit=yes

# G.6: a crash. A pipe in kernel.core_pattern starts a helper program outside the unit; with the
# core size limit 0 it must not start. Count the journal's coredump entries around each crash.
cd_count() { sudo -n journalctl -b --no-pager -q -t systemd-coredump 2>/dev/null | grep -c 'dumped core\|Process .* of user' || true; }
before=$(cd_count)
{ bash -c 'ulimit -c unlimited; kill -SEGV $$'; } 2>/dev/null
sleep 3
after_control=$(cd_count)
ok G.6a "control: the runner's crash with core limit unlimited moved the coredump entries from $before to $after_control (core_pattern: $(cut -c1-60 /proc/sys/kernel/core_pattern))"
UNIT_MAX=30 unit_legs sbx-g6 -- $LIFE crash
sleep 3
after_unit=$(cd_count)
ok G.6 "recorded: with the image's core_pattern a crash in a unit (LimitCORE=0) moved the coredump entries from $after_control to $after_unit"
sudo -n sysctl -w kernel.core_pattern=core >/dev/null 2>&1
if [ "$(cat /proc/sys/kernel/core_pattern)" = core ]; then ok G.7 "the runner set kernel.core_pattern to a plain file name"; else fail G.7 "kernel.core_pattern is $(cat /proc/sys/kernel/core_pattern)"; fi
UNIT_MAX=30 unit_legs sbx-g8 -- $LIFE crash
sleep 3
after_plain=$(cd_count)
if [ "$after_plain" = "$after_unit" ]; then
  ok G.8 "with a plain core_pattern a crash in a unit starts no helper: entries stay at $after_plain"
else
  fail G.8 "with a plain core_pattern a crash changed the entries from $after_unit to $after_plain"
fi
endgroup
finish G
