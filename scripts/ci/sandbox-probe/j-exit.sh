#!/bin/bash
# Group J: exit codes through the launcher, a signal, a time limit, a missing program, and
# arguments that must reach the program as written.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "J exit codes"
n=0
for want in 0 1 3 77; do
  n=$((n + 1))
  unit_legs "sbx-j$n" -- /bin/sh -c "exit $want"
  rc=$?
  if [ "$rc" -eq "$want" ]; then ok "J.$n" "a unit that exits $want makes the launcher exit $want"; else fail "J.$n" "a unit that exits $want gave $rc"; fi
done

# J.5: a signal (the unit's own shell kills itself with SIGKILL).
unit_legs sbx-j5 -- /bin/sh -c 'kill -9 $$'
rc=$?
if [ "$rc" -ne 0 ]; then ok J.5 "a unit killed by a signal gives a nonzero exit ($rc)"; else fail J.5 "a unit killed by a signal gave 0"; fi

# J.6: the time limit ends the unit, with the manager's result "timeout".
UNIT_MAX=3 unit_legs sbx-j6 -- /bin/sleep 30
rc=$?
if [ "$rc" -ne 0 ] && grep -q 'timeout' "$SBX_LOGS/sbx-j6.systemd"; then
  ok J.6 "RuntimeMaxSec ended the unit with result timeout (exit $rc)"
else
  fail J.6 "time limit: exit $rc, manager says: $(tr '\n' ';' <"$SBX_LOGS/sbx-j6.systemd" | cut -c1-300)"
fi

# J.7: a program that does not exist, on the host network (no guard) and behind the guard.
unit_host sbx-j7 -- /usr/bin/sbx-no-such-program
rc=$?
if [ "$rc" -ne 0 ]; then ok J.7 "a missing program without the guard gives a nonzero exit ($rc): $(grep -o 'status=[0-9/A-Z]*' "$SBX_LOGS/sbx-j7.systemd" | head -1)"; else fail J.7 "a missing program gave 0"; fi
unit_legs sbx-j8 -- /usr/bin/sbx-no-such-program
rc=$?
if [ "$rc" -ne 0 ]; then ok J.8 "a missing program behind the guard gives a nonzero exit ($rc)"; else fail J.8 "a missing program behind the guard gave 0"; fi

# J.9: arguments with $ and % reach the program as written.
unit_legs sbx-j9 -- /usr/bin/printf '%s\n' 'a$HOME' 'b%h' 'c$$' 'd%%' 'e${USER}'
rc=$?
want=$(printf '%s\n' 'a$HOME' 'b%h' 'c$$' 'd%%' 'e${USER}')
got=$(cat "$SBX_LOGS/sbx-j9.log")
if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
  ok J.9 "arguments with \$ and % reach the program as written"
else
  fail J.9 "arguments changed on the way: $(printf '%s' "$got" | tr '\n' ' ')"
fi

# J.10: what the manager prints at the end of a waited unit (printed).
sed -e 's/^/manager | /' "$SBX_LOGS/sbx-j3.systemd" | head -20
if grep -q 'status=3' "$SBX_LOGS/sbx-j3.systemd"; then ok J.10 "the manager's end text names the command's own status 3"; else fail J.10 "the manager's end text does not name status 3"; fi
endgroup
finish J
