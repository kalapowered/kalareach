#!/bin/bash
# Group E: socket families, the 32-bit system call table and io_uring.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "E families"
FAM="/usr/bin/python3 $TOOLS/fam.py"

# The runner's own view as a control (no sandbox): print only.
ctl=$($FAM families | tr '\n' ';' | sed -e 's/RESULT fam //g')
ok E.0 "control, the runner (no sandbox): $ctl"
ctl=$($FAM uring | tr '\n' ';')
ok E.0b "control, the runner: $ctl"

UNIT_MAX=60 unit_legs sbx-e1 -- $FAM families
for name in AF_VSOCK AF_SMC AF_RXRPC AF_TIPC AF_RDS AF_KCM AF_PACKET AF_ALG; do
  if has sbx-e1 "^RESULT fam $name refused"; then ok "E.1.$name" "socket($name) is refused in the unit"; else fail "E.1.$name" "socket($name) was not refused: $(grep "fam $name" "$SBX_LOGS/sbx-e1.log" | head -1)"; fi
done
for name in AF_UNIX AF_INET AF_INET6 AF_NETLINK; do
  if has sbx-e1 "^RESULT fam $name allowed"; then ok "E.2.$name" "socket($name) works in the unit"; else fail "E.2.$name" "socket($name) is refused: $(grep "fam $name" "$SBX_LOGS/sbx-e1.log" | head -1)"; fi
done

UNIT_MAX=60 unit_legs sbx-e2 -- $FAM uring
if has sbx-e2 '^RESULT uring EPERM$'; then ok E.3 "io_uring_setup returns EPERM in the unit"; else fail E.3 "io_uring_setup: $(rawlog sbx-e2 | head -1)"; fi

# The 32-bit table: the control first (the runner), then the unit.
if [ -x /usr/local/lib/sandbox-probe/ia32 ]; then
  g=$(/usr/local/lib/sandbox-probe/ia32 getpid 2>&1; echo "exit=$?")
  v=$(/usr/local/lib/sandbox-probe/ia32 vsock 2>&1; echo "exit=$?")
  ok E.4a "control, the runner: int 0x80 getpid: $(printf '%s' "$g" | tr '\n' ' '); socket(AF_VSOCK): $(printf '%s' "$v" | tr '\n' ' ')"
  UNIT_MAX=60 unit_legs sbx-e3 -- /usr/local/lib/sandbox-probe/ia32 vsock
  rc=$?
  ret=$(sed -n 's/^RESULT ia32 vsock \(-\{0,1\}[0-9]*\)$/\1/p' "$SBX_LOGS/sbx-e3.log")
  if { [ -z "$ret" ] && [ "$rc" -ne 0 ]; } || { [ -n "$ret" ] && [ "$ret" -lt 0 ]; }; then
    ok E.4 "a 32-bit socket(AF_VSOCK) through int 0x80 does not succeed in the unit (exit $rc, return '${ret:-none}')"
  else
    fail E.4 "a 32-bit socket(AF_VSOCK) returned $ret (exit $rc)"
  fi
  UNIT_MAX=60 unit_legs sbx-e4 -- /usr/local/lib/sandbox-probe/ia32 getpid
  rc=$?
  ok E.5 "a harmless 32-bit call (getpid) in the unit: exit $rc, $(rawlog sbx-e4 | head -1)"
else
  fail E.4 "the 32-bit helper was not built"
fi
endgroup
finish E
