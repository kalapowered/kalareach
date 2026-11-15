#!/bin/bash
# Group C: the namespace by its path, the guard, two negative controls, and the address filter
# by itself.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "C namespace"
legs=$(bash "$SBX_DIR/make-netns.sh" inode sbx-legs)
svc=$(bash "$SBX_DIR/make-netns.sh" inode sbx-svc)
host=$(stat -L -c %i /proc/self/ns/net)
if [ "$legs" != "$svc" ] && [ "$legs" != "$host" ] && [ "$svc" != "$host" ]; then
  ok C.1 "the two namespaces and the runner's namespace are three different inodes"
else
  fail C.1 "two of the namespaces share an inode"
fi

# C.2: the runner's own view of each namespace: the loopback alone, up, both addresses.
for ns in sbx-legs sbx-svc; do
  links=$(sudo -n ip -n "$ns" -o link show)
  if [ "$(printf '%s\n' "$links" | wc -l)" -eq 1 ] && printf '%s\n' "$links" | grep -q 'lo:.*<LOOPBACK,UP,LOWER_UP>'; then
    ok "C.2.$ns" "$ns holds the loopback alone, up"
  else
    fail "C.2.$ns" "$ns: $(printf '%s' "$links" | tr '\n' ';' | cut -c1-200)"
  fi
  sudo -n ip -n "$ns" -o addr show dev lo | grep -q 'inet 127.0.0.1/8' && sudo -n ip -n "$ns" -o -6 addr show dev lo | grep -q 'inet6 ::1/128' \
    && ok "C.3.$ns" "$ns: 127.0.0.1 and ::1 on lo" || fail "C.3.$ns" "$ns: an address is missing"
  routes=$(sudo -n ip -n "$ns" route show; sudo -n ip -n "$ns" -6 route show | grep -v ' dev lo ' || true)
  [ -z "$routes" ] && ok "C.4.$ns" "$ns has no route outside lo" || fail "C.4.$ns" "$ns routes: $(printf '%s' "$routes" | tr '\n' ';' | cut -c1-200)"
done

# C.5: a unit joined to the legs' namespace passes the guard and stands in that inode.
unit_legs sbx-c5 --no-wait -- /usr/bin/python3 "$TOOLS/net.py" ifaces
sleep 2
bash "$SBX_DIR/stop-unit.sh" --name sbx-c5 --log-dir "$SBX_LOGS" >/dev/null
if has sbx-c5 "^RESULT ifaces lo$" && has sbx-c5 "^RESULT netns net:\[$legs\]$"; then
  ok C.5 "a unit in the legs' namespace sees lo alone and inode $legs, the guard passed"
else
  fail C.5 "the unit's own view: $(rawlog sbx-c5 | tr '\n' ';' | cut -c1-300)"
fi

# C.6: the host's view of a running unit's process.
unit_legs sbx-c6 --no-wait -- /usr/bin/sleep 30
sleep 1
pid=$(sudo -n systemctl show -p MainPID --value sbx-c6.service)
seen=$(sudo -n stat -L -c %i "/proc/$pid/ns/net" 2>/dev/null || echo none)
[ "$seen" = "$legs" ] && ok C.6 "the host sees the unit's process in inode $legs" || fail C.6 "the host sees inode $seen, not $legs"
bash "$SBX_DIR/stop-unit.sh" --name sbx-c6 --log-dir "$SBX_LOGS" >/dev/null

# C.7: negative control 1. A unit joined to PID 1's namespace (the host's) is refused by the guard.
bash "$SBX_DIR/run-unit.sh" --name sbx-c7 --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
  --log-dir "$SBX_LOGS" --guard "$GUARD" --netns-path /proc/1/ns/net --netns-inode "$legs" "${LEGS_BINDS[@]}" \
  --runtime-max 30 -- /usr/bin/id -u
rc=$?
if [ "$rc" -eq 97 ] && has sbx-c7 "guard: refused: network namespace inode" && ! has sbx-c7 "^[0-9][0-9]*$"; then
  ok C.7 "a unit joined to the host's namespace was refused by the guard (exit $rc), its command never ran"
else
  fail C.7 "host-namespace unit: exit $rc, log: $(rawlog sbx-c7 | tr '\n' ';' | cut -c1-200)"
fi

# C.8: negative control 2. A namespace path that does not exist stops the start.
bash "$SBX_DIR/run-unit.sh" --name sbx-c8 --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
  --log-dir "$SBX_LOGS" --guard "$GUARD" --netns-path /run/netns/sbx-missing --netns-inode 1 "${LEGS_BINDS[@]}" \
  --runtime-max 30 -- /usr/bin/id -u
rc=$?
if [ "$rc" -ne 0 ] && [ ! -s "$SBX_LOGS/sbx-c8.log" ]; then
  ok C.8 "a missing namespace path stopped the start (exit $rc), the command never ran"
else
  fail C.8 "missing path: exit $rc, log size $(stat -c %s "$SBX_LOGS/sbx-c8.log")"
fi

# C.9: the guard also refuses a unit without no-new-privileges (the property is dropped on purpose).
unit_legs sbx-c9 --prop NoNewPrivileges=no -- /usr/bin/id -u
rc=$?
if [ "$rc" -eq 97 ] && has sbx-c9 "guard: refused: NoNewPrivs is not 1"; then
  ok C.9 "the guard refused a unit without NoNewPrivileges (exit $rc)"
else
  fail C.9 "no-NNP unit: exit $rc, log: $(rawlog sbx-c9 | tr '\n' ';' | cut -c1-200)"
fi

# C.10: the address filter by itself, on the host network: 127.0.0.1 is allowed, 127.0.0.2 is not.
listeners_start || fail C.10 "listeners did not start"
runner_view=$(/usr/bin/python3 "$TOOLS/net.py" check tcp:127.0.0.1:18443 tcp:127.0.0.2:18444)
if [ "$(printf '%s\n' "$runner_view" | grep -c ' reached ')" -eq 2 ]; then
  ok C.10 "control: the runner reaches 127.0.0.1:18443 and 127.0.0.2:18444"
else
  fail C.10 "control failed: $(printf '%s' "$runner_view" | tr '\n' ';')"
fi
unit_host sbx-c11 --prop IPAddressDeny=any --prop 'IPAddressAllow=127.0.0.1/32 ::1/128' -- \
  /usr/bin/python3 "$TOOLS/net.py" check tcp:127.0.0.1:18443 tcp:127.0.0.2:18444
if has sbx-c11 "^RESULT tcp:127.0.0.1:18443 reached" && has sbx-c11 "^RESULT tcp:127.0.0.2:18444 blocked"; then
  ok C.11 "the address filter alone allows 127.0.0.1 and refuses 127.0.0.2 ($(grep -o 'blocked [A-Z]*' "$SBX_LOGS/sbx-c11.log" | head -1))"
else
  fail C.11 "address filter alone: $(rawlog sbx-c11 | tr '\n' ';' | cut -c1-300)"
fi
listeners_stop
endgroup
finish C
