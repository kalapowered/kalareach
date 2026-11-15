#!/bin/bash
# Group B: every property of the unit's list is accepted by the manager on its own and together,
# and `systemctl show` echoes each one on a running unit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "B properties"
dry="$SBX_LOGS/../b-dry.txt"
unit_legs sbx-b1 --dry-run -- /usr/bin/sleep 90 >"$dry"
n=$(grep -c '^PROPERTY ' "$dry")
ok B.1 "the launcher lists $n properties for a namespaced unit"

# B.2: each property alone, on a trivial unit, with the manager's own words when refused.
i=0
while IFS= read -r line; do
  prop=${line#PROPERTY }
  case $prop in StandardOutput=* | StandardInput=* | StandardError=* | User=* | Group=* | Type=*) continue ;; esac
  i=$((i + 1))
  msg=$(sudo -n systemd-run --wait --collect --quiet -p User=kr-legs -p Type=exec -p "$prop" /usr/bin/true 2>&1 </dev/null)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "B.2.$i" "accepted alone: ${prop%%=*}"
  else
    fail "B.2.$i" "refused alone: ${prop%%=*}; manager says: $(printf '%s' "$msg" | tr '\n' ' ' | cut -c1-240)"
  fi
done < <(grep '^PROPERTY ' "$dry")

# B.3: the whole list on one running unit.
unit_legs sbx-b1 --no-wait -- /usr/bin/sleep 90
state=none
for _ in $(seq 1 20); do
  state=$(sudo -n systemctl show -p ActiveState --value sbx-b1.service 2>/dev/null || echo none)
  [ "$state" = active ] && break
  sleep 0.5
done
if [ "$state" = active ]; then ok B.3 "the unit with the whole list is active"; else fail B.3 "the unit with the whole list is $state"; fi

sudo -n systemctl show sbx-b1.service --no-pager >"$SBX_LOGS/../b-shown.txt" 2>&1
j=10
while IFS="$(printf '\t')" read -r verdict name detail; do
  j=$((j + 1))
  if [ "$verdict" = ok ]; then ok "B.$j" "echoed: $name"; else fail "B.$j" "not echoed as set: $name $detail"; fi
done < <(/usr/bin/python3 "$TOOLS/propcheck.py" "$dry" "$SBX_LOGS/../b-shown.txt")

# B.4: what the running process holds.
pid=$(sudo -n systemctl show -p MainPID --value sbx-b1.service)
if [ -n "$pid" ] && [ "$pid" != 0 ]; then
  st=$(sudo -n cat "/proc/$pid/status")
  printf '%s\n' "$st" | grep -q '^NoNewPrivs:[[:space:]]*1$' && ok B.4 "NoNewPrivs 1" || fail B.4 "NoNewPrivs is not 1"
  printf '%s\n' "$st" | grep -q '^Seccomp:[[:space:]]*2$' && ok B.5 "Seccomp 2" || fail B.5 "Seccomp is not 2"
  printf '%s\n' "$st" | grep -q '^CapEff:[[:space:]]*0*$' && ok B.6 "CapEff zero" || fail B.6 "CapEff is not zero"
  printf '%s\n' "$st" | grep -q '^CapBnd:[[:space:]]*0*$' && ok B.7 "CapBnd zero" || fail B.7 "CapBnd is not zero"
  printf '%s\n' "$st" | grep -q '^Uid:[[:space:]]*[1-9]' && ok B.8 "not uid 0" || fail B.8 "uid 0"
else
  fail B.4 "no main process to read"
fi

# B.9: systemd-analyze's own view (printed).
sec=$(sudo -n systemd-analyze security sbx-b1.service --no-pager 2>&1 | tail -n +1 | cut -c1-140)
printf '%s\n' "$sec" | sed -e 's/^/analyze | /' | head -90
ok B.9 "systemd-analyze security printed"

bash "$SBX_DIR/stop-unit.sh" --name sbx-b1 --log-dir "$SBX_LOGS" || fail B.10 "the unit did not end"

# The variant with /dev/shm made inaccessible instead of a tmpfs (printed: the fallback).
unit_legs sbx-b2 --shm inaccessible --no-wait -- /usr/bin/sleep 20
sleep 2
state=$(sudo -n systemctl show -p ActiveState --value sbx-b2.service 2>/dev/null || echo none)
ok B.200 "variant with /dev/shm inaccessible: state $state"
bash "$SBX_DIR/stop-unit.sh" --name sbx-b2 --log-dir "$SBX_LOGS" >/dev/null || true
endgroup
finish B
