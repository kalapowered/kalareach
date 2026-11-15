#!/bin/bash
# Group M: a refused address, shown by a pair. The same probe (tools/m-try.py) runs in a unit that has no address
# rule (the twin) and in a unit with the fetch unit's rule; a party of the probe's own answers at each address.
# What the pair shows: the twin is answered, the rule's unit gets the filter's EPERM for a datagram and a timeout
# for a connection, and the party sees the twin's packets alone. Also printed: the manager's report of the rule.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/k-lib.sh"

group "M pairs"
port=18470
ownip=$(hostname -I | awk '{print $1}')
names=(metadata wireserver private-10 private-172 private-192 loopback loopback-other own)
addrs=(169.254.169.253 168.63.129.16 10.255.255.254 172.16.255.254 192.168.255.254 127.0.0.1 127.0.0.2 "$ownip")
plog="$RUNNER_TEMP/m-party.log"
ppid=''
echo "M facts: kernel $(uname -r); $(systemctl --version | head -n 1); $(python3 --version)"

cleanup() {
  [ -z "$ppid" ] || kill "$ppid" 2>/dev/null
  for a in "${addrs[@]:0:5}"; do sudo -n ip addr del "$a/32" dev lo 2>/dev/null; done
}
trap cleanup EXIT

for a in "${addrs[@]:0:5}"; do
  sudo -n ip addr add "$a/32" dev lo scope host || fail M.0 "address $a could not be put on lo"
done
/usr/bin/python3 "$TOOLS/m-party.py" "$port" "$plog" "${addrs[@]}" &
ppid=$!
for _ in $(seq 1 40); do grep -q '^READY$' "$plog" 2>/dev/null && break; sleep 0.25; done
grep -q '^READY$' "$plog" && ok M.0 "the party is bound at ${#addrs[@]} addresses, port $port" || fail M.0 "the party did not start"

UNIT_MAX=60 unit_host sbx-m-twin -- /usr/bin/python3 "$TOOLS/m-try.py" "$port" m-twin "${addrs[@]}"
UNIT_MAX=60 unit_fetch sbx-m-rule -- /usr/bin/python3 "$TOOLS/m-try.py" "$port" m-rule "${addrs[@]}"
sleep 1
kill "$ppid" 2>/dev/null
wait "$ppid" 2>/dev/null
ppid=''
for a in "${addrs[@]:0:5}"; do sudo -n ip addr del "$a/32" dev lo || fail M.0 "address $a could not be removed"; done
left=$(ip -4 -o addr show dev lo | grep -c -v '127.0.0.1/8')
[ "$left" -eq 0 ] && ok M.0r "the addresses of the controls are gone from lo" || fail M.0r "$left addresses stand on lo"

res() { grep -m1 "^M-RESULT $2 $3 " "$SBX_LOGS/sbx-m-$1.log" | cut -d' ' -f4; }
for i in "${!addrs[@]}"; do
  a=${addrs[$i]}
  n=${names[$i]}
  tt=$(res twin "$a" tcp)
  tu=$(res twin "$a" udp)
  rt=$(res rule "$a" tcp)
  ru=$(res rule "$a" udp)
  pt=$(grep -c "^TCP $a\$" "$plog")
  pu=$(grep -c "^UDP $a m-twin\$" "$plog")
  pr=$(grep -c "^UDP $a m-rule\$" "$plog")
  what="$n: twin tcp=$tt udp=$tu; rule tcp=$rt udp=$ru; party tcp=$pt twin-udp=$pu rule-udp=$pr"
  if [ "$tt" = reached ] && [ "$tu" = sent ] && { [ "$rt" = timeout ] || [ "$rt" = EPERM ]; } && [ "$ru" = EPERM ] && [ "$pt" = 1 ] && [ "$pu" = 1 ] && [ "$pr" = 0 ]; then
    ok "M.1.$n" "$what"
  else
    fail "M.1.$n" "$what"
  fi
done

# The manager's report of the rule, as the fetch unit's options give it, and the twin's (no rule).
UNIT_MAX=40 unit_fetch sbx-m-hold --no-wait -- /bin/sleep 30
for p in IPAddressDeny IPAddressAllow; do
  echo "M report: $p=$(sudo -n systemctl show -p "$p" --value sbx-m-hold.service)"
  echo "M report raw: $(sudo -n systemctl show -p "$p" sbx-m-hold.service)"
done
bash "$SBX_DIR/stop-unit.sh" --name sbx-m-hold --log-dir "$SBX_LOGS"
UNIT_MAX=40 unit_host sbx-m-hold2 --no-wait -- /bin/sleep 30
echo "M report twin: deny=[$(sudo -n systemctl show -p IPAddressDeny --value sbx-m-hold2.service)] allow=[$(sudo -n systemctl show -p IPAddressAllow --value sbx-m-hold2.service)]"
bash "$SBX_DIR/stop-unit.sh" --name sbx-m-hold2 --log-dir "$SBX_LOGS"
endgroup
finish M
