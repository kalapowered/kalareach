#!/bin/bash
# Group D: reach. Through the byte proxy between the service's and the legs' namespace (both
# ways, idle, half-close); a second listener of the service out of reach; no reach from a
# namespaced unit to any outside address, the metadata addresses, the host's loopback, the
# resolver, an abstract socket or a path socket of the runner's; `find / -type s` in a unit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "D reach"
NET="/usr/bin/python3 $TOOLS/net.py"
svc_ino=$(bash "$SBX_DIR/make-netns.sh" inode sbx-svc)
ownip=$(hostname -I | awk '{print $1}')
listeners_start || fail D.0 "the runner's canary listeners did not start"

# The service: one process with two listeners in its own namespace, 8443 (the service's port)
# and 8444 (stands for the inspector). Started the way a helper's detached server is kept: the
# unit's type exec with the control group as its end.
UNIT_MAX=900 unit_svc sbx-d-svc --no-wait --type exec --exit-type cgroup -- /usr/bin/python3 "$TOOLS/echo.py" serve 8443 8444
ready=0
for _ in $(seq 1 20); do
  if sudo -n ip netns exec sbx-svc /usr/bin/python3 "$TOOLS/net.py" check tcp:127.0.0.1:8443 | grep -q ' reached '; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" -eq 1 ] && ok D.1 "the service answers inside its namespace (the trusted observer's view)" || fail D.1 "the service does not answer in its namespace"
sudo -n ip netns exec sbx-svc /usr/bin/python3 "$TOOLS/net.py" check tcp:127.0.0.1:8444 | grep -q ' reached ' \
  && ok D.2 "the second listener (8444) answers in the service's namespace" || fail D.2 "the second listener does not answer in the service's namespace"

# The proxy, form 1: one transient socket unit in the legs' namespace, its service in the
# service's namespace, both from `systemd-run`'s own properties.
start_proxy_1() {
  sudo -n systemd-run --unit=sbx-proxy --collect \
    --socket-property=ListenStream=127.0.0.1:8443 --socket-property=NetworkNamespacePath=/run/netns/sbx-legs \
    -p NetworkNamespacePath=/run/netns/sbx-svc -p DynamicUser=yes -p NoNewPrivileges=yes -p CapabilityBoundingSet= \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateDevices=yes -p PrivateTmp=yes -p ProtectProc=invisible \
    -p 'RestrictAddressFamilies=AF_INET AF_UNIX' -p SystemCallArchitectures=native -p IPAddressDeny=any -p 'IPAddressAllow=127.0.0.1/32' \
    -p StandardOutput=null -p RuntimeMaxSec=900 \
    "$GUARD" --netns-inode "$svc_ino" -- /usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:8443 2>&1
}
# Form 2: unit files in /run/systemd/system.
start_proxy_2() {
  sudo -n tee /run/systemd/system/sbx-proxy2.socket >/dev/null <<'UNIT'
[Socket]
ListenStream=127.0.0.1:8443
NetworkNamespacePath=/run/netns/sbx-legs
[Install]
WantedBy=sockets.target
UNIT
  sudo -n tee /run/systemd/system/sbx-proxy2.service >/dev/null <<UNIT
[Service]
ExecStart=/usr/local/lib/sandbox/guard.sh --netns-inode $svc_ino -- /usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:8443
NetworkNamespacePath=/run/netns/sbx-svc
DynamicUser=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_UNIX
SystemCallArchitectures=native
IPAddressDeny=any
IPAddressAllow=127.0.0.1/32
StandardOutput=null
UNIT
  sudo -n systemctl daemon-reload && sudo -n systemctl start sbx-proxy2.socket 2>&1
}
proxy_works() {
  UNIT_MAX=40 unit_legs "$1" -- /usr/bin/python3 "$TOOLS/echo.py" line 8443 NONCE-ONE
  has "$1" '^RESULT reply svc-8443 ENO-ECNON$'
}

form=none
msg=$(start_proxy_1)
printf '%s\n' "$msg" | sed -e 's/^/proxy-form-1 | /' | head -6
if proxy_works sbx-d-p1; then
  form=1
else
  fail D.3a "proxy form 1 (--socket-property with NetworkNamespacePath) did not carry a request: $(printf '%s' "$msg" | tr '\n' ' ' | cut -c1-200)"
  sudo -n systemctl stop sbx-proxy.socket sbx-proxy.service 2>/dev/null
  msg=$(start_proxy_2)
  printf '%s\n' "$msg" | sed -e 's/^/proxy-form-2 | /' | head -6
  if proxy_works sbx-d-p2; then form=2; else fail D.3b "proxy form 2 (unit files) did not carry a request: $(printf '%s' "$msg" | tr '\n' ' ' | cut -c1-200)"; fi
fi
if [ "$form" != none ]; then ok D.3 "a request and its reply crossed the proxy (form $form), nonce reversed by the service"; else fail D.3 "no proxy form works; one shared namespace is the fallback"; fi

if [ "$form" != none ]; then
  # The proxy's own namespaces, by the host's view.
  psvc=$(sudo -n systemctl show -p MainPID --value sbx-proxy.service sbx-proxy2.service 2>/dev/null | grep -v '^0$' | head -1)
  [ -n "$psvc" ] && printf '%s\n' "proxy service pid sits in namespace $(sudo -n stat -L -c %i "/proc/$psvc/ns/net" 2>/dev/null) (service's is $svc_ino)" | sed -e 's/^/info | /'
  unit_legs sbx-d-p3 -- /usr/bin/python3 "$TOOLS/echo.py" eof 8443 NONCE-EOF
  if has sbx-d-p3 '^RESULT reply svc-8443 eof NONCE-EOF bytes=' && has sbx-d-p3 '^RESULT end closed$'; then
    ok D.4 "half-close: the service saw the end of the request, answered, and the stream then ended"
  else
    fail D.4 "half-close: $(rawlog sbx-d-p3 | tr '\n' ';' | cut -c1-200)"
  fi
  # Idle: 60 seconds, then data.
  UNIT_MAX=150 unit_legs sbx-d-p4 -- /usr/bin/python3 "$TOOLS/echo.py" line 8443 NONCE-IDLE 60 &
  idle_pid=$!
fi

# The second listener (8444) must not be reachable from the legs' namespace; nor 8443 without the proxy.
UNIT_MAX=40 unit_legs sbx-d-l1 -- $NET check tcp:127.0.0.1:8444 tcp:127.0.0.1:8445 
if has sbx-d-l1 '^RESULT tcp:127.0.0.1:8444 blocked'; then ok D.5 "the service's second listener (8444) is out of the legs' reach"; else fail D.5 "the legs reached 8444"; fi

# No reach from a namespaced unit to anything outside, in both namespaces.
targets=(
  tcp:1.1.1.1:443 "tcp:[2606:4700:4700::1111]:443" tcp:169.254.169.254:80 tcp:168.63.129.16:80
  "tcp:$ownip:22" "tcp:$ownip:18445" udp:8.8.8.8:53 tcp:127.0.0.53:53 udp:127.0.0.53:53 tcp:127.0.0.54:53 udp:127.0.0.54:53
  tcp:127.0.0.1:18443 tcp:127.0.0.2:18444
  unix:@sbx-abstract unix:/run/sbx-canary.sock unix:/tmp/sbx-canary.sock unix:/var/sbx-canary.sock
  unix:/opt/sbx-canary.sock unix:/srv/sbx-canary.sock unix:/var/tmp/sbx-canary.sock
)
runner_view=$(/usr/bin/python3 "$TOOLS/net.py" check "${targets[@]}")
printf '%s\n' "$runner_view" | grep -q '^RESULT tcp:1.1.1.1:443 reached' && ok D.6 "control: the runner reaches 1.1.1.1:443" || fail D.6 "control: the runner does not reach 1.1.1.1:443"
printf '%s\n' "$runner_view" | sed -e 's/^RESULT /control | /' -e "s/$ownip/OWNIP/g"
for ns in legs svc; do
  if [ "$ns" = legs ]; then
    UNIT_MAX=120 unit_legs "sbx-d-x-$ns" -- $NET check "${targets[@]}"
  else
    UNIT_MAX=120 unit_svc "sbx-d-x-$ns" -- $NET check "${targets[@]}"
  fi
  reached=$(grep -c ' reached ' "$SBX_LOGS/sbx-d-x-$ns.log")
  total=$(grep -c '^RESULT ' "$SBX_LOGS/sbx-d-x-$ns.log")
  if [ "$reached" -eq 0 ] && [ "$total" -eq "${#targets[@]}" ]; then
    ok "D.7.$ns" "from the $ns namespace all ${#targets[@]} outside, host-loopback, resolver, abstract and path targets are blocked"
  else
    fail "D.7.$ns" "from the $ns namespace $reached of $total targets answered: $(grep ' reached ' "$SBX_LOGS/sbx-d-x-$ns.log" | sed -e "s/$ownip/OWNIP/g" | tr '\n' ';' | cut -c1-300)"
  fi
done
# The same list one more time with the time each answer took: every refusal is quick.
start=$(date +%s)
UNIT_MAX=120 unit_legs sbx-d-t1 -- $NET check "${targets[@]}"
took=$(( $(date +%s) - start ))
[ "$took" -le $(( ${#targets[@]} * 2 + 5 )) ] && ok D.8 "the whole list was refused in $took s (a refusal is not a wait for a time-out)" || fail D.8 "the list took $took s"

# Names: getent and a library lookup fail in the unit.
UNIT_MAX=40 unit_legs sbx-d-g1 -- /usr/bin/getent hosts github.com
rc=$?
[ "$rc" -ne 0 ] && ok D.9 "getent hosts github.com fails in the unit (exit $rc)" || fail D.9 "getent resolved a name in the unit"
UNIT_MAX=40 unit_legs sbx-d-g2 -- $NET dns github.com
has sbx-d-g2 '^RESULT dns:github.com blocked' && ok D.10 "a library lookup of github.com fails in the unit" || fail D.10 "a library lookup resolved github.com"

# Every socket the unit can see: none but its own.
UNIT_MAX=60 unit_legs sbx-d-s1 -- /usr/bin/find / -path /proc -prune -o -type s -print
others=$(grep -v -E '^(/home/kr-legs/|/tmp/|/dev/shm/)' "$SBX_LOGS/sbx-d-s1.log" | grep -c . || true)
[ "$others" -eq 0 ] && ok D.11 "find / -type s in a unit lists no socket outside the account's own folders" || fail D.11 "find / -type s lists $others sockets: $(grep -v -E '^(/home/kr-legs/|/tmp/|/dev/shm/)' "$SBX_LOGS/sbx-d-s1.log" | tr '\n' ' ' | cut -c1-300)"

if [ "$form" != none ]; then
  wait "$idle_pid"
  if has sbx-d-p4 '^RESULT reply svc-8443 ELDI-ECNON$'; then ok D.12 "a connection idle for 60 s then carried data through the proxy"; else fail D.12 "idle connection: $(rawlog sbx-d-p4 | tr '\n' ';' | cut -c1-200)"; fi
fi

# Teardown.
sudo -n systemctl stop sbx-proxy.socket sbx-proxy.service sbx-proxy2.socket sbx-proxy2.service 2>/dev/null
bash "$SBX_DIR/stop-unit.sh" --name sbx-d-svc --log-dir "$SBX_LOGS" >/dev/null || fail D.13 "the service unit did not end"
listeners_stop
echo "proxy form used: $form"
endgroup
finish D
