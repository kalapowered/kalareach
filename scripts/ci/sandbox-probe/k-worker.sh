#!/bin/bash
# Groups K.3 and K.4: a public Worker of the probe's own under Wrangler 4.131.2 on Node 22, and
# real clients through the byte proxy.
#   K.3  the Worker (a D1 database with one migration, a Durable Object, TLS with a certificate
#        that the probe makes, an inspector port of 0) is started the way a helper keeps a
#        server: a starter that leaves a detached server and exits, in the service's unit. It
#        serves https://127.0.0.1:8443 to the legs' namespace through the proxy; the inspector
#        and the Worker's other listeners are out of the legs' reach; Wrangler's own outbound
#        calls fail at once and it serves all the same.
#   K.4  a Rust client of the stack that core's legs use (HTTPS requests with a body, several
#        requests on one connection, HTTP/2 when offered, a WebSocket that upgrades, exchanges
#        frames and closes from each side), from a legs unit through the proxy and, as a control,
#        straight to the service from a unit in the service's namespace.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/k-lib.sh"

group "K.3 worker"
NODE=/home/kr-svc/node/bin/node
WRANGLER_JS=/home/kr-svc/web/node_modules/wrangler/bin/wrangler.js
WRANGLER_BIN=/home/kr-svc/web/node_modules/.bin/wrangler
WORKER_DIR=/home/kr-svc/web/probe-worker
CLIENT=/opt/kr-legs/target/debug/sandbox-probe-client
ORIGIN=https://127.0.0.1:8443
SVCENV=(--env "PATH=/home/kr-svc/node/bin:$BASE_PATH" --env CI=1 --env WRANGLER_SEND_METRICS=false --env CLOUDFLARE_INCLUDE_PROCESS_ENV=false)

# ---- the client program, built offline by the build account (the fetch unit ran before) ----
chan=$(toolchain) || { fail K.3.0 "no toolchain version from the fetch step"; endgroup; finish K.3; exit 1; }
mapfile -t BENV < <(build_env "$chan")
start=$(now)
UNIT_MAX=1500 unit_legs sbx-k-cb --workdir /home/kr-legs/core "${BENV[@]}" -- /opt/kr-legs/cargo/bin/cargo build --locked --offline \
  --manifest-path /home/kr-legs/core/scripts/ci/sandbox-probe/tools/client/Cargo.toml
rc=$?
echo "client build $(elapsed "$start" "$(now)") s; $(peak sbx-k-cb)"
[ "$rc" -eq 0 ] && ok K.3.0 "the probe's client program built offline in $(elapsed "$start" "$(now)") s" || fail K.3.0 "the client build exit $rc: $(grep -E '^error' "$SBX_LOGS/sbx-k-cb.log" | head -3 | tr '\n' ' ' | cut -c1-200)"

# ---- Node 22, Wrangler 4.131.2, the Worker's files and the certificate (the runner's trusted code) ----
node_src=$(ls -d /opt/hostedtoolcache/node/22.*/x64 2>/dev/null | sort -V | tail -1)
if [ -z "$node_src" ]; then
  echo "no Node 22 in the image's tool cache; taking the release from nodejs.org"
  dl="$RUNNER_TEMP/nodedl"
  mkdir -p "$dl"
  curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/SHASUMS256.txt" https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt
  tarball=$(awk '/linux-x64\.tar\.xz$/ {print $2}' "$dl/SHASUMS256.txt")
  curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/$tarball" "https://nodejs.org/dist/latest-v22.x/$tarball"
  (cd "$dl" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c --quiet -)
  tar -xJf "$dl/$tarball" -C "$dl"
  node_src="$dl/${tarball%.tar.xz}"
fi
echo "node: $("$node_src/bin/node" --version) from $(case $node_src in /opt/hostedtoolcache/*) echo the image tool cache ;; *) echo nodejs.org ;; esac)"
sudo -n install -d -o kr-svc -g kr-svc -m 0700 /home/kr-svc/web /home/kr-svc/state /home/kr-svc/certs
sudo -n install -d -o kr-svc -g kr-svc -m 0755 /home/kr-svc/node /home/kr-svc/node/bin
sudo -n install -o kr-svc -g kr-svc -m 0755 "$node_src/bin/node" /home/kr-svc/node/bin/node
start=$(now)
sudo -n -u kr-svc env HOME=/home/kr-svc PATH="$node_src/bin:/usr/bin:/bin" \
  npm install --prefix /home/kr-svc/web --no-audit --no-fund --loglevel=error wrangler@4.131.2 2>&1 | tail -5
echo "wrangler install $(elapsed "$start" "$(now)") s"
wv=$(sudo -n -u kr-svc env HOME=/home/kr-svc "$NODE" "$WRANGLER_JS" --version 2>/dev/null | tail -1)
[ "$wv" = 4.131.2 ] && ok K.3.1 "Wrangler $wv on Node $("$node_src/bin/node" --version)" || fail K.3.1 "Wrangler version is '$wv'"

sudo -n cp -R "$PROBE_ROOT/tools/worker" "$WORKER_DIR"
sudo -n chown -R kr-svc:kr-svc "$WORKER_DIR"
certs="$RUNNER_TEMP/certs"
bash "$PROBE_ROOT/tools/make-certs.sh" "$certs" >/dev/null 2>&1 || fail K.3.2 "make-certs failed"
sudo -n install -o kr-svc -g kr-svc -m 0600 "$certs/leaf.key" "$certs/leaf.pem" /home/kr-svc/certs/
sudo -n install -m 0644 -o root -g root "$certs/ca.pem" /usr/local/share/ca-certificates/sandbox-probe-ca.crt
sudo -n update-ca-certificates 2>&1 | sed -e 's/^/ca | /' | head -3
ok K.3.2 "a certificate authority and a leaf for https://127.0.0.1 were made by the probe; the authority is in the system store, the leaf key is the service account's alone"

# ---- the migration, then the service ----
svc_ino=$(bash "$SBX_DIR/make-netns.sh" inode sbx-svc)
start=$(now)
UNIT_MAX=300 unit_svc sbx-k-mig "${SVCENV[@]}" -- "$NODE" "$WRANGLER_JS" d1 migrations apply sandbox-probe-db --local \
  --persist-to /home/kr-svc/state --config "$WORKER_DIR/wrangler.toml"
rc=$?
if [ "$rc" -eq 0 ] && has sbx-k-mig '0001_probe_notes.sql'; then ok K.3.3 "the D1 migration applied in the service's unit in $(elapsed "$start" "$(now)") s"; else fail K.3.3 "the D1 migration: exit $rc; $(tail -3 "$SBX_LOGS/sbx-k-mig.log" | tr '\n' ';' | cut -c1-200)"; fi

t0=$(now)
watch_mem sbx-k-svc &
UNIT_MAX=1500 unit_svc sbx-k-svc --no-wait --type exec --exit-type cgroup "${SVCENV[@]}" -- \
  "$NODE" "$K_TOOLS/start-worker.mjs" "$WRANGLER_BIN" "$WORKER_DIR/wrangler.toml" 8443 /home/kr-svc/state /home/kr-svc/certs /home/kr-svc/worker.log
ready=0
for _ in $(seq 1 120); do
  if sudo -n ip netns exec sbx-svc curl -s -o /dev/null --max-time 2 --cacert "$certs/ca.pem" "$ORIGIN/health"; then ready=1; break; fi
  sleep 0.5
done
t1=$(now)
if [ "$ready" -eq 1 ]; then ok K.3.4 "the Worker answered https://127.0.0.1:8443 in the service's namespace $(elapsed "$t0" "$t1") s after its unit started (start time)"; else fail K.3.4 "the Worker did not answer within 60 s"; fi
active=$(sudo -n systemctl show -p ActiveState --value sbx-k-svc.service 2>/dev/null)
sub=$(sudo -n systemctl show -p SubState --value sbx-k-svc.service 2>/dev/null)
mainpid=$(sudo -n systemctl show -p MainPID --value sbx-k-svc.service 2>/dev/null)
echo "service unit after the starter exited: ActiveState=$active SubState=$sub MainPID=$mainpid"
if [ "$active" = active ] && [ "$mainpid" = 0 ]; then
  ok K.3.5 "the starter exited (MainPID 0) and left a detached server; the unit stayed active ($active/$sub): its exit is the control group's"
else
  fail K.3.5 "the unit is not active with the starter gone: $active/$sub MainPID=$mainpid"
fi

# ---- the proxy, and what the legs' namespace reaches ----
msg=$(start_proxy 8443 "$svc_ino")
printf '%s\n' "$msg" | sed -e 's/^/proxy | /' | head -4
t2=$(now)
UNIT_MAX=60 unit_legs sbx-k-p1 -- $NET check tcp:127.0.0.1:8443
has sbx-k-p1 '^RESULT tcp:127.0.0.1:8443 reached' && ok K.3.6 "the legs' namespace connects to 127.0.0.1:8443 through the byte proxy" || fail K.3.6 "no connection through the proxy"

ports=$(sudo -n ip netns exec sbx-svc ss -H -ltn | awk '{n = split($4, a, ":"); print a[n]}' | sort -un | tr '\n' ' ')
echo "listening ports in the service's namespace: $ports"
others=()
for p in $ports; do [ "$p" = 8443 ] || others+=("$p"); done
if [ "${#others[@]}" -ge 1 ]; then
  args=()
  for p in "${others[@]}"; do args+=("tcp:127.0.0.1:$p" "tcp:[::1]:$p"); done
  UNIT_MAX=120 unit_legs sbx-k-p2 -- $NET check "${args[@]}"
  if [ "$(grep -c ' reached ' "$SBX_LOGS/sbx-k-p2.log")" -eq 0 ] && [ "$(grep -c '^RESULT ' "$SBX_LOGS/sbx-k-p2.log")" -eq "${#args[@]}" ]; then
    ok K.3.7 "the Worker has ${#others[@]} listener(s) besides 8443 (the inspector among them); none is reachable from the legs' namespace"
  else
    fail K.3.7 "reached from the legs: $(grep ' reached ' "$SBX_LOGS/sbx-k-p2.log" | tr '\n' ';' | cut -c1-200)"
  fi
else
  fail K.3.7 "only 8443 listens in the service's namespace: the inspector's port was not seen"
fi

# Wrangler's own outbound calls: a lookup and a fetch from Node in the service's namespace fail at once.
UNIT_MAX=60 unit_svc sbx-k-o1 "${SVCENV[@]}" -- "$NODE" -e "
const t = Date.now();
require('dns').lookup('registry.npmjs.org', (e) => {
  console.log('RESULT dns', e ? e.code : 'resolved', Date.now() - t, 'ms');
  fetch('https://registry.npmjs.org/wrangler').then(
    () => console.log('RESULT fetch reached', Date.now() - t, 'ms'),
    (e) => console.log('RESULT fetch', (e.cause && e.cause.code) || e.name, Date.now() - t, 'ms'));
});"
dns_line=$(grep '^RESULT dns ' "$SBX_LOGS/sbx-k-o1.log")
fetch_line=$(grep '^RESULT fetch ' "$SBX_LOGS/sbx-k-o1.log")
ms_of() { printf '%s' "$1" | awk '{print $(NF-1)}'; }
if [ -n "$dns_line" ] && [ -n "$fetch_line" ] && ! printf '%s\n%s\n' "$dns_line" "$fetch_line" | grep -q -E 'resolved|reached' \
  && [ "$(ms_of "$fetch_line")" -le 5000 ]; then
  ok K.3.8 "outbound calls from Node in the service's namespace fail at once ($dns_line; $fetch_line)"
else
  fail K.3.8 "outbound: '$dns_line' '$fetch_line'"
fi

# ---- K.4: the real clients ----
run_client() {
  # run_client NAME NAMESPACE [ARGS...]: the build account in the namespace, the client program.
  local name=$1 ns=$2
  shift 2
  bash "$SBX_DIR/run-unit.sh" --name "$name" --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
    --log-dir "$SBX_LOGS" --guard "$GUARD" --netns "$ns" "${LEGS_BINDS[@]}" --runtime-max 300 -- "$CLIENT" "$ORIGIN" "$@"
}
run_client sbx-k-c1 sbx-legs      # through the proxy (a fresh Durable Object: this one goes first)
run_client sbx-k-c0 sbx-svc       # straight to the service, the control
cases=(https-post https-d1 https-sequence https-one-connection https-h2 ws-echo ws-client-close ws-server-close ws-log)
for c in "${cases[@]}"; do
  p=$(grep "^RESULT $c " "$SBX_LOGS/sbx-k-c1.log" | awk '{print $3}')
  d=$(grep "^RESULT $c " "$SBX_LOGS/sbx-k-c0.log" | awk '{print $3}')
  detail=$(grep "^RESULT $c " "$SBX_LOGS/sbx-k-c1.log" | cut -d' ' -f4- | cut -c1-160)
  if [ "$p" = ok ]; then
    ok "K.4.$c" "through the proxy: $detail (straight to the service: ${d:-no line})"
  elif [ "$d" = ok ]; then
    fail "K.4.$c" "works straight to the service and FAILS through the proxy: $detail"
  else
    fail "K.4.$c" "fails straight to the service too (${d:-no line}); through the proxy: ${p:-no line} $detail"
  fi
done

# The client that ends its half of the stream before it reads: the limit named in the reach group.
run_client sbx-k-h1 sbx-legs half-close
run_client sbx-k-h0 sbx-svc half-close
hp=$(grep '^RESULT https-half-close ' "$SBX_LOGS/sbx-k-h1.log" | awk '{print $3}')
hd=$(grep '^RESULT https-half-close ' "$SBX_LOGS/sbx-k-h0.log" | awk '{print $3}')
if [ "$hd" != ok ]; then
  fail K.4.half-close "the half-closing client fails straight to the service (${hd:-no line}): the control is broken"
elif [ "$hp" = ok ]; then
  ok K.4.half-close "a client that half-closes before it reads also works through the proxy (straight: ok)"
else
  ok K.4.half-close "named limit: a client that half-closes before it reads works straight to the service and loses the reply through the proxy (${hp:-no line}); no client of K.4 does this"
fi

# ---- teardown: the proxy, the service, and everything of the service account ----
sudo -n cat /home/kr-svc/worker.log 2>/dev/null | tail -n 40 >"$SBX_LOGS/sbx-k-worker.log"
echo "Worker log: $(wc -l <"$SBX_LOGS/sbx-k-worker.log") lines (warn level)"
# Wrangler's own outbound call (it asks Cloudflare for the Request.cf object) failed in the unit,
# and the Worker served the clients all the same.
if grep -q 'getaddrinfo EAI_AGAIN' "$SBX_LOGS/sbx-k-worker.log" && grep -q '^RESULT https-post ok' "$SBX_LOGS/sbx-k-c1.log"; then
  ok K.3.8b "Wrangler's own outbound call failed at once in the unit (its log: $(grep -m1 -o 'Unable to fetch the `Request.cf` object' "$SBX_LOGS/sbx-k-worker.log"), then getaddrinfo EAI_AGAIN) and it served the clients all the same"
else
  fail K.3.8b "no outbound failure in Wrangler's log, or the Worker did not serve: $(head -3 "$SBX_LOGS/sbx-k-worker.log" | tr '\n' ';' | cut -c1-200)"
fi
stop_proxy
bash "$SBX_DIR/stop-unit.sh" --name sbx-k-svc --log-dir "$SBX_LOGS" || fail K.3.9 "the service unit did not end"
stop_mem sbx-k-svc
echo "the service unit's peak memory (Wrangler, workerd and the starter): $(mem_peak sbx-k-svc)"
bash "$SBX_DIR/replay-log.sh" "$SBX_LOGS/sbx-k-worker.log" sbx-k-worker
unit_gone sbx-k-svc && ok K.3.9 "the service unit ended on stop with an empty control group" || fail K.3.9 "the service unit is still there"
if no_processes kr-svc; then ok K.3.10 "no process of the service account is left (workerd and Wrangler ended with the unit)"; else fail K.3.10 "the service account has processes: $(ps -u kr-svc -o pid=,comm= | tr '\n' ';' | cut -c1-200)"; fi
left=$(sudo -n ip netns exec sbx-svc ss -H -ltn | wc -l)
[ "$left" -eq 0 ] && ok K.3.11 "no listener is left in the service's namespace" || fail K.3.11 "$left listeners are left in the service's namespace"
endgroup
finish K.3-K.4
