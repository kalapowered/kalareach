#!/bin/bash
# Group K.1 (builds): core's four build commands, offline, each in a unit of its own in the
# legs' namespace (no route, so a fetch cannot happen even if a build tried), as the build
# account, after the fetch unit has ended. Each build's time and memory peak are printed from
# the manager's own end text.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/k-lib.sh"

group "K.1 builds"
chan=$(toolchain) || { fail K.1.b0 "no toolchain version from the fetch step"; endgroup; finish K.1b; exit 1; }
mapfile -t BENV < <(build_env "$chan")
echo "nproc $(nproc); $(free -g | awk '/^Mem:/ {print $2 " GB memory, " $7 " GB available"}'); disk $(df -h / | tail -1 | awk '{print $3 " used, " $4 " free"}')"

# The private repository's runner has 2 vCPU and 8 GB; this public one has 4 and 15. The builds run
# in a unit that is held to two CPUs and 7 GiB of memory (no swap), so that their time and peak
# are those of the smaller runner. Set EMULATE_PRIVATE_RUNNER=0 for the unconstrained figures.
EMULATE_PRIVATE_RUNNER=${EMULATE_PRIVATE_RUNNER:-1}
LIMITS=()
if [ "$EMULATE_PRIVATE_RUNNER" = 1 ]; then
  LIMITS=(--prop "AllowedCPUs=0-1" --prop "MemoryMax=7G" --prop "MemorySwapMax=0")
  UNIT_MAX=60 unit_legs sbx-k-np "${LIMITS[@]}" -- /bin/bash -c 'echo "cpus: $(nproc) allowed: $(grep Cpus_allowed_list /proc/self/status | cut -f2)"; echo "memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unreadable)"'
  grep -a -E '^cpus:|^memory.max' "$SBX_LOGS/sbx-k-np.log"
  [ "$(sed -n 's/^cpus: \([0-9]*\) .*/\1/p' "$SBX_LOGS/sbx-k-np.log")" = 2 ] && ok K.1.b0 "the build units are held to 2 CPUs (nproc 2), like the private runner" || fail K.1.b0 "the CPU limit did not take: $(grep -a '^cpus:' "$SBX_LOGS/sbx-k-np.log")"
fi

total_start=$(now)
i=0
run_build() {
  local what=$1
  shift
  i=$((i + 1))
  local name="sbx-k-b$i" start end rc
  start=$(now)
  watch_mem "$name" &
  UNIT_MAX=3000 unit_legs "$name" --workdir /home/kr-legs/core ${LIMITS[@]+"${LIMITS[@]}"} "${BENV[@]}" -- /opt/kr-legs/cargo/bin/cargo "$@"
  rc=$?
  end=$(now)
  stop_mem "$name"
  local took
  took=$(elapsed "$start" "$end")
  if [ "$rc" -eq 0 ]; then
    ok "K.1.b$i" "$what: exit 0 in $took s; peak memory $(mem_peak "$name"); manager text: $(peak "$name")"
  else
    fail "K.1.b$i" "$what: exit $rc after $took s; peak memory $(mem_peak "$name"); errors: $(grep -E '^error(\[|:)' "$SBX_LOGS/$name.log" | head -3 | tr '\n' ' ' | cut -c1-200)"
  fi
  df -h / | tail -1 | awk -v n="$i" '{print "after build " n ": " $3 " used, " $4 " free"}'
  return "$rc"
}

run_build "origin checker (kr-e2e-m1b bin, no default features)" build --locked --offline -p kr-e2e-m1b --no-default-features --bin kr-e2e-m1b-origin || true
run_build "kr-sync-integration tests built" test --locked --offline -p kr-sync-integration --no-run || true
run_build "kr-cli, kr-controller, kr-worker bins" build --locked --offline -p kr-cli -p kr-controller -p kr-worker --bins || true
run_build "kr-e2e-m1b tests built" test --locked --offline -p kr-e2e-m1b --no-run || true

total_end=$(now)
total=$(elapsed "$total_start" "$total_end")
echo "all four builds: $total s"
if awk -v t="$total" 'BEGIN { exit (t > 1500) ? 0 : 1 }'; then
  fail K.1.bt "the four builds took $total s, more than 25 minutes of a 30-minute job"
else
  ok K.1.bt "the four builds took $total s in total (25 minutes is the line for a 30-minute job)"
fi
for f in kr kr-controller kr-worker; do
  [ -x "/opt/kr-legs/target/debug/$f" ] 2>/dev/null || sudo -n test -x "/opt/kr-legs/target/debug/$f" || fail "K.1.bin" "no $f binary after the builds"
done
sudo -n du -sh /opt/kr-legs/target 2>/dev/null | awk '{print "target folder: " $1}'
no_processes kr-legs && ok K.1.b9 "no process of the build account is left after the builds" || fail K.1.b9 "the build account still has processes"
endgroup
finish K.1b
