#!/bin/bash
# Group K.2: core's control daemon in a legs unit (after the builds). The unit starts the daemon
# with the file secret store as a process of its own session, asks it `kr list --json` and
# `kr doctor`, lists the account's processes and exits while the daemon still runs. The runner
# then checks that the unit's end took every process with it.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/k-lib.sh"

group "K.2 daemon"
chan=$(toolchain) || { fail K.2.0 "no toolchain version"; endgroup; finish K.2; exit 1; }
mapfile -t BENV < <(build_env "$chan")
log="$SBX_LOGS/sbx-k-daemon.log"

start=$(now)
UNIT_MAX=300 unit_legs sbx-k-daemon --workdir /home/kr-legs/core "${BENV[@]}" -- /bin/bash "$K_TOOLS/daemon-leg.sh"
rc=$?
end=$(now)
echo "daemon unit ran $(elapsed "$start" "$end") s, exit $rc; $(peak sbx-k-daemon)"

grep -q '^DAEMON list answered=1' "$log" && ok K.2.1 "the daemon started with the file secret store and kr list --json answered ($(sed -n 's/^DAEMON list answered=1 //p' "$log"))" || fail K.2.1 "kr list --json did not answer: $(grep '^DAEMON' "$log" | head -3 | tr '\n' ';' | cut -c1-200)"
grep -q '^DAEMON list json=yes' "$log" && ok K.2.2 "the answer of kr list --json is valid JSON" || fail K.2.2 "the answer is not JSON"
n=$(sed -n 's/^DAEMON doctor detached-lines=//p' "$log")
[ "${n:-0}" -ge 1 ] && ok K.2.3 "kr doctor names the detached supervisor ($n lines)" || fail K.2.3 "kr doctor does not name the detached supervisor ($(grep '^DAEMON doctor' "$log" | tr '\n' ';' | cut -c1-160))"
grep -q '^DAEMON resolv-conf-target .* exists=no' "$log" && ok K.2.4 "the resolver's configuration is a dangling link in the unit (as it is for every unit with a private /run)" || fail K.2.4 "the resolver's configuration is not dangling: $(grep '^DAEMON resolv-conf' "$log" | cut -c1-160)"
p=$(sed -n 's/^DAEMON log panics=//p' "$log")
w=$(sed -n 's/^DAEMON log warn-lines=//p' "$log")
[ "${p:-1}" -eq 0 ] && [ "$(sed -n 's/^DAEMON list answered=//p' "$log" | cut -c1)" = 1 ] && ok K.2.5 "with that configuration the daemon logged no failure and kept answering; $w log lines mention the resolver or DNS (0 means the daemon builds no resolver until it opens an endpoint: K.2.9 does that)" || fail K.2.5 "the daemon failed with the dangling resolver: panics=${p:-?}"
grep -q '^DAEMON controller-running=1' "$log" && ok K.2.6 "the daemon was still running when the unit's own command exited" || fail K.2.6 "the daemon was not running at the end of the command"
grep '^DAEMON-PS ' "$log" | sed -e 's/^DAEMON-PS /processes before the unit end | /'
grep '^DAEMON-DOCTOR \|^DAEMON-LOG ' "$log" | head -8

unit_gone sbx-k-daemon && ok K.2.7 "the unit is gone after its command exited" || fail K.2.7 "the unit is still there"
if no_processes kr-legs; then
  ok K.2.8 "nothing of the account is left when the unit ends: the manager ended the daemon, its supervisor and their workers"
else
  fail K.2.8 "the account has processes after the unit's end: $(ps -u kr-legs -o pid=,comm= | tr '\n' ';' | cut -c1-200)"
fi
# The transport endpoint builds the DNS resolver from the system's configuration, which is the
# dangling link here. Core's own test that binds an endpoint with no resolver of its own runs in
# the same kind of unit, offline: the bind must succeed, and what the test says about the resolver
# is printed.
start=$(now)
UNIT_MAX=1500 unit_legs sbx-k-tr --workdir /home/kr-legs/core "${BENV[@]}" --env RUST_LOG=warn -- /opt/kr-legs/cargo/bin/cargo test --locked --offline \
  -p kr-transport --lib -- an_endpoint_looks_names_up_with_no_http_client --nocapture
rc=$?
echo "transport test unit $(elapsed "$start" "$(now)") s, exit $rc"
if [ "$rc" -eq 0 ] && grep -a -q 'test result: ok. 1 passed' "$SBX_LOGS/sbx-k-tr.log"; then
  ok K.2.9 "an endpoint bound with the system resolver configuration (a dangling link in this unit) succeeded: core's own test passed"
else
  fail K.2.9 "the endpoint test: exit $rc; $(grep -a -E '^error|test result|panicked' "$SBX_LOGS/sbx-k-tr.log" | head -3 | tr '\n' ';' | cut -c1-240)"
fi
echo "resolver-related lines in that test's output: $(grep -a -c -i -E 'resolv|nameserver|dns' "$SBX_LOGS/sbx-k-tr.log")"
grep -a -i -E 'resolv|nameserver' "$SBX_LOGS/sbx-k-tr.log" | head -3 | cut -c1-200 | sed -e 's/^/transport-test | /'
no_processes kr-legs && ok K.2.10 "no process of the account is left after the transport test" || fail K.2.10 "the account still has processes"
endgroup
finish K.2
