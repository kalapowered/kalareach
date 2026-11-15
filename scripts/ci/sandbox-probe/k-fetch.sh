#!/bin/bash
# Group K.1 (fetch): the fetch unit with the network and its own rules. usage: k-fetch.sh core|client
#   - the address refusals: the metadata addresses, private ranges and the loopback but the
#     resolver's stub are refused; the stub answers
#   - the resolver's folder is read-only, and the resolver's file is the stub's
#   - the repository's own settings are not read by the fetch step's form
#   - Git, Rustup and Cargo are the account's trusted entry points, by absolute path
#   - the unit has ended and its control group is empty before anything else starts
mode=${1:?usage: k-fetch.sh core|client}
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/k-lib.sh"

group "K.1 fetch ($mode)"
sha=${GITHUB_SHA:?}
ownip=$(hostname -I | awk '{print $1}')
echo "resolver file of the runner: $(readlink /etc/resolv.conf || echo 'a regular file'); stub folder: $([ -d /run/systemd/resolve ] && echo present || echo absent)"
listeners_start || fail K.1.0 "the runner's canary listeners did not start"
[ -d /run/systemd/resolve ] || fail K.1.0r "the runner has no /run/systemd/resolve to bind"

# The refusals, from a unit with the fetch unit's properties.
targets=(
  tcp:1.1.1.1:443 tcp:169.254.169.254:80 tcp:168.63.129.16:80 tcp:10.0.0.1:80 tcp:172.16.0.1:80 tcp:192.168.0.1:80
  "tcp:$ownip:22" "tcp:$ownip:18445" tcp:127.0.0.1:18443 tcp:127.0.0.2:18444 unix:@sbx-abstract
  udp:127.0.0.53:53
)
UNIT_MAX=120 unit_fetch sbx-k-fr -- $NET check "${targets[@]}"
fr="$SBX_LOGS/sbx-k-fr.log"
has_line() { grep -q -- "$1" "$fr"; }
has_line '^RESULT tcp:1.1.1.1:443 reached' && ok K.1.1 "the fetch unit reaches a public address (1.1.1.1:443)" || fail K.1.1 "the fetch unit does not reach 1.1.1.1:443"
bad=0
for t in tcp:169.254.169.254:80 tcp:168.63.129.16:80 tcp:10.0.0.1:80 tcp:172.16.0.1:80 tcp:192.168.0.1:80 "tcp:$ownip:22" "tcp:$ownip:18445" tcp:127.0.0.1:18443 tcp:127.0.0.2:18444; do
  grep -q -- "^RESULT $t blocked" "$fr" || { bad=$((bad + 1)); echo "not blocked: ${t//$ownip/OWNIP}"; }
done
[ "$bad" -eq 0 ] && ok K.1.2 "the metadata addresses, private ranges, the runner's own address and the host loopback are refused in the fetch unit" || fail K.1.2 "$bad refusals did not hold"
# An abstract socket belongs to the network namespace, and the fetch unit stands in the host's: the
# address filter does not cover it. The line records which way it went; it is a named residual.
if has_line '^RESULT unix:@sbx-abstract reached'; then
  ok K.1.2b "residual: an abstract socket of the runner's (host namespace) is reachable from the fetch unit; no address filter covers it"
else
  ok K.1.2b "an abstract socket of the runner's (host namespace) is not reachable from the fetch unit"
fi
has_line '^RESULT udp:127.0.0.53:53 reached' && ok K.1.3 "the resolver's stub (127.0.0.53:53) answers in the fetch unit" || fail K.1.3 "the stub did not answer"

UNIT_MAX=60 unit_fetch sbx-k-fg -- /usr/bin/getent hosts github.com
[ $? -eq 0 ] && ok K.1.4 "a name resolves in the fetch unit (getent hosts github.com)" || fail K.1.4 "a name does not resolve in the fetch unit"

UNIT_MAX=60 unit_fetch sbx-k-fw -- /bin/bash -c 'grep -c "^nameserver 127.0.0.53" /etc/resolv.conf; (: >/run/systemd/resolve/stub-resolv.conf) 2>&1 | head -1; touch /run/systemd/resolve/probe 2>&1 | head -1'
if has sbx-k-fw '^1$' && [ "$(grep -c -E 'Read-only file system|Permission denied' "$SBX_LOGS/sbx-k-fw.log")" -ge 2 ]; then
  ok K.1.5 "the resolver's file names only the stub, and its folder refuses a write"
else
  fail K.1.5 "resolver file or its read-only bind: $(tr '\n' ';' <"$SBX_LOGS/sbx-k-fw.log" | cut -c1-200)"
fi

# The fetch itself.
start=$(now)
UNIT_MAX=1500 unit_fetch sbx-k-fetch -- /bin/bash "$K_TOOLS/fetch-core.sh" "$CORE_URL" "$sha" "$mode"
rc=$?
end=$(now)
echo "fetch took $(elapsed "$start" "$end") s; $(peak sbx-k-fetch)"
[ "$rc" -eq 0 ] && ok K.1.6 "the fetch unit ended with exit 0 (checkout, rustup-init with its hash checked, toolchain, crates for $mode) in $(elapsed "$start" "$end") s" || fail K.1.6 "the fetch unit exit $rc"
has sbx-k-fetch '^FETCH crates fetched' && ok K.1.7 "the crates of the lock file were fetched with --locked and no repository setting" || fail K.1.7 "the crates were not fetched"
grep '^FETCH ' "$SBX_LOGS/sbx-k-fetch.log" | sed -e 's/^/fetch | /'

# The repository's own setting is live inside its folder and not read by the fetch step's form.
UNIT_MAX=120 unit_fetch sbx-k-trap -- /bin/bash "$K_TOOLS/fetch-trap.sh"
inside=$(sed -n 's/^TRAP inside=//p' "$SBX_LOGS/sbx-k-trap.log")
outside=$(sed -n 's/^TRAP fetch-form=//p' "$SBX_LOGS/sbx-k-trap.log")
if [ "$inside" = /home/kr-legs/work/trap-target ] && [ -n "$outside" ] && [ "$outside" != /home/kr-legs/work/trap-target ]; then
  ok K.1.8 "a repository setting is live inside the checkout and not read by the fetch step's form (outside: $outside)"
else
  fail K.1.8 "inside='$inside' fetch-form='$outside'"
fi

# Ended, and nothing left of it.
for u in sbx-k-fr sbx-k-fg sbx-k-fw sbx-k-fetch sbx-k-trap; do
  unit_gone "$u" || fail K.1.9 "$u is still there"
done
if no_processes kr-legs; then ok K.1.9 "the fetch units have ended and the account has no process, so the control group is empty before the next step"; else fail K.1.9 "the account still has processes"; fi

listeners_stop
echo "k-fetch: disk $(df -h / | tail -1 | awk '{print $3 " used, " $4 " free"}')"
endgroup
finish "K.1-$mode"
