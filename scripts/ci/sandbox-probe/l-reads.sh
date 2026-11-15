#!/bin/bash
# Group L: the launcher's reads. A command of a check can fail AFTER it printed an accepted answer;
# a check reads the command's status before it reads its output. Each case below makes one
# command of one of the five launcher files print its answer and then fail (a stand-in first on the
# PATH of the one command that the case runs, or, for a builtin, a function in a BASH_ENV file),
# and the script must refuse or end with a failure; a control with the real command (or with the
# stand-ins answering normally, where the real command would start a unit or make a namespace)
# must pass. Nothing is started, made or changed outside the case's own folder, except in the
# controls marked "real", which use the runner's own sudo, systemd and ip.
#
# Two files name a path that a case cannot make its own: the guard reads /proc/self/..., and the
# stop helper reads /sys/fs/cgroup/system.slice/NAME.service/cgroup.procs. The case runs a copy
# of each with that ONE path changed to a folder of its own and prints the change.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "L launcher reads"
STUB=$PROBE_ROOT/tools/l-stub.sh
LIE_PRINTF=$PROBE_ROOT/tools/l-lie-printf.env
PWD_FAILS=$PROBE_ROOT/tools/l-pwd-fails.env
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sbx-l.XXXXXX") || {
  fail L.0 "no folder of its own"
  endgroup
  finish L
  exit 1
}
bin=$work/bin
mkdir -p "$bin"
for t in sed wc id od awk cat stat sleep sudo ip systemctl; do
  ln -s "$STUB" "$bin/$t"
done

n=0
# trial CMD...: runs CMD with no input; T_RC and T_OUT hold its status and its output file.
trial() {
  n=$((n + 1))
  T_OUT=$work/out.$n
  "$@" >"$T_OUT" 2>&1 </dev/null
  T_RC=$?
}
shown() { tr '\n' ';' <"$1" | cut -c1-160; }
# pair ID WHAT WANT_RC PATTERN SENTINEL: runs P_FAIL (a command with a failing stand-in) and then
# P_CTL (the control). ok when P_FAIL ends with WANT_RC, prints PATTERN and not SENTINEL (the
# line that only a run that accepted the answer prints), and P_CTL ends with 0 and prints SENTINEL.
pair() {
  local id=$1 what=$2 want=$3 pat=$4 sent=$5 bad_rc bad_out
  trial "${P_FAIL[@]}"
  bad_rc=$T_RC
  bad_out=$T_OUT
  trial "${P_CTL[@]}"
  if [ "$bad_rc" -eq "$want" ] && grep -q -- "$pat" "$bad_out" && ! grep -q -- "$sent" "$bad_out" \
    && [ "$T_RC" -eq 0 ] && grep -q -- "$sent" "$T_OUT"; then
    ok "$id" "$what"
  else
    fail "$id" "$what: stand-in rc $bad_rc [$(shown "$bad_out")], control rc $T_RC [$(shown "$T_OUT")]"
  fi
}

# L.0: the shell that runs the five files (their first line is #!/bin/bash).
ok L.0.shell "the five files run under /bin/bash: $(/bin/bash --version | head -1)"

# ---- the guard, bound to a /proc/self lookalike -------------------------------------------------
# mkguard NAME NNP SECCOMP CAPEFF: the lookalike (loopback alone, both addresses, no route) with
# the given process status, and a copy of the guard with /proc/self replaced by it; sets GCMD.
mkguard() {
  local name=$1 dir=$work/fx-$1 inode
  mkdir -p "$dir/ns" "$dir/net"
  : >"$dir/ns/net"
  printf '%s\n' \
    'Inter-|   Receive                                                |  Transmit' \
    ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed' \
    '    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0' >"$dir/net/dev"
  printf '%s\n' '00000000000000000000000000000001 01 80 10 80       lo' >"$dir/net/if_inet6"
  printf '%s\n' 'Main:' '  +-- 127.0.0.0/8 2 0 2' '     +-- 127.0.0.0/31 1 0 0' '        |-- 127.0.0.0' \
    '           /32 link BROADCAST' '           /8 host LOCAL' '        |-- 127.0.0.1' '           /32 host LOCAL' \
    '     |-- 127.255.255.255' '        /32 link BROADCAST' >"$dir/net/fib_trie"
  printf '%s\n' 'Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT' >"$dir/net/route"
  printf '%s\n' '00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000003 00000000 80200001       lo' >"$dir/net/ipv6_route"
  printf 'Name:\tbash\nNoNewPrivs:\t%s\nSeccomp:\t%s\nCapEff:\t%s\n' "$2" "$3" "$4" >"$dir/status"
  sed -e "s#/proc/self#$dir#g" "$SBX_DIR/guard.sh" >"$work/guard-$name.sh"
  inode=$(stat -L -c %i "$dir/ns/net")
  GCMD=(bash "$work/guard-$name.sh" --netns-inode "$inode" -- /usr/bin/echo l-guard-passed)
}
mkguard ok 1 2 0000000000000000
G_OK=("${GCMD[@]}")
mkguard nnp 0 2 0000000000000000
G_NNP=("${GCMD[@]}")
mkguard seccomp 1 0 0000000000000000
G_SECCOMP=("${GCMD[@]}")
mkguard cap 1 2 000001ffffffffff
G_CAP=("${GCMD[@]}")
echo "guard copy: /proc/self replaced by $work/fx-NAME (fx-ok, fx-nnp, fx-seccomp, fx-cap); changed lines of the first copy:"
diff "$SBX_DIR/guard.sh" "$work/guard-ok.sh" | grep -c '^<'
if sed -e "s#$work/fx-ok#/proc/self#g" "$work/guard-ok.sh" | cmp -s - "$SBX_DIR/guard.sh"; then
  ok L.0.guard "the guard copy differs from the file only in the one path /proc/self"
else
  fail L.0.guard "the guard copy differs from the file in more than /proc/self"
fi
trial "${G_OK[@]}"
if [ "$T_RC" -eq 0 ] && grep -q '^l-guard-passed$' "$T_OUT"; then
  ok L.0.fixture "the guard passes the lookalike with the real tools (control of L.1 to L.5)"
else
  fail L.0.fixture "the lookalike is refused: rc $T_RC [$(shown "$T_OUT")]"
fi

S="PATH=$bin:$PATH"
P_CTL=("${G_OK[@]}")

P_FAIL=(env "$S" L_AFTER=awk "${G_OK[@]}")
pair L.1 "guard: awk on the IPv6 route file ends 2 with no answer: refused (97); the real awk passes" 97 'cannot read .*net/ipv6_route' l-guard-passed

P_FAIL=(env "$S" L_AFTER=id "${G_OK[@]}")
pair L.2 "guard: id prints the account's id and fails: refused (97); the real id passes" 97 'cannot read the account' l-guard-passed

P_FAIL=(env "$S" L_AFTER=sed "${G_OK[@]}")
pair L.3 "guard: the interface read prints lo and fails: refused (97); the real tools pass" 97 'cannot read .*net/dev' l-guard-passed

P_FAIL=(env "$S" L_AFTER=wc "${G_OK[@]}")
pair L.4 "guard: wc prints the route count and fails: refused (97); the real wc passes" 97 'cannot read .*net/route' l-guard-passed

# L.5: the status text comes through a producer that prints a healthy status and then fails,
# while the process's own status is not healthy: the guard must go by its own read.
P_FAIL=(env "BASH_ENV=$LIE_PRINTF" "${G_NNP[@]}")
pair L.5.nnp "guard: a producer prints NoNewPrivs 1 and fails, the status says 0: refused (97)" 97 'NoNewPrivs is not 1' l-guard-passed
P_FAIL=(env "BASH_ENV=$LIE_PRINTF" "${G_SECCOMP[@]}")
pair L.5.seccomp "guard: a producer prints Seccomp 2 and fails, the status says 0: refused (97)" 97 'no seccomp filter' l-guard-passed
P_FAIL=(env "BASH_ENV=$LIE_PRINTF" "${G_CAP[@]}")
pair L.5.cap "guard: a producer prints CapEff 0 and fails, the status says a capability: refused (97)" 97 'a capability is effective' l-guard-passed

# ---- make-netns.sh, answered by a canned ip (sudo -n ip ...) ------------------------------------
M=(bash "$SBX_DIR/make-netns.sh" add sbx-l-n1)
P_CTL=(env "$S" "${M[@]}")
P_FAIL=(env "$S" L_AFTER=ip-link "${M[@]}")
pair L.6.link "make-netns: the interface listing prints one line and fails: refused (1); the answering stand-in passes" 1 'cannot list the interfaces' 'make-netns: sbx-l-n1 inode='
P_FAIL=(env "$S" L_AFTER=ip-addr4 "${M[@]}")
pair L.6.addr4 "make-netns: the IPv4 address listing prints 127.0.0.1 and fails: refused (1)" 1 'cannot list the addresses' 'make-netns: sbx-l-n1 inode='
P_FAIL=(env "$S" L_AFTER=ip-addr6 "${M[@]}")
pair L.6.addr6 "make-netns: the IPv6 address listing prints ::1 and fails: refused (1)" 1 'cannot list the addresses' 'make-netns: sbx-l-n1 inode='

# ---- replay-log.sh ------------------------------------------------------------------------------
printf '%s\n' 'one line of a unit output' >"$work/replay.log"
R=(bash "$SBX_DIR/replay-log.sh" "$work/replay.log" l)
P_CTL=("${R[@]}")
P_FAIL=(env "$S" L_AFTER=od "${R[@]}")
pair L.7 "replay-log: the token's od prints 48 hexadecimal digits and fails: no token (1); the real od passes" 1 'replay-log: no token' '^::stop-commands::'

# ---- stop-unit.sh, answered by a canned systemctl, bound to a cgroup folder of the case ----------
mkdir -p "$work/su" "$work/cg/sbx-l-s1.service" "$work/cg/sbx-l-s4.service"
: >"$work/cg/sbx-l-s1.service/cgroup.procs"
printf '%s\n' 1234 >"$work/cg/sbx-l-s4.service/cgroup.procs"
cp "$SBX_DIR/replay-log.sh" "$work/su/replay-log.sh"
sed -e "s#^cg=\"/sys/fs/cgroup/system.slice/#cg=\"$work/cg/#" "$SBX_DIR/stop-unit.sh" >"$work/su/stop-unit.sh"
echo "stop-unit copy: the cgroup folder /sys/fs/cgroup/system.slice/ replaced by $work/cg/; changed lines:"
diff "$SBX_DIR/stop-unit.sh" "$work/su/stop-unit.sh" | grep '^[<>]'
if [ "$(diff "$SBX_DIR/stop-unit.sh" "$work/su/stop-unit.sh" | grep -c '^<')" -eq 1 ]; then
  ok L.0.stop "the stop helper copy differs from the file in one line, the cgroup folder's path"
else
  fail L.0.stop "the stop helper copy differs from the file in other than one line"
fi
mkdir -p "$work/logs-su"
P_CTL=(env "$S" L_UNIT=gone bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
P_FAIL=(env "$S" L_UNIT=gone L_AFTER=sudo bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
pair L.8.manager "stop-unit: every call to the manager fails (it cannot be asked): not 'ended', 1; the answering stand-in says ended" 1 'cannot ask about sbx-l-s1' 'stop-unit: sbx-l-s1 ended'
P_FAIL=(env "$S" L_UNIT=gone L_AFTER=systemctl bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
pair L.8.show "stop-unit: the property read prints that the unit is not found and fails: not 'ended', 1" 1 'cannot ask about sbx-l-s1' 'stop-unit: sbx-l-s1 ended'
P_FAIL=(env "$S" L_UNIT=gone L_AFTER=cat bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
pair L.8.procs "stop-unit: the read of the group's process file prints nothing and fails: not 'ended', 1" 1 'cannot ask about sbx-l-s1' 'stop-unit: sbx-l-s1 ended'

# Controls that the cures keep: a group with a process, and a unit that stays active, are still there.
trial env "$S" L_UNIT=gone bash "$work/su/stop-unit.sh" --name sbx-l-s4 --log-dir "$work/logs-su"
if [ "$T_RC" -eq 1 ] && grep -q 'sbx-l-s4 is still there after 30 seconds' "$T_OUT"; then
  ok L.8.remaining "stop-unit: a unit that is gone but whose group still holds a process is still there (1)"
else
  fail L.8.remaining "rc $T_RC [$(shown "$T_OUT")]"
fi
trial env "$S" L_UNIT=active bash "$work/su/stop-unit.sh" --name sbx-l-s5 --log-dir "$work/logs-su"
if [ "$T_RC" -eq 1 ] && grep -q 'sbx-l-s5 is still there after 30 seconds' "$T_OUT"; then
  ok L.8.active "stop-unit: a unit that stays active is still there after the 30 tries (1)"
else
  fail L.8.active "rc $T_RC [$(shown "$T_OUT")]"
fi

# ---- the launcher's and the helper's own folder (pwd prints the folder and fails) ----------------
P_FAIL=(env "BASH_ENV=$PWD_FAILS" bash "$SBX_DIR/run-unit.sh" --dry-run --name sbx-l-h --user kr-legs --group kr-legs
  --workdir /home/kr-legs/work --log-dir "$work" --host-network --runtime-max 5 -- /usr/bin/true)
P_CTL=(bash "$SBX_DIR/run-unit.sh" --dry-run --name sbx-l-h --user kr-legs --group kr-legs
  --workdir /home/kr-legs/work --log-dir "$work" --host-network --runtime-max 5 -- /usr/bin/true)
pair L.9.run "run-unit: pwd prints the folder and fails: refused (2); the real pwd lists the properties" 2 'run-unit: cannot find its own folder' '^PROPERTY '
P_FAIL=(env "$S" L_UNIT=gone "BASH_ENV=$PWD_FAILS" bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
P_CTL=(env "$S" L_UNIT=gone bash "$work/su/stop-unit.sh" --name sbx-l-s1 --log-dir "$work/logs-su")
pair L.9.stop "stop-unit: pwd prints the folder and fails: refused (2); the real pwd goes on" 2 'stop-unit: cannot find its own folder' 'stop-unit: sbx-l-s1 ended'

# ---- controls with the real commands of the runner (sudo, systemd, ip) -------------------------------
if sudo -n true >/dev/null 2>&1 && id kr-legs >/dev/null 2>&1; then
  show=$(sudo -n systemctl show -p LoadState -p ActiveState sbx-l-missing.service 2>&1)
  show_rc=$?
  unit_legs sbx-l-s2 -- /usr/bin/true >/dev/null 2>&1
  trial bash "$SBX_DIR/stop-unit.sh" --name sbx-l-s2 --log-dir "$SBX_LOGS"
  ended_rc=$T_RC
  ended_out=$T_OUT
  unit_legs sbx-l-s3 --no-wait -- /usr/bin/sleep 60 >/dev/null 2>&1
  sleep 1
  trial bash "$SBX_DIR/stop-unit.sh" --name sbx-l-s3 --log-dir "$SBX_LOGS"
  if [ "$show_rc" -eq 0 ] && printf '%s\n' "$show" | grep -q '^LoadState=not-found$' \
    && [ "$ended_rc" -eq 0 ] && grep -q 'stop-unit: sbx-l-s2 ended' "$ended_out" \
    && [ "$T_RC" -eq 0 ] && grep -q 'stop-unit: sbx-l-s3 ended' "$T_OUT"; then
    ok L.8.real "real systemd: a missing unit answers LoadState=not-found with status 0; stop-unit ends a finished unit and a running one (0)"
  else
    fail L.8.real "show rc $show_rc [$(printf '%s' "$show" | tr '\n' ';' | cut -c1-120)]; finished unit rc $ended_rc [$(shown "$ended_out")]; running unit rc $T_RC [$(shown "$T_OUT")]"
  fi
  trial bash "$SBX_DIR/make-netns.sh" add sbx-l-n9
  add_rc=$T_RC
  add_out=$T_OUT
  trial bash "$SBX_DIR/make-netns.sh" delete sbx-l-n9
  if [ "$add_rc" -eq 0 ] && grep -q 'make-netns: sbx-l-n9 inode=[0-9][0-9]*$' "$add_out" && [ "$T_RC" -eq 0 ]; then
    ok L.6.real "real ip: a namespace is made with the loopback alone and removed (0)"
  else
    fail L.6.real "add rc $add_rc [$(shown "$add_out")], delete rc $T_RC [$(shown "$T_OUT")]"
  fi
else
  emit L.8.real skip "no passwordless sudo or no probe accounts on this machine"
  emit L.6.real skip "no passwordless sudo or no probe accounts on this machine"
fi

endgroup
finish L
