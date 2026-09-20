#!/usr/bin/env bash
# KR-ACC-011: WSL2 acceptance. Several distributions, independent operation, NAT and mirrored
# networking, and environment-specific paths.
#
# This runs on a Windows host with WSL2, in Git Bash or MSYS2. It is an acceptance run, so a
# prerequisite it cannot meet is a failure rather than a skip: a run that cannot establish these
# results has not established them.
#
# What it establishes, in order:
#
#   1. WSL 2 is installed, the default version is 2, and two distributions are registered. A second
#      one is made by exporting and importing the first when only one is there, and is removed
#      again at the end.
#   2. Each distribution runs KalaReach on its own: its own control daemon, its own worker, its own
#      Linux paths and process identifiers, with the native Windows installation taking no part.
#   3. Argument vectors cross `wsl.exe --exec` unchanged, including values a shell would rewrite.
#   4. Windows reaches each distribution through the process bridge alone, learns that
#      distribution's own environment identity, and gets an answer to a real read across it.
#   5. A listing of stopped distributions comes from the cache and starts nothing. A refresh that
#      was told to start one does.
#   6. The bridge behaves the same in NAT and in mirrored networking mode, which is what decides
#      whether any automatic behaviour is needed.
#
# Every artefact is written under ${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}. The Windows
# daemon this starts keeps its keys in its own run directory (never the Credential Manager).
#
# Knobs, all optional:
#   KR_WSL_HELPER     absolute path of the helper inside a distribution (default /usr/local/bin/kr)
#   KR_WSL_USER       the Linux user the helper runs as (default root)
#   KR_WSL_SECOND     the name of the second distribution this script makes (default kr-acc-011)
#   KR_WSL_KEEP       1 to keep the second distribution and the daemons for inspection
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts"
run_dir="$artifacts/wsl-$(date -u '+%Y%m%dT%H%M%SZ')"
mkdir -p "$run_dir"
helper_path="${KR_WSL_HELPER:-/usr/local/bin/kr}"
linux_user="${KR_WSL_USER:-root}"
second_name="${KR_WSL_SECOND:-kr-acc-011}"
keep="${KR_WSL_KEEP:-0}"

passed=0
fail() {
  # Standard error, so that a check inside a command substitution still says what went wrong
  # rather than handing its message to the variable being assigned.
  echo "FAIL: $*" >&2
  exit 1
}
pass() {
  passed=$((passed + 1))
  echo "PASS: $*"
}
step() { echo; echo "==> $*"; }

echo "kalareach wsl2 acceptance (KR-ACC-011)"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  artefacts: $artifacts"

# What this run made, and therefore what it may remove or end. Nothing else is touched: every
# process ended below is one this script started and recorded.
made_distribution=""
wslconfig_path=""
wslconfig_saved=""
wslconfig_existed=0
daemons=""
windows_daemon=""

cleanup() {
  local status=$?
  if [ -n "$windows_daemon" ]; then
    kill "$windows_daemon" 2>/dev/null || true
  fi
  if [ "$keep" != "1" ]; then
    for distribution in $daemons; do
      # The identifier this script recorded when it started that daemon, and no pattern. The
      # substitution below runs inside the distribution, which is why it stays unexpanded here.
      # shellcheck disable=SC2016
      wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
        'test -f /tmp/kr-acc-controller.pid && kill $(cat /tmp/kr-acc-controller.pid)' \
        >/dev/null 2>&1 || true
    done
    if [ -n "$made_distribution" ]; then
      echo "removing the distribution this run made: $made_distribution"
      wsl.exe --unregister "$made_distribution" >/dev/null 2>&1 || true
    fi
  fi
  # The networking mode is the operator's setting. It goes back exactly as it was.
  if [ -n "$wslconfig_saved" ] && [ -n "$wslconfig_path" ]; then
    if [ "$wslconfig_existed" = "1" ]; then
      cp "$wslconfig_saved" "$wslconfig_path"
    else
      rm -f "${wslconfig_path:?}"
    fi
    wsl.exe --shutdown >/dev/null 2>&1 || true
  fi
  echo "evidence kept under $run_dir"
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------
step "1. WSL 2, and the distributions this acceptance needs"

command -v wsl.exe >/dev/null 2>&1 ||
  fail "this acceptance runs on a Windows host with WSL2; wsl.exe is not on this machine"

# wsl.exe writes UTF-16LE. Dropping the null bytes is enough to read it as text here.
wsl_text() { wsl.exe "$@" 2>&1 | tr -d '\000\r'; }

version_text="$(wsl_text --version)"
echo "$version_text"
echo "$version_text" | grep -qi "WSL version" ||
  fail "wsl.exe --version did not report a WSL version; this needs WSL 2 from the Microsoft installer"

wsl_text --set-default-version 2 >/dev/null ||
  fail "the default WSL version could not be set to 2"

registered() { wsl_text -l -q | sed 's/[[:space:]]*$//' | grep -v '^$'; }
state_of() {
  # The state column of `wsl -l -v` for one distribution, matched on the whole name.
  wsl_text -l -v | sed 's/^[* ]*//' |
    awk -v want="$1" '{
      name = $0
      sub(/[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/, "", name)
      if (name == want) { print $(NF - 1) }
    }'
}

mapfile -t distributions < <(registered)
[ "${#distributions[@]}" -gt 0 ] ||
  fail "no WSL distribution is registered; install one before running this acceptance"
first="${distributions[0]}"
echo "registered: ${distributions[*]}"

if [ "${#distributions[@]}" -lt 2 ]; then
  echo "only one distribution is registered; making a second from it"
  tarball="$run_dir/$first.tar"
  wsl.exe --export "$first" "$(cygpath -w "$tarball" 2>/dev/null || echo "$tarball")" >/dev/null 2>&1 ||
    fail "the distribution could not be exported to make a second one"
  target_dir="C:\\kala\\wsl\\$second_name"
  wsl.exe --import "$second_name" "$target_dir" \
    "$(cygpath -w "$tarball" 2>/dev/null || echo "$tarball")" --version 2 >/dev/null 2>&1 ||
    fail "the second distribution could not be imported"
  made_distribution="$second_name"
  # The one this run made, by the name it gave it. Reading a position out of the listing again
  # would take whichever name the registry happens to put second.
  second="$second_name"
  mapfile -t distributions < <(registered)
else
  second="${distributions[1]}"
fi
[ "${#distributions[@]}" -ge 2 ] || fail "this acceptance needs two distributions"
[ "$first" != "$second" ] || fail "the two distributions this acceptance needs are the same one"
pass "two distributions are registered: $first and $second"

# ---------------------------------------------------------------------------------------------
step "2. Argument vectors cross --exec unchanged"

# Every one of these would be rewritten by a shell. `--exec` hands the vector to the program named
# next, so each arrives as one element.
# The values below are meant to stay literal: the point is that nothing expands them.
# shellcheck disable=SC2016
awkward_out="$(wsl.exe -d "$first" -u "$linux_user" --exec /bin/sh -c 'printf "%s\n" "$@"' -- \
  "arg 1" "arg'2" 'arg"3' 'space and $HOME and `backtick`' 'semi;colon && ampersand' | tr -d '\r')"
# shellcheck disable=SC2016
awkward_expected="$(printf 'arg 1\narg'"'"'2\narg"3\nspace and $HOME and `backtick`\nsemi;colon && ampersand')"
[ "$awkward_out" = "$awkward_expected" ] ||
  fail "an argument vector was rewritten across the WSL boundary: $awkward_out"
pass "argument vectors cross --exec exactly as they were built"

# ---------------------------------------------------------------------------------------------
step "3. Each distribution runs KalaReach on its own"

# The helper and the daemon are built inside the distribution, from the same commit, into that
# distribution's own filesystem. Nothing here is a Windows binary, and nothing crosses /mnt.
commit="$(git rev-parse HEAD)"

build_inside() {
  local distribution="$1"
  # A helper from another commit would prove something about another candidate, so the commit that
  # built it is recorded beside it and checked here.
  if wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
    "test -x '$helper_path' && test \"\$(cat /usr/local/lib/kalareach-acc-commit 2>/dev/null)\" = '$commit'" 2>/dev/null; then
    echo "  $distribution: the helper at $helper_path was built from this commit"
    return 0
  fi
  echo "  $distribution: building the helper inside the distribution (this takes a few minutes)"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    command -v cargo >/dev/null 2>&1 || {
      echo 'cargo is not installed in this distribution' >&2
      exit 1
    }
    rm -rf /tmp/kalareach-src
    cp -a /mnt/c/kala/kalareach /tmp/kalareach-src
    cd /tmp/kalareach-src
    cargo build -p kr-cli --bin kr -p kr-controller --bin kr-controller -p kr-worker --bin kr-worker
    install -m 0755 target/debug/kr '$helper_path'
    install -m 0755 target/debug/kr-controller '$(dirname "$helper_path")/kr-controller'
    install -m 0755 target/debug/kr-worker '$(dirname "$helper_path")/kr-worker'
    mkdir -p /usr/local/lib
    printf '%s' '$commit' >/usr/local/lib/kalareach-acc-commit
  " || fail "$distribution could not build the Linux helper"
}

start_daemon_inside() {
  local distribution="$1"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    running=0
    if [ -f /tmp/kr-acc-controller.pid ] && kill -0 \$(cat /tmp/kr-acc-controller.pid) 2>/dev/null; then
      running=1
    fi
    if [ \$running -eq 0 ]; then
      nohup '$(dirname "$helper_path")/kr-controller' \
        --worker '$(dirname "$helper_path")/kr-worker' --secret-store file \
        >/tmp/kr-controller.log 2>&1 &
      echo \$! >/tmp/kr-acc-controller.pid
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if '$helper_path' list >/dev/null 2>&1; then
        exit 0
      fi
      sleep 1
    done
    echo 'the daemon inside the distribution did not answer' >&2
    tail -n 40 /tmp/kr-controller.log >&2 || true
    exit 1
  " || fail "$distribution did not start its own control daemon"
  daemons="$daemons $distribution"
}

inside() {
  local distribution="$1"
  shift
  # The distribution's own default paths, which is what the helper the Windows side starts will
  # discover. A directory of this run's own here would leave the two halves talking past each other.
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "$*" | tr -d '\r'
}

# One line of JSON with the spaces taken out, so an assertion can name a whole key path.
compact() { tr -d ' \n\r'; }

# The first value one named string key carries in a compacted document, or nothing. These are this
# product's own documents and the key is named in full, so the match is exact; and finding nothing
# is not a failure here, because the check that follows says what was missing.
json_string() {
  awk -v key="\"$1\":\"" '
    {
      start = index($0, key)
      if (start == 0) { exit }
      rest = substr($0, start + length(key))
      end = index(rest, "\"")
      if (end == 0) { exit }
      print substr(rest, 1, end - 1)
      exit
    }'
}

for distribution in "$first" "$second"; do
  build_inside "$distribution"
  start_daemon_inside "$distribution"
done
pass "each distribution built and started its own KalaReach with no native Windows installation"

# Linux paths, binaries and process identifiers stay inside the distribution. Each assertion below
# names the process it is about and reads that process's own Linux paths out of /proc.
installed_dir="$(dirname "$helper_path")"
for distribution in "$first" "$second"; do
  # The daemon: the Linux binary this run installed in this distribution, running as the Linux user
  # the enrolment names.
  daemon_pid="$(inside "$distribution" 'cat /tmp/kr-acc-controller.pid')"
  [[ "$daemon_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution did not report a Linux process identifier for its daemon"
  daemon_exe="$(inside "$distribution" "readlink -f /proc/$daemon_pid/exe | head -n 1")"
  [ "$daemon_exe" = "$installed_dir/kr-controller" ] ||
    fail "$distribution's daemon $daemon_pid runs $daemon_exe, not the $installed_dir/kr-controller installed in it"
  daemon_user="$(inside "$distribution" "stat -c %U /proc/$daemon_pid | head -n 1")"
  [ "$daemon_user" = "$linux_user" ] ||
    fail "$distribution's daemon runs as $daemon_user and the enrolment names $linux_user"
  daemon_root="$(inside "$distribution" "readlink /proc/$daemon_pid/root | head -n 1")"
  [ "$daemon_root" = "/" ] ||
    fail "$distribution's daemon has root $daemon_root rather than this distribution's own"

  # A session of the distribution's own, named by the identifier the create answered with.
  session="$(inside "$distribution" "'$helper_path' --json new --invisible --shell /bin/sh" | compact)"
  created="$(printf '%s' "$session" | json_string session_id)"
  [ -n "$created" ] ||
    fail "$distribution could not create a session of its own: $session"
  echo "  $distribution created session $created"
  listed="$(inside "$distribution" "'$helper_path' --json list" | compact)"
  case "$listed" in
    *"\"session_id\":\"$created\""*) : ;;
    *) fail "$distribution does not list $created, the session it created: $listed" ;;
  esac

  # The worker serving it: this distribution's own Linux process, running the binary installed
  # here, as the same Linux user, with this distribution's filesystem as its root. Nothing on the
  # Windows side takes part in it, and nothing it opens comes through /mnt.
  worker_pid="$(inside "$distribution" 'pgrep -n -x kr-worker | head -n 1')"
  [[ "$worker_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution runs no worker for session $created"
  worker_exe="$(inside "$distribution" "readlink -f /proc/$worker_pid/exe | head -n 1")"
  [ "$worker_exe" = "$installed_dir/kr-worker" ] ||
    fail "$distribution's worker $worker_pid runs $worker_exe, not the $installed_dir/kr-worker installed in it"
  worker_user="$(inside "$distribution" "stat -c %U /proc/$worker_pid | head -n 1")"
  [ "$worker_user" = "$linux_user" ] ||
    fail "$distribution's worker runs as $worker_user and the enrolment names $linux_user"
  worker_root="$(inside "$distribution" "readlink /proc/$worker_pid/root | head -n 1")"
  [ "$worker_root" = "/" ] ||
    fail "$distribution's worker has root $worker_root rather than this distribution's own"
  crossing="$(inside "$distribution" "ls -l /proc/$worker_pid/fd | grep -c ' /mnt/' | head -n 1")"
  [ "$crossing" = "0" ] ||
    fail "$distribution's worker has $crossing open files under /mnt, so it reaches out of the distribution"

  inside "$distribution" "'$helper_path' close $created" >/dev/null ||
    fail "$distribution could not close session $created"
done
pass "each distribution's daemon and worker are its own Linux processes, binaries, users and paths"

# ---------------------------------------------------------------------------------------------
step "4. Windows reaches each distribution through the process bridge"

kr_exe=""
for candidate in "C:/kala/target/debug/kr.exe" "target/debug/kr.exe" "C:/kala/target/release/kr.exe"; do
  if [ -f "$candidate" ]; then
    kr_exe="$candidate"
    break
  fi
done
[ -n "$kr_exe" ] || fail "no Windows kr.exe was found; build it with cargo build -p kr-cli --bin kr"
controller_exe="$(dirname "$kr_exe")/kr-controller.exe"
worker_exe="$(dirname "$kr_exe")/kr-worker.exe"
[ -f "$controller_exe" ] || fail "no Windows kr-controller.exe beside $kr_exe"

# The Windows daemon this run owns, with its keys in its own directory rather than the platform
# credential store. Every path handed to one of these native programs is a Windows path, including
# the two in the environment: this shell's own form means nothing to them.
windows_runtime="$run_dir/windows-run"
windows_state="$run_dir/windows-state"
mkdir -p "$windows_runtime" "$windows_state"
windows_path() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }
"$controller_exe" --runtime-dir "$(windows_path "$windows_runtime")" \
  --state-dir "$(windows_path "$windows_state")" \
  --worker "$(windows_path "$worker_exe")" \
  --secret-store file >"$run_dir/windows-controller.log" 2>&1 &
windows_daemon=$!
KR_RUNTIME_DIR="$(windows_path "$windows_runtime")"
KR_STATE_DIR="$(windows_path "$windows_state")"
export KR_RUNTIME_DIR KR_STATE_DIR
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "$kr_exe" bridge list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"$kr_exe" bridge list >/dev/null 2>&1 ||
  fail "the Windows daemon did not answer: $(tail -n 20 "$run_dir/windows-controller.log")"
pass "a Windows control daemon is running for this acceptance"

enrol_distribution() {
  local distribution="$1" label="$2" answer identity
  "$kr_exe" --json bridge enrol --access wsl --label "$label" --target "$distribution" \
    --user "$linux_user" --helper "$helper_path" --probe >"$run_dir/enrol-$label.json" 2>&1 ||
    fail "enrolling $distribution failed: $(cat "$run_dir/enrol-$label.json")"
  answer="$(compact <"$run_dir/enrol-$label.json")"
  identity="$(printf '%s' "$answer" | json_string environment_id)"
  [ -n "$identity" ] ||
    fail "enrolling $distribution recorded no environment identity: $answer"
  printf '%s' "$identity"
}

first_id="$(enrol_distribution "$first" "first")"
second_id="$(enrol_distribution "$second" "second")"
echo "  $first is environment $first_id"
echo "  $second is environment $second_id"
[ -n "$first_id" ] && [ -n "$second_id" ] ||
  fail "a distribution did not answer with an environment identity"
[ "$first_id" != "$second_id" ] ||
  fail "two distributions answered with the same environment identity"
pass "each distribution answered the bridge with its own environment identity"

# The identity the enrolment recorded is the one that distribution reports for itself.
for pair in "$first:$first_id" "$second:$second_id"; do
  distribution="${pair%%:*}"
  recorded="${pair##*:}"
  doctor="$(inside "$distribution" "'$helper_path' --json doctor" | compact)" ||
    fail "$distribution could not report on itself"
  reported="$(printf '%s' "$doctor" | json_string environment_id)"
  [ -n "$reported" ] ||
    fail "$distribution named no environment of its own: $doctor"
  [ "$reported" = "$recorded" ] ||
    fail "$distribution reports environment $reported and the enrolment recorded $recorded"
done
pass "the recorded identity is the one each distribution reports for itself"

refresh_and_check() {
  local label="$1" expect_id="$2" flags="${3:-}" text
  # shellcheck disable=SC2086
  "$kr_exe" --json bridge refresh "$label" $flags >"$run_dir/refresh-$label.json" 2>&1 ||
    fail "refreshing $label failed: $(cat "$run_dir/refresh-$label.json")"
  text="$(compact <"$run_dir/refresh-$label.json")"
  # The verification is what the destination answered. Matching the whole document would accept the
  # enrolment's own identity where the verification is absent, so the key path is named here.
  case "$text" in
    *"\"verification\":{\"environment_id\":\"$expect_id\""*) : ;;
    *) fail "the refresh of $label carried no verification from $expect_id: $text" ;;
  esac
  case "$text" in
    *'"role":"controller"'*) : ;;
    *) fail "the refresh of $label was not answered by a control daemon: $text" ;;
  esac
}

refresh_and_check first "$first_id"
refresh_and_check second "$second_id"
pass "a refresh opens a bridge to each distribution and carries a read to its own daemon"

# ---------------------------------------------------------------------------------------------
step "5. A listing reads the cache and starts nothing"

wsl.exe -t "$second" >/dev/null 2>&1 || fail "the second distribution could not be stopped"
sleep 2
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "$second is not stopped, so this check would prove nothing"

# A refresh observes, and observing starts nothing: this one was not told to start the environment.
"$kr_exe" --json bridge refresh second >"$run_dir/refresh-stopped.json" 2>&1 ||
  fail "the refresh of the stopped distribution failed: $(cat "$run_dir/refresh-stopped.json")"
observed="$(compact <"$run_dir/refresh-stopped.json")"
case "$observed" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the refresh did not observe $second as stopped: $observed" ;;
esac
case "$observed" in
  *'"verification":null'*) : ;;
  *) fail "a stopped distribution answered a bridge: $observed" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the refresh started $second although it was not told to"
pass "a refresh observed the stopped distribution and started nothing"

"$kr_exe" --json bridge list >"$run_dir/list-while-stopped.json" 2>&1 ||
  fail "the listing failed: $(cat "$run_dir/list-while-stopped.json")"
listing="$(compact <"$run_dir/list-while-stopped.json")"
# The row for the stopped distribution alone: everything after its identity up to the end of that
# row. Another row's source or status cannot satisfy these.
row="${listing#*\"environment_id\":\""$second_id"\"}"
[ "$row" != "$listing" ] ||
  fail "the stopped distribution is missing from the listing: $listing"
row="${row%%\},\{\"enrolment\"*}"
case "$row" in
  *'"observation":"cache"'*) : ;;
  *) fail "the stopped distribution's row is not from the cache: $row" ;;
esac
case "$row" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the listing does not repeat what was observed of $second: $row" ;;
esac
case "$row" in
  *'"last_observed_at_ms":'*) : ;;
  *) fail "the stopped distribution's row carries no observation time: $row" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the listing started $second, which a listing must never do"
pass "the listing reported the stopped distribution from the cache and started nothing"

# Starting the distribution again is one step; the daemon inside it is another, because stopping a
# distribution ends every process in it. The refresh below starts the distribution, and the bridge
# is checked once that distribution is serving again.
"$kr_exe" --json bridge refresh second --start >"$run_dir/refresh-start.json" 2>&1 ||
  fail "the refresh that was told to start failed: $(cat "$run_dir/refresh-start.json")"
[ "$(state_of "$second")" = "Running" ] ||
  fail "the refresh that was told to start did not start $second"
pass "a refresh that was told to start the distribution started it"

start_daemon_inside "$second"
refresh_and_check second "$second_id"
pass "the bridge reaches the distribution that was started again"

# ---------------------------------------------------------------------------------------------
step "6. NAT and mirrored networking"

# USERPROFILE is a Windows path. The redirection below is this shell's, so it needs the form this
# shell opens files by.
wslconfig_path="$(cygpath -u "${USERPROFILE:?the Windows profile directory}")/.wslconfig"
wslconfig_saved="$run_dir/wslconfig.saved"
if [ -f "$wslconfig_path" ]; then
  wslconfig_existed=1
  cp "$wslconfig_path" "$wslconfig_saved"
else
  : >"$wslconfig_saved"
fi

networking_facts() {
  local mode="$1" distribution="$2" effective addresses
  # What WSL is actually doing, not what the file asks for.
  effective="$(inside "$distribution" 'wslinfo --networking-mode 2>/dev/null || true' | tr -d ' ')"
  echo "  $mode: $distribution reports networking mode: ${effective:-unknown}"
  [ -n "$effective" ] ||
    fail "$mode: this WSL build does not report its networking mode, so the mode cannot be established"
  [ "$effective" = "$mode" ] ||
    fail "$mode was asked for and $effective is in effect"
  addresses="$(inside "$distribution" 'ip -br addr' || true)"
  echo "  $mode: $distribution addresses:"
  printf '    %s\n' "$addresses"
  inside "$distribution" 'ping -c 1 -W 2 127.0.0.1 >/dev/null 2>&1 && echo loopback-ok' |
    grep -q loopback-ok || fail "$mode: loopback is not reachable inside $distribution"
}

set_mode() {
  local mode="$1"
  printf '[wsl2]\nnetworkingMode=%s\n' "$mode" >"$wslconfig_path"
  wsl.exe --shutdown >/dev/null 2>&1 ||
    fail "the distributions could not be shut down to take up $mode networking"
  sleep 3
  daemons=""
  for distribution in "$first" "$second"; do
    start_daemon_inside "$distribution"
  done
}

for mode in nat mirrored; do
  set_mode "$mode"
  networking_facts "$mode" "$first"
  # The bridge opens no socket, so it must behave the same in both modes. This is the measurement
  # that decides whether any automatic behaviour is needed, rather than assuming one.
  refresh_and_check first "$first_id"
  pass "$mode: the process bridge opened and carried a read unchanged"
done

# ---------------------------------------------------------------------------------------------
step "7. The helper refuses what may not cross"

# Input that is not a frame at all: the helper ends non-zero and says why.
malformed_code=0
malformed="$(printf 'not a bridge frame' |
  wsl.exe -d "$first" -u "$linux_user" --exec "$helper_path" bridge --stdio 2>&1)" || malformed_code=$?
[ "$malformed_code" -ne 0 ] ||
  fail "the helper served a stream that is not a bridge frame: $malformed"
echo "$malformed" | grep -qi "bridge" ||
  fail "the helper gave no diagnostic for input that is not a frame: $malformed"
pass "input that is not a bridge frame ends the helper non-zero with a diagnostic"

# A properly encoded handshake that declares a network origin has to be refused by protocol, not by
# a parse failure. The suite that builds those frames runs inside the distribution, against the
# Linux helper this run installed.
inside "$first" 'cd /tmp/kalareach-src && cargo test -p kr-cli --test bridge' >"$run_dir/wsl-bridge-suite.log" 2>&1 ||
  fail "the bridge suite failed inside $first: $(tail -n 30 "$run_dir/wsl-bridge-suite.log")"
grep -q "test result: ok" "$run_dir/wsl-bridge-suite.log" ||
  fail "the bridge suite reported no result inside $first"
pass "the bridge suite passes inside the distribution, including the refusal of a network origin"

echo
echo "KR-ACC-011: $passed checks passed."
