#!/usr/bin/env bash
# Qualifies the managed shell packages end to end, on this machine.
#
#   bash scripts/e2e-fence.sh          build or verify the packages, then qualify them
#   bash scripts/e2e-fence.sh <log>    the same, with a copy of everything in <log>
#
# Each step is something the operating system can see:
#
#   * the packages rebuilt from their pinned upstream releases and patch sets, into an installation
#     on the internal disk, and the identity each build wrote beside its binary
#   * the startup customisations the qualification runs against, fetched once by digest
#   * a real control daemon, a real worker it launched, and a real managed session whose root
#     shell is one of those packages
#   * the whole corpus under tests/shells/ driven against the packages that were just built: the
#     customisations, the person's own bindings and profile order, Ctrl-D at the root prompt, the
#     fence races and what a launch past its budget installs
#   * the upstream register checked against the pins and against what is installed
#
# Every path this script uses is on the internal disk and the binaries it starts are copied there
# first. A process a service manager launches is its own identity to the operating system, and one
# that reaches a removable volume asks the person at the machine for permission.
#
# Nothing here reaches the person's own credential store: the daemon is given `--secret-store
# file`, so the keys a run creates leave with the run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
# shellcheck source=scripts/lib/owned-processes.sh
. "$root/scripts/lib/owned-processes.sh"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts"

# This run is about every case. A filter left in the environment would qualify one of them and
# report all of them, so it is taken out here rather than trusted.
unset KR_QUALIFICATION_CASE

# One root for the whole run: the builder installs here, the daemon resolves here, and the corpus
# drives what is here.
if [ -n "${KR_SHELL_PREFIX:-}" ]; then
  packages="$KR_SHELL_PREFIX"
elif [ "$(uname -s)" = "Darwin" ]; then
  packages="$HOME/Library/Caches/kalareach/shells"
else
  packages="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shells"
fi
export KR_SHELL_PREFIX="$packages"
export KR_SHELL_PACKAGES="$packages"

if [ -n "${KR_SHELL_STACKS:-}" ]; then
  stacks="$KR_SHELL_STACKS"
elif [ "$(uname -s)" = "Darwin" ]; then
  stacks="$HOME/Library/Caches/kalareach/shell-stacks"
else
  stacks="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shell-stacks"
fi

echo "kalareach shell-integration qualification"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  evidence: $artifacts"
echo

failed=0
# A stage that could not run at all, as opposed to one that ran and did not hold. Either ends this
# run without success: a qualification that skipped a stage has not qualified what that stage is
# about, and saying so is the whole point of running it.
incomplete=0
fail() {
  echo "FAILED: $*"
  failed=1
}

require() {
  if [ "$1" != "$2" ]; then
    fail "$3 (expected $2, got $1)"
  else
    echo "  ok: $3"
  fi
}

# The run's own root, on the internal disk, with the binaries beside it.
# Short on purpose: a Unix socket address is 103 bytes on this platform, and the endpoint a case
# binds is under a directory of its own beneath the temporary directory. A run root of the usual
# length leaves a case no room for one.
run_root="$(mktemp -d "${TMPDIR:-/tmp}/kr-fence.XXXXXX")"
mkdir -p "$run_root/bin" "$run_root/r" "$run_root/s" "$run_root/cwd"
chmod 700 "$run_root/r" "$run_root/s"

# The launchd jobs this run's daemon defined, by label. On macOS the daemon writes one definition
# per worker's job into its environment's jobs directory and removes it once the job has gone.
defined_jobs() {
  local definition
  for definition in "$run_root"/s/environments/*/jobs/kr-worker-*.plist; do
    [ -e "$definition" ] || continue
    basename "$definition" .plist
  done
}

# Each of those jobs launchd still has loaded, as <domain>/<label>, one to a line. launchd answers
# 113 for a job a domain does not have and 112 for a domain that is not there. A job launchd could
# not answer about otherwise is named with its answer, so a question nobody could read is not
# taken for a job that has gone. A host with no launchd has no such job.
jobs_left() {
  [ "$(uname -s)" = Darwin ] || return 0
  local uid label domain rc
  uid="$(id -u)"
  for label in $(defined_jobs); do
    for domain in "gui/$uid" "user/$uid"; do
      /bin/launchctl print "$domain/$label" >/dev/null 2>&1 && rc=0 || rc=$?
      case $rc in
        0) echo "$domain/$label" ;;
        112 | 113) ;;
        *) echo "$domain/$label (launchctl print answered $rc)" ;;
      esac
    done
  done
}

cleanup() {
  local status=$?
  for session in $("$run_root/bin/kr" list --json 2>/dev/null | /usr/bin/env python3 -c \
    'import json,sys
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in document.get("sessions", []):
    print(entry["display_number"])' 2>/dev/null); do
    "$run_root/bin/kr" close "$session" >/dev/null 2>&1 || true
  done
  # A closed session's worker ends, and the daemon then removes the worker's launchd job. The daemon
  # is left running until that has happened, within a bound, because a job it has not removed by
  # the time it stops stays loaded.
  local deadline=$(( $(date +%s) + 90 ))
  while [ -n "$(jobs_left)" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 1
  done
  # Each by its record, and only while its number still names the process this run started.
  end_owned_processes
  sleep 1
  local left keep=0 target
  left="$(pgrep -u "$(id -u)" -f "$run_root" 2>/dev/null | grep -v "^$$\$" || true)"
  if [ -n "$left" ]; then
    echo "FAILED: these processes outlived the script"
    # The identifiers are one argument each, which is what this call wants.
    # shellcheck disable=SC2046,SC2086
    ps -o pid=,command= -p $(printf '%s' "$left" | tr '\n' ' ') || true
    failed=1
    # A process still running may be reading the run's directories, so they are kept for it.
    keep=1
  else
    echo "no process this run started is still running"
  fi
  left="$(jobs_left)"
  if [ -n "$left" ]; then
    echo "FAILED: these launchd jobs this run's daemon defined were still loaded"
    printf '%s\n' "$left" | sed 's/^/  /'
    failed=1
    # Removed all the same, each by the label this run's own daemon gave it, so the run leaves
    # nothing loaded behind it. launchd ends whatever is still running inside one.
    while IFS= read -r target; do
      /bin/launchctl bootout "${target%% *}" >/dev/null 2>&1 || true
    done <<<"$left"
    left="$(jobs_left)"
    if [ -n "$left" ]; then
      echo "FAILED: these are still loaded after their removal"
      printf '%s\n' "$left" | sed 's/^/  /'
      keep=1
    fi
  elif [ "$(uname -s)" = Darwin ]; then
    echo "no launchd job this run's daemon defined is still loaded"
  fi
  if [ "$keep" -eq 0 ]; then
    rm -rf "${run_root:?}"
  else
    echo "$run_root is kept"
  fi
  # A run whose processes outlived it did not pass, whatever the last command returned.
  if [ "$failed" -ne 0 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

echo "1. the packages, from their pinned upstream releases and patch sets"
# The identity is a digest of the inputs, so a package that is already installed from these inputs
# reports that nothing changed, and one that is not is built here. Either way what the corpus then
# drives is a package this run stood behind.
if ! bash scripts/build-shells.sh --all --no-upstream-tests > "$run_root/build.log" 2>&1; then
  tail -40 "$run_root/build.log"
  fail "the packages could not be built"
  exit 1
fi
grep -E "is current, nothing changed|installed" "$run_root/build.log" || true

# A second build of one package, from inputs of its own. An installation a person updates holds
# two builds, and the qualification's replacement case needs two that are really different: the
# identity is a digest of the build's inputs, so a flag that reaches the compiler is a second
# package rather than a second copy of the first. The ordinary build runs again afterwards, so
# the installation this run then qualifies is the pinned one.
if ! CPPFLAGS="${CPPFLAGS:+$CPPFLAGS }-DKR_QUALIFICATION_BUILD=1" \
    bash scripts/build-shells.sh --zsh --no-upstream-tests > "$run_root/second-build.log" 2>&1; then
  tail -20 "$run_root/second-build.log"
  fail "a second build of the zsh package could not be made"
fi
grep -E "built zsh|is current, nothing changed" "$run_root/second-build.log" || true
cp "$run_root/second-build.log" "$artifacts/shell-packages-second-build.log"
# Which build that was. The pointer names it now, before the pinned one is put back, so the stage
# that needs a second package names the one this stage made rather than whichever the directory
# happens to list first.
second_identity="$(cat "$packages/zsh/current" 2>/dev/null || true)"
if ! bash scripts/build-shells.sh --zsh --no-upstream-tests >> "$run_root/build.log" 2>&1; then
  tail -20 "$run_root/build.log"
  fail "the pinned zsh package could not be put back"
fi
# Copied once the log is complete: the restoration above writes into it, and a copy taken before
# that would leave the run's evidence without the step that put the pinned package back.
cp "$run_root/build.log" "$artifacts/shell-packages-build.log"

for shell in zsh bash fish; do
  identity="$(cat "$packages/$shell/current" 2>/dev/null || true)"
  if [ -z "$identity" ]; then
    fail "$shell is not installed"
  else
    echo "  ok: $shell is $identity"
  fi
done
# This package rebuilds no shell: it is qualified against the editor this host already has, and
# publishing that qualification is what puts it where the corpus looks.
if command -v pwsh >/dev/null 2>&1; then
  if ! pwsh -NoProfile -Command "
    Import-Module ./shells/psreadline/module/KalaReach.ShellBridge.psd1
    Publish-KalaReachQualification | Format-List" > "$run_root/psreadline.log" 2>&1; then
    tail -20 "$run_root/psreadline.log"
    fail "the PSReadLine package could not be qualified"
  fi
  cp "$run_root/psreadline.log" "$artifacts/psreadline-qualification.log"
fi
if [ -r "$packages/powershell/current" ]; then
  echo "  ok: powershell is $(cat "$packages/powershell/current")"
else
  fail "the PSReadLine package is not qualified on this host and no editor was found to qualify it against"
fi

echo
echo "2. the startup customisations, by digest"
if ! bash scripts/fetch-shell-stacks.sh > "$run_root/stacks.log" 2>&1; then
  tail -20 "$run_root/stacks.log"
  fail "the startup customisations could not be fetched"
fi
tail -12 "$run_root/stacks.log"
cp "$run_root/stacks.log" "$artifacts/shell-stacks-fetch.log"

echo
echo "3. a real daemon, a real worker and a real managed session"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build -q -p kr-controller -p kr-worker -p kr-cli
target_dir="${CARGO_TARGET_DIR:-$root/target}"
# The attachment's restoration guard is one of these: an attached terminal must come back even if
# the process holding it is killed outright, and the guard is what holds its state.
for binary in kr-controller kr-worker kr kr-attach-guard; do
  if [ ! -x "$target_dir/debug/$binary" ]; then
    fail "the build did not produce $binary"
    exit 1
  fi
  cp "$target_dir/debug/$binary" "$run_root/bin/$binary"
  # Started once, here, where nothing is timed: the operating system checks a newly written
  # executable the first time it starts, and on a loaded machine that check alone can outlast a
  # create's rendezvous.
  "$run_root/bin/$binary" --version >/dev/null
done
export KR_RUNTIME_DIR="$run_root/r"
export KR_STATE_DIR="$run_root/s"
kr="$run_root/bin/kr"

managed_shell="$packages/zsh/$(cat "$packages/zsh/current")/bin/zsh"
(cd "$run_root" && SHELL="$managed_shell" exec "$run_root/bin/kr-controller" \
  --runtime-dir "$run_root/r" \
  --state-dir "$run_root/s" \
  --secret-store file \
  --worker "$run_root/bin/kr-worker") \
  >"$run_root/controller.log" 2>&1 &
remember_process "$!" "$run_root/bin/kr-controller"

deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if "$kr" doctor --json >/dev/null 2>&1; then break; fi
  sleep 0.2
done
if ! "$kr" doctor --json >"$artifacts/fence-doctor.json" 2>&1; then
  tail -20 "$run_root/controller.log"
  fail "the control daemon did not start"
  exit 1
fi
echo "  ok: the control daemon answered"

# The image a session's root shell is running, as the kernel reports it. The session record says
# which package the worker was told to launch; this says which one the process that answers the
# person is actually running, which is the question an update has to answer. The walk starts at
# the worker started for that session and takes the first process under it running a package out
# of this installation.
root_image() {
  /usr/bin/env python3 -c '
import os, subprocess, sys

session, prefix = sys.argv[1], sys.argv[2].rstrip("/") + "/"


def image(pid):
    link = "/proc/%d/exe" % pid
    if os.path.exists(link):
        try:
            return os.path.realpath(link)
        except OSError:
            return ""
    listing = subprocess.run(
        ["lsof", "-p", str(pid), "-a", "-d", "txt", "-Fn"],
        capture_output=True, text=True,
    ).stdout
    for line in listing.splitlines():
        if line.startswith("n"):
            return line[1:]
    return ""


table = subprocess.run(
    ["ps", "-A", "-o", "pid=,ppid=,command="], capture_output=True, text=True
).stdout
children, commands = {}, {}
for line in table.splitlines():
    fields = line.split(None, 2)
    if len(fields) < 3 or not fields[0].isdigit() or not fields[1].isdigit():
        continue
    pid, parent = int(fields[0]), int(fields[1])
    children.setdefault(parent, []).append(pid)
    commands[pid] = fields[2]

queue = [
    pid for pid, command in commands.items()
    if "kr-worker" in command and "--session " + session in command
]
seen = set()
while queue:
    pid = queue.pop(0)
    if pid in seen:
        continue
    seen.add(pid)
    running = image(pid)
    if running.startswith(prefix):
        print(running)
        break
    queue.extend(children.get(pid, []))
' "$1" "$packages"
}

read_json() {
  /usr/bin/env python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    if document is None:
        break
    document = document.get(key) if isinstance(document, dict) else None
print("" if document is None else document)
' "$1" "$2"
}

# The session's own home, so nothing this run does reaches the person's own startup files. The
# customisation is one of the pinned set, installed the way its own documentation says to; the
# marked entry is added by the product's own installer rather than by this script.
session_home="$run_root/home"
mkdir -p "$session_home/.config"
# The customisation this session runs, from the index the fetcher wrote.
starship_root="$(/usr/bin/env python3 -c '
import json, sys
index = json.load(open(sys.argv[1]))
for entry in index["stacks"]:
    if entry["id"] == "starship" and entry["status"] == "installed":
        print(entry["root"] or "")
        break
' "$stacks/index.json" 2>/dev/null || true)"
if [ -z "$starship_root" ]; then
  fail "the customisation this session runs is not installed"
fi
cp "$root/tests/shells/zsh/starship/home/starship.toml" "$session_home/.config/starship.toml"
cat > "$session_home/.zshrc" <<ZSHRC
# The person's own configuration, with a customisation from the pinned set.
print -r -- user-top >> "$session_home/order"
HISTFILE=
setopt no_beep
bindkey '^D' delete-char
export STARSHIP_CONFIG="$session_home/.config/starship.toml"
export STARSHIP_CACHE="$session_home/.cache/starship"
eval "\$("$starship_root/starship" init zsh)"
[[ -n "\$STARSHIP_SESSION_KEY" ]] && print -r -- stack >> "$session_home/order"
kr-user-binding-ran() { print -r -- ran >> "$session_home/binding" }
kr-user-widget() { BUFFER='kr-user-binding-ran'; CURSOR=\$#BUFFER }
zle -N kr-user-widget
bindkey '^[q' kr-user-widget
print -r -- user-bottom >> "$session_home/order"
ZSHRC

if ! HOME="$session_home" ZDOTDIR="$session_home" SHELL="$managed_shell" \
    "$kr" shell install --json >"$artifacts/fence-shell-install.json" 2>&1; then
  cat "$artifacts/fence-shell-install.json"
  fail "the marked startup entry could not be installed"
fi
if grep -qi "kalareach shell integration" "$session_home/.zshrc"; then
  echo "  ok: the marked entry is in the session's own startup file"
else
  fail "the marked entry is not in the startup file the session will read"
fi

if HOME="$session_home" ZDOTDIR="$session_home" SHELL="$managed_shell" \
    "$kr" new --invisible --shell-mode managed --cwd "$run_root/cwd" \
    --json >"$artifacts/fence-create.json" 2>"$run_root/create.err"; then
  display="$(read_json "$artifacts/fence-create.json" display_number)"
  mode="$(read_json "$artifacts/fence-create.json" shell_mode)"
  require "$mode" "managed" "the session the daemon made runs the managed package"

  # The root integration qualified: the worker reports the session rather than closing it, which
  # is what it does when the packaged shell's hooks do not activate.
  if HOME="$session_home" "$kr" status "$display" --json >"$artifacts/fence-status.json" 2>&1; then
    require "$(read_json "$artifacts/fence-status.json" shell_mode)" "managed" \
      "the session reports the managed mode it was created in"
    require "$(read_json "$artifacts/fence-status.json" state)" "live" \
      "the session the daemon made is live"
    session_id="$(read_json "$artifacts/fence-status.json" session_id)"
    require "$(root_image "$session_id")" "$managed_shell" \
      "the live root process of that session is running the package the installation resolves"
  else
    fail "the daemon could not report on the session it made"
    exit 1
  fi

  # The person's own startup ran inside that session, in its own order, with the customisation.
  # Waits here are counted off the clock rather than off a number of attempts: a loaded machine
  # makes every attempt take longer, so an attempt count is a budget nobody chose.
  order_deadline=$(( $(date +%s) + 20 ))
  while [ "$(date +%s)" -lt "$order_deadline" ]; do
    [ -s "$session_home/order" ] && break
    sleep 0.2
  done
  cp "$session_home/order" "$artifacts/fence-session-order.txt" 2>/dev/null || true
  require "$(tr '\n' ' ' < "$session_home/order" 2>/dev/null | sed 's/ *$//')" \
    "user-top stack user-bottom" \
    "the session's shell ran the person's startup, and the customisation, in its own order"

  # A second package installed while that session runs. The pointer is what a new session
  # resolves; the one already running keeps what it started.
  first_identity="$(cat "$packages/zsh/current")"
  second="$second_identity"
  if [ -n "$second" ] && [ "$second" != "$first_identity" ] && [ -x "$packages/zsh/$second/bin/zsh" ]; then
    printf '%s' "$second" > "$packages/zsh/current"
    if HOME="$session_home" ZDOTDIR="$session_home" SHELL="$packages/zsh/$second/bin/zsh" \
        "$kr" new --invisible --shell-mode managed --cwd "$run_root/cwd" \
        --json >"$artifacts/fence-create-2.json" 2>&1; then
      second_display="$(read_json "$artifacts/fence-create-2.json" display_number)"
      HOME="$session_home" "$kr" status "$second_display" --json >"$artifacts/fence-status-2.json" 2>&1 || true
      require "$(read_json "$artifacts/fence-status-2.json" state)" "live" \
        "the session made after the update is live"
      require "$(root_image "$(read_json "$artifacts/fence-status-2.json" session_id)")" \
        "$packages/zsh/$second/bin/zsh" \
        "the live root process of a session made after the update is running the package the installation now resolves"
      HOME="$session_home" "$kr" status "$display" --json >"$artifacts/fence-status-1.json" 2>&1 || true
      require "$(read_json "$artifacts/fence-status-1.json" state)" "live" \
        "the session that was already running is still live"
      require "$(root_image "$session_id")" "$managed_shell" \
        "the live root process that was already running is still the package it started"
      HOME="$session_home" "$kr" close "$second_display" >/dev/null 2>&1 || true
    else
      sed 's/^/    /' "$artifacts/fence-create-2.json"
      fail "a second managed session could not be created"
    fi
    printf '%s' "$first_identity" > "$packages/zsh/current"
  else
    fail "the second build this run made is not an installed package of its own, so no update can be demonstrated"
  fi

  # A terminal attached to that session, and the two things a person does at it: the key they
  # bound, and the gesture. Both go to the packaged shell the worker started, through the
  # daemon's own attachment, and the gesture ends that attachment rather than the shell.
  rm -f "${session_home:?}/binding"
  KR_ATTACH_DISPLAY="$display" KR_ATTACH_HOME="$session_home" KR_ATTACH_KR="$kr" \
    /usr/bin/env python3 "$root/scripts/attach-drive.py" >"$artifacts/fence-attach.log" 2>&1 \
    && attach_rc=0 || attach_rc=$?
  sed 's/^/    /' "$artifacts/fence-attach.log" | head -8
  if [ "${attach_rc:-1}" -ne 0 ]; then
    fail "the terminal attached to that session did not answer as a person's would"
  fi
  # What the key the person bound actually did. The widget writes a command line and the shell
  # runs it, so the file is written by that session's own root shell rather than read off a
  # screen that could have been showing anything.
  require "$(cat "$session_home/binding" 2>/dev/null || true)" "ran" \
    "the key the person bound ran their own command in the session's root shell"
  # The gesture ended the attachment and left the session. The record still answers, and the
  # shell that was started for it is still the process running.
  HOME="$session_home" "$kr" status "$display" --json >"$artifacts/fence-status-3.json" 2>&1 || true
  require "$(read_json "$artifacts/fence-status-3.json" state)" "live" \
    "the gesture ended the attachment and left the session live"
  require "$(read_json "$artifacts/fence-status-3.json" attachments)" "0" \
    "the session has no attachment after the gesture"
  require "$(root_image "$session_id")" "$managed_shell" \
    "the root shell the gesture was made at is still the process running"

  # The session is closed through the daemon, and the daemon is asked again: it keeps a closed
  # session's record and answers for it, so the close is what the record says.
  if ! HOME="$session_home" "$kr" close "$display" >"$run_root/close.log" 2>&1; then
    cat "$run_root/close.log"
    fail "the daemon could not close the session it made"
  fi
  # Closure is a sequence, so the record is asked again until it settles. A status that cannot be
  # read is asked again as well: a daemon busy enough to answer late is not a session refusing to
  # close, and stopping at the first unreadable answer reports whatever the sequence was part way
  # through.
  closed_state=""
  closed_deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$closed_deadline" ]; do
    if HOME="$session_home" "$kr" status "$display" --json >"$artifacts/fence-closed.json" 2>&1; then
      closed_state="$(read_json "$artifacts/fence-closed.json" state)"
      [ "$closed_state" = "closed" ] && break
    fi
    sleep 0.3
  done
  require "$closed_state" "closed" "the session the daemon closed reports itself closed"

  echo "  the fenced launch has no verb on the command line, so it is driven against these same"
  echo "  packages by the corpus below, over the published bridge contract."
else
  # What the daemon printed while it was refusing, and what the worker it launched said for
  # itself: an answer that only says something did not happen in time carries no reason, and the
  # reason is in the worker's own diagnostics.
  cp "$run_root/controller.log" "$artifacts/fence-controller.log" 2>/dev/null || true
  sleep 3
  worker_said=""
  for diagnostics in "$run_root"/s/environments/*/jobs/*.diagnostics; do
    [ -r "$diagnostics" ] || continue
    cp "$diagnostics" "$artifacts/fence-worker.log"
    worker_said="$(cat "$diagnostics")"
  done
  echo "  the daemon refused a managed session:"
  echo "    $(read_json "$artifacts/fence-create.json" message)"
  [ -n "$worker_said" ] && echo "    the worker said: $worker_said"
  fail "a managed session could not be created"
fi

echo
echo "4. the corpus, against the packages this run stood behind"
# The checks that need the packages and the customisations are left out of an ordinary run. This
# one built the first and fetched the second, so it includes them, and a missing one fails.
if ! KR_TEST_ARTIFACTS_DIR="$artifacts" \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    cargo test -p kr-shell-integration --test qualification -- --test-threads=1 --include-ignored \
    >"$run_root/qualification.log" 2>&1; then
  tail -60 "$run_root/qualification.log"
  fail "the qualification did not hold"
fi
grep -E "^(test |test result)" "$run_root/qualification.log" || true
cp "$run_root/qualification.log" "$artifacts/qualification.log"
if [ -r "$artifacts/qualification-cases.tsv" ]; then
  echo
  echo "  what each case qualified:"
  sed 's/^/    /' "$artifacts/qualification-cases.tsv"
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "the qualification did not pass"
  exit 1
fi
if [ "$incomplete" -ne 0 ]; then
  echo "the qualification is incomplete: a stage above could not run, and what it is about is"
  echo "not qualified by this run"
  exit 2
fi
echo "every package was qualified against every customisation this host has"
