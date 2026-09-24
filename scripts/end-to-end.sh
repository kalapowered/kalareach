#!/usr/bin/env bash
# Runs the host's end-to-end demonstrations: real processes, real sockets, real terminals.
#
# Every one of these starts something the operating system can see — a control daemon, a worker it
# spawned, a shell in a pseudo-terminal, an attach command on a real terminal — and checks a
# behaviour the specification names. They are ordinary `cargo test` binaries, so they run in the
# workspace suite too; this script exists to run exactly those, in one place, with a log.
#
# Every step is checked. A suite that fails to build, a suite that runs no tests, or a suite that
# fails all end this script with a non-zero status, because a script that exits zero without
# demonstrating anything is worse than no script.
#
# Nothing here reaches the person's own credential store. A suite that needs a key store opens one
# in its own temporary directory, and a daemon a suite starts is given `--secret-store file`, so
# the keys a run creates leave with the run. Items written to the platform's credential store would
# not: nothing collects them, and a run that wrote there would add to them every time.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

echo "kalareach end-to-end demonstrations"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  secret store: a directory inside each suite's own temporary host"
echo
# Nothing this script started may outlive it, and the check at its end fails when something does.
# A worker is deliberately not a child of whatever created it, which is what makes a session survive
# a control daemon's restart, so a suite that failed to close a session leaves a worker running
# until the machine is restarted.
#
# This run gets a temporary root of its own and every process it starts lives under it: the suites
# put their runtime directories, state directories and copied binaries there, so a process whose
# command line names that root is one of ours and nothing else is. That is what makes the check
# below an answer about this run rather than about whatever else the machine happens to be doing.
#
# Nothing it started may hold this directory open either. Cargo runs each suite from the workspace,
# which can be on a removable volume, and a worker is not a child of whatever asked for it: the
# host gives every process it launches a working directory of its own under the state directory,
# and the suites check what the kernel actually gave it. The run root below is on the internal
# disk, so those directories, the copied binaries, the sockets and the journals all are.
run_base="${TMPDIR:-/tmp}"; run_root="$(mktemp -d "${run_base%/}/kalareach-run.XXXXXX")"
export TMPDIR="$run_root"
# The same directory as the kernel resolves it. A daemon resolves the paths it hands a worker, and
# resolving can change the spelling (on macOS the temporary directory is reached through a symbolic
# link), so a process belongs to this run when its command line names either spelling.
run_root_resolved="$(cd "$run_root" && pwd -P)"

# Every process of this user whose command line names this run's root, in either spelling, as a
# whole path: a worker names it in its own path and in every directory it is given, and so does
# anything else a suite started there. The root is compared as text, so no character in it is read
# as a pattern, and it counts only when what follows it ends the path. When the process list cannot
# be read, this fails rather than answer that nothing is running.
survivors() {
  local listing
  listing="$(ps -U "$(id -u)" -ww -o pid= -o command=)" || return 1
  printf '%s\n' "$listing" |
    ROOT="$run_root" RESOLVED="$run_root_resolved" SELF="$$" awk '
      function names(text, root,   at, next_char) {
        if (root == "") return 0
        while ((at = index(text, root)) > 0) {
          next_char = substr(text, at + length(root), 1)
          if (next_char == "" || next_char == "/" || next_char == " ") return 1
          text = substr(text, at + 1)
        }
        return 0
      }
      {
        pid = $1
        command = $0
        sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", command)
        if (pid != ENVIRON["SELF"] && (names(command, ENVIRON["ROOT"]) || names(command, ENVIRON["RESOLVED"]))) print pid
      }'
}

# However the run ends, having passed, failed part way, been interrupted or been told to stop, its
# root goes when nothing it started is running. Anything still running is not signalled from here:
# the list names processes by numbers, which another process could hold by the time a signal went.
# Each suite ends the workers it started by the means it holds, and what is left is reported, with
# the root kept for whoever looks.
finish() {
  local left
  if left="$(survivors)" && [ -z "$left" ]; then
    rm -rf "${run_root:?}"
  fi
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The check this script ends with: it fails when any process this run started, a worker above all,
# is still running once the suites are done, or when that cannot be established.
check_no_survivors() {
  local deadline left
  # Closure is a sequence (a grace period, a forced stop and a drain), so a worker that is on its
  # way out is given time to finish going rather than reported as a leak.
  deadline=$(( $(date +%s) + 60 ))
  while :; do
    if ! left="$(survivors)"; then
      echo "FAILED: the process list could not be read, so nothing this run started can be said to have ended"
      return 1
    fi
    if [ -z "$left" ]; then
      echo "no process this run started is still running"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      break
    fi
    sleep 1
  done
  echo "FAILED: these processes outlived the script; $run_root is kept"
  ps -o pid=,command= -p "$(printf '%s\n' "$left" | paste -sd, -)" || true
  return 1
}


# Each entry is "crate:test-binary  what it demonstrates".
suites=(
  "kr-worker:host|a daemon restart that keeps the shell, the session limit, a retried create token, and a closed session answering from the worker's own record"
  "kr-worker:terminal|the terminal-engine boundary: a query answered by the host, a screen drawn rather than history replayed, a projected terminal, and a side effect with one destination"
  "kr-worker:authority|controller fencing at dispatch, freshness windows, preconditions, and a fenced connection's subscription stopping"
  "kr-worker:receipts|the receipt transitions, de-duplication, the revalidation before the marker, the action window, the raw input stream and this machine's own time service"
  "kr-controller:barrier|a revocation announced while a worker is isolated, the dispatch lease, and a mutation whose admission lapses while it waits for a store lock"
  "kr-worker:backpressure|a client that stops reading is resynchronised and holds the read loop up for nobody"
  "kr-worker:session|a real shell, its closure, and the input lease"
  "kr-worker:fence|the root editor's fence over a real endpoint: the hold, the detach, the attribution and the launch transaction"
  "kr-controller:shell|which shell a create may launch, what it is labelled as, and the guarded startup entries"
  "kr-controller:contracts|the two contracts the transport names: a revocable registration and a durable commit that outlives its caller"
  "kr-controller:envelope|what the daemon accepts on its client endpoint"
  "kr-controller:project|real repositories through the daemon: a clone, an adoption, a workspace with its inclusion preview, a verified download into it, a daemon killed mid-clone whose destination is untouched, and the owner authorising a location and binding a repository to one under a fresh confirmation"
  "kr-controller:voice|the voice coordinator against a real daemon: a voice grant written into the host's own store, a call whose end revokes it while the session keeps running, an unlocked-screen action refused without a signed confirmation, and a voice method unreachable from local IPC"
  "kr-controller:changeset|real repositories through the daemon: an immutable version captured while the source keeps changing, an independent materialisation of it, a proposal that writes no working tree, a preflight conflict that writes nothing, and a mutation whose authority has gone that leaves no claim behind"
  "kr-cli:attach|a killed attachment restoring its terminal, and a detach from another window"
  "kr-cli:lifecycle|a session made with kr new: an agent's question answered from another window, a detach that leaves everything else running, a reattach drawn from the screen, and closure by the shell's exit, end of input, a crash and kr close, none of them restarted"
  "kr-controller:network|a device pairing over iroh and over a relay, attaching, subscribing from a cursor, typing under the input lease, reconnecting, being revoked mid-connection, and losing its path without taking the session with it"
)

# The network suite starts a worker process, and the only place it can look for one is beside its
# own binary. Building it first is what makes the suite run rather than say it could not.
echo "building the worker the suites launch"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build -p kr-worker --bin kr-worker
# The build is started once, now, and waited for, before any suite's deadline counts. The operating
# system checks a newly written executable the first time it starts, which on a loaded machine can
# take long enough to spend a create's rendezvous. The check is made again for every new copy, so
# each suite also starts its own copy once, before it times anything.
first_start=$SECONDS
"${CARGO_TARGET_DIR:-$root/target}/debug/kr-worker" --version >/dev/null
echo "the new worker's first start took $((SECONDS - first_start)) s"

failed=0
for entry in "${suites[@]}"; do
  target="${entry%%|*}"
  description="${entry#*|}"
  crate="${target%%:*}"
  suite="${target##*:}"
  echo
  echo "running $crate --test $suite"
  echo "  demonstrates: $description"
  # The network suite is ignored by default, because the binary it launches is built above rather
  # than by the package under test. Running it here is the whole point of this script. The flag is
  # a plain word rather than an array: this shell runs under `set -u`, where an empty array
  # expansion is an error on the version macOS ships.
  ignored=""
  if [ "$suite" = "network" ]; then
    ignored="--include-ignored"
  fi
  # shellcheck disable=SC2086
  if ! output="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test -p "$crate" --test "$suite" \
    -- --test-threads=1 $ignored 2>&1)"; then
    echo "$output"
    echo "FAILED: $crate --test $suite"
    failed=1
    continue
  fi
  echo "$output" | grep -E "^(test |test result)" || true
  if ! grep -qE "^test result: ok\. [1-9][0-9]* passed" <<<"$output"; then
    echo "$output"
    echo "FAILED: $crate --test $suite demonstrated nothing"
    failed=1
  fi
done

echo
if ! check_no_survivors; then
  failed=1
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "one or more demonstrations failed"
  exit 1
fi
echo "every demonstration passed"
