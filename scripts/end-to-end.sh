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
echo

# Each entry is "crate:test-binary  what it demonstrates".
suites=(
  "kr-worker:host|a daemon restart that keeps the shell, the session limit, a retried create token, and a closed session answering from the worker's own record"
  "kr-worker:terminal|the terminal-engine boundary: a query answered by the host, a screen drawn rather than history replayed, a projected terminal, and a side effect with one destination"
  "kr-worker:authority|controller fencing at dispatch, freshness windows, preconditions, and a fenced connection's subscription stopping"
  "kr-worker:backpressure|a client that stops reading is resynchronised and holds the read loop up for nobody"
  "kr-worker:session|a real shell, its closure, and the input lease"
  "kr-controller:contracts|the two contracts the transport names: a revocable registration and a durable commit that outlives its caller"
  "kr-controller:envelope|what the daemon accepts on its client endpoint"
  "kr-cli:attach|a killed attachment restoring its terminal, and a detach from another window"
)

failed=0
for entry in "${suites[@]}"; do
  target="${entry%%|*}"
  description="${entry#*|}"
  crate="${target%%:*}"
  suite="${target##*:}"
  echo
  echo "running $crate --test $suite"
  echo "  demonstrates: $description"
  if ! output="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test -p "$crate" --test "$suite" \
    -- --test-threads=1 2>&1)"; then
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
if [ "$failed" -ne 0 ]; then
  echo "one or more demonstrations failed"
  exit 1
fi
echo "every demonstration passed"
