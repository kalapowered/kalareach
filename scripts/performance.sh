#!/usr/bin/env bash
# Measures the two performance requirements the host answers for, in a release build.
#
# KR-PERF-003 is a five-minute average, so this script takes five minutes. KR-PERF-004 is measured
# from the connection to a screen a terminal can draw, not to the first byte on the wire.
#
# Every step is checked. A build that fails, a measurement that produces no samples, or a
# measurement that misses its bound all end this script with a non-zero status, because a
# performance script that exits zero without measuring anything is worse than no script.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

echo "kalareach performance measurements"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo
# Nothing this script started may outlive it. A worker is deliberately not a child of whatever
# created it, which is what makes a session survive a control daemon's restart, so a suite that
# failed to close a session leaves a worker running until the machine is restarted. The processes
# running before this script are recorded, and anything of ours that is running afterwards and was
# not is a leak this script fails on rather than leaves behind.
host_processes() {
  # Matched by executable name rather than by command line, so a build or a test runner that
  # merely names a crate is not mistaken for a host process, and neither is another checkout's.
  pgrep -u "$(id -u)" -x 'kr-worker|kr-controller' 2>/dev/null | sort || true
}

check_no_survivors() {
  local before="$1" deadline survivors
  # Closure is a sequence (a grace period, a forced stop and a drain), so a worker that is on its
  # way out is given time to finish going rather than reported as a leak.
  deadline=$(( $(date +%s) + 60 ))
  while :; do
    survivors="$(comm -13 <(printf '%s\n' "$before") <(host_processes))"
    if [ -z "$survivors" ]; then
      echo "no worker or daemon this script started is still running"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      break
    fi
    sleep 1
  done
  echo "FAILED: these processes outlived the script"
  # shellcheck disable=SC2086
  ps -o pid=,command= -p $(printf '%s' "$survivors" | tr '\n' ' ') || true
  return 1
}

before_processes="$(host_processes)"


# A release build, because the requirements are about the product rather than about a build with
# every check compiled into it.
echo "building the release profile"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build --release --workspace

measurement() {
  local name="$1"
  echo
  echo "running $name"
  local output
  # The measurement prints its own conditions. `--nocapture` is what lets them reach this log.
  if ! output="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test --release -p kr-worker \
    --test performance -- --ignored --exact --nocapture "$name" 2>&1)"; then
    echo "$output"
    echo "FAILED: $name did not meet its bound"
    return 1
  fi
  echo "$output"
  if ! grep -q "measurement" <<<"$output"; then
    echo "FAILED: $name produced no measurement"
    return 1
  fi
  if ! grep -qE "^test result: ok\. 1 passed" <<<"$output"; then
    echo "FAILED: $name did not run"
    return 1
  fi
}

failed=0
measurement attach_to_a_usable_screen || failed=1
measurement idle_resources_for_twenty_sessions_and_thirty_two_views || failed=1

echo
if ! check_no_survivors "$before_processes"; then
  failed=1
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "one or more measurements failed"
  exit 1
fi
echo "all measurements met their bounds"
