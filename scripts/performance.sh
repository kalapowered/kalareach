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

measurement attach_to_a_usable_screen
measurement idle_resources_for_twenty_sessions_and_thirty_two_views

echo
echo "all measurements met their bounds"
