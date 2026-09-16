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

# What the machine is, and what else it is doing. A resource figure is about a machine under
# conditions, so a run that does not record them cannot be compared with the next one, and a
# processor average taken while the machine was busy with something else is not the same
# measurement as one taken while it was quiet.
processors() {
  sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo unknown
}

processor_name() {
  sysctl -n machdep.cpu.brand_string 2>/dev/null ||
    sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1 ||
    echo unknown
}

power_mode() {
  local mode="" supply=""
  if command -v pmset > /dev/null 2>&1; then
    mode="$(pmset -g 2>/dev/null | awk '/^[[:space:]]*powermode/ { print $2; exit }')" || true
    supply="$(pmset -g batt 2>/dev/null | sed -n "s/Now drawing from '\(.*\)'/\1/p")" || true
    printf 'powermode %s, %s' "${mode:-unknown}" "${supply:-unknown}"
  elif [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    printf 'governor %s' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
  else
    printf 'unknown'
  fi
}

load_average() {
  if [ -r /proc/loadavg ]; then
    cut -d' ' -f1-3 /proc/loadavg
  else
    sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{ print $1, $2, $3 }' || echo unknown
  fi
}

echo "kalareach performance measurements"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  processors: $(processors) logical, $(processor_name)"
echo "  power: $(power_mode)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo
# Nothing this script started may outlive it. A worker is deliberately not a child of whatever
# created it, which is what makes a session survive a control daemon's restart, so a suite that
# failed to close a session leaves a worker running until the machine is restarted.
#
# This run gets a temporary root of its own and every process it starts lives under it: the suites
# put their runtime directories, state directories and copied binaries there, so a process whose
# command line names that root is one of ours and nothing else is. That is what makes the check
# below an answer about this run rather than about whatever else the machine happens to be doing.
run_root="$(mktemp -d "${TMPDIR:-/tmp}/kalareach-run.XXXXXX")"
export TMPDIR="$run_root"

survivors() {
  pgrep -u "$(id -u)" -f "$run_root" 2>/dev/null | grep -v "^$$\$" || true
}

check_no_survivors() {
  local deadline left
  # Closure is a sequence (a grace period, a forced stop and a drain), so a worker that is on its
  # way out is given time to finish going rather than reported as a leak.
  deadline=$(( $(date +%s) + 60 ))
  while :; do
    left="$(survivors)"
    if [ -z "$left" ]; then
      echo "no process this run started is still running"
      rm -rf "$run_root"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      break
    fi
    sleep 1
  done
  echo "FAILED: these processes outlived the script"
  # shellcheck disable=SC2086
  ps -o pid=,command= -p $(printf '%s' "$left" | tr '\n' ' ') || true
  return 1
}


# A release build, because the requirements are about the product rather than about a build with
# every check compiled into it.
echo "building the release profile"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build --release --workspace

# Runs one measurement out of a named target.
#
# The target matters: the resource and attach measurements live beside the suite that closes the
# sessions they create, and the two input measurements live in their own target, because what they
# measure is one keystroke's path rather than a whole host's footprint.
measurement_in() {
  local target_flag="$1" target="$2" name="$3"
  echo
  echo "running $name"
  # The load at each edge of the measurement, so a figure can be read against what else the machine
  # was doing while it was taken.
  echo "  load average entering this measurement: $(load_average)"
  local output
  # The measurement prints its own conditions. `--nocapture` is what lets them reach this log.
  if ! output="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test --release -p kr-worker \
    "$target_flag" "$target" -- --ignored --exact --nocapture "$name" 2>&1)"; then
    echo "$output"
    echo "  load average leaving this measurement: $(load_average)"
    echo "FAILED: $name did not meet its bound"
    return 1
  fi
  echo "$output"
  echo "  load average leaving this measurement: $(load_average)"
  if ! grep -q "measurement" <<<"$output"; then
    echo "FAILED: $name produced no measurement"
    return 1
  fi
  if ! grep -qE "^test result: ok\. 1 passed" <<<"$output"; then
    echo "FAILED: $name did not run"
    return 1
  fi
}

measurement() {
  measurement_in --test performance "$1"
}

input_measurement() {
  measurement_in --bench input_latency "$1"
}

failed=0

# The suite's own regressions, before the measurements. What closes the sessions a run creates is
# code like any other, and this is the script that owns this suite: `cargo test --workspace` stops
# at the failing upstream suite before it and nothing else runs it.
echo
echo "running the measurement suite's own regressions"
if ! regressions="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test --release -p kr-worker \
  --test performance 2>&1)"; then
  echo "$regressions"
  echo "FAILED: the measurement suite's own regressions"
  failed=1
elif ! grep -qE "^test result: ok\. [1-9]" <<<"$regressions"; then
  echo "$regressions"
  echo "FAILED: the measurement suite ran no regression"
  failed=1
else
  grep -E "^test " <<<"$regressions" || true
fi

# The input measurements' own regressions, for the same reason: the percentile helper and the root
# programs each measurement needs are code, and nothing else runs them.
echo
echo "running the input measurements' own regressions"
if ! regressions="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test --release -p kr-worker \
  --bench input_latency 2>&1)"; then
  echo "$regressions"
  echo "FAILED: the input measurements' own regressions"
  failed=1
elif ! grep -qE "^test result: ok\. [1-9]" <<<"$regressions"; then
  echo "$regressions"
  echo "FAILED: the input measurements ran no regression"
  failed=1
else
  grep -E "^test " <<<"$regressions" || true
fi

measurement attach_to_a_usable_screen || failed=1
input_measurement added_input_forwarding_latency || failed=1
input_measurement paste_prefix_recogniser_deadline || failed=1
measurement idle_resources_for_twenty_sessions_and_thirty_two_views || failed=1

echo
if ! check_no_survivors; then
  failed=1
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "one or more measurements failed"
  exit 1
fi
echo "all measurements met their bounds"
