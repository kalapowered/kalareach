#!/usr/bin/env bash
# Reports where a hosted runner's disk goes, and how low it runs between two reports.
#
#   scripts/disk-report.sh begin <label>   report, then start sampling the free space
#   scripts/disk-report.sh step <label>    report, with the lowest free space since the last report
#   scripts/disk-report.sh end <label>     report, stop sampling, and list every interval's lowest
#
# A report prints the free space of the root, of the volume the workspace is on (where the target
# directory and the staging directories of the tests are) and of the temporary directory, and the
# size of what a build or a test run leaves on that volume: the target directory, Cargo's registry
# and Git checkouts, the pnpm store, Xcode's DerivedData, the simulators and their runtimes, and
# the temporary directories. `begin` adds the preinstalled software that takes the most room.
#
# The free space is sampled every two seconds into a file in the runner's temporary directory, from
# `begin` until `end`, because a figure read between two steps says nothing about the lowest point
# in one: a build writes its largest files while it runs. Each report names the lowest sample since
# the report before it, and the label of the report that ends each interval is the step or the
# steps the interval covers. The sampler is a process of this script, ended by the pid `begin`
# recorded.
#
# This reads and reports. It removes nothing, and it exits 0 whatever it could not read.

set -uo pipefail

mode="${1:-}"
label="${2:-}"
if [ -z "$mode" ] || [ -z "$label" ]; then
    echo "usage: disk-report.sh begin|step|end <label>" >&2
    exit 2
fi

state="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kr-disk-report"
samples="$state/samples"
pidfile="$state/sampler.pid"
interval=2

# The free space, in KiB, of the volume the current directory is on.
free_kib() {
    df -Pk . 2> /dev/null | awk 'NR == 2 { print $4 }'
}

# A size in KiB as GiB, or MiB below one GiB.
human() {
    awk -v kib="$1" 'BEGIN {
        if (kib >= 1048576) printf "%.1f GiB", kib / 1048576
        else printf "%.0f MiB", kib / 1024
    }'
}

# The size of what is at each path given, one line named by the label, or "absent".
size_of() {
    name="$1"
    shift
    total=0
    found=0
    for path in "$@"; do
        if [ -e "$path" ]; then
            kib="$(du -skx "$path" 2> /dev/null | awk '{ print $1 }')"
            total=$((total + ${kib:-0}))
            found=1
        fi
    done
    if [ "$found" -eq 1 ]; then
        printf '  %-34s %s\n' "$name" "$(human "$total")"
    else
        printf '  %-34s absent\n' "$name"
    fi
}

pnpm_store() {
    if command -v pnpm > /dev/null 2>&1; then
        pnpm store path 2> /dev/null && return
    fi
    echo "$HOME/Library/pnpm/store"
    echo "$HOME/.local/share/pnpm/store"
}

report() {
    echo "== disk: $label ($(date -u +%H:%M:%SZ))"
    df -h / 2> /dev/null
    df -h . 2> /dev/null | sed 1d
    if [ -n "${TMPDIR:-}" ]; then
        df -h "$TMPDIR" 2> /dev/null | sed 1d
    fi
    target="${CARGO_TARGET_DIR:-$PWD/target}"
    size_of "the target directory" "$target"
    size_of "Cargo's registry" "$HOME/.cargo/registry"
    size_of "Cargo's Git checkouts" "$HOME/.cargo/git"
    # shellcheck disable=SC2046 # one path to a line, and none has a space
    size_of "the pnpm store" $(pnpm_store)
    size_of "Xcode's DerivedData" "$HOME/Library/Developer/Xcode/DerivedData"
    size_of "the simulators' devices" "$HOME/Library/Developer/CoreSimulator"
    size_of "the simulators' runtimes" /System/Library/AssetsV2/com_apple_MobileAsset_*SimulatorRuntime
    size_of "the simulators' caches" /Library/Developer/CoreSimulator/Caches
    size_of "the temporary directory" "${TMPDIR:-/tmp}"
    size_of "/private/tmp" /private/tmp
    size_of "the test evidence" "${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
    if [ "$mode" = begin ]; then
        echo "  the preinstalled software that takes the most room:"
        size_of "  the Xcodes" /Applications/Xcode_*.app
        size_of "  the Android SDK" "$HOME/Library/Android"
        size_of "  .NET" "$HOME/.dotnet"
        size_of "  the hosted tool cache" "$HOME/hostedtoolcache"
        size_of "  Homebrew" /opt/homebrew
        size_of "  the browsers" "/Applications/Google Chrome.app" "/Applications/Firefox.app" \
            "/Applications/Microsoft Edge.app" "/Applications/Google Chrome for Testing.app"
        if command -v xcrun > /dev/null 2>&1; then
            xcrun simctl runtime list 2> /dev/null | sed -n '/^Total Disk Images/p' | sed 's/^/  runtimes: /'
        fi
    fi
}

# The lowest sample after the last mark, as "<KiB> <epoch>", or nothing without one.
lowest_since_mark() {
    [ -f "$samples" ] || return 0
    awk '
        $1 == "M" { low = ""; at = "" }
        $1 == "S" && (low == "" || $3 < low) { low = $3; at = $2 }
        END { if (low != "") print low, at }
    ' "$samples"
}

say_lowest() {
    read -r kib at <<< "$(lowest_since_mark)"
    if [ -z "${kib:-}" ]; then
        echo "  lowest free space since the last report: no samples"
        return
    fi
    when="$(date -u -r "$at" +%H:%M:%SZ 2> /dev/null || date -u -d "@$at" +%H:%M:%SZ 2> /dev/null)"
    echo "  lowest free space since the last report: $(human "$kib") at ${when:-$at}"
}

mark() {
    mkdir -p "$state"
    printf 'M %s %s\n' "$(date +%s)" "$label" >> "$samples"
}

# The interval each report ended, with the lowest free space in it, and the free space through the
# run at ten-minute spacing, so that a step's place in the run can be read against the log's times.
list_intervals() {
    [ -f "$samples" ] || return 0
    echo "  the lowest free space in each interval:"
    awk '
        function human(kib) {
            if (kib >= 1048576) return sprintf("%.1f GiB", kib / 1048576)
            return sprintf("%.0f MiB", kib / 1024)
        }
        $1 == "S" && (low == "" || $3 < low) { low = $3 }
        $1 == "M" {
            name = $0
            sub(/^M [0-9]+ /, "", name)
            if (low != "") printf "    %-10s %s\n", human(low), name
            if (low != "" && (all == "" || low < all)) all = low
            low = ""
        }
        END { if (all != "") printf "  the lowest of all: %s\n", human(all) }
    ' "$samples"
    echo "  the free space every ten minutes (UTC):"
    awk '
        function human(kib) {
            if (kib >= 1048576) return sprintf("%.1f GiB", kib / 1048576)
            return sprintf("%.0f MiB", kib / 1024)
        }
        $1 == "S" && (last == "" || $2 - last >= 600) {
            last = $2
            printf "%s %s\n", $2, human($3)
        }
    ' "$samples" | while read -r at free; do
        printf '    %s  %s\n' "$(date -u -r "$at" +%H:%M:%S 2> /dev/null || date -u -d "@$at" +%H:%M:%S 2> /dev/null)" "$free"
    done
}

case "$mode" in
    begin)
        mkdir -p "$state"
        : > "$samples"
        report
        nohup bash "$0" sample sampler < /dev/null > /dev/null 2>&1 &
        echo "$!" > "$pidfile"
        disown 2> /dev/null || true
        mark
        ;;
    step)
        report
        say_lowest
        mark
        ;;
    end)
        report
        say_lowest
        mark
        if [ -f "$pidfile" ]; then
            kill "$(cat "$pidfile")" 2> /dev/null || true
            rm -f "$pidfile"
        fi
        list_intervals
        ;;
    sample)
        while :; do
            printf 'S %s %s\n' "$(date +%s)" "$(free_kib)" >> "$samples"
            sleep "$interval"
        done
        ;;
    *)
        echo "disk-report: unknown mode $mode" >&2
        exit 2
        ;;
esac
exit 0
