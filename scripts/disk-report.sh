#!/usr/bin/env bash
# Reports where a hosted runner's disk goes, and how low it runs between two reports.
#
#   scripts/disk-report.sh begin <label>    report, then start sampling the free space
#   scripts/disk-report.sh step <label>     report, with the lowest free space since the last report
#   scripts/disk-report.sh end <label>      stop sampling, report, and list every interval's lowest
#   scripts/disk-report.sh report <label>   report alone, with no sampling
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
# steps the interval covers. The sampler is one Python process that wakes to read the volume's free
# space and sleeps again, so it starts no other program; `end` stops it by a stop file that it
# reads at each wake, and signals no process. A measurement that asserts on an idle host is
# preceded by `end` and followed by `report`.
#
# On a hosted macOS runner `end` also reads the kernel's log for the lines that say a write to the
# data volume failed, from the first sample to now, and keeps them in `disk-faults.txt` in the
# test evidence directory. The volume has returned I/O errors in bursts while a build ran, and a
# program the linker wrote in a burst cannot be started: these lines are what says so.
#
# This reads and reports. It removes nothing and signals no process, and it exits 0 whatever it
# could not read, including a disk with no room left to write the samples to.

set -uo pipefail

mode="${1:-}"
label="${2:-}"
if [ -z "$mode" ] || [ -z "$label" ]; then
    echo "usage: disk-report.sh begin|step|end|report <label>" >&2
    exit 2
fi

state="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kr-disk-report"
samples="$state/samples"
tokenfile="$state/sampler.token"
stopfile="$state/sampler.stop"
interval=2

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
    fi
}

# The sampler: one process that reads the free space of the volume it was started in and sleeps.
# A write that fails, on a disk with no room, is skipped and tried again at the next wake. At each
# wake it reads the stop file, and it ends, after one last line `E <time>` in the samples, when
# the file holds the token it was started with. A sampler that an earlier `begin` left running has
# another token and is told to end by the stop file that `begin` writes first.
start_sampler() {
    if ! command -v python3 > /dev/null 2>&1; then
        echo "  no sampling: python3 is not installed"
        return
    fi
    token="$$.$(date +%s).$RANDOM"
    printf '%s\n' "$token" > "$tokenfile" 2> /dev/null || return
    python3 -I -c '
# kr-disk-sampler
import os
import sys
import time

path, interval, stop, token = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
while True:
    try:
        with open(stop) as told:
            if told.read().strip() == token:
                break
    except OSError:
        pass
    try:
        volume = os.statvfs(".")
        with open(path, "a") as samples:
            samples.write("S %d %d\n" % (time.time(), volume.f_bavail * volume.f_frsize // 1024))
    except OSError:
        pass
    time.sleep(interval)
try:
    with open(path, "a") as samples:
        samples.write("E %d\n" % time.time())
except OSError:
    pass
' "$samples" "$interval" "$stopfile" "$token" < /dev/null > /dev/null 2>&1 &
    disown 2> /dev/null || true
}

# Tells the sampler this script started to end, by writing its token to the stop file, and waits
# a few seconds for the line it ends with. No process is signalled, so no process number is read
# or held, and a process that has another number's place is not touched.
stop_sampler() {
    [ -f "$tokenfile" ] || return 0
    cat "$tokenfile" > "$stopfile" 2> /dev/null || return 0
    waited=0
    while [ "$waited" -lt 10 ] && ! grep -q '^E ' "$samples" 2> /dev/null; do
        sleep 0.5
        waited=$((waited + 1))
    done
}

# The lowest sample after the last mark, as "<KiB> <epoch>", or nothing without one.
lowest_since_mark() {
    [ -f "$samples" ] || return 0
    awk '
        $1 == "M" { low = ""; at = "" }
        $1 == "S" && NF == 3 && (low == "" || $3 + 0 < low + 0) { low = $3; at = $2 }
        END { if (low != "") print low, at }
    ' "$samples"
}

say_lowest() {
    # shellcheck disable=SC2046 # two numbers, or nothing
    set -- $(lowest_since_mark)
    if [ "$#" -lt 2 ]; then
        echo "  lowest free space since the last report: no samples"
        return
    fi
    when="$(date -u -r "$2" +%H:%M:%SZ 2> /dev/null || date -u -d "@$2" +%H:%M:%SZ 2> /dev/null)"
    echo "  lowest free space since the last report: $(human "$1") at ${when:-$2}"
}

mark() {
    mkdir -p "$state" 2> /dev/null
    printf 'M %s %s\n' "$(date +%s)" "$label" 2> /dev/null >> "$samples" || true
}

# The interval each report ended, with the lowest free space in it, then any samples taken after
# the last report (which a report that could not write its mark leaves), and the free space through
# the run at ten-minute spacing, so that a step's place in the run can be read against the log's
# times.
list_intervals() {
    [ -f "$samples" ] || return 0
    echo "  the lowest free space in each interval:"
    awk '
        function human(kib) {
            if (kib >= 1048576) return sprintf("%.1f GiB", kib / 1048576)
            return sprintf("%.0f MiB", kib / 1024)
        }
        function close_interval(name) {
            if (low != "") printf "    %-10s %s\n", human(low), name
            if (low != "" && (all == "" || low + 0 < all + 0)) all = low
            low = ""
        }
        $1 == "S" && NF == 3 && (low == "" || $3 + 0 < low + 0) { low = $3 }
        $1 == "M" {
            name = $0
            sub(/^M [0-9]+ /, "", name)
            close_interval(name)
        }
        END {
            close_interval("after the last report")
            if (all != "") printf "  the lowest of all: %s\n", human(all)
        }
    ' "$samples"
    echo "  the free space every ten minutes (UTC):"
    awk '
        function human(kib) {
            if (kib >= 1048576) return sprintf("%.1f GiB", kib / 1048576)
            return sprintf("%.0f MiB", kib / 1024)
        }
        $1 == "S" && NF == 3 && (last == "" || $2 - last >= 600) {
            last = $2
            printf "%s %s\n", $2, human($3)
        }
    ' "$samples" | while read -r at free; do
        printf '    %s  %s\n' "$(date -u -r "$at" +%H:%M:%S 2> /dev/null || date -u -d "@$at" +%H:%M:%S 2> /dev/null)" "$free"
    done
}

# Runs a command whose output goes to a file, with a limit on its time that it carries itself: the
# program that starts it sets its own alarm and then becomes the command, so the alarm outlives the
# change and nobody signals the command from outside. The words before `--` run that program (for
# example `sudo -n`, so that the alarm is the root process's own). The status is the command's, or
# 142 when the alarm ended it.
# alarmed <seconds> <file> [<prefix word>...] -- <command word>...
alarmed() {
    limit="$1"
    out="$2"
    shift 2
    prefix=()
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
        prefix+=("$1")
        shift
    done
    shift
    "${prefix[@]+"${prefix[@]}"}" /usr/bin/perl -e 'alarm shift; exec @ARGV or exit 127' "$limit" "$@" > "$out" 2> /dev/null
}

# The kernel's lines about a write to storage that failed, from the first sample to now, on a
# hosted macOS runner. The log is read as root where the runner allows it (`sudo -n`, which never
# asks for a password) and the read ends by itself after 90 seconds.
kernel_storage_errors() {
    [ "$(uname -s)" = Darwin ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || return 0
    first="$(awk '$1 == "S" { print $2; exit }' "$samples" 2> /dev/null)"
    [ -n "${first:-}" ] || return 0
    minutes=$((($(date +%s) - first) / 60 + 2))
    out="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/disk-faults.txt"
    mkdir -p "$(dirname "$out")" 2> /dev/null
    predicate='process == "kernel" AND (eventMessage CONTAINS "I/O error" OR eventMessage CONTAINS "cluster_pageout" OR eventMessage CONTAINS "cluster_push() failed" OR eventMessage CONTAINS "trim_list failed")'
    read_ok=0
    for attempt in sudo plain; do
        if [ "$attempt" = sudo ]; then
            # the redirect is in alarmed, so the runner's own shell writes the file, in its directory
            alarmed 90 "$out" sudo -n -- /usr/bin/log show --last "${minutes}m" --style compact --predicate "$predicate"
        else
            alarmed 90 "$out" -- /usr/bin/log show --last "${minutes}m" --style compact --predicate "$predicate"
        fi
        status=$?
        if [ "$status" -eq 142 ]; then
            echo "  the kernel's log was not read in 90 seconds"
            return 0
        fi
        if [ "$status" -eq 0 ]; then
            read_ok=1
            break
        fi
    done
    if [ "$read_ok" -ne 1 ]; then
        echo "  the kernel's log could not be read"
        return 0
    fi
    count="$(grep -c 'kernel\[' "$out" || true)"
    if [ "${count:-0}" -eq 0 ]; then
        echo "  the kernel logged no storage error since the job began"
    else
        echo "  the kernel logged $count storage error lines since the job began, from $(grep 'kernel\[' "$out" | sed -n '1p' | cut -c1-19) to $(grep 'kernel\[' "$out" | sed -n '$p' | cut -c1-19) (kept in disk-faults.txt)"
    fi
}

# A shell that sources this file gets the functions and nothing is run.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

case "$mode" in
    begin)
        mkdir -p "$state" 2> /dev/null
        stop_sampler
        : > "$samples"
        report
        mark
        start_sampler
        ;;
    step)
        report
        say_lowest
        mark
        ;;
    end)
        stop_sampler
        report
        say_lowest
        mark
        list_intervals
        kernel_storage_errors
        ;;
    report)
        report
        ;;
    *)
        echo "disk-report: unknown mode $mode" >&2
        exit 2
        ;;
esac
exit 0
