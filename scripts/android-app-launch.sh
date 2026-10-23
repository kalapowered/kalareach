#!/usr/bin/env bash
# Installs the debug Android application on a running device, starts it, and shows that it runs.
#
#   scripts/android-app-launch.sh <the .apk> <screenshot.png> [--serial <adb serial>]
#
# A build that packages the application says nothing of whether the phone can start it: a library
# that does not load, a plugin the system cannot instantiate and a page that never opens all leave a
# green build. This holds, one condition at a time, that on the device
#
#   * the application installs and its main activity starts;
#   * the application's process is running with native code mapped from its package, which is the
#     Rust library (libcompanion_tauri.so): the package stores it uncompressed and the system maps
#     it from there, so its mapping is named for the package and not for the library;
#   * the web view has opened its debugging socket and lists a page with a title that the
#     application's own protocol served (tauri.localhost), which is the interface's document
#     loaded by the Rust shell;
#   * the screen shows the page: below the status bar it is more than a blank field;
#   * the system logged no fatal exception for the application;
#
# and then saves a screenshot of the screen to the path given. Each wait ends when its condition
# holds; the deadline (KR_LAUNCH_DEADLINE, 240 seconds) only ends a step that is hung, and the
# message names the condition. The device is the caller's: it is not started or stopped here, and the
# application is uninstalled when this ends.
#
# It needs `adb` (on PATH, or under ANDROID_HOME) and `python3` and `curl`. The debug application is
# debuggable, which is what lets `run-as` read its process's maps on a device whose build is a user
# build, such as one with Google Play. Exit status: 0 when every condition held, 1 when one did not,
# 2 for a usage or environment fault.

set -uo pipefail

package=to.kala.reach
activity="$package/.MainActivity"
deadline="${KR_LAUNCH_DEADLINE:-240}"

die() {
    printf 'android-app-launch: %s\n' "$*" >&2
    exit 2
}
say() { printf 'android-app-launch: %s\n' "$*"; }

apk="${1:-}"
screenshot="${2:-}"
[ -f "$apk" ] && [ -n "$screenshot" ] || die "usage: android-app-launch.sh <the .apk> <screenshot.png> [--serial <serial>]"
shift 2
serial="${ANDROID_SERIAL:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --serial)
            serial="${2:?--serial needs a value}"
            shift 2
            ;;
        *) die "unknown argument $1" ;;
    esac
done

if command -v adb > /dev/null 2>&1; then
    adb="$(command -v adb)"
elif [ -x "${ANDROID_HOME:-/nonexistent}/platform-tools/adb" ]; then
    adb="$ANDROID_HOME/platform-tools/adb"
else
    die "adb is not on the path and ANDROID_HOME names none"
fi
for tool in python3 curl; do
    command -v "$tool" > /dev/null 2>&1 || die "$tool is needed and is not on the path"
done
if [ -z "$serial" ]; then
    serial="$("$adb" devices | awk '$2 == "device" { print $1; exit }')"
fi
[ -n "$serial" ] || die "no Android device is running"

dev() { "$adb" -s "$serial" "$@"; }

installed=0
forwarded=""
cleanup() {
    [ -z "$forwarded" ] || dev forward --remove "tcp:$forwarded" > /dev/null 2>&1 || true
    [ "$installed" -eq 0 ] || dev uninstall "$package" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Waits until `$2` (a command line) succeeds, or fails the run naming `$1` after the deadline.
wait_for() {
    local what=$1 started
    shift
    started=$(date +%s)
    until "$@"; do
        if [ $(($(date +%s) - started)) -gt "$deadline" ]; then
            printf 'android-app-launch: FAIL: gave up waiting for %s\n' "$what" >&2
            exit 1
        fi
        sleep 1
    done
    say "ok: $what"
}

booted() { [ "$(dev shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; }
wait_for "the device to finish starting" booted
say "device: $serial, API $(dev shell getprop ro.build.version.sdk | tr -d '\r'), $(dev shell getprop ro.product.cpu.abilist | tr -d '\r')"

dev uninstall "$package" > /dev/null 2>&1 || true
dev install -r "$apk" > /dev/null || { echo "android-app-launch: FAIL: the application did not install" >&2; exit 1; }
installed=1
say "ok: the application installed"

dev logcat -b all -c
started="$(dev shell am start -W -n "$activity" | tr -d '\r')"
grep -q '^Status: ok' <<< "$started" || { printf 'android-app-launch: FAIL: the main activity did not start:\n%s\n' "$started" >&2; exit 1; }
say "ok: the main activity started"

pid=""
running() {
    pid="$(dev shell pidof "$package" 2> /dev/null | tr -d '\r' | awk '{ print $1 }')"
    [ -n "$pid" ]
}
wait_for "the application's process" running

# At least a mebibyte of the package mapped as code.
native_code_mapped() {
    dev shell "run-as $package cat /proc/$pid/maps" 2> /dev/null | tr -d '\r' | python3 -c '
import sys

total = 0
for line in sys.stdin:
    fields = line.split()
    if len(fields) >= 6 and fields[1] == "r-xp" and fields[5].endswith("/base.apk"):
        start, end = fields[0].split("-")
        total += int(end, 16) - int(start, 16)
sys.exit(0 if total >= 1 << 20 else 1)
'
}
wait_for "native code of the package to be mapped into process $pid" native_code_mapped

# The web view's debugging socket is named for the process; forwarding it reaches the page list.
port=$((9400 + pid % 500))
socket=""
socket_open() {
    socket="$(dev shell cat /proc/net/unix 2> /dev/null | tr -d '\r' | awk '{ print $NF }' | grep "^@webview_devtools_remote_$pid" | head -n 1)"
    [ -n "$socket" ]
}
wait_for "the web view to open its debugging socket" socket_open
dev forward "tcp:$port" "localabstract:${socket#@}" > /dev/null || die "the web view's socket could not be forwarded"
forwarded="$port"

title=""
page_has_title() {
    title="$(curl -fsS --max-time 5 "http://127.0.0.1:$port/json" 2> /dev/null | python3 -c '
import json
import sys

try:
    pages = [entry for entry in json.load(sys.stdin) if entry.get("type") == "page"]
except ValueError:
    pages = []
for page in pages:
    if page.get("title") not in (None, "", "tauri.localhost") and "://tauri.localhost" in page.get("url", ""):
        print(page["title"])
        break
')"
    [ -n "$title" ]
}
wait_for "the web view to list a page with a title, served by the application's own protocol" page_has_title
say "page title: $title"

# The device's screen as the raw pixels `screencap` writes: a small header and then four bytes a
# pixel. The page is drawn when more than half a percent of the sampled pixels below the status bar
# differ from the colour that covers most of them.
screen_shows_the_page() {
    dev exec-out screencap 2> /dev/null | python3 -I -c '
import collections
import struct
import sys

data = sys.stdin.buffer.read()
if len(data) < 16:
    sys.exit(1)
width, height = struct.unpack_from("<II", data, 0)
header = len(data) - width * height * 4
if header not in (12, 16) or width == 0 or height == 0:
    sys.exit(1)
sampled = []
for row in range(height * 12 // 100, height, 4):
    start = header + row * width * 4
    line = data[start : start + width * 4]
    sampled.extend(line[i : i + 3] for i in range(0, len(line), 16))
common = collections.Counter(sampled).most_common(1)[0][0]
different = sum(1 for pixel in sampled if max(abs(a - b) for a, b in zip(pixel, common)) > 30)
sys.exit(0 if different * 200 > len(sampled) else 1)
'
}
wait_for "the screen to show the page" screen_shows_the_page

log="$(dev logcat -d -b all 2> /dev/null | tr -d '\r')"
if grep -E -q 'FATAL EXCEPTION|Fatal signal' <<< "$log"; then
    echo "android-app-launch: FAIL: the system logged a fatal exception or signal:" >&2
    grep -E -A8 'FATAL EXCEPTION|Fatal signal' <<< "$log" | head -40 >&2
    exit 1
fi
say "ok: no fatal exception or signal in the log"
running || { echo "android-app-launch: FAIL: the application's process ended before the screenshot" >&2; exit 1; }

mkdir -p "$(dirname "$screenshot")"
dev exec-out screencap -p > "$screenshot"
[ "$(head -c 8 "$screenshot" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || { echo "android-app-launch: FAIL: the screenshot is not a PNG image" >&2; exit 1; }
say "screenshot: $screenshot ($(wc -c < "$screenshot" | tr -d ' ') bytes)"
