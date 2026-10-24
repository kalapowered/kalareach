#!/usr/bin/env bash
# Installs the debug Android application on a running device, starts it, and shows that it runs.
#
#   scripts/android-app-launch.sh <the .apk> <screenshot.png> --serial <adb serial>
#
# A build that packages the application says nothing of whether the phone can start it: a library
# that does not load, a plugin the system cannot instantiate and a page that never opens all leave a
# green build. This holds, one condition at a time, that on the device
#
#   * the application installs and its main activity starts;
#   * the application's process is running with native code mapped from its package, which is the
#     Rust library (libcompanion_tauri.so): the package stores it uncompressed and the system maps
#     it from there, so its mapping is named for the package and not for the library;
#   * the web view has opened its debugging socket and lists the interface's own document, titled
#     as the interface titles it (KalaReach), which the application's own protocol served
#     (tauri.localhost) and the Rust shell loaded: an error page or a blank document has another
#     title or another address;
#   * the interface has mounted: the document's root, which index.html leaves empty, holds what the
#     interface's script drew, and the page has text on it, read over the web view's debugging
#     protocol;
#   * the screen shows the page: below the status bar it is more than a blank field;
#   * the system logged no fatal exception or signal for the application's own process (a crash of
#     another process of the device is not looked for), and the process is still the one that was
#     started;
#
# and saves a screenshot of the screen to the path given: the very frame that was found to show the
# page, so it is taken while that condition holds and not after other checks. Each wait ends when its
# condition holds; the deadline (KR_LAUNCH_DEADLINE, 240 seconds) only ends a step that is hung, and
# the message names the condition. A process that ends is not waited out: once the application has a
# process, every wait stops when that process is found gone and says how it ended, from the device's
# log (a crash, or a device short of memory that kills the application's web view renderer or the
# application itself). The device is named by its serial (--serial, or ANDROID_SERIAL), never taken
# for being the first one listed: it is the caller's, it is not started or stopped here, a copy of
# the application already on it is uninstalled first, with its data, and the application is
# uninstalled again when this ends.
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
[ -f "$apk" ] && [ -n "$screenshot" ] || die "usage: android-app-launch.sh <the .apk> <screenshot.png> --serial <serial>"
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
[ -n "$serial" ] || die "android needs --serial (or ANDROID_SERIAL), the serial of the device to run on: no device is taken for being the first listed"
case "$("$adb" devices | awk -v serial="$serial" '$1 == serial { print $2 }')" in
    device) ;;
    *) die "no Android device with the serial $serial is running" ;;
esac

dev() { "$adb" -s "$serial" "$@"; }

installed=0
forwarded=""
cleanup() {
    [ -z "$forwarded" ] || dev forward --remove "tcp:$forwarded" > /dev/null 2>&1 || true
    [ "$installed" -eq 0 ] || dev uninstall "$package" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# The application's process, once it has one: every wait after that is held to it.
watched=""

application_runs() {
    local pids
    pids="$(dev shell pidof "$package" 2> /dev/null | tr -d '\r')"
    case " $pids " in
        *" $watched "*) return 0 ;;
    esac
    return 1
}

# True when the process being watched is gone. One look that fails is looked at again after a
# second, since a call of adb that fails is not the end of a process.
application_has_ended() {
    [ -n "$watched" ] || return 1
    application_runs && return 1
    sleep 1
    ! application_runs
}

# What the device has to spare: a device that is short of memory ends the application's processes,
# which is how this check has failed on a hosted runner.
device_memory() {
    printf 'device memory: %s' "$(dev shell cat /proc/meminfo 2> /dev/null | tr -d '\r' | awk '/^(MemTotal|MemAvailable):/ { printf "%s %d MiB  ", $1, $2 / 1024 }')"
}

# Reads the device's log for how the process `$1` of the package `$2` ended, and says it.
IFS= read -r -d '' ended_program << 'PYTHON' || true
import re
import sys

pid, package = sys.argv[1], sys.argv[2]
lines = sys.stdin.read().splitlines()
# The renderer processes of the application's own web view, which it names when one is lost.
renderers = set()
for line in lines:
    fields = line.split(None, 5)
    if len(fields) == 6 and fields[2] == pid and ("aw_browser_terminator" in line or "onServiceDisconnected" in line):
        named = re.search(r"[Rr]ender(?:er)? process \((\d+)\)|pid=(\d+)", line)
        if named:
            renderers.add(named.group(1) or named.group(2))
crashed = application_killed = renderer_killed = renderer_lost = ended_from_outside = False
evidence = []
for number, line in enumerate(lines):
    fields = line.split(None, 5)
    if len(fields) < 6:
        continue
    kill = re.search(r"lowmemorykiller: Kill '[^']*' \((\d+)\)", line)
    if "FATAL EXCEPTION" in line and any("Process: " + package + ", PID: " + pid in near for near in lines[number : number + 6]):
        crashed = True
        evidence.extend(lines[number : number + 8])
    elif "Fatal signal" in line and "pid " + pid + " (" + package + ")" in line:
        crashed = True
        evidence.append(line)
    elif kill and kill.group(1) == pid:
        application_killed = True
        evidence.append(line)
    elif kill and kill.group(1) in renderers:
        renderer_killed = True
        evidence.append(line)
    elif fields[2] == pid and ("aw_browser_terminator" in line or "onServiceDisconnected" in line):
        renderer_lost = renderer_lost or "killing application" in line
        evidence.append(line)
    elif re.search(r"Process " + pid + r" exited due to signal \d+", line) or (
        "ActivityManager" in line and "Process " + package + " (pid " + pid + ") has died" in line
    ):
        ended_from_outside = True
        evidence.append(line)
if crashed:
    print("the application crashed: the system logged a fatal exception or signal for it")
elif application_killed:
    print("the low-memory killer of the system ended the application: the device is short of memory")
elif renderer_killed and renderer_lost:
    print("the low-memory killer of the system ended the renderer of the web view and the web view then ended the application: the device is short of memory")
elif renderer_lost:
    print("the web view lost its renderer process and ended the application with it")
elif ended_from_outside:
    print("the process was ended from outside, and the log names no reason")
else:
    print("the log names no reason")
for line in evidence[:14]:
    print("    " + line.strip()[:200])
PYTHON

# Fails the run because the watched process ended `$1` (a phrase that says when), with how it ended
# as far as the device's log tells.
ended() {
    printf "android-app-launch: FAIL: the application's process (%s) ended %s\n" "$watched" "$1" >&2
    dev logcat -d -b all | tr -d '\r' | python3 -I -c "$ended_program" "$watched" "$package" >&2
    printf 'android-app-launch: %s\n' "$(device_memory)" >&2
    exit 1
}

# Waits until `$2` (a command line) succeeds, or fails the run naming `$1` after the deadline, or as
# soon as the process being watched is found gone. The wait started at `wait_started`, which a
# condition that keeps its own time reads to know how much of the deadline is left.
wait_started=0
wait_for() {
    local what=$1
    shift
    wait_started=$(date +%s)
    until "$@"; do
        if application_has_ended; then
            ended "while waiting for $what"
        fi
        if [ $(($(date +%s) - wait_started)) -ge "$deadline" ]; then
            printf 'android-app-launch: FAIL: gave up waiting for %s\n' "$what" >&2
            [ -z "${mount_answers:-}" ] || printf 'android-app-launch: the page check answered:%s\n' "$mount_answers" >&2
            [ -z "${screen_note:-}" ] || printf 'android-app-launch: the last look at the screen: %s\n' "$screen_note" >&2
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
watched="$pid"

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

# The web view's debugging socket is named for the process; forwarding it to a free port of this
# machine reaches the page list.
socket=""
socket_open() {
    socket="$(dev shell cat /proc/net/unix 2> /dev/null | tr -d '\r' | awk '{ print $NF }' | grep -x "@webview_devtools_remote_$pid" | head -n 1)"
    [ -n "$socket" ]
}
wait_for "the web view to open its debugging socket" socket_open
port="$(dev forward tcp:0 "localabstract:${socket#@}" | tr -d '\r')"
case "$port" in
    '' | *[!0-9]*) die "the web view's socket could not be forwarded" ;;
esac
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
    # The document of the interface itself: it has the title that index.html gives it, and the
    # protocol of the application served it.
    if page.get("title") == "KalaReach" and "://tauri.localhost" in page.get("url", ""):
        print(page["title"])
        break
')"
    [ -n "$title" ]
}
wait_for "the web view to list the interface's own document, served by the application's own protocol" page_has_title
say "page title: $title"

# The interface mounted. index.html holds an empty root that the interface's script fills, so a
# document that loaded and whose script failed has a title and an address and nothing in its root.
# The page is asked, over the debugging protocol on the forwarded port (a WebSocket, which Python's
# own library has no client for: the handshake and one text frame each way are written here),
# whether its root has children and its body has text. One connection is kept for the whole wait and
# asked once a second, because the web view's debugging socket takes a connection that ends without
# a closing frame badly, and a page that is still starting is asked again and not reconnected to.
# The wait is the one the other waits have, with one deadline for the whole of it: each exchange is
# given what is left of it, so neither a page that keeps sending events nor a second exchange, after
# a first that ended early, can hold the wait past its end. Every distinct answer of a failed wait
# is printed. The program is kept in a variable, since the system's own bash cannot parse a
# here-document inside a command substitution.
mount_answers=""
started_at=$(date +%s)
IFS= read -r -d '' mount_program << 'PYTHON' || true
import base64
import json
import os
import socket
import struct
import sys
import time
import urllib.request

port = int(sys.argv[1])
limit = time.monotonic() + int(sys.argv[2])


def refuse(reason):
    print(reason)
    sys.exit(1)


def remaining():
    left = limit - time.monotonic()
    if left <= 0:
        raise OSError("the wait ran out of time")
    return left


def mask_frame(opcode, payload):
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    if len(payload) < 126:
        header = bytes([0x80 | opcode, 0x80 | len(payload)])
    else:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", len(payload))
    return header + mask + masked


# The forwarded port is on this machine: no proxy, whatever the machine's settings say.
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with direct.open(f"http://127.0.0.1:{port}/json", timeout=remaining()) as listing:
        entries = json.load(listing)
except (OSError, ValueError) as error:
    refuse(f"the page list could not be read: {type(error).__name__}: {error}")
pages = [p for p in entries if p.get("type") == "page" and "://tauri.localhost" in p.get("url", "")]
if not pages:
    refuse(f"no page of the application's protocol is listed: {json.dumps(entries)[:300]}")
try:
    path = "/" + pages[0]["webSocketDebuggerUrl"].split("/", 3)[3]
except (KeyError, IndexError):
    refuse(f"the page names no debugging address: {json.dumps(pages[0])[:300]}")

expression = (
    "(() => { const root = document.getElementById('root');"
    " return JSON.stringify({ children: root ? root.childElementCount : -1,"
    " text: document.body ? document.body.innerText.trim().length : 0 }); })()"
)
last = "the page was not asked"
try:
    connection = socket.create_connection(("127.0.0.1", port), timeout=remaining())
    key = base64.b64encode(os.urandom(16)).decode()
    connection.sendall(
        (
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        connection.settimeout(remaining())
        chunk = connection.recv(4096)
        if not chunk:
            refuse(f"the connection closed during the handshake after {buffer[:200]!r}")
        buffer += chunk
    head, _, buffer = buffer.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 101"):
        refuse(f"the handshake was answered {head[:200]!r}")

    def take(count):
        global buffer
        while len(buffer) < count:
            connection.settimeout(remaining())
            chunk = connection.recv(65536)
            if not chunk:
                raise OSError("the connection closed")
            buffer += chunk
        taken, buffer = buffer[:count], buffer[count:]
        return taken

    asked = 0
    while True:
        asked += 1
        payload = json.dumps(
            {"id": asked, "method": "Runtime.evaluate", "params": {"expression": expression, "returnByValue": True}}
        ).encode()
        connection.settimeout(remaining())
        connection.sendall(mask_frame(1, payload))
        while True:
            first, second = take(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", take(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", take(8))[0]
            frame = take(length)
            if first & 0x0F != 1:
                continue
            message = json.loads(frame)
            if message.get("id") == asked:
                break
        answer = message.get("result", {}).get("result", {})
        if "value" not in answer:
            refuse(f"the page answered {json.dumps(message)[:300]}")
        value = json.loads(answer["value"])
        if value["children"] > 0 and value["text"] > 0:
            connection.sendall(mask_frame(8, struct.pack(">H", 1000)))
            sys.exit(0)
        last = f"the page's root held {value['children']} elements and its body {value['text']} characters of text"
        time.sleep(min(1, remaining()))
except (OSError, ValueError, KeyError, TypeError) as error:
    refuse(f"the debugging exchange failed: {type(error).__name__}: {error}; the last answer: {last}")
PYTHON
interface_mounted() {
    local answer status left=$((deadline - ($(date +%s) - wait_started)))
    [ "$left" -gt 0 ] || return 1
    answer="$(python3 -I -c "$mount_program" "$port" "$left" 2>&1)"
    status=$?
    case "$mount_answers" in
        *"$answer"*) ;;
        *) mount_answers="$mount_answers $(($(date +%s) - started_at))s: $answer;" ;;
    esac
    return "$status"
}
wait_for "the interface to have drawn into the document's root" interface_mounted

# The device's screen as the raw pixels `screencap` writes: a small header and then four bytes a
# pixel. The page is drawn when more than half a percent of the sampled pixels below the status bar
# differ from the colour that covers most of them. The frame that shows it is written out as the
# screenshot (a PNG made from those same pixels), so the picture kept is the one the condition was
# found to hold on, and no later look at the screen can find the application gone. The frame is the
# application's only if its process was there when the frame was read, which is looked at at once.
# The program says 0 when the page is drawn and the picture is written, 1 when the page is not
# drawn or the stream is not a whole frame (read again), and 2 when the screen's frames cannot be
# read (a whole frame in a pixel format that is not RGBA_8888) or the picture cannot be kept, which
# no later frame would change.
mkdir -p "$(dirname "$screenshot")"
screen_note=""
screen_shows_the_page() {
    local result status
    result="$(dev exec-out screencap 2> /dev/null | python3 -I -c '
import binascii
import collections
import struct
import sys
import zlib

data = sys.stdin.buffer.read()
if len(data) < 16:
    print(f"the capture was {len(data)} bytes, too few for a frame: {data[:60]!r}")
    sys.exit(1)
width, height, pixel_format = struct.unpack_from("<III", data, 0)
# A whole frame is a header (three words, and a fourth on newer systems) and then every pixel of
# the screen in the size the format gives it. A capture that failed writes its error text, and one
# that was cut off writes less than a frame: neither says what the screen is, so they are read again
# and the format is judged only on a stream that is a whole frame for it.
bytes_a_pixel = {1: 4, 2: 4, 3: 3, 4: 2, 5: 4, 0x16: 8, 0x2B: 4}
sizes = [bytes_a_pixel[pixel_format]] if pixel_format in bytes_a_pixel else range(1, 9)
header = next((h for h in (12, 16) for size in sizes if len(data) - h == width * height * size), None)
if header is None or width == 0 or height == 0:
    print(f"the capture was {len(data)} bytes, not a whole frame of {width} x {height} pixels; it began {data[:40]!r}")
    sys.exit(1)
if pixel_format != 1:
    print(f"the screen is in pixel format {pixel_format}, and only RGBA_8888 is read", file=sys.stderr)
    sys.exit(2)
sampled = []
for row in range(height * 12 // 100, height, 4):
    start = header + row * width * 4
    line = data[start : start + width * 4]
    sampled.extend(line[i : i + 3] for i in range(0, len(line), 16))
common = collections.Counter(sampled).most_common(1)[0][0]
different = sum(1 for pixel in sampled if max(abs(a - b) for a, b in zip(pixel, common)) > 30)
if different * 200 <= len(sampled):
    print(f"the capture was a whole frame of {width} x {height} pixels, and the page is not drawn in it")
    sys.exit(1)


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body))


rows = b"".join(
    b"\0" + data[header + row * width * 4 : header + (row + 1) * width * 4] for row in range(height)
)
try:
    with open(sys.argv[1], "wb") as image:
        image.write(b"\x89PNG\r\n\x1a\n")
        image.write(chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)))
        image.write(chunk(b"IDAT", zlib.compress(rows, 6)))
        image.write(chunk(b"IEND", b""))
except OSError as error:
    print(f"the screenshot could not be written: {error}", file=sys.stderr)
    sys.exit(2)
' "$screenshot"; printf 'status:%s' "${PIPESTATUS[1]}")"
    status=${result##*status:}
    screen_note=${result%status:*}
    screen_note=${screen_note%$'\n'}
    if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
        echo "android-app-launch: FAIL: the screen cannot be read as a picture, or the screenshot cannot be written" >&2
        exit 1
    fi
    [ "$status" -eq 0 ] || return 1
    if application_has_ended; then
        ended "when the screen was read"
    fi
}
wait_for "the screen to show the page" screen_shows_the_page
say "$(device_memory)"

log="$(dev logcat -d -b all | tr -d '\r')" || { echo "android-app-launch: FAIL: the device's log could not be read" >&2; exit 1; }
# A Java crash logs `FATAL EXCEPTION` and, within the next lines, `Process: <package>, PID: ...`; a
# native one logs `Fatal signal ... pid <pid> (<package>)`. A crash of another process of the device
# (a system service, Google Play) is not the application's and is left alone.
crashed="$(awk -v package="$package" '
    BEGIN { process = "Process: " package ","; native = "(" package ")" }
    /FATAL EXCEPTION/ { watching = NR; next }
    watching && NR <= watching + 5 && index($0, process) { print; watching = 0 }
    /Fatal signal/ && index($0, native) { print }
' <<< "$log")"
if [ -n "$crashed" ]; then
    echo "android-app-launch: FAIL: the system logged a fatal exception or signal for the application:" >&2
    grep -E -A8 'FATAL EXCEPTION|Fatal signal' <<< "$log" | head -40 >&2
    exit 1
fi
say "ok: no fatal exception or signal for the application in the log"
if application_has_ended; then
    ended "after the log was read"
fi
say "ok: the application's process ($watched) is still the one that started"

[ "$(head -c 8 "$screenshot" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || { echo "android-app-launch: FAIL: the screenshot is not a PNG image" >&2; exit 1; }
say "screenshot: $screenshot ($(wc -c < "$screenshot" | tr -d ' ') bytes)"
