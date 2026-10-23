#!/usr/bin/env bash
# Installs the application built for the iOS Simulator on a booted simulator, starts it, and shows
# that it runs.
#
#   scripts/ios-app-launch.sh <KalaReach.app> <simulator identifier> <screenshot.png>
#
# A build that packages the application says nothing of whether the phone can start it: a plugin
# the shell cannot reach and a page that never opens both leave a green build. This holds, one
# condition at a time, that
#
#   * the Swift plugin's entry point (`init_plugin_companion_platform`) is in the built application,
#     which is the compiled form of `PlatformPlugin.swift` that the shell calls to register it;
#   * the application installs and its process runs on the simulator;
#   * the web view's content process runs for it, which the system starts for the page the shell
#     opens;
#   * the screen shows the page: below the status bar it is more than a blank field, which is what
#     the simulator shows until the page has loaded and drawn;
#   * the system wrote no crash report for the application;
#
# and then saves a screenshot of the simulator's screen to the path given. Each wait ends when its
# condition holds; the deadline (KR_LAUNCH_DEADLINE, 240 seconds) only ends a step that is hung, and
# the message names the condition. The simulator is the caller's: it is neither booted nor shut
# down here, and the application is uninstalled when this ends. It is named by its identifier, never
# by "booted", so another simulator cannot be the one driven. Exit status: 0 when every condition
# held, 1 when one did not, 2 for a usage or environment fault.

set -uo pipefail

bundle_id=to.kala.reach
deadline="${KR_LAUNCH_DEADLINE:-240}"

die() {
    printf 'ios-app-launch: %s\n' "$*" >&2
    exit 2
}
say() { printf 'ios-app-launch: %s\n' "$*"; }
fail() {
    printf 'ios-app-launch: FAIL: %s\n' "$*" >&2
    exit 1
}

app="${1:-}"
udid="${2:-}"
screenshot="${3:-}"
[ -d "$app" ] && [ -n "$udid" ] && [ -n "$screenshot" ] || die "usage: ios-app-launch.sh <KalaReach.app> <simulator identifier> <screenshot.png>"
command -v xcrun > /dev/null 2>&1 || die "xcrun is needed and is not on the path"
booted="$(xcrun simctl list devices booted)"
case "$booted" in
    *"$udid"*) ;;
    *) die "no simulator with the identifier $udid is booted" ;;
esac

installed=0
cleanup() {
    [ "$installed" -eq 0 ] || {
        xcrun simctl terminate "$udid" "$bundle_id" > /dev/null 2>&1 || true
        xcrun simctl uninstall "$udid" "$bundle_id" > /dev/null 2>&1 || true
    }
}
trap cleanup EXIT

# Waits until a command line succeeds, or fails the run naming `$1` after the deadline.
wait_for() {
    local what=$1 started
    shift
    started=$(date +%s)
    until "$@"; do
        [ $(($(date +%s) - started)) -le "$deadline" ] || fail "gave up waiting for $what"
        sleep 1
    done
    say "ok: $what"
}

# The plugin's entry point is a symbol of one of the application's Mach-O files: the executable
# itself, or the debug library a debug build keeps its code in.
has_plugin_entry() {
    local file symbols
    while IFS= read -r file; do
        symbols="$(nm -gU "$file" 2> /dev/null || true)"
        case "$symbols" in
            *init_plugin_companion_platform*)
                say "plugin entry point: init_plugin_companion_platform in ${file#"$app"/}"
                return 0
                ;;
        esac
    done < <(find "$app" -type f \( -name '*.dylib' -o -perm -u+x \) 2> /dev/null)
    return 1
}
has_plugin_entry || fail "no Mach-O file of $app defines the Swift plugin's entry point init_plugin_companion_platform"

xcrun simctl uninstall "$udid" "$bundle_id" > /dev/null 2>&1 || true
xcrun simctl install "$udid" "$app" || fail "the application did not install"
installed=1
say "ok: the application installed"

marker="$(mktemp "${TMPDIR:-/tmp}/kr-ios-launch.XXXXXX")"
trap 'rm -f "${marker:?}"; cleanup' EXIT
launched="$(xcrun simctl launch "$udid" "$bundle_id")" || fail "the application did not launch: $launched"
say "launched: $launched"

# What the simulator's own launchd says is running: `<pid> <status> <label>` for each job.
jobs_of_simulator() { xcrun simctl spawn "$udid" launchctl list 2> /dev/null; }
app_runs() { jobs_of_simulator | awk -v id="UIKitApplication:$bundle_id" 'index($3, id) == 1 && $1 != "-" { found = 1 } END { exit !found }'; }
wait_for "the application's process" app_runs

# The simulator's processes are processes of this machine, children of the simulator's own launchd:
# the web view's content process is one of those children, as the application is.
simulator_pid="$(ps -axo pid=,command= | awk -v udid="$udid" 'index($0, "launchd_sim") && index($0, "Devices/" udid "/") { print $1; exit }')"
[ -n "$simulator_pid" ] || fail "no launchd_sim of the simulator $udid runs on this machine"
content_runs() { ps -axo ppid=,command= | awk -v parent="$simulator_pid" '$1 == parent && index($0, "com.apple.WebKit.WebContent") { found = 1 } END { exit !found }'; }
wait_for "the web view's content process" content_runs

# A screenshot of the simulator, reduced by the system's own image tool to a bitmap the check can
# read without a library: the page is drawn when more than half a percent of what lies below the
# status bar differs from the colour that covers most of it.
work="$(mktemp -d "${TMPDIR:-/tmp}/kr-ios-launch-screen.XXXXXX")"
trap 'rm -f "${marker:?}"; rm -rf "${work:?}"; cleanup' EXIT
screen_shows_the_page() {
    xcrun simctl io "$udid" screenshot --type=png "$work/screen.png" > /dev/null 2>&1 || return 1
    sips -Z 200 "$work/screen.png" --out "$work/screen.bmp" -s format bmp > /dev/null 2>&1 || return 1
    python3 -I - "$work/screen.bmp" << 'PYTHON'
import collections
import struct
import sys

data = open(sys.argv[1], "rb").read()
offset = struct.unpack_from("<I", data, 10)[0]
width, height = struct.unpack_from("<ii", data, 18)
bits = struct.unpack_from("<H", data, 28)[0]
if bits not in (24, 32) or width <= 0 or height == 0:
    sys.exit(1)
step = bits // 8
stride = (width * step + 3) // 4 * 4
rows = abs(height)
# Rows are stored bottom-up for a positive height: the status bar is the last 12 percent of them.
pixels = []
for row in range(rows):
    stored = rows - 1 - row if height > 0 else row
    if row < rows * 12 // 100:
        continue
    line = data[offset + stored * stride : offset + stored * stride + width * step]
    pixels.extend(tuple(line[i : i + 3]) for i in range(0, len(line), step))
if not pixels:
    sys.exit(1)
common = collections.Counter(pixels).most_common(1)[0][0]
different = sum(1 for pixel in pixels if max(abs(a - b) for a, b in zip(pixel, common)) > 30)
sys.exit(0 if different * 200 > len(pixels) else 1)
PYTHON
}
wait_for "the screen to show the page" screen_shows_the_page

crashes="$(find "$HOME/Library/Logs/DiagnosticReports" -maxdepth 1 \( -name 'KalaReach*' -o -name 'companion*' \) -newer "$marker" 2> /dev/null)"
[ -z "$crashes" ] || fail "the system wrote a crash report for the application: $crashes"
say "ok: no crash report for the application"
app_runs || fail "the application's process ended before the screenshot"

mkdir -p "$(dirname "$screenshot")"
xcrun simctl io "$udid" screenshot --type=png "$screenshot" > /dev/null 2>&1 || fail "the simulator's screen could not be captured"
[ "$(head -c 8 "$screenshot" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || fail "the screenshot is not a PNG image"
say "screenshot: $screenshot ($(wc -c < "$screenshot" | tr -d ' ') bytes)"
