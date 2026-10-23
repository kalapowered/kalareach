#!/usr/bin/env bash
# Operates the desktop application's native window controls on macOS, through the system's own
# accessibility interface, and holds each answer to the state the window reports.
#
#   scripts/desktop-controls-macos.sh <the application's binary> <screenshot.png>
#
# The interface under test is the page, which a browser test drives. What a browser cannot reach is
# the operating system's own part of the application: the window the shell opens and the menu bar
# it gives the application. This starts the built binary, and with System Events:
#
#   1. waits until the application has a window, and reads that it is not minimized;
#   2. chooses Minimize from the Window menu, and waits until the window reports it is minimized;
#   3. restores the window, and waits until it reports it is not minimized;
#   4. saves a screenshot of the screen, with the window showing;
#   5. chooses Quit from the application menu, and waits until the process has ended.
#
# Every wait ends when its condition holds. The deadline (KR_CONTROLS_DEADLINE, 180 seconds) only
# ends a step that is hung, and the message names the condition. Only the process this script
# started is touched.
#
# It drives the desktop of the machine it runs on and sends the keyboard and the pointer nothing:
# a run needs a desktop session whose shell may use the accessibility interface, such as a hosted
# runner has, and it refuses to start anywhere but on one (GITHUB_ACTIONS=true and
# RUNNER_ENVIRONMENT=github-hosted). Exit status: 0 when every condition held, 1 when one did not,
# 2 for a usage or environment fault.

set -uo pipefail

die() {
    printf 'desktop-controls-macos: %s\n' "$*" >&2
    exit 2
}
say() { printf 'desktop-controls-macos: %s\n' "$*"; }

# A hosted runner's desktop belongs to the run. Anywhere else this would operate someone's own.
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    die "this drives the desktop and runs only on a GitHub-hosted runner (GITHUB_ACTIONS is true and RUNNER_ENVIRONMENT is github-hosted there)"
fi

binary="${1:-}"
screenshot="${2:-}"
[ -x "$binary" ] && [ -n "$screenshot" ] || die "usage: desktop-controls-macos.sh <the application's binary> <screenshot.png>"
[ "$(uname -s)" = Darwin ] || die "this drives macOS"
deadline="${KR_CONTROLS_DEADLINE:-180}"

expect_end=0
log="$(mktemp "${TMPDIR:-/tmp}/kr-desktop-controls.XXXXXX")"
"$binary" > "$log" 2>&1 &
app=$!
cleanup() {
    if kill -0 "$app" 2> /dev/null; then
        kill "$app" 2> /dev/null || true
    fi
    rm -f "${log:?}"
}
trap cleanup EXIT
say "started $binary as process $app"

# Runs AppleScript statements against the application's process. Its output is the script's answer.
ax() {
    osascript 2>&1 << SCRIPT
tell application "System Events"
    tell (first process whose unix id is $app)
        $1
    end tell
end tell
SCRIPT
}

# Waits until `$2` (a command line) succeeds, or fails the run naming `$1` after the deadline.
wait_for() {
    local what=$1 started
    shift
    started=$(date +%s)
    until "$@"; do
        if [ "$expect_end" -eq 0 ] && ! kill -0 "$app" 2> /dev/null; then
            printf 'desktop-controls-macos: FAIL: the application ended while this waited for %s\n' "$what" >&2
            sed -n '1,40p' "$log" >&2
            exit 1
        fi
        if [ $(($(date +%s) - started)) -gt "$deadline" ]; then
            printf 'desktop-controls-macos: FAIL: gave up waiting for %s\n' "$what" >&2
            sed -n '1,40p' "$log" >&2
            exit 1
        fi
        sleep 1
    done
    say "ok: $what"
}

has_window() { [ "$(ax 'return (count of windows) > 0')" = true ]; }
is_minimized() { [ "$(ax 'return value of attribute "AXMinimized" of window 1')" = true ]; }
is_showing() { [ "$(ax 'return value of attribute "AXMinimized" of window 1')" = false ]; }
has_ended() { ! kill -0 "$app" 2> /dev/null; }

wait_for "the application to open a window" has_window
wait_for "the window to report it is not minimized" is_showing

ax 'set frontmost to true' > /dev/null
say "window: $(ax 'return name of window 1') ($(ax 'return (item 1 of (get size of window 1)) as text') wide)"

answer="$(ax 'click menu item "Minimize" of menu 1 of menu bar item "Window" of menu bar 1')" \
    || { printf 'desktop-controls-macos: FAIL: the Window menu has no Minimize item: %s\n' "$answer" >&2; exit 1; }
wait_for "the window to report it is minimized after Minimize was chosen" is_minimized

ax 'set value of attribute "AXMinimized" of window 1 to false' > /dev/null
wait_for "the window to report it is not minimized after it was restored" is_showing

mkdir -p "$(dirname "$screenshot")"
screencapture -x -t png "$screenshot" || { echo "desktop-controls-macos: FAIL: the screen could not be captured" >&2; exit 1; }
[ "$(head -c 8 "$screenshot" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || { echo "desktop-controls-macos: FAIL: the screenshot is not a PNG image" >&2; exit 1; }
say "screenshot: $screenshot ($(wc -c < "$screenshot" | tr -d ' ') bytes)"

quit_name="$(ax 'return name of (last menu item of menu 1 of menu bar item 2 of menu bar 1)')"
case "$quit_name" in
    Quit*) ;;
    *) printf 'desktop-controls-macos: FAIL: the application menu ends in "%s", not in Quit\n' "$quit_name" >&2; exit 1 ;;
esac
ax 'click (last menu item of menu 1 of menu bar item 2 of menu bar 1)' > /dev/null
expect_end=1
wait_for "the application to end" has_ended
say "$quit_name ended the application"
