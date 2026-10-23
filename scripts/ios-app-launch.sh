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
xcrun simctl list devices booted | grep -q "$udid" || die "no simulator with the identifier $udid is booted"

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
    local file
    while IFS= read -r file; do
        if nm -gU "$file" 2> /dev/null | grep -q 'init_plugin_companion_platform'; then
            say "plugin entry point: init_plugin_companion_platform in ${file#"$app"/}"
            return 0
        fi
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

content_runs() { jobs_of_simulator | grep -q 'com\.apple\.WebKit\.WebContent' ; }
wait_for "the web view's content process" content_runs

crashes="$(find "$HOME/Library/Logs/DiagnosticReports" -maxdepth 1 \( -name 'KalaReach*' -o -name 'companion*' \) -newer "$marker" 2> /dev/null)"
[ -z "$crashes" ] || fail "the system wrote a crash report for the application: $crashes"
say "ok: no crash report for the application"
app_runs || fail "the application's process ended before the screenshot"

mkdir -p "$(dirname "$screenshot")"
xcrun simctl io "$udid" screenshot --type=png "$screenshot" > /dev/null 2>&1 || fail "the simulator's screen could not be captured"
[ "$(head -c 8 "$screenshot" | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] || fail "the screenshot is not a PNG image"
say "screenshot: $screenshot ($(wc -c < "$screenshot" | tr -d ' ') bytes)"
