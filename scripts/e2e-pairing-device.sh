#!/usr/bin/env bash
#
# Pairs a phone with a real host through the application's own screens, on the iOS Simulator or the
# Android emulator.
#
# The machine side is `kr-controller`'s ignored `pairing_device` suite: the real daemon on the
# loopback interface. It issues the invitations as pictures of their QR codes. This script puts each
# picture where a phone finds it (the simulator's photo library, or the wall of the emulator's
# virtual camera scene), and the installed application is driven through its own screens by the
# platform's UI automation: XCUITest on the simulator, `uiautomator` on the emulator. The
# application is the shipped build, with no debug probe in it. Every prompt of the system is answered
# by the button a person would press, from outside the application.
#
# What the run shows, per platform:
#   a changed secret       a QR code whose secret has one bit changed opens nothing: the host locks no
#                          candidate (KR-REQ-10.36, 10.38)
#   a scanned invitation   the phone reads the host's QR code, shows the value the host shows, and is
#                          paired once the host approves it (KR-REQ-10.36, 10.37, 10.38)
#   another service        a code QR that names another service raises the system's alert with that
#                          service's name before anything is contacted: Cancel contacts nothing, and
#                          accepting contacts it once (KR-REQ-10.17); screenshots under /tmp
#
# A simulator or an emulator only inside the Mac's device lease, and the builds inside a build slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-pairing-device.sh ios
#
# Usage:
#   scripts/e2e-pairing-device.sh ios
#   scripts/e2e-pairing-device.sh android
#
# KR_PAIRING_IOS_APP and KR_PAIRING_ANDROID_APK name a build to install instead of making one.
# KR_PAIRING_SHOTS is where the screenshots go (default /tmp/kr-pair-phone).
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
case "$platform" in
    ios | android) ;;
    *) printf 'usage: %s ios|android\n' "$0" >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/pairing-device-$platform"
shots="${KR_PAIRING_SHOTS:-/tmp/kr-pair-phone}"
cache="${HOME}/Library/Caches/kalareach-tests/pairing-device"
mkdir -p "${artefacts:?}" "${shots:?}" "${cache:?}"
app_id=to.kala.reach
log="$artefacts/run.log"
: >"${log:?}"
# The host's files hold an invitation's secret: they live on the internal disk, for this run.
harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-pairing-device.XXXXXX")"
harness_pid=""
feeder_pid=""
emulator_pid=""
emulator_serial=""
emulator_adb=""

say() { printf '== [pairing-device] %s\n' "$*" | tee -a "$log"; }

# Ends what this script started and removes what it made. The host is asked to finish and ended by
# the pid this script recorded only when it does not; so is the feeder; the emulator is asked to stop
# through its serial and ended by its pid when it does not.
finish() {
    touch "$harness/finish" 2>/dev/null
    for pid in "$feeder_pid" "$harness_pid"; do
        [ -n "$pid" ] || continue
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    done
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        local stopped=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$stopped" -lt 30 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
    rm -rf "${harness:?}"
}
trap finish EXIT

# ---- The host --------------------------------------------------------------------------------

build_harness() {
    say "building the host"
    cargo test --manifest-path "$here/Cargo.toml" -p kr-controller --test pairing_device --no-run \
        --message-format=json >"$artefacts/harness-build.json" 2>"$artefacts/harness-build.log" \
        || { say "the host did not build; see $artefacts/harness-build.log"; return 2; }
    harness_exe="$(python3 - "$artefacts/harness-build.json" <<'PY'
import json
import sys

found = ""
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if (
        message.get("reason") == "compiler-artifact"
        and message.get("executable")
        and message["target"]["name"] == "pairing_device"
    ):
        found = message["executable"]
print(found)
PY
)"
    [ -n "$harness_exe" ] && [ -x "$harness_exe" ] || { say "the host left no executable"; return 2; }
}

# Starts the host, which reaches the phone as `peer`, and waits until it is up.
start_harness() { # <peer>
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SECONDS=1500 \
        "$harness_exe" --ignored --exact a_phone_scans_pairs_and_confirms_against_a_real_host --nocapture \
        >"$artefacts/harness.log" 2>&1 &
    harness_pid=$!
    local waited=0
    while [ ! -s "$harness/ready.json" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the host ended before it was ready; see $artefacts/harness.log"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 180 ] || { say "the host was not ready in time"; return 2; }
    done
    say "the host is up, reached as $1"
}

# ---- What the run must have shown ------------------------------------------------------------

required_checks=(
    "a changed secret locked nothing"
    "the phone shows the host's value"
    "the phone is paired"
    "cancelled: no connection"
    "accepted: one connection"
)

# What the host wrote in one of its files, on one line, or nothing when it wrote none.
host_file() { # <name>
    [ -f "$harness/$1" ] && tr -d '\n' <"$harness/$1"
}

# Decides the run from the lines the driver reported and the files the host wrote.
judge() { # <driver output>
    local bad=0 check
    for check in "${required_checks[@]}"; do
        if grep -q -F "PAIRING $check" "$1"; then
            say "check=$check ok=1"
        else
            say "check=$check ok=0 detail=the driver did not report it"
            bad=1
        fi
    done
    local result
    result="$(host_file control-result.txt)"
    if [ "$result" = "candidate_locked=0" ]; then
        say "check=the host locked no candidate on a changed secret ok=1"
    else
        say "check=the host locked no candidate on a changed secret ok=0 detail=${result:-no record}"
        bad=1
    fi
    if [ -s "$harness/host-value.txt" ] && [ -s "$harness/paired.txt" ]; then
        say "check=the host showed its value and approved the phone ok=1 detail=value $(host_file host-value.txt) invitation $(host_file direct-length.txt) characters"
    else
        say "check=the host showed its value and approved the phone ok=0 detail=no record"
        bad=1
    fi
    result="$(host_file connections.txt)"
    if [ "$result" = "1" ]; then
        say "check=the other service took one connection in all ok=1"
    else
        say "check=the other service took one connection in all ok=0 detail=${result:-no record}"
        bad=1
    fi
    return "$bad"
}

# ---- The iOS Simulator -----------------------------------------------------------------------

# Puts each picture the host writes into the simulator's photo library, and says so with a file.
feed_ios() { # <udid>
    while [ ! -e "$harness/finish" ]; do
        for picture in "$harness"/*.png; do
            [ -e "$picture" ] || continue
            [ -e "$picture.added" ] && continue
            xcrun simctl addmedia "$1" "$picture" >/dev/null 2>&1 && : >"$picture.added"
        done
        sleep 1
    done
}

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" udid app="${KR_PAIRING_IOS_APP:-}"
    udid="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" udid "$device")"
    [ -n "$udid" ] || { say "no iOS simulator named $device"; return 3; }

    if [ -z "$app" ]; then
        say "building the application for the simulator"
        # No push: the build names no Firebase configuration.
        printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$companion/src-tauri/gen/apple/Local.xcconfig"
        rm -rf "${companion:?}/src-tauri/gen/apple/build"
        ( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
            || { say "the build failed; see $artefacts/build.log"; return 2; }
        app="$companion/src-tauri/gen/apple/build/arm64-sim/KalaReach.app"
    fi
    [ -d "$app" ] || { say "there is no application at $app"; return 2; }

    say "building the tests that drive it"
    local derived="$cache/ios-tests"
    ( cd "$companion/src-tauri/gen/apple" && xcodebuild build-for-testing -project companion-tauri.xcodeproj \
        -scheme KalaReachUITests -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$derived" ) >"$artefacts/build-tests.log" 2>&1 \
        || { tail -20 "$artefacts/build-tests.log"; say "the tests did not build"; return 2; }
    local plan
    plan="$(ls "$derived"/Build/Products/*.xctestrun 2>/dev/null | head -1)"
    [ -f "$plan" ] || { say "the test build left no plan"; return 2; }
    build_harness || return 2

    # A simulator that is already running is someone else's: it is neither used nor shut down.
    if xcrun simctl list devices booted | grep -q "$udid"; then
        say "the simulator $device is already running, which is left alone"
        return 3
    fi
    say "starting the simulator $device"
    xcrun simctl boot "$udid" >/dev/null 2>&1
    xcrun simctl bootstatus "$udid" -b >/dev/null 2>&1
    xcrun simctl uninstall "$udid" "$app_id" >/dev/null 2>&1
    xcrun simctl install "$udid" "$app" || { say "the application did not install"; return 2; }

    # A simulator shares this machine's network: the host is where the invitation says.
    start_harness 127.0.0.1 || return 2
    feed_ios "$udid" &
    feeder_pid=$!

    say "driving the application"
    local out="$artefacts/xcodebuild.log" status=0
    TEST_RUNNER_KR_PAIRING_DIR="$harness" xcodebuild test-without-building -xctestrun "$plan" \
        -destination "platform=iOS Simulator,id=$udid" -only-testing:KalaReachUITests/PairingTests \
        >"$out" 2>&1 || status=$?
    grep -E "Test Case .* (passed|failed)|error:|XCTAssert|PAIRING" "$out" | sed 's/^/    /' | tee -a "$log"
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    judge "$out" || status=2
    [ "$status" = 0 ] || return 2
}

# ---- The Android emulator --------------------------------------------------------------------

# Gives the emulator's camera the picture each time the host writes one: the wall of its virtual
# scene shows it, and a file says so.
feed_android() { # <adb> <serial>
    while [ ! -e "$harness/finish" ]; do
        for picture in "$harness"/*.png; do
            [ -e "$picture" ] || continue
            [ -e "$picture.added" ] && continue
            "$1" -s "$2" emu virtualscene-image wall "$picture" 2>/dev/null | grep -q '^OK' && : >"$picture.added"
        done
        sleep 1
    done
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd apk="${KR_PAIRING_ANDROID_APK:-}"
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" serial_port=5594 grpc_port="${KR_PAIRING_GRPC_PORT:-8754}"
    local serial="emulator-$serial_port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }
    # Before the builds, so a machine without KalaReach's virtual device does not wait for one.
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        return 3
    fi

    if [ -z "$apk" ]; then
        say "building the application for the emulator"
        ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts/build.log" 2>&1 \
            || { say "the build failed; see $artefacts/build.log"; return 2; }
        apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    fi
    [ -f "$apk" ] || { say "there is no package at $apk"; return 2; }
    build_harness || return 2

    # A device already on the serial is someone else's: it is neither used nor stopped.
    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    say "starting the emulator $avd"
    # The camera is the virtual scene, whose wall shows the host's picture; its pose is moved over the
    # emulator's controller, which listens on the loopback interface only.
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -grpc "$grpc_port" -no-snapshot-save \
        -no-boot-anim -no-window -no-audio -no-metrics -gpu swiftshader_indirect -netdelay none \
        -netspeed full -camera-back virtualscene \
        -virtualscene-poster "wall=$here/fixtures/pairing/qr-direct.png" >"$artefacts/emulator.log" 2>&1 &
    emulator_pid=$!
    emulator_serial=$serial
    emulator_adb=$adb
    local booted=0
    for _ in $(seq 1 180); do
        kill -0 "$emulator_pid" 2>/dev/null || break
        if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
        sleep 2
    done
    # The emulator this script started is the one that answered: its process is still there.
    { [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; return 3; }

    # The camera looks at the wall's picture from two metres: a host's largest code gets about six
    # pixels to a module there.
    python3 "$here/scripts/lib/pairing-android.py" pose "$grpc_port" position -1.807 0.32 3.584 \
        && python3 "$here/scripts/lib/pairing-android.py" pose "$grpc_port" rotation 0 210 0 \
        || { say "the camera could not be placed"; return 2; }

    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    # The application asks about notifications at its start on this version of Android, which this run
    # is not about: the answer the person would give is given up front. The camera is asked about by the
    # scanner, and answered on its own screen.
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

    # The emulator reaches this machine's loopback interface as 10.0.2.2.
    start_harness 10.0.2.2 || return 2
    feed_android "$adb" "$serial" &
    feeder_pid=$!

    say "driving the application"
    local out="$artefacts/driver.log" status=0
    python3 "$here/scripts/lib/pairing-android.py" drive "$adb" "$serial" "$harness" "$shots" >"$out" 2>&1 || status=$?
    sed 's/^/    /' "$out" | tee -a "$log"
    "$adb" -s "$serial" logcat -d 2>/dev/null | tail -400 >"$artefacts/logcat.log"
    judge "$out" || status=2
    [ "$status" = 0 ] || return 2
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
