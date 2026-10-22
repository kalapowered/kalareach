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
#   owner confirmations    the paired phone is an owner device: the host's own request appears on the
#                          phone's Attention tab, and the phone's ceremony (Face ID on the simulator;
#                          the screen lock's PIN on the emulator) confirms it. A cancelled prompt
#                          confirms nothing and leaves the request listed; the same request is then
#                          confirmed, and the host spends that confirmation (KR-REQ-10.52). A second
#                          device the host asks the phone to confirm is confirmed against the value
#                          it shows (KR-REQ-10.37)
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
presence_pid=""
# The PIN the emulator's screen lock is given for the confirmations case, and taken off at the end.
screen_lock_pin=1234
emulator_pid=""
emulator_serial=""
emulator_adb=""
# Whether the phone's logs were searched for an invitation's text and secret, and whether any held one.
logs_searched=0
logs_found=0

# What the iOS run makes or changes outside this script's own directories: a simulator of its own,
# whose photo library takes the pictures, and two files of the build that are put back as they were.
simulator_made=""
xcconfig="$companion/src-tauri/gen/apple/Local.xcconfig"
xcconfig_saved=""
xcconfig_made=""
plist="$companion/src-tauri/gen/apple/companion-tauri_iOS/Info.plist"
plist_saved=""

say() { printf '== [pairing-device] %s\n' "$*" | tee -a "$log"; }

# Ends what this script started and removes what it made. The host is asked to finish and ended by
# the pid this script recorded only when it does not; so is the feeder; the emulator is asked to stop
# through its serial and ended by its pid when it does not, after the application and the tunnel it
# was given are taken away; the simulator this script made is shut down and deleted, which takes its
# photo library with it; and the two files of the iOS build are put back as they were.
finish() {
    touch "$harness/finish" 2>/dev/null
    for pid in "$feeder_pid" "$presence_pid" "$harness_pid"; do
        [ -n "$pid" ] || continue
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    done
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        # The screen lock the confirmations case set, taken off again.
        "$emulator_adb" -s "$emulator_serial" shell locksettings clear --old "$screen_lock_pin" >/dev/null 2>&1
        "$emulator_adb" -s "$emulator_serial" reverse --remove-all >/dev/null 2>&1
        "$emulator_adb" -s "$emulator_serial" uninstall "$app_id" >/dev/null 2>&1
        "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        local stopped=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$stopped" -lt 30 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
    if [ -n "$simulator_made" ]; then
        xcrun simctl shutdown "$simulator_made" >/dev/null 2>&1
        xcrun simctl delete "$simulator_made" >/dev/null 2>&1
    fi
    if [ -n "$xcconfig_saved" ]; then
        cp "$xcconfig_saved" "$xcconfig" 2>/dev/null
    elif [ -n "$xcconfig_made" ]; then
        rm -f "${xcconfig:?}"
    fi
    [ -z "$plist_saved" ] || cp "$plist_saved" "$plist" 2>/dev/null
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
start_harness() { # <peer> [<peer of the other service>]
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SERVICE_PEER="${2:-$1}" KR_HARNESS_SECONDS=1500 \
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
# What only one platform's run shows: the scanner has a camera on the emulator and none on the
# simulator, and the phone's ceremony is Face ID on one and the screen lock on the other.
platform_checks=()
if [ "$platform" = android ]; then
    platform_checks=(
        "the scanner is kept out of screenshots"
        "the scanner closes on Cancel"
        "the scanner fits the largest text size"
        "the attachment picker offers no file on a paired phone, and says nothing of the camera"
        "a phone with no screen lock cannot confirm"
        "the host's request is cancelled at the prompt"
        "the host's request is confirmed with the screen lock"
        "a new device is confirmed against its value"
    )
else
    platform_checks=(
        "the host's request is cancelled at the alert"
        "the host's request is confirmed with Face ID"
        "a new device is confirmed against its value"
    )
fi

# What the host wrote in one of its files, on one line, or nothing when it wrote none.
host_file() { # <name>
    [ -f "$harness/$1" ] && tr -d '\n' <"$harness/$1"
}

# Searches one of the phone's logs for every form of an invitation's text and secret that the host
# recorded: the log is read whole, and a match in it fails the run.
search_log() { # <command that prints the log...>
    cat "$harness"/secrets-*.txt >"$harness/secrets.all" 2>/dev/null
    [ -s "$harness/secrets.all" ] || return 0
    # The control: the same search finds a line that holds one, so a search that finds nothing is
    # one that looked.
    head -n 1 "$harness/secrets.all" >"$harness/log-control.txt"
    if ! grep -q -i -F -f "$harness/secrets.all" "$harness/log-control.txt"; then
        logs_found=2
        return 0
    fi
    "$@" >"$harness/log-searched.txt" 2>/dev/null
    logs_searched=$((logs_searched + 1))
    if grep -q -i -F -f "$harness/secrets.all" "$harness/log-searched.txt"; then
        logs_found=1
    fi
}

# Decides the run from the lines the driver reported and the files the host wrote.
judge() { # <driver output>
    local bad=0 check
    for check in "${required_checks[@]}" ${platform_checks[@]+"${platform_checks[@]}"}; do
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
    if [ "$logs_searched" -ge 1 ] && [ "$logs_found" = 0 ]; then
        say "check=no log holds an invitation's text or secret ok=1 detail=$logs_searched log read whole"
    else
        say "check=no log holds an invitation's text or secret ok=0 detail=searched $logs_searched, found $logs_found"
        bad=1
    fi
    result="$(host_file challenge-open.txt)"
    case "$result" in
        "unanswered=1 refused="?*) say "check=the host kept the cancelled request and refused the invitation behind it ok=1 detail=$result" ;;
        *) say "check=the host kept the cancelled request and refused the invitation behind it ok=0 detail=${result:-no record}"; bad=1 ;;
    esac
    result="$(host_file confirm-result.txt)"
    case "$result" in
        *"channel=owner_device_presence consumed=false"*"channel=owner_device_presence consumed=true"*)
            say "check=the host took the phone's presence once and spent it on the invitation ok=1" ;;
        *) say "check=the host took the phone's presence once and spent it on the invitation ok=0 detail=${result:-no record}"; bad=1 ;;
    esac
    result="$(host_file device-result.txt)"
    case "$result" in
        "answered channel=owner_device_presence"*) say "check=the host took the phone's presence for the new device ok=1" ;;
        *) say "check=the host took the phone's presence for the new device ok=0 detail=${result:-no record}"; bad=1 ;;
    esac
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

# Face ID on the simulator: enrolled once, and a matching face sent each second from the moment the
# test says the prompt is wanted until it says the prompt is done, since a match sent before the
# system's prompt is up is lost.
enrol_face_id() { # <udid>
    xcrun simctl spawn "$1" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1 >/dev/null 2>&1
    xcrun simctl spawn "$1" notifyutil -p com.apple.BiometricKit.enrollmentChanged >/dev/null 2>&1
}

match_face_id() { # <udid>
    while [ ! -e "$harness/finish" ]; do
        if [ -e "$harness/faceid-wanted" ] && [ ! -e "$harness/faceid-done" ]; then
            xcrun simctl spawn "$1" notifyutil -p com.apple.BiometricKit_Sim.pearl.match >/dev/null 2>&1
        fi
        # Each prompt is its own: the test asks again by removing both files.
        sleep 1
    done
}

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" udid app="${KR_PAIRING_IOS_APP:-}"
    # The simulator is one of this run's own, of the model and the runtime of the one named, so that
    # nothing of an earlier run is in its photo library and nothing of this one is left in another's.
    local template
    template="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" template "$device")"
    [ -n "$template" ] || { say "no iOS simulator named $device"; return 3; }

    if [ -z "$app" ]; then
        say "building the application for the simulator"
        # No push: the build names no Firebase configuration. The file is a developer's own when it
        # exists, and is put back as it was; the build also rewrites the end of one tracked file.
        if [ -f "$xcconfig" ]; then
            xcconfig_saved="$(mktemp "${TMPDIR:-/tmp}/kr-xcconfig.XXXXXX")"
            cp "$xcconfig" "$xcconfig_saved"
        else
            xcconfig_made=1
        fi
        plist_saved="$(mktemp "${TMPDIR:-/tmp}/kr-info-plist.XXXXXX")"
        cp "$plist" "$plist_saved"
        printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$xcconfig"
        rm -rf "${companion:?}/src-tauri/gen/apple/build"
        ( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
            || { say "the build failed; see $artefacts/build.log"; return 2; }
        cp "$plist_saved" "$plist"
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

    say "making and starting a simulator like $device"
    # shellcheck disable=SC2086
    udid="$(xcrun simctl create "kr-pairing-device-$$" $template)" \
        || { say "the simulator could not be made"; return 3; }
    simulator_made="$udid"
    xcrun simctl boot "$udid" >/dev/null 2>&1
    xcrun simctl bootstatus "$udid" -b >/dev/null 2>&1
    xcrun simctl install "$udid" "$app" || { say "the application did not install"; return 2; }

    enrol_face_id "$udid"
    # A simulator shares this machine's network: the host is where the invitation says.
    start_harness 127.0.0.1 || return 2
    feed_ios "$udid" &
    feeder_pid=$!
    match_face_id "$udid" &
    presence_pid=$!

    say "driving the application"
    local out="$artefacts/xcodebuild.log" status=0
    TEST_RUNNER_KR_PAIRING_DIR="$harness" xcodebuild test-without-building -xctestrun "$plan" \
        -destination "platform=iOS Simulator,id=$udid" -only-testing:KalaReachUITests/PairingTests \
        >"$out" 2>&1 || status=$?
    grep -E "Test Case .* (passed|failed)|error:|XCTAssert|PAIRING" "$out" | sed 's/^/    /' | tee -a "$log"
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    search_log xcrun simctl spawn "$udid" log show --last 40m --style compact
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

    # The camera starts at its first view of the wall's picture. The emulator's camera is a frame of
    # 1280 by 960 pixels and a host's direct invitation is a dense code, so the driver moves the
    # camera to another view when a view is not read, as a person moves a phone.
    python3 "$here/scripts/lib/pairing-android.py" aim "$grpc_port" || { say "the camera could not be placed"; return 2; }

    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    # The application asks about notifications at its start on this version of Android, which this run
    # is not about: the answer the person would give is given up front. The camera is asked about by the
    # scanner, and answered on its own screen.
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

    # The emulator reaches this machine's loopback interface as 10.0.2.2, which carries the direct
    # invitation's datagrams. The application's connections to the other service of the code case
    # did not arrive at the host through that address (the host saw no connection at all), so that
    # service is reached on the emulator's own loopback interface, which `adb reverse` ties to the
    # host's listener.
    start_harness 10.0.2.2 127.0.0.1 || return 2
    local service_port
    service_port="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["service_port"])' "$harness/ready.json")"
    "$adb" -s "$serial" reverse "tcp:$service_port" "tcp:$service_port" >/dev/null \
        || { say "the emulator's loopback interface could not be tied to the other service"; return 2; }
    feed_android "$adb" "$serial" &
    feeder_pid=$!

    say "driving the application"
    local out="$artefacts/driver.log" status=0
    python3 "$here/scripts/lib/pairing-android.py" drive "$adb" "$serial" "$harness" "$shots" "$grpc_port" >"$out" 2>&1 || status=$?
    sed 's/^/    /' "$out" | tee -a "$log"
    # The crash buffer, and the main buffer without the compositor's and the screen reader's polling.
    search_log "$adb" -s "$serial" logcat -d -b all
    "$adb" -s "$serial" logcat -d -b crash >"$artefacts/crash.log" 2>&1
    "$adb" -s "$serial" logcat -d 2>/dev/null | grep -v -E 'CompositionEngine|AccessibilityNodeInfoDumper' | tail -2000 >"$artefacts/logcat.log"
    # What the application's native half printed to its standard streams.
    "$adb" -s "$serial" logcat -d -s RustStdoutStderr 2>/dev/null >"$artefacts/application.log"
    judge "$out" || status=2
    [ "$status" = 0 ] || return 2
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
