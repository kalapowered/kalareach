#!/usr/bin/env bash
#
# Drives the voice call's bridge on the iOS Simulator or the Android emulator, with the real
# application, the real platform plugin and the application's own call.
#
# A debug build of the application reads a request from its data directory when it starts, runs
# the call's commands from an open to an end (companion-tauri's `probe`), and writes one line per
# check beside the request. This script builds that application, starts one device, puts the
# request where the application reads it, starts the application, and reads the lines back. It
# claims what the lines say and nothing more: each check it requires must be named in the result
# with verdict 1 (a check the application did not report is a check that did not run), no line may
# have another verdict, and a result that never says `done=1` fails the run. A device that is
# already running is someone else's: the script neither uses nor stops it.
#
# The answer the application gives its own offer is built from the offer's sections and leads
# nowhere, so the connection is described and applied and never carries media. What this proves is
# the bridge (commands, news, refusals and the end), not a provider and not audio.
#
# A simulator, an emulator or a VM only inside the Mac's device lease, and a build inside a build
# slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-voice-call-bridge.sh ios
#
# Usage:
#   scripts/e2e-voice-call-bridge.sh ios
#   scripts/e2e-voice-call-bridge.sh android
#
# On Android the script grants the microphone and notification permissions up front, so no
# question stands between the call and its checks. `KR_PROBE_PERMISSIONS` runs the permission
# question itself: `allow` answers the system's dialogs by tapping Allow, `deny` by tapping Don't
# allow (the open is then refused for the microphone, which the first check shows), and `none`
# answers nothing (the open goes on with what is allowed when its time for the answer is up). The
# dialogs are answered in the script's own wait for the result: nothing runs in the background.
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

permissions="${KR_PROBE_PERMISSIONS:-granted}"
case "$permissions" in
    granted | allow | deny | none) ;;
    *) printf 'KR_PROBE_PERMISSIONS is granted, allow, deny or none\n' >&2; exit 2 ;;
esac
[ "$platform" = android ] || [ "$permissions" = granted ] || {
    printf 'KR_PROBE_PERMISSIONS is for the Android leg only\n' >&2; exit 2
}

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-bridge-$platform"
mkdir -p "${artefacts:?}"
run="$(uuidgen)"
app_id=to.kala.reach
result_name="result-$run.txt"
log="$artefacts/run.log"
: >"${log:?}"
# The emulator this script started, by its pid and its serial, and the adb that reaches it.
emulator_pid=""
emulator_serial=""
emulator_adb=""

say() { printf '== [voice-call-bridge] %s\n' "$*" | tee -a "$log"; }

# shellcheck source=scripts/lib/voice-call-judge.sh
. "$here/scripts/lib/voice-call-judge.sh"

# Ends what this script started. The emulator is asked to stop through its serial, which the script
# took only after it found the serial free, and is ended by its pid when it does not stop.
finish() {
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        local stopped=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$stopped" -lt 30 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
}
trap finish EXIT

# The checks the bridge must have made and passed, by the names the application gives them. A
# result with fewer is a run that stopped short, whatever it says at its end.
required_checks=(
    "open"
    "a second open is refused"
    "held before permit"
    "offer"
    "answer applied"
    "the end is told"
    "nothing held after stop"
    "a command to an ended call is refused"
    "an answer that is not one is refused"
    "a call that could not use its answer ends"
    "permit"
    "news after permit has no gap"
    "a muted microphone is held and never reported as capturing"
)

# Reads the lines the application wrote, and decides the run.
judge() { # <result file>
    judge_voice_call_result "$1" "$run" "${required_checks[@]}"
}

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" udid
    udid="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" udid "$device")"
    [ -n "$udid" ] || { say "no iOS simulator named $device"; return 3; }

    say "building the debug application for the simulator"
    # No push: the build names no Firebase configuration.
    printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$companion/src-tauri/gen/apple/Local.xcconfig"
    rm -rf "${companion:?}/src-tauri/gen/apple/build"
    ( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
        || { say "the build failed; see $artefacts/build.log"; return 2; }
    local app="$companion/src-tauri/gen/apple/build/arm64-sim/KalaReach.app"
    [ -d "$app" ] || { say "the build left no application"; return 2; }

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
    # The microphone is allowed up front, so no dialog stands between the call and its check.
    xcrun simctl privacy "$udid" grant microphone "$app_id"

    local data
    data="$(xcrun simctl get_app_container "$udid" "$app_id" data)"
    local directory="$data/Library/Application Support/$app_id/kr-probe"
    mkdir -p "$directory"
    printf '{"run":"%s"}\n' "$run" >"$directory/request.json"
    say "starting the application, run $run"
    xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; return 2; }

    local waited=0
    while [ ! -s "$directory/$result_name" ] || ! grep -q '^done=1$' "$directory/$result_name"; do
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -lt 240 ] || break
    done
    cp "$directory/$result_name" "$artefacts/$result_name" 2>/dev/null
    # What the application said while it ran, kept for a run that wrote no result.
    xcrun simctl spawn "$udid" log show --last 10m --style compact \
        --predicate 'process == "KalaReach"' 2>/dev/null | tail -200 >"$artefacts/application.log"
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    judge "$artefacts/$result_name"
}

# Where to tap to answer the system's permission dialog that stands on the emulator's screen, as
# two numbers, or nothing when none does. `allow` is the button that lets the application use the
# microphone while it is open, or lets it post notifications; `deny` is Don't allow.
permission_dialog_point() { # allow|deny
    "$adb" -s "$serial" shell uiautomator dump /sdcard/kr-ui.xml >/dev/null 2>&1 || return 1
    "$adb" -s "$serial" exec-out cat /sdcard/kr-ui.xml >"$artefacts/ui.xml" 2>/dev/null || return 1
    python3 - "$1" "$artefacts/ui.xml" <<'PY'
import re
import sys

buttons = {
    "allow": ["permission_allow_foreground_only_button", "permission_allow_button"],
    "deny": ["permission_deny_button"],
}[sys.argv[1]]
screen = open(sys.argv[2], encoding="utf-8").read()
for button in buttons:
    found = re.search(
        r'resource-id="com\.android\.permissioncontroller:id/' + button
        + r'"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
        screen,
    )
    if found:
        left, top, right, bottom = map(int, found.groups())
        print((left + right) // 2, (top + bottom) // 2)
        sys.exit(0)
sys.exit(1)
PY
}

# Answers the permission dialog that stands on the screen, if one does, once. The script asks in
# its own wait for the result, so nothing runs in the background and nothing outlives the script.
answer_permission_dialog() { # allow|deny
    local point
    point="$(permission_dialog_point "$1")" && "$adb" -s "$serial" shell input tap $point
    return 0
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" port=5586
    local serial="emulator-$port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }
    # Before the build, so a machine without KalaReach's virtual device does not wait for one.
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        return 3
    fi

    say "building the debug application for the emulator"
    ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts/build.log" 2>&1 \
        || { say "the build failed; see $artefacts/build.log"; return 2; }
    local apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    [ -f "$apk" ] || { say "the build left no package"; return 2; }

    # A device already on the serial is someone else's: it is neither used nor stopped.
    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$port" -no-snapshot-save -no-boot-anim -no-window -no-audio \
        -no-metrics -gpu swiftshader_indirect -netdelay none -netspeed full >"$artefacts/emulator.log" 2>&1 &
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

    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    case "$permissions" in
        granted)
            "$adb" -s "$serial" shell pm grant "$app_id" android.permission.RECORD_AUDIO
            "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null
            ;;
        allow | deny | none) say "the permission question is left to the application, answer: $permissions" ;;
    esac

    # The application reads its data directory, which is the application's own directory on
    # Android (`activity.dataDir`), and `run-as` starts there.
    "$adb" -s "$serial" shell run-as "$app_id" mkdir -p kr-probe
    "$adb" -s "$serial" shell "run-as $app_id sh -c 'printf \"{\\\"run\\\":\\\"$run\\\"}\" > kr-probe/request.json'"
    say "starting the application, run $run"
    "$adb" -s "$serial" shell am start -n "$app_id/.MainActivity" >/dev/null
    # The process is named while it runs: a log read by pid after the application has ended has
    # no pid to read.
    local pid="" tries=0
    while [ -z "$pid" ] && [ "$tries" -lt 20 ]; do
        pid="$("$adb" -s "$serial" shell pidof "$app_id" 2>/dev/null | tr -d '\r')"
        [ -n "$pid" ] || { sleep 1; tries=$((tries + 1)); }
    done

    local text="" until=$((SECONDS + 300))
    while :; do
        text="$("$adb" -s "$serial" shell run-as "$app_id" cat "kr-probe/$result_name" 2>/dev/null | tr -d '\r')"
        case "$text" in *done=1*) break ;; esac
        case "$permissions" in
            allow | deny) answer_permission_dialog "$permissions" ;;
        esac
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/$result_name"
    # What the application said while it ran, kept for a run that wrote no result.
    if [ -n "$pid" ]; then
        "$adb" -s "$serial" logcat -d --pid="$pid" 2>/dev/null | tail -200 >"$artefacts/logcat.log"
    else
        "$adb" -s "$serial" logcat -d 2>/dev/null | tail -200 >"$artefacts/logcat.log"
    fi
    judge "$artefacts/$result_name"
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
