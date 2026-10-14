#!/usr/bin/env bash
#
# Drives the voice call's bridge on the iOS Simulator or the Android emulator, with the real
# application, the real platform plugin and the application's own call.
#
# A debug build of the application reads a request from its data directory when it starts, runs
# the call's commands from an open to an end (companion-tauri's `probe`), and writes one line per
# check beside the request. This script builds that application, starts one device, puts the
# request where the application reads it, starts the application, and reads the lines back. It
# claims what the lines say and nothing more: a check the application did not report is a check
# that did not run, and any line that is not `ok=1`, or a result that never says `done=1`, fails
# the run.
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
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
case "$platform" in
    ios | android) ;;
    *) printf 'usage: %s ios|android\n' "$0" >&2; exit 2 ;;
esac

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-bridge-$platform"
mkdir -p "${artefacts:?}"
run="$(uuidgen)"
app_id=to.kala.reach
result_name="result-$run.txt"
log="$artefacts/run.log"
: >"${log:?}"

say() { printf '== [voice-call-bridge] %s\n' "$*" | tee -a "$log"; }

# Reads the lines the application wrote, and decides the run.
judge() { # <result file>
    local file=$1 bad=0
    [ -s "$file" ] || { say "the application wrote no result"; return 2; }
    grep -q "^run=$run\$" "$file" || { say "the result names another run"; return 2; }
    while IFS= read -r line; do
        say "$line"
        case "$line" in
            check=*" ok=1 "*) ;;
            check=*) bad=1 ;;
        esac
    done <"$file"
    grep -q '^done=1$' "$file" || { say "the result never says done"; return 2; }
    [ "$bad" = 0 ] || { say "a check did not pass"; return 2; }
    say "every check passed"
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

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd="${KR_ANDROID_AVD:-Nines_API_36_Play}"
    local adb="$sdk/platform-tools/adb" port=5586
    local serial="emulator-$port"
    [ -x "$adb" ] || { say "no adb under $sdk"; return 3; }

    say "building the debug application for the emulator"
    ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts/build.log" 2>&1 \
        || { say "the build failed; see $artefacts/build.log"; return 2; }
    local apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    [ -f "$apk" ] || { say "the build left no package"; return 2; }

    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$port" -no-snapshot-save -no-boot-anim -no-window -no-audio \
        -no-metrics -gpu swiftshader_indirect -netdelay none -netspeed full >"$artefacts/emulator.log" 2>&1 &
    local emulator=$!
    local booted=0
    for _ in $(seq 1 180); do
        if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
        kill -0 "$emulator" 2>/dev/null || break
        sleep 2
    done
    [ "$booted" = 1 ] || { say "the emulator did not come up"; kill "$emulator" 2>/dev/null; return 3; }

    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.RECORD_AUDIO
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

    # The application reads its data directory, which is the application's own directory on
    # Android (`activity.dataDir`), and `run-as` starts there.
    "$adb" -s "$serial" shell run-as "$app_id" mkdir -p kr-probe
    "$adb" -s "$serial" shell "run-as $app_id sh -c 'printf \"{\\\"run\\\":\\\"$run\\\"}\" > kr-probe/request.json'"
    say "starting the application, run $run"
    "$adb" -s "$serial" shell am start -n "$app_id/.MainActivity" >/dev/null

    local waited=0 text=""
    while :; do
        text="$("$adb" -s "$serial" shell run-as "$app_id" cat "kr-probe/$result_name" 2>/dev/null | tr -d '\r')"
        case "$text" in *done=1*) break ;; esac
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -lt 300 ] || break
    done
    printf '%s\n' "$text" >"$artefacts/$result_name"
    # What the application said while it ran, kept for a run that wrote no result.
    "$adb" -s "$serial" logcat -d --pid="$("$adb" -s "$serial" shell pidof "$app_id" | tr -d '\r')" 2>/dev/null \
        | tail -200 >"$artefacts/logcat.log"
    "$adb" -s "$serial" emu kill >/dev/null 2>&1
    wait "$emulator" 2>/dev/null
    judge "$artefacts/$result_name"
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
