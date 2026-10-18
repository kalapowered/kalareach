#!/usr/bin/env bash
#
# Runs a whole voice call on the iOS Simulator or the Android emulator, with the real application,
# the real platform plugin and a real host.
#
# The machine side is `kr-controller`'s ignored `voice_device` suite: the real daemon on the
# loopback interface and a stand-in for the managed voice service on one loopback port. This script
# builds the debug application and that suite, starts one device, starts the suite, has it issue a
# direct invitation, and hands the application a request (the stand-in's origin, the token its
# control accepts and the invitation). The application pairs with the host, allows voice, starts a
# call through the commands the page uses and reads the call to its end (companion-tauri's `probe`
# harness), writing one line per check beside the request. The script reads those lines back and
# the report the suite wrote of what the stand-in saw, and fails the run on any check that is not
# `ok=1`, any result that never says `done=1`, and any host-side figure that is not what a call
# that ran and ended once leaves.
#
# The stand-in's answer is built from the offer's sections and leads nowhere, so the connection
# never carries media and fails after about half a minute; native code then ends the call. What
# this proves is the call from the pairing to its end through the real daemon and the real native
# code, not a provider and not audio.
#
# A simulator or an emulator only inside the Mac's device lease, and the builds inside a build
# slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-voice-call-device.sh ios
#
# Usage:
#   scripts/e2e-voice-call-device.sh ios
#   scripts/e2e-voice-call-device.sh android
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

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-device-$platform"
mkdir -p "${artefacts:?}"
run="$(uuidgen)"
app_id=to.kala.reach
result_name="result-$run.txt"
log="$artefacts/run.log"
: >"${log:?}"
# The harness's files hold an invitation's secret: they live on the internal disk, for this run.
harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-voice-device.XXXXXX")"
harness_pid=""
# The emulator this script started, by its pid and its serial, and the adb that reaches it.
emulator_pid=""
emulator_serial=""
emulator_adb=""

say() { printf '== [voice-call-device] %s\n' "$*" | tee -a "$log"; }

# Ends what this script started and removes what it made. The harness is asked to finish; its
# process is ended only when it does not, and only by the pid this script recorded. The emulator is
# asked to stop through its serial, which the script took only after it found the serial free, and
# is ended by its pid when it does not stop.
finish() {
    touch "$harness/finish" 2>/dev/null
    if [ -n "$harness_pid" ]; then
        local waited=0
        while kill -0 "$harness_pid" 2>/dev/null && [ "$waited" -lt 30 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$harness_pid" 2>/dev/null && kill "$harness_pid" 2>/dev/null
    fi
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

# Builds the machine side once, and says where its executable is.
build_harness() {
    say "building the host and the voice service stand-in"
    cargo test --manifest-path "$here/Cargo.toml" -p kr-controller --test voice_device --no-run \
        --message-format=json >"$artefacts/harness-build.json" 2>"$artefacts/harness-build.log" \
        || { say "the harness did not build; see $artefacts/harness-build.log"; return 2; }
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
        and message["target"]["name"] == "voice_device"
    ):
        found = message["executable"]
print(found)
PY
)"
    [ -n "$harness_exe" ] && [ -x "$harness_exe" ] || { say "the harness left no executable"; return 2; }
}

# Starts the host and the stand-in for a phone that reaches this machine as `peer`, and waits
# until they are up. Sets `origin`, `port` and `token`.
start_harness() { # <peer>
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SECONDS=900 \
        "$harness_exe" --ignored --exact a_phone_is_paired_and_runs_a_call_against_a_real_host --nocapture \
        >"$artefacts/harness.log" 2>&1 &
    harness_pid=$!
    local waited=0
    while [ ! -s "$harness/ready.json" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the harness ended before it was ready; see $artefacts/harness.log"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 180 ] || { say "the harness was not ready in time"; return 2; }
    done
    origin="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["origin"])' "$harness/ready.json")"
    token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$harness/ready.json")"
    port="${origin##*:}"
    say "the host and the voice service are up, the service at $origin"
}

# Has the harness issue the invitation, and writes the request the application reads into
# `request_file`.
write_request() { # <request file>
    touch "$harness/go"
    local waited=0
    while [ ! -s "$harness/invitation.txt" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the harness ended before it issued the invitation; see $artefacts/harness.log"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 60 ] || { say "no invitation was issued in time"; return 2; }
    done
    ( umask 077; python3 - "$run" "$origin" "$token" "$harness/invitation.txt" >"$1" <<'PY'
import json
import sys

run, origin, token, invitation = sys.argv[1:5]
print(json.dumps({
    "run": run,
    "harness": {
        "origin": origin,
        "token": token,
        "invitation": open(invitation, encoding="utf-8").read().strip(),
    },
}))
PY
    )
}

# The checks a whole call must have made and passed, by the names the application gives them. A
# result with fewer is a run that stopped short, whatever it says at its end.
required_checks=(
    "paired"
    "connected to the host"
    "voice is allowed"
    "a call is prepared"
    "the host started the call"
    "the call runs with its control attached"
    "native code holds the call"
    "native code ends a call whose connection fails"
    "the media stopped on this device"
    "the host revoked the grant"
    "the voice service was told the call is over"
    "nothing held after the end"
)

# Reads the lines the application wrote, and decides the run.
judge() { # <result file>
    local file=$1 bad=0 name
    [ -s "$file" ] || { say "the application wrote no result"; return 2; }
    grep -q "^run=$run\$" "$file" || { say "the result names another run"; return 2; }
    while IFS= read -r line; do
        say "$line"
        # A check's name holds no "=", so its verdict is the one before its detail, whatever the
        # detail says.
        case "$line" in
            check=*)
                [ "$(printf '%s' "$line" | sed -n 's/^check=[^=]* ok=\([01]\) detail=.*/\1/p')" = 1 ] || bad=1
                ;;
        esac
    done <"$file"
    grep -q '^done=1$' "$file" || { say "the result never says done"; return 2; }
    [ "$bad" = 0 ] || { say "a check did not pass"; return 2; }
    for name in "${required_checks[@]}"; do
        grep -q "^check=$name ok=1 detail=" "$file" || { say "the check '$name' was not made"; return 2; }
    done
    say "every check of the application passed"
}

# Reads what the stand-in and the host saw, and decides whether it is what a call that ran and
# ended once leaves.
judge_host() {
    touch "$harness/finish"
    local waited=0
    while [ ! -s "$harness/report.json" ] && [ "$waited" -lt 60 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    [ -s "$harness/report.json" ] || { say "the host wrote no report; see $artefacts/harness.log"; return 2; }
    cp "$harness/report.json" "$artefacts/host-report.json"
    python3 - "$artefacts/host-report.json" <<'PY' | tee -a "$log"
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
expected = "Bearer " + report["token"]
checks = [
    ("the service created one call", report["creations"] == 1, report["creations"]),
    ("the host told the service the call is over", report["host_closes"] >= 1, report["host_closes"]),
    # The service opens a control for the phone's token only, so a control that attached used it.
    (
        "the control attached with the phone's token",
        bool(report["control_tokens"]) and all(each == expected for each in report["control_tokens"]),
        len(report["control_tokens"]),
    ),
    (
        "the control asked the service to close the call",
        "close" in report["control_commands"],
        ",".join(report["control_commands"]),
    ),
]
bad = False
for name, ok, detail in checks:
    print("== [voice-call-device] host check=%s ok=%d detail=%s" % (name, ok, detail))
    bad = bad or not ok
sys.exit(1 if bad else 0)
PY
    local rc=${PIPESTATUS[0]}
    [ "$rc" = 0 ] || { say "a host check did not pass"; return 2; }
    say "every host check passed"
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
    # The microphone is allowed up front, so no dialog stands between the call and its check.
    xcrun simctl privacy "$udid" grant microphone "$app_id"

    # A simulator shares this machine's network: the host is where the invitation says.
    start_harness 127.0.0.1 || return 2
    local data directory
    data="$(xcrun simctl get_app_container "$udid" "$app_id" data)"
    directory="$data/Library/Application Support/$app_id/kr-probe"
    mkdir -p "$directory"
    write_request "$directory/request.json" || return 2
    say "starting the application, run $run"
    xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; return 2; }

    local waited=0
    while [ ! -s "$directory/$result_name" ] || ! grep -q '^done=1$' "$directory/$result_name"; do
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -lt 420 ] || break
    done
    cp "$directory/$result_name" "$artefacts/$result_name" 2>/dev/null
    # What the application said while it ran, kept for a run that wrote no result.
    xcrun simctl spawn "$udid" log show --last 15m --style compact \
        --predicate 'process == "KalaReach"' 2>/dev/null | tail -300 >"$artefacts/application.log"
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    local app_rc=0 host_rc=0
    judge "$artefacts/$result_name" || app_rc=$?
    judge_host || host_rc=$?
    [ "$app_rc" = 0 ] && [ "$host_rc" = 0 ] || return 2
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd="${KR_ANDROID_AVD:-Nines_API_36_Play}"
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" serial_port=5586
    local serial="emulator-$serial_port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }

    say "building the debug application for the emulator"
    ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts/build.log" 2>&1 \
        || { say "the build failed; see $artefacts/build.log"; return 2; }
    local apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    [ -f "$apk" ] || { say "the build left no package"; return 2; }
    build_harness || return 2

    # A device already on the serial is someone else's: it is neither used nor stopped.
    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim -no-window -no-audio \
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
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.RECORD_AUDIO
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

    # The emulator reaches this machine's loopback interface as 10.0.2.2, so the invitation names
    # the host there; the voice service is on this machine's loopback TCP port, which the emulator
    # reaches as its own through a reverse forward.
    start_harness 10.0.2.2 || return 2
    "$adb" -s "$serial" reverse "tcp:$port" "tcp:$port" >/dev/null \
        || { say "the voice service could not be forwarded to the emulator"; return 2; }

    local request="$harness/request.json" remote="/data/local/tmp/kr-request-$run.json"
    write_request "$request" || return 2
    # The application reads its data directory, which is the application's own directory on
    # Android (`activity.dataDir`), and `run-as` starts there.
    "$adb" -s "$serial" shell run-as "$app_id" mkdir -p kr-probe
    "$adb" -s "$serial" push "$request" "$remote" >/dev/null
    "$adb" -s "$serial" shell run-as "$app_id" cp "$remote" kr-probe/request.json
    "$adb" -s "$serial" shell rm -f "$remote"
    say "starting the application, run $run"
    "$adb" -s "$serial" shell am start -n "$app_id/.MainActivity" >/dev/null
    # The process is named while it runs: a log read by pid after the application has ended has
    # no pid to read.
    local pid="" tries=0
    while [ -z "$pid" ] && [ "$tries" -lt 20 ]; do
        pid="$("$adb" -s "$serial" shell pidof "$app_id" 2>/dev/null | tr -d '\r')"
        [ -n "$pid" ] || { sleep 1; tries=$((tries + 1)); }
    done

    local text="" until=$((SECONDS + 420))
    while :; do
        text="$("$adb" -s "$serial" shell run-as "$app_id" cat "kr-probe/$result_name" 2>/dev/null | tr -d '\r')"
        case "$text" in *done=1*) break ;; esac
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/$result_name"
    # What the application said while it ran, kept for a run that wrote no result.
    if [ -n "$pid" ]; then
        "$adb" -s "$serial" logcat -d --pid="$pid" 2>/dev/null | tail -300 >"$artefacts/logcat.log"
    else
        "$adb" -s "$serial" logcat -d 2>/dev/null | tail -300 >"$artefacts/logcat.log"
    fi
    local app_rc=0 host_rc=0
    judge "$artefacts/$result_name" || app_rc=$?
    judge_host || host_rc=$?
    [ "$app_rc" = 0 ] && [ "$host_rc" = 0 ] || return 2
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
