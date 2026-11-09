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
# The first mode, `native-failure`, is the default. The stand-in's answer is built from the offer's
# sections and leads nowhere, so the connection never carries media and fails after about half a
# minute; native code then ends the call. What this proves is the call from the pairing to its end
# through the real daemon and the real native code, not a provider and not audio.
#
# The second mode, `outage`, runs the call against a peer inside the same application (a debug
# build starts one when `kr-probe/peer.json` names a loopback port and a token). The stand-in asks
# the peer for each call's answer, so the call connects and carries audio, and the machine reads
# what the peer received once a second. The checks read the audio each end carried from the
# connection's counters, never from an elapsed time; this script takes the voice service away when
# the application has read its figure of the first audio, and the application then shows the
# control unreachable, exercises the local mute and silence, stops the call without the service
# and finds the closure not confirmed. The peer is a full ICE agent and not the provider's lite
# one, sends nothing to a speaker of this machine (the Android peer mutes its speaker and the iOS
# peer's synthetic device only drains what it is played), and stands in for no provider: what is
# proved is that the call connects to an answer marked as the provider's and carries audio, not that
# the provider's own does.
#
# The emulator's audio: the outage mode starts it with `-audio none` unless `KR_EMULATOR_AUDIO_ARGS`
# says otherwise (it may be set to an empty string); a run may also pass `QEMU_AUDIO_OUT_DRV`,
# `QEMU_WAV_PATH` and `QEMU_AUDIO_IN_DRV` through the environment. The input driver should be
# `none` wherever it works, so that no microphone of this machine is opened.
#
# A simulator or an emulator only inside the Mac's device lease, and the builds inside a build
# slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-voice-call-device.sh ios
#
# Usage:
#   scripts/e2e-voice-call-device.sh ios [native-failure|outage]
#   scripts/e2e-voice-call-device.sh android [native-failure|outage]
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available,
# 4 every check that measured passed and some check could not measure (a direction of audio that
# nothing counted, a lock screen the peer heard no call to have published); the run says which, and
# is partial evidence.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
mode="${2:-native-failure}"
case "$platform" in
    ios | android) ;;
    *) printf 'usage: %s ios|android [native-failure|outage]\n' "$0" >&2; exit 2 ;;
esac
case "$mode" in
    native-failure | outage) ;;
    *) printf 'usage: %s ios|android [native-failure|outage]\n' "$0" >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-device-$platform-$mode${KR_RUN_TAG:+-$KR_RUN_TAG}"
mkdir -p "${artefacts:?}"
run="$(uuidgen)"
app_id=to.kala.reach
result_name="result-$run.txt"
log="$artefacts/run.log"
: >"${log:?}"
# The harness's files hold an invitation's secret: they live on the internal disk, for this run.
harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-voice-device.XXXXXX")"
harness_pid=""
# The loopback port of the application's peer and the token it accepts, made for this run. The
# port is free on this machine when it is chosen; on the emulator the same number is the peer's
# port inside the guest, reached through an adb forward.
peer_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
peer_token="$(uuidgen)"
# The emulator this script started, by its pid and its serial, and the adb that reaches it.
emulator_pid=""
emulator_serial=""
emulator_adb=""
# Whether the device on the serial was shown to be KalaReach's virtual device. Until it is, nothing is
# installed into it, changed in it or stopped through it, and only this script's own emulator process
# is ended, by its pid.
emulator_checked=0
# Set once this run has made its adb forward of the peer's port, so that only that forward is removed.
peer_forward=""
# The simulator application's directory for the run's request, set when the run has made it, so that its
# request and peer files are removed however the run ends.
app_data_directory=""

say() { printf '== [voice-call-device] %s\n' "$*" | tee -a "$log"; }

# shellcheck source=scripts/lib/voice-call-judge.sh
. "$here/scripts/lib/voice-call-judge.sh"

# Ends what this script started and removes what it made. The harness is asked to finish; its
# process is ended only when it does not, and only by the pid this script recorded. The emulator, once
# its device was shown to be KalaReach's, is asked to stop through its serial, which the script took only
# after it found the serial free, and is ended by its pid when it does not stop (an emulator not yet
# shown to be is ended by its pid alone).
finish() {
    touch "$harness/finish" 2>/dev/null
    # A later launch of the installed application must not find this run's request or start its peer.
    [ -z "$app_data_directory" ] || rm -f "${app_data_directory:?}/request.json" "${app_data_directory:?}/peer.json"
    if [ -n "$harness_pid" ]; then
        local waited=0
        while kill -0 "$harness_pid" 2>/dev/null && [ "$waited" -lt 30 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$harness_pid" 2>/dev/null && kill "$harness_pid" 2>/dev/null
    fi
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        if [ "$emulator_checked" = 1 ]; then
            [ -z "$peer_forward" ] || "$emulator_adb" -s "$emulator_serial" forward --remove "tcp:$peer_port" >/dev/null 2>&1
            "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        else
            kill "$emulator_pid" 2>/dev/null
        fi
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
    local audio_port="" audio_token=""
    if [ "$mode" = outage ]; then
        audio_port="$peer_port"
        audio_token="$peer_token"
    fi
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SECONDS=900 \
        KR_HARNESS_AUDIO_PORT="$audio_port" KR_HARNESS_AUDIO_TOKEN="$audio_token" \
        KR_HARNESS_PLATFORM="$platform" KR_TEST_ARTIFACTS_DIR="$artefacts" \
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
    ( umask 077; python3 - "$run" "$origin" "$token" "$harness/invitation.txt" "$mode" >"$1" <<'PY'
import json
import sys

run, origin, token, invitation, mode = sys.argv[1:6]
print(json.dumps({
    "run": run,
    "harness": {
        "origin": origin,
        "token": token,
        "invitation": open(invitation, encoding="utf-8").read().strip(),
        "mode": mode.replace("-", "_"),
    },
}))
PY
    )
}

# The checks a whole call must have made and passed, by the names the application gives them. A
# result with fewer is a run that stopped short, whatever it says at its end. A name that ends in
# "?" may be reported as not measured; the run is then partial evidence.
if [ "$mode" = outage ]; then
    required_checks=(
        "paired"
        "connected to the host"
        "voice is allowed"
        "a call is prepared"
        "the host started the call"
        "the call runs with its control attached"
        "native code holds the call"
        "audio reaches the call from the peer?"
        "audio leaves the call for the peer?"
        "the call takes audio to the speaker side?"
        "the first audio played out?"
        "the control reads unreachable when the service is gone"
        "the microphone mutes with the service gone"
        "the speaker is silenced with the service gone"
        "the media stays connected with the service gone?"
        "a stop with the service gone returns"
        "the media stopped on this device"
        "the host revoked the grant"
        "the closure of the call at the service is not confirmed"
        "nothing held after the end"
    )
else
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
fi

# Takes the voice service away once the application has read its figure of the first audio: the
# outage mode's cue, read from the lines the application has written so far.
take_the_service_away_when_cued() { # <the result text so far>
    [ "$mode" = outage ] || return 0
    [ ! -e "$harness/down" ] || return 0
    case "$1" in
        *"check=the first audio played out ok="*) touch "$harness/down"; say "the voice service is taken away" ;;
    esac
}

# Reads the lines the application wrote, and decides the run.
judge() { # <result file>
    judge_voice_call_result "$1" "$run" "${required_checks[@]}"
}

# Reads what the stand-in and the host saw, and decides whether it is what the run leaves.
judge_host() {
    # The application's lines go to the machine side first, which reads the figure of the first
    # audio from them when it finishes.
    [ ! -s "$artefacts/$result_name" ] || cp "$artefacts/$result_name" "$harness/figures.txt"
    touch "$harness/finish"
    local waited=0
    while [ ! -s "$harness/report.json" ] && [ "$waited" -lt 60 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    [ -s "$harness/report.json" ] || { say "the host wrote no report; see $artefacts/harness.log"; return 2; }
    cp "$harness/report.json" "$artefacts/host-report.json"
    # A direction the application could not measure is no evidence against the peer's side of it.
    local flags=()
    if grep -q '^check=audio leaves the call for the peer ok=2 ' "$artefacts/$result_name" 2>/dev/null; then
        flags=(--send-unmeasured)
    fi
    python3 "$here/scripts/lib/voice-call-host-judge.py" "$artefacts/host-report.json" "$mode" "$platform" \
        ${flags[@]+"${flags[@]}"} | tee -a "$log"
    local rc=${PIPESTATUS[0]}
    case "$rc" in
        0) say "every host check passed" ;;
        4) say "every host check that measured passed, and some could not measure" ;;
        *) say "a host check did not pass"; return 2 ;;
    esac
    return "$rc"
}

# Decides the run from the two verdicts: a failure in either fails it, and a part that could not
# measure in either leaves it partial.
conclude() { # <application status> <host status>
    if [ "$1" = 2 ] || [ "$2" = 2 ]; then
        say "the run failed"
        return 2
    fi
    if [ "$1" = 4 ] || [ "$2" = 4 ]; then
        say "the run is partial: every check that measured passed, and some could not measure"
        return 4
    fi
    say "the run passed"
    return 0
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
    app_data_directory="$directory"
    write_request "$directory/request.json" || return 2
    # The peer the application starts at launch, which only the outage mode asks for. A simulator
    # shares this machine's loopback interface, so the peer's port is reached as it is.
    if [ "$mode" = outage ]; then
        ( umask 077; printf '{"port":%s,"token":"%s"}\n' "$peer_port" "$peer_token" >"$directory/peer.json" )
    fi
    say "starting the application, run $run"
    xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; return 2; }

    local waited=0
    while [ ! -s "$directory/$result_name" ] || ! grep -q '^done=1$' "$directory/$result_name"; do
        take_the_service_away_when_cued "$(cat "$directory/$result_name" 2>/dev/null)"
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
    conclude "$app_rc" "$host_rc"
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" serial_port=5586
    local serial="emulator-$serial_port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }
    # Before the builds, so a machine without KalaReach's virtual device does not wait for one.
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        return 3
    fi

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
    # The call's audio needs the guest to have an audio device, so the outage mode does not disable
    # audio support; `-audio none` is the first thing tried (see the header).
    local audio=(-no-audio)
    if [ "$mode" = outage ]; then
        read -r -a audio <<<"${KR_EMULATOR_AUDIO_ARGS--audio none}"
    fi
    say "starting the emulator $avd, audio arguments: ${audio[*]-none}"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim -no-window \
        ${audio[@]+"${audio[@]}"} \
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
    # And the device on the serial is KalaReach's virtual device: one that took the serial after the
    # check that it was free would have answered the boot wait too. Before anything is installed,
    # set or stopped on it.
    local reported
    reported="$(kr_android_device_name "$adb" "$serial")"
    if [ "$reported" != "$avd" ]; then
        say "the device on $serial reports ${reported:-no name}, not $avd, so it is left alone: nothing is installed into it, changed in it or stopped through it"
        return 3
    fi
    emulator_checked=1

    # Only Wi-Fi carries the run. The emulator's simulated mobile network drops and returns every
    # minute or so, and a loss the run did not make would be read as part of what it measures.
    # KR_EMULATOR_MOBILE_DATA=on leaves it as the emulator starts it.
    if [ "${KR_EMULATOR_MOBILE_DATA:-off}" != on ]; then
        "$adb" -s "$serial" shell svc data disable >/dev/null 2>&1
        say "mobile data is off on the emulator"
    fi

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
    # The other way: the application's peer listens on the emulator's loopback interface, and this
    # machine reaches it on the same port number.
    if [ "$mode" = outage ]; then
        # Without a rebind, so that a port someone else forwarded since it was chosen is not taken over.
        "$adb" -s "$serial" forward --no-rebind "tcp:$peer_port" "tcp:$peer_port" >/dev/null \
            || { say "the application's peer could not be forwarded to this machine"; return 2; }
        peer_forward=1
    fi

    local request="$harness/request.json" remote="/data/local/tmp/kr-request-$run.json"
    write_request "$request" || return 2
    # The application reads its data directory, which is the application's own directory on
    # Android (`activity.dataDir`), and `run-as` starts there.
    "$adb" -s "$serial" shell run-as "$app_id" mkdir -p kr-probe
    "$adb" -s "$serial" push "$request" "$remote" >/dev/null
    "$adb" -s "$serial" shell run-as "$app_id" cp "$remote" kr-probe/request.json
    "$adb" -s "$serial" shell rm -f "$remote"
    if [ "$mode" = outage ]; then
        local peer_remote="/data/local/tmp/kr-peer-$run.json" peer_local="$harness/peer.json"
        ( umask 077; printf '{"port":%s,"token":"%s"}\n' "$peer_port" "$peer_token" >"$peer_local" )
        "$adb" -s "$serial" push "$peer_local" "$peer_remote" >/dev/null
        "$adb" -s "$serial" shell run-as "$app_id" cp "$peer_remote" kr-probe/peer.json
        "$adb" -s "$serial" shell rm -f "$peer_remote"
    fi
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
        take_the_service_away_when_cued "$text"
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/$result_name"
    # What the application said while it ran, kept for a run that wrote no result.
    if [ -n "$pid" ]; then
        "$adb" -s "$serial" logcat -d --pid="$pid" 2>/dev/null \
            | grep -v -E 'avc: |AssetManager|HWUI|vulkan|glBind|Tauri/Plugin' | tail -1500 >"$artefacts/logcat.log"
    else
        "$adb" -s "$serial" logcat -d 2>/dev/null | tail -300 >"$artefacts/logcat.log"
    fi
    local app_rc=0 host_rc=0
    judge "$artefacts/$result_name" || app_rc=$?
    judge_host || host_rc=$?
    conclude "$app_rc" "$host_rc"
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
