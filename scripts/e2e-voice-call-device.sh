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
# The third mode, `delegating`, runs the call with the gate on that hands spoken requests to the
# host. In the shipped configuration a delegation the provider announces is answered to the model
# that nothing was done and the host is sent nothing; a debug build's probe turns the acceptance on
# for its own call, and the same call is then run through the legs of the gate. A leg is one call,
# against a host that holds one real session (so that a status can be read), a stand-in service and
# a fresh install. The application plays the person and the provider: it writes the provider's
# events to the call's own `oai-events` channel through the peer, has the stand-in announce each
# delegation on the control socket as the service does, and reads what became of each one from the
# call's own state, so no leg decides by a time it does not control. Each negative leg is read
# beside its control, a request the same call handed over before the break the leg makes:
#
#   production        the shipped configuration: "nothing was done", nothing at the host
#   positive          no break, not the first utterance: the host performs a status
#   first_utterance   the first thing said in the call never acts
#   mute              a mute and an unmute between two parts of a command
#   gap               the debug build's drop hook takes audio out of the recorder
#   dtx               the peer's answer turns discontinuous transmission on
#   malformed         a required event on the data channel that fails its schema
#   late_fragment     a fragment of a request arrives after the request was read
#   broker_disagrees  the service announces a delegation at another offset than the provider's
#
# A leg counts only on a call whose own recorder did not break before the leg's subject: the leg reads
# native code's record of capture before it says anything, and a break it did not make (the gate's
# gap between two recorder buffers fires when a loaded machine stalls the emulator at the call's
# start) ends that attempt, which the script keeps under its own name and plays again on a new call,
# up to `KR_LEG_ATTEMPTS` (three attempts in all), when that break is the only thing that failed in
# it. A leg that breaks by itself on every attempt fails, and a leg that passed only on a replay ends
# with exit 4, partial, naming each attempt's failure: a rerun is not a pass.
#
# `delegating` with no leg runs them all, one after another, with one build and one device. The
# simulator has no recorder, so a run with the peer's file naming a synthetic recorder gives the call
# a recording device of its own that makes a tone, opens no microphone of this machine and is the
# one the drop hook acts on; the emulator records silence at the pace of real audio. Neither proves
# anything of what a phone's system does to a recording (the Android rule that a silenced recording
# is a break, a route change, a call or Siri): that needs a phone, and this run claims no production
# stop point.
#
# The emulator's audio: the outage and delegating modes start it with `-audio none` unless
# `KR_EMULATOR_AUDIO_ARGS` says otherwise (it may be set to an empty string); a run may also pass
# `QEMU_AUDIO_OUT_DRV`, `QEMU_WAV_PATH` and `QEMU_AUDIO_IN_DRV` through the environment. The input
# driver should be `none` wherever it works, so that no microphone of this machine is opened.
#
# The Android application is the debug build, which is not minified. `KR_MINIFY_DEBUG=1` runs the
# minifier on it, with the release build's rules, and keeps the debug build's test hooks: the call
# then starts in an application whose unreached classes the minifier has removed and renamed, as it
# does the store's (in R8's debug mode, which does not optimise across the classes that are left).
# A native library that finds a class by name aborts the first call there when the rules do not
# keep the class. Any value of the variable other than 1 stops the run.
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
#   scripts/e2e-voice-call-device.sh ios|android delegating [<leg>]
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available,
# 4 every check that measured passed and some check could not measure (a direction of audio that
# nothing counted, a lock screen the peer heard no call to have published), or a leg passed only on a
# replay; the run says which, and is partial evidence. A run of several legs exits with the worst of
# theirs, so exit 0 of `delegating` says that every leg passed on its first attempt.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
mode="${2:-native-failure}"
usage() {
    printf 'usage: %s ios|android [native-failure|outage]\n       %s ios|android delegating [production|positive|first_utterance|mute|gap|dtx|malformed|late_fragment|broker_disagrees]\n' "$0" "$0" >&2
    exit 2
}
case "$platform" in
    ios | android) ;;
    *) usage ;;
esac
case "$mode" in
    native-failure | outage | delegating) ;;
    *) usage ;;
esac
all_legs=(production positive first_utterance mute gap dtx malformed late_fragment broker_disagrees)
legs=("")
if [ "$mode" = delegating ]; then
    wanted="${3:-all}"
    if [ "$wanted" = all ]; then
        legs=("${all_legs[@]}")
    else
        known=0
        for each in "${all_legs[@]}"; do
            [ "$each" != "$wanted" ] || known=1
        done
        [ "$known" = 1 ] || usage
        legs=("$wanted")
    fi
elif [ -n "${3:-}" ]; then
    usage
fi

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts_base="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-device-$platform-$mode${KR_RUN_TAG:+-$KR_RUN_TAG}"
app_id=to.kala.reach
# What belongs to one run (one call): set by `begin_run`, ended by `end_run`.
leg=""
artefacts=""
run=""
result_name=""
log=""
harness=""
harness_pid=""
peer_port=""
peer_token=""
# The loopback port of the stand-in the run forwarded into the emulator, set once it has, so that
# only that forward is removed.
service_forward=""
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

say() { printf '== [voice-call-device] %s\n' "$*" | tee -a "${log:-/dev/null}"; }

# shellcheck source=scripts/lib/voice-call-judge.sh
. "$here/scripts/lib/voice-call-judge.sh"

# Starts one run: a name, a directory for its evidence, a directory on the internal disk for the
# harness's files (they hold an invitation's secret), and a loopback port and a token for the
# application's peer. The port is free on this machine when it is chosen; on the emulator the same
# number is the peer's port inside the guest, reached through an adb forward.
begin_run() { # <leg>
    leg="$1"
    run="$(uuidgen)"
    result_name="result-$run.txt"
    artefacts="$artefacts_base${leg:+-$leg}"
    mkdir -p "${artefacts:?}"
    log="$artefacts/run.log"
    : >"${log:?}"
    harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-voice-device.XXXXXX")"
    harness_pid=""
    peer_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    peer_token="$(uuidgen)"
    peer_forward=""
    service_forward=""
    app_data_directory=""
    set_required_checks
}

# Ends what this run started and removes what it made. The harness is asked to finish; its process is
# ended only when it does not, and only by the pid this script recorded. A forward made into the
# emulator is removed through the serial the script took after it found it free.
end_run() {
    [ -n "$harness" ] || return 0
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
    if [ "$emulator_checked" = 1 ] && [ -n "$emulator_adb" ]; then
        [ -z "$peer_forward" ] || "$emulator_adb" -s "$emulator_serial" forward --remove "tcp:$peer_port" >/dev/null 2>&1
        [ -z "$service_forward" ] || "$emulator_adb" -s "$emulator_serial" reverse --remove "tcp:$service_forward" >/dev/null 2>&1
    fi
    rm -rf "${harness:?}"
    harness=""
    harness_pid=""
}

# Ends the run, then the emulator: once its device was shown to be KalaReach's, it is asked to stop
# through its serial, and is ended by its pid when it does not stop (an emulator not yet shown to be
# is ended by its pid alone).
finish() {
    end_run
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        if [ "$emulator_checked" = 1 ]; then
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
}
trap finish EXIT

# Builds the machine side once, and says where its executable is.
build_harness() {
    local out="$artefacts_base"
    mkdir -p "${out:?}"
    say "building the host and the voice service stand-in"
    cargo test --manifest-path "$here/Cargo.toml" -p kr-controller --test voice_device --no-run \
        --message-format=json >"$out/harness-build.json" 2>"$out/harness-build.log" \
        || { say "the harness did not build; see $out/harness-build.log"; return 2; }
    harness_exe="$(python3 - "$out/harness-build.json" <<'PY'
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
# until they are up. Sets `origin`, `port` and `token`. A run with a peer (the outage and the
# delegating modes) has the stand-in ask the peer for each call's answer; a delegating run also has
# the host hold one real session, and names its leg, which the answer may depend on.
start_harness() { # <peer>
    local audio_port="" audio_token="" sessions="" harness_leg=""
    if [ "$mode" = outage ] || [ "$mode" = delegating ]; then
        audio_port="$peer_port"
        audio_token="$peer_token"
    fi
    if [ "$mode" = delegating ]; then
        sessions=1
        harness_leg="$leg"
    fi
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SECONDS=900 \
        KR_HARNESS_AUDIO_PORT="$audio_port" KR_HARNESS_AUDIO_TOKEN="$audio_token" \
        KR_HARNESS_SESSIONS="$sessions" KR_HARNESS_LEG="$harness_leg" \
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
    ( umask 077; python3 - "$run" "$origin" "$token" "$harness/invitation.txt" "$mode" "$leg" "$harness/ready.json" >"$1" <<'PY'
import json
import sys

run, origin, token, invitation, mode, leg, ready = sys.argv[1:8]
harness = {
    "origin": origin,
    "token": token,
    "invitation": open(invitation, encoding="utf-8").read().strip(),
    "mode": mode.replace("-", "_"),
}
if mode == "delegating":
    harness["leg"] = leg
    harness["session_ids"] = json.load(open(ready, encoding="utf-8")).get("session_ids", [])
print(json.dumps({"run": run, "harness": harness}))
PY
    )
}

# The checks a whole call must have made and passed, by the names the application gives them. A
# result with fewer is a run that stopped short, whatever it says at its end. A name that ends in
# "?" may be reported as not measured; the run is then partial evidence.
set_required_checks() {
    case "$mode" in
        outage)
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
            ;;
        delegating)
            required_checks=(
                "the host named a session to read"
                "paired"
                "connected to the host"
                "voice is allowed"
                "a call is prepared"
                "the host started the call"
                "the call runs with its control attached"
                "native code holds the call"
                "native code's capture is on"
                "the provider's events channel is open"
                "the call carries audio before the leg begins"
                "the recorder delivered without a break before the leg began"
            )
            case "$leg" in
                production)
                    required_checks+=(
                        "a delegation the service announces is answered that nothing was done"
                        "what the data channel says changes nothing the call shows"
                    )
                    ;;
                positive)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said after it is performed"
                    )
                    ;;
                first_utterance)
                    required_checks+=(
                        "the first utterance is refused"
                        "the same command said after it is performed"
                    )
                    ;;
                mute)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said before the break is performed"
                        "the person mutes between two parts of a command"
                        "the microphone is back to capturing after the unmute"
                        "a mute between two parts of a command refuses it"
                        "the call stays refused after the microphone is back"
                    )
                    ;;
                gap)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said before the break is performed"
                        "the drop hook took audio out of the recorder"
                        "a gap in the recorder refuses the command"
                    )
                    ;;
                dtx)
                    required_checks+=("a command in a call whose answer turns DTX on is refused")
                    ;;
                malformed)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said before the break is performed"
                        "a required event that fails its schema refuses the next command"
                    )
                    ;;
                late_fragment)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said before the late fragment is performed"
                        "a fragment after the read taints the call and the earlier outcome stands"
                        "the next command is refused"
                    )
                    ;;
                broker_disagrees)
                    required_checks+=(
                        "the first utterance is refused"
                        "a status said before the break is performed"
                        "a delegation the voice service does not announce as the provider did is refused"
                        "the refusal leaves the call as it was"
                    )
                    ;;
            esac
            required_checks+=(
                "what the call showed of each delegation"
                "native code held the call to the leg's end"
                "the person ends the call"
                "the media stopped on this device"
                "the host revoked the grant"
                "the voice service was told the call is over"
                "the end names no request that may have been carried out"
                "nothing held after the end"
            )
            ;;
        *)
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
            ;;
    esac
}

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
    # The judge's own exit status is kept beside the report, so that a run which never got a verdict
    # from it (no report, or a judge that stopped) is never taken for one that failed only on the
    # recorder's break.
    rm -f "${artefacts:?}/host-judge.rc"
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
        ${leg:+"$leg"} ${flags[@]+"${flags[@]}"} | tee -a "$log"
    local rc=${PIPESTATUS[0]}
    printf '%s\n' "$rc" >"$artefacts/host-judge.rc"
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

# Decides every run of a script from the verdict of each: the worst of them, where a failure is
# worse than a run that could not measure.
worst=0
note_verdict() { # <leg> <status> [<attempts>]
    say "== leg ${1:-the call} exit $2${3:+ after $3 attempts}"
    case "$2" in
        0) ;;
        4) [ "$worst" != 0 ] || worst=4 ;;
        *) worst=2 ;;
    esac
}

# Plays one run of a leg, and plays it again on a new call, up to `KR_LEG_ATTEMPTS` (three attempts in
# all), when the only thing that failed in it is the call's own recorder having broken by itself (see
# `leg_is_replayable`): a break the leg did not make, which a phone's recorder can make when the device
# is busy with its own start (the emulator on a loaded machine does). The attempt counts for nothing,
# is kept under its own name with the failed checks it lists, and the leg's verdict is its last
# attempt's. An attempt in which anything else failed (the revocation of the grant, the end of the
# call, a wrong or doubled reply to a delegation, a host that gave no verdict, a result that never says
# done) fails the leg at once, so that a later clean attempt never hides it. A leg whose recorder
# breaks by itself on every attempt fails, and says so. A rerun is not a pass: a leg that passed only
# on a later attempt ends with exit 4, "partial", naming the leg and what failed in each attempt, so
# that exit 0 of the script says every leg passed on its first attempt.
play_leg() { # <leg> <runner> <runner arguments...>
    local each=$1 runner=$2 rc attempt=1 attempts="${KR_LEG_ATTEMPTS:-3}" kept history=""
    shift 2
    while :; do
        begin_run "$each"
        rc=0
        "$runner" "$@" || rc=$?
        end_run
        [ "$rc" != 0 ] || break
        leg_is_replayable "$artefacts/$result_name" "$log" "$artefacts/host-judge.rc" || break
        history="$history attempt $attempt: $(grep -h ' ok=0 detail=' "$artefacts/$result_name" | cut -c1-200 | tr '\n' ' ')"
        say "== leg ${each:-the call} attempt $attempt of $attempts: the recorder broke by itself"
        if [ "$attempt" -ge "$attempts" ]; then
            say "== leg ${each:-the call}: the recorder broke by itself on all $attempts attempts, so the leg fails"
            break
        fi
        kept="$artefacts-attempt-$attempt"
        [ ! -e "$kept" ] || kept="$kept-$run"
        mv "$artefacts" "$kept" || break
        attempt=$((attempt + 1))
    done
    if [ "$rc" = 0 ] && [ "$attempt" -gt 1 ]; then
        say "== leg ${each:-the call} passed only on attempt $attempt, so the run is partial; what failed before:$history"
        rc=4
    fi
    note_verdict "$each" "$rc" "$attempt"
}

# The text the iOS simulator's application peer file holds: a port and a token, and for the
# delegating mode the synthetic recorder the call needs on a simulator.
peer_file_text() {
    if [ "$mode" = delegating ]; then
        printf '{"port":%s,"token":"%s","recorder":"synthetic"}\n' "$peer_port" "$peer_token"
    else
        printf '{"port":%s,"token":"%s"}\n' "$peer_port" "$peer_token"
    fi
}

# One call on the simulator: a fresh install, the host and the stand-in, the request, the
# application, and the verdicts.
ios_run() { # <simulator udid> <application>
    local udid="$1" app="$2"
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
    # The peer the application starts at launch, which the outage and delegating modes ask for. A
    # simulator shares this machine's loopback interface, so the peer's port is reached as it is.
    if [ "$mode" = outage ] || [ "$mode" = delegating ]; then
        ( umask 077; peer_file_text >"$directory/peer.json" )
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

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" udid
    udid="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" udid "$device")"
    [ -n "$udid" ] || { say "no iOS simulator named $device"; return 3; }

    say "building the debug application for the simulator"
    # No push: the build names no Firebase configuration.
    printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$companion/src-tauri/gen/apple/Local.xcconfig"
    rm -rf "${companion:?}/src-tauri/gen/apple/build"
    mkdir -p "${artefacts_base:?}"
    ( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts_base/build.log" 2>&1 \
        || { say "the build failed; see $artefacts_base/build.log"; return 2; }
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

    local each
    for each in "${legs[@]}"; do
        play_leg "$each" ios_run "$udid" "$app"
    done
    return "$worst"
}

# One call on the emulator: a fresh install, the host and the stand-in, the request, the
# application, and the verdicts.
android_run() { # <adb> <serial> <package>
    local adb="$1" serial="$2" apk="$3"
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
    service_forward="$port"
    # The other way: the application's peer listens on the emulator's loopback interface, and this
    # machine reaches it on the same port number.
    if [ "$mode" = outage ] || [ "$mode" = delegating ]; then
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
    if [ "$mode" = outage ] || [ "$mode" = delegating ]; then
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
    # The next run installs afresh: this application is stopped, by its own package name.
    "$adb" -s "$serial" shell am force-stop "$app_id" >/dev/null 2>&1
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

    case "${KR_MINIFY_DEBUG:-}" in
        "" | 1) ;;
        *) say "KR_MINIFY_DEBUG is $KR_MINIFY_DEBUG, and the build reads only 1"; return 2 ;;
    esac
    say "building the debug application for the emulator${KR_MINIFY_DEBUG:+ (KR_MINIFY_DEBUG=$KR_MINIFY_DEBUG)}"
    mkdir -p "${artefacts_base:?}"
    ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts_base/build.log" 2>&1 \
        || { say "the build failed; see $artefacts_base/build.log"; return 2; }
    local apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    [ -f "$apk" ] || { say "the build left no package"; return 2; }
    build_harness || return 2

    # A device already on the serial is someone else's: it is neither used nor stopped.
    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    # The call's audio needs the guest to have an audio device, so the outage and delegating modes
    # do not disable audio support; `-audio none` is the first thing tried (see the header).
    local audio=(-no-audio)
    if [ "$mode" = outage ] || [ "$mode" = delegating ]; then
        read -r -a audio <<<"${KR_EMULATOR_AUDIO_ARGS--audio none}"
    fi
    say "starting the emulator $avd, audio arguments: ${audio[*]-none}"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim -no-window \
        ${audio[@]+"${audio[@]}"} \
        -no-metrics -gpu swiftshader_indirect -netdelay none -netspeed full >"$artefacts_base/emulator.log" 2>&1 &
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

    local each
    for each in "${legs[@]}"; do
        play_leg "$each" android_run "$adb" "$serial" "$apk"
    done
    return "$worst"
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
