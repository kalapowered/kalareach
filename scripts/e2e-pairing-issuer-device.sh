#!/usr/bin/env bash
#
# Pairs a phone with a host whose issuing side is the real `kr pair` command, on the iOS Simulator or the
# Android emulator, and keeps what the command's terminal showed.
#
# `scripts/e2e-pairing-device.sh` pairs the phone with a host that its test harness drives through
# library calls, so no leg of it shows what the person at the host sees. This one starts the real
# `kr-controller` daemon (the shipped daemon's own source, built with the `testing` feature that starts no
# launchd job; it has no owner and joins the network on the loopback interface alone) and runs the real `kr`
# below a pseudo-terminal, as a person at the host runs it:
#
#   kr pair invite --direct --owner   the host has no owner, so the command asks for the word `pair`, issues
#                                     the invitation and draws its QR code; the drawing is put where the
#                                     phone finds it (the simulator's photo library, or the wall of the
#                                     emulator's virtual camera scene)
#   kr pair status <id>               read before the phone scans (no device, no value), and again once the
#                                     phone shows its value (the device and the value), in its text form and
#                                     in its JSON form, which also names the permissions proposed
#   kr pair confirm <id>              asks for the verification value the new device shows. The value is the
#                                     one the phone's screen showed, read off that screen by the driver; it is
#                                     typed with its last character changed first, which the command refuses
#                                     (and `kr pair status` shows nothing paired), and then as it was shown,
#                                     which the command accepts: the command takes the value only when it is
#                                     the one the host holds (KR-REQ-10.28)
#
# The transcripts are the evidence: for each command, `<name>.raw` holds every byte it printed, `<name>.txt`
# what the screen showed, `<name>.timed.txt` the same lines with their times and the moments the helper
# typed (`scripts/lib/pairing-issuer.py`). The phone's side is the installed application, driven through its
# own screens (XCUITest on the simulator, `uiautomator` on the emulator); it writes the value it shows to
# `phone-value.txt`. The application is a build made as `scripts/e2e-pairing-device.sh` makes its own (its
# `run_ios` and `run_android`), named by KR_ISSUER_IOS_APP or KR_ISSUER_ANDROID_APK.
#
# A simulator or an emulator only inside the Mac's device lease, and the host builds inside a build slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-pairing-issuer-device.sh ios
#
# Usage:
#   KR_ISSUER_IOS_APP=<KalaReach.app> scripts/e2e-pairing-issuer-device.sh ios
#   KR_ISSUER_ANDROID_APK=<package> scripts/e2e-pairing-issuer-device.sh android
#
# KR_PAIRING_SHOTS is where the phone's screenshots go (default /tmp/kr-pair-issuer); KR_PAIRING_GRPC_PORT is
# the port of the Android emulator's controller (default 8754), which must be free: the camera is moved
# through it, so a port that already answers would move another emulator's. KR_ISSUER_BIND is the address the
# host's endpoint binds to (default 127.0.0.1:0); an Android run names a fixed port, so that the address the
# invitation carries can be reached from the emulator. KR_IOS_PACKAGES names an absolute folder that the iOS
# test build keeps the Swift packages in (see scripts/lib/xcode.sh).
#
# The host's tree (keys of a test host, for this account alone) is left under /private/tmp/kr-dl5-host.* when
# the run ends, and its path is printed: it is for the person who ran this to remove.
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail
# Nothing this run writes is readable by another account.
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
case "$platform" in
    ios | android) ;;
    *) printf 'usage: %s ios|android\n' "$0" >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"
# shellcheck source=scripts/lib/xcode.sh
. "$here/scripts/lib/xcode.sh"
# shellcheck source=scripts/lib/artifacts-dir.sh
. "$here/scripts/lib/artifacts-dir.sh"
# shellcheck source=scripts/lib/host-program.sh
. "$here/scripts/lib/host-program.sh"
kr_artifacts_dir
artefacts="$kr_artifacts/pairing-issuer-device-$platform"
transcripts="$artefacts/transcripts"
shots="${KR_PAIRING_SHOTS:-/tmp/kr-pair-issuer}"
mkdir -p "${artefacts:?}" "${transcripts:?}" "${shots:?}"
if [ ! -O "$shots" ] || [ -k "$shots" ]; then
    printf 'KR_PAIRING_SHOTS names %s, which is shared or another account'"'"'s: name a folder of its own\n' "$shots" >&2
    exit 2
fi
keep_private() {
    chmod 700 "$artefacts" "$shots" 2>/dev/null
    find "$artefacts" -type d -exec chmod 700 {} + 2>/dev/null
    find "$artefacts" -type f -exec chmod 600 {} + 2>/dev/null
    find "$shots" -maxdepth 1 -type f \( -name '*.png' -o -name '*.txt' \) -exec chmod 600 {} + 2>/dev/null
}
keep_private
app_id=to.kala.reach
log="$artefacts/run.log"
: >"${log:?}"
# The files the phone's driver and this script pass to each other: the invitation's picture, the value
# the phone shows, and the approval. A folder of this run's own inside the output folder, so that what
# it holds stays with the run.
harness="$artefacts/phone-$(date +%s)-$$"
mkdir -p "${harness:?}"
# The host: its runtime and state folders and the home folder `kr` runs with, made when the host starts,
# at a short path for the daemon's sockets.
hostroot=""
daemon_pid=""
driver_pid=""
feeder_pid=""
emulator_pid=""
emulator_serial=""
emulator_adb=""
emulator_checked=0
simulator_made=""
issuer_kr=""
issuer_controller=""
invitation=""
# The moments, in seconds since the epoch, at which each step finished: the checks read their order.
moments=""

say() { printf '== [pairing-issuer-device] %s\n' "$*" | tee -a "$log"; }

# Ends what this script started: the phone's driver, the feeder and the daemon by the pids this script
# recorded (the daemon is asked to stop first), and the emulator or simulator it started.
finish() {
    touch "$harness/finish" 2>/dev/null
    for pid in "$driver_pid" "$feeder_pid"; do
        [ -n "$pid" ] || continue
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    done
    if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill "$daemon_pid" 2>/dev/null
        local stopped=0
        while kill -0 "$daemon_pid" 2>/dev/null && [ "$stopped" -lt 20 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$daemon_pid" 2>/dev/null && kill -9 "$daemon_pid" 2>/dev/null
    fi
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        if [ "$emulator_checked" = 1 ]; then
            "$emulator_adb" -s "$emulator_serial" reverse --remove-all >/dev/null 2>&1
            "$emulator_adb" -s "$emulator_serial" uninstall "$app_id" >/dev/null 2>&1
            "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        else
            kill "$emulator_pid" 2>/dev/null
        fi
        local ended=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$ended" -lt 30 ]; do
            sleep 1
            ended=$((ended + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
    if [ -n "$simulator_made" ]; then
        xcrun simctl shutdown "$simulator_made" >/dev/null 2>&1
        xcrun simctl delete "$simulator_made" >/dev/null 2>&1
    fi
    keep_private
    [ -z "$hostroot" ] || printf '== host tree left at %s (test keys, for this account alone): remove it when read\n' "$hostroot"
}
trap finish EXIT

# ---- The host --------------------------------------------------------------------------------

# Builds one program and prints where it is: <name> <cargo build arguments...>.
build_program() {
    local name="$1"
    shift
    cargo build --locked "$@" --bin "$name" --message-format=json >"$artefacts/build-$name.json" 2>"$artefacts/build-$name.log" \
        || { say "$name did not build; see $artefacts/build-$name.log" >&2; return 2; }
    python3 - "$artefacts/build-$name.json" "$name" <<'PY'
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
        and message["target"]["name"] == sys.argv[2]
    ):
        found = message["executable"]
print(found)
PY
}

# Builds the daemon and `kr`, and puts both where they are started from.
build_host() {
    local built
    say "building the host"
    built="$(cd "$here" && build_program kr-controller-held -p kr-controller --features testing)" || return 2
    [ -x "$built" ] || { say "the daemon left no executable"; return 2; }
    issuer_controller="$(host_install "$built" kr-controller)" || { say "the daemon could not be installed"; return 2; }
    built="$(cd "$here" && build_program kr -p kr-cli)" || return 2
    [ -x "$built" ] || { say "kr left no executable"; return 2; }
    issuer_kr="$(host_install "$built" kr)" || { say "kr could not be installed"; return 2; }
}

# Starts the daemon: no owner, its endpoint on the address KR_ISSUER_BIND names, no relay and no discovery.
# Its environment's identity and configuration document are written before it starts, so that it reads them.
start_host() {
    local bind="${KR_ISSUER_BIND:-127.0.0.1:0}"
    hostroot="$(mktemp -d /private/tmp/kr-dl5-host.XXXXXX)" || return 2
    local environment_id state
    environment_id="$(uuidgen | tr 'A-F' 'a-f')"
    state="$hostroot/s/environments/${environment_id%%-*}"
    mkdir -p "$hostroot/r" "$hostroot/h" "$state"
    printf '%s\n' "$environment_id" >"$hostroot/s/environment-id"
    printf '{\n  "version": 3,\n  "level": 1,\n  "revision": 1,\n  "network": { "enabled": true, "bind_address": "%s" }\n}\n' "$bind" >"$state/config.json"
    host_start "$issuer_controller" --runtime-dir "$hostroot/r" --state-dir "$hostroot/s" --secret-store file \
        >"$artefacts/daemon.log" 2>&1 &
    daemon_pid=$!
    local waited=0
    until python3 - "$hostroot/r" <<'PY'
import socket
import sys
from pathlib import Path

for path in Path(sys.argv[1]).glob("*/c.sock"):
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(path))
        sys.exit(0)
    except OSError:
        pass
sys.exit(1)
PY
    do
        kill -0 "$daemon_pid" 2>/dev/null || { say "the daemon ended before it answered; see $artefacts/daemon.log"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 120 ] || { say "the daemon did not answer in time"; return 2; }
    done
    say "the host is up (its endpoint binds $bind)"
}

# Runs one command of the helper: <verb> <name> [options...].
issuer() {
    local verb="$1" name="$2"
    shift 2
    python3 "$here/scripts/lib/pairing-issuer.py" "$verb" --name "$name" --kr "$issuer_kr" \
        --runtime-dir "$hostroot/r" --state-dir "$hostroot/s" --home "$hostroot/h" --out "$transcripts" "$@" \
        | tee -a "$log"
}

moment() { moments="$moments $1=$(date +%s)"; }
moment_of() { printf '%s' "$moments" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }

# ---- What the run must have shown ------------------------------------------------------------

# What a transcript holds, as a check: the text of the screen of `<name>`, every phrase in it.
screen_has() { # <name> <phrase>...
    local name="$1" phrase
    shift
    for phrase in "$@"; do
        grep -q -F -- "$phrase" "$transcripts/$name.txt" 2>/dev/null || return 1
    done
}

# The value a status or a phone shows, with its grouping taken away.
plain_value() { tr -d ' -' | tr 'A-F' 'a-f'; }

judge() { # <driver output>
    local bad=0 phone_value="" shown=""
    [ -s "$harness/phone-value.txt" ] && phone_value="$(plain_value <"$harness/phone-value.txt" | tr -d '\n')"

    if screen_has invite "This host has no owner yet" "Type pair to issue the invitation:" \
        "Scan this QR code with the new device" "kr pair confirm $invitation" \
        && [ "$(cat "$transcripts/invite.exit" 2>/dev/null)" = 0 ]; then
        say "check=the command asked for the word that issues the host's first invitation, drew the invitation's QR code and named the command that approves it ok=1 detail=invitation $invitation"
    else
        say "check=the command asked for the word that issues the host's first invitation, drew the invitation's QR code and named the command that approves it ok=0 detail=see $transcripts/invite.txt"
        bad=1
    fi

    if screen_has status-before "Invitation $invitation: open" \
        && ! screen_has status-before "verification value" \
        && ! screen_has status-before "The device is"; then
        say "check=before the phone scanned, the status named no device and no value ok=1"
    else
        say "check=before the phone scanned, the status named no device and no value ok=0 detail=see $transcripts/status-before.txt"
        bad=1
    fi

    shown="$(sed -n 's/.*its verification value is \([^.;]*\).*/\1/p' "$transcripts/status-after.txt" 2>/dev/null | head -1 | plain_value | tr -d '\n')"
    if [ -n "$phone_value" ] && [ "$shown" = "$phone_value" ] \
        && screen_has status-after "a device is waiting for approval" "The device is "; then
        say "check=once the phone showed its value, the status named the device and showed the value the phone shows ok=1 detail=value $phone_value on the phone and on the command line"
    else
        say "check=once the phone showed its value, the status named the device and showed the value the phone shows ok=0 detail=phone '$phone_value', command line '$shown'"
        bad=1
    fi

    if screen_has status-after-json '"proposed_grant"' '"candidate"' '"verification_value"'; then
        say "check=the status in JSON names the candidate and the permissions proposed ok=1"
    else
        say "check=the status in JSON names the candidate and the permissions proposed ok=0 detail=see $transcripts/status-after-json.txt"
        bad=1
    fi

    if screen_has confirm-wrong "the new device shows:" "that is not the verification value this host sees, so the device was not approved" \
        && [ "$(cat "$transcripts/confirm-wrong.exit" 2>/dev/null)" != 0 ] \
        && screen_has status-after-refusal "a device is waiting for approval" \
        && ! screen_has status-after-refusal "paired as device"; then
        say "check=a value with one character changed was refused and the device stayed unapproved ok=1"
    else
        say "check=a value with one character changed was refused and the device stayed unapproved ok=0 detail=see $transcripts/confirm-wrong.txt and status-after-refusal.txt"
        bad=1
    fi

    if screen_has confirm "answered this invitation, and becomes this host's first owner if you approve it." \
        "Type the verification value the new device shows:" "Paired " \
        && [ "$(cat "$transcripts/confirm.exit" 2>/dev/null)" = 0 ]; then
        say "check=the command asked for the value the new device shows and approved the device on the value read from the phone's screen ok=1"
    else
        say "check=the command asked for the value the new device shows and approved the device on the value read from the phone's screen ok=0 detail=see $transcripts/confirm.txt"
        bad=1
    fi

    if [ -n "$phone_value" ] && grep -q -i -F "PAIRING the phone shows the value $phone_value" "$1" 2>/dev/null; then
        say "check=the phone showed its value ok=1 detail=value $phone_value"
    else
        say "check=the phone showed its value ok=0 detail=the driver did not report it"
        bad=1
    fi
    if grep -q -F "PAIRING the phone is paired" "$1" 2>/dev/null && screen_has status-final "paired as device"; then
        say "check=the phone is paired once the command approved it, and the status says so ok=1"
    else
        say "check=the phone is paired once the command approved it, and the status says so ok=0 detail=see $1 and $transcripts/status-final.txt"
        bad=1
    fi

    # The order: the invitation was drawn, then read before any scan, then scanned; the phone showed its value
    # before the status that names it and the question that asks for it.
    local invite_done status_before_done picture_given value_seen status_after_done confirm_done
    invite_done="$(moment_of invite_done)"
    status_before_done="$(moment_of status_before_done)"
    picture_given="$(moment_of picture_given)"
    value_seen="$(moment_of value_seen)"
    status_after_done="$(moment_of status_after_done)"
    confirm_done="$(moment_of confirm_done)"
    if [ -n "$invite_done" ] && [ -n "$status_before_done" ] && [ -n "$picture_given" ] && [ -n "$value_seen" ] \
        && [ -n "$status_after_done" ] && [ -n "$confirm_done" ] \
        && [ "$invite_done" -le "$status_before_done" ] && [ "$status_before_done" -le "$picture_given" ] \
        && [ "$picture_given" -le "$value_seen" ] && [ "$value_seen" -le "$status_after_done" ] \
        && [ "$status_after_done" -le "$confirm_done" ]; then
        say "check=the order was the invitation drawn, the status before any scan, the phone's scan, the phone's value, the status naming the device, the approval ok=1 detail=$moments"
    else
        say "check=the order was the invitation drawn, the status before any scan, the phone's scan, the phone's value, the status naming the device, the approval ok=0 detail=$moments"
        bad=1
    fi
    return "$bad"
}

# ---- The sequence, once a phone is ready -----------------------------------------------------

# Runs the commands while the phone's driver (already started by `start_driver`) answers on its screen.
issue_and_approve() { # <driver output>
    # The phone is at its pairing screen, waiting for the picture, before the invitation is issued: an
    # invitation stays open for minutes only.
    start_driver "$1"
    issuer invite invite || return 2
    moment invite_done
    invitation="$(cat "$transcripts/invitation-id.txt")"
    # Read before the phone has the picture: the command says nothing of a device.
    issuer status status-before --invitation "$invitation" || return 2
    moment status_before_done
    cp "$transcripts/invite-qr.png" "$harness/direct.png"
    moment picture_given

    local waited=0
    until [ -s "$harness/phone-value.txt" ]; do
        kill -0 "$driver_pid" 2>/dev/null || { say "the phone's driver ended before the phone showed its value; see $1"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 420 ] || { say "the phone showed no value in time"; return 2; }
    done
    moment value_seen
    # The status is read until the host has recorded the candidate the phone's binding made.
    local tries=0
    while [ "$tries" -lt 20 ]; do
        issuer status status-after --invitation "$invitation" >/dev/null || return 2
        grep -q -F "a device is waiting for approval" "$transcripts/status-after.txt" && break
        sleep 2
        tries=$((tries + 1))
    done
    issuer status status-after-json --invitation "$invitation" --json || return 2
    moment status_after_done
    # One character of the phone's value changed: the command refuses, and the device is not approved.
    issuer confirm confirm-wrong --invitation "$invitation" --value-file "$harness/phone-value.txt" --change-one || return 2
    issuer status status-after-refusal --invitation "$invitation" >/dev/null || return 2
    issuer confirm confirm --invitation "$invitation" --value-file "$harness/phone-value.txt" || return 2
    moment confirm_done
    : >"$harness/approve"
    wait "$driver_pid"
    local code=$?
    driver_pid=""
    issuer status status-final --invitation "$invitation" >/dev/null || return 2
    return "$code"
}

# ---- The iOS Simulator -----------------------------------------------------------------------

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

ios_plan=""
ios_udid=""

start_driver_ios() { # <driver output>
    TEST_RUNNER_KR_PAIRING_DIR="$harness" TEST_RUNNER_KR_PAIRING_SHOTS="$shots" TEST_RUNNER_KR_PAIRING_ISSUER=1 \
        xcodebuild test-without-building -xctestrun "$ios_plan" \
        -destination "platform=iOS Simulator,id=$ios_udid" \
        -only-testing:KalaReachUITests/PairingTests/testIssuerAnInvitationTheCommandDrewPairsAndShowsItsValue \
        >"$artefacts/xcodebuild.log" 2>&1 &
    driver_pid=$!
}

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" app="${KR_ISSUER_IOS_APP:-}" template
    template="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" template "$device")"
    [ -n "$template" ] || { say "no iOS simulator named $device"; return 3; }
    [ -d "$app" ] || { say "KR_ISSUER_IOS_APP names no application ($app)"; return 2; }

    say "building the tests that drive it"
    local derived="$HOME/Library/Caches/kalareach-tests/pairing-issuer-device/ios-tests"
    mkdir -p "$derived"
    kr_shared_packages || { say "the folder that KR_IOS_PACKAGES names cannot be used"; return 2; }
    ( cd "$companion/src-tauri/gen/apple" && kr_with_packages_lock xcodebuild build-for-testing -project companion-tauri.xcodeproj \
        -scheme KalaReachUITests -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$derived" ${kr_package_options[@]+"${kr_package_options[@]}"} ) >"$artefacts/build-tests.log" 2>&1 \
        || { tail -20 "$artefacts/build-tests.log"; say "the tests did not build"; return 2; }
    ios_plan="$(ls "$derived"/Build/Products/*.xctestrun 2>/dev/null | head -1)"
    [ -f "$ios_plan" ] || { say "the test build left no plan"; return 2; }
    build_host || return 2

    say "making and starting a simulator like $device"
    # shellcheck disable=SC2086
    ios_udid="$(xcrun simctl create "kr-pairing-issuer-$$" $template)" \
        || { say "the simulator could not be made"; return 3; }
    simulator_made="$ios_udid"
    xcrun simctl boot "$ios_udid" >/dev/null 2>&1
    xcrun simctl bootstatus "$ios_udid" -b >/dev/null 2>&1
    xcrun simctl install "$ios_udid" "$app" || { say "the application did not install"; return 2; }
    start_host || return 2
    feed_ios "$ios_udid" &
    feeder_pid=$!

    say "issuing and approving"
    local out="$artefacts/xcodebuild.log" status=0
    issue_and_approve "$out" || status=$?
    grep -E "Test Case .* (passed|failed|skipped)|error:|XCTAssert|PAIRING" "$out" | sed 's/^/    /' | tee -a "$log"
    xcrun simctl terminate "$ios_udid" "$app_id" >/dev/null 2>&1
    judge "$out" || status=2
    [ "$status" = 0 ] || return 2
}

# ---- The Android emulator --------------------------------------------------------------------

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

android_grpc_port=""

start_driver_android() { # <driver output>
    python3 "$here/scripts/lib/pairing-android.py" issuer "$emulator_adb" "$emulator_serial" "$harness" "$shots" "$android_grpc_port" \
        >"$1" 2>&1 &
    driver_pid=$!
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd apk="${KR_ISSUER_ANDROID_APK:-}"
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" serial_port=5594 grpc_port="${KR_PAIRING_GRPC_PORT:-8754}"
    local serial="emulator-$serial_port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        return 3
    fi
    [ -f "$apk" ] || { say "KR_ISSUER_ANDROID_APK names no package ($apk)"; return 2; }
    python3 "$here/scripts/lib/android-network-config.py" debug "$apk" | tee -a "$log" \
        || { say "the package's network security configuration is not the development build's"; return 2; }
    build_host || return 2

    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$grpc_port") 2>/dev/null; then
        say "the port $grpc_port is already taken, so no emulator is started (KR_PAIRING_GRPC_PORT names another port)"
        return 3
    fi
    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -grpc "$grpc_port" -no-snapshot-save \
        -no-boot-anim -no-window -no-audio -no-metrics -gpu swiftshader_indirect -netdelay none \
        -netspeed full -camera-back virtualscene \
        -virtualscene-poster "wall=$here/fixtures/pairing/qr-direct.png" >"$artefacts/emulator.log" 2>&1 &
    emulator_pid=$!
    emulator_serial=$serial
    emulator_adb=$adb
    android_grpc_port=$grpc_port
    local booted=0
    for _ in $(seq 1 180); do
        kill -0 "$emulator_pid" 2>/dev/null || break
        if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
        sleep 2
    done
    { [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; return 3; }
    local reported
    reported="$(kr_android_device_name "$adb" "$serial")"
    if [ "$reported" != "$avd" ]; then
        say "the device on $serial reports ${reported:-no name}, not $avd, so it is left alone"
        return 3
    fi
    emulator_checked=1
    python3 "$here/scripts/lib/pairing-android.py" aim "$grpc_port" || { say "the camera could not be placed"; return 2; }
    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null
    start_host || return 2
    # The host's endpoint is on the loopback interface of this machine; the emulator's own loopback
    # interface is tied to it for the port the endpoint binds to, when KR_ISSUER_BIND names one.
    local bound="${KR_ISSUER_BIND:-}"
    if [ -n "$bound" ] && [ "${bound##*:}" != 0 ]; then
        "$adb" -s "$serial" reverse "tcp:${bound##*:}" "tcp:${bound##*:}" >/dev/null \
            || { say "the emulator's loopback interface could not be tied to the host's port"; return 2; }
    fi
    feed_android "$adb" "$serial" &
    feeder_pid=$!

    say "issuing and approving"
    local out="$artefacts/driver.log" status=0
    issue_and_approve "$out" || status=$?
    sed 's/^/    /' "$out" | tee -a "$log"
    "$adb" -s "$serial" logcat -d 2>/dev/null | grep -v -E 'CompositionEngine|AccessibilityNodeInfoDumper' | tail -2000 >"$artefacts/logcat.log"
    judge "$out" || status=2
    [ "$status" = 0 ] || return 2
}

case "$platform" in
    ios) start_driver() { start_driver_ios "$@"; }; run_ios ;;
    android) start_driver() { start_driver_android "$@"; }; run_android ;;
esac
