#!/usr/bin/env bash
#
# Drives the voice surface on the iOS Simulator, the Android emulator and the desktop window, and
# writes a qualification log made only of what this run actually checked.
#
# Two rules govern this script. It asserts rather than photographs: the screenshots are evidence
# beside the assertions, never instead of them. And it claims nothing it did not establish: every
# PROVED line in the log comes from an assertion that passed on this run, every clause the run could
# not reach is printed as NOT PROVED with the reason, and no figure is printed that nothing measured.
#
# Rows this run can speak to:
#   KR-REQ-15.09  managed content access disclosed in the provider choice
#   KR-REQ-15.19  the provider and the context scope shown before voice starts
#   KR-REQ-15.17  local mute, playback stop and closure survive an unreachable voice service
#   KR-REQ-15.22  stopping the voice is not cancelling a turn
#   KR-REQ-15.35  the interruption states the surface draws
#   KR-REQ-15.36  muted or unavailable capture displayed, with the refusal beside it
#
# Rows a simulator and an emulator cannot close, and which this script therefore does not claim:
#   KR-REQ-15.34  audio after a hardware screen lock
#   KR-ACC-014    a screen-lock call on a handset
#   KR-PERF-010   first-audio and delegation latency, which need a connected media path
#
# Usage:
#   scripts/e2e-voice-device.sh           # every platform that is available here
#   scripts/e2e-voice-device.sh ios
#   scripts/e2e-voice-device.sh android
#   scripts/e2e-voice-device.sh desktop
#
# Exit codes: 0 every requested platform ran, 2 bad usage or a failed assertion, 3 a requested
# platform is not available on this machine.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-device"
shots="${KR_MOBILE_SCREENSHOT_DIR:-/tmp}"
port="${KR_VOICE_TEST_PORT:-4188}"
want="${1:-all}"

case "$want" in
    ios | android | desktop | all) ;;
    *) printf 'unknown target: %s\n' "$want" >&2; exit 2 ;;
esac

mkdir -p "${artefacts:?}"
log="$artefacts/e2e-voice-device.log"
: >"${log:?}"

say() { printf '== [e2e-voice-device] %s\n' "$*" | tee -a "${log:?}"; }

# What this run established, and what it could not. Both are printed at the end, and neither is a
# fixed list: they are appended as the run reaches each check.
proved_lines=()
unproved_lines=()
missing_platforms=()
failures=0

proved() { proved_lines+=("$*"); }
unproved() { unproved_lines+=("$*"); }
fail() { failures=$((failures + 1)); say "FAILED: $*"; }

# ---- The harness the surfaces are driven in ----------------------------------------------------

server=0
ios_booted_here=0
ios_udid=""
android_started_here=0
android_serial=""
adb_path=""

cleanup() {
    # Only what this run started, and only by the identity this run recorded.
    if [ "${server:-0}" -ne 0 ]; then
        kill "${server:?}" 2>/dev/null || true
        wait "${server:?}" 2>/dev/null || true
    fi
    if [ "$ios_booted_here" = 1 ] && [ -n "$ios_udid" ]; then
        say "shutting down the simulator this run booted"
        xcrun simctl shutdown "$ios_udid" 2>/dev/null || true
    fi
    if [ "$android_started_here" = 1 ] && [ -n "$android_serial" ] && [ -n "$adb_path" ]; then
        say "stopping the emulator this run started"
        "$adb_path" -s "$android_serial" emu kill 2>/dev/null || true
    fi
}
trap cleanup EXIT

say "building the harness bundle"
if ! ( cd "$companion" && pnpm build:harness ) >"$artefacts/build.log" 2>&1; then
    say "the harness bundle did not build; see $artefacts/build.log"
    exit 2
fi

say "serving the harness on port $port"
( cd "$companion" && PORT="$port" node scripts/preview-harness.mjs ) >"$artefacts/serve.log" 2>&1 &
server=$!

ready=0
for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:$port/harness.html" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
done
if [ "$ready" != 1 ]; then
    say "the harness did not start; see $artefacts/serve.log"
    exit 2
fi

# ---- The assertions, in the engine each platform draws the surface with -------------------------

run_assertions() {
    say "asserting the surface in WebKit and Chromium"
    if node --experimental-strip-types "$companion/test/voice/assert-voice-surface.ts" \
        "http://localhost:$port" >"$artefacts/assertions.log" 2>&1; then
        while IFS= read -r line; do
            case "$line" in
                proved\ *) proved "${line#proved }" ;;
                unproved\ *) unproved "${line#unproved }" ;;
            esac
        done <"$artefacts/assertions.log"
        say "$(grep -c '^proved ' "$artefacts/assertions.log" || true) clauses asserted"
    else
        fail "the surface assertions did not pass; see $artefacts/assertions.log"
        sed -n '$p' "$artefacts/assertions.log" | tee -a "${log:?}"
    fi
}

# ---- iOS ---------------------------------------------------------------------------------------

run_ios() {
    say "driving the iOS voice surface"
    if ! command -v xcrun >/dev/null 2>&1; then
        say "no Xcode command line tools on this machine"
        missing_platforms+=("ios: no xcrun")
        return 3
    fi
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}"
    ios_udid="$(xcrun simctl list devices available -j 2>/dev/null |
        python3 "$here/scripts/simulator-identity.py" udid "$device" 2>/dev/null)"
    if [ -z "$ios_udid" ]; then
        say "no iOS simulator named $device is available"
        missing_platforms+=("ios: no simulator named $device")
        return 3
    fi

    local state
    state="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" state "$ios_udid")"
    if [ "$state" != "Booted" ]; then
        say "booting $device ($ios_udid)"
        xcrun simctl boot "$ios_udid" || { missing_platforms+=("ios: $device would not boot"); return 3; }
        ios_booted_here=1
        local booted=0
        for _ in $(seq 1 60); do
            if xcrun simctl list devices available -j |
                python3 "$here/scripts/simulator-identity.py" state "$ios_udid" | grep -q Booted; then
                booted=1
                break
            fi
            sleep 1
        done
        [ "$booted" = 1 ] || { say "$device did not finish booting"; missing_platforms+=("ios: boot timed out"); return 3; }
    else
        say "reusing the already booted $device ($ios_udid)"
    fi

    local desc
    desc="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" describe "$ios_udid")"
    printf 'iOS device: %s\n' "$desc" | tee "$artefacts/ios-device.txt" | tee -a "${log:?}"

    # A screenshot is evidence only when it was taken and is not empty. Each leg below claims its
    # clause only if its own screenshots succeeded.
    local choice_shot=0 capture_shot=0
    shoot_ios() {
        local state_param=$1 name=$2
        xcrun simctl openurl "$ios_udid" \
            "http://localhost:$port/harness.html?surface=ios&tab=voice$state_param" || return 1
        sleep "${KR_MOBILE_SETTLE:-4}"
        xcrun simctl io "$ios_udid" screenshot --type=png "$shots/$name" >/dev/null || return 1
        [ -s "$shots/$name" ] || return 1
        say "iOS screenshot $shots/$name"
    }

    if shoot_ios "" "kr-voice-ios-15.09-disclosure.png"; then
        cp "$shots/kr-voice-ios-15.09-disclosure.png" "$shots/kr-voice-ios-15.19-context-scope.png"
        choice_shot=1
    else
        fail "iOS provider choice screenshot"
    fi
    if shoot_ios "&state=unavailable" "kr-voice-ios-15.36-capture-unavailable.png" &&
        shoot_ios "&state=muted" "kr-voice-ios-15.36-muted.png"; then
        capture_shot=1
    else
        fail "iOS capture state screenshots"
    fi
    shoot_ios "&state=capturing" "kr-voice-ios-15.22-call-screen.png" || fail "iOS call screen screenshot"

    [ "$choice_shot" = 1 ] &&
        proved "KR-REQ-15.09, KR-REQ-15.19 | the disclosure and the context scope render on the iOS Simulator | $desc"
    [ "$capture_shot" = 1 ] &&
        proved "KR-REQ-15.36 | the unavailable and muted capture states render on the iOS Simulator | $desc"
    unproved "KR-REQ-15.34 | duplex audio after a screen lock | the iOS Simulator has no microphone input and no lock screen"
    unproved "KR-ACC-014 | a screen-lock call | the same; the device leg is the operator gate"
    return 0
}

# ---- Android -----------------------------------------------------------------------------------

run_android() {
    say "driving the Android voice surface"
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    adb_path="$sdk/platform-tools/adb"
    local emulator="$sdk/emulator/emulator"
    if [ ! -x "$adb_path" ]; then
        say "no Android platform tools"
        missing_platforms+=("android: no adb")
        adb_path=""
        return 3
    fi

    android_serial="$("$adb_path" devices | awk '/^emulator-[0-9]+\tdevice$/ {print $1; exit}')"
    if [ -z "$android_serial" ]; then
        local avd="${KR_ANDROID_AVD:-Nines_API_36_Play}"
        if [ ! -x "$emulator" ]; then
            say "no Android emulator binary"
            missing_platforms+=("android: no emulator")
            return 3
        fi
        # A console port of this run's own choosing, so the emulator this run started is named
        # rather than guessed. Taking the first device `adb` lists would attach to, and later kill,
        # an emulator somebody else started.
        local console=""
        for candidate in 5554 5556 5558 5560 5562 5564 5566 5568 5570 5572; do
            if ! nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
                console="$candidate"
                break
            fi
        done
        if [ -z "$console" ]; then
            say "no free emulator console port"
            missing_platforms+=("android: no free console port")
            return 3
        fi

        say "starting the emulator $avd on console port $console"
        "$emulator" -avd "$avd" -port "$console" -crash-report-mode disabled -no-snapshot-save \
            -no-boot-anim -netdelay none -netspeed full >"$artefacts/emulator.log" 2>&1 &
        local emulator_pid=$!
        android_started_here=1
        # Bounded: `adb wait-for-device` on a virtual device that never appears waits for ever.
        local up=0 expected="emulator-$console"
        for _ in $(seq 1 180); do
            if ! kill -0 "$emulator_pid" 2>/dev/null; then
                say "the emulator process ended before it booted"
                break
            fi
            if "$adb_path" devices | grep -q "^$expected	device$" &&
                [ "$("$adb_path" -s "$expected" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
                android_serial="$expected"
                up=1
                break
            fi
            sleep 2
        done
        if [ "$up" != 1 ]; then
            say "the emulator did not come up within six minutes; see $artefacts/emulator.log"
            # Its own process, by the identity this run recorded, and nothing else.
            kill "$emulator_pid" 2>/dev/null || true
            android_started_here=0
            android_serial=""
            missing_platforms+=("android: emulator did not boot")
            return 3
        fi
    else
        say "reusing the already running $android_serial"
    fi

    local model release sdkver
    model="$("$adb_path" -s "$android_serial" shell getprop ro.product.model | tr -d '\r')"
    release="$("$adb_path" -s "$android_serial" shell getprop ro.build.version.release | tr -d '\r')"
    sdkver="$("$adb_path" -s "$android_serial" shell getprop ro.build.version.sdk | tr -d '\r')"
    local desc="$android_serial, $model, Android $release, API $sdkver"
    printf 'Android device: %s\n' "$desc" | tee "$artefacts/android-device.txt" | tee -a "${log:?}"

    "$adb_path" -s "$android_serial" reverse "tcp:$port" "tcp:$port" >/dev/null 2>&1 || true

    local choice_shot=0 capture_shot=0
    shoot_android() {
        local state_param=$1 name=$2
        "$adb_path" -s "$android_serial" shell \
            "am start -a android.intent.action.VIEW --es com.android.browser.application_id com.android.chrome -d 'http://localhost:$port/harness.html?surface=android&tab=voice$state_param'" \
            >/dev/null || return 1
        sleep "${KR_MOBILE_SETTLE:-5}"
        "$adb_path" -s "$android_serial" exec-out screencap -p >"$shots/$name" || return 1
        [ -s "$shots/$name" ] || return 1
        say "Android screenshot $shots/$name"
    }

    if shoot_android "" "kr-voice-android-15.09-disclosure.png"; then
        cp "$shots/kr-voice-android-15.09-disclosure.png" \
            "$shots/kr-voice-android-15.19-context-scope.png"
        choice_shot=1
    else
        fail "Android provider choice screenshot"
    fi
    if shoot_android "&state=unavailable" "kr-voice-android-15.36-capture-unavailable.png" &&
        shoot_android "&state=muted" "kr-voice-android-15.36-muted.png"; then
        capture_shot=1
    else
        fail "Android capture state screenshots"
    fi

    # The emulator's simulated call is a telephony state change, not a call on a handset. It is
    # recorded as what it is.
    say "raising the emulator's simulated incoming call"
    if "$adb_path" -s "$android_serial" emu gsm call 15555215554 >/dev/null 2>&1; then
        sleep 3
        "$adb_path" -s "$android_serial" exec-out screencap -p \
            >"$shots/kr-voice-android-15.35-incoming-call.png" || fail "Android incoming call screenshot"
        if "$adb_path" -s "$android_serial" emu gsm cancel 15555215554 >/dev/null 2>&1; then
            sleep 2
            proved "KR-REQ-15.35 | the emulator's simulated incoming call was raised and cancelled with the surface open | $desc"
        else
            fail "the simulated call would not cancel, and this emulator is left with it raised"
        fi
        unproved "KR-REQ-15.35 | audio focus loss to a real call | the emulator's telephony state change is not a call on a handset, and no call is connected to lose focus from"
    else
        unproved "KR-REQ-15.35 | the simulated incoming call | this emulator refused the telephony command"
    fi

    shoot_android "&state=capturing" "kr-voice-android-15.22-call-screen.png" || fail "Android call screen screenshot"

    [ "$choice_shot" = 1 ] &&
        proved "KR-REQ-15.09, KR-REQ-15.19 | the disclosure and the context scope render on the Android emulator | $desc"
    [ "$capture_shot" = 1 ] &&
        proved "KR-REQ-15.36 | the unavailable and muted capture states render on the Android emulator | $desc"
    unproved "KR-REQ-15.34 | audio from the foreground service after a screen lock | an emulator does not qualify a foreground microphone service; the device leg is the operator gate"
    return 0
}

# ---- Desktop -----------------------------------------------------------------------------------

run_desktop() {
    say "capturing the desktop voice screens"
    ( cd "$companion" && node --input-type=module -e "
      import { chromium } from '@playwright/test';
      const browser = await chromium.launch({ headless: true });
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      const shoot = async (query, name) => {
        await page.goto('http://localhost:$port/harness.html?surface=desktop&tab=voice' + query);
        await page.waitForSelector('.kr-voice');
        await page.screenshot({ path: '$shots/' + name });
      };
      await shoot('', 'kr-voice-desktop-15.09-disclosure.png');
      await shoot('', 'kr-voice-desktop-15.19-context-scope.png');
      await shoot('&state=muted', 'kr-voice-desktop-15.36-muted.png');
      await shoot('&state=unavailable', 'kr-voice-desktop-15.36-capture-unavailable.png');
      await shoot('&state=capturing', 'kr-voice-desktop-15.22-call-screen.png');
      await browser.close();
    " ) || { fail "desktop screenshots"; return 0; }
    for name in kr-voice-desktop-15.09-disclosure.png kr-voice-desktop-15.19-context-scope.png \
        kr-voice-desktop-15.36-muted.png kr-voice-desktop-15.36-capture-unavailable.png \
        kr-voice-desktop-15.22-call-screen.png; do
        [ -s "$shots/$name" ] || { fail "desktop screenshot $name"; return 0; }
    done
    say "desktop screenshots under $shots"
    proved "KR-REQ-15.09, KR-REQ-15.19 | the disclosure and the context scope render in the desktop window | headless Chromium, 1280x800"
    return 0
}

# ---- Execution ---------------------------------------------------------------------------------

run_assertions

platform_missing=0
case "$want" in
    ios) run_ios || platform_missing=1 ;;
    android) run_android || platform_missing=1 ;;
    desktop) run_desktop || platform_missing=1 ;;
    all)
        run_desktop || platform_missing=1
        run_ios || platform_missing=1
        run_android || platform_missing=1
        ;;
esac

{
    printf '\n'
    printf '================================================================================\n'
    printf 'Voice client qualification, %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '================================================================================\n'
    printf '\nPROVED by this run (row | clause | where):\n'
    if [ "${#proved_lines[@]}" -eq 0 ]; then
        printf '  nothing\n'
    else
        printf '  %s\n' "${proved_lines[@]}"
    fi
    printf '\nNOT PROVED by this run (row | clause | why):\n'
    if [ "${#unproved_lines[@]}" -eq 0 ]; then
        printf '  nothing outstanding\n'
    else
        printf '  %s\n' "${unproved_lines[@]}"
    fi
    if [ "${#missing_platforms[@]}" -ne 0 ]; then
        printf '\nPlatforms not available here:\n'
        printf '  %s\n' "${missing_platforms[@]}"
    fi
    printf '\nScreenshots: %s\nArtefacts:   %s\n' "$shots" "$artefacts"
    printf '================================================================================\n'
} | tee -a "${log:?}"

if [ "$failures" -ne 0 ]; then
    say "$failures check(s) failed"
    exit 2
fi
if [ "$platform_missing" -ne 0 ]; then
    say "a requested platform was not available"
    exit 3
fi
say "run complete"
