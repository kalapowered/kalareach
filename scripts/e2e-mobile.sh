#!/usr/bin/env bash
#
# Drives the companion application's mobile surfaces on the iOS Simulator and the Android
# emulator, and photographs what each requirement needs.
#
# The surfaces run in the platform's own engine at the platform's own geometry: WebKit on the iOS
# Simulator and Chromium on the Android emulator, which are the engines the packaged application's
# WebView is. That is what makes the safe areas, the system text size, the touch targets and the
# software keyboard real rather than simulated in a desktop browser at a phone-sized window.
#
# It never starts a simulator or an emulator that is already running, and it stops only what it
# started itself. Screenshots go under /tmp; everything else goes to the artefact directory.
#
# Usage:
#   scripts/e2e-mobile.sh              # both platforms
#   scripts/e2e-mobile.sh ios          # one of them
#   scripts/e2e-mobile.sh android
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/companion-mobile"
shots="${KR_MOBILE_SCREENSHOT_DIR:-/tmp}"
port="${KR_MOBILE_PORT:-4188}"
want="${1:-both}"

mkdir -p "$artefacts"

say() { printf '== %s\n' "$*"; }

# ---- The bundle under test --------------------------------------------------------------------
#
# The harness bundle, which is the shipped interface with a host that answers without a machine.
# It is built rather than served from a development server, so what the phone loads is output.

say "building the harness bundle"
( cd "$companion" && pnpm build:harness ) >"$artefacts/build.log" 2>&1

say "serving it on port $port"
( cd "$companion" && node scripts/preview-harness.mjs ) >"$artefacts/serve.log" 2>&1 &
server=$!
# Only ever this process: another worker's server on another port is not this script's to stop.
trap 'kill "$server" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:$port/harness.html" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
curl -fsS "http://localhost:$port/harness.html" >/dev/null

# The screens each requirement needs, as an address the shell opens on. A notification about one
# session opens that session, so these are the product's own addresses rather than test-only ones.
screens=(
    "inbox-13.01|tab=attention"
    "sessions-13.10|tab=sessions"
    "hosts-13.02|tab=hosts"
    "account-17.32|tab=account"
    "session-13.17|session=8a7b6c50-22bb-4c3d-8e4f-000000000101"
)

# ---- iOS ---------------------------------------------------------------------------------------

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}"
    local udid started=0
    udid="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" udid "$device")"
    if [ -z "$udid" ]; then
        say "no iOS simulator named $device; skipping iOS"
        return 0
    fi
    local state
    state="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" state "$udid")"
    if [ "$state" != "Booted" ]; then
        say "booting $device"
        xcrun simctl boot "$udid"
        started=1
        sleep 8
    else
        say "using the already booted $device"
    fi

    xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" describe "$udid" |
        tee "$artefacts/ios-device.txt"

    for screen in "${screens[@]}"; do
        local name="${screen%%|*}" query="${screen#*|}"
        xcrun simctl openurl "$udid" "http://localhost:$port/harness.html?surface=ios&$query"
        sleep "${KR_MOBILE_SETTLE:-4}"
        xcrun simctl io "$udid" screenshot --type=png "$shots/kr-mobile-ios-$name.png" >/dev/null
        say "ios $name -> $shots/kr-mobile-ios-$name.png"
    done

    if [ "$started" = 1 ]; then
        say "shutting down the simulator this run booted"
        xcrun simctl shutdown "$udid"
    fi
}

# ---- Android -----------------------------------------------------------------------------------

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    local adb="$sdk/platform-tools/adb" emulator="$sdk/emulator/emulator"
    local serial started=0 pid=0
    if [ ! -x "$adb" ]; then
        say "no Android platform tools; skipping Android"
        return 0
    fi
    serial="$("$adb" devices | awk '/^emulator-[0-9]+\tdevice$/ {print $1; exit}')"
    if [ -z "$serial" ]; then
        local avd="${KR_ANDROID_AVD:-$("$emulator" -list-avds | head -n 1)}"
        if [ -z "$avd" ]; then
            say "no Android virtual device; skipping Android"
            return 0
        fi
        say "starting the emulator $avd"
        "$emulator" -avd "$avd" -no-snapshot-save -no-boot-anim -netdelay none -netspeed full \
            >"$artefacts/emulator.log" 2>&1 &
        pid=$!
        started=1
        "$adb" wait-for-device
        for _ in $(seq 1 120); do
            [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
            sleep 2
        done
        serial="$("$adb" devices | awk '/^emulator-[0-9]+\tdevice$/ {print $1; exit}')"
    else
        say "using the already running $serial"
    fi
    if [ -z "$serial" ]; then
        say "the emulator did not come up; skipping Android"
        return 0
    fi

    {
        printf 'serial: %s\n' "$serial"
        printf 'model: %s\n' "$("$adb" -s "$serial" shell getprop ro.product.model | tr -d '\r')"
        printf 'release: %s\n' "$("$adb" -s "$serial" shell getprop ro.build.version.release | tr -d '\r')"
        printf 'sdk: %s\n' "$("$adb" -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')"
    } | tee "$artefacts/android-device.txt"

    # 10.0.2.2 is the host as the emulator addresses it.
    "$adb" -s "$serial" reverse "tcp:$port" "tcp:$port" >/dev/null 2>&1 || true

    # A browser that has never been opened shows its own first-run screens over the page. These
    # switches are the browser's own way of saying this is an automated run.
    "$adb" -s "$serial" shell \
        "echo 'chrome --disable-fre --no-default-browser-check --no-first-run --disable-features=Translate' > /data/local/tmp/chrome-command-line" \
        >/dev/null 2>&1 || true
    "$adb" -s "$serial" shell am set-debug-app --persistent com.android.chrome >/dev/null 2>&1 || true
    "$adb" -s "$serial" shell am force-stop com.android.chrome >/dev/null 2>&1 || true
    # An emulator sharing a busy machine drops frames during a transition, and a screenshot taken
    # mid-transition is a photograph of a fade. Turning the transitions off removes the race.
    "$adb" -s "$serial" shell \
        "settings put global window_animation_scale 0; settings put global transition_animation_scale 0; settings put global animator_duration_scale 0" \
        >/dev/null 2>&1 || true
    for screen in "${screens[@]}"; do
        local name="${screen%%|*}" query="${screen#*|}"
        # The address is quoted for the device's own shell: an unquoted ampersand there would
        # put the rest of the query in the background instead of in the request.
        # Through the reverse forward, so the device addresses the host by the same name the
        # host does and nothing depends on the emulator's own network address.
        # The browser's own application identifier reuses the tab it already has, so a run of
        # five addresses is one tab rather than five and no tab-count advice appears over them.
        "$adb" -s "$serial" shell \
            "am start -a android.intent.action.VIEW --es com.android.browser.application_id com.android.chrome -d 'http://localhost:$port/harness.html?surface=android&$query'" \
            >/dev/null
        sleep "${KR_MOBILE_SETTLE:-6}"
        "$adb" -s "$serial" exec-out screencap -p >"$shots/kr-mobile-android-$name.png"
        say "android $name -> $shots/kr-mobile-android-$name.png"
    done

    if [ "$started" = 1 ] && [ "$pid" != 0 ]; then
        say "stopping the emulator this run started"
        kill "$pid" 2>/dev/null || true
    fi
}

case "$want" in
    ios) run_ios ;;
    android) run_android ;;
    both) run_ios; run_android ;;
    *) printf 'unknown platform: %s\n' "$want" >&2; exit 2 ;;
esac

say "artefacts in $artefacts, screenshots in $shots"
