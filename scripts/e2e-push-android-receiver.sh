#!/usr/bin/env bash
#
# Runs the Android push receiver and the scheduler behind it in the application's own process on
# the emulator, with no screen of the application started (`PushReceiverInstrumentedTest`).
#
# The instrumentation runs as the application, and hands the application's Firebase receiver the
# data of a message the way the provider does. One case shows a delivery shown by the receiver alone.
# The other posts a registration challenge's answer to a gateway that is not there, which the
# receiver hands to WorkManager, and then brings the gateway up: the scheduler's retry is the answer
# the gateway takes. What it shows beyond the unit cases is that the receiver, the library the
# function is loaded from and the scheduler work in a process the system built for them.
#
# The test package is built for the arm64 flavour with Gradle, beside the application's own build
# for it (`pnpm android --target aarch64 --debug`), and both are installed on the emulator of
# KalaReach's own virtual device. An emulator only inside the Mac's device lease, and the build
# inside a build slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-push-android-receiver.sh
#
# Exit codes: 0 every case passed, 2 a case failed or a build did, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="$here/apps/companion/src-tauri/gen/android"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/push-android-receiver"
mkdir -p "${artefacts:?}"
app_id=to.kala.reach
log="$artefacts/run.log"
: >"${log:?}"

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

say() { printf '== [push-android-receiver] %s\n' "$*" | tee -a "$log"; }

sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
adb="${KR_ADB:-$sdk/platform-tools/adb}"
serial_port=5598
serial="emulator-$serial_port"
emulator_pid=""

finish() {
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        "$adb" -s "$serial" uninstall "$app_id.test" >/dev/null 2>&1
        "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
        "$adb" -s "$serial" emu kill >/dev/null 2>&1
        local stopped=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$stopped" -lt 30 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
}
trap finish EXIT

[ -x "$adb" ] || { say "no adb at $adb"; exit 3; }
if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
    say "$avd"
    exit 3
fi

say "building the application and its tests for the arm64 flavour"
( cd "$project" && ./gradlew --console=plain :app:assembleArm64Debug :app:assembleArm64DebugAndroidTest \
    -PabiList=arm64-v8a -ParchList=arm64 -PtargetList=aarch64 ) >"$artefacts/build.log" 2>&1 \
    || { tail -30 "$artefacts/build.log"; say "the build failed; see $artefacts/build.log"; exit 2; }
apk="$project/app/build/outputs/apk/arm64/debug/app-arm64-debug.apk"
tests="$project/app/build/outputs/apk/androidTest/arm64/debug/app-arm64-debug-androidTest.apk"
[ -f "$apk" ] && [ -f "$tests" ] || { say "the build left no package"; exit 2; }

if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
    say "a device is already on $serial, which is left alone"
    exit 3
fi
say "starting the emulator $avd"
"$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim \
    -no-window -no-audio -no-metrics -gpu swiftshader_indirect >"$artefacts/emulator.log" 2>&1 &
emulator_pid=$!
booted=0
for _ in $(seq 1 180); do
    kill -0 "$emulator_pid" 2>/dev/null || break
    if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
    sleep 2
done
{ [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; exit 3; }

"$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
"$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the application did not install"; exit 2; }
"$adb" -s "$serial" install -r "$tests" >/dev/null || { say "the tests did not install"; exit 2; }

say "running the receiver's cases in the application's process"
"$adb" -s "$serial" shell am instrument -w -r \
    -e class to.kala.reach.companion.push.PushReceiverInstrumentedTest \
    "$app_id.test/androidx.test.runner.AndroidJUnitRunner" >"$artefacts/instrument.txt" 2>&1
sed 's/^/    /' "$artefacts/instrument.txt" | grep -E "INSTRUMENTATION_STATUS: (test|class|stack|numtests)|INSTRUMENTATION_RESULT|OK \(|FAILURES" | tee -a "$log" >/dev/null
"$adb" -s "$serial" logcat -d -s KalaReachPush:I >"$artefacts/receiver.log" 2>&1
if grep -q "^OK (" "$artefacts/instrument.txt" && ! grep -q "FAILURES" "$artefacts/instrument.txt"; then
    say "$(grep '^OK (' "$artefacts/instrument.txt" | head -1): every case passed"
    exit 0
fi
say "a case did not pass; see $artefacts/instrument.txt"
exit 2
