#!/usr/bin/env bash
#
# Shows that the Android release build, minified as it ships, checks who it is talking to: its TLS is
# verified by the platform's verifier, which the minifier would otherwise remove.
#
# The build is the release variant, minified, signed with the debug key and installed on the Android
# emulator. It is driven through its own pairing screen with `uiautomator`. Two things are shown:
#
#   an issuer the system does not trust   The application is pointed at a local TLS server whose
#                          certificate a private authority issued, and attempts a code. The server
#                          records the TCP connection, the ClientHello, the fatal alert the phone
#                          sent and the requests that reached it: the phone sends the alert after the
#                          server's hello and no request arrives. This is the refusal of an issuer
#                          the system does not trust, not of a name that does not match: the emulator's
#                          Play image has no root, and a release build trusts no authority a person
#                          adds. The name check is the shared Rust code the client library's own
#                          case holds on the desktop.
#   the deployed room      One attempt with a code no host holds (an unknown locator) at the deployed
#                          service. The room admits a socket for any locator and gives an unknown
#                          one the same timeout and error shape as a known one, so the attempt
#                          reserves nothing. The pairing screen's outcome is the observable: the
#                          words for an attempt the room admitted and no host answered, never the
#                          words for a service that could not be reached, which is what a build
#                          that lost the platform verifier shows. The two sentences differ, so the
#                          screen decides it; the product's log is not read.
#
# The attempt at the deployed service is the only call to a production service, it carries no
# credential, and the script makes one a run. The local time of each is printed and kept in
# `release-attempts.txt` beside the run's log.
#
# `--without-keep-rule` builds the release without the rule that keeps the platform verifier's Kotlin
# half (`gen/android/app/proguard-rules.pro`), restoring the file afterwards: the run then fails its
# deployed-service check, which is what shows the check can fail.
#
# A simulator or an emulator only inside the Mac's device lease, and the build inside a build slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-android-release.sh [--without-keep-rule]
#
# KR_RELEASE_APK names a signed package to install instead of making one.
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
without_rule=0
case "${1:-}" in
    "") ;;
    --without-keep-rule) without_rule=1 ;;
    *) printf 'usage: %s [--without-keep-rule]\n' "$0" >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/release-tls-android"
shots="${KR_PAIRING_SHOTS:-/tmp/kr-pair-phone}"
mkdir -p "${artefacts:?}" "${shots:?}"
app_id=to.kala.reach
log="$artefacts/run.log"
: >"${log:?}"
harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-release-tls.XXXXXX")"
harness_pid=""
emulator_pid=""
emulator_serial=""
emulator_adb=""
rules="$companion/src-tauri/gen/android/app/proguard-rules.pro"
rules_saved=""

say() { printf '== [release-tls] %s\n' "$*" | tee -a "$log"; }

# Ends what this script started and puts back what it changed: the host is asked to finish and ended
# by the pid recorded only when it does not; the emulator is asked to stop through its serial after
# the application and the tunnel it was given are taken away, and ended by its pid when it does not;
# and the rules file is put back as it was.
finish() {
    touch "$harness/finish" 2>/dev/null
    if [ -n "$harness_pid" ]; then
        local waited=0
        while kill -0 "$harness_pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$harness_pid" 2>/dev/null && kill "$harness_pid" 2>/dev/null
    fi
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
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
    [ -z "$rules_saved" ] || cp "$rules_saved" "$rules" 2>/dev/null
    rm -rf "${harness:?}"
}
trap finish EXIT

sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
adb="${KR_ADB:-$sdk/platform-tools/adb}"
[ -x "$adb" ] || { say "no adb at $adb"; exit 3; }
if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
    say "$avd"
    exit 3
fi

# ---- The package ------------------------------------------------------------------------------

# The newest build tools hold the signer and the aligner.
tools="$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1)"
[ -n "$tools" ] && [ -x "$tools/apksigner" ] && [ -x "$tools/zipalign" ] \
    || { say "no Android build tools with apksigner and zipalign under $sdk/build-tools"; exit 3; }

apk="${KR_RELEASE_APK:-}"
if [ -z "$apk" ]; then
    if [ "$without_rule" = 1 ]; then
        say "taking the keep rule for the platform verifier out of the build, to put it back afterwards"
        rules_saved="$(mktemp "${TMPDIR:-/tmp}/kr-proguard.XXXXXX")"
        cp "$rules" "$rules_saved"
        grep -v 'org.rustls.platformverifier' "$rules_saved" >"$rules"
        if grep -q 'org.rustls.platformverifier' "$rules"; then
            say "the keep rule is still in the rules file"
            exit 2
        fi
    fi
    say "building the minified release for the emulator"
    ( cd "$companion" && pnpm android --target aarch64 --apk ) >"$artefacts/build.log" 2>&1 \
        || { say "the build failed; see $artefacts/build.log"; exit 2; }
    [ -z "$rules_saved" ] || { cp "$rules_saved" "$rules"; rules_saved=""; }
    unsigned="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
    [ -f "$unsigned" ] || { say "there is no release package at $unsigned"; exit 2; }
    aligned="$artefacts/aligned.apk"
    apk="$artefacts/release-signed.apk"
    rm -f "${aligned:?}" "${apk:?}"
    # 16 KB pages: the native code is aligned to them in the package, as the build itself aligns it.
    "$tools/zipalign" -P 16 -f 4 "$unsigned" "$aligned" \
        && "$tools/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android \
            --key-pass pass:android --out "$apk" "$aligned" \
        || { say "the package could not be aligned and signed"; exit 2; }
fi
[ -f "$apk" ] || { say "there is no package at $apk"; exit 2; }

# Whether the verifier's Kotlin half survived the minifier, read from the package itself.
retained="$("$sdk/cmdline-tools/latest/bin/apkanalyzer" dex packages --defined-only "$apk" 2>/dev/null \
    | grep -c 'org.rustls.platformverifier' || true)"
say "the package defines $retained entries of the platform verifier"

# ---- The host --------------------------------------------------------------------------------

say "building the server the phone is pointed at"
cargo test --manifest-path "$here/Cargo.toml" -p kr-controller --test release_tls_device --no-run \
    --message-format=json >"$artefacts/harness-build.json" 2>"$artefacts/harness-build.log" \
    || { say "the server did not build; see $artefacts/harness-build.log"; exit 2; }
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
        and message["target"]["name"] == "release_tls_device"
    ):
        found = message["executable"]
print(found)
PY
)"
[ -n "$harness_exe" ] && [ -x "$harness_exe" ] || { say "the server left no executable"; exit 2; }

# ---- The emulator ----------------------------------------------------------------------------

serial_port=5596
serial="emulator-$serial_port"
if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
    say "a device is already on $serial, which is left alone"
    exit 3
fi
say "starting the emulator $avd"
"$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim -no-window \
    -no-audio -no-metrics -gpu swiftshader_indirect -netdelay none -netspeed full \
    >"$artefacts/emulator.log" 2>&1 &
emulator_pid=$!
emulator_serial=$serial
emulator_adb=$adb
booted=0
for _ in $(seq 1 180); do
    kill -0 "$emulator_pid" 2>/dev/null || break
    if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
    sleep 2
done
{ [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; exit 3; }

"$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
"$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; exit 2; }
"$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

KR_HARNESS_DIR="$harness" KR_HARNESS_SECONDS=900 \
    "$harness_exe" --ignored --exact an_issuer_the_system_does_not_trust_is_refused_before_any_request --nocapture \
    >"$artefacts/harness.log" 2>&1 &
harness_pid=$!
waited=0
while [ ! -s "$harness/tls-listening.json" ]; do
    kill -0 "$harness_pid" 2>/dev/null || { say "the server ended before it was ready; see $artefacts/harness.log"; exit 2; }
    sleep 1
    waited=$((waited + 1))
    [ "$waited" -lt 120 ] || { say "the server was not ready in time"; exit 2; }
done
port="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["port"])' "$harness/tls-listening.json")"
# The server is on this machine's loopback interface, which the emulator's own loopback interface is
# tied to; the address the emulator reaches this machine by is not used.
"$adb" -s "$serial" reverse "tcp:$port" "tcp:$port" >/dev/null \
    || { say "the emulator's loopback interface could not be tied to the server"; exit 2; }
say "the server is up on port $port"

# ---- The run ---------------------------------------------------------------------------------

say "driving the application"
out="$artefacts/driver.log"
status=0
python3 "$here/scripts/lib/pairing-android.py" release "$adb" "$serial" "$harness" "$shots" "$port" "$artefacts/release-attempts.txt" \
    >"$out" 2>&1 || status=$?
sed 's/^/    /' "$out" | tee -a "$log"
"$adb" -s "$serial" logcat -d -b crash >"$artefacts/crash.log" 2>&1

# What the server saw: judged from its own record, never from what the phone's screen said.
record="$harness/tls-control.json"
cp "$record" "$artefacts/tls-control.json" 2>/dev/null
verdict="$(python3 - "$record" <<'PY'
import json
import sys

try:
    seen = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    print("no record")
    raise SystemExit(0)
problems = []
if seen["accepted"] < 1:
    problems.append("the phone never connected")
if seen["client_hellos"] < 1:
    problems.append("the server read no ClientHello")
if not seen["alerts"]:
    problems.append("the phone sent no fatal alert")
if seen["handshakes"] != 0:
    problems.append("a handshake completed")
if seen["request_bytes"] != 0:
    problems.append("a request reached the server")
print("; ".join(problems) if problems else "ok " + ",".join(seen["alerts"]))
PY
)"
if [ "${verdict%% *}" = ok ]; then
    say "check=the phone refused the untrusted issuer after the server's hello, and no request arrived ok=1 detail=${verdict#ok }"
else
    say "check=the phone refused the untrusted issuer after the server's hello, and no request arrived ok=0 detail=$verdict"
    status=2
fi
for check in "the application admitted the attempt at the deployed service" "the application could not reach the local server"; do
    if grep -q -F "RELEASE-TLS $check" "$out"; then
        say "check=$check ok=1"
    else
        say "check=$check ok=0 detail=the driver did not report it"
        status=2
    fi
done
[ "$status" = 0 ] || exit 2
