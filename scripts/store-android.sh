#!/usr/bin/env bash
# Builds, signs and checks the Android bundle that goes to Google Play's testing tracks.
#
#   scripts/store-android.sh [--build-number <n>]     build, sign and check
#   scripts/store-android.sh --device <directory>     run a built bundle on the emulator
#
# The first form makes the minified release bundle for the two architectures phones and the
# emulator use, signs it with the upload key, and holds the signed file to `store-bundle.mjs`. Its
# output is one directory, `$KR_STORE_ROOT/<version>-<build number>/`: the signed bundle,
# `store-build.json` (the file's digest, versions, signer and the tools that made it) and the
# check's log. Nothing is uploaded anywhere.
#
# The upload key and its password are files under `~/.config/kalareach-secrets/android-upload/`
# (`KR_SECRETS_DIR` moves the directory). Gradle never sees them: it builds an unsigned bundle,
# and `jarsigner` signs it afterwards with `-storepass:file`, so the password is neither on a
# command line, nor in the environment, nor in a log, nor in the build's long-lived process.
# Push needs the Firebase configuration of the application: `firebase-apps/google-services.json`
# in the same directory (`KR_GOOGLE_SERVICES_JSON` names another). It goes into the bundle as the
# application's configuration and nowhere else.
#
# The version is `version` in `tauri.conf.json`. The build number is the whole minutes since
# 2026-10-01T00:00Z, and it must be above the one the receipt for this platform holds, so it is the
# version code Google Play compares. `--build-number` names one by hand under the same rule.
#
# The second form installs the bundle's universal package, signed with the same key, on the
# KalaReach emulator, starts it, records what the platform says about its page size and its app
# links, and then runs the release TLS check on it. It starts an emulator, so it runs inside the
# device lease:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/store-android.sh --device <directory>
#
# and the first form is a heavy build:
#
#   bash lead-scripts/with-slot.sh <label> scripts/store-android.sh
#
# Exit codes: 0 every check passed, 2 bad usage, a missing input or a failed check, 3 no device.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
kr_store_tag=store-android
# shellcheck source=scripts/lib/store-build.sh
. "$here/scripts/lib/store-build.sh"
# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
java_home="${KR_JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
upload_dir="$KR_SECRETS_DIR/android-upload"
keystore="$upload_dir/kalareach-upload.p12"
password_file="$upload_dir/keystore-password"
certificate="$upload_dir/upload-certificate.pem"
firebase="${KR_GOOGLE_SERVICES_JSON:-$KR_SECRETS_DIR/firebase-apps/google-services.json}"
bundletool="${KR_BUNDLETOOL:-$(command -v bundletool || true)}"
app_id=to.kala.reach

mode=build
number_given=""
device_dir=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-number) number_given="${2:-}"; shift 2 || { echo "usage: --build-number <n>" >&2; exit 2; } ;;
        --device) mode=device; device_dir="${2:-}"; shift 2 || { echo "usage: --device <directory>" >&2; exit 2; } ;;
        *) echo "usage: $0 [--build-number <n>] | --device <directory>" >&2; exit 2 ;;
    esac
done

[ -x "$bundletool" ] || { kr_store_say "bundletool is not installed (brew install bundletool, or KR_BUNDLETOOL)"; exit 2; }
for tool in "$java_home/bin/jarsigner" "$java_home/bin/keytool"; do
    [ -x "$tool" ] || { kr_store_say "no $tool"; exit 2; }
done
export PATH="$java_home/bin:$PATH"
export JAVA_HOME="$java_home"
kr_store_require_file "$keystore" "the upload keystore" || exit 2
kr_store_require_file "$password_file" "the upload keystore's password file" || exit 2
[ -f "$certificate" ] || { kr_store_say "no upload certificate at $certificate"; exit 2; }

# ---- The emulator leg --------------------------------------------------------------------------

if [ "$mode" = device ]; then
    record="$device_dir/store-build.json"
    [ -f "$record" ] || { kr_store_say "no store-build.json in $device_dir"; exit 2; }
    version_code="$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).versionCode))' "$record")"
    bundle="$device_dir/$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).file)' "$record")"
    [ -f "$bundle" ] || { kr_store_say "no bundle at $bundle"; exit 2; }
    shots="${KR_STORE_SHOTS:-/tmp/kr-store-android}"
    leg="$device_dir/device"
    mkdir -p "${leg:?}" "${shots:?}"
    log="$leg/leg.log"
    : >"$log"
    say() { kr_store_say "$*" | tee -a "$log"; }

    tools="$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1)"
    [ -x "$tools/zipalign" ] && [ -x "$tools/apksigner" ] || { say "no build tools with zipalign and apksigner"; exit 2; }
    adb="${KR_ADB:-$sdk/platform-tools/adb}"
    [ -x "$adb" ] || { say "no adb at $adb"; exit 3; }
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        exit 3
    fi

    # The universal package: one installable file made from the bundle, signed with the same key.
    say "making the universal package from the bundle"
    rm -f -- "${leg:?}/KalaReach.apks" "${leg:?}/universal.apk"
    "$bundletool" build-apks --bundle="$bundle" --output="$leg/KalaReach.apks" --mode=universal \
        --ks="$keystore" --ks-pass="file:$password_file" --ks-key-alias=upload --key-pass="file:$password_file" \
        >>"$log" 2>&1 || { say "bundletool could not make the package"; exit 2; }
    unzip -q -o "$leg/KalaReach.apks" universal.apk -d "$leg" || { say "the package set holds no universal.apk"; exit 2; }
    apk="$leg/universal.apk"
    status=0
    if "$tools/zipalign" -c -P 16 4 "$apk" >>"$log" 2>&1; then
        say "check=the universal package's native libraries are aligned for 16 KB pages ok=1"
    else
        say "check=the universal package's native libraries are aligned for 16 KB pages ok=0"
        status=2
    fi
    wanted="$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
    found="$("$tools/apksigner" verify --print-certs "$apk" 2>>"$log" | sed -n 's/.*certificate SHA-256 digest: //p' | head -1)"
    if [ -n "$found" ] && [ "$found" = "$wanted" ]; then
        say "check=the universal package is signed by the upload key ok=1"
    else
        say "check=the universal package is signed by the upload key ok=0"
        status=2
    fi

    serial_port=5598
    serial="emulator-$serial_port"
    emulator_pid=""
    finish() {
        if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
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
    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        exit 3
    fi
    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim -no-window \
        -no-audio -no-metrics -gpu swiftshader_indirect >"$leg/emulator.log" 2>&1 &
    emulator_pid=$!
    booted=0
    for _ in $(seq 1 180); do
        kill -0 "$emulator_pid" 2>/dev/null || break
        if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
        sleep 2
    done
    { [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; exit 3; }

    page="$("$adb" -s "$serial" shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r')"
    say "the emulator's page size is ${page:-unknown} bytes"
    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >>"$log" 2>&1 || { say "the package did not install"; exit 2; }
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS >>"$log" 2>&1
    "$adb" -s "$serial" logcat -c
    "$adb" -s "$serial" shell monkey -p "$app_id" -c android.intent.category.LAUNCHER 1 >>"$log" 2>&1
    sleep 20
    pid="$("$adb" -s "$serial" shell pidof "$app_id" 2>/dev/null | tr -d '\r')"
    "$adb" -s "$serial" exec-out screencap -p >"$shots/store-launch-$version_code.png" 2>/dev/null
    "$adb" -s "$serial" logcat -d -b crash >"$leg/crash.log" 2>&1
    "$adb" -s "$serial" logcat -d 2>/dev/null | grep -v -E 'CompositionEngine|AccessibilityNodeInfoDumper' | tail -3000 >"$leg/logcat.log"
    "$adb" -s "$serial" shell pm get-app-links "$app_id" >"$leg/app-links.txt" 2>&1
    "$adb" -s "$serial" shell dumpsys package "$app_id" 2>/dev/null | grep -E 'versionCode|versionName|signatures|targetSdk' >"$leg/package.txt"
    if [ -n "$pid" ]; then
        say "check=the store-signed application starts and is running ok=1 detail=pid $pid"
    else
        say "check=the store-signed application starts and is running ok=0"
        status=2
    fi
    if [ -z "$(tr -d '[:space:]' <"$leg/crash.log")" ]; then
        say "check=the crash log is empty after the start ok=1"
    else
        say "check=the crash log is empty after the start ok=0 detail=see $leg/crash.log"
        status=2
    fi
    if grep -q "versionCode=$version_code" "$leg/package.txt"; then
        say "check=the installed version code is $version_code ok=1"
    else
        say "check=the installed version code is $version_code ok=0"
        status=2
    fi
    say "Firebase lines in the log: $(grep -c -i 'FirebaseApp' "$leg/logcat.log" || true); app links: $(tr -s ' ' <"$leg/app-links.txt" | grep -E 'reach.kala.to|Domain verification state' | head -3 | tr '\n' ';')"
    finish
    emulator_pid=""
    trap - EXIT

    # The release TLS check on exactly this package, in the same device session. It starts its own
    # emulator once this one has ended, and its single call to the deployed service is the positive
    # control for the platform verifier (it carries no credential).
    say "running the release TLS check on the store-signed package"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(kr_store_cargo_target "$here")}"
    KR_TEST_ARTIFACTS_DIR="$leg/e2e" KR_RELEASE_APK="$apk" bash "$here/scripts/e2e-android-release.sh" \
        >"$leg/e2e-release.log" 2>&1
    e2e=$?
    grep -E '^== \[release-tls\]' "$leg/e2e-release.log" | tee -a "$log"
    if [ "$e2e" = 0 ]; then say "check=the release TLS check passed on the store-signed package ok=1"
    else say "check=the release TLS check passed on the store-signed package ok=0 detail=exit $e2e"; status=2; fi
    exit "$status"
fi

# ---- The build ---------------------------------------------------------------------------------

kr_store_clean_tree "$here" || exit 2
[ -f "$firebase" ] || { kr_store_say "no Firebase configuration at $firebase"; exit 2; }

ndk_version="$(sed -n 's/^ *ndkVersion = "\(.*\)"$/\1/p' "$companion/src-tauri/gen/android/app/build.gradle.kts")"
ndk="$sdk/ndk/$ndk_version"
[ -n "$ndk_version" ] && [ -d "$ndk/toolchains" ] || { kr_store_say "the NDK the build pins ($ndk_version) is not at $ndk"; exit 2; }

version="$(kr_store_version "$here")" || exit 2
number="$(kr_store_number android "$number_given")" || exit 2
out="$KR_STORE_ROOT/$version-$number"
[ ! -e "$out" ] || { kr_store_say "$out exists already"; exit 2; }
mkdir -p "$out"
kr_store_say "version $version, build number $number, into $out"

# The shell's own NDK may be an older one: a release linked by it would not be laid out for 16 KB
# pages, so the build names the one the project pins.
export NDK_HOME="$ndk" ANDROID_NDK_HOME="$ndk" ANDROID_NDK_ROOT="$ndk" ANDROID_HOME="$sdk"
export KR_GOOGLE_SERVICES_JSON="$firebase"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(kr_store_cargo_target "$here")}"

unsigned="$companion/src-tauri/gen/android/app/build/outputs/bundle/universalRelease/app-universal-release.aab"
rm -f -- "${unsigned:?}"
marker="$out/.started"
: >"$marker"
kr_store_say "building the release bundle for aarch64 and x86_64"
( cd "$companion" && pnpm android --aab --ci --target aarch64 x86_64 \
    --config "{\"bundle\":{\"android\":{\"versionCode\":$number}}}" ) \
    || { kr_store_say "the build failed"; exit 2; }
[ -f "$unsigned" ] && [ "$unsigned" -nt "$marker" ] || { kr_store_say "the build left no new bundle at $unsigned"; exit 2; }

signed="$out/KalaReach-$version-$number.aab"
kr_store_say "signing with the upload key"
jarsigner -keystore "$keystore" -storetype PKCS12 -storepass:file "$password_file" \
    -sigalg SHA256withRSA -digestalg SHA-256 -signedjar "$signed" "$unsigned" upload >"$out/sign.log" 2>&1 \
    || { kr_store_say "jarsigner failed (see $out/sign.log)"; exit 2; }

kr_store_say "checking the signed bundle"
commit="$(git -C "$here" rev-parse HEAD)"
dirty=false
[ -z "$(git -C "$here" status --porcelain --untracked-files=no)" ] || dirty=true
node "$companion/scripts/store-bundle.mjs" --android "$signed" --version-code "$number" --version-name "$version" \
    --certificate "$certificate" --secret-file "$password_file" --bundletool "$bundletool" \
    --record "$out/store-build.json" \
    --note "commit=$commit" --note "uncommittedChanges=$dirty" --note "ndk=$ndk_version" \
    --note "abis=arm64-v8a,x86_64" --note "builtAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --note "java=$("$java_home/bin/java" -version 2>&1 | head -1)" \
    --note "tauriCli=$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$companion/node_modules/@tauri-apps/cli/package.json")" \
    2>&1 | tee "$out/check.log"
checked=${PIPESTATUS[0]}
rm -f -- "${marker:?}"
[ "$checked" = 0 ] || { kr_store_say "the bundle does not hold; nothing was recorded as built"; exit 2; }

kr_store_receipt android "$number"
kr_store_say "built and checked: $signed"
kr_store_say "sha256 $(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).sha256)' "$out/store-build.json")"
