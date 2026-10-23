#!/usr/bin/env bash
# Runs the native library's run-time cases on a phone target, on the device itself.
#
#   scripts/native-library-tests.sh android [--serial <adb serial>]
#   scripts/native-library-tests.sh ios --udid <simulator identifier>
#
# The cryptography every platform shares is libsodium, built from source for each target by the
# `kr-crypto` crate. Linux, macOS and Windows run its tests where they build them. A phone target
# is built by the companion's jobs and, until this, never executed: a library that compiles for
# Android or iOS can still fail on the device. This builds the crate's test programs for the
# target and runs each one on a device that is already running, through a cargo runner:
#
#   android   x86_64-linux-android on an emulator; KR_ANDROID_TARGET names another target the
#             device runs, such as aarch64-linux-android on an Apple silicon emulator. The programs
#             are pushed with `adb` and run in a directory of their own on the device. It needs an
#             NDK (see scripts/lib/android-ndk.sh) and `adb`, found on PATH or under ANDROID_HOME.
#   ios       aarch64-apple-ios-sim in a booted simulator, run with `xcrun simctl spawn`. The
#             simulator is named by its identifier, never by "booted", so a second simulator cannot
#             change the target.
#
# The device is the caller's: this boots nothing and shuts nothing down. Locally, run it inside
# `scripts/../lead-scripts/with-device.sh`'s lease with a device that command started.
#
# What runs, each case counted:
#
#   * every unit test of the crate's library, which holds the published vectors of X25519, the
#     authenticated box, Ed25519 and the key derivation, the sealed objects and the streams, but
#     for the two named in `skipped_cases` below;
#   * the three cases of tests/libsodium.rs that exercise the library and read no file of the
#     repository, each by name: the published XChaCha20-Poly1305 vector, the secretstream that needs
#     its final record, and the clearing of a caller's own buffer through libsodium's zeroing call.
#
# A named case that does not run exactly once and pass, a library run that runs no test, and any
# failure fail the run. The other cases of tests/libsodium.rs read the repository's sources, which
# a device has no checkout of. This reports the target and the counts. The other architectures of a
# phone are compiled by their own jobs and not run here.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
self="$root/scripts/native-library-tests.sh"

# The cases of tests/libsodium.rs that need nothing but the library.
named_cases=(
    the_pairing_aead_opens_the_published_xchacha20_poly1305_vector
    an_object_is_a_secretstream_that_needs_its_final_record
    a_buffer_the_caller_assembled_is_cleared_through_libsodium
)

# The library's own tests that are not about the library and cannot run on a device, each by its
# full name and with the reason.
skipped_cases=(
    # Makes a named pipe, which the directory a device's shell may write to refuses.
    relay::tests::a_named_pipe_in_the_key_s_place_does_not_hold_the_relay_open
    # Reads the repository's published lease vectors, which a device has no checkout of.
    vectors::tests::a_lease_naming_a_key_the_vectors_do_not_sign_with_is_refused
)

say() { printf 'native-library-tests: %s\n' "$*"; }
die() {
    printf 'native-library-tests: %s\n' "$*" >&2
    exit 2
}

# -- the runner ----------------------------------------------------------------------------------
# Cargo runs each test program as `<runner> <program> <arguments>`. This script is its own runner:
# `--run <platform> <device>` is how it is called then.

quote() {
    local word=$1
    printf "'%s'" "${word//\'/\'\\\'\'}"
}

find_adb() {
    if command -v adb > /dev/null 2>&1; then
        command -v adb
    elif [ -x "${ANDROID_HOME:-/nonexistent}/platform-tools/adb" ]; then
        printf '%s\n' "$ANDROID_HOME/platform-tools/adb"
    else
        return 1
    fi
}

if [ "${1:-}" = "--run" ]; then
    platform=$2
    device=$3
    program=$4
    shift 4
    case "$platform" in
        android)
            adb="$(find_adb)" || die "adb is not on the path"
            remote=/data/local/tmp/kr-native-tests
            "$adb" -s "$device" shell "mkdir -p $remote"
            "$adb" -s "$device" push "$program" "$remote/$(basename "$program")" > /dev/null
            command_line="cd $remote && chmod 755 ./$(basename "$program") && TMPDIR=$remote ./$(basename "$program")"
            for word in "$@"; do
                command_line="$command_line $(quote "$word")"
            done
            # The remote exit status is adb's own: `adb shell` passes it on.
            exec "$adb" -s "$device" shell "$command_line"
            ;;
        ios)
            exec xcrun simctl spawn "$device" "$program" "$@"
            ;;
        *) die "--run: unknown platform $platform" ;;
    esac
fi

# -- the run -------------------------------------------------------------------------------------

platform="${1:-}"
[ -n "$platform" ] || die "usage: native-library-tests.sh android [--serial <serial>] | ios --udid <identifier>"
shift

serial="${ANDROID_SERIAL:-}"
udid=""
while [ $# -gt 0 ]; do
    case "$1" in
        --serial)
            serial="${2:?--serial needs a value}"
            shift 2
            ;;
        --udid)
            udid="${2:?--udid needs a value}"
            shift 2
            ;;
        *) die "unknown argument $1" ;;
    esac
done

case "$platform" in
    android)
        target="${KR_ANDROID_TARGET:-x86_64-linux-android}"
        # shellcheck source=scripts/lib/android-ndk.sh
        . "$root/scripts/lib/android-ndk.sh"
        kr_android_toolchain "$target" || exit 2
        adb="$(find_adb)" || die "adb is not on the path and ANDROID_HOME names none"
        if [ -z "$serial" ]; then
            serial="$("$adb" devices | awk '$2 == "device" { print $1; exit }')"
        fi
        [ -n "$serial" ] || die "no Android device is running: start the emulator first"
        case "$target" in
            x86_64-linux-android) abi=x86_64 ;;
            aarch64-linux-android) abi=arm64-v8a ;;
            i686-linux-android) abi=x86 ;;
            armv7-linux-androideabi) abi=armeabi-v7a ;;
        esac
        abis="$("$adb" -s "$serial" shell getprop ro.product.cpu.abilist | tr -d '\r')"
        case ",$abis," in
            *",$abi,"*) ;;
            *) die "$serial runs $abis, which does not run $target ($abi)" ;;
        esac
        device="$serial"
        say "device: $serial ($abis), api $("$adb" -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')"
        linker_variable="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"
        export "$linker_variable=$KR_ANDROID_TOOLS/$KR_ANDROID_COMPILER"
        ;;
    ios)
        target=aarch64-apple-ios-sim
        [ -n "$udid" ] || die "ios needs --udid, the identifier of a booted simulator"
        # shellcheck source=scripts/lib/xcode.sh
        . "$root/scripts/lib/xcode.sh"
        command -v xcrun > /dev/null 2>&1 || die "xcrun is needed and is not on the path"
        kr_select_xcode
        if ! xcrun simctl list devices booted | grep -q "$udid"; then
            die "no simulator with the identifier $udid is booted"
        fi
        device="$udid"
        say "device: simulator $udid, $(xcodebuild -version | paste -sd' ' -)"
        ;;
    *) die "unknown platform $platform: android or ios" ;;
esac

runner_variable="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
export "$runner_variable=bash $self --run $platform $device"

cd "$root"
log="$(mktemp "${TMPDIR:-/tmp}/kr-native-library-tests.XXXXXX")"
trap 'rm -f "${log:?}"' EXIT

# One cargo run, its output shown and kept in `$log`. The status is cargo's.
run() {
    echo "== cargo test --locked -p kr-crypto --target $target $*"
    local status=0
    cargo test --locked -p kr-crypto --target "$target" "$@" 2>&1 | tee "$log" || status=${PIPESTATUS[0]}
    return "$status"
}

failed=0

# The library's own unit tests: the count is read from the harness's summary.
skips=()
for name in "${skipped_cases[@]}"; do
    skips+=(--skip "$name")
done
if run --lib -- "${skips[@]}"; then
    library="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed; 0 failed.*/\1/p' "$log" | tail -n 1)"
    if [ -z "$library" ] || [ "$library" -eq 0 ]; then
        echo "native-library-tests: the library run on $target ran no test" >&2
        failed=1
    fi
else
    echo "native-library-tests: the library's tests failed on $target" >&2
    library=0
    failed=1
fi

ran=()
for name in "${named_cases[@]}"; do
    if run --test libsodium -- --exact "$name" && grep -q '^test result: ok\. 1 passed; 0 failed' "$log"; then
        ran+=("$name")
    else
        echo "native-library-tests: $name did not run once and pass on $target" >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi
say "$target on $device: $library library tests passed; ${#ran[@]} named cases passed:"
printf '    %s\n' "${ran[@]}"
