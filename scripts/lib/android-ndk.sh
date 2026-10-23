#!/usr/bin/env bash
# The Android NDK's tools for one Android target.
#
# Source this file and call `kr_android_toolchain <target>`. The workspace builds a C library
# (libsodium) from source for every target, and the NDK's compiler and archiver are what it must
# build it with: a host's own archiver can produce an empty archive for an Android target. The
# function finds the NDK from `NDK_HOME`, `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`, in that order,
# and exports, for cargo and the build scripts it runs:
#
#   KR_ANDROID_TOOLS      the NDK's `bin` directory for this host
#   KR_ANDROID_COMPILER   the compiler for the target, named after the platform level the
#                         application declares as its minimum
#   CC_<target>, AR, RANLIB, NM, STRIP
#
# It returns 2 and says why, on standard error, when the target is not one of the companion's, no
# NDK is named, or the NDK holds no such toolchain.

# The platform level the application declares as its minimum (`minSdkVersion` in
# `apps/companion/src-tauri/tauri.conf.json`): the compiler is named after the level it builds for.
KR_ANDROID_LEVEL=29

kr_android_toolchain() {
    local target=$1 compiler ndk candidate tools=""
    case "$target" in
        armv7-linux-androideabi) compiler="armv7a-linux-androideabi${KR_ANDROID_LEVEL}-clang" ;;
        aarch64-linux-android | i686-linux-android | x86_64-linux-android) compiler="${target}${KR_ANDROID_LEVEL}-clang" ;;
        *)
            echo "android-ndk: $target is not an Android target of the companion" >&2
            return 2
            ;;
    esac
    ndk="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
    if [ -z "$ndk" ]; then
        echo "android-ndk: set NDK_HOME to an Android NDK: the C library in the companion's graph is built with its compiler" >&2
        return 2
    fi
    for candidate in "$ndk"/toolchains/llvm/prebuilt/*/bin; do
        if [ -x "$candidate/llvm-ar" ] && [ -x "$candidate/$compiler" ]; then
            tools="$candidate"
            break
        fi
    done
    if [ -z "$tools" ]; then
        echo "android-ndk: $ndk holds no toolchain with $compiler and llvm-ar" >&2
        return 2
    fi
    export KR_ANDROID_TOOLS="$tools"
    export KR_ANDROID_COMPILER="$compiler"
    export "CC_${target//-/_}=$tools/$compiler"
    export AR="$tools/llvm-ar"
    export RANLIB="$tools/llvm-ranlib"
    export NM="$tools/llvm-nm"
    export STRIP="$tools/llvm-strip"
}
