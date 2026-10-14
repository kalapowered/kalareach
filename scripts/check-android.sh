#!/usr/bin/env bash
# Lints the companion's Rust for an Android target, with warnings refused.
#
#   scripts/check-android.sh [<target>]      default: aarch64-linux-android
#
# Every other check of this workspace compiles for the machine it runs on, and the companion
# application ships on a phone: a crate it links can stop building for Android, or gain an Android
# only warning, while every host build stays green. This lints the companion's library, and every
# crate of this workspace that library links on the target, with the features the application
# links, and stops at the first error or warning. It does not build the packaged application:
# `pnpm -C apps/companion android` does that.
#
# It needs the target (`rustup target add <target>`) and an Android NDK, named by `NDK_HOME`,
# `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`. The NDK is what the C library the graph builds from
# source (libsodium) is compiled with; nothing is linked, so the NDK that `apps/companion` pins
# for packaging is not required and any recent one will do. A host with no NDK is refused by name.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

target="${1:-aarch64-linux-android}"

# The platform level the application declares as its minimum (`minSdkVersion` in
# `apps/companion/src-tauri/tauri.conf.json`): the compiler is named after the level it builds for.
level=29
case "$target" in
    armv7-linux-androideabi) compiler="armv7a-linux-androideabi${level}-clang" ;;
    aarch64-linux-android | i686-linux-android | x86_64-linux-android) compiler="${target}${level}-clang" ;;
    *)
        echo "check-android: $target is not an Android target of the companion" >&2
        exit 2
        ;;
esac

ndk="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$ndk" ]; then
    echo "check-android: set NDK_HOME to an Android NDK: the C library in the companion's graph is built with its compiler" >&2
    exit 2
fi
tools=""
for candidate in "$ndk"/toolchains/llvm/prebuilt/*/bin; do
    if [ -x "$candidate/llvm-ar" ] && [ -x "$candidate/$compiler" ]; then
        tools="$candidate"
        break
    fi
done
if [ -z "$tools" ]; then
    echo "check-android: $ndk holds no toolchain with $compiler and llvm-ar" >&2
    exit 2
fi

# The C library's build script runs whatever archiver it finds under the plain names, and a
# host's own archiver can produce an empty archive for this target. Nothing is linked here, but the
# archive stays in the target directory, where the packaging build refuses an empty one, so the
# toolchain's tools are named exactly as that build names them.
export "CC_${target//-/_}=$tools/$compiler"
export AR="$tools/llvm-ar"
export RANLIB="$tools/llvm-ranlib"
export NM="$tools/llvm-nm"
export STRIP="$tools/llvm-strip"

# The companion alone is named: Cargo lints every crate of this workspace that it links as well,
# each with the features the companion asks of it. Naming those crates one by one would turn on
# their default features, and the companion links some of them without.
echo "== check-android: companion-tauri and the crates of this workspace it links, for $target with $tools"
cargo clippy --locked --lib -p companion-tauri --target "$target" -- -D warnings
