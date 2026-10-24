#!/bin/bash
# Builds the library that opens a sealed notification preview, for the notification extension to link.
#
# The extension is a separate process with its own binary, so it carries the one function that opens
# a preview (`companion-preview`) and what it depends on, as a static library of its own, and not the
# application's whole Rust archive. Xcode runs this as a build phase of the extension and of the unit
# tests that run the extension's code, with `PLATFORM_NAME`, `ARCHS`, `CONFIGURATION` and `SRCROOT`
# set. The library is left in `Externals/preview/<platform>/<configuration>`, where the targets look
# for it. Cargo does nothing when the library is up to date.
set -eu

case "${PLATFORM_NAME:?}" in
    iphoneos) triple=aarch64-apple-ios ;;
    iphonesimulator) triple=aarch64-apple-ios-sim ;;
    *)
        echo "error: the preview library is built for a phone or its simulator, not for ${PLATFORM_NAME}" >&2
        exit 1
        ;;
esac
case "${ARCHS:?}" in
    arm64) ;;
    *)
        echo "error: the preview library is built for arm64 only, not for ${ARCHS}" >&2
        exit 1
        ;;
esac

# Xcode's build phases run with a short path.
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

root="$(cd "${SRCROOT:?}/../../../../.." && pwd)"
profile=debug
profile_flag=()
if [ "${CONFIGURATION:?}" = "release" ] || [ "${CONFIGURATION}" = "Release" ]; then
    profile=release
    profile_flag=(--release)
fi

target_directory="${CARGO_TARGET_DIR:-${root}/target}"
(cd "${root}" && cargo rustc --locked --package companion-preview --lib --crate-type staticlib --target "${triple}" ${profile_flag[@]+"${profile_flag[@]}"})

destination="${SRCROOT}/Externals/preview/${PLATFORM_NAME}/${CONFIGURATION}"
mkdir -p "${destination}"
cp "${target_directory}/${triple}/${profile}/libcompanion_preview.a" "${destination}/libcompanion_preview.a"
