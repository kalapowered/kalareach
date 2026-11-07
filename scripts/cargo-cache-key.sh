#!/usr/bin/env bash
# Prints what names a cache of the build output of this workspace's third-party crates: the
# settings a crate is built with, the week, and the third-party dependencies.
#
#   scripts/cargo-cache-key.sh
#
# One line, `<settings>-<week>-<dependencies>`, each part sixteen hex digits or an ISO week.
#
# settings   The toolchain, the build settings of `.cargo/config.toml`, the `[profile]` tables of the
#            workspace's `Cargo.toml`, the `CARGO_PROFILE_*` and `RUSTFLAGS` variables of the
#            environment, the variables the native compilers read (the deployment target and the
#            SDK, the compilers, their flags and wrappers), comments left out, and the runner
#            image: a crate built with other settings is not the crate a cache holds, and an edit
#            to a comment changes none. Cargo does not see a change to a variable that only a
#            compiler reads: a build script that compiles C runs again only for the variables it
#            names, and what it built before stays in the cache. The
#            image is `ImageOS` and `ImageVersion`, which a hosted runner sets. A native build
#            leaves its configured tree in the cache (a CMake tree holds the paths of the tools
#            and libraries it found), and on another image those paths are gone or other, so a
#            cache built on one image is not restored on another, by an exact key or by a prefix.
#            Where a variable is not set, or is empty, it reads `unset` in what is digested, so
#            that a machine that is not a hosted runner has a key of its own and is not taken for
#            one.
# week       The ISO week, so that what a cache holds is rebuilt from nothing at least weekly. A
#            cache that is restored and saved again only grows: Cargo never removes a unit that no
#            build asks for, and a feature a manifest turns on changes no line of Cargo.lock.
# dependencies
#            Cargo.lock lists two kinds of package. Every crate from a registry or a Git
#            repository carries a `source` line; a crate of this workspace carries none. Those
#            crates' versions change on every release and their `dependencies` lists change with
#            every edit to a manifest, so a digest of the whole file would name a new cache for
#            each of them, though nothing a cache holds depends on either. This digest covers the
#            packages with a `source` line only: it changes when a dependency is added, removed,
#            or moved to another version or revision, and at no other time. Each package is a block
#            of lines set apart by a blank line, so awk reads one block as one record.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if command -v sha256sum > /dev/null 2>&1; then
    digest() { sha256sum | cut -c1-16; }
else
    digest() { shasum -a 256 | cut -c1-16; }
fi

# Each part is assigned to a variable first, so that a file that cannot be read stops the script.
toolchain="$(grep -h -v -E '^[[:space:]]*(#|$)' rust-toolchain.toml .cargo/config.toml)"
profiles="$(awk '/^\[profile/ { keep = 1 } /^\[/ && !/^\[profile/ { keep = 0 } keep && !/^[[:space:]]*(#|$)/' Cargo.toml)"
# The settings the workflow gives every build by environment variable: Rust's, and what the native
# compilers read, which the `cc` crate and the C builds of the third-party crates take from the
# environment, also for one target (`CC_x86_64_apple_darwin`) or for the host (`HOST_CC`).
rust_variables='CARGO_PROFILE_|RUSTFLAGS=|CARGO_ENCODED_RUSTFLAGS='
native_variables='MACOSX_DEPLOYMENT_TARGET=|SDKROOT=|DEVELOPER_DIR=|CRATE_CC_|CXXSTDLIB='
native_variables+='|((HOST|TARGET)_)?(CC|CXX|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|AR|ARFLAGS|RANLIB)(_[^=]*)?='
environment="$(env | grep -E "^($rust_variables|$native_variables)" | LC_ALL=C sort || true)"
image="ImageOS=${ImageOS:-unset} ImageVersion=${ImageVersion:-unset}"
settings="$(printf '%s\n%s\n%s\n%s\n' "$toolchain" "$profiles" "$environment" "$image" | digest)"
week="$(date -u +%G-W%V)"
dependencies="$(awk 'BEGIN { RS = ""; ORS = "\n\n" } /\nsource = / { print }' Cargo.lock | digest)"

echo "$settings-$week-$dependencies"
