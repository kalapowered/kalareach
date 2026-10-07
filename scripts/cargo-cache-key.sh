#!/usr/bin/env bash
# Prints what names a cache of the build output of this workspace's third-party crates: the
# settings a crate is built with, the week, and the third-party dependencies.
#
#   scripts/cargo-cache-key.sh
#
# One line, `<settings>-<week>-<dependencies>`, each part sixteen hex digits or an ISO week.
#
# settings   The toolchain, the build settings of `.cargo/config.toml` and the `[profile]` tables of
#            the workspace's `Cargo.toml`, comments left out: a crate built with other settings is
#            not the crate a cache holds, and an edit to a comment changes none.
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

settings="$({
    grep -h -v -E '^[[:space:]]*(#|$)' rust-toolchain.toml .cargo/config.toml
    awk '/^\[profile/ { keep = 1 } /^\[/ && !/^\[profile/ { keep = 0 } keep && !/^[[:space:]]*(#|$)/' Cargo.toml
} | digest)"
week="$(date -u +%G-W%V)"
dependencies="$(awk 'BEGIN { RS = ""; ORS = "\n\n" } /\nsource = / { print }' Cargo.lock | digest)"

echo "$settings-$week-$dependencies"
