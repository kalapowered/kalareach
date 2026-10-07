#!/usr/bin/env bash
# Prints the digest that names a cache of the build output of this workspace's third-party crates.
#
#   scripts/cargo-dependency-key.sh
#
# Cargo.lock lists two kinds of package. Every crate from a registry or a Git repository carries a
# `source` line; a crate of this workspace carries none. Those crates' versions change on every
# release and their `dependencies` lists change with every edit to a manifest, so a digest of the
# whole file would name a new cache for each of them, though nothing a cache holds depends on
# either. This digest covers the packages with a `source` line only: it changes when a dependency
# is added, removed, or moved to another version or revision, and at no other time.
#
# Each package is a block of lines set apart by a blank line, so awk reads one block as one record.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v sha256sum > /dev/null 2>&1; then
    digest() { sha256sum; }
else
    digest() { shasum -a 256; }
fi

awk 'BEGIN { RS = ""; ORS = "\n\n" } /\nsource = / { print }' "$root/Cargo.lock" | digest | cut -d' ' -f1
