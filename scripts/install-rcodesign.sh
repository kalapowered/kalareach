#!/usr/bin/env bash
# Puts the pinned `rcodesign` (the apple-codesign command-line signer) in a cache directory and
# prints the path of the executable.
#
#   scripts/install-rcodesign.sh [<directory>]
#
# One tool signs every Mach-O file of a macOS release tree, ad hoc in a run that proves the pipeline
# and with the Developer ID for a release, so a proving run signs the way a release does. The
# executable is the project's own release build for macOS, a universal binary that runs on the Apple
# Silicon and the Intel runners and on a developer's Mac, and the SHA-256 of its archive is held
# here: an archive that differs is refused, and so is an executable that does not say it is the
# pinned version. <directory> defaults to $KR_TOOLS_DIR, else ~/.cache/kalareach-tools.

set -euo pipefail

version="0.29.0"
archive_sha256="d98372d5524226ccf9dc0eda03d4e4f5826182dabb2fc3f2bd303ed9113a748d"
archive="apple-codesign-${version}-macos-universal.tar.gz"
url="https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F${version}/${archive}"

if [ "$(uname -s)" != Darwin ]; then
    echo "install-rcodesign: the pinned build is the macOS one, and this is not macOS" >&2
    exit 1
fi

directory="${1:-${KR_TOOLS_DIR:-$HOME/.cache/kalareach-tools}}"
executable="$directory/rcodesign-$version/rcodesign"

has_version() { [ -x "$1" ] && [ "$("$1" --version 2> /dev/null)" = "apple-codesign $version" ]; }

if has_version "$executable"; then
    printf '%s\n' "$executable"
    exit 0
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/kr-rcodesign.XXXXXX")"
trap 'rm -rf "${work:?}"' EXIT
curl --proto '=https' --tlsv1.2 --silent --show-error --fail --location --output "$work/$archive" "$url"
actual="$(shasum -a 256 "$work/$archive" | cut -d' ' -f1)"
if [ "$actual" != "$archive_sha256" ]; then
    echo "install-rcodesign: $archive has the digest $actual, and the pinned one is $archive_sha256" >&2
    exit 1
fi
tar -xzf "$work/$archive" -C "$work"
mkdir -p "$directory/rcodesign-$version"
cp "$work/apple-codesign-$version-macos-universal/rcodesign" "$executable.new"
chmod 755 "$executable.new"
mv "$executable.new" "$executable"
if ! has_version "$executable"; then
    echo "install-rcodesign: $executable does not say it is apple-codesign $version" >&2
    exit 1
fi
printf '%s\n' "$executable"
