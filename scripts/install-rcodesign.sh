#!/usr/bin/env bash
# Puts the pinned `rcodesign` (the apple-codesign command-line signer) in a cache directory and
# prints the path of the executable.
#
#   scripts/install-rcodesign.sh [<directory>]
#   scripts/install-rcodesign.sh --verify <executable>
#   scripts/install-rcodesign.sh self-test
#
# One tool signs every Mach-O file of a macOS release tree, ad hoc in a run that proves the pipeline
# and with the Developer ID for a release, so a proving run signs the way a release does. The
# executable is the project's own release build for macOS, a universal binary that runs on the Apple
# Silicon and the Intel runners and on a developer's Mac, and the SHA-256 of its archive and of the
# executable in it are held here. An archive that differs is refused. An executable is used only
# when its own SHA-256 is the pinned one, each time, a cached one included: a program that prints
# the pinned version is not thereby the pinned program. `--verify` says whether a given executable is
# the pinned one, for a caller that was handed a path (the signer, which reads the Developer ID
# key). <directory> defaults to $KR_TOOLS_DIR, else ~/.cache/kalareach-tools.

set -euo pipefail

version="0.29.0"
archive_sha256="d98372d5524226ccf9dc0eda03d4e4f5826182dabb2fc3f2bd303ed9113a748d"
executable_sha256="75ef370d4de9fc99d8b26a168bed9c256da8364d8b9fdb2be762ab42fc6a9978"
archive="apple-codesign-${version}-macos-universal.tar.gz"
url="https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F${version}/${archive}"

if [ "$(uname -s)" != Darwin ]; then
    echo "install-rcodesign: the pinned build is the macOS one, and this is not macOS" >&2
    exit 1
fi

is_pinned() { # <path>: the pinned executable, by its digest and then by what it says it is
    [ -x "$1" ] || return 1
    [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$executable_sha256" ] || return 1
    [ "$("$1" --version 2> /dev/null)" = "apple-codesign $version" ]
}

self_test() {
    local work status=0 here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-rcodesign-test.XXXXXX")"
    trap 'rm -rf "${work:?}"' RETURN
    # A program that says it is the pinned version and is not the pinned program.
    printf '#!/bin/sh\necho "apple-codesign %s"\n' "$version" > "$work/rcodesign"
    chmod 755 "$work/rcodesign"
    if bash "${BASH_SOURCE[0]}" --verify "$work/rcodesign" 2> /dev/null; then
        echo "self-test FAILED: a program that prints the pinned version was taken for the pinned program"
        status=1
    else
        echo "self-test ok: a program that prints the pinned version is not the pinned program"
    fi
    # The signer is handed such a program in the environment, and it would read the key.
    mkdir -p "$work/tree"
    : > "$work/key"; : > "$work/cert"; : > "$work/chain"
    if KR_RCODESIGN="$work/rcodesign" KR_SIGN_KEY="$work/key" KR_SIGN_CERT="$work/cert" KR_SIGN_CHAIN="$work/chain" \
        bash "$here/sign-macos-tree.sh" "$work/tree" developer-id > "$work/out" 2>&1; then
        echo "self-test FAILED: the signer went on with a program of its own choosing for the Developer ID"
        status=1
    elif grep -q 'pinned' "$work/out"; then
        echo "self-test ok: the signer refuses a program of its own choosing for the Developer ID and says it is not the pinned one"
    else
        echo "self-test FAILED: the signer stopped, and not for the pin: $(head -1 "$work/out")"
        status=1
    fi
    # A pinned copy in the directory the signer runs in, and another program of the same name on PATH
    # that says the pinned version and leaves a mark when it runs. The signer is handed the bare name.
    # What is hashed has to be what runs, so the mark must not appear. Only where the pinned
    # executable is at hand.
    local pinned="${KR_TOOLS_DIR:-$HOME/.cache/kalareach-tools}/rcodesign-$version/rcodesign"
    if is_pinned "$pinned"; then
        mkdir -p "$work/bin" "$work/here"
        cp "$pinned" "$work/here/rcodesign"
        printf '#!/bin/sh\n: > "%s/ran"\necho "apple-codesign %s"\n' "$work" "$version" > "$work/bin/rcodesign"
        chmod 755 "$work/bin/rcodesign"
        (cd "$work/here" && PATH="$work/bin:$PATH" KR_RCODESIGN=rcodesign KR_SIGN_KEY="$work/key" KR_SIGN_CERT="$work/cert" KR_SIGN_CHAIN="$work/chain" \
            bash "$here/sign-macos-tree.sh" "$work/tree" developer-id > "$work/out2" 2>&1) || true
        if [ -e "$work/ran" ]; then
            echo "self-test FAILED: a program found on PATH ran in place of the file that was hashed"
            status=1
        elif ! grep -q 'holds no Mach-O file' "$work/out2"; then
            echo "self-test FAILED: the signer did not get past the check of the pin to the tree: $(head -1 "$work/out2")"
            status=1
        else
            echo "self-test ok: the file that is hashed is the file that runs, for a name with no directory"
        fi
    else
        echo "self-test note: the pinned executable is not installed here, so the case of a bare name was not run"
    fi
    [ "$status" -eq 0 ] && echo "install-rcodesign: the self-test passed"
    return "$status"
}

case "${1:-}" in
    --verify)
        # One file is named, by its absolute path, and the same file is hashed and run: a bare name
        # would be hashed where this runs and run from PATH.
        candidate="${2:?name the executable}"
        case "$candidate" in /*) ;; *) candidate="$PWD/$candidate" ;; esac
        if is_pinned "$candidate"; then exit 0; fi
        echo "install-rcodesign: ${2} is not the pinned rcodesign $version (SHA-256 $executable_sha256)" >&2
        exit 1
        ;;
    self-test)
        self_test
        exit
        ;;
esac

directory="${1:-${KR_TOOLS_DIR:-$HOME/.cache/kalareach-tools}}"
executable="$directory/rcodesign-$version/rcodesign"

if is_pinned "$executable"; then
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
if ! is_pinned "$executable.new"; then
    rm -f "$executable.new"
    echo "install-rcodesign: the executable in $archive is not the pinned one (SHA-256 $executable_sha256)" >&2
    exit 1
fi
mv "$executable.new" "$executable"
printf '%s\n' "$executable"
