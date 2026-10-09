#!/usr/bin/env bash
# Places the signed archives `libsodium-sys-stable`'s build script reads when `SODIUM_DIST_DIR`
# names a directory, so that the build downloads nothing.
#
#   scripts/place-libsodium-archive.sh DIR     make DIR hold the archives and their signatures
#   scripts/place-libsodium-archive.sh --key   print the name a cache of DIR is keyed by
#
# On Windows the crate links libsodium's own prebuilt MSVC binaries. The build script starts from
# the source archive the crate ships, which it cannot configure there, and falls back to the
# prebuilt archive, which it downloads from libsodium's download host while it compiles. A lookup
# of that name that fails then stops the build before any test runs. With the variable set the
# build script reads both archives and their signatures from the directory and downloads nothing.
# It still checks each against libsodium's public key, so what is placed is never trusted on its
# own.
#
# The source archive comes from the crate's own files, the prebuilt one from the download host. The
# file at the prebuilt archive's name is replaced upstream from time to time, so no digest of it
# can be pinned here: the build script's signature check is the pin. A file that is already in DIR
# stays; each missing one is fetched, and a request that does not answer is tried again for a
# while. The crate is pinned exactly in the workspace manifest. A change of that pin can name
# other archives, and this script stops on it, before the build panics on a file it cannot find.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

crate=libsodium-sys-stable
crate_version=1.24.0
archive=libsodium-1.0.22-stable-msvc
base_url=https://download.libsodium.org/libsodium/releases

usage() {
    echo "usage: place-libsodium-archive.sh DIR | --key" >&2
    exit 2
}

[ $# -eq 1 ] || usage

locked="$(grep -A1 -x "name = \"$crate\"" "$root/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')"
if [ "$locked" != "$crate_version" ]; then
    echo "place-libsodium-archive: Cargo.lock locks $crate ${locked:-nothing}, and this script knows the archive of $crate_version." >&2
    echo "place-libsodium-archive: Read the archive name in the new version's build.rs and change crate_version and archive." >&2
    exit 1
fi

if [ "$1" = "--key" ]; then
    echo "libsodium-archive-$crate_version"
    exit 0
fi

dir="$1"
mkdir -p "$dir"

# The crate's own files, which hold the source archive and its signature. Cargo unpacks the crate
# when it fetches it.
crate_dir() {
    local cargo_home candidate
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    if command -v cygpath > /dev/null 2>&1; then
        cargo_home="$(cygpath -u "$cargo_home")"
    fi
    for candidate in "$cargo_home"/registry/src/*/"$crate-$crate_version"; do
        if [ -d "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

if [ ! -s "$dir/LATEST.tar.gz" ] || [ ! -s "$dir/LATEST.tar.gz.minisig" ]; then
    if ! source_dir="$(crate_dir)"; then
        echo "place-libsodium-archive: fetching the crates"
        (cd "$root" && cargo fetch --locked)
        source_dir="$(crate_dir)"
    fi
    echo "place-libsodium-archive: taking the source archive from $source_dir"
    cp -- "$source_dir/LATEST.tar.gz" "$source_dir/LATEST.tar.gz.minisig" "$dir/"
fi

# An archive and its signature belong together, so a missing one is fetched with the other.
if [ ! -s "$dir/$archive.zip" ] || [ ! -s "$dir/$archive.zip.minisig" ]; then
    rm -f -- "${dir:?}/$archive.zip" "${dir:?}/$archive.zip.minisig"
    for file in "$archive.zip" "$archive.zip.minisig"; do
        echo "place-libsodium-archive: fetching $file"
        curl --fail --location --silent --show-error \
            --connect-timeout 20 --max-time 600 \
            --retry 6 --retry-delay 10 --retry-max-time 300 --retry-all-errors \
            --output "$dir/$file.part" "$base_url/$file"
        mv "$dir/$file.part" "$dir/$file"
    done
else
    echo "place-libsodium-archive: $archive is already in $dir"
fi

# What the build will read, for the log.
if command -v sha256sum > /dev/null 2>&1; then
    (cd "$dir" && sha256sum LATEST.tar.gz "$archive.zip" "$archive.zip.minisig")
else
    (cd "$dir" && shasum -a 256 LATEST.tar.gz "$archive.zip" "$archive.zip.minisig")
fi
