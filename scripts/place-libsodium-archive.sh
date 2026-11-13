#!/usr/bin/env bash
# Places the archives `libsodium-sys-stable`'s build script reads when `SODIUM_DIST_DIR` names a
# directory, so that the build downloads nothing and links only bytes this script names.
#
#   scripts/place-libsodium-archive.sh DIR     make DIR hold the archives and their signatures
#   scripts/place-libsodium-archive.sh --key   print the name a cache of DIR is keyed by, which is
#                                              also the name of the directory the action places
#
# On Windows the crate links libsodium's own prebuilt MSVC libraries. The build script starts from
# the source archive the crate ships, which it cannot configure there, and falls back to a prebuilt
# archive. Windows links the archive of libsodium's release tag, as every other target compiles
# that tag: upstream's `libsodium-1.0.22-msvc.zip`, signed on 2026-04-09 at 22:11:03 UTC by the key
# that has the id 1fe8b442180f62e7 (the signature's trusted comment holds the time). Upstream's
# `-stable-` archive of the same version is replaced in place from time to time, so it is not used.
#
# The build script reads a fixed base name, `libsodium-1.0.22-stable-msvc`, so the tag's archive
# and its signature lie under that name in DIR. The build then checks the signature against
# libsodium's public key, and the signature it checks is upstream's own for the tag's bytes: the
# check covers the bytes, not the name.
#
# This script holds the size and the SHA-256 of both files and refuses any other bytes, for a
# test job and for a release job alike: a file that is in DIR (a restored cache holds one) and a
# file it has just fetched are each compared before the build can read them, and a file that does
# not match is refused and never placed. The source archive comes from the crate's own files,
# which `Cargo.lock` pins by checksum, and is never taken from DIR. The crate is pinned exactly in
# the workspace manifest, and a change of that pin can name other archives: this script stops on it.
#
# The digests move only together with the crate's pin, to the archive of the release tag that the
# new crate version bundles, so that every target keeps one tag. They never move alone, and a
# refusal in a job is not cured by a new digest in the change that met the refusal: the refusal
# means that upstream's file or the directory's content is not what a review fixed.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

crate=libsodium-sys-stable
crate_version=1.24.0
# The archive and its signature as upstream publishes them, and the name the build script reads.
archive=libsodium-1.0.22-msvc.zip
archive_bytes=17690194
archive_sha256=3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279
signature=libsodium-1.0.22-msvc.zip.minisig
signature_bytes=320
signature_sha256=3210cf4d985f7b192bb8d5eb2ec7f481e0f47420f144cf1069921f714bfad1d1
placed=libsodium-1.0.22-stable-msvc
# Where the files are fetched from. Only the place can change: what comes from it is held to the
# size and the digest above whatever the place.
base_url="${LIBSODIUM_ARCHIVE_BASE_URL:-https://download.libsodium.org/libsodium/releases}"

usage() {
    echo "usage: place-libsodium-archive.sh DIR | --key" >&2
    exit 2
}

[ $# -eq 1 ] || usage

locked="$({ grep -A1 -x "name = \"$crate\"" "$root/Cargo.lock" || true; } | sed -n 's/^version = "\(.*\)"$/\1/p')"
if [ "$locked" != "$crate_version" ]; then
    echo "place-libsodium-archive: Cargo.lock locks $crate ${locked:-nothing}, and this script knows the archive of $crate_version." >&2
    echo "place-libsodium-archive: Read the archive name in the new version's build.rs, take the release tag's archive that it bundles, and change crate_version and the archive's name, sizes and digests together." >&2
    exit 1
fi

if [ "$1" = "--key" ]; then
    echo "libsodium-archive-$crate_version-${archive_sha256:0:12}-${signature_sha256:0:12}"
    exit 0
fi

dir="$1"

sha256_of() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum -- "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 -- "$1" | cut -d ' ' -f 1
    fi
}

bytes_of() {
    wc -c < "$1" | tr -d ' '
}

# check FILE UPSTREAM-NAME EXPECTED-BYTES EXPECTED-SHA256 WHERE: succeeds when FILE has the size and
# the digest; otherwise says what was expected and what is there, and fails. A file of another
# length is refused on its length alone, and its digest is not read.
check() {
    local file="$1" name="$2" want_bytes="$3" want_sha="$4" where="$5" got_bytes got_sha
    got_bytes="$(bytes_of "$file")"
    if [ "$got_bytes" = "$want_bytes" ]; then
        got_sha="$(sha256_of "$file")"
        if [ "$got_sha" = "$want_sha" ]; then
            return 0
        fi
        got_sha="sha256 $got_sha"
    else
        got_sha="a digest that was not read"
    fi
    echo "place-libsodium-archive: refused $name from $where: Windows links only the file with $want_bytes bytes and sha256 $want_sha, and this one has $got_bytes bytes and $got_sha. Nothing was placed. A file that upstream has changed is a decision for a reviewed change of this script together with the crate's pin, and a directory that holds other bytes is not used." >&2
    return 1
}

# The two files, each as `upstream's name|the name the build reads|bytes|sha256`.
files=(
    "$archive|$placed.zip|$archive_bytes|$archive_sha256"
    "$signature|$placed.zip.minisig|$signature_bytes|$signature_sha256"
)

mkdir -p "$dir"

# What is already in DIR (a restored cache) is compared before anything is fetched or placed.
for entry in "${files[@]}"; do
    IFS='|' read -r name target want_bytes want_sha <<< "$entry"
    if [ -e "$dir/$target" ]; then
        check "$dir/$target" "$name" "$want_bytes" "$want_sha" "$dir" || exit 1
    fi
done

# A missing file is fetched, compared where it was written, and only then put in its place.
for entry in "${files[@]}"; do
    IFS='|' read -r name target want_bytes want_sha <<< "$entry"
    if [ -e "$dir/$target" ]; then
        echo "place-libsodium-archive: $name is already in $dir and matches"
        continue
    fi
    echo "place-libsodium-archive: fetching $name"
    part="$dir/$target.part"
    rm -f -- "${part:?}"
    curl --fail --location --silent --show-error \
        --connect-timeout 20 --max-time 600 \
        --retry 6 --retry-delay 10 --retry-max-time 300 --retry-all-errors \
        --output "$part" "$base_url/$name"
    if ! check "$part" "$name" "$want_bytes" "$want_sha" "$base_url/$name"; then
        rm -f -- "${part:?}"
        exit 1
    fi
    mv -- "$part" "$dir/$target"
done

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

if ! source_dir="$(crate_dir)"; then
    echo "place-libsodium-archive: fetching the crates"
    (cd "$root" && cargo fetch --locked)
    source_dir="$(crate_dir)"
fi
echo "place-libsodium-archive: taking the source archive from $source_dir"
cp -- "$source_dir/LATEST.tar.gz" "$source_dir/LATEST.tar.gz.minisig" "$dir/"

# What the build will read, for the log: upstream's name for each file, what the build calls it,
# and the time in the signature's trusted comment.
echo "place-libsodium-archive: the build reads $placed.zip, which is upstream's $archive"
sed -n 's/^trusted comment: /place-libsodium-archive: signature of the tag archive: /p' "$dir/$placed.zip.minisig"
(
    cd "$dir"
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum LATEST.tar.gz "$placed.zip" "$placed.zip.minisig"
    else
        shasum -a 256 LATEST.tar.gz "$placed.zip" "$placed.zip.minisig"
    fi
)
