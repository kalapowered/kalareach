#!/usr/bin/env bash
# Builds the two native modules the editor-ABI cases load, against the headers of this repository's
# own Zsh package, and leaves them in one directory.
#
#   build-modules.sh --archive <zsh source archive> --output <directory>
#
# A module is built against the tree of the shell it will be loaded into, so this makes that tree
# the way the package's build does: the pinned release, the package's patches and bridge sources,
# and the package's own configure flags. It stops after the headers, which is where a module's
# build starts, and compiles kr_user.c twice, as a person would compile a module of their own:
#
#   kr_user_compatible.so   what the package provides is everything it imports
#   kr_user_newer.so        the same, and one call to a function this release's editor lacks
#   kr_user_lazy.so         imports from a package module that has not been loaded yet
#   kr_user_weak.so         imports a name it is content to lose
#
# The archive is the one `scripts/build-shells.sh` fetched and pinned; nothing is fetched here.
# Output that already exists is left as it is.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
package="$root/shells/zsh"
archive=""
output=""

while [ $# -gt 0 ]; do
    case "$1" in
        --archive) shift; archive="${1:?--archive needs a file}" ;;
        --output) shift; output="${1:?--output needs a directory}" ;;
        *) echo "build-modules: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$archive" ] && [ -n "$output" ] || { echo "usage: build-modules.sh --archive <file> --output <dir>" >&2; exit 2; }

variants="compatible newer lazy weak"
complete=1
for variant in $variants; do
    [ -f "$output/kr_user_$variant.so" ] || complete=0
done
if [ "$complete" -eq 1 ]; then
    echo "build-modules: $output already holds the modules"
    exit 0
fi

# The pinned facts, read from the package's manifest as the build reads them.
read_manifest() {
    python3 - "$package/manifest.json" "$1" <<'PYTHON'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
what = sys.argv[2]
if what == "directory":
    print(manifest["upstream"]["directory"])
elif what == "configure":
    print(" ".join(manifest["configure"]))
elif what == "cflags":
    print(" ".join(manifest["cflags"]))
elif what == "patches":
    print("\n".join(patch["file"] for patch in manifest["patches"]))
elif what == "sources":
    print("\n".join("%s:%s" % (source["file"], source["install"]) for source in manifest["sources"]))
elif what == "sha256":
    print(manifest["upstream"]["sha256"])
PYTHON
}

digest() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
if [ "$(digest "$archive")" != "$(read_manifest sha256)" ]; then
    echo "build-modules: $archive is not the archive the package pins" >&2
    exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/kr-module-abi.XXXXXX")"
trap 'rm -rf "${work:?}"' EXIT

tar -x -f "$archive" -C "$work"
tree="$work/$(read_manifest directory)"

while IFS= read -r file; do
    patch -p1 --forward --batch --fuzz=0 -d "$tree" < "$package/$file" > "$work/patch.log" \
        || { cat "$work/patch.log" >&2; echo "build-modules: $file does not apply" >&2; exit 1; }
done < <(read_manifest patches)

while IFS=: read -r from into; do
    mkdir -p "$tree/$(dirname "$into")"
    cp "$package/$from" "$tree/$into"
done < <(read_manifest sources)

# One moment for every file, as the package's build gives it, so nothing tries to regenerate what
# the release ships already generated.
: > "$work/.moment"
find "$tree" -exec touch -r "$work/.moment" {} +

cflags="$(read_manifest cflags)"
(
    cd "$tree"
    # shellcheck disable=SC2046
    CFLAGS="$cflags" ./configure --prefix="$work/unused" $(read_manifest configure) > "$work/configure.log" 2>&1
    make prep > "$work/prep.log" 2>&1
    make -C Src headers > "$work/headers.log" 2>&1
) || { tail -30 "$work"/*.log >&2; echo "build-modules: the headers did not build" >&2; exit 1; }

# How this platform builds a module, as the tree's own makefile says it.
make_variable() {
    sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$tree/Src/Makefile" | head -1
}
dlcflags="$(make_variable DLCFLAGS)"
dlldflags="$(make_variable DLLDFLAGS)"
dlld="$(make_variable DLLD)"
[ -n "$dlld" ] || dlld=cc

mkdir -p "$output"
for variant in $variants; do
    define=""
    case "$variant" in
        newer) define="-DKR_NEWER_IMPORT" ;;
        lazy) define="-DKR_LAZY_IMPORT" ;;
        weak) define="-DKR_WEAK_IMPORT" ;;
    esac
    # shellcheck disable=SC2086
    cc -DMODULE "-DKR_WIDGET=\"kr-user-$variant\"" $define $cflags $dlcflags -I"$tree/Src/Zle" -I"$tree/Src" -I"$tree" \
        -c "$here/kr_user.c" -o "$work/kr_user_$variant.o"
    # shellcheck disable=SC2086
    $dlld $dlldflags -o "$work/kr_user_$variant.so" "$work/kr_user_$variant.o"
    cp "$work/kr_user_$variant.so" "$output/kr_user_$variant.so.part"
    mv "$output/kr_user_$variant.so.part" "$output/kr_user_$variant.so"
done
echo "build-modules: built $variants in $output"
