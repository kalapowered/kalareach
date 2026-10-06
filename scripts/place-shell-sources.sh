#!/usr/bin/env bash
# Places the pinned upstream archives the managed shell packages are built from, where
# scripts/build-shells.sh looks for them.
#
#   scripts/place-shell-sources.sh --all             place every shell's archive
#   scripts/place-shell-sources.sh --zsh --bash      place two
#   scripts/place-shell-sources.sh --all --key       print the digest a cache of the archives is named by
#
# build-shells.sh fetches an archive only when <prefix>/sources does not hold it, and checks every
# archive against the digest its manifest pins before it uses it. This script fills that directory
# first. An archive that is already there stays. Any other is fetched from the URL its manifest
# names and, when that server does not answer, from each mirror listed below. It never judges the
# bytes it places: build-shells.sh does, so a mirror that serves anything but the pinned release
# stops the build at its digest check.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(uname -s)" = "Darwin" ]; then
    default_prefix="$HOME/Library/Caches/kalareach/shells"
else
    default_prefix="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shells"
fi
prefix="${KR_SHELL_PREFIX:-$default_prefix}"

selected=""
print_key=0

usage() {
    cat >&2 <<'USAGE'
usage: place-shell-sources.sh [--zsh] [--bash] [--fish] [--all] [options]

  --zsh, --bash, --fish, --all   whose upstream archive to place
  --key                  print the digest of the pinned archives and place nothing
  --prefix DIR           the packages' installation, whose sources directory is filled
                         (default: where build-shells.sh installs)
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --zsh|--bash|--fish) selected="$selected ${1#--}" ;;
        --all) selected="zsh bash fish" ;;
        --key) print_key=1 ;;
        --prefix) shift; prefix="${1:?--prefix needs a directory}" ;;
        -h|--help) usage ;;
        *) echo "place-shell-sources: unknown argument $1" >&2; usage ;;
    esac
    shift
done

if [ -z "$selected" ]; then
    echo "place-shell-sources: name at least one shell" >&2
    usage
fi

for tool in curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "place-shell-sources: $tool is needed and is not installed" >&2
        exit 1
    fi
done

digest_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    else
        shasum -a 256 | cut -d' ' -f1
    fi
}

# A manifest's pinned archive as one tab-separated line: its file name, its URL and its SHA-256.
pinned_archive() {
    python3 - "$1" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    upstream = json.load(handle)["upstream"]
print("%s\t%s\t%s" % (upstream["archive"], upstream["url"], upstream["sha256"]))
PYTHON
}

# The mirrors of one archive, one URL a line, in the order to try them. Each serves the release
# bytes its manifest pins; a mirror that does not is caught by the digest check in build-shells.sh.
mirrors_of() {
    local url="$1" archive="$2" path host
    case "$url" in
        https://ftp.gnu.org/gnu/*)
            path="${url#https://ftp.gnu.org/gnu/}"
            for host in mirrors.kernel.org mirrors.ocf.berkeley.edu mirrors.dotsrc.org; do
                echo "https://$host/gnu/$path"
            done
            ;;
        https://downloads.sourceforge.net/project/zsh/*)
            echo "https://www.zsh.org/pub/$archive"
            echo "https://www.zsh.org/pub/old/$archive"
            ;;
    esac
}

pins=""
for shell_name in zsh bash fish; do
    case " $selected " in
        *" $shell_name "*) ;;
        *) continue ;;
    esac
    line="$(pinned_archive "$root/shells/$shell_name/manifest.json")"
    IFS=$'\t' read -r archive url sha256 <<<"$line"
    pins="$pins$archive $sha256
"
    if [ "$print_key" -eq 1 ]; then
        continue
    fi

    sources="$prefix/sources"
    destination="$sources/$archive"
    if [ -f "$destination" ]; then
        echo "place-shell-sources: $archive is already in $sources"
        continue
    fi
    mkdir -p "$sources"

    placed=0
    for source in "$url" $(mirrors_of "$url" "$archive"); do
        echo "place-shell-sources: fetching $archive from $source"
        if curl --fail --location --silent --show-error \
            --connect-timeout 20 --max-time 900 --retry 1 --retry-delay 5 \
            --output "$destination.part" "$source"; then
            mv "$destination.part" "$destination"
            placed=1
            break
        fi
        rm -f -- "${destination:?}.part"
        echo "place-shell-sources: $source did not serve $archive" >&2
    done
    if [ "$placed" -eq 0 ]; then
        echo "place-shell-sources: no server listed for $archive answered" >&2
        exit 1
    fi
done

if [ "$print_key" -eq 1 ]; then
    printf '%s' "$pins" | digest_stdin
fi
