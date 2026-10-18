#!/usr/bin/env bash
# Places the pinned upstream sources the managed shell packages are built from, where
# scripts/build-shells.sh looks for them.
#
#   scripts/place-shell-sources.sh --all             place every shell's sources
#   scripts/place-shell-sources.sh --zsh --bash      place two
#   scripts/place-shell-sources.sh --all --key       print the digest a cache of the sources is named by
#
# A shell's sources are its upstream archive and, for a shell built from Rust, everything its build
# would otherwise fetch while it compiles: one `.crate` file for each crate its Cargo.lock takes
# from crates.io, and one git bundle for each repository the manifest's `cargo.git` pins. The
# crates are named by the archive's own lock and checked against the checksums it carries; a
# repository is named by the revision the lock holds and checked by build-shells.sh against the
# tree digest the manifest pins. A shell built this way fetches nothing once these are placed.
#
# A crate or a repository that is already in <prefix>/sources stays. Any other is fetched from
# the URL its manifest or lock names and, for an archive and a repository, when that server does
# not answer, from each mirror listed below. An archive or a crate that arrives is checked
# against its pin before it is kept; for an archive the next server is tried when the bytes
# differ, and a crate has one server. An archive that is already there with other bytes is
# replaced, in one step, by the pinned bytes, so a cache left by an older pin never blocks a run.
# A repository, and a crate that was already there, are judged by build-shells.sh before they are
# used.

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

absolute_prefix() {
    mkdir -p "$prefix"
    prefix="$(cd "$prefix" && pwd)"
}

usage() {
    cat >&2 <<'USAGE'
usage: place-shell-sources.sh [--zsh] [--bash] [--fish] [--all] [options]

  --zsh, --bash, --fish, --all   whose upstream sources to place
  --key                  print the digest of the pinned sources and place nothing
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

# The prefix is used from other directories below, so it is made absolute first.
if [ "$print_key" -eq 0 ]; then
    absolute_prefix
fi

needed="curl python3"
case " $selected " in
    *" fish "*) needed="$needed git tar" ;;
esac
for tool in $needed; do
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

digest_file() {
    digest_stdin < "$1"
}

# A manifest's pinned archive as one tab-separated line: its file name, its URL, its SHA-256 and the
# directory it unpacks to.
pinned_archive() {
    python3 - "$1" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    upstream = json.load(handle)["upstream"]
for key in ("archive", "directory"):
    if "/" in upstream[key] or upstream[key] in ("", ".", ".."):
        sys.exit("place-shell-sources: the manifest's %s %r is not a plain name" % (key, upstream[key]))
print("%s\t%s\t%s\t%s" % (upstream["archive"], upstream["url"], upstream["sha256"],
                          upstream["directory"]))
PYTHON
}

# A manifest's pinned repositories, one tab-separated line each: name, URL, locked revision and the
# tree digest. A shell with no `cargo` section prints nothing and a shell whose section lists none
# prints nothing either.
pinned_repositories() {
    python3 - "$1" <<'PYTHON'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    cargo = json.load(handle).get("cargo")
for entry in (cargo or {}).get("git", []):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", entry["name"]):
        sys.exit("place-shell-sources: the manifest's repository name %r is not a plain name" % entry["name"])
    print("%s\t%s\t%s\t%s" % (entry["name"], entry["url"], entry["revision"], entry["sha256"]))
PYTHON
}

# Whether a manifest names a `cargo` section: the shell is built from Rust sources the lock of its
# archive names.
has_cargo_section() {
    python3 - "$1" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    sys.exit(0 if "cargo" in json.load(handle) else 1)
PYTHON
}

# The crates.io packages of a Cargo.lock on standard input, one tab-separated line each: name,
# version and the checksum the lock holds. build-shells.sh reads the same file strictly and refuses
# anything this does not place.
registry_crates() {
    python3 -c '
import re
import sys

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
package = {}
def flush():
    if package.get("source") == REGISTRY:
        if not (re.fullmatch(r"[A-Za-z0-9_.-]+", package["name"])
                and re.fullmatch(r"[A-Za-z0-9_.+-]+", package["version"])):
            sys.exit("place-shell-sources: Cargo.lock names a crate that is not a plain name")
        print("%s\t%s\t%s" % (package["name"], package["version"], package["checksum"]))
    package.clear()
for line in sys.stdin:
    line = line.rstrip("\n")
    if line == "[[package]]":
        flush()
        continue
    found = re.fullmatch(r"(name|version|source|checksum) = \"([^\"]*)\"", line)
    if found:
        package[found.group(1)] = found.group(2)
flush()
'
}

# The mirrors of one archive, one URL a line, in the order to try them. Each serves the release
# bytes its manifest pins; a mirror that does not is skipped at the digest check.
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

# The copies of one pinned repository, one URL a line. The owner of fluent-ftl-tools publishes the
# same history on both forges; a revision either one serves is the same commit, and the tree digest
# build-shells.sh checks says so.
repository_mirrors_of() {
    case "$1" in
        https://codeberg.org/danielrainer/fluent-ftl-tools)
            echo "https://github.com/danielrainer/fluent-ftl-tools"
            ;;
    esac
}

# Places one archive: leaves a good one where it is, reports a bad one, or fetches the pinned bytes.
place_archive() {
    local archive="$1" url="$2" sha256="$3" sources="$4"
    local destination="$sources/$archive" actual source placed
    if [ -f "$destination" ]; then
        actual="$(digest_file "$destination")"
        if [ "$actual" = "$sha256" ]; then
            echo "place-shell-sources: $archive is already in $sources"
            return 0
        fi
        echo "place-shell-sources: $archive in $sources has digest $actual and the manifest pins $sha256; placing it again" >&2
    fi
    mkdir -p "$sources"

    placed=0
    for source in "$url" $(mirrors_of "$url" "$archive"); do
        echo "place-shell-sources: fetching $archive from $source"
        if curl --fail --location --silent --show-error \
            --connect-timeout 20 --max-time 900 --retry 1 --retry-delay 5 \
            --output "$destination.part" "$source"; then
            actual="$(digest_file "$destination.part")"
            if [ "$actual" = "$sha256" ]; then
                mv "$destination.part" "$destination"
                placed=1
                break
            fi
            echo "place-shell-sources: $source served $archive with digest $actual, not the pinned $sha256" >&2
        else
            echo "place-shell-sources: $source did not serve $archive" >&2
        fi
        rm -f -- "${destination:?}.part"
    done
    if [ "$placed" -eq 0 ]; then
        echo "place-shell-sources: no server listed for $archive answered with the pinned bytes" >&2
        exit 1
    fi
}

# Places the .crate file of every crates.io package in the Cargo.lock of a shell's archive.
place_crates() {
    local archive="$1" directory="$2" sources="$3"
    local scratch lock crates crate version checksum file url actual count=0 fetched=0
    # The file is unpacked as the build unpacks it: a release that lists the lock twice leaves the
    # later one, which a stream of the member would not show.
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/kr-place-lock.XXXXXX")"
    if ! tar -x -f "$sources/$archive" -C "$scratch" "$directory/Cargo.lock" \
        || [ ! -f "$scratch/$directory/Cargo.lock" ]; then
        rm -rf -- "${scratch:?}"
        echo "place-shell-sources: $archive holds no $directory/Cargo.lock" >&2
        exit 1
    fi
    lock="$(cat "$scratch/$directory/Cargo.lock")"
    rm -rf -- "${scratch:?}"
    # Read into a variable first, so that a parser that fails stops the run here.
    crates="$(registry_crates <<<"$lock")"
    while IFS=$'\t' read -r crate version checksum; do
        [ -n "$crate" ] || continue
        count=$((count + 1))
        file="$sources/$crate-$version.crate"
        if [ -f "$file" ]; then
            continue
        fi
        url="https://static.crates.io/crates/$crate/$version/download"
        if ! curl --fail --location --silent --show-error \
            --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 \
            --output "$file.part" "$url"; then
            rm -f -- "${file:?}.part"
            echo "place-shell-sources: $url did not serve $crate $version" >&2
            exit 1
        fi
        actual="$(digest_file "$file.part")"
        if [ "$actual" != "$checksum" ]; then
            rm -f -- "${file:?}.part"
            echo "place-shell-sources: $crate $version from $url has digest $actual and Cargo.lock pins $checksum" >&2
            exit 1
        fi
        mv "$file.part" "$file"
        fetched=$((fetched + 1))
    done <<<"$crates"
    echo "place-shell-sources: $count crates in the lock of $archive, $fetched fetched"
}

# Places one pinned repository as a git bundle holding its locked revision.
place_repository() {
    local name="$1" url="$2" revision="$3" sources="$4"
    local file="$sources/$name-${revision:0:12}.bundle"
    local scratch source attempt placed=0
    if [ -f "$file" ]; then
        echo "place-shell-sources: $name is already in $sources"
        return 0
    fi
    for source in "$url" $(repository_mirrors_of "$url"); do
        for attempt in 1 2 3; do
            echo "place-shell-sources: fetching $name $revision from $source (attempt $attempt)"
            scratch="$(mktemp -d "${TMPDIR:-/tmp}/kr-place-$name.XXXXXX")"
            if git init --quiet --bare "$scratch" \
                && git -C "$scratch" fetch --quiet --no-tags "$source" "+$revision:refs/heads/pinned" \
                && [ "$(git -C "$scratch" rev-parse refs/heads/pinned)" = "$revision" ] \
                && git -C "$scratch" bundle create --quiet "$file.part" refs/heads/pinned; then
                rm -rf -- "${scratch:?}"
                mv "$file.part" "$file"
                placed=1
                break 2
            fi
            rm -rf -- "${scratch:?}"
            rm -f -- "${file:?}.part"
            if [ "$attempt" -lt 3 ]; then
                sleep 5
            fi
        done
        echo "place-shell-sources: $source did not serve $name $revision" >&2
    done
    if [ "$placed" -eq 0 ]; then
        echo "place-shell-sources: no server listed for $name answered" >&2
        exit 1
    fi
}

pins=""
for shell_name in zsh bash fish; do
    case " $selected " in
        *" $shell_name "*) ;;
        *) continue ;;
    esac
    manifest="$root/shells/$shell_name/manifest.json"
    line="$(pinned_archive "$manifest")"
    IFS=$'\t' read -r archive url sha256 directory <<<"$line"
    pins="$pins$archive $sha256
"
    repositories="$(pinned_repositories "$manifest")"
    while IFS=$'\t' read -r name repository_url revision tree; do
        if [ -n "$name" ]; then
            pins="${pins}git $name $revision $tree
"
        fi
    done <<<"$repositories"
    if [ "$print_key" -eq 1 ]; then
        continue
    fi

    sources="$prefix/sources"
    place_archive "$archive" "$url" "$sha256" "$sources"
    if has_cargo_section "$manifest"; then
        place_crates "$archive" "$directory" "$sources"
        while IFS=$'\t' read -r name repository_url revision tree; do
            if [ -n "$name" ]; then
                place_repository "$name" "$repository_url" "$revision" "$sources"
            fi
        done <<<"$repositories"
    fi
done

if [ "$print_key" -eq 1 ]; then
    printf '%s' "$pins" | digest_stdin
fi
