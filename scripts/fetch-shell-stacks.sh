#!/usr/bin/env bash
# Fetches the startup customisations the shell-integration qualification runs against.
#
#   scripts/fetch-shell-stacks.sh            fetch what this host needs and write the index
#   scripts/fetch-shell-stacks.sh --check    report what is installed without fetching anything
#   scripts/fetch-shell-stacks.sh --offline  write the index from what is already here
#
# Each stack in fixtures/shells/stacks.lock is pinned to one release by URL and SHA-256. This
# script is the only thing that reaches the network: the qualification reads the cache written
# here, so a suite's result never depends on what a source was serving while it ran.
#
# A source this host cannot reach, or one whose digest does not match the pin, is written into the
# index as unreachable with the reason. It is never substituted with another version and never
# taken from the machine's own package manager: a qualification has to say which build it
# qualified, and a stack it could not fetch is a stack it did not qualify.
#
# Installed trees live outside the repository, under the platform's cache directory, because a
# process started from a service manager that opens a path on a removable volume makes the
# operating system ask the person at the machine for permission first.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$root/fixtures/shells/stacks.lock"

check_only=0
offline=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) check_only=1 ;;
        --offline) offline=1 ;;
        -h|--help)
            sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 2
            ;;
        *) echo "fetch-shell-stacks: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

if [ ! -f "$lock" ]; then
    echo "fetch-shell-stacks: $lock is missing" >&2
    exit 1
fi

for tool in curl tar python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "fetch-shell-stacks: $tool is needed and is not on the path" >&2
        exit 1
    fi
done

if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    echo "fetch-shell-stacks: no sha256 tool on the path" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) os="apple-darwin"; default_cache="$HOME/Library/Caches/kalareach/shell-stacks" ;;
    Linux)  os="unknown-linux-gnu"; default_cache="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shell-stacks" ;;
    *) echo "fetch-shell-stacks: $(uname -s) is not one of the platforms these stacks are pinned for" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) arch="aarch64" ;;
    x86_64|amd64) arch="x86_64" ;;
    *) echo "fetch-shell-stacks: $(uname -m) is not one of the platforms these stacks are pinned for" >&2; exit 1 ;;
esac
platform="$arch-$os"

cache="${KR_SHELL_STACKS:-$default_cache}"
archives="$cache/archives"
mkdir -p "$cache" "$archives"

echo "fetch-shell-stacks: platform $platform, cache $cache"

# The lock, flattened to one line per stack: the fields this script needs, tab separated, with the
# source this platform takes. A field with nothing in it is written as `-`, because a shell reading
# tab-separated fields treats a run of tabs as one separator and would otherwise shift every field
# after an empty one. A stack with no source for this platform comes through with no url, which is
# recorded rather than treated as a failure.
lines="$(python3 - "$lock" "$platform" <<'PYTHON'
import json
import sys

lock = json.load(open(sys.argv[1]))
platform = sys.argv[2]
for stack in lock["stacks"]:
    chosen = None
    for source in stack["sources"]:
        if source["platform"] in ("any", platform):
            chosen = source
            break
    print(
        "\t".join(
            [
                stack["id"],
                stack["version"],
                stack["role"],
                stack.get("program") or "-",
                stack.get("entry") or "-",
                chosen["url"] if chosen else "-",
                chosen["sha256"] if chosen else "-",
                str(chosen.get("strip_components", 0)) if chosen else "0",
            ]
        )
    )
PYTHON
)"

records=()

record() {
    # id version status root executable url sha256 reason
    records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8")")
}

while IFS=$'\t' read -r id version role program entry url sha strip; do
    [ -n "$id" ] || continue
    [ "$program" = "-" ] && program=""
    [ "$entry" = "-" ] && entry=""
    [ "$url" = "-" ] && url=""
    [ "$sha" = "-" ] && sha=""
    target="$cache/$id/$version"
    stamp="$target.sha256"
    executable=""
    if [ "$role" = "program" ] && [ -n "$program" ]; then
        executable="$target/$program"
    fi

    if [ -z "$url" ]; then
        echo "  $id $version: no source pinned for $platform"
        record "$id" "$version" "unsupported_platform" "" "" "" "" "no source is pinned for $platform"
        continue
    fi

    if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$sha" ] && [ -d "$target" ] \
       && { [ -z "$entry" ] || [ -e "$target/$entry" ]; } \
       && { [ -z "$program" ] || [ -x "$target/$program" ]; }; then
        echo "  $id $version: installed"
        record "$id" "$version" "installed" "$target" "$executable" "$url" "$sha" ""
        continue
    fi

    if [ "$check_only" -eq 1 ]; then
        echo "  $id $version: not installed"
        record "$id" "$version" "unreachable" "" "" "$url" "$sha" "not installed and nothing was fetched"
        continue
    fi

    if [ "$offline" -eq 1 ] && { [ ! -f "$archives/$sha.tar.gz" ] || [ "$(digest "$archives/$sha.tar.gz")" != "$sha" ]; }; then
        echo "  $id $version: not installed and no archive kept for it"
        record "$id" "$version" "unreachable" "" "" "$url" "$sha" "no archive for the pinned digest is kept here and this run does not fetch"
        continue
    fi

    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-stack.XXXXXX")"
    archive="$work/archive.tar.gz"
    # Archives are kept by their pinned digest, so a rebuild, a second platform's run and a rerun
    # after a source went away all unpack the same bytes. Nothing is taken from here that does not
    # hash to the pin, so a cached file is the pinned release or it is not used.
    kept="$archives/$sha.tar.gz"
    if [ -f "$kept" ] && [ "$(digest "$kept")" = "$sha" ]; then
        echo "  $id $version: unpacking the archive already fetched"
        cp "$kept" "$archive"
    else
        echo "  $id $version: fetching"
        # Several attempts with a pause between them. A release host that answers 5xx to a burst
        # is a transient condition, and a qualification that recorded a stack as unreachable over
        # one of them would have said something untrue about the stack.
        if ! curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors --max-time 300 -o "$archive" "$url"; then
            echo "    could not be fetched"
            record "$id" "$version" "unreachable" "" "" "$url" "$sha" "the source could not be fetched"
            rm -rf "${work:?}"
            continue
        fi
        got="$(digest "$archive")"
        if [ "$got" != "$sha" ]; then
            echo "    digest $got does not match the pin $sha"
            record "$id" "$version" "unreachable" "" "" "$url" "$sha" "the digest was $got rather than the pinned $sha"
            rm -rf "${work:?}"
            continue
        fi
        cp "$archive" "$kept.part" && mv "$kept.part" "$kept"
    fi
    mkdir -p "$work/tree"
    if ! tar -xzf "$archive" -C "$work/tree" --strip-components "$strip"; then
        echo "    could not be unpacked"
        record "$id" "$version" "unreachable" "" "" "$url" "$sha" "the archive could not be unpacked"
        rm -rf "${work:?}"
        continue
    fi
    if [ -n "$executable" ] && [ ! -f "$work/tree/$program" ]; then
        echo "    the archive holds no $program"
        record "$id" "$version" "unreachable" "" "" "$url" "$sha" "the archive holds no $program"
        rm -rf "${work:?}"
        continue
    fi
    if [ -n "$entry" ] && [ ! -e "$work/tree/$entry" ]; then
        echo "    the archive holds no $entry"
        record "$id" "$version" "unreachable" "" "" "$url" "$sha" "the archive holds no $entry"
        rm -rf "${work:?}"
        continue
    fi
    [ -n "$executable" ] && chmod +x "$work/tree/$program"
    mkdir -p "$cache/$id"
    rm -rf "${target:?}"
    mv "$work/tree" "$target"
    printf '%s' "$sha" > "$stamp"
    rm -rf "${work:?}"
    echo "    installed at $target"
    record "$id" "$version" "installed" "$target" "$executable" "$url" "$sha" ""
done <<< "$lines"

index="$cache/index.json"
collected="$(mktemp "${TMPDIR:-/tmp}/kr-stacks.XXXXXX")"
printf '%s\n' "${records[@]}" > "$collected"
python3 - "$index" "$platform" "$lock" "$collected" <<'PYTHON'
import hashlib
import json
import sys

index_path, platform, lock_path, collected = sys.argv[1:5]
with open(lock_path, "rb") as handle:
    lock_digest = hashlib.sha256(handle.read()).hexdigest()

entries = []
for line in open(collected, encoding="utf-8").read().splitlines():
    if not line.strip():
        continue
    id_, version, status, root, executable, url, sha, reason = line.split("\t")
    entries.append(
        {
            "id": id_,
            "version": version,
            "status": status,
            "root": root or None,
            "executable": executable or None,
            "url": url or None,
            "sha256": sha or None,
            "reason": reason or None,
        }
    )

with open(index_path, "w", encoding="utf-8") as handle:
    json.dump(
        {"platform": platform, "lock_sha256": lock_digest, "stacks": entries},
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")

installed = sum(1 for entry in entries if entry["status"] == "installed")
print(f"fetch-shell-stacks: {installed} of {len(entries)} installed; index at {index_path}")
for entry in entries:
    if entry["status"] != "installed":
        print(f"  {entry['id']} {entry['version']}: {entry['status']} ({entry['reason']})")
PYTHON
rm -f "${collected:?}"
