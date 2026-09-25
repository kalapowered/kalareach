#!/usr/bin/env bash
# Runs the conformance report: every identifier the tests name, what each test came to on this
# platform, the commands that reproduce them and the run's identities, in one result keyed by
# identifier.
#
#   scripts/run-conformance.sh                    every group this platform runs
#   scripts/run-conformance.sh --group <name>     one group; repeat it for several. The groups are
#                                                 rust, end-to-end, performance, typescript and
#                                                 applications
#   scripts/run-conformance.sh --all-terminals    every group, and then section 27's terminal
#                                                 matrix, which fails naming each terminal until
#                                                 its runs exist
#
# The evidence directory is KR_TEST_ARTIFACTS_DIR, or a new directory under the platform's
# temporary directory when that is not set. The report refuses one outside the temporary
# directory. The result is <evidence>/conformance/result.json, and each step's log is beside it.
# docs/conformance/README.md states the result's schema and how the report reads the tests.
#
# The applications group runs programs this script fetches once, each pinned by URL and SHA-256 in
# tests/conformance/applications.lock, into a cache outside the repository
# (KR_CONFORMANCE_APPLICATIONS, or the platform's cache directory). The cache is named by an
# absolute path without `..`, and is refused inside the repository; nothing in it is read, written
# or replaced through a link. A program whose project publishes source only is built there from that
# release's source. A release this host cannot fetch or build is recorded as not installed, with
# the reason, and never taken from the system's package manager.
#
# On Windows the report is started from a native shell rather than this script; the script says
# how. Exit status: 0 when the run passed, 1 when it ran and did not, 2 when it was refused before
# running anything.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

groups=()
all_terminals=0
while [ $# -gt 0 ]; do
    case "$1" in
        --group)
            [ $# -ge 2 ] || { echo "run-conformance: --group needs a name" >&2; exit 2; }
            groups+=("$2")
            shift
            ;;
        --all-terminals) all_terminals=1 ;;
        -h|--help)
            sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 2
            ;;
        *) echo "run-conformance: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$all_terminals" -eq 1 ] && [ ${#groups[@]} -gt 0 ]; then
    echo "run-conformance: --all-terminals runs every group, so it takes no --group" >&2
    exit 2
fi

selected() {
    local wanted="$1" group
    [ ${#groups[@]} -eq 0 ] && return 0
    for group in "${groups[@]}"; do
        [ "$group" = "$wanted" ] && return 0
    done
    return 1
}

case "$(uname -s)" in
    Darwin) os="apple-darwin"; family=macos ;;
    Linux) os="unknown-linux-gnu"; family=linux ;;
    MINGW*|MSYS*|CYGWIN*)
        # A POSIX runtime on Windows enables privileges in the token of everything it starts and
        # changes how the console's interrupt reaches it, so the suites would not run as they run
        # on their own. The report is started from a native shell there.
        echo "run-conformance: on Windows, start the report from PowerShell or cmd:" >&2
        echo "  pnpm install --frozen-lockfile" >&2
        echo "  cargo run --locked -p kr-conformance --bin kr-conformance -- run --root . --evidence <a directory under %TEMP%>" >&2
        exit 2
        ;;
    *) echo "run-conformance: $(uname -s) is not a platform the report runs on" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) arch="aarch64" ;;
    x86_64|amd64) arch="x86_64" ;;
    *) echo "run-conformance: $(uname -m) is not an architecture the report runs on" >&2; exit 2 ;;
esac
platform="$arch-$os"

evidence="${KR_TEST_ARTIFACTS_DIR:-}"
if [ -z "$evidence" ]; then
    evidence="$(mktemp -d "${TMPDIR:-/tmp}/kr-conformance.XXXXXX")"
fi
export KR_TEST_ARTIFACTS_DIR="$evidence"

echo "run-conformance: platform $platform, evidence $evidence"

if command -v sha256sum > /dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum > /dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    digest() { echo "no-digest-tool"; }
fi

# The application cache as a real path, or a refusal: an absolute path named without `..`, the
# part of it that exists resolved through its links, and outside the repository. Nothing is made
# until it has been judged.
application_cache() {
    local wanted="$1"
    case "$wanted" in
        /*) ;;
        *) echo "run-conformance: the application cache $wanted is not an absolute path" >&2; return 1 ;;
    esac
    case "/$wanted/" in
        */../*) echo "run-conformance: the application cache $wanted steps up with .." >&2; return 1 ;;
    esac
    local existing="$wanted" rest=""
    while [ ! -d "$existing" ]; do
        rest="/$(basename "$existing")$rest"
        existing="$(dirname "$existing")"
    done
    local resolved repository
    resolved="$(cd "$existing" && pwd -P)$rest"
    resolved="${resolved/#\/\///}"
    repository="$(cd "$root" && pwd -P)"
    case "$resolved/" in
        "$repository"/*)
            echo "run-conformance: the application cache $wanted is inside the repository" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$resolved"
}

# Fetches, and where the lock says so builds, every application the lock pins for this platform,
# into the cache, and writes the cache's index. What could not be fetched or built is written into
# the index as not installed, with the reason, and the matrix reports it as not run here.
fetch_applications() {
    local lock="$root/tests/conformance/applications.lock"
    local cache="$1"
    local archives="$cache/archives"
    # Nothing is written through a link: not the archives, not the index.
    local place
    for place in "$archives" "$cache/index.json"; do
        if [ -L "$place" ]; then
            echo "run-conformance: $place is a link, and the application cache writes through none" >&2
            exit 2
        fi
    done
    mkdir -p "$archives"
    for tool in curl tar python3 make; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            echo "run-conformance: $tool is needed to fetch the applications and is not on the path" >&2
            exit 2
        fi
    done
    local jobs
    jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

    # The lock, one application per line: the fields this script needs, tab separated, for the
    # source this platform takes. A field with nothing in it is `-`, because a shell reading
    # tab-separated fields treats a run of tabs as one separator.
    local lines
    lines="$(python3 - "$lock" "$platform" "$family" <<'PYTHON'
import json
import re
import sys

lock = json.load(open(sys.argv[1]))
platform, family = sys.argv[2], sys.argv[3]
for application in lock["applications"]:
    # Each names a directory of the cache, so each is one plain name.
    for name in (application["id"], application["version"]):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            sys.exit(f"the lock names {name!r}, which is not a plain directory name")
    chosen = None
    for source in application["sources"]:
        if source["platform"] == platform or (source["platform"] == "unix" and family != "windows"):
            chosen = source
            break
    build = (chosen or {}).get("build")
    configure = []
    environment = []
    libraries = []
    if build:
        configure = build.get("configure", []) + build.get("configure_" + family, [])
        environment = [f"{name}={value}" for name, value in sorted(build.get("environment", {}).items())]
        libraries = build.get("libraries", [])
    reason = application.get("not_run", {}).get(family) or f"no build of {application['name']} is pinned for {platform}"
    print("\t".join([
        application["id"],
        application["version"],
        application.get("role", "program"),
        chosen["url"] if chosen else "-",
        chosen["sha256"] if chosen else "-",
        str(chosen.get("strip_components", 0)) if chosen else "0",
        chosen.get("executable", "-") if chosen else "-",
        "source" if build else "release",
        " ".join(configure) or "-",
        " ".join(environment) or "-",
        ",".join(libraries) or "-",
        reason,
    ]))
PYTHON
)"

    local records=()
    # Each library installed so far, as its identifier and its prefix, one per line: a program
    # built after it names it in its build's variables.
    local prefixes=""
    local id version role url sha strip executable kind configure environment libraries reason
    while IFS=$'\t' read -r id version role url sha strip executable kind configure environment libraries reason; do
        [ -n "$id" ] || continue
        [ "$executable" = "-" ] && executable=""
        [ "$configure" = "-" ] && configure=""
        [ "$environment" = "-" ] && environment=""
        [ "$libraries" = "-" ] && libraries=""
        local target="$cache/$id/$version"
        local stamp="$target.stamp"
        local wanted="$sha $kind $configure $environment"
        # What is installed, and what a new installation replaces, is only ever a directory of the
        # cache's own: a link there could take either somewhere else.
        if [ -L "$cache/$id" ] || [ -L "$target" ] || [ -L "$stamp" ]; then
            echo "  $id $version: its place in the cache is a link, so nothing is used or replaced there"
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "its place in the application cache is a link")")
            continue
        fi
        if [ "$url" = "-" ]; then
            echo "  $id $version: $reason"
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unsupported_platform - - "$kind" - "$reason")")
            continue
        fi
        if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$wanted" ] && { [ -z "$executable" ] || [ -x "$target/$executable" ]; }; then
            echo "  $id $version: installed"
            [ "$role" = library ] && prefixes+="$id"$'\t'"$target"$'\n'
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" installed "$url" "$sha" "$kind" "${executable:+$target/$executable}" -)")
            continue
        fi
        local extension="${url##*/}"
        extension="${extension#*.tar}"
        local kept="$archives/$sha.tar$extension"
        if [ -L "$kept" ] || [ -L "$kept.part" ]; then
            echo "    its archive in the cache is a link, so nothing is read or written there"
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "its archive in the application cache is a link")")
            continue
        fi
        if [ ! -f "$kept" ] || [ "$(digest "$kept")" != "$sha" ]; then
            echo "  $id $version: fetching $url"
            # Several attempts with a pause between them: a release host that answers a burst
            # with an error is a passing condition, and recording the release as unavailable over
            # one would say something untrue about it.
            if ! curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors --max-time 600 -o "$kept.part" "$url"; then
                echo "    could not be fetched"
                records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "the release could not be fetched")")
                continue
            fi
            local got
            got="$(digest "$kept.part")"
            if [ "$got" != "$sha" ]; then
                echo "    digest $got does not match the pin $sha"
                rm -f "${kept:?}.part"
                records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "the release's digest did not match the pin")")
                continue
            fi
            mv "$kept.part" "$kept"
        fi
        local work
        work="$(mktemp -d "${TMPDIR:-/tmp}/kr-application.XXXXXX")"
        mkdir -p "$work/tree"
        if ! tar -xf "$kept" -C "$work/tree" --strip-components "$strip"; then
            echo "    could not be unpacked"
            rm -rf "${work:?}"
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "the release could not be unpacked")")
            continue
        fi
        rm -rf "${target:?}"
        mkdir -p "$(dirname "$target")"
        if [ "$kind" = "source" ]; then
            echo "  $id $version: building from the release's source"
            # Built with the system's own tools and libraries only: nothing a package manager put
            # on the path is reached for.
            local variables=()
            local pair library prefix
            for pair in $environment; do
                while IFS=$'\t' read -r library prefix; do
                    [ -n "$library" ] && pair="${pair//\{$library\}/$prefix}"
                done <<< "$prefixes"
                variables+=("$pair")
            done
            for library in ${libraries//,/ }; do
                if ! grep -q "^$library"$'\t' <<< "$prefixes"; then
                    echo "    needs $library, which is not installed"
                fi
            done
            # shellcheck disable=SC2086
            if ! (cd "$work/tree" \
                && env -i HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
                    ${variables[@]+"${variables[@]}"} ./configure --prefix="$target" $configure \
                && make -j"$jobs" && make install) > "$work/build.log" 2>&1; then
                echo "    did not build; the end of its log:"
                tail -n 20 "$work/build.log" | sed 's/^/      /'
                rm -rf "${work:?}" "${target:?}"
                records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "the release's source did not build on this host")")
                continue
            fi
        else
            mv "$work/tree" "$target"
        fi
        rm -rf "${work:?}"
        if [ -n "$executable" ] && [ ! -x "$target/$executable" ]; then
            echo "    holds no $executable"
            records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" unavailable "$url" "$sha" "$kind" - "the release holds no $executable")")
            continue
        fi
        printf '%s' "$wanted" > "$stamp"
        echo "    installed"
        [ "$role" = library ] && prefixes+="$id"$'\t'"$target"$'\n'
        records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$version" "$role" installed "$url" "$sha" "$kind" "${executable:+$target/$executable}" -)")
    done <<< "$lines"

    local collected
    collected="$(mktemp "${TMPDIR:-/tmp}/kr-applications.XXXXXX")"
    printf '%s\n' "${records[@]}" > "$collected"
    python3 - "$cache/index.json" "$platform" "$lock" "$collected" <<'PYTHON'
import hashlib
import json
import sys

index_path, platform, lock_path, collected = sys.argv[1:5]
with open(lock_path, "rb") as handle:
    lock_digest = hashlib.sha256(handle.read()).hexdigest()
applications = []
for line in open(collected, encoding="utf-8").read().splitlines():
    if not line.strip():
        continue
    id_, version, role, status, url, sha, kind, executable, reason = line.split("\t")
    if role != "program":
        continue
    applications.append({
        "id": id_,
        "version": version,
        "status": status,
        "url": None if url == "-" else url,
        "sha256": None if sha == "-" else sha,
        "build": kind,
        "executable": None if executable in ("-", "") else executable,
        "reason": None if reason == "-" else reason,
    })
with open(index_path, "w", encoding="utf-8") as handle:
    json.dump({"platform": platform, "lock_sha256": lock_digest, "applications": applications}, handle, indent=2)
    handle.write("\n")
installed = sum(1 for application in applications if application["status"] == "installed")
print(f"run-conformance: {installed} of {len(applications)} applications installed; index at {index_path}")
PYTHON
    rm -f "${collected:?}"
}

arguments=(run --root "$root" --evidence "$evidence")
if [ ${#groups[@]} -gt 0 ]; then
    for group in "${groups[@]}"; do
        arguments+=(--group "$group")
    done
fi
[ "$all_terminals" -eq 1 ] && arguments+=(--all-terminals)

if selected applications; then
    case "$family" in
        macos) default_cache="$HOME/Library/Caches/kalareach/conformance-applications" ;;
        *) default_cache="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/conformance-applications" ;;
    esac
    cache="$(application_cache "${KR_CONFORMANCE_APPLICATIONS:-$default_cache}")" || exit 2
    export KR_CONFORMANCE_APPLICATIONS="$cache"
    echo "run-conformance: applications in $KR_CONFORMANCE_APPLICATIONS"
    # Called on its own, so that any command of it that fails ends the script: a refusal inside it
    # exits 2 itself.
    fetch_applications "$KR_CONFORMANCE_APPLICATIONS"
    arguments+=(--applications "$KR_CONFORMANCE_APPLICATIONS")
fi

# The report reads the TypeScript tests with the packages' own compiler wherever that group is
# selected, on Windows as well, where it lists them without running them.
if selected typescript; then
    pnpm install --frozen-lockfile
fi

cargo build --locked -p kr-conformance --bin kr-conformance
binary="${CARGO_TARGET_DIR:-$root/target}/debug/kr-conformance"
exec "$binary" "${arguments[@]}"
