#!/usr/bin/env bash
# Copies the bundled plugin package out of a signed catalogue generation, by digest.
#
#   scripts/sync-bundled-plugins.sh                  copy the package and write the lock
#   scripts/sync-bundled-plugins.sh --verify         re-check the bundle already on disk
#
# KalaReach ships one package with the host, so a fresh installation has something to match,
# present and activate before any repository is reachable. `bundled-plugins/` holds those bytes and
# `bundled-plugins.lock` names them: the package, its version, the digest and exact length of every
# file, the trust root the chain was verified against, and the generation the bytes came from.
#
# The copy is made from a catalogue generation, never from the fixture packages under `fixtures/`.
# A generation is a trust root, the TUF metadata over it and every target that metadata pins, and
# it lives in the plugin repository beside the packages it was built from.
#
# The generation is taken out of the pinned commit into a private directory of this run's own
# making, and everything after that reads only from there. The chain is verified over that copy,
# against its root and with expiry enforced, before a payload is read; the payloads are then
# resolved by the digest the verified metadata pins. Nothing reads the plugin checkout's working
# tree after the export, so a file that changes there mid-run cannot become a bundled byte.
#
# What this never does: execute anything out of the package, follow a link into it, accept a path
# that leaves the package directory, accept two names that are one file on any platform, or accept
# a file that is not the exact length the metadata pinned. Lengths are checked from the metadata
# before the copy and recomputed from the bytes afterwards, so nothing expands into the bundle
# undeclared.
#
# `--verify` is the offline half. It reads the lock, recomputes every digest under the bundle
# directory and reports any drift. It reaches no network, runs no build and needs no plugin
# repository: this repository, `bash` and `python3` are the whole of what it wants.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The generation inside the plugin repository, the package taken from it, and where it lands. The
# package is pinned by identity rather than by position: the entry the index carries under this
# identifier is the one that is copied, whatever order the index is in.
generation_path="snapshots/development"
plugin_id="kalareach/example-declarative"
package_version="0.1.0"
bundle_name="fixture"

# The repository the generation is published from. The lock records it beside the commit, which is
# what makes "where did these bytes come from" answerable from the lock alone.
plugins_repository="https://github.com/kalapowered/kalareach-plugins"

# What one bundled package may cost, from the package contract: 64 MiB of payloads across at most
# 512 files, with a manifest of at most 1 MiB. The declared sizes are checked against these before
# the copy, so an oversized generation is refused before a byte of it is read.
max_package_bytes=$((64 * 1024 * 1024))
max_package_files=512
max_manifest_bytes=$((1024 * 1024))

verify_only=false
plugins="${KALAREACH_PLUGINS:-}"
pinned_commit=""
bundle_root="$root/bundled-plugins"
lock_file="$root/bundled-plugins.lock"

usage() {
    cat <<'USAGE'
usage: sync-bundled-plugins.sh [options]

  --verify              check the bundle on disk against the lock and fetch nothing
  --plugins DIR         the plugin repository checkout to copy from (default: the
                        kalareach-plugins checkout beside this one, or $KALAREACH_PLUGINS)
  --commit SHA          the commit that checkout must be at (default: the lock's)
  --bundle-root DIR     the bundle directory (default: bundled-plugins)
  --lock FILE           the lock file (default: bundled-plugins.lock)
  -h, --help            print this
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --verify) verify_only=true ;;
        --plugins) plugins="${2:?--plugins needs a directory}"; shift ;;
        --commit) pinned_commit="${2:?--commit needs a commit}"; shift ;;
        --bundle-root) bundle_root="${2:?--bundle-root needs a directory}"; shift ;;
        --lock) lock_file="${2:?--lock needs a file}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "sync-bundled-plugins: unknown argument $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

fail() {
    echo "sync-bundled-plugins: $*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 ||
    fail "python3 is needed to read the signed metadata and to digest the payloads"

# Reads the lock and a bundle directory, recomputes every digest and length, and reports drift.
#
# Every open is relative to a directory handle, with links refused at each step, so a name that
# becomes a link between the check and the read is refused by the read: there is no check to race.
# Each file is measured through its own open handle before its bytes are read, and read one byte
# past what the lock declared, so neither a substituted device nor a file that grew can be read
# without bound.
#
# The third argument says what to make of an entry in the bundle directory that is not one of the
# lock's packages. `strict` reports it, which is what a bundle at rest should never have; `lenient`
# passes over it, which is what a run still holding its own private working directories needs.
#
# Nothing here opens a socket or looks at the plugin repository: the lock and the bytes beside it
# are the whole input, which is what makes this the check a build with no network can run.
check_bundle() {
    python3 - "$1" "$2" "$3" <<'PY'
import hashlib
import json
import os
import stat
import sys

lock_path, bundle_root, strictness = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(lock_path, "rb") as handle:
        lock = json.load(handle)
except OSError as error:
    sys.exit(f"sync-bundled-plugins: the lock {lock_path} cannot be read: {error}")
except ValueError as error:
    sys.exit(f"sync-bundled-plugins: the lock {lock_path} is not readable JSON: {error}")

if lock.get("lock_version") != 1:
    sys.exit(f"sync-bundled-plugins: the lock is version {lock.get('lock_version')!r}, not 1")

# The package contract's alphabet: a relative POSIX path of ASCII letters, digits, '.', '-' and
# '_'. Restricting the alphabet is the only version of this rule that stays true across platforms,
# because Windows resolves device names through their extension and macOS folds case and
# normalises, so two names outside it can render alike and open the same file.
ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_")
WINDOWS_DEVICES = {
    "con", "prn", "aux", "nul",
    *(f"com{digit}" for digit in "0123456789"),
    *(f"lpt{digit}" for digit in "0123456789"),
}


def rejection(path):
    """Says why a path may not name a file inside a package, or nothing when it may."""
    if not path:
        return "is empty"
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        return "is absolute"
    if "\\" in path:
        return "contains a backslash"
    for segment in path.split("/"):
        if segment == "":
            return "has an empty segment"
        if set(segment) == {"."}:
            return "traverses"
        if segment.endswith("."):
            return "has a segment that ends with a dot"
        if any(character not in ALPHABET for character in segment):
            return "is outside the package path alphabet"
        if segment.split(".", 1)[0].casefold() in WINDOWS_DEVICES:
            return "names a device Windows resolves"
    return None


def open_directory(name, parent_fd=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    return os.open(name, flags, dir_fd=parent_fd)


def open_file(name, parent_fd):
    # No link is followed, and the open does not wait: a name replaced by a named pipe would
    # otherwise hold this read open until somebody wrote to it, and no declared length bounds that.
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def scan(parent_fd, prefix, files, directories, problems):
    """Records every name under an opened directory, refusing anything that is not a file."""
    with os.scandir(parent_fd) as entries:
        listed = list(entries)
    for entry in listed:
        relative = f"{prefix}{entry.name}"
        if entry.is_symlink():
            problems.append(f"{relative} is a link")
        elif entry.is_dir(follow_symlinks=False):
            directories.add(relative)
            child = open_directory(entry.name, parent_fd)
            try:
                scan(child, f"{relative}/", files, directories, problems)
            finally:
                os.close(child)
        elif entry.is_file(follow_symlinks=False):
            files.add(relative)
        else:
            problems.append(f"{relative} is not a regular file")


problems = []
checked = 0

try:
    bundle_fd = open_directory(bundle_root)
except OSError as error:
    sys.exit(f"sync-bundled-plugins: {bundle_root} is not a readable directory: {error}")

expected_packages = {package["directory"].split("/")[0] for package in lock["packages"]}

try:
    # A package the lock does not name is drift too: a host reads what is in this directory, not
    # what the lock says should be.
    if strictness == "strict":
        with os.scandir(bundle_fd) as entries:
            for entry in list(entries):
                if entry.name not in expected_packages:
                    problems.append(f"{entry.name} is in the bundle and not in the lock")

    for package in lock["packages"]:
        name = package["directory"]
        label = rejection(name)
        if label is not None:
            problems.append(f"the lock's directory {name!r} {label}")
            continue

        declared = {}
        for entry in [package["manifest"], *package["payloads"]]:
            label = rejection(entry["path"])
            if label is not None:
                problems.append(f"{name}/{entry['path']} {label}")
                continue
            if entry["path"] in declared:
                problems.append(f"the lock names {name}/{entry['path']} twice")
                continue
            declared[entry["path"]] = entry

        # Two names that fold to one file, and a name that is another name's directory. Every
        # prefix is compared, not only the whole path, because `Assets/a` and `assets/b` are two
        # directories on Linux and one on a default macOS volume.
        folded = {}
        for path in declared:
            segments = path.split("/")
            for depth in range(1, len(segments) + 1):
                prefix = "/".join(segments[:depth])
                key = "/".join(segment.casefold() for segment in segments[:depth])
                kind = "file" if depth == len(segments) else "directory"
                if key in folded and folded[key] != (prefix, kind):
                    problems.append(
                        f"{name}/{prefix} and {name}/{folded[key][0]} are one name"
                    )
                folded.setdefault(key, (prefix, kind))

        # Segment by segment, so a link anywhere on the way to the package is refused rather than
        # only one at its last name.
        descent = []
        try:
            parent_fd = bundle_fd
            for segment in name.split("/"):
                descent.append(open_directory(segment, parent_fd))
                parent_fd = descent[-1]
            package_fd = descent[-1]
        except OSError as error:
            for descriptor in descent:
                os.close(descriptor)
            problems.append(f"{name} is not a readable package directory: {error}")
            continue

        try:
            # Everything that is there, so a file or a directory the lock does not account for is a
            # finding rather than something nobody looked at.
            present, present_directories = set(), set()
            try:
                scan(package_fd, "", present, present_directories, problems)
            except OSError as error:
                problems.append(f"{name} cannot be read through: {error}")

            expected_directories = {
                "/".join(path.split("/")[:depth])
                for path in declared
                for depth in range(1, len(path.split("/")))
            }
            for extra in sorted(present - set(declared)):
                problems.append(f"{name}/{extra} is in the bundle and not in the lock")
            for extra in sorted(present_directories - expected_directories):
                problems.append(f"{name}/{extra} is a directory the lock does not account for")

            total = 0
            for path, entry in sorted(declared.items()):
                segments = path.split("/")
                opened = [package_fd]
                try:
                    try:
                        for segment in segments[:-1]:
                            opened.append(open_directory(segment, opened[-1]))
                        file_fd = open_file(segments[-1], opened[-1])
                    except OSError as error:
                        problems.append(f"{name}/{path} is not a readable payload: {error}")
                        continue
                    with os.fdopen(file_fd, "rb", closefd=True) as source:
                        information = os.fstat(source.fileno())
                        if not stat.S_ISREG(information.st_mode):
                            problems.append(f"{name}/{path} is not a regular file")
                            continue
                        declared_size = int(entry["size_bytes"])
                        if information.st_size != declared_size:
                            total += information.st_size
                            problems.append(
                                f"{name}/{path} is {information.st_size} bytes"
                                f" and the lock declares {declared_size}"
                            )
                            continue
                        content = source.read(declared_size + 1)
                    total += len(content)
                    if len(content) != declared_size:
                        problems.append(
                            f"{name}/{path} read as {len(content)} bytes"
                            f" and the lock declares {declared_size}"
                        )
                        continue
                    if hashlib.sha256(content).hexdigest() != entry["digest"]:
                        problems.append(f"{name}/{path} is not the payload the lock names")
                        continue
                    checked += 1
                finally:
                    for descriptor in opened[1:]:
                        os.close(descriptor)

            if total != int(package["total_size_bytes"]):
                problems.append(
                    f"{name} holds {total} bytes"
                    f" and the lock declares {package['total_size_bytes']}"
                )
        finally:
            for descriptor in descent:
                os.close(descriptor)
finally:
    os.close(bundle_fd)

if problems:
    for problem in problems:
        print(f"sync-bundled-plugins: {problem}", file=sys.stderr)
    sys.exit(f"sync-bundled-plugins: {len(problems)} finding(s) against {lock_path}")

print(
    f"sync-bundled-plugins: {len(lock['packages'])} package(s), {checked} file(s) match"
    f" {os.path.basename(lock_path)} (generation {lock['source']['generation']})"
)
PY
}

# Renames one path onto another, refusing to move it inside a directory that is already there.
# `mv` would put the source inside an existing destination directory; a rename replaces the
# destination or fails, which is the behaviour publishing a package needs.
rename_path() {
    python3 -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' "$1" "$2"
}

if [ "$verify_only" = true ]; then
    [ -f "$lock_file" ] || fail "$lock_file is not there, so there is nothing to verify against"
    [ -d "$bundle_root" ] || fail "$bundle_root is not there, so there is nothing to verify"
    check_bundle "$lock_file" "$bundle_root" strict
    exit 0
fi

# From here on the bundle is being made, which means reading a generation.

if [ -z "$plugins" ]; then
    # The checkout beside this one, found from the repository rather than from this script's own
    # path, so a working tree attached to this repository resolves where the main checkout does.
    if common="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
        plugins="$(dirname "$(dirname "$common")")/kalareach-plugins"
    else
        plugins="$(dirname "$root")/kalareach-plugins"
    fi
fi

if [ -z "$pinned_commit" ]; then
    [ -f "$lock_file" ] || fail "there is no lock to take the pinned commit from; pass --commit"
    pinned_commit="$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["source"]["commit"])' "$lock_file")"
fi

[ -d "$plugins/.git" ] || [ -f "$plugins/.git" ] ||
    fail "$plugins is not a plugin repository checkout; pass --plugins"
plugins="$(cd "$plugins" && pwd)"

# The commit is the pin, and it pins two things: the generation whose bytes are bundled, and the
# source of the tool that verifies them. Both are taken out of the commit below, so what the
# checkout's working tree happens to hold is never read; the checkout has to be at the pin all the
# same, because a run is about the commit the person named.
head="$(git -C "$plugins" rev-parse HEAD)"
[ "$head" = "$pinned_commit" ] || fail "$plugins is at $head and the pin is $pinned_commit"
git -C "$plugins" cat-file -e "$pinned_commit:$generation_path" 2>/dev/null ||
    fail "$pinned_commit carries no $generation_path"

# One sync at a time. The directory is the lock: creating it is one operation the filesystem either
# does or refuses, so two runs cannot both believe they own the publish. The owner file says which
# run holds it, and a release removes it only when it is still that run's.
publish_lock="$bundle_root/.sync.lock"
held_lock=false
stage_root="$bundle_root/.staging.$$"
staged_bundle="$stage_root/bundle"
staging="$staged_bundle/$bundle_name"
export_root="$stage_root/checkout"
generation="$export_root/$generation_path"
plan="$stage_root/plan.tsv"
staged_lock="$stage_root/lock.json"
pending_lock="$(dirname "$lock_file")/.$(basename "$lock_file").$$.pending"
retiring="$bundle_root/.retiring.$$"
published="$bundle_root/$bundle_name"

owner_of_publish_lock() {
    awk '{print $1; exit}' "$publish_lock/owner" 2>/dev/null || true
}

# What to do about a run that did not finish, decided from what is on disk rather than from how far
# a variable got: a flag is set after the rename it describes, and an interruption lands between the
# two. The staged package is the witness. It is still there when nothing was published, and it is
# gone when the rename that published it ran.
cleanup() {
    local status=$?
    set +e
    local published_here=false
    if [ ! -d "$staging" ] && [ -e "$published" ]; then
        published_here=true
    fi
    rm -rf "${stage_root:?}"
    if [ "$published_here" = true ]; then
        if [ -f "$pending_lock" ]; then
            # The package is published and the lock that describes it is not. Neither is thrown
            # away: a person decides, with both in front of them.
            echo "sync-bundled-plugins: $published is the new package and $lock_file is not the" \
                "new lock; the new lock is at $pending_lock and the previous package at" \
                "$retiring" >&2
        elif [ -d "$retiring" ]; then
            rm -rf "${retiring:?}"
        fi
    else
        rm -f "${pending_lock:?}"
        if [ -d "$retiring" ]; then
            rename_path "$retiring" "$published" ||
                echo "sync-bundled-plugins: the previous package is at $retiring" >&2
        fi
    fi
    if [ "$held_lock" = true ] && [ "$(owner_of_publish_lock)" = "$$" ]; then
        held_lock=false
        rm -rf "${publish_lock:?}"
    fi
    return "$status"
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

mkdir -p "$bundle_root"
mkdir "$publish_lock" 2>/dev/null ||
    fail "$publish_lock is there, so another sync holds this bundle; remove it if none does"
held_lock=true
echo "$$ $(date '+%F %T')" >"$publish_lock/owner"

mkdir "$stage_root"
chmod 700 "$stage_root"
mkdir "$staged_bundle" "$staging" "$export_root"

# The repository, taken out of the commit rather than read from the working tree: both the
# generation and the source of the tool that verifies it. Everything after this reads only from
# here, so the bytes that are verified are the bytes that are copied even if somebody checks out
# another branch beside this run. The export is inside this run's own private directory, which
# nothing publishes and the exit takes with it.
git -C "$plugins" archive --format=tar "$pinned_commit" | tar -x -f - -C "$export_root"
[ -d "$generation" ] || fail "the export of $pinned_commit carries no $generation_path"

# Nothing in the export may be a link or anything else that is not a file or a directory. A commit
# can carry a link, and a link under the metadata would be read by the verifier and again by the
# steps below, with the file it names free to change between the two. Refusing them here is what
# makes "the export is what was verified" true of the whole generation rather than of the payloads
# alone.
python3 - "$export_root" "$generation_path" <<'PY'
import os
import sys

export_root, generation_path = sys.argv[1], sys.argv[2]
problems = []


def open_directory(name, parent_fd=None):
    return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)


def scan(parent_fd, prefix):
    with os.scandir(parent_fd) as entries:
        listed = list(entries)
    for entry in listed:
        relative = f"{prefix}{entry.name}"
        if entry.is_symlink():
            problems.append(f"{relative} is a link")
        elif entry.is_dir(follow_symlinks=False):
            child = open_directory(entry.name, parent_fd)
            try:
                scan(child, f"{relative}/")
            finally:
                os.close(child)
        elif not entry.is_file(follow_symlinks=False):
            problems.append(f"{relative} is not a regular file")


descent = [open_directory(export_root)]
try:
    for segment in generation_path.split("/"):
        descent.append(open_directory(segment, descent[-1]))
    scan(descent[-1], f"{generation_path}/")
finally:
    for descriptor in descent:
        os.close(descriptor)

if problems:
    for problem in problems:
        print(f"sync-bundled-plugins: {problem}", file=sys.stderr)
    sys.exit(f"sync-bundled-plugins: {len(problems)} finding(s) in the exported generation")
PY

# The chain first: root, timestamp, snapshot, targets and every target's digest and length, through
# the client the plugin repository publishes with, built from the same commit. Expiry is enforced,
# because metadata that has expired blocks a new generation however well it is signed. Nothing has
# been taken out of the generation at this point, and nothing is until this returns.
#
# The build output goes beside this repository. The plugin checkout is something this script reads
# through Git and never writes.
echo "sync-bundled-plugins: verifying $generation_path at $pinned_commit"
(
    cd "$root"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/catalogue-tool" \
        cargo run --quiet --locked --manifest-path "$export_root/pipeline/Cargo.toml" -- \
        --repository "$export_root" verify "$generation"
)

# What the verified metadata says this package consists of, checked against what the index says
# before anything is copied. The two have to agree: the metadata proves the bytes and the index is
# what a host reads to decide, so a package whose index entry names a payload the metadata does not
# pin is a package this script will not bundle.
python3 - \
    "$generation" "$plugin_id" "$package_version" "$plan" \
    "$max_package_bytes" "$max_package_files" "$max_manifest_bytes" <<'PY'
import json
import os
import sys

generation, plugin_id, version, plan_path = sys.argv[1:5]
max_package_bytes, max_package_files, max_manifest_bytes = (int(value) for value in sys.argv[5:8])


def load(path):
    with open(path, "rb") as handle:
        return json.load(handle)


targets = load(os.path.join(generation, "metadata", "targets.json"))["signed"]["targets"]
index = load(os.path.join(generation, "targets", "index.json"))

entry = next(
    (
        candidate
        for candidate in index["entries"]
        if candidate["plugin_id"] == plugin_id and candidate["version"] == version
    ),
    None,
)
if entry is None:
    sys.exit(f"sync-bundled-plugins: the index carries no {plugin_id} {version}")
if entry["revocation"] is not None:
    sys.exit(f"sync-bundled-plugins: {plugin_id} {version} is revoked and takes no new bindings")

prefix = f"packages/{entry['publisher_id']}/{entry['plugin_name']}/{entry['version']}"

# Every file, the manifest included. A manifest does not declare itself, so its digest and length
# come from the index entry that points at it.
files = [("manifest", "plugin.json", entry["manifest_digest"], int(entry["manifest_size_bytes"]))]
for payload in entry["payloads"]:
    files.append((payload["role"], payload["path"], payload["digest"], int(payload["size_bytes"])))

problems = []

if len(files) > max_package_files:
    problems.append(f"the package declares {len(files)} files, over the {max_package_files} limit")
if int(entry["manifest_size_bytes"]) > max_manifest_bytes:
    problems.append(
        f"the manifest declares {entry['manifest_size_bytes']} bytes,"
        f" over the {max_manifest_bytes} byte limit"
    )

declared_total = sum(size for _, _, _, size in files)
if declared_total > max_package_bytes:
    problems.append(
        f"the package declares {declared_total} bytes, over the {max_package_bytes} byte limit"
    )
if declared_total != int(entry["total_size_bytes"]):
    problems.append(
        f"the declared files add to {declared_total} bytes"
        f" and the entry says {entry['total_size_bytes']}"
    )

# The metadata is what proves a byte. A file the index declares and the metadata does not pin is a
# file nothing signed, and a digest or length the two disagree about is a package that cannot be
# resolved by digest at all.
for _, path, digest, size in files:
    name = f"{prefix}/{path}"
    pinned = targets.get(name)
    if pinned is None:
        problems.append(f"the targets metadata does not pin {name}")
        continue
    if pinned["hashes"]["sha256"] != digest:
        problems.append(
            f"{name} is pinned as {pinned['hashes']['sha256']} and declared as {digest}"
        )
    if int(pinned["length"]) != size:
        problems.append(f"{name} is pinned at {pinned['length']} bytes and declared at {size}")

if problems:
    for problem in problems:
        print(f"sync-bundled-plugins: {problem}", file=sys.stderr)
    sys.exit(f"sync-bundled-plugins: {len(problems)} finding(s) against {plugin_id} {version}")

with open(plan_path, "w", encoding="utf-8") as handle:
    for role, path, digest, size in files:
        handle.write(f"{role}\t{path}\t{digest}\t{size}\n")

print(
    f"sync-bundled-plugins: {plugin_id} {version} declares {len(files)} file(s),"
    f" {declared_total} bytes, all pinned by the verified metadata"
)
PY

# The copy. Every open is relative to a directory handle rather than made from a string: the
# exported generation is opened once, each segment down to the package and each segment of a
# payload's path is opened beneath it with links refused and without waiting, and the payload is
# read through the handle that comes out. The bytes are digested before they are written, so a
# source that is not the payload the metadata pinned never reaches the staging directory.
python3 - "$export_root" "$generation_path" "$plugin_id" "$package_version" "$plan" "$staging" <<'PY'
import hashlib
import os
import stat
import sys

export_root, generation_path, plugin_id, version, plan_path, staging = sys.argv[1:7]
publisher, name = plugin_id.split("/", 1)
descent = [
    *generation_path.split("/"),
    "targets",
    "packages",
    publisher,
    name,
    version,
]

files = []
with open(plan_path, encoding="utf-8") as handle:
    for line in handle:
        role, path, digest, size = line.rstrip("\n").split("\t")
        files.append((role, path, digest, int(size)))


def open_directory(segment, parent_fd=None):
    return os.open(segment, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)


def open_file(segment, parent_fd):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    return os.open(segment, flags, dir_fd=parent_fd)


descended = [open_directory(export_root)]
try:
    for segment in descent:
        descended.append(open_directory(segment, descended[-1]))
    package_fd = descended[-1]

    for role, path, digest, size in files:
        segments = path.split("/")
        opened = []
        try:
            try:
                parent_fd = package_fd
                for segment in segments[:-1]:
                    opened.append(open_directory(segment, parent_fd))
                    parent_fd = opened[-1]
                file_fd = open_file(segments[-1], parent_fd)
            except OSError as error:
                sys.exit(f"sync-bundled-plugins: {path} is not a readable payload: {error}")
            with os.fdopen(file_fd, "rb", closefd=True) as source:
                information = os.fstat(source.fileno())
                if not stat.S_ISREG(information.st_mode):
                    sys.exit(f"sync-bundled-plugins: {path} is not a regular file")
                if information.st_size != size:
                    sys.exit(
                        f"sync-bundled-plugins: {path} is {information.st_size} bytes"
                        f" and the metadata pins {size}"
                    )
                # One byte past what was pinned, so a file that grew between the measurement and
                # the read is refused rather than silently truncated to its declared length.
                content = source.read(size + 1)
        finally:
            for descriptor in opened:
                os.close(descriptor)
        if len(content) != size:
            sys.exit(
                f"sync-bundled-plugins: {path} read as {len(content)} bytes"
                f" and the metadata pins {size}"
            )
        if hashlib.sha256(content).hexdigest() != digest:
            sys.exit(f"sync-bundled-plugins: {path} is not the payload {digest[:12]}")
        destination = os.path.join(staging, *segments)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "xb") as sink:
            sink.write(content)
        print(f"sync-bundled-plugins:   {role} {path} ({size} bytes)")
finally:
    for descriptor in descended:
        os.close(descriptor)
PY

# The lock, written from the plan and the exported generation's own root. It is written beside the
# staged copy, so the copy can be checked against the document that will describe it before either
# of them is published.
python3 - \
    "$generation" "$plugin_id" "$package_version" "$plan" "$bundle_name" \
    "$plugins_repository" "$pinned_commit" "$generation_path" "$staged_lock" <<'PY'
import hashlib
import json
import os
import sys

(
    generation,
    plugin_id,
    version,
    plan_path,
    bundle_name,
    repository,
    commit,
    generation_path,
    lock_path,
) = sys.argv[1:10]

with open(os.path.join(generation, "targets", "index.json"), "rb") as handle:
    index = json.load(handle)
entry = next(
    candidate
    for candidate in index["entries"]
    if candidate["plugin_id"] == plugin_id and candidate["version"] == version
)

with open(os.path.join(generation, "root.json"), "rb") as handle:
    root_bytes = handle.read()
root = json.loads(root_bytes)["signed"]

files = []
with open(plan_path, encoding="utf-8") as handle:
    for line in handle:
        role, path, digest, size = line.rstrip("\n").split("\t")
        files.append((role, path, digest, int(size)))

manifest = next(file for file in files if file[0] == "manifest")
payloads = sorted((file for file in files if file[0] != "manifest"), key=lambda file: file[1])

lock = {
    "lock_version": 1,
    "source": {
        "repository": repository,
        "commit": commit,
        "generation_path": generation_path,
        "tree_url": f"{repository}/tree/{commit}/{generation_path}",
        "generation": index["generation"],
        "produced_at": index["produced_at"],
    },
    "trust_root": {
        "digest": hashlib.sha256(root_bytes).hexdigest(),
        "version": root["version"],
        "expires": root["expires"],
        "key_ids": sorted(root["roles"]["root"]["keyids"]),
    },
    "packages": [
        {
            "directory": bundle_name,
            "plugin_id": entry["plugin_id"],
            "publisher_id": entry["publisher_id"],
            "plugin_name": entry["plugin_name"],
            "version": entry["version"],
            "sdk_range": entry["sdk_range"],
            "wit_range": entry["wit_range"],
            "manifest": {
                "path": manifest[1],
                "digest": manifest[2],
                "size_bytes": str(manifest[3]),
            },
            "payloads": [
                {"role": role, "path": path, "digest": digest, "size_bytes": str(size)}
                for role, path, digest, size in payloads
            ],
            "total_size_bytes": str(sum(size for _, _, _, size in files)),
        }
    ],
}

with open(lock_path, "w", encoding="utf-8") as handle:
    json.dump(lock, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

# What was written, measured rather than assumed: every digest and length recomputed from the
# staged bytes, every path checked against the package contract, and anything the lock does not
# account for reported. This is the check that catches an expansion nothing declared.
check_bundle "$staged_lock" "$staged_bundle" strict

# A signature proves who produced a package, not that the package is safe to keep. The validator is
# the safety half, and it runs over the staged copy before it is published: the schema, the paths,
# the declared lengths and digests, the capability requests and the things a manifest may not say.
# It executes nothing out of the package.
echo "sync-bundled-plugins: validating the staged package"
(
    cd "$root"
    cargo run --quiet --locked -p kr-plugin-sdk --bin kr-plugin-sandbox -- "$staging"
)

# The new lock goes beside the one it replaces before the package moves, so the last step of the
# publish is a rename within a directory this run has already written to.
rename_path "$staged_lock" "$pending_lock"

# The publish. An entry already there is replaced only when it is the entry the lock on disk
# describes; anything else is somebody's work or a partial copy, and this stops rather than
# overwriting it. The published name then changes by rename alone, so what is under it is a whole
# package or the package that was there before.
if [ -e "$published" ]; then
    [ -f "$lock_file" ] ||
        fail "$published is there and no lock describes it; move it aside to replace it"
    check_bundle "$lock_file" "$bundle_root" lenient >/dev/null 2>&1 ||
        fail "$published is not what $lock_file describes; move it aside to replace it"
    rename_path "$published" "$retiring"
fi
rename_path "$staging" "$published"
rename_path "$pending_lock" "$lock_file"
if [ -d "$retiring" ]; then
    rm -rf "${retiring:?}"
fi

# Lenient, because this run's own private directories are still beside the package it published
# and go with its exit. `--verify` is the strict reading, and continuous integration runs it.
check_bundle "$lock_file" "$bundle_root" lenient
echo "sync-bundled-plugins: $published is $plugin_id $package_version from $generation_path at $pinned_commit"
