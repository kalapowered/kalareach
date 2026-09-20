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
# it lives in the plugin repository beside the packages it was built from. The chain is verified
# first, through that repository's own catalogue tool and against that root, and only then is
# anything read: what is copied is the payload the verified metadata names, resolved by its digest.
#
# What this never does: execute anything out of the package, follow a link into it, accept a path
# that leaves the package directory, accept two names that are one file, or accept a file that is
# not the exact length the metadata pinned. Lengths are checked from the metadata before the copy
# and recomputed from the bytes afterwards, so nothing expands into the bundle undeclared.
#
# `--verify` is the offline half. It reads the lock, recomputes every digest under the bundle
# directory and reports any drift. It reaches no network and needs no plugin repository.

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

# Where the plugin repository is by default: the checkout beside this one. It is found from the
# repository rather than from this script's own path, so a working tree attached to this repository
# resolves to the same place the main checkout does.
default_plugins() {
    local common
    if common="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
        printf '%s/kalareach-plugins\n' "$(dirname "$(dirname "$common")")"
    else
        printf '%s/kalareach-plugins\n' "$(dirname "$root")"
    fi
}

verify_only=false
plugins="${KALAREACH_PLUGINS:-$(default_plugins)}"
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
# Nothing here opens a socket or looks at the plugin repository: the lock and the bytes beside it
# are the whole input, which is what makes this the check a build with no network can run.
check_bundle() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import json
import os
import sys

lock_path, bundle_root = sys.argv[1], sys.argv[2]

try:
    with open(lock_path, "rb") as handle:
        lock = json.load(handle)
except OSError as error:
    sys.exit(f"sync-bundled-plugins: the lock {lock_path} cannot be read: {error}")
except ValueError as error:
    sys.exit(f"sync-bundled-plugins: the lock {lock_path} is not readable JSON: {error}")

if lock.get("lock_version") != 1:
    sys.exit(f"sync-bundled-plugins: the lock is version {lock.get('lock_version')!r}, not 1")

problems = []
checked = 0

for package in lock["packages"]:
    directory = os.path.join(bundle_root, package["directory"])
    declared = {package["manifest"]["path"]: package["manifest"]}
    for payload in package["payloads"]:
        declared[payload["path"]] = payload

    # Everything that is there, so a file the lock does not name is a finding rather than a file
    # nobody looked at. A link is refused wherever it appears: as a payload, as a directory on the
    # way to one, and as anything else under the package.
    present = set()
    for parent, directories, files in os.walk(directory):
        for name in list(directories):
            if os.path.islink(os.path.join(parent, name)):
                relative = os.path.relpath(os.path.join(parent, name), directory)
                problems.append(f"{package['directory']}/{relative} is a link")
                directories.remove(name)
        for name in files:
            relative = os.path.relpath(os.path.join(parent, name), directory)
            present.add(relative.replace(os.sep, "/"))

    for extra in sorted(present - set(declared)):
        problems.append(f"{package['directory']}/{extra} is in the bundle and not in the lock")

    total = 0
    for path, entry in sorted(declared.items()):
        absolute = os.path.join(directory, *path.split("/"))
        if os.path.islink(absolute):
            problems.append(f"{package['directory']}/{path} is a link")
            continue
        if not os.path.isfile(absolute):
            problems.append(f"{package['directory']}/{path} is not in the bundle")
            continue
        with open(absolute, "rb") as handle:
            content = handle.read()
        total += len(content)
        if len(content) != int(entry["size_bytes"]):
            problems.append(
                f"{package['directory']}/{path} is {len(content)} bytes"
                f" and the lock declares {entry['size_bytes']}"
            )
            continue
        if hashlib.sha256(content).hexdigest() != entry["digest"]:
            problems.append(f"{package['directory']}/{path} is not the payload the lock names")
            continue
        checked += 1

    if total != int(package["total_size_bytes"]):
        problems.append(
            f"{package['directory']} holds {total} bytes"
            f" and the lock declares {package['total_size_bytes']}"
        )

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

if [ "$verify_only" = true ]; then
    [ -f "$lock_file" ] || fail "$lock_file is not there, so there is nothing to verify against"
    [ -d "$bundle_root" ] || fail "$bundle_root is not there, so there is nothing to verify"
    check_bundle "$lock_file" "$bundle_root"
    exit 0
fi

# From here on the bundle is being made, which means reading a generation.

if [ -z "$pinned_commit" ]; then
    [ -f "$lock_file" ] || fail "there is no lock to take the pinned commit from; pass --commit"
    pinned_commit="$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["source"]["commit"])' "$lock_file")"
fi

[ -d "$plugins/.git" ] || [ -f "$plugins/.git" ] ||
    fail "$plugins is not a plugin repository checkout; pass --plugins"
plugins="$(cd "$plugins" && pwd)"
generation="$plugins/$generation_path"
[ -d "$generation" ] || fail "$generation is not there; that checkout carries no $generation_path"

# The commit is the pin. A checkout at another commit holds other bytes, and a checkout with
# uncommitted changes under the generation holds bytes no commit ever had, so both are refused
# before the chain is verified rather than after the copy.
head="$(git -C "$plugins" rev-parse HEAD)"
[ "$head" = "$pinned_commit" ] || fail "$plugins is at $head and the pin is $pinned_commit"
[ -z "$(git -C "$plugins" status --porcelain -- "$generation_path")" ] ||
    fail "$generation has uncommitted changes, so it is not $pinned_commit"

# The chain first: root, timestamp, snapshot, targets and every target's digest and length, through
# the client the plugin repository publishes with. Expiry is enforced, because metadata that has
# expired blocks a new generation however well it is signed. Nothing has been taken out of the
# generation at this point, and nothing is until this returns.
#
# The build output goes beside this repository. The plugin checkout is something this script reads
# and never writes.
echo "sync-bundled-plugins: verifying $generation_path at $pinned_commit"
(
    cd "$root"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/catalogue-tool" \
        cargo run --quiet --locked --manifest-path "$plugins/pipeline/Cargo.toml" -- \
        --repository "$plugins" verify "$generation"
)

# A private directory beside the published entry, holding the package under its published name. The
# copy is made, digested and validated in here; the published name only ever changes by a rename.
stage_root="$bundle_root/.staging.$$"
staging="$stage_root/$bundle_name"
retiring="$bundle_root/.retiring.$$"
plan="$stage_root/plan.tsv"
staged_lock="$stage_root/lock.json"
published="$bundle_root/$bundle_name"

cleanup() {
    rm -rf "${stage_root:?}"
    if [ -d "$retiring" ]; then
        # The publish did not finish. What was there goes back where it was, rather than being left
        # under a dotted name for somebody to find later.
        if [ -e "$published" ]; then
            rm -rf "${retiring:?}"
        else
            mv "$retiring" "$published"
        fi
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$bundle_root"
rm -rf "${stage_root:?}"
mkdir "$stage_root"
chmod 700 "$stage_root"
mkdir "$staging"

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

# An unsafe path is refused here, where it is still a name in a document, rather than after a copy
# has followed it. The alphabet is the package contract's: a relative POSIX path of ASCII letters,
# digits, '.', '-' and '_', with no traversal, no empty segment and no trailing dot. Two names that
# fold to one file are refused with it, because a bundle where one payload can overwrite another is
# a bundle whose digests mean nothing.
alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_")
seen = {}
for _, path, _, _ in files:
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        problems.append(f"{path} is absolute")
        continue
    if "\\" in path:
        problems.append(f"{path} contains a backslash")
        continue
    segments = path.split("/")
    if any(segment == "" for segment in segments):
        problems.append(f"{path} has an empty segment")
        continue
    if any(set(segment) == {"."} for segment in segments):
        problems.append(f"{path} traverses")
        continue
    if any(segment.endswith(".") for segment in segments):
        problems.append(f"{path} has a segment ending in a dot")
        continue
    outside = [
        character for segment in segments for character in segment if character not in alphabet
    ]
    if outside:
        problems.append(f"{path} contains {outside[0]!r}, outside the package path alphabet")
        continue
    folded = path.casefold()
    if folded in seen:
        problems.append(f"{path} and {seen[folded]} are one file")
        continue
    seen[folded] = path

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
# package directory is opened once, each segment of a payload's path is opened beneath it with
# links refused, and the payload itself is opened in the directory that comes out. A name that
# became a link between the check and the open is refused by the open, because there is no check to
# race. The bytes are digested before they are written, so a source that is not the payload the
# metadata pinned never reaches the staging directory at all.
python3 - "$generation" "$plugin_id" "$package_version" "$plan" "$staging" <<'PY'
import hashlib
import os
import stat
import sys

generation, plugin_id, version, plan_path, staging = sys.argv[1:6]
publisher, name = plugin_id.split("/", 1)
package = os.path.join(generation, "targets", "packages", publisher, name, version)

files = []
with open(plan_path, encoding="utf-8") as handle:
    for line in handle:
        role, path, digest, size = line.rstrip("\n").split("\t")
        files.append((role, path, digest, int(size)))


def open_directory(parent_fd, segment):
    return os.open(segment, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)


root_fd = os.open(package, os.O_RDONLY | os.O_DIRECTORY)
try:
    for role, path, digest, size in files:
        segments = path.split("/")
        opened = [root_fd]
        try:
            for segment in segments[:-1]:
                opened.append(open_directory(opened[-1], segment))
            handle_fd = os.open(
                segments[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=opened[-1]
            )
        except OSError as error:
            sys.exit(f"sync-bundled-plugins: {path} is not a readable payload: {error}")
        try:
            with os.fdopen(handle_fd, "rb", closefd=True) as source:
                information = os.fstat(source.fileno())
                if not stat.S_ISREG(information.st_mode):
                    sys.exit(f"sync-bundled-plugins: {path} is not a regular file")
                if information.st_size != size:
                    sys.exit(
                        f"sync-bundled-plugins: {path} is {information.st_size} bytes"
                        f" and the metadata pins {size}"
                    )
                # One byte past what was pinned, so a file that grew between the check and the read
                # is refused rather than silently truncated to its declared length.
                content = source.read(size + 1)
        finally:
            for descriptor in opened[1:]:
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
    os.close(root_fd)
PY

# The lock, written from the plan and the generation's own root. It is written beside the staged
# copy, so the copy can be checked against the document that will describe it before either of them
# is published.
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
# staged bytes, and any file the lock does not name reported. This is the check that catches an
# expansion nothing declared.
check_bundle "$staged_lock" "$stage_root"

# A signature proves who produced a package, not that the package is safe to keep. The validator is
# the safety half, and it runs over the staged copy before it is published: the schema, the paths,
# the declared lengths and digests, the capability requests and the things a manifest may not say.
# It executes nothing out of the package.
echo "sync-bundled-plugins: validating the staged package"
(
    cd "$root"
    cargo run --quiet --locked -p kr-plugin-sdk --bin kr-plugin-sandbox -- "$staging"
)

# The publish. An entry already there is replaced only when it is the entry the lock on disk
# describes; anything else is somebody's work or a partial copy, and this stops rather than
# overwriting it. The published name changes by rename alone, so it is never half a package.
if [ -e "$published" ]; then
    [ -f "$lock_file" ] ||
        fail "$published is there and no lock describes it; move it aside to replace it"
    check_bundle "$lock_file" "$bundle_root" >/dev/null 2>&1 ||
        fail "$published is not what $lock_file describes; move it aside to replace it"
    mv "$published" "$retiring"
fi
mv "$staging" "$published"
rm -rf "${retiring:?}"

# The lock last, and in one rename, so a lock on disk always describes bytes that are already there.
mv "$staged_lock" "$lock_file"

check_bundle "$lock_file" "$bundle_root"
echo "sync-bundled-plugins: $published is $plugin_id $package_version from $generation_path at $pinned_commit"
