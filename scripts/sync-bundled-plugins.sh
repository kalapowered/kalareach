#!/usr/bin/env bash
# Copies the signed catalogue generation that ships with the host out of the plugin repository,
# by digest, and writes what the host reads from it.
#
#   scripts/sync-bundled-plugins.sh                  copy the generation and write the lock
#   scripts/sync-bundled-plugins.sh --verify         re-check the bundle already on disk
#   scripts/sync-bundled-plugins.sh --generate       write the two Rust files from the bundle
#   scripts/sync-bundled-plugins.sh --verify --release
#                                                    also require a root a release trusts
#
# KalaReach ships a catalogue generation with the host, so a fresh installation has the adapters'
# packages to match, present and activate before any repository is reachable. `bundled-plugins/`
# holds those bytes and `bundled-plugins.lock` names them: every metadata file and every package,
# the digest and exact length of every file, the trust root the chain was verified against, and the
# generation and commit the copy came from. The host compiles the bundle in
# (`crates/kr-plugin-catalogue/src/bundled_files.rs`, generated here) and reads the trust a build
# commits from `seed_trust.rs`, generated here from the constants below.
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
# What this never does: execute anything out of a package, follow a link into it, accept a path
# that leaves the package directory, accept two names that are one file on any platform, or accept
# a file that is not the exact length the metadata pinned. Lengths are checked from the metadata
# before the copy and recomputed from the bytes afterwards, so nothing expands into the bundle
# undeclared.
#
# `--verify` is the offline half. It reads the lock, recomputes every digest under the bundle
# directory, reports any drift, checks the roots (every numbered root from 1 to the highest, the
# highest the same bytes as `root.json`, and no root this build would not trust), bounds the
# embedded index, runs the release scan's checks over every file, and regenerates the
# two Rust files and reports any difference. It reaches no network, runs no build and needs no
# plugin repository: this repository, `bash` and `python3` are the whole of what it wants.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The generation inside the plugin repository, and the packages taken from it. Each is pinned by
# identity and version rather than by position: the entry the index carries under the identifier is
# the one that is copied, whatever order the index is in.
generation_path="snapshots/development"
bundled_packages=(
    "kalareach/claude-code@0.4.0"
    "kalareach/codex@0.2.1"
    "kalareach/example-declarative@0.1.0"
    "kalareach/gemini-cli@0.4.0"
    "kalareach/kimi-cli@0.1.1"
    "kalareach/kimi-code-cli@0.2.1"
    "kalareach/opencode@0.2.1"
    "kalareach/opencode-attach@0.1.1"
    "kalareach/qoder-cli@0.4.0"
)

# The repository the generation is published from. The lock records it beside the commit, which is
# what makes "where did these bytes come from" answerable from the lock alone.
plugins_repository="https://github.com/kalapowered/kalareach-plugins"

# Where a host that seeds from this bundle reaches the official repository, and the trust a build
# commits. A release trusts a root only for the key identifiers in the production set, which stays
# empty until the production root exists; a development build trusts the development lineage's
# root keys as well. The development keys are derived from a published phrase and anybody can sign
# with them: they are named by their public keys here, and the identifier a host compares is
# computed from each, as the update client computes it.
official_metadata_url="https://plugins.reach.kala.to/metadata/"
official_targets_url="https://plugins.reach.kala.to/targets/"
production_root_keys=()
production_root_threshold=1
development_root_public_keys=(
    "feeee867a08f8e51a4cf954dd10bbd5c6e90a98d642375d9f0586625f614f211"
)

# What the embedded index may cost, from the default repository budgets: 64 MiB of metadata and
# 100,000 entries.
max_index_bytes=$((64 * 1024 * 1024))
max_index_entries=100000

# What one bundled package may cost, from the package contract: 64 MiB of payloads across at most
# 512 files, with a manifest of at most 1 MiB. The declared sizes are checked against these before
# the copy, so an oversized generation is refused before a byte of it is read.
max_package_bytes=$((64 * 1024 * 1024))
max_package_files=512
max_manifest_bytes=$((1024 * 1024))

verify_only=false
generate_only=false
release=false
plugins="${KALAREACH_PLUGINS:-}"
pinned_commit=""
bundle_root="$root/bundled-plugins"
lock_file="$root/bundled-plugins.lock"
trust_out="$root/crates/kr-plugin-catalogue/src/seed_trust.rs"
files_out="$root/crates/kr-plugin-catalogue/src/bundled_files.rs"

usage() {
    cat <<'USAGE'
usage: sync-bundled-plugins.sh [options]

  --verify              check the bundle on disk against the lock and fetch nothing
  --generate            write the generated Rust files from the bundle on disk and the constants
                        above, and fetch nothing
  --release             with --verify: also require a root a release trusts
  --plugins DIR         the plugin repository checkout to copy from (default: the
                        kalareach-plugins checkout beside this one, or $KALAREACH_PLUGINS)
  --commit SHA          the commit that checkout must be at (default: the lock's)
  --bundle-root DIR     the bundle directory (default: bundled-plugins)
  --lock FILE           the lock file (default: bundled-plugins.lock)
  --trust-out FILE      the generated trust constants (default: crates/kr-plugin-catalogue/src/seed_trust.rs)
  --files-out FILE      the generated table of bundled files (default: crates/kr-plugin-catalogue/src/bundled_files.rs)
  -h, --help            print this
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --verify) verify_only=true ;;
        --generate) generate_only=true ;;
        --release) release=true ;;
        --plugins) plugins="${2:?--plugins needs a directory}"; shift ;;
        --commit) pinned_commit="${2:?--commit needs a commit}"; shift ;;
        --bundle-root) bundle_root="${2:?--bundle-root needs a directory}"; shift ;;
        --lock) lock_file="${2:?--lock needs a file}"; shift ;;
        --trust-out) trust_out="${2:?--trust-out needs a file}"; shift ;;
        --files-out) files_out="${2:?--files-out needs a file}"; shift ;;
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
[ "$release" = false ] || [ "$verify_only" = true ] || fail "--release belongs to --verify"
[ "$generate_only" = false ] || [ "$verify_only" = false ] || fail "--generate and --verify are two runs"

work="$(mktemp -d "${TMPDIR:-/tmp}/sync-bundled-plugins.XXXXXX")"
trap 'rm -rf "${work:?}"' EXIT

# The reading and writing of a bundle, in one program so that the copy and the check share one
# rule for what a path may be, one way to open a file and one rendering of what the host compiles.
cat >"$work/bundle.py" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

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

LOCK_VERSION = 2
INDEX = "targets/index.json"
METADATA_FILES = ["root.json", "snapshot.json", "targets.json", "timestamp.json"]


def fail(message):
    sys.exit(f"sync-bundled-plugins: {message}")


def rejection(path):
    """Says why a path may not name a file inside a bundle, or nothing when it may."""
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
    return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)


def open_file(name, parent_fd):
    # No link is followed, and the open does not wait: a name replaced by a named pipe would
    # otherwise hold this read open until somebody wrote to it, and no declared length bounds that.
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def read_bounded(root_fd, relative, size):
    """Reads one file through directory handles, with links refused, and returns its bytes.

    Returns (bytes, problem). A file that is not the declared length is measured through its own
    handle and refused before it is read; the read stops one byte past what was declared, so a file
    that grew in between is refused rather than truncated.
    """
    segments = relative.split("/")
    opened = []
    try:
        try:
            parent = root_fd
            for segment in segments[:-1]:
                opened.append(open_directory(segment, parent))
                parent = opened[-1]
            file_fd = open_file(segments[-1], parent)
        except OSError as error:
            return None, f"{relative} is not a readable file: {error}"
        with os.fdopen(file_fd, "rb", closefd=True) as source:
            information = os.fstat(source.fileno())
            if not stat.S_ISREG(information.st_mode):
                return None, f"{relative} is not a regular file"
            if information.st_size != size:
                return None, (
                    f"{relative} is {information.st_size} bytes and {size} are declared"
                )
            content = source.read(size + 1)
        if len(content) != size:
            return None, f"{relative} read as {len(content)} bytes and {size} are declared"
        return content, None
    finally:
        for descriptor in opened:
            os.close(descriptor)


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


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def key_id(public_hex):
    """The identifier the update client gives an Ed25519 key: the digest of its canonical JSON."""
    key = {"keytype": "ed25519", "keyval": {"public": public_hex}, "scheme": "ed25519"}
    return sha256(json.dumps(key, sort_keys=True, separators=(",", ":")).encode())


def render_trust(release_keys, threshold, development_keys, metadata_url, targets_url):
    def listing(keys):
        if not keys:
            return "&[]"
        body = "".join(f'    "{key}",\n' for key in keys)
        return f"&[\n{body}]"

    return (
        "//! The trust a build commits, and where the official repository is.\n"
        "//!\n"
        "//! Generated by `scripts/sync-bundled-plugins.sh`; change the constants there and run it.\n"
        "\n"
        "/// Where a host that seeds from the bundle fetches the official repository's metadata.\n"
        f'pub const OFFICIAL_METADATA_URL: &str = "{metadata_url}";\n'
        "\n"
        "/// Where it fetches the official repository's targets.\n"
        f'pub const OFFICIAL_TARGETS_URL: &str = "{targets_url}";\n'
        "\n"
        "/// The root key identifiers a release trusts without the owner. Empty until the production\n"
        "/// root exists, so a release build refuses every seed bundle.\n"
        f"pub const PRODUCTION_ROOT_KEYS: &[&str] = {listing(release_keys)};\n"
        "\n"
        "/// The signatures of those keys a production root has to carry.\n"
        f"pub const PRODUCTION_ROOT_THRESHOLD: u64 = {threshold};\n"
        "\n"
        "/// The root key identifiers of the development lineage, trusted by a build with debug\n"
        "/// assertions. The keys are derived from a published phrase and anybody can sign with them.\n"
        f"pub const DEVELOPMENT_ROOT_KEYS: &[&str] = {listing(development_keys)};\n"
    )


def render_files(paths):
    """The table of bundled files, named from the repository root by the names the host knows them
    by, so a bundle checked where it was copied to renders the same."""
    lock_relative, bundle_relative = "bundled-plugins.lock", "bundled-plugins"
    lines = [
        "//! The bundled generation, compiled in.\n",
        "//!\n",
        "//! Generated by `scripts/sync-bundled-plugins.sh`; run it to change what is bundled.\n",
        "\n",
        "/// The lock that names every file below.\n",
        "pub const LOCK: &[u8] = include_bytes!(concat!(\n",
        "    env!(\"CARGO_MANIFEST_DIR\"),\n",
        f"    \"/../../{lock_relative}\"\n",
        "));\n",
        "\n",
        "/// Every file of the bundle, by its path relative to the bundle directory.\n",
        "pub const FILES: &[(&str, &[u8])] = &[\n",
    ]
    for path in sorted(paths):
        lines.append(
            f'    (\n        "{path}",\n        include_bytes!(concat!(\n'
            f'            env!("CARGO_MANIFEST_DIR"),\n'
            f'            "/../../{bundle_relative}/{path}"\n        )),\n    ),\n'
        )
    lines.append("];\n")
    return "".join(lines)


def read_lock(path):
    try:
        with open(path, "rb") as handle:
            lock = json.load(handle)
    except OSError as error:
        fail(f"the lock {path} cannot be read: {error}")
    except ValueError as error:
        fail(f"the lock {path} is not readable JSON: {error}")
    if lock.get("lock_version") != LOCK_VERSION:
        fail(f"the lock is version {lock.get('lock_version')!r}, not {LOCK_VERSION}")
    return lock


def declared_files(lock):
    """Every file the lock accounts for, by path relative to the bundle, with its entry."""
    declared = {}
    problems = []
    for entry in lock["metadata"]:
        label = rejection(entry["path"])
        if label is not None:
            problems.append(f"the lock's metadata path {entry['path']!r} {label}")
            continue
        if entry["path"] in declared:
            problems.append(f"the lock names {entry['path']} twice")
            continue
        declared[entry["path"]] = entry
    for package in lock["packages"]:
        directory = package["directory"]
        label = rejection(directory)
        if label is not None:
            problems.append(f"the lock's directory {directory!r} {label}")
            continue
        expected = (
            f"targets/packages/{package['publisher_id']}/{package['plugin_name']}"
            f"/{package['version']}"
        )
        if directory != expected:
            problems.append(f"the lock's directory {directory!r} is not {expected!r}")
            continue
        for entry in [package["manifest"], *package["payloads"]]:
            label = rejection(entry["path"])
            if label is not None:
                problems.append(f"{directory}/{entry['path']} {label}")
                continue
            path = f"{directory}/{entry['path']}"
            if path in declared:
                problems.append(f"the lock names {path} twice")
                continue
            declared[path] = entry
    return declared, problems


def folded_collisions(paths):
    """Two names that fold to one file, and a name that is another name's directory. Every prefix
    is compared, not only the whole path, because `Assets/a` and `assets/b` are two directories on
    Linux and one on a default macOS volume."""
    problems = []
    folded = {}
    for path in sorted(paths):
        segments = path.split("/")
        for depth in range(1, len(segments) + 1):
            prefix = "/".join(segments[:depth])
            key = "/".join(segment.casefold() for segment in segments[:depth])
            kind = "file" if depth == len(segments) else "directory"
            if key in folded and folded[key] != (prefix, kind):
                problems.append(f"{prefix} and {folded[key][0]} are one name")
            folded.setdefault(key, (prefix, kind))
    return problems


def numbered_roots(declared):
    roots = {}
    for path in declared:
        match = re.fullmatch(r"metadata/([1-9][0-9]*)\.root\.json", path)
        if match:
            roots[int(match.group(1))] = path
    return roots
PY

# Reads the lock and a bundle directory, recomputes every digest and length, and reports drift.
#
# Every open is relative to a directory handle, with links refused at each step, so a name that
# becomes a link between the check and the read is refused by the read: there is no check to race.
# Each file is measured through its own open handle before its bytes are read, and read one byte
# past what the lock declared, so neither a substituted device nor a file that grew can be read
# without bound.
#
# The third argument says what to make of an entry in the bundle directory that is not one of the
# lock's files. `strict` reports it, which is what a bundle at rest should never have; `lenient`
# passes over it, which is what a run still holding its own private working directories needs.
#
# The fourth says whether the two generated Rust files are compared too, and the fifth whether the
# root has to be one a release trusts.
#
# Nothing here opens a socket or looks at the plugin repository: the lock and the bytes beside it
# are the whole input, which is what makes this the check a build with no network can run.
check_bundle() {
    local lock="$1" bundle="$2" strictness="$3" generated="$4" release_only="$5"
    PYTHONPATH="$work" python3 - "$lock" "$bundle" "$strictness" "$generated" "$release_only" \
        "$trust_out" "$files_out" "$root" \
        "$official_metadata_url" "$official_targets_url" "$production_root_threshold" \
        "$max_index_bytes" "$max_index_entries" \
        "$(printf '%s,' "${production_root_keys[@]+"${production_root_keys[@]}"}")" \
        "$(printf '%s,' "${development_root_public_keys[@]}")" <<'PY'
import importlib.util
import json
import os
import sys

from bundle import *  # noqa: F401,F403 - the program above

(
    lock_path, bundle_root, strictness, generated, release_only, trust_out, files_out,
    repository_root, metadata_url, targets_url, production_threshold,
    max_index_bytes, max_index_entries, production_keys, development_public_keys,
) = sys.argv[1:16]
production_keys = [key for key in production_keys.split(",") if key]
development_keys = sorted(key_id(key) for key in development_public_keys.split(",") if key)
max_index_bytes, max_index_entries = int(max_index_bytes), int(max_index_entries)

lock = read_lock(lock_path)
problems = []
checked = 0

try:
    bundle_fd = open_directory(bundle_root)
except OSError as error:
    fail(f"{bundle_root} is not a readable directory: {error}")

declared, found = declared_files(lock)
problems.extend(found)
problems.extend(folded_collisions(declared))

contents = {}
try:
    # What is there, so a file or a directory the lock does not account for is a finding rather
    # than something nobody looked at.
    present, present_directories = set(), set()
    try:
        scan(bundle_fd, "", present, present_directories, problems)
    except OSError as error:
        problems.append(f"{bundle_root} cannot be read through: {error}")
    if strictness == "lenient":
        # This run's own private working directories sit beside the bundle until it exits.
        present = {path for path in present if not path.split("/")[0].startswith(".")}
        present_directories = {
            path for path in present_directories if not path.split("/")[0].startswith(".")
        }
    expected_directories = {
        "/".join(path.split("/")[:depth])
        for path in declared
        for depth in range(1, len(path.split("/")))
    }
    for extra in sorted(present - set(declared)):
        problems.append(f"{extra} is in the bundle and not in the lock")
    for extra in sorted(present_directories - expected_directories):
        problems.append(f"{extra} is a directory the lock does not account for")

    for path, entry in sorted(declared.items()):
        content, problem = read_bounded(bundle_fd, path, int(entry["size_bytes"]))
        if problem is not None:
            problems.append(problem)
            continue
        if sha256(content) != entry["digest"]:
            problems.append(f"{path} is not the payload the lock names")
            continue
        contents[path] = content
        checked += 1
finally:
    os.close(bundle_fd)

# What each package adds up to, and that the lock's account of it is one number.
for package in lock["packages"]:
    total = sum(
        int(entry["size_bytes"]) for entry in [package["manifest"], *package["payloads"]]
    )
    if total != int(package["total_size_bytes"]):
        problems.append(
            f"{package['plugin_id']} declares files adding to {total} bytes"
            f" and the lock says {package['total_size_bytes']}"
        )

# The roots: every numbered root from 1 to the highest, the highest the same bytes as root.json and
# the one the lock names, and the generation's own flag for how its targets are named agreeing with
# the layout.
roots = numbered_roots(declared)
highest = max(roots) if roots else 0
if highest != lock["trust_root"]["version"]:
    problems.append(
        f"the lock's root is version {lock['trust_root']['version']}"
        f" and the highest numbered root is {highest}"
    )
for version in range(1, highest + 1):
    if version not in roots:
        problems.append(f"metadata/{version}.root.json is missing; the roots run from 1")
root_document = None
if highest and "metadata/root.json" in contents and roots.get(highest) in contents:
    if contents["metadata/root.json"] != contents[roots[highest]]:
        problems.append(f"metadata/root.json is not {roots[highest]}, the highest root")
    if sha256(contents[roots[highest]]) != lock["trust_root"]["digest"]:
        problems.append(f"{roots[highest]} is not the root the lock names")
    try:
        root_document = json.loads(contents[roots[highest]])["signed"]
    except (ValueError, KeyError) as error:
        problems.append(f"{roots[highest]} is not a root document: {error}")
if root_document is not None:
    root_role = sorted(root_document["roles"]["root"]["keyids"])
    if root_role != sorted(lock["trust_root"]["key_ids"]):
        problems.append("the lock's root key identifiers are not the root's own")
    if root_document.get("consistent_snapshot"):
        problems.append(
            "the root says targets are named by their digest, and the bundle names them plain"
        )
    # A store that adopted any earlier root has to be able to follow the chain, and a build trusts
    # a root only when all of its root keys are the development set's or all are the production
    # set's, so every shipped root is held to that, not only the highest.
    for version, path in sorted(roots.items()):
        if path not in contents:
            continue
        try:
            keys = sorted(json.loads(contents[path])["signed"]["roles"]["root"]["keyids"])
        except (ValueError, KeyError, TypeError) as error:
            problems.append(f"{path} is not a root document: {error}")
            continue
        if not keys or not (
            all(key in development_keys for key in keys)
            or (production_keys and all(key in production_keys for key in keys))
        ):
            problems.append(
                f"{path} names root keys that are not all development keys and not all"
                " production keys this build commits"
            )
        elif (
            production_keys
            and all(key in production_keys for key in keys)
            and json.loads(contents[path])["signed"]["roles"]["root"]["threshold"]
            < int(production_threshold)
        ):
            problems.append(f"{path} does not meet the production threshold")
    if release_only == "true":
        if not production_keys:
            problems.append("a release trusts no root yet: the production set is empty")
        elif any(key not in production_keys for key in root_role):
            problems.append("the highest root is not signed by production keys only")
        elif root_document["roles"]["root"]["threshold"] < int(production_threshold):
            problems.append("the highest root does not meet the production threshold")

# The index: within the metadata budget, and carrying each bundled package at its digest.
index_content = contents.get(INDEX)
if index_content is not None:
    if len(index_content) > max_index_bytes:
        problems.append(f"{INDEX} is {len(index_content)} bytes, over the {max_index_bytes} budget")
    try:
        index = json.loads(index_content)
        if len(index["entries"]) > max_index_entries:
            problems.append(
                f"{INDEX} has {len(index['entries'])} entries, over the {max_index_entries} budget"
            )
        if str(index["generation"]) != str(lock["source"]["generation"]) or str(
            index["produced_at"]
        ) != str(lock["source"]["produced_at"]):
            problems.append(
                f"{INDEX} is generation {index['generation']} built at {index['produced_at']}"
                f" and the lock names generation {lock['source']['generation']}"
                f" built at {lock['source']['produced_at']}"
            )
        for package in lock["packages"]:
            entry = next(
                (
                    candidate
                    for candidate in index["entries"]
                    if candidate["plugin_id"] == package["plugin_id"]
                    and candidate["version"] == package["version"]
                ),
                None,
            )
            if entry is None:
                problems.append(f"{INDEX} carries no {package['plugin_id']} {package['version']}")
            elif entry["manifest_digest"] != package["manifest"]["digest"]:
                problems.append(f"{INDEX} names another {package['plugin_id']} than the lock")
    except (ValueError, KeyError) as error:
        problems.append(f"{INDEX} is not a catalogue index: {error}")

# What a file is, by the release scan's own checks: no private key, key seed or credential,
# whatever a file is called.
scan_script = os.path.join(repository_root, "scripts", "check-release-secrets.py")
# Loading the scan writes nothing beside it.
sys.dont_write_bytecode = True
try:
    spec = importlib.util.spec_from_file_location("check_release_secrets", scan_script)
    release_scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release_scan)
except Exception as error:  # noqa: BLE001 - whatever stops the scan loading is a finding
    release_scan = None
    problems.append(f"{scan_script} cannot be loaded, so the files are not scanned: {error}")
if release_scan is not None:
    try:
        for path, content in sorted(contents.items()):
            for scanned, what in release_scan.scan_member(path, content, 0):
                problems.append(f"{scanned} {what}")
    except Exception as error:  # noqa: BLE001 - a scan that fails has not cleared the files
        problems.append(f"{scan_script} failed, so the files are not cleared: {error}")

# What the host compiles in and the trust it commits, regenerated and compared.
if generated == "true":
    wanted = {
        trust_out: render_trust(
            production_keys, production_threshold, development_keys, metadata_url, targets_url
        ),
        files_out: render_files(set(declared)),
    }
    for path, text in wanted.items():
        try:
            with open(path, encoding="utf-8") as handle:
                held = handle.read()
        except OSError as error:
            problems.append(f"{path} cannot be read: {error}")
            continue
        if held != text:
            problems.append(f"{path} is not what this script generates; run it to regenerate")

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
# destination or fails, which is the behaviour publishing a bundle needs.
rename_path() {
    python3 -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' "$1" "$2"
}

# What the host compiles in and the trust it commits, written from the lock and the bundle on disk,
# each by a rename of a file beside it.
write_generated() {
PYTHONPATH="$work" python3 - \
    "$lock_file" "$bundle_root" "$root" "$trust_out" "$files_out" \
    "$official_metadata_url" "$official_targets_url" "$production_root_threshold" \
    "$(printf '%s,' "${production_root_keys[@]+"${production_root_keys[@]}"}")" \
    "$(printf '%s,' "${development_root_public_keys[@]}")" <<'PY'
import os
import sys

from bundle import *  # noqa: F401,F403 - the program above

lock_path, bundle_root, repository_root, trust_out, files_out = sys.argv[1:6]
metadata_url, targets_url, threshold = sys.argv[6:9]
production_keys = [key for key in sys.argv[9].split(",") if key]
development_keys = sorted(key_id(key) for key in sys.argv[10].split(",") if key)

lock = read_lock(lock_path)
declared, problems = declared_files(lock)
if problems:
    fail("; ".join(problems))
outputs = {
    trust_out: render_trust(production_keys, threshold, development_keys, metadata_url, targets_url),
    files_out: render_files(set(declared)),
}
for path, text in outputs.items():
    pending = f"{path}.{os.getpid()}.pending"
    with open(pending, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.rename(pending, path)
PY

}

if [ "$generate_only" = true ]; then
    [ -f "$lock_file" ] || fail "$lock_file is not there, so there is nothing to generate from"
    [ -d "$bundle_root" ] || fail "$bundle_root is not there, so there is nothing to generate from"
    write_generated
    check_bundle "$lock_file" "$bundle_root" strict true false
    exit 0
fi

if [ "$verify_only" = true ]; then
    [ -f "$lock_file" ] || fail "$lock_file is not there, so there is nothing to verify against"
    [ -d "$bundle_root" ] || fail "$bundle_root is not there, so there is nothing to verify"
    check_bundle "$lock_file" "$bundle_root" strict true "$release"
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
publish_lock="$root/.bundled-plugins.sync.lock"
held_lock=false
stage_root="$root/.bundled-plugins.staging.$$"
staged_bundle="$stage_root/bundle"
export_root="$stage_root/checkout"
generation="$export_root/$generation_path"
staged_lock="$stage_root/lock.json"
pending_lock="$(dirname "$lock_file")/.$(basename "$lock_file").$$.pending"
retiring="$(dirname "$bundle_root")/.$(basename "$bundle_root").retiring.$$"

owner_of_publish_lock() {
    awk '{print $1; exit}' "$publish_lock/owner" 2>/dev/null || true
}

# What to do about a run that did not finish, decided from what is on disk rather than from how far
# a variable got: a flag is set after the rename it describes, and an interruption lands between the
# two. The staged bundle is the witness. It is still there when nothing was published, and it is
# gone when the rename that published it ran.
cleaned=false
cleanup() {
    local status=$?
    set +e
    # A signal ends the run through its exit, which runs this once. Another signal while it runs
    # must not abandon it half done, and a second pass would find the staging directory gone and
    # mistake a published bundle for an unpublished one.
    trap '' INT TERM
    [ "$cleaned" = false ] || return "$status"
    cleaned=true
    local published_here=false
    if [ ! -d "$staged_bundle" ] && [ -e "$bundle_root" ] && [ -d "$stage_root" ]; then
        published_here=true
    fi
    rm -rf "${stage_root:?}"
    if [ "$published_here" = true ]; then
        if [ -f "$pending_lock" ]; then
            # The bundle is published and the lock that describes it is not. Neither is thrown
            # away: a person decides, with both in front of them.
            echo "sync-bundled-plugins: $bundle_root is the new bundle and $lock_file is not the" \
                "new lock; the new lock is at $pending_lock and the previous bundle at" \
                "$retiring" >&2
        elif [ -d "$retiring" ]; then
            rm -rf "${retiring:?}"
        fi
    else
        rm -f "${pending_lock:?}"
        if [ -d "$retiring" ]; then
            rename_path "$retiring" "$bundle_root" ||
                echo "sync-bundled-plugins: the previous bundle is at $retiring" >&2
        fi
    fi
    if [ "$held_lock" = true ] && [ "$(owner_of_publish_lock)" = "$$" ]; then
        held_lock=false
        rm -rf "${publish_lock:?}"
    fi
    return "$status"
}

trap 'cleanup; rm -rf "${work:?}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$publish_lock" 2>/dev/null ||
    fail "$publish_lock is there, so another sync holds this bundle; remove it if none does"
held_lock=true
echo "$$ $(date '+%F %T')" >"$publish_lock/owner"

mkdir "$stage_root"
chmod 700 "$stage_root"
mkdir "$staged_bundle" "$export_root"

# The repository, taken out of the commit rather than read from the working tree: both the
# generation and the source of the tool that verifies it. Everything after this reads only from
# here, so the bytes that are verified are the bytes that are copied even if somebody checks out
# another branch beside this run. The export is inside this run's own private directory, which
# nothing publishes and the exit takes with it.
git -C "$plugins" archive --format=tar "$pinned_commit" | tar -x -f - -C "$export_root"
[ -d "$generation" ] || fail "the export of $pinned_commit carries no $generation_path"

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

# What the verified metadata says each package consists of, checked against what the index says
# before anything is copied; then the copy of the generation's metadata, its index and those
# packages, and the lock that describes them. The two have to agree: the metadata proves the bytes
# and the index is what a host reads to decide, so a package whose index entry names a payload the
# metadata does not pin is a package this script will not bundle.
#
# Every open of the copy is relative to a directory handle rather than made from a string: the
# exported generation is opened once, each segment down to a file is opened beneath it with links
# refused and without waiting, and the bytes are read through the handle that comes out. They are
# digested before they are written, so a source that is not what the metadata pinned never reaches
# the staging directory. Nothing in the export may be a link or anything else that is not a file or
# a directory: a link under the metadata would be read by the verifier and again by this copy, with
# the file it names free to change between the two.
PYTHONPATH="$work" python3 - \
    "$export_root" "$generation_path" "$staged_bundle" "$staged_lock" \
    "$plugins_repository" "$pinned_commit" \
    "$max_package_bytes" "$max_package_files" "$max_manifest_bytes" \
    "${bundled_packages[@]}" <<'PY'
import json
import os
import sys

from bundle import *  # noqa: F401,F403 - the program above

export_root, generation_path, staged_bundle, lock_path = sys.argv[1:5]
repository, commit = sys.argv[5:7]
max_package_bytes, max_package_files, max_manifest_bytes = (int(value) for value in sys.argv[7:10])
wanted = [spec.split("@", 1) for spec in sys.argv[10:]]

problems = []
descent = [open_directory(export_root)]
try:
    for segment in generation_path.split("/"):
        descent.append(open_directory(segment, descent[-1]))
    generation_fd = descent[-1]
    exported, directories = set(), set()
    scan(generation_fd, "", exported, directories, problems)
    if problems:
        for problem in problems:
            print(f"sync-bundled-plugins: {generation_path}/{problem}", file=sys.stderr)
        sys.exit(f"sync-bundled-plugins: {len(problems)} finding(s) in the exported generation")

    def read_exported(relative):
        """One exported file, whole, read through the handle with the length it has."""
        segments = relative.split("/")
        opened = []
        try:
            parent = generation_fd
            for segment in segments[:-1]:
                opened.append(open_directory(segment, parent))
                parent = opened[-1]
            file_fd = open_file(segments[-1], parent)
            with os.fdopen(file_fd, "rb", closefd=True) as source:
                information = os.fstat(source.fileno())
                if not stat.S_ISREG(information.st_mode):
                    fail(f"{relative} is not a regular file")
                return read_bounded_open(source, relative, information.st_size)
        except OSError as error:
            fail(f"{relative} is not a readable file: {error}")
        finally:
            for descriptor in opened:
                os.close(descriptor)

    def read_bounded_open(source, relative, size):
        content = source.read(size + 1)
        if len(content) != size:
            fail(f"{relative} changed while it was read")
        return content

    def write_staged(relative, content):
        destination = os.path.join(staged_bundle, *relative.split("/"))
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "xb") as sink:
            sink.write(content)

    # The metadata: every numbered root and the three roles over the targets, and the index.
    numbered = sorted(
        (int(name.split(".")[0]), name)
        for name in os.listdir(os.path.join(export_root, generation_path, "metadata"))
        if re.fullmatch(r"[1-9][0-9]*\.root\.json", name)
    )
    names = [name for _, name in numbered]
    if [version for version, _ in numbered] != list(range(1, len(numbered) + 1)) or not numbered:
        fail("the generation ships roots that do not run from version 1 without a gap")
    metadata_files = {}
    for name in [*names, *METADATA_FILES]:
        metadata_files[f"metadata/{name}"] = read_exported(f"metadata/{name}")
    highest_name = names[-1]
    highest_bytes = metadata_files[f"metadata/{highest_name}"]
    top_root = read_exported("root.json")
    if metadata_files["metadata/root.json"] != highest_bytes or top_root != highest_bytes:
        fail(f"root.json is not {highest_name}, the highest root the generation ships")
    root = json.loads(highest_bytes)["signed"]
    if root.get("consistent_snapshot"):
        fail("the generation names its targets by digest, and the bundle names them plain")

    index_bytes = read_exported(INDEX)
    index = json.loads(index_bytes)
    targets = json.loads(metadata_files["metadata/targets.json"])["signed"]["targets"]

    lock_metadata = []
    for path, content in metadata_files.items():
        write_staged(path, content)
        lock_metadata.append({"path": path, "digest": sha256(content), "size_bytes": str(len(content))})
    pinned_index = targets.get("index.json")
    if pinned_index is None or pinned_index["hashes"]["sha256"] != sha256(index_bytes):
        fail("the targets metadata does not pin the index it carries")
    write_staged(INDEX, index_bytes)
    lock_metadata.append(
        {"path": INDEX, "digest": sha256(index_bytes), "size_bytes": str(len(index_bytes))}
    )
    lock_metadata.sort(key=lambda entry: entry["path"])

    lock_packages = []
    for plugin_id, version in wanted:
        entry = next(
            (
                candidate
                for candidate in index["entries"]
                if candidate["plugin_id"] == plugin_id and candidate["version"] == version
            ),
            None,
        )
        if entry is None:
            fail(f"the index carries no {plugin_id} {version}")
        if entry["revocation"] is not None:
            fail(f"{plugin_id} {version} is revoked and takes no new bindings")
        prefix = f"packages/{entry['publisher_id']}/{entry['plugin_name']}/{entry['version']}"

        # Every file, the manifest included. A manifest does not declare itself, so its digest and
        # length come from the index entry that points at it.
        files = [
            ("manifest", "plugin.json", entry["manifest_digest"], int(entry["manifest_size_bytes"]))
        ]
        for payload in entry["payloads"]:
            files.append(
                (payload["role"], payload["path"], payload["digest"], int(payload["size_bytes"]))
            )
        found = []
        if len(files) > max_package_files:
            found.append(f"the package declares {len(files)} files, over the {max_package_files} limit")
        if int(entry["manifest_size_bytes"]) > max_manifest_bytes:
            found.append(
                f"the manifest declares {entry['manifest_size_bytes']} bytes,"
                f" over the {max_manifest_bytes} byte limit"
            )
        declared_total = sum(size for _, _, _, size in files)
        if declared_total > max_package_bytes:
            found.append(
                f"the package declares {declared_total} bytes, over the {max_package_bytes} byte limit"
            )
        if declared_total != int(entry["total_size_bytes"]):
            found.append(
                f"the declared files add to {declared_total} bytes"
                f" and the entry says {entry['total_size_bytes']}"
            )
        # The metadata is what proves a byte. A file the index declares and the metadata does not
        # pin is a file nothing signed, and a digest or length the two disagree about is a package
        # that cannot be resolved by digest at all.
        for _, path, digest, size in files:
            name = f"{prefix}/{path}"
            pinned = targets.get(name)
            if pinned is None:
                found.append(f"the targets metadata does not pin {name}")
                continue
            if pinned["hashes"]["sha256"] != digest:
                found.append(f"{name} is pinned as {pinned['hashes']['sha256']} and declared as {digest}")
            if int(pinned["length"]) != size:
                found.append(f"{name} is pinned at {pinned['length']} bytes and declared at {size}")
        if found:
            for problem in found:
                print(f"sync-bundled-plugins: {problem}", file=sys.stderr)
            sys.exit(f"sync-bundled-plugins: {len(found)} finding(s) against {plugin_id} {version}")

        for role, path, digest, size in files:
            content = read_exported(f"targets/{prefix}/{path}")
            if len(content) != size or sha256(content) != digest:
                fail(f"{path} of {plugin_id} is not the payload the metadata pins")
            write_staged(f"targets/{prefix}/{path}", content)
        print(
            f"sync-bundled-plugins: {plugin_id} {version} declares {len(files)} file(s),"
            f" {declared_total} bytes, all pinned by the verified metadata"
        )
        manifest = files[0]
        lock_packages.append(
            {
                "directory": f"targets/{prefix}",
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
                "payloads": sorted(
                    (
                        {"role": role, "path": path, "digest": digest, "size_bytes": str(size)}
                        for role, path, digest, size in files[1:]
                    ),
                    key=lambda payload: payload["path"],
                ),
                "total_size_bytes": str(declared_total),
            }
        )
    lock_packages.sort(key=lambda package: package["plugin_id"])

    lock = {
        "lock_version": LOCK_VERSION,
        "source": {
            "repository": repository,
            "commit": commit,
            "generation_path": generation_path,
            "tree_url": f"{repository}/tree/{commit}/{generation_path}",
            "generation": index["generation"],
            "produced_at": index["produced_at"],
        },
        "trust_root": {
            "digest": sha256(highest_bytes),
            "version": root["version"],
            "expires": root["expires"],
            "key_ids": sorted(root["roles"]["root"]["keyids"]),
        },
        "metadata": lock_metadata,
        "packages": lock_packages,
    }
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(lock, handle, indent=2, sort_keys=True)
        handle.write("\n")
finally:
    for descriptor in descent:
        os.close(descriptor)
PY

# What was written, measured rather than assumed: every digest and length recomputed from the
# staged bytes, every path checked against the package contract, and anything the lock does not
# account for reported. This is the check that catches an expansion nothing declared. The two
# generated files do not exist yet, so they are not compared here.
check_bundle "$staged_lock" "$staged_bundle" strict false false

# A signature proves who produced a package, not that the package is safe to keep. The validator is
# the safety half, and it runs over each staged package before it is published: the schema, the
# paths, the declared lengths and digests, the capability requests and the things a manifest may
# not say. It executes nothing out of a package.
echo "sync-bundled-plugins: validating the staged packages"
for directory in "$staged_bundle"/targets/packages/*/*/*; do
    (
        cd "$root"
        cargo run --quiet --locked -p kr-plugin-sdk --bin kr-plugin-sandbox -- "$directory"
    )
done

# The new lock goes beside the one it replaces before the bundle moves, so the last step of the
# publish is a rename within a directory this run has already written to.
rename_path "$staged_lock" "$pending_lock"

# The publish. A bundle already there is replaced only when it is the bundle the lock on disk
# describes; anything else is somebody's work or a partial copy, and this stops rather than
# overwriting it. The published name then changes by rename alone, so what is under it is a whole
# bundle or the bundle that was there before.
if [ -e "$bundle_root" ]; then
    [ -f "$lock_file" ] ||
        fail "$bundle_root is there and no lock describes it; move it aside to replace it"
    check_bundle "$lock_file" "$bundle_root" lenient false false >/dev/null 2>&1 ||
        fail "$bundle_root is not what $lock_file describes; move it aside to replace it"
    rename_path "$bundle_root" "$retiring"
fi
rename_path "$staged_bundle" "$bundle_root"
rename_path "$pending_lock" "$lock_file"
if [ -d "$retiring" ]; then
    rm -rf "${retiring:?}"
fi

write_generated

# Lenient, because this run's own private directories are still beside the bundle it published and
# go with its exit. `--verify` is the strict reading, and continuous integration runs it.
check_bundle "$lock_file" "$bundle_root" lenient true false
echo "sync-bundled-plugins: $bundle_root is ${#bundled_packages[@]} package(s) from $generation_path at $pinned_commit"
