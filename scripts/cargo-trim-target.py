#!/usr/bin/env python3
"""Removes this workspace's own build output from a Cargo target directory.

    cargo-trim-target.py [target-directory]

What a later build can reuse from another checkout is what third-party crates built: a crate of
this workspace is built again whatever the directory holds, because Cargo takes a path crate's
freshness from its files' modification times and a checkout resets them. The workspace's output,
the test programs above all, is most of a target directory's size, so a cache of it is kept
without that output.

`cargo clean --workspace` removes the same output but also removes a third-party crate's files
whose name is a workspace test target's name (a test file `windows.rs` takes the `windows` crate's
metadata with it), and Cargo then builds that crate and everything that depends on it again. This
tells a unit's owner by its dependency file instead: a crate from a registry or from Git is read
from Cargo's registry or Git checkouts, an absolute path, and a crate of this workspace is read
from a path relative to the workspace.

Every directory below the target directory that holds `deps` is a profile's (`debug`, `release`,
and the same inside a directory named for a target triple). In each, a unit is a name and a
16-digit hash, and its files, its fingerprint directory and its build directories carry both.
What cannot be told is left alone, which costs a build and never a wrong result. A file that
cannot be removed is reported and left.
"""
import os
import re
import shutil
import sys

# A path read from a registry, or from a Git checkout, whichever way the platform writes it.
THIRD_PARTY = re.compile(r"[\\/](?:registry[\\/]src|git[\\/]checkouts)[\\/]")
HASH = re.compile(r"-([0-9a-f]{16})(?=\.|$)")
FINGERPRINT = re.compile(r"^(.*)-([0-9a-f]{16})$")


def read(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def remove(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    except OSError as error:
        print(f"cargo-trim-target: left {path}: {error}", file=sys.stderr)


def owned_by_workspace(directory):
    """The dependency files of a directory, and whether none of them names a third-party source."""
    files = [name for name in os.listdir(directory) if name.endswith(".d")]
    return bool(files) and not any(
        THIRD_PARTY.search(read(os.path.join(directory, name))) for name in files
    )


def trim_profile(profile):
    deps = os.path.join(profile, "deps")
    fingerprints = os.path.join(profile, ".fingerprint")
    builds = os.path.join(profile, "build")

    # The units of this workspace: the dependency file of each names no third-party source.
    units = set()
    for name in os.listdir(deps):
        if name.endswith(".d") and not THIRD_PARTY.search(read(os.path.join(deps, name))):
            units.add(name[: -len(".d")])
    hashes = {unit.rsplit("-", 1)[1] for unit in units if HASH.search(unit)}

    removed = 0
    for name in os.listdir(deps):
        found = HASH.search(name)
        if not found:
            continue
        head = name[: found.end()]
        # A library's files are `lib<unit>.rlib` and `lib<unit>.rmeta`; its dependency file is `<unit>.d`.
        if head in units or (head.startswith("lib") and head[3:] in units):
            remove(os.path.join(deps, name))
            removed += 1

    # A build script is its own unit: the directory it was compiled in holds its dependency file,
    # and the directory it ran in is named for the same package.
    packages = set()
    if os.path.isdir(builds):
        for name in os.listdir(builds):
            directory = os.path.join(builds, name)
            if os.path.isdir(directory) and owned_by_workspace(directory):
                packages.add(name.rsplit("-", 1)[0])
        for name in os.listdir(builds):
            if name.rsplit("-", 1)[0] in packages:
                remove(os.path.join(builds, name))

    if os.path.isdir(fingerprints):
        for name in os.listdir(fingerprints):
            found = FINGERPRINT.match(name)
            if found and (found.group(2) in hashes or found.group(1) in packages):
                remove(os.path.join(fingerprints, name))

    # What was copied out of `deps` for the person to run, and what no build here reads again.
    for name in os.listdir(profile):
        path = os.path.join(profile, name)
        if name in ("examples", "incremental") or (
            os.path.isfile(path) and not name.startswith(".") and name != "CACHEDIR.TAG"
        ):
            remove(path)

    print(f"cargo-trim-target: {profile}: {len(units)} workspace units, {removed} files removed")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "target"
    if not os.path.isdir(target):
        print(f"cargo-trim-target: no {target}")
        return
    profiles = []
    for directory, names, _ in os.walk(target):
        if "deps" in names:
            profiles.append(directory)
            names[:] = []
        elif os.path.relpath(directory, target).count(os.sep) >= 2:
            names[:] = []
    for profile in sorted(profiles):
        trim_profile(profile)
    remove(os.path.join(target, "doc"))


main()
