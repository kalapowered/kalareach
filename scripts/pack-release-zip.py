#!/usr/bin/env python3
"""Packs a Windows release tree into its archive, `kalareach-<target>-<release>.zip`, and its sums.

    pack-release-zip.py pack --tree TREE --out DIRECTORY
    pack-release-zip.py self-test

The tree is a directory named `kalareach-<target>-<release>` that holds `bin/`, `shells/`, `share/`
and the signed `release.json`. The archive holds that directory whole, each file once, in the order
of its path, with the time of every entry fixed so that the same tree packs to the same bytes. A
link, a device or an empty directory in the tree is refused, as a host refuses them in an archive.
`SHA256SUMS` is written beside the archive with each line ended by a line feed alone, which is what
`sha256sum -c` and `shasum -a 256 -c` read wherever they are run. An archive packed into a directory
that already holds one adds its line to it.

What the archive holds is checked afterwards by `check-release-archive.py`, which reads it as a host
stages one. This only writes it.

`self-test` packs a tree, holds the archive to what the tree held, and then offers a link and an
empty directory, which have to be refused.
"""

import argparse
import hashlib
import os
import stat
import sys
import tempfile
import zipfile

# A zip cannot hold a time before 1980. A fixed time keeps one tree to one archive.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


class Refused(Exception):
    """A tree that is not packed, with the reason."""


def files_of(tree):
    """Every file of the tree, by its path relative to the tree, sorted."""
    found = []
    for directory, subdirectories, names in os.walk(tree):
        for name in subdirectories:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                raise Refused(f"{os.path.relpath(path, tree)} is a link, which a release does not hold")
        if not names and not subdirectories and directory != tree:
            raise Refused(f"{os.path.relpath(directory, tree)} is an empty directory, which a release does not hold")
        for name in names:
            path = os.path.join(directory, name)
            mode = os.lstat(path).st_mode
            if not stat.S_ISREG(mode):
                raise Refused(f"{os.path.relpath(path, tree)} is not a regular file")
            found.append(os.path.relpath(path, tree).replace(os.sep, "/"))
    return sorted(found)


def pack(tree, out):
    tree = os.path.abspath(tree)
    top = os.path.basename(tree)
    if not top.startswith("kalareach-"):
        raise Refused(f"{top} is not named kalareach-<target>-<release>")
    if not os.path.isfile(os.path.join(tree, "release.json")):
        raise Refused(f"{top} holds no release.json")
    members = files_of(tree)
    os.makedirs(out, exist_ok=True)
    archive = os.path.join(out, top + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
        for relative in members:
            info = zipfile.ZipInfo(f"{top}/{relative}", FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if relative.startswith("bin/") else 0o644) << 16
            with open(os.path.join(tree, relative), "rb") as handle:
                zipped.writestr(info, handle.read())
    digest = hashlib.sha256()
    with open(archive, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    # The sums of every archive packed into this directory, one line each and in order of name, so
    # that two targets' archives share the one file a release publishes.
    sums_path = os.path.join(out, "SHA256SUMS")
    lines = {}
    if os.path.exists(sums_path):
        with open(sums_path, encoding="utf-8") as sums:
            for line in sums.read().splitlines():
                digest_text, _, name = line.partition("  ")
                lines[name] = digest_text
    lines[f"{top}.zip"] = digest.hexdigest()
    with open(sums_path, "w", encoding="utf-8", newline="\n") as sums:
        for name in sorted(lines):
            sums.write(f"{lines[name]}  {name}\n")
    return archive


def self_test():
    failures = 0

    def report(label, ok, detail=""):
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}{(': ' + detail) if detail else ''}")
        if not ok:
            failures += 1

    with tempfile.TemporaryDirectory(prefix="kr-pack-zip-") as scratch:
        tree = os.path.join(scratch, "kalareach-x86_64-pc-windows-msvc-0.1.0+aaaaaaaaaaaa")
        for relative, content in (
            ("release.json", b"{}"),
            ("bin/kr.exe", b"MZ"),
            ("share/LICENSE", b"licence"),
        ):
            path = os.path.join(tree, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)
        out = os.path.join(scratch, "out")
        archive = pack(tree, out)
        with zipfile.ZipFile(archive) as zipped:
            names = zipped.namelist()
        top = os.path.basename(tree)
        report(
            "the archive holds the tree whole, once, in order, under its own directory",
            names == sorted(f"{top}/{name}" for name in ("bin/kr.exe", "release.json", "share/LICENSE")),
            ", ".join(names),
        )
        again = pack(tree, os.path.join(scratch, "again"))
        with open(archive, "rb") as first, open(again, "rb") as second:
            report("the same tree packs to the same bytes", first.read() == second.read())
        with open(os.path.join(out, "SHA256SUMS"), "rb") as handle:
            sums = handle.read()
        report("the sums end each line in a line feed alone", sums.endswith(b"\n") and b"\r" not in sums)
        other = os.path.join(scratch, "kalareach-aarch64-pc-windows-msvc-0.1.0+aaaaaaaaaaaa")
        for relative in ("release.json", "bin/kr.exe"):
            path = os.path.join(other, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(b"x")
        pack(other, out)
        with open(os.path.join(out, "SHA256SUMS"), encoding="utf-8") as handle:
            names = [line.split("  ", 1)[1] for line in handle.read().splitlines()]
        report(
            "a second archive adds its line to the sums of the first",
            names == sorted([os.path.basename(other) + ".zip", top + ".zip"]),
            ", ".join(names),
        )

        os.symlink("bin/kr.exe", os.path.join(tree, "bin", "link.exe"))
        try:
            pack(tree, os.path.join(scratch, "link"))
            report("a link in the tree", False, "it was not refused")
        except Refused as error:
            report("a link in the tree", True, f"refused: {error}")
        os.remove(os.path.join(tree, "bin", "link.exe"))
        os.makedirs(os.path.join(tree, "share", "empty"))
        try:
            pack(tree, os.path.join(scratch, "empty"))
            report("an empty directory in the tree", False, "it was not refused")
        except Refused as error:
            report("an empty directory in the tree", True, f"refused: {error}")
    return failures


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    packing = commands.add_parser("pack", help="pack one tree")
    packing.add_argument("--tree", required=True)
    packing.add_argument("--out", required=True)
    commands.add_parser("self-test", help="check the packer against trees made to fail")
    parsed = parser.parse_args(arguments)
    if parsed.command == "self-test":
        return 1 if self_test() else 0
    try:
        archive = pack(parsed.tree, parsed.out)
    except Refused as error:
        print(f"pack-release-zip: {error}", file=sys.stderr)
        return 1
    print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
