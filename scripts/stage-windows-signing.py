#!/usr/bin/env python3
"""Sets apart the files of a Windows release tree that are signed, and puts them back once they are.

    stage-windows-signing.py stage --tree TREE --staging DIRECTORY
    stage-windows-signing.py restore --tree TREE --staging DIRECTORY --receipt FILE
    stage-windows-signing.py self-test

The files that carry an Authenticode signature are the host's executables in `bin/` and every file
of the PowerShell package that runs: the module and the startup script. A PowerShell execution
policy that asks for every script to be signed refuses the package unless all of them are, so they
are signed together or not at all. Everything else in the tree is data and is not sent to the
signing service.

`stage` copies each such file to DIRECTORY at the path it has in the tree. The signing service signs
that directory, and the signature check writes a receipt of what it accepted: one line for each
file, its SHA-256, its path and what it was signed with. `restore` takes the receipt as the word on
what was signed. It refuses unless the receipt lists exactly the files this staged and each staged
file has the digest the receipt gives, and only then copies each signed file over the one in the
tree and writes the receipt into the tree as `share/signatures.txt`, with every line ended by a
line feed alone. The manifest is written after that, since a signature changes the bytes it covers.
"""

import argparse
import hashlib
import os
import shutil
import sys
import tempfile

RECEIPT = "share/signatures.txt"


class Refused(Exception):
    """A tree or a receipt that is not what a signed release is, with the reason."""


def signable(relative):
    """Whether the file at `relative` (parts separated by `/`) is signed."""
    parts = relative.split("/")
    if parts[0] == "bin" and len(parts) == 2:
        return parts[1].endswith(".exe")
    if parts[:3] == ["shells", "psreadline", "module"] and len(parts) == 4:
        return True
    return relative == "shells/psreadline/startup/kr-profile.ps1"


def files_of(directory):
    found = []
    for base, _, names in os.walk(directory):
        for name in names:
            found.append(os.path.relpath(os.path.join(base, name), directory).replace(os.sep, "/"))
    return sorted(found)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def stage(tree, staging):
    chosen = [relative for relative in files_of(tree) if signable(relative)]
    if not any(relative.startswith("bin/") for relative in chosen):
        raise Refused(f"{tree} holds no executable to sign")
    if os.path.exists(staging) and os.listdir(staging):
        raise Refused(f"{staging} is not empty")
    for relative in chosen:
        destination = os.path.join(staging, *relative.split("/"))
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copyfile(os.path.join(tree, *relative.split("/")), destination)
    return chosen


def receipt_entries(receipt):
    """The digest and the path of each file the receipt accepted."""
    entries = {}
    with open(receipt, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split("  ", 2)
            if len(fields) < 2:
                raise Refused(f"{receipt} has a line that is not `<sha256>  <path>  ...`: {line!r}")
            digest, path = fields[0].strip().lower(), fields[1].strip().replace("\\", "/")
            if path in entries:
                raise Refused(f"{receipt} lists {path} twice")
            entries[path] = digest
    return entries


def restore(tree, staging, receipt):
    entries = receipt_entries(receipt)
    staged = files_of(staging)
    if sorted(entries) != staged:
        extra = sorted(set(entries) - set(staged))
        missing = sorted(set(staged) - set(entries))
        raise Refused(f"the receipt and what was staged differ: it lists {extra} that were not staged, and lacks {missing}")
    if sorted(relative for relative in files_of(tree) if signable(relative)) != staged:
        raise Refused("the tree's files to sign are not the ones that were staged")
    for relative, digest in entries.items():
        if sha256_of(os.path.join(staging, *relative.split("/"))) != digest:
            raise Refused(f"{relative} is not the file the receipt accepted")
    for relative in staged:
        shutil.copyfile(os.path.join(staging, *relative.split("/")), os.path.join(tree, *relative.split("/")))
    with open(receipt, encoding="utf-8") as source:
        text = source.read().replace("\r\n", "\n").replace("\r", "\n")
    destination = os.path.join(tree, *RECEIPT.split("/"))
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")
    return len(staged)


def self_test():
    failures = 0

    def report(label, ok, detail=""):
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}{(': ' + detail) if detail else ''}")
        if not ok:
            failures += 1

    def make(scratch):
        tree = os.path.join(scratch, "tree")
        for relative in (
            "bin/kr.exe",
            "bin/kr-worker.exe",
            "shells/psreadline/module/KalaReach.ShellBridge.psm1",
            "shells/psreadline/startup/kr-profile.ps1",
            "shells/psreadline/manifest.json",
            "share/LICENSE",
            "release.json",
        ):
            path = os.path.join(tree, *relative.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(relative.encode())
        return tree

    def sign_and_receipt(staging, receipt, skip=None, wrong=None):
        lines = ["# sha256  path  signed by"]
        for relative in files_of(staging):
            path = os.path.join(staging, *relative.split("/"))
            with open(path, "ab") as handle:
                handle.write(b"\nsigned")
            if relative == skip:
                continue
            digest = "0" * 64 if relative == wrong else sha256_of(path)
            lines.append(f"{digest}  {relative.replace('/', chr(92))}  CN=Test")
        with open(receipt, "w", encoding="utf-8", newline="") as handle:
            handle.write("\r\n".join(lines) + "\r\n")

    with tempfile.TemporaryDirectory(prefix="kr-stage-signing-") as scratch:
        tree = make(scratch)
        staging = os.path.join(scratch, "staging")
        chosen = stage(tree, staging)
        report(
            "the executables and the PowerShell package are staged and the data is not",
            chosen
            == [
                "bin/kr-worker.exe",
                "bin/kr.exe",
                "shells/psreadline/module/KalaReach.ShellBridge.psm1",
                "shells/psreadline/startup/kr-profile.ps1",
            ],
            ", ".join(chosen),
        )
        receipt = os.path.join(scratch, "receipt.txt")
        sign_and_receipt(staging, receipt)
        count = restore(tree, staging, receipt)
        with open(os.path.join(tree, "bin", "kr.exe"), "rb") as handle:
            signed = handle.read().endswith(b"signed")
        with open(os.path.join(tree, RECEIPT), "rb") as handle:
            written = handle.read()
        report("a receipt that holds puts each signed file back", count == 4 and signed)
        report("the receipt is written with line feeds alone", b"\r" not in written and written.endswith(b"\n"))
        with open(os.path.join(tree, "share", "LICENSE"), "rb") as handle:
            report("a data file is as it was", handle.read() == b"share/LICENSE")

        for label, skip, wrong in (
            ("a receipt that leaves a staged file out", "bin/kr.exe", None),
            ("a receipt that gives another digest", None, "bin/kr.exe"),
        ):
            fresh = make(os.path.join(scratch, label.replace(" ", "-")))
            staged_here = os.path.join(scratch, label.replace(" ", "-") + "-staging")
            stage(fresh, staged_here)
            bad = os.path.join(scratch, label.replace(" ", "-") + ".txt")
            sign_and_receipt(staged_here, bad, skip, wrong)
            try:
                restore(fresh, staged_here, bad)
                report(label, False, "it was not refused")
            except Refused as error:
                report(label, True, f"refused: {error}")
        empty = os.path.join(scratch, "no-programs")
        os.makedirs(os.path.join(empty, "share"))
        with open(os.path.join(empty, "share", "LICENSE"), "wb") as handle:
            handle.write(b"x")
        try:
            stage(empty, os.path.join(scratch, "none"))
            report("a tree with no executable", False, "it was not refused")
        except Refused as error:
            report("a tree with no executable", True, f"refused: {error}")
    return failures


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    staging = commands.add_parser("stage", help="copy the files to be signed")
    staging.add_argument("--tree", required=True)
    staging.add_argument("--staging", required=True)
    restoring = commands.add_parser("restore", help="put the signed files back")
    restoring.add_argument("--tree", required=True)
    restoring.add_argument("--staging", required=True)
    restoring.add_argument("--receipt", required=True)
    commands.add_parser("self-test", help="check the staging against receipts made to fail")
    parsed = parser.parse_args(arguments)
    if parsed.command == "self-test":
        return 1 if self_test() else 0
    try:
        if parsed.command == "stage":
            for relative in stage(parsed.tree, parsed.staging):
                print(relative)
        else:
            print(f"stage-windows-signing: {restore(parsed.tree, parsed.staging, parsed.receipt)} signed files are in the tree")
    except Refused as error:
        print(f"stage-windows-signing: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
