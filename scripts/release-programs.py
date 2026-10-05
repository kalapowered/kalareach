#!/usr/bin/env python3
"""Says which programs a host needs for one release target, from `scripts/release-programs.json`.

    release-programs.py names --target <target triple> [--suffix <text>]
    release-programs.py builds --target <target triple>
    release-programs.py self-test

`names` prints each program's name, one to a line, with the suffix after it where the target gives
executables one (`.exe` on Windows). `builds` prints each as `<package>/<name>`, the package that
builds it and its name. The file is the one list the release builds, the Windows archive check and
the host's own check of a release read, so none of them keeps a list of its own: the host reads it
when it is built, and this script is how a workflow reads it. Only Python's standard library is
used, so it runs on every runner a release is built on.
"""

import argparse
import json
import os
import sys

LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release-programs.json")


def programs(target):
    """The programs a release for `target` carries, as (package, name) pairs."""
    with open(LIST, encoding="utf-8") as source:
        listed = json.load(source)["programs"]
    needed = [
        (program["package"], program["name"])
        for program in listed
        if target not in program.get("not_on", [])
    ]
    if not needed:
        # A reader that finds nothing would let every step that loops over it pass over nothing.
        raise SystemExit(f"{LIST} names no program for {target}")
    return needed


def self_test():
    """Holds the reader to what each target needs, written out here apart from the file."""
    everywhere = [
        ("kr-cli", "kr"),
        ("kr-cli", "kr-attach-guard"),
        ("kr-worker", "kr-worker"),
        ("kr-controller", "kr-controller"),
        ("kr-describe-model", "kr-describe-inference"),
        ("kr-hook", "kr-hook"),
        ("kr-plugin-host", "kr-plugin-host"),
    ]
    expected = {
        "aarch64-apple-darwin": everywhere,
        "x86_64-apple-darwin": everywhere,
        "aarch64-unknown-linux-gnu": everywhere,
        "x86_64-unknown-linux-gnu": everywhere,
        "x86_64-pc-windows-msvc": everywhere,
        "aarch64-pc-windows-msvc": [pair for pair in everywhere if pair[1] != "kr-describe-inference"],
    }
    failed = 0
    for target, wanted in expected.items():
        found = programs(target)
        if sorted(found) == sorted(wanted):
            print(f"PASS {target}: {len(found)} programs")
        else:
            print(f"FAIL {target}: wanted {sorted(wanted)}, read {sorted(found)}")
            failed += 1
    return 1 if failed else 0


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("names", "builds"):
        command = commands.add_parser(name)
        command.add_argument("--target", required=True)
        if name == "names":
            command.add_argument("--suffix", default="")
    commands.add_parser("self-test")
    chosen = parser.parse_args(arguments)
    # A name read by a shell on Windows must not end in a carriage return.
    sys.stdout.reconfigure(newline="\n")

    if chosen.command == "self-test":
        return self_test()
    for package, name in programs(chosen.target):
        print(f"{name}{chosen.suffix}" if chosen.command == "names" else f"{package}/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
