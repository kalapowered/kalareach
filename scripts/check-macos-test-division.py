#!/usr/bin/env python3
"""Holds the macOS test legs of the landing workflow to the workspace.

The `macos` job of `.github/workflows/core-ci.yml` runs the workspace's tests in two legs, each on a
runner of its own, and each leg's matrix entry names the packages it tests in a `packages` value of
`-p <package>` words. Every test the workspace has must run in exactly one leg, once: this reads the
two lists from the workflow, asks Cargo for the workspace's members, and fails when

  * a member is in neither list, so its tests would run in no leg,
  * a member is in both lists, or twice in one, so its tests would run twice,
  * a list names a package that is not a member of the workspace, or the one package the landing
    workflow leaves out of the macOS run (`kr-sync-integration`, every test of which is a leg
    against a live deployment, which the rust job runs),
  * a list has a word that is not `-p` or a package, or the workflow has not both legs.

A new crate therefore has to be put in one of the lists before the job passes.

    python3 scripts/check-macos-test-division.py check [--locked]
    python3 scripts/check-macos-test-division.py self-test

`self-test` puts the check through a workflow and a workspace that are written out here: the
division that holds, a member left out, a member in both lists, a member twice in one list, a name
that is no member, the left-out package named, a word that is no package and a leg that is missing.
Each fault must be refused and named, and the division that holds must pass.
"""

import argparse
import json
import os
import re
import subprocess
import sys

WORKFLOW = os.path.join(".github", "workflows", "core-ci.yml")
JOB = "macos"
LEGS = ["tests-1", "tests-2"]
LEFT_OUT = "kr-sync-integration"


def job_text(workflow):
    """The lines of the `macos` job: from its key to the next key at the same indentation."""
    lines = workflow.splitlines()
    try:
        start = lines.index(f"  {JOB}:")
    except ValueError:
        raise SystemExit(f"the workflow has no {JOB} job")
    end = len(lines)
    for at in range(start + 1, len(lines)):
        line = lines[at]
        if re.match(r"  [A-Za-z0-9_-]+:\s*$", line):
            end = at
            break
    return lines[start:end]


def lists(workflow):
    """The packages each leg of the matrix names, by `part`, as the words of its `packages` value."""
    lines = job_text(workflow)
    found = {}
    part = None
    at = 0
    while at < len(lines):
        line = lines[at]
        at += 1
        matched = re.match(r"\s+part:\s*(\S+)\s*$", line)
        if matched:
            part = matched.group(1)
            continue
        matched = re.match(r"(\s+)packages:\s*(>-|>|\|-|\||)\s*(.*)$", line)
        if not matched or part is None:
            continue
        indent = len(matched.group(1))
        words = matched.group(3).split()
        while at < len(lines) and (
            not lines[at].strip() or len(lines[at]) - len(lines[at].lstrip()) > indent
        ):
            words.extend(lines[at].split())
            at += 1
        found.setdefault(part, []).extend(words)
        part = None
    return found


def packages_of(words):
    """The package names in a list of `-p <package>` words, and the words that are neither."""
    names = []
    odd = []
    at = 0
    while at < len(words):
        if words[at] == "-p" and at + 1 < len(words):
            names.append(words[at + 1])
            at += 2
        else:
            odd.append(words[at])
            at += 1
    return names, odd


def problems(workflow, members):
    """What is wrong with the division of `members` in `workflow`, one sentence for each fault."""
    found = lists(workflow)
    faults = []
    for leg in LEGS:
        if leg not in found:
            faults.append(f"the {JOB} job's matrix has no {leg} leg with a packages list")
    if faults:
        return faults
    named = {}
    for leg in LEGS:
        names, odd = packages_of(found[leg])
        for word in odd:
            faults.append(f"{leg}: `{word}` is not `-p` or the name of a package after it")
        for name in sorted({name for name in names if names.count(name) > 1}):
            faults.append(f"{leg}: {name} is named more than once")
        named[leg] = set(names)
    for name in sorted(named[LEGS[0]] & named[LEGS[1]]):
        faults.append(f"{name} is in both legs, so its tests run twice")
    wanted = set(members) - {LEFT_OUT}
    for name in sorted(wanted - named[LEGS[0]] - named[LEGS[1]]):
        faults.append(f"{name} is in no leg, so its tests run nowhere")
    for leg in LEGS:
        for name in sorted(named[leg] - set(members)):
            faults.append(f"{leg}: {name} is not a package of the workspace")
        if LEFT_OUT in named[leg]:
            faults.append(f"{leg}: {LEFT_OUT} is named, and the macOS run leaves it out")
    return faults


def workspace_members(locked):
    """The names of the workspace's member packages, from Cargo."""
    command = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
    if locked:
        command.append("--locked")
    answer = subprocess.run(command, capture_output=True, text=True, check=False)
    if answer.returncode != 0:
        sys.stderr.write(answer.stderr)
        raise SystemExit("cargo metadata failed")
    metadata = json.loads(answer.stdout)
    member_ids = set(metadata["workspace_members"])
    return sorted(
        package["name"] for package in metadata["packages"] if package["id"] in member_ids
    )


def check(locked):
    with open(WORKFLOW, encoding="utf-8") as file:
        workflow = file.read()
    members = workspace_members(locked)
    faults = problems(workflow, members)
    if faults:
        for fault in faults:
            print(f"check-macos-test-division: {fault}", file=sys.stderr)
        return 1
    found = lists(workflow)
    counts = [len(packages_of(found[leg])[0]) for leg in LEGS]
    print(
        f"the {LEGS[0]} leg has {counts[0]} packages and the {LEGS[1]} leg {counts[1]}: "
        f"the workspace's {len(members)} members less {LEFT_OUT}, each in one leg"
    )
    return 0


def fixture(first, second):
    """A workflow with a `macos` job whose two legs name these packages, and a job before and after it."""

    def entry(part, names):
        words = " ".join(f"-p {name}" for name in names)
        return (
            f"          - name: macos-{part}\n"
            f"            part: {part}\n"
            f"            packages: >-\n"
            f"              {words}\n"
        )

    return (
        "jobs:\n"
        "  rust:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - name: rust\n"
        "            part: first\n"
        "            packages: >-\n"
        "              -p not-a-macos-package\n"
        f"  {JOB}:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        + (entry("tests-1", first) if first is not None else "")
        + (entry("tests-2", second) if second is not None else "")
        + "          - name: macos-demonstrations\n"
        "            part: demonstrations\n"
        "  after:\n"
        "    runs-on: x\n"
    )


def self_test():
    members = ["alpha", "beta", "gamma", "delta", LEFT_OUT]
    cases = [
        ("the division that holds", fixture(["alpha", "beta"], ["gamma", "delta"]), []),
        (
            "a member left out",
            fixture(["alpha"], ["gamma", "delta"]),
            ["beta is in no leg"],
        ),
        (
            "a member in both lists",
            fixture(["alpha", "beta"], ["beta", "gamma", "delta"]),
            ["beta is in both legs"],
        ),
        (
            "a member twice in one list",
            fixture(["alpha", "beta", "alpha"], ["gamma", "delta"]),
            ["tests-1: alpha is named more than once"],
        ),
        (
            "a name that is no member",
            fixture(["alpha", "beta", "epsilon"], ["gamma", "delta"]),
            ["tests-1: epsilon is not a package of the workspace"],
        ),
        (
            "the left-out package named",
            fixture(["alpha", "beta"], ["gamma", "delta", LEFT_OUT]),
            [f"tests-2: {LEFT_OUT} is named"],
        ),
        (
            "a word that is no package",
            fixture(["alpha", "beta"], ["gamma", "delta"]).replace(
                "-p gamma", "--exclude gamma"
            ),
            ["tests-2: `--exclude` is not", "gamma is in no leg"],
        ),
        (
            "a leg that is missing",
            fixture(["alpha", "beta", "gamma", "delta"], None),
            ["has no tests-2 leg"],
        ),
    ]
    failed = False
    for what, workflow, expected in cases:
        faults = problems(workflow, members)
        ok = (not faults) if not expected else all(
            any(want in fault for fault in faults) for want in expected
        )
        if expected == [] and faults:
            ok = False
        if not ok:
            failed = True
            print(f"self-test: {what}: wanted {expected or 'no fault'}, got {faults}", file=sys.stderr)
        else:
            print(f"self-test: {what}: {'accepted' if not expected else 'refused, ' + '; '.join(faults)}")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="the workflow's lists against the workspace")
    checking.add_argument("--locked", action="store_true")
    commands.add_parser("self-test", help="the check against faults it must refuse")
    arguments = parser.parse_args()
    if arguments.command == "check":
        return check(arguments.locked)
    return self_test()


if __name__ == "__main__":
    sys.exit(main())
