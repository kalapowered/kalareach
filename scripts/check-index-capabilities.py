#!/usr/bin/env python3
"""Keeps a release that requests `skill_target.install` out of an index an older host would refuse.

    python3 -I scripts/check-index-capabilities.py check <index.json> --first-release <version> \\
        (--oldest-supported <version> | --oldest-supported-from-tags <checkout>)
    python3 -I scripts/check-index-capabilities.py self-test

A host refuses a whole catalogue index generation that lists a release requesting a capability the
host does not know, and then stops reading that repository's later revocations. So a repository the
product serves lists a release that requests `skill_target.install` only when no host release the
product still supports predates the release that adds the capability. The plugins pipeline builds
the index and runs `check` on it before it publishes it.

`--first-release` is the version of the first host release that knows the capability. The oldest
supported host release is given in one of two forms:

- `--oldest-supported <version>`: the version itself.
- `--oldest-supported-from-tags <checkout>`: read from a checkout of this repository whose release
  tags are fetched (`git fetch --tags`), the way `scripts/check-retained-release.sh` reads them. The
  oldest level the checkout retains is the lowest directory of `crates/kr-protocol/retained/`; the
  oldest supported host release is the lowest release tag `packages/v<version>+<commit>` whose
  version is at that level (`0.<minor>` below 1.0.0, the major number from it).

Versions are semantic versions; a build suffix (`+<commit>`) is read and ignored. The index is the
catalogue index's JSON: each entry has a `plugin_id`, a `version` and a list `capabilities` whose
members name a `capability`. An entry counts whether or not it carries a revocation, because the
older host refuses the generation that lists it.

Exit status is 0 when the index may be published, 1 when an entry requests the capability while the
oldest supported host release predates `--first-release` (one line on standard error for each such
release, naming it and the two versions), and 2 for an unreadable index, a version that is not a
semantic version or a bad command. Nothing is read from the network.

`self-test` builds indexes and a repository of release tags in a folder of its own and runs the
command on each: it must pass the indexes that may be published and refuse the others.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CAPABILITY = "skill_target.install"

_NUMBER = r"(0|[1-9][0-9]*)"
_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(
    rf"^{_NUMBER}\.{_NUMBER}\.{_NUMBER}"
    rf"(?:-({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
RELEASE_TAG = re.compile(r"^packages/v([^+]+)\+[0-9a-f]+$")
LEVEL_DIRECTORY = re.compile(r"^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$")


class Refused(Exception):
    """An input the command cannot read; the message is its one line."""


def parse_version(text, what):
    """The precedence key of a semantic version: a release sorts above its own pre-releases."""
    match = SEMVER.match(text)
    if match is None:
        raise Refused(f"{what} is not a semantic version: {text!r}")
    major, minor, patch = (int(part) for part in match.group(1, 2, 3))
    if match.group(4) is None:
        return (major, minor, patch, 1, ())
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in match.group(4).split(".")
    )
    return (major, minor, patch, 0, identifiers)


def level_of(version):
    """The compatibility level of a version: `0.<minor>` below 1.0.0, the major number from it."""
    major, minor = SEMVER.match(version).group(1, 2)
    return f"0.{minor}" if major == "0" else major


def level_key(level):
    return tuple(int(part) for part in level.split("."))


def read_index(path):
    """The entries of the index as (plugin id, version, capability words)."""
    try:
        with open(path, encoding="utf-8") as handle:
            index = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise Refused(f"the index {path} cannot be read: {error}") from error
    if not isinstance(index, dict) or not isinstance(index.get("entries"), list):
        raise Refused(f"the index {path} has no list of entries")
    entries = []
    for position, entry in enumerate(index["entries"]):
        label = f"entry {position} of the index {path}"
        if not isinstance(entry, dict):
            raise Refused(f"{label} is not an object")
        plugin_id, version, capabilities = (entry.get(key) for key in ("plugin_id", "version", "capabilities"))
        if not isinstance(plugin_id, str) or not isinstance(version, str):
            raise Refused(f"{label} has no plugin_id and version")
        if not isinstance(capabilities, list):
            raise Refused(f"{label} ({plugin_id} {version}) has no list of capabilities")
        words = []
        for request in capabilities:
            if not isinstance(request, dict) or not isinstance(request.get("capability"), str):
                raise Refused(f"{label} ({plugin_id} {version}) has a capability request with no capability")
            words.append(request["capability"])
        entries.append((plugin_id, version, words))
    return entries


def read_oldest_from_tags(checkout):
    """The oldest supported host release: the lowest release tag at the oldest retained level."""
    retained = os.path.join(checkout, "crates", "kr-protocol", "retained")
    try:
        levels = [name for name in os.listdir(retained) if LEVEL_DIRECTORY.match(name)]
    except OSError as error:
        raise Refused(f"the retained levels of {checkout} cannot be read: {error}") from error
    if not levels:
        raise Refused(f"{retained} holds no retained level")
    oldest_level = min(levels, key=level_key)
    try:
        listed = subprocess.run(
            ["git", "-C", checkout, "tag", "--list", "packages/v*"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refused(f"the release tags of {checkout} cannot be read: {error}") from error
    at_level = []
    for tag in listed:
        match = RELEASE_TAG.match(tag)
        if match is not None and SEMVER.match(match.group(1)) and level_of(match.group(1)) == oldest_level:
            at_level.append(match.group(1))
    if not at_level:
        raise Refused(f"{checkout} has no release tag at the oldest retained level {oldest_level}; fetch the tags")
    return min(at_level, key=lambda version: parse_version(version, "a release tag"))


def check(index, first_release, oldest_supported, checkout):
    if (oldest_supported is None) == (checkout is None):
        raise Refused("give exactly one of --oldest-supported and --oldest-supported-from-tags")
    first_key = parse_version(first_release, "--first-release")
    if oldest_supported is None:
        oldest_supported = read_oldest_from_tags(checkout)
    oldest_key = parse_version(oldest_supported, "--oldest-supported")
    entries = read_index(index)
    requesting = [(plugin_id, version) for plugin_id, version, words in entries if CAPABILITY in words]
    if requesting and oldest_key < first_key:
        for plugin_id, version in requesting:
            print(
                f"REFUSED: {plugin_id} {version} requests {CAPABILITY}, and the oldest supported host "
                f"release {oldest_supported} predates {first_release}, the release that adds it",
                file=sys.stderr,
            )
        return 1
    if requesting:
        print(
            f"ok: {len(requesting)} of {len(entries)} entries request {CAPABILITY}; the oldest supported "
            f"host release {oldest_supported} does not predate {first_release}"
        )
    else:
        print(f"ok: none of {len(entries)} entries requests {CAPABILITY}")
    return 0


# ---- the self-test ----


def entry(plugin_id, version, *words):
    return {
        "plugin_id": plugin_id,
        "version": version,
        "capabilities": [{"capability": word, "reason": "a reason"} for word in words],
    }


def self_test():
    scratch = tempfile.mkdtemp(prefix="kalareach-index-capabilities-")
    results = []
    script = os.path.abspath(__file__)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": scratch,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def expect(name, condition, detail=""):
        print(("ok    " if condition else "FAIL  ") + name)
        if not condition and detail:
            print("      " + detail.rstrip().replace("\n", "\n      "))
        results.append(bool(condition))

    def index(name, *entries):
        path = os.path.join(scratch, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"index_version": 1, "generation": 1, "publishers": [], "entries": list(entries)}, handle)
        return path

    def run(*arguments):
        done = subprocess.run(
            [sys.executable, "-I", script, "check", *arguments],
            capture_output=True,
            text=True,
            cwd=scratch,
            env=environment,
            check=False,
        )
        return done.returncode, done.stdout.splitlines(), done.stderr.splitlines()

    def git(directory, *arguments):
        subprocess.run(["git", "-C", directory, *arguments], check=True, capture_output=True, env=environment)

    try:
        plain = index(
            "plain.json",
            entry("kalareach/example-one", "1.0.0", "metadata.match", "presentation.declarative"),
            entry("kalareach/example-two", "2.1.0", "metadata.match"),
        )
        requesting = index(
            "requesting.json",
            entry("kalareach/example-one", "1.0.0", "metadata.match"),
            entry("kalareach/skills-one", "1.2.0", "metadata.match", CAPABILITY),
            entry("kalareach/skills-two", "0.3.1", CAPABILITY),
        )

        code, out, err = run(plain, "--first-release", "0.90.0", "--oldest-supported", "0.77.0")
        expect(
            "an index with no such request passes",
            code == 0 and err == [] and out == [f"ok: none of 2 entries requests {CAPABILITY}"],
            f"exit {code}, stdout {out}, stderr {err}",
        )

        code, out, err = run(requesting, "--first-release", "0.90.0", "--oldest-supported", "0.77.0")
        lines = [
            f"REFUSED: kalareach/skills-one 1.2.0 requests {CAPABILITY}, and the oldest supported host "
            "release 0.77.0 predates 0.90.0, the release that adds it",
            f"REFUSED: kalareach/skills-two 0.3.1 requests {CAPABILITY}, and the oldest supported host "
            "release 0.77.0 predates 0.90.0, the release that adds it",
        ]
        expect(
            "a request with an older supported host fails, one line for each release",
            code == 1 and out == [] and err == lines,
            f"exit {code}, stdout {out}, stderr {err}",
        )

        code, out, err = run(requesting, "--first-release", "0.90.0", "--oldest-supported", "0.91.2+0123456789ab")
        expect(
            "a request after the window passes",
            code == 0
            and err == []
            and out
            == [
                f"ok: 2 of 3 entries request {CAPABILITY}; the oldest supported host release "
                "0.91.2+0123456789ab does not predate 0.90.0"
            ],
            f"exit {code}, stdout {out}, stderr {err}",
        )

        code, out, err = run(requesting, "--first-release", "0.90.0", "--oldest-supported", "0.90.0")
        expect("a host release that is the first release does not predate it", code == 0 and err == [], f"exit {code}, stderr {err}")

        code, out, err = run(requesting, "--first-release", "0.90.0", "--oldest-supported", "0.90.0-rc.1")
        expect(
            "a pre-release of the first release predates it",
            code == 1 and len(err) == 2,
            f"exit {code}, stderr {err}",
        )

        revoked = index("revoked.json", {**entry("kalareach/skills-one", "1.2.0", CAPABILITY), "revocation": {"reason": "security"}})
        code, out, err = run(revoked, "--first-release", "0.90.0", "--oldest-supported", "0.77.0")
        expect("a revoked entry that requests it still counts", code == 1 and len(err) == 1, f"exit {code}, stderr {err}")

        broken = os.path.join(scratch, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write('{"entries": [{"plugin_id": "kalareach/example-one", "version": "1.0.0"}]}')
        code, out, err = run(broken, "--first-release", "0.90.0", "--oldest-supported", "0.77.0")
        expect(
            "an entry with no capabilities list is refused as unreadable",
            code == 2 and out == [] and len(err) == 1 and "no list of capabilities" in err[0],
            f"exit {code}, stdout {out}, stderr {err}",
        )

        code, out, err = run(plain, "--first-release", "0.90", "--oldest-supported", "0.77.0")
        expect(
            "a version that is not a semantic version is refused",
            code == 2 and len(err) == 1 and "--first-release is not a semantic version" in err[0],
            f"exit {code}, stderr {err}",
        )

        code, out, err = run(plain, "--first-release", "0.90.0")
        expect("a missing oldest supported release is refused", code == 2 and len(err) == 1, f"exit {code}, stderr {err}")

        checkout = os.path.join(scratch, "checkout")
        os.makedirs(os.path.join(checkout, "crates", "kr-protocol", "retained", "0.77"))
        os.makedirs(os.path.join(checkout, "crates", "kr-protocol", "retained", "0.78"))
        git(checkout, "init", "-q")
        git(checkout, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-q", "--allow-empty", "-m", "a commit")
        for tag in (
            "packages/v0.76.2+aaaaaaaaaaaa",
            "packages/v0.77.1+cccccccccccc",
            "packages/v0.77.0+bbbbbbbbbbbb",
            "packages/v0.78.0+dddddddddddd",
            "v0.70.0",
        ):
            git(checkout, "tag", tag)

        code, out, err = run(requesting, "--first-release", "0.77.1", "--oldest-supported-from-tags", checkout)
        expect(
            "read from the tags, the oldest release at the oldest retained level is the oldest supported",
            code == 1
            and len(err) == 2
            and all("the oldest supported host release 0.77.0 predates 0.77.1" in line for line in err),
            f"exit {code}, stderr {err}",
        )

        code, out, err = run(requesting, "--first-release", "0.77.0", "--oldest-supported-from-tags", checkout)
        expect("read from the tags, a first release that is the oldest passes", code == 0 and err == [], f"exit {code}, stderr {err}")

        bare = os.path.join(scratch, "bare")
        os.makedirs(os.path.join(bare, "crates", "kr-protocol", "retained", "0.77"))
        git(bare, "init", "-q")
        code, out, err = run(plain, "--first-release", "0.90.0", "--oldest-supported-from-tags", bare)
        expect(
            "a checkout with no release tag at the oldest retained level is refused",
            code == 2 and len(err) == 1 and "fetch the tags" in err[0],
            f"exit {code}, stderr {err}",
        )
    finally:
        # Only a directory this run made, under the directory it made it in.
        if scratch.startswith(os.path.join(tempfile.gettempdir(), "kalareach-index-capabilities-")):
            shutil.rmtree(scratch, ignore_errors=True)

    failed = results.count(False)
    print(f"{len(results) - failed} of {len(results)} cases hold")
    return 1 if failed else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="refuse an index an older supported host would refuse")
    checking.add_argument("index", help="the catalogue index, as JSON")
    checking.add_argument("--first-release", required=True, help="the first host release that knows the capability")
    checking.add_argument("--oldest-supported", help="the oldest host release the product still supports")
    checking.add_argument(
        "--oldest-supported-from-tags",
        metavar="CHECKOUT",
        help="read the oldest supported host release from this checkout's release tags",
    )
    commands.add_parser("self-test", help="prove each case on indexes built for the purpose")
    arguments = parser.parse_args(argv)
    if arguments.command == "self-test":
        return self_test()
    try:
        return check(arguments.index, arguments.first_release, arguments.oldest_supported, arguments.oldest_supported_from_tags)
    except Refused as error:
        print(f"cannot check: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
