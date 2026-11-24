#!/usr/bin/env python3
"""Makes the third-party notice of a release, or holds the committed one to what the lock now makes.

    generate-notices.py write --kr-release PROGRAM [--cargo-about PROGRAM] [--work DIR]
    generate-notices.py check --kr-release PROGRAM [--cargo-about PROGRAM] [--work DIR]
    generate-notices.py self-test

The notice, `docs/releases/third-party-notices.txt`, is what every release archive carries as
`share/THIRD-PARTY-NOTICES.txt`. It is made from two sources of crates:

  * the programs a release builds (`scripts/release-programs.json`): cargo-about runs on the
    manifest of each program's package, for every platform a release is built for, and
  * the fish package: its pinned upstream archive is placed and checked by
    `scripts/place-shell-sources.sh`, its crates are fetched as its own `Cargo.lock` names them, and
    cargo-about runs on that tree for the platforms fish is built for.

The lock also names crates that no release platform builds, such as a dependency's own
dependencies for an operating system a release does not target. `kr-release notice-gaps` lists the
crates the lock takes into the release programs that the entries do not name, and they are written
last, under a heading of their own, so that `kr-release` can hold the committed text to the lock
and a crate added to the lock stops a release until this runs again.

`about.toml` says which licences a crate may be used under and which one a crate that offers
several is recorded under. The output of the runs is merged into one text: each licence text once,
with the crates that use it. `check` makes the notice again and refuses a committed one that
differs. The merge reads no clock and no path of the machine, so the same lock gives the same
bytes on every machine.

cargo-about runs offline over the sources cargo has fetched, because online it fetches a missing
licence file from the crate's repository, and the notice would then depend on that server.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ABOUT_VERSION = "0.9.3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTICE = os.path.join(ROOT, "docs", "releases", "third-party-notices.txt")
CONFIG = os.path.join(ROOT, "about.toml")
# fish's own crates are licensed as fish is, which `shells/fish/LICENSE` reproduces, and the notice
# has no entry for them. The run over fish's tree accepts those licences so that it can read them,
# after every licence a dependency may be used under, so that they pick no crate's alternative.
FISH_OWN_LICENCES = ["GPL-2.0-only", "LGPL-2.0-or-later", "PSF-2.0"]
FISH_TARGETS = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
]

HEADER = """\
THIRD-PARTY NOTICES

KalaReach is distributed under the BSD-3-Clause licence in share/LICENSE. Each shell package keeps
its own licence in its directory under shells/. This file reproduces the licences of the
third-party crates that the release's programs and its fish package are built from.

The list covers every platform a release is built for, so the list for one archive is a subset of
it. A crate that is offered under several licences is recorded under the one this project takes it
under. The entry of a crate under the Mozilla Public License 2.0, or taken from a Git repository,
names where its source is. Each licence text appears once, followed by the crates it applies to. An
entry gives the crate, its version, whether the programs, the fish package or both are built from
it, and the authors its package names.
"""


def fail(message):
    sys.exit(f"generate-notices: {message}")


def read_packages():
    """The packages the release programs come from, from the one list the release builds read."""
    with open(os.path.join(ROOT, "scripts", "release-programs.json"), encoding="utf-8") as source:
        listed = json.load(source)["programs"]
    return sorted({program["package"] for program in listed})


def toolchain():
    """The channel the repository pins, so a run in another directory uses the same compiler."""
    with open(os.path.join(ROOT, "rust-toolchain.toml"), encoding="utf-8") as source:
        for line in source:
            if line.strip().startswith("channel"):
                return line.split("=", 1)[1].strip().strip('"')
    fail("rust-toolchain.toml names no channel")


def run(command, **options):
    done = subprocess.run(command, capture_output=True, text=True, **options)
    if done.returncode != 0:
        fail(f"{' '.join(command[:3])} failed:\n{done.stdout[-1500:]}{done.stderr[-3000:]}")
    return done


def check_version(program):
    said = run([program, "--version"]).stdout.strip()
    if said != f"cargo-about {ABOUT_VERSION}":
        fail(f"{program} says '{said}' and the notice is made with cargo-about {ABOUT_VERSION}")


def about(program, manifest, output, config, extra=(), environment=None):
    """One cargo-about run over a manifest, written as JSON."""
    run(
        [program, "generate", "--format", "json", "--offline", "--locked", "--config", config,
         "--manifest-path", manifest, "--output-file", output, *extra],
        env=environment,
    )
    with open(output, encoding="utf-8") as source:
        return json.load(source)


def fish_tree(work):
    """The pinned fish archive, checked and extracted, with its crates fetched as its lock names them."""
    prefix = os.path.join(work, "shells")
    run(["bash", os.path.join(ROOT, "scripts", "place-shell-sources.sh"), "--prefix", prefix, "--fish"])
    with open(os.path.join(ROOT, "shells", "fish", "manifest.json"), encoding="utf-8") as source:
        upstream = json.load(source)["upstream"]
    archive = os.path.join(prefix, "sources", os.path.basename(upstream["url"]))
    digest = hashlib.sha256(open(archive, "rb").read()).hexdigest()
    if digest != upstream["sha256"]:
        fail(f"{archive} has digest {digest} and the manifest pins {upstream['sha256']}")
    unpacked = os.path.join(work, "fish-source")
    with tarfile.open(archive, "r:xz") as tar:
        tar.extractall(unpacked, filter="data")
    entries = os.listdir(unpacked)
    if len(entries) != 1:
        fail(f"the fish archive unpacks to {len(entries)} directories")
    tree = os.path.join(unpacked, entries[0])
    cargo_home = os.path.join(work, "fish-cargo-home")
    os.makedirs(cargo_home, exist_ok=True)
    # Git is the client for the repositories and reads no configuration of the account that runs
    # this, whose rewrite of an https address to ssh would ask for a key.
    environment = {
        **os.environ,
        "CARGO_HOME": cargo_home,
        "RUSTUP_TOOLCHAIN": toolchain(),
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    run(["cargo", "fetch", "--locked"], cwd=tree, env=environment)
    return tree, environment


def fish_config(work):
    """about.toml with the licences of fish's own crates added at the end of the accepted list."""
    with open(CONFIG, encoding="utf-8") as source:
        text = source.read()
    end = '    "MPL-2.0",\n]\n'
    if text.count(end) != 1:
        fail("about.toml does not end its accepted list with MPL-2.0")
    added = "".join(f'    "{name}",\n' for name in FISH_OWN_LICENCES)
    path = os.path.join(work, "fish-about.toml")
    with open(path, "w", encoding="utf-8", newline="\n") as target:
        target.write(text.replace(end, '    "MPL-2.0",\n' + added + "]\n"))
    return path


def collect(program, work):
    """Every cargo-about answer: the programs' packages, then fish."""
    check_version(program)
    answers = []
    for package in read_packages():
        manifest = os.path.join(ROOT, "crates", package, "Cargo.toml")
        if not os.path.isfile(manifest):
            fail(f"{manifest} is not a manifest: release-programs.json names a package that has no crate")
        answers.append(
            ("programs", about(program, manifest, os.path.join(work, f"{package}.json"), CONFIG))
        )
    tree, environment = fish_tree(work)
    config = fish_config(work)
    targets = [item for target in FISH_TARGETS for item in ("--target", target)]
    answers.append(
        (
            "fish",
            about(program, os.path.join(tree, "Cargo.toml"), os.path.join(work, "fish.json"), config, targets, environment),
        )
    )
    return answers


def source_of(package):
    """Where a crate's source is, as a URL a person can open."""
    source = package["source"]
    name, version = package["name"], package["version"]
    if source.startswith("registry+"):
        return f"https://crates.io/crates/{name}/{version}"
    if source.startswith("git+"):
        return source[len("git+"):]
    fail(f"{name} {version} comes from {source}, which is neither a registry nor a Git repository")


def merge(answers):
    """The licence texts, each with the crates that use it."""
    texts = {}
    for origin, answer in answers:
        for licence in answer["licenses"]:
            text = licence["text"].replace("\r\n", "\n").strip("\n") + "\n"
            key = (licence["id"], hashlib.sha256(text.encode("utf-8")).hexdigest())
            block = texts.setdefault(key, {"id": licence["id"], "name": licence["name"], "text": text, "crates": {}})
            for use in licence["used_by"]:
                package = use["crate"]
                if package["source"] is None:
                    continue
                entry = block["crates"].setdefault(
                    (package["name"], package["version"], package["source"]),
                    {"origins": set(), "authors": package["authors"], "package": package},
                )
                entry["origins"].add(origin)
    return [block for block in texts.values() if block["crates"]]


def entry_line(key, entry, licence_id):
    name, version, _ = key
    package = entry["package"]
    fields = [f"{name} {version}", " and ".join(sorted(entry["origins"])), ", ".join(entry["authors"])]
    if licence_id == "MPL-2.0" or package["source"].startswith("git+"):
        fields.append(f"source {source_of(package)}")
    return ("  - " + " | ".join(fields)).rstrip()


def render(blocks):
    ordered = sorted(blocks, key=lambda block: (block["id"], min(block["crates"]), block["text"]))
    rule = "=" * 100
    parts = [HEADER]
    for block in ordered:
        parts.append(f"\n{rule}\nLicence: {block['id']} ({block['name']})\n{rule}\n\nUsed by:\n\n")
        for key in sorted(block["crates"]):
            parts.append(entry_line(key, block["crates"][key], block["id"]) + "\n")
        parts.append("\n" + block["text"])
    return "".join(parts)


UNUSED = """\

====================================================================================================
Crates the lock reaches that no release platform builds
====================================================================================================

The lock names these crates among the dependencies of the release programs, and no build for a
release platform compiles them in. They are listed so that a crate added to the lock stops a
release until this notice is made again.

"""


def make(program, kr_release, work):
    body = render(merge(collect(program, work)))
    entries = os.path.join(work, "entries.txt")
    with open(entries, "w", encoding="utf-8", newline="\n") as target:
        target.write(body)
    unused = run([kr_release, "notice-gaps", "--checkout", ROOT, "--notice", entries]).stdout.split("\n")
    unused = [line for line in unused if line]
    return body + (UNUSED + "".join(f"  - {line}\n" for line in unused) if unused else "")


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("write", "check"):
        command = commands.add_parser(name)
        command.add_argument("--kr-release", required=True, help="the kr-release program, built from this checkout")
        command.add_argument("--cargo-about", default="cargo-about")
        command.add_argument("--work", help="a directory for the runs, which is kept; a new one by default")
    commands.add_parser("self-test")
    chosen = parser.parse_args(arguments)
    if chosen.command == "self-test":
        return self_test()
    with tempfile.TemporaryDirectory(prefix="kr-notices-") as scratch:
        work = chosen.work or scratch
        os.makedirs(work, exist_ok=True)
        made = make(chosen.cargo_about, chosen.kr_release, work)
    if chosen.command == "write":
        with open(NOTICE, "w", encoding="utf-8", newline="\n") as target:
            target.write(made)
        print(f"generate-notices: wrote {NOTICE}")
        return 0
    with open(NOTICE, encoding="utf-8", newline="") as source:
        committed = source.read()
    if committed != made:
        print("generate-notices: docs/releases/third-party-notices.txt is not what the lock makes; run "
              "`python3 scripts/generate-notices.py write` and commit it", file=sys.stderr)
        return 1
    print("generate-notices: the committed notice is the one the lock makes")
    return 0


def synthetic(name, version, source, authors=()):
    return {"name": name, "version": version, "source": source, "authors": list(authors)}


def self_test():
    """Holds merge and render to what a notice must do, over answers made up here."""
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    mit = "Copyright (c) 2020 A\n\nPermission is hereby granted\n"
    mpl = "Mozilla Public License Version 2.0\n"

    def licence(identifier, text, crates):
        return {"id": identifier, "name": identifier, "text": text, "used_by": [{"crate": c, "path": None} for c in crates]}

    alpha, beta = synthetic("alpha", "1.0.0", registry, ["A"]), synthetic("beta", "2.0.0", registry)
    forked = synthetic("forked", "0.1.0", "git+https://example.org/forked?rev=abc#abc")
    own = synthetic("own", "0.1.0", None)
    selectors = synthetic("selectors", "0.38.0", registry)
    programs = {"licenses": [licence("MIT", mit, [alpha, own]), licence("MPL-2.0", mpl, [selectors, forked])]}
    fish = {"licenses": [licence("MIT", mit + "\n", [alpha, beta])]}
    text = render(merge([("programs", programs), ("fish", fish)]))
    failed = 0

    def expect(what, condition):
        nonlocal failed
        print(("PASS " if condition else "FAIL ") + what)
        failed += 0 if condition else 1

    expect("a licence text that two runs share appears once", text.count("Permission is hereby granted") == 1)
    expect("a crate both builds use says both", "  - alpha 1.0.0 | fish and programs | A\n" in text)
    expect("a crate of the fish run alone says fish", "  - beta 2.0.0 | fish |\n" in text)
    expect("a crate of the project itself has no entry", "own 0.1.0" not in text)
    expect("an MPL-2.0 crate names its source", "selectors 0.38.0 | programs |  | source https://crates.io/crates/selectors/0.38.0\n" in text)
    expect("a crate from a Git repository names its source", "source https://example.org/forked?rev=abc#abc\n" in text)
    expect("the same answers in another order make the same text", text == render(merge([("fish", fish), ("programs", programs)])))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
