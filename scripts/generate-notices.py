#!/usr/bin/env python3
"""Makes the third-party notice of a release, or holds the committed one to what the lock now makes.

    generate-notices.py write --kr-release PROGRAM [--cargo-about PROGRAM] [--work DIR]
    generate-notices.py check --kr-release PROGRAM [--cargo-about PROGRAM] [--work DIR]
    generate-notices.py self-test

The notice, `docs/releases/third-party-notices.txt`, is what every release archive carries as
`share/THIRD-PARTY-NOTICES.txt`. `kr-release` is built first (`cargo build -p kr-release`); its
program is the one named by `--kr-release`.

Which crates the notice covers. For each of the two sources of crates, `cargo tree` lists what a
release build compiles in: the packages of `scripts/release-programs.json`, for every platform a
release is built for, over normal and build edges, and the fish package, for the platforms fish is
built for and the features its CMake build selects. A crate that only a test, another package's
features or a platform no release builds for brings in is not in that list. `cargo-about` says which
licence each crate is recorded under; a listed crate that it does not answer for stops the run, and
an answer for a crate that is not listed is left out. A path package that is not a member of the
workspace it belongs to stops the run too.

What the notice says for each crate. The text of a crate's own licence file, where `cargo-about`
took one. Where it took none, every licence file in the crate's package (a name that starts
`LICENSE`, `LICENCE`, `COPYING` or `UNLICENSE`), without the alternative of a dual licence that the
crate declares. Every notice file of the package (a name that starts `COPYRIGHT`, `NOTICE`,
`NOTICES` or `PATENTS`, or holds `THIRD-PARTY`), for every crate. Where a package ships no licence
file, none of the licence it is recorded under, or a file that holds a template's placeholder, the
upstream text that `scripts/notice-texts.json` keeps in `docs/releases/notice-texts/`, with its
source and digest; a text kept for a crate whose package ships its own, or for a crate no release
build compiles, stops the run. The same file names the licences of the works that a crate bundles
and builds in (libsodium, llama.cpp and ggml, PCRE2). fish's `COPYING` and the licence file of each
of its workspace crates are read from its pinned archive. A text that holds a template's
placeholder stops the run.

The lock also names crates that no release build compiles. `kr-release notice-gaps` lists the crates
the lock takes into the release programs that the entries do not name, and they are written last,
each with the reason it is left out, so that `kr-release` can hold the committed text to the lock
and a crate added to the lock stops a release until this runs again.

`about.toml` says which licences a crate may be used under and which one a crate that offers
several is recorded under. `check` makes the notice again and refuses a committed one that differs.
The merge reads no clock and no path of the machine, so the same lock gives the same bytes on every
machine.

cargo-about runs offline over the sources cargo has fetched, because online it fetches a missing
licence file from the crate's repository, and the notice would then depend on that server.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile

ABOUT_VERSION = "0.9.3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTICE = os.path.join(ROOT, "docs", "releases", "third-party-notices.txt")
CONFIG = os.path.join(ROOT, "about.toml")
TEXTS = os.path.join(ROOT, "scripts", "notice-texts.json")
TEXTS_DIRECTORY = os.path.join(ROOT, "docs", "releases", "notice-texts")
# fish's own crates are licensed as fish is, and the run over fish's tree accepts those licences so
# that cargo-about can read them, after every licence a dependency may be used under, so that they
# pick no crate's alternative. The notice carries fish's `COPYING` and each fish crate's own licence
# file, and a crate of fish's workspace that declares any other licence stops the run.
FISH_OWN_LICENCES = ["GPL-2.0-only", "LGPL-2.0-or-later", "PSF-2.0"]
# What a crate of fish's workspace may declare: fish's own licences, `fish-printf`'s MIT and the CC0-1.0
# of `fish-widecharwidth`, both of which ship their own licence file.
FISH_MEMBER_LICENCES = set(FISH_OWN_LICENCES) | {"MIT", "CC0-1.0"}
FISH_TARGETS = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
]

# What the permissive templates of the SPDX list hold where the owner's copyright line goes. The
# GPL's own text has `<year>` and `<name of author>` in the paragraph that tells a program how to
# apply it, so those are not here.
PLACEHOLDER = re.compile(r"<(owner|copyright holders?|organi[sz]ation)>", re.IGNORECASE)
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|unlicen[cs]e)", re.IGNORECASE)
NOTICE_FILE = re.compile(r"^(copyright|notices?|patents)|third[-_ ]?party", re.IGNORECASE)

# How a licence text announces itself. A file that matches exactly one is put under that licence.
SIGNATURES = [
    ("Apache-2.0", ["Apache License", "Version 2.0, January 2004"]),
    ("MPL-2.0", ["Mozilla Public License Version 2.0"]),
    ("BSD-3-Clause", ["Redistribution and use in source and binary forms", "Neither the name"]),
    ("ISC", ["Permission to use, copy, modify, and/or distribute this software for any purpose"]),
    ("MIT", ["Permission is hereby granted, free of charge"]),
    ("Zlib", ["This software is provided 'as-is'"]),
    ("CC0-1.0", ["CC0 1.0 Universal"]),
    ("Unlicense", ["This is free and unencumbered software released into the public domain"]),
]

HEADER = """\
THIRD-PARTY NOTICES

KalaReach is distributed under the BSD-3-Clause licence in share/LICENSE. Each shell package keeps
its own licence in its directory under shells/. This file carries the licence texts and notices of
the third-party crates that the release's programs and its fish package are built from, as the
crates' own packages state them, and the licence texts of the libraries that some of those crates
bundle. It does not cover the companion application. It also carries the whole of fish's own
licence file, COPYING, whose terms cover more than the licence in fish's directory under shells/.

The list covers every platform a release is built for, so the list for one archive is a subset of
it. A crate that is offered under several licences is recorded under the one this project takes it
under. Each text appears once, followed by the crates it applies to. An entry gives the crate, its
version, whether the programs, the fish package or both are built from it, and the authors its
package names. The entry of a crate under the Mozilla Public License 2.0, or taken from a Git
repository, names where its source is. Where a package ships no licence text, the entry names the
upstream file that the text comes from.
"""

UNUSED = """\

====================================================================================================
Crates the lock reaches that no release build compiles
====================================================================================================

The lock names these crates among the dependencies of the release programs, and no release build
compiles them in. Each line says why. They are listed so that a crate added to the lock stops a
release until this notice is made again.

"""

REPAIR = (
    "build kr-release with `cargo build -p kr-release`, run `python3 scripts/generate-notices.py write "
    "--kr-release target/debug/kr-release`, and commit the result"
)


def fail(message):
    sys.exit(f"generate-notices: {message}")


def read_programs():
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


def about_targets():
    """The platforms a release is built for, from the list `about.toml` gives cargo-about."""
    with open(CONFIG, encoding="utf-8") as source:
        found = re.search(r"^targets = \[(.*?)\]", source.read(), re.DOTALL | re.MULTILINE)
    if not found:
        fail("about.toml has no targets list")
    return re.findall(r'"([^"]+)"', found.group(1))


def run(command, **options):
    done = subprocess.run(command, capture_output=True, text=True, **options)
    if done.returncode != 0:
        fail(f"{' '.join(command[:3])} failed:\n{done.stdout[-1500:]}{done.stderr[-3000:]}")
    return done


def check_version(program):
    said = run([program, "--version"]).stdout.strip()
    if said != f"cargo-about {ABOUT_VERSION}":
        fail(f"{program} says '{said}' and the notice is made with cargo-about {ABOUT_VERSION}")


def restricted(cargo_home):
    """The environment of every call that reaches a Git repository: Git reads no configuration of the
    account that runs this, whose rewrite of an https address to ssh would ask for a key."""
    return {
        **os.environ,
        "CARGO_HOME": cargo_home,
        "RUSTUP_TOOLCHAIN": toolchain(),
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def identity(name, version, source):
    """What names a crate: its name, its version and where it comes from (None for crates.io, else
    the repository and the first eight letters of the revision). None for a path package."""
    if source is None or source.startswith("/"):
        return None
    if source.startswith(("registry+", "sparse+")):
        if "crates.io" not in source:
            fail(f"{name} {version} comes from {source}, a registry that is not crates.io")
        return (name, version, None)
    if source.startswith("git+"):
        source = source[len("git+"):]
    if source.startswith("https://"):
        address, _, revision = source.partition("#")
        return (name, version, f"{address}#{revision[:8]}")
    fail(f"{name} {version} comes from {source}, which is neither a registry nor a Git repository")


def tree_line(line):
    """`name vX.Y.Z (source) (*)` as an identity, or `("path", name, version)` for a path package."""
    line = re.sub(r" \((\*|proc-macro)\)", "", line.strip())
    found = re.match(r"^(\S+) v(\S+)(?: \((.+)\))?$", line)
    if not found:
        fail(f"cargo tree printed '{line}', which is not a package line")
    name, version, source = found.groups()
    if source is None:
        return (name, version, None)
    if source.startswith("/"):
        return ("path", name, version)
    return identity(name, version, source)


def compiled(directory, packages, targets, extra, environment, edges="normal,build"):
    """The crates `cargo tree` lists for these packages built together on these platforms, and the
    path packages among them, by name."""
    found, paths = set(), set()
    for target in targets:
        command = ["cargo", "tree", "-e", edges, "--target", target, "--locked", "--offline",
                   "--prefix", "none", "--format", "{p}", "--color", "never", *extra]
        for package in packages:
            command += ["-p", package]
        for line in run(command, cwd=directory, env=environment).stdout.splitlines():
            if not line.strip():
                continue
            crate = tree_line(line)
            if crate[0] == "path":
                paths.add(crate[1])
            else:
                found.add(crate)
    return found, paths


def members(directory, environment):
    """The packages of the workspace at `directory` by name: their folder, version, authors and
    declared licence."""
    done = run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked", "--offline"],
               cwd=directory, env=environment)
    return {
        package["name"]: {
            "root": os.path.dirname(package["manifest_path"]),
            "version": package["version"],
            "authors": package["authors"],
            "licence": package.get("license") or "",
        }
        for package in json.loads(done.stdout)["packages"]
    }


def roots(directory, environment):
    """Where cargo keeps each crate's package and what the package declares as its licence, by identity."""
    done = run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], cwd=directory, env=environment)
    found = {}
    for package in json.loads(done.stdout)["packages"]:
        source = package["source"]
        if source is not None:
            found[identity(package["name"], package["version"], source)] = (
                os.path.dirname(package["manifest_path"]), package.get("license") or "")
    return found


def about(program, manifest, output, config, extra=(), environment=None):
    """One cargo-about run over a manifest, written as JSON."""
    run(
        [program, "generate", "--format", "json", "--offline", "--locked", "--config", config,
         "--manifest-path", manifest, "--output-file", output, *extra],
        env=environment,
    )
    with open(output, encoding="utf-8") as source:
        return json.load(source)


def safe_extract(archive, destination):
    """Unpacks a tar archive into `destination`, refusing a member, or the target of a link, that
    would land outside it and a device file; `tarfile`'s own filter is not in every Python this runs
    under (the Mac's is 3.9)."""
    base = os.path.realpath(destination)

    def inside(path):
        return os.path.commonpath([base, os.path.realpath(path)]) == base

    with tarfile.open(archive, "r:xz") as tar:
        for member in tar.getmembers():
            target = os.path.join(base, member.name)
            if member.isdev() or not inside(target):
                fail(f"{archive} holds {member.name}, which is a device or lands outside the folder it unpacks to")
            if member.issym() and not inside(os.path.join(os.path.dirname(target), member.linkname)):
                fail(f"{archive} holds {member.name}, a link to {member.linkname} outside the folder it unpacks to")
            if member.islnk() and not inside(os.path.join(base, member.linkname)):
                fail(f"{archive} holds {member.name}, a link to {member.linkname} outside the folder it unpacks to")
        tar.extractall(base)


def fish_tree(work):
    """The pinned fish archive, checked and extracted, with its crates fetched as its lock names them."""
    cargo_home = os.path.join(work, "fish-cargo-home")
    os.makedirs(cargo_home, exist_ok=True)
    environment = restricted(cargo_home)
    prefix = os.path.join(work, "shells")
    run(["bash", os.path.join(ROOT, "scripts", "place-shell-sources.sh"), "--prefix", prefix, "--fish"],
        env=environment)
    with open(os.path.join(ROOT, "shells", "fish", "manifest.json"), encoding="utf-8") as source:
        manifest = json.load(source)
    upstream = manifest["upstream"]
    archive = os.path.join(prefix, "sources", os.path.basename(upstream["url"]))
    with open(archive, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    if digest != upstream["sha256"]:
        fail(f"{archive} has digest {digest} and the manifest pins {upstream['sha256']}")
    unpacked = os.path.join(work, "fish-source")
    os.makedirs(unpacked, exist_ok=True)
    safe_extract(archive, unpacked)
    entries = os.listdir(unpacked)
    if len(entries) != 1:
        fail(f"the fish archive unpacks to {len(entries)} directories, not one")
    tree = os.path.join(unpacked, entries[0])
    run(["cargo", "fetch", "--locked"], cwd=tree, env=environment)
    return tree, environment, fish_features(manifest["configure"])


def fish_features(configure):
    """The cargo features fish's CMake build selects: it passes `--no-default-features` and adds
    `localize-messages` unless `-DWITH_MESSAGE_LOCALIZATION=OFF`."""
    flags = [flag for flag in configure if flag.startswith("-DWITH_MESSAGE_LOCALIZATION=")]
    if len(flags) > 1 or any(flag.split("=", 1)[1] not in ("ON", "OFF") for flag in flags):
        fail(f"the fish configuration sets WITH_MESSAGE_LOCALIZATION in a way this reads no further: {flags}")
    return [] if flags and flags[0].endswith("=OFF") else ["localize-messages"]


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


def answers_of(answer):
    """What cargo-about says for each crate, by identity: its authors, its source and the licences it
    found, each as (id, name, text, whether the text is a file of the crate)."""
    found = {}
    for licence in answer["licenses"]:
        for use in licence["used_by"]:
            package = use["crate"]
            key = identity(package["name"], package["version"], package["source"])
            if key is None:
                continue
            entry = found.setdefault(key, {"authors": package["authors"], "source": package["source"], "licences": []})
            entry["licences"].append((licence["id"], licence["name"], licence["text"], licence["source_path"] is not None))
    return found


def collect(program, work):
    """What each release build compiles and what cargo-about and cargo metadata say of those crates,
    as one record for the programs and one for fish."""
    check_version(program)
    targets = about_targets()
    packages = read_programs()
    environment = dict(os.environ)
    answered = {}
    for package in packages:
        manifest = os.path.join(ROOT, "crates", package, "Cargo.toml")
        if not os.path.isfile(manifest):
            fail(f"{manifest} is not a manifest: release-programs.json names a package that has no crate")
        answered.update(answers_of(about(program, manifest, os.path.join(work, f"{package}.json"), CONFIG)))
    listed, paths = compiled(ROOT, packages, targets, [], environment)
    result = [record("programs", listed, paths, members(ROOT, environment), answered, roots(ROOT, environment))]
    tree, fish_environment, features = fish_tree(work)
    flags = ["--no-default-features"] + (["--features", ",".join(features)] if features else [])
    answer = answers_of(about(program, os.path.join(tree, "Cargo.toml"), os.path.join(work, "fish.json"),
                              fish_config(work), [item for target in FISH_TARGETS for item in ("--target", target)] + flags,
                              fish_environment))
    listed, paths = compiled(tree, ["fish"], FISH_TARGETS, flags, fish_environment)
    fish = record("fish", listed, paths, members(tree, fish_environment), answer, roots(tree, fish_environment))
    fish["tree"] = tree
    result.append(fish)
    return result


def record(name, listed, paths, member, answered, where):
    """One origin's record, after the checks that tie the three views of its crates together: what
    cargo tree compiles, what cargo-about answers and what cargo metadata locates."""
    stray = sorted(path for path in paths if path not in member)
    if stray:
        fail(f"the {name} build compiles in {', '.join(stray)}, path packages that are not members of its workspace")
    lacking = by_identity(listed - set(answered))
    if lacking:
        shown = ", ".join(f"{n} {v}" for n, v, _ in lacking[:8])
        fail(f"cargo tree lists {len(lacking)} crates of the {name} build that cargo-about gives no licence for, the first {shown}")
    unplaced = by_identity(listed - set(where))
    if unplaced:
        fail(f"cargo metadata finds no package for {len(unplaced)} crates of the {name} build, the first {unplaced[0][0]} {unplaced[0][1]}")
    return {"name": name, "listed": listed, "answers": {key: answered[key] for key in listed},
            "roots": {key: where[key][0] for key in listed}, "declared": {key: where[key][1] for key in listed},
            "paths": paths, "members": member}


def by_identity(keys):
    """Identities in an order that holds when two crates differ only in where they come from."""
    return sorted(keys, key=lambda key: (key[0], key[1], key[2] or ""))


def normal(text):
    return text.replace("\r\n", "\n").strip("\n") + "\n"


# The one file of a package that is not UTF-8: rav1e's PATENTS has Windows-1252 quotation marks.
ENCODINGS = {"rav1e-0.8.1/PATENTS": "cp1252"}


def read_text(path):
    with open(path, "rb") as source:
        data = source.read()
    encoding = ENCODINGS.get(os.path.join(os.path.basename(os.path.dirname(path)), os.path.basename(path)), "utf-8")
    try:
        return normal(data.decode(encoding))
    except UnicodeDecodeError:
        fail(f"{path} is not UTF-8 text")


def files_named(folder, pattern):
    """The plain files at the top of `folder` whose names match `pattern`, in name order."""
    return sorted(
        name for name in os.listdir(folder)
        if pattern.search(name) and os.path.isfile(os.path.join(folder, name))
    )


def licence_files(folder):
    """The licence files of a package: the names that start as a licence file's do, except a file
    that is a notice (`LICENSE-THIRD-PARTY`)."""
    return [name for name in files_named(folder, LICENCE_FILE) if not NOTICE_FILE.search(name)]


def identify(text):
    """The one licence a text announces, or None when it announces none or more than one."""
    seen = [name for name, words in SIGNATURES if all(word in text for word in words)]
    return seen[0] if len(seen) == 1 else None


def alone(folder, recorded, declared):
    """The licence files of a package, as (name, text), without the ones for another licence that the
    package declares beside the recorded one: a crate under `MIT OR Apache-2.0` is taken under MIT, and
    its Apache file is the alternative that this project does not take it under. A file for a licence
    the package does not declare (the BSD-3-Clause terms of code that a crate carries) stays."""
    base = recorded.split(" WITH ")[0]
    kept = []
    for file_name in licence_files(folder):
        text = read_text(os.path.join(folder, file_name))
        other = identify(text)
        if other is not None and other != base and other in declared:
            continue
        kept.append((file_name, text))
    return kept


def lacks(recorded, texts):
    """Whether none of the texts is the text of the recorded licence, where every one of them says
    which licence it is."""
    base = recorded.split(" WITH ")[0]
    seen = [identify(text) for text in texts]
    return base in {name for name, _ in SIGNATURES} and base not in seen and None not in seen


def placeholder(text):
    found = PLACEHOLDER.search(text)
    return found.group(0) if found else None


def keep_texts(listing=TEXTS, directory=TEXTS_DIRECTORY):
    """The upstream texts kept in the repository, each held to its digest."""
    with open(listing, encoding="utf-8") as source:
        kept = json.load(source)
    files = {}
    for item in kept["texts"]:
        path = os.path.join(directory, item["id"])
        if not os.path.isfile(path):
            fail(f"scripts/notice-texts.json names {item['id']}, which docs/releases/notice-texts does not hold")
        with open(path, "rb") as source:
            digest = hashlib.sha256(source.read()).hexdigest()
        if digest != item["sha256"]:
            fail(f"docs/releases/notice-texts/{item['id']} has digest {digest} and scripts/notice-texts.json says {item['sha256']}")
        text = read_text(path)
        if "lines" in item:
            first, last = item["lines"]
            lines = text.split("\n")[:-1]
            if not 1 <= first <= last <= len(lines):
                fail(f"scripts/notice-texts.json asks for lines {first} to {last} of {item['id']}, which has {len(lines)} lines")
            text = normal("\n".join(lines[first - 1:last]))
        files[item["id"]] = {**item, "text": text}
    return kept, files


def kept_title(text, names):
    """The name a kept text's licence goes under: the one its entry in the listing gives, else the licence's."""
    return text.get("name") or names.get(text["licence"], text["licence"])


def kept_source(text):
    """The words that say where a kept text comes from and what was done to it."""
    words = f"text {text['source']}"
    if "lines" in text:
        words += f", lines {text['lines'][0]} to {text['lines'][1]}"
    if "edit" in text:
        words += " without its copyright line"
    return words


def source_of(source, name, version):
    """Where a crate's source is, as a URL a person can open."""
    if source.startswith(("registry+", "sparse+")):
        return f"https://crates.io/crates/{name}/{version}"
    return source[len("git+"):]


class Blocks:
    """The licence texts, each with the crates that use it."""

    def __init__(self):
        self.texts = {}

    def add(self, kind, licence, name, text, crate, authors, origin, source, extra=None):
        bad = placeholder(text)
        if bad:
            fail(f"the text of {crate[0]} {crate[1]} holds the placeholder {bad}")
        key = (kind, licence, hashlib.sha256(text.encode("utf-8")).hexdigest())
        block = self.texts.setdefault(key, {"kind": kind, "id": licence, "name": name, "text": text, "crates": {}})
        entry = block["crates"].setdefault(
            (crate[0], crate[1], crate[2] or ""),
            {"origins": set(), "authors": authors, "source": source, "extra": extra},
        )
        entry["origins"].add(origin)


def entry_line(key, entry, licence):
    name, version, _ = key
    fields = [f"{name} {version}", " and ".join(sorted(entry["origins"])), ", ".join(entry["authors"])]
    source = entry["source"]
    if source is not None and (licence == "MPL-2.0" or source.startswith("git+")):
        fields.append(f"source {source_of(source, name, version)}")
    if entry["extra"]:
        fields.append(entry["extra"])
    return ("  - " + " | ".join(fields)).rstrip()


def render(blocks):
    ordered = sorted(blocks.texts.values(), key=lambda block: (block["kind"], block["id"], min(block["crates"]), block["text"]))
    rule = "=" * 100
    parts = [HEADER]
    for block in ordered:
        title = "Notice file" if block["kind"] == "notice" else "Licence"
        parts.append(f"\n{rule}\n{title}: {block['id']} ({block['name']})\n{rule}\n\nUsed by:\n\n")
        for key in sorted(block["crates"]):
            parts.append(entry_line(key, block["crates"][key], block["id"]) + "\n")
        parts.append("\n" + block["text"])
    return "".join(parts)


def pinned_for(kept, name, version, where):
    """The kept entry for a crate, or None. An entry names a repository when it is for a crate taken
    from one."""
    for item in kept["crates"]:
        if item["name"] == name and item["version"] == version:
            repository = item.get("repository")
            if (repository is None and where is None) or (repository and where and where.startswith(repository)):
                return item
    return None


def declared_tokens(expression):
    return {word for word in re.findall(r"[A-Za-z0-9.+-]+", expression) if word not in ("AND", "OR", "WITH")}


def gather(records, kept, files):
    """Every crate's texts, put in blocks, with the checks on what the kept texts stand for."""
    blocks = Blocks()
    names = {}
    for each in records:
        for answer in each["answers"].values():
            for identifier, name, _, _ in answer["licences"]:
                names.setdefault(identifier, name)
    used_texts, used_crates = set(), set()
    compiled_crates = {}
    for each in records:
        for key in by_identity(each["answers"]):
            answer = each["answers"][key]
            name, version, where = key
            folder = each["roots"][key]
            compiled_crates.setdefault((name, version), set()).add(each["name"])
            crate = (name, version, where)
            args = (answer["authors"], each["name"], answer["source"])
            recorded = answer["licences"][0][0]
            taken = [(i, t) for i, _, t, own in answer["licences"] if own]
            owned = alone(folder, recorded, declared_tokens(each["declared"][key]))
            item = pinned_for(kept, name, version, where)
            if item is not None:
                # A file that holds a template's placeholder is the package's own template, not its text.
                taken = [(i, t) for i, t in taken if not placeholder(t)]
                owned = [(f, t) for f, t in owned if not placeholder(t)]
            needs = not taken and (not owned or lacks(recorded, [text for _, text in owned]))
            if item is not None and not needs:
                fail(f"scripts/notice-texts.json keeps a text for {name} {version}, whose package ships the licence text itself")
            if needs and item is None:
                what = f"file of its recorded licence {recorded}" if owned else "licence file"
                fail(f"{name} {version} ships no {what} and scripts/notice-texts.json keeps no text for it")
            for identifier, text in taken:
                blocks.add("licence", identifier, names.get(identifier, identifier), normal(text), crate, *args)
            for file_name, text in owned:
                identifier = identify(text) or recorded
                blocks.add("licence", identifier, names.get(identifier, identifier), text, crate, *args)
            if item is not None:
                used_crates.add((item["name"], item["version"], item.get("repository")))
                for identifier in item["texts"]:
                    used_texts.add(identifier)
                    text = files[identifier]
                    blocks.add("licence", text["licence"], kept_title(text, names), text["text"], crate, *args, kept_source(text))
            for file_name in files_named(folder, NOTICE_FILE):
                blocks.add("notice", "Notice file", file_name, read_text(os.path.join(folder, file_name)), crate, *args)
        for name in sorted(each["paths"]):
            if each["name"] == "fish":
                fish_member(blocks, name, each["members"][name])
    for item in kept["crates"]:
        if (item["name"], item["version"], item.get("repository")) not in used_crates:
            fail(f"scripts/notice-texts.json keeps a text for {item['name']} {item['version']}, which no release build compiles")
    for work in kept["works"]:
        carrier = (work["carried_by"]["name"], work["carried_by"]["version"])
        if carrier not in compiled_crates:
            fail(f"{work['name']} {work['version']} is bundled in {carrier[0]} {carrier[1]}, which no release build compiles")
        text = files[work["text"]]
        used_texts.add(work["text"])
        for origin in sorted(compiled_crates[carrier]):
            blocks.add("licence", text["licence"], kept_title(text, names), text["text"],
                       (work["name"], work["version"], None), [], origin, None,
                       f"bundled in {carrier[0]} {carrier[1]}, {kept_source(text)}")
    for identifier in files:
        if identifier not in used_texts:
            fail(f"scripts/notice-texts.json lists the text {identifier}, which no crate or work uses")
    return blocks


def fish_member(blocks, name, member):
    """The licence files of a crate of fish's own workspace, put under the licence it declares."""
    expression = member["licence"]
    unknown = sorted(declared_tokens(expression) - FISH_MEMBER_LICENCES)
    if unknown:
        fail(f"{name} of the fish workspace declares {', '.join(unknown)}, a licence this notice has no text for")
    for file_name in licence_files(member["root"]):
        text = read_text(os.path.join(member["root"], file_name))
        blocks.add("licence", expression or name, f"the fish package, {file_name}", text,
                   (name, member["version"], None), member["authors"], "fish", None)


def reasons(gaps_list, packages, targets, environment):
    """Why each crate that the lock reaches and no build compiles is left out, one line to a crate."""
    built, _ = compiled(ROOT, packages, targets, [], environment)
    tested, _ = compiled(ROOT, packages, targets, [], environment, "normal,build,dev")
    elsewhere, _ = compiled(ROOT, packages, ["all"], [], environment)
    lines = []
    for gap in gaps_list:
        crate, _, source = gap.partition(" | source ")
        name, version = crate.split(" ")
        address, _, revision = source.partition("#")
        key = (name, version, f"{address}#{revision[:8]}" if source else None)
        if key in built:
            fail(f"{name} {version} is compiled by a release build and the notice has no entry for it")
        if key in tested:
            why = "only a test of a release program uses it"
        elif key in elsewhere:
            why = "only a platform that no release is built for uses it"
        else:
            why = "only features that other packages of the workspace turn on bring it in"
        lines.append(f"{gap} | {why}")
    return lines


def make(program, kr_release, work):
    records = collect(program, work)
    kept, files = keep_texts()
    body = render(gather(records, kept, files))
    entries = os.path.join(work, "entries.txt")
    with open(entries, "w", encoding="utf-8", newline="\n") as target:
        target.write(body)
    gaps_list = [line for line in run([kr_release, "notice-gaps", "--checkout", ROOT, "--notice", entries]).stdout.split("\n") if line]
    lines = reasons(gaps_list, read_programs(), about_targets(), dict(os.environ))
    return body + (UNUSED + "".join(f"  - {line}\n" for line in lines) if lines else "")


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
        print(f"generate-notices: docs/releases/third-party-notices.txt is not what the lock makes: {REPAIR}",
              file=sys.stderr)
        return 1
    print("generate-notices: the committed notice is the one the lock makes")
    return 0


HOME = [None]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
REPOSITORY = "git+https://example.org/forked?rev=abcdef0123456789#abcdef0123456789"


def synthetic(name, version, source=REGISTRY, authors=(), licences=(), folder=None, declared="MIT"):
    """One crate as `gather` takes it: what cargo-about answered, where its package is and what it declares."""
    key = identity(name, version, source)
    return key, {"authors": list(authors), "source": source, "licences": list(licences)}, folder or HOME[0], declared


def made_up(crates, paths=(), members_=(), name="programs"):
    answers = {key: answer for key, answer, _, _ in crates}
    return {"name": name, "listed": set(answers), "answers": answers,
            "roots": {key: folder for key, _, folder, _ in crates},
            "declared": {key: declared for key, _, _, declared in crates}, "paths": set(paths),
            "members": {member: {"root": "/nowhere", "version": "0.1.0", "authors": [], "licence": "MIT"} for member in members_}}


def self_test():
    with tempfile.TemporaryDirectory(prefix="kr-notices-test-") as scratch:
        return self_checks(scratch)


def self_checks(scratch):
    """Holds the reading of cargo's lines, the placeholder refusal, the choice of a crate's texts, the
    checks on the kept texts and the text's layout to what a notice must do, over made-up crates and
    folders."""
    failed = 0
    HOME[0] = os.path.join(scratch, "home")
    os.makedirs(HOME[0])

    def expect(what, condition):
        nonlocal failed
        print(("PASS " if condition else "FAIL ") + what)
        failed += 0 if condition else 1

    def refuses(what, call, words):
        try:
            call()
        except SystemExit as stop:
            expect(what, words in str(stop))
        except Exception:
            expect(what, False)
        else:
            expect(what, False)

    def made(call):
        """What `call` returns, or an empty text where it refuses."""
        try:
            return call()
        except SystemExit:
            return ""

    mit = "MIT License\n\nCopyright (c) 2020 A Person\n\nPermission is hereby granted, free of charge, to any person\n"
    template = "MIT License\n\nCopyright (c) <year> <copyright holders>\n\nPermission is hereby granted, free of charge\n"
    bsd = "Copyright (c) 2020 Tailscale Inc\n\nRedistribution and use in source and binary forms\n\nNeither the name\n"
    gpl = "Copyright (C) <year>  <name of author>\n\nGNU GENERAL PUBLIC LICENSE\n"

    expect("a crates.io line is a crate", tree_line("serde v1.0.1") == ("serde", "1.0.1", None))
    expect("a proc macro mark and a repeat mark are dropped", tree_line("serde_derive v1.0.1 (proc-macro) (*)") == ("serde_derive", "1.0.1", None))
    expect("a path line is a path package", tree_line("kr-cli v0.1.0 (/home/a/crates/kr-cli)") == ("path", "kr-cli", "0.1.0"))
    expect("a repository line keeps the repository and eight letters of the revision",
           tree_line("forked v0.1.0 (https://example.org/forked?rev=abcdef0123456789#abcdef01)")
           == identity("forked", "0.1.0", REPOSITORY))
    refuses("a registry that is not crates.io is refused", lambda: identity("x", "1", "registry+https://other.example/index"), "not crates.io")
    expect("the placeholder of a permissive template is found", placeholder(template) == "<copyright holders>")
    expect("the GPL's own paragraph is not a placeholder", placeholder(gpl) is None)
    expect("a text names the one licence it announces", identify(mit) == "MIT" and identify(bsd) == "BSD-3-Clause")
    expect("a text of two licences names none", identify(mit + bsd) is None)

    def licences(text, own=True):
        return [("MIT", "MIT License", text, own)]

    plain = synthetic("plain", "1.0.0", authors=["A"], licences=licences(mit))
    forked = synthetic("forked", "0.1.0", REPOSITORY, licences=licences(mit))
    nothing = {"texts": [], "crates": [], "works": []}
    blocks = gather([made_up([plain, forked])], nothing, {})
    text = render(blocks)
    expect("a text that two crates share appears once", text.count("Permission is hereby granted") == 1)
    expect("a crate that has a file of its own has its entry", "  - plain 1.0.0 | programs | A\n" in text)
    expect("a crate from a repository names its source", "source https://example.org/forked?rev=abcdef0123456789#abcdef0123456789\n" in text)
    refuses("a text with a template's placeholder is refused",
            lambda: gather([made_up([synthetic("bad", "1.0.0", licences=licences(template))])], nothing, {}), "placeholder <copyright holders>")
    refuses("a path package that is not a member is refused",
            lambda: record("programs", set(), {"stranger"}, {}, {}, {}), "stranger")
    refuses("a crate cargo tree lists and cargo-about does not answer for is refused",
            lambda: record("programs", {("lost", "1.0.0", None)}, set(), {}, {}, {}), "lost 1.0.0")

    empty = os.path.join(scratch, "empty-1.0.0")
    os.makedirs(empty)
    refuses("a crate that ships no file and has no kept text is refused",
            lambda: gather([made_up([synthetic("empty", "1.0.0", licences=licences(template, False), folder=empty)])], nothing, {}),
            "empty 1.0.0 ships no licence file")
    folder = os.path.join(scratch, "bare-1.0.0")
    os.makedirs(folder)
    with open(os.path.join(folder, "LICENSE-BSD3"), "w", encoding="utf-8") as target:
        target.write(bsd)
    with open(os.path.join(folder, "COPYRIGHT"), "w", encoding="utf-8") as target:
        target.write("Copyright 2020 The Authors\n")
    directory = os.path.join(scratch, "texts")
    os.makedirs(directory)
    kept_text = "MIT License\n\nCopyright (c) 2025 N0, INC.\n\nPermission is hereby granted, free of charge\n"
    with open(os.path.join(directory, "n0-MIT"), "w", encoding="utf-8") as target:
        target.write(kept_text)
    digest = hashlib.sha256(kept_text.encode("utf-8")).hexdigest()
    listing = os.path.join(scratch, "notice-texts.json")

    def keep(texts, crates, works):
        with open(listing, "w", encoding="utf-8") as target:
            json.dump({"texts": texts, "crates": crates, "works": works}, target)
        return keep_texts(listing, directory)

    item = {"id": "n0-MIT", "licence": "MIT", "source": "https://example.org/n0/LICENSE-MIT", "sha256": digest}
    pinned = {"name": "bare", "version": "1.0.0", "texts": ["n0-MIT"]}
    refuses("a kept text with another digest is refused", lambda: keep([{**item, "sha256": "0" * 64}], [], []), "has digest")
    refuses("a kept text that is not in the folder is refused", lambda: keep([{**item, "id": "gone"}], [], []), "does not hold")
    kept, files = keep([item], [pinned], [])
    dual = os.path.join(scratch, "dual-1.0.0")
    os.makedirs(dual)
    for file_name, text in (("LICENSE-MIT", mit), ("LICENSE-APACHE", "Apache License\nVersion 2.0, January 2004\n")):
        with open(os.path.join(dual, file_name), "w", encoding="utf-8") as target:
            target.write(text)
    text = render(gather([made_up([synthetic("dual", "1.0.0", licences=licences(template, False), folder=dual,
                                             declared="MIT OR Apache-2.0")])], nothing, {}))
    expect("a crate under MIT or Apache is carried under the one it is recorded under",
           "Permission is hereby granted" in text and "Apache License" not in text)
    both = synthetic("bare", "1.0.0", licences=licences(template, False), folder=folder)
    text = render(gather([made_up([both])], kept, files))
    expect("a crate whose package lacks its recorded licence's text gets the kept one besides its own file",
           "Copyright (c) 2025 N0, INC." in text and "Copyright (c) 2020 Tailscale Inc" in text)
    expect("a crate's notice files are carried", "Notice file: Notice file" in text and "Copyright 2020 The Authors" in text)
    expect("a kept text names its source on the entry", "text https://example.org/n0/LICENSE-MIT" in text)
    refuses("a kept text for a crate that no release build compiles is refused",
            lambda: gather([made_up([plain])], kept, files), "no release build compiles")
    refuses("a kept text for a crate that ships its licence text is refused",
            lambda: gather([made_up([plain])], *keep([item], [{**pinned, "name": "plain"}], [])), "ships the licence text itself")
    kept, files = keep([item], [], [])
    refuses("a kept text that nothing uses is refused", lambda: gather([made_up([plain])], kept, files), "no crate or work uses")
    work = {"name": "libx", "version": "1.0", "carried_by": {"name": "gone", "version": "1.0.0"}, "text": "n0-MIT"}
    kept, files = keep([item], [], [work])
    refuses("a bundled work whose carrier is not compiled is refused", lambda: gather([made_up([plain])], kept, files), "which no release build compiles")
    work["carried_by"] = {"name": "plain", "version": "1.0.0"}
    kept, files = keep([item], [], [work])
    text = render(gather([made_up([plain])], kept, files))
    expect("a bundled work has its entry and its text", "  - libx 1.0 | programs |  | bundled in plain 1.0.0, text https://example.org/n0/LICENSE-MIT\n" in text)

    refuses("a crate that cargo tree lists and cargo metadata cannot place is refused",
            lambda: record("programs", {plain[0]}, set(), {}, {plain[0]: plain[1]}, {}), "cargo metadata finds no package for 1 crates")
    expect("a crate from a Git repository and the same crate from crates.io are two entries",
           render(gather([made_up([synthetic("twin", "1.0.0", licences=licences(mit)),
                                   synthetic("twin", "1.0.0", REPOSITORY, licences=licences(mit))])], nothing, {})).count("  - twin 1.0.0 | programs") == 2)

    def archive(name, member):
        path = os.path.join(scratch, name)
        with tarfile.open(path, "w:xz") as tar:
            tar.addfile(member)
        return path

    into = os.path.join(scratch, "into")
    os.makedirs(into)
    outside = tarfile.TarInfo("../outside")
    refuses("an archive member outside the folder it unpacks to is refused",
            lambda: safe_extract(archive("outside.tar.xz", outside), into), "lands outside the folder it unpacks to")
    link = tarfile.TarInfo("link")
    link.type, link.linkname = tarfile.SYMTYPE, "../../elsewhere"
    refuses("a link that points outside the folder it unpacks to is refused",
            lambda: safe_extract(archive("symbolic.tar.xz", link), into), "a link to ../../elsewhere outside the folder")
    hard = tarfile.TarInfo("hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "../elsewhere"
    refuses("a hard link that points outside the folder it unpacks to is refused",
            lambda: safe_extract(archive("hard.tar.xz", hard), into), "a link to ../elsewhere outside the folder")
    refuses("a fish configuration that sets message localization twice is refused",
            lambda: fish_features(["-DWITH_MESSAGE_LOCALIZATION=ON", "-DWITH_MESSAGE_LOCALIZATION=OFF"]), "reads no further")
    bytes_file = os.path.join(scratch, "latin1.txt")
    with open(bytes_file, "wb") as target:
        target.write(b"Copyright \xa9 2020\n")
    refuses("a file that is not UTF-8 text is refused", lambda: read_text(bytes_file), "is not UTF-8 text")

    shipped = os.path.join(scratch, "shipped-1.0.0")
    os.makedirs(shipped)
    with open(os.path.join(shipped, "LICENSE-MIT"), "w", encoding="utf-8") as target:
        target.write(template)
    standard = os.path.join(scratch, "standard")
    os.makedirs(standard)
    with open(os.path.join(standard, "mit-plain"), "w", encoding="utf-8") as target:
        target.write("Permission is hereby granted, free of charge\nline two\nline three\n")
    plain_item = {"id": "mit-plain", "licence": "MIT", "source": "https://example.org/spdx/MIT.txt",
                  "sha256": hashlib.sha256(b"Permission is hereby granted, free of charge\nline two\nline three\n").hexdigest(),
                  "edit": {"removed": "the copyright line"}, "name": "a standard text"}
    with open(listing, "w", encoding="utf-8") as target:
        json.dump({"texts": [plain_item], "crates": [{"name": "shipped", "version": "1.0.0", "texts": ["mit-plain"]}], "works": []}, target)
    kept_plain, files_plain = keep_texts(listing, standard)
    text = made(lambda: render(gather([made_up([synthetic("shipped", "1.0.0", licences=licences(template), folder=shipped)])],
                                      kept_plain, files_plain)))
    expect("a kept text answers a crate whose own file holds a placeholder",
           "Permission is hereby granted" in text and "<YEAR>" not in text and "<copyright holders>" not in text
           and "text https://example.org/spdx/MIT.txt without its copyright line" in text and "(a standard text)" in text)

    fish_folder = os.path.join(scratch, "fish-widecharwidth")
    os.makedirs(fish_folder)
    with open(os.path.join(fish_folder, "LICENSE"), "w", encoding="utf-8") as target:
        target.write("CC0 1.0 Universal\n")
    fish_blocks = Blocks()
    made(lambda: fish_member(fish_blocks, "widecharwidth", {"root": fish_folder, "version": "0.0.0", "authors": [], "licence": "CC0-1.0"}))
    text = render(fish_blocks)
    expect("a crate of fish's own workspace under CC0-1.0 is carried with its licence file",
           "Licence: CC0-1.0 (the fish package, LICENSE)" in text and "CC0 1.0 Universal" in text)

    lined = "one\ntwo\nthree\nfour\n"
    with open(os.path.join(standard, "lined"), "w", encoding="utf-8") as target:
        target.write(lined)
    lined_item = {"id": "lined", "licence": "MIT", "source": "https://example.org/Readme", "lines": [2, 3],
                  "sha256": hashlib.sha256(lined.encode("utf-8")).hexdigest()}
    with open(listing, "w", encoding="utf-8") as target:
        json.dump({"texts": [lined_item], "crates": [], "works": []}, target)
    expect("a kept text shows the lines asked for", keep_texts(listing, standard)[1]["lined"]["text"] == "two\nthree\n")
    with open(listing, "w", encoding="utf-8") as target:
        json.dump({"texts": [{**lined_item, "lines": [3, 9]}], "crates": [], "works": []}, target)
    refuses("a kept text with lines outside the file is refused", lambda: keep_texts(listing, standard), "asks for lines 3 to 9 of lined, which has 4 lines")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
