#!/usr/bin/env python3
"""Makes the third-party notice of a release, or holds the committed one to what the lock now makes.

    generate-notices.py write [--product programs|companion] --kr-release PROGRAM [--cargo-about PROGRAM] [--askalono PROGRAM] [--work DIR]
    generate-notices.py check [--product programs|companion] --kr-release PROGRAM [--cargo-about PROGRAM] [--askalono PROGRAM] [--work DIR]
    generate-notices.py self-test [--askalono PROGRAM]

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

What the notice says for each crate. The licence files of the crate's own package (a name that starts
`LICENSE`, `LICENCE`, `COPYING` or `UNLICENSE`), without a file that is the text of an alternative of
a dual licence (a file that holds only the header of that alternative stays, as a statement), and every
notice file of the package (a name that starts `COPYRIGHT`, `NOTICE`, `NOTICES` or `PATENTS`, or holds
`THIRD-PARTY`). askalono reads each file, offline, over the SPDX licence list at one
pinned revision, without regard to case, punctuation and line breaks, and names every licence the file
holds; the file is carried under the licence it is, or under a heading that says it names a licence and
holds none of its text. A crate under several licences that all apply has the text of each. Where a
package holds no text of a licence it is recorded under (a file that only names the licence is not a
text of it), or a file holds a template's placeholder, the upstream text that `scripts/notice-texts.json`
keeps in `docs/releases/notice-texts/`, with its source and digest, is carried beside the package's own
files. A kept text for a crate from Git names the package's source and revision, and one for a
JavaScript package names `npm`. A kept text for a crate
that ships its own, or for a crate no release build compiles, stops the run, and so does a kept text that
is not the licence the listing says it is. The same file names the licences of the works that a crate
bundles and builds in (libsodium, llama.cpp and ggml, PCRE2). An excerpt of a source file names `file`,
its path in the package that carries the work, and ends where the file's licence comment ends. A
bundled work names the source of the crate that carries it when that crate comes from Git, and stops the
run when the source moves. fish's `COPYING`, its `doc_src/license.rst`
and the licence file of each of its workspace crates are read from its pinned archive. A text that holds
a template's placeholder stops the run.

The lock also names crates that no release build compiles. `kr-release notice-gaps` lists the crates
the lock takes into the release programs that the entries do not name, and they are written last,
each with the reason it is left out, so that `kr-release` can hold the committed text to the lock
and a crate added to the lock stops a release until this runs again.

`--product companion` makes the notice of the companion application instead,
`docs/releases/companion-third-party-notices.txt`. It covers the crates of the package that
`scripts/companion-notice.json` names, with the features and for the platforms that file lists, made
as above, and the production JavaScript packages of the interface, which `pnpm licenses` lists from the
packages that `pnpm install --frozen-lockfile --prod --filter "@kalareach/companion..."` installed. A
JavaScript package is recorded under the first of its licences that `about.toml` lists, and its texts
are chosen as a crate's are. An entry of `scripts/notice-texts.json` is for the release programs' notice
unless it lists `"products": ["companion"]`, or both.

`about.toml` says which licences a crate may be used under and which one a crate that offers
several is recorded under. `check` makes the notice again and refuses a committed one that differs.
The merge reads no clock and no path of the machine, so the same lock gives the same bytes on every
machine.

cargo-about runs offline over the sources cargo has fetched, because online it fetches a missing
licence file from the crate's repository, and the notice would then depend on that server. The fish
preparation fetches the pinned fish archive and its crates, and the SPDX licence list is fetched at its
pinned revision; the rest runs offline.
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
import textwrap

ABOUT_VERSION = "0.9.3"
# The licence reader: askalono, run over the SPDX licence list at this revision (list version 3.29.0).
ASKALONO_VERSION = "0.5.0"
SPDX_REPOSITORY = "https://github.com/spdx/license-list-data"
SPDX_REVISION = "31ba1a50e5397e00a304dbadc76531740e89ee48"
# The lowest score at which askalono, and cargo-about, take a match for a licence.
MATCH_SCORE = 0.8
READ_PASSES = 6
NO_MATCH = "Confidence threshold not high enough for any known license"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTICE = os.path.join(ROOT, "docs", "releases", "third-party-notices.txt")
CONFIG = os.path.join(ROOT, "about.toml")
COMPANION_NOTICE = os.path.join(ROOT, "docs", "releases", "companion-third-party-notices.txt")
COMPANION_CONFIG = os.path.join(ROOT, "scripts", "companion-notice.json")
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
PLACEHOLDER = re.compile(r"<(owner|copyright holders?|organi[sz]ation|owner organi[sz]ation name)>|\[(year|fullname)\]", re.IGNORECASE)
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|unlicen[cs]e)", re.IGNORECASE)
NOTICE_FILE = re.compile(r"^(copyright|notices?|patents)|third[-_ ]?party", re.IGNORECASE)

# A text that is another licence's text where a package records that licence: MITNFA is the MIT licence
# and a rule on modified copies, and Unicode-3.0 is the text that Unicode-DFS-2016 became.
VARIANTS = {"MITNFA": "MIT", "Unicode-3.0": "Unicode-DFS-2016"}
# What fish's licence file COPYING names for the licences of the rest of fish's code, whose terms the
# notice carries from the pinned archive and requires.
FISH_LICENCES = os.path.join("doc_src", "license.rst")
STATEMENT = "this file names a licence and holds none of its text"
# What a line of a source file's comment starts with, in the languages of the bundled works.
COMMENT_LINE = ("//", "/*", "*")

HEADER = """\
THIRD-PARTY NOTICES

KalaReach is distributed under the BSD-3-Clause licence in share/LICENSE. Each shell package keeps
its own licence in its directory under shells/. This file carries the licence texts and notices of
the third-party crates that the release's programs and its fish package are built from, as the
crates' own packages state them, and the licence texts of the libraries that some of those crates
bundle. It does not cover the companion application. It also carries fish's own licence file,
COPYING, and doc_src/license.rst, the file that COPYING names for the licences of the rest of fish's
code, each as the pinned fish archive has it.

The list covers every platform a release is built for, so the list for one archive is a subset of
it. A crate that is offered under several licences is recorded under the one this project takes it
under. Each block lists the crates that use a text and then gives the text, under the licence it is. A
file that holds the texts of several licences is one block under a heading that names all of them, and
a file that holds no licence's text, only a statement that names a licence or the header of one, has a
heading that says so. An entry gives the crate, its version, whether the programs, the fish package or
both are built from it, and the authors its package names. The entry of a crate under the Mozilla Public
License 2.0, or taken from a Git repository, names where its source is. Where a package ships no text of
a licence it is recorded under, the notice carries the upstream text beside the package's own files, and
the entry names the upstream file.
"""

COMPANION_HEADER = """\
THIRD-PARTY NOTICES

KalaReach is distributed under the BSD-3-Clause licence. This file carries the licence texts and
notices of the third-party software that the KalaReach companion application is built from: the Rust
crates of its native program, for every platform it is built for, and the JavaScript packages in the
production dependency closure of its interface, as the packages themselves state them, and the licence
texts of the libraries that some of those crates bundle. It does not yet list the native libraries that
the Android and iOS builds link.

The list covers every platform the application is built for, so the list for one platform is a subset
of it. A package that is offered under several licences is recorded under the one this project takes
it under. Each block lists the packages that use a text and then gives the text, under the licence it
is. A file that holds the texts of several licences is one block under a heading that names all of
them, and a file that holds no licence's text, only a statement that names a licence or the header of
one, has a heading that says so. An entry gives the package, its version, whether the Rust crates
(rust) or the JavaScript packages (javascript) are built from it, and the authors its package names.
The entry of a crate under the Mozilla Public License 2.0, or taken from a Git repository, names where
its source is. Where a package ships no text of a licence it is recorded under, the notice carries the
upstream text beside the package's own files, and the entry names the upstream file.
"""

COMPANION_UNUSED = """\

====================================================================================================
Crates the lock reaches that no companion build compiles
====================================================================================================

The lock names these crates among the dependencies of the companion application, and no companion
build compiles them in. Each line says why. They are listed so that a crate added to the lock fails a
check until this notice is made again.

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
    "build kr-release with `cargo build -p kr-release`, fetch the crates with `cargo fetch --locked`, put "
    "cargo-about 0.9.3 and askalono 0.5.0 on the PATH, run `python3 scripts/generate-notices.py write "
    "--kr-release target/debug/kr-release`, and commit the result"
)
COMPANION_REPAIR = (
    "install the production packages with `pnpm install --frozen-lockfile --prod --filter "
    "\"@kalareach/companion...\"`, build kr-release with `cargo build -p kr-release`, fetch the crates "
    "with `cargo fetch --locked`, put cargo-about 0.9.3 and askalono 0.5.0 on the PATH, run "
    "`python3 scripts/generate-notices.py write --product companion --kr-release target/debug/kr-release`, "
    "and commit the result"
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


def git_environment():
    """The environment of every call that reaches a Git repository: Git reads no configuration of the
    account that runs this, whose rewrite of an https address to ssh would ask for a key."""
    return {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def restricted(cargo_home):
    """The environment of the calls that reach a Git repository through cargo."""
    return {
        **git_environment(),
        "CARGO_HOME": cargo_home,
        "RUSTUP_TOOLCHAIN": toolchain(),
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
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


class Reader:
    """Says which licences a text is. It runs askalono over the SPDX licence list at one revision, offline
    once the list is fetched. askalono reads each text normalised for case, punctuation and white space,
    so a line break inside a phrase changes nothing. One run names one licence in a text, so the reader
    blanks the lines that run matched and reads what is left, until nothing that is left matches. A match
    is the licence's text only when askalono's kind for it is `original`; a header match is a statement."""

    def __init__(self, program, work):
        said = run([program, "--version"]).stdout.strip()
        if said != f"askalono {ASKALONO_VERSION}":
            fail(f"{program} says '{said}' and the notice is read with askalono {ASKALONO_VERSION}")
        self.program = program
        self.directory = os.path.join(work, "reader")
        os.makedirs(self.directory, exist_ok=True)
        self.cache = self.spdx_cache()
        self.known = {}
        with open(os.path.join(self.directory, "spdx-list", "json", "licenses.json"), encoding="utf-8") as source:
            self.names = {item["licenseId"]: item["name"] for item in json.load(source)["licenses"]}

    def of(self, text):
        """The licences a text is, once `prepare` has read it."""
        return self.known[text]

    def prepare(self, texts):
        """Reads the texts not read yet, all in one run."""
        new = sorted({text for text in texts if text not in self.known})
        if new:
            for text, found in zip(new, self.read(new)):
                self.known[text] = refine(found, text)

    def spdx_cache(self):
        """The cache askalono matches against, made from the pinned revision of the SPDX list."""
        listing = os.path.join(self.directory, "spdx-list")
        os.makedirs(listing, exist_ok=True)
        environment = git_environment()
        if not os.path.isdir(os.path.join(listing, ".git")):
            run(["git", "init", "-q", listing], env=environment)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=listing, env=environment, capture_output=True, text=True)
        if head.stdout.strip() != SPDX_REVISION:
            run(["git", "fetch", "-q", "--depth", "1", SPDX_REPOSITORY, SPDX_REVISION], cwd=listing, env=environment)
            run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=listing, env=environment)
            head = run(["git", "rev-parse", "HEAD"], cwd=listing, env=environment)
            if head.stdout.strip() != SPDX_REVISION:
                fail(f"the SPDX licence list fetched is at {head.stdout.strip()} and the notice is read against {SPDX_REVISION}")
        cache = os.path.join(self.directory, "spdx.cache")
        run([self.program, "--cache", cache, "cache", "load-spdx", os.path.join(listing, "json", "details")])
        return cache

    def batch(self, options, names):
        """askalono's answer for each of these files, in the order of the files: each answer names the
        file it is for."""
        done = subprocess.run([self.program, "--cache", self.cache, "--format", "json", "id", *options, "--batch"],
                              input="\n".join(names) + "\n", capture_output=True, text=True)
        answers = [json.loads(line) for line in done.stdout.splitlines()]
        if done.returncode != 0 or len(answers) != len(names):
            fail(f"askalono answered {len(answers)} lines for {len(names)} texts, exit {done.returncode}:\n{done.stderr[-1500:]}")
        by_path = {}
        for answer in answers:
            path = answer["path"].rstrip("\n")
            if path not in names or path in by_path:
                fail(f"askalono answered for {path}, a text that was not asked for or is answered twice")
            by_path[path] = answer
        for answer in answers:
            if "error" in answer and answer["error"] != NO_MATCH:
                fail(f"askalono could not read a text: {answer['error']}")
        return [None if "error" in by_path[name] else by_path[name]["result"] for name in names]

    def read(self, texts):
        """The licences each text is, as a set of SPDX names: empty for a text that is none of them. Two
        readings are put together: the one that looks for every licence inside the text (`-m`), and the
        one that takes the text whole and, where it finds a block of a licence inside, blanks the block
        and reads what is left."""
        found = [set() for _ in texts]
        regions = [[] for _ in texts]
        lines = [text.split("\n") for text in texts]
        names = []
        for index, text in enumerate(texts):
            name = os.path.join(self.directory, f"{index}.txt")
            with open(name, "w", encoding="utf-8", newline="\n") as target:
                target.write(text)
            names.append(name)
        for index, result in enumerate(self.batch(["-m"], names)):
            if result is not None:
                inside = [part for part in result["containing"] if part["score"] >= MATCH_SCORE]
                found[index] |= {part["license"]["name"] for part in inside if is_text(part)}
                regions[index] = [(*part["line_range"], part["license"]["name"]) for part in inside if is_text(part)]
        pending = list(range(len(texts)))
        for _ in range(READ_PASSES):
            if not pending:
                break
            for index in pending:
                with open(names[index], "w", encoding="utf-8", newline="\n") as target:
                    target.write("\n".join(lines[index]))
            again = []
            for index, result in zip(pending, self.batch(["--optimize"], [names[index] for index in pending])):
                if result is None:
                    continue
                if result["license"] is not None and result["score"] >= MATCH_SCORE and is_text(result):
                    found[index].add(result["license"]["name"])
                inside = [part for part in result["containing"] if part["score"] >= MATCH_SCORE]
                for part in inside:
                    first, last = part["line_range"]
                    clash = is_text(part) and disagreeing(regions[index], first, last, part["license"]["name"])
                    if clash:
                        fail(f"askalono reads lines {clash[0]} to {clash[1]} of a text as {clash[2]} in one reading and as {clash[3]} in the other")
                    if is_text(part):
                        found[index].add(part["license"]["name"])
                    blank(lines[index], first, last)
                if inside:
                    again.append(index)
            pending = again
        return [frozenset(names) for names in found]


def blank(lines, first, last):
    """Blanks the lines of a match: askalono's range starts at the index of a line and ends before the index `last`."""
    lines[first:last] = [""] * (last - first)


def disagreeing(regions, first, last, name):
    """The first region of the other reading that overlaps these lines and names another licence, as the
    lines they share (counted from 1), its licence and this one; None where there is none. Only matches
    that are a licence's text are regions: a header makes no claim on the lines it is found in."""
    for start, end, other in regions:
        if other != name and max(start, first) < min(end, last):
            return max(start, first) + 1, min(end, last), other, name
    return None


def is_text(match):
    """Whether askalono's match is the text of a licence (its kind is `original`) and not a header of it,
    which names the licence and holds none of its terms."""
    return match["license"]["kind"] == "original"


def refine(found, text):
    """askalono's cache has no text of Unicode-3.0 and reads it as Unicode-DFS-2016, whose text is the
    same but for a few words; the title of the text tells them apart. askalono reads the Markdown licence
    of John Gruber, the three-clause BSD text with "Markdown" where BSD-3-Clause names the holder, as
    BSD-3-Clause-Clear, which adds a limit on the grant and a sentence on patent rights that Gruber's
    text does not have; his name tells them apart."""
    if "Unicode-DFS-2016" in found and re.search(r"UNICODE\s+LICENSE\s+V3", text, re.IGNORECASE):
        return (found - {"Unicode-DFS-2016"}) | {"Unicode-3.0"}
    if "BSD-3-Clause-Clear" in found and "John Gruber" in text:
        return (found - {"BSD-3-Clause-Clear"}) | {"BSD-3-Clause"}
    return found


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


def placeholder(text):
    found = PLACEHOLDER.search(text)
    return found.group(0) if found else None


def keep_texts(listing=TEXTS, directory=TEXTS_DIRECTORY):
    """The upstream texts kept in the repository, each held to its digest."""
    with open(listing, encoding="utf-8") as source:
        kept = json.load(source)
    for entry in kept["crates"] + kept["works"]:
        unknown = sorted(set(entry.get("products", [])) - set(PRODUCT_BUILDS))
        if unknown:
            fail(f"scripts/notice-texts.json lists the product {unknown[0]} for {entry['name']}, which is neither programs nor companion")
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


def kept_source(text):
    """The words that say where a kept text comes from and what was done to it."""
    words = f"text {text['source']}"
    span = text.get("excerpt") or text.get("lines")
    if span:
        words += f", lines {span[0]} to {span[1]}"
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

    def __init__(self, reader):
        self.reader = reader
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

    def add_licence(self, text, crate, authors, origin, source, file_name, extra=None):
        """A licence file, under the licence or licences its text is, or as a statement where its text
        is none of them."""
        self.reader.prepare([text])
        found = sorted(self.reader.of(text))
        if not found:
            self.add("statement", file_name, "", text, crate, authors, origin, source, extra)
            return
        names = [self.reader.names.get(identifier, identifier) for identifier in found]
        self.add("licence", " and ".join(found), " and ".join(names) + (", in one file" if len(found) > 1 else ""),
                 text, crate, authors, origin, source, extra)


def entry_line(key, entry, licence):
    name, version, _ = key
    fields = [f"{name} {version}", " and ".join(sorted(entry["origins"])), ", ".join(entry["authors"])]
    source = entry["source"]
    if source is not None and (licence == "MPL-2.0" or source.startswith("git+")):
        fields.append(f"source {source_of(source, name, version)}")
    if entry["extra"]:
        fields.append(entry["extra"])
    return ("  - " + " | ".join(fields)).rstrip()


def render(blocks, header=HEADER):
    ordered = sorted(blocks.texts.values(), key=lambda block: (block["kind"], block["id"], min(block["crates"]), block["text"]))
    rule = "=" * 100
    parts = [header]
    for block in ordered:
        title = {"licence": f"Licence: {block['id']} ({block['name']})",
                 "notice": f"Notice file: {block['id']}" + (f" ({block['name']})" if block["name"] else ""),
                 "statement": f"Licence statement: {block['id']} ({STATEMENT})"}[block["kind"]]
        parts.append(f"\n{rule}\n{title}\n{rule}\n\nUsed by:\n\n")
        for key in sorted(block["crates"]):
            parts.append(entry_line(key, block["crates"][key], block["id"]) + "\n")
        parts.append("\n" + block["text"])
    return "".join(parts)


def in_scope(item, product):
    """Whether a kept entry is for this product's notice: the release programs' unless it says otherwise."""
    return product in item.get("products", ["programs"])


def pinned_for(kept, name, version, where, product):
    """The kept entry for a crate, or None. An entry for a crate taken from Git names the package's
    source as cargo tree gives it, the repository and the first eight letters of its revision. An
    entry for a JavaScript package names `npm`."""
    for item in kept["crates"]:
        if in_scope(item, product) and item["name"] == name and item["version"] == version and item.get("package") == where:
            return item
    return None


def declared_tokens(expression):
    return {word for word in re.findall(r"[A-Za-z0-9.+-]+", expression) if word not in ("AND", "OR", "WITH")}


def alone(files, required, declared, reader):
    """The licence files of a package without the ones that are only an alternative the package
    offers: a crate under `MIT OR Apache-2.0` is taken under MIT, and its Apache file is the alternative
    that this project does not take it under. A file is dropped only when the reader names at least one
    licence in it and every licence it names is declared and not required. A file in which the reader
    names no licence, such as one that holds only the header of the alternative, stays and is carried as
    a statement; so does a file that holds a required licence beside another."""
    alternatives = declared - set(required)
    kept = []
    for file_name, text in files:
        found = reader.of(text)
        if found and found <= alternatives:
            continue
        kept.append((file_name, text))
    return kept


def lacking(required, texts, reader):
    """The required licences that none of the texts is. A text that is a licence with one clause more
    (MITNFA, the MIT licence and a rule on modified copies) is that licence's text."""
    covered = set()
    for text in texts:
        for found in reader.of(text):
            covered |= {found, VARIANTS.get(found, found)}
    return sorted(set(required) - covered)


PRODUCT_BUILDS = {"programs": "release build", "companion": "companion build"}


def texts_of_other_products(kept, product):
    """The kept texts that only entries of another product's notice use."""
    found = set()
    for item in kept["crates"]:
        if not in_scope(item, product):
            found.update(item["texts"])
    for work in kept["works"]:
        if not in_scope(work, product):
            found.update(work["texts"])
    return found


def gather(records, kept, files, reader, product="programs"):
    """Every crate's texts, put in blocks, with the checks on what the kept texts stand for."""
    blocks = Blocks(reader)
    plans = {}
    reading = [text["text"] for text in files.values()]
    for each in records:
        for key in by_identity(each["answers"]):
            answer = each["answers"][key]
            folder = each["roots"][key]
            item = pinned_for(kept, key[0], key[1], key[2], product)
            taken = [normal(t) for _, _, t, own in answer["licences"] if own]
            owned = [(name, read_text(os.path.join(folder, name))) for name in licence_files(folder)]
            if item is not None:
                # A file that holds a template's placeholder is the package's own template, not its text.
                taken = [t for t in taken if not placeholder(t)]
                owned = [(f, t) for f, t in owned if not placeholder(t)]
            plans[(each["name"], key)] = (item, taken, owned)
            reading += taken + [t for _, t in owned]
    reader.prepare(reading)
    used_texts, used_crates = set(), set()
    compiled_crates = {}
    for each in records:
        for key in by_identity(each["answers"]):
            answer = each["answers"][key]
            name, version, where = key
            folder = each["roots"][key]
            compiled_crates.setdefault((name, version, where), {})[each["name"]] = folder
            crate = (name, version, where)
            args = (answer["authors"], each["name"], answer["source"])
            required = sorted({i.split(" WITH ")[0] for i, _, _, _ in answer["licences"]})
            item, taken, owned = plans[(each["name"], key)]
            carried = alone(owned, required, declared_tokens(each["declared"][key]), reader)
            notices = [(n, read_text(os.path.join(folder, n))) for n in files_named(folder, NOTICE_FILE)]
            named = {}
            for n, t in notices:
                named.setdefault(t, n)
            carried += [(named.get(t), t) for t in taken if t not in {text for _, text in carried}]
            missing = lacking(required, [t for _, t in carried], reader)
            if item is not None and not missing:
                fail(f"scripts/notice-texts.json keeps a text for {name} {version}, whose package ships the licence text itself")
            if missing and item is None:
                elsewhere = sorted(c.get("package") or "crates.io" for c in kept["crates"] if in_scope(c, product) and (c["name"], c["version"]) == (name, version))
                note = f" (it keeps a text for this crate from {', '.join(elsewhere)}, not from {where or 'crates.io'})" if elsewhere else ""
                if carried:
                    held = ", ".join(f"{f or 'a file cargo-about took'} ({' and '.join(sorted(reader.of(t))) or 'no licence text'})" for f, t in carried)
                    fail(f"{name} {version} ships no text of {' and '.join(missing)}, its recorded licence, only {held}, and scripts/notice-texts.json keeps no text for it{note}")
                fail(f"{name} {version} ships no licence file and scripts/notice-texts.json keeps no text for it{note}")
            for file_name, text in carried:
                blocks.add_licence(text, crate, *args, file_name or "a file of the package")
            if item is not None:
                used_crates.add((item["name"], item["version"], item.get("package")))
                covered = [t for _, t in carried]
                for identifier in item["texts"]:
                    used_texts.add(identifier)
                    kept_text = files[identifier]
                    add_kept(blocks, kept_text, crate, *args, extra=kept_source(kept_text))
                    covered.append(kept_text["text"])
                still = lacking(required, [t for t in covered], reader)
                if still:
                    fail(f"scripts/notice-texts.json keeps texts for {name} {version} that are not the text of {' and '.join(still)}")
            for file_name, notice_text in notices:
                if notice_text not in {text for _, text in carried}:
                    blocks.add("notice", "Notice file", file_name, notice_text, crate, *args)
        for name in sorted(each["paths"]):
            if each["name"] == "fish":
                fish_member(blocks, name, each["members"][name])
    for item in kept["crates"]:
        identity_of_item = (item["name"], item["version"], item.get("package"))
        if in_scope(item, product) and identity_of_item not in used_crates:
            now = sorted({k[2] or "crates.io" for each in records for k in each["answers"] if k[:2] == identity_of_item[:2]})
            fail(f"scripts/notice-texts.json keeps a text for {item['name']} {item['version']} from {item.get('package') or 'crates.io'}, "
                 f"which no {PRODUCT_BUILDS[product]} compiles" + (f"; the lock has it from {', '.join(now)}" if now else ""))
    for work in kept["works"]:
        carried_by = work["carried_by"]
        carrier = (carried_by["name"], carried_by["version"], carried_by.get("package"))
        if not in_scope(work, product):
            if carrier in compiled_crates:
                fail(f"{work['name']} {work['version']} is bundled in {carrier[0]} {carrier[1]}, which a {PRODUCT_BUILDS[product]} "
                     f"compiles, and scripts/notice-texts.json lists the work for another product only")
            continue
        if carrier not in compiled_crates:
            now = sorted({k[2] or "crates.io" for k in compiled_crates if k[:2] == carrier[:2]})
            if now:
                fail(f"{work['name']} {work['version']} is bundled in {carrier[0]} {carrier[1]} from {carrier[2] or 'crates.io'}, "
                     f"and the lock has that crate from {', '.join(now)}")
            fail(f"{work['name']} {work['version']} is bundled in {carrier[0]} {carrier[1]}, which no {PRODUCT_BUILDS[product]} compiles")
        for identifier in work["texts"]:
            text = files[identifier]
            used_texts.add(identifier)
            for origin in sorted(compiled_crates[carrier]):
                if "excerpt" in text:
                    check_excerpt(text, compiled_crates[carrier][origin], carrier)
                add_kept(blocks, text, (work["name"], work["version"], None), [], origin, None,
                         extra=f"bundled in {carrier[0]} {carrier[1]}, {kept_source(text)}")
    for identifier in files:
        if identifier not in used_texts and identifier not in texts_of_other_products(kept, product):
            fail(f"scripts/notice-texts.json lists the text {identifier}, which no crate or work uses")
    return blocks


def check_excerpt(text, root, carrier):
    """A kept excerpt of a source file is the lines of that file in the package that carries the work, and
    it ends where the file's licence comment ends."""
    first, last = text["excerpt"]
    where = f"{text['id']} is kept as lines {first} to {last} of {text.get('file')}, and {carrier[0]} {carrier[1]}"
    path = os.path.join(root, text.get("file") or "")
    if not text.get("file") or not os.path.isfile(path):
        fail(f"{where} has no such file")
    with open(path, "rb") as source:
        try:
            lines = source.read().decode("utf-8").replace("\r\n", "\n").split("\n")
        except UnicodeDecodeError:
            fail(f"{path} is not UTF-8 text")
    if lines[first - 1:last] != text["text"].split("\n")[:-1]:
        fail(f"{where} holds other lines there")
    if last < len(lines) and lines[last].lstrip().startswith(COMMENT_LINE):
        fail(f"{text['id']} ends at line {last} of {text['file']}, and line {last + 1} still belongs to the comment")


def add_kept(blocks, text, crate, authors, origin, source, extra):
    """A kept text, under the licence its text is, which must be the one the listing says it is."""
    blocks.reader.prepare([text["text"]])
    found = blocks.reader.of(text["text"])
    if text.get("statement"):
        if found:
            fail(f"scripts/notice-texts.json lists {text['id']} as a statement, and its text is {' and '.join(sorted(found))}")
    elif text["licence"] not in found:
        fail(f"scripts/notice-texts.json lists {text['id']} as {text['licence']}, and its text is {' and '.join(sorted(found)) or 'none of the licences'}")
    blocks.add_licence(text["text"], crate, authors, origin, source, text["source"].rsplit("/", 1)[-1], extra)


def fish_member(blocks, name, member):
    """The licence files of a crate of fish's own workspace, with the notice file the licence file of
    fish names."""
    unknown = sorted(declared_tokens(member["licence"]) - FISH_MEMBER_LICENCES)
    if unknown:
        fail(f"{name} of the fish workspace declares {', '.join(unknown)}, a licence this notice has no text for")
    crate = (name, member["version"], None)
    shipped = []
    for file_name in licence_files(member["root"]):
        shipped.append(read_text(os.path.join(member["root"], file_name)))
        blocks.add_licence(shipped[-1], crate, member["authors"], "fish", None, file_name)
    # A member under fish's own licences, as fish and most of its crates are, has them carried by COPYING and
    # doc_src/license.rst. Any other member needs the text of its licence in its package, but for the
    # CC0-1.0 dedication, which asks for no notice.
    declared = declared_tokens(member["licence"])
    needed = [] if declared & set(FISH_OWN_LICENCES) else sorted(declared - {"CC0-1.0"})
    missing = lacking(needed, shipped, blocks.reader)
    if missing:
        fail(f"{name} of the fish workspace is under {' and '.join(missing)}, and its package ships no licence text")
    if name == "fish":
        path = os.path.join(member["root"], FISH_LICENCES)
        if not os.path.isfile(path):
            fail(f"the fish archive holds no {FISH_LICENCES}, the file that COPYING names for the licences of fish's other code")
        blocks.add("notice", f"{FISH_LICENCES} of the fish package", "", read_text(path), crate, member["authors"], "fish", None)


WHOSE = {
    "programs": {"tests": "a release program", "platforms": "no release is built for"},
    "companion": {"tests": "the companion application", "platforms": "the companion application is not built for"},
}


def reasons(gaps_list, packages, targets, environment, extra=(), product="programs"):
    """Why each crate that the lock reaches and no build compiles is left out, one line to a crate."""
    built, _ = compiled(ROOT, packages, targets, list(extra), environment)
    tested, _ = compiled(ROOT, packages, targets, list(extra), environment, "normal,build,dev")
    elsewhere, _ = compiled(ROOT, packages, ["all"], list(extra), environment)
    whose = WHOSE[product]
    lines = []
    for gap in gaps_list:
        crate, _, source = gap.partition(" | source ")
        name, version = crate.split(" ")
        address, _, revision = source.partition("#")
        key = (name, version, f"{address}#{revision[:8]}" if source else None)
        if key in built:
            fail(f"{name} {version} is compiled by a {PRODUCT_BUILDS[product]} and the notice has no entry for it")
        if key in tested:
            why = f"only a test of {whose['tests']} uses it"
        elif key in elsewhere:
            why = f"only a platform that {whose['platforms']} uses it"
        else:
            why = "only features that other packages of the workspace turn on bring it in"
        lines.append(f"{gap} | {why}")
    return lines


JAVASCRIPT_ORIGIN = "javascript"


def read_companion():
    """What the companion's notice is made for: its package, the features its bundles are built with,
    its platforms and the JavaScript package its interface is built from."""
    with open(COMPANION_CONFIG, encoding="utf-8") as source:
        return json.load(source)


def accepted_licences():
    """The licences `about.toml` accepts, in the order that chooses between the alternatives of an `OR`."""
    with open(CONFIG, encoding="utf-8") as source:
        found = re.search(r"^accepted = \[(.*?)\]", source.read(), re.DOTALL | re.MULTILINE)
    if not found:
        fail("about.toml has no accepted list")
    return re.findall(r'"([^"]+)"', found.group(1))


def chosen(name, version, expression, accepted):
    """The licence a JavaScript package is recorded under: of the alternatives its expression offers,
    the first that `about.toml` accepts, as for a crate."""
    if re.search(r"\bAND\b|[()]", expression.strip("() ")):
        fail(f"{name} {version} declares {expression}, which has an AND or a parenthesis that this notice does not read")
    ranks = {alternative.strip(): accepted.index(alternative.strip())
             for alternative in re.split(r"\s+OR\s+", expression.strip("() ")) if alternative.strip() in accepted}
    if not ranks:
        fail(f"{name} {version} declares {expression or 'no licence'}, which names no licence that about.toml accepts")
    return min(ranks, key=ranks.get)


def package_manager():
    with open(os.path.join(ROOT, "package.json"), encoding="utf-8") as source:
        return json.load(source)["packageManager"].split("@", 1)[1]


IMPORT = re.compile(r"""(?:^|\n)[ \t]*(?:import|export)\s+(type\s+)?(?:[^;'"]*?\bfrom\s+)?['"]([^'"\n]+)['"]"""
                    r"""|\bimport\(\s*['"]([^'"\n]+)['"]\s*\)""")
SOURCE_FILE = re.compile(r"\.(ts|tsx|js|jsx|mjs)$")


def package_of(specifier):
    """The package a module specifier names: none for a relative path or a module of Node."""
    if specifier.startswith((".", "/", "node:")):
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") else parts[0]


def check_imports(folder, name, label):
    """The packages that the interface's own sources import, which the build ships (a type-only import is
    erased and not counted). Each has to be among the `dependencies` of the interface's package.json, which
    is what the notice lists. Returns the packages imported."""
    with open(os.path.join(folder, "package.json"), encoding="utf-8") as source:
        manifest = json.load(source)
    if manifest["name"] != name:
        fail(f"{label}/package.json is the package {manifest['name']}, and scripts/companion-notice.json names {name}")
    held = set(manifest.get("dependencies", {}))
    imported = set()
    for directory, _, files in os.walk(os.path.join(folder, "src")):
        for file_name in files:
            if SOURCE_FILE.search(file_name):
                for found in IMPORT.finditer(read_text(os.path.join(directory, file_name))):
                    package = None if found.group(1) else package_of(found.group(2) or found.group(3))
                    if package:
                        imported.add(package)
    for package in sorted(imported - held):
        fail(f"{label}/src imports {package}, which is not among the dependencies of {label}/package.json, so the notice would not list it")
    return imported


def javascript_record(config):
    """What `pnpm licenses` lists for the production packages of the interface and of the workspace
    packages it is built from, as the record `gather` takes: one entry for each version, with the folder
    of its installed package."""
    check_imports(os.path.join(ROOT, "apps", "companion"), config["javascript"], "apps/companion")
    wanted = package_manager()
    said = run(["pnpm", "--version"], cwd=ROOT).stdout.strip()
    if said != wanted:
        fail(f"pnpm says '{said}' and the notice is made with pnpm {wanted}")
    listing = json.loads(run(["pnpm", "licenses", "list", "--prod", "--json", "--long",
                              "--filter", config["javascript"] + "..."], cwd=ROOT).stdout)
    accepted = accepted_licences()
    answers, roots_, declared = {}, {}, {}
    for expression, group in sorted(listing.items()):
        for item in group:
            if len(item["versions"]) != len(item["paths"]):
                fail(f"pnpm lists {item['name']} with {len(item['versions'])} versions and {len(item['paths'])} folders")
            for version, path in zip(item["versions"], item["paths"]):
                if not os.path.isdir(path):
                    fail(f"{item['name']} {version} is not installed, which the generator needs to read its licence files: {COMPANION_REPAIR}")
                key = (item["name"], version, "npm")
                recorded = chosen(item["name"], version, item.get("license") or expression, accepted)
                answers[key] = {"authors": [item["author"]] if item.get("author") else [], "source": None,
                                "licences": [(recorded, recorded, "", False)]}
                roots_[key] = path
                declared[key] = item.get("license") or expression
    if not answers:
        fail(f"pnpm lists no production package of {config['javascript']}")
    return {"name": JAVASCRIPT_ORIGIN, "listed": set(answers), "answers": answers, "roots": roots_,
            "declared": declared, "paths": set(), "members": {}}


def collect_companion(program, work):
    """The Rust crates the companion's package compiles in on its platforms, as for the programs, and
    the JavaScript packages of its interface."""
    check_version(program)
    config = read_companion()
    environment = dict(os.environ)
    flags = ["--features", ",".join(config["features"])]
    workspace = members(ROOT, environment)
    if config["package"] not in workspace:
        fail(f"scripts/companion-notice.json names {config['package']}, which is no package of the workspace")
    manifest = os.path.join(workspace[config["package"]]["root"], "Cargo.toml")
    answered = answers_of(about(program, manifest, os.path.join(work, "companion.json"), CONFIG,
                                [item for target in config["targets"] for item in ("--target", target)] + flags))
    listed, paths = compiled(ROOT, [config["package"]], config["targets"], flags, environment)
    return [record("rust", listed, paths, workspace, answered, roots(ROOT, environment)), javascript_record(config)]


def make_companion(program, askalono, kr_release, work):
    records = collect_companion(program, work)
    kept, files = keep_texts()
    body = render(gather(records, kept, files, Reader(askalono, work), "companion"), COMPANION_HEADER)
    entries = os.path.join(work, "companion-entries.txt")
    with open(entries, "w", encoding="utf-8", newline="\n") as target:
        target.write(body)
    gaps_list = [line for line in run([kr_release, "notice-gaps", "--product", "companion", "--checkout", ROOT,
                                       "--notice", entries]).stdout.split("\n") if line]
    config = read_companion()
    lines = reasons(gaps_list, [config["package"]], config["targets"], dict(os.environ),
                    ["--features", ",".join(config["features"])], "companion")
    return body + (COMPANION_UNUSED + "".join(f"  - {line}\n" for line in lines) if lines else "")


def make(program, askalono, kr_release, work):
    records = collect(program, work)
    kept, files = keep_texts()
    body = render(gather(records, kept, files, Reader(askalono, work)))
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
        command.add_argument("--product", choices=["programs", "companion"], default="programs",
                             help="the notice of the release archives (the default) or of the companion application")
        command.add_argument("--kr-release", required=True, help="the kr-release program, built from this checkout")
        command.add_argument("--cargo-about", default="cargo-about")
        command.add_argument("--askalono", default="askalono")
        command.add_argument("--work", help="a directory for the runs, which is kept; a new one by default")
    commands.add_parser("self-test").add_argument("--askalono", default="askalono")
    chosen = parser.parse_args(arguments)
    if chosen.command == "self-test":
        return self_test(chosen.askalono)
    with tempfile.TemporaryDirectory(prefix="kr-notices-") as scratch:
        work = chosen.work or scratch
        os.makedirs(work, exist_ok=True)
        made = (make_companion if chosen.product == "companion" else make)(
            chosen.cargo_about, chosen.askalono, chosen.kr_release, work)
    notice = COMPANION_NOTICE if chosen.product == "companion" else NOTICE
    if chosen.command == "write":
        with open(notice, "w", encoding="utf-8", newline="\n") as target:
            target.write(made)
        print(f"generate-notices: wrote {notice}")
        return 0
    with open(notice, encoding="utf-8", newline="") as source:
        committed = source.read()
    if committed != made:
        committed_name = os.path.relpath(notice, ROOT).replace(os.sep, "/")
        repair = COMPANION_REPAIR if chosen.product == "companion" else REPAIR
        print(f"generate-notices: {committed_name} is not what the lock makes: {repair}", file=sys.stderr)
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


def self_test(askalono):
    with tempfile.TemporaryDirectory(prefix="kr-notices-test-") as scratch:
        return self_checks(scratch, Reader(askalono, scratch))


def self_checks(scratch, reader):
    """Holds the reading of cargo's lines, the licence reader, the placeholder refusal, the choice of a
    crate's texts, the checks on the kept texts and the text's layout to what a notice must do, over
    made-up crates and folders."""
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

    def rendered(crates, used, files_):
        """The notice text of these crates, or an empty text where the run refuses."""
        return made(lambda: render(gather(crates, used, files_, reader)))

    def licence_text(identifier):
        """The SPDX list's text of a licence, with a holder where the template has a placeholder."""
        with open(os.path.join(reader.directory, "spdx-list", "json", "details", f"{identifier}.json"), encoding="utf-8") as source:
            text = json.load(source)["licenseText"]
        return normal(re.sub(r"<(copyright holders|owner)>", "A Person", text.replace("<year>", "2020")))

    def licence_header(identifier):
        """The SPDX list's standard header of a licence, with a holder where the header has a placeholder."""
        with open(os.path.join(reader.directory, "spdx-list", "json", "details", f"{identifier}.json"), encoding="utf-8") as source:
            header = json.load(source)["standardLicenseHeader"]
        return normal(header.replace("[yyyy] [name of copyright owner]", "2020 A Person"))

    def write(folder, name, text):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as target:
            target.write(text)

    mit, isc, apache, bsd = (licence_text(name) for name in ("MIT", "ISC", "Apache-2.0", "BSD-3-Clause"))
    template = mit.replace("2020 A Person", "<year> <copyright holders>")
    gpl = "Copyright (C) <year>  <name of author>\n\nGNU GENERAL PUBLIC LICENSE\n"
    statement = "Copyright 2012 The Authors\n\nLicensed under the Apache License or the MIT license, at your option.\n"

    expect("a crates.io line is a crate", tree_line("serde v1.0.1") == ("serde", "1.0.1", None))
    expect("a proc macro mark and a repeat mark are dropped", tree_line("serde_derive v1.0.1 (proc-macro) (*)") == ("serde_derive", "1.0.1", None))
    expect("a path line is a path package", tree_line("kr-cli v0.1.0 (/home/a/crates/kr-cli)") == ("path", "kr-cli", "0.1.0"))
    expect("a repository line keeps the repository and eight letters of the revision",
           tree_line("forked v0.1.0 (https://example.org/forked?rev=abcdef0123456789#abcdef01)")
           == identity("forked", "0.1.0", REPOSITORY))
    refuses("a registry that is not crates.io is refused", lambda: identity("x", "1", "registry+https://other.example/index"), "not crates.io")
    expect("the placeholder of a permissive template is found", placeholder(template) == "<copyright holders>")
    expect("the placeholders of GitHub's and NCSA's templates are found",
           placeholder("Copyright (c) [year] [fullname]") == "[year]" and placeholder("Copyright <Owner Organization Name>") == "<Owner Organization Name>")
    expect("the GPL's own paragraph and Apache's appendix are not placeholders",
           placeholder(gpl) is None and placeholder(apache) is None)

    wrapped = textwrap.fill(" ".join(isc.split()), 24)
    reader.prepare([mit, isc, apache, bsd, mit + bsd, statement, isc.replace("for any purpose", "for any\npurpose"), wrapped,
                    isc + "\n\n" + apache, "UNICODE LICENSE V3\n"])
    expect("a text names the licence it is", reader.of(mit) == {"MIT"} and reader.of(bsd) == {"BSD-3-Clause"} and reader.of(apache) == {"Apache-2.0"})
    expect("a line break inside a phrase does not hide a licence",
           reader.of(isc.replace("for any purpose", "for any\npurpose")) == {"ISC"} and reader.of(wrapped) == {"ISC"})
    expect("a file that holds two licences names both", reader.of(mit + bsd) == {"MIT", "BSD-3-Clause"} and reader.of(isc + "\n\n" + apache) == {"ISC", "Apache-2.0"})
    expect("a statement of a licence is none of the licences", reader.of(statement) == frozenset())
    expect("the Unicode licence's third version is told from its second",
           refine(frozenset({"Unicode-DFS-2016"}), "UNICODE LICENSE V3\n") == {"Unicode-3.0"}
           and refine(frozenset({"Unicode-DFS-2016"}), "UNICODE, INC. LICENSE AGREEMENT\n") == {"Unicode-DFS-2016"})
    gruber = "Copyright \u00a9 2004, John Gruber\nhttp://daringfireball.net/\nAll rights reserved.\n"
    expect("the Markdown licence of John Gruber is read as BSD-3-Clause",
           refine(frozenset({"BSD-3-Clause-Clear", "MIT"}), "MIT text\n\n" + gruber) == {"BSD-3-Clause", "MIT"})
    expect("a text read as BSD-3-Clause-Clear without his name stays so",
           refine(frozenset({"BSD-3-Clause-Clear"}), "BSD 3-Clause Clear License\n") == {"BSD-3-Clause-Clear"})

    # How askalono's answers are read: a range blanks the lines it names, an answer is for the file it names,
    # and the two readings of a text may not call one region two licences.
    blanked = ["a", "b", "c", "d"]
    blank(blanked, 1, 3)
    expect("a licence match blanks its own lines and no more", blanked == ["a", "", "", "d"])

    def fake(name, body):
        """A reader whose program answers as `body` says, for the `paths` it is given and the options it is run with."""
        program = os.path.join(scratch, name)
        with open(program, "w", encoding="utf-8") as target:
            target.write(f"#!{sys.executable}\nimport json, sys\npaths = [line.rstrip('\\n') for line in sys.stdin if line.strip()]\n{body}")
        os.chmod(program, 0o755)
        stand_in = object.__new__(Reader)
        stand_in.program, stand_in.cache, stand_in.directory = program, "none", os.path.join(scratch, name + "-reader")
        os.makedirs(stand_in.directory)
        return stand_in

    backwards = fake("answers-backwards", '''
for path in reversed(paths):
    print(json.dumps({"path": path + "\\n", "result": {"score": 0.0, "license": None, "containing": [], "marker": path}}))
''')
    expect("askalono's answers are matched to the texts by their paths, not their order",
           [answer["marker"] for answer in backwards.batch(["--optimize"], ["x", "y"])] == ["x", "y"])
    stranger = fake("answers-for-another", '''
for path in paths:
    print(json.dumps({"path": "other\\n", "result": {"score": 0.0, "license": None, "containing": []}}))
''')
    refuses("an answer for a path that was not asked for is refused", lambda: stranger.batch(["--optimize"], ["x"]),
            "askalono answered for other, a text that was not asked for or is answered twice")
    clashing = fake("answers-that-clash", '''
def part(name, first, last):
    return {"score": 0.95, "license": {"name": name, "kind": "original", "aliases": []}, "line_range": [first, last]}
for path in paths:
    containing = [part("MIT", 0, 5)] if "-m" in sys.argv else [part("ISC", 2, 8)]
    print(json.dumps({"path": path + "\\n", "result": {"score": 0.0, "license": None, "containing": containing}}))
''')
    refuses("a region that the two readings call two licences is refused", lambda: clashing.read(["a\nb\nc\nd\ne\nf\ng\nh\n"]),
            "askalono reads lines 3 to 5 of a text as MIT in one reading and as ISC in the other")

    def licences(text, own=True):
        return [("MIT", "MIT License", text, own)]

    plain = synthetic("plain", "1.0.0", authors=["A"], licences=licences(mit))
    forked = synthetic("forked", "0.1.0", REPOSITORY, licences=licences(mit))
    nothing = {"texts": [], "crates": [], "works": []}
    blocks = gather([made_up([plain, forked])], nothing, {}, reader)
    text = render(blocks)
    expect("a text that two crates share appears once", text.count("Permission is hereby granted") == 1)
    expect("a crate that has a file of its own has its entry", "  - plain 1.0.0 | programs | A\n" in text)
    expect("a crate from a repository names its source", "source https://example.org/forked?rev=abcdef0123456789#abcdef0123456789\n" in text)
    refuses("a text with a template's placeholder is refused",
            lambda: gather([made_up([synthetic("bad", "1.0.0", licences=licences(template))])], nothing, {}, reader), "placeholder <copyright holders>")
    refuses("a path package that is not a member is refused",
            lambda: record("programs", set(), {"stranger"}, {}, {}, {}), "stranger")
    refuses("a crate cargo tree lists and cargo-about does not answer for is refused",
            lambda: record("programs", {("lost", "1.0.0", None)}, set(), {}, {}, {}), "gives no licence for, the first lost 1.0.0")

    empty = os.path.join(scratch, "empty-1.0.0")
    os.makedirs(empty)
    refuses("a crate that ships no file and has no kept text is refused",
            lambda: gather([made_up([synthetic("empty", "1.0.0", licences=licences(template, False), folder=empty)])], nothing, {}, reader),
            "empty 1.0.0 ships no licence file")
    folder = os.path.join(scratch, "bare-1.0.0")
    write(folder, "LICENSE-BSD3", bsd)
    write(folder, "COPYRIGHT", "Copyright 2020 The Authors\n")
    directory = os.path.join(scratch, "texts")
    kept_text = mit.replace("2020 A Person", "2025 N0, INC.")
    write(directory, "n0-MIT", kept_text)
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
    write(dual, "LICENSE-MIT", mit)
    write(dual, "LICENSE-APACHE", apache)
    text = rendered([made_up([synthetic("dual", "1.0.0", licences=licences(template, False), folder=dual,
                                             declared="MIT OR Apache-2.0")])], nothing, {})
    expect("a crate under MIT or Apache is carried under the one it is recorded under",
           "Permission is hereby granted" in text and "Apache License" not in text)
    both = synthetic("bare", "1.0.0", licences=licences(template, False), folder=folder)
    text = rendered([made_up([both])], kept, files)
    expect("a crate whose package lacks its recorded licence's text gets the kept one besides its own file",
           "Copyright (c) 2025 N0, INC." in text and "Redistribution and use in source and binary forms" in text)
    expect("a crate's notice files are carried", "Notice file: Notice file" in text and "Copyright 2020 The Authors" in text)
    expect("a kept text names its source on the entry", "text https://example.org/n0/LICENSE-MIT" in text)
    refuses("a kept text for a crate that no release build compiles is refused",
            lambda: gather([made_up([plain])], kept, files, reader), "no release build compiles")
    refuses("a kept text for a crate that ships its licence text is refused",
            lambda: gather([made_up([plain])], *keep([item], [{**pinned, "name": "plain"}], []), reader), "ships the licence text itself")
    kept, files = keep([item], [], [])
    refuses("a kept text that nothing uses is refused", lambda: gather([made_up([plain])], kept, files, reader), "no crate or work uses")
    refuses("a kept text that is not the licence it is listed as is refused",
            lambda: gather([made_up([both])], *keep([{**item, "licence": "ISC"}], [pinned], []), reader), "as ISC, and its text is MIT")
    work = {"name": "libx", "version": "1.0", "carried_by": {"name": "gone", "version": "1.0.0"}, "texts": ["n0-MIT"]}
    kept, files = keep([item], [], [work])
    refuses("a bundled work whose carrier is not compiled is refused", lambda: gather([made_up([plain])], kept, files, reader), "which no release build compiles")
    work["carried_by"] = {"name": "plain", "version": "1.0.0"}
    kept, files = keep([item], [], [work])
    text = rendered([made_up([plain])], kept, files)
    expect("a bundled work has its entry and its text", "  - libx 1.0 | programs |  | bundled in plain 1.0.0, text https://example.org/n0/LICENSE-MIT\n" in text)
    write(directory, "n0-second", "Notice 2025 N0\n")
    second = {"id": "n0-second", "licence": "MIT", "source": "https://example.org/n0/NOTICE", "statement": True,
              "sha256": hashlib.sha256(b"Notice 2025 N0\n").hexdigest()}
    work["texts"] = ["n0-MIT", "n0-second"]
    kept, files = keep([item, second], [], [work])
    text = rendered([made_up([plain])], kept, files)
    expect("a bundled work takes more than one text", "Permission is hereby granted" in text and "Notice 2025 N0" in text)
    other = {"name": "libx", "version": "1.0", "carried_by": {"name": "plain", "version": "1.0.0"}, "texts": ["n0-MIT"],
             "products": ["companion"]}
    kept, files = keep([item], [], [other])
    refuses("a work kept for another product alone is refused when this product compiles its carrier",
            lambda: gather([made_up([plain])], kept, files, reader), "lists the work for another product only")
    kept, files = keep([item], [], [{**other, "carried_by": {"name": "gone", "version": "1.0.0"}}])
    expect("a work kept for another product alone is not asked of a product that compiles no carrier of it",
           rendered([made_up([plain])], kept, files) != "")

    # A kept excerpt of a source file is the file's own lines and ends where the licence comment ends.
    carrier_folder = os.path.join(scratch, "carrier-1.0.0")
    source_lines = ["// Copyright 2025 N0", "// Permission is hereby granted", "// to anyone.", "", "int x;"]
    write(os.path.join(carrier_folder, "src"), "lib.c", "".join(line + "\n" for line in source_lines))
    carrier = synthetic("carrier", "1.0.0", licences=licences(mit), folder=carrier_folder)

    def excerpted(lines_, first, last, file_name="src/lib.c"):
        """What the run does for a work that keeps these lines as lines `first` to `last` of a file of its carrier."""
        body = "".join(line + "\n" for line in lines_)
        write(directory, "excerpt", body)
        entry = {"id": "excerpt", "licence": "MIT", "source": "https://example.org/lib.c", "statement": True,
                 "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(), "excerpt": [first, last], "file": file_name}
        kept_, files_ = keep([entry], [], [{"name": "libx", "version": "1.0", "carried_by": {"name": "carrier", "version": "1.0.0"}, "texts": ["excerpt"]}])
        return lambda: render(gather([made_up([carrier])], kept_, files_, reader))

    refuses("a kept excerpt that stops before the licence comment of its file ends is refused",
            excerpted(source_lines[:2], 1, 2), "ends at line 2 of src/lib.c, and line 3 still belongs to the comment")
    expect("a kept excerpt that ends where the licence comment ends is carried",
           "to anyone." in made(excerpted(source_lines[:3], 1, 3)) and "lines 1 to 3" in made(excerpted(source_lines[:3], 1, 3)))
    refuses("a kept excerpt that is not the lines of its file is refused",
            excerpted(["// Copyright 2025 N0", "// Permission is denied", "// to anyone."], 1, 3), "holds other lines there")
    refuses("a kept excerpt of a file that the carrier does not have is refused",
            excerpted(source_lines[:3], 1, 3, "src/gone.c"), "carrier 1.0.0 has no such file")

    refuses("a crate that cargo tree lists and cargo metadata cannot place is refused",
            lambda: record("programs", {plain[0]}, set(), {}, {plain[0]: plain[1]}, {}), "cargo metadata finds no package for 1 crates")
    expect("a crate from a Git repository and the same crate from crates.io are two entries",
           rendered([made_up([synthetic("twin", "1.0.0", licences=licences(mit)),
                                   synthetic("twin", "1.0.0", REPOSITORY, licences=licences(mit))])], nothing, {}).count("  - twin 1.0.0 | programs") == 2)

    # A file that is a statement is no licence's text.
    stated = os.path.join(scratch, "stated-1.0.0")
    write(stated, "COPYING", statement)
    refuses("a crate whose only file is a statement is refused until a text is kept for it",
            lambda: gather([made_up([synthetic("stated", "1.0.0", licences=licences(template, False), folder=stated)])], nothing, {}, reader),
            "ships no text of MIT, its recorded licence, only COPYING (no licence text)")
    kept, files = keep([item], [{"name": "stated", "version": "1.0.0", "texts": ["n0-MIT"]}], [])
    text = rendered([made_up([synthetic("stated", "1.0.0", licences=licences(template, False), folder=stated)])], kept, files)
    expect("a statement is carried as one beside the kept text of the licence",
           "Licence statement: COPYING (" + STATEMENT + ")" in text and "Copyright (c) 2025 N0, INC." in text)

    # A header of a licence is a statement: it names the licence and holds none of its terms.
    header = licence_header("Apache-2.0")
    reader.prepare([header, header + "\n" + mit])
    expect("a file that holds only the header of a licence is a statement", reader.of(header) == frozenset())
    headed = os.path.join(scratch, "headed-1.0.0")
    write(headed, "LICENSE", header)
    refuses("a crate under Apache-2.0 whose only file is the Apache header is refused until a text is kept for it",
            lambda: gather([made_up([synthetic("headed", "1.0.0", licences=[("Apache-2.0", "Apache License 2.0", "", False)],
                                                    folder=headed, declared="Apache-2.0")])], nothing, {}, reader),
            "headed 1.0.0 ships no text of Apache-2.0, its recorded licence, only LICENSE (no licence text)")
    write(directory, "n0-apache", apache)
    kept_apache = {"id": "n0-apache", "licence": "Apache-2.0", "source": "https://example.org/n0/LICENSE-APACHE",
                   "sha256": hashlib.sha256(apache.encode("utf-8")).hexdigest()}
    kept, files = keep([kept_apache], [{"name": "headed", "version": "1.0.0", "texts": ["n0-apache"]}], [])
    text = rendered([made_up([synthetic("headed", "1.0.0", licences=[("Apache-2.0", "Apache License 2.0", "", False)],
                                         folder=headed, declared="Apache-2.0")])], kept, files)
    expect("a crate under Apache-2.0 whose only file is the Apache header is carried once an Apache text is kept for it",
           "Licence statement: LICENSE (" + STATEMENT + ")" in text and "Licence: Apache-2.0 (Apache License 2.0)" in text
           and "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text and "text https://example.org/n0/LICENSE-APACHE" in text)
    alternative = os.path.join(scratch, "alternative-1.0.0")
    write(alternative, "LICENSE-MIT", mit)
    write(alternative, "LICENSE-APACHE", header)
    text = rendered([made_up([synthetic("alternative", "1.0.0", licences=licences(template, False), folder=alternative,
                                         declared="MIT OR Apache-2.0")])], nothing, {})
    expect("a file that holds only the header of the alternative licence stays, as a statement",
           "Licence statement: LICENSE-APACHE (" + STATEMENT + ")" in text and "Permission is hereby granted" in text)
    third = os.path.join(scratch, "third-1.0.0")
    write(third, "LICENSE-THIRD-PARTY", header + "\n" + mit)
    text = rendered([made_up([synthetic("third", "1.0.0", licences=licences(header + "\n" + mit), folder=third)])], nothing, {})
    expect("a text that a notice file and a licence answer share is carried once",
           text.count("Permission is hereby granted") == 1 and "Licence: MIT (MIT License)\n" in text and "Notice file" not in text)

    # A kept text listed as a statement may not be a licence's text, and the kept texts of a crate have to be
    # the texts of every licence it is recorded under.
    refuses("a kept text listed as a statement that is a licence's text is refused",
            lambda: gather([made_up([both])], *keep([{**item, "statement": True}], [pinned], []), reader),
            "lists n0-MIT as a statement, and its text is MIT")
    answer = [("MIT", "MIT License", "", False), ("BSD-3-Clause", "BSD 3-Clause", "", False)]
    refuses("kept texts that are not the text of the crate's recorded licence are refused",
            lambda: gather([made_up([synthetic("bare", "1.0.0", licences=answer, folder=empty, declared="MIT AND BSD-3-Clause")])],
                           *keep([item], [pinned], []), reader),
            "keeps texts for bare 1.0.0 that are not the text of BSD-3-Clause")
    unicode_folder = os.path.join(scratch, "unicoded-1.0.0")
    write(unicode_folder, "LICENSE", licence_text("Unicode-3.0"))
    nfa_folder = os.path.join(scratch, "nfa-1.0.0")
    write(nfa_folder, "LICENSE-MIT", licence_text("MITNFA"))
    unicoded = synthetic("unicoded", "1.0.0", licences=[("Unicode-DFS-2016", "Unicode License Agreement", "", False)],
                         folder=unicode_folder, declared="Unicode-DFS-2016")
    nfa = synthetic("nfa", "1.0.0", licences=licences(template, False), folder=nfa_folder)
    expect("a text of Unicode-3.0 is the text of a crate recorded under Unicode-DFS-2016, and MITNFA of MIT",
           "Licence: Unicode-3.0" in rendered([made_up([unicoded])], nothing, {}) and "Licence: MITNFA" in rendered([made_up([nfa])], nothing, {}))

    # No licence of an AND is dropped, a file with two licences stays whole, and a file for an
    # alternative that is not taken goes.
    anded = os.path.join(scratch, "anded-1.0.0")
    write(anded, "LICENSE-MIT", mit)
    write(anded, "LICENSE-BSD", bsd)
    answer = [("MIT", "MIT License", "", False), ("BSD-3-Clause", "BSD 3-Clause", "", False)]
    text = rendered([made_up([synthetic("anded", "1.0.0", licences=answer, folder=anded, declared="MIT AND BSD-3-Clause")])], nothing, {})
    expect("a crate under two licences that both apply carries both texts",
           "Permission is hereby granted" in text and "Redistribution and use in source and binary forms" in text)
    joined = os.path.join(scratch, "joined-1.0.0")
    write(joined, "LICENSE", isc + "\n\n" + apache)
    text = rendered([made_up([synthetic("joined", "1.0.0", licences=[("ISC", "ISC License", "", False)], folder=joined,
                                             declared="ISC AND (Apache-2.0 OR ISC)")])], nothing, {})
    expect("a file that holds two licences is carried whole under both",
           "Licence: Apache-2.0 and ISC (Apache License 2.0 and ISC License, in one file)" in text and "Apache License" in text and "Permission to use, copy" in text)

    # A kept text is bound to the source and the revision of its package.
    moved = "git+https://example.org/forked?rev=1234567890abcdef#1234567890abcdef"
    package = identity("forked", "0.1.0", REPOSITORY)[2]
    kept, files = keep([item], [{"name": "forked", "version": "0.1.0", "package": package, "texts": ["n0-MIT"]}], [])
    old = synthetic("forked", "0.1.0", REPOSITORY, licences=licences(template, False), folder=empty)
    new = synthetic("forked", "0.1.0", moved, licences=licences(template, False), folder=empty)
    expect("a kept text answers the package at the revision it names",
           "Copyright (c) 2025 N0, INC." in made(lambda: render(gather([made_up([old])], kept, files, reader))))
    refuses("a kept text for a Git package that has moved to another revision is refused",
            lambda: gather([made_up([new])], kept, files, reader),
            "keeps a text for this crate from https://example.org/forked?rev=abcdef0123456789#abcdef01, not from https://example.org/forked?rev=1234567890abcdef#12345678")

    # A bundled work is bound to the source and the revision of the crate that carries it.
    old_carrier = synthetic("forked", "0.1.0", REPOSITORY, licences=licences(mit))
    new_carrier = synthetic("forked", "0.1.0", moved, licences=licences(mit))
    forked_work = {"name": "libx", "version": "1.0", "carried_by": {"name": "forked", "version": "0.1.0", "package": package}, "texts": ["n0-MIT"]}
    kept, files = keep([item], [], [forked_work])
    expect("a bundled work answers the carrier at the revision it names",
           "bundled in forked 0.1.0, text https://example.org/n0/LICENSE-MIT" in made(lambda: render(gather([made_up([old_carrier])], kept, files, reader))))
    refuses("a bundled work whose carrier has moved to another revision is refused",
            lambda: gather([made_up([new_carrier])], kept, files, reader),
            "libx 1.0 is bundled in forked 0.1.0 from https://example.org/forked?rev=abcdef0123456789#abcdef01, "
            "and the lock has that crate from https://example.org/forked?rev=1234567890abcdef#12345678")

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
    patents = os.path.join(scratch, "rav1e-0.8.1")
    os.makedirs(patents)
    with open(os.path.join(patents, "PATENTS"), "wb") as target:
        target.write(b"\x93Affiliate\x94\n")
    expect("the one file that is Windows-1252 text is read as such",
           made(lambda: read_text(os.path.join(patents, "PATENTS"))) == "“Affiliate”\n")

    shipped = os.path.join(scratch, "shipped-1.0.0")
    write(shipped, "LICENSE-MIT", template)
    standard = os.path.join(scratch, "standard")
    plain_text = "Permission is hereby granted, free of charge\nline two\nline three\n"
    write(standard, "mit-plain", mit.split("\n\n", 2)[2])
    plain_item = {"id": "mit-plain", "licence": "MIT", "source": "https://example.org/spdx/MIT.txt",
                  "sha256": hashlib.sha256(mit.split("\n\n", 2)[2].encode("utf-8")).hexdigest(),
                  "edit": {"removed": "the copyright line"}, "name": "a standard text"}
    with open(listing, "w", encoding="utf-8") as target:
        json.dump({"texts": [plain_item], "crates": [{"name": "shipped", "version": "1.0.0", "texts": ["mit-plain"]}], "works": []}, target)
    kept_plain, files_plain = keep_texts(listing, standard)
    text = made(lambda: render(gather([made_up([synthetic("shipped", "1.0.0", licences=licences(template), folder=shipped)])],
                                      kept_plain, files_plain, reader)))
    expect("a kept text answers a crate whose own file holds a placeholder",
           "Permission is hereby granted" in text and "<year>" not in text and "<copyright holders>" not in text
           and "text https://example.org/spdx/MIT.txt without its copyright line" in text and "(MIT License)" in text)

    # fish's own licence files.
    fish_folder = os.path.join(scratch, "fish-widecharwidth")
    write(fish_folder, "LICENSE", licence_text("CC0-1.0"))
    fish_blocks = Blocks(reader)
    made(lambda: fish_member(fish_blocks, "widecharwidth", {"root": fish_folder, "version": "0.0.0", "authors": [], "licence": "CC0-1.0"}))
    text = render(fish_blocks)
    expect("a crate of fish's own workspace under CC0-1.0 is carried with its licence file under the licence it is",
           "Licence: CC0-1.0 (Creative Commons Zero v1.0 Universal)" in text and "CC0 1.0 Universal" in text)
    printf_folder = os.path.join(scratch, "fish-printf")
    write(printf_folder, "COPYING", statement)
    printf_entry = {"root": printf_folder, "version": "0.2.1", "authors": [], "licence": "MIT"}
    refuses("a crate of fish's workspace under MIT whose only file is a statement is refused",
            lambda: fish_member(Blocks(reader), "printf", printf_entry), "printf of the fish workspace is under MIT, and its package ships no licence text")
    dedication = os.path.join(scratch, "fish-widecharwidth-dedication")
    write(dedication, "LICENSE",
          "widecharwidth - wcwidth implementation\nWritten in 2018 by ridiculous_fish\n"
          "To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring "
          "rights to this software to the public domain worldwide. This software is distributed without any warranty.\n"
          "You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see "
          "<http://creativecommons.org/publicdomain/zero/1.0/>.\n")
    dedication_blocks = Blocks(reader)
    made(lambda: fish_member(dedication_blocks, "widecharwidth", {"root": dedication, "version": "0.0.0", "authors": [], "licence": "CC0-1.0"}))
    expect("fish-widecharwidth's four-line file is carried as a statement",
           "Licence statement: LICENSE (" + STATEMENT + ")" in render(dedication_blocks))
    fish_root = os.path.join(scratch, "fish-root")
    write(fish_root, "COPYING", statement)
    fish_member_entry = {"root": fish_root, "version": "4.0.0", "authors": [], "licence": "GPL-2.0-only"}
    refuses("fish's licence file for the rest of its code is required", lambda: fish_member(Blocks(reader), "fish", fish_member_entry), "holds no doc_src/license.rst")
    write(os.path.join(fish_root, "doc_src"), "license.rst", "fish includes a copy of Alpine.js\n")
    fish_blocks = Blocks(reader)
    made(lambda: fish_member(fish_blocks, "fish", fish_member_entry))
    text = render(fish_blocks)
    expect("fish's licence file for the rest of its code is carried whole",
           "Notice file: doc_src/license.rst of the fish package\n" in text and "Alpine.js" in text)

    app = os.path.join(scratch, "app")
    write(app, "package.json", json.dumps({"name": "@x/app", "dependencies": {"held": "1.0.0"}, "devDependencies": {"dev-only": "1.0.0"}}))
    write(os.path.join(app, "src"), "main.ts", "import { a } from 'held'\nimport type { T } from 'dev-only'\nimport './local'\nexport { x } from 'held/sub'\n")
    expect("a type-only import of a package that its dependencies do not hold is not refused",
           made(lambda: check_imports(app, "@x/app", "app")) == {"held"})
    write(os.path.join(app, "src"), "value.ts", "import {\n  v\n} from 'dev-only/sub'\n")
    refuses("a package that the interface imports and its dependencies do not hold is refused",
            lambda: check_imports(app, "@x/app", "app"), "app/src imports dev-only")

    accepted = ["MIT", "ISC", "Apache-2.0"]
    expect("a package under an OR is recorded under the first licence that about.toml lists",
           chosen("a", "1.0.0", "Apache-2.0 OR MIT", accepted) == "MIT")
    refuses("a package whose licences about.toml lists none of is refused",
            lambda: chosen("a", "1.0.0", "GPL-3.0-only OR AGPL-3.0-only", accepted), "names no licence that about.toml accepts")
    refuses("a package that declares no licence is refused", lambda: chosen("a", "1.0.0", "", accepted), "declares no licence")
    refuses("a package whose licence expression has an AND is refused",
            lambda: chosen("a", "1.0.0", "MIT AND ISC", accepted), "which has an AND or a parenthesis that this notice does not read")
    refuses("a package whose licence expression has a parenthesis is refused",
            lambda: chosen("a", "1.0.0", "MIT OR (ISC OR Apache-2.0)", accepted),
            "which has an AND or a parenthesis that this notice does not read")

    def script(folder_, declared="MIT"):
        key = ("left-pad", "1.3.0", "npm")
        return {"name": JAVASCRIPT_ORIGIN, "listed": {key},
                "answers": {key: {"authors": [], "source": None, "licences": [(declared, declared, "", False)]}},
                "roots": {key: folder_}, "declared": {key: declared}, "paths": set(), "members": {}}

    packaged = os.path.join(scratch, "left-pad")
    os.makedirs(packaged)
    with open(os.path.join(packaged, "LICENSE"), "w", encoding="utf-8") as target:
        target.write(mit)
    text = render(gather([script(packaged)], nothing, {}, reader, "companion"), COMPANION_HEADER)
    expect("a JavaScript package has an entry that says javascript and carries the text of its own licence file",
           "  - left-pad 1.3.0 | javascript" in text and "Permission is hereby granted" in text)
    bare_package = os.path.join(scratch, "bare-package")
    os.makedirs(bare_package)
    refuses("a JavaScript package that ships no licence file and has no kept text is refused",
            lambda: gather([script(bare_package)], nothing, {}, reader, "companion"), "left-pad 1.3.0 ships no licence file")
    refuses("a kept entry for an unknown product is refused",
            lambda: keep([item], [{**pinned, "products": ["compainon"]}], []), "which is neither programs nor companion")
    kept_for, files_for = keep([item], [{**pinned, "products": ["companion"]}], [])
    try:
        gather([made_up([plain])], kept_for, files_for, reader, "programs")
        asked = True
    except SystemExit:
        asked = False
    expect("a text kept for the companion alone is not asked of the release programs' notice", asked)
    refuses("a text kept for the companion alone is refused when no companion build compiles its crate",
            lambda: gather([made_up([plain], name="rust")], kept_for, files_for, reader, "companion"), "which no companion build compiles")
    with open(os.path.join(ROOT, "scripts", "check-mobile-graph.py"), encoding="utf-8") as source:
        graph = re.search(r"^MOBILE_TARGETS = \[(.*?)\]", source.read(), re.DOTALL | re.MULTILINE)
    expect("the companion's notice covers every mobile target that the graph check reads",
           bool(graph) and set(re.findall(r'"([^"]+)"', graph.group(1))) <= set(read_companion()["targets"]))

    lined = "one\ntwo\nthree\nfour\n"
    write(standard, "lined", lined)
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
