#!/usr/bin/env python3
"""Refuses to send anything that is not the product.

    python3 scripts/check-outgoing-records.py check [--range <base>..<head>] [--package-dir <glob>]...
    python3 scripts/check-outgoing-records.py self-test

Two places a file can leave this repository, and both are checked.

The outgoing commit range. Every commit in it, not only the tree at the end: a file removed in a
later commit is still in the earlier one, and a push sends both. So each commit's own tree is read
for names, and every file a commit added or changed is read for contents.

The published package file lists. What a package would carry is not what Git tracks: a manifest's
`files`, an ignore file and a step that runs before packing all decide it, and only the packer knows
the answer. Each public npm package under `packages/`, `apps/` and `workers/` is asked with
`npm pack --dry-run`, running the steps the real pack runs, and each file it lists is read where it
is. The release's own packer, `pnpm pack`, adds the workspace `LICENSE` to a package that has none;
that file is tracked, so the commit scan reads it whenever a commit changes it. `--package-dir`
names directories whose every file a package ships whole; a glob that matches no directory is a
finding, because a check that looked at nothing has proved nothing.

What it refuses is anything that is a record of building this product rather than part of it:
local planning and review records, build-agent instruction files and credentials. A finding names
the path and where it was found, and never prints what was in it. The names and the three credential
shapes are those the website repository's own record check refuses, except that a private key needs
a body after its header: a header quoted in source text is not a key, and tests that refuse keys
quote one.

The `.gitignore` proof is not made here; each repository has a script that creates every assistant
instruction name in a clone and asks `git check-ignore` about it.

The outgoing range is, in order: `--range`; the pull request's base branch (`GITHUB_BASE_REF`);
the commit a push replaced (`GITHUB_EVENT_BEFORE`); the commits on `HEAD` that `origin/main` lacks.
A range that cannot be worked out is a failure. A range that holds no commit is not a clean one:
an empty list reads as "nothing to refuse", so the tree at `HEAD` is inspected instead.

Exit status is 0 when everything outgoing is the product, 1 when it is not, 2 for a bad command.

`self-test` builds repositories for the purpose and plants each fault in them: the check must refuse
every one and pass the near misses.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

# The row this copy of the check carries, written in front of each self-test case.
KEY = ""

SCRIPT = os.path.abspath(__file__)
MAX_CONTENT_BYTES = 32 * 1024 * 1024
PACK_SECONDS = 600
BATCH_BYTES = 64 * 1024 * 1024
NPM_ROOTS = ("packages", "apps", "workers")
EMPTY = "0" * 40

# Paths that are a record of the build rather than the product, with why each is refused. The first
# group is the build-agent instruction files and configuration, the second is this product's own
# local records, which live outside every checkout, and the third is credential material. The first
# rule that matches names the reason, so `.cursorrules` reads as a configuration file. A single
# letter in brackets (`artifact[s]`, `hand[o]ff`) matches what the plain letter does and keeps this
# file's own text from matching the repository's patterns for records it must not name; do not
# simplify them.
FORBIDDEN = [
    (r"(^|/)(agents|claude|gemini)[^/]*\.md\Z", "a build-agent instruction file"),
    (
        r"(^|/)\.(claude|codex|agents|gemini|cursor|windsurf|aider|clinerules)",
        "a build-agent configuration directory or file",
    ),
    (r"(^|/)\.cursorrules\Z|(^|/)\.windsurfrules\Z", "a build-agent instruction file"),
    (
        r"(^|/)\.github/(copilot-instructions\.md|instructions/|prompts/)",
        "a build-agent instruction file",
    ),
    (
        r"(^|/)kalareach(-ledger|-goal)?\.md\Z",
        "a local planning record that lives outside every checkout",
    ),
    (
        r"(^|/)kalareach-artifact[s](/|\Z)",
        "the local records directory, which lives outside every checkout",
    ),
    (r"(^|/)[^/]*-(hand[o]ff|assignment|plan|audit)\.md\Z", "a local task record"),
    (r"(^|/)(logs|run-slots|lead-scripts)/", "a local run record or coordination script"),
    (r"(^|/)reviews/[^/]*-review-\d+\.md\Z", "a local review record"),
    # Every `.env` and every suffix of one. The example file is allowed back by name below rather
    # than by a pattern, because `.env.example.private` is not the example file.
    (r"(^|/)\.env(\.|\Z)", "an environment file that may hold values"),
    (r"(^|/)\.dev\.vars(\.|\Z)", "a local runtime secrets file"),
    (r"\.(pem|p8|p12|pfx|jks|keystore)\Z", "key or certificate material"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)\Z", "a private SSH key"),
    (r"(^|/)[^/]*(service-account|credentials|secret)[^/]*\.json\Z", "a credential file"),
]
FORBIDDEN = [(re.compile(pattern, re.IGNORECASE | re.ASCII), why) for pattern, why in FORBIDDEN]

# Paths that may match a pattern above. The example file holds names and never values.
ALLOWED = (".env.example",)

# Shapes that are a credential wherever they appear. Narrow on purpose: a check that guessed at what
# a secret looks like would refuse a release for a string in a dependency.
PEM_HEADER = re.compile(rb"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----")
# A key is told by what its body is, not by how it is laid out. The body of every unencrypted
# private key is the base64 of a DER SEQUENCE (the bytes 0x30 and a length, which read `M` and a
# letter from `A` to `P`), of an OpenSSH key (`b3Bl`, from "openssh-key-v1") or, for a PGP block,
# of a packet tag (`l`); an encrypted traditional key says so in its `Proc-Type` and `DEK-Info`
# header lines, and a PGP block may carry `Version` lines first. So the
# text after a header is read past what a key written out as source text has between its lines
# (white space, escaped line breaks, a backslash that continues a string, quotes, joiners, commas,
# comment markers including `///` and `//!`), and the body is that signature followed by 16
# characters of base64 in all, wherever the source text breaks them. A quoted header followed by
# code or prose does not read as a key. The read goes forward one item at a time and never back,
# so its time is in proportion to the window; keep it so.
LAYOUT = re.compile(rb"\s+|\\+(?:[rnt/]|\r?\n)|[\"'`+,;#*/!]+")
NAME_LINE = re.compile(rb"[A-Za-z-]+: [^\r\n\\]*(?:\r?\n|\\r|\\n)")
ENCRYPTED_LINE = re.compile(rb"(?:Proc-Type|DEK-Info): ")
BASE64 = re.compile(rb"[A-Za-z0-9+/]+")
BODY_START = re.compile(rb"M[A-P]|b3Bl")
PGP_BODY_START = re.compile(rb"l")
BODY_CHARACTERS = 16
KEY_WINDOW = 8192


def key_body_follows(window, pgp):
    """Whether the text after a private key's header is the body of a key."""
    position = 0
    encrypted = False
    while True:
        item = NAME_LINE.match(window, position)
        if item is not None:
            encrypted = encrypted or ENCRYPTED_LINE.match(item.group()) is not None
        else:
            item = LAYOUT.match(window, position)
        if item is None:
            break
        position = item.end()
    start = PGP_BODY_START if pgp else BODY_START
    if not encrypted and start.match(window, position) is None:
        return False
    seen = 0
    while seen < BODY_CHARACTERS:
        run = BASE64.match(window, position)
        if run is not None:
            seen += len(run.group())
            position = run.end()
            continue
        item = LAYOUT.match(window, position)
        if item is None:
            break
        position = item.end()
    return seen >= BODY_CHARACTERS
LIVE_KEY = re.compile(rb"\bsk_live_[0-9A-Za-z]{20,}")
WEBHOOK_SECRET = re.compile(rb"\bwhsec_[0-9A-Za-z]{20,}")


class GitFailed(Exception):
    pass


def git(*arguments, input_bytes=None, root=None):
    done = subprocess.run(
        ["git", *arguments],
        cwd=root,
        input=input_bytes,
        capture_output=True,
    )
    if done.returncode != 0:
        raise GitFailed(done.stderr.decode(errors="replace").strip())
    return done.stdout


def repository_root():
    try:
        return git("rev-parse", "--show-toplevel").decode().strip()
    except (GitFailed, FileNotFoundError):
        return os.getcwd()


def refused_name(path):
    """Why a path is not the product, or None."""
    if path in ALLOWED:
        return None
    for pattern, why in FORBIDDEN:
        if pattern.search(path):
            return why
    return None


def refused_contents(data):
    """What a file holds that is a credential, one description each."""
    found = []
    for header in PEM_HEADER.finditer(data):
        pgp = b"PGP" in (header.group(1) or b"")
        if key_body_follows(data[header.end() : header.end() + KEY_WINDOW], pgp):
            found.append("a private key")
            break
    if LIVE_KEY.search(data):
        found.append("a live payment provider key")
    if WEBHOOK_SECRET.search(data):
        found.append("a webhook endpoint secret")
    return found


def outgoing_range(requested, environment, root):
    """The commits being sent, or None when they cannot be worked out.

    CI knows: a push names what the remote had before it, and a pull request names the branch it
    would merge into. Outside CI the comparison is with origin/main.
    """
    if requested:
        return requested
    base = environment.get("GITHUB_BASE_REF", "")
    if base:
        return f"origin/{base}...HEAD"
    before = environment.get("GITHUB_EVENT_BEFORE", "")
    if before and before != EMPTY:
        return f"{before}..HEAD"
    try:
        git("rev-parse", "--verify", "--quiet", "origin/main", root=root)
    except GitFailed:
        return None
    return "origin/main..HEAD"


def nul_separated(data):
    return [os.fsdecode(part) for part in data.split(b"\0") if part]


def tree_paths(commit, root):
    return nul_separated(git("ls-tree", "-r", "-z", "--name-only", commit, root=root))


def blobs_added_or_changed(commit, root):
    """(path, blob) for every file the commit wrote. A merge's own resolution is read as well: a
    file that differs from both parents was written by the merge and is in nothing else."""
    # A type change (`T`) is a symlink or a submodule that became a file: the new blob is read.
    raw = git(
        "diff-tree", "-r", "-z", "-m", "--root", "--no-commit-id", "--no-renames", "--raw",
        "--diff-filter=AMT", commit,
        root=root,
    )
    parts = [part for part in raw.split(b"\0") if part]
    found = {}
    for index in range(0, len(parts) - 1, 2):
        fields = parts[index].lstrip(b":").split()
        if len(fields) < 5 or fields[1] == b"160000":
            continue
        # A merge lists a file once for each parent it differs from.
        found[(os.fsdecode(parts[index + 1]), fields[3].decode())] = None
    return list(found)


def scan_blobs(blobs, root):
    """What each blob holds that is a credential: a dict of blob id to descriptions, or to None
    when it could not be read or is larger than this will read. The blobs are read in batches and
    only the verdict is kept, so a long range is never held in memory whole."""
    verdicts = {}

    def flush(batch):
        if not batch:
            return
        wanted = b"".join(blob.encode() + b"\n" for blob in batch)
        stream = git("cat-file", "--batch", input_bytes=wanted, root=root)
        at = 0
        for blob in batch:
            end = stream.index(b"\n", at)
            size = int(stream[at:end].split()[2])
            verdicts[blob] = refused_contents(stream[end + 1 : end + 1 + size])
            at = end + 1 + size + 1

    ordered = sorted(set(blobs))
    for start in range(0, len(ordered), 500):
        chunk = ordered[start : start + 500]
        wanted = b"".join(blob.encode() + b"\n" for blob in chunk)
        sizes = git("cat-file", "--batch-check", input_bytes=wanted, root=root).decode().splitlines()
        batch, held = [], 0
        for blob, line in zip(chunk, sizes):
            fields = line.split()
            if len(fields) != 3 or int(fields[2]) > MAX_CONTENT_BYTES:
                verdicts[blob] = None
                continue
            if batch and held + int(fields[2]) > BATCH_BYTES:
                flush(batch)
                batch, held = [], 0
            batch.append(blob)
            held += int(fields[2])
        flush(batch)
    return verdicts


def pack_listing(text):
    """The file paths in `npm pack --json`, read from the last JSON array in its output. A step
    that runs before packing may write to standard output ahead of it."""
    decoder = json.JSONDecoder()
    offset = 0
    listing = None
    for line in text.splitlines(keepends=True):
        if line.strip() == "[":
            try:
                value, _ = decoder.raw_decode(text, offset)
            except ValueError:
                value = None
            if isinstance(value, list):
                listing = value
        offset += len(line)
    if listing is None:
        return None
    # A package lists at least its own manifest. A listing that names no file is no listing.
    paths = [
        file["path"]
        for entry in listing
        if isinstance(entry, dict) and isinstance(entry.get("files"), list)
        for file in entry["files"]
        if isinstance(file, dict) and isinstance(file.get("path"), str)
    ]
    return paths or None


def npm_packages(root):
    """The public npm packages in the workspace and what the packer says each would carry."""
    packages = []
    for base in NPM_ROOTS:
        parent = os.path.join(root, base)
        if not os.path.isdir(parent):
            continue
        for name in sorted(os.listdir(parent)):
            directory = os.path.join(parent, name)
            manifest = os.path.join(directory, "package.json")
            if not os.path.isfile(manifest):
                continue
            try:
                with open(manifest, encoding="utf-8") as handle:
                    parsed = json.load(handle)
            except ValueError:
                parsed = None
            if not isinstance(parsed, dict):
                packages.append(
                    {
                        "name": f"{base}/{name}",
                        "directory": directory,
                        "files": None,
                        "reason": "package.json is not a JSON object",
                    }
                )
                continue
            # A private package is never published, so what it would carry is not a way anything
            # leaves this repository.
            if parsed.get("private") is True:
                continue
            label = parsed.get("name") if isinstance(parsed.get("name"), str) else f"{base}/{name}"
            reason = ""
            try:
                # Whatever the configuration says, the steps that run before packing run: they
                # generate files the package carries.
                done = subprocess.run(
                    ["npm", "pack", "--dry-run", "--json", "--ignore-scripts=false"],
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    timeout=PACK_SECONDS,
                )
                files = pack_listing(done.stdout) if done.returncode == 0 else None
                if files is None:
                    lines = [
                        line
                        for line in done.stderr.strip().splitlines()
                        if line.strip() and "complete log of this run" not in line
                    ]
                    reason = lines[-1][:200] if lines else f"npm exited {done.returncode}"
            except (OSError, subprocess.TimeoutExpired) as problem:
                files = None
                reason = type(problem).__name__
            packages.append({"name": label, "directory": directory, "files": files, "reason": reason})
    return packages


def directory_packages(patterns, root):
    """Directories matched by each glob, and every file under each one."""
    packages = []
    unmatched = []
    for pattern in patterns:
        matches = sorted(
            match for match in glob.glob(pattern, root_dir=root) if os.path.isdir(os.path.join(root, match))
        )
        if not matches:
            unmatched.append(pattern)
        for match in matches:
            directory = os.path.join(root, match)
            files, links = [], []
            for current, directories, names in os.walk(directory):
                for name in directories + names:
                    full = os.path.join(current, name)
                    relative = os.path.relpath(full, directory).replace(os.sep, "/")
                    if os.path.islink(full):
                        links.append(relative)
                    elif name in names:
                        files.append(relative)
            packages.append({"name": match, "directory": directory, "files": sorted(files), "links": links})
    return packages, unmatched


def package_findings(held):
    """What one package would carry that is not the product."""
    if held["files"] is None:
        reason = f" ({held['reason']})" if held.get("reason") else ""
        return [f"{held['name']} could not be packed{reason}, so what it would carry is unknown"]
    findings = [
        f"{path} in the package {held['name']} is a link, so what it points at was not inspected"
        for path in held.get("links", [])
    ]
    for path in held["files"]:
        why = refused_name(path)
        if why is not None:
            findings.append(f"{path} is {why}; it is in the package {held['name']}")
            continue
        full = os.path.join(held["directory"], path)
        try:
            if not os.path.isfile(full) or os.path.getsize(full) > MAX_CONTENT_BYTES:
                raise OSError
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError:
            findings.append(
                f"{path} in the package {held['name']} could not be read, so its contents were not inspected"
            )
            continue
        for what in refused_contents(data):
            findings.append(f"{path} contains {what} in the package {held['name']}")
    return findings


def run_check(range_argument, package_patterns):
    """Reads the outgoing content and prints what it found. Returns the exit status."""
    root = repository_root()
    print("outgoing records")

    resolved = outgoing_range(range_argument, os.environ, root)
    if resolved is None:
        print("\nThe outgoing commit range could not be worked out. Pass --range <base>..<head>.")
        return 1
    try:
        commits = git("rev-list", "--end-of-options", resolved, root=root).decode().split()
    except GitFailed:
        print(f"\nThe range {resolved} could not be read.")
        return 1

    # A range that holds no commit is not a clean range; it is a range nobody inspected. The tree
    # at the head is inspected instead, so the check always looks at something.
    try:
        head = git("rev-parse", "HEAD", root=root).decode().strip()
    except GitFailed:
        print("\nThe repository has no commit to inspect.")
        return 1
    inspected = commits or [head]

    findings = []
    found = {}
    # Oldest first, so a path is named for the first commit in the range that holds it.
    for commit in reversed(inspected):
        for path in tree_paths(commit, root):
            found.setdefault(path, commit)
    print(f"  commits    {len(commits)} in {resolved}")
    print(f"  trees      {len(inspected)} inspected")
    print(f"  paths      {len(found)} across every one of them")
    if not commits:
        print("             The range holds no commit, so the tree at HEAD was inspected instead.")
    for path, commit in found.items():
        why = refused_name(path)
        if why is not None:
            findings.append(f"{path} is {why}; it is in commit {commit[:12]}")

    # And what those commits put in them. A credential inside a source file is not a filename
    # anything would refuse, and one removed in a later commit is still in the earlier one.
    written = []
    for commit in inspected:
        if commits:
            written += [(commit, path, blob) for path, blob in blobs_added_or_changed(commit, root)]
        else:
            tree = git("ls-tree", "-r", "-z", commit, root=root)
            for entry in tree.split(b"\0"):
                meta, _, path = entry.partition(b"\t")
                fields = meta.split()
                if len(fields) == 3 and fields[1] == b"blob":
                    written.append((commit, os.fsdecode(path), fields[2].decode()))
    verdicts = scan_blobs([blob for _, _, blob in written], root)
    for commit, path, blob in written:
        problems = verdicts.get(blob)
        if problems is None:
            findings.append(
                f"{path} in commit {commit[:12]} could not be read, or is too large to, "
                "so its contents were not inspected"
            )
            continue
        for what in problems:
            findings.append(f"{path} contains {what}; it is in commit {commit[:12]}")
    print(f"  contents   {len(written)} files the range added or changed")

    packages = npm_packages(root)
    directories, unmatched = directory_packages(package_patterns, root)
    for held in packages + directories:
        findings += package_findings(held)
    for pattern in unmatched:
        findings.append(f"the package directories {pattern} matched no directory, so nothing was inspected")
    print(f"  packages   {len(packages) + len(directories)} that would be published")

    if not findings:
        print("\nEverything outgoing is the product.")
        return 0
    print("\nThese are not the product:")
    for finding in findings:
        print(f"  - {finding}")
    print("\nRemove each of them from every commit in the range, not only from the last one.")
    return 1


# ---------------------------------------------------------------------------------------------
# The self-test.

GIT_ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "Check",
    "GIT_AUTHOR_EMAIL": "check@example.invalid",
    "GIT_COMMITTER_NAME": "Check",
    "GIT_COMMITTER_EMAIL": "check@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def planted(*parts):
    """A name put together at run time, so this file never holds one."""
    return "".join(parts)


class Fixture:
    """A repository with one base commit, under the self-test's scratch directory."""

    made = 0

    def __init__(self, scratch):
        Fixture.made += 1
        self.directory = os.path.join(scratch, f"repository-{Fixture.made}")
        os.makedirs(self.directory)
        self.git("init", "--quiet", "--initial-branch=main")
        self.write("README.md", "# A product\n")
        self.base = self.commit("Start")

    def git(self, *arguments, input_bytes=None):
        done = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *arguments],
            cwd=self.directory,
            env={**os.environ, **GIT_ENVIRONMENT},
            input=input_bytes,
            capture_output=True,
        )
        if done.returncode != 0:
            raise RuntimeError(f"git {' '.join(arguments)} failed: {done.stderr.decode().strip()}")
        return done.stdout.decode().strip()

    def write(self, path, content):
        full = os.path.join(self.directory, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(content if isinstance(content, bytes) else content.encode())

    def delete(self, path):
        os.remove(os.path.join(self.directory, path))

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def holds(self, commit, path):
        return path in self.git("ls-tree", "-r", "--name-only", commit).split("\n")

    def run(self, *arguments, environment=None):
        """Runs the check in this repository and returns its status and what it printed."""
        clean = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        clean.update(environment or {})
        done = subprocess.run(
            [sys.executable, "-I", SCRIPT, "check", *arguments],
            cwd=self.directory,
            env=clean,
            capture_output=True,
            text=True,
        )
        return done.returncode, done.stdout + done.stderr


def self_test():
    scratch = tempfile.mkdtemp(prefix="kalareach-outgoing-")
    results = []

    def expect(name, condition, detail=""):
        label = f"{KEY}: {name}" if KEY else name
        print(("ok    " if condition else "FAIL  ") + label)
        if not condition and detail:
            print(textwrap.indent(detail.rstrip(), "      "))
        results.append(bool(condition))

    try:
        cases(scratch, expect)
    finally:
        # Only a directory this run made, under the directory it made it in.
        if scratch.startswith(os.path.join(tempfile.gettempdir(), "kalareach-outgoing-")):
            shutil.rmtree(scratch, ignore_errors=True)

    failed = results.count(False)
    print(f"{len(results) - failed} of {len(results)} cases hold")
    return 1 if failed else 0


def cases(scratch, expect):
    agent_file = planted("CLA", "UDE.md")
    local_names = {
        agent_file: "a build-agent instruction file",
        planted("docs/AGE", "NTS.md"): "a build-agent instruction file",
        planted(".cla", "ude/settings.json"): "a build-agent configuration directory or file",
        planted(".cursor", "rules"): "a build-agent configuration directory or file",
        planted(".github/copilot-", "instructions.md"): "a build-agent instruction file",
        planted("kalareach", "-ledger.md"): "a local planning record",
        planted("notes/kalareach-", "artifacts/x.txt"): "the local records directory",
        planted("docs/x", "-hand", "off.md"): "a local task record",
        planted("log", "s/run.txt"): "a local run record",
        planted("lead-", "scripts/go.sh"): "a local run record or coordination script",
        planted("reviews/x-", "review-", "1.md"): "a local review record",
        ".env": "an environment file",
        ".env.local": "an environment file",
        ".dev.vars": "a local runtime secrets file",
        "deploy/server.pem": "key or certificate material",
        "keys/AuthKey.p8": "key or certificate material",
        "keys/id_ed25519": "a private SSH key",
        "config/service-account.json": "a credential file",
    }
    private_key = (
        planted("-----", "BEGIN PRIVATE KEY", "-----")
        + "\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzfakekeymaterial\n"
        + planted("-----", "END PRIVATE KEY", "-----\n")
    )
    key_body = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzfakekeymaterial"
    live_key = planted("sk", "_live_", "51H8xKjE2eZvKYlo2C0aBcDeFgHiJkLmNoPqRsTuVwXyZ")
    webhook_secret = planted("whsec", "_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")

    # A range carrying only the product passes.
    fx = Fixture(scratch)
    fx.write("src/main.rs", "fn main() {}\n")
    fx.write(".env.example", "TOKEN=\n")
    fx.write("src/logs.rs", "pub fn logs() {}\n")
    fx.write("docs/logs-and-more.md", "# Notes\n")
    head = fx.commit("Add the program")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect("a range carrying only the product passes", status == 0, output)

    # A file added in one commit and removed in the next is still in the first, and a push sends
    # both.
    fx = Fixture(scratch)
    fx.write(agent_file, "notes\n")
    added = fx.commit("Add notes")
    fx.delete(agent_file)
    removed = fx.commit("Remove notes")
    status, output = fx.run("--range", f"{fx.base}..{removed}")
    expect(
        "a record added in one commit and deleted in the next is found in the commit that added it",
        status == 1
        and agent_file in output
        and added[:12] in output
        and not fx.holds(removed, agent_file),
        output,
    )

    # Every kind of name is refused, wherever it is put.
    fx = Fixture(scratch)
    for path in local_names:
        fx.write(path, "x\n")
    added = fx.commit("Add every kind")
    fx.git("rm", "-r", "--quiet", ".")
    fx.write("README.md", "# A product\n")
    removed = fx.commit("Remove every kind")
    status, output = fx.run("--range", f"{fx.base}..{removed}")
    missing = [path for path, why in local_names.items() if f"  - {path} is {why}" not in output]
    expect(
        "every kind of local record, instruction file and credential name is refused by its path",
        status == 1 and not missing,
        f"not named: {missing}\n{output}",
    )

    # The example environment file is the product (the first case adds it); a suffix of it is not.
    fx = Fixture(scratch)
    fx.write(".env.example.private", "TOKEN=\n")
    head = fx.commit("Add a suffix")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a suffix of the example environment file is not the example file",
        status == 1 and ".env.example.private" in output,
        output,
    )

    # A key with a body added and removed in the next commit is found in the first, by what it holds.
    fx = Fixture(scratch)
    fx.write("src/keys.rs", private_key)
    added = fx.commit("Add a key")
    fx.write("src/keys.rs", "pub const KEY: &str = \"\";\n")
    removed = fx.commit("Remove the key")
    status, output = fx.run("--range", f"{fx.base}..{removed}")
    expect(
        "a private key added and removed later is found in the commit that added it, and not printed",
        status == 1
        and "src/keys.rs" in output
        and "a private key" in output
        and added[:12] in output
        and key_body not in output,
        output,
    )

    # A key written out as source text is still a key. A header quoted in source text, or in prose,
    # is not one: the tests that refuse keys quote one.
    header = planted("-----", "BEGIN PRIVATE KEY", "-----")
    shapes = {
        "src/joined.rs": f'const K: &str = "{header}\\n" + "{key_body[:32]}" + "{key_body[32:]}";\n',
        "src/lines.js": f'const K = ["{header}", "{key_body[:32]}", "{key_body[32:]}"].join("\\n");\n',
        "src/comment.py": f"# {header}\n# {key_body}\n",
        "src/slashes.ts": f"// {header}\n// {key_body}\n",
        "src/docs.rs": f"//! {header}\n//! {key_body}\n",
        "src/triple.rs": f"/// {header}\n/// {key_body}\n",
        "src/continued.rs": f'const K: &str = "{header}\\n\\\n{key_body}";\n',
        "src/quoted.sh": f"K='{header}\n'\"'\"'{key_body}'\n",
        "src/ticks.js": f"const K = `{header}` + `{key_body}`;\n",
        "src/starred.c": f"/*\n * {header}\n * {key_body}\n */\n",
        "src/semi.txt": f"{header};\t{key_body};\n",
        "src/escaped.json": json.dumps({"k": f"{header}\n{key_body}\n"}).replace("\\n", "\\\\n"),
        "src/short.txt": header
        + "\n"
        + "\n".join(key_body[i : i + 16] for i in range(0, len(key_body), 16))
        + "\n",
        "src/encrypted.pem.txt": f"{header}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{key_body}\n",
        "src/eight.js": f'const K = "{header}\\n" + "{key_body[:8]}" + "{key_body[8:]}";\n',
        "src/uneven.js": f'const K = "{header}\\n" +\n  "{key_body[:24]}" +\n  "{key_body[24:32]}" +\n  "{key_body[32:]}\\n";\n',
        "src/commented-short.rs": f"// {header}\n" + "".join(f"// {key_body[i : i + 24]}\n" for i in range(0, len(key_body), 24)),
        "src/php.json": '{"k":"' + header + "\\n" + key_body[:10] + "\\/" + key_body[10:] + '\\n"}\n',
        "src/openssh.txt": planted("-----", "BEGIN OPENSSH PRIVATE KEY", "-----") + "\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n",
        "src/pgp.asc": planted("-----", "BEGIN PGP PRIVATE KEY BLOCK", "-----") + "\n\nlQOYBGPexampleexampleexampleexampleexample\n",
        "src/pgp-version.asc": planted("-----", "BEGIN PGP PRIVATE KEY BLOCK", "-----") + "\nVersion: Example 1.0\n\nlQOYBGPexampleexampleexampleexampleexample\n",
    }
    fx = Fixture(scratch)
    for path, text in shapes.items():
        fx.write(path, text)
    added = fx.commit("Add keys written as source")
    fx.git("rm", "--quiet", *shapes)
    removed = fx.commit("Remove them")
    status, output = fx.run("--range", f"{fx.base}..{removed}")
    missing = [path for path in shapes if f"  - {path} contains a private key" not in output]
    expect(
        "a key split by quotes, joiners, comment markers, doubled escapes or short lines is a key",
        status == 1 and not missing and key_body[:32] not in output,
        f"not named: {missing}\n{output}",
    )

    fx = Fixture(scratch)
    fx.write("src/test.rs", f'write("server.txt", "{header}\\n");\n')
    fx.write("src/format.rs", f'format!("{header}\\n{{}}\\n", body);\n')
    fx.write("docs/prose.md", f"The file starts with {header} and then carries the base64 text.\n")
    fx.write("src/call.js", f'const marker = "{header}";\nvalidatePrivateKey(marker);\n')
    fx.write("src/name.js", f"const marker = '{header}\\n' + base64PrivateKey;\n")
    fx.write("docs/long.md", f"Quoting {header} internationalization notes is not a key.\n")
    fx.write("docs/note.md", f"{header}\nNote: the internationalization of the notes follows here\ninternationalizationofthenotes\n")
    fx.write("src/bang.js", f'const marker = "{header}";\n!validatePrivateKeyAndCertificateChain(marker);\n')
    fx.write("src/digest.rs", f'const H: &str = "{header}"; const D: &str = "{"a1" * 32}";\n')
    fx.write("src/table.rs", f'let x = "{header}"; MAPPINGTABLE.get(1);\n')
    head = fx.commit("Quote a header")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect("a private key header with no body after it, quoted or in prose, is not a key", status == 0, output)

    fx = Fixture(scratch)
    fx.write("src/pay.rs", f'const PAY: &str = "{live_key}";\n')
    fx.write("src/hook.rs", f'const HOOK: &str = "{webhook_secret}";\n')
    head = fx.commit("Add secrets")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a live payment key and a webhook secret are refused by what they hold, and not printed",
        status == 1
        and "src/pay.rs" in output
        and "src/hook.rs" in output
        and live_key not in output
        and webhook_secret not in output,
        output,
    )

    # A merge brings its side branch's commits with it.
    fx = Fixture(scratch)
    fx.git("checkout", "--quiet", "-b", "side")
    fx.write(agent_file, "notes\n")
    added = fx.commit("Add notes on the side")
    fx.delete(agent_file)
    fx.commit("Remove notes on the side")
    fx.git("checkout", "--quiet", "main")
    fx.write("src/main.rs", "fn main() {}\n")
    fx.commit("Work on main")
    fx.git("merge", "--quiet", "--no-ff", "-m", "Merge the side", "side")
    merged = fx.git("rev-parse", "HEAD")
    status, output = fx.run("--range", f"{fx.base}..{merged}")
    expect(
        "a record added and removed on a merged branch is found",
        status == 1 and agent_file in output and added[:12] in output,
        output,
    )

    # A merge's own resolution is read: a file that differs from both parents is in nothing else.
    fx = Fixture(scratch)
    fx.write("src/conf.txt", "base\n")
    start = fx.commit("Add the file")
    fx.git("checkout", "--quiet", "-b", "side")
    fx.write("src/conf.txt", "side\n")
    fx.commit("Change it on the side")
    fx.git("checkout", "--quiet", "main")
    fx.write("src/conf.txt", "main\n")
    fx.commit("Change it on main")
    fx.git("merge", "--quiet", "--no-commit", "-s", "ours", "side")
    fx.write("src/conf.txt", private_key)
    merged = fx.commit("Merge the side")
    status, output = fx.run("--range", f"{start}..{merged}")
    expect(
        "a credential written by a merge's resolution alone is found, once",
        status == 1
        and output.count("src/conf.txt contains a private key") == 1
        and merged[:12] in output,
        output,
    )

    # A link that becomes a file holding a key, and the file removed in the next commit.
    fx = Fixture(scratch)
    os.makedirs(os.path.join(fx.directory, "config"))
    os.symlink("elsewhere.toml", os.path.join(fx.directory, "config", "app.toml"))
    linked = fx.commit("Add a link")
    os.remove(os.path.join(fx.directory, "config", "app.toml"))
    fx.write("config/app.toml", private_key)
    changed = fx.commit("Make it a file")
    fx.delete("config/app.toml")
    removed = fx.commit("Remove the file")
    status, output = fx.run("--range", f"{linked}..{removed}")
    expect(
        "a link that becomes a file holding a key is read, although the next commit removes it",
        status == 1 and "config/app.toml contains a private key" in output and changed[:12] in output,
        output,
    )

    # The package file lists.
    npm_manifest = json.dumps(
        {
            "name": "lib",
            "version": "1.0.0",
            "files": ["out"],
            "scripts": {"prepack": "echo noise from the pack step && node write.js"},
        }
    )
    writes = "const fs = require('node:fs');\nfs.mkdirSync('out', { recursive: true });\n"

    fx = Fixture(scratch)
    fx.write(".gitignore", "out/\n")
    fx.write("packages/lib/package.json", npm_manifest)
    fx.write("packages/lib/write.js", writes + f"fs.writeFileSync('out/{agent_file}', 'x');\n")
    head = fx.commit("Add a package")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a record in a package's file list is found although no commit holds it",
        status == 1
        and f"{agent_file} is a build-agent instruction file; it is in the package lib" in output
        and not fx.holds(head, "packages/lib/out/" + agent_file),
        output,
    )
    # Fresh, because the run above left the generated files on disk.
    fx = Fixture(scratch)
    fx.write(".gitignore", "out/\n")
    fx.write("packages/lib/package.json", npm_manifest)
    fx.write("packages/lib/write.js", writes + f"fs.writeFileSync('out/{agent_file}', 'x');\n")
    head = fx.commit("Add a package")
    status, output = fx.run("--range", f"{fx.base}..{head}", environment={"NPM_CONFIG_IGNORE_SCRIPTS": "true"})
    expect(
        "a configuration that skips the steps before packing does not hide what they generate",
        status == 1 and f"{agent_file} is a build-agent instruction file; it is in the package lib" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write(".gitignore", "out/\n")
    fx.write("packages/lib/package.json", npm_manifest)
    fx.write("packages/lib/write.js", writes + "fs.writeFileSync('out/index.js', 'export {};');\n")
    head = fx.commit("Add a package")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a package whose list holds only the product passes",
        status == 0 and "1 that would be published" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write(".gitignore", "out/\n")
    fx.write("packages/lib/package.json", npm_manifest)
    fx.write("packages/lib/write.js", writes + f"fs.writeFileSync('out/data.txt', {json.dumps(private_key)});\n")
    head = fx.commit("Add a package")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a private key in a package's file list is found by its contents, and not printed",
        status == 1
        and "out/data.txt contains a private key in the package lib" in output
        and key_body not in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write(".gitignore", "out/\n")
    fx.write("packages/lib/package.json", npm_manifest.replace('"version"', '"private": true, "version"'))
    fx.write("packages/lib/write.js", writes + f"fs.writeFileSync('out/{agent_file}', 'x');\n")
    head = fx.commit("Add a private package")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect("a private package is never published, so its list is not read", status == 0, output)

    fx = Fixture(scratch)
    fx.write("packages/lib/package.json", npm_manifest)
    fx.write("packages/lib/write.js", "process.exit(1);\n")
    head = fx.commit("Add a package that cannot be packed")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a package that cannot be packed is a finding, not a pass",
        status == 1 and "lib could not be packed" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write("packages/lib/package.json", "[]\n")
    head = fx.commit("Add a manifest that is not an object")
    status, output = fx.run("--range", f"{fx.base}..{head}")
    expect(
        "a manifest that is not a JSON object is a finding and not a skipped package",
        status == 1 and "package.json is not a JSON object" in output,
        output,
    )

    # Directories whose every file a package ships.
    fx = Fixture(scratch)
    fx.write("plugins/acme/one/plugin.json", "{}\n")
    fx.write("plugins/acme/two/plugin.json", "{}\n")
    fx.write("plugins/acme/two/" + agent_file, "notes\n")
    head = fx.commit("Add two packages")
    status, output = fx.run("--range", f"{fx.base}..{head}", "--package-dir", "plugins/*/*")
    expect(
        "a record in a package directory is found, and the clean one beside it is not named",
        status == 1
        and f"{agent_file} is a build-agent instruction file; it is in the package plugins/acme/two" in output
        and "plugins/acme/one" not in output.split("These are not the product")[-1],
        output,
    )
    status, output = fx.run("--range", f"{fx.base}..{head}", "--package-dir", "plugins/*/three")
    expect(
        "a package directory pattern that matches nothing is refused",
        status == 1 and "matched no directory" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write("plugins/acme/one/plugin.json", "{}\n")
    fx.write("plugins/acme/two/plugin.json", "{}\n")
    head = fx.commit("Add two packages")
    status, output = fx.run("--range", f"{fx.base}..{head}", "--package-dir", "plugins/*/*")
    expect(
        "package directories holding only the product pass",
        status == 0 and "2 that would be published" in output,
        output,
    )

    # The range.
    fx = Fixture(scratch)
    status, output = fx.run("--range", "nosuch..HEAD")
    expect("a range that cannot be read is a failure", status == 1 and "could not be read" in output, output)
    status, output = fx.run()
    expect(
        "a range nobody could work out is a failure and not an empty pass",
        status == 1 and "could not be worked out" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write(agent_file, "notes\n")
    fx.write("src/pay.rs", f'const PAY: &str = "{live_key}";\n')
    head = fx.commit("Add notes and a key")
    status, output = fx.run("--range", f"{head}..{head}")
    expect(
        "a range holding no commit inspects the tree at the head, its names and its contents",
        status == 1
        and agent_file in output
        and "no commit" in output
        and "src/pay.rs contains a live payment provider key" in output,
        output,
    )

    fx = Fixture(scratch)
    fx.write(agent_file, "notes\n")
    added = fx.commit("Add notes")
    fx.delete(agent_file)
    removed = fx.commit("Remove notes")
    status, output = fx.run(environment={"GITHUB_EVENT_BEFORE": fx.base})
    expect(
        "a push is read from the commit it replaced",
        status == 1 and agent_file in output and added[:12] in output,
        output,
    )
    status, output = fx.run(environment={"GITHUB_EVENT_BEFORE": EMPTY})
    expect(
        "a push that replaced nothing falls back to the default and fails when there is none",
        status == 1 and "could not be worked out" in output,
        output,
    )
    fx.git("update-ref", "refs/remotes/origin/release", fx.base)
    status, output = fx.run(environment={"GITHUB_BASE_REF": "release"})
    expect(
        "a pull request is read against its base branch, whichever branch that is",
        status == 1 and agent_file in output and added[:12] in output,
        output,
    )
    fx.git("update-ref", "refs/remotes/origin/main", fx.base)
    status, output = fx.run()
    expect(
        "with nothing named the range is what origin/main lacks",
        status == 1 and agent_file in output and added[:12] in output,
        output,
    )


# ---------------------------------------------------------------------------------------------


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="read the outgoing commits and package file lists")
    check.add_argument("--range", dest="range_argument", help="the commits being sent")
    check.add_argument("--package-dir", action="append", default=[], help="a glob of package directories")
    commands.add_parser("self-test", help="prove each refusal on a planted fault")
    arguments = parser.parse_args(argv)
    if arguments.command == "self-test":
        return self_test()
    return run_check(arguments.range_argument, arguments.package_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
