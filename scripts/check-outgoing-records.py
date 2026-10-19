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
import base64
import binascii
import glob
import hashlib
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
# A key is told by what its body is, not by how it is laid out. The body of an unencrypted private
# key is the base64 of a structure that begins the same way every time: a DER SEQUENCE whose first
# element is the INTEGER version (PKCS#8, PKCS#1, SEC1, DSA) or an algorithm SEQUENCE and its OID
# (encrypted PKCS#8); the bytes `openssh-key-v1` of an OpenSSH key; or, in a PGP block, a secret key
# packet in either header format with a version from 3 to 6. An encrypted traditional key says so
# in its `Proc-Type` and `DEK-Info` lines, and its body is ciphertext. So the text after a header
# is read past what a key written out as source text has between its lines (white space, escaped
# line breaks of any depth, a backslash that continues a string, a PowerShell `n, quotes and string
# prefixes, joiners, commas, margins, comment markers including `///` and `//!`), and the first 32
# characters of base64, taken wherever the source text breaks them, have to begin with that
# structure, so a placeholder shorter than 32 characters is not a key. Where there is no structure
# to check (ciphertext, or a kind of block this does not know, unless its body is a DER structure)
# the body has to look like random bytes, in one of two ways. Where the block's end marker follows
# the body, only base64 and what source text puts between its pieces (of any size) may lie between
# the header and the marker, and the characters of the whole body have to be as many and as
# different as those of random bytes. Where it does not (a body cut off, or a marker elsewhere), the
# first 32 characters have no words (the pieces that source text breaks apart, by quotes, joiners,
# comment markers or line breaks, are one word; a comma, a semicolon, or spaces alone, ends a word,
# which is what separates the pieces of a body from a list of short strings; every word is at least
# 8 characters), hold 17 or more different characters, and the text after them goes on as a body
# goes on (a line break, a quote, an escape, padding, the end, or a space and another long run of
# base64, or a last short one that padding, a quote or the end follows), not into a short word, a
# call or code.
# A quoted header followed by code or prose does not decode to one. The read goes forward one item
# at a time and never back, so its time is in proportion to the window; keep it so.
STRING_PREFIX = rb"(?:u8|[bBrRuUfFL]{1,2})(?=[\"'])"
LAYOUT = re.compile(
    rb"\s+|\\+(?:[rnt/]|\r?\n)|`[rnt]|" + STRING_PREFIX + rb"|[\"'`+,;#*/!@|]+"
)
STRING_PREFIX = re.compile(STRING_PREFIX)
NAME_LINE = re.compile(rb"[A-Za-z-]+: (?:[^\r\n\\`]|\\+/)*(?:\r?\n|\\r|\\n|`[rn])")
ENCRYPTED_LINE = re.compile(rb"(?:Proc-Type|DEK-Info): ")
# JSON may write the `/` of base64 as `\/`, and it is a character of the body there.
BASE64 = re.compile(rb"(?:[A-Za-z0-9+/]|\\+/)+")
MINIMUM_RUN = 8
PADDING = re.compile(rb"=+")
WORD_GAP_WITH_COMMAS = re.compile(rb"[ \t,;]+")
WORD_GAP = re.compile(rb"[ \t;]+")
SPACED_RUN = re.compile(rb"[ \t]+((?:[A-Za-z0-9+/]|\\+/)*)")
BODY_CHARACTERS = 32
END_MARKER = b"-----END "
DISTINCT_CHARACTERS = 17
KEY_WINDOW = 8192


def after_der_length(raw, index):
    """Where the content of a DER element begins, given where its length starts."""
    if index >= len(raw):
        return None
    if raw[index] < 0x80:
        return index + 1
    count = raw[index] & 0x7F
    return index + 1 + count if 1 <= count <= 4 else None


def der_private_key(raw):
    if raw[:1] != b"\x30":
        return False
    inner = after_der_length(raw, 1)
    if inner is None:
        return False
    if raw[inner : inner + 2] == b"\x02\x01" or raw[inner : inner + 1] == b"\x06":
        return True
    if raw[inner : inner + 1] == b"\x30":
        algorithm = after_der_length(raw, inner + 1)
        return algorithm is not None and raw[algorithm : algorithm + 1] == b"\x06"
    return False


# The public-key algorithms an OpenPGP key packet names: RSA, ElGamal, DSA, ECDH, ECDSA, EdDSA, X25519,
# X448, Ed25519 and Ed448.
PGP_ALGORITHMS = (1, 2, 3, 16, 17, 18, 19, 22, 25, 26, 27, 28)


def pgp_private_key(raw):
    """A secret key packet, or the public key packet that a block of secret subkeys starts with, in
    either header format, with a version, a creation time and an algorithm that a key has."""
    tag = raw[0]
    if not tag & 0x80:
        return False
    if tag & 0x40:
        kind = tag & 0x3F
        first = raw[1]
        at = 2 if first < 192 else 3 if first < 224 else 6 if first == 255 else None
    else:
        kind = (tag >> 2) & 0x0F
        at = (2, 3, 5)[tag & 3] if tag & 3 < 3 else None
    if kind not in (5, 6) or at is None or raw[at] not in (3, 4, 5, 6):
        return False
    return raw[at + (7 if raw[at] == 3 else 5)] in PGP_ALGORITHMS


# The kinds of block whose body has a structure to check. Any other kind (`NEBULA X25519`, the
# Cosmos `TENDERMINT`, whatever a tool invents) holds a private key in a format this does not know:
# a DER structure is taken for a key, and anything else has to look like random bytes.
STRUCTURED_KINDS = (b"", b"RSA", b"DSA", b"EC", b"ENCRYPTED", b"OPENSSH", b"PGP")


CLEAN_ENDS = (b"", b"\r", b"\n", b'"', b"'", b"`", b"\\", b"=", b"<")
LAST_PIECE_ENDS = (b"", b"=", b'"', b"'", b"`", b"<")


def body_ends_cleanly(window, position):
    """Whether the text after a body goes on as a body goes on, and not into a short word, a call or code."""
    if window[position : position + 1] in CLEAN_ENDS:
        return True
    spaced = SPACED_RUN.match(window, position)
    if spaced is None:
        return False
    after = window[spaced.end() : spaced.end() + 1]
    if not spaced.group(1):
        return after in CLEAN_ENDS
    # The next line of a body written on one line is a long run; its last line may be a short one.
    return len(spaced.group(1)) >= MINIMUM_RUN or after in LAST_PIECE_ENDS


def completes_block(window, position):
    """Whether the body that starts at `position` runs up to the block's end marker as only base64
    and what source text puts between pieces of it, in words of at least 8 characters (the last may
    be shorter) that only spaces, tabs, commas and semicolons separate, and has as many different characters as random
    bytes do. The end marker is the evidence that makes pieces of any size safe; the words and the
    characters are what tell a body from a sentence, a heading or a list of names between the
    markers."""
    body = bytearray()
    words = []
    last = position
    while True:
        item = STRING_PREFIX.match(window, position)
        if item is None:
            run = BASE64.match(window, position)
            if run is not None:
                characters = run.group().replace(b"\\", b"")
                if characters.strip(b"+/"):
                    if words and WORD_GAP_WITH_COMMAS.fullmatch(window, last, run.start()) is None:
                        words[-1] += len(characters)
                    else:
                        words.append(len(characters))
                    body += characters
                    last = run.end()
            item = run or PADDING.match(window, position) or LAYOUT.match(window, position)
        if item is None:
            break
        position = item.end()
    if not window.startswith(END_MARKER, position):
        return False
    if any(word < MINIMUM_RUN for word in words[:-1]):
        return False
    # 17 different characters in 32, and one more for each three after that, up to 40; random
    # base64 holds 25 in 32, 31 in 43, 40 in 64 and 55 in 128, and words and identifiers fewer.
    return len(set(body)) >= min(DISTINCT_CHARACTERS + (len(body) - BODY_CHARACTERS) // 3, 40)


def key_body_follows(window, kind):
    """Whether the text after a private key's header is the body of a key of that kind."""
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
    start = position
    taken = bytearray()
    words = []
    last = 0
    while len(taken) < BODY_CHARACTERS:
        item = STRING_PREFIX.match(window, position)
        if item is not None:
            position = item.end()
            continue
        run = BASE64.match(window, position)
        if run is not None:
            position = run.end()
            characters = run.group().replace(b"\\", b"")
            # A `+` or a `/` by itself is a joiner or a comment marker, not part of the body.
            if characters.strip(b"+/"):
                taken += characters
                gap = window[last : run.start()]
                if words and b"," not in gap and WORD_GAP.fullmatch(gap) is None:
                    words[-1] += len(characters)
                else:
                    words.append(len(characters))
                last = position
            continue
        item = LAYOUT.match(window, position)
        if item is None:
            break
        position = item.end()
    if len(taken) < BODY_CHARACTERS:
        return False
    raw = binascii.a2b_base64(bytes(taken[:BODY_CHARACTERS]))
    if encrypted or kind not in STRUCTURED_KINDS:
        # Ciphertext and key material in a format this does not know are random bytes, and 32
        # characters of random base64 hold 17 or more different ones (all but one draw in 478,000);
        # words and identifiers hold fewer, and their text goes on as text.
        if not encrypted and der_private_key(raw):
            return True
        return (
            len(set(taken[:BODY_CHARACTERS])) >= DISTINCT_CHARACTERS
            and min(words) >= MINIMUM_RUN
            and body_ends_cleanly(window, position)
        ) or completes_block(window, start)
    if kind == b"PGP":
        return pgp_private_key(raw)
    return der_private_key(raw) or raw[:12] == b"openssh-key-"


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
        kind = (header.group(1) or b"").strip()
        if key_body_follows(data[header.end() : header.end() + KEY_WINDOW], kind):
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
    pgp_header = planted("-----", "BEGIN PGP PRIVATE KEY BLOCK", "-----")

    def pgp_body(*packet):
        """The base64 of a key packet's start, as an armoured block carries it."""
        return base64.b64encode(bytes(packet) + b"the-secret-material-of-the-key-0123456789").decode().rstrip("=")

    # Ciphertext and key material in a format the check does not know are random bytes.
    cipher = base64.b64encode(hashlib.sha256(b"ciphertext").digest()).decode().rstrip("=")
    slashed = cipher[:3] + "/" + cipher[4:]
    wide = base64.b64encode(hashlib.sha512(b"ciphertext").digest()).decode().rstrip("=")

    def pieces(text, size):
        return [text[i : i + size] for i in range(0, len(text), size)]

    # A TPM 2.0 key file: a DER body of an unknown kind whose first 32 characters hold 16 different ones.
    tss2 = base64.b64encode(
        bytes.fromhex("3082021206066781050a0103a0030101ff02044000000104") + b"a-blob-the-tpm-wrapped"
    ).decode()
    nebula_header = planted("-----", "BEGIN NEBULA X25519 PRIVATE KEY", "-----")
    nebula_end = planted("-----", "END NEBULA X25519 PRIVATE KEY", "-----")
    tendermint_header = planted("-----", "BEGIN TENDERMINT PRIVATE KEY", "-----")
    fragments = [f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"[i : i + 12] for i in range(0, 52, 12)]
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
        "src/powershell.ps1": f'$k = "{header}`n{key_body}`n"\n',
        "src/ed25519.rs": f'const K: &str = "{header}\\n" + "MC4CAQAwBQYDK2VwBCIEIGexampleexampleexampleexample";\n',
        "src/sec1.rs": f'const K: &str = "{header}\\n" + "MHcCAQEEIexampleexampleexampleexampleexample";\n',
        "src/python.py": f'K = (b"{header}\\n"\n     b"{key_body[:4]}"\n     b"{key_body[4:8]}"\n     b"{key_body[8:32]}"\n     b"{key_body[32:]}")\n',
        "src/ps-encrypted.ps1": f'$k = "{header}`nProc-Type: 4,ENCRYPTED`nDEK-Info: AES-128-CBC,0123456789ABCDEF`n`n{cipher}"\n',
        "src/margin.kt": f'val k = """\n    |{header}\n    |{key_body}\n""".trimMargin()\n',
        "src/wide.cc": f'const wchar_t* k = L"{header}\\n" L"{key_body}";\n',
        "src/enc-pkcs8.pem.txt": planted("-----", "BEGIN ENCRYPTED PRIVATE KEY", "-----") + "\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIexampleexampleexample\n",
        "src/encrypted-ciphertext.pem.txt": f"{header}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{cipher}\n",
        "src/uneven.js": f'const K = "{header}\\n" +\n  "{key_body[:24]}" +\n  "{key_body[24:32]}" +\n  "{key_body[32:]}\\n";\n',
        "src/commented-short.rs": f"// {header}\n" + "".join(f"// {key_body[i : i + 24]}\n" for i in range(0, len(key_body), 24)),
        "src/php.json": '{"k":"' + header + "\\n" + key_body[:10] + "\\/" + key_body[10:] + '\\n"}\n',
        "src/php-encrypted.json": json.dumps({"k": f"{header}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{slashed}\n"}).replace("/", "\\/"),
        "src/php-nebula.json": json.dumps({"k": f"{nebula_header}\n{slashed}\n"}).replace("/", "\\/"),
        "src/pgp-comment-slash.json": json.dumps({"k": f"{pgp_header}\nComment: https://keybase.io/crypto\n\n{pgp_body(0xC5, 0x5B, 4, 0x5F, 0, 0, 1, 27)}\n"}).replace("/", "\\/"),
        "src/tss2.txt": planted("-----", "BEGIN TSS2 PRIVATE KEY", "-----") + f"\n{tss2}\n",
        "src/cipher-pieces.py": f'K = (b"{header}\\n"\n     b"Proc-Type: 4,ENCRYPTED\\n"\n     b"DEK-Info: AES-128-CBC,0123456789ABCDEF\\n\\n"\n'
        + "".join(f'     b"{piece}"\n' for piece in pieces(cipher, 4))
        + "     )\n",
        "src/nebula-pieces.js": f'const key = "{nebula_header}\\n" +\n' + " +\n".join(f'  "{piece}"' for piece in pieces(cipher, 7)) + ";\n",
        "src/nebula-padded.yml": f"key: |\n  {nebula_header}\n  {cipher}=\n  {nebula_end}\n",
        "src/nebula-crlf.txt": f"{nebula_header}\r\n{cipher}\r\n",
        "src/nebula-single.py": f"K = '{nebula_header}\\n' '{cipher}'\n",
        "src/nebula-template.js": f"const k = `{nebula_header}\n{cipher}`;\n",
        "src/nebula-xml.xml": f"<key>{nebula_header}\n{cipher}</key>\n",
        "src/nebula-eof.txt": f"{nebula_header}\n{cipher}",
        "src/nebula-collapsed.env": f"KEY={nebula_header}{cipher}{nebula_end}\n",
        "src/nebula-oneline.sh": f'KEY="{nebula_header} {cipher[:40]} {cipher[40:]}= {nebula_end}"\n',
        "src/nebula-distinct17.txt": f"{nebula_header}\n{'AbCdEfGhIjKlMnOpQ' * 3}\n",
        "src/nebula-eights.txt": f"{nebula_header}\n" + " ".join(pieces(cipher[:40], 8)) + "\n",
        "src/nebula-array.js": 'const key = ["' + nebula_header + '", "' + '", "'.join(pieces(cipher + "=", 4)) + '", "' + nebula_end + '"].join("\\n");\n',
        "src/nebula-array-long.js": 'const key = ["' + nebula_header + '", "' + '", "'.join(pieces(cipher + wide + wide[::-1], 4)) + '", "' + nebula_end + '"].join("\\n");\n',
        "src/nebula-array.go": f"var key = []string{{\n\t\"{nebula_header}\",\n" + "".join(f'\t"{piece}",\n' for piece in pieces(cipher + "=", 7)) + f'\t"{nebula_end}",\n}}\n',
        "src/nebula-unpadded.sh": f"KEY='{nebula_header} {wide[:64]} {wide[64:68]} {nebula_end}'\n",
        "src/nebula-unpadded-lines.txt": f"{nebula_header} {wide[:64]} {wide[64:68]}\n{nebula_end}\n",
        "src/nebula-last-slash.json": json.dumps({"k": f"{nebula_header} {wide[:64]} ab/c="}).replace("/", "\\/"),
        "src/nebula-padded-eof.txt": f"{nebula_header}\n{cipher}=\n",
        "src/nebula-array-slash.json": json.dumps({"k": [nebula_header, *pieces(slashed + "=", 4), nebula_end]}).replace("/", "\\/"),
        "src/last-quote.sh": f'KEY="{nebula_header} {wide[:64]} abcd"\n',
        "src/last-single.sh": f"KEY='{nebula_header} {wide[:64]} abcd'\n",
        "src/last-backtick.js": f"const key = `{nebula_header} {wide[:64]} abcd`;\n",
        "src/last-xml.xml": f"<key>{nebula_header} {wide[:64]} abcd</key>\n",
        "src/last-padding.txt": f"{nebula_header} {wide[:64]} ab==\n",
        "src/last-eof.txt": f"{nebula_header} {wide[:64]} abcd",
        "src/nebula-spaces.sh": f'KEY="{nebula_header} {cipher[:16]} {cipher[16:32]} {cipher[32:]}"\n',
        "src/nebula-pieces.rs": f"// {nebula_header}\n" + "".join(f"// {piece}\n" for piece in pieces(cipher, 5)),
        "src/openssh.txt": planted("-----", "BEGIN OPENSSH PRIVATE KEY", "-----") + "\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n",
        "src/pgp.asc": f"{pgp_header}\n\n{pgp_body(0x95, 0x03, 0x98, 4, 0x5F, 0, 0, 1, 1)}\n",
        "src/pgp-version.asc": f"{pgp_header}\nVersion: Example 1.0\n\n{pgp_body(0x95, 0x03, 0x98, 4, 0x5F, 0, 0, 1, 1)}\n",
        "src/pgp-v3.asc": f"{pgp_header}\n\n{pgp_body(0x95, 0x01, 0x8F, 3, 0x5F, 0, 0, 1, 0, 0, 1)}\n",
        "src/pgp-slash.json": json.dumps({"k": f"{pgp_header}\n\n{pgp_body(0x94, 0x57, 4, *(1700003663).to_bytes(4, 'big'), 22)}\n"}).replace("/", "\\/"),
        "src/pgp-short.asc": f"{pgp_header}\n\n{pgp_body(0x94, 0x58, 4, 0x5F, 0, 0, 1, 22)}\n",
        "src/pgp-new.asc": f"{pgp_header}\n\n{pgp_body(0xC5, 0x5B, 4, 0x5F, 0, 0, 1, 27)}\n",
        "src/pgp-new-long.asc": f"{pgp_header}\n\n{pgp_body(0xC5, 0xC2, 0xD8, 4, 0x5F, 0, 0, 1, 1)}\n",
        "src/pgp-public-first.asc": f"{pgp_header}\n\n{pgp_body(0xC6, 0x33, 4, 0x5F, 0, 0, 1, 19)}\n",
        "src/pgp-v6.asc": f"{pgp_header}\n\n{pgp_body(0xC5, 0x40, 6, 0x5F, 0, 0, 1, 27)}\n",
        "src/pgp-comment.asc": f"{pgp_header}\nComment: Convert to {header} for OpenSSL\n\n{pgp_body(0xC5, 0x5B, 4, 0x5F, 0, 0, 1, 27)}\n",
        "src/nebula.yml": f"key: |\n  {nebula_header}\n  {cipher}\n",
        "src/cosmos.txt": f"{tendermint_header}\nkdf: bcrypt\nsalt: 0123456789ABCDEF0123456789ABCDEF\ntype: secp256k1\n\n{cipher}\n",
        "src/joiners.js": f'const key = "{header}\\n" +\n  "MC4C" +\n  "AQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\\n";\n',
        "src/openssh-joined.js": 'const key = "' + planted("-----", "BEGIN OPENSSH PRIVATE KEY", "-----") + '\\n" +\n  ' + " +\n  ".join(f'"{piece}"' for piece in fragments) + ";\n",
        "src/openssh-comments.rs": "// " + planted("-----", "BEGIN OPENSSH PRIVATE KEY", "-----") + "\n" + "".join(f"// {piece}\n" for piece in fragments),
        "src/at.m": f'NSString *k = @"{header}\\n" @"{key_body}";\n',
        "src/u8.cpp": f'auto k = u8"{header}\\n" u8"{key_body[:4]}" u8"{key_body[4:]}";\n',
        "src/rb.py": f'K = (rb"{header}\\n"\n     rb"{key_body[:4]}"\n     rb"{key_body[4:]}")\n',
        "src/tab.ps1": f'$k = "{header}`t{key_body}"\n',
        "src/ps-encrypted-crlf.ps1": f'$k = "{header}`r`nProc-Type: 4,ENCRYPTED`r`nDEK-Info: AES-128-CBC,0123456789ABCDEF`r`n`r`n{cipher}"\n',
        "src/python-encrypted.py": f'K = (b"{header}\\n"\n     b"Proc-Type: 4,ENCRYPTED\\n"\n     b"DEK-Info: AES-128-CBC,0123456789ABCDEF\\n\\n"\n     b"{cipher}")\n',
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
    fx.write("docs/note.md", f"{header}\nNote: the internationalization of the notes follows here\ninternationalizationofthenotesfollowhere\n")
    fx.write("src/bang.js", f'const marker = "{header}";\n!validatePrivateKeyAndCertificateChain(marker);\n')
    fx.write("src/digest.rs", f'const H: &str = "{header}\\n{"a1" * 32}";\n')
    fx.write("src/words.md", f"{header} MAKE SURE THE HEADER IS PRESENT, MAY be followed by lines, MIME types and MCPServerConfiguration.load(H).\n")
    fx.write("src/length.js", f'const marker = "{header}";\nMAXPASSWORDLENGTH.toString();\n')
    fx.write("docs/placeholder.md", f"{header}\nMIIEpAIBAAKCAQEA...\n-----END\n")
    fx.write("src/armour.js", f'const ARMOR = "{pgp_header}";\nlet armoredSecretKey = await readKey(ARMOR);\n')
    fx.write("docs/lines.md", f"{pgp_header} lines up the armour headers first, then the packets.\n")
    fx.write("docs/wrap.md", f"{nebula_header}\n# wrap up last segment yield section, content\n")
    fx.write("docs/digest-note.md", f"{header}\nNote: the digest follows\n{cipher}\n")
    for name, unknown in (("nebula", nebula_header), ("tendermint", tendermint_header)):
        fx.write(f"src/{name}.js", f'const marker = "{unknown}";\nvalidatePrivateKeyAndCertificateChain(marker);\n')
        fx.write(f"docs/{name}.md", f"{unknown} This header identifies a private key in the configuration file.\n")
    fx.write("src/nebula-call.js", f'const marker = "{nebula_header}";\nexportPrivateKeyAndCertificateChain(marker);\n')
    tendermint_end = planted("-----", "END TENDERMINT PRIVATE KEY", "-----")
    # Between the markers of a block: a sentence, a table row, a list of words and a list of long words are not a body.
    for name, text in {
        "docs/placeholder-sentence.md": f"{nebula_header}\npaste your base64 encoded private key here\n{nebula_end}\n",
        "docs/placeholder-insert.md": f"{tendermint_header}\nInsert the 32 byte X25519 private key in base64\n{tendermint_end}\n",
        "docs/placeholder-table.md": f"| {nebula_header} | the private key in base64 | {nebula_end} |\n",
        "docs/long-words.md": f"{nebula_header}\nSynchronization Administration Configuration Interoperability\n{nebula_end}\n",
        "docs/comma-words.md": f"{nebula_header}\nBoxed, Browser, Carrier, Ending, Loopback, Plan, Reply, Unavailable,\n{nebula_end}\n",
        "src/array-no-marker.js": f"{nebula_header}\n" + ", ".join(f'"{piece}"' for piece in pieces(cipher, 4)) + "\n- item\n",
        "src/hyphenated.rs": f"{nebula_header}\nGrantExecutableCapabilityForTheHostAndMore-managed\n",
        "src/capability.rs": f"{nebula_header}\nGrantExecutableCapability,\n/// Changing host-management\n",
    }.items():
        fx.write(name, text)
    fx.write("docs/spaced-call.md", f"{nebula_header} {cipher} (see the key format notes)\n")
    fx.write("src/nebula-args.js", f'assertKeyFormat("{nebula_header}",\n  "private", "public", "export", "format", "X25519", "chain");\n')
    fx.write("src/tendermint-args.js", f'assertKeyFormat("{tendermint_header}", unmarshalX25519PrivateKey, marshalX25519PrivateKey);\n')
    fx.write("src/tendermint-comment.rs", f"// {tendermint_header}\n// TendermintArmoredPrivateKeyDecoder handles everything\n")
    fx.write("docs/words.md", f"{nebula_header}\nprivate backups storage folders rotated\n")
    fx.write("docs/hex.md", f"{nebula_header}\n{hashlib.sha256(b'digest1').hexdigest()}\n")
    fx.write("src/lanes.js", f'const A = "{pgp_header}";\nnextBaseLanes, renderLanes, remainingChildLanes;\n')
    fx.write("docs/list.md", f"{pgp_header}\nlist README files before checking signatures\n")
    fx.write("src/names.js", f'const A = "{pgp_header}";\nlet armoredSecretKey, armoredPublicKey, revocationCertificate;\n')
    fx.write("src/limits.js", f'const marker = "{header}";\nMAXPASSWORDLENGTH, MINPASSWORDLENGTH, PASSWORDHISTORY;\n')
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
