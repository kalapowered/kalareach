#!/usr/bin/env python3
"""Refuses a release tree, an archive or a checkout that holds a private key or an official credential.

The release's signing keys live in hardware-backed services and its channel roots on offline media;
none of them belongs in a repository, a release tree or an archive, and an independently signed app
supplies its own push credentials. This reads every file it is given and fails on what could only
be one of those:

  * a PEM private key: a `-----BEGIN ... PRIVATE KEY-----` header followed by a base64 body, in a
    file, inside a JSON string with its line breaks written as `\\n`, or wrapped in base64 again. A
    header quoted in source text, with no body after it, is not a key;
  * a JSON Web Key with private members: `d` (or `p`, `q`, `dp`, `dq`, `qi`) on an RSA, EC or OKP
    key, or `k` on a symmetric one;
  * a raw seed: a file of exactly 32 or 64 bytes that is not text (an Ed25519 or X25519 seed, or a
    seed and public key), the same in hex (64 or 128 digits) or in base64 (44 or 88 characters);
  * a file that is named for a credential: an APNs signing key (`AuthKey_*.p8`, any `.p8`), a
    PKCS#12 or Java key store, an SSH private key, a Firebase configuration file
    (`google-services.json`, `GoogleService-Info.plist`) or a provisioning profile;
  * a Google API key or a service-account document written into a file.

A path may be a directory, a file, or an archive (`.tar`, `.tar.gz`, `.tgz`, `.zip`, read member by
member, nested archives included). A directory is read whole, every file under it: a release tree
has no directory that is not part of the release. `--tracked` reads the files the repository
tracks instead, which is what a checkout's scan means.

What this does not find: a key in a binary encoding (DER, PuTTY, age, minisign), a key in an archive
format it does not read (tar.xz, apk, ipa, nupkg are read as raw bytes), and a secret that is not a
key. A file it cannot inspect is reported as such and is never counted as clean.

    python3 scripts/check-release-secrets.py scan [--tracked] PATH...
    python3 scripts/check-release-secrets.py self-test

`self-test` plants each kind of secret in a scratch tree and in an archive built from it, and the
scan must name every one; it plants the near misses (a header quoted with no body, a public JWK, a
text file of 32 characters, a public key) and the scan must pass them; and it scans this
repository's own tracked files, which must be clean.
"""

import argparse
import base64
import fnmatch
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

MAX_ARCHIVE_DEPTH = 3

PEM_HEADER = re.compile(rb"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----")
# What follows a private key's header: escaped or real line breaks, optional `Name: value` header
# lines (an encrypted key's `Proc-Type`, a PGP block's `Version`), then the base64 body.
PEM_BODY = re.compile(
    rb"\A(?:\s|\\r|\\n)*(?:[A-Za-z-]+: [^\r\n\\]*(?:\r?\n|\\r|\\n)+)*[A-Za-z0-9+/]{32,}"
)
JWK_PRIVATE = {"RSA": {"d", "p", "q", "dp", "dq", "qi"}, "EC": {"d"}, "OKP": {"d"}, "oct": {"k"}}
JWK_FALLBACK = re.compile(rb'"(?:d|p|q|dp|dq|qi|k)"\s*:\s*"[A-Za-z0-9_-]{16,}"')
GOOGLE_API_KEY = re.compile(rb"AIza[0-9A-Za-z_-]{35}")
SERVICE_ACCOUNT = re.compile(rb'"type"\s*:\s*"service_account"')
HEX = re.compile(rb"\A[0-9a-fA-F]+\Z")
BASE64 = re.compile(rb"\A[A-Za-z0-9+/]+={0,2}\Z")
# A long run of base64, which may be a key encoded again.
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
# The most a file may be for this to read it as a JSON document or as an encoded key.
TEXT_LIMIT = 64 * 1024 * 1024

# Names that are a credential whatever they hold, as glob patterns on the file's own name.
CREDENTIAL_NAMES = [
    ("AuthKey_*.p8", "an APNs signing key"),
    ("*.p8", "an APNs or App Store Connect signing key"),
    ("*.p12", "a PKCS#12 key store"),
    ("*.pfx", "a PKCS#12 key store"),
    ("*.jks", "a Java key store"),
    ("*.keystore", "a key store"),
    ("id_rsa", "an SSH private key"),
    ("id_dsa", "an SSH private key"),
    ("id_ecdsa", "an SSH private key"),
    ("id_ed25519", "an SSH private key"),
    ("google-services.json", "a Firebase configuration for an Android build"),
    ("GoogleService-Info.plist", "a Firebase configuration for an Apple build"),
    ("*.mobileprovision", "a provisioning profile"),
    ("*.provisionprofile", "a provisioning profile"),
]

ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".zip")

def looks_like_text(data):
    return all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data)


def jwk_problems(value, path):
    found = []
    if isinstance(value, dict):
        kty = value.get("kty")
        if isinstance(kty, str):
            private = sorted(JWK_PRIVATE.get(kty, {"d", "k"}) & set(value))
            if private:
                found.append((path, f"a JSON Web Key ({kty}) with private members {private}"))
        for inner in value.values():
            found += jwk_problems(inner, path)
    elif isinstance(value, list):
        for inner in value:
            found += jwk_problems(inner, path)
    return found


def pem_problems(path, data, how):
    """A PEM private key in `data`: its header followed by a base64 body."""
    found = []
    for header in PEM_HEADER.finditer(data):
        tail = data[header.end(): header.end() + 8192]
        if PEM_BODY.match(tail):
            kind = (header.group(1) or b"").decode().strip() or "PKCS#8"
            found.append((path, f"holds a PEM private key ({kind}){how}"))
    return found


def scan_bytes(path, data, name=None):
    """Returns [(path, what)] for one file's bytes.

    `name` is the file's own name, which is not the tail of `path` for a member of an archive.
    """
    found = []
    name = name if name is not None else os.path.basename(path)

    for pattern, what in CREDENTIAL_NAMES:
        if fnmatch.fnmatchcase(name, pattern):
            found.append((path, f"is named for {what}"))
            break

    found += pem_problems(path, data, "")
    if len(data) <= TEXT_LIMIT:
        # A key encoded again: base64 of a PEM block, on its own or inside a document.
        for run in BASE64_RUN.finditer(data):
            try:
                inner = base64.b64decode(run.group(0) + b"=" * (-len(run.group(0)) % 4))
            except ValueError:
                continue
            found += pem_problems(path, inner, ", encoded again in base64")
            if found and found[-1][1].endswith("encoded again in base64"):
                break

    # The line ending of a seed written as text is not part of the seed.
    bare = data.rstrip(b"\r\n")
    if len(data) in (32, 64) and not looks_like_text(data) and len(set(data)) >= 16:
        found.append((path, f"is a raw {len(data)}-byte binary file, the size of a private key seed"))
    if len(bare) in (64, 128) and HEX.match(bare):
        found.append((path, "is a file of hex digits the size of a private key seed"))
    if len(bare) in (44, 88) and BASE64.match(bare):
        found.append((path, "is a base64 file the size of a private key seed"))

    if b'"kty"' in data:
        if len(data) > TEXT_LIMIT:
            found.append((path, "may hold a JSON Web Key and is too large to inspect for one"))
        else:
            try:
                found += jwk_problems(json.loads(data), path)
            except (ValueError, UnicodeDecodeError):
                if JWK_FALLBACK.search(data):
                    found.append((path, "holds what reads as a JSON Web Key's private member"))

    if GOOGLE_API_KEY.search(data):
        found.append((path, "holds a Google API key"))
    if SERVICE_ACCOUNT.search(data):
        found.append((path, "holds a service-account document"))
    return found


def scan_archive(path, data, depth):
    """Reads one archive from its bytes, member by member."""
    if depth > MAX_ARCHIVE_DEPTH:
        return [(path, "nests archives deeper than the scan reads")]
    found = []
    lower = path.lower()
    try:
        if lower.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        found += scan_member(f"{path}!{info.filename}", archive.read(info), depth,
                                             os.path.basename(info.filename))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive.getmembers():
                    if member.isreg():
                        found += scan_member(
                            f"{path}!{member.name}", archive.extractfile(member).read(), depth,
                            os.path.basename(member.name),
                        )
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as error:
        return [(path, f"is an archive the scan could not read ({error})")]
    return found


def scan_member(path, data, depth, name=None):
    if path.lower().endswith(ARCHIVE_SUFFIXES):
        return scan_archive(path, data, depth + 1)
    return scan_bytes(path, data, name)


def files_under(directory, unread):
    """Every file under `directory`; a directory that cannot be listed is added to `unread`."""
    def note(error):
        unread.append((str(error.filename), f"was not inspected, because it cannot be listed ({reason(error)})"))

    for root, directories, names in os.walk(directory, onerror=note):
        directories.sort()
        for name in sorted(names):
            yield os.path.join(root, name)


def reason(error):
    return error.strerror or type(error).__name__


def tracked_files(directory):
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=directory, capture_output=True,
                             check=True).stdout
    for name in listing.split(b"\0"):
        if name:
            path = os.path.join(directory, name.decode())
            if os.path.isfile(path) and not os.path.islink(path):
                yield path


def scan_paths(paths, tracked):
    found = []
    for given in paths:
        if os.path.isdir(given):
            files = tracked_files(given) if tracked else files_under(given, found)
        elif os.path.isfile(given):
            files = [given]
        else:
            found.append((given, "does not exist"))
            continue
        for path in files:
            if os.path.islink(path):
                continue
            # Only a regular file is opened: a pipe or a device would wait for a writer that is
            # never going to come, and holds no key a release could ship.
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    found.append((path, "was not inspected, because it is not a regular file"))
                    continue
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError as error:
                found.append((path, f"was not inspected, because it cannot be read ({reason(error)})"))
                continue
            found += scan_member(path, data, 0) if path.lower().endswith(ARCHIVE_SUFFIXES) \
                else scan_bytes(path, data)
    return found


def self_test():
    failures = []
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4"

    planted = {
        "pem-pkcs8": ("keys/signing.pem",
                      f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n".encode()),
        "pem-rsa": ("keys/rsa.key",
                    f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n".encode()),
        "pem-ec-encrypted": ("keys/ec.pem",
                             ("-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                              f"DEK-Info: AES-128-CBC,00\n\n{body}\n-----END EC PRIVATE KEY-----\n").encode()),
        "pem-openssh": ("ssh/deploy",
                        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n".encode()),
        "pem-in-json": ("cfg/service.json",
                        json.dumps({"private_key": f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"}).encode()),
        "jwk-ec": ("keys/root.jwk",
                   json.dumps(dict(kty="EC", crv="P-256",
                                   x="f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                                   y="x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                                   d="jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")).encode()),
        "jwk-set-with-rsa": ("keys/set.json",
                             json.dumps(dict(keys=[dict(
                                 kty="RSA", n="0vx7agoebGcQSuu", e="AQAB",
                                 d="X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH")])).encode()),
        "seed-binary-32": ("keys/root.seed", bytes(range(7, 39))),
        "seed-binary-64": ("keys/pair.bin", bytes((i * 37 + 11) % 256 for i in range(64))),
        "seed-hex": ("keys/seed.txt", ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n").encode()),
        "seed-base64": ("keys/seed.b64", b"nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=\n"),
        "apns-key": ("push/AuthKey_ABC123DEFG.p8", b"anything"),
        # At the top of an archive, where the member's own name is the whole of its path.
        "firebase-at-the-root": ("google-services.json", b"{}"),
        # Under directories a checkout scan leaves out, which a release tree has no such thing as.
        "pem-under-node_modules": ("node_modules/pkg/private.pem",
                                   f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n".encode()),
        "pem-wrapped-in-base64": ("keys/wrapped.b64", base64.b64encode(
            f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n".encode())),
        "seed-hex-crlf": ("keys/seed-crlf.txt",
                          b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\r\n"),
        "firebase-android": ("app/google-services.json", b"{}"),
        "firebase-apple": ("app/GoogleService-Info.plist", b"<plist/>"),
        # Written in two pieces so this file does not hold the whole of what it plants.
        "google-api-key": ("app/config.json",
                           b'{"api_key": "AI' + b'zaSyA1234567890abcdefghijklmnopqrstuv1"}'),
        "service-account": ("cfg/sa.json",
                            b'{"type": "service' + b'_account", "project_id": "x"}'),
    }
    near_misses = {
        "quoted-header": ("src/test.rs", b'write("deploy/server.pem", "-----BEGIN PRIVATE KEY-----\\n");\n'),
        "public-jwk": ("keys/public.jwk",
                       json.dumps(dict(kty="EC", crv="P-256",
                                       x="f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                                       y="x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")).encode()),
        "public-pem": ("keys/public.pem", f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode()),
        "certificate": ("keys/cert.pem", f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()),
        "text-32": ("notes/thirty-two.txt", b"the quick brown fox jumps over th"),
        "zero-32": ("fixtures/zero", bytes(32)),
        "long-binary": ("bin/kr", os.urandom(4096)),
        "header-then-code": ("src/pem.rs", b'let h = "-----BEGIN PRIVATE KEY-----"; let digest = "' + b"a" * 64 + b'";\n'),
    }

    def write(directory, files):
        for relative, data in files.values():
            path = os.path.join(directory, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)

    def flagged(found, relative):
        return any(path.endswith(relative) or f"!{relative}" in path for path, _ in found)

    with tempfile.TemporaryDirectory(prefix="kalareach-secrets-") as scratch:
        secrets = os.path.join(scratch, "secrets")
        clean = os.path.join(scratch, "clean")
        write(secrets, planted)
        write(clean, near_misses)

        # A directory holding a secret of each kind, and the same tree as a tar.gz and as a zip.
        tar_path = os.path.join(scratch, "tree.tar.gz")
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(secrets, arcname="release")
        zip_path = os.path.join(scratch, "tree.zip")
        with zipfile.ZipFile(zip_path, "w") as archive:
            for directory, _, names in os.walk(secrets):
                for name in names:
                    full = os.path.join(directory, name)
                    archive.write(full, os.path.relpath(full, secrets))
        nested_path = os.path.join(scratch, "nested.zip")
        with zipfile.ZipFile(nested_path, "w") as archive:
            archive.write(tar_path, "inner/release.tar.gz")

        for where, path in (("directory", secrets), ("tar.gz", tar_path), ("zip", zip_path),
                            ("nested archive", nested_path)):
            found = scan_paths([path], False)
            for label, (relative, _) in planted.items():
                if not flagged(found, relative):
                    failures.append(f"{where}: the planted {label} ({relative}) was not found")

        found = scan_paths([clean], False)
        if found:
            failures.append(f"the near misses were refused: {found}")

        clean_tar = os.path.join(scratch, "clean.tar.gz")
        with tarfile.open(clean_tar, "w:gz") as archive:
            archive.add(clean, arcname="release")
        found = scan_paths([clean_tar], False)
        if found:
            failures.append(f"the near misses in an archive were refused: {found}")

    # A file that cannot be read is named as one that was not inspected, and never counted as clean.
    if os.name == "posix" and os.geteuid() != 0:
        with tempfile.TemporaryDirectory(prefix="kalareach-secrets-") as scratch:
            hidden = os.path.join(scratch, "tree", "unreadable.bin")
            os.makedirs(os.path.dirname(hidden))
            with open(hidden, "wb") as handle:
                handle.write(b"anything")
            os.chmod(hidden, 0)
            try:
                found = scan_paths([os.path.dirname(hidden)], False)
            except OSError as error:
                found = None
                failures.append(f"a file that cannot be read stopped the scan with {error!r}")
            if found is not None and not any("not inspected" in what for _, what in found):
                failures.append(f"a file that cannot be read was counted clean: {found}")

    # A directory that cannot be listed is named as one that was not inspected.
    if os.name == "posix" and os.geteuid() != 0:
        with tempfile.TemporaryDirectory(prefix="kalareach-secrets-") as scratch:
            sealed = os.path.join(scratch, "tree", "sealed")
            os.makedirs(sealed)
            with open(os.path.join(sealed, "key.pem"), "wb") as handle:
                handle.write(b"anything")
            os.chmod(sealed, 0)
            try:
                found = scan_paths([os.path.join(scratch, "tree")], False)
            finally:
                os.chmod(sealed, 0o700)
            if not any("cannot be listed" in what for _, what in found):
                failures.append(f"a directory that cannot be listed was counted clean: {found}")

    # A pipe in a tree is named, and never opened: opening it would wait for a writer.
    if hasattr(os, "mkfifo"):
        with tempfile.TemporaryDirectory(prefix="kalareach-secrets-") as scratch:
            os.makedirs(os.path.join(scratch, "tree"))
            os.mkfifo(os.path.join(scratch, "tree", "pipe"))
            found = scan_paths([os.path.join(scratch, "tree")], False)
            if not any("not a regular file" in what for _, what in found):
                failures.append(f"a pipe in a tree was not named: {found}")

    # A document too large to read for a private JSON Web Key is refused and never counted as clean.
    global TEXT_LIMIT
    saved, TEXT_LIMIT = TEXT_LIMIT, 64
    try:
        big = json.dumps(dict(kty="EC", crv="P-256", x="a" * 43, y="b" * 43,
                              d="c" * 43)).encode() + b" " * 100
        found = scan_bytes("big.jwk", big)
        if not any("too large to inspect" in what for _, what in found):
            failures.append(f"a document larger than the limit was counted clean: {found}")
    finally:
        TEXT_LIMIT = saved

    found = scan_paths([root], True)
    if found:
        failures.append("this repository's tracked files are not clean: "
                        + "; ".join(f"{path} {what}" for path, what in found))

    if failures:
        sys.stderr.write("\n".join(failures) + "\n")
        return 1
    print(f"check-release-secrets self-test: {len(planted)} planted secrets found in a directory, "
          f"two archive formats and a nested archive; {len(near_misses)} near misses and this "
          "repository's own tracked files pass")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    scanning = commands.add_parser("scan", help="scan directories, files and archives")
    scanning.add_argument("--tracked", action="store_true",
                          help="for a directory, read the files the repository tracks")
    scanning.add_argument("paths", nargs="+")
    commands.add_parser("self-test", help="plant each kind of secret, and the near misses")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        return self_test()

    found = scan_paths(arguments.paths, arguments.tracked)
    if found:
        sys.stderr.write("A private key or an official credential is in what was scanned:\n")
        for path, what in found:
            sys.stderr.write(f"  {path} {what}\n")
        return 1
    print("no private key or official credential found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
