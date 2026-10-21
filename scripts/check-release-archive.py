#!/usr/bin/env python3
"""Checks a release archive the way a host stages one, before it is signed for release or published.

    check-release-archive.py check --archive FILE [--sums SHA256SUMS]
    check-release-archive.py self-test

A release archive is `kalareach-<target>-<release>.tar.gz` (a `.zip` on Windows): one top directory
that holds `bin/`, `shells/`, `share/` and `release.json`. This refuses an archive that a host would
refuse, from the archive alone and never from a host:

  * an entry that is a link, a hard link, a device, a pipe or a sparse file, or anything but a file
    or a directory;
  * an absolute path, a path that climbs out of the top directory (`..`), a path with a backslash,
    a NUL or a drive letter, a path outside the one top directory, a file where the top directory
    is, a path that is a file and a directory, and two paths that are one path on a system that
    folds case;
  * a file the manifest in the archive does not list, a listed file that is missing, and a listed
    file whose length or SHA-256 digest differs;
  * a top directory that is not the one the manifest's target and release name;
  * a `SHA256SUMS` that does not give the archive's own digest.

What it does not read is a signature: `kr-release verify` holds the manifest to the channel's root,
and the host holds it again when it installs the release.

`self-test` makes an archive that passes and then one with each fault above planted in it, and the
check has to refuse every one and pass the first.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import zipfile

MANIFEST = "release.json"


class Refused(Exception):
    """An archive a host would refuse, with the reason."""


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def digest_text(raw):
    """A manifest digest, which is unpadded base64url of the 32 bytes, as lower-case hex."""
    padded = raw + "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(padded).hex()


def split(name):
    return name.replace("\\", "/").split("/")


def check_name(name, top):
    """Refuses a path that names something outside the release or that a system reads differently."""
    if "\x00" in name or "\\" in name:
        raise Refused(f"{name!r} holds a NUL or a backslash")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise Refused(f"{name!r} is an absolute path")
    parts = name.rstrip("/").split("/")
    if ".." in parts or "." in parts[1:] or "" in parts:
        raise Refused(f"{name!r} climbs out of the release or names a part a system reads differently")
    if parts[0] != top:
        raise Refused(f"{name!r} is not inside the one top directory {top!r}")
    return "/".join(parts[1:])


def members(archive):
    """Yields (name, kind, bytes) for each entry of an archive, refusing what a release never holds."""
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as opened:
            for info in opened.infolist():
                mode = info.external_attr >> 16
                if (mode & 0o170000) not in (0, 0o100000, 0o040000):
                    raise Refused(f"{info.filename!r} is neither a file nor a directory")
                if info.is_dir():
                    yield info.filename, "dir", b""
                else:
                    yield info.filename, "file", opened.read(info)
        return
    with tarfile.open(archive, "r:*") as opened:
        for member in opened:
            if member.issym() or member.islnk():
                raise Refused(f"{member.name!r} is a link")
            if member.ischr() or member.isblk() or member.isfifo():
                raise Refused(f"{member.name!r} is a device or a pipe")
            if member.issparse() or any(key.startswith("GNU.sparse") for key in member.pax_headers):
                raise Refused(f"{member.name!r} is a sparse file")
            if member.isdir():
                yield member.name, "dir", b""
            elif member.isfile():
                yield member.name, "file", opened.extractfile(member).read()
            else:
                raise Refused(f"{member.name!r} is neither a file nor a directory")


def check(archive, sums=None):
    """Checks one archive, and returns the manifest's members as the archive holds them."""
    base = os.path.basename(archive)
    for suffix in (".tar.gz", ".zip"):
        if base.endswith(suffix):
            top = base[: -len(suffix)]
            break
    else:
        raise Refused(f"{base} is not a .tar.gz or a .zip")

    files = {}
    # Every path the archive names, file or directory, explicit or as the parent of another: a path
    # is one or the other, and two spellings that a system folding case reads as one are refused.
    kinds = {}
    folded = {}

    def note(path, kind):
        lowered = path.lower()
        if lowered in folded and folded[lowered] != path:
            raise Refused(f"{path!r} and {folded[lowered]!r} are one path on a system that folds case")
        folded[lowered] = path
        if kinds.setdefault(path, kind) != kind:
            raise Refused(f"{path!r} is a file and a directory in the archive")

    for name, kind, data in members(archive):
        relative = check_name(name, top) if name.rstrip("/") != top else ""
        if relative == "":
            if kind == "file":
                raise Refused(f"{name!r} is a file where the top directory is")
            continue
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            note("/".join(parts[:depth]), "dir")
        note(relative, kind)
        if kind == "dir":
            continue
        if relative in files:
            raise Refused(f"{name!r} is in the archive twice")
        files[relative] = data

    if MANIFEST not in files:
        raise Refused(f"the archive holds no {MANIFEST}")
    signed = json.loads(files[MANIFEST])["signed"]
    expected_top = f"kalareach-{signed['target']}-{signed['release']}"
    if top != expected_top:
        raise Refused(f"the archive is named {top!r} and its manifest is of {expected_top!r}")
    listed = {entry["path"]: entry for entry in signed["files"]}
    for path, entry in sorted(listed.items()):
        if path not in files:
            raise Refused(f"{path} is listed and not in the archive")
        data = files[path]
        if len(data) != int(entry["length"]) or sha256_hex(data) != digest_text(entry["sha256"]):
            raise Refused(f"{path} is not the file the manifest lists")
    unlisted = sorted(path for path in files if path not in listed and path != MANIFEST)
    if unlisted:
        raise Refused(f"{unlisted[0]} is in the archive and the manifest does not list it")

    if sums is not None:
        digest = hashlib.sha256()
        with open(archive, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        stated = {}
        with open(sums, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    value, _, name = line.strip().partition("  ")
                    stated[name.lstrip("*")] = value
        if stated.get(base) != digest.hexdigest():
            raise Refused(f"SHA256SUMS does not give the digest of {base}")
    return signed


# ------------------------------------------------------------------------------------------------
# The check, put through archives made to fail before it is trusted with a real one.


def manifest_for(files, target="x86_64-unknown-linux-gnu", release="0.1.0+aaaaaaaaaaaa"):
    def digest(data):
        return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")

    return json.dumps(
        {
            "signed": {
                "_type": "kalareach-release",
                "release": release,
                "target": target,
                "files": [
                    {"path": path, "length": str(len(data)), "sha256": digest(data), "mode": "regular"}
                    for path, data in sorted(files.items())
                ],
            },
            "signatures": [],
        }
    ).encode()


def good_files():
    return {"bin/kr": b"a program", "share/update-root.json": b"{}", "shells/zsh/current": b"abc"}


def write_tar(path, top, files, extra=(), manifest=None):
    """A tar.gz of `files` under `top`, with each of `extra` added: (name, TarInfo type, data, edit)."""
    with tarfile.open(path, "w:gz") as archive:
        body = dict(files)
        body[MANIFEST] = manifest if manifest is not None else manifest_for(files)
        for name, data in sorted(body.items()):
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
        for name, kind, data, edit in extra:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
            info.mode = 0o644
            if edit:
                edit(info)
            archive.addfile(info, io.BytesIO(data) if info.size else None)


def write_zip(path, top, files, extra=()):
    """A zip of `files` under `top`, with each of `extra` added: (name, unix mode, data)."""
    with zipfile.ZipFile(path, "w") as archive:
        body = dict(files)
        body[MANIFEST] = manifest_for(files, target="x86_64-pc-windows-msvc")
        for name, data in sorted(body.items()):
            archive.writestr(f"{top}/{name}", data)
        for name, mode, data in extra:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)


def self_test():
    failures = 0
    with tempfile.TemporaryDirectory() as scratch:
        top = "kalareach-x86_64-unknown-linux-gnu-0.1.0+aaaaaaaaaaaa"
        target = os.path.join(scratch, top + ".tar.gz")

        def made(files=None, extra=(), manifest=None, name=None, top_name=None):
            path = os.path.join(scratch, name or (top + ".tar.gz"))
            write_tar(path, top_name or top, files if files is not None else good_files(), extra, manifest)
            return path

        def expect(label, refused, build):
            nonlocal failures
            path = build()
            try:
                check(path)
                outcome = "passed"
            except Refused as error:
                outcome = f"refused: {error}"
            ok = (outcome != "passed") if refused else (outcome == "passed")
            print(f"{'ok  ' if ok else 'FAIL'} {label}: {outcome}")
            if not ok:
                failures += 1

        expect("a release of regular files", False, made)
        expect("an absolute path", True, lambda: made(extra=[("/etc/passwd", tarfile.REGTYPE, b"x", None)]))
        expect("a path that climbs out", True, lambda: made(extra=[(f"{top}/../x", tarfile.REGTYPE, b"x", None)]))
        expect("a path outside the top directory", True, lambda: made(extra=[("other/x", tarfile.REGTYPE, b"x", None)]))
        expect(
            "a link",
            True,
            lambda: made(extra=[(f"{top}/bin/link", tarfile.SYMTYPE, b"", lambda info: setattr(info, "linkname", "kr"))]),
        )
        expect(
            "a hard link",
            True,
            lambda: made(extra=[(f"{top}/bin/again", tarfile.LNKTYPE, b"", lambda info: setattr(info, "linkname", f"{top}/bin/kr"))]),
        )
        expect("a device", True, lambda: made(extra=[(f"{top}/bin/null", tarfile.CHRTYPE, b"", None)]))
        expect("a pipe", True, lambda: made(extra=[(f"{top}/bin/pipe", tarfile.FIFOTYPE, b"", None)]))
        expect(
            "a sparse file",
            True,
            lambda: made(
                extra=[
                    (f"{top}/share/hole", tarfile.REGTYPE, b"x", lambda info: info.pax_headers.update({"GNU.sparse.major": "1"}))
                ]
            ),
        )
        expect("a file the manifest does not list", True, lambda: made(extra=[(f"{top}/bin/extra", tarfile.REGTYPE, b"x", None)]))
        expect(
            "a listed file that is missing",
            True,
            lambda: made(files={"bin/kr": b"a program"}, manifest=manifest_for(good_files())),
        )
        expect(
            "a file that is not the listed one",
            True,
            lambda: made(files={**good_files(), "bin/kr": b"another program"}, manifest=manifest_for(good_files())),
        )
        expect(
            "two paths that are one where case is folded",
            True,
            lambda: made(
                files={**good_files(), "share/A": b"x", "share/a": b"y"},
            ),
        )
        expect(
            "a file where the top directory is",
            True,
            lambda: made(extra=[(top, tarfile.REGTYPE, b"x", None)]),
        )
        expect(
            "a path that is a file and a directory",
            True,
            lambda: made(extra=[(f"{top}/bin/kr/", tarfile.DIRTYPE, b"", None)]),
        )
        expect(
            "a file that is the parent of another",
            True,
            lambda: made(files={**good_files(), "share": b"x"}),
        )
        expect("a top directory the manifest does not name", True, lambda: made(top_name="kalareach-other", name=top + ".tar.gz"))

        # The same faults in a zip, which is what a Windows release is.
        ztop = "kalareach-x86_64-pc-windows-msvc-0.1.0+aaaaaaaaaaaa"

        def zipped(extra=(), files=None):
            path = os.path.join(scratch, ztop + ".zip")
            write_zip(path, ztop, files if files is not None else good_files(), extra)
            return path

        def expect_zip(label, refused, build):
            nonlocal failures
            try:
                check(build())
                outcome = "passed"
            except Refused as error:
                outcome = f"refused: {error}"
            ok = (outcome != "passed") if refused else (outcome == "passed")
            print(f"{'ok  ' if ok else 'FAIL'} {label}: {outcome}")
            if not ok:
                failures += 1

        expect_zip("a zip release of regular files", False, lambda: zipped())
        expect_zip("a zip with a link", True, lambda: zipped([(f"{ztop}/bin/link", 0o120777, b"kr")]))
        expect_zip("a zip with a file where the top directory is", True, lambda: zipped([(ztop, 0o100644, b"x")]))
        expect_zip("a zip with a file that is also a directory", True, lambda: zipped([(f"{ztop}/bin/kr/", 0o040755, b"")]))
        expect_zip("a zip with a path that climbs out", True, lambda: zipped([(f"{ztop}/../x", 0o100644, b"x")]))

        sums = os.path.join(scratch, "SHA256SUMS")
        made()
        with open(target, "rb") as handle:
            digest = sha256_hex(handle.read())
        for label, content, refused in (
            ("sums that give the digest", f"{digest}  {top}.tar.gz\n", False),
            ("sums that give another digest", f"{'0' * 64}  {top}.tar.gz\n", True),
            ("sums that name no archive", f"{digest}  other.tar.gz\n", True),
        ):
            with open(sums, "w", encoding="utf-8") as handle:
                handle.write(content)
            try:
                check(target, sums)
                outcome = "passed"
            except Refused as error:
                outcome = f"refused: {error}"
            ok = (outcome != "passed") if refused else (outcome == "passed")
            print(f"{'ok  ' if ok else 'FAIL'} {label}: {outcome}")
            if not ok:
                failures += 1
    return failures


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="check one archive")
    checking.add_argument("--archive", required=True)
    checking.add_argument("--sums")
    commands.add_parser("self-test", help="check the check against archives made to fail")
    parsed = parser.parse_args(arguments)
    if parsed.command == "self-test":
        return 1 if self_test() else 0
    try:
        check(parsed.archive, parsed.sums)
    except Refused as error:
        print(f"check-release-archive: {error}", file=sys.stderr)
        return 1
    print(f"check-release-archive: {os.path.basename(parsed.archive)} is a release archive")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
