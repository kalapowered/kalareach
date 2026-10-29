#!/usr/bin/env python3
"""Holds a staged macOS release tree to the tree the build run made, so that signing is the only difference.

    scripts/check-staged-tree.py compare <the run's tree, a tar> <the staged tree, a tar> [<tar to write>]
    scripts/check-staged-tree.py self-test

The macOS trees are built on a hosted runner, signed and notarised on another machine, and sealed
by a job that has the update channel's release keys. Sealing writes the manifest again over the files
as they are, so whatever the signing machine handed over is what the manifest then vouches for. This
check is what stops a staged tree from carrying anything but signatures:

  * the staged tree has exactly the members of the run's tree: the same directories and regular
    files at the same modes, and nothing else (no link, no device);
  * `release.json` is the run's, byte for byte, and the run's `release.json` states the length and
    the SHA-256 of every other regular file;
  * every file that is not Mach-O is the run's, by those lengths and digests;
  * every Mach-O file is the run's outside its code signature. A signature is the last thing in the
    file, in the last segment, so what precedes it must be equal; the only fields of the headers that
    signing sets are the size of the signature, and the size of the last segment that holds it in
    the file and in memory. The first two follow from where the signature starts and the length of the
    file; the third has to be the second rounded up to 16 KiB, as the signer sets it, so that none of the three can be
    set to anything else. The signature itself is checked where the tree is verified
    (`check-macos-signatures.sh`), against the team and the notarisation.

When a third argument is given and the trees agree, the staged tree is written there, member by member
as this check read it, in the standard form every tar program reads alike. That tar, and not the staged
one, is what the next job unpacks: a tar can be built so that one reader sees a member in one place and
another reader in another, and the check holds only what it read.

A Mach-O layout that cannot be compared exactly is refused and named: a universal file, a 32-bit or
a big-endian file, a file with no signature, or a signature that is not at the end of the file.
Standard library only.
"""

import base64
import hashlib
import io
import json
import struct
import sys
import tarfile

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe": "64-bit",
    b"\xce\xfa\xed\xfe": "32-bit",
    b"\xfe\xed\xfa\xcf": "64-bit big-endian",
    b"\xfe\xed\xfa\xce": "32-bit big-endian",
    b"\xca\xfe\xba\xbe": "universal",
    b"\xca\xfe\xba\xbf": "universal",
    b"\xbe\xba\xfe\xca": "universal",
    b"\xbf\xba\xfe\xca": "universal",
}
# The size the signer rounds the last segment up to in memory: 16 KiB, for arm64 and x86-64 files alike
# (the sizes of the 89 files of each architecture of a release tree, in the run's ad hoc signature and
# in the Developer ID one, are all that rounding of their sizes in the file).
SEGMENT_ROUNDING = 0x4000
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
HEADER = 32


class Refusal(Exception):
    pass


def is_macho(head):
    return head[:4] in MACHO_MAGICS


def commands(data):
    """The load commands of a thin 64-bit little-endian Mach-O file, as (offset, command, size)."""
    magic = data[:4]
    if magic not in MACHO_MAGICS:
        raise Refusal("is not a Mach-O file")
    if MACHO_MAGICS[magic] != "64-bit":
        raise Refusal(f"is a {MACHO_MAGICS[magic]} Mach-O file, whose layout is not compared")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    offset, found = HEADER, []
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise Refusal("has a load command beyond the end of the file")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > HEADER + sizeofcmds:
            raise Refusal("has a load command that does not fit the header")
        found.append((offset, command, size))
        offset += size
    return found


def signature_fields(data):
    """The places the signing of a file sets, and the offset the signature starts at.

    Returns (offset of the signature, the byte ranges that signing sets).
    """
    found = commands(data)
    signatures = [c for c in found if c[1] == LC_CODE_SIGNATURE]
    if len(signatures) != 1:
        raise Refusal(f"has {len(signatures)} code signature commands, and one is needed to compare it")
    sig_offset, _, sig_size = signatures[0]
    if sig_size != 16:
        raise Refusal("has a code signature command of another size")
    dataoff, datasize = struct.unpack_from("<II", data, sig_offset + 8)
    if dataoff + datasize != len(data):
        raise Refusal("has a code signature that is not at the end of the file")
    segments = [(o, struct.unpack_from("<16s", data, o + 8)[0].rstrip(b"\0")) for o, c, _ in found if c == LC_SEGMENT_64]
    last = max(segments, key=lambda s: struct.unpack_from("<Q", data, s[0] + 40)[0])
    vmsize, fileoff, filesize = struct.unpack_from("<QQQ", data, last[0] + 32)
    if fileoff + filesize != len(data):
        raise Refusal("has a last segment that does not end with the file")
    if vmsize != (filesize + SEGMENT_ROUNDING - 1) // SEGMENT_ROUNDING * SEGMENT_ROUNDING:
        raise Refusal("has a last segment whose size in memory is not its size in the file rounded up to 16 KiB, as the signer sets it")
    if fileoff > dataoff:
        raise Refusal("has a code signature before the start of the last segment")
    # The size of the signature and of the segment that holds it are what signing sets.
    ranges = [(sig_offset + 12, sig_offset + 16), (last[0] + 32, last[0] + 40), (last[0] + 48, last[0] + 56)]
    return dataoff, ranges


def equal_outside_signature(built, staged):
    """None when the two files differ only in their code signature, else why they do not."""
    try:
        built_at, built_ranges = signature_fields(built)
    except Refusal as error:
        return f"the run's file {error}"
    try:
        staged_at, staged_ranges = signature_fields(staged)
    except Refusal as error:
        return f"the staged file {error}"
    if built_at != staged_at:
        return f"the signature starts at {staged_at} and the run's file has none there but at {built_at}"
    if built_ranges != staged_ranges:
        return "the headers lay out the segments and the signature differently"
    first, second = bytearray(built[:built_at]), bytearray(staged[:staged_at])
    for start, end in built_ranges:
        first[start:end] = bytes(end - start)
        second[start:end] = bytes(end - start)
    if first != second:
        at = next(i for i in range(len(first)) if first[i] != second[i])
        return f"the bytes differ at offset {at}, before the signature"
    return None


def digest(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def members(path):
    archive = tarfile.open(path)
    found = {}
    top = None
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        parts = name.split("/")
        if name.startswith("/") or ".." in parts or "." in parts or "" in parts:
            raise Refusal(f"{path}: {member.name} is not a path inside the tree")
        if top is None:
            top = parts[0]
        if parts[0] != top:
            raise Refusal(f"{path}: {member.name} is outside the top directory {top}")
        if len(parts) == 1:
            if not member.isdir():
                raise Refusal(f"{path}: the top is not a directory")
            if "" in found:
                raise Refusal(f"{path}: the top directory is there twice")
            found[""] = member
            continue
        relative = "/".join(parts[1:])
        if not (member.isreg() or member.isdir()):
            raise Refusal(f"{path}: {relative} is a link or a special file, and a tree has only directories and regular files")
        if relative in found:
            raise Refusal(f"{path}: {relative} is there twice")
        found[relative] = member
    if top is None:
        raise Refusal(f"{path}: empty")
    return archive, top, found


def compare(built_path, staged_path, out_path=None):
    problems = []
    built_archive, built_top, built = members(built_path)
    staged_archive, staged_top, staged = members(staged_path)
    if built_top != staged_top:
        problems.append(f"the staged tree is {staged_top} and the run's is {built_top}")
    for relative in sorted(set(built) - set(staged)):
        problems.append(f"{relative or 'the top directory'} is in the run's tree and not in the staged one")
    for relative in sorted(set(staged) - set(built)):
        problems.append(f"{relative} is in the staged tree and not in the run's")
    manifest = json.loads(built_archive.extractfile(built["release.json"]).read())["signed"]["files"]
    listed = {entry["path"]: entry for entry in manifest}
    regular = {r for r, m in built.items() if m.isreg() and r != "release.json"}
    if not built[""].isdir() or not staged[""].isdir():
        problems.append("the top is not a directory")
    if regular != set(listed):
        problems.append(f"the run's release.json lists {len(listed)} files and the run's tree has {len(regular)} besides it")
    for relative in sorted(set(built) & set(staged)):
        built_member, staged_member = built[relative], staged[relative]
        if built_member.isdir() != staged_member.isdir():
            problems.append(f"{relative} is a directory in one tree and a file in the other")
            continue
        if (built_member.mode & 0o7777) != (staged_member.mode & 0o7777):
            problems.append(f"{relative or 'the top directory'} has mode {oct(staged_member.mode & 0o7777)}, and the run's has {oct(built_member.mode & 0o7777)}")
        if built_member.isdir():
            continue
        built_data = built_archive.extractfile(built_member).read()
        staged_data = staged_archive.extractfile(staged_member).read()
        if relative == "release.json":
            if built_data != staged_data:
                problems.append("release.json is not the run's")
            continue
        entry = listed.get(relative)
        if is_macho(built_data[:4]):
            reason = equal_outside_signature(built_data, staged_data)
            if reason:
                problems.append(f"{relative}: {reason}")
            continue
        if entry is None:
            continue
        if str(len(staged_data)) != entry["length"] or digest(staged_data) != entry["sha256"]:
            problems.append(f"{relative} is not the file the run's release.json describes")
    if out_path and not problems:
        write(staged_archive, staged_top, staged, out_path)
    return problems


def write(archive, top, found, out_path):
    """The staged tree as this check read it, in the standard form."""
    with tarfile.open(out_path, "w", format=tarfile.PAX_FORMAT) as out:
        for relative in sorted(found, key=lambda r: (not found[r].isdir(), r)):
            member = found[relative]
            info = tarfile.TarInfo(f"{top}/{relative}" if relative else top)
            info.mode, info.mtime = member.mode & 0o7777, member.mtime
            if member.isdir():
                info.type = tarfile.DIRTYPE
                out.addfile(info)
            else:
                data = archive.extractfile(member).read()
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))


# --- the self-test -------------------------------------------------------------------------------


def macho(payload, signature, vmsize=None):
    """A thin 64-bit file of a text segment, a last segment and, when there is one, a code signature at its end."""
    sig = signature or b""
    text = struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, 72, b"__TEXT", 0, 0x4000, 0, 0x4000, 5, 5, 0, 0)
    link_filesize = len(payload) + len(sig)
    link = struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, 72, b"__LINKEDIT", 0x4000,
                       (link_filesize + 0x3FFF) & ~0x3FFF if vmsize is None else vmsize, 0x4000, link_filesize, 1, 1, 0, 0)
    code = struct.pack("<IIII", LC_CODE_SIGNATURE, 16, 0x4000 + len(payload), len(sig)) if signature is not None else b""
    body_commands = text + link + code
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 3 if signature is not None else 2, len(body_commands), 0, 0)
    body = header + body_commands
    return body + b"\0" * (0x4000 - len(body)) + payload + sig


def release_of(files):
    manifest = [{"length": str(len(data)), "mode": "executable" if mode & 0o111 else "regular", "path": path, "sha256": digest(data)}
                for path, data, mode in files]
    return json.dumps({"signed": {"files": manifest}}).encode()


def tree(top, files, release, dirs=("bin", "share"), extra=(), top_mode=0o755):
    """A tree as a tar in memory: files are (path, bytes, mode), and release is the bytes of release.json."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in (top,) + tuple(f"{top}/{d}" for d in dirs):
            info = tarfile.TarInfo(name)
            info.type, info.mode = tarfile.DIRTYPE, top_mode if name == top else 0o755
            archive.addfile(info)
        for path, data, mode in list(files) + [("release.json", release, 0o644)]:
            info = tarfile.TarInfo(f"{top}/{path}")
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
        for info in extra:
            archive.addfile(info)
    return buffer.getvalue()


def tar_readers_agree(top, files, release, work):
    """What the next job unpacks is what was compared, even for a tar built so that readers differ."""
    import subprocess

    good = tree(top, files, release, dirs=("bin", "share"))
    # A member in the old form, with its directory in the prefix field and no ustar magic: this check
    # joins the prefix to the name whatever the magic says, and another reader may not.
    raw = bytearray(good)
    wanted = f"{top}/share/doc.txt".encode()
    at = next(i for i in range(0, len(raw), 512) if bytes(raw[i:i + 100]).rstrip(b"\0") == wanted)
    raw[at:at + 100] = b"doc.txt".ljust(100, b"\0")
    raw[at + 345:at + 500] = f"{top}/share".encode().ljust(155, b"\0")
    raw[at + 257:at + 265] = bytes(8)
    raw[at + 148:at + 156] = b" " * 8
    raw[at + 148:at + 156] = f"{sum(raw[at:at + 512]):06o}".encode() + b"\0 "
    with open(f"{work}/built.tar", "wb") as handle:
        handle.write(good)
    with open(f"{work}/crafted.tar", "wb") as handle:
        handle.write(bytes(raw))
    try:
        problems = compare(f"{work}/built.tar", f"{work}/crafted.tar", f"{work}/normalized.tar")
    except Refusal as error:
        problems = [str(error)]
    if problems:
        print(f"self-test FAILED: a tar with a member in the old form was not read as the standard form reads it ({problems})")
        return False
    listing = lambda path: set(subprocess.run(["tar", "-tf", path], capture_output=True, text=True).stdout.split())
    seen_by_python = {f"{top}/share/doc.txt"}
    if not (seen_by_python <= listing(f"{work}/normalized.tar")):
        print("self-test FAILED: the tar written for the next job does not hold the member the check compared")
        return False
    note = "" if not (seen_by_python <= listing(f"{work}/crafted.tar")) else " (this tar program reads the crafted tar as the check does)"
    print("self-test ok: the tar written for the next job holds what the check compared, in the standard form" + note)
    return True


def self_test():
    import tempfile

    top = "kalareach-aarch64-apple-darwin-0.1.0+aaaaaaaaaaaa"
    payload = bytes(range(256)) * 8
    adhoc, signed = b"A" * 300, b"S" * 1200

    def files(signature=signed, payload=payload, text=b"#!/bin/sh\n", mode=0o755):
        return [("bin/kr", macho(payload, signature), 0o755), ("bin/run", text, mode), ("share/doc.txt", b"hello\n", 0o644)]

    built_files = files(signature=adhoc)
    release = release_of(built_files)
    results = []

    with tempfile.TemporaryDirectory() as work:

        def run(name, staged, expect, built=None):
            problems = []
            try:
                with open(f"{work}/built.tar", "wb") as handle:
                    handle.write(built or tree(top, built_files, release))
                with open(f"{work}/staged.tar", "wb") as handle:
                    handle.write(staged)
                problems = compare(f"{work}/built.tar", f"{work}/staged.tar")
            except Refusal as error:
                problems = [str(error)]
            ok = (not problems) if expect is None else any(expect in p for p in problems)
            print(("self-test ok: " if ok else "self-test FAILED: ") + name + ("" if ok else f" ({problems})"))
            results.append(ok)

        def staged(**kwargs):
            return tree(top, files(**kwargs), release)

        run("a staged tree that differs only in the signature of its Mach-O file passes", staged(), None)
        run("a changed text file of the same length is refused", staged(text=b"#!/bin/zh\n"), "bin/run is not the file")
        run("a changed mode is refused", staged(mode=0o644), "bin/run has mode")
        run("a changed byte of a Mach-O file before its signature is refused", staged(payload=payload[:10] + b"X" + payload[11:]), "bytes differ")
        run("a Mach-O file with another length before its signature is refused", staged(payload=payload + b"Y"), "signature starts at")
        run("a file only the staged tree has is refused", tree(top, files() + [("bin/extra", b"x", 0o755)], release), "bin/extra is in the staged tree")
        run("a file only the run's tree has is refused", tree(top, files()[:2], release), "share/doc.txt is in the run's tree")
        link = tarfile.TarInfo(f"{top}/bin/link")
        link.type, link.linkname = tarfile.SYMTYPE, "kr"
        run("a link in the staged tree is refused", tree(top, files(), release, extra=[link]), "is a link or a special file")
        run("a release.json that is not the run's is refused", tree(top, files(), release.replace(b'"regular"', b'"regulaR"')), "release.json is not the run's")
        universal = [("bin/kr", b"\xca\xfe\xba\xbe" + b"\0" * 60, 0o755)] + files()[1:]
        universal_release = release_of(universal)
        run("a universal file is refused and named", tree(top, universal, universal_release), "universal Mach-O",
            built=tree(top, universal, universal_release))
        bare = [("bin/kr", macho(payload, None), 0o755)] + files()[1:]
        bare_release = release_of(bare)
        run("a Mach-O file with no code signature is refused", tree(top, bare, bare_release), "has 0 code signature commands",
            built=tree(top, bare, bare_release))
        tail = [("bin/kr", macho(payload, signed) + b"tail", 0o755)] + files()[1:]
        run("a code signature that is not at the end of the file is refused", tree(top, tail, release), "not at the end of the file")
        for label, vm in (("zero", 0), ("a huge", 0x100000000000)):
            odd = [("bin/kr", macho(payload, signed, vmsize=vm), 0o755)] + files()[1:]
            run(f"a last segment of {label} size in memory is refused", tree(top, odd, release), "rounded up to 16 KiB")
        run("a changed mode of the top directory is refused", tree(top, files(), release, top_mode=0o700), "the top directory has mode")
        twice = tarfile.TarInfo(f"{top}/bin/extra-dir")
        twice.type, twice.mode = tarfile.DIRTYPE, 0o755
        run("a directory that is there twice is refused", tree(top, files(), release, extra=[twice, twice]), "is there twice")
        hard = tarfile.TarInfo(f"{top}/bin/hard")
        hard.type, hard.linkname = tarfile.LNKTYPE, f"{top}/bin/kr"
        run("a hard link in the staged tree is refused", tree(top, files(), release, extra=[hard]), "is a link or a special file")
        dotted = tarfile.TarInfo(f"{top}/./bin/aliased")
        dotted.size = 1
        run("a path with a . part is refused", tree(top, files(), release, extra=[dotted]), "is not a path inside the tree")
        results.append(tar_readers_agree(top, files(), release, work))
    if not all(results):
        print(f"check-staged-tree: {results.count(False)} self-test case(s) failed", file=sys.stderr)
        return 1
    print("check-staged-tree: the self-test passed")
    return 0


def main(argv):
    if argv[1:2] == ["self-test"]:
        return self_test()
    if len(argv) in (4, 5) and argv[1] == "compare":
        try:
            problems = compare(argv[2], argv[3], argv[4] if len(argv) == 5 else None)
        except (Refusal, tarfile.TarError, KeyError, ValueError) as error:
            print(f"check-staged-tree: {error}", file=sys.stderr)
            return 1
        for problem in problems:
            print(f"check-staged-tree: {problem}", file=sys.stderr)
        if problems:
            print(f"check-staged-tree: the staged tree differs from the run's in {len(problems)} place(s) besides its signatures", file=sys.stderr)
            return 1
        print("check-staged-tree: the staged tree differs from the run's in its signatures only")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
