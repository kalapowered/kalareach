#!/usr/bin/env python3
"""Reads each release executable's platform floor back out of the binary and refuses one that does
not match the release baseline for its target.

    check-release-floors.py check --target <target triple> <executable>...
    check-release-floors.py self-test

A floor is what the executable itself says about the oldest system it runs on, read from its own
headers rather than from the build settings that were meant to put it there:

* macOS: the minimum system version in the Mach-O header of every architecture it carries. A
  release build targets macOS 14.0, and the check wants exactly that: a lower floor is a build that
  did not target the baseline (Rust's own default is 11.0 on Apple Silicon), and a higher one would
  refuse to start on it.
* Linux: the newest glibc symbol version the executable needs. glibc 2.35 is Ubuntu 22.04's, the
  oldest Linux release target, so a newer one is refused: the executable would not load there.
* Windows: the subsystem version in the PE header, the oldest Windows the image says it runs on.
  Windows 11 is NT 10.0, so a newer one is refused.

Each target's machine is checked as well, so an executable built for the other architecture is
refused rather than read. Only Python's standard library is used, so the check runs on every
runner the release is built on.
"""

import argparse
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile

# Section 3's release baselines, as each binary format states them.
MACOS_MINIMUM = (14, 0, 0)
GLIBC_NEWEST = (2, 35)
WINDOWS_NEWEST = (10, 0)

TARGETS = {
    "aarch64-apple-darwin": ("mach-o", "arm64"),
    "x86_64-apple-darwin": ("mach-o", "x86_64"),
    "x86_64-unknown-linux-gnu": ("elf", "x86_64"),
    "aarch64-unknown-linux-gnu": ("elf", "aarch64"),
    "x86_64-pc-windows-msvc": ("pe", "x86_64"),
    "aarch64-pc-windows-msvc": ("pe", "aarch64"),
}


class Refused(Exception):
    """A binary this check cannot read as the release says it should be."""


def dotted(version):
    """A version as people write it: 14.0 rather than 14.0.0, and 2.2.5 as it is."""
    shown = list(version)
    while len(shown) > 2 and shown[-1] == 0:
        shown.pop()
    return ".".join(str(part) for part in shown)


def unpack(layout, data, offset):
    """Unpacks `layout` at `offset`, refusing a binary too short to hold it."""
    size = struct.calcsize(layout)
    if offset < 0 or offset + size > len(data):
        raise Refused("it ends before the header it declares")
    return struct.unpack_from(layout, data, offset)


# ------------------------------------------------------------------------------------------------
# Mach-O
# ------------------------------------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
MACHO_CPUS = {CPU_TYPE_X86_64: "x86_64", CPU_TYPE_ARM64: "arm64"}


def unpacked_version(value):
    return (value >> 16, (value >> 8) & 0xFF, value & 0xFF)


def macho_slices(data):
    """Returns the (offset, length) of every architecture a Mach-O file carries."""
    (magic,) = unpack(">I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        (count,) = unpack(">I", data, 4)
        slices = []
        for index in range(count):
            if magic == FAT_MAGIC:
                _, _, offset, length, _ = unpack(">iiIII", data, 8 + index * 20)
            else:
                _, _, offset, length, _, _ = unpack(">iiQQII", data, 8 + index * 32)
            slices.append((offset, length))
        return slices
    return [(0, len(data))]


def read_macho_slice(data):
    """Returns (architecture, minimum system version) for one thin 64-bit Mach-O image."""
    magic, cputype, _, _, count, _, _, _ = unpack("<IiiIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise Refused("it is not a 64-bit Mach-O image")
    architecture = MACHO_CPUS.get(cputype & 0xFFFFFFFF, "cpu type {:#x}".format(cputype))
    minimum = None
    offset = 32
    for _ in range(count):
        command, size = unpack("<II", data, offset)
        if size < 8:
            raise Refused("a load command declares a size smaller than its own header")
        if command == LC_BUILD_VERSION:
            _, _, platform_id, value, _, _ = unpack("<IIIIII", data, offset)
            if platform_id != PLATFORM_MACOS:
                raise Refused("it was built for Apple platform {}, not macOS".format(platform_id))
            minimum = unpacked_version(value)
        elif command == LC_VERSION_MIN_MACOSX:
            _, _, value, _ = unpack("<IIII", data, offset)
            minimum = unpacked_version(value)
        offset += size
    if minimum is None:
        raise Refused("it declares no minimum macOS version")
    return architecture, minimum


def check_macho(data, architecture):
    slices = macho_slices(data)
    found = []
    for offset, length in slices:
        found.append(read_macho_slice(data[offset : offset + length]))
    # Every image is held to the baseline, not only the one for this target: a universal file is
    # one download, and each of its images has to start on the baseline.
    wrong = [minimum for _, minimum in found if minimum != MACOS_MINIMUM]
    carried = [arch for arch, _ in found]
    described = ", ".join("{} for macOS {}".format(arch, dotted(minimum)) for arch, minimum in found)
    if architecture not in carried:
        return False, "Mach-O {}, which carries no {} image".format(described, architecture)
    baseline = "the baseline is macOS {}".format(dotted(MACOS_MINIMUM))
    if wrong:
        return False, "Mach-O {}; {}".format(described, baseline)
    return True, "Mach-O {}; {}".format(described, baseline)


# ------------------------------------------------------------------------------------------------
# ELF
# ------------------------------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
EM_X86_64 = 62
EM_AARCH64 = 183
ELF_MACHINES = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}
SHT_GNU_VERNEED = 0x6FFFFFFE

# The ABI markers glibc's own version names carry beside its releases, and the release that first
# accepts each one. A linker newer than the oldest target's writes these without being asked.
GLIBC_MARKERS = {"GLIBC_ABI_DT_RELR": (2, 36)}


def glibc_version(name):
    """Returns the glibc release a `GLIBC_...` version name needs, or None when it names none.

    `GLIBC_x.y[.z]` needs that release and a known ABI marker the release that introduced it.
    Anything else under glibc's prefix, `GLIBC_PRIVATE` among them, needs no release this check can
    name, and the caller refuses it.
    """
    if name in GLIBC_MARKERS:
        return GLIBC_MARKERS[name]
    parts = name[len("GLIBC_") :].split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def c_string(data, offset):
    end = data.find(b"\0", offset)
    if offset < 0 or end < 0:
        raise Refused("a version name runs past its string table")
    return data[offset:end].decode("ascii", "replace")


def read_elf(data):
    """Returns (architecture, every version name the executable needs from glibc's libraries)."""
    if data[:4] != ELF_MAGIC:
        raise Refused("it is not an ELF image")
    if len(data) < 64 or data[4] != 2 or data[5] != 1:
        raise Refused("it is not a 64-bit little-endian ELF image")
    (machine,) = unpack("<H", data, 18)
    architecture = ELF_MACHINES.get(machine, "machine {}".format(machine))
    (section_offset,) = unpack("<Q", data, 40)
    entry_size, count, _ = unpack("<HHH", data, 58)
    if section_offset == 0 or count == 0:
        raise Refused("it has no section headers, so the versions it needs cannot be read")
    if entry_size < 64:
        raise Refused("its section headers are smaller than a 64-bit ELF section header")
    sections = []
    for index in range(count):
        _, kind, _, _, offset, size, link, info, _, _ = unpack(
            "<IIQQQQIIQQ", data, section_offset + index * entry_size
        )
        sections.append((kind, offset, size, link, info))
    names = []
    for kind, offset, size, link, info in sections:
        if kind != SHT_GNU_VERNEED:
            continue
        if link >= len(sections):
            raise Refused("its version needs name a string table it does not have")
        _, strings_offset, strings_size, _, _ = sections[link]
        strings = data[strings_offset : strings_offset + strings_size]
        entry = offset
        for _ in range(info):
            _, auxiliary_count, _, auxiliary, following = unpack("<HHIII", data, entry)
            item = entry + auxiliary
            for _ in range(auxiliary_count):
                _, _, _, name, following_item = unpack("<IHHII", data, item)
                names.append(c_string(strings, name))
                item += following_item
            if following == 0:
                break
            entry += following
    return architecture, names


def check_elf(data, architecture):
    found, names = read_elf(data)
    if found != architecture:
        return False, "ELF {}, not {}".format(found, architecture)
    baseline = "the baseline is glibc {} (Ubuntu 22.04)".format(dotted(GLIBC_NEWEST))
    glibc = [name for name in names if name.startswith("GLIBC_")]
    unnamed = sorted({name for name in glibc if glibc_version(name) is None})
    if unnamed:
        return False, "ELF {} needing {}, which no glibc release this check knows provides; {}".format(
            found, ", ".join(unnamed), baseline
        )
    versions = [glibc_version(name) for name in glibc]
    if not versions:
        return True, "ELF {} needing no versioned glibc symbol; {}".format(found, baseline)
    newest = max(versions)
    sentence = "ELF {} that needs glibc {} or newer; {}".format(found, dotted(newest), baseline)
    return newest <= GLIBC_NEWEST, sentence


# ------------------------------------------------------------------------------------------------
# PE
# ------------------------------------------------------------------------------------------------

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
PE_MACHINES = {IMAGE_FILE_MACHINE_AMD64: "x86_64", IMAGE_FILE_MACHINE_ARM64: "aarch64"}
PE32 = 0x10B
PE32_PLUS = 0x20B


def read_pe(data):
    """Returns (architecture, subsystem version) for a PE image."""
    if data[:2] != b"MZ":
        raise Refused("it is not a PE image")
    (header,) = unpack("<I", data, 0x3C)
    if data[header : header + 4] != b"PE\0\0":
        raise Refused("it has no PE signature where its DOS header points")
    machine, _, _, _, _, optional_size, _ = unpack("<HHIIIHH", data, header + 4)
    optional = header + 24
    if optional_size < 52:
        raise Refused("its optional header is too short to hold a subsystem version")
    (magic,) = unpack("<H", data, optional)
    if magic not in (PE32, PE32_PLUS):
        raise Refused("its optional header is neither PE32 nor PE32+")
    major, minor = unpack("<HH", data, optional + 48)
    architecture = PE_MACHINES.get(machine, "machine {:#x}".format(machine))
    return architecture, (major, minor)


def check_pe(data, architecture):
    found, version = read_pe(data)
    if found != architecture:
        return False, "PE {}, not {}".format(found, architecture)
    sentence = "PE {} declaring Windows {} as its oldest; the baseline is Windows 11 (NT {})".format(
        found, dotted(version), dotted(WINDOWS_NEWEST)
    )
    return version <= WINDOWS_NEWEST, sentence


# ------------------------------------------------------------------------------------------------
# The check
# ------------------------------------------------------------------------------------------------

CHECKS = {"mach-o": check_macho, "elf": check_elf, "pe": check_pe}


def check_file(target, path):
    """Returns (passed, sentence) for one executable."""
    kind, architecture = TARGETS[target]
    name = os.path.basename(path)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        passed, sentence = CHECKS[kind](data, architecture)
    except (OSError, Refused) as error:
        return False, "{} ({}): {}".format(name, target, error)
    return passed, "{} ({}): {}".format(name, target, sentence)


# ------------------------------------------------------------------------------------------------
# The check's own test
# ------------------------------------------------------------------------------------------------


def packed_version(version):
    major, minor, patch = version
    return (major << 16) | (minor << 8) | patch


def synthetic_macho(cputype, commands):
    body = b"".join(commands)
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, cputype, 0, 2, len(commands), len(body), 0, 0)
    return header + body


def build_version_command(platform_id, minimum):
    return struct.pack("<IIIIII", LC_BUILD_VERSION, 24, platform_id, packed_version(minimum), 0, 0)


def version_min_command(minimum):
    return struct.pack("<IIII", LC_VERSION_MIN_MACOSX, 16, packed_version(minimum), 0)


def synthetic_fat(images):
    header = struct.pack(">II", FAT_MAGIC, len(images))
    offset = 8 + 20 * len(images)
    table = b""
    body = b""
    for cputype, image in images:
        table += struct.pack(">iiIII", cputype, 0, offset + len(body), len(image), 0)
        body += image
    return header + table + body


def synthetic_elf(machine, names):
    """An ELF image whose only version needs are `names`, all from libc.so.6."""
    strings = b"\0libc.so.6\0"
    offsets = []
    for name in names:
        offsets.append(len(strings))
        strings += name.encode("ascii") + b"\0"
    needs = struct.pack("<HHIII", 1, len(names), 1, 16, 0)
    for index, offset in enumerate(offsets):
        following = 16 if index + 1 < len(offsets) else 0
        needs += struct.pack("<IHHII", 0, 0, 2 + index, offset, following)
    section_names = b"\0.dynstr\0.gnu.version_r\0.shstrtab\0"
    strings_at = 64
    needs_at = strings_at + len(strings)
    names_at = needs_at + len(needs)
    headers_at = names_at + len(section_names)
    identity = ELF_MAGIC + bytes([2, 1, 1]) + bytes(9)
    header = identity + struct.pack(
        "<HHIQQQIHHHHHH", 3, machine, 1, 0, 0, headers_at, 0, 64, 56, 0, 64, 4, 3
    )

    def section(name, kind, offset, size, link=0, info=0):
        return struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, offset, size, link, info, 1, 0)

    headers = (
        section(0, 0, 0, 0)
        + section(1, 3, strings_at, len(strings))
        + section(9, SHT_GNU_VERNEED, needs_at, len(needs), link=1, info=1)
        + section(24, 3, names_at, len(section_names))
    )
    return header + strings + needs + section_names + headers


def synthetic_pe(machine, version):
    dos = b"MZ" + bytes(0x3C - 2) + struct.pack("<I", 64)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, 240, 0x22)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, PE32_PLUS)
    struct.pack_into("<HH", optional, 48, version[0], version[1])
    struct.pack_into("<H", optional, 68, 3)
    return dos + coff + bytes(optional)


SYNTHETIC = [
    (
        "a Mach-O built for macOS 11.0, Rust's default",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_ARM64, [build_version_command(PLATFORM_MACOS, (11, 0, 0))]),
        False,
    ),
    (
        "a Mach-O built for macOS 14.0",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_ARM64, [build_version_command(PLATFORM_MACOS, (14, 0, 0))]),
        True,
    ),
    (
        "a Mach-O built for macOS 15.0, which would not start on 14",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_ARM64, [build_version_command(PLATFORM_MACOS, (15, 0, 0))]),
        False,
    ),
    (
        "a Mach-O stating its floor the older way, at 14.0",
        "x86_64-apple-darwin",
        synthetic_macho(CPU_TYPE_X86_64, [version_min_command((14, 0, 0))]),
        True,
    ),
    (
        "a Mach-O stating its floor the older way, at 13.0",
        "x86_64-apple-darwin",
        synthetic_macho(CPU_TYPE_X86_64, [version_min_command((13, 0, 0))]),
        False,
    ),
    (
        "a Mach-O stating its floor the older way, at 15.0",
        "x86_64-apple-darwin",
        synthetic_macho(CPU_TYPE_X86_64, [version_min_command((15, 0, 0))]),
        False,
    ),
    (
        "a Mach-O built for iOS",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_ARM64, [build_version_command(2, (14, 0, 0))]),
        False,
    ),
    (
        "a Mach-O that declares no floor",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_ARM64, []),
        False,
    ),
    (
        "a Mach-O for Intel checked as Apple Silicon",
        "aarch64-apple-darwin",
        synthetic_macho(CPU_TYPE_X86_64, [build_version_command(PLATFORM_MACOS, (14, 0, 0))]),
        False,
    ),
    (
        "a universal Mach-O whose Apple Silicon image is at 14.0",
        "aarch64-apple-darwin",
        synthetic_fat(
            [
                (
                    CPU_TYPE_X86_64,
                    synthetic_macho(
                        CPU_TYPE_X86_64, [build_version_command(PLATFORM_MACOS, (14, 0, 0))]
                    ),
                ),
                (
                    CPU_TYPE_ARM64,
                    synthetic_macho(
                        CPU_TYPE_ARM64, [build_version_command(PLATFORM_MACOS, (14, 0, 0))]
                    ),
                ),
            ]
        ),
        True,
    ),
    (
        "a universal Mach-O whose Intel image is at 15.0, checked as Apple Silicon",
        "aarch64-apple-darwin",
        synthetic_fat(
            [
                (
                    CPU_TYPE_X86_64,
                    synthetic_macho(
                        CPU_TYPE_X86_64, [build_version_command(PLATFORM_MACOS, (15, 0, 0))]
                    ),
                ),
                (
                    CPU_TYPE_ARM64,
                    synthetic_macho(
                        CPU_TYPE_ARM64, [build_version_command(PLATFORM_MACOS, (14, 0, 0))]
                    ),
                ),
            ]
        ),
        False,
    ),
    (
        "an ELF needing glibc 2.34",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_X86_64, ["GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.34"]),
        True,
    ),
    (
        "an ELF needing glibc 2.35",
        "aarch64-unknown-linux-gnu",
        synthetic_elf(EM_AARCH64, ["GLIBC_2.17", "GLIBC_2.35"]),
        True,
    ),
    (
        "an ELF needing glibc 2.38, which Ubuntu 22.04 does not have",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_X86_64, ["GLIBC_2.17", "GLIBC_2.38", "GLIBC_2.34"]),
        False,
    ),
    (
        "an ELF needing glibc's private symbols",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_X86_64, ["GLIBC_2.17", "GLIBC_PRIVATE"]),
        False,
    ),
    (
        "an ELF whose packed relocations need glibc 2.36",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_X86_64, ["GLIBC_2.17", "GLIBC_ABI_DT_RELR"]),
        False,
    ),
    (
        "an ELF cut off inside its header",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_X86_64, ["GLIBC_2.17"])[:20],
        False,
    ),
    (
        "an ELF for ARM64 checked as x86-64",
        "x86_64-unknown-linux-gnu",
        synthetic_elf(EM_AARCH64, ["GLIBC_2.17"]),
        False,
    ),
    (
        "a PE declaring Windows 6.0",
        "x86_64-pc-windows-msvc",
        synthetic_pe(IMAGE_FILE_MACHINE_AMD64, (6, 0)),
        True,
    ),
    (
        "a PE declaring Windows 10.0",
        "aarch64-pc-windows-msvc",
        synthetic_pe(IMAGE_FILE_MACHINE_ARM64, (10, 0)),
        True,
    ),
    (
        "a PE declaring a Windows newer than 10.0",
        "x86_64-pc-windows-msvc",
        synthetic_pe(IMAGE_FILE_MACHINE_AMD64, (10, 1)),
        False,
    ),
    (
        "a PE for x86-64 checked as ARM64",
        "aarch64-pc-windows-msvc",
        synthetic_pe(IMAGE_FILE_MACHINE_AMD64, (6, 0)),
        False,
    ),
    (
        "a file that is no executable at all",
        "x86_64-unknown-linux-gnu",
        b"#!/bin/sh\nexit 0\n",
        False,
    ),
]


def expect(cases, name, passed, sentence, wanted):
    right = passed == wanted
    cases.append((name, right))
    verdict = "passed" if passed else "refused"
    print("{:<8} {:<8} {}: {}".format("right" if right else "WRONG", verdict, name, sentence))


def self_test():
    """Checks this checker against binaries whose floors are known, and returns the exit code."""
    cases = []
    with tempfile.TemporaryDirectory(prefix="release-floors-") as directory:
        for index, (name, target, image, wanted) in enumerate(SYNTHETIC):
            path = os.path.join(directory, "synthetic-{}".format(index))
            with open(path, "wb") as handle:
                handle.write(image)
            passed, sentence = check_file(target, path)
            expect(cases, name, passed, sentence, wanted)
        real_macos_builds(directory, cases)
    failed = [name for name, right in cases if not right]
    print("{} cases, {} wrong".format(len(cases), len(failed)))
    return 1 if failed else 0


def real_macos_builds(directory, cases):
    """Builds one program at Rust's default macOS target and one at the release's, and checks both.

    Only a macOS host can build either, so anywhere else this says it did not run. rustc is run
    from the repository's root, so the toolchain the repository pins is the one that builds them.
    """
    if sys.platform != "darwin":
        print("not run  the two macOS builds: this is not a macOS host")
        return
    rustc = shutil.which("rustc")
    if rustc is None:
        print("not run  the two macOS builds: rustc is not on the search path")
        return
    target = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[platform.machine()]
    source = os.path.join(directory, "main.rs")
    with open(source, "w") as handle:
        handle.write("fn main() {}\n")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name, deployment, wanted in [
        ("a program built at Rust's default macOS target", None, False),
        ("a program built at macOS 14.0", "14.0", True),
    ]:
        environment = dict(os.environ)
        environment.pop("MACOSX_DEPLOYMENT_TARGET", None)
        if deployment is not None:
            environment["MACOSX_DEPLOYMENT_TARGET"] = deployment
        output = os.path.join(directory, "built-{}".format(deployment or "default"))
        subprocess.run(
            [rustc, "--edition", "2021", "--target", target, "-o", output, source],
            cwd=root,
            env=environment,
            check=True,
        )
        passed, sentence = check_file(target, output)
        expect(cases, name, passed, sentence, wanted)


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="check each executable against its baseline")
    checking.add_argument("--target", required=True, choices=sorted(TARGETS))
    checking.add_argument("executables", nargs="+")
    commands.add_parser("self-test", help="check this checker against binaries of known floors")
    options = parser.parse_args(arguments)
    if options.command == "self-test":
        return self_test()
    refused = 0
    for path in options.executables:
        passed, sentence = check_file(options.target, path)
        print("{:<8} {}".format("ok" if passed else "refused", sentence))
        refused += 0 if passed else 1
    print("{} executables, {} refused".format(len(options.executables), refused))
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
