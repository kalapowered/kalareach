#!/usr/bin/env python3
"""Reads what Windows programs import and what their links said, for programs that carry their C runtime.

Every Windows MSVC program of the product links the static C runtime, so none of them imports a runtime
library: not Visual C++'s, not the universal runtime's, not an older or a debug one, and not libsodium's
own. This reads each program's imports with Microsoft's `dumpbin`, refuses the ones on that list, and
checks that every other import is a Windows API set or a library in the system directory of the machine.
A program that cannot be read fails the read; none is skipped.

    read-windows-imports.py find-dumpbin --arch x64|arm64   print the `dumpbin` that runs on this machine
    read-windows-imports.py imports --dumpbin PATH FILE...  read each program's imports
    read-windows-imports.py messages LOG...                 refuse a link that reported LNK4098
    read-windows-imports.py control --dumpbin PATH          show that both reads fail when their fault is present
    read-windows-imports.py self-test                       run the reads on recorded `dumpbin` output
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Libraries no program of the product imports: Visual C++'s runtime, its C++ library, OpenMP, the
# concurrency runtime, the universal runtime (the API sets and the library behind them, debug builds
# included), older and debug runtimes (`msvcr120`, `msvcrt`, `msvcp140d`), and libsodium's own library.
DENIED = re.compile(r"^(vcruntime|msvcp|vcomp|concrt|ucrtbase|msvcr|api-ms-win-crt-|libsodium)", re.I)
API_SET = re.compile(r"^(api|ext)-ms-win-", re.I)


def dependents(text):
    """The libraries `dumpbin /dependents` lists, as (imports, delay-load imports)."""
    imports, delay, current = [], [], None
    for row in text.splitlines():
        if "Image has the following dependencies" in row:
            current = imports
        elif "Image has the following delay load dependencies" in row:
            current = delay
        elif re.match(r"^\s*Summary", row):
            current = None
        elif current is not None:
            found = re.match(r"^\s+(\S+\.dll)\s*$", row, re.I)
            if found:
                current.append(found.group(1))
    return imports, delay


def classify(name, system_dir):
    """What a library is: DENIED, a Windows API set, a library of the system directory, or NOT FOUND."""
    if DENIED.match(name):
        return "DENIED"
    if API_SET.match(name):
        return "a Windows API set"
    if system_dir is not None and (system_dir / name).is_file():
        return "a Windows system library"
    return "NOT FOUND"


def read_imports(dumpbin, program, system_dir):
    """Each library the program imports with what it is, and the problems found; a read that cannot be made is a problem."""
    run = subprocess.run([dumpbin, "/nologo", "/dependents", str(program)], capture_output=True, text=True)
    if run.returncode != 0:
        return [], [f"dumpbin could not read {program}: exit {run.returncode}: {run.stderr.strip() or run.stdout.strip()}"]
    imports, delay = dependents(run.stdout)
    if not imports:
        return [], [f"dumpbin listed no library for {program}, so its imports cannot be read"]
    rows = [(name, classify(name, system_dir), "") for name in imports]
    rows += [(name, classify(name, system_dir), " (delay-load)") for name in delay]
    why = {
        "DENIED": "a runtime library, which no program of the product imports",
        "NOT FOUND": "a library that is no Windows API set and is not in the system directory",
    }
    problems = [f"{program} imports {name}{note}, {why[what]}" for name, what, note in rows if what in why]
    return rows, problems


def imports_command(dumpbin, programs, system_dir):
    problems = []
    for program in programs:
        path = Path(program)
        if not path.is_file():
            problems.append(f"{program} is not there, so its imports cannot be read")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"== {path.name}: {path.stat().st_size} bytes, sha256 {digest}")
        rows, found = read_imports(dumpbin, path, system_dir)
        for name, what, note in rows:
            print(f"   {name + note:<44} {what}")
        problems += found
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    print(f"No program of {len(programs)} imports a runtime library, and every import is a Windows library.")
    return 0


def reports_lnk4098(text):
    """Whether a link's output holds the linker's report of objects that ask for two C runtimes."""
    return "LNK4098" in text


def messages_command(logs):
    """Exit 1 when a link reported LNK4098, 2 when a log cannot be read, 0 when none did."""
    for log in logs:
        path = Path(log)
        if not path.is_file() or path.stat().st_size == 0:
            print(f"::error::The log {log} is not there or is empty, so its link cannot be read.")
            return 2
    reported = [
        f"{log}:{number}: {row.strip()}"
        for log in logs
        for number, row in enumerate(Path(log).read_text(errors="replace").splitlines(), 1)
        if reports_lnk4098(row)
    ]
    if reported:
        print("\n".join(reported))
        print("::error::A link reported LNK4098: objects asking for two different C runtimes.")
        return 1
    print("No link reported LNK4098.")
    return 0


def pick_dumpbin(candidates, arch):
    """The newest `dumpbin` of the host that has the architecture of the machine: Hostx64/x64 or Hostarm64/arm64."""
    wanted = f"/bin/host{arch}/{arch}/dumpbin.exe"
    chosen = [c for c in candidates if c.replace("\\", "/").lower().endswith(wanted)]

    def version(path):
        found = re.search(r"/MSVC/([0-9.]+)/", path.replace("\\", "/"))
        return tuple(int(part) for part in found.group(1).split(".")) if found else ()

    return max(chosen, key=version) if chosen else None


def find_dumpbin_command(arch):
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    run = subprocess.run([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"], capture_output=True, text=True)
    install = run.stdout.strip().splitlines()[0] if run.returncode == 0 and run.stdout.strip() else ""
    if not install:
        print("::error::vswhere found no Visual Studio install, so dumpbin cannot be found.", file=sys.stderr)
        return 1
    found = pick_dumpbin([str(p) for p in Path(install, "VC/Tools/MSVC").glob("*/bin/Host*/*/dumpbin.exe")], arch)
    if found is None:
        print(f"::error::No Host{arch}/{arch} dumpbin.exe under {install}, so the imports cannot be read.", file=sys.stderr)
        return 1
    print(found)
    return 0


HELLO = 'fn main() { println!("{}", std::env::args().count()); }\n'


def control_command(dumpbin, system_dir):
    """Links three small programs and checks that each read answers as it must.

    A read that finds nothing is worth something only when it is shown to find the fault: the program
    that carries its runtime passes both reads, the one that imports the dynamic runtime is refused by
    the import read, and a link that asks for both runtimes prints LNK4098 through the same build path
    that the product's builds print their messages by.
    """
    work = Path(tempfile.mkdtemp(prefix="read-windows-imports-"))
    source = work / "hello.rs"
    source.write_text(HELLO)
    cases = [
        ("static", ["-C", "target-feature=+crt-static"], False, False),
        ("dynamic", ["-C", "target-feature=-crt-static"], True, False),
        ("both", ["-C", "target-feature=-crt-static", "-C", "link-arg=/DEFAULTLIB:libcmt"], True, True),
    ]
    failed = []
    for name, flags, imports_runtime, says_lnk4098 in cases:
        program, log = work / f"{name}.exe", work / f"{name}.log"
        build = subprocess.run(
            ["rustc", "--edition", "2021", "-o", str(program), *flags, str(source)],
            cwd=ROOT, capture_output=True, text=True,
        )
        log.write_text(build.stdout + build.stderr)
        if build.returncode != 0 or not program.is_file():
            failed.append(f"the {name} control did not link: {build.stderr.strip()[-400:]}")
            continue
        _, problems = read_imports(dumpbin, program, system_dir)
        refused = bool(problems)
        said = reports_lnk4098(log.read_text(errors="replace"))
        print(f"control {name}: the import read refuses it: {refused}; the link said LNK4098: {said}")
        if refused != imports_runtime:
            failed.append(f"the {name} control: the import read refused it: {refused}, expected {imports_runtime}")
        if said != says_lnk4098:
            failed.append(f"the {name} control: the link said LNK4098: {said}, expected {says_lnk4098}")
    for why in failed:
        print(f"::error::{why}")
    return 1 if failed else 0


# What `dumpbin /dependents` prints, from the imports of the host's `kr` and of a program that links the
# dynamic runtime, so that the reads are held to the form the tool gives.
CLEAN = """Microsoft (R) COFF/PE Dumper Version 14.51.36231.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file kr.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    KERNEL32.dll
    api-ms-win-core-synch-l1-2-0.dll
    WS2_32.dll
    ADVAPI32.dll
    ntdll.dll
    bcryptprimitives.dll
    USERENV.dll
    CRYPT32.dll
    bcrypt.dll
    api-ms-win-core-realtime-l1-1-1.dll

  Summary

        1000 .data
       12000 .rdata
"""
DYNAMIC = CLEAN.replace("    ntdll.dll\n", "    ntdll.dll\n    VCRUNTIME140.dll\n    api-ms-win-crt-runtime-l1-1-0.dll\n    api-ms-win-crt-heap-l1-1-0.dll\n")
DELAY = CLEAN.replace("  Summary", "  Image has the following delay load dependencies:\n\n    MSVCP140.dll\n\n  Summary")


def self_test():
    failures = []

    def check(what, got, want):
        if got != want:
            failures.append(f"{what}: got {got!r}, expected {want!r}")

    clean, delay = dependents(CLEAN)
    check("the clean program lists ten imports", len(clean), 10)
    check("it has no delay-load import", delay, [])
    check("the first and last import are read", (clean[0], clean[-1]), ("KERNEL32.dll", "api-ms-win-core-realtime-l1-1-1.dll"))
    check("the summary's lines are no import", any(".data" in name for name in clean), False)
    check("a delay-load import is read as one", dependents(DELAY)[1], ["MSVCP140.dll"])
    check("it is not an ordinary import", "MSVCP140.dll" in dependents(DELAY)[0], False)
    check("a text with no list has no import", dependents("Dump of file x.exe\n"), ([], []))

    with tempfile.TemporaryDirectory() as directory:
        system = Path(directory)
        for name in ("KERNEL32.dll", "WS2_32.dll", "ADVAPI32.dll", "ntdll.dll", "bcryptprimitives.dll", "USERENV.dll", "CRYPT32.dll", "bcrypt.dll"):
            (system / name).write_text("")
        check("no import of the clean program is refused or lost", [classify(n, system) for n in clean].count("DENIED") + [classify(n, system) for n in clean].count("NOT FOUND"), 0)
        check("a library of the system directory is named so", classify("KERNEL32.dll", system), "a Windows system library")
        check("an API set is named so", classify("api-ms-win-core-synch-l1-2-0.dll", system), "a Windows API set")
        check("an extension API set is named so", classify("ext-ms-win-gdi-desktop-l1-1-0.dll", system), "a Windows API set")
        check("a library that is nowhere is not found", classify("nowhere.dll", system), "NOT FOUND")
        check("with no system directory a plain library is not found", classify("kernel32.dll", None), "NOT FOUND")

    for name in (
        "VCRUNTIME140.dll", "vcruntime140_1.dll", "VCRUNTIME140D.dll", "MSVCP140.dll", "msvcp140d.dll", "VCOMP140.DLL",
        "CONCRT140.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "API-MS-WIN-CRT-STDIO-L1-1-0.dll", "ucrtbase.dll", "UCRTBASED.dll",
        "MSVCR120.dll", "msvcr100d.dll", "MSVCRT.dll", "libsodium.dll", "libsodium-26.dll",
    ):
        check(f"{name} is on the deny list", classify(name, None), "DENIED")
    for name in ("api-ms-win-core-file-l1-2-0.dll", "KERNEL32.dll", "oleaut32.dll", "mscoree.dll", "bcryptprimitives.dll"):
        check(f"{name} is not on the deny list", classify(name, None) == "DENIED", False)

    check("the program that imports the dynamic runtime has three more libraries", len(dependents(DYNAMIC)[0]), 13)
    check("its denied imports are three", [n for n in dependents(DYNAMIC)[0] if DENIED.match(n)], ["VCRUNTIME140.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll"])

    # The newest dumpbin of the machine's own architecture, and none of the other's.
    paths = [
        r"C:\VS\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe",
        r"C:\VS\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\dumpbin.exe",
        r"C:\VS\VC\Tools\MSVC\14.51.36231\bin\Hostarm64\arm64\dumpbin.exe",
        r"C:\VS\VC\Tools\MSVC\14.51.36231\bin\Hostx64\arm64\dumpbin.exe",
        r"C:\VS\VC\Tools\MSVC\14.9.1\bin\Hostx64\x64\dumpbin.exe",
    ]
    check("the x64 dumpbin is the newest one by version", pick_dumpbin(paths, "x64"), paths[1])
    check("the ARM64 dumpbin is the native one", pick_dumpbin(paths, "arm64"), paths[2])
    check("no dumpbin of an architecture that has none", pick_dumpbin(paths[:2], "arm64"), None)

    with tempfile.TemporaryDirectory() as directory:
        quiet, loud, empty = (Path(directory) / n for n in ("quiet.log", "loud.log", "empty.log"))
        quiet.write_text("warning: unused variable\nLINK : warning LNK4099: PDB not found\n")
        loud.write_text("LINK : warning LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs\n")
        empty.write_text("")
        check("a log with no LNK4098 passes", messages_command([str(quiet)]), 0)
        check("a log with LNK4098 is refused", messages_command([str(quiet), str(loud)]), 1)
        check("an empty log cannot be read", messages_command([str(empty)]), 2)
        check("a log that is not there cannot be read", messages_command([str(Path(directory) / "none.log")]), 2)

    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("The reads of imports and of linker messages hold what they must on recorded output.")
    return 0


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    find = commands.add_parser("find-dumpbin")
    find.add_argument("--arch", choices=("x64", "arm64"), required=True)
    for name in ("imports", "control"):
        command = commands.add_parser(name)
        command.add_argument("--dumpbin", required=True)
        command.add_argument("--system-dir", default=os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))
        if name == "imports":
            command.add_argument("programs", nargs="+")
    commands.add_parser("messages").add_argument("logs", nargs="+")
    commands.add_parser("self-test")
    chosen = parser.parse_args(arguments)
    if chosen.command == "find-dumpbin":
        return find_dumpbin_command(chosen.arch)
    if chosen.command == "imports":
        return imports_command(chosen.dumpbin, chosen.programs, Path(chosen.system_dir))
    if chosen.command == "control":
        return control_command(chosen.dumpbin, Path(chosen.system_dir))
    if chosen.command == "messages":
        return messages_command(chosen.logs)
    return self_test()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
