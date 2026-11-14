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
import contextlib
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Libraries no program of the product imports: Visual C++'s runtime, its C++ library, OpenMP, the
# concurrency runtime, C++/CX and C++ AMP, MFC and its managed libraries (`mfcm140`), the universal
# runtime (the API sets and the library behind them, debug builds included), older and debug runtimes
# (`msvcr120`, `msvcrt`, `msvcp140d`), and libsodium's own library. The Windows component `msvcp_win`
# has the prefix of the C++ library and is refused with it: no program of the product imports it.
DENIED = re.compile(
    r"^(vcruntime|msvcp|vcomp|concrt|vccorlib|vcamp|mfcm?\d|ucrtbase|msvcr|api-ms-win-crt-|libsodium)", re.I
)
API_SET = re.compile(r"^(api|ext)-ms-win-", re.I)
# What an API set import looks like: the contract name and `.dll`, nothing else. The API set query is made
# for no other form.
API_SET_NAME = re.compile(r"(api|ext)-ms-win-[a-z0-9-]+\.dll", re.I)


def dependents(text):
    """The libraries `dumpbin /dependents` lists, as (imports, delay-load imports).

    Every entry of a list is a library, whatever its extension (`WINSPOOL.DRV` is one) and even with a
    space in its name: an entry that is not read would be an import that is not checked.
    """
    imports, delay, current = [], [], None
    for row in text.splitlines():
        if "Image has the following dependencies" in row:
            current = imports
        elif "Image has the following delay load dependencies" in row:
            current = delay
        elif re.match(r"^\s*Summary", row):
            current = None
        elif current is not None:
            found = re.match(r"^\s+(\S(?:.*\S)?)\s*$", row)
            if found:
                current.append(found.group(1))
    return imports, delay


def plain(name):
    """Whether an import is a file name alone: no path part, no drive and no dot segment."""
    return not any(mark in name for mark in "/\\:\0") and name not in (".", "..")


def api_set_present(name):
    """Whether this machine implements an API set contract, asked of the system's `IsApiSetImplemented`,
    which answers from the API set schema and loads nothing; None where it cannot be asked (not Windows).

    Only a plain API set name is asked about: the question takes the contract name without `.dll`."""
    if API_SET_NAME.fullmatch(name) is None:
        raise ValueError(f"{name!r} is no plain API set name, so the API set query is not made for it")
    if os.name != "nt":
        return None
    import ctypes

    try:
        query = ctypes.WinDLL("api-ms-win-core-apiquery-l2-1-0.dll").IsApiSetImplemented
    except (OSError, AttributeError):
        return None
    query.argtypes = [ctypes.c_char_p]
    query.restype = ctypes.c_int
    return bool(query(name[: -len(".dll")].encode("ascii")))


def classify(name, system_dir, api_present=api_set_present):
    """What a library is: DENIED, a Windows API set, a library of the system directory, NOT FOUND, a name
    that is NOT A PLAIN NAME or an API set that this machine cannot be asked about (NOT CHECKED).

    An import is a file name alone, so a name with a path part, a drive or a dot segment is refused, and
    so is an API set name of any other form than the contract name and `.dll`. An API set is a name the
    system resolves, so a name that this machine does not implement is NOT FOUND, however well it is
    spelled, and where the system cannot be asked the name is not accepted by its prefix."""
    if not plain(name):
        return "NOT A PLAIN NAME"
    if DENIED.match(name):
        return "DENIED"
    if API_SET.match(name):
        if API_SET_NAME.fullmatch(name) is None:
            return "NOT A PLAIN NAME"
        answer = api_present(name)
        return "NOT CHECKED" if answer is None else "a Windows API set" if answer else "NOT FOUND"
    if system_dir is not None and (system_dir / name).is_file():
        return "a Windows system library"
    return "NOT FOUND"


def read_imports(dumpbin, program, system_dir, api_present=api_set_present):
    """Each library the program imports with what it is, and the problems found; a read that cannot be made is a problem."""
    run = subprocess.run([dumpbin, "/nologo", "/dependents", str(program)], capture_output=True, text=True)
    if run.returncode != 0:
        return [], [f"dumpbin could not read {program}: exit {run.returncode}: {run.stderr.strip() or run.stdout.strip()}"]
    imports, delay = dependents(run.stdout)
    if not imports:
        return [], [f"dumpbin listed no library for {program}, so its imports cannot be read"]
    rows = [(name, classify(name, system_dir, api_present), "") for name in imports]
    rows += [(name, classify(name, system_dir, api_present), " (delay-load)") for name in delay]
    why = {
        "DENIED": "a runtime library, which no program of the product imports",
        "NOT FOUND": "a library that is no Windows API set and is not in the system directory",
        "NOT A PLAIN NAME": "a name with a path part, a drive or a dot segment, or an API set name of another form, which no import has and which the system is not asked about",
        "NOT CHECKED": "an API set that this machine cannot be asked about (it can be asked on Windows only), so it is not accepted",
    }
    problems = [f"{program} imports {name}{note}, {why[what]}" for name, what, note in rows if what in why]
    return rows, problems


def imports_command(dumpbin, programs, system_dir, api_present=api_set_present):
    problems = []
    for program in programs:
        path = Path(program)
        if not path.is_file():
            problems.append(f"{program} is not there, so its imports cannot be read")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"== {path.name}: {path.stat().st_size} bytes, sha256 {digest}")
        rows, found = read_imports(dumpbin, path, system_dir, api_present)
        for name, what, note in rows:
            print(f"   {name + note:<44} {what}")
        problems += found
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    print(f"No program of {len(programs)} imports a runtime library, and every import is a Windows API set or a library of the system directory.")
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
    the import read, and a link that asks for both runtimes prints LNK4098 where this read looks for it.
    The programs are linked by `rustc` with the lint levels it has by default, which the product's builds
    keep (no flag or setting of ours changes the level of the linker's messages).
    """
    failed = []
    # The system answers for an API set by name: a real contract must be implemented here and one that does not exist must not.
    for name, want in (("api-ms-win-core-synch-l1-2-0.dll", True), ("api-ms-win-core-nothing-of-the-kind-l1-1-0.dll", False)):
        got = api_set_present(name)
        print(f"control API set {name}: this machine implements it: {got}")
        if got is not want:
            failed.append(f"the API set control {name}: implemented: {got}, expected {want}")
    work = Path(tempfile.mkdtemp(prefix="read-windows-imports-"))
    source = work / "hello.rs"
    source.write_text(HELLO)
    cases = [
        ("static", ["-C", "target-feature=+crt-static"], False, False),
        ("dynamic", ["-C", "target-feature=-crt-static"], True, False),
        ("both", ["-C", "target-feature=-crt-static", "-C", "link-arg=/DEFAULTLIB:libcmt"], True, True),
    ]
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
    odd = CLEAN.replace("    bcrypt.dll\n", "    bcrypt.dll\n    WINSPOOL.DRV\n    my library.dll\n")
    check("an entry that is no .dll is read", dependents(odd)[0][-3:-1], ["WINSPOOL.DRV", "my library.dll"])
    check("it is classified by the same rule", [classify(n, None) for n in ("WINSPOOL.DRV", "VCCORLIB140.dll", "mfc140u.dll", "VCAMP140.dll")], ["NOT FOUND", "DENIED", "DENIED", "DENIED"])
    check("a Media Foundation library is no MFC", classify("mfcore.dll", None), "NOT FOUND")
    check("it is not an ordinary import", "MSVCP140.dll" in dependents(DELAY)[0], False)
    check("a text with no list has no import", dependents("Dump of file x.exe\n"), ([], []))

    with tempfile.TemporaryDirectory() as directory:
        system = Path(directory)
        for name in ("KERNEL32.dll", "WS2_32.dll", "ADVAPI32.dll", "ntdll.dll", "bcryptprimitives.dll", "USERENV.dll", "CRYPT32.dll", "bcrypt.dll"):
            (system / name).write_text("")
        implemented = lambda n: True  # the self-test holds the classification, not the machine it runs on
        classes = [classify(n, system, implemented) for n in clean]
        check("no import of the clean program is refused or lost", classes.count("DENIED") + classes.count("NOT FOUND"), 0)
        check("a library of the system directory is named so", classify("KERNEL32.dll", system), "a Windows system library")
        check("an API set is named so", classify("api-ms-win-core-synch-l1-2-0.dll", system, implemented), "a Windows API set")
        check("an extension API set is named so", classify("ext-ms-win-gdi-desktop-l1-1-0.dll", system, implemented), "a Windows API set")
        check("a library that is nowhere is not found", classify("nowhere.dll", system), "NOT FOUND")
        check("with no system directory a plain library is not found", classify("kernel32.dll", None), "NOT FOUND")
        # The loader answers for a plain API set name alone: a plain name it knows, one it does not know, and
        # where it cannot be asked (a machine that is not Windows) the name is not accepted by its prefix.
        for answer, want in ((False, "NOT FOUND"), (True, "a Windows API set"), (None, "NOT CHECKED")):
            check(f"an API set that the loader answers {answer} for", classify("api-ms-win-core-x-l1-1-0.dll", None, lambda n, a=answer: a), want)
        check("a denied name is refused before the loader is asked", classify("api-ms-win-crt-heap-l1-1-0.dll", None, lambda n: True), "DENIED")
        asked = []

        def listening(name):
            asked.append(name)
            return True

        for name in (
            "api-ms-win-x/../helper.dll", "api-ms-win-core-x-l1-1-0.dll\\..\\helper.dll", "ext-ms-win-x/y.dll", "api-ms-win-core-x-l1-1-0.dll.exe",
            "api-ms-win-core_x-l1-1-0.dll", "api-ms-win-core-x-l1-1-0", "ext-ms-win-c:x.dll", "api-ms-win-.dll", "api-ms-win-core-x-l1-1-0.dll\n",
            "C:\\Windows\\System32\\kernel32.dll", "C:kernel32.dll", "..\\kernel32.dll", "sub/kernel32.dll", "..", ".",
        ):
            check(f"the name {name!r} is refused as no plain name", classify(name, system, listening), "NOT A PLAIN NAME")
        check("no such name is asked of the loader", asked, [])
        check("an API set name in capitals is a plain name", classify("API-MS-WIN-CORE-X-L1-1-0.DLL", None, listening), "a Windows API set")
        check("and the loader is asked for it", asked, ["API-MS-WIN-CORE-X-L1-1-0.DLL"])
        try:
            api_set_present("api-ms-win-x/../helper.dll")
            check("the loader's question refuses a name that is not plain", "answered", "ValueError")
        except ValueError:
            pass
        if os.name != "nt":
            check("where the loader cannot be asked the answer is None", api_set_present("api-ms-win-core-synch-l1-2-0.dll"), None)

        # The whole read, with `dumpbin` answering from a record: a program that lists an API set that the
        # loader cannot be asked about, or a name with a path part, is refused with an error that says so.
        program = system / "program.exe"
        program.write_bytes(b"MZ")
        records = {
            "no loader": (CLEAN, lambda n: None, 1, ["cannot be asked about"]),
            "a loader that knows them": (CLEAN, lambda n: True, 0, []),
            "a loader that does not": (CLEAN, lambda n: False, 1, ["api-ms-win-core-synch-l1-2-0.dll, a library that is no Windows API set"]),
            "a name with a path part": (CLEAN.replace("    ntdll.dll\n", "    ntdll.dll\n    api-ms-win-x/../helper.dll\n"), lambda n: True, 1, ["api-ms-win-x/../helper.dll"]),
        }
        for label, (record, loader, want_exit, want_in) in records.items():
            answer = subprocess.CompletedProcess([], 0, stdout=record, stderr="")
            out = io.StringIO()
            with unittest.mock.patch.object(subprocess, "run", return_value=answer), contextlib.redirect_stdout(out):
                code = imports_command("dumpbin", [str(program)], system, loader)
            check(f"the read of a program with {label} ends with {want_exit}", code, want_exit)
            errors = [row for row in out.getvalue().splitlines() if row.startswith("::error::")]
            check(f"it names the cause with {label}", all(any(text in row for row in errors) for text in want_in), True)
            check(f"it reports an error only when it refuses with {label}", bool(errors), want_exit == 1)

    for name in (
        "VCRUNTIME140.dll", "vcruntime140_1.dll", "VCRUNTIME140D.dll", "MSVCP140.dll", "msvcp140d.dll", "VCOMP140.DLL",
        "CONCRT140.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "API-MS-WIN-CRT-STDIO-L1-1-0.dll", "ucrtbase.dll", "UCRTBASED.dll",
        "MSVCR120.dll", "msvcr100d.dll", "MSVCRT.dll", "libsodium.dll", "libsodium-26.dll",
        "mfc140.dll", "MFC140U.dll", "mfcm140.dll", "MFCM140U.dll", "mfcm100d.dll",
    ):
        check(f"{name} is on the deny list", classify(name, None), "DENIED")
    for name in ("api-ms-win-core-file-l1-2-0.dll", "KERNEL32.dll", "oleaut32.dll", "mscoree.dll", "bcryptprimitives.dll", "mfcore.dll", "mfcmapi.dll"):
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
        # The refusals print workflow annotations, which a green self-test must not leave in a run's log.
        with contextlib.redirect_stdout(io.StringIO()):
            answers = [
                messages_command([str(quiet)]),
                messages_command([str(quiet), str(loud)]),
                messages_command([str(empty)]),
                messages_command([str(Path(directory) / "none.log")]),
            ]
        check("a log with no LNK4098 passes", answers[0], 0)
        check("a log with LNK4098 is refused", answers[1], 1)
        check("an empty log cannot be read", answers[2], 2)
        check("a log that is not there cannot be read", answers[3], 2)

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
    # A path that a shell captures must not end in a carriage return.
    sys.stdout.reconfigure(newline="\n")
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
