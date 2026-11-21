#!/usr/bin/env python3
"""Holds the macOS test legs of the landing workflow to the workspace.

The `macos` job of `.github/workflows/core-ci.yml` runs the workspace's tests in two legs, each on a
runner of its own, and each leg's matrix entry names the packages it tests in a `packages` value of
`-p <package>` words. Every test the workspace has must run in exactly one leg, once: this reads the
two lists from the workflow, asks Cargo for the workspace's members, and fails when

  * a member is in neither list, so its tests would run in no leg,
  * a member is in both lists, or twice in one, so its tests would run twice,
  * a list names a package that is not a member of the workspace, or the one package the landing
    workflow leaves out of the macOS run (`kr-sync-integration`, every test of which is a leg
    against a live deployment, which the rust job runs),
  * a list has a word that is not `-p` or a package, or names no package (`cargo test` with no
    package selects every member of the workspace),
  * the matrix has a test leg twice, has none, or has a test part besides the two (the Test step
    runs every part that begins with `tests`, so an extra one would run packages again).

A new crate therefore has to be put in one of the lists before the job passes.

The legs also build with the features of their own packages' dependency graph, and the one step
that ran the whole workspace built with the features all 47 packages asked for together. The
`features` command compares the two with `cargo tree` and fails on a package whose features differ
and that is not named, with its reason, in `FEATURE_DIFFERENCES` below.

    python3 scripts/check-macos-test-division.py check [--locked]
    python3 scripts/check-macos-test-division.py features
    python3 scripts/check-macos-test-division.py self-test

`self-test` puts the check through a workflow and a workspace that are written out here: the
division that holds, a member left out, a member in both lists, a member twice in one list, a name
that is no member, the left-out package named, a word that is no package, a leg that is missing, a
leg twice, an extra test leg, an empty list, and the comparison of features. Each fault must be
refused and named, and the division that holds must pass.
"""

import argparse
import json
import os
import re
import subprocess
import sys

WORKFLOW = os.path.join(".github", "workflows", "core-ci.yml")
JOB = "macos"
LEGS = ["tests-1", "tests-2"]
LEFT_OUT = "kr-sync-integration"


def job_text(workflow):
    """The lines of the `macos` job: from its key to the next key at the same indentation."""
    lines = workflow.splitlines()
    try:
        start = lines.index(f"  {JOB}:")
    except ValueError:
        raise SystemExit(f"the workflow has no {JOB} job")
    end = len(lines)
    for at in range(start + 1, len(lines)):
        line = lines[at]
        if re.match(r"  [A-Za-z0-9_-]+:\s*$", line):
            end = at
            break
    return lines[start:end]


def decode(value):
    """The name a matrix value gives, as GitHub reads it: a plain or a quoted scalar, a comment after
    it left off, in lower case because GitHub compares and matches `startsWith` without regard to
    case. `None` for any other form, an expression among them."""
    value = re.sub(r"\s+#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value.lower() if re.fullmatch(r"[A-Za-z0-9_-]+", value) else None


def unreadable(workflow):
    """The lines of the job that name a part or open an entry in a form this does not read: an
    entry written as a flow mapping or a flow sequence, and a part that is not a name."""
    odd = []
    for line in job_text(workflow):
        text = line.strip()
        if text.startswith("#"):
            continue
        if re.match(r"-\s+[{\[]", text):
            odd.append(text)
        elif re.search(r"\bpart:", text):
            matched = re.match(r"(?:-\s+)?part:\s*(.*)$", text)
            if not matched or decode(matched.group(1)) is None:
                odd.append(text)
    return odd


def entries(workflow):
    """The matrix entries of the job, in order, as (part, words of its `packages` value or None)."""
    lines = job_text(workflow)
    found = []
    at = 0
    while at < len(lines):
        line = lines[at]
        at += 1
        if line.lstrip().startswith("#"):
            continue
        matched = re.match(r"\s+(?:-\s+)?part:\s*(.*)$", line)
        if matched:
            found.append([decode(matched.group(1)) or "", None])
            continue
        matched = re.match(r"(\s+)(?:-\s+)?packages:\s*(>-|>|\|-|\||)\s*(.*)$", line)
        if not matched or not found:
            continue
        indent = len(matched.group(1))
        words = matched.group(3).split()
        while at < len(lines) and (
            not lines[at].strip() or len(lines[at]) - len(lines[at].lstrip()) > indent
        ):
            words.extend(lines[at].split())
            at += 1
        found[-1][1] = words
    return [(part, words) for part, words in found]


def lists(workflow):
    """The words of the `packages` value of each test leg named in LEGS, by `part`."""
    return {part: words for part, words in entries(workflow) if part in LEGS and words is not None}


def packages_of(words):
    """The package names in a list of `-p <package>` words, and the words that are neither."""
    names = []
    odd = []
    at = 0
    while at < len(words):
        if words[at] == "-p" and at + 1 < len(words):
            names.append(words[at + 1])
            at += 2
        else:
            odd.append(words[at])
            at += 1
    return names, odd


def problems(workflow, members):
    """What is wrong with the division of `members` in `workflow`, one sentence for each fault."""
    faults = [
        f"the matrix has a line in a form the check does not read: {text}"
        for text in unreadable(workflow)
    ]
    parts = [part for part, _ in entries(workflow)]
    for part in sorted(
        {part for part in parts if part.lower().startswith("tests") and part not in LEGS}
    ):
        faults.append(f"the matrix has a test leg {part}, which the check does not hold to the workspace")
    for leg in LEGS:
        if parts.count(leg) == 0:
            faults.append(f"the {JOB} job's matrix has no {leg} leg")
        elif parts.count(leg) > 1:
            faults.append(f"the {JOB} job's matrix has the {leg} leg {parts.count(leg)} times")
    found = lists(workflow)
    for leg in LEGS:
        if parts.count(leg) == 1 and leg not in found:
            faults.append(f"{leg} has no packages list")
    if faults:
        return faults
    named = {}
    for leg in LEGS:
        names, odd = packages_of(found[leg])
        if not names:
            faults.append(f"{leg} names no package, and `cargo test` with none selects every member")
        for word in odd:
            faults.append(f"{leg}: `{word}` is not `-p` or the name of a package after it")
        for name in sorted({name for name in names if names.count(name) > 1}):
            faults.append(f"{leg}: {name} is named more than once")
        named[leg] = set(names)
    for name in sorted(named[LEGS[0]] & named[LEGS[1]]):
        faults.append(f"{name} is in both legs, so its tests run twice")
    wanted = set(members) - {LEFT_OUT}
    for name in sorted(wanted - named[LEGS[0]] - named[LEGS[1]]):
        faults.append(f"{name} is in no leg, so its tests run nowhere")
    for leg in LEGS:
        for name in sorted(named[leg] - set(members)):
            faults.append(f"{leg}: {name} is not a package of the workspace")
        if LEFT_OUT in named[leg]:
            faults.append(f"{leg}: {LEFT_OUT} is named, and the macOS run leaves it out")
    return faults


def workspace_members(locked):
    """The names of the workspace's member packages, from Cargo."""
    command = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
    if locked:
        command.append("--locked")
    answer = subprocess.run(command, capture_output=True, text=True, check=False)
    if answer.returncode != 0:
        sys.stderr.write(answer.stderr)
        raise SystemExit("cargo metadata failed")
    metadata = json.loads(answer.stdout)
    member_ids = set(metadata["workspace_members"])
    return sorted(
        package["name"] for package in metadata["packages"] if package["id"] in member_ids
    )


def check(locked):
    with open(WORKFLOW, encoding="utf-8") as file:
        workflow = file.read()
    members = workspace_members(locked)
    faults = problems(workflow, members)
    if faults:
        for fault in faults:
            print(f"check-macos-test-division: {fault}", file=sys.stderr)
        return 1
    found = lists(workflow)
    counts = [len(packages_of(found[leg])[0]) for leg in LEGS]
    print(
        f"the {LEGS[0]} leg has {counts[0]} packages and the {LEGS[1]} leg {counts[1]}: "
        f"the workspace's {len(members)} members less {LEFT_OUT}, each in one leg"
    )
    return 0


# What a leg's build has less of than the one step that ran the whole workspace: each feature, keyed
# by package, leg, direction (`less`, which is all there is today) and feature, with the reason that
# it does not change what a case does. A leg builds with the features of its own packages'
# dependency graph, so a feature that only the other leg's packages ask for is left out of it, as it
# is of the product's own programs. The reasons say what was read: a feature that only adds items
# cannot change a case of a package that does not name them, and the ones that can change behaviour
# without changing an item are named one by one, with the part of the leg that answers for them.
# A difference with no entry here fails `features`; an entry that no longer differs is noted.
OTHER = (
    'asked for only by packages of the other leg; a leg package that used an item it gates would not compile, so for a feature that only adds items nothing changes; an effect on behaviour that leaves the interface alone was not traced'
)
MERGED = (
    "the difference is in the merged view only: the target-only view shows none, so the leg's target copy has the features the whole workspace's has, and the difference is in a host copy (a build script's or a procedural macro's dependency) or in a copy that this leg does not build; not traced further"
)
OBJC2_ITEMS = (
    'adds standard-library support or Objective-C exception catching to items that only a caller naming objc2 uses, and no package of tests-1 names objc2 in its manifest'
)
OBJECT_FORMATS = (
    "readers and writers for other object file formats; the only reader in tests-1 (kr-project's boundary/macho.rs) gives every file that is not Mach-O, and every parse error, the same answer with or without them"
)
SERDE_CORE = (
    "in the target-only view only: tests-2's target copy of serde_core lacks `default` (standard-library support the whole workspace turns on through a tests-1 package); the host copy has it, and nothing in tests-2 asks for an item that it gates"
)

FEATURE_ROWS = [
    ('tests-1', 'bindgen', 'default logging prettyplease',
     MERGED),
    ('tests-1', 'bit-set', 'default',
     MERGED),
    ('tests-1', 'bitflags', 'serde serde_core',
     OTHER),
    ('tests-1', 'block2', 'default std',
     OTHER),
    ('tests-1', 'bumpalo', 'allocator-api2',
     MERGED),
    ('tests-1', 'dispatch2', 'block2 default libc std',
     OTHER),
    ('tests-1', 'foldhash', 'default std',
     'decides how the hasher takes its seed; the order of a hash map is unspecified either way'),
    ('tests-1', 'hashbrown', 'serde',
     OTHER),
    ('tests-1', 'icu_properties', 'default',
     OTHER),
    ('tests-1', 'kr-plugin-sdk', 'testing',
     "turned on by kr-plugin-sdk's own tests, which are tests-2's; it adds one item in validate.rs that only those tests call"),
    ('tests-1', 'kr-shell-integration', 'testing',
     "asked for by kr-cli's tests only, which are tests-2's; it adds seams in the terminal profile code that act only where a case sets them"),
    ('tests-1', 'num-rational', 'num-bigint-std',
     OTHER),
    ('tests-1', 'objc2', 'default exception',
     OBJC2_ITEMS),
    ('tests-1', 'objc2', 'disable-encoding-assertions',
     "without it objc2 keeps its run-time check of a message's encoding, which can only panic in a `msg_send` call, and no package of tests-1 names objc2 in its manifest"),
    ('tests-1', 'objc2-core-foundation', 'CFBase',
     OTHER),
    ('tests-1', 'object', 'coff elf pe write write_core write_std xcoff',
     OBJECT_FORMATS),
    ('tests-1', 'proc-macro2', 'span-locations',
     "gives a macro's spans line and column numbers, which only a macro's diagnostics read, and no tests-1 case prints one"),
    ('tests-1', 'regex', 'default perf perf-backtrack perf-cache perf-dfa perf-inline perf-literal perf-onepass unicode unicode-age unicode-bool unicode-case unicode-gencat unicode-script unicode-segment',
     MERGED),
    ('tests-1', 'regex-syntax', 'default',
     OTHER),
    ('tests-1', 'rgb', 'argb as-bytes bytemuck default grb',
     OTHER),
    ('tests-1', 'rmcp', 'client transport-child-process',
     OTHER),
    ('tests-1', 'rustix', 'pipe stdio',
     OTHER),
    ('tests-1', 'serde_json', 'float_roundtrip',
     'only jsonschema asks for it, and only kr-codex-stand-in, a tests-2 package, pulls that in; without it tests-1 parses floats with the faster parser, which can differ from the exact one in the last place for some long inputs, and tests-1 parses only short decimals (0.0 and 2.5 in session_export.rs, two-decimal elapsed times in the Go report), which both read exactly'),
    ('tests-1', 'serde_json', 'unbounded_depth',
     'only cargo_metadata asks for it, through tauri-utils, a tests-2 dependency; it adds a method that lifts the depth limit where a caller calls it, no tests-1 code calls it, and the default limit of 128 holds either way'),
    ('tests-1', 'simdutf8', 'public_imp',
     OTHER),
    ('tests-1', 'smallvec', 'serde',
     'adds serialisation items that only a caller naming them uses, and no tests-1 case names them'),
    ('tests-1', 'smallvec', 'union',
     'changes how a small vector is laid out in memory, and no tests-1 case asserts the size of a type'),
    ('tests-1', 'stable_deref_trait', 'alloc default std',
     MERGED),
    ('tests-1', 'ureq', '_ring _rustls _tls rustls rustls-no-provider rustls-webpki-roots',
     MERGED),
    ('tests-1', 'uuid', 'serde',
     OTHER),
    ('tests-1', 'zlib-rs', 'std',
     MERGED),
    ('tests-2', 'chrono', 'clock iana-time-zone winapi windows-link',
     OTHER),
    ('tests-2', 'displaydoc', 'default std',
     MERGED),
    ('tests-2', 'form_urlencoded', 'default',
     OTHER),
    ('tests-2', 'hyper-util', 'server service',
     OTHER),
    ('tests-2', 'iroh', 'test-utils',
     OTHER),
    ('tests-2', 'iroh-metrics', 'service',
     OTHER),
    ('tests-2', 'iroh-relay', 'server test-utils',
     OTHER),
    ('tests-2', 'kr-changeset', 'fault-injection',
     "turned on by kr-changeset's own tests and kr-controller's, which are tests-1's; its hooks act only where a case arms them"),
    ('tests-2', 'kr-client', 'default',
     'tests-1 selects kr-client as a package, which gives it its default features; tests-2 selects other packages, and nothing there asks for `default`; the only feature `default` holds is `terminal`, which tests-2 still has, so nothing changes'),
    ('tests-2', 'kr-crypto', 'testing',
     "asked for by kr-controller's tests only, which are tests-1's; it adds a stand-in for the key store that acts only where a case installs it"),
    ('tests-2', 'kr-protocol', 'testing',
     "asked for by kr-controller's and kr-ipc's tests only, which are tests-1's; it adds two items in retained.rs that only those tests call"),
    ('tests-2', 'kr-transfer', 'testing',
     "turned on by kr-transfer's own tests, which are tests-1's; it adds seams that act only where a case sets them"),
    ('tests-2', 'nom', 'default',
     OTHER),
    ('tests-2', 'noq', 'platform-verifier',
     OTHER),
    ('tests-2', 'noq-proto', 'platform-verifier',
     OTHER),
    ('tests-2', 'rcgen', 'x509-parser',
     OTHER),
    ('tests-2', 'reqwest', 'json',
     OTHER),
    ('tests-2', 'ring', 'std',
     OTHER),
    ('tests-2', 'serde_core', 'default',
     SERDE_CORE),
    ('tests-2', 'simdutf8', 'default',
     OTHER),
    ('tests-2', 'tower', 'log',
     'emits log events, which show only where a case installs a subscriber; not traced for such a case'),
    ('tests-2', 'tower', 'make',
     OTHER),
    ('tests-2', 'tower', 'tracing',
     'emits tracing events, which show only where a case installs a subscriber; not traced for such a case'),
]
FEATURE_DIFFERENCES = {
    (package, leg, "less", feature): reason
    for leg, package, names, reason in FEATURE_ROWS
    for feature in names.split()
}

TARGET = "aarch64-apple-darwin"
# The two views of the graph, each as `cargo tree` takes its edges. The first merges the host and the
# target copies of a package, as the whole workspace's one step built them; the second is the target
# build alone, so that a merge cannot hide a difference of the copy a case runs against.
VIEWS = {"merged": "normal,build,dev", "target": "normal,dev,no-proc-macro"}
NODE = re.compile(r"^(\S+) v(\S+)(?: \(([^)]*)\))?(?: (\S+))?$")


def unified_features(tree):
    """The features each package of a `cargo tree` listing has, as {(name, version): {features}}."""
    found = {}
    for line in tree.splitlines():
        line = line.strip()
        while line.endswith(" (*)") or line.endswith(" (proc-macro)"):
            line = line.rsplit(" (", 1)[0]
        matched = NODE.match(line)
        if not matched:
            continue
        name, version, source, features = matched.groups()
        found.setdefault((name, version), set()).update(features.split(",") if features else [])
        found[(name, version)].discard("")
    return found


def feature_differences(whole, leg):
    """What the leg's packages have less or more than the whole workspace's, as sorted tuples of
    (package, `less` or `more`, feature)."""
    differences = set()
    for key, features in leg.items():
        if key not in whole:
            continue
        for feature in whole[key] - features:
            differences.add((key[0], "less", feature))
        for feature in features - whole[key]:
            differences.add((key[0], "more", feature))
    return sorted(differences)


def unlisted(differences, leg, allowed):
    """The differences of `leg`, as (package, leg, direction, feature), that `allowed` does not name."""
    return [(package, leg, direction, feature) for package, direction, feature in differences
            if (package, leg, direction, feature) not in allowed]


def tree(edges, arguments):
    command = ["cargo", "tree", "--locked", "-e", edges, "--target", TARGET, "--prefix", "none", "-f", "{p} {f}"]
    answer = subprocess.run(command + arguments, capture_output=True, text=True, check=False)
    if answer.returncode != 0:
        sys.stderr.write(answer.stderr)
        raise SystemExit("cargo tree failed")
    return answer.stdout


def features():
    with open(WORKFLOW, encoding="utf-8") as file:
        workflow = file.read()
    found = lists(workflow)
    whole = {
        view: unified_features(tree(edges, ["--workspace", "--exclude", LEFT_OUT]))
        for view, edges in VIEWS.items()
    }
    failed = False
    seen = set()
    for leg in LEGS:
        names, _ = packages_of(found[leg])
        arguments = [word for name in names for word in ("-p", name)]
        differences = set()
        for view, edges in VIEWS.items():
            differences.update(feature_differences(whole[view], unified_features(tree(edges, arguments))))
        seen.update((package, leg, direction, feature) for package, direction, feature in differences)
        for package, _, direction, feature in unlisted(sorted(differences), leg, FEATURE_DIFFERENCES):
            failed = True
            print(
                f"check-macos-test-division: {leg} builds {package} with {feature} {direction} than the whole "
                f"workspace's one step, and FEATURE_DIFFERENCES has no entry for it",
                file=sys.stderr,
            )
    for entry in sorted(set(FEATURE_DIFFERENCES) - seen):
        print(f"note: FEATURE_DIFFERENCES names {entry}, which no longer differs; remove it")
    if not failed:
        print(f"every feature the legs build with differently has an entry with its reason, {len(FEATURE_DIFFERENCES)} in all")
    return 1 if failed else 0


def fixture(first, second, extra=(), raw=""):
    """A workflow with a `macos` job whose two legs name these packages, and a job before and after it."""

    def entry(part, names):
        words = " ".join(f"-p {name}" for name in names)
        return (
            f"          - name: macos-{part}\n"
            f"            part: {part}\n"
            f"            packages: >-\n"
            f"              {words}\n"
        )

    return (
        "jobs:\n"
        "  rust:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - name: rust\n"
        "            part: first\n"
        "            packages: >-\n"
        "              -p not-a-macos-package\n"
        f"  {JOB}:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        + (entry("tests-1", first) if first is not None else "")
        + (entry("tests-2", second) if second is not None else "")
        + "".join(entry(part, names) for part, names in extra)
        + raw
        + "          - name: macos-demonstrations\n"
        "            part: demonstrations\n"
        "  after:\n"
        "    runs-on: x\n"
    )


def self_test():
    members = ["alpha", "beta", "gamma", "delta", LEFT_OUT]
    cases = [
        ("the division that holds", fixture(["alpha", "beta"], ["gamma", "delta"]), []),
        (
            "a member left out",
            fixture(["alpha"], ["gamma", "delta"]),
            ["beta is in no leg"],
        ),
        (
            "a member in both lists",
            fixture(["alpha", "beta"], ["beta", "gamma", "delta"]),
            ["beta is in both legs"],
        ),
        (
            "a member twice in one list",
            fixture(["alpha", "beta", "alpha"], ["gamma", "delta"]),
            ["tests-1: alpha is named more than once"],
        ),
        (
            "a name that is no member",
            fixture(["alpha", "beta", "epsilon"], ["gamma", "delta"]),
            ["tests-1: epsilon is not a package of the workspace"],
        ),
        (
            "the left-out package named",
            fixture(["alpha", "beta"], ["gamma", "delta", LEFT_OUT]),
            [f"tests-2: {LEFT_OUT} is named"],
        ),
        (
            "a word that is no package",
            fixture(["alpha", "beta"], ["gamma", "delta"]).replace(
                "-p gamma", "--exclude gamma"
            ),
            ["tests-2: `--exclude` is not", "gamma is in no leg"],
        ),
        (
            "a leg that is missing",
            fixture(["alpha", "beta", "gamma", "delta"], None),
            ["has no tests-2 leg"],
        ),
        (
            "a leg twice in the matrix",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("tests-1", ["alpha"])]),
            ["the tests-1 leg 2 times"],
        ),
        (
            "an extra test leg that would run packages again",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("tests-3", ["alpha"])]),
            ["a test leg tests-3"],
        ),
        (
            "an extra test leg in single quotes, which GitHub reads as the same name",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("'tests-3'", ["alpha"])]),
            ["a test leg tests-3"],
        ),
        (
            "an extra test leg in double quotes",
            fixture(["alpha", "beta"], ["gamma", "delta"], [('"tests-3"', ["alpha"])]),
            ["a test leg tests-3"],
        ),
        (
            "an extra test leg whose name differs only in case, which `startsWith` ignores",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("Tests-3", ["alpha"])]),
            ["a test leg tests-3"],
        ),
        (
            "an extra test leg with a comment after its name",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("tests-3 # more", ["alpha"])]),
            ["a test leg tests-3"],
        ),
        (
            "a second tests-1 in quotes",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("'tests-1'", ["alpha"])]),
            ["the tests-1 leg 2 times"],
        ),
        (
            "a second tests-1 that differs in case",
            fixture(["alpha", "beta"], ["gamma", "delta"], [("Tests-1", ["alpha"])]),
            ["the tests-1 leg 2 times"],
        ),
        (
            "a leg written as a flow mapping, which the check does not read",
            fixture(
                ["alpha", "beta"],
                ["gamma", "delta"],
                raw="          - {name: macos-tests-3, part: tests-3, packages: -p alpha}\n",
            ),
            ["a form the check does not read"],
        ),
        (
            "a part that is an expression, which the check does not read",
            fixture(
                ["alpha", "beta"],
                ["gamma", "delta"],
                raw="          - name: x\n            part: ${{ inputs.part }}\n",
            ),
            ["a form the check does not read"],
        ),
        (
            "an empty list, which `cargo test` takes as every member",
            fixture([], ["alpha", "beta", "gamma", "delta"]),
            ["tests-1 names no package"],
        ),
    ]
    failed = False
    for what, workflow, expected in cases:
        faults = problems(workflow, members)
        ok = (not faults) if not expected else all(
            any(want in fault for fault in faults) for want in expected
        )
        if expected == [] and faults:
            ok = False
        if not ok:
            failed = True
            print(f"self-test: {what}: wanted {expected or 'no fault'}, got {faults}", file=sys.stderr)
        else:
            print(f"self-test: {what}: {'accepted' if not expected else 'refused, ' + '; '.join(faults)}")
    # The features: a difference is found, and is refused unless its package is named for its leg.
    whole = unified_features(
        "alpha v1.0.0 (/w/alpha) testing,extra\nserde v1.0.0 derive,std\n"
        "serde v1.0.0 derive,std (*)\nmacro v0.1.0 (proc-macro)\nbeta v1.0.0 (/w/beta)\n"
    )
    leg = unified_features("alpha v1.0.0 (/w/alpha) extra\nserde v1.0.0 derive,std\nmacro v0.1.0 (proc-macro)\n")
    found = feature_differences(whole, leg)
    cases = [
        ("a feature the leg lacks is found", found == [("alpha", "less", "testing")]),
        ("it is refused when no reason names it", unlisted(found, "tests-1", {}) == [("alpha", "tests-1", "less", "testing")]),
        ("it is accepted when its feature is named for the leg", unlisted(found, "tests-1", {("alpha", "tests-1", "less", "testing"): "x"}) == []),
        ("it is refused for another leg", unlisted(found, "tests-2", {("alpha", "tests-1", "less", "testing"): "x"}) == [("alpha", "tests-2", "less", "testing")]),
        ("a package only the whole run has is no difference", feature_differences(whole, {}) == []),
        (
            "a new feature of a package that is named for another feature is refused",
            unlisted(
                feature_differences(
                    whole | {("beta", "1.0.0"): {"x", "y"}},
                    leg | {("beta", "1.0.0"): set()},
                ),
                "tests-1",
                {
                    ("alpha", "tests-1", "less", "testing"): "named",
                    ("beta", "tests-1", "less", "x"): "x is named, y is not",
                },
            )
            == [("beta", "tests-1", "less", "y")],
        ),
    ]
    for what, ok in cases:
        if not ok:
            failed = True
        print(f"self-test: {what}: {'ok' if ok else 'WRONG'}")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="the workflow's lists against the workspace")
    checking.add_argument("--locked", action="store_true")
    commands.add_parser("features", help="the legs' unified features against the whole workspace's")
    commands.add_parser("self-test", help="the check against faults it must refuse")
    arguments = parser.parse_args()
    if arguments.command == "check":
        return check(arguments.locked)
    if arguments.command == "features":
        return features()
    return self_test()


if __name__ == "__main__":
    sys.exit(main())
