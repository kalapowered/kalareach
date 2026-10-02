#!/usr/bin/env python3
"""Keeps the host's packages out of the companion's mobile dependency graph.

The companion application runs on a phone. The host side of the product (the control daemon, the
workers, the managed shell packages, the plugin runtime, the services a host runs for its
environments) is a set of separate build products for desktops and servers, and none of it is
linked into what ships to iOS or Android. The documents that describe each of those services say
which side of the line it is on; this holds the graph to them.

For every mobile target this asks Cargo for the companion's normal and build dependencies (the
graph that ships, without dev-dependencies) and fails when a crate on the host list is in it. It
also fails when a crate under `crates/` is on neither list, so a new crate is classified when it is
added and the host list cannot go stale by omission.

    python3 scripts/check-mobile-graph.py check [--locked]
    python3 scripts/check-mobile-graph.py self-test

`self-test` builds two small workspaces and puts the check through them: one whose companion
depends on a host crate, which must be refused on every target and named, and one that does not,
which must pass.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import textwrap

COMPANION = "companion-tauri"
FEATURES = ["custom-protocol"]

# The targets the companion's mobile builds are made for.
MOBILE_TARGETS = [
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "i686-linux-android",
    "x86_64-linux-android",
]

# Crates a phone may link: the shared client and what it is made of.
SHARED = {
    "kr-cbor": "docs/protocol/README.md: the KR-CBOR-1 encoding, shared by every client",
    "kr-client": "docs/client/README.md: the shared native client library",
    "kr-crypto": "docs/crypto/README.md: purpose-separated keys and secret storage",
    "kr-flush": "the directory flush every local store uses",
    "kr-ipc": "docs/host/README.md: runtime directories and typed frames the client's local connection uses",
    "kr-pairing": "docs/pairing/README.md: the pairing flows a device runs",
    "kr-plugin-sdk": "docs/plugins/sdk.md: the package contract types a client reads",
    "kr-protocol": "docs/protocol/README.md: wire types and the method table",
    "kr-transport": "docs/transport/README.md: how a client reaches a host",
    "kr-voice": "docs/voice/client.md: the voice client's coordinator",
    "kr-width": "docs/terminal/README.md: the width model a phone measures with, the same tables as the desktop",
}

# The host's packages, each with the document that puts it on the host's side.
HOST_ONLY = {
    "kr-controller": "docs/host/README.md: the control daemon",
    "kr-worker": "docs/host/README.md: the session worker",
    "kr-cli": "docs/cli/README.md: the kr command line",
    "kr-hook": "docs/host/README.md: the forwarder an application starts beside its terminal",
    "kr-shell-integration": "docs/shell-integration/host.md: the worker's side of the root-editor contract",
    "kr-term": "docs/terminal/README.md: the terminal engine a host runs for each session",
    "kr-term-probe": "docs/terminal/README.md: the tool that measures a physical terminal against the grid",
    "kr-transfer": "docs/transfer/README.md: filesystem authority and previews on the host",
    "kr-project": "docs/project/README.md: repositories, workspaces and the restricted Git profile",
    "kr-changeset": "docs/project/README.md: change sets captured and applied on the host",
    "kr-automation": "docs/automation/README.md: the workflow engine a host runs",
    "kr-attention": "docs/host/README.md: the attention engine a host runs",
    "kr-delivery": "docs/delivery/README.md: the delivery journal and push outbox a host keeps",
    "kr-describe": "docs/describe/README.md: local session descriptions on the host",
    "kr-describe-model": "docs/describe/README.md: the inference process a host runs",
    "kr-plugin-host": "docs/plugins/runtime.md: the per-environment plugin process",
    "kr-plugin-runtime": "docs/plugins/runtime.md: where a plugin component runs",
    "kr-plugin-service": "docs/plugins/runtime.md: the worker's client of the plugin host",
    "kr-plugin-catalogue": "docs/plugins/catalogue.md: enrolment and activation on the host",
}


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(f"$ {' '.join(command)}\n{result.stdout}{result.stderr}")
        raise SystemExit(f"{command[0]} exited {result.returncode}")
    return result.stdout


def workspace_crates(root):
    """Names of the workspace crates that live under crates/."""
    metadata = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1",
                               "--offline"], root))
    real = os.path.realpath(root)
    return sorted(
        package["name"]
        for package in metadata["packages"]
        if os.path.relpath(os.path.realpath(package["manifest_path"]), real).startswith(
            "crates" + os.sep)
    )


def graph(root, package, target, locked, offline):
    """Crate names in the package's shipped dependency graph for one target."""
    command = ["cargo", "tree", "-p", package, "--target", target,
               "-e", "normal,build", "--prefix", "none", "-f", "{p}"]
    if locked:
        command.append("--locked")
    if offline:
        command.append("--offline")
    for feature in FEATURES:
        command += ["--features", feature]
    names = set()
    for line in run(command, root).splitlines():
        if line.strip():
            names.add(line.split()[0])
    return names


def problems_in(root, package, host_only, shared, targets, locked, classify, offline=False):
    problems = []
    if classify:
        for name in workspace_crates(root):
            if name not in host_only and name not in shared:
                problems.append(
                    f"{name} is a workspace crate on neither the host list nor the shared list"
                )
    for target in targets:
        found = graph(root, package, target, locked, offline)
        for name in sorted(found & set(host_only)):
            problems.append(f"{target}: {package} links {name} ({host_only[name]})")
    return problems


def self_test():
    failures = []

    def workspace(scratch, companion_depends_on_host):
        root = os.path.join(scratch, "with-host" if companion_depends_on_host else "without")
        for name in ("kr-client", "kr-worker", COMPANION):
            os.makedirs(os.path.join(root, "crates", name, "src"))
        manifests = {
            "kr-client": "",
            "kr-worker": "",
            COMPANION: 'kr-client = { path = "../kr-client" }\n'
            + ('kr-worker = { path = "../kr-worker" }\n' if companion_depends_on_host else ""),
        }
        with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as handle:
            handle.write('[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n')
        for name, dependencies in manifests.items():
            with open(os.path.join(root, "crates", name, "Cargo.toml"), "w",
                      encoding="utf-8") as handle:
                handle.write(textwrap.dedent(f"""\
                    [package]
                    name = "{name}"
                    version = "0.1.0"
                    edition = "2024"

                    [features]
                    custom-protocol = []

                    [dependencies]
                    """) + dependencies)
            with open(os.path.join(root, "crates", name, "src", "lib.rs"), "w",
                      encoding="utf-8") as handle:
                handle.write("")
        return root

    host = {"kr-worker": "the session worker"}
    shared = {"kr-client": "the shared client", COMPANION: "the companion"}
    targets = ["aarch64-apple-ios", "aarch64-linux-android"]

    with tempfile.TemporaryDirectory(prefix="kalareach-mobile-graph-") as scratch:
        clean = workspace(scratch, False)
        found = problems_in(clean, COMPANION, host, shared, targets, False, True, True)
        if found:
            failures.append(f"a companion with no host crate was refused: {found}")

        dirty = workspace(scratch, True)
        found = problems_in(dirty, COMPANION, host, shared, targets, False, True, True)
        for target in targets:
            if not any(target in line and "kr-worker" in line for line in found):
                failures.append(f"a companion linking kr-worker passed on {target}: {found}")

        # A crate on neither list is refused until it is classified.
        found = problems_in(clean, COMPANION, host, {"kr-client": "x"}, targets, False, True, True)
        if not any(COMPANION in line and "neither" in line for line in found):
            failures.append(f"an unclassified crate passed: {found}")

    if failures:
        sys.stderr.write("\n".join(failures) + "\n")
        return 1
    print("check-mobile-graph self-test: a clean graph passes, a host crate is named on each "
          "target, and an unclassified crate is refused")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="hold this workspace's mobile graph to the list")
    checking.add_argument("--locked", action="store_true", help="pass --locked to cargo tree")
    commands.add_parser("self-test", help="put the check through a pass and its refusals")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        return self_test()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    shared = dict(SHARED)
    shared[COMPANION] = "the companion application itself"
    shared["companion-platform"] = "the companion's native platform services"
    problems = problems_in(root, COMPANION, HOST_ONLY, shared, MOBILE_TARGETS,
                           arguments.locked, True)
    if problems:
        sys.stderr.write("The companion's mobile dependency graph is not the client's alone:\n")
        for problem in problems:
            sys.stderr.write(f"  {problem}\n")
        return 1
    print(f"{COMPANION} links no host crate on {len(MOBILE_TARGETS)} mobile targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
