#!/usr/bin/env python3
"""Reads the network security configuration a packaged Android application ends up with, and says
whether it is the one this project ships.

    android-network-config.py release <package.apk>
    android-network-config.py debug <package.apk>

A release build allows no cleartext traffic, and Android's revocation check in the platform
verifier's Kotlin half fetches the revocation lists certificate authorities publish over plain HTTP
(Let's Encrypt, Google Trust Services and SSL.com have all dropped OCSP, and Cloudflare serves
certificates from each of them). Where that fetch is refused, the verifier reports the certificate
as revoked and the application reaches no service whose certificate comes from such an authority.
The verifier's Kotlin half therefore brings a network security configuration that permits cleartext
traffic to the hosts it lists, which are the hosts those authorities publish their revocation lists
on (some of them general web hosts), and to nothing else.

What is checked is what the system would do, not what the package says somewhere:

* The manifest names the configuration by resource. The check follows that name to the file the
  package holds under it, so a configuration the manifest does not name decides nothing, whatever
  it says.
* A host is permitted cleartext traffic by the most specific rule that matches it (the domain
  itself, or a parent domain whose rule includes subdomains), and by the default where none does.
* A release package permits cleartext traffic to the revocation-list hosts of the authorities
  the deployed service's certificates come from, by their exact names, and to no host of this
  project, nor any parent domain of one, nor any other host. A debug package permits it everywhere,
  for the development server's plain HTTP.

The check runs against its own negative controls first (a configuration the manifest does not name,
a disabled entry, a parent where an exact host is needed, a broad exception, a permissive default),
which are built from the real output of the build tools in `scripts/fixtures/android-network-config`,
and does not read the package if any of them gives the wrong answer.

Exit codes: 0 the package is as shipped, 2 it is not or cannot be read, 3 there are no build tools
or a control gave the wrong answer.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# The hosts of the authorities' revocation lists that the deployed service's certificates name:
# Google Trust Services, Let's Encrypt (its E5 intermediate) and SSL.com. The names are exact: a
# parent domain's permission is not the host's unless the rule says it includes subdomains.
REQUIRED = ["c.pki.goog", "e5.c.lencr.org", "crls.ssl.com"]

# What no release package permits: this project's own hosts, their parent domain, and any host
# that is none of the above.
FORBIDDEN = ["kala.to", "reach.kala.to", "www.kala.to", "to", "example.com"]

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "android-network-config"


@dataclass
class Element:
    name: str
    indent: int
    attributes: dict[str, str] = field(default_factory=dict)
    children: list["Element"] = field(default_factory=list)
    text: str = ""

    def child(self, name: str) -> "Element | None":
        return next((each for each in self.children if each.name == name), None)

    def descendant(self, name: str) -> "Element | None":
        if self.name == name:
            return self
        for each in self.children:
            found = each.descendant(name)
            if found is not None:
                return found
        return None


def parse(tree: str) -> Element | None:
    """The element tree of `aapt2 dump xmltree`'s output.

    Each line names its kind (`E` element, `A` attribute, `T` text) after its indentation. An
    element's attributes are indented two columns past it, and its child elements and text four.
    """
    root: Element | None = None
    stack: list[Element] = []
    for line in tree.splitlines():
        found = re.match(r"^( *)([NEAT]): ?(.*)$", line)
        if not found or found.group(2) == "N":
            continue
        indent, kind, rest = len(found.group(1)), found.group(2), found.group(3)
        while stack and stack[-1].indent >= indent:
            stack.pop()
        if kind == "E":
            element = Element(rest.split(" ")[0], indent)
            if stack:
                stack[-1].children.append(element)
            elif root is None:
                root = element
            stack.append(element)
        elif stack and kind == "A":
            name, _, value = rest.partition("=")
            # The attribute's name may carry its namespace and its resource number.
            name = re.sub(r"\(0x[0-9a-f]+\)$", "", name.split(":")[-1])
            value = re.sub(r' \(Raw: .*\)$', "", value)
            stack[-1].attributes[name] = value.strip('"')
        elif stack and kind == "T":
            stack[-1].text = rest.strip().strip("'")
    return root


def resource_files(resources: str) -> dict[int, list[str]]:
    """The file or files each resource of the package's table holds, from `aapt2 dump resources`."""
    files: dict[int, list[str]] = {}
    current: int | None = None
    for line in resources.splitlines():
        resource = re.match(r"^\s*resource 0x([0-9a-f]+) ", line)
        if resource:
            current = int(resource.group(1), 16)
            continue
        file = re.search(r"\(file\) (\S+)", line)
        if file and current is not None:
            files.setdefault(current, []).append(file.group(1))
    return files


def flag(value: str | None, otherwise: bool) -> bool:
    return otherwise if value is None else value == "true"


def verdicts(configuration: Element, host: str) -> set[bool]:
    """What the configuration says of cleartext traffic to `host`: the answers of the most specific
    rules that match it (more than one when rules of the same length disagree), or the default's."""
    base = configuration.child("base-config")
    default = flag(base.attributes.get("cleartextTrafficPermitted") if base else None, False)
    host = host.lower()
    matching: list[tuple[int, bool]] = []

    def collect(parent: Element, inherited: bool) -> None:
        for each in parent.children:
            if each.name != "domain-config":
                continue
            permitted = flag(each.attributes.get("cleartextTrafficPermitted"), inherited)
            for domain in each.children:
                if domain.name != "domain":
                    continue
                name = domain.text.lower()
                includes = domain.attributes.get("includeSubdomains") == "true"
                if host == name or (includes and host.endswith("." + name)):
                    matching.append((len(name), permitted))
            collect(each, permitted)

    collect(configuration, default)
    if not matching:
        return {default}
    longest = max(length for length, _ in matching)
    return {permitted for length, permitted in matching if length == longest}


def problems(
    mode: str, manifest: str, resources: str, read: Callable[[str], str]
) -> list[str]:
    """What is wrong with the package, in words; empty when it is as shipped."""
    found: list[str] = []
    root = parse(manifest)
    application = root.descendant("application") if root else None
    if application is None:
        return ["the manifest has no application element"]
    named = application.attributes.get("networkSecurityConfig")
    if named is None:
        return ["the manifest names no network security configuration"]
    reference = re.fullmatch(r"@0x([0-9a-f]+)", named)
    if not reference:
        return [f"the manifest names its network security configuration by {named}, not by a resource"]
    paths = resource_files(resources).get(int(reference.group(1), 16), [])
    if not paths:
        return [f"the package holds nothing under {named}, the resource the manifest names"]
    for path in paths:
        configuration = parse(read(path))
        if configuration is None or configuration.name != "network-security-config":
            found.append(f"{path}, which the manifest names, is not a network security configuration")
            continue
        if mode == "debug":
            for host in ("10.0.2.2", "192.168.1.5", "localhost"):
                if verdicts(configuration, host) != {True}:
                    found.append(f"cleartext traffic to {host} is not permitted, so the development server is out of reach")
            continue
        base = configuration.child("base-config")
        if base is None or base.attributes.get("cleartextTrafficPermitted") != "false":
            found.append("the configuration does not turn cleartext traffic off by default")
        for host in REQUIRED:
            if verdicts(configuration, host) != {True}:
                found.append(f"cleartext traffic to {host} is not permitted, and its revocation list is needed")
        for host in FORBIDDEN:
            if True in verdicts(configuration, host):
                found.append(f"cleartext traffic to {host} is permitted")
    return found


def controls() -> list[str]:
    """Runs the check against configurations that must fail, and the one that must pass. Returns
    what a control got wrong; empty when every answer is the right one."""
    manifest = (FIXTURES / "manifest.xmltree").read_text()
    resources = (FIXTURES / "resources.txt").read_text()
    good = (FIXTURES / "config.xmltree").read_text()
    wrong: list[str] = []

    def run(mode: str, config: str, *, manifest_text: str = manifest, resources_text: str = resources) -> list[str]:
        return problems(mode, manifest_text, resources_text, lambda _path: config)

    def expect(name: str, found: list[str], want_failure: bool) -> None:
        if bool(found) != want_failure:
            wrong.append(f"{name}: {'it passed' if want_failure else 'it failed: ' + '; '.join(found)}")

    expect("the shipped configuration", run("release", good), False)
    expect("the shipped configuration as a debug package's", run("debug", good), True)

    # Cleartext on by default.
    permissive = good.replace("A: cleartextTrafficPermitted=false", "A: cleartextTrafficPermitted=true", 1)
    expect("a configuration that permits cleartext by default", run("release", permissive), True)
    expect("a configuration that permits cleartext by default, as a debug package's", run("debug", permissive), False)

    # Every entry disabled: the hosts are listed and the permission is off.
    first_entry = good.index("A: cleartextTrafficPermitted=true")
    disabled = good[:first_entry] + "A: cleartextTrafficPermitted=false" + good[first_entry + len("A: cleartextTrafficPermitted=true"):]
    expect("a configuration whose entry is disabled", run("release", disabled), True)

    # A parent where the exact host is needed: the host's own entry is gone, and its parent's is not
    # one that includes subdomains.
    parent = good.replace("'e5.c.lencr.org'", "'c.lencr.org'").replace(
        "A: includeSubdomains=true\n            T: 'c.lencr.org'", "A: includeSubdomains=false\n            T: 'c.lencr.org'"
    )
    expect("a configuration with the parent of a needed host", run("release", parent), True)

    # A broad exception: a parent domain of this project's own hosts, subdomains included.
    broad = good.rstrip("\n") + "\n        E: domain (line=900)\n          A: includeSubdomains=true\n            T: 'to'\n"
    expect("a configuration that permits a parent domain of this project's hosts", run("release", broad), True)
    ours = good.rstrip("\n") + "\n        E: domain (line=900)\n          A: includeSubdomains=false\n            T: 'kala.to'\n"
    expect("a configuration that permits this project's own host", run("release", ours), True)

    # An entry that overrides the broad one for the one host: the more specific rule decides.
    nested = good.rstrip("\n") + (
        "\n    E: domain-config (line=950)\n      A: cleartextTrafficPermitted=false\n"
        "        E: domain (line=951)\n          A: includeSubdomains=true\n            T: 'c.pki.goog'\n"
    )
    expect("a configuration that disables one needed host in a second entry", run("release", nested), True)

    # The configuration the manifest does not name: the table sends the name to a file that holds
    # none of the permissions, while the file that holds them is in the package, named by nobody.
    unused = resources.replace("res/8G.xml", "res/unused.xml")
    expect(
        "a package whose manifest names another configuration than the one with the permissions",
        problems("release", manifest, unused, lambda path: good if path == "res/8G.xml" else "E: network-security-config (line=2)\n    E: base-config (line=3)\n      A: cleartextTrafficPermitted=false\n"),
        True,
    )
    # A manifest that names none.
    expect(
        "a manifest that names no configuration",
        run("release", good, manifest_text=re.sub(r".*networkSecurityConfig.*\n", "", manifest)),
        True,
    )
    return wrong


def aapt2() -> str | None:
    sdk = os.environ.get("ANDROID_HOME") or str(Path.home() / "Library/Android/sdk")
    found = sorted(Path(sdk).glob("build-tools/*/aapt2"), key=lambda path: [int(part) if part.isdigit() else 0 for part in re.split(r"\D+", path.parent.name)])
    return str(found[-1]) if found else None


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) != 2 or arguments[0] not in ("release", "debug") or not Path(arguments[1]).is_file():
        print(f"usage: {sys.argv[0]} <release|debug> <package.apk>", file=sys.stderr)
        return 2
    mode, package = arguments

    def say(text: str) -> None:
        print(f"== [{mode}-package] {text}", flush=True)

    wrong = controls()
    for each in wrong:
        say(f"the check itself is wrong: {each}")
    if wrong:
        return 3
    say("the check refuses the controls it must refuse and passes the one it must pass")

    tool = aapt2()
    if tool is None:
        print("no aapt2 under the Android SDK's build-tools", file=sys.stderr)
        return 3

    def dump(*words: str) -> str:
        done = subprocess.run([tool, "dump", *words], capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise SystemExit(f"aapt2 could not read the package: {done.stderr.strip()[:200]}")
        return done.stdout

    found = problems(
        mode,
        dump("xmltree", package, "--file", "AndroidManifest.xml"),
        dump("resources", package),
        lambda path: dump("xmltree", package, "--file", path),
    )
    for each in found:
        say(each)
    if not found:
        say(
            "cleartext traffic is off by default, and permitted for the revocation-list hosts and no host of this project"
            if mode == "release"
            else "cleartext traffic is permitted, for the development server"
        )
    return 2 if found else 0


if __name__ == "__main__":
    sys.exit(main())
