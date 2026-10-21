#!/usr/bin/env python3
"""Writes what a package manager installs a KalaReach release from.

    package-managers.py render --release RELEASE --url-prefix URL --archive FILE... --out DIR
    package-managers.py self-test

A release archive is `kalareach-<target>-<release>.tar.gz` (a `.zip` on Windows), the unpacked tree
of `bin/`, `shells/`, `share/` and the signed `release.json`. Each package manager here unpacks that
tree under a prefix of its own and puts its `kr` on the search path, and nothing runs after the
unpack: the first command of that `kr` admits the release into the host's store of releases, so
there is no install hook to write.

  * macOS: a Homebrew cask, `Casks/kalareach.rb`, for both architectures.
  * Linux: a Homebrew formula, `Formula/kalareach.rb`, for both architectures.
  * Windows: a winget portable package, `manifests/k/KalaHoldings/KalaReach/<release>/`, for both
    architectures.

Each file carries the URL of the archive it installs and the archive's SHA-256, which is read from
the archive named here and never typed. `--url-prefix` is the address of the directory the archives
are served from. A family renders only when both of its architectures are given, because a file for
one architecture would leave the other with no install and no word of it.

`self-test` renders a release from archives it makes, holds each file to what its package manager
reads, and then plants each fault in the inputs, which has to be refused.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

ARCHIVE = re.compile(
    r"^kalareach-(?P<target>[a-z0-9_]+-[a-z0-9]+-[a-z0-9]+(?:-[a-z0-9]+)?)-(?P<release>\d+\.\d+\.\d+\+[0-9a-f]{12})\.(?P<kind>tar\.gz|zip)$"
)

HOMEPAGE = "https://github.com/kalapowered/kalareach"
DESCRIPTION = "Managed terminal sessions for AI coding agents"

# What winget names the package and its publisher, which is the name its Authenticode signature
# carries. A submission to winget's community repository is the owner's to make.
WINGET_PACKAGE = "KalaHoldings.KalaReach"
WINGET_PUBLISHER = "Kala Holdings Inc."
WINGET_MANIFEST_VERSION = "1.12.0"

# The shells a release carries are other people's, so the formula says every licence that holds a
# file of the tree.
FORMULA_LICENCES = ["BSD-3-Clause", "Zsh", "GPL-3.0-or-later", "GPL-2.0-only"]

FAMILIES = {
    "cask": ("aarch64-apple-darwin", "x86_64-apple-darwin"),
    "formula": ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"),
    "winget": ("aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc"),
}


class Refused(Exception):
    """Inputs a package manager's files cannot be made from, with the reason."""


class Archive:
    def __init__(self, path):
        name = os.path.basename(path)
        found = ARCHIVE.match(name)
        if not found:
            raise Refused(f"{name} is not named kalareach-<target>-<release>.tar.gz or .zip")
        self.name = name
        self.target = found["target"]
        self.release = found["release"]
        wanted = "zip" if "windows" in self.target else "tar.gz"
        if found["kind"] != wanted:
            raise Refused(f"{name} is a .{found['kind']} and a {self.target} release is a .{wanted}")
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
        except OSError as error:
            raise Refused(f"{path} cannot be read: {error}") from error
        self.sha256 = digest.hexdigest()


def read_archives(paths, release):
    found = {}
    for path in paths:
        archive = Archive(path)
        if archive.release != release:
            raise Refused(f"{archive.name} is release {archive.release}, and this run is for {release}")
        if archive.target in found:
            raise Refused(f"{archive.target} is given twice")
        found[archive.target] = archive
    known = {target for targets in FAMILIES.values() for target in targets}
    for target in found:
        if target not in known:
            raise Refused(f"{target} is not a target a package manager here installs")
    return found


def quoted(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cask(release, url_prefix, archives):
    arm, intel = (archives[target] for target in FAMILIES["cask"])
    return f"""cask "kalareach" do
  arch arm: "aarch64", intel: "x86_64"

  version {quoted(release)}
  sha256 arm:   {quoted(arm.sha256)},
         intel: {quoted(intel.sha256)}

  url "{url_prefix}/kalareach-#{{arch}}-apple-darwin-#{{version}}.tar.gz"
  name "KalaReach"
  desc {quoted(DESCRIPTION)}
  homepage {quoted(HOMEPAGE)}

  # The release stays where Homebrew unpacked it. The first command of this `kr` admits that
  # release into the host's own store, so nothing runs after the unpack, and removing the cask
  # never touches the store.
  binary "kalareach-#{{arch}}-apple-darwin-#{{version}}/bin/kr"
end
"""


def formula(release, url_prefix, archives):
    arm, intel = (archives[target] for target in FAMILIES["formula"])
    licences = ", ".join(quoted(licence) for licence in FORMULA_LICENCES)
    return f"""class Kalareach < Formula
  desc {quoted(DESCRIPTION)}
  homepage {quoted(HOMEPAGE)}
  version {quoted(release)}
  license all_of: [{licences}]

  on_linux do
    on_arm do
      url "{url_prefix}/{arm.name}"
      sha256 {quoted(arm.sha256)}
    end
    on_intel do
      url "{url_prefix}/{intel.name}"
      sha256 {quoted(intel.sha256)}
    end
  end

  # The release stays where Homebrew unpacked it. The first command of this `kr` admits that
  # release into the host's own store, so there is no post-install step, and removing the formula
  # never touches the store.
  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"bin/kr"
  end

  test do
    # `kr --version` states the crate's version; the release name adds the commit after a plus.
    assert_match version.to_s.split("+").first, shell_output("#{{bin}}/kr --version")
  end
end
"""


def winget(release, url_prefix, archives):
    arm, intel = (archives[target] for target in FAMILIES["winget"])
    head = f"PackageIdentifier: {WINGET_PACKAGE}\nPackageVersion: {quoted(release)}\n"
    tail = f"ManifestVersion: {WINGET_MANIFEST_VERSION}\n"
    installers = []
    for architecture, archive in (("x64", intel), ("arm64", arm)):
        url = quoted(url_prefix + "/" + archive.name)
        # The release's directory, then its program, with the separators a Windows path has.
        nested = quoted("kalareach-" + archive.target + "-" + release + "\\bin\\kr.exe")
        installers.append(
            f"""  - Architecture: {architecture}
    InstallerUrl: {url}
    InstallerSha256: {archive.sha256.upper()}
    NestedInstallerFiles:
      - RelativeFilePath: {nested}
        PortableCommandAlias: kr"""
        )
    return {
        f"{WINGET_PACKAGE}.yaml": head
        + f"DefaultLocale: en-US\nManifestType: version\n"
        + tail,
        f"{WINGET_PACKAGE}.installer.yaml": head
        + "InstallerType: zip\nNestedInstallerType: portable\nInstallModes:\n  - silent\n"
        # The programs of a release find one another beside themselves, so `kr` is started from the
        # release's own directory on the search path: a link to it in winget's links directory would
        # make the host look for its programs beside the link.
        + "ArchiveBinariesDependOnPath: true\n"
        + "Commands:\n  - kr\nInstallers:\n"
        + "\n".join(installers)
        + "\nManifestType: installer\n"
        + tail,
        f"{WINGET_PACKAGE}.locale.en-US.yaml": head
        + f"PackageLocale: en-US\nPublisher: {quoted(WINGET_PUBLISHER)}\n"
        + f"PublisherUrl: {quoted('https://github.com/kalapowered')}\n"
        + "PackageName: KalaReach\n"
        + f"PackageUrl: {quoted(HOMEPAGE)}\n"
        + "License: BSD-3-Clause\n"
        + f"LicenseUrl: {quoted(HOMEPAGE + '/blob/main/LICENSE')}\n"
        + f"ShortDescription: {quoted(DESCRIPTION)}\n"
        + "Tags:\n  - terminal\n  - cli\n  - ai\n"
        + "ManifestType: defaultLocale\n"
        + tail,
    }


def render(release, url_prefix, paths, out):
    """Writes each family's files whose archives are given, and returns the paths it wrote."""
    if not re.fullmatch(r"\d+\.\d+\.\d+\+[0-9a-f]{12}", release):
        raise Refused(f"{release} is not a release name, `<version>+<twelve hex digits>`")
    if not re.fullmatch(r"https?://[^\s\"]+[^/\s\"]|file:///[^\s\"]+[^/\s\"]", url_prefix):
        raise Refused(f"{url_prefix} is not the address of a directory, written with no trailing slash")
    archives = read_archives(paths, release)
    written = []
    for family, targets in FAMILIES.items():
        given = [target for target in targets if target in archives]
        if not given:
            continue
        if len(given) != len(targets):
            missing = ", ".join(target for target in targets if target not in archives)
            raise Refused(f"the {family} installs both architectures, and {missing} is not given")
        if family == "cask":
            files = {"Casks/kalareach.rb": cask(release, url_prefix, archives)}
        elif family == "formula":
            files = {"Formula/kalareach.rb": formula(release, url_prefix, archives)}
        else:
            base = f"manifests/k/{WINGET_PACKAGE.replace('.', '/')}/{release}"
            files = {f"{base}/{name}": text for name, text in winget(release, url_prefix, archives).items()}
        for relative, text in files.items():
            destination = os.path.join(out, relative)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            written.append(destination)
    if not written:
        raise Refused("no family of archives is given: a package manager installs both architectures of one system")
    return written


def self_test():
    failures = 0

    def report(label, ok, detail=""):
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}{(': ' + detail) if detail else ''}")
        if not ok:
            failures += 1

    release = "0.1.0+4254aa6e62e5"
    prefix = "https://example.invalid/releases/host%2Fv0.1.0%2B4254aa6e62e5"
    with tempfile.TemporaryDirectory(prefix="kr-package-managers-") as scratch:
        made = {}
        for target in [t for targets in FAMILIES.values() for t in targets]:
            suffix = "zip" if "windows" in target else "tar.gz"
            path = os.path.join(scratch, f"kalareach-{target}-{release}.{suffix}")
            with open(path, "wb") as handle:
                handle.write(f"an archive of {target}".encode())
            made[target] = path
        out = os.path.join(scratch, "out")
        written = render(release, prefix, list(made.values()), out)
        names = sorted(os.path.relpath(path, out) for path in written)
        report(
            "a release renders a cask, a formula and the three winget files",
            len(names) == 5
            and "Casks/kalareach.rb" in names
            and "Formula/kalareach.rb" in names,
            ", ".join(names),
        )

        def text(relative):
            with open(os.path.join(out, relative), encoding="utf-8") as handle:
                return handle.read()

        def digest(target):
            return hashlib.sha256(f"an archive of {target}".encode()).hexdigest()

        cask_text = text("Casks/kalareach.rb")
        report(
            "the cask names each architecture's digest, read from its archive",
            digest("aarch64-apple-darwin") in cask_text and digest("x86_64-apple-darwin") in cask_text,
        )
        formula_text = text("Formula/kalareach.rb")
        report(
            "the formula names each archive's address and digest",
            all(
                f"{prefix}/kalareach-{target}-{release}.tar.gz" in formula_text and digest(target) in formula_text
                for target in FAMILIES["formula"]
            ),
        )
        report(
            "no file runs anything after the unpack",
            "post_install" not in formula_text and "postflight" not in cask_text,
        )
        installer = text(f"manifests/k/KalaHoldings/KalaReach/{release}/{WINGET_PACKAGE}.installer.yaml")
        report(
            "winget names each Windows archive's digest in upper case",
            all(digest(target).upper() in installer for target in FAMILIES["winget"]),
        )
        report(
            "winget puts the tree's `bin` on the search path",
            installer.count("ArchiveBinariesDependOnPath: true") == 1,
        )
        report(
            "winget starts `kr` from the tree's `bin`",
            installer.count("PortableCommandAlias: kr") == 2 and "\\\\bin\\\\kr.exe" in installer,
        )
        ruby = shutil.which("ruby")
        if ruby:
            for relative in ("Casks/kalareach.rb", "Formula/kalareach.rb"):
                outcome = subprocess.run([ruby, "-c", os.path.join(out, relative)], capture_output=True, text=True)
                report(f"ruby reads {relative}", outcome.returncode == 0, outcome.stderr.strip())
        else:
            print("skip ruby is not here, so the cask and formula are not read by it")

        def refused(label, action):
            try:
                action()
                report(label, False, "it was not refused")
            except Refused as error:
                report(label, True, f"refused: {error}")

        refused(
            "an archive of another release",
            lambda: render("0.2.0+aaaaaaaaaaaa", prefix, list(made.values()), os.path.join(scratch, "x1")),
        )
        refused(
            "a family with one architecture only",
            lambda: render(
                release,
                prefix,
                [made[t] for t in made if t != "x86_64-apple-darwin"],
                os.path.join(scratch, "x2"),
            ),
        )
        refused(
            "an address that ends in a slash",
            lambda: render(release, prefix + "/", list(made.values()), os.path.join(scratch, "x3")),
        )
        refused(
            "an archive named for no target",
            lambda: render(release, prefix, [made["aarch64-apple-darwin"].replace("apple-darwin", "plan9")], os.path.join(scratch, "x4")),
        )
        wrong = os.path.join(scratch, f"kalareach-x86_64-pc-windows-msvc-{release}.tar.gz")
        with open(wrong, "wb") as handle:
            handle.write(b"x")
        refused("a Windows archive that is not a zip", lambda: render(release, prefix, [wrong], os.path.join(scratch, "x5")))
        refused("no archive at all", lambda: render(release, prefix, [], os.path.join(scratch, "x6")))
    return failures


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    rendering = commands.add_parser("render", help="write the files for a release's archives")
    rendering.add_argument("--release", required=True)
    rendering.add_argument("--url-prefix", required=True)
    rendering.add_argument("--archive", action="append", required=True)
    rendering.add_argument("--out", required=True)
    commands.add_parser("self-test", help="check the renderer against inputs made to fail")
    parsed = parser.parse_args(arguments)
    if parsed.command == "self-test":
        return 1 if self_test() else 0
    try:
        written = render(parsed.release, parsed.url_prefix, parsed.archive, parsed.out)
    except Refused as error:
        print(f"package-managers: {error}", file=sys.stderr)
        return 1
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
