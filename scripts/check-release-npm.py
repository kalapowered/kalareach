#!/usr/bin/env python3
"""Holds the plugin SDK's npm publication to the archive a release attaches.

A tag `packages/v<version>+<commit>` releases two archives, and the SDK's is the one published to
the npm registry as well. What the registry serves has to be what the release carries, so this
packs the same source with `npm pack`, the tool a person would run to see what npm would publish,
and compares it with the release archive:

  * every file the two hold is the same file, member by member and digest by digest. `pnpm pack`
    adds the workspace's LICENSE and npm does not, so that one file may exist in the archive alone;
  * the two manifests say the same thing. pnpm and npm write the same document with its members in
    another order, and pnpm leaves out six scripts that run only where a package is made or
    published (`prepack`, `postpack`, `prepare`, `prepublishOnly`, `publish`, `postpublish`), so
    they are compared as documents without those. Any other script is compared, and a script that
    runs on install is refused outright;
  * the manifest is one the registry accepts and the provenance statement can attach to: a public
    scoped package, not marked private, naming the repository the release runs in, publishing with
    provenance, and pointing its entry points into files the archive holds;
  * a Node that installs the archive under `node_modules` imports the package by its name, reaches
    its schema through the export map, and gets the validator and the SDK version;
  * `npm publish --dry-run` on the release archive itself accepts it.

Nothing here publishes. The publishing job runs the real command on the archive this check
approved, after it has held that archive to the digest the check recorded.

    python3 scripts/check-release-npm.py check --archive <archive> [--source <package directory>]
    python3 scripts/check-release-npm.py self-test

`self-test` puts the check through a package it must pass and through each way of going wrong it
must refuse, so a check that agrees with everything cannot pass for one that agrees with the
release.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPOSITORY = "git+https://github.com/kalapowered/kalareach.git"

# What pnpm puts in an archive that npm does not: the workspace's licence file, copied into each
# package it packs.
ARCHIVE_ONLY = {"LICENSE"}


def read_archive(path):
    """Returns {member path: (sha256, is executable)} for an npm archive, refusing an odd member."""
    members = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            if not name.startswith("package/") or name.startswith("/") or ".." in name.split("/"):
                raise SystemExit(f"{path} holds a member outside package/: {name}")
            if member.isdir():
                continue
            if not member.isreg():
                raise SystemExit(f"{path} holds {name}, which is not a regular file")
            data = archive.extractfile(member).read()
            members[name[len("package/"):]] = (
                hashlib.sha256(data).hexdigest(),
                bool(member.mode & 0o111),
                data,
            )
    return members


def manifest_of(members, where):
    if "package.json" not in members:
        raise SystemExit(f"{where} holds no package.json")
    return json.loads(members["package.json"][2])


def targets(value):
    """Every string an entry point declaration names."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for inner in value.values():
            yield from targets(inner)


def manifest_problems(manifest, members):
    problems = []
    if manifest.get("private") is True:
        problems.append("the manifest is marked private, so npm refuses to publish it")
    name = manifest.get("name", "")
    if not name.startswith("@kalareach/"):
        problems.append(f"the manifest names {name!r}, which is not in the @kalareach scope")
    publish = manifest.get("publishConfig") or {}
    if publish.get("access") != "public":
        problems.append("a scoped package is published restricted unless publishConfig.access is public")
    if publish.get("provenance") is not True:
        problems.append("publishConfig.provenance is not true, so a publish would carry no provenance")
    repository = manifest.get("repository")
    url = repository.get("url") if isinstance(repository, dict) else repository
    if url != REPOSITORY:
        problems.append(
            f"repository.url is {url!r}; the provenance statement binds to {REPOSITORY!r}"
        )
    for script in sorted(INSTALL_SCRIPTS & set(manifest.get("scripts") or {})):
        problems.append(f"the manifest has a {script} script, which would run on every consumer's install")
    for field in ("main", "types", "exports"):
        if field not in manifest:
            problems.append(f"the manifest declares no {field}")
    declared = set()
    for field in ("main", "types", "exports"):
        declared.update(targets(manifest.get(field)))
    for target in sorted(declared):
        path = target[2:] if target.startswith("./") else target
        if path.endswith("/*") or "*" in path:
            prefix = path.split("*")[0]
            present = any(member.startswith(prefix) for member in members)
        else:
            present = path in members
        if not present:
            problems.append(f"the manifest points at {target}, which the archive does not hold")
        if path.endswith((".ts", ".tsx")) and not path.endswith(".d.ts"):
            problems.append(f"{target} is TypeScript source, which a consumer's Node cannot load")
    return problems


# The scripts pnpm leaves out of the manifest it packs, and only those: they run where a package is
# made or published, and a consumer of the archive never runs them. pnpm keeps the install scripts
# and `prepublish` in the manifest, so a difference in one of those is a difference in what a
# consumer runs and is never normalised away.
LIFECYCLE = {"prepack", "postpack", "prepare", "prepublishOnly", "publish", "postpublish"}

# The scripts a consumer's install would run. A published SDK has none.
INSTALL_SCRIPTS = {"preinstall", "install", "postinstall"}


def without_lifecycle(manifest):
    kept = dict(manifest)
    if "scripts" in kept:
        kept["scripts"] = {k: v for k, v in kept["scripts"].items() if k not in LIFECYCLE}
    return kept


def compare_problems(archive, npm):
    problems = []
    for path in sorted(set(archive) | set(npm)):
        if path == "package.json":
            continue
        if path not in npm:
            if path not in ARCHIVE_ONLY:
                problems.append(f"{path} is in the release archive and npm would not publish it")
        elif path not in archive:
            problems.append(f"{path} is what npm would publish and the release archive lacks it")
        elif archive[path][0] != npm[path][0]:
            problems.append(f"{path} differs: release {archive[path][0]}, npm {npm[path][0]}")
        elif archive[path][1] != npm[path][1]:
            problems.append(f"{path} differs in its executable bit")
    if without_lifecycle(manifest_of(archive, "the release archive")) != without_lifecycle(
        manifest_of(npm, "npm's archive")
    ):
        problems.append("the two manifests are different documents")
    return problems


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(f"$ {' '.join(command)}\n{result.stdout}{result.stderr}")
        raise SystemExit(f"{command[0]} exited {result.returncode}")
    return result.stdout


def npm_pack(source, destination):
    """Packs the package directory with npm, which runs the package's own prepack first."""
    listing = json.loads(run(["npm", "pack", "--json", "--pack-destination", destination],
                             cwd=source))
    return os.path.join(destination, listing[0]["filename"])


def published_package(document):
    """Returns the package record of an `npm publish --json` answer.

    npm 10 prints the record itself; npm 11 prints it under the package's own name. Either way what
    comes back names the package and its version, or it is empty and the caller refuses.
    """
    if isinstance(document, dict) and "name" not in document and len(document) == 1:
        (inner,) = document.values()
        if isinstance(inner, dict):
            return inner
    return document if isinstance(document, dict) else {}


def dry_run_publish(archive):
    """Asks npm whether it would publish the archive, which needs no login."""
    output = run(["npm", "publish", os.path.abspath(archive), "--dry-run", "--json"])
    return published_package(json.loads(output))


def load_problems(archive_path, source):
    """Installs the archive where a consumer's Node finds it and imports it by its name."""
    with tempfile.TemporaryDirectory(prefix="kalareach-consumer-") as scratch:
        modules = os.path.join(scratch, "node_modules")
        installed = os.path.join(modules, "@kalareach", "plugin-sdk")
        os.makedirs(installed)
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                member.name = member.name[len("package/"):]
                if member.name:
                    archive.extract(member, installed, filter="data")
        # The one dependency the package names, taken from the checkout's own install.
        ajv = os.path.realpath(os.path.join(source, "node_modules", "ajv"))
        os.symlink(ajv, os.path.join(modules, "ajv"))
        program = (
            "const sdk = await import('@kalareach/plugin-sdk');"
            "const schema = await import('@kalareach/plugin-sdk/schema/package-contract.json',"
            " { with: { type: 'json' } });"
            "if (typeof sdk.validatePluginManifest !== 'function') throw new Error('no validator');"
            "if (typeof sdk.sdkVersion !== 'string') throw new Error('no sdk version');"
            "if (schema.default.sdk_version !== sdk.sdkVersion) throw new Error('schema mismatch');"
        )
        result = subprocess.run(["node", "--input-type=module", "-e", program], cwd=scratch,
                                capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return [f"a consumer cannot import the archive: {result.stderr.strip()[-400:]}"]
    return []


def check(archive_path, source):
    problems = []
    archive = read_archive(archive_path)
    manifest = manifest_of(archive, archive_path)
    problems += manifest_problems(manifest, archive)
    with tempfile.TemporaryDirectory(prefix="kalareach-npm-") as scratch:
        packed = read_archive(npm_pack(source, scratch))
        problems += compare_problems(archive, packed)
        problems += manifest_problems(manifest_of(packed, "npm's archive"), packed)
        problems += load_problems(archive_path, source)
        published = dry_run_publish(archive_path)
        if published.get("name") != manifest.get("name") or (
            published.get("version") != manifest.get("version")
        ):
            problems.append(
                f"npm would publish {published.get('name')} {published.get('version')}, "
                f"not {manifest.get('name')} {manifest.get('version')}"
            )
    return problems


def self_test():
    """Runs the check on the source tree's own package and on each way it must refuse."""
    source = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "packages", "plugin-sdk"))
    failures = []
    refusals = 0

    def expect(label, problems, wanted):
        nonlocal refusals
        if wanted is not None:
            refusals += 1
        if wanted is None:
            if problems:
                failures.append(f"{label}: expected a pass, got {problems}")
        elif not any(wanted in problem for problem in problems):
            failures.append(f"{label}: expected a refusal naming {wanted!r}, got {problems}")

    # The two shapes of npm's dry-run answer, and one that names no package.
    record = {"id": "@kalareach/plugin-sdk@0.50.0", "name": "@kalareach/plugin-sdk", "version": "0.50.0"}
    for label, document in (("npm 10's answer", record), ("npm 11's answer", {record["name"]: record})):
        if published_package(document).get("name") != record["name"]:
            failures.append(f"{label} was not read as the package record")
    if published_package({"error": {"code": "E401"}}).get("name") is not None:
        failures.append("an answer that names no package was read as one")

    with tempfile.TemporaryDirectory(prefix="kalareach-npm-self-") as scratch:
        pnpm_dir = os.path.join(scratch, "pnpm")
        os.makedirs(pnpm_dir)
        run(["pnpm", "pack", "--pack-destination", pnpm_dir], cwd=source)
        (name,) = os.listdir(pnpm_dir)
        good = os.path.join(pnpm_dir, name)

        expect("the unedited archive", check(good, source), None)

        def rewritten(label, edit):
            """Repacks the good archive with one edit to its members and returns its path."""
            members = read_archive(good)
            edit(members)
            path = os.path.join(scratch, f"{label}.tgz")
            with tarfile.open(path, "w:gz") as out:
                for member_path, (_, executable, data) in sorted(members.items()):
                    info = tarfile.TarInfo(f"package/{member_path}")
                    info.size = len(data)
                    info.mode = 0o755 if executable else 0o644
                    out.addfile(info, io.BytesIO(data))
            return path

        def flip_a_byte(members):
            digest, executable, data = members["dist/src/index.js"]
            edited = bytearray(data)
            edited[-1] ^= 0x01
            members["dist/src/index.js"] = (None, executable, bytes(edited))

        expect("a byte changed in a published file",
               check(rewritten("byte", flip_a_byte), source), "dist/src/index.js differs")

        def add_a_file(members):
            members["dist/extra.js"] = (None, False, b"export {}\n")

        expect("a file the release carries and npm would not",
               check(rewritten("extra", add_a_file), source), "dist/extra.js is in the release")

        def drop_a_file(members):
            del members["wit/kalareach-plugin.wit"]

        expect("a file npm would publish and the release lacks",
               check(rewritten("dropped", drop_a_file), source), "the release archive lacks it")

        def edit_manifest(**changes):
            def edit(members):
                manifest = json.loads(members["package.json"][2])
                manifest.update(changes)
                members["package.json"] = (None, False, json.dumps(manifest).encode())
            return edit

        expect("a private package",
               check(rewritten("private", edit_manifest(private=True)), source), "marked private")
        expect("a restricted package",
               check(rewritten("restricted", edit_manifest(publishConfig={"provenance": True})),
                     source), "publishConfig.access")
        expect("a package with no provenance",
               check(rewritten("noprov", edit_manifest(publishConfig={"access": "public"})),
                     source), "no provenance")
        expect("another repository",
               check(rewritten("repo", edit_manifest(
                   repository={"type": "git", "url": "git+https://github.com/other/other.git"})),
                     source), "repository.url")
        def with_scripts(**scripts):
            def edit(members):
                manifest = json.loads(members["package.json"][2])
                manifest["scripts"] = dict(manifest.get("scripts") or {}, **scripts)
                members["package.json"] = (None, False, json.dumps(manifest).encode())
            return edit

        expect("an install script added to the release archive",
               check(rewritten("postinstall", with_scripts(postinstall="node steal.js")), source),
               "postinstall script")
        expect("a prepublish script the two archives disagree on",
               check(rewritten("prepublish", with_scripts(prepublish="node steal.js")), source),
               "different documents")
        expect("TypeScript source as the entry point",
               check(rewritten("source", edit_manifest(main="./dist/src/index.ts")), source),
               "which the archive does not hold")

    if failures:
        sys.stderr.write("\n".join(failures) + "\n")
        return 1
    print(f"check-release-npm self-test: the unedited archive passes and each of {refusals} faults is refused")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check", help="hold one release archive to npm's own pack")
    checking.add_argument("--archive", required=True, help="the release's SDK archive")
    checking.add_argument("--source", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "packages", "plugin-sdk"),
        help="the package directory of the commit the archive was packed from")
    commands.add_parser("self-test", help="put the check through a pass and its refusals")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        return self_test()

    problems = check(arguments.archive, os.path.abspath(arguments.source))
    if problems:
        sys.stderr.write("The release archive and npm's own pack disagree:\n")
        for problem in problems:
            sys.stderr.write(f"  {problem}\n")
        return 1
    print("npm would publish exactly the release archive's contents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
