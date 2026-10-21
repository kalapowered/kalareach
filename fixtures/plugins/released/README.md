# Released package manifests

Copies of the manifests of released connector packages, held here so the host's command integration
is tested against the declarations a real release makes rather than against ones a test made up.

| | |
| --- | --- |
| Source | `kalareach-plugins`, `snapshots/development/targets/packages/kalareach/<package>/<version>/plugin.json` |
| Commit | `bb50ebb41f7ebe4e5fb8cb388b816c849007306d` |
| Packages | `claude-code`, `gemini-cli` and `qoder-cli`, each at 0.5.0 |

## What it is

Each file is the manifest byte for byte. A package's hash is the SHA-256 digest of its manifest, and
the manifest names every other file of the package by digest, so these three files are the package
identities an owner confirms when installing those releases. The rest of each package is not copied:
these files pin what each release declares, not a whole package a host could install.

`crates/kr-hook/tests/fixtures.rs` pins each file by that digest, checks that its command
integration is one the package contract accepts, and checks that Qoder CLI's flags are the two
elements in `fixtures/bridges/qoder-cli/flags.json`. The worker's test packages take their command
integrations from these files, so the worker's and the launcher's tests run with the declarations
the releases make.

## How it changes

By a deliberate re-copy, and no other way. Nothing in this repository writes into this directory,
and no test regenerates it. A new release is copied from a named commit of the plugins repository
into a directory named for its version, with the commit in the table above and the digests in the
suite changed in the same change.

## The whole Codex package

`kalareach/codex/0.3.0/` is a different kind of copy: every file of the package, not only its
manifest, so a host can install it and the gateway's whole path runs on what the release declares.

| | |
| --- | --- |
| Source | `kalareach-plugins`, `plugins/kalareach/codex/` |
| Commit | `782f32d6a5d3f74f1f00c27f60c37b85e0928ce7`, the commit of the plugins repository these files are copied from; the manifest's `source.revision` names `cb39424b9bf23de38b91d6cbc787d4824439877d`, the commit that holds the package's other five files |
| Files | `plugin.json`, `connector.json`, `presentation.json`, `README.md`, `fixtures/conformance.json`, `fixtures/frames.json` |
| Package hash | `5e252bd9f93856fd03c5ff4d3a2a4359dd1f4a1d663ab9d0b18479441dc0cd4b`, the SHA-256 digest of `plugin.json` |

Each file is byte for byte what the plugins repository holds, and the manifest names every other
file by digest, so the package check refuses a copy that differs. Where a checkout of the plugins
repository sits beside this one, `crates/kr-worker/tests/bundled_codex.rs` also compares each file
with the repository's. The worker's in-process cases keep using the Codex-shaped test package under
`crates/kr-worker`, which stays until this package is the one a host ships.

