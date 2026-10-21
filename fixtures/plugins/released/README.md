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
| Commit | `6029c7845a1a16f3c6ef27097818848ad9641960`, the revision the manifest's `source.revision` names |
| Files | `plugin.json`, `connector.json`, `presentation.json`, `README.md`, `fixtures/conformance.json`, `fixtures/frames.json` |
| Package hash | `a37d8d7eaf63f8502ae2da2e57a39784a01a159426060aca53a48647d30b928f`, the SHA-256 digest of `plugin.json` |

Each file is byte for byte what the plugins repository holds, and the manifest names every other
file by digest, so the package check refuses a copy that differs. Where a checkout of the plugins
repository sits beside this one, `crates/kr-worker/tests/bundled_codex.rs` also compares each file
with the repository's. The worker's in-process cases keep using the Codex-shaped test package under
`crates/kr-worker`, which stays until this package is the one a host ships.

