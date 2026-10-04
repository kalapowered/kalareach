# Released package manifests

Copies of the manifests of released connector packages, held here so the host's command integration
is tested against the declarations a real release makes rather than against ones a test made up.

| | |
| --- | --- |
| Source | `kalareach-plugins`, `snapshots/development/targets/packages/kalareach/<package>/<version>/plugin.json` |
| Commit | `9f003bb6b31899e0c59b6e24d0b10756a16ff7ab` |
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
