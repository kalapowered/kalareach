# The release manifest and the release record

A release is a tree of regular files: `bin/` with the host's programs, `shells/` with the qualified
shell packages, `share/` with the update channel's root and the release record, and `release.json`.
`release.json` is the release's manifest in the signed envelope of
[the update documents](../host/updates.md#what-a-release-is-and-how-it-is-checked). This page says
what each member of the manifest states, where its value is read from, and what stops a release
from being written or signed. `kr-release` (`crates/kr-release`) writes the manifest and the record
and signs the manifest, and the host verifies it with the same code, so a signature that verifies
for one verifies for the other.

A tree holds no link, no file with a second name, no device and no empty directory: an archive
writes a second name as a link, and a host refuses an archive that holds one. A file is a program
when it is one of the host's programs in `bin/` (`scripts/release-programs.json` lists them) or a
file in a shell package's own `bin/`; the file system of the machine that built the tree is not
asked.

## The members

| Member | What it states | Where it is read from |
| --- | --- | --- |
| `release`, `sequence`, `commit`, `target`, `os_floor` | What the release is, where it stands among releases, the commit it was built from, its target and the oldest system it runs on | The command's arguments, which the release workflow gives it |
| `protocol_version` | The protocol package version the programs were built from | The version `kr-release` was built with, which is the commit's |
| `public_majors` | The public protocol majors the host accepts from a device | The table of public majors of the same build: every major that is not retired. The major the control daemon states is in it |
| `retained_levels` | The compatibility levels the control daemon speaks to a worker at | The levels the same build retains, its own first |
| `shells` | What each shell package is made of | The package in the tree and the repository's pins for the shell (below) |
| `agents` | The executable builds of supported agents the release is qualified against, with the capabilities each opens | The bundled signed plugin index (below) |
| `dependencies` | The cryptographic libraries the release is built with, as resolved | `Cargo.toml` and `Cargo.lock` (below) |
| `stores` | Every store the programs read, with the version each writes and the lowest it brings forward | `stored-formats.lock` |
| `files` | Every file but the manifest, with its length, SHA-256 digest and whether it is a program | The tree |

A reader reads past a member it does not know, and the signature covers the manifest whole, so a
member a later release adds is checked by the host that reads past it. Every member above is
required: a manifest that leaves one out is not read, so a tool that forgets what a release owes
its readers cannot sign one.

## Shell packages

`shells/<shell>/<identity>/` holds a package as `scripts/build-shells.sh` installed it, with the
identity record the build wrote, and `shells/<shell>/current` names the identity. For each package
the manifest states:

- `upstream`: the shell's version, the upstream revision the patches apply to, the archive and its
  SHA-256 digest, from `shells/<shell>/manifest.json`.
- `patches`: each reader patch in the order it is applied, with its own revision, the upstream
  revision it was applied to (`base_revision`, the package's own), the digest of the patch file
  and, where the patch is a published upstream change, the upstream commit it was taken from
  (`source_commit`). The two upstream revisions are kept apart: the terminfo patch of the Zsh
  package is taken from upstream commit `4c89849c98172c951a9def3690e8647dae76308f` and applied to
  `zsh-5.9`.
- `sources`: the bridge sources the package adds to the shell, each with its digest.
- `modules`: each module the shell loads, the directory it searches for it, relative to the
  release, and the editor ABI the module was built for. A package that loads no module lists none.
- `profile_order`: for a login shell and for an interactive one, the arguments the host starts the
  shell with and the startup files that hold the package's marked entry, each with where in the
  file the entry goes and the lines that open and close it.

The arguments name no option that skips or replaces a startup file of the person's (`-f`,
`--norc`, `--noprofile`, `--rcfile`), so every startup file runs in the order the shell reads them
and the entry runs among them. A person who moves a startup directory moves the entry with it, and
the location says so in the shell's own words (`${ZDOTDIR:-$HOME}/.zshrc`). The member is made from
the host's own tables of where it puts an entry, so a change to one is a change to the other.
The qualification corpus drives each shell through its startup files and holds the order it records
to the order they ran in.

### What refuses a package

`kr-release` refuses a tree, before a manifest is written and again before it is signed, when a
package:

- was built from another upstream archive than the pins name, with a patch of another revision or
  another base revision, or with other patches than the pins list;
- was built from other inputs than the checkout holds: the build script, the manifest, a patch, a
  source or the startup entry, each compared with the digest the build recorded;
- carries a startup entry that is not the checkout's;
- lists a module whose directory is missing or empty, or built for another editor ABI;
- names a directory outside the package for a module;
- is not a package a worker can read, as the worker reads one.

A `release.json` that is not what the tree and the repository make now is not signed. Editing a
member after the manifest was written, or a file after the manifest listed it, is refused at that
step, and a host refuses it again when it installs the tree.

A package that has moved from where it was built is the package it was. The worker declares it as
the build recorded it, and the shell says the same of itself, so a package under
`versions/<release>/shells/` starts a managed session where it is; the files the worker opens are
named where the package sits. The Zsh package finds its modules from where its executable is
(`shells/zsh/patches/0005-module-paths-from-executable.patch`), through the search path the
manifest names.

## Agents

The signed plugin index at the commit the bundled catalogue was taken from names, for an entry
whose record passed every part of the version qualification, each executable build by application,
distribution, version, operating system, architecture and digest. The manifest lists the builds
for its own target with the capabilities of the entry that names them. A named build opens every
capability its release declares, and the index carries no schema hash for a build today, so the
member is omitted until a record supplies one. The index names no build yet, so `agents` is empty.
`kr-release` reads the index only when it is the one the bundled metadata pins.

## Dependencies

| Library | Pinned in `Cargo.toml` |
| --- | --- |
| `libsodium-sys-stable` | `=1.24.0` |
| `hkdf` | `=0.13.0` |
| `hmac` | `=0.13.0` |
| `sha2` | `=0.11.0` |
| `subtle` | `=2.6.1` |
| `zeroize` | `=1.9.0` |
| `keyring` | `=4.2.0` |
| `spake2` | `=0.4.0` |

The manifest states each library's version and registry checksum, every crate the lock resolves it
to with its version and checksum, the digest of `Cargo.lock`, and the digest of each pairing vector
under `fixtures/pairing/`. The versions are read from `Cargo.toml` and the lock, and must be the
versions [the cryptography reference](../crypto/README.md#release-manifest) and
[the pairing reference](../pairing/README.md#release-manifest) name: a pin that moves without its
documents stops the manifest. A crate in a pinned library's graph without a registry checksum
stops it too.

## The release record

`share/release-record.json` lists what the release was qualified against, by digest, and the
manifest lists the file, so its signature covers the record. `docs/releases/records.json` is where
the classes are written down.

| Class | Cited |
| --- | --- |
| Vendor routes | The plugins repository's qualification notes at the commit the bundled catalogue was taken from |
| Dependency and runtime revisions | `Cargo.toml`, `Cargo.lock`, the toolchain file, each shell's pins, the stack pins, the bundled catalogue's lock and the lock of stored formats |
| Model assets | Each model profile with its model, conversion and runtime revisions and the digest of each asset |
| Provider event schemas | The voice providers' profiles and their digests, in the web repository at a pinned commit |
| Service limits | The managed service's limits, in the web repository at a pinned commit |

A class is recorded, unavailable or pending. A recorded class lists each record with the
repository, revision, path and digest. A record in this checkout is read and digested when the
record is made. A record in another repository is checked against its digest when that repository
is at hand (`--plugins`, `--web`) and cited by it when it is not, and the record says which. An
unavailable class names the capability the release leaves off and why. A pending class is allowed
in a run that proves the pipeline and refused in a release: `kr-release` stops a record that has
one unless it is told it is a development run.

Every capability the release enables by evidence cites the qualification records of the plugin
that declares it. A listed build whose plugin cites none stops the record, so a release cannot
enable a capability on no evidence. A record that is missing, or is not the one cited, stops it.

## Building and signing a release

```sh
kr-release record   --tree T --checkout C --target TRIPLE [--plugins DIR] [--web DIR]
kr-release manifest --tree T --checkout C --release R --sequence N --commit SHA --target TRIPLE --floor macos=14.0
kr-release sign     --tree T --checkout C --key KEY... [--plugins DIR] [--web DIR]
kr-release verify   --tree T --root ROOT
```

The tree is complete, and every step that changes a file has run, before the manifest is written:
the platform's signature changes the bytes the manifest's digests cover. `sign` assembles the
manifest again, refuses a `release.json` that is not what the tree makes, and signs it with each
key. The channel's root names the keys that may sign and how many must; a release signed by one
key of a two-key threshold, or by one key described twice, does not verify, and a root that names
one key under two identifiers in a role is refused. `verify` is a host's own check of a release:
the signatures against the root, then every file against the manifest.

`kr-release dev-keys --out DIR` makes a root and the keys for it. A run that proves the pipeline
signs with those and throws them away with the run; the channel's own keys are in hardware and on
offline media, never in a tree, an archive or a repository.
