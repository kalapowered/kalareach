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
member a later release adds is checked by the host that reads past it. A reader also takes a
manifest that lacks what a later release added, since `kr host rollback` and the helpers' pins read
the manifest of an earlier release: `agents`, `dependencies` and the members of a shell entry beyond
its `shell`, `identity` and `patch_revisions` may be absent. The rest is required. `kr-release`
writes every member and refuses to sign a `release.json` that is not what the tree makes, so a tool
that forgets what a release owes its readers cannot sign one.

## Shell packages

`shells/<shell>/<identity>/` holds a package as `scripts/build-shells.sh` installed it, with the
identity record the build wrote, and `shells/<shell>/current` names the identity. For each package
the manifest states:

- `patch_revisions`: the revision of each patch, in the order they are applied. The release before
  package managers requires this member and reads a shell package by it, so every entry keeps it. It
  repeats the revisions of `patches` and is refused when it does not.
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

The member states what the host does and no more: the arguments, which name no option that skips or
replaces a startup file of the person's (`-f`, `--no-rcs`, `--norc`, `--noprofile`, `--rcfile`,
`--no-config`, `-N`), and the files the host puts its entry in. The order the shell reads its own
startup files in is the shell's, and a login Bash reaches `.bashrc` only where its login file
sources it, which is why the host also puts an entry in the first login file. A person who moves a
startup directory moves the entry with it, and the location says so in the shell's own words
(`${ZDOTDIR:-$HOME}/.zshrc`). The member is made from the host's own tables of where it puts an
entry, so a change to one is a change to the other. The qualification corpus drives each shell
through its startup files and holds the order they ran in, which the member does not restate.

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
the classes are written down. The vendor routes cite the plugins repository at the commit
`bundled-plugins.lock` names, so synchronising the bundled catalogue to another commit moves the
citation too, and the record is refused until `records.json` says the new commit and digest.

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
key of a two-key threshold, or by one key described twice, does not verify. A release key is an
Ed25519 key of 32 bytes, the one spelling of a key; a root that names a key of another kind or
size, or one key under two identifiers in a role, is refused. `verify` is a host's own check of a release:
the signatures against the root, then every file against the manifest.

`kr-release dev-keys --out DIR` makes a root and the keys for it. A run that proves the pipeline
signs with those and throws them away with the run; the channel's own keys are in hardware and on
offline media, never in a tree, an archive or a repository.

## Publishing

A `host/v<version>+<commit>` tag starts two workflows: `release-tree.yml` for the four macOS and Linux
targets and `release-windows.yml` for the two Windows targets. In each, a first job settles which
commit the run is about, and every job after it checks that commit out by its identifier and not by
the ref, so a branch that moves while the trees build, or while the signing waits for approval,
cannot change what is built or signed. The next job builds the programs on a runner of the target's
own kind, assembles the tree, signs its manifest with keys of its own, packs it and holds the archive
to what a host stages. It reads no secret and uses no environment, and the archive it keeps says in
its name that it is not a release. The last job signs for release behind the `release-signing` environment: the platform's own signature first (Developer ID and
notarisation on macOS, Authenticode on Windows), then the manifest again, since the first changed the
files, with the channel's release keys. It runs for a tag and the default branch only.

The channel's release keys do not exist yet. They are made at a key ceremony and held in hardware
and on offline media, and no mechanism of this repository gives a run one. So the job that signs
stops at that step on every platform, with the same refusal, and **tagging a host release does not
publish one until the ceremony has been held.** The ceremony belongs to the project owner. A release
that has been published is never changed: a correction is a new commit under its own tag.

## Package managers

`scripts/package-managers.py render` writes a Homebrew cask for macOS, a Homebrew formula for Linux
and a winget portable manifest for Windows from the archives of one release. Each file carries the
address of the archive it installs and the archive's SHA-256, which the script reads from the archive
and never takes from a person. The cask also names the macOS the release's files are built to, the
floor `scripts/check-release-floors.py` holds them to, so Homebrew refuses an older system at the
install and not at the first command. A family renders only when both of its architectures are given.

None of them runs anything after it unpacks the release: Homebrew's `post_install` runs sandboxed,
and a winget portable package has no hook. On macOS and Linux the `kr` that Homebrew puts on the
search path admits its own release instead. Its first command checks the release against the
channel's root as `kr host install` does and puts it in the user's store of releases. Where the
store holds no release yet, that root is the one the release carries, so the first install rests on
the package manager's checksum of the archive; once a release is current, a new one is checked
against the newer of that release's root and the one the host recorded at its last switch. The
command then runs as the store's copy, so the daemon, the workers and the helpers never run from the package manager's directory.
When another release is current, the first command packs the new one as a release archive and hands
it to the current release's `kr` as an update, which switches to it or waits for a live worker as
any update does, and the command goes on with the release that is current. The current release may
be one from before package managers, and it takes an archive as it takes any update, since the
manifest keeps the member that release requires of a shell package. An update that waited leaves its
release staged, and the next command offers it again; one that failed after it staged the release
is not offered again. A release the store keeps already, and no update left staged, or one no newer than the current
release, is not offered again, so a rollback stands. `kr host rollback`, `kr host versions` and
`kr doctor` admit nothing: they run as the store's copy of the release that is current, so a
release that one refuses never holds them back, and a refusal of any other command names that copy.
The store names the package manager in a file of its own, `installer`; the file only records who
admitted the releases, and `current` says which one runs. A release before this one does not know
the file and treats the install as its own. Removing the package removes the package manager's
directory and never touches `versions/`. A Windows host keeps no store of releases, so the winget package's `kr`
runs from the directory winget unpacked the release in. The winget manifest asks for that directory
to go on the search path, because the programs of a release are found beside the one that starts
them, and a link to `kr` in winget's links directory would hide them.

`scripts/check-homebrew-install.sh` installs a release with Homebrew itself from a tap of the run's
own, upgrades it to the next release and removes it, and holds each of those to what the store says.
The tree job runs it for the cask on the macOS runners, and the `formula` job runs it for the formula
on an x86_64 Linux runner of a newer image than the floor-checked build, since Homebrew on an older
one builds a toolchain of its own to install anything. The hosted Arm Linux image carries no Homebrew,
so the formula for Arm Linux is rendered by the same code from the same archives and installed by no
run. A Homebrew in a directory of its own runs the check on a machine that has none to spare. Opening a tap repository and submitting to winget's community
repository are the project owner's to do.
