# KalaReach package releases

`@kalareach/protocol` and `@kalareach/plugin-sdk` are generated from the Rust types in this
repository and published as immutable archives attached to a GitHub release. A consumer pins one
archive by its URL and its integrity, so its lockfile records exactly which bytes it installs and
where they came from. There is no registry entry, no path dependency on a neighbouring checkout and
no Git dependency on a branch. The archives are public downloads, so installing a consumer needs no
credential for this repository.

What these digests establish is byte integrity: that an archive is the one the release published.
They are not signatures, and they say nothing about who published it. Release signing and its keys
belong to the signed host and client packages, which are a separate release path.

## What a release carries

| Asset | What it is |
| --- | --- |
| `kalareach-protocol-<version>+<commit>.tgz` | The protocol package: the generated types, the type declarations, the JSON Schema, the KR-CBOR-1 codec, the conformance vectors under `fixtures/` for the `accounts`, `cbor`, `crypto`, `pairing`, `protocol`, `push` and `service` areas, and a `provenance.json` naming the commit it was packed from |
| `kalareach-plugin-sdk-<version>+<commit>.tgz` | The plugin SDK package: the manifest types, the package contract as data, the JSON Schema and the published WIT file |
| `SHA512SUMS` | The sha512 of each archive, in the format `sha512sum -c` reads, and above it the same digest in the `sha512-<base64>` form a lockfile records as an integrity |

`<commit>` is the first twelve characters of the commit the archives were packed from. Both packages
carry the same version, because one release publishes one version of both.

The vector areas the protocol package carries are the ones for the types and the codec it publishes.
`fixtures/relay` is not among them: the relay lease and receipt types are checked in this repository
and in the relay implementation, and a consumer that needs those vectors reads them from a checkout
rather than from this package.

## How a release is cut

A release is one commit's output. Tag that commit and push the tag:

```bash
commit=$(git rev-parse HEAD)
version=$(node -p "require('./packages/protocol/package.json').version")
git tag "packages/v${version}+${commit:0:12}" "$commit"
git push origin "packages/v${version}+${commit:0:12}"
```

The version comes out of the package rather than being typed, so a bump cannot leave this naming
the version before it.

`.github/workflows/package-release.yml` runs on a tag matching `packages/v*`. It packs the archives
with `scripts/release-packages.sh`, refuses to go on if that tag already has a release or a draft,
attaches the archives and `SHA512SUMS` to a draft, and publishes the draft only once GitHub's record
of every asset, down to the sha256 GitHub computed over the bytes it stored, matches what was packed.
Publication then confirms that the release cannot be replaced, and the last step fetches each asset
back from the URL GitHub serves it at, holds it to the packed sha512, and writes those URLs into the
notes.

The script is what makes the release that commit's output rather than a working tree's:

- it refuses a tree with uncommitted or untracked changes, and refuses a tag that does not name this
  commit at this version;
- it asks each generator whether the committed schema, TypeScript types, WIT package and
  conformance vectors are still what it produces, so an archive never carries output that has
  drifted from the Rust types it came from;
- it packs from a fresh checkout of the commit, taking the committed bytes with no line-ending
  conversion from a setting or from an attribute file outside the commit, because a working tree
  also holds files Git ignores, pnpm packs what is inside a published directory whether Git ignores
  it or not, and it packs the bytes it finds;
- it refuses a configured `pack-gzip-level`, which changes the compressed bytes, `ignore-scripts`,
  which would skip the step that generates most of what the protocol package publishes,
  `skip-manifest-obfuscation`, which changes the manifest written into the archive, and a configured
  `pnpmfile` or `global-pnpmfile`, which can rewrite that manifest from outside the commit;
- it packs each archive twice and compares the two, then asks each archive what it contains, against
  what the package in the checkout publishes rather than against the archive's own manifest: a file
  under every published path, the file behind every entry point, those declarations unchanged, a
  manifest naming that package and version, and a provenance file naming this commit;
- it names each archive after the commit and writes `SHA512SUMS` beside them, and nothing reaches
  the output directory until all of that has passed.

Run it before tagging to see exactly what a release would carry:

```bash
bash scripts/release-packages.sh --output /tmp/kalareach-packages
```

It needs the pinned Rust toolchain for the generators, and pnpm for the install and the pack.

A published archive is never replaced. Turn on the repository's immutable-releases setting before
cutting the first release, so that GitHub holds to that rather than a convention holding to it: a URL
a consumer pinned then keeps resolving to the bytes its lockfile recorded, whoever has write access.
The workflow fails right after publishing when the release it published turns out to be replaceable.

Immutability is about replacement and not about availability: a whole release can still be deleted,
and the tag of a deleted immutable release cannot be used again. So a published release stays where
it is, and a mistake is corrected by releasing a new commit under its own tag. A run that failed
before publishing is the other case: it leaves a draft, and once that draft is deleted the same tag
can be released again by re-running the run that failed, because pushing a tag that is already on
the remote produces no event at all.

## How a consumer pins a release

Each asset URL is the one the release notes list, and the one GitHub reports for that asset. It
takes this shape, with parts of the tag percent-encoded:

```
https://github.com/kalapowered/kalareach/releases/download/packages/v<version>+<commit>/<asset>
```

Ask for that URL in the dependent package's `package.json`:

```json
{
  "dependencies": {
    "@kalareach/protocol": "https://github.com/kalapowered/kalareach/releases/download/packages/v0.2.0+0123456789ab/kalareach-protocol-0.2.0+0123456789ab.tgz"
  }
}
```

Then install so the lockfile records the resolution:

```bash
pnpm install --no-frozen-lockfile
```

pnpm writes the URL and the archive's digest into the lockfile as
`resolution: {integrity: sha512-…, tarball: <the URL>}`. Every later `pnpm install
--frozen-lockfile` installs that resolution and nothing else: it refuses to change the lockfile, and
an archive it has to download is refused unless it hashes to the recorded integrity. An install
whose store already holds that archive does not download it again, which is why the integrity is
recorded rather than checked once at pin time. The URL says where, and the integrity says what.

Check the integrity the lockfile recorded against the release's `SHA512SUMS` before committing it.
The two must agree; when they do not, the lockfile was written against something other than the
release it names.

## Verifying an archive

From the directory holding the downloaded assets, with GNU `sha512sum` or with `shasum -a 512`:

```bash
grep -v '^#' SHA512SUMS | sha512sum -c -
```

The `grep` drops the header lines, which carry the `sha512-<base64>` integrity forms as comments;
some implementations report a comment line as improperly formatted rather than skipping it.

The protocol archive also names its origin from the inside:

```bash
tar -xzOf kalareach-protocol-<version>+<commit>.tgz package/provenance.json
```

`core_commit` there is the commit the archive was packed from. It is an unsigned statement the
archive makes about itself, so what it gives a consumer is a consistency check between the archive,
its file name and the commit that consumer pinned, not independent proof of where the archive came
from. The plugin SDK archive carries no such file; its commit is the one in the release tag and in
its own name.

## Reproducing a release

The archive layout is pnpm's: members in a fixed order under a fixed timestamp, with fixed
permissions and no machine identity. What is left is the environment, and the script narrows it: the
checkout takes the committed bytes with no line-ending conversion, and a configured value for any of
the pnpm settings the script lists is refused rather than packed under. The double pack inside one
run catches something that varies from moment to moment; it says nothing about another machine, which
is what the pinned Node and pnpm versions are for.

To reproduce a release, use a fresh checkout of its commit, the pnpm version in the root
`package.json`'s `packageManager` field, and the Node version the release workflow installs. Where
the digests differ, compare the two archives member by member before concluding anything about the
release: the record of what a release published is the `SHA512SUMS` attached to it, which is what a
consumer verifies against.

## What a version bump requires

Both packages carry one version, and one tag publishes both.

Bump the version when the generated output changes in a way a consumer cannot take without changing
its own code. That includes a type or export that was removed or renamed, a field whose shape
changed, an optional field that became required, and a new variant in a closed union, which breaks
any consumer that handles the previous variants exhaustively. While the version is below `1.0.0`
that is a minor bump. A change that only adds an independent type keeps the version; the commit in
the tag and in each archive's name already tells two releases apart.

Counting exported names does not establish compatibility: the names can be identical while a union
or a field beneath them has changed. Read the diff of `packages/protocol/src/generated/protocol.ts`
and `packages/plugin-sdk/src/generated/plugin-sdk.ts`.

A bump is one commit that changes the `version` in `packages/protocol/package.json` and
`packages/plugin-sdk/package.json` together. A consumer then moves its URL, its lockfile integrity
and the commit it names in its own documentation, in one commit of its own.
