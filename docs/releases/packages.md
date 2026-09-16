# KalaReach package releases

`@kalareach/protocol` and `@kalareach/plugin-sdk` are generated from the Rust types in this
repository and published as immutable archives attached to a GitHub release. A consumer pins one
archive by its URL and its integrity, so its lockfile records exactly which bytes it installs and
where they came from. There is no registry entry, no path dependency on a neighbouring checkout and
no Git dependency on a branch. The archives are public downloads, so installing a consumer needs no
credential for this repository.

## What a release carries

| Asset | What it is |
| --- | --- |
| `kalareach-protocol-<version>+<commit>.tgz` | The protocol package: the generated types, the type declarations, the JSON Schema, the KR-CBOR-1 codec and the cross-language conformance vectors for the types it publishes, plus a `provenance.json` naming the commit it was packed from |
| `kalareach-plugin-sdk-<version>+<commit>.tgz` | The plugin SDK package: the manifest types, the package contract as data, the JSON Schema and the published WIT file |
| `SHA512SUMS` | The sha512 of each archive, in the format `sha512sum -c` reads, and above it the same digest in the `sha512-<base64>` form a lockfile records as an integrity |

`<commit>` is the first twelve characters of the commit the archives were packed from. Both packages
carry the same version, because one release publishes one version of both.

## How a release is cut

A release is one commit's output. Tag that commit and push the tag:

```bash
commit=$(git rev-parse HEAD)
git tag "packages/v0.1.0+${commit:0:12}" "$commit"
git push origin "packages/v0.1.0+${commit:0:12}"
```

`.github/workflows/package-release.yml` runs on any tag under `packages/`, packs the archives with
`scripts/release-packages.sh`, creates the release for that tag with the two archives and
`SHA512SUMS` attached, then fetches each asset back by its published URL and holds it to the digests
that were packed.

The script is what makes the release that commit's output rather than a working tree's:

- it refuses a tree with uncommitted or untracked changes, and refuses a tag that does not name this
  commit at this version;
- it asks each generator whether the committed schema, TypeScript types, WIT package and
  conformance vectors are still what it produces, so an archive never carries output that has
  drifted from the Rust types it came from;
- it packs each archive twice and compares the two, so the digests it publishes describe the commit
  and not one run;
- it names each archive after the commit and writes `SHA512SUMS` beside them.

Run it before tagging to see exactly what a release would carry:

```bash
bash scripts/release-packages.sh --output /tmp/kalareach-packages
```

It needs the pinned Rust toolchain for the generators, and pnpm for the install and the pack.

A release is created once. Pushing the same tag again, or re-running its workflow, fails because the
release exists: a published archive is never replaced, and a mistaken release is deleted together
with its tag before a corrected one is cut.

## How a consumer pins a release

An asset URL has one form:

```
https://github.com/kalapowered/kalareach/releases/download/packages/v<version>+<commit>/<asset>
```

Ask for that URL in the dependent package's `package.json`:

```json
{
  "dependencies": {
    "@kalareach/protocol": "https://github.com/kalapowered/kalareach/releases/download/packages/v0.1.0+0123456789ab/kalareach-protocol-0.1.0+0123456789ab.tgz"
  }
}
```

Then install so the lockfile records the resolution:

```bash
pnpm install --no-frozen-lockfile
```

pnpm writes the URL and the archive's digest into the lockfile as
`resolution: {integrity: sha512-…, tarball: <the URL>}`. Every later
`pnpm install --frozen-lockfile` downloads that URL and refuses the archive unless it hashes to that
integrity, which is the property that makes the pin worth anything: the URL says where, the
integrity says what.

Check the integrity the lockfile recorded against the release's `SHA512SUMS` before committing it.
The two must agree; when they do not, the lockfile was written against something other than the
release it names.

## Verifying an archive

From the directory holding the downloaded assets:

```bash
grep -v '^#' SHA512SUMS | sha512sum -c -
```

The `grep` drops the header, which carries the `sha512-<base64>` integrity forms as comments; every
checksum tool then reads the rest.

The protocol archive also names its origin from the inside:

```bash
tar -xzOf kalareach-protocol-<version>+<commit>.tgz package/provenance.json
```

`core_commit` there is the commit the archive was packed from, so a consumer that pins a commit can
confirm the archive is that commit rather than trusting a file name. The plugin SDK archive carries
no such file; its commit is the one in the release tag and in its own name.

## Reproducing a release

From a clean checkout at the release's commit, with the pnpm version in the root `package.json`'s
`packageManager` field and the Node version the release workflow installs, `release-packages.sh`
produces archives with the same digests as the release. The archive format belongs to pnpm, so a
different pnpm or Node may pack the same files into different bytes; that is why both are pinned and
why the sums are published with the release rather than derived on the fly.

## What a version bump requires

Both packages carry one version, and one tag publishes both.

Bump the version when the generated output changes in a way a consumer cannot take without changing
its own code: a type or export that was removed or renamed, a field whose shape changed, an optional
field that became required. While the version is below `1.0.0` that is a minor bump. A change that
only adds keeps the version; the commit in the tag and in each archive's name already tells two
releases apart.

A bump is one commit that changes the `version` in `packages/protocol/package.json` and
`packages/plugin-sdk/package.json` together. A consumer then moves its URL, its lockfile integrity
and whatever it pins the commit in its own documentation to, in one commit of its own.
