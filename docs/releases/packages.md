# KalaReach package releases

`@kalareach/protocol` and `@kalareach/plugin-sdk` are generated from the Rust types in this
repository and published as immutable archives attached to a GitHub release. A consumer pins one
archive by its URL and its integrity, so its lockfile records exactly which bytes it installs and
where they came from. A pin is never a registry entry, a path dependency on a neighbouring checkout
or a Git dependency on a branch. The archives are public downloads, so installing a consumer needs no
credential for this repository.

What these digests establish is byte integrity: that an archive is the one the release published.
They are not signatures, and they say nothing about who published it. Release signing and its keys
belong to the signed host and client packages, which are a separate release path.

The Windows half of that path, and the identity behind every signature on it, is in
[docs/releases/windows-signing.md](windows-signing.md).

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
creates a draft, attaches the archives and `SHA512SUMS` to the draft that creation returned, and
publishes it only once GitHub's record of every asset, down to the sha256 GitHub computed over the
bytes it stored, matches what was packed. Publication then confirms that the tag resolves to the
release it just published and that the release cannot be replaced, and the last step fetches each
asset back from the URL GitHub serves it at, holds it to the packed sha512, and writes those URLs
into the notes.

One tag is one run at a time. A second run for a tag that is already being released waits for the
first to finish rather than running beside it, and the run already under way is never cancelled for
the one waiting; when the waiting run's turn comes, it finds whatever the run before it made and
refuses to go on if that is a release or a draft. A first run that failed before creating either
leaves the tag as it found it, and the run that follows releases it. What is guaranteed is that two
runs for one tag never overlap, not that every run gets its turn: GitHub holds one run waiting per
tag, so a third arrival takes the waiting one's place. Nothing is lost when it does, because a run
that has not started has created nothing.
Reading a release moments after writing to it can reach a copy of GitHub's records
that has not caught up, so each of the three reads that follow is attempted up to five times, three
seconds apart, before its answer is taken as the release's state. Repeating them changes nothing:
they are reads, and an answer that is wrong rather than late is still wrong on the last attempt. The
notes are written the same way, and writing the same notes twice leaves the same notes.

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

## Publishing the plugin SDK to the npm registry

Publishing to the npm registry happens at the same time that archives are published, and is
triggered by the same tag. The workflow `.github/workflows/package-npm.yml` is triggered by a tag of
the form `packages/v*`, the same as for the release, and so it will run alongside the release
workflow. It publishes the plugin SDK archive that the release workflow attached to the release,
rather than building a second one. Only the plugin SDK is published, as `@kalareach/plugin-sdk`; the
protocol package is not published to the npm registry. A consumer that pins the release URL, as
described below, still takes its archive from GitHub.

The `package-npm` workflow has two jobs, `check` and `publish`. The `check` job fetches the plugin
SDK archive and `SHA512SUMS` file from the release, and performs a number of checks. Because the
release workflow will be running at the same time, and the release may not be published yet, the job
will wait up to 50 minutes for the release to become available. The job requires the release to be
immutable. The checks confirm that the archive in the release matches the hash listed in
`SHA512SUMS`, and that it matches an archive created by `npm pack` from the same commit. It also
runs `npm publish --dry-run` on the archive to see what npm would publish. Finally, it records the
sha512 of the archive so that it can be checked again in the `publish` job. The `publish` job will
only run if the `check` job is successful, and it will wait until someone has approved the
deployment. It downloads the release again, and refuses any archive whose sha512 is not the recorded
value. It then publishes the archive to the npm registry, using
`npm publish --provenance --access public` to attach provenance information identifying the workflow
and the commit from which it was published. It authenticates to the npm registry using the
workflow's own identity, via OpenID Connect, so this repository holds no npm token.

It is possible to run the workflow on a branch to test the `check` job. In that case, it will not
use an archive from a release, but will use the `scripts/release-packages.sh` script to pack the
checked-out commit, and then run the same checks and the dry run. The `publish` job will fail, due
to the deployment policy on the environment it uses, but it will not run any of its steps, so will
not publish anything.

### The `npm-publish` environment

The `publish` job uses the `npm-publish` GitHub environment, so that a person has to approve the
deployment. The environment has a required reviewer, so that a deployment to it requires approval
from someone, and a deployment policy that only allows it to be used from tags of the form
`packages/v*`. It is separate from the `release-signing` environment used in the Windows release
workflow, which only allows the `main` branch and tags of the form `host/v*`, and which has access
to the signing identity used for signing Windows binaries. An npm publish does not need that signing
identity, and `release-signing` would refuse a `packages/v*` tag anyway, so the npm publish has an
environment of its own. The repository administrator owns `npm-publish` and its reviewers.

### Configuring the package as a trusted publisher

Publishing to the npm registry requires the package to have a trusted publisher configured for the
workflow. The package must exist before it can be configured, so the first publish will need to be
done manually by someone who is an owner of the `@kalareach` organisation. After that, the package
settings on npmjs.com can be used to add a trusted publisher for the workflow, with GitHub Actions
as the provider and these fields:

| Field | Value |
| --- | --- |
| Organisation or user | `kalapowered` |
| Repository | `kalareach` |
| Workflow filename | `package-npm.yml` |
| Environment name | `npm-publish` |
| Allowed actions | `npm publish` |

The `npm stage publish` action will always be allowed, but the `npm dist-tag` action should not be
allowed, because the workflow does not run that command. Trusted publishing needs npm 11.5.1 or
later and Node 22.14.0 or later on a GitHub-hosted runner, and the workflow installs versions that
meet both. Unfortunately, the npm website does not check these details, and there is no way to edit
the trusted publisher, only to remove it and add it again. If any of the details are wrong, the
publish will fail with an authentication error, and the trusted publisher will need to be removed
and added again with the correct details. All of the details are case-sensitive, and the workflow
filename should be the filename only, including the extension.

### Configuring the package to disallow publishing with tokens

Once a trusted publisher has been configured and used to publish a version, the package can be
configured to disallow publishing with tokens. This can be done from the package settings on
npmjs.com, by changing the "Publishing access" option to "Require two-factor authentication and
disallow tokens", and selecting "Update Package Settings". This will prevent anyone from publishing
a version using a token, but will still allow someone to publish a version if they have two-factor
authentication enabled on their account. However, the trusted publisher will still be able to
publish versions, because it uses a short-lived token that is specific to the workflow. Any token
used for the first publish should be revoked.

### Approving a deployment to the npm registry

Once a tag of the form `packages/v*` has been pushed, the workflow will run. When the `check` job
passes, the `publish` job waits, and GitHub asks the environment's reviewer to approve it. A run
waits at most 30 days for an approval. The reviewer:

1. Opens the run from the repository's Actions tab and confirms that `check` passed, which means the
   archive matches the release's sums and what `npm pack` makes.
2. Reads the tag, which names the version and the commit, and decides whether that version should go
   on the registry. npm accepts a version number once, so a published version cannot be published
   again with another archive.
3. Chooses Review deployments, selects `npm-publish`, and chooses Approve and deploy. Choosing
   Reject ends the run with nothing published.
4. When the job finishes, runs `npm view @kalareach/plugin-sdk version` and checks that the package
   page shows the provenance for that version.

If, for some reason, the reviewer rejects the deployment, go back to the run's page and click
"Re-run" to ask the `publish` job for approval again. GitHub offers "Re-run" for 30 days after a run
starts, which is as long as a run waits for approval, so a run whose approval expired cannot be
re-run. In that case a new run can be started by hand, with the tag as its ref, using the command
line tool: `gh workflow run package-npm.yml --ref <tag>`.

Whether re-running the existing run or starting a new run, the action will run the version of the
workflow as it was at the tagged commit. This means if a problem occurred because the workflow was
incorrect, then a new tag is needed to fix it. If, however, the problem was with the package's
settings on npm (e.g. the trusted publisher field has a typo), then simply fix the problem and run
the action again.

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

## The shell packages' update target

The managed shell packages are upstream releases with KalaReach's own patch sets, so a security
update to one of those upstream projects is a release of ours.

Each is triaged within one working day of the advisory. The package it affects is rebuilt against
the fixed upstream release, requalified against the whole corpus under `tests/shells/`, and
published within fourteen days of that release. No binary is
distributed before its requalification passes, and no package is swapped into a session that is
already running: a session keeps the package identity it started with until it ends.

A package whose fourteen days pass without a requalified build is flagged, and the flag names the
choices rather than leaving a stale package as a silent default: keep the pinned package, run that
shell in `native_compat` without the managed empty-prompt Ctrl-D and fenced launch, or run a
different managed shell. `docs/shell-integration/upstream.md` is the register of the sources each
package tracks, the triage record and those choices.

## What a version bump requires

Both packages carry one version, and one tag publishes both.

Bump the version when the generated output changes in a way a consumer cannot take without changing
its own code. That includes a type or export that was removed or renamed, a field whose shape
changed, an optional field that became required, and a new variant in a closed union, which breaks
any consumer that handles the previous variants exhaustively. While the version is below `1.0.0`
that is a minor bump. A change that only adds an independent type keeps the version; the commit in
the tag and in each archive's name already tells two releases apart.

A new member of an existing type takes that bump too, an optional member included. The Rust types
refuse a member they do not know, those of a session's local path among them, so a build without
the member cannot read a frame that carries it. The version is compiled into every host process,
which states it in its answer to a hello, and `kr attach` relies on this rule: it reads a worker's
screens only when the worker's version has the same minor number as its own below `1.0.0`, or the
same major number from `1.0.0`, and a patch number never decides. A member released without the
bump would let it attach to a worker whose frames it cannot read.

Counting exported names does not establish compatibility: the names can be identical while a union
or a field beneath them has changed. Read the diff of `packages/protocol/src/generated/protocol.ts`
and `packages/plugin-sdk/src/generated/plugin-sdk.ts`.

A bump is one commit that changes the `version` in `packages/protocol/package.json` and
`packages/plugin-sdk/package.json` together. A consumer then moves its URL, its lockfile integrity
and the commit it names in its own documentation, in one commit of its own.
