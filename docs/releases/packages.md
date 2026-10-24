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

A release is one commit's output. Fetch the release tags and run the two checks of
[a level is one surface](#a-level-is-one-surface) on that commit, then tag it and push the tag:

```bash
git fetch --force --prune origin '+refs/tags/packages/v*:refs/tags/packages/v*'
cargo run --locked -p kr-protocol --bin kr-protocol-gen -- --in-level
cargo run --locked -p kr-protocol --bin kr-protocol-gen -- --public-contract
commit=$(git rev-parse HEAD)
version=$(node -p "require('./packages/protocol/package.json').version")
git tag "packages/v${version}+${commit:0:12}" "$commit"
git push origin "packages/v${version}+${commit:0:12}"
```

The version comes out of the package rather than being typed, so a bump cannot leave this naming
the version before it.

`.github/workflows/package-release.yml` runs on a tag matching `packages/v*`. It runs the two checks
above first, packs the archives
with `scripts/release-packages.sh`, refuses to go on if that tag already has a release or a draft,
creates a draft, attaches the archives and `SHA512SUMS` to the draft that creation returned, and
publishes it only once GitHub's record of every asset, down to the sha256 GitHub computed over the
bytes it stored, matches what was packed. Publication then confirms that the tag resolves to the
release it just published and that the release cannot be replaced, and the last step fetches each
asset back from the URL GitHub serves it at, holds it to the packed sha512, and writes those URLs
into the notes.

From a tag whose commit has this workflow, one publication runs at a time, whatever its tag. (A run or a re-run of an
older tag uses that tag's own workflow, which serialises per tag and runs no check; the first tag
that has this one is the first to be held to it.) A second run waits for the first to finish
rather than running beside it, and the run already under way is never cancelled for the one
waiting; when the waiting run's turn comes, it finds whatever the run before it made and refuses to
go on if that is a release or a draft of its own tag. A first run that failed before creating
either leaves the tag as it found it, and the run that follows releases it. What is guaranteed is
that two runs never overlap, not that every run gets its turn: GitHub holds one run waiting, so a
third arrival takes the waiting one's place and cancels it. Nothing is lost when it does, because a
run that has not started has created nothing. Start that run again by hand, with `gh run rerun`,
once the run under way has ended. Do the same for a run that stopped at its second check
because a tag arrived while it packed, and for a `package-npm` run that gave up waiting for its
release, which it does after fifty minutes.
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

## A level is one surface

A compatibility level is `0.<minor>` below `1.0.0` and the major number from it, and every build at
a level reads and writes the same frames. A host's control daemon meets workers of any release at
its own level across an update and a rollback, and `kr` and `kr-hook` talk to a worker of their
level directly, so the first release of a level fixes what the level is. A later change to that
surface moves the level, in the train that makes it, with its cut
([support-window.md](support-window.md#cutting-a-release)). It is never made at the same level under
a new tag.

Every landing on main is tagged and published, so the branches that change the surface of a new
level land in one train. Three branches that land in three trains make three releases, and the
first of them is the level.

The surface is these four things:

- the types of the retained surface, `SURFACE_ROOTS` in `crates/kr-protocol/src/retained.rs`;
- the parameters and result of each method a worker serves, the payload of each notification it
  sends, and the frames of `kr bridge`. `crates/kr-protocol/src/worker_surface.rs` holds the first
  two as tables: the worker refuses a method that has no row, and `kr-protocol-gen` writes the
  tables to `crates/kr-protocol/worker-surface.json`;
- the protocol the plugin host speaks, `PLUGIN_HOST_PROTOCOL`, and, for each retained level, the protocol that level recorded, which the control daemon has a route for (`RETAINED_PLUGIN_HOST_PROTOCOLS`);
- the table of public majors.

The shell bridge's `root.*` methods are not in it, and neither are the hook's registration, its
`kr_hello` line and its private exchange: their peers are the shell package and the forwarder that
a session launched, which have releases of their own. Nothing checks that a hook of one release
works with a worker of another at the same level; the upgrade suite does not drive one yet.

`kr-protocol-gen --in-level` holds a commit to it. It lists the release tags on origin with `git
ls-remote`, requires this checkout's tags to be origin's, each at the same commit, and compares the
commit with every release at its level that the record of exclusions does not name, whether or not
the commit's history reaches it. It fails naming the release and each difference, in the schema
(cut over both revisions' roots, so that a root that was dropped cannot hide a change), in the
tables of what the worker serves (renaming an event, or serving a method no longer, changes no
definition of the schema), in the plugin host protocol and in the table of public majors. A release
from before `worker-surface.json` has no table to compare, so its tables are left out and its schema, plugin
host protocol and table of public majors are compared; the check says so. When no
release is at the commit's level, the commit moves it, and the check runs
`scripts/check-retained-release.sh` in the same run.

The check fails when it cannot list origin's tags, when this checkout's tags are not origin's, when
a release's tree cannot be read and when a source is in a form it does not read, and it never leaves
a release out. A tag that only one side has at the commit under test is left out of the comparison,
because a release tags a commit after it lands. Fetch the tags first with the command in the
procedure above, which also removes a tag that origin no longer has; delete a tag that only this
checkout has with `git tag -d`.

core-ci runs the check in its `rust` job, and `package-release.yml` runs it before it packs and
again, after a new fetch, just before it publishes. Run it before the tag too, as the procedure above
does. A tag the check refuses stays in every list until it is deleted. Delete a refused tag that was
never published from origin and from every clone, and tag the corrected commit.

### Releases a level's contract does not cover

Level 0.76 was released before its last planned change had landed. `packages/v0.76.0+d3a552aa2ea6`
and `packages/v0.76.0+53a2e0be5111` each speak a surface without `ForwardedMutation.lease`, which the
level has. They stay published, since a published release stays where it is, and
`crates/kr-protocol/retained/EXCLUDED` records them as excluded. The record gives for each the tag,
its full commit, its level, the digest of the surface its own schema has, and why. It is closed to
these two tags. It is read and checked: each digest against the tag's own schema, each tag against
the inventory, and an excluded release against the kept releases of its level, each of which has to
have it in its history. A level that has no kept release is refused. Release selection, the cut's
comparison, the in-level check and the upgrade suite skip what it names, and the public-contract
report does not.

The record is removed with every reader of it at the 0.78 cut, and `kr-protocol-gen --check` fails
once its level is neither this build's nor a retained one. No host build was released from either
commit: they carry only the TypeScript archives. A host built at one of them drains its workers before an update
or a rollback; see [the support window](support-window.md#a-host-built-at-an-excluded-release).
The npm publish runs for the two tags were cancelled and nobody re-runs or approves them. npm takes
one archive per version, and the three 0.76.0 plugin SDK archives are the same.

### The public contract

The package publishes every type of the schema, and a client built from one release meets a host of
another across a level move. Until public 1.0 freezes, which happens at the first client release
(a host, command line, desktop or mobile build published for people to install), the public
contract may change with a level move.

`kr-protocol-gen --public-contract` compares the commit's whole schema, every definition a root,
with the releases a client may have been built from, and reports what an earlier reader cannot read.
A definition that is new is not a difference. A member that is added is not one either when it is
optional and the earlier release's object carries `x-kalareach-read-only-metadata`, because that
object's reader drops a member it does not know. Every other difference is reported: a member or a
variant added to a closed object, a member, a variant or a definition removed, and any change.
`SessionSummary.root` is one: an earlier strict reader cannot read the summary of a command session.
No client was released, so no shim carries it.

Until `crates/kr-protocol/retained/PUBLIC_FREEZE` exists, the references are the releases at the
commit's level, the excluded ones included, and the check reports and does not fail. That file,
`release=<tag>`, is made at the first client release. From then the references are that release and
every later one that shares a public major that is not retired with the commit, and a difference
fails the check. It fails at all times when it cannot read what it compares.

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
`SHA512SUMS`, and that it matches an archive created by `npm pack` from the same commit. When npm
does not already have the version, it also runs `npm publish --dry-run` on the archive to see what
npm would publish. Finally, it records the sha512 of the archive so that it can be checked again in
the `publish` job. The `publish` job runs only if the `check` job succeeds and npm does not already
have the version, and it waits until someone has approved the deployment. It downloads the release
again, and refuses any archive whose sha512 is not the recorded value. It then publishes the archive
to the npm registry, using `npm publish --provenance --access public` to attach provenance
information identifying the workflow and the commit from which it was published. It authenticates to
the npm registry using the workflow's own identity, via OpenID Connect, so this repository holds no
npm token.

It is possible to run the workflow on a branch to test the `check` job. In that case, it will not
use an archive from a release, but will use the `scripts/release-packages.sh` script to pack the
checked-out commit, and then run the same checks, with the dry run if npm does not already have the
version. A version npm does not have then reaches the `publish` job, which will fail, due to the
deployment policy on the environment it uses, but it will not run any of its steps, so will not
publish anything.

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
workflow. The package needs to already exist to add trusted publishers for it, which is why its
first version, `0.0.0`, was manually published by an owner of the `@kalareach` organisation. This
version is a placeholder containing only a manifest and a README, no code is included. Note that no
release is numbered `0.0.0`, and a release numbered `0.0.0` would fail the registry check, since npm
already has that version with another archive. To add a trusted publisher for the workflow, go to
the package's settings on npmjs.com and add a new trusted publisher, selecting GitHub Actions as the
provider and filling out the fields as follows:

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

### A version npm already has

Since npm only allows a specific version to be published once, and a tag names a commit as well as a
version, so that two releases can carry the same version, there is need to check whether the version
is already published on npm or not before it goes to the stage for manual approval (in order to
avoid going all the way there only to fail at the very last step of the job, i. e. on
`npm publish`). That's why there is a job called `check`. It basically runs the command
`npm view @kalareach/plugin-sdk@<version> dist.integrity` for the version in the archive and
compares the returned value to the archive's own sha512 integrity. There are three scenarios
possible:

- The version doesn't exist on npm. In this case, the process continues as described above (awaiting
  for manual approval in the `publish` job).
- The version exists on npm with the same integrity. That archive is already published, so the whole
  run is terminated with a notice and the `publish` job is skipped. Nobody is asked to approve
  anything.
- The version exists on npm with a different integrity. The `check` job fails and outputs both
  integrities in the message. This archive cannot be published under that version, so the release
  needs a version npm does not have.

A registry that cannot be reached or read also fails the `check` job. It is never taken to mean that
the version is absent.

### Approving a deployment to the npm registry

Once a tag of the form `packages/v*` has been pushed, the workflow will run. When the `check` job
passes and npm does not already have the version, the `publish` job waits, and GitHub asks the
environment's reviewer to approve it. A run waits at most 30 days for an approval. The reviewer:

1. Opens the run from the repository's Actions tab and confirms that `check` passed, which means the
   archive matches the release's sums and what `npm pack` makes.
2. Reads the tag, which names the version and the commit, and decides whether that version should go
   on the registry. npm accepts a version number once, so a published version cannot be published
   again with another archive; a version npm already has never reaches this step.
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

Each is triaged within one working day of the advisory, an advisory against a crate or repository that the fish build compiles included. The package it affects is rebuilt against
the fixed upstream release, requalified against the whole corpus under `tests/shells/`, and
published within fourteen days of that release. No binary is
distributed before its requalification passes, and no package is swapped into a session that is
already running: a session keeps the package identity it started with until it ends.

A package whose fourteen days pass without a requalified build is flagged in the register, a row of
`docs/shell-integration/upstream.md` that no code reads, and the flag names the choices rather than
leaving a stale package as a silent default: keep the pinned package, which a session does when the
person selects nothing, run that
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
the member cannot read a frame that carries it. The exception is an object whose schema carries
`x-kalareach-read-only-metadata`: its reader drops a member it does not know, so an optional member
added to one changes nothing an earlier public reader can read, and the public-contract report
accepts it. A member of a type on a level's surface moves the level whatever its kind. The version is compiled into every host process,
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
