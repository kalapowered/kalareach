# Signing and publishing the macOS and Linux host

A host release for macOS and Linux is made in four steps. Two of them hold a key, and each key is used
in one place: the Developer ID and the notary key stay on the machine that signs, and the update
channel's two release keys are secrets of one deployment environment that one job reads. This page
says what each step does, what it checks before it goes on, what to do when it stops, and how a key
is replaced.

[The release manifest](manifest.md) says what a release is. [Windows signing](windows-signing.md)
is the same job for the Windows archives, which this procedure does not touch.

## The four steps

| Step | Where | What it does | What it holds |
| --- | --- | --- | --- |
| Build | `release-tree.yml`, run by hand on `main` | Builds the four trees (two macOS, two Linux) on their own platforms, proves them with keys made for the run, and keeps each tree as it stands before the run's signature goes on it, for three days | no secret |
| Sign | `scripts/sign-macos-release.sh`, on the machine that holds the Developer ID | Signs and notarises the two macOS trees and leaves them where the next step can take them | the Developer ID key and the notary key, read from files |
| Seal | `release-host.yml`, job `channel` | Writes each manifest again over the files as they now are, signs it with the update channel's two release keys, and packs the archive | the two release keys, behind the `update-signing` environment |
| Publish | `release-host.yml`, job `publish` | Publishes the four archives and their sums as one pre-release, after each archive has been verified and installed on its own platform | the right to write a release |

Every step takes a digest from the step before it and checks it. A tree is changed by a signature,
and the manifest lists the digest of every file, so the manifest is written after the signature and
never before.

## What is signed, and how

All the programs of a macOS tree, the host's seven and the programs and modules of the shell
packages, are signed by one identity, `Developer ID Application: Kala Holdings Inc (L775WGST9V)`,
with the hardened runtime and Apple's timestamp. One identity signs the whole tree because a hardened
process loads only code signed by its own team: a shell module of another team is refused, and the
shell says so when it tries to load it. The signature is made by `rcodesign` (the `apple-codesign` signer), which reads
the key and the certificate from files by path. Nothing is imported into a keychain and nothing
changes the keychains or their search list. `scripts/install-rcodesign.sh` puts the pinned release of
`rcodesign` in a cache directory after it holds the archive to its SHA-256, and the proving runs sign
ad hoc with the same tool.

No program is sandboxed, because the host runs the person's own development tools, and no program
takes an exception to library validation. One program has one entitlement:

| Program | Entitlement | Why |
| --- | --- | --- |
| `bin/kr-plugin-host` | `com.apple.security.cs.allow-unsigned-executable-memory` | It runs Wasmtime, which writes machine code into memory and then makes it executable. The hardened runtime ends a process that runs such code without the entitlement. `allow-jit` does not help: Wasmtime does not map memory with `MAP_JIT` |
| every other file | none | None makes code at run time |

`scripts/check-plugin-host-entitlement.sh` shows both halves on the processor it runs on: the
`kr-plugin-runtime` test that calls a component's exports succeeds without the hardened runtime, is
ended with the hardened runtime and no entitlement, and succeeds with the entitlement. It first runs a
probe that makes code at run time under the hardened runtime and no entitlement, and on a machine that does
not end the probe (the virtual machines that host a build can be one) it says that nothing is shown and
succeeds. The build step runs it on both Mac architectures in every run, and with `--host` it also runs the
`service` suite of `kr-plugin-host`, which starts the plugin host as its own process, with the plugin host
signed in place the same three ways. The Mac runners GitHub hosts do not end the probe, so a build run shows
neither half and runs neither call. Run both by hand on a Mac that enforces the hardened runtime, such as the
machine that signs, to show them: the step "Show what the plugin host's entitlement is for" in
`.github/workflows/release-tree.yml` lists the two commands.

`scripts/check-macos-signatures.sh` holds a tree to what it is supposed to be: every file passes
`codesign --verify --strict`, the entitlements are the list above and no other, and a Developer ID
tree has the hardened runtime, a timestamp, a chain of three certificates ending at Apple, and the
team above, by name and by a designated requirement over the Developer ID certificate. A Developer
ID of another team, the individual team of the same person included, is refused. A notarised tree is
also held to `codesign --check-notarization` and to the system's assessment as a Notarized Developer
ID. The script tests itself with trees made to fail.

## Notarisation

`xcrun notarytool submit` takes a zip of each tree with an App Store Connect API key of the
organisation's team: the key file, its key identifier and its issuer identifier, read from
`asc-api-key.json`. The submission is made without waiting, so its identifier is printed as soon as the
service has the upload, and the script then waits for it. The step goes on only when the status is
`Accepted`. A status of `In Progress` when the wait times out is not a failure of the submission:
resume it with `xcrun notarytool wait <submission id>` and the same key options. `notarytool log
<submission id>` has the service's reasons for a refusal, and the script saves it as
`<work>/<top>.notary-log.json`, in the folder [named below](#signing-a-release).

A tar archive of executables cannot carry a stapled ticket, because a ticket attaches to an
application, a package or a disk image. Apple keeps it. The first time a person opens a program that
came from a browser or a quarantining tool, Gatekeeper asks Apple's service whether it is notarised,
so that first launch needs a network. On a macOS 26.6.2 guest, Safari with its default settings
decompressed a `.tar.gz` to a `.tar` that carries the flag, and `tar -xf` put the flag on every one of the
1,606 files it unpacked from that `.tar`. No other browser and not Archive Utility was measured. With the
guest's network blocked, the system refused the first run of a flagged `kr` with a "Not Opened" window, and
the command waited behind the window. That copy kept refusing when the network came back, and after `spctl`
and `codesign --check-notarization` had accepted it; the same `.tar`, unpacked again into a new directory,
ran. No first run of a flagged copy with the network on was measured. A program fetched by `curl`, or put in
the store by `kr host install`, carries no quarantine flag: the tree `curl` fetched ran with the network
blocked, and the store held no flagged file.

## The files that sign

They are under `~/.config/kalareach-secrets/apple`, mode 0600, and the script refuses to run when
one is missing or has another mode:

| File | What it is |
| --- | --- |
| `developer-id-application.key` | the private key, PKCS #8 PEM |
| `developer-id-application.pem` | the certificate, which has to be a Developer ID Application of the team, valid for at least 30 days more, and the key's own |
| `DeveloperIDG2CA.cer` | Apple's Developer ID intermediate certificate, DER |
| `asc-api-key.json` | `key_id`, `issuer_id`, `team_id` and `key_file` of the notary key |
| the `.p8` that `key_file` names | the notary key |

## Signing a release

On the machine that holds those files, after `release-tree.yml` has built the trees at a commit on
`main`:

```sh
scripts/sign-macos-release.sh --build-run <run id> --commit <full commit hash>
```

The script takes the two macOS trees from the run's artefacts, after it holds the run to the commit
and each artefact to the digest GitHub states for it and to the sum beside it. It signs, checks,
notarises, checks again, and puts the two signed trees, the notary submissions, a record of the run and commit they came
from and one file of sums over all of them in a draft pre-release named `host-staging/v<release>`, the one place a command outside a workflow can
leave files for one. It ends by printing the command that starts the sealing, with the digest of the
sums as an input. `--no-stage` stops before the draft. A draft that is already there is a refusal
that names `scripts/sign-macos-release.sh --remove-staging <release>`; the script removes a draft it
made itself when one of its later steps fails, and the publish job removes it after publishing.

The script works in a new folder for each run, `<work>`: `$KR_RELEASE_WORK/<stamp>` when `KR_RELEASE_WORK`
is set, and `~/Library/Caches/kalareach-release/<stamp>` when it is not, where `<stamp>` is the time the run
started as `YYYYMMDD-HHMMSS`. It keeps the folder. A run that stages prints no path to it, so the newest
folder is the last run's; `--no-stage` prints the path, and so does a submission the service did not accept.
For each tree, `<top>` is `kalareach-<target>-<release>`: the notary log is `<work>/<top>.notary-log.json`,
and the tree taken from the run's artefact is `<work>/<target>/<top>`, so the log is not beside the tree.

The sealing is started by hand:

```sh
gh workflow run release-host.yml --ref main -f commit=<sha> -f build_run=<run id> -f staged_sums_sha256=<hex>
```

The workflow's `source` job holds the inputs to what they name before anything is approved: the commit
is on `main` (by the copy of `scripts/check-commit-on-main.sh` that `main` holds, so that no script of the
commit runs before the commit has been held to `main`), the run is a successful `release-tree.yml` run on that
commit, each tree is the artefact whose digest GitHub states, and the staged files hash to the input. Each staged
macOS tree is held to the run's tree by `scripts/check-staged-tree.py`: the same directories and files at the same
modes, the run's `release.json`, every file that is not Mach-O as that manifest describes it, and every Mach-O
file equal to the run's outside its code signature. The job passes on the tar that check writes from what it
read, and not the staged one. It prints every digest in the run's summary. The person who approves the `update-signing` deployment compares
the staged sums, and the digest of the sums, with what the signing script printed; the digests of the two macOS trees
to be sealed are those of the tars the check wrote, which the signing script never saw. The files the sealing job takes are kept for three days, so the approval has to come within three
days of the dispatch. The approval is the one approval of a release: the jobs after it run without another,
and `publish` runs only after every archive has been verified against the root committed in
`release/tester-channel/root.json`, installed into a store, and started on its own platform: the control daemon, a worker and a shell create a session and close it.

The `matrix` job runs beside `source`. It builds `kr-release-matrix-check` at the commit and asks
whether the signed release matrix the managed service publishes lists a tier for the package version
the commit carries ([packages.md](packages.md#the-release-matrix)). It holds no key and no write
access, and `channel` waits for it, so a release that the matrix does not list is refused before anyone is
asked to approve the use of the release keys. `publish` asks again, with the program `matrix` built,
held to its sum and to the digest `matrix` stated, before it writes anything, because the approval between the two
can come days later and a newer matrix revision may have dropped the version; a re-run of `publish` asks
afresh. The program is kept for five days and the trees for three, so it outlasts them. The first job comes
after the notarisation, which takes about an hour, so run the same check at the commit before the signing starts:

```sh
cargo run --locked --release -p kr-release-matrix-check -- --origin https://reach.kala.to
```

Two things keep a run on any other branch away from the release keys: every job behind `source` carries
the condition that the ref is `main`, and the `update-signing` environment accepts deployments from `main`
only and names the maintainer as its reviewer. A dispatch on another ref runs `matrix` and nothing else.

`publish` refuses to make a draft unless something shows that the repository makes releases immutable.
A workflow's token cannot read the repository's setting, which needs the right to administer it, and
the workflow holds no credential that has it. So the job reads the repository's releases and requires
the most recently published one, of any kind, to report itself immutable, which a release published
while the setting is off does not. That shows the setting as it was at that release, and it is kept as
the check, with three more around it: whoever dispatches the workflow reads the setting with their own
login first (`gh api repos/<owner>/<repo>/immutable-releases` answers 200 with `"enabled": true` when it
is on); whoever approves the `update-signing` deployment reads it again just before approving; and
after `publish` publishes, it confirms that the tag is at the commit, that the release is immutable, and
that the public release holds what it checked. Another writer to the repository could replace an asset
of the draft between the job's last check of it and its publication; the check after publication
shows that, and it cannot undo it.

## Reading a refusal

| Refusal | What it means | What to do |
| --- | --- | --- |
| a file is not mode 0600, or the certificate expires within 30 days | the script will not sign with a file it cannot trust | fix the mode, or renew the certificate |
| the run is not a successful `release-tree.yml` run on `main` at the commit | the trees are not the ones the commit made | build again at the commit |
| an artefact is not the one GitHub holds the digest of | the file changed after the run kept it | build again |
| `is not signed by the team L775WGST9V` | a file was signed with another identity | sign again from an unsigned tree |
| `has entitlements, and only bin/kr-plugin-host has one` | a program carries an entitlement the host does not allow | remove it from the signing step |
| the submission is `Invalid` | Apple's service refused a file | read the log the script saved |
| `already has a release` | the tag is taken, and a published release is never replaced | release the corrected commit under its own tag |
| `the update channel's release keys are not set up` | the environment has no key | the owner sets `RELEASE_CHANNEL_TARGETS_KEY_1` and `_2` |
| `is not on main` | the commit is not in `main`'s history | land the commit, then build again |
| `is not the tree the run built with its programs signed` | a staged macOS tree differs from the run's in more than its signatures; the lines before it name where | sign a tree of the run again, from the run's own artefact |
| `is not the pinned rcodesign` | the signer was handed a program of its own choosing for the Developer ID | unset `KR_RCODESIGN`, or give it the pinned executable |
| `is in no tier of the release matrix`, or `the published release matrix was not accepted` | the matrix the managed service publishes does not list the commit's package version, or does not verify | publish a matrix revision that lists the version, then re-run the failed job; its sealed archives are kept for one day, and a refusal at `matrix`, before the approval, is a new dispatch |
| `nothing shows that this repository makes releases immutable` | the setting reads as off, or the most recently published release is not immutable | turn the setting on and publish a package release, then re-run the failed `publish` job within the day the sealed archives are kept; later, dispatch again |
| `the system does not accept <file> as a Notarized Developer ID`, with `source=Unnotarized Developer ID`, for Mach-O files of one or both macOS targets in their `check` job while the other checks pass | the system on the macOS runner assessed files as not notarised that the signing script had seen accepted; the first release saw this once, and the cause is not known | re-run the failed job once, as [below](#a-check-job-that-refuses-the-files-of-a-macos-target); a second refusal is investigated, not re-run |

### A check job that refuses the files of a macOS target

A `check` job for a macOS target holds each Mach-O file of the unpacked archive to `Notarized Developer ID`
with `scripts/check-macos-signatures.sh`. The archive carries no stapled ticket, so the system answers
from Apple's service. The first host release saw an answer of `Unnotarized Developer ID` for files that
the signing script had seen accepted. `release-host` run 40909452060 was dispatched at 16:13 UTC on 29
October, and in its first attempt the `check` job for the Intel macOS target failed at 05:42 UTC on 30
October. It refused 86 of the 89 Mach-O files, each with `source=Unnotarized Developer ID`, and accepted
the other 3, while the other three `check` jobs passed. Its second attempt passed on the same bytes. The
cause is not known. When a `check` job refuses Mach-O files of one or both macOS targets with
`Unnotarized Developer ID` and the other checks pass, re-run it once:

```sh
gh run rerun --failed <run id>
```

That runs the failed jobs again, and `publish` after them. `channel` keeps its result, so nobody is asked
to approve again. A re-run on the same bytes cannot make a file that is not notarised pass, so it costs
a job and no safety. The sealed archives are kept for one day after the sealing, and both `check` and
`publish` take them, so start the re-run early enough for the two jobs to finish within that day; a
`check` job can wait for a runner for a while before it starts.

A second refusal is investigated, not re-run, and so is any other refusal of a notarised tree. Work through
these in order and stop at the first that applies:

1. Compare the digests in `source`'s summary with what the signing script printed. If they differ, the
   sealed trees are not the ones that were signed. Do not re-run: sign again and dispatch again.
2. Read the submission's status and log with `xcrun notarytool info <submission id>` and
   `xcrun notarytool log <submission id>` (the notary key options as for `wait`). The submission
   identifiers are in `source`'s summary, under the notary submissions. A status other than `Accepted`
   ends here in the same way: sign again and dispatch again.
3. Download the sealed archive of the target from the `release-host` run while it exists:

   ```sh
   gh run download <run id> --repo kalapowered/kalareach --name sealed-<target>
   ```

   That leaves `kalareach-<target>-<release>.tar.gz`; unpack it. Print the CDHash of a file the `check`
   job refused (its log names them) with `codesign -dvvv <file>` (`-dvv` does not print it), on its
   `CDHash=` line, and look for it among the `ticketContents` of `<work>/<top>.notary-log.json` on the
   signing machine. If it is not there, the file is not one the service notarised, and its bytes changed
   after the notarisation. Do not re-run: sign again and dispatch again.
4. If it is there, assess the file on a Mac with a network, with
   `/usr/sbin/spctl --assess --type open --context context:primary-signature -vv <file>`. When it
   prints `accepted` with `source=Notarized Developer ID`, the bytes are good and the refusal came from the
   runner: re-run the failed jobs again while the sealed archives exist, and dispatch again once they have
   expired. When `spctl` refuses it too, do not re-run: nothing is published, and whoever owns the release
   decides whether to sign again.

## Keys, and replacing them

The Developer ID certificate lasts until 2027-11-27. A replacement is a new certificate for the same
team, made from a new key, and the script needs nothing else changed: the team identifier is the
same. A lost key is a new certificate and no revocation, since permissions name the team. A leaked key
is a new build signed with a new certificate, taken by hosts through the update channel first, and
then a revocation, because Apple stops installed copies from launching once a certificate is revoked.
The notary key is replaced in App Store Connect.

The update channel's root is `release/tester-channel/root.json`. It names two release keys, both of
which have to sign (two of two), and it expires in 2099. A key is replaced only with a successor root
signed by the root it replaces, which a host reads and follows; no command in this repository writes
one, so a lost release key ends further updates of hosts installed from this root, and those hosts
install again from a release signed under a new root. [Signing keys and who rotates them](keys.md)
lists the key with the others.
