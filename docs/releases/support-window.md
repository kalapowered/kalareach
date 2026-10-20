# Support window

KalaReach lists the public protocol majors it negotiates and says how long each is supported. Support means both how long a peer application created with a major can still connect to a host, and how long an existing session remains functional after an update of the host application. The first period is referred to as the public window, the second, the local window.

## Public majors

The client offers the host a list of every protocol version it has, which is every version of each major it has not retired. The host selects the highest version that is also in its own list, which is built the same way. If the two lists share no version, the host refuses the client with the error code `UNSUPPORTED_SCHEMA` before it exchanges any session data. The following table is the `PUBLIC_MAJORS` list in `kr-protocol`. If this table and that list disagree, a test fails.

<!-- public-majors:begin -->
| Major | Versions | Replaced | Supported until | Retired |
| --- | --- | --- | --- | --- |
| 1 | 1.0 | not replaced | none | no |
<!-- public-majors:end -->

A major version will be supported for at least 12 months after it has been replaced by a new major version. A release is permitted to stop negotiating a major, often called retiring it, only if the release before it was built after the support window for that major had ended. Nothing in KalaReach itself causes a major version to stop being supported based on the passage of time. The support window for major version 1 has not started since it has not been replaced by a subsequent major version.

The rules that keep this promise are tested on fixed rows, on this build's table, and on the table each retained release recorded. No row will be removed. No version of a major that is not retired will be removed. The replaced day for a major never changes once it is set. The supported-until day for a major will never be changed except to a later day. The replaced day, the first time it is set for a major, will never be before the day the previous release was built. The supported-until day for a major will always be at least 12 months after its replaced day. A major will only be retired in a release whose previous release was built after its supported-until day. At least one major will always be available for negotiation.

## Sessions that outlive an update

Since running sessions continue to use the worker process that started them, it is possible for a release update to leave the host with one version of worker running while the control daemon is running a different version. The control daemon always speaks to the worker at the compatibility level defined by the daemon, and also at the level of each release it retains, which are listed below. If the worker running on the host is at any other compatibility level, the worker holds the update. In this case `kr host update` and `kr host rollback` wait: they exit with exit code 9, print the name of the session, and start again whatever they stopped. The time window during which the host may not be updated is limited to the time that a session is running on the host, regardless of what the public table indicates.

<!-- retained-levels:begin -->
| Level | Release | Built |
| --- | --- | --- |
| 0.75 | 0.75.0+8f22acfc5fa2 | 2026-10-19T17:24:37+02:00 |
<!-- retained-levels:end -->

The day a release was built is the committer date of its commit.

`kr attach`, `kr detach` and the contact tools reach a worker at another level through the `kr` of the release that worker runs. The store keeps that release while the worker is running. Where the store has no `kr` of that release, `kr attach` and `kr detach` refuse the worker and each call of the contact tools is refused. `kr status`, `kr share` and the `kr question` commands never hand over: they do not read such a worker and say which session they did not read and the command that does. `kr close` goes through the control daemon, which closes the session at the worker's level; only when no daemon answers and it reaches the worker itself does it do the same as `kr status`. `kr-hook` hands over to the hook of the worker's own release when the store holds that release and its hook, the worker is at a level other than the hook's own, and enough of the hook's half second remains, and in every other case it talks to the worker directly. `docs/host/updates.md` describes each command.

## What the checks cannot see

The retained surface is compared by a regression check, which does not prove that two releases read each other's frames. `kr-protocol-gen --check` compares the schema of the frames that the control daemon reads from or writes to a worker with the one the release before kept. The `retained_surface` test compares the source of the rules that the decoders apply, the limits that frames are read under, and whether a set of probe inputs is accepted as before. These checks will not pick up on, for example, upgrading a dependency that the decoder uses; `Cargo.lock` shows such a change and a review of it must read it. They will also not pick up on rules that are applied through an indirect call they cannot name, rules that only the worker or the controller applies and that are not listed, inputs that are not probed, or probes that are added after a level was retained. Note also that the test does not follow what a method of an inherent implementation calls, records a limit written as another constant by its text rather than its value, and will not pick up on changes to the meaning of a decoded value if no listed source moves. The upgrade suite, which runs a worker from the release before alongside a new daemon, covers part of what the checks cannot. Its cases inside the level update from, and roll back to, the newest release of the commit's own level in the commit's history that the record of exclusions does not name, with workers that survive the update, workers of the new build during the rollback, a paired device's mutation and `kr attach`.

Two kinds of edit escape the checks of the table, and a review has to catch them. A branch that edits the table and its recorded copy together, between two landings, is seen only at the landing, which reads the release's own source and compares the recorded table with it; for a release whose source lists no table the record is the one major its protocol version names, and the same comparison holds it. If someone writes the wrong day for a release's build, or the wrong first replaced day, it will only be apparent when reading those two lines. Note that no date is given for when major 1 was replaced, since it never was.

The checks of a level do not reach the shell bridge's `root.*` methods, whose peer is the shell package a session launched, or the hook's registration, its `kr_hello` line and its private exchange. Nothing yet runs a hook of one release against a worker of another at the same level.

## A host built at an excluded release

A level is one surface, and two early releases of level 0.76 do not have the surface the level has: `packages/v0.76.0+d3a552aa2ea6` and `packages/v0.76.0+53a2e0be5111` have no `ForwardedMutation.lease`. `crates/kr-protocol/retained/EXCLUDED` names them ([packages.md](packages.md#releases-a-levels-contract-does-not-cover)). No host build was released from either commit. A worker of one of them is at the level of the daemon that replaces it, so `kr host update` and `kr host rollback` do not hold for it, and the daemon forwards a paired device's mutation to it with a lease that the worker cannot read. A host built at one of these commits drains its workers before an update or a rollback: end each of its sessions, or wait until it ends. After the 0.77 cut the daemon speaks to a worker of 0.76 with the retained 0.76 surface, which has the lease, so it sends the lease to an excluded worker as well. The 0.78 cut stops retaining 0.76, and removes the record and everything that reads it.

## Cutting a release

A release retains the compatibility level of the newest release at the highest level below its own, and the release tags are the only record of which release that is, so `scripts/check-retained-release.sh` reads them. Run that script on a clean checkout of the commit to release, with the tags fetched. `kr-protocol-gen --in-level`, which core-ci and the release workflow run, runs it when no release is at the commit's own level, which is the commit that cuts a level ([a level is one surface](packages.md#a-level-is-one-surface)).

The script takes the newest tag in the form `packages/v<version>+<commit>` in the history of that commit at the highest level below its own that `retained/EXCLUDED` does not name, and fails unless that level is the newest the build retains. It then compares the schema, the table of public majors and the plugin host protocol of every release tagged at that level that the record does not name, taken from the tags and not from the history of the commit, with those the level kept. If the level's record refers to an earlier release of the same level, it moves the record to the newest one, and the level's row in the table above with it. It runs the `retained_surface` test against the source tree of that release, to hold the rules and limits the level kept to the release they came from, the `public_majors` tests against the record as it now stands, and `kr-protocol-gen --check`. If the record moved, the script fails after it lists the two files it changed: commit them, run the upgrade suite, which builds the release the record now names, and run the script again on that commit.

### Retaining a level

A release that raises the compatibility level retains the level of the release before it, and the cut is one commit on the branch that raises it. The release before is the one `kr-protocol-gen --predecessor` prints. Extract its commit with `git archive` into a directory of its own: the steps that read the release read that tree.

1. Run `kr-protocol-gen --retain <level> --commit <full commit>`. It creates the directory `crates/kr-protocol/retained/<level>/` with the surface, release record, plugin host protocol, and the table of public majors, and an empty list of frames.
2. Add that level to the list of retained levels, and then replace the level you're dropping. In `crates/kr-protocol/src/retained.rs` add to `RETAINED_WORKER_LEVELS` and add `include_str!` paths to `RETAINED`. Remove the directory of the level this release stops retaining, replace that level's row in the table above, and update the tests that hardcode the level number.
3. Then record the rules the surface reads from the release's tree: `KR_RELEASE_TREE=<tree> cargo test -p kr-cli --test retained_surface -- --ignored record_the_rules_of_the_surface`. That writes `sources.json`, `limits.json`, and `vectors.json`.
4. Also record the exchange with a worker of that release, with `TMPDIR` set to a neutral directory, by running `KR_RECORD_FRAMES=1 cargo test -p kr-cli --features upgrade-suite --test upgrade the_frames_ -- --nocapture` and extracting the text between the `FRAMES-JSON-BEGIN` and `FRAMES-JSON-END` lines as `frames.json`.
5. Search the tree for code that says it goes once no retained level is below some level, and remove what this cut makes unneeded, in a commit of its own. The cut that stops retaining 0.76 removes `retained/EXCLUDED` and the code that reads it in `kr-protocol-gen` and in the upgrade suite.
6. In the commit after the cut, record the files that are not kept within `retained/`, as described in the next section.

### Recordings beside the tests

These three recordings, kept outside of the `retained/` directory, are of the release before, and are kept near the tests that read them, rather than with the other recordings from that release. The `registration-<level>.txt` file contains what a worker of that release publishes for a launch. The `bridge-hello-<level>.json` file contains the first frame that the forwarder of that release writes. The `channel-frames-<level>.json` file contains the approval that the forwarder of that release relays, and the verdict that the worker of that release writes back. In each of these, `<level>` is the compatibility level of the release. The `the_recordings_beside_the_tests_are_of_the_release_before` test in the `kr-protocol` crate will fail if any of these files is named for an older level, or if the registration refers to a release other than the one that the newest retained level was cut from. When `scripts/check-retained-release.sh` moves the level's record to a later release of the level, make the recordings again from that release's tree.

The recordings are the bytes the release's code writes, and must be created by that code in that release's tree, never by hand. They include values that vary between runs, like a process number, a start value, a credential, and the paths of the launch's directory, and those values belong to the recording. The tests that read it check what each value has to be and never the value itself.

The four ignored test cases are each beside the tests that read its recording or the writer it records. These run in the release’s tree against the release’s forwarder and worker, and write their recordings to the directory specified by the `KR_RECORD_DIR` environment variable. Run these in the order given below in the tree extracted from the release you cut: `KR_RECORD_RELEASE` should be set to the name of the release you cut (check the `RELEASE` file in the `retained/<level>/` directory you generated above). Set `TMPDIR` to a neutral directory, since the registration records the launch's directory under it:

```text
export KR_RECORD_DIR=<an empty directory> KR_RECORD_RELEASE=<release name> TMPDIR=<a neutral directory>
cargo test --locked -p kr-hook --test listener -- --ignored record_the_hello
cargo test --locked -p kr-hook --test channel -- --ignored record_the_approval
cargo test --locked -p kr-worker --test channels -- --ignored record_the_frames
cargo test --locked -p kr-worker --lib -- --ignored record_the_registration
```

The first runs the release's hook against a listener the case owns, through a registration the case wrote with a credential the worker's own code generated, and keeps the first line it writes as `bridge-hello.json`. The second has the release's channel relay a tool approval to a worker's listener. The third reads that approval, has the release's worker answer it through `agent.approval.respond`, and writes both frames as `channel-frames.json`. The fourth writes `registration.txt`, the registration of a launch as the release's worker renders it, with the release line that a worker run from a store adds.

Move `bridge-hello.json` and `channel-frames.json` into `crates/kr-worker/tests/fixtures/` with the names given above, and move `registration.txt` into `crates/kr-hook/tests/fixtures/` with its name above. Remove the corresponding files for the previous level and change the file names the tests include.

A release from before the recorders has none in its tree, so keep a second extract of it. The 4 functions corresponding to the recorders, extracted from the same 4 files in the branch that raises the level, have to be added alone to the release's own files. Compare each of the four files with its copy by using `git diff --no-index --numstat <release file> <changed file>`: the second column has to be 0, and then read the added lines. Remove this paragraph as soon as the release of the retained level has the recorders.
