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
| 0.74 | 0.74.0+d59b70150cd2 | 2026-10-17T18:47:29+02:00 |
<!-- retained-levels:end -->

The day a release was built is the committer date of its commit.

`kr attach`, `kr detach` and the contact tools reach a worker at another level through the `kr` of the release that worker runs. The store keeps that release while the worker is running. Where the store has no `kr` of that release, `kr attach` and `kr detach` refuse the worker and each call of the contact tools is refused. `kr status`, `kr share` and the `kr question` commands never hand over: they do not read such a worker and say which session they did not read and the command that does. `kr close` goes through the control daemon, which closes the session at the worker's level; only when no daemon answers and it reaches the worker itself does it do the same as `kr status`. `kr-hook` hands over to the hook of the worker's own release for a worker from compatibility level 0.75 on, when the store holds that release and its hook, the worker is at a level other than the hook's own, and enough of the hook's half second remains, and in every other case, including every worker below that level, which admits only the forwarder the update made current, it talks to the worker directly. `docs/host/updates.md` describes each command.

## What the checks cannot see

The retained surface is compared by a regression check, which does not prove that two releases read each other's frames. `kr-protocol-gen --check` compares the schema of the frames that the control daemon reads from or writes to a worker with the one the release before kept. The `retained_surface` test compares the source of the rules that the decoders apply, the limits that frames are read under, and whether a set of probe inputs is accepted as before. These checks will not pick up on, for example, upgrading a dependency that the decoder uses; `Cargo.lock` shows such a change and a review of it must read it. They will also not pick up on rules that are applied through an indirect call they cannot name, rules that only the worker or the controller applies and that are not listed, inputs that are not probed, or probes that are added after a level was retained. Note also that the test does not follow what a method of an inherent implementation calls, records a limit written as another constant by its text rather than its value, and will not pick up on changes to the meaning of a decoded value if no listed source moves. The upgrade suite, which runs a worker from the release before alongside a new daemon, covers part of what the checks cannot.

Two kinds of edit escape the checks of the table, and a review has to catch them. A branch that edits the table and its recorded copy together, between two landings, is seen only at the landing, which reads the release's own source and compares the recorded table with it; for a release whose source lists no table the record is the one major its protocol version names, and the same comparison holds it. If someone writes the wrong day for a release's build, or the wrong first replaced day, it will only be apparent when reading those two lines. Note that no date is given for when major 1 was replaced, since it never was.

## Cutting a release

A release retains the compatibility level of the newest release at the highest level below its own, and the release tags are the only record of which release that is, so `scripts/check-retained-release.sh` reads them. Nothing runs it by itself: run that script on a clean checkout of the commit to release, with the tags fetched.

The script takes the newest tag in the form `packages/v<version>+<commit>` in the history of that commit at the highest level below its own, and fails unless that level is the newest the build retains. It then compares the schema of every release tagged at that level, and the table of public majors and the plugin host protocol of the newest, with those the level kept. If the level's record refers to an earlier release of the same level, it moves the record to the newest one, and the level's row in the table above with it. It runs the `retained_surface` test against the source tree of that release, to hold the rules and limits the level kept to the release they came from, the `public_majors` tests against the record as it now stands, and `kr-protocol-gen --check`. If the record moved, the script fails after it lists the two files it changed: commit them, run the upgrade suite, which builds the release the record now names, and run the script again on that commit.
