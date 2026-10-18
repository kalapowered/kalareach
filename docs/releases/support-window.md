# Support window

KalaReach lists the public protocol majors it negotiates and says how long each is supported. Support means both how long a peer application created with a major can still connect to a host, and how long an existing session remains functional after an update of the host application. The first period is referred to as the public window, the second, the local window.

## Public majors

The host will offer the client a list of all protocol versions it will accept, which is every version of each major it has not retired, and the client will similarly offer the host a list of all versions it has. The two will negotiate to use the highest version both have. If the peer offers no version the host has, the host refuses it with the error code `UNSUPPORTED_SCHEMA` before it exchanges any session data. The following table is automatically generated from the `PUBLIC_MAJORS` list in `kr-protocol`. If this table and that list disagree, the tests will fail.

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

The `kr` and `kr-hook` of a release do not read the frames of a worker at another level in the shape they have. They reach the worker through the release that worker runs. The store keeps this release available while the worker is running. Where that cannot be done, they say which session they did not read. For more information on each of these commands, see `docs/host/updates.md`.

## What the checks cannot see

The retained surface is compared by a regression check, which does not prove that two releases read each other's frames. The check command compares whether the frames that the control daemon reads from or writes to a worker have the same schema as in the release before, whether the rules that the decoders apply have the same source, whether the limits that frames are read under are the same, and whether a set of probe inputs is accepted as before. It will not pick up on, for example, upgrading a dependency that the decoder uses; `Cargo.lock` shows such a change and a review of it must read it. The check command will also not pick up on rules that are applied through an indirect call it cannot name, rules that only the worker or the controller applies and that are not listed, inputs that are not probed, or probes that are added after a level was retained. Note also that the check command does not follow what a method of an inherent implementation calls, records a limit written as another constant by its text rather than its value, and will not pick up on changes to the meaning of a decoded value if no listed source moves. The upgrade suite, which runs a worker from the release before alongside a new daemon, covers what the check cannot.

Two kinds of edit escape the checks of the table, and a review has to catch them. A branch that edits the table and its recorded copy together, between two landings, is seen only at the next landing. If someone writes the wrong day for a release's build, or the wrong first replaced day, it will only be apparent when reading those two lines. Note that no date is given for when major 1 was replaced, since it never was.
