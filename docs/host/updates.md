# Updating a host

A host installed with `kr host install` keeps each release it runs in a directory of its own and
never changes one in place. An update adds the new release beside the old one, makes it current in
one step, and replaces the control daemons. It never replaces a worker: a session keeps running the
release it started from, with that release's shell package and module tree, until it closes. Going
back to an older release is a switch of the same kind (see "Rolling back").

## The store

Each user has one store of releases:

| Platform | Store |
| --- | --- |
| macOS | `~/Library/Application Support/KalaReach/host` |
| Linux | `$XDG_DATA_HOME/kalareach/host`, `~/.local/share/kalareach/host` by default |

| Path | What it is |
| --- | --- |
| `versions/<release>/` | One release: `bin/`, `shells/`, `share/` and `release.json`, read-only once it is there |
| `current` | A relative symbolic link to the release new processes start from |
| `staging/` | A release being unpacked and checked before it is renamed into `versions/` |
| `trash/` | A release being removed, moved out of `versions/` before anything of it is deleted |
| `roots/` | The runtime and state roots each control daemon of the store has served |
| `install.json` | The store's record: the release current before the last switch, a release staged for a later update, and an update under way |
| `update.lock`, `install.lock` | The locks an update and a starting control daemon take |

A release is named by its version and the first twelve hexadecimal digits of its commit, as its tag
names it: `0.2.0+4254aa6e62e5`. Every program of a release states that name in its build identifier,
`kr-worker/0.2.0+4254aa6e62e5`, in its answer to a hello, so `kr doctor`, a support bundle and every
refusal name the release a program runs.

## Which release a process runs

A program finds its release from the kernel's record of its own image, never from the path it was
started through, and holds that release for as long as it runs: a shared lock on its release's
`release.json`. A release is removed only once nothing holds it. A program whose release is being
removed does not start, and neither does one anywhere under `staging/`, whose release is still
being installed, or one inside a release but outside its `bin/`, which would run it unheld:

```text
kr: ~/Library/Application Support/KalaReach/host/trash/0.1.0+aaaaaaaaaaaa-… is being removed from this host, so this program of it does not start
```

What a program starts, it starts from its own release: a control daemon starts its own release's
worker with its own release's shell packages, and opens a window with its own release's `kr`; `kr`
starts its own release's restoration guard; a worker launches through its own release's forwarder.
A daemon of an installed release refuses `--worker` and `KR_SHELL_PACKAGES`, which would name
programs or packages the store does not hold for it.

What has to follow an update names its path through `current` instead, so it is written once:

- the directory to put on the search path, `current/bin`;
- the service definition `kr host startup --set service` writes, which starts `current/bin/kr-controller`;
- the command an agent's configuration runs to reach the contact tools, `current/bin/kr`;
- the forwarder a native bridge's registration starts, `current/bin/kr-hook`;
- the file each shell's startup entry sources, `current/shells/<shell>/<entry>`, which only calls
  the running shell's own bridge builtin, so a shell of any release the host keeps reads it and runs
  its own release's integration.

A control daemon of a store holds the install lock, shared, while it takes its environment, and
exits when `current` names another release: that release's daemon serves the host. It records the
roots it serves in the store, which is how an update finds every environment.

## Installing the first release

Unpack the release archive and run its own `kr`:

```sh
tar -xzf kalareach-aarch64-apple-darwin-0.2.0+4254aa6e62e5.tar.gz
kalareach-aarch64-apple-darwin-0.2.0+4254aa6e62e5/bin/kr host install
```

`kr host install` copies the release into a new store, checks it as an update checks one, makes it
read-only and current, and says where its programs are: put `current/bin` on your search path.
`--store <directory>` names another store. A store that already has a current release takes another
release through `kr host update`, which hands its daemons over first. The search path and the
shells' profiles are yours, or your installer's, to change.

An install holds the update lock throughout, so it waits, exit 9, while another install or update
of the store runs. It writes the store's record before any program of the release is in the store,
so each program started from there holds its release from its first moment, and it puts the
release in `versions/` and makes it current under the install lock, so a control daemon of it
started meanwhile waits for `current` to name it. An install that stopped between the two is
finished by installing the same release again. What the stopped install left is never trusted in
place: when its manifest is, byte for byte, the one just checked, it is removed and the copy this
install checked takes its place, so nothing it was short of, changed in, linked to or left
writable survives, and nothing outside the store is touched. A release a running program holds is
not removed, and the install waits, exit 9. Another release under the same name is refused, and so
is a directory whose manifest is a link or a pipe, which is not read: the install names the
directory and says to make it writable, as a release in the store is not, remove it, and run the
command again.

An install or an update waits for a control daemon that is starting, which holds the install lock
while it starts, for at most thirty seconds, and an update does so before it stops anything. A
daemon that takes longer makes the run exit with 9 and name the store, with nothing stopped: every
control daemon the update had prepared resumes. Every wait of an install or an update on the
store has a bound: a release's files and an environment's lock file are opened without following a
link or waiting for a writer, the release archive without waiting for one (a link a person names it
by is followed), and an environment's registry is read by the controller's own reader, as it is
and with nothing made beside it, which refuses a link, and what is not a regular file, before it
opens anything, so a pipe in any of these places is refused; a registry that records an earlier
schema is opened for writing only after the same checks, and a `-shm` file beside a registry that
is not a regular file is refused too, and a program other than this host's that has the registry
open is waited for at most five seconds for each statement; the system's own tool that says
its version is given ten seconds and is ended if it prints more than 4096 bytes, whatever a
program it starts does; and a program that starts in a release that is being removed or replaced
waits for that removal for at most thirty seconds.

## Updating

```sh
kr host update --archive kalareach-aarch64-apple-darwin-0.3.0+9f1c2b3a4d5e.tar.gz
kr host update --archive <archive> --check   # check the release and what holds an update, change nothing
kr host versions                             # the releases this host keeps
```

Only the current release's `kr` updates the host. An update, in order:

1. takes the update lock, so one update runs at a time and `current` stays as it is, checks under
   it that it is still the current release's `kr`, and finishes or undoes an update an earlier run
   left part way;
2. stages the release and checks it, as below;
3. asks every worker the store's environments describe what it is, and stops nothing: a live
   worker at a compatibility level the new release's control daemon does not speak holds the
   update;
4. asks each control daemon to prepare, and records how each was started before any is told to
   stop;
5. takes the install lock, waiting up to thirty seconds for a control daemon that is starting;
   reads the store's environments again, so an environment whose daemon started after the first
   look is found; and looks at every environment no prepared daemon serves, where a daemon that
   holds one holds the update, with nothing stopped and each prepared daemon resumed. Only then
   does it tell each prepared daemon to stop, one after the other. The first that answers that it
   does not stop, because its attempt is over, holds the update: the daemons not yet told resume,
   and those already told are waited for to have gone, up to thirty seconds from the last telling,
   before anything is started again. Once every daemon has stopped, it holds every environment's
   lock, reads every store the new release lists and refuses the switch, naming each, when one is at
   a version the new release does not read (see "Rolling back"), brings forward any registry that
   records an earlier schema (see "Environments whose daemon did not run"), and reads every
   environment's registry as it is. A log that a daemon ended by a
   signal left beside the registry is taken into its file first, as the daemon's own stop would
   have; a registry that is a link, or is not a regular file, is refused before anything is opened,
   and the run then starts again what it stopped and exits with 1. A worker at a level the new
   release does not retain, a worker that does not answer its challenge and has not ended, and a
   session still being started each hold the update;
6. switches `current` in one rename, lets go of the locks, starts each daemon as it was started
   before, now from the new release, and waits for each to answer as a daemon of it;
7. removes the releases nothing needs: not the current one, not the previous one, not one staged
   for a later update, and not one a running program holds.

An update that is held waits. It starts again every daemon it stopped, from the release still
current, keeps the new release staged for the next attempt, which replaces it by the copy it checks
then, and exits with 9. When a daemon it stopped does not start again, it exits with 1 instead,
says which, and keeps the update recorded, as below:

```text
kr: the update to 0.3.0+9f1c2b3a4d5e waits: session 7 runs kr-worker/0.2.0+4254aa6e62e5 with protocol 0.45.0, which the control daemon of 0.3.0+9f1c2b3a4d5e does not speak; run kr host update again once that has changed
```

A daemon whose configuration document chooses the service start is started again by the service manager; any other is started through `current` with the arguments it was started with, in the directory it was started in, with the variables it had that decide its paths, writing to the environment's `controller.log`. A live session is never stopped, restarted or moved: its worker, its shell and its agents go on running the release they started from, and that release, its module tree among it, stays in the store until nothing holds it.

## What a release is, and how it is checked

A release archive is `kalareach-<target>-<release>.tar.gz`: one top directory holding `bin/`,
`shells/`, `share/` and `release.json`. `release.json` is the release's manifest in The Update
Framework's signed envelope: its release name and sequence, its commit, the target and the oldest
operating system it runs on, the protocol package version its programs were built from, the public
protocol majors it accepts, the compatibility levels its control daemon speaks to a worker at, its
shell packages, the stores its programs read with the versions of each it reads (see "Stored
formats"), and every file with its length, SHA-256 digest and whether it is a program.

A release is taken in only whole and checked:

- The archive is refused at the first entry that is a link, a device, a sparse file or anything
  but a file or a directory, whose path is absolute or climbs out of the top directory, or that
  repeats a file. A file is written whole: an archiver that leaves the holes of a sparse file out,
  in GNU's form or in the POSIX form that carries `GNU.sparse` keys, writes an archive this host
  does not take. An archive that is not a regular file, a pipe among them, is refused at once.
- The manifest is signed by a threshold of the release keys the update channel's root names for
  its targets role. The root the host trusts is the newer of the one the current release carries,
  at `share/update-root.json`, and the one `install.json` recorded when the host last switched to
  a release (see "Rolling back"); a release carries that root or the one that follows it, the next
  version, signed by a threshold of the current root's root keys as well as its own.
- Every file the manifest lists is there with its length and digest, and nothing else is.
- The following programs must all be listed as programs of `bin/` in order for a release to be
  accepted, regardless of who signed it: `kr`, `kr-attach-guard`, `kr-controller`, `kr-worker`,
  `kr-describe-inference`, `kr-hook`, `kr-plugin-host`. If any of those are missing, the entire
  release will be refused, and the refusal names each one it lacks.
- It is for this host's target, and this host's operating system is at or above its floor
  (the macOS release, or the GNU C library's version on Linux).
- It is newer than the current release.

Only then is it made read-only, flushed and renamed into `versions/`. What an archive says about a
file's mode or owner is not read: a file is a program when the manifest says it is.

There is a list of programs (`scripts/release-programs.json`) that the release builds and the
Windows archive check read as well. A host holds a release that is being taken in to the list its
own build carries, and holds nothing already in the store to it. A release installed from a previous
build with fewer programs in its manifest can still be started, is still shown by `kr host
versions`, and can be updated to a release with all the programs that the host now needs. A program
is added to the list in the release that starts needing it. It's trickier to remove programs from
the list though: a release that stops carrying a program is refused by every host whose current
release was built with that program in its list.

A release that carries no update channel root can be installed with `kr host install`, which takes
the release's own word for what it is, and a host whose current release carries none has no key to
check any other release against: `kr host update` refuses every archive there, and says so.

## The handover

A control daemon is replaced by the release that updates the host, through
`host.update.handover`, which only the owner's own socket may call. A handover is an attempt: it
takes one of three steps, and only `prepare` begins one.

| Step | What the daemon does |
| --- | --- |
| `prepare` | Begins an attempt under a new identity. Closes its gate to new sessions, waits up to 45 seconds for the creates it has already started to settle, and answers with the attempt, its process, the arguments it was started with and the directory it was started in. The gate stays closed for five minutes unless the attempt ends first. An attempt already open is over. A daemon that cannot say how it was started, because its working directory was removed, refuses before it changes anything. |
| `stop` | Stops, when it names the attempt `prepare` answered and that attempt is the one the gate is closed for, within its five minutes. Refused for any other, so a daemon that was never prepared, one whose preparation lapsed and one whose attempt was ended or superseded are never stopped by it. |
| `resume` | Ends the attempt it names, or whichever is open when it names none, and opens the gate: the update is not going ahead. Naming an attempt that is already over changes nothing. Refused, `ENVIRONMENT_UNAVAILABLE`, once the daemon has been told to stop. |

An attempt ends at its first stop or resume, when its five minutes lapse, and when a later
`prepare` begins another. Every decision is made under the lock the gate is under, and a stop
names its attempt, so a stop that arrives late, after the update it belonged to gave up and
whatever came after, finds its attempt over and ends nothing. A daemon told to stop takes no other
step: it refuses to resume and to prepare, and one that has resumed refuses a stop, so an updater
that sees a daemon resume knows no stop of any earlier attempt will end it. A stop or a resume is
taken whatever the daemon can say of how it was started, and a step that answers an error is a
step that was not taken. Each step is claimed under its action identifier. A repeat whose answer was
lost gets that answer and begins no second attempt, and an identifier reused for another step is
refused with `ID_CONFLICT`.

A create that arrives while the gate is closed is refused with `RESOURCE_UNAVAILABLE`, naming the
release the host is being updated to; the caller creates the session again once the new daemon is
running. Every create the daemon had already started is finished before it answers `prepare`:
whichever release it launched, that worker has taken its own hold on its release by then. A create
that does not settle within the 45 seconds makes the daemon refuse the step, and the update waits.
Nothing a session is doing stops at any step: a worker belongs to the service manager, and the next
daemon finds it again.

An update that starts a stopped daemon again, or settles one an earlier run left, and finds a
daemon already holding the environment asks it to resume, naming no attempt, before it takes it
for the environment's daemon. One that resumes goes on serving, and no stop of any earlier attempt
can end it; one that has been told to stop is waited for until it has gone, and then the daemon is
started again as it was recorded. One that does not listen is either starting or on its way out:
it is waited for until it answers, or until it has gone and the recorded daemon is started. Where
another daemon of the store is starting meanwhile and holds the install lock for more than thirty
seconds, the environment cannot be looked at: the update says that, and names no process to stop.
A daemon that answers as the release asked for by the time it is looked at is serving, and is not
named either.

A control daemon speaks to a worker only at a compatibility level its release retains. It refuses a
worker at another level before anything but the hello is exchanged, `UNSUPPORTED_SCHEMA`, and says
in its log which session it has left running unreached, and why.

## Environments whose daemon did not run

When a control daemon starts, it migrates its registry if needed to the schema it reads for its
release. This migration does not run for all environments of a host, for instance if a second user
account, container or WSL distribution with a control daemon has not had its daemon run since an
earlier schema step. The update command only reads the registry at the schema for its release.

When a registry is at an earlier schema, the update command migrates it. It does this once every
daemon has stopped and it has taken the install lock and the lock for each environment, for each
environment whose registry records an earlier schema. It runs the registry migration for the
environment, the same as the control daemon does when it starts, and then it classes the registry
the same as other registries at the schema for the release for the command. It does not migrate a
registry at the same schema as the running release. The migration commits for each step,
so if the update command fails part way through, the registry will be at the version for the last
step that completed and the current release will continue from that point. With `--json`, it
includes in the `carried` list in the output the details for each registry it brings forward: the
environment, the schema it was at and the schema the migration brought it to.

The update command carries forward a registry to the schema of the release that runs it, because
that is the only release whose migration code the running program has. The registry will remain at
this schema until the control daemon for the environment runs for the new release the first time, or
until a later update carries it on. Changes in the registry's rows that a schema after the running
release's makes will not apply to the environment until that time.

If the update command cannot carry forward a registry, for instance because the registry is at a
later schema than the release reads, is missing a table or the command fails to carry forward the
registry for a step, it exits with status 1. It reports the environment and schema of the registry
it failed to carry forward, then starts again every daemon it stopped from the release still current
and does not switch the release. It never makes a table again, empty, for a registry that is missing
one, because the command would then not detect any running worker when it reads the empty registry.
An update that waits or fails after it carried a registry says in its message which registries it
had carried, which were then at the schema this release reads, and names any recorded environment it
could not reach, as below. A check carries nothing. An update to the release that is already
current, once it has settled any update an earlier run left part way, looks at no environment. So
neither lists a carried registry.

The update command does not fail if it cannot find the state for an environment. The store will list
the roots served by a previous control daemon for the environment, but the update command cannot
look at the identity for the environment because what holds it is not there, perhaps because the
container or distribution has stopped or a directory has been unmounted. It reports the roots and
reason in the outcome of a finished update or of a check, or as `not_reached` with `--json`, and
continues with the other environments. If a control daemon is running for the environment, it is
not handed over and keeps the release it runs. The update command does stop, before it stops anything, if
it fails in any other way to look at an identity; a link, or a file that is not a regular file, is
among those failures.

## When an update stops part way

The store's record says how far an update came, and each daemon's restart is recorded before that daemon is told to stop. The update stays recorded until every daemon it stopped answers again. The next `kr host update` or `kr host rollback` looks at what `current` actually names. Naming the release the update started from, the switch did not happen: every daemon the update recorded is started again from it, and the new release stays staged. Naming the new release, the switch happened. `kr host update --archive` of that same release starts every recorded daemon that is not running from it, and one that runs and does not answer as its daemon is named with how to stop it. Any other run asks each recorded daemon whether it answers as a daemon of the release now current, and starts none: a daemon of a release that failed may hold its environment and answer nothing, and every run that started it again would find the environment held again. Each look at an environment, before a daemon is started in it, waits up to thirty seconds for a control daemon that is starting; when that runs out, the daemon is not started, and the message names the process that holds each environment where one does. A daemon that still does not start leaves the update recorded, and the run exits with 1:

```text
kr: an update an earlier run left part way is not settled yet: a control daemon it stopped did not start again, and the next kr host update starts it before anything else, while kr host rollback goes back to 0.1.0+aaaaaaaaaaaa: the control daemon of environment 7c9e… (process 4242) is still running and does not answer; stop it with `kill 4242` and run kr host update or kr host rollback again
```

If an update that has switched leaves a daemon that cannot start, there are two ways out. `kr host rollback` goes back to the release the update began from (see "Rolling back from an update whose daemon did not start"). `kr host update --archive` of a release that does not have the fault goes on past it: the archive is checked before any daemon is started, the daemons the failed update owed are started from the new release, the release that failed becomes the previous one, and nothing stays recorded. If the archive is of the release that is already current, the daemons owed are started from it and the update is settled, or, if one does not start, the situation is reported as above. An update that has not switched cannot be rolled back; if its daemon does not start from the release that remains current, it holds every update and rollback until it does.

## Rolling back

```sh
kr host rollback                                # to the release this host was on before its last switch
kr host rollback --to 0.1.0+aaaaaaaaaaaa        # to another release the store keeps
```

Like `kr host update`, `kr host rollback` switches to a different release by surveying the workers of all live sessions and handing each control daemon over to the target release's. Like `kr host update`, `kr host rollback` records what it has done, so that a run which stopped part way is settled by the next run. Like `kr host update`, `kr host rollback` does not affect any live session. The session's worker, the session shell, and all its agents continue to run the release they were started in, and that release remains in the release store as long as anything holds it.

`kr host rollback` can be run only using the `kr` binary of the current release. The release to roll back to, either given with `--to` or the release that was current before the host was last switched, must already be in the release store (`kr host versions` lists the releases it holds) and must be older than the current release. (To go to a newer release, use `kr host update --archive`.) The target release’s manifest is read from the release store; it is not checked against the update channel’s root again, as it was checked when the release was accepted into the store, and the root may have changed since. If no release is given with `--to` and there is none to roll back to, `kr host rollback` exits with exit code 2 and says to name one with `--to`.

If a live session’s worker is running at a compatibility level that the target release’s control daemon will not speak, `kr host rollback` waits: it exits with exit code 9 and names the session. This is true both if the session was found during the first survey, when no daemon has been stopped, and if it was found later, after some daemons had been stopped; each daemon that was stopped is started again in that case.

```text
kr: the rollback to 0.1.0+aaaaaaaaaaaa waits: session 7 runs kr-worker/0.2.0+bbbbbbbbbbbb with protocol 0.48.0, which the control daemon of 0.1.0+aaaaaaaaaaaa does not speak; run kr host rollback again once that has changed
```

### Rolling back from an update whose daemon did not start

An update can switch `current` and then find that a control daemon it stopped will not start from the new release. That is the case a rollback is for. The update stays recorded as switched. `kr host rollback`, run with the `kr` of the release now current, goes back to the release the update began from. It does not take the release before that, which is what a rollback takes when nothing is left recorded. After two updates that each left a daemon that did not start, it takes the release the first began from, which is the last whose daemon ran. `--to` still names any older release.

The rollback does not start the daemon of the release that failed. It asks each daemon the update recorded whether it answers as a daemon of `current`. If every one does, the update is settled and the rollback goes back from there as it does after any update. If not, it takes the same survey, hands over the daemons that run, checks the stores, takes the locks and switches, as for any switch. After the switch it starts, from the older release and in the way the record says each was started, every daemon it stopped and every daemon the failed update still owed. Where the failed update and the rollback both recorded a daemon for an environment, the rollback's record, which is the newer, is used. The release that failed becomes the previous release and stays in the store.

The check of the stores is the one every switch makes, against the stores as they stand. A control daemon of the release that failed may have changed a store before it ended, so the older release can find a store at a version it does not read. The rollback is then refused, naming the store, and the failed update stays recorded. `kr host update --archive` of a release that fixes the fault goes on past it, so a store the older release cannot read does not leave the host with no way forward.

A rollback, or an update that goes on past a failed one, that stops before its own switch leaves the failed update recorded, with the daemons it had stopped added, and the next run takes it up again. One that stops after its switch is finished by `kr host update --archive` of the release now current, which starts what it and the failed update owed from that release, whatever state the record shows, because the run goes by what `current` names. A `kr host rollback` after it starts none of them: it asks, as above. The trust the host holds is never lowered on the way: the root the failed update recorded is kept even if the root file of the release that failed is gone, and a root file that is there and cannot be read refuses the switch, as it does for any switch.

A daemon of the release that failed that holds its environment and answers nothing is not stopped by the updater, as no daemon it did not stop is. The rollback, or an update to a release that fixes the fault, waits with exit code 9 and names the process in its message, with the `kill` command that stops it. Run the command again after stopping the daemon with the given `kill` command. A daemon that is still starting holds the store's start lock, and the message then names the process that holds each recorded environment where one does; where none is named, run the command again once the daemon has started or stopped.

Three limits. A rollback after a rescue whose own daemon did not start has a default target that is newer than `current`, so it is refused as not older: name an older release with `--to`, or update to a release that fixes the fault. The registry of an environment is copied to the temporary directory to be classed, so a registry too large for that directory refuses the rollback, naming the environment. And the `kr` used to run a rollback must be from the current release. It is therefore not possible to run a rollback from a release whose `kr` cannot run.

### What a daemon started again keeps

A control daemon that an update, a rollback or the undo of a refused switch starts again is started with the variables that decided its paths in the daemon it replaces, and with none of those that the `kr` which starts it has and the daemon did not. When a daemon makes way it states the value of each of `HOME`, `TMPDIR`, `XDG_RUNTIME_DIR`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME`, `KR_RUNTIME_DIR`, `KR_STATE_DIR`, and on Windows `LOCALAPPDATA` and `USERPROFILE`, that it has, and which it has none of, together with the directory it reads its configuration document in. The store's record keeps both, and the daemon is started again with exactly those variables, whatever the `kr` that starts it has. It inherits all other environment variables from `kr`, as before. A daemon that cannot state one of them as text does not make way, and the update waits with a message that names the variable. A record that an earlier release left holds no variables, and its daemon is started as it always was, with the environment of the `kr` that starts it.

Whether a daemon is started again by the service manager is decided by the configuration document it reads, at the directory it said: where that document chooses the service start, the manager starts it, with the manager's environment, and any other daemon is started as above. So a daemon a person started by hand whose document chooses the service start is started again by the manager, and a daemon the manager started whose document chooses nothing is started again as above. The manager is asked through the definition `kr host startup` wrote, which is found from the `HOME` and `XDG_CONFIG_HOME` of the `kr` that asks it: a `kr` run with other values for them cannot start the daemon that way, and says so.

The configuration document is looked for where a daemon that made way said it reads it, as well as where the `kr` that runs the update puts it. The first is where the restarted daemon reads it; the second is where a daemon started later by a command of the same account would. An environment with no running daemon says nothing, so its document is looked for only where the `kr` puts it, and a document that only a daemon started later with other variables would read is not looked at. A daemon that meets a document it does not understand uses the defaults and changes nothing; `kr doctor` reports it.

### What the older release has to be able to read

Rolling back is only safe if the stores on disk are in a format that the target release can read (see "Stored formats"). After stopping all control daemons and locking all environments, but before anything is brought forward, `kr host rollback` opens each store the target release’s manifest specifies, at the path that manifest gives. If a store is at a version that is not in the range of versions the target release reads for it, `kr host rollback` does not switch to the target release or bring any store forward, starts again each daemon it stopped, and exits with exit code 1, naming the stores that cannot be read, the environments they are in, the versions they are at and the range of versions that the target release reads for them:

```text
kr: the switch to 0.1.0+aaaaaaaaaaaa was not made, and no store was brought forward, because it cannot read the stores as they are: registry of environment 7c9e… at …/registry.sqlite records schema version 7, and 0.1.0+aaaaaaaaaaaa reads versions 1 to 6
```

`kr host update` performs this same check before it switches to a new release. In performing this check, `kr host update` and `kr host rollback` follow these rules:

- A store that is not mentioned in the manifest of the target release is not checked; the target release does not read it. Similarly, a store that does not exist yet is not checked; the target release will create it and write it at whatever version it will write it, and any subsequent release which reads that version will be able to read it.
- If a record does not have a version, it is taken to have the version specified by the manifest of the target release for that case (which will be 0 unless the manifest says otherwise).
- If a database lacks a version number, or has more than one version number, a record is not JSON (or is not a map in canonical encoding when the containing store is recorded as being a member of a CBOR map), a store has a version number that is not a whole number, or a store is not a regular file, it is refused by name as not having a version number that can be shown to be in range.
- As always, the default configuration will be loaded if the configuration document can’t be read or if the version of the document is not a whole number (so also if it’s a number above 18446744073709551615, which cannot be read as one). So in those cases, the configuration document won’t be refused. If the document can be read and has a whole number as version, it will be treated like the other stores. So if the version is not within the range specified in the manifest of the target release, it will be refused (so also if it’s too small or if it’s larger than the version of any release that will read the store). The configuration document will be looked for in the directory its daemon said it reads it in when the daemon made way, in the state directory of the environment, where this `kr`'s own environment variables put it, and in the home directory of the account under which `kr` is run. A daemon that made way is started again with the variables it had, so it reads the first of these. The others are where a daemon started later by a command of this account would read it. An environment with no running daemon says nothing, and a document that only a daemon started later with other variables would read is not looked at.
- A registry that is behind the version the running `kr` reads is brought forward by an update before the target release meets it, so the check uses the version that the running `kr` reads and the refusal says so. A rollback brings no registry forward: the release it goes to reads a registry no newer than its own, and the schema of the running `kr` may be beyond that, so the check uses the version the registry has. A registry behind the schema of the running `kr` was not opened by a daemon of that release, so the workers it records are classed from a private copy brought forward to that schema; a worker that holds the switch still holds it. The registry is not migrated and no record of it changes; the check takes into the file what a daemon that ended by a signal left in its log, as an update's does. Nothing is brought forward before the check.
- The names of any stores, specified by the release to be switched to, that have a scope or a way of recording their version that the running `kr` doesn't know about will be listed as stores the release to be switched to won't be able to read.

### What is kept, and what does not go back

The release that a rollback leaves becomes the previous release and stays in the store. The store keeps the current release, the previous one, one staged for a later update, and any release a running program holds. A session started under the newer release keeps that release in the store, and `kr host versions` shows it as held.

Rolling back will not decrease the root the host will trust. A release contains the root with which the release was built (a first release that carries no root adds none). The host stores the newest root of any release it has been switched to. When `kr host update` or `kr host rollback` is run, before the environments will be surveyed or any daemon will be stopped, the root the switch will settle on will be calculated: the newest of the root stored on the host, the root of the release the host is currently switched to and the root of the release to which the host will be switched. That root will be stored when the update is recorded, before any daemon will be told about the update. When the update is settled, the root the host will trust will be taken from the recorded update. No releases will be read when the update is settled. So the root stored on the host is never replaced by an older one. (If an update was recorded by an earlier build of `kr`, the update doesn’t contain the root. When that update will be settled, the root will be calculated from those roots of its two releases that can be read, as they stand.) When `kr host update` is run, the new release will be checked against the newest of the root stored on the host and the root of the release the host is currently switched to. So after rolling back to a release with the first root, archives signed with a key the newer root retired are refused. If a root can’t be read or if two roots have the same version but are different, an error will occur when `kr host update` or `kr host rollback` is run, before any environments will be surveyed or any daemons will be stopped (after an unfinished update will be settled).

To move forward again, give `kr host update --archive` an archive of a newer release. An archive of the release just rolled back from can be given just like any other archive, except that the copy of it in the store can't be replaced while a session of that release is live, and the update then waits, exiting with exit code 9. This does not hold for a release that carried a rotation and whose manifest only the retired key signed: after a rollback to the release before it, that archive is refused like any other signed with a retired key, and the way forward is a later release signed with a key the newer root names.

When a host is rolled back, the control daemon of the release the host is rolled back to is started with the arguments of the control daemon it replaces and the variables that decided its paths, or, where its document chooses the service start, by the service manager from the definition that was created when `kr host startup` was run. If for some reason it cannot be started, the rollback is still recorded, and `kr host update --archive` of the release that is now current will try to start it before doing anything else. (`kr host rollback` after that, however, will not try; it asks, and goes back from the release that is now current. See "Rolling back from an update whose daemon did not start".) It can also be started manually, by running it with whatever arguments it needs. (The service definition that `kr host startup` created runs the control daemon through `current`, so it always runs the control daemon of the release to which the host is switched.)

When `kr host update --check` is run, the stores will not be checked. But if a store is listed in a way this version of `kr` doesn’t know, the store will still be refused and a release without a store in its manifest cannot be rolled back to. Stores that are mentioned in the manifest of the release the host will be rolled back to but that are not present on the host, and environments that can’t be reached, will not be checked. A `kr` command that writes a record between the check and the switch is not held off. This cannot cause problems today since all records written by commands are version 1 and thus read by all releases. The update suite fails when the version of such a record is raised past 1 while nothing holds commands off a switch, so the first release that needs more has to build that first: every writer of a versioned record would take a lock that an update holds exclusively across its check and its switch, and would refuse to write a version that the current release does not write. A `kr` outside an installed release, and a program of a release older than that rule, would still not be held off. The registry stores session create requests, closure records and the configuration it accepted, and most changes to those raise the version of the registry, so a rollback across such a release is refused. On Windows, `kr host rollback` says what `kr host update` says: that the host keeps no store of releases.

## Stored formats

Every database or JSON record that a program keeps under a state root and reads back is a store, and every store has a version. The lock names what is not a store, and why: for example the per-session journals, which keep the archive's own rule, locks, markers and logs. A store's version is the version of all its tables and all the values kept in them (for the registry, that includes the create request recorded for a session, the record made when a session closes, and the configuration document an environment accepted). That version is recorded in the store, as the one row of a table, as SQLite's own `user_version`, or as a member of the record. Changing any of those, a table or the kind of value kept in one, raises the store's version, and the release carries the step that takes an earlier store forward. But those steps only go up. A release reads stores from the lowest version it brings forward up to the version it writes, and refuses a store that is above that. Two stores, the configuration document and the terminal preference, are loaded in every release as empty when they cannot be read.

The registry file is opened for writing by the registry, the grant store, the device store and the pairing tables. Each of these creates and migrates its own tables when it opens the file. The file has a single version number, which any change to the tables or kept values of these four parts raises, with a step in the registry's chain that is empty when the writer's own open does the work. A migration opens the other three before it writes the version, whether it is a daemon starting or an update carrying the file forward. A file that a migration brought to a version therefore has all four writers at least at the shape that version stands for. A file whose version an earlier build recorded before the other writers had opened it is not covered by that: each writer brings its own tables to the current shape the next time it opens the file.

Note that the version number may not be present in records written to other stores by older releases. In that case the records are treated as if their version number was 0. For example, the record used by the `kr` client to record answers not yet sent and the plan to merge two machines are both recorded in KR-CBOR-1. The version is stated for the record in the current release but not for older releases. The version will be written when a release next gets a chance to write the records. For the enrolment record and the machine group this is when the daemon next opens them; for terminal preference it is when the daemon starts; for shell entries it is when `kr shell install` or `kr shell remove` holds them; for the action record that the agent's installation uses it is when a client requests that action again, and the result will be converted to the latest record shape at the same time. Failure to write the stamp doesn't cause an error for the agent action record or when reading terminal preference; it does cause an error when opening the enrolment record, the machine group, or when holding the shell entries, and the message names the file. Any of these records that this doesn't reach will continue to have version number 0 and will continue to be read as the version the manifest gives for a record that states none. The agent installation record has its own version number and is converted when reading. A catalogue database an earlier build wrote has no version number and will be read as though it were version 0, and `user_version` will be set to 1 when it is next opened.

### What a release says about its stores

A release's manifest lists each store its programs read. For each store it gives the version which will be written and the lowest version from which that release brings the store forward:

```json
{ "store": "registry", "scope": "environment", "path": "registry.sqlite",
  "recording": { "kind": "sqlite_table", "table": "schema_version" },
  "version": 7, "migrates_from": 1 }
```

The scope says where the path starts: `install` for the store of releases, `state_root`, `environment` for an environment’s state directory, or `configuration` for the configuration document, which is sought where “What the older release has to be able to read” says. If the path ends with `/*.` and an extension, such as `/*.json` or `/*.answer`, it names a directory in which multiple records of that extension may be stored. The version is recorded in a table (`sqlite_table`), in SQLite's own `user_version` (`sqlite_user_version`), or in a member of a JSON object (`json_member`) or of a map in KR-CBOR-1 (`cbor_member`). If a release is offered that does not list any stores, the host refuses that release.

Each store mentioned here must be maintained for as long as the data stored within it needs to be maintained. This means that each store's name, scope, path, and recording method must be maintained for as long as that store is maintained. If a release intends to move the location of a store then it must mention the new store in this listing; the old store will still exist but will have a higher version number than previous releases will know how to read. When an older `kr` that doesn't know how to interpret the scope or recording method of a store is asked to switch to a release that does include a store using that scope or recording method then it must refuse and name that store. This means that a release that adds a scope or recording method must understand those new features but not use them - it must not include any stores using those features in this list. The next release can then use those features, and when an older `kr` checks whether it should switch to that release it will already know how to interpret those features.

### The lock

The file `stored-formats.lock`, at the root of the repository, maps each store to its manifest entry, to a digest of what its version stands for, and to the names of the types it keeps. The digest includes the definitions of each database a store keeps, as a running daemon creates them. For each type a store keeps, in a database or in a JSON record, it includes the schema the protocol generates for that type (omitting any type definition names or prose in the type, but including the name given to the type in the table definitions), or, for a kept type that belongs to one crate and has no such schema, its source code. Where the table declares them, it includes the words the code matches stored text against by hand. It includes the names each store owns, and the files and directories within them. A list of words the table does not declare is not in the digest.

The update suite checks this by starting a daemon, running a session and checking that the code generates the same digest as the lock. If the digest has changed but the version has not then it fails, asking for the version to be raised and the lock to be written. The lock can be written by running the ignored test `write_the_lock`. This refuses if the digest has changed and the version has not, if the version is lowered, if a store is moved to another place or if a store is dropped. This is to ensure that changes are given a new version; it can be avoided by editing the lock by hand, but that will be checked by whoever reads the change to the lock. If the lock already exists and can’t be read then writing the lock also refuses, to make sure that any refusal isn’t lost.

The lock also names everything else under the state root, along with the reason it has no version: locks, markers, logs, directories containing content, leftovers from crashes, and the per-session journals, which keep the archive's own rule. After a daemon has run, every entry of the state root and of each environment's directory must be a store or be named, and a database found anywhere which is neither fails the check. The names in the source and those in the lock are compared, so an exception that is not in the committed lock fails the check.

It is worth noting what the check does not do: it does not compare the lock with the lock on the main branch (so a change to the lock is for a person to review), it does not check that all of the types in a store are declared, it does not check that all types nested inside a given type are declared, and it does not check for encoding differences (e.g. the difference between a JSON and CBOR encoding of a UUID or 64-bit number).

## Windows

A Windows host keeps no store: a directory link there cannot be replaced in one step by a user who
does not administer the machine. Its installer replaces the release, and `kr host install`,
`kr host update`, `kr host rollback` and `kr host versions` say so.
