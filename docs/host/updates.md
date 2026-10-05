# Updating a host

A host installed with `kr host install` keeps each release it runs in a directory of its own and
never changes one in place. An update adds the new release beside the old one, makes it current in
one step, and replaces the control daemons. It never replaces a worker: a session keeps running the
release it started from, with that release's shell package and module tree, until it closes.

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
   lock, brings forward any registry that records an earlier schema (see "Environments whose daemon
   did not run"), and reads every environment's registry as it is. A log that a daemon ended by a
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

A daemon started by the service manager is started again by it; any other is started through
`current` with the arguments it was started with, in the directory it was started in, writing to
the environment's `controller.log`. A live session is never stopped, restarted or moved: its worker,
its shell and its agents go on running the release they started from, and that release, its module
tree among it, stays in the store until nothing holds it.

## What a release is, and how it is checked

A release archive is `kalareach-<target>-<release>.tar.gz`: one top directory holding `bin/`,
`shells/`, `share/` and `release.json`. `release.json` is the release's manifest in The Update
Framework's signed envelope: its release name and sequence, its commit, the target and the oldest
operating system it runs on, the protocol package version its programs were built from, the public
protocol majors it accepts, the compatibility levels its control daemon speaks to a worker at, its
shell packages, and every file with its length, SHA-256 digest and whether it is a program.

A release is taken in only whole and checked:

- The archive is refused at the first entry that is a link, a device, a sparse file or anything
  but a file or a directory, whose path is absolute or climbs out of the top directory, or that
  repeats a file. A file is written whole: an archiver that leaves the holes of a sparse file out,
  in GNU's form or in the POSIX form that carries `GNU.sparse` keys, writes an archive this host
  does not take. An archive that is not a regular file, a pipe among them, is refused at once.
- The manifest is signed by a threshold of the release keys the update channel's root names for its
  targets role. The root the host trusts is the one the current release carries, at
  `share/update-root.json`; a release carries that root or the one that follows it, the next
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

The store's record says how far an update came, and each daemon's restart is recorded before that
daemon is told to stop. The update stays recorded until every daemon it stopped answers again, so
a daemon that does not start, before the switch or after it, is started by the next run. The next
`kr host update` settles an update left part way before anything else, by what `current` actually
names. Naming the release the update started from, the switch did not happen: every daemon the
update recorded is started again from it, and the new release stays staged. Naming the new
release, the switch happened: every recorded daemon that is not running is started from it, and
one that runs and does not answer as its daemon is named with how to stop it. Each look at an
environment, before a daemon is started in it, waits up to thirty seconds for a control daemon
that is starting; when that runs out, the daemon is not started. A daemon that still does not
start leaves the update recorded, and the run exits with 1:

```text
kr: an update an earlier run left part way is not settled yet: a control daemon it stopped did not start again, and the next kr host update starts it before anything else: the control daemon of environment 7c9e… (process 4242) is still running and does not answer; stop it with `kill 4242` and run kr host update again
```

## Windows

A Windows host keeps no store: a directory link there cannot be replaced in one step by a user who
does not administer the machine. Its installer replaces the release, and `kr host install`,
`kr host update` and `kr host versions` say so.
