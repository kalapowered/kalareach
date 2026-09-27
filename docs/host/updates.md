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
finished by installing the same release again: the release it left is checked file by file, as a
staged release is, and made read-only before it is made current. Another release under the same
name, or one that has lost, gained or changed a file, is refused.

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
5. once every daemon has stopped, holds the install lock and reads the store's environments again,
   so an environment whose daemon started after the first look is found; holds every
   environment's lock, where a daemon the update did not stop holds the update; and reads every
   environment's registry: a worker at a level the new release does not retain, a worker that does
   not answer its challenge and has not ended, and a session still being started each hold the
   update;
6. switches `current` in one rename, lets go of the locks, starts each daemon as it was started
   before, now from the new release, and waits for each to answer as a daemon of it;
7. removes the releases nothing needs: not the current one, not the previous one, not one staged
   for a later update, and not one a running program holds.

An update that is held waits. It starts again every daemon it stopped, from the release still
current, keeps the new release staged for the next attempt, which checks it file by file again
before it uses it, and exits with 9. When a daemon it stopped does not start again, it exits with 1
instead, says which, and keeps the update recorded, as below:

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

- The archive is refused at the first entry that is a link, a device or anything but a file or a
  directory, whose path is absolute or climbs out of the top directory, or that repeats a file.
- The manifest is signed by a threshold of the release keys the update channel's root names for its
  targets role. The root the host trusts is the one the current release carries, at
  `share/update-root.json`; a release carries that root or the one that follows it, the next
  version, signed by a threshold of the current root's root keys as well as its own.
- Every file the manifest lists is there with its length and digest, and nothing else is.
- It is for this host's target, and this host's operating system is at or above its floor
  (the macOS release, or the GNU C library's version on Linux).
- It is newer than the current release.

Only then is it made read-only, flushed and renamed into `versions/`. What an archive says about a
file's mode or owner is not read: a file is a program when the manifest says it is.

A release that carries no update channel root can be installed with `kr host install`, which takes
the release's own word for what it is, and a host whose current release carries none has no key to
check any other release against: `kr host update` refuses every archive there, and says so.

## The handover

A control daemon is replaced by the release that updates the host, through
`host.update.handover`, which only the owner's own socket may call. It takes one of three steps:

| Step | What the daemon does |
| --- | --- |
| `prepare` | Closes its gate to new sessions, waits up to 45 seconds for the creates it has already started to settle, and answers with its process, the arguments it was started with and the directory it was started in. The gate stays closed for five minutes unless a `stop` or a `resume` comes first. |
| `stop` | Stops. It is refused when the gate is open, so a daemon whose preparation lapsed is never stopped while it is starting sessions. |
| `resume` | Opens the gate again. The update is not going ahead now. Refused, `ENVIRONMENT_UNAVAILABLE`, once the daemon has been told to stop: a stop and a resume are decided in the order they arrive, so a daemon that resumes is one no stop of the handover ends. |

A create that arrives while the gate is closed is refused with `RESOURCE_UNAVAILABLE`, naming the
release the host is being updated to; the caller creates the session again once the new daemon is
running. Every create the daemon had already started is finished before it answers `prepare`:
whichever release it launched, that worker has taken its own hold on its release by then. A create
that does not settle within the 45 seconds makes the daemon refuse the step, and the update waits.
Nothing a session is doing stops at any step: a worker belongs to the service manager, and the next
daemon finds it again.

An update that starts a stopped daemon again, or settles one an earlier run left, and finds a
daemon already holding the environment asks it to resume before it takes it for the environment's
daemon. One that resumes goes on serving, from then on whatever stop of the handover arrives; one
that has been told to stop is waited for until it has gone, and then the daemon is started again
as it was recorded.

A control daemon speaks to a worker only at a compatibility level its release retains. It refuses a
worker at another level before anything but the hello is exchanged, `UNSUPPORTED_SCHEMA`, and says
in its log which session it has left running unreached, and why.

## When an update stops part way

The store's record says how far an update came, and each daemon's restart is recorded before that
daemon is told to stop. The update stays recorded until every daemon it stopped answers again, so
a daemon that does not start, before the switch or after it, is started by the next run. The next
`kr host update` settles an update left part way before anything else, by what `current` actually
names. Naming the release the update started from, the switch did not happen: every daemon the
update recorded is started again from it, and the new release stays staged. Naming the new
release, the switch happened: every recorded daemon that is not running is started from it, and
one that runs and does not answer as its daemon is named with how to stop it. A daemon that still
does not start leaves the update recorded, and the run exits with 1:

```text
kr: an update an earlier run left part way is not settled yet: a control daemon it stopped did not start again, and the next kr host update starts it before anything else: the control daemon of environment 7c9e… (process 4242) is still running and does not answer; stop it with `kill 4242` and run kr host update again
```

## Windows

A Windows host keeps no store: a directory link there cannot be replaced in one step by a user who
does not administer the machine. Its installer replaces the release, and `kr host install`,
`kr host update` and `kr host versions` say so.
