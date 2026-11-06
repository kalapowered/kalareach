# The project service

`kr-project` owns the repositories a person works in, the working copies selected on them, and every
Git invocation KalaReach makes. `docs/project/` describes the ten methods, the identity model, the
staged publication and the credential rule. This file describes one thing: the boundary each Git
invocation runs inside, and exactly which mechanism holds which guarantee on each platform.

The Git that runs outside all of this is the one that says which Git this host has. Resolving the
program starts it two to four times, the first time anything needs it and not before (for its
version and its own helper directory, and again for the copy under that directory), each with an
environment of nothing and no repository named, and none of them under a boundary. On Linux the
first need is the proof the daemon makes when it starts; elsewhere it is a request, or work the
daemon resumes when it starts. A host whose Git is missing, or cannot answer, still opens the
service. Each request that runs Git is refused until a resolution finds one, and a resolution that
failed is made again by the next request that arrives when no resolution is under way.

Resolution is bounded, because it is made outside every boundary of a program this host has not yet
shown to be Git. The questions are given ten seconds in all to answer, and an answer of 64 KiB; the
clean-up that follows takes a few seconds more at most. A program still under way when the time ends
is ended with the processes in its group, and one that has ended has the rest of its group ended
with it. A program whose answer passes 64 KiB is ended at that point and refused, whatever it would
have exited with, and no more than that is kept. A process that has left the group and keeps the
pipe is out of reach: the answer is refused after a second, or when the time the program was given
ends if that comes first, and this host closes its end of the pipe, so this host holds nothing of
the process. It may go on, and a write it makes to the closed pipe fails. A child that cannot be
waited on is refused, and nothing is signalled by its number, which may be another process's by now.
A program that does not answer in time, a child that cannot be waited on or collected, output that
cannot be read, and a host too short of descriptors, processes or memory to look for the program, to
ask it, or to resolve the path to it, are faults that pass, as is the time running out before the
program's end or the end of its output is seen, even when the wait is not looked at again until the
time is out, and whatever a read returns after it, bytes or an end, is not taken: the look is
refused as `UPSTREAM_UNAVAILABLE`; the other refusals are `HOST_NOT_CONFIGURED`, among them a
program that has ended and left its output open for a second inside the time it was given, as a read
made after that second and inside the time found it. A look is made by one request at a time, and a
request that arrives while one is under way waits for that look and shares its result, so a program
that hangs is started once for all of them. A copy of Git under the helper directory that does not
answer in time, answers with more, or ends and leaves its output open, refuses the whole look. One
that cannot run, or answers differently, leaves the program on the search path as the one that runs.
A host that is short of descriptors, processes or memory when a copy is started, or when the path of
the copy or of the helper directory it reports is resolved, refuses the look rather than taking the
copy for one that is not there, cannot run or answers differently.

## Why there is one

The service reads a repository's configuration before it runs Git, blanks every driver the
repository defines, and reads the configuration again afterwards to refuse a result produced under
one it did not read. That is worth having and it is not enough. Git resolves the directory it was
pointed at for itself and reads the configuration for itself, after those readings, so somebody
writing to the repository under the same account can add a driver, or put a different tree at the
path, in between. Reading again notices that afterwards. It does not undo a helper that ran or a
write that landed in the wrong tree.

So the invocation is also enclosed, by the operating system, from outside Git. The enclosure is
built from the objects this service opened, applied to the child before Git exists, and gone when
the invocation ends.

## What it holds

The boundary gives three guarantees, on the platforms that can hold them. macOS and Linux can;
Windows cannot, and the service refuses there rather than claiming them, which the table and the
section after it explain.

**Only Git executes:** the Git program, the helpers under Git's own `--exec-path`, and the approved
credential broker's ssh program for a remote that needs one. A driver, filter, hook, credential
helper, pager, filesystem monitor or `core.sshCommand` planted anywhere else (in the repository, in
the staging directory, in the invocation's own temporary directory) cannot be executed, whenever it
was planted.

One addition, and it is exactly bounded. Git builds two things as command strings and starts them
through the system shell: its connection to a repository over its own transport, and its call to a
credential helper. So an invocation that clones (from a local path, over ssh or over https) has that
shell in its execution list as well. Every such invocation is a clone that checks nothing out: no
attribute is consulted, so no driver, filter or text conversion is looked for, and a hook is looked
for in a directory this service owns and keeps empty, which is a fixed override rather than anything
the clone decides. The checkout that follows is a separate invocation whose execution list holds no
shell at all, and it is the one that consults the repository's attributes.

**Only this operation's network.** A local operation reaches no address and nothing may listen. An
operation that reaches a remote may open outbound connections on the ports its transport uses (443
and 80 for https, 22 for ssh, and the port the validated remote URL named where it named one) and
resolve the remote's name over the same kind of connection. Nothing may listen there either.

**Only this operation's directories are written:** the repository's working tree and its Git common
directory, the destination the operation reserved, and one temporary directory created for this
invocation. An invocation is granted the directories its own work needs and no more: the one that
moves a reference with its expected old value is granted the Git common directory alone, and the
working tree is not writable by it. Git's temporary files go in that directory rather than in one
shared with everything else on the machine. When the invocation ends the directory is taken away by
the record this service wrote before it made it, and only if it is empty but for this service's own
mark; what is not is left where it is, with a line saying so. The paragraph on it below says what
that does and does not establish.

**Directories, not names.** Every directory the boundary lets an invocation write in is opened first
and required to be the object the caller holds an identity for: the working tree by the identity the
repository's record carries, or, for a checkout handed over by path, by the one read from the
directory opened a moment before; the Git common directory by its own; the reserved destination by
the identity the reservation returned; the invocation's own temporary directory by the identity read
when it was made. A directory substituted at one of those names is refused before anything starts.
The programs an invocation may execute (Git's, the approved ssh program and the connection shell)
and Git's helper directory are not written in, and nobody holds an identity for them: Linux opens
each by its path when it makes its rules, and the profile on macOS names each by its path. The
child then does not start at a path either: it moves into the open working directory before the
boundary is applied and before Git runs, with `-C .` as its only directory argument.

What the kernels then enforce is this: **opens for writing succeed only inside the granted root
objects' subtrees as they stand at open time; execution stays confined; the granted roots are
re-confirmed by identity before the spawn and after the run.** Which object a subtree is, is decided
by the opened directory on Linux, where Landlock's rules are attached to it, and by the resolved
path on macOS, where the profile names it.

Neither kernel asks again on each write through a file already open, so a file opened inside a
granted subtree that a same-account writer then moves out of it is still written through that
descriptor. That is an accepted limit: the writer who could move it already holds write access to
it.

The re-confirmation after the run is **detection** and is described as such: it says that a root
changed, it does not keep one from changing, it is on those roots and not on every descendant of
them, and two readings cannot tell a change made and undone from no change at all.

**Reads are not confined for the owner's own operations.** Git reads the system's shared
libraries, its locale data and its certificate store, and a read confinement that missed one of
those would fail an operation for a reason that has nothing to do with safety. The owner already
holds the account's authority over the owner's own files, so what such an operation can reach by
reading is what the account the service runs as can reach, as it was before. An operation performed
for a caller bounded by a grant is confined on Linux and on macOS and refused elsewhere, and the
section on that caller below says what it is promised. Windows confines reading with everything
else, and what an invocation reads outside the directories the operation owns is granted by name.

## Which mechanism holds which guarantee

**Windows runs no Git at all.** Its mechanisms cannot hold two of the three guarantees, so the
service refuses there rather than claiming a boundary it does not have; the last section says which
two and why. The table below describes what is written for that platform, not what it enforces.

| | macOS | Linux | Windows (refused) |
| --- | --- | --- | --- |
| Execution | A sandbox profile permitting `process-exec` on this invocation's own execution list and nothing else, applied by the system's own launcher before it runs Git | Landlock, with the execute right on this invocation's own execution list, on Git's helper directory and on the system's program loader, and nowhere else | An application container granted read and write on the repository, and **refused** the execute right there, so a permission inherited from the same directory cannot add it back, though one written on a file itself can |
| Network | The same profile: no rule at all for a local operation, and one outbound rule per port for a remote one | Landlock's TCP connect rules per port for a remote operation, and a system-call filter that makes a socket only of what the boundary can account for: a connected pair of local ones for any operation, the internet families for a remote one and on those only a TCP stream socket, and nothing else at all, listening included | The container's capabilities: none at all for a local operation, and the client capability for a remote one, which does not bound ports (one of the two reasons the service refuses here) |
| Writes | The same profile, which permits `file-write` under the operation's own directories and nowhere else | Landlock's write rights, attached to the opened objects rather than to their names, and never carrying the execute right | The container's grants on those directories |
| Reads | The whole filesystem for the owner. For a caller bounded by a grant, the same profile with read rules only for the objects the invocation is granted, named by their resolved paths, and for the support set named for this host's Git, and a refusal when a filesystem is mounted beneath a granted directory; beyond those, only the names and attributes of the root directory, of symbolic links and of the directories above a granted path | The whole filesystem for the owner. For a caller bounded by a grant, Landlock with no rule on the whole filesystem: read rights only on the objects the invocation is granted and on the support set named for this host's Git, and a refusal when a filesystem is mounted beneath a granted directory | The container's grants on those directories, and read grants by name on what it is lent |
| Inherited descriptors | Every descriptor the service opens is closed when a child executes, and the child marks every other descriptor from the fourth on to close when it executes the launcher; a system that cannot list them fails the spawn | The same, and after the rules are applied the child marks every descriptor from the fourth on to close when it executes Git; a kernel that cannot mark them fails the spawn | An explicit list of the three standard handles, and no other |
| Descendants | The child leads its own process group, and ending it ends the group | The same | A job object the process is created inside, which it cannot leave and which ends everything in it |

## What a platform refuses rather than pretends

Where a guarantee cannot be enforced from outside Git, the operation that needs it is refused. None
of these falls back to reading the configuration and hoping.

* **A kernel older than Linux 6.2** cannot mediate truncation, so a process could shorten a file the
  boundary never made writable. No Git is run there, and a bubblewrap container around the service
  does not change that: the refusal is about what this kernel can enforce rather than about what
  surrounds the process. Supporting such a kernel means a different mechanism, not a wrapper. The
  refusal is `HOST_NOT_CONFIGURED`, which a client does not send again, and it says which interface
  version the kernel has and which the boundary needs. It is made before Git is looked for. A kernel
  that reports no interface at all is refused the same way. It may have the interface and still
  withhold it from this process, because Landlock is not enabled at boot or a system-call filter
  surrounds the process, and the refusal names those causes too.
* **A kernel older than Linux 6.7** has no rules for which addresses a process reaches, so an
  operation that needs a remote is refused there under the same code and in the same words. The
  refusal comes when the invocation that reaches the remote is built, and not before Git is looked
  for. Local operations still run: their filesystem confinement is the same, and the system-call
  filter that refuses them an internet socket does not depend on the kernel's Landlock version.
* **A machine whose system calls this service does not hold the numbers for** refuses every
  invocation rather than installing a filter that would not mean what it says, as
  `HOST_NOT_CONFIGURED`.
* **A host with no launcher to apply a sandbox profile with**, or **no shell for an invocation that
  has to reach a repository**, refuses that invocation rather than running it unenclosed.
* **A caller bounded by a grant, on Windows or on a platform with no boundary.** Neither confines
  what Git reads, and Windows runs no Git at all. Such a caller's invocation is refused with that
  reason rather than run with the owner's reach.
* **A caller bounded by a grant, on a macOS host that cannot run Git inside the read-confined
  profile.** That is a host with no launcher, one whose Git does not start under the profile, and
  one whose support set cannot be named: a library Git loads is not found, or lies where no support
  object may (the machine's shared temporary directory, `/private/etc`, the top of a person's home
  or of its `Library`, the top of a volume, a package prefix such as `/opt/homebrew` or
  `/usr/local`, or an application bundle), or a program in Git's helper directory is built for the
  other kind of Mac. The account's own home and `Library` are held by every name they have: the
  one the environment gives, the one the system's account database gives, and each with its links
  resolved, so a home reached through a link, one outside `/Users` and a `Library` moved elsewhere
  are refused as the plain ones are, and so is a directory that holds one. Each refusal names the
  object, and the host does not qualify.
* **A caller bounded by a grant, on a Linux host that cannot name the support set** is refused when
  a program in Git's helper directory has a loader, or a library its loader resolves, that cannot be
  named or lies in a system directory such as `/etc`, `/proc` or `/dev`. So is an invocation that
  finds a support object gone when it starts. Each refusal names the object.
* **A caller bounded by a grant, over a directory with another filesystem mounted beneath it**, or
  with an operation that would reach a remote, is refused. A location says nothing about which
  providers this host may reach for such a caller, and its reads name no certificate store and no
  resolver file.
* **Windows, every invocation.** Two of the three guarantees are not things an application container
  can hold: a permission written on a file itself beats the refusal this service writes on the
  directory above it, and a container's capability permits reaching the network or nothing without
  bounding which ports. So the service refuses there and says which guarantee it cannot make. A
  third limit would have been decisive had the first two not applied: on an ordinary installation
  Git lives somewhere only an administrator may change the permissions of, so the container could
  not have been granted read and execute on it either.
* **A platform with none of these mechanisms** runs no Git at all.

## What a caller bounded by a grant is promised

An operation performed for a caller bounded by a grant, such as a paired device, reaches every name
through a location the owner authorised. Which callers reach these operations at all is decided at
the daemon's door, and `docs/host/README.md` says which. This is what the project service holds for
such a caller once one does.

On Linux and on macOS each Git invocation of such an operation runs inside one boundary that
confines what the program reads. The paragraph below describes Linux's, and the one after it
macOS's.

On Linux it is one Landlock ruleset that confines what the program reads. It may read the
directories the operation owns and the ones it is lent, such as a clone's source, along with Git's
own program and helper directory, the profile's own empty directories and the four device nodes. It
may also read a support set named for this host's Git: the loader each of Git's programs names for
itself, and the directories holding the libraries that loader resolves for them. Nothing else the
account can read is readable, and nothing in `/proc`, `/dev/shm` or `/etc` is. The invocation writes
only the operation's own directories and the device nodes. It executes only the installed Git, never
anything in the location, which it may read and write but not execute. It reaches no network, and a
remote clone is refused for such a caller. Before Git executes, every descriptor the child holds
from the fourth on is marked to close, so a descriptor the service left open is no way round the
rules. The configuration audit runs inside the same boundary, so a configuration that includes a
file outside the location fails when it is read rather than being noticed afterwards.

On macOS it is a sandbox profile that denies by default and names what the program may read: the
directories the operation owns and the ones it is lent, Git's own program, the profile's own empty
directories, the device nodes and a support set. Git's helper directory is named for execution and
not for reading.

The support set is the libraries the system does not supply itself. The system's libraries are
mapped from a shared cache without opening files, so a Git that links only those has an empty
support set, and the Git that comes with Xcode is one. A Git that brings libraries of its own, as
Homebrew's does, has the directory of each. They are found by reading the load commands of Git and
of each program in its helper directory, then of every library those name, following `@rpath`,
`@loader_path` and `@executable_path`. Each program is followed on its own, since what those names
mean to a library depends on the program that loaded it; a helper that is a symbolic link is the
program the link leads to, which is what the loader names it by, and a hard link is a program of its
own with its own `@executable_path`. Only this machine's own kind of program is read: a program in
Git's helper directory built for the other kind of Mac, which the system could run under
translation, refuses the set and says so.

The system judges the path a file has, not the name Git opened it by, so every path in the profile
is resolved first. A link in the tree to a file outside is refused at the file it leads to, and so
is the data volume's own name for that file. A rule written with that name grants nothing, since the
system never matches it, so a directory given by it makes the operation fail and does not widen what
is read.

Three reads go beyond the grants, and each tells a name or an attribute and no content. The root
directory lists the names at the top of the filesystem and nothing beneath them; the loader opens it
to start any program. A symbolic link may be read wherever it is, which tells where it points. The
directories above a granted path may be examined, which tells that they exist and what their
attributes are; Git resolves a name one directory at a time and asks about each. The profile also
allows `sysctl-read` without a filter, as the owner's profile does: it is a question to the kernel
and not the read of a file, and this boundary does not narrow it. A program inside the profile can
read the argument list of another process of the same account through it, and through the same
call without that rule, which the Linux boundary's closure of `/proc` has no counterpart for.

The profile names paths where the Linux ruleset holds objects. A granted directory that a writer
under the same account renames or replaces while Git runs is read under the name the profile holds.
After the run this host opens again the directories the operation owns and reports one that is not
the object it started against, and it cannot tell a change made and undone between the two readings
from none. The paths the invocation is lent, a clone's source for one, and the support set are held
by name alone: one of them replaced while Git runs is read under its name and nothing detects it. A
mount at a lent directory itself is no mount beneath it, so the check does not refuse it, and for a
lent directory nothing reports it. Nothing prevents any of it. The other limits are Linux's: the
invocation writes only the operation's own directories, executes only the installed Git and reaches
no network, and a remote clone is refused for such a caller.

The mount check reads the table of mounted filesystems from the kernel without asking any
filesystem to answer for itself, so a share that has stopped answering cannot hold an invocation. It
refuses what any program of this account can attach to a directory it owns: a disk image, a network
share or a user-space volume. The table gives a mount the name the profile holds, so a mount carried
beneath a granted directory by moving a directory above it, and one made through the data volume's
own name for a path, are refused as one made at the granted directory's own name.

So the boundary bounds what the caller's own request can reach, repository content included. A
symbolic link to a file outside, an object store borrowing another repository's objects, a
configuration including a file outside and a descriptor left open are all refused.

**It does not make the location's tree private.** Git reads the tree as the host presents it, and
this holds for every directory the invocation is granted, the support set's and the profile's own
included, not only for the location. Immediately before each invocation this host reads the mount
table and refuses the operation when it names a mount point beneath a granted directory's path. That
stops a filesystem, or a second view of another directory, mounted there at that moment. It compares
paths, though, and a granted directory can have other names: bound somewhere else on the host, it
can have a filesystem mounted beneath that other name, and a symbolic link in the tree to the other
name then reaches that filesystem through the granted directory's own rule. The check does not see
that, and it sees nothing after its own moment either. A filesystem mounted beneath a granted
directory while Git runs, a directory holding a mount that another program moves beneath one while
Git runs, and an automatic mount that Git's own lookup of a path sets off are all read as part of
the tree. So is a hard link already inside the tree to a file elsewhere on the same filesystem.
Another program running as this host's user account, or the host's own mount arrangement, can put
any of these there. The confinement holds against what the caller can reach through repository
content; it does not defend the location against this host's own user account or the host's own
mount arrangement.

A host that cannot hold this refuses such a caller and says why: on Windows, on a Linux kernel older
than 6.2, on a macOS host with no launcher or whose Git does not start under the profile, where the
support set cannot be named or would take in a system directory such as `/etc`, where a support
object is gone, and where the mount table names a filesystem beneath a granted directory. A host
proves it by running one Git invocation under exactly these rules, when the daemon starts and at
each `host.doctor`. On macOS that run shows that the launcher applied the profile, since it ends
before Git starts when it cannot, and that Git starts inside it with the support set named. It does
not try a read outside the grants: the profile has no rule that would allow one.

## What is left

What is left is stated rather than implied.

**The support set is named once and kept.** It is named when the first invocation for such a
caller needs it, and kept until the service restarts, a refusal as well as an answer. A Git replaced
in place leaves it naming what is no longer there: on macOS a package manager that upgrades a
library moves it to a directory that carries the version. An invocation that needs what moved then
fails closed, and so does a `host.doctor` proof when it is Git's own program that needs it, until
the daemon restarts. A library restored after the set was refused is not found either.

**A substitution inside a granted subtree is outside the guarantee.** The tree Git works in is the
object this service opened, so nothing can redirect that. What a substitution can still reach is a
directory Git was *given by name* (a reserved worktree destination, which on macOS the path rules
still permit and which on Linux does not arise, because the rules there are attached to the opened
objects) and a directory put at an unrecorded name *inside* a tree the operation owns, which no
confinement that grants a tree can refuse part of. The first ends the run with the result the
service declares for a changed root, because the destination is a granted root and its identity is
read again. The second is a limit rather than a guarantee: the only writer who could put a directory
there is a writer under this same account, who could write those files directly and needs no
substitution to do it. What that writer still cannot get is anything executed, or any address the
operation was not given. Waiting for Git establishes that Git has gone rather than that everything
it started has.

**On Windows the execution refusal would rest on permissions a repository can carry its own.** The
container is refused the execute right on the directories the operation owns, and that refusal beats
every permission that reaches those files the way it does. What it does not beat is one written on a
file itself, which Windows consults first, and a writer who can create files in the repository can
write one. That is why the service refuses on Windows rather than claiming the guarantee.

**On Linux a socket is made only of what the boundary can account for.** Landlock's rules are about
TCP, and a system-call filter reads scalar arguments while an address is behind a pointer, so
nothing there could bound where a datagram goes. Rather than permit one, the boundary refuses it,
and it refuses by naming what may be made rather than what may not: a filter written the other way
round would permit everything it had not heard of, the sockets that reach the machine this one runs
inside among them. What may be made is short:

* A **connected pair of local sockets**, for either kind of operation, of the stream kind and of no
  protocol besides. Such a pair is joined to its own other half, cannot be connected again and
  cannot be given a destination, so it has no way to reach anything.
* For a **remote** operation, the internet families, and on those only a stream socket of the
  protocol the port rules govern, because a stream socket of another protocol is one those rules
  would say nothing about.

Everything else is refused, listening included: a single local socket, a pair of the kind that
carries a destination on every message, and every family this list does not name. A local socket
with an address is the one a program reaches another program on this machine by name with, and a
proxy on one, or a connection handed over one already made, would be a way past every port rule
here. The family the kernel answers questions about this machine's own addresses on is refused for
the same reason: on a host that lets an ordinary account make a network namespace of its own, a
socket of that family reaches another program rather than the kernel.

What that costs is what a C library asks over a local socket or over that family: its name service
cache, a resolver's own interface, and the kernel's list of this machine's addresses. Each is a step
a C library falls back from (to the files, to the resolver itself over TCP, and to asking about both
kinds of address), and the child is told to use that connection (`RES_OPTIONS=use-vc`), with the
port a resolver answers on added to the rules on any address, because which machine answers a name
is not this service's to decide. **A host whose name service has no fallback to the resolver, or
whose resolver will not take that instruction, cannot turn a name that needs the resolver into an
address inside this boundary**, and the operation fails saying so.

**An https remote named rather than numbered is looked up over IPv4.** The library Git fetches with
asks whether this machine has IPv6 by making a datagram socket and throwing it away, and a datagram
socket is the one thing this filter cannot bound; refused that question, the affected builds of that
library answer it "no" and ask the resolver for IPv4 addresses alone. **A name that has only an IPv6
address therefore fails that lookup inside this boundary.** An address written out in full does not
go through it, and neither does `localhost`, which that library answers out of its own head; both
need saying separately because neither is evidence about the other. Git's own transport over ssh
does not ask the question at all. Closing this without permitting a datagram socket means a build of
that library whose question is asked on a stream socket, which this filter already permits.

A credential broker that would reach an agent or a secret service over a local socket cannot do so
inside the boundary either. That is a real limit and not a theoretical one:
`git-credential-libsecret` is one of the brokers this service will run, and what it asks over a
local socket it will not get here. A broker whose answer comes from its own store on disk works; one
that needs another program on this machine does not, and the operation fails rather than the
credential being found some other way.

**An invocation's temporary directory is this service's mark, not its birth certificate.** Neither
macOS nor Linux offers a call that creates a directory and hands back the object it created, so
creating one and opening it are two acts and nothing can prove the object that opened is the object
that was made. What this service does instead: the name goes into a record of its own *before*
anything of that name is created; the directory is made through the handle this service holds on the
directory above it, under a name of thirty-two random characters; a *second empty directory* of
another such name is created inside it as a mark, which fails outright if anything is at that name
already; and the outer directory is then opened and required to hold that mark and nothing else and
to be one object across two opens. What that establishes is that the directory the invocation gets
is one object carrying this service's own mark, not that this service created it, because a
directory put at the name before the mark was made would be marked as readily. The directory they
are all made in is the service's own, open to the account the service runs as and to nobody else, so
putting anything at a name in there is already that account's own doing.

**Nothing in there is removed unless the record names both objects, nothing is removed by
descending, and no file and no directory with anything in it is removed at all.** When an invocation
ends, and again when the service starts and sweeps what a daemon that died mid-invocation left, the
record has to name the directory *and* the mark inside it; the name is opened and the object is
required to be the one recorded; it is required to hold this service's own mark and nothing besides;
the mark is required to be the object recorded as well; and only then is the mark taken away and the
directory after it. Both of those removals are the kind that takes only an empty directory, so this
path cannot destroy a file's contents or anything held in a directory: a name holding a file, or a
directory with something in it, fails the removal instead.

What is left where it is, each with a line saying which and why: a directory holding what Git left
behind, a directory that is no longer the object the record names, a mark that is not the object
this service made, a file where a mark should be, a directory this service was recorded as *about
to* make but never got as far as identifying, and a directory this service never recorded at all.
What is left stays in the record, so the next start tries again rather than forgetting it. A record
this service cannot read takes nothing away and stops the service rather than being written into.

Two acts in that are still by name: taking away the mark, and taking away the directory. Neither
platform removes a directory that an open handle names, so an empty directory a same-account writer
puts at one of those names in the instant between the check and the removal is one this service
would remove, along with whatever a directory carries that is not an entry in it. In the same
instant a writer can move this service's own directory elsewhere and leave an empty one behind, and
the record then says the directory has gone while it is in fact somewhere else. Those are the whole
of what this can cost, because neither removal takes a file or a directory with anything in it.

**The port list would not be enforced on Windows.** An application container's capability permits
reaching the network or nothing at all; bounding which ports it reaches needs a system-wide filtering
policy an ordinary account cannot set. That is the second of the two reasons the service refuses
there.

**A Windows grant whose removal fails would be left behind.** Each is taken away when the invocation
ends and the container profile is deleted with it, and neither is checked, because there is nothing
left to do about a failure at that point. One invocation at a time changes a path's permissions, so
two of this service's own invocations cannot lose each other's entries; another program editing the
same permissions at the same time still can.

**A repository's configuration can still make Git refuse to do something**, produce a limitation or
name a helper this service will not run. That is the restricted profile's business and it is
unchanged: the boundary is in addition to the configuration neutralisation, not instead of it.
