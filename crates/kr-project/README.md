# The project service

`kr-project` owns the repositories a person works in, the working copies selected on them, and every
Git invocation KalaReach makes. `docs/project/` describes the ten methods, the identity model, the
staged publication and the credential rule. This file describes one thing: the boundary each Git
invocation runs inside, and exactly which mechanism holds which guarantee on each platform.

The Git that runs outside all of this is the one that says which Git this host has. Resolving the
program starts it two to four times at startup — for its version and its own helper directory, and
again for the copy under that directory — each with an environment of nothing and no repository
named, and none of them under a boundary.

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

Three guarantees, on the platforms that can hold them. macOS and Linux can; Windows cannot, and the
service refuses there rather than claiming them, which the table and the section after it explain.

**Only Git executes.** The Git program, the helpers under Git's own `--exec-path`, and the approved
credential broker's ssh program for a remote that needs one. A driver, filter, hook, credential
helper, pager, filesystem monitor or `core.sshCommand` planted anywhere else — in the repository, in
the staging directory, in the invocation's own temporary directory — cannot be executed, whenever it
was planted.

One addition, and it is exactly bounded. Git builds two things as command strings and starts them
through the system shell: its connection to a repository over its own transport, and its call to a
credential helper. So an invocation that clones — from a local path, over ssh or over https — has
that shell in its execution list as well. Every such invocation is a clone that checks nothing out:
no attribute is consulted, so no driver, filter or text conversion is looked for, and a hook is
looked for in a directory this service owns and keeps empty, which is a fixed override rather than
anything the clone decides. The checkout that follows is a separate invocation whose execution list
holds no shell at all, and it is the one that consults the repository's attributes.

**Only this operation's network.** A local operation reaches no address and nothing may listen. An
operation that reaches a remote may open outbound connections on the ports its transport uses — 443
and 80 for https, 22 for ssh, and the port the validated remote URL named where it named one — and
resolve the remote's name over the same kind of connection. Nothing may listen there either.

**Only this operation's directories are written.** The repository's working tree and its Git common
directory, the destination the operation reserved, and one temporary directory created for this
invocation. Git's temporary files go in that directory rather than in one shared with everything
else on the machine. When the invocation ends the directory is taken away by the record this service
wrote before it made it, and only if it is empty but for this service's own mark; what is not is
left where it is, with a line saying so. The paragraph on it below says what that does and does not
establish.

**Directories, not names.** Every directory the boundary is built from is opened first and required
to be the object its record names: the working tree by the identity the repository's record carries,
the Git common directory by its own, the reserved destination by the identity the reservation
returned. A directory substituted at one of those names is refused before anything starts. The child
then does not start at a path either: it moves into the open working directory before the boundary
is applied and before Git runs, with `-C .` as its only directory argument.

What the kernel then enforces is this: a file is opened for writing only inside the subtree of one of
those granted root objects, as the kernel works that out **when the file is opened** — by the object
itself on Linux, where the rules are attached to the opened directories, and by the resolved path on
macOS, where the profile names them. Neither kernel asks again on each write through a descriptor
already open, so a file opened inside a granted subtree and then moved out of it is still written
through that descriptor.

After the child has gone, each granted root is required to still be the object it was before its
result reaches a caller, and a root that is not ends the run with this service's declared honest
result. That second reading is **detection** and is described as such: it says that a root changed,
it does not keep one from changing, it is on those roots and not on every descendant of them, and
two readings cannot tell a change made and undone from no change at all.

**Reads are not confined on macOS or Linux.** Git reads the system's shared libraries, its locale
data and its certificate store, and a read confinement that missed one of those would fail an
operation for a reason that has nothing to do with safety. What a repository can reach by reading is
what the account the service runs as can reach, as it was before. Windows is the exception: its
mechanism confines reading with everything else, and what an invocation reads outside the
directories the operation owns is granted by name.

## Which mechanism holds which guarantee

**Windows runs no Git at all.** Its mechanisms cannot hold two of the three guarantees, so the
service refuses there rather than claiming a boundary it does not have; the last section says which
two and why. The table below describes what is written for that platform, not what it enforces.

| | macOS | Linux | Windows (refused) |
| --- | --- | --- | --- |
| Execution | A sandbox profile permitting `process-exec` on this invocation's own execution list and nothing else, applied by the system's own launcher before it runs Git | Landlock, with the execute right on this invocation's own execution list, on Git's helper directory and on the system's program loader, and nowhere else | An application container granted read and write on the repository, and **refused** the execute right there, so a permission inherited from the same directory cannot add it back, though one written on a file itself can |
| Network | The same profile: no rule at all for a local operation, and one outbound rule per port for a remote one | Landlock's TCP connect rules per port for a remote operation, and a system-call filter that makes a socket only of a family the boundary accounts for: the two that reach no machine but this one for any operation, the internet ones for a remote operation and only as a stream socket, and nothing else at all, listening included | The container's capabilities: none at all for a local operation, and the client capability for a remote one, which does not bound ports — one of the two reasons the service refuses here |
| Writes | The same profile, which permits `file-write` under the operation's own directories and nowhere else | Landlock's write rights, attached to the opened objects rather than to their names, and never carrying the execute right | The container's grants on those directories |
| Descendants | The child leads its own process group, and ending it ends the group | The same | A job object the process is created inside, which it cannot leave and which ends everything in it |

## What a platform refuses rather than pretends

Where a guarantee cannot be enforced from outside Git, the operation that needs it is refused. None
of these falls back to reading the configuration and hoping.

* **A kernel older than Linux 6.2** cannot mediate truncation, so a process could shorten a file the
  boundary never made writable. No Git is run there, and a bubblewrap container around the service
  does not change that: the refusal is about what this kernel can enforce rather than about what
  surrounds the process. Supporting such a kernel means a different mechanism, not a wrapper.
* **A kernel older than Linux 6.7** has no rules for which addresses a process reaches, so an
  operation that needs a remote is refused there. Local operations still run: their filesystem
  confinement is the same, and the system-call filter that refuses them an internet socket does not
  depend on the kernel's Landlock version.
* **A machine whose system calls this service does not hold the numbers for** refuses every
  invocation rather than installing a filter that would not mean what it says.
* **A host with no launcher to apply a sandbox profile with**, or **no shell for an invocation that
  has to reach a repository**, refuses that invocation rather than running it unenclosed.
* **Windows, every invocation.** Two of the three guarantees are not things an application container
  can hold: a permission written on a file itself beats the refusal this service writes on the
  directory above it, and a container's capability permits reaching the network or nothing without
  bounding which ports. So the service refuses there, says which guarantee it cannot make, and the
  platform task that qualifies this host on Windows is what changes the mechanism. A third limit
  would have mattered had the first two not: on an ordinary installation Git lives somewhere only an
  administrator may change the permissions of, so the container could not have been granted read and
  execute on it either.
* **A platform with none of these mechanisms** runs no Git at all.

## What is left

Stated rather than implied.

**A substitution inside a granted subtree is outside the guarantee.** The tree Git works in is the
object this service opened, so nothing can redirect that. What a substitution can still reach is a
directory Git was *given by name* — a reserved worktree destination, which on macOS the path rules
still permit and which on Linux does not arise, because the rules there are attached to the opened
objects — and a directory put at an unrecorded name *inside* a tree the operation owns, which no
confinement that grants a tree can refuse part of. The first ends the run with the declared honest
result, because the destination is a granted root and its identity is read again. The second is a
limit rather than a guarantee: the only writer who could put a directory there is a writer under
this same account, who could write those files directly and needs no substitution to do it. What
that writer still cannot get is anything executed, or any address the operation was not given.
Waiting for Git establishes that Git has gone rather than that everything it started has.

**On Windows the execution refusal would rest on permissions a repository can carry its own.** The
container is refused the execute right on the directories the operation owns, and that refusal beats
every permission that reaches those files the way it does. What it does not beat is one written on a
file itself, which Windows consults first, and a writer who can create files in the repository can
write one. That is why the service refuses on Windows rather than claiming the guarantee.

**On Linux a socket is made only of a family the boundary accounts for.** Landlock's rules are about
TCP, and a system-call filter reads scalar arguments while an address is behind a pointer, so
nothing there could bound where a datagram goes. Rather than permit one, the boundary refuses it,
and it refuses by naming what may be made rather than what may not: a filter written the other way
round would permit every family it had not heard of, the ones that reach the machine this one runs
inside among them. Two families are accounted for whatever the operation is — the one that reaches
this machine's own services by a path rather than an address, and the one a C library asks the
kernel about this machine's own addresses on. A remote operation adds the internet families, on
which the only socket is a stream socket of the protocol Landlock's port rules govern, because a
stream socket of another protocol is one those rules would say nothing about. Everything else is
refused, listening included, and the call that makes a pair of sockets is judged by the same
families as the one that makes a single socket. Turning a name into an address goes over the same
kind of connection, which the child is told to do and for which the port a resolver answers on is
added to the rules, on any address, because which machine answers a name is not this service's to
decide. A system whose resolver will not take that instruction cannot resolve a name inside the
boundary, and the operation fails saying so.

**An invocation's temporary directory is this service's mark, not its birth certificate.** Neither
macOS nor Linux offers a call that creates a directory and hands back the object it created, so
creating one and opening it are two acts and nothing can prove the object that opened is the object
that was made. What this service does instead: the name goes into a record of its own *before*
anything of that name is created; the directory is made through the handle this service holds on the
directory above it, under a name of thirty-two random characters; a second such name is written
inside it as a mark; and the directory is then opened and required to hold that mark and nothing
else and to be one object across two opens. What that establishes is that the directory the
invocation gets is one object carrying this service's own mark — not that this service created it,
because a directory put at the name before the mark was written would be marked as readily. The
directory they are all made in is the service's own, open to the account the service runs as and to
nobody else, so putting anything at a name in there is already that account's own doing.

**Nothing in there is removed that this service has no record of making, and nothing is removed by
descending.** When an invocation ends, and again when the service starts and sweeps what a daemon
that died mid-invocation left, the name is opened, the object is required to be the one the record
names, the directory is required to hold this service's own mark and nothing besides, the mark is
required to be the object the record names as well, and only then is the mark taken out and the
directory removed. A directory holding what Git left behind, a directory that is no longer the
object the record names, a mark that is not the file this service made, and a directory this service
never recorded making are all left where they are, each with a line saying which and why. What was
left stays in the record, so the next start tries again rather than forgetting it. A record this
service cannot read takes nothing away at all.

One act in that is still by name: removing the directory itself. Neither platform removes a
directory that an open handle names, so an empty directory a same-account writer puts at that name
in the instant between the check and the removal is one this service would remove. It cannot remove
anything that is not empty.

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
