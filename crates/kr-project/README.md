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
| Network | The same profile: no rule at all for a local operation, and one outbound rule per port for a remote one | Landlock's TCP connect rules per port for a remote operation, and a system-call filter that makes a socket only of what the boundary can account for: a connected pair of local ones for any operation, the kernel's own address answers and the internet families for a remote one and on those only a TCP stream socket, and nothing else at all, listening included | The container's capabilities: none at all for a local operation, and the client capability for a remote one, which does not bound ports — one of the two reasons the service refuses here |
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

**On Linux a socket is made only of what the boundary can account for.** Landlock's rules are about
TCP, and a system-call filter reads scalar arguments while an address is behind a pointer, so
nothing there could bound where a datagram goes. Rather than permit one, the boundary refuses it,
and it refuses by naming what may be made rather than what may not: a filter written the other way
round would permit everything it had not heard of, the sockets that reach the machine this one runs
inside among them. What may be made is short.

* A **connected pair of local sockets**, for either kind of operation, of the stream kind and of no
  protocol besides. Such a pair is joined to its own other half and has no address.
* For a **remote** operation, the family the kernel answers questions about this machine's own
  addresses on, and only for that; and the internet families, and on those only a stream socket of
  the protocol the port rules govern, because a stream socket of another protocol is one those
  rules would say nothing about.

Everything else is refused, listening included: a single local socket, a pair of the kind that
carries a destination on every message, and every family this list does not name. A local socket
with an address is the one a program reaches another program on this machine by name with, and a
proxy on one — or a connection handed over one already made — would be a way past every port rule
here.

What that costs is what a C library asks over a local socket or over that family: its name service
cache, a resolver's own interface, and the kernel's list of this machine's addresses. Each is a step
a C library falls back from — to the files, to the resolver itself over TCP, and to asking about
both kinds of address — and the child is told to use that connection (`RES_OPTIONS=use-vc`), with
the port a resolver answers on added to the rules on any address, because which machine answers a
name is not this service's to decide. An address written out in full, and a name the files answer,
are reached either way. **A host whose name service has no fallback to the resolver, or whose
resolver will not take that instruction, cannot turn a name that needs the resolver into an address
inside this boundary**, and the operation fails saying so.

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
is one object carrying this service's own mark — not that this service created it, because a
directory put at the name before the mark was made would be marked as readily. The directory they
are all made in is the service's own, open to the account the service runs as and to nobody else,
so putting anything at a name in there is already that account's own doing.

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
