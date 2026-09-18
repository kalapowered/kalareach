# The project service

`kr-project` owns the repositories a person works in, the working copies selected on them, and every
Git invocation KalaReach makes. `docs/project/` describes the ten methods, the identity model, the
staged publication and the credential rule. This file describes one thing: the boundary each Git
invocation runs inside, and exactly which mechanism holds which guarantee on each platform.

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
resolve the remote's name. Nothing may listen there either. The table below says where the port list
is enforced and where it is not.

**Only this operation's directories are written.** The repository's working tree and its Git common
directory, the destination the operation reserved, and one temporary directory created for this
invocation and removed with it. Git's temporary files go in that directory rather than in one shared
with everything else on the machine, and it is taken away through the handle this service opened
when it made it rather than through the name it gave it.

**Directories, not names.** Every directory the boundary is built from is opened first and required
to be the object its record names: the working tree by the identity the repository's record carries,
the Git common directory by its own, the reserved destination by the identity the reservation
returned. A directory substituted at one of those names is refused before anything starts. The child
then does not start at a path either: it moves into the open working directory before the boundary
is applied and before Git runs, with `-C .` as its only directory argument. And after the child has
gone, every one of those directories is required to still be that object before anything it produced
is used: a substitution made while Git ran is this service's declared refusal rather than a result
nobody can account for.

**Reads are not confined on macOS or Linux.** Git reads the system's shared libraries, its locale
data and its certificate store, and a read confinement that missed one of those would fail an
operation for a reason that has nothing to do with safety. What a repository can reach by reading is
what the account the service runs as can reach, as it was before. Windows is the exception: its
mechanism confines reading with everything else, and what an invocation reads outside the
directories the operation owns is granted by name.

## Which mechanism holds which guarantee

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Execution | A sandbox profile permitting `process-exec` on Git's program and helper directory and nothing else, applied by the system's own launcher before it runs Git | Landlock, with the execute right on Git's program and helper directory and nowhere else | An application container granted read and write on the repository, and **refused** the execute right there, so no other permission the repository carries can add it back |
| Network | The same profile: no rule at all for a local operation, and one outbound rule per port for a remote one | Landlock's TCP connect rules per port for a remote operation, and a system-call filter that refuses a local one an internet socket at all and refuses every one of them a listening or raw socket | The container's capabilities: none at all for a local operation, and the client capability for a remote one. **The port list is not enforced here**; see below |
| Writes | The same profile, which permits `file-write` under the operation's own directories and nowhere else | Landlock's write rights, attached to the opened objects rather than to their names, and never carrying the execute right | The container's grants on those directories |
| Descendants | The child leads its own process group, and ending it ends the group | The same | A job object the process is created inside, which it cannot leave and which ends everything in it |

## What a platform refuses rather than pretends

Where a guarantee cannot be enforced from outside Git, the operation that needs it is refused. None
of these falls back to reading the configuration and hoping.

* **A kernel older than Linux 6.2** cannot mediate truncation, so a process could shorten a file the
  boundary never made writable. No Git is run there, and that is the whole of it: a bubblewrap
  container around the service would give an operator the same confinement from one level up, and
  this service would still refuse inside one, because the refusal is about what this kernel can
  enforce rather than about what is around the process. Supporting such a kernel means a different
  mechanism, not a wrapper.
* **A kernel older than Linux 6.7** has no rules for which addresses a process reaches, so an
  operation that needs a remote is refused there. Local operations still run: their filesystem
  confinement is the same, and the system-call filter that refuses them an internet socket does not
  depend on the kernel's Landlock version.
* **A machine whose system calls this service does not hold the numbers for** refuses every
  invocation rather than installing a filter that would not mean what it says.
* **A host with no launcher to apply a sandbox profile with**, or **no shell for an invocation that
  has to reach a repository**, refuses that invocation rather than running it unenclosed.
* **A Windows host where Git is installed somewhere only an administrator may change** — the
  ordinary `C:\Program Files\Git` among them — cannot have the container granted read and execute
  there, so the grant fails and the invocation is refused. That is a real limit of this mechanism on
  an ordinary installation rather than a corner case.
* **A platform with none of these mechanisms** runs no Git at all.

## What is left

Stated rather than implied.

**A substitution while Git runs is refused rather than prevented.** Two of the three mechanisms
write their rules against paths, because that is what they take, so a directory put at one of those
names while Git ran is one the rules still permitted; and a directory put *inside* a tree the
operation owns is inside a tree the operation owns, which no confinement that grants a tree can
refuse part of. The object the child works in is still the one this service opened, and every
directory the boundary was built around is required to still be that object before anything the
child produced is used. So the answer is a refusal that names what changed. Landlock is the
exception for the first of the two: its rules are attached to the opened objects themselves.

**On Windows the execution refusal rests on permissions a repository can carry its own.** The
container is refused the execute right on the directories the operation owns, and a refusal beats
every grant that reaches the object the same way. What it does not beat is a grant written directly
on a file inside that directory, which Windows consults before it reaches an inherited refusal. A
writer who can create files in the repository can write such a grant. This is a property of the
mechanism rather than of the code, and it is one reason the platform is not qualified.

**A remote operation's non-TCP traffic on Linux is not bounded by address.** Landlock's rules cover
TCP, and a system-call filter reads scalar arguments while an address is behind a pointer. Turning a
host name into an address is what needs it. So for a remote operation on Linux the port list is a
TCP guarantee; a local operation has no internet socket at all and the question does not arise.

**The port list is not enforced on Windows.** An application container's capability permits reaching
the network or nothing at all; bounding which ports it reaches needs a system-wide filtering policy
an ordinary account cannot set. A local operation there still reaches no address, which is the half
of the guarantee the capability does express.

**A Windows grant whose removal fails is left behind.** Each is taken away when the invocation ends
and the container profile is deleted with it. Neither the removal nor the deletion is checked,
because there is nothing left to do about a failure at that point, so what may remain is a grant
naming a container that may still exist. One invocation at a time changes a path's permissions, so
two of this service's own invocations cannot lose each other's entries; another program editing the
same permissions at the same time still can.

**A repository's configuration can still make Git refuse to do something**, produce a limitation or
name a helper this service will not run. That is the restricted profile's business and it is
unchanged: the boundary is in addition to the configuration neutralisation, not instead of it.
