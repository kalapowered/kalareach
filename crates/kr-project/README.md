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
built from the directories this service opened, applied to the child before Git exists, and gone
when the invocation ends.

## What it holds

**Only Git executes.** The Git program, the helpers under Git's own `--exec-path`, and the approved
credential broker's ssh program for a remote that needs one. A driver, filter, hook, credential
helper, pager, filesystem monitor or `core.sshCommand` planted anywhere else — in the repository, in
the staging directory, in the invocation's own temporary directory — cannot be executed, whenever it
was planted.

One addition, and it is exactly bounded. Git starts its connection to a repository over its own
transport as a command string, which the system shell runs, so an invocation that clones from a
local path or over ssh has that shell in its list as well. Every such invocation is a clone that
checks nothing out: nothing in one consults a repository's attributes, so nothing in one looks for a
driver, filter or hook, so there is nothing in one for a repository to reach the shell through. The
checkout that follows is a separate invocation whose list holds no shell at all.

**Only this operation's network.** A local operation reaches no address and nothing may listen. An
operation that reaches a remote may open outbound connections on the ports its transport uses — 443
and 80 for https, 22 for ssh, and the port the validated remote URL named where it named one — and
resolve the remote's name. Nothing may listen there either.

**Only this operation's directories are written.** The repository's working tree and its Git common
directory, the destination the operation reserved, and one temporary directory created for this
invocation and removed with it. Git's temporary files go in that directory rather than in one shared
with everything else on the machine.

**The child starts in a directory rather than at a name.** This service opens the directory, records
the object it opened, and the child moves into that open directory before the boundary is applied and
before Git runs, with `-C .` as its only directory argument. A tree substituted at the name
afterwards is therefore not the tree Git works in. The boundary's own rules name paths, because that
is what the mechanisms take, so a substitution moves the verified tree out from under them: the
invocation fails with this service's declared answer and the substituted tree is never written.

**Reads are not confined.** Git reads the system's shared libraries, its locale data and its
certificate store, and a read confinement that missed one of those would fail an operation for a
reason that has nothing to do with safety. What a repository can reach by reading is what the account
the service runs as can reach, as it was before.

## Which mechanism holds which guarantee

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Execution | A sandbox profile compiled into the child before it runs Git, permitting `process-exec` on Git's program and helper directory and nothing else | Landlock, with the execute right on Git's program and helper directory and nowhere else | An application container whose grants on the repository carry read and write and no execute right, and read and execute on Git's own installation |
| Network | The same profile: no rule at all for a local operation, and one outbound rule per port for a remote one | Landlock's TCP rules for a remote operation, and a system-call filter that refuses a local one an internet socket at all and refuses every one of them a listening socket | The container's capabilities: the client capability for a remote operation and none at all for a local one |
| Writes | The same profile, which permits `file-write` under the operation's own directories and nowhere else | Landlock's write rights on those directories, never with the execute right | The container's grants on those directories |
| Descendants | The child leads its own process group, and ending it ends the group | The same | A job object the process is created inside, which it cannot leave and which ends everything in it |

## What a platform refuses rather than pretends

Where a guarantee cannot be enforced from outside Git, the operation that needs it is refused. None
of these falls back to reading the configuration and hoping.

* **A kernel with no Landlock** cannot enclose an invocation at all, and none is run. A host in that
  position runs the service inside a bubblewrap container, which gives the same confinement from one
  level up.
* **A kernel whose Landlock cannot restrict which addresses a process reaches** (before the fourth
  interface version, which arrived in Linux 6.7) refuses an operation that needs a remote. Local
  operations still run: their filesystem confinement is the same, and the system-call filter that
  refuses them an internet socket does not depend on the kernel's Landlock version.
* **A machine whose system calls this service does not hold the numbers for** refuses every
  invocation rather than installing a filter that would not mean what it says.
* **A Windows host where Git is installed somewhere only an administrator may change** cannot be
  granted to the container, so the grant fails and the invocation is refused. Every grant this
  service makes is attempted before anything starts and taken away again when the invocation ends.
* **A platform with none of these mechanisms** runs no Git at all.

## What is left

Two things, stated rather than implied.

The boundary's rules name paths, because every platform's mechanism takes paths. The object the
child works in is the one this service opened, so a substitution cannot redirect it; what a
substitution can do is make the invocation fail, which is the declared answer rather than a silent
one.

A repository's configuration can still make Git refuse to do something, produce a limitation or
name a helper this service will not run. That is the restricted profile's business and it is
unchanged: the boundary is in addition to the configuration neutralisation, not instead of it.
