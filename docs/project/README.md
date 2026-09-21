# Project reference

A **project repository** is a source tree in one execution environment. A **workspace** is one
selected working copy of it and the policy that says what a reviewer sees. `project_repository_id`
names the first, `workspace_id` the second, and neither is ever a path a client supplied.

Plugin catalogues are a different thing with a different vocabulary: `catalogue.*` configures where
plugin packages come from and cannot create a source repository.

## The ten methods

| Method | What it does | Authority |
| --- | --- | --- |
| `project.list` | The environment's repositories as scoped metadata | a scoped view |
| `project.read` | One repository, its workspaces, and the operation that created it | a scoped read |
| `project.init` | Creates an empty repository at an authorised destination | `project.create` |
| `project.clone` | Clones a validated remote into an authorised destination | `project.create` |
| `project.adopt` | Registers a checkout that is already there, changing nothing in it | `project.create` |
| `project.operation.cancel` | Stops owned repository work and reports its staging paths | the operation's owner |
| `workspace.list` | The workspaces of an environment or of one repository | a scoped view |
| `workspace.create` | Previews, and then creates, a shared or an isolated working copy | `workspace.manage` |
| `workspace.read` | One workspace's policy, its bound sessions and what it holds | a scoped read |
| `workspace.remove` | Removes a workspace under a retention policy | `workspace.manage` |

A view and a read never delete. `workspace.remove` is the only method that removes anything, and
what it may remove is the whole of the section below on retention.

## Identity is the object, not the path

A repository's identity is the stable filesystem identity of its Git common directory: the device
and inode on Unix, the volume serial and file index on Windows. A workspace's is that of its own
working tree.

* Renaming a checkout keeps both, so a record still names the same objects afterwards.
* A different repository moved to a recorded path has a different identity, and nothing is served
  from the record until the identity matches again.
* A linked worktree is a new object with a new identity, so adding one creates a record rather than
  widening a grant that covers an existing one.

Everything this host does to the filesystem itself goes through an open directory descriptor rather
than a path: the same authority model the transfer service uses for a staging area and for a
client's chosen destination. A destination is a parent directory resolved once and one
single-component name inside it: no separator, no traversal segment, no reserved device name.

A Git invocation is the exception, and it is stated rather than glossed over. Git resolves the
directory `-C` names for itself and reads the configuration for itself, so neither is under a handle
this host holds. What the host does about that is in the limits section below.

## Creating a repository

```text
project.init / clone / adopt
  │
  ├─ 1. resolve the destination        a parent handle and one name
  ├─ 2. probe it                       absent, empty, non-empty, or occupied
  ├─ 3. write the operation row        its key is the caller's action identifier
  ├─ 4. stage                          .kr-project-<32 hex>/tree beside the destination
  ├─ 5. record the staged witness      its identity and its creation instant; the row moves to
  │                                     `publishing`
  ├─ 6. publish                        one no-replace rename of that exact object
  └─ 7. write the repository row       the row moves to `completed`, the claim is settled
```

**A destination that exists is refused.** An empty directory is an existing destination too, and a
clone is never merged into one. The refusal names the one adoption flow that admits it:
`existing_checkout`, which reads what is there, records its identity and its current reference, and
writes nothing into the working tree. It does not fetch, does not check anything out and does not
touch the index.

**New content is staged in a private sibling.** The sibling is in the same parent as the
destination, so the publication is a rename inside one directory and cannot cross a filesystem. It
is created owner-only, so nothing under another account reads a repository this host has not
finished building.

**The publication replaces nothing.** On Linux and Apple platforms it is one system call that fails
when the destination name is taken (`renameat2(RENAME_NOREPLACE)` and `renameatx_np(RENAME_EXCL)`),
so an entry that appeared between the check and the publication is never overwritten however close
the race is. On Windows the guarantee is the platform's own: `MoveFileEx` refuses to rename a
directory onto a name that exists, and `MOVEFILE_REPLACE_EXISTING` does not apply to a directory.
The limits section below says which part of this has not been executed.

**The object published is the object that was staged.** The publication re-reads the staged
repository and refuses unless it is the one the row recorded, so a replacement between the recording
and the rename is refused rather than published under the same action.

**A crash is reconciled against the create token.** The operation row's key is the action identifier
the caller submitted, and the staged repository's *witness* is recorded before the rename: its
filesystem identity, and the instant the filesystem says it was created — or, where the platform
does not report a creation instant, its modification instant. So a replacement daemon
never asks "does the name exist"; it asks which name holds *that object*. The creation instant is
the second half of the witness because a filesystem reuses a device and inode pair once the object
that held them is gone, and reuse with the same creation instant is not something a filesystem
produces. Where a platform reports no creation instant, the witness is the identity alone and the
host says so rather than claiming more.

| What the replacement finds | What it does |
| --- | --- |
| The destination holds the staged object | Finishes the operation: writes the repository row and settles the claim |
| The staging directory still holds it | Finishes the same publication, which is not another clone |
| Neither holds it | Records the operation as unknown and keeps the staging path, named in the result. The cleanup deliberately leaves an `unknown` operation's staging path alone, because ownership of what is there is exactly what is uncertain |
| No witness was recorded | Nothing was published: removes the staged content and closes the operation |

A staging sibling's *name* goes on to the row before the directory exists, and the sibling's own
filesystem identity goes on to it as soon as it does. So the cleanup removes a name this host
recorded **and** checks that the object at that name is still the one it recorded: a repository a
user happened to call `.kr-project-something` is not this host's to delete, and neither is a
replacement at a name this host used once.

A failure *after* the rename landed is not a failure of the operation: the repository exists. The
row is in `publishing` with the witness, so the same reconciliation runs immediately rather than
recording a failure nothing would revisit.

**An operation is idempotent.** The action is claimed in the same transaction as the operation row,
and the row's key *is* that action identifier, so a second copy of one action finds the claim rather
than starting a second clone. A repeat after the operation settled is answered from its record; a
repeat while it is still running is told so and pointed at `project.read` or
`project.operation.cancel`. A failure is retained under its own code, so asking again with the same
identifier is owed what happened rather than a fresh attempt.

## Remotes, providers and credentials

A network operation names three things and carries no fourth.

1. **The transport** is `https`, `ssh`, or a local path on this host. Everything else is refused by
   name: `git://`, `ext::`, `file://`, an `http://` URL, and any `<transport>::<address>` form,
   which is how Git names a remote helper program. The allowlist exists because the set of
   transports Git can be talked into using is not closed.
2. **The URL carries no credential.** A password in the authority is refused outright rather than
   stripped, because a caller that sent one has a credential in its own state and needs to know. An
   `https` URL carries no user name either, since a token is often the user rather than the
   password. A query and a fragment are refused as well: a repository URL needs neither, and
   `?access_token=` is the other place a credential reaches remote state. An `ssh` remote keeps its
   user, because ssh needs it and an ssh user name is not a secret.

   No refusal repeats the URL it refused. A URL this host could not parse is one it could not vouch
   for either, and a malformed authority is exactly where a credential sits, so a refusal names what
   is wrong instead. What a diagnostic from Git itself may repeat is settled further down, under
   the restricted profile.
3. **The provider** is the host name as this host resolved it, recorded beside the remote so a
   receipt says which service was reached.
4. **The broker** is one this host has. It supplies a *program* — a credential helper, and an ssh
   command for the ssh transport — resolved to an absolute path inside Git's own helper directory.
   The host never sees the credential itself. A broker with no **transport** program is a refusal
   rather than an attempt: without ssh there is no way to reach an ssh remote at all.

   A broker with no **credential helper** is not that case. Git ships one for the platform's own
   secret store on some hosts and not on others, and an https remote that needs no credential is an
   ordinary thing to fetch, so the fetch goes ahead carrying none. What the profile guarantees
   either way is that no credential of the user's is used without the broker: the helper list is
   emptied, the ask-pass programs are empty and the terminal prompt is off, so a remote that does
   want a credential refuses the fetch rather than finding one somewhere this host did not grant.
   A failed attempt that carried no credential says so beside whatever Git said: what was available
   for it, rather than why it failed. This host cannot tell a refused authentication from a remote
   it never reached, and it does not repeat Git's own words, so what it can honestly add is the
   context a person on such a host would otherwise be missing.

After a clone the stored `remote.<name>.url` is read back and compared with the URL this host
passed. A rewrite, a helper or a version of Git that stored something else would be a credential in
remote state waiting to happen, so the clone is not published. Nothing this service prints repeats a
credential: a URL in a diagnostic has its password removed, and a remote's own record has no field
one could travel in.

## Workspaces

A workspace is `shared_existing` or `isolated`. There is no default, because the two make different
promises and a host that chose would be choosing for the user.

**`shared_existing`** is the user's own working tree, used where it is. Dirty and untracked files
stay exactly as they are. Every session bound to it sees the others' edits, and an apply to it is
best-effort conflict detection rather than compare-and-swap. Its policy includes every class, so
asking for a shared workspace with an exclusion is refused: an exclusion is what an isolated
workspace is for.

**`isolated`** materialises a separate working tree from a named base, and says how it is separated:

| Mechanism | What it separates | What it shares |
| --- | --- | --- |
| `git_worktree` | The working files | The objects, the references and the configuration, under the same account. **Not a security sandbox.** |
| `independent_clone` | The working files and the object store | Nothing. It costs the objects it copies. |

### The inclusion preview

The create interface previews what will be included, and the preview is `workspace.create` with
`preview_only` set. The parameters are the same type, so a client shows and creates from one object
rather than two that could drift apart in its own code. It is not a promise that the tree has not
changed between the two calls: the preview says so among its limitations, and a creation takes its
own reading.

Five classes, five decisions:

| Class | What it is |
| --- | --- |
| `dirty_file` | A tracked file with an uncommitted change |
| `untracked_file` | A file Git neither tracks nor ignores |
| `submodule` | A submodule, counted from the index and never looked inside |
| `generated_artefact` | A file an ignore rule covers |
| `binary_file` | Cuts across the others: a dirty or untracked file whose content is binary |

`binary_file` is a decision about content rather than about origin, so a policy that includes dirty
files and excludes binaries leaves a binary dirty file out. The test for binary is Git's own, a null
byte in the first eight thousand bytes of content as it is stored.

Content has a third answer. A path this host did not read — because the preview reads at most
twenty thousand of them, or because it could not open it at all — is `unknown` rather than text. An
exclusion of binary files leaves an unknown path out, because excluding what might be binary is the
direction that honours the request, and the preview says how many it could not classify.

Each entry also carries what the working tree holds for it: `present`, `deleted` or `unmerged`. A
copy is not the only way to carry an inclusion. A deletion the user has is carried by *removing* the
path from the new workspace, because the checkout put the base's copy there.

The counts cover every path the status reported, including the ones the bounded list leaves out; the
list says how many those are. `counts_complete` says whether the counts are the whole of their
classes. It is false when any bound was reached: a wholly ignored directory is one entry in Git's own
status output, so this host walks it to count and copy what an inclusion covers, and a directory
deeper or larger than the walk's bound, an entry the host could not read, a link or a device it did
not count, or a path it did not classify as text or binary all make every count a lower bound with
the reason among the limitations.

A submodule is counted from the index and never entered, so what a submodule holds is neither
measured nor copied. Including one records the decision and names the path among the creation's
`unapplied` list.

The preview also carries what a workspace of that kind cannot promise, in the host's own words: that
a worktree is not a sandbox, that a working tree can change between the preview and the copy, and
that a shared workspace's apply is best-effort. A client shows these rather than deciding for the
user.

### Nothing is cleaned, stashed or discarded

An exclusion means the new workspace holds the base's version of that file, or nothing where the
base holds nothing. It never means the original is touched. The service reads the source tree
and writes only into the new one.

An inclusion replaces the destination rather than writing over it: the copy is written to a name of
this host's own, derived from the destination's path, given the source's permission bits, flushed
to disk, and then renamed over the
destination. A rename replaces a file in one step, so the destination is either the base's file or
the user's and never half of each, and a failure anywhere before the rename leaves the destination
as it was. What the host could not carry it names rather than hides: a symbolic link, a device, a
submodule's own working tree, a path whose parent could not be created, a path whose permissions
could not be carried and a path whose destination could not be replaced all appear in the
creation's `unapplied` list, and so does a temporary file a failed copy left behind because even
its cleanup failed. The workspace is still returned because it is usable, and what it does not
hold is stated.

An **exclusion** of a dirty tracked file means the workspace holds the *base's* version of it, not
that the path is absent: the checkout put the base's content there and an exclusion is the host not
replacing it. A path the base does not have — an untracked file, an ignored one — is absent.

That rule is enforced from underneath as well as stated: the restricted profile's subcommand
allowlist does not contain `clean`, `stash`, `reset`, `restore`, `commit`, `push`, `revert`,
`rebase`, `merge`, `gc` or `prune`, and no invocation carries `--force` in any form. They are not
commands this service can run at all.

### Cleanup and retention

Cleanup is explicit, and it happens only after every session bound to the workspace has finished. A
live bound session refuses a removal whatever retention policy it carries. Neither session closure
nor marking a review complete removes anything: what closure does is record that the session ended.

| Policy | What it removes |
| --- | --- |
| `keep_everything` | Nothing, while the workspace holds anything. The result lists what. |
| `remove_retained` | Everything, including what is held. Carrying this policy *is* the user's approval of the list the first request returned. |

There is deliberately no third policy that removes the working files while keeping the dirty content
in them. Keeping content means capturing it, and capturing an immutable version of a workspace is
the change-set service's; a policy that claimed to keep what it had just deleted would be a lie.

**What a workspace holds is measured, not assumed.** An empty retention table does not establish a
clean tree: a workspace created from its base alone holds nothing, and then somebody edits a file in
it. So every removal reads the workspace's own status first and records what it found, and
`keep_everything` then keeps the workspace because of that as readily as because of a pin.

**Cleanup waits for every session and every run.** Both are recorded bindings and either refuses a
removal while it is live, whatever policy the request carries. A run can hold a workspace between
two sessions or after its last one ended, which is why it is its own binding rather than inferred
from a session.

**The reservation and the checks are one transaction.** The action is claimed, the holders are
counted and the workspace moves to `removal_pending` together, and nothing new may hold a workspace
from that moment. Otherwise a session bound between the check and the deletion would be a live
holder of a tree that was already going, and two copies of one removal action would both delete
before either was told it lost.

A **shared** workspace is the user's own working tree, so removing it removes the selection and no
file. No retention policy deletes a tree the user is working in.

A workspace record survives its removal, so a later read says what happened rather than nothing. An
isolated workspace's identity is what authorises the removal: it is recorded before anything is
written into the tree, it is checked before anything is removed, and a workspace whose
materialisation never recorded one is **refused** rather than removed. This host does not delete a
directory it cannot prove it created; the directory is left for a person to look at, and the reason
is on the record.

The deletion itself goes the way a staging sibling's does. The identity is checked through the open
handle, the contents are removed *through that same handle* so that no name in the path can be
swapped underneath them, and the name itself is taken away with an empty-directory removal, which
refuses a directory that is not empty. A directory whose metadata this host could not read at all
is not one it found absent, so it is not one it reports as gone either.

## The restricted Git execution profile

Section 14 requires brokered Git reads to run through argument vectors **and** a restricted
execution profile, and says outright that building an argument vector is not that isolation. So
every invocation this service makes goes through one type, which decides four things a repository
cannot argue with.

**Which program runs.** The Git binary is resolved once to an absolute path and its own
`--exec-path` is recorded with it. Both are passed explicitly, so an inherited `GIT_EXEC_PATH` or a
directory earlier on `PATH` cannot substitute another program. Git 2.32 or later is required,
because the profile rests on `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM`.

**What environment it runs in.** The child's environment is built from nothing and then filled in.
Every variable Git reads that can name a program — `GIT_EXTERNAL_DIFF`, `GIT_SSH`,
`GIT_SSH_COMMAND`, `GIT_ASKPASS`, `GIT_PAGER`, `GIT_EDITOR`, `GIT_TEMPLATE_DIR`,
`GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG_KEY_<n>` — is absent unless the profile put it
there. `PATH` holds the Git binary's own directory and its helper directory and nothing else, so a
remote helper somewhere on the user's path is unreachable. `HOME` is an empty directory this host
owns, so no `~/.gitconfig`, `~/.gitignore` or `~/.ssh/config` is read. The child has no terminal, so
nothing can prompt and nothing can page.

**What configuration applies.** `GIT_CONFIG_NOSYSTEM=1`, and the global and system files both point
at a zero-byte file this host owns, so the only configuration left is the repository's own. On top of
it go the host's overrides, carried as `GIT_CONFIG_COUNT` with a `GIT_CONFIG_KEY_<n>` and
`GIT_CONFIG_VALUE_<n>` pair for each one. That form beats every configuration file and reaches every
subprocess Git starts. It is used in place of `-c` because `-c` splits its argument at the first
`=`, so a configuration key whose subsection contains one could not be overridden at all. A
command-line `-c` would take precedence over this form, and nothing here passes one: the argument
checker refuses `-c` in any spelling, so the environment form is the only source of overrides.

Hooks are looked for in an empty directory this host owns; the filesystem monitor, the pager, the
editor, the credential prompt, the proxy, the alternate-reference command, the external diff, the
signature programs and the pack-serving hook are all set to nothing; the template directory a new
repository copies hooks from is an empty one this host owns; every transport is refused and the one
this operation validated is allowed back.

**No submodule is entered.** A submodule is its own repository, and its configuration lives in the
parent's modules directory, which the parent's own configuration listing does not read. A driver
defined there is one the audit cannot see, and checking a submodule's dirtiness runs Git *inside*
the submodule, where it would apply. So every read passes `--ignore-submodules=all` as well as
setting `submodule.recurse=false` and `diff.ignoreSubmodules=all`, submodules are counted from the
index, and the preview says that what a submodule holds is neither measured nor copied. An index
that holds a path this host cannot read as text is refused rather than approximated: decoding it
lossily would have the host asking the filesystem about a different name, and a submodule it could
not find would look like one that is not there.

That cuts both ways for a removal. An empty status is an empty status of the tree *outside* its
submodules, so a workspace holding a populated submodule is a workspace whose contents this host
has not wholly read: the measurement records that, and `keep_everything` keeps the workspace rather
than deleting work nobody inspected.

**What the repository's own configuration is allowed to name.** A `filter`, `diff` or `merge` driver
is named by an attribute and *defined* in configuration, and the set of names is whatever the
repository chose, so a fixed list of overrides cannot cover it. The effective configuration is
therefore read first, and every driver it defines is blanked by name.

A driver's subsection keeps the bytes the repository chose, because a configuration subsection is
case-sensitive: an override spelled `filter.mixed.clean` does not reach `filter.Mixed.clean`. The
listing is classified from its bytes rather than as text, because Git accepts a subsection that is
not valid text and reading it lossily would hand the host a name with a replacement character in it.

The keys that remain are dealt with in one of three ways, and never ignored:

* **Blanked.** An override sets the key to nothing. The limitation is reported with the result,
  because section 14 asks the host to expose a limitation rather than execute an ungranted helper.
  Content a driver would have converted is read as it is stored.
* **Refused.** `remote.<name>.vcs`, `remote.<name>.uploadpack`, `remote.<name>.receivepack`,
  `url.<base>.insteadOf` and `url.<base>.pushInsteadOf` are multi-valued or name the other side's
  program, so an override adds to them rather than replacing them. A *read* of such a repository is
  allowed and states the limitation; adopting it into this host's registry is refused, because a
  record is a promise to serve the repository and its remotes.
* **Inexpressible.** A key that is not valid text, or a driver whose subsection holds a control
  character, cannot be carried in an environment value at all. Whether it would run cannot be
  decided either way, so **every** operation on the repository is refused, a read included: a read
  that ran beside one of these could be a read that went through it.

A configuration key can itself carry a credential: `[url "https://token@host/"]` puts one in the
subsection. A key on its way into a limitation or a refusal is therefore not parsed as a URL, which
is what a subsection is not. A subsection is repeated only when it is a *name*: ASCII
letters, digits and `-`, `_`, `.`. A remote, a driver and a filter are all named that way, and
naming them is the whole use of the message; a URL, a query and anything holding a credential are
not names. Anything else is replaced by its length and a fingerprint of its bytes: a person can
still find the key in the file and tell two keys apart, and nothing the repository chose is echoed.
**Git's own standard error is not repeated at all.** Git prints the configuration key *and the
value* it objected to, and a value is unconstrained text; Git also cuts its own diagnostics off at
four kilobytes, so what reaches this host can be a credential whose every character of punctuation
the truncation removed. A rule that decides from the shape of that text reads some of those shapes
wrongly, including ones with no URL and no punctuation in them at all: there is no rule over
unconstrained text that tells a secret from a message.

So what a failure says is: the class Git named in its first word (`fatal`, `error`, `warning`,
`hint`), how many characters there were, and a fingerprint of them. Two failures can be told apart
and one can be recognised again. What carries the *meaning* is this host's own text: which
subcommand, which exit code, which repository, which workspace, which destination, which remote as
it was validated, all from its own records.

The invocation's description is the subcommand and how many arguments followed it, not the
arguments: a caller can put anything in a branch name, a revision or a path, and
`--initial-branch=access_token=…` is a branch name Git rejects and a description would otherwise
carry.

Everything else this service says that it did not write itself goes through one rule: a whole
piece of text is repeated only when it holds no `://` and no character outside a letter, a digit,
whitespace and `- _ . , ; : ( ) ! ' * + ~ /`. Otherwise it becomes its length and a fingerprint.
That covers a branch name, a revision, a broker name, a destination's parent, the paths `rev-parse`
reports, a malformed status record (whole, before it is shortened), a submodule path from the
index, and a decoding refusal from the wire. It is applied where each message is composed, so this
host's own words stay legible, **and** again wherever a message becomes something somebody reads: a
failure becomes text in exactly one place, and the whole of it goes through the rule there, so a
caller inside this host, a log line, the daemon's own standard error and the wire all read the same
sentence. The journal is under the same bar on both sides: every write that keeps free text and
every read of one, including the diagnostics inside a stored answer, which is what a repeat of an
action is answered from. A bar at the places everything passes does not depend on anybody
remembering.

Nothing here rewrites the user's Git configuration. The overrides live on one child process's
command line and in its environment. A terminal command under broad shell access keeps normal Git
behaviour, because it never comes through here.

`fixtures/project/restricted-profile.json` is the list as one document: every execution-capable key,
what Git would run it during, and how this host stops it. The tests build a real repository, plant
each entry as a program that writes a sentinel file when it runs, and then take a status, a review
refresh, a clone and an adoption against it. No sentinel may appear.

### Four limits the host states rather than hides

**The publication's no-replace guarantee is the platform's.** On Linux and Apple platforms it is one
system call: `renameat2` with `RENAME_NOREPLACE`, and `renameatx_np` with `RENAME_EXCL`. On Windows
it is `MoveFileEx`'s own refusal to rename a directory onto a name that exists, which
`MOVEFILE_REPLACE_EXISTING` does not override for a directory. The occupancy check before the rename
is a courtesy that gives a better diagnostic, and the identity comparison afterwards is a second
check rather than the guarantee. The Windows path has not been executed on Windows in this build.

**A Git invocation resolves its own working directory and reads its own configuration.** Both are
outside this host's handles: it passes a path with `-C`, and Git opens the configuration for itself.
So a writer under the same operating-system account could put a different tree at that path, or add
a driver the audit did not blank, between the check and the invocation. Neither is preventable
through Git's own interface, so what this host does is notice, and shorten the window. Before each
write to the user's own repository (adding a worktree, staging a clone of it, pruning a worktree
record) it re-reads the configuration and refuses a change; after a review refresh it re-opens the
path, compares both filesystem identities, re-reads the configuration and compares its digest, and
a result produced against something else is refused rather than returned. A write *inside* a
directory this host created, such as the checkout in a staged clone, runs under the configuration
of a repository this host made a moment earlier. Detection is not
prevention: a driver added in the moment between the last reading and the process starting runs,
and this host reports afterwards that the configuration changed. Closing that needs an isolation
boundary outside Git — a sandbox that denies the process anything but the paths it was granted —
and this build does not have one. Not every read confirms, either: the measurement a removal takes
reads the tree once and treats anything it could not establish as work to keep.

**One removal of a workspace at a time.** `removal_pending` is a state a workspace *rests* in — it
holds work the user has not approved removing — so the state alone cannot say whether a removal is
running. A reservation does: while one removal holds it, a second is refused rather than allowed to
measure a tree the first is deleting underneath it. The reservation is given up after the answer is
built, on the failure path as well as the ordinary one and whether or not the journal accepted the
reason. Two things can still leave one behind: a panic inside the call, and a release the journal
itself refuses. The next recovery releases every reservation it finds, because the daemon that held
one is gone.

**Partial progress survives, and is not called finished.** A workspace whose materialisation this
host did not finish keeps every file in its directory: the files may be the user's, and this host
does not know which of them it wrote. What it does not do is call that workspace ready. The row
moves out of the states anything may hold, the reason is recorded, and a person decides. What the
inclusion had applied when the daemon ended is recorded too. Every path it will attempt goes in as
`planned` before the copy starts, and each outcome replaces its own row in batches, so a crash
anywhere leaves every path either resolved or planned and none of them unaccounted for. `planned`
means this host did not establish what became of that path rather than that nothing happened to
it: a copy that landed and whose flush this host never saw leaves the row as it was. The reason on
the workspace says how many paths were carried and how many are unestablished.

The temporary name a copy writes under follows from the destination's own path rather than from
chance, which is what makes the `planned` row account for the temporary as well: a person or a
later task can turn the recorded path back into the one name a copy of it could have left behind.
What that name does not establish is ownership. A repository can hold a tracked file at it, and
nothing tells that file apart from a copy an earlier daemon left, so the copy is created
exclusively and nothing is ever removed to make room for it: an occupied name means the path is
reported as unapplied and what is there is untouched.

Applying a change set path by path is the diff service's contract, not this one's; what this
service records is which tree it created, what it carried into it, and how far it got.

**A cancellation contains a process group on Unix and a single process elsewhere.** Every Git child
this service starts leads its own process group, so a cancellation ends the helper, the ssh process
and the credential helper along with Git, and the result says so only when the kill and the reap
both succeeded. Windows containment is a Job Object, which is a call outside safe Rust and therefore
not in this crate; a cancellation there ends the Git process and **always** says that the host could
not confirm the rest. A reader thread that still holds a pipe after Git has gone is waited on for
five seconds and then left to its own end, so a descendant cannot hold the call open.

## Storage layout

```text
<state>/environments/<prefix>/projects/
  projects.sqlite
  git-profile/
    empty-config        a zero-byte file, read as the global and the system configuration
    hooks/              empty; core.hooksPath points here
    template/           empty; init.templateDir points here
    home/               empty; the child's HOME
```

The directory is owner-only, and the three directories inside `git-profile` are checked to be empty
every time the service opens: their emptiness is the guarantee, so something left in one of them is a
refusal rather than a thing to work around.

## The journal

`projects.sqlite`, write-ahead logging, full synchronisation, forward-only migrations: the tables are created
where they are absent and a store an earlier build wrote gains the columns added since, one
`ALTER TABLE` each, in one transaction with the version that describes them, so a store is never
left saying it is at a version whose columns it does not have. The version says which build wrote the
store rather than which columns it has, so the step runs for every version below the current one
and adds whatever is missing instead of trusting a number to describe a shape. A store from a
*later* build is refused rather than half read.

The same upgrade carries the *contents* forward, because a store an earlier build wrote holds the
text that build composed: every free-text reason in it goes through the rule, and so does each
diagnostic inside a recorded answer, decoded by the method that produced it and encoded again. The
data fields and the row's own identity are untouched, so a repeat of an action still finds its own
answer. A recorded answer this build cannot decode is left alone rather than stopping the upgrade,
and reading one refuses it: a store that will not open is a daemon that never serves.

| Table | What it holds |
| --- | --- |
| `operations` | One row per creation, keyed by the caller's action identifier: the create token |
| `operation_paths` | Every staging path an operation left behind or removed |
| `workspace_progress` | Every path an inclusion will attempt, written as `planned` before it starts, then each outcome as it settles: `carried`, `removed`, `unapplied`, or `leftover` for a copy in progress nobody could take away |
| `projects` | One row per repository, with both filesystem identities |
| `workspaces` | One row per working copy, with its policy, its base and its tree's identity |
| `workspace_sessions` | Which sessions are bound to a workspace, and which are still live |
| `workspace_runs` | Which automation runs are bound to it, and which are still live |
| `workspace_retained` | Dirty content, pinned change sets and review evidence, each identified by its kind, its reason and the change set it names |
| `actions` | One row per claimed action: the claim, and its result when there is one |
| `events`, `cursors` | The outbox and its consumers |

Every transition of an owned object commits with the outbox row that announces it, in one
transaction. The `actions` table is the exception and deliberately so: it is the de-duplication
record rather than an object whose transitions a consumer replays, and what a consumer replays is
the state each claim was opened beside.

The journal's lock is never held across a subprocess. A clone can take minutes; each transaction
takes the lock and releases it, and every Git invocation runs with none held. A guard is always
bound to a local first, never taken in the head of a condition or a loop: a temporary guard there
lives for the whole body, and a helper that takes the same lock would wait for itself.

Every transition of an owned object commits with the outbox row that announces it, in one
transaction: the state setters, the session and run bindings, the retention changes, the staging
records and the inclusion's progress batches, as well as the two calls that begin an operation and
a workspace. A change a consumer cannot replay is a change that happened here and never happened
anywhere downstream. The two exceptions are stated where they are: the `actions` table, which is
the de-duplication record rather than an object whose transitions anybody replays, and the removal
reservation, which is a lock this daemon holds rather than a fact about the workspace.

### What recovery resolves

| What an earlier daemon left | What a replacement does |
| --- | --- |
| An operation in `staging` or `publishing` | Reconciles it against the create token, as the table above says |
| A staging sibling a row names, whose operation has ended | Removes it, when the object at that name is the one the row recorded. Nothing is removed because of its name alone: a repository a user called `.kr-project-something` is not this host's, and a name with no recorded identity beside it is left for a person. The contents go through the sibling's own open handle and the name itself through an empty-directory removal, which refuses anything that was put there since |
| A staging sibling a *workspace* row names | The same, whatever state the row is in: a workspace that reached `ready` while its cleanup failed keeps the name until one of these recoveries takes the directory away. The name is forgotten only once the directory is gone |
| A workspace in `materialising` | Leaves every file in the directory alone and moves the row to `removal_pending` with the reason, including how many of the inclusion's paths had been applied. The files may be the user's, and this host does not know which of them it wrote; what it does know is that the workspace is not what its creation asked for, so nothing new may hold it and no read calls it ready |
| A removal reservation | Releases it. The daemon that held it is gone, and leaving it would refuse every later removal of that workspace |
| An action claim with no result | Consults the object the claim names. A completed operation's own rows reconstruct the result the caller never received, and so do a ready workspace's and a removed one's; that is what the claim settles with. A reconstructed answer is the state the journal holds rather than a replay of the bytes the first call returned, and where a creation's inclusion preview is part of it, the preview says it is not a measurement this host still holds. An operation still in `staging` or `publishing` is one this host may yet decide, so its claim stays open on purpose for the next recovery. Anything else settles as an unknown outcome naming the object and the state it is in. An open claim is not an answer, and neither is a permanent unknown where the state says otherwise |

## Errors

| Code | When |
| --- | --- |
| `INVALID_ARGUMENT` | A destination that exists, a name that is not one component, a policy that disagrees with its kind, a revision the repository does not hold |
| `REPOSITORY_UNTRUSTED` | A transport, a URL, a broker or a configuration this host will not use |
| `SOURCE_CHANGED` | A repository or a workspace is no longer the object its record names |
| `RESOURCE_UNAVAILABLE` | No such repository, workspace or operation; a workspace a live session still holds; an operation its owner stopped |
| `PERMISSION_DENIED` | A cancellation of another actor's work |
| `ID_CONFLICT` | One action identifier used for two different requests |
| `OUTCOME_UNKNOWN` | An interrupted publication this host cannot resolve, or an action a copy of itself is still performing |
| `UPSTREAM_UNAVAILABLE` | A Git invocation failed, ran past its deadline, or produced more output than the host accepts |
| `QUOTA_EXCEEDED` | An inclusion that would copy more than the host moves without being asked |
| `HOST_NOT_CONFIGURED` | Installed Git is missing or older than the profile needs |
| `STORAGE_UNAVAILABLE` | The journal or the service's own directories |

## Change sets

A **change set** names exact work. A version of one is immutable: it records which repository and
which working copy it came from, the revision it is against, every selected path with the digest of
its content, the dirty, untracked and binary changes it includes, everything it leaves out and why,
the policy and grant it was captured under, and where it came from. New edits produce a new version;
nothing ever changes what an earlier test or review was about.

| Method | What it does | Authority |
| --- | --- | --- |
| `diff.read` | A working copy's changes, or a captured version's, with both sides' content revisions | `files.read` |
| `changeset.capture` | An immutable version of a working copy | `changeset.create` |
| `changeset.read` | One exact version, every version beside it, and everything that names it | `files.read` |
| `changeset.materialize` | An independent copy of one exact version, in a directory of this host's own | `workspace.manage` |
| `diff.apply` | Applies a version at a named destination class | `files.apply_diff` |
| `diff.revert` | Puts the base's own content back for the paths a version changed | `files.apply_diff` |

### The base is the commit, and the index is not it

A version is against a **revision**. What the captured tree is compared with is the commit `HEAD`
names, never the index, so a staged change is an uncommitted change like any other: a staged
addition is a path the base never held, a staged deletion is a path the base does hold, and
excluding an uncommitted change falls back to what the commit has rather than to what is staged. A
path the index lost while the file stayed on disk is not a deletion either: `git rm --cached` leaves
an untracked file there, and what the working tree holds is what is captured, with the commit's own
object recorded beside it so a revert still has somewhere to go back to.

### How consistent the source was, and the mechanism behind each answer

Three classes, no default, and no fourth that means "probably fine". A capture is described as what
it actually was.

| Class | What it rests on |
| --- | --- |
| `atomic_snapshot` | The base commit's **own tree**, walked from `<revision>^{tree}` through immutable tree objects and read blob by blob. The commit is immutable and so is everything under it, so the whole listing is one instant by construction. Nothing of the working tree is read |
| `quiesced_capture` | A reservation over **this very working tree**, granted before the first reading and still holding after the last one. The interval the capture read across is one nothing was allowed to write to |
| `per_file_capture` | Files read one at a time from a live tree, each one the same object of the same length written at the same instant after its read as before it, with the base revision, the index and the status unchanged at the end |

No filesystem this service runs on offers an unprivileged atomic snapshot of a directory tree, so
there is no fourth mechanism and no capture is described as one. A caller can require a class, and
a capture that cannot reach the one it asked for is refused rather than served a weaker one under
that name. A source that keeps changing is retried within a bound and then rejected with
`SOURCE_CHANGED`.

**A quiesced capture is a reservation, and nothing else makes one.** A capture that is offered a
quiescence authority asks it, before it reads anything, to hold the workspace still. The authority
answers at once or refuses at once: it never waits, so a workspace that cannot be held now is
captured as the weaker class this host can actually perform, and a caller that required the
stronger one is refused rather than served a weaker one under that name.

What the capture then does with the grant is what makes the class honest:

* **It checks that the grant covers what it is reading.** A grant names the workspace and the
  working tree it holds, the working tree by identity rather than by name, and a grant over
  anything else is refused rather than read under.
* **It watches the grant through the read**, at each point where the answer could have changed: the
  grant's own identity, its deadline by this host's clock, and its own answer to whether it has
  held without interruption. A grant that lapses is never trusted again, because a reservation
  taken afresh is a different grant over a different interval.
* **It contradicts the grant with what it sees.** A file that changed while a reservation was
  supposed to be holding the tree still is this host's own evidence that nothing held it, and the
  capture drops to the weaker class whatever the grant says. That counts a change this host read
  past as well as one it could not: a file re-read whole on a second attempt still had something
  writing to it, so the content is kept and the class is not. A caller that required the stronger
  class is refused there rather than served the weaker one.
* **It gives the grant back** after the last reading, however the capture ended.

The grant releases the workspace at its own deadline whatever the capture is doing, so a capture
that stops without giving it back cannot hold a workspace for ever.

Two things are recorded separately on the version's policy, because they are separate facts:
`quiescence_declared` is what the caller said about its own work, which this host cannot check and
which decides nothing, and `quiescence_held` is whether a reservation actually held the workspace
for the whole read, which is what decides the class.

The reservation mechanism itself belongs to the workflow service, which knows what is running
against a workspace and can keep it off. What a reservation cannot promise is an editor outside
KalaReach: an implementer that cannot exclude one refuses to grant rather than granting something
it cannot honour.

### What a capture will not read

The grant and the rules decide before anything is opened, in this order, and a path any of them
removes is never opened at all:

1. A repository's own administrative data, and any other repository's whole tree. `.git` in any
   component is refused whatever its case, and so is the directory **this** repository resolves its
   own data to.

   For a repository nested in the tree, **what a directory is decides, never what it is called.**
   Every path the capture's own readings name, and every directory above it, is opened through the
   working tree's own handle and asked whether it holds a `.git`. One that does is another
   repository: its tree is that object, and where it keeps its data is found by **descending to it
   one component at a time** from the same handle, refusing a link, refusing a step above the tree
   and refusing an absolute name. The identity of the directory the descent reached is what is
   kept, along with the identity of the common directory it names when it names one. Every
   directory the capture opens is then compared with those objects, so no spelling of any of them,
   through a link, through `..`, relative or absolute, reaches one under another name.

   A place this host cannot descend to refuses the whole capture rather than being guessed at. A
   place that is not there excludes nothing, because there is nothing of it to capture. What is
   inside would otherwise be that repository's configuration, which holds its remotes and can hold
   a credential, and its object database, which holds every version of every file in it.

   A link is not the only way a path reaches content the path does not name, so two more things are
   refused. The first is a **mount**. Every name a capture resolves is walked one component at a
   time, each directory is opened with the handle above it and then held as the directory the next
   component is opened in, and each one is compared with the mount the working tree itself is on.
   A directory somewhere else ends the capture, and so does the file a read returns if it is
   somewhere else: a mount over a name holds another tree entirely, and the path that reaches it
   crosses no link to get there. A path that becomes a mount after the capture looked at it refuses
   the capture rather than being excluded and read around. Other readers of the same tree — a
   download, a measurement, a copy of a workspace — ask for none of this, so a project with a
   mounted directory in it is ordinary to them.

   The second is a link **out** of a repository's own data. Every directory of that data is looked
   inside once, entry by entry, and every file it holds is opened: data that holds a link, a mount
   of a directory or of a file, or anything that is not a plain file or a plain directory is data
   this host does not capture around, because each of those makes something of the tree part of
   that repository's own data under a path that crosses nothing either. The scan works from the
   handles this host opened when it read the repository's identity, so a directory mounted over the
   administrative directory afterwards is not what gets examined. Data deeper, or with more
   entries, than this host reads refuses on the same terms, naming the limit it reached. None of
   this is skipped, and what was found is named where it was found.

   What none of this covers is an actor that can **mount and unmount while the capture runs**. Such
   an actor already holds the repository's own data, and a cover placed over a directory for the
   length of one step and taken away before the next is outside what this host promises. What it
   does promise is about the tree as it stands: a link, a second name, a mount that is there when
   the capture reads, and the ordinary races an account without that privilege can arrange — a
   rename, a replacement, a file swapped under a reader — which handle-based resolution answers by
   holding the object rather than the name.

   What is left is a *file* with two names in two directories: a hard link from a repository's own
   data to a file of the tree is an alias nothing about either path says is there. A mount over a
   file is refused on both sides; a second hard link is not.

   Finding these repositories is not the same job as reading the tree, and it does not stop where
   reading stops. Nothing is read inside a nested repository's tree, which would leave a
   repository nested inside **that** one unaccounted for: its own `.git` is named by no reading of
   the capture, and the directory it keeps its data in can be anywhere the tree reaches, ordinary
   content to everything else. So every nested tree is walked for `.git` entries and for nothing
   else — no content of it is read — and each repository found that way has its data placed and
   excluded like any other.

   Discovery goes down two more roads for the same reason, and reads nothing along either. A
   **link** is followed: never to capture anything, because what a version holds for a link is its
   target as text, but to look, because the repository at the other end of one can keep its own
   data at an ordinary path of this tree. The target is resolved the way every other name here is,
   one component at a time with a link on the way refused, and what it reaches is searched like
   any other directory. And a `.git` **inside** a repository's own data is read rather than passed
   over: everything under that data is excluded already, which says nothing about where a
   repository whose tree sits there keeps its own, so that reference is followed too.

   All of this spends the same entry budget the scan of a repository's own data does, and a set of
   trees deeper, or with more entries, than this host looks through refuses the capture rather
   than being half searched. Following one of those names is bounded too: each place named can
   name another, so the number of references followed to reach a directory has an end of its own,
   and a repository whose data names itself is looked through once rather than for ever.

   Each directory is looked through once, by what it is **and the mount it was reached on** —
   outside this tree as much as inside it, because two views of one directory hold different
   children and passing the second over would leave whatever is in it unaccounted for. Every one
   of them is a handle this host opened and kept: nothing is searched by resolving a name a second
   time, because two directories renamed in between would have this host ask about one place and
   look inside another.

   What this covers is what a capture reads and what those walks reach: a repository in a
   directory that no path of the capture goes near, that lies inside no tree they walk and that no
   link of this tree names, is one the capture does not reach either. A repository somewhere else
   on this machine can still name a directory of this tree as its own data, and nothing inside the
   tree says so.

2. This host's own secret rules: `.env` and its variants, a private key by name or by suffix, a
   credential or authentication file, and everything under `.ssh`, `.gnupg` or `.aws`. No wire field
   turns them off, and the version records that they were applied.
3. The caller's own exclusions, and then its selection when it made one.

A symbolic link and a submodule are named rather than captured: a link's Git object holds its
target rather than content, and writing either out as a regular file would make a materialisation a
different tree.

### Materialisations, and what a result may say

A materialisation is an independent copy of one exact version, written out of this host's own
content-addressed store into a private directory of its own. That directory is **made**, with a
creation that fails when the name is taken, and adopted only when what it reaches is empty; its
identity is compared again before a release removes anything. Between the creation and the opening
lies one window no call on these platforms closes, because there is no "open the directory I just
made": what bounds it is the emptiness rule, which means a release still takes away nothing that
was there first. That window is a stated limitation rather than something this host establishes. Neither the repository nor the working
copy the version came from is touched, so the agent whose tree was captured keeps working.

Recording a result re-reads the materialisation and says what it establishes:

* it still holds the version — the same paths, the same content, the same modes, and every file
  still the object this host wrote, of the same length, last written at the same instant — and the
  result attests that version;
* it holds something else — the result attests **no version at all**, and this host records a
  **derived version** with its own identity beside it, held against deletion for as long as the
  result is, which is what the directory held when the result was recorded rather than what the
  run read. A run that changed a file, tested the change
  and put the file back leaves a directory that reads as modified and a reading no command ever
  used, so naming that reading as the tested version would be a claim this host cannot make;
* it holds something this host cannot represent, cannot read, or would not have captured in the
  first place, or something was written into it after the run the caller reported had ended — the
  result is `indeterminate` and attests nothing at all.

The limit, stated rather than left to be discovered: this host reads the directory when the
materialisation is made and again when the result is recorded. It does not watch it while the run
is happening. What it records at each path when it writes it — the object, the length and the
instant it was last written — is what tells a file nobody touched from one a run rewrote with the
same bytes; a run that restored all three together is not something two readings would show.
Binding a result to the bytes a command actually read needs a host that owns the execution.

An identical source promises nothing about network services, installed dependencies, secrets or
graphical state. Every version and every materialisation carries that sentence.

### Where an apply goes, and what it comes to

An apply names its destination class. There is no default, and the one that cannot lose anybody's
work is the one a caller gets by asking for it plainly.

| Class | What it is |
| --- | --- |
| `proposal` | Two immutable versions and no write to any working tree: what the destination holds now, and what it would hold. A person decides |
| `versioned_reference` | The expected-old-value comparison, and then the limitation. This host reads the reference and compares it: a value that differs is `DRAFT_CONFLICT`. It does **not** move the reference, because its restricted execution profile runs no subcommand that writes one, so what a caller gets is the limitation rather than the update. A compare-and-swap **update** is not implemented here and this row is not closed by it |
| `shared_existing` | The user's own working tree, written in place. Best-effort conflict detection, not universal no-clobber compare-and-swap |

An apply carries **operations**, not only content: a path the version holds is installed, and a
path the version's working tree deleted is taken away. A deletion travels with the object its base
revision held, its mode, and, for a version captured from a repository, this host's own copy of
that content, so a revert puts the file back without depending on the destination's repository
still holding the object. A version **derived** from a materialisation is read from a directory
rather than from a repository, so a deletion it records for the first time carries the object and
the mode but no content, and reverting that one does read the destination's repository. A deletion
it carries forward from the version it came from keeps whatever that version held for it. A version whose only change is a
deletion reads as that change rather than as an empty diff. What the base held has to be file
content either way: a deleted link or submodule is a revert this host refuses rather than writing
out as a regular file. A
request that names no paths carries every one of them, and one that names paths carries exactly
those.

A direct apply to `shared_existing` cannot be chosen until the request carries back the limitations
this host returns for it, and a preflight is how a caller obtains them: it needs no acknowledgement
and it writes nothing at all, in this store or any other. What a direct apply then does, in order: the preflight, which compares every
affected path with what the request expects and answers `DRAFT_CONFLICT` with **nothing written
anywhere** if they differ; the claim on the action, taken here rather than earlier so that a refused
preflight leaves nothing durable behind; an immutable capture of the destination as it stands; the content staged
in a directory of this host's own beside the destination and read back against its digest; the apply's header and a `planned` row for
**every** operation written in one transaction, before any of them is attempted; then, per
operation, a temporary created exclusively **in the destination's own directory** and written with
the validated bytes, the destination's permissions put on it, the destination rechecked against
that same directory handle as the last thing before the rename, the staged name confirmed to still
be the file this host created, the rename, and the destination read back twice: once through the
directory this host published into, against the content and the permissions it set, and once by
resolving the whole path again from the working tree and comparing the object it reaches with the
one this host renamed into place. A parent somebody moved aside is therefore never reported as a
success about the path the request named. Finally an immutable capture of the destination as it
now stands.

Nothing is removed to make room. A staging name that is already taken is a path this host reports
and leaves exactly as it is.

**The content is staged inside a directory of this host's own.** For each path it writes, this
host creates a directory in the destination's own directory, exclusively, so a name that is
already taken is one it leaves exactly as it is rather than one it removes to make room. The
validated bytes go into a single file inside it, and the publication renames that file over the
destination, which is a rename inside one directory and can cross no filesystem.

That directory is what makes the cleanup a rule rather than a judgement:

* **This host removes exactly two names, and both are its own**: the one name it writes inside
  that directory, and the directory itself once it is empty. A name of the person's own making is
  never the target of a removal, whatever another writer does at the moment of it.
* **Each goes only while it is the object the journal recorded.** The directory's identity and the
  file's are compared through open handles first, each against what the journal recorded when this
  host made it, so a directory somebody substituted and a file somebody put inside this host's own
  directory are both left exactly as they are and named in the answer.
* **The staged file goes only out of a directory this host can show is shut.** The handle that gave
  the identity answers for the rest: it is a directory, this account owns it, its mode admits
  nobody else, and on macOS it carries no access-control list, because a list there can admit an
  account the mode bits do not mention. The same four are asked when the directory is made, before
  a byte is written inside it, so a directory this host cannot show is shut is one it stages
  nothing through rather than one it discovers later; and they are asked again before the file goes.
* **The removal reaches the object rather than the name where the platform allows it.** Windows
  deletes the staged file through the handle whose identity was compared, so no name can redirect
  it. Unix has no call that removes a name only while it still names a given object, and no
  platform has one for a directory, so every other removal is named relative to an open handle
  instead of by a path: the staged file relative to the staging directory, and the staging
  directory relative to the directory that holds it. On Unix that directory is asked first whether
  it belongs to this account and is not one every account on the machine may write in, and it is
  asked the same before the staging name is ever created, so a tree this host could not clean up
  after itself in is one it stages nothing in rather than one it leaves residue in.
* **The writers this leaves are the ones the person has already admitted to that tree.** A process
  running as the same account, and any account the person has given write access to the working
  tree, can put something else at such a name in the moment between the comparison and the
  removal. Each of them can already rewrite the destination this apply publishes, so neither is
  something a removal could exclude, and that is the limit of what a removal in user space can
  promise. A name outside that, this host reports rather than removes.
* **Anything else inside it refuses the removal.** Taking the directory away is an empty-directory
  removal, so a file somebody else put there keeps the directory, keeps the record, and is
  reported rather than swept away with it.
* **A record is cleared only once what it names is durably gone**, which means after a removal and
  a sync of the directory that held the name. A sync this host could not finish keeps the record.

**A daemon that dies between staging a path and publishing it leaves that directory behind**, and
the journal is what makes it recoverable rather than a thing a person has to find. Before the name
exists the journal records it beside the destination path; the moment the directory exists the
journal records **the object this host created**; and the record is cleared once the directory is
gone. So the next daemon, before it serves anything, looks at every directory an apply still has
recorded and applies the rule above to it.

A record the journal names with no object beside it is one this host died before it could show was
its own, or one whose name was already taken when it looked. It is never removed. It does resolve:
once the name holds nothing and that absence is durable there is nothing left to account for, and
the record goes. Until then the path is named in the answer so a person can look at it.

A tree whose own rules refuse this host what it needs keeps its record for as long as that is true.
A staging directory this host cannot open is one it can never prove, and a directory it may not
remove a name from is one it never removes a name from; in both the record stands, every recovery
takes it up again, the apply's own answer goes on naming the path, and the person's own change to
the tree is what ends it. This host
asks the same question before it makes a name, so it does not stage in a tree it can already see
will refuse it.

**The record outlives the apply.** An apply that could not take its own temporary away in the
moment settles all the same, with the names it could not clear in its answer, and the record stays
where it is. Every outstanding record is taken up by the next recovery, whatever the apply it
belongs to came to, so an obligation this host could not discharge is neither hidden from the
caller nor forgotten by the host. A record is cleared only where the name is proved to hold
nothing of this apply's: after a removal this host made durable, or where the name holds nothing or
holds something this host did not make. A name this host could not look at keeps its record.

Permissions are the destination's own, put on the staged copy through the handle this host created
it with, before the rename, so a file that was executable stays executable and one that was not
does not become one. A destination whose permissions this host cannot read is a path it does not
replace. What it carries is three things, which decide between them who may use the file. On Unix
they are its mode bits, the user and group it belongs to, and the access-control list beside them.
On Windows there are no mode bits, so they are its discretionary access-control list, the account it
belongs to, and its read-only attribute, which is what answers there whether the file may be
written. Anything else a platform keeps about a file, a security label or an audit list among it, is
not carried and is not claimed to be. A destination that carries a list is applied to rather than
refused. The list is read through the destination's own handle and put on the staged copy before the
rename, and where the destination has none of its own, any list the copy inherited from the
directory it was made in comes off it, so the published file carries the protection of the file it
replaced and nothing else. On Windows every file has a list, so what counts as one of the
destination's own is a list it protects against the directory above it or an entry it holds itself;
entries it merely inherits are what the staged copy receives in the same directory anyway, and are
carried by being left alone. The published file is then read back through its handle, and a mode,
an owner or a list that is not the one this host set leaves the path unresolved rather than
reported as applied. Where a host can neither read nor put back the platform's lists, or cannot give
the copy the account the destination has, the path is left exactly as it was: on Windows giving a
file to another account needs a privilege this service does not hold, so a destination owned by
somebody else is left alone rather than published under the wrong owner, and a read-only
destination is left alone too, because the platform will not let a rename replace one. What a
Windows destination inherits from the directory it sits in is not carried and does not have to be:
the copy is staged in the same directory and receives what that directory gives every object made
there. Content is written byte for byte, so a line ending is whatever the version holds.

An apply comes to one of five classes. **A preflight conflict is an error, not a result**:
`diff.apply` and `diff.revert` return `DRAFT_CONFLICT`, and a preflight that finds the destination
as expected returns a result with no outcome class at all, because nothing ran.

| Outcome | What it means |
| --- | --- |
| `preflight_conflict` | The destination was not what the request expected. Nothing was written, anywhere: no apply row, and not even the claim on the action, which is taken only once the preflight has passed. The caller receives `DRAFT_CONFLICT`, and the same action identifier can be used again |
| `applied` | Every operation landed and this host read each one back |
| `conflict_after_partial_writes` | Some landed, and then the destination stopped being what the request expected |
| `interrupted_apply` | This host stopped before finishing. Some operations may have landed and some may not; the rows say which |
| `uncertain_outcome` | This host cannot say what the destination holds, or an operation it planned is one it did not resolve |

A crash after one file cannot produce `applied`. `applied` is recorded only when every operation the
apply planned is confirmed in the destination, and a path whose row still says `planned` means this
host did not establish what became of it — which is not the same as saying it did not write it. A
replacement daemon settles such an apply as `interrupted_apply`, names exactly the paths on each
side, and **settles the action it was performed under with that answer**, so a caller that repeats
the action is told what happened rather than applying a second time against a destination the first
attempt already changed. The action is settled first and the apply afterwards, so a host that stops
between the two leaves the apply undecided and the next recovery does both again. A recovery also
looks for the other half of that gap, an apply that says what it came to and an action nobody
answered, and carries the apply's own outcome to the caller.

Marking a review complete records that somebody acknowledged **that version**. It runs no Git
invocation, writes to no working tree and removes nothing. `commit`, `push`, `revert`, `reset`,
`clean` and `stash` are not subcommands this host can run at all.

### Retention

A version is not deleted while anything names it: a materialisation that has not been released, a
review acknowledgement or any other evidence, a later version derived from it, a recorded result, an
apply that names it on either side, or a pin the project service holds against the workspace. The
counting and the removal are one transaction inside the change-set store, and a materialisation, a
result with both the version it attests and the reading it carries beside it, a derived version and
an apply with every version it names on either side are each written under a check, in the same
transaction, that those versions are still there — so a holder recorded while a deletion is
deciding is either counted or refused, and never left pointing at something that is gone. The
project service's pin lives in another store and is checked first; a pin recorded between that
check and the transaction is not covered, and that is written down rather than hidden.

### Authority, and where it is decided

Every change-set mutation takes a claim on its action before it acts: one action, one effect. What
the store asks **inside the transaction that records that claim** is whether the authority the
mutation arrived under is still in force. Between a request being admitted and the moment it acts
lie a task to be scheduled, a blocking thread and this journal's own lock, and authority can run
out inside any of them. Deciding it inside that transaction means a mutation whose authority went
leaves no claim row: the next attempt finds nothing rather than a claim nobody can settle.

**A claim carries no authority forward, and asking is not enough.** An answer is true when it is
given and can be false a moment later, so the daemon is asked to **hold** its answer instead: it
takes what a revocation would have to take, runs the effect, and lets go afterwards. Every
transaction that commits an effect runs inside such a hold, because the interval before an effect
is longer than the interval before a request: the clone identity a capture fixes, the change set
and the version it records after reading a whole working tree, the row a materialisation is
written under before a byte of it exists, the journal an apply opens, and the transaction that
counts every holder and deletes a version. Each of those transactions also begins immediately
rather than deferring, so the store's own waiting happens inside the hold rather than between the
answer and the writes. A revocation that begins while an effect is committing therefore finishes
after it, and a mutation either commits under authority that was in force throughout or does not
commit at all.

**An apply's journal is a fence, and the database holds it to that.** Every row of an apply's
progress belongs to the apply's header, which cannot be absent while the rows exist, so a decision
taken when the header was written is good for the writes that follow it rather than something each
write has to be trusted to have repeated. That is what makes the reading on the far side of an
apply, the one that records what the destination now holds, stand behind the header rather than
asking again: the paths have already been written, and authority that ran out while they were
being written stops the next request rather than taking away the record of what this one did. An
apply that stopped between two of its paths because a deadline passed would leave a working tree
neither as it was nor as the request asked for, which is the state the outcome classes exist to
avoid.

A repeat of an action never reaches any of those questions, because the record of the first attempt
answers it: a receipt stays readable after the window that admitted it has gone.

### Storage layout

```text
<state>/environments/<prefix>/changesets/
  changesets.sqlite
  objects/<aa>/<rest>     one blob per distinct content, named by its own SHA-256 digest
  materialisations/<id>/  one independent copy of one exact version
  staging/<action>/       one apply's validated content, before it reaches a destination
```

and, for the moment a path is published, one directory of this host's own beside the destination
itself:

```text
<destination directory>/.kr-apply-<digest of the path>/content
```

A blob's name **is** the digest of its content, so storing the same content twice stores it once, a
manifest that names a digest names exactly one sequence of bytes, and a read that does not hash back
to its own name is refused as damage rather than served.

The journal carries the storage format it was written in, and the boundary is decided when it is
opened rather than at the first query that needs a column. A journal from a later format is refused
because this build cannot know what a column it does not have holds; one from an earlier format is
refused because the rows it holds cannot answer what this build reads out of them, and the refusal
says which formats they are and that the directory has to be taken away and the work captured
again. A journal that opens is one every query can rely on.

## What a caller builds on

A change set captures an exact version of a workspace; an automation run materialises one; a client
library calls the ten methods above. All three want the same three things from here, and they are
what the interface gives:

* A `project_repository_id` and a `workspace_id` that mean one object each, whatever happens to the
  paths they were created at.
* An `AuthorisedDirectory` for a working tree, from `OpenedRepository::work_tree`, so a capture reads
  through the same authority the creation wrote through.
* A `RestrictedProfile`, from `ProjectService::profile`, so every later Git invocation runs under the
  same profile and its driver overrides come from the same audit.

The change-set service above is the first of those three. It opens every repository through
`OpenedRepository`, runs every Git invocation under that profile and inside its execution boundary,
reads every file through the working tree's own handle, and writes nothing into the user's
repository except through an apply the caller explicitly chose.

**Where repository work runs.** The boundary is the condition, not a formality: a host whose
containment cannot keep a repository from being executed from, and cannot bound which ports a
remote operation reaches, refuses to start Git rather than claiming a confinement it does not have.
On macOS and Linux the boundary holds and every repository operation runs. On Windows it does not,
so this host runs no repository operation there and says so in the refusal each call returns. The
transfer service beneath it is a separate thing and runs on all three: uploads, downloads, the
staging area, and everything a file's handle answers about its protection.
