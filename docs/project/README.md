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

Everything after the first open goes through an open directory descriptor rather than a path, which
is the same authority model the transfer service uses for a staging area and for a client's chosen
destination. A destination is a parent directory resolved once and one single-component name inside
it: no separator, no traversal segment, no reserved device name.

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
filesystem identity, and the instant the filesystem says it was created. So a replacement daemon
never asks "does the name exist"; it asks which name holds *that object*. The creation instant is
the second half of the witness because a filesystem reuses a device and inode pair once the object
that held them is gone, and reuse with the same creation instant is not something a filesystem
produces. Where a platform reports no creation instant, the witness is the identity alone and the
host says so rather than claiming more.

| What the replacement finds | What it does |
| --- | --- |
| The destination holds the staged object | Finishes the operation: writes the repository row and settles the claim |
| The staging directory still holds it | Finishes the same publication, which is not another clone |
| Neither holds it | Records the operation as unknown and keeps the staging path, named in the result |
| No witness was recorded | Nothing was published: removes the staged content and closes the operation |

A staging sibling exists for a moment before the row that names it is updated, so recovery also
removes any sibling no operation row accounts for, in the parents this host has used. Recovery runs
before anything is served, so no operation is in flight when it does.

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

   No refusal repeats the URL it refused. A URL this host could not parse is one it could not redact
   either, and a malformed authority is exactly where a credential sits, so a refusal names what is
   wrong instead. Where a diagnostic from Git itself carries a URL, the whole user information is
   removed unless the scheme is `ssh` and it holds no colon.
3. **The provider** is the host name as this host resolved it, recorded beside the remote so a
   receipt says which service was reached.
4. **The broker** is one this host has. It supplies a *program* — a credential helper, and an ssh
   command for the ssh transport — resolved to an absolute path inside Git's own helper directory.
   The host never sees the credential itself. A broker with no program for the transport in question
   is a refusal rather than an attempt.

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
`preview_only` set: the same parameters, so a user cannot be shown a preview of one policy and given
a workspace built under another. It creates nothing.

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

The counts are exact for every class. The list of paths is bounded, because a reply travels in one
control frame and a working tree can hold a million ignored files; what it leaves out it counts, and
says so among its limitations. A wholly ignored directory is one entry in Git's own status output,
so this host walks it to keep the counts exact and to copy what an inclusion covers; a directory
deeper or larger than the walk's bound is reported rather than silently left out.

The preview also carries what a workspace of that kind cannot promise, in the host's own words: that
a worktree is not a sandbox, that a working tree can change between the preview and the copy, and
that a shared workspace's apply is best-effort. A client shows these rather than deciding for the
user.

### Nothing is cleaned, stashed or discarded

An exclusion means the new workspace starts without that file. It never means the original is
touched. The service reads the source tree and writes only into the new one.

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
| `keep_everything` | Nothing, while anything is retained. The result lists what is held. |
| `keep_retained_evidence` | The working files. Dirty content, pinned change sets and review evidence stay. |
| `remove_retained` | Everything, including what is held. Carrying this policy *is* the user's approval. |

A **shared** workspace is the user's own working tree, so removing it removes the selection and no
file. No retention policy deletes a tree the user is working in.

A workspace record survives its removal, so a later read says what happened rather than nothing. An
isolated workspace's identity is checked before anything is removed: a record whose object has been
replaced does not authorise removing whatever now holds its path.

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
`GIT_CONFIG_VALUE_<n>` pair for each one. That form has the same precedence as `git -c`, beats every
configuration file and reaches every subprocess Git starts. It is used in place of `-c` because `-c`
splits its argument at the first `=`, so a configuration key whose subsection contains one could not
be overridden at all.

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
index, and the preview says that what a submodule holds is neither measured nor copied.

**What the repository's own configuration is allowed to name.** A `filter`, `diff` or `merge` driver
is named by an attribute and *defined* in configuration, and the set of names is whatever the
repository chose, so a fixed list of overrides cannot cover it. The effective configuration is
therefore read first, and every driver it defines is blanked by name.

A driver's subsection keeps the bytes the repository chose, because a configuration subsection is
case-sensitive: an override spelled `filter.mixed.clean` does not reach `filter.Mixed.clean`. A name
holding a control character cannot be carried in an environment value at all, so a driver named that
way is refused rather than left alone.

The keys that remain are dealt with in one of two ways, and never ignored:

* **Blanked.** An override sets the key to nothing. The limitation is reported with the result,
  because section 14 asks the host to expose a limitation rather than execute an ungranted helper.
  Content a driver would have converted is read as it is stored.
* **Refused.** `remote.<name>.vcs`, `remote.<name>.uploadpack`, `remote.<name>.receivepack`,
  `url.<base>.insteadOf` and `url.<base>.pushInsteadOf` are multi-valued or name the other side's
  program, so an override adds to them rather than replacing them. A *read* of such a repository is
  allowed and states the limitation; adopting it into this host's registry is refused, because a
  record is a promise to serve the repository and its remotes.

Nothing here rewrites the user's Git configuration. The overrides live on one child process's
command line and in its environment. A terminal command under broad shell access keeps normal Git
behaviour, because it never comes through here.

`fixtures/project/restricted-profile.json` is the list as one document: every execution-capable key,
what Git would run it during, and how this host stops it. The tests build a real repository, plant
each entry as a program that writes a sentinel file when it runs, and then take a status, a review
refresh, a clone and an adoption against it. No sentinel may appear.

### Three limits the host states rather than hides

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
through Git's own interface, so what this host does is notice. After every read it re-opens the
path, compares both filesystem identities, re-reads the configuration and compares its digest; a
result produced against something else is refused rather than returned. What remains is a change
made and undone inside one invocation, which two readings cannot distinguish from no change at all.

**A cancellation contains a process group on Unix and a single process elsewhere.** Every Git child
this service starts leads its own process group, so a cancellation ends the helper, the ssh process
and the credential helper along with Git. Windows containment is a Job Object, which is a call
outside safe Rust and therefore not in this crate; a cancellation there ends the Git process and the
result says that the host could not confirm the rest.

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

`projects.sqlite`, write-ahead logging, full synchronisation, forward-only migrations. Every state
change commits with the outbox row that announces it.

| Table | What it holds |
| --- | --- |
| `operations` | One row per creation, keyed by the caller's action identifier: the create token |
| `operation_paths` | Every staging path an operation left behind or removed |
| `projects` | One row per repository, with both filesystem identities |
| `workspaces` | One row per working copy, with its policy, its base and its tree's identity |
| `workspace_sessions` | Which sessions are bound to a workspace, and which are still live |
| `workspace_retained` | Dirty content, pinned change sets and review evidence |
| `actions` | One row per claimed action: the claim, and its result when there is one |
| `events`, `cursors` | The outbox and its consumers |

The journal's lock is never held across a subprocess. A clone can take minutes; each transaction
takes the lock and releases it, and every Git invocation runs with none held.

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
