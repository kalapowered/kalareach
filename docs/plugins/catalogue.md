# Repositories and the catalogue

`docs/plugins/README.md` says what a package is. `docs/plugins/runtime.md` says where its component
runs. This is the part in between: where a package comes from, what makes it trustworthy, what it
costs to hold, and what a host will and will not do with it.

A host synchronises the **complete signed metadata snapshot** of every repository it is enrolled
in: compact descriptions, declarative match rules, capability declarations and immutable payload
hashes and sizes. That snapshot is small enough to hold whole, which is what makes catalogue search
work with no network at all. Everything a host would only need *after* deciding to install stays
behind a content hash until something explicitly asks for it.

```text
repository ──signed metadata──▶ index (held whole, searched offline)
                │
                └──payload, by content hash──▶ cache ──verify──▶ package ──▶ binding
```

The client is its own crate, `crates/kr-plugin-catalogue`. It verifies, stores and fetches, and it
hosts no component, so the control daemon that serves the catalogue and plugin methods links no
Wasm engine. Components run in the plugin runtime's own process, as `docs/plugins/runtime.md`
describes.

## Enrolment comes first

Nothing is fetched before a repository is enrolled, and enrolment fixes four things.

| | |
| --- | --- |
| The trust root | The one this repository's metadata is verified against, and no other |
| The budgets | What the enrolment asks for, within what this host's configuration allows: 64 MiB of metadata and 100,000 entries a sync, two kept generations in 128 MiB of kept metadata, and 1 GiB of cached payloads by default |
| The capability ceiling | Metadata matching, declarative presentation and already-authorised broker semantic events |
| The mirror setting | Off, so a sync fetches metadata and not every payload |

An enrolment that asks for more than the configuration's `enrolment` budgets allow is refused
before anything is fetched, with `QUOTA_EXCEEDED` and the name of the budget it is past.
`docs/host/README.md` has the configuration.

Each repository keeps its own root. An enterprise or vendor repository that adopted a root out of
band is not verified against the official one, and adopting a second root never widens the first.

Adopting a root is the owner's decision, and so is enlarging what a repository's packages may do
without a further grant. Re-anchoring an existing repository is two deliberate acts, `catalogue.remove`
and `catalogue.add`, so a root never changes underneath a repository somebody is already using.

A version-control location is refused at enrolment, by name. A branch moves, and a repository whose
"current revision" decided what a host installed would have no signed statement of what it
published. That is the thing the metadata exists to replace.

## What a sync does

1. Fetch and verify root, timestamp, snapshot and targets metadata with the `tough` client, against
   the root this host adopted. It is the same exact release the publishing pipeline signs with, so
   the end that writes a generation and the end that reads one cannot drift into two readings of
   one document.
2. Check every vendor delegation's scope. A delegated role in a KalaReach catalogue may sign
   `packages/<publisher>/…` for one publisher and nothing else; a role that claims the index,
   another publisher's prefix, a bare wildcard or a hash-prefix bin is refused. A delegation chain
   deeper than three roles is refused while the client walks it: the transport a sync fetches
   through learns each role's depth from the document that delegates to it, and refuses a role
   past the bound before its document is asked for. A role delegated to twice would have two
   depths and two scopes, and is refused as the second delegation arrives.
3. Read the index, inside the metadata budget together with the metadata that pins it, and check
   what each entry declares: safe paths, no two names that collide on a case-insensitive
   filesystem, a manifest that does not declare itself, and declared sizes inside one package's
   limits. The budget counts every document the client fetches while it loads the metadata, and
   the index once, by what the sync fetched it for rather than by where it lives: targets
   published inside the metadata location, or a location whose fragment the client drops, are
   counted like any other.
4. Refuse a generation older than the one already accepted, one that puts different bytes under a
   generation number this host already accepted, and one that is not the generation the owner
   pinned. A role whose metadata version went backwards has already been refused by the client, in
   step 1.
5. Fetch the whole generation, where the full offline mirror is on.
6. Activate the index atomically, and carry the root verification arrived at forward.

Steps 4 and 5 are in that order deliberately. A mirror that cannot be completed activates nothing,
so the generation this host is on stays the one it has payloads for. And the root a host carries
forward is the one verification ended on rather than the one it started from: a rotation is signed
by the root it replaces, and a host that always restarted from the original could have old trust
restored by a repository that simply withheld the newer root.

A sync reads the root it verifies from, and the generation it is on, once it holds the repository's
lock. Two syncs that wait for each other therefore never both start from the root the first one
moved past, and a root is recorded only over one of a lower version: a sync that arrives at a root
the repository has since moved past records nothing, and its generation and checkpoint go no
further either.

The client's rollback protection is the metadata it last verified: each role's new version is
compared with the one it holds. That store is this host's accepted trust checkpoint, and the client
never writes into it. Every verification works in a private copy of it, and the copy becomes the
accepted checkpoint, document by document with each document renamed into place whole, only once the
metadata has verified and under the same admission as any other change. A verification that fails,
is interrupted or is refused leaves the checkpoint exactly as it was, and no interruption leaves a
half-written document the client would skip. The copy starts from the documents the client reads
back, the timestamp, the snapshot and the latest time it saw, and the client writes the rest afresh,
so a checkpoint holds one generation's documents and never the delegated documents of the
generations before it. Once the metadata has verified, the checkpoint is kept whatever happens to
the rest of the sync, provided it fits the retained metadata budget beside the generation in use and
beside the new one, counted at the most it holds while it is published; one that does not is refused
before it is kept. The documents it no longer holds are removed before any new one is written, so
one generation's delegated documents never stand beside the next's, and each document it keeps
counts at the larger of its accepted and verified sizes. The latest time the client saw while it
fetched a full mirror is kept too, in a commit of its own once the mirror has finished or stopped on
an error, which is what lets it refuse a clock set back behind that time; a sync cancelled during
the mirror, or refused at that commit, keeps the time the checkpoint already had.

Where a new root changes the keys that sign timestamps or snapshots, those roles may start again
from lower versions, and the client drops their old versions when it sees the change. A sync that
keeps such a root and then fails leaves the next sync starting from that root, where the change is
no longer visible to the client, so the change is recorded with the root and the next sync's copy
starts without those versions. This host keeps no second floor of its own: one compared whatever
the keys would refuse exactly those valid lower versions.

Expired metadata stops at step 1, and stops there only. It blocks a **new** generation; it does not
reach into what is installed. A pinned package stays usable offline under the grants it already
has, which is the difference between a repository going quiet and a host breaking.

## When a payload is fetched

Three reasons, and no others:

- an explicit install;
- an explicit enable;
- an activation for a package that is already installed and enabled here.

Anything else asking for an uncached payload gets `PACKAGE_UNAVAILABLE_OFFLINE`. A host that
invented an enabled capability instead would be telling somebody an action will work when the bytes
that would perform it are not here.

The **full offline mirror** setting is the one way to fetch everything. It is explicit, it runs
inside the repository's approved payload budget, and it replaces unconditional download as a sync
strategy rather than replacing the complete-catalogue rule. The whole set is measured before
anything is fetched, and reported complete only when all of it is here: fetching one object at a
time and making room for each in turn would evict the ones already fetched and finish with part of
a generation.

A payload is fetched out of the generation this host accepted, and no other. When a generation is
accepted, every target it pins is kept with it: the digest, the length and the location the client
resolved. A payload is fetched from that location and checked against that digest and length, and
no metadata is read to do it. A repository that has moved on to a later generation therefore does
not make the accepted one uninstallable while its bytes are still there, and it does not stand in
for it either: the later generation is a sync's to verify and accept.

## Two activations, each atomic on its own

The index is written whole and flushed, and only then does the pointer move to name it. A reader
sees one generation or the previous one, never a mixture.

A package is staged in a directory of its own, every payload is verified as a set, and the directory
is renamed into place once all of them verify. A package is therefore never half installed.

A package already here is used only after every file its manifest declares is checked where it
lies; the name of its directory never counts as the package. One that is incomplete or altered is
fetched and checked again, then repaired where it lies: each file that does not hold the checked
bytes is replaced by a rename of its own. The directory never disappears, and a binding reading a
file that was intact keeps reading the same file. What an installation records, the capabilities
the package asks for and the payloads it consists of, is read from the manifest the package hash
names. An index entry that says something else about the same hash is refused, whether the package
was fetched just now or was already here.

The two are independent, which is what makes an interruption safe in both directions: an
interrupted index fetch leaves the previous index usable, and an interrupted payload fetch leaves
the installed package usable.

## Where the store writes

The catalogue's records live in its own directory, and each enrolment's files in a directory of its
own under `repositories/`, with five directories inside: the trust checkpoint (`datastore`), the
index documents (`index`), the payload cache (`payloads`), the extracted packages (`packages`) and
the work in progress (`staging`).

The store holds these directories open. Each is opened inside the one above it without following
a link, from the catalogue's own directory down, and everything the store writes, renames or
removes, it does through those handles rather than through a name again. A directory that is a link,
or not a directory, fails the open itself, so it is refused before anything is written through it,
however its name is spelt; one that becomes a link after it was opened redirects nothing, because
the handle holds the directory itself. Every write opens the directories again first, so a link put
in place while an operation runs is refused at that operation's next write, and what an operation
that waited for the repository's lock clears from staging is the staging directory it opened, not
whatever the name reaches by then. A directory symbolic link and a Windows junction are both links.
The directories above the catalogue's own are the host's, and are opened as the host names them.

Two writers reach the catalogue's files by name. The update client writes its private working copy
of the trust checkpoint by path while it verifies, and what it verified is read back through the
copy's own handle; a link put in place of `staging` during a verification is refused at the store's
next write, after the client has written its documents through it. The records' database is opened
by its name once the catalogue's directory has been checked. A process that can replace the
catalogue's directories while it runs already controls the catalogue's files, and nothing this host
can do defeats that.

## A signature is provenance, not safety

Whoever signed a package, its contents are untrusted input. Before anything is activated the host
runs the same validator the publishing pipeline runs, so a package this host accepts is a package
that repository's build accepted. It rejects a path that escapes the package, an entry that is not a
regular file, duplicate and case-colliding names, a file the manifest does not declare, a payload
that is absent, and a length or digest that is not what was declared.

Sync executes no installation scripts. Writing a package's bytes as data and reading them back to
check them is the whole of what a sync does with them.

## Budgets, and what is never evicted

A declared size decides whether a fetch starts. The bytes that arrive decide whether it finishes.
Neither stands in for the other: a repository that declares one megabyte and sends a gigabyte fails
the second check, and one that declares a gigabyte never reaches it.

Exceeding a budget names the exact allowance that ran out, because "out of space" sends a person to
the wrong setting. The last generation stays usable either way.

Everything a repository leaves on disk is inside one of them. Each is the enrolment's, within what
the configuration allows, and the table has the defaults:

| What stays | Budget |
| --- | --- |
| The signed metadata and the index one sync fetches | Metadata: 64 MiB and 100,000 entries |
| The generations kept, the one in use among them | Retained generations: two |
| The trust checkpoint and every kept generation's index | Retained metadata: 128 MiB |
| Cached payloads, the packages extracted from them, and a package being staged | Cached payloads: 1 GiB |

A repository keeps the generation it is on and the one before it. Accepting a generation past the
retained-generation budget removes the oldest it is no longer on, index and all, in the same commit
that moves it on; so does a kept index that would take the kept metadata past its budget. The
record of a generation goes before its index document does, and a reader whose records named a
document a sync then removed reads its records again and answers from what is kept now.

What stays is decided before a sync keeps anything of what it verified. Its checkpoint has to fit
beside the new generation, which is what stays if the sync succeeds, and beside the generation in
use, which is what stays if it goes no further; the generations the repository is not on make room
for that first, and their index documents are removed before the checkpoint is published into the
room they held; a document that cannot be removed stops the sync. A sync that fits neither way is
refused before its checkpoint is kept, and the generation in use stays as it was. The time the
client last saw is counted at the most its document can hold, so what the budget counts does not
move with the clock.

An installed package costs its extracted copy as well as its cached payloads. A package is staged
whole before it is renamed into place, so room for the copy it stages and for every payload it
still has to fetch is made before anything is fetched: the staging is counted at its largest rather
than discovered part way. A cached payload is used only at the length declared for it; a cached
object of any other length is fetched again under the declared length rather than staged on the
declaration's word. Staging holds only the work of the operation holding the repository's lock, and
whatever an operation that stopped left there is removed when the lock is next taken; what cannot
be removed stops the operation, because the room it takes would be outside every budget.

One package and one synchronisation have limits of their own, whatever a repository declares. A
package may declare at most `package_bytes`, hold at most `object_count` files and take at most
`expanded_pack_bytes` once extracted. The package format's own maxima, 64 MiB, 512 files and
64 MiB, are the defaults and the ceiling: the configuration can lower each limit and never raise
it. One synchronisation may transfer at most `transfer_bytes`, 2 GiB by default, and the metadata,
the index and a full mirror's payloads count together; a payload the mirror already holds intact
costs nothing. What the index and a mirror declare is checked before either is fetched, and the
bytes are counted again as they arrive. A sync that goes past the limit stops, names it, and leaves
the generation in use as it was.

The package limits are read each time a package is used: when it is installed, enabled, checked
after it is extracted and admitted. So a lowered limit reaches packages already installed. One past
a limit in force is not admitted, and no new binding uses it, while a live binding keeps the
release it holds. Changing a limit moves the admissions to a new revision in the same step, and a
change whose revision cannot be written puts nothing in force.

Reclaiming space never takes a payload an installed package, a live binding or a pinned generation
still needs. That is every file such a package consists of, not only the manifest its hash names: a
component nobody can read is a binding that does not work, and an installed package with its files
evicted is one that cannot run. An extracted package nothing holds goes before any cached payload:
it is a second copy of payloads, and having it again costs only an extraction. It leaves in one
rename, so it is removed whole or not at all, and a copy set aside that cannot then be deleted stops
the operation, since the room it takes is not free. What a live package consists of is read from the
installation or the binding that holds it, or from its own manifest where it is activated here. A
live package this repository holds nothing of, neither an extracted copy nor its manifest in the
cache, is another repository's, and it does not stop this repository's reclaim: nothing here is its
to lose. One this repository holds and whose files it cannot name stops the reclaim rather than
being guessed at. When the only thing left to evict is one of those, the sync reports the limit
instead.

What the live bindings hold is what the workers report. A reclaim that needs room asks at the
admission revision its own transaction reads, and while any worker has not answered at that
revision it is refused, retryably, with the sessions it waits for named: a worker that has not
answered may hold a release nothing else here describes. A reclaim with room to spare asks nothing.

## Matching, enabling and binding

Downloading the whole catalogue does not activate every module. Four separate facts decide whether
a package runs against an application:

- it is **installed** here, at one exact package hash;
- it is **enabled** here, which is a separate decision from installing it;
- it is **admitted**: supported on this host's operating system and architecture, whole in the
  store, within the package limits in force, and not revoked by its repository;
- its declarative rules **recognise** what is running.

The control daemon decides what is admitted, from the catalogue's current records, and hands each
session's worker the whole set with the state of every release a live binding holds: with the
worker's launch, after every change that could alter it, and every 30 seconds while the worker has
not answered at the current admission revision or holds a release no installation describes. A
worker binds only a package the admissions it holds admit, at the frame they were handed over in. It
reads each admitted package itself, from its checked copy and with the check a publisher's build
runs, so the match rules, the actions, the connector table and the command integration all come from
the manifest the package hash names.

Match rules are indexed by executable file stem and by distribution, so recognising a running
application is a lookup rather than a scan of every rule in the catalogue. An explicit selection
wins a conflict outright; an exact rule beats an inferred one; two exact rules are a conflict the
person settles, not one the host settles for them. A worker applies the same rule. A program the
command integration launched is bound to the connector its command resolved. A program found running
that the integration did not launch is bound to the one admitted package that recognises it, which
need not have a connector table, and one that two packages recognise exactly is adopted by neither.
An instance nothing recognised when it started is bound once a package that recognises its program
is admitted.

A binding records the hash it was made against and stays on it. An upgrade moves the installation
and leaves every live binding where it is, because a running process was qualified against the bytes
it bound to and not against the bytes that arrived afterwards. The binding also records the release
and the repository it came through, and the program it was made for with the version the program's
signed record named then; a later record for the same program changes no live binding's version.

What a binding may do follows its installation. A grant the owner withdraws reaches every live
binding of the package, on every release it holds, and the next action that needs it is refused. A
grant the owner confirms reaches only bindings on the installed release: a release the installation
left is held to what it could do when it was left, and never gains. A package disabled or removed,
or one the organisation's adapter allowlist no longer names, ends its bindings at the next
snapshot, each once no request it admitted is still open, and a
binding is reported as ending until it has closed. A binding closes only at a snapshot, so while a
worker reports one as ending, the host sends that worker a snapshot every 30 seconds: the binding
closes within about 30 seconds of its last request finishing, with no other change.

`plugin.list` counts each installation's live bindings, and every release a worker still holds that
no installation describes, from reports every worker makes after the read began. While a worker
has not answered, a count is null rather than a guess. It also says whether the admissions in force
let new bindings use each installation and, where they do not, why: disabled, revoked, not among the
adapters the organisation allows, not for this host, not whole in the store, past a package limit,
or a record the host cannot hand to a worker, each by kind and in words that name the package.
`plugin.remove` answers with the bindings its own refresh found, which are the ones the workers are
told to end, and with null when a worker did not answer or the admissions moved before the removal
committed.

## Revocation

A revoked release stops receiving new bindings immediately, and stops matching, so nothing new is
ever offered it.

An active binding is not torn down under a request that is already running: the process was
qualified against the bytes it bound to. The session is told once, with the repository's own
statement, and the administrator's disable policy decides what happens next, at the next admission
and never in the middle of one:

| Policy | A live binding on a revoked release |
| --- | --- |
| Warn only, the default | Keeps serving |
| Disable at the next admission | Keeps observing, and every rich admission through it is refused with the revocation as the reason, until the revocation no longer stands or the policy only warns |
| Disable at once | Admits nothing more, and closes once the requests it admitted have finished |

The release's state is found by where the release came from, so a revocation reaches a binding on
an old release after an upgrade, or after the package moved to another repository. The first notice
raises the trusted adapter item for the session, which escalates and repeats until the session holds
no binding on a revoked release of that package, and the notice that says so resolves it. Both
travel with the package's name while privacy mode withholds their words, and a notice the session's
journal cannot write yet is kept, in order, until the journal recovers. `plugin.list` reports which
installations and live releases are revoked. The policy is set in the host's configuration document
(`ceilings.disable_policy`, see the host guide) and is in force from the next admission; a document
that names none has the default, which only warns, and a host with no usable document keeps the
policy it holds.

## Capabilities and qualification

A repository ceiling stops thousands of passive downloads from becoming thousands of permission
prompts. Past the default, each decision is somebody's and they are not interchangeable.

| What the package asks for | Who has to say so |
| --- | --- |
| Metadata matching, declarative presentation, authorised broker events | Nobody; the enrolment already did |
| Raw terminal streams, transcript tails, process observation, upstream actions | An explicit package or repository grant |
| Terminal input, filesystem, network, approval decoding and answering | An explicit installation grant, which a repository ceiling cannot reach |
| A native bridge, which runs under the application's own permissions, or a command integration, which changes how the application runs | An installation grant the owner confirms, on every release |
| Anything the installation it replaces could not do, or, for a first installation, anything past the ceiling | The owner's confirmation, because an increase is a new decision |

A grant names only capabilities the package asks for. An installation that may do anything the
installation it replaces could not, or, with nothing to replace, anything its repository's ceiling
does not permit by itself, carries the owner's confirmation of that exact installation, and so does
every release that installs a native bridge or declares a command integration. What the replaced
installation could do is read under the ceiling it was installed under, so a move to a repository
that permits more is an increase too. The confirmation names the repository and its ceiling, as
`catalogue.list` reports them, the release, the package hash, the grant and, where the grant holds a
native bridge, the publisher's statement; it is accepted and
consumed the way `plugin.grant`'s is, and asked again when the installation is recorded. The
installation is held to the ceiling the owner was shown: a repository whose ceiling changed after
the confirmation, before the installation holds it or before the installation is recorded, refuses
it, and a new confirmation is needed. An installation that widens nothing needs none, and one that
is given is spent all the same. `plugin.grant` takes the same confirmation for every widening of an
installed package, so removing a package and installing it again is not a way around it.

The owner device shows the installation itself, not a summary of it. For an installation that grants
`native_bridge.install`, the host reads the publisher's description of what the bridge does from the
verified manifest of the exact package hash. The manifest of a release that is installed already is
read where it is installed. Otherwise it comes from the cached payload, or is fetched by its hash
and checked against the length and hash the signed index declares. The statement is part of the
digest the confirmation covers, so a confirmation shown one statement cannot install a release whose
manifest says another. It is shown on the owner device apart from the host's own notice that the
bridge runs under the application's permissions, outside the plugin sandbox. The terminal signs
nothing. When you run `kr plugin install` or `kr plugin repo add`, the command asks the host for the
challenge that names the exact request, an owner device answers it, and the repeated request spends
that one answer.

Qualification data ships as signed, immutable catalogue artifacts, separately from host binaries. A
vendor can say "this release was qualified against ExternalApp 1.4" without waiting for a core release,
and four lines hold:

- a qualification cannot create a new primitive effect: it may only describe a capability the
  installed package already requests;
- it cannot raise a grant: what a package may do is the ceiling and the installation grant, decided
  without reading a word of qualification data;
- it cannot turn an old live binding into a different version: evidence names the exact package hash
  it is about;
- it cannot say the capability works *here*: only a host probe or a live binding establishes that,
  and a catalogue record gets its own state saying which release it describes.

## Native bridges

A release whose manifest carries a native bridge recipe changes files in the application's own
directory, which the host does not own. A registration there is the package running in that
application's name, so the daemon applies the recipe only while the installation stands: it holds
`native_bridge.install`, the package is enabled, its repository has not revoked the release, and the
organisation's adapter allowlist, where there is one, names it. It takes the recipe out as soon as
any of those stops holding (a disable, a revocation that reaches the host in a synchronisation, a
list that no longer names the package, a withdrawn grant, a removal), whatever the disable policy
says about live bindings, and puts it back when they hold again. The installation stays. Where the
index that says whether the release is revoked cannot be read, the registration is not kept on its
account. After every plugin change, every synchronisation, pin and removal, every change of the
allowlist, and each time the daemon starts, each package's bridge is brought to what its
installation wants. The method's answer and receipt say what the catalogue did and are never changed
by the recipe.

A recipe is applied only where a signed record names the application's executable. The version check
below reads the builds the release's entry in the repository's signed index names for this host's
operating system and architecture, each an executable's SHA-256 digest with its version. Records
arrive with a synchronisation, so every package's bridge is followed after every sync as well as
after every plugin change. No published release names a build yet, so every recipe is still refused
and nothing is written; the package's journal records why, and the check runs again after every
plugin change, every synchronisation and each time the daemon starts.

Before anything is written, everything the recipe needs is checked, and a failed check is a refusal
that writes nothing:

- the host changes an application's directory on macOS and Linux only, because only there does it
  walk the directory from one handle without following a link and check what a replacement keeps,
  as the steps below describe;
- the application is one whose directory this host knows: Claude Code's is `.claude` in the
  account's home, the directory it reads when `CLAUDE_CONFIG_DIR` is not set;
- the forwarder the registration is expected to start is the `kr-hook` beside the daemon;
- every step the recipe installs has the removal that undoes it, and every file it installs is the
  bytes its recipe names;
- every executable the package's match rules name on the daemon's search path is read, never run,
  and each must be one a build of the release names by its SHA-256 digest, at a version inside the
  recipe's range. A version nothing establishes refuses the recipe;
- every path is walked from one handle on the application's directory, each directory opened without
  following a link, and a link or a non-directory on the way, or a destination that is not a regular
  file, is refused;
- a file already at a destination that no record of this host names with its digest is refused, even
  when it holds the same bytes, and so is a configuration key already set that this host did not
  set, whatever its value;
- a configuration document is edited only when it is strict JSON with no member name repeated in any
  object, when the key leaves it, or the document the key creates, within the 1 MiB the host reads
  back, and when a replacement keeps its protection: one with an access-control list, one in a
  directory that would give its replacement one, and one another user owns are refused.

Every file the recipe installs is JSON this host can read, whatever its name says. Every command in
one is the forwarder, in a form this host reads: its name alone, with the application and the
surface as the two arguments in a list, or one line of its name, the application and the surface,
separated by single spaces. An object that holds a command carries only a type, a name, the command,
its arguments and a time limit, so that nothing beside the command can run it in another place or
environment.

Every configuration key the recipe adds is one this host names for the application, with the one
value that enables what the release installed. For Claude Code that is `enabledPlugins.<name>` in
`settings.json`, set to `true`. A key that would make the application run a program, such as a
status line, an API key helper or a credential refresh, is not on the list, so no value a bridge
adds can hold a command.

This host does not read what else a registration file asks the application to do. The owner's
confirmation of the publisher's statement is the only control on that.

A configuration key is spliced into the document's own text and every other byte is kept, so the
document's layout, its members' order and its numbers are as they were, and removing the key
restores the document exactly. The replacement has exactly the permission bits of the document it
replaces, and one that would belong to another user or group than the document does is not put in
its place. A document whose bytes, permission bits or owners change between the host's reading and
its replacement is read again, so what somebody changed meanwhile is kept, and one that gains an
access-control list meanwhile is not replaced. Access-control lists are read through paths, so they
are read only while the paths still lead to the directory the host holds and the document it read,
checked before and after, and the replacement is refused otherwise. A program running as the same
user that swaps a path and puts it back between those checks, or changes the document after the last
of them and before the rename, is not caught. Each file is written under a temporary name, flushed
and renamed into place only where nothing is; directories are made the same way.

Each change is noted in the package's journal before it is made: a file or a directory with the
temporary name it is about to be made under, then with the identity of what was made there, then as
in place once its directory has been flushed. A daemon that stops part way leaves notes the next run
settles from what is on disk. What is still at its temporary name with the recorded identity was
never put in place, and is removed. A destination that is the object staged, by device and inode, is
the host's, whatever is at the temporary name now and whatever has been written to it since, and is
recorded as in place only after its directory is flushed; the removal then finds what changed and
leaves it. An absence is flushed before its record goes too, so a removal a stopped run made is
durable before it is forgotten, and a record goes only once what it names is gone from its own
directory and that is flushed, with the document synced too where the record is a key. Anything else
is left alone.

Two things can be the host's without the host being able to show it: something at a temporary name
when the run stopped before recording what it made there, and a key whose document was replaced
after the host wrote the key and before it recorded doing so. Neither is taken out or claimed. Each
is named in the journal, and the bridge is reported as unsettled, never as applied, until it is
gone.

The application's directory is recorded by its identity as well as its path. A directory put in its
place is never changed, and nothing it holds or lacks is taken as saying anything about the
original. Nothing at the path, or a link that leads nowhere, is not taken as the original deleted
either: absence at a path cannot tell a deleted directory from one moved away. Either way what the
release placed stays recorded, with the identities that settle what a stopped run left in flight,
the removal is reported as unfinished, and it is taken out once the original comes back to its path.

An application either finishes, or is taken out and recorded as refused with its reason. When
something cannot be taken out, such as a file in a directory that is no longer writable, the bridge
stays recorded as being removed, names what is left, and the next reconciliation tries again. A
refusal is reported as clean only when nothing the host placed is left: while anything a removal or
a refusal had to leave because somebody changed it is still there, the refusal is reported as
unsettled, by every later run and report, and what is left is named. A release is reported as
applied only once every change is in place and nothing is unsettled.

A removal takes out each file only while it is the file the host installed and still holds the bytes
installed: a copy with the same bytes put in its place is somebody's own, and is left. The key goes
only while it holds the value written, and a settings document the host created goes with it only
while it is still that document: one put in its place keeps its file and loses only the key. Then
the directories the host made go, once they hold nothing else. Whatever changed since is left in
place and named in the journal. A release applied in a directory the host no longer keeps the
application's plugins in is taken out of it before the release is applied in the new one. The
journal also says what an applied release yields for the sessions that launch its application: the
application name its registration invokes the forwarder for, the registrations it makes and the
forwarder it is expected to start.

`kr doctor` has a row for the native bridges. As for the other checks, the row states a package's
name, an application's name and any note by class and length only. The row also contains the state
of the bridge, the number of files the host published for the bridge and each file's digest. The row
emits a warning when the bridge is applying, removing or unsettled, or when it is applied and its
files no longer match what was applied, or when it was removed and something a removal left in
place is still there. If the host refused a recipe and nothing of it is in place, the row reports
it as refused and emits no warning; a refusal that had to leave something in place is unsettled. On
Windows the host refuses every recipe, and the row says so.

## The transport, and the broker

A repository is read over https or from a local directory, and nothing else: a Git URL, a branch or
a revision is refused by name at enrolment, because a branch is not update authority. The default
transport fetches over https with the platform's own trust store and reads a local directory mirror,
and a host may supply another. Which transport carried the bytes changes nothing above: verification
never trusted the transport, only the signatures over what it delivered.

Capability evidence from a live binding, admission of a package's declarative proxy and what the
workers hold live come from the trusted broker through a trait the catalogue client defines. Where
no broker is bound, there is no live evidence, no proxy is admitted and no worker holds anything,
and each says so rather than guessing.
