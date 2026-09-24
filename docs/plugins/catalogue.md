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
| The budgets | 64 MiB of metadata and 100,000 entries a sync, two kept generations in 128 MiB of kept metadata, and 1 GiB of cached payloads by default |
| The capability ceiling | Metadata matching, declarative presentation and already-authorised broker semantic events |
| The mirror setting | Off, so a sync fetches metadata and not every payload |

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

Everything a repository leaves on disk is inside one of them:

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

## Matching, enabling and binding

Downloading the whole catalogue does not activate every module. Three separate facts decide whether
a package runs against an application:

- it is **installed** here, at one exact package hash;
- it is **enabled** here, which is a separate decision from installing it;
- its declarative rules **recognise** what is running.

Match rules are indexed by executable file stem and by distribution, so recognising a running
application is a lookup rather than a scan of every rule in the catalogue. An explicit selection
wins a conflict outright; an exact rule beats an inferred one; two exact rules are a conflict the
person settles, not one the host settles for them.

A binding records the hash it was made against and stays on it. An upgrade moves the installation
and leaves every live binding where it is, because a running process was qualified against the bytes
it bound to and not against the bytes that arrived afterwards.

## Revocation

A revoked release stops receiving new bindings immediately, and stops matching, so nothing new is
ever offered it.

An active binding is not torn down under a request that is already running: the process was
qualified against the bytes it bound to. The catalogue lists each live binding on a revoked release
against that exact release, with the administrator's explicit disable policy beside it — keep
serving, admit nothing new, or disable at the next admission — for the person or the caller that
reads it. A revocation changes nothing under a request already running.

## Capabilities and qualification

A repository ceiling stops thousands of passive downloads from becoming thousands of permission
prompts. Past the default, each decision is somebody's and they are not interchangeable.

| What the package asks for | Who has to say so |
| --- | --- |
| Metadata matching, declarative presentation, authorised broker events | Nobody; the enrolment already did |
| Raw terminal streams, transcript tails, process observation, upstream actions | An explicit package or repository grant |
| Terminal input, filesystem, network, approval decoding and answering | An explicit installation grant, which a repository ceiling cannot reach |
| A native bridge, which runs under the application's own permissions | An installation grant the owner confirms, on every release |
| Anything the installation it replaces could not do, or, for a first installation, anything past the ceiling | The owner's confirmation, because an increase is a new decision |

A grant names only capabilities the package asks for. An installation that may do anything the
installation it replaces could not, or, with nothing to replace, anything its repository's ceiling
does not permit by itself, carries the owner's confirmation of that exact installation, and so does
every release that installs a native bridge. What the replaced installation could do is read under
the ceiling it was installed under, so a move to a repository that permits more is an increase
too. The confirmation names the repository and its ceiling, as `catalogue.list` reports them, the
release, the package hash and the grant; it is accepted and consumed the way `plugin.grant`'s is,
and asked again when the installation is recorded. An installation that widens nothing needs none,
and one that is given is spent all the same. `plugin.grant` takes the same confirmation for every
widening of an installed package, so removing a package and installing it again is not a way
around it.

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

## The transport, and the broker

A repository is read over https or from a local directory, and nothing else: a Git URL, a branch or
a revision is refused by name at enrolment, because a branch is not update authority. The default
transport fetches over https with the platform's own trust store and reads a local directory mirror,
and a host may supply another. Which transport carried the bytes changes nothing above: verification
never trusted the transport, only the signatures over what it delivered.

Capability evidence from a live binding, and admission of a package's declarative proxy, come from
the trusted broker through a trait the catalogue client defines. Where no broker is bound, there
is no live evidence and no proxy is admitted, and both say so rather than guessing.
