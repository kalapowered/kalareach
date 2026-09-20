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

## Enrolment comes first

Nothing is fetched before a repository is enrolled, and enrolment fixes four things.

| | |
| --- | --- |
| The trust root | The one this repository's metadata is verified against, and no other |
| The budgets | 64 MiB of metadata, 100,000 entries and 1 GiB of cached payloads by default |
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
   another publisher's prefix, a bare wildcard or a hash-prefix bin is refused, and a delegation
   chain deeper than three roles is refused with it.
3. Read the index, inside the metadata budget, and check what each entry declares: safe paths, no
   two names that collide on a case-insensitive filesystem, a manifest that does not declare
   itself, and declared sizes inside one package's limits.
4. Refuse a generation older than the one already accepted, one whose metadata version went
   backwards in any role, one that puts different bytes under a generation number this host already
   accepted, and one that is not the generation the owner pinned.
5. Fetch the whole generation, where the full offline mirror is on.
6. Activate the index atomically, and carry the root verification arrived at forward.

Steps 4 and 5 are in that order deliberately. A mirror that cannot be completed activates nothing,
so the generation this host is on stays the one it has payloads for. And the root a host carries
forward is the one verification ended on rather than the one it started from: a rotation is signed
by the root it replaces, and a host that always restarted from the original could have old trust
restored by a repository that simply withheld the newer root.

The client keeps its own trusted metadata, and its rollback protection is only as durable as that
store. The versions each role was accepted at are therefore written beside the activated generation
as well, and compared on every sync, so an unreadable datastore costs a re-fetch rather than a
protection.

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

A payload is fetched out of the generation this host accepted, and no other. A repository that has
moved on to a later generation is an absence until the host synchronises, not a quiet substitution
of whatever it publishes now.

## Two activations, each atomic on its own

The index is written whole and flushed, and only then does the pointer move to name it. A reader
sees one generation or the previous one, never a mixture.

A package is staged in a directory of its own, every payload is verified as a set, and the directory
is renamed into place once all of them verify. A package is therefore never half installed.

The two are independent, which is what makes an interruption safe in both directions: an
interrupted index fetch leaves the previous index usable, and an interrupted payload fetch leaves
the installed package usable.

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

Reclaiming space never takes a payload a live binding or a pinned generation still needs. That is
every file such a package consists of, not only the manifest its hash names: a component nobody can
read is a binding that does not work. When the only thing left to evict is one of those, the sync
reports the limit instead.

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

An active binding is not torn down under a request that is already running. It warns, and it follows
the administrator's explicit disable policy at the point that policy names: keep serving, admit
nothing new, or disable at the next admission.

## Capabilities and qualification

A repository ceiling stops thousands of passive downloads from becoming thousands of permission
prompts. Past the default, each decision is somebody's and they are not interchangeable.

| What the package asks for | Who has to say so |
| --- | --- |
| Metadata matching, declarative presentation, authorised broker events | Nobody; the enrolment already did |
| Transcript tails, process observation, upstream actions | An explicit package or repository grant |
| Raw terminal streams, terminal input, filesystem, network, approval decoding and answering | An explicit installation grant |
| A native bridge, which runs under the application's own permissions | An installation grant the owner confirms |
| Anything the previous installation did not hold | An installation grant, because an increase is a new decision |

Qualification data ships as signed, immutable catalogue artifacts, separately from host binaries. A
vendor can say "this release was qualified against Codex 1.4" without waiting for a core release,
and four lines hold:

- a qualification cannot create a new primitive effect: it may only describe a capability the
  installed package already requests;
- it cannot raise a grant: what a package may do is the ceiling and the installation grant, decided
  without reading a word of qualification data;
- it cannot turn an old live binding into a different version: evidence names the exact package hash
  it is about;
- it cannot say the capability works *here*: only a host probe or a live binding establishes that,
  and a catalogue record gets its own state saying which release it describes.

## What is not here yet

The client reads a repository through a transport the host supplies, and the one this build ships
reads a local directory: an official, vendor or community repository is reachable as a local
directory or a mirror of one. An https enrolment is refused by name until a host supplies a network
transport, rather than failing somewhere later with a message about trust. Nothing above changes
when that transport lands, because verification never trusted the transport.

Capability evidence from a live binding, and admission of a package's declarative proxy, come from
the trusted broker through a trait this crate defines. Until a broker is bound, there is no live
evidence and no proxy is admitted, and both say so rather than guessing.
