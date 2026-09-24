//! `changeset.capture`: reading a working tree into an immutable version.
//!
//! Everything here goes through the project service. The repository is opened with
//! [`kr_project::OpenedRepository`], every Git invocation runs under
//! [`kr_project::ProjectService::profile`] inside the execution boundary, and every file is read
//! through [`kr_project::OpenedRepository::work_tree`], which is an open directory descriptor
//! rather than a path. A capture writes nothing into the user's repository.
//!
//! # The base is the commit, and the index is not it
//!
//! A version is against a **revision**, so what the captured tree is compared with is the commit
//! `HEAD` names and never the index. `git diff --raw` against that revision reports, for every
//! path whose working tree differs from it, the mode and the object **the commit** holds. A path
//! the diff does not name has a working tree equal to the commit's own content, whatever the index
//! happens to hold for it. So a staged change is an uncommitted change like any other, a staged
//! addition is a path the base never held, and a staged deletion is a path the base does hold.
//!
//! # What a capture reads, and in which order
//!
//! 1. `HEAD`, which is the base revision, read inside each attempt and read again at the end.
//! 2. `git ls-files --stage -z`, the index, for the object an apply's preflight compares against.
//! 3. `git diff --raw -z <revision>`, which says how the working tree differs from the base and
//!    what the base holds for each of those paths.
//! 4. `git status --porcelain=v2 -z`, which adds the untracked and ignored paths.
//! 5. The grant and the policy decide, path by path, **before anything is opened**. A path a
//!    secret rule covers, a path under `.git`, and a path the grant leaves out are never opened.
//! 6. The content: from the working tree through the authorised handle, or from an immutable Git
//!    object with `git cat-file blob`.
//! 7. Steps 1, 2, 3 and 4 again. Anything that changed underneath is retried within
//!    [`kr_protocol::changeset::MAX_CAPTURE_RETRIES`] and then rejected with `SOURCE_CHANGED`.
//!
//! # The three consistency classes, and the mechanism each rests on
//!
//! * [`SourceConsistency::AtomicSnapshot`] is a capture of the base commit's **own tree**, read by
//!   walking immutable tree objects from `<revision>^{tree}` and reading each blob with
//!   `cat-file`. The commit is immutable and so is every object under it, so the whole tree is one
//!   instant by construction rather than by timing. Nothing of the working tree is read at all. A
//!   caller asks for it with `required_consistency`, and a policy that would include any
//!   uncommitted work is refused rather than served a weaker class under the name it asked for.
//! * [`SourceConsistency::QuiescedCapture`] needs a **reservation over this very working tree,
//!   granted before the first reading and still holding after the last one**. The capture asks a
//!   [`QuiescenceAuthority`] for it, compares what it was granted with what it asked for, and
//!   watches the grant's own identity and its bound through the read. A declaration alone never
//!   decides the class, and neither does a reading of who holds the workspace: both describe two
//!   instants and say nothing about the interval between them.
//! * [`SourceConsistency::PerFileCapture`] otherwise. Files read one at a time from a live tree,
//!   with each file's identity, length and modification instant compared across its own read and
//!   the whole selection compared across the capture. The captured tree is still immutable and
//!   exactly identified; what it is not is one instant of the working tree.
//!
//! No filesystem this service runs on offers an unprivileged atomic snapshot of a directory tree,
//! so there is no fourth mechanism and no capture is described as one.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::Read as _;

use kr_project::{OpenedRepository, RestrictedProfile};
use kr_protocol::changeset::{
    CapturedPath, ContentOrigin, Exclusion, ExclusionReason, FileGrant, MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RETRIES, MAX_PATH_RETRIES, PathClass, SourceConsistency,
};
use kr_protocol::ids::WorkspaceId;
use kr_protocol::project::{
    ChangeKind, ContentClass, InclusionChoice, InclusionClass, InclusionPolicy,
};
use kr_protocol::scalars::{Digest256, Nullable, U64};
use kr_transfer::authority::ObjectKind;
use kr_transfer::{AuthorisedDirectory, ObjectIdentity, ObjectPolicy, RelativeName};

use crate::error::{ChangeSetError, Result};
use crate::grant::{self, GrantDecision};
use crate::objects::ObjectStore;
use crate::version::Manifest;

/// How many Git objects one capture reads.
///
/// Reading content from a Git object costs one invocation each, and the boundary makes each one a
/// process of its own. A capture that would need more than this says so with the figure rather
/// than running for an hour: the caller narrows its grant, or accepts the working tree as the
/// source and the per-file class that goes with it.
pub const MAX_OBJECT_READS: usize = 4_096;

/// How many paths one capture walks into from a wholly ignored or untracked directory.
///
/// Git reports a directory nothing in which is tracked as **one** record with a trailing
/// separator, so a capture that took that record literally would hold a path that is a directory
/// and would miss every file under it. The walk expands it, and a tree deeper or wider than this
/// is refused with the figure rather than captured short.
pub const MAX_WALK_ENTRIES: usize = 200_000;

/// How deep one walk goes, into a reported directory or into the base commit's own tree.
pub const MAX_WALK_DEPTH: usize = 64;

/// How many references one discovery follows before it refuses.
///
/// A `gitdir:` line, a `commondir` and a link each name a place to go and look, and each place can
/// name another. What stops a chain of them is not the depth of any one walk — each of those
/// starts a walk of its own — so the number of references followed to reach a directory is
/// counted and bounded too. Deeper than any layout this host is asked about, and finite.
pub const MAX_REFERENCE_HOPS: usize = 64;

/// The furthest this capture climbs to reach a directory named from above where it started.
///
/// Deeper than any filesystem this host is asked about, and finite, which is what matters: the
/// directory a handle is in can be changed under the walk, so the walk has an end of its own. It
/// counts the levels the climb goes up, so a tree exactly this many levels below the root of its
/// filesystem is still reached; the open that confirms the root is not one of them.
pub const MAX_CLIMB_HOPS: usize = 256;

/// Largest single file one capture reads, in bytes.
///
/// The total bound is charged as the capture goes rather than at the end, and this is the bound on
/// one file, so a file larger than a host should hold in memory is refused before it is read
/// rather than after.
pub const MAX_CAPTURE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// One capture's request, together with what this host worked out about the repository itself.
///
/// The administrative prefix is not the caller's to state: it is where this repository actually
/// keeps its own data, read from the repository at the moment the capture opens it. A `.git`
/// **file** can point at a directory of any name inside the same tree, which the name rule cannot
/// see, so the resolved location travels beside the request and the walk refuses it as well.
#[derive(Clone, Copy)]
struct Scope<'a> {
    request: &'a CaptureRequest<'a>,
    administrative_prefix: Option<&'a str>,
    /// Every place a repository **nested in this tree** keeps its own data, as a path relative to
    /// the working tree.
    ///
    /// Worked out from each nested repository's own `.git`, which is a directory beside its tree
    /// or a file pointing anywhere it can reach. A path under one of these is that repository's
    /// configuration, which holds its remotes and can hold a credential, or its object database.
    nested: &'a BTreeSet<String>,
}

impl<'a> std::ops::Deref for Scope<'a> {
    type Target = CaptureRequest<'a>;

    fn deref(&self) -> &Self::Target {
        self.request
    }
}

/// The Git file modes a captured tree can hold.
///
/// `100644` and `100755` are file content. `120000` is a symbolic link, whose object holds the
/// target rather than content, and `160000` is a submodule. Writing either out as a regular file
/// would make a materialisation a different tree, so both are named and left out.
pub(crate) const REGULAR_MODES: &[&str] = &["100644", "100755"];

/// What the capture is asked to read.
#[derive(Clone, Copy, Debug)]
pub struct CaptureRequest<'a> {
    /// One decision per class of the working tree.
    pub policy: &'a InclusionPolicy,
    /// What the caller's grant selects and excludes.
    pub grant: &'a FileGrant,
    /// True when the caller has quiesced the working tree.
    pub quiescence_declared: bool,
    /// The class the caller requires, when it requires one.
    pub required_consistency: Option<SourceConsistency>,
    /// Where to ask for this workspace to be held still, when the caller offers somewhere.
    pub quiescence: Option<Quiescence<'a>>,
}

/// Where a capture asks for a workspace to be held still, and which workspace that is.
#[derive(Clone, Copy, Debug)]
pub struct Quiescence<'a> {
    /// Who grants the reservation.
    pub authority: &'a dyn QuiescenceAuthority,
    /// The workspace the caller resolved this repository from.
    pub workspace_id: WorkspaceId,
}

/// Exactly what one reservation covers.
///
/// Both halves are compared with what the capture asked for: a grant over another workspace, or
/// over another working tree of the same one, holds nothing of this read still. The working tree
/// is named by its **identity**, read through the handle the capture is about to read every file
/// through, so a second name for the same directory is the same subject and a different directory
/// under the same path is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuiescenceSubject {
    /// The workspace whose working tree this capture reads.
    pub workspace_id: WorkspaceId,
    /// That working tree, by identity rather than by name.
    pub work_tree: ObjectIdentity,
}

/// Who holds a workspace still while a capture reads it.
///
/// This is the seam this crate exposes and the workflow service owns: a capture is the
/// only thing here that asks for a reservation, and nothing here can grant one. It is what
/// [`SourceConsistency::QuiescedCapture`] rests on, so an implementer owes the capture the whole
/// of this contract:
///
/// * **Exclusion, continuously.** From the moment a grant is returned until it is released or its
///   bound passes, every writer the implementer coordinates is kept off the workspace: the working
///   tree, the index and the repository's own references alike. An advisory lock only KalaReach
///   respects does not exclude an editor outside it, and an implementer that cannot exclude one
///   refuses instead of granting.
/// * **Now or not at all.** [`Self::reserve`] never waits. A workspace it cannot hold still at the
///   moment it is asked is [`None`], and the capture goes on as the weaker class it can actually
///   perform, or refuses when the caller required the stronger one.
/// * **Nothing owned after a refusal.** A [`None`] or an error leaves the capture holding nothing,
///   so there is nothing for it to release.
pub trait QuiescenceAuthority: Send + Sync + std::fmt::Debug {
    /// Holds `subject` still now, or refuses now.
    ///
    /// # Errors
    ///
    /// Returns whatever the implementer returns when it cannot answer at all, which is not the
    /// same as refusing: a refusal is `Ok(None)`.
    fn reserve(&self, subject: QuiescenceSubject) -> Result<Option<Box<dyn QuiescenceLease + '_>>>;
}

/// One granted reservation, for as long as the capture holds it.
///
/// The implementer's duties do not end at the grant:
///
/// * **The bound is the implementer's own deadline**, not a hint to the capture. Whatever the
///   capture is doing, the reservation releases the workspace when [`Self::bound`] passes, so a
///   capture that stops without releasing cannot hold a workspace for ever.
/// * **A lapse is permanent.** Once [`Self::holding`] answers false, this grant never holds again.
///   A reservation taken afresh is a **different** grant with a different [`Self::grant_id`], and
///   it says nothing about the interval this capture has already read.
/// * **Release is idempotent and cannot fail.** The capture releases a grant however it ends,
///   including on the error paths, and a release of something already released does nothing.
pub trait QuiescenceLease: Send + Sync + std::fmt::Debug {
    /// What this grant holds still.
    fn subject(&self) -> QuiescenceSubject;

    /// This grant's own identity, distinct from every other grant of the same subject.
    fn grant_id(&self) -> u128;

    /// The instant this grant releases the workspace whatever the capture is doing.
    fn bound(&self) -> std::time::Instant;

    /// Whether this grant has excluded every writer without interruption since it was granted.
    fn holding(&self) -> bool;

    /// Gives the workspace back.
    fn release(&self);
}

/// The grant one capture holds, released however that capture ends.
struct Granted<'a> {
    lease: Box<dyn QuiescenceLease + 'a>,
    /// The grant that was taken. A lease answering with another one is another grant, whatever it
    /// says about holding.
    grant_id: u128,
    /// The deadline the grant was taken under, read once so a lease that moves its own bound
    /// forward cannot extend what this capture relies on.
    bound: std::time::Instant,
}

impl Drop for Granted<'_> {
    fn drop(&mut self) {
        self.lease.release();
    }
}

impl Granted<'_> {
    /// Whether this exact grant is still holding the workspace, by this host's clock as well.
    fn holding(&self) -> bool {
        std::time::Instant::now() < self.bound
            && self.lease.grant_id() == self.grant_id
            && self.lease.holding()
    }
}

/// What the quiescence reservation came to, which is what decides the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reservation {
    /// The caller offered no authority to ask.
    NotAsked,
    /// The authority would not hold the workspace still at the moment it was asked.
    Refused,
    /// A grant was taken and has held through every reading so far.
    Held,
    /// A grant was taken and stopped holding before the read finished.
    Lapsed,
    /// A grant said it was holding and this host read a file that was being written anyway.
    Contradicted,
}

impl Reservation {
    /// Asks the grant whether it is still holding, once, at one point of the read.
    ///
    /// A lapse is recorded once and never reconsidered: a grant that stopped holding while this
    /// host was reading leaves an interval nothing covered, and a reservation taken again after
    /// that is a different grant over a different interval.
    fn still_holding(&mut self, granted: Option<&Granted<'_>>) {
        if *self == Self::Held && !granted.is_some_and(Granted::holding) {
            *self = Self::Lapsed;
        }
    }

    /// Records that the tree changed under a grant that was supposed to be holding it still.
    ///
    /// The capture's own contradiction of the reservation: whatever the grant answers, a change
    /// this host detected is one the reservation did not keep out. A change a later attempt read
    /// past counts exactly as one that exhausted this host's retries: both are readings of a tree
    /// something was writing to.
    fn changed_underneath(&mut self) {
        if *self == Self::Held {
            *self = Self::Contradicted;
        }
    }
}

/// Why a grant that was taken stopped covering the read.
const LAPSED: &str = "the reservation that was holding this workspace still stopped holding it \
                      before the read finished";

/// Why a grant this host was told it had did not do what a grant does.
const CHANGED: &str = "the working tree changed while a reservation was supposed to be holding \
                       it still, so nothing held it still";

/// Refuses a capture whose caller required the class the reservation did not deliver.
fn required_quiescence_refused(why: &str) -> ChangeSetError {
    ChangeSetError::InvalidArgument(
        format!(
            "this request requires a quiesced_capture and this host did not perform one: {why}"
        )
        .into(),
    )
}

/// What one capture established.
#[derive(Clone, Debug)]
pub struct Captured {
    /// The whole captured tree.
    pub manifest: Manifest,
    /// The revision it is against.
    pub base_revision: String,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Option<String>,
    /// How consistent the source was.
    pub consistency: SourceConsistency,
    /// What decided that class, in this host's own words.
    pub consistency_detail: String,
    /// Every distinct content digest the tree names.
    pub objects: Vec<kr_protocol::scalars::Digest256>,
}

/// One entry of the index listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// The mode Git records for it, such as `100644` or `100755`.
    pub mode: String,
    /// The object the index holds for it.
    pub object_id: String,
    /// Its merge stage: zero for an ordinary entry, higher for an unresolved one.
    pub stage: u32,
}

/// One path whose working tree differs from the base revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseDifference {
    /// The mode the base revision holds, or nothing when the base does not hold the path.
    pub base_mode: Option<String>,
    /// The object the base revision holds, or nothing when the base does not hold the path.
    pub base_object_id: Option<String>,
    /// Git's own one-letter status: `A`, `D`, `M`, `T`, `U`.
    pub status: char,
}

/// Whether anything KalaReach knows of still holds the workspace.
///
/// The one mechanism behind [`SourceConsistency::QuiescedCapture`] that is not a declaration: the
/// project service records every session and automation run bound to a workspace, and a capture
/// that finds none of them live before and after the read has established that nothing this host
/// knows about was writing. What it does not establish is that an editor outside KalaReach was
/// not, and the record says so.
pub type QuiescenceProbe<'a> = &'a dyn Fn() -> Result<bool>;

/// Returns where one repository keeps its administrative data, relative to its working tree.
///
/// `.git` on an ordinary repository. A `.git` **file** can point at a directory of any name inside
/// the same tree, and the name rule alone would not see that one, so the resolved location is
/// worked out once and carried with the request.
#[must_use]
pub fn administrative_prefix(repository: &OpenedRepository) -> Option<String> {
    let inside = repository
        .git_dir_path()
        .strip_prefix(repository.top_level())
        .ok()?;
    let relative = inside.to_str()?;
    (!relative.is_empty()).then(|| relative.replace('\\', "/"))
}

/// Reads a working tree into a captured tree.
///
/// # Errors
///
/// Returns [`ChangeSetError::SourceChanged`] when the source kept changing past the bound,
/// [`ChangeSetError::InvalidArgument`] when the repository has no commit yet or the required
/// consistency class cannot be reached, and whatever the project service returns for a Git
/// invocation or a refused repository.
pub fn capture(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    request: &CaptureRequest<'_>,
    quiet: QuiescenceProbe<'_>,
) -> Result<Captured> {
    // Where this repository actually keeps its administrative data, read from the repository this
    // capture opened rather than assumed to be `.git`.
    let administrative = administrative_prefix(repository);
    if request.required_consistency == Some(SourceConsistency::AtomicSnapshot) {
        // A snapshot reads the commit's own tree and nothing of the working tree, but which paths
        // hold another repository is a question about the tree on disk, and it is asked here for
        // the same reason: a version does not hold another repository's configuration, whichever
        // side its content was read from.
        let reading = Reading::take(
            profile,
            repository,
            request.grant,
            administrative.as_deref(),
        )?;
        let nested = nested_repositories(repository, reading_paths(&reading))?;
        let request = Scope {
            request,
            administrative_prefix: administrative.as_deref(),
            nested: &nested,
        };
        return snapshot(profile, repository, store, request);
    }
    // The reservation is taken **before the first reading** and given back after the last one.
    // Everything between them is what the class is a claim about, so nothing is read before this.
    let required_quiesced =
        request.required_consistency == Some(SourceConsistency::QuiescedCapture);
    let mut reservation = Reservation::NotAsked;
    let mut granted = None;
    if let Some(quiescence) = request.quiescence {
        let subject = QuiescenceSubject {
            workspace_id: quiescence.workspace_id,
            work_tree: repository.identity().work_tree,
        };
        match quiescence.authority.reserve(subject)? {
            Some(lease) => {
                // A grant over anything but the working tree this capture has open holds none of
                // this read still, whatever it says about itself.
                if lease.subject() != subject {
                    let found = lease.subject();
                    lease.release();
                    return Err(ChangeSetError::WrongState {
                        detail: format!(
                            "this host asked for workspace {} and working tree {} to be held \
                             still, and was granted a reservation over workspace {} and working \
                             tree {}, which holds nothing of this capture still",
                            subject.workspace_id,
                            subject.work_tree,
                            found.workspace_id,
                            found.work_tree
                        )
                        .into(),
                    });
                }
                granted = Some(Granted {
                    grant_id: lease.grant_id(),
                    bound: lease.bound(),
                    lease,
                });
                reservation = Reservation::Held;
            }
            None => reservation = Reservation::Refused,
        }
    }
    if reservation != Reservation::Held && required_quiesced {
        return Err(required_quiescence_refused(match reservation {
            Reservation::Refused => {
                "the reservation that would have held this workspace still was refused"
            }
            _ => "this request carries nowhere to reserve this workspace from",
        }));
    }
    let nothing = BTreeSet::new();
    let request = Scope {
        request,
        administrative_prefix: administrative.as_deref(),
        nested: &nothing,
    };
    let mut last_change = String::new();
    for attempt in 0..=MAX_CAPTURE_RETRIES {
        let before = Reading::take(
            profile,
            repository,
            request.grant,
            request.administrative_prefix,
        )?;
        let quiet_before = quiet()?;
        reservation.still_holding(granted.as_ref());
        if reservation == Reservation::Lapsed && required_quiesced {
            return Err(required_quiescence_refused(LAPSED));
        }
        // Where every repository nested in this tree keeps its own data, worked out from the
        // directories this reading names. It has to be done before anything is planned, because a
        // path under one of them is never content whatever else decides about it.
        let nested = nested_repositories(repository, reading_paths(&before))?;
        let request = Scope {
            nested: &nested,
            ..request
        };
        let planned = plan(&before, request);
        let mut rewritten = false;
        let read = read_content(
            profile,
            repository,
            store,
            &planned,
            request,
            &mut rewritten,
        );
        // A file that was written while this host read it and whose next attempt read it whole.
        // The content is a complete reading, so the capture carries on; what it cannot be is a
        // reading of a tree nothing was writing. The class goes down here rather than at the
        // retry bound, because a change a retry read past is the same contradiction of the
        // reservation as one that exhausted the retries.
        if rewritten {
            reservation.changed_underneath();
            if required_quiesced {
                return Err(required_quiescence_refused(CHANGED));
            }
        }
        let manifest = match read {
            Ok(manifest) => manifest,
            Err(ChangeSetError::SourceChanged { detail }) if attempt < MAX_CAPTURE_RETRIES => {
                last_change = detail.as_str().to_owned();
                // A file that changed while a grant was supposed to be holding the tree still is
                // this host's own evidence that it was not, so the retry runs without the class
                // however the grant answers afterwards.
                reservation.changed_underneath();
                if required_quiesced {
                    return Err(required_quiescence_refused(CHANGED));
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        reservation.still_holding(granted.as_ref());
        if reservation == Reservation::Lapsed && required_quiesced {
            return Err(required_quiescence_refused(LAPSED));
        }
        // Everything the selection was decided from is read again. A file this host did not touch
        // changing is exactly what a per-file capture cannot exclude, and what it must not
        // describe as one instant.
        let after = Reading::take(
            profile,
            repository,
            request.grant,
            request.administrative_prefix,
        )?;
        if after != before {
            last_change = format!(
                "the working tree changed while this host was reading it: {}",
                before.difference(&after)
            );
            reservation.changed_underneath();
            if required_quiesced {
                return Err(required_quiescence_refused(CHANGED));
            }
            if attempt < MAX_CAPTURE_RETRIES {
                continue;
            }
            return Err(changed(&last_change));
        }
        let quiet_after = quiet()?;
        reservation.still_holding(granted.as_ref());
        if reservation == Reservation::Lapsed && required_quiesced {
            return Err(required_quiescence_refused(LAPSED));
        }
        let (consistency, consistency_detail) =
            classify(request, reservation, quiet_before && quiet_after);
        if let Some(required) = request.required_consistency
            && !consistency.satisfies(required)
        {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "this capture's source is a {} and the request requires a {}: \
                     {consistency_detail}",
                    consistency.as_str(),
                    required.as_str()
                )
                .into(),
            ));
        }
        // Every reading is done, so the workspace goes back before this host spends any time on
        // the manifest. What the class describes is the interval that has just ended.
        drop(granted.take());
        let objects = distinct_objects(&manifest);
        return Ok(Captured {
            manifest,
            base_revision: before.revision,
            base_reference: before.reference,
            consistency,
            consistency_detail,
            objects,
        });
    }
    Err(changed(&last_change))
}

fn changed(detail: &str) -> ChangeSetError {
    ChangeSetError::SourceChanged {
        detail: format!(
            "{detail}, and this host tried {} times",
            MAX_CAPTURE_RETRIES + 1
        )
        .into(),
    }
}

/// Returns every distinct content digest a manifest names.
///
/// A deletion names one too: what the base held for the path it removes is content this version
/// carries, and a version's objects are everything it would need to be delivered.
pub(crate) fn distinct_objects(manifest: &Manifest) -> Vec<kr_protocol::scalars::Digest256> {
    let mut digests: Vec<_> = manifest
        .paths
        .iter()
        .map(|entry| entry.content_digest)
        .chain(
            manifest
                .deletions
                .iter()
                .filter_map(|deleted| deleted.content_digest),
        )
        .collect();
    digests.sort_unstable();
    digests.dedup();
    digests
}

/// Everything one attempt decides its selection from, read together and compared afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reading {
    revision: String,
    reference: Option<String>,
    index: BTreeMap<String, IndexEntry>,
    differences: BTreeMap<String, BaseDifference>,
    staged: BTreeMap<String, BaseDifference>,
    status: Vec<kr_project::workspace::StatusEntry>,
}

impl Reading {
    fn take(
        profile: &RestrictedProfile,
        repository: &OpenedRepository,
        grant: &FileGrant,
        administrative_prefix: Option<&str>,
    ) -> Result<Self> {
        let (revision, reference) = repository.head(profile)?;
        let Some(revision) = revision else {
            return Err(ChangeSetError::InvalidArgument(
                "this repository has no commit yet, so there is no base revision a version could \
                 be captured against; commit once and capture again"
                    .into(),
            ));
        };
        let index = read_index(profile, repository)?;
        let differences = read_differences(profile, repository, &revision, false)?;
        // The second diff is the index against the same commit. It is what completes the base
        // inventory: a path whose **only** change is staged does not appear in the working-tree
        // diff at all, and without this reading this host would have no object identifier for what
        // the commit holds there.
        let staged = read_differences(profile, repository, &revision, true)?;
        let status = read_status(profile, repository, grant, administrative_prefix)?;
        Ok(Self {
            revision,
            reference,
            index,
            differences,
            staged,
            status,
        })
    }

    /// Returns what changed between two readings, in this host's own words.
    fn difference(&self, other: &Self) -> String {
        if self.revision != other.revision {
            return "a commit landed while this host was reading the working tree".to_owned();
        }
        if self.index != other.index {
            return "the index changed while this host was reading the working tree".to_owned();
        }
        if self.differences != other.differences || self.staged != other.staged {
            return "what the working tree holds that the base revision does not changed"
                .to_owned();
        }
        "the untracked and ignored paths changed".to_owned()
    }

    /// Returns what the base revision holds for one path, when it holds it.
    ///
    /// A path the diff names carries the base's own mode and object. A path it does not name has a
    /// working tree equal to the base's content, so the base does hold it; the index's object is
    /// the base's only when nothing is staged for it, which the status says.
    fn base_of(&self, path: &str) -> Option<(String, String)> {
        if let Some(difference) = self.differences.get(path) {
            return match (&difference.base_mode, &difference.base_object_id) {
                (Some(mode), Some(object_id)) => Some((mode.clone(), object_id.clone())),
                _ => None,
            };
        }
        if let Some(difference) = self.staged.get(path) {
            // The working tree matches the base and the index does not, so the index's object is
            // not the base's. The index-against-commit diff is where the base's own object for
            // such a path comes from.
            return match (&difference.base_mode, &difference.base_object_id) {
                (Some(mode), Some(object_id)) => Some((mode.clone(), object_id.clone())),
                _ => None,
            };
        }
        // The working tree and the index both match the commit, so the index's object is the
        // commit's.
        self.index
            .get(path)
            .map(|entry| (entry.mode.clone(), entry.object_id.clone()))
    }
}

/// Reads `git ls-files --stage -z`, which is what the index holds for every tracked path.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the index holds a path this host cannot read
/// as text, and whatever the project service returns for the invocation.
pub fn read_index(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
) -> Result<BTreeMap<String, IndexEntry>> {
    let arguments: [&OsStr; 3] = [
        OsStr::new("ls-files"),
        OsStr::new("--stage"),
        OsStr::new("-z"),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(&output.stdout, "this repository's index")?;
    let mut entries = BTreeMap::new();
    for record in text.split('\0') {
        // `<mode> <object> <stage>\t<path>`
        let Some((fields, path)) = record.split_once('\t') else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let parts: Vec<&str> = fields.splitn(3, ' ').collect();
        if parts.len() < 3 {
            continue;
        }
        let stage = parts[2].trim().parse::<u32>().unwrap_or(0);
        let entry = IndexEntry {
            mode: parts[0].to_owned(),
            object_id: parts[1].to_owned(),
            stage,
        };
        // An unmerged path has several stages. The first one wins the map and the stage is kept,
        // so the plan can see that the path is unmerged rather than ordinary.
        entries.entry(path.to_owned()).or_insert(entry);
    }
    Ok(entries)
}

/// Reads how the working tree differs from one revision, and what that revision holds.
///
/// This is what makes the base the **commit** rather than the index: Git reports the source mode
/// and the source object from the revision itself, so a staged change never passes for the base's
/// own content.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the repository names a path this host cannot
/// read as text, and whatever the project service returns for the invocation.
pub fn read_differences(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    revision: &str,
    staged: bool,
) -> Result<BTreeMap<String, BaseDifference>> {
    check_object_id(revision)?;
    let cached: &OsStr = OsStr::new(if staged { "--cached" } else { "--no-color" });
    let arguments: [&OsStr; 8] = [
        OsStr::new("diff"),
        OsStr::new("--raw"),
        OsStr::new("-z"),
        // Git abbreviates an object identifier in this format by default, and an abbreviation can
        // become ambiguous as a repository grows and resolves to something else in another
        // repository. A content revision is exact or it is not one.
        OsStr::new("--no-abbrev"),
        OsStr::new("--no-renames"),
        OsStr::new("--ignore-submodules=all"),
        cached,
        OsStr::new(revision),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(
        &output.stdout,
        "this repository's own report of its changes",
    )?;
    // `:<srcmode> <dstmode> <srcsha> <dstsha> <status>\0<path>\0`
    let mut fields = text.split('\0');
    let mut entries = BTreeMap::new();
    while let Some(meta) = fields.next() {
        let Some(meta) = meta.strip_prefix(':') else {
            continue;
        };
        let Some(path) = fields.next() else {
            break;
        };
        if path.is_empty() {
            continue;
        }
        let parts: Vec<&str> = meta.split(' ').collect();
        if parts.len() < 5 {
            return Err(ChangeSetError::InvalidArgument(
                "this repository reported a change record this format does not define".into(),
            ));
        }
        let status = parts[4].chars().next().unwrap_or('?');
        let absent = |value: &str| value.bytes().all(|byte| byte == b'0');
        // The identifier this record carries becomes the base object of a captured path and the
        // thing a revert reads back, so it is checked here, where it is read, rather than where
        // it is used.
        let base_object_id = if absent(parts[2]) {
            None
        } else {
            check_object_id(parts[2])?;
            Some(parts[2].to_owned())
        };
        entries.insert(
            path.to_owned(),
            BaseDifference {
                base_mode: (!absent(parts[0])).then(|| parts[0].to_owned()),
                base_object_id,
                status,
            },
        );
    }
    Ok(entries)
}

/// Reads `git status --porcelain=v2 -z`, with the same arguments the project service uses.
///
/// A record whose path ends in a separator is a whole directory Git reported as one entry, and
/// this expands it into the files it holds, through the working tree's own handle. The grant
/// decides a directory **before** the walk descends into it, so nothing under an excluded prefix
/// is even listed.
///
/// # Errors
///
/// Returns whatever the project service returns for the invocation, and
/// [`ChangeSetError::QuotaExceeded`] when the walk would exceed [`MAX_WALK_ENTRIES`].
pub fn read_status(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    grant: &FileGrant,
    administrative_prefix: Option<&str>,
) -> Result<Vec<kr_project::workspace::StatusEntry>> {
    // `--ignore-submodules=all` is not an optimisation. Checking a submodule's dirtiness runs Git
    // *inside* the submodule, under a configuration the project service's audit never read.
    let arguments: [&OsStr; 7] = [
        OsStr::new("status"),
        OsStr::new("--porcelain=v2"),
        OsStr::new("-z"),
        OsStr::new("--untracked-files=all"),
        OsStr::new("--ignored=matching"),
        OsStr::new("--no-renames"),
        OsStr::new("--ignore-submodules=all"),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let reported = exactly(&output.stdout, "this repository's own status")?;
    let entries = kr_project::workspace::parse_status(reported)?;
    let mut expanded = Vec::with_capacity(entries.len());
    let mut budget = MAX_WALK_ENTRIES;
    let tree = confined_tree(repository)?;
    for entry in entries {
        if let Some(prefix) = entry.path.strip_suffix('/') {
            walk(
                &tree,
                prefix,
                entry.class,
                grant,
                administrative_prefix,
                &mut expanded,
                &mut budget,
                0,
            )?;
        } else {
            expanded.push(entry);
        }
    }
    expanded.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(expanded)
}

/// Decodes what Git reported, refusing text this host cannot carry exactly.
///
/// A lossy decoding puts a replacement character where a byte was, and this host would then be
/// asking the filesystem about a different name: two different paths can become one, and a path
/// can go missing without anything saying so. A repository whose names this host cannot read is
/// refused rather than approximated.
fn exactly<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        ChangeSetError::InvalidArgument(
            format!(
                "{what} names a path this host cannot read as text, so it cannot say what that \
                 path holds"
            )
            .into(),
        )
    })
}

/// Expands one directory entry into the files it holds.
///
/// The walk goes through the authorised directory handle, so nothing outside the working tree is
/// reached and a link is neither followed nor counted as content. Four things stop it: a directory
/// the grant excludes, a directory a secret rule covers, a directory named `.git`, which holds a
/// repository's own administrative data including its remotes and any credential a configuration
/// file carries, and a directory that **holds** a `.git` entry, which is another repository's tree
/// and is never read inside.
#[allow(clippy::too_many_arguments)]
fn walk(
    tree: &kr_transfer::AuthorisedDirectory,
    prefix: &str,
    class: InclusionClass,
    grant: &FileGrant,
    administrative_prefix: Option<&str>,
    out: &mut Vec<kr_project::workspace::StatusEntry>,
    budget: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "a directory this capture would read is more than {MAX_WALK_DEPTH} levels deep, \
                 and this host does not capture a tree it cannot walk to the bottom of"
            )
            .into(),
        });
    }
    // The decision is made before anything beneath the prefix is listed, which is what "the grant
    // applies before capture" means for a directory. The one entry is kept so the content read
    // records the exclusion with its reason rather than the path going missing.
    if !grant::may_traverse(grant, prefix)
        || administrative_prefix.is_some_and(|name| grant::under(prefix, name))
    {
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    }
    let Ok(name) = RelativeName::parse(prefix) else {
        // A name this host cannot carry beneath the working tree's handle is kept as the one entry
        // the status reported, so the content read names it as unsupported rather than this walk
        // dropping it.
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    };
    let Ok(directory) = open_beneath(tree, &name, prefix)? else {
        // Not a directory after all, or not reachable. It is still one entry the status reported,
        // and the content read decides what it is.
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    };
    // A directory holding a `.git` entry of any kind is **another repository's tree**, and this
    // host never reads inside one. The name rule catches a `.git` directory, but a `.git` file
    // points that repository's data at a directory of any name, by any spelling, anywhere it can
    // reach: beside it, above it, or through a link. Nothing this walk could resolve would answer
    // every one of those, and reading the wrong answer means capturing a repository's
    // configuration, which holds its remotes and can hold a credential, and its object database.
    // So the whole tree is one entry and this walk stops at it, which is what it already does for
    // a submodule.
    if directory
        .handle()
        .symlink_metadata(grant::ADMINISTRATIVE_DIRECTORY)
        .is_ok()
    {
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    }
    let entries = directory
        .handle()
        .entries()
        .map_err(ChangeSetError::storage)?;
    for entry in entries {
        let entry = entry.map_err(ChangeSetError::storage)?;
        let file_name = entry.file_name().into_string().map_err(|_| {
            ChangeSetError::InvalidArgument(
                "this working tree holds a name this host cannot read as text, so it cannot say \
                 what that path holds"
                    .into(),
            )
        })?;
        let child = format!("{prefix}/{file_name}");
        let kind = entry.file_type().map_err(ChangeSetError::storage)?;
        if *budget == 0 {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would walk into more than {MAX_WALK_ENTRIES} entries that Git \
                     reported as whole directories; narrow the grant or the policy"
                )
                .into(),
            });
        }
        *budget -= 1;
        if kind.is_dir() {
            walk(
                tree,
                &child,
                class,
                grant,
                administrative_prefix,
                out,
                budget,
                depth + 1,
            )?;
            continue;
        }
        // A link, a socket or a device is not file content. It is kept as an entry so the content
        // read names it as unsupported rather than leaving it out with no record.
        out.push(kr_project::workspace::StatusEntry {
            path: child,
            class,
            change: ChangeKind::Present,
        });
    }
    Ok(())
}

/// What the capture decided to do about one path, before anything is opened.
#[derive(Clone, Debug)]
enum Plan {
    /// Read it from the working tree.
    WorkingTree {
        class: PathClass,
        change: ChangeKind,
        base_object_id: Option<String>,
        base_mode: Option<String>,
        index_mode: Option<String>,
    },
    /// Read it from this immutable Git object.
    GitObject {
        class: PathClass,
        object_id: String,
        mode: String,
    },
    /// Leave it out, for this reason.
    Exclude {
        reason: ExclusionReason,
        detail: String,
    },
    /// The working tree deleted it, and this is what the base holds for it.
    ///
    /// A deletion is an operation rather than an absence: an apply performs it, a diff read names
    /// it, and a revert puts the base's own content back, which needs the base's own object.
    Deleted {
        base_object_id: Option<String>,
        base_mode: Option<String>,
    },
}

/// Decides what to do about every path, from the index, the base difference and the status alone.
///
/// Nothing is opened here. That is the point: the grant and the secret rules decide before the
/// capture reads anything, so a secret is never read, let alone stored.
fn plan(reading: &Reading, request: Scope<'_>) -> BTreeMap<String, Plan> {
    let mut planned: BTreeMap<String, Plan> = BTreeMap::new();
    // One path can appear twice: a file removed from the index and still on disk is reported both
    // as a staged deletion and as untracked. What the working tree holds is the entry that
    // decides, so a present entry is kept over an absent one whichever order they arrive in.
    let mut status: BTreeMap<&str, &kr_project::workspace::StatusEntry> = BTreeMap::new();
    for entry in &reading.status {
        match status.get(entry.path.as_str()) {
            Some(held) if held.change != ChangeKind::Deleted => {}
            _ => {
                status.insert(entry.path.as_str(), entry);
            }
        }
    }

    // Every path the base revision holds, and every tracked path the working tree holds.
    let mut tracked: Vec<&String> = reading.index.keys().collect();
    let from_base: Vec<&String> = reading.differences.keys().collect();
    tracked.extend(from_base);
    tracked.sort_unstable();
    tracked.dedup();

    for path in tracked {
        if let Some(refusal) = refused_here(request, path) {
            planned.insert(path.clone(), refusal);
            continue;
        }
        let index = reading.index.get(path);
        if index.is_some_and(|entry| entry.mode == "160000")
            || reading
                .differences
                .get(path)
                .is_some_and(|difference| difference.base_mode.as_deref() == Some("160000"))
        {
            planned.insert(path.clone(), unsupported_submodule());
            continue;
        }
        if index.is_some_and(|entry| entry.stage != 0) {
            planned.insert(path.clone(), unresolved_merge());
            continue;
        }
        let Some(difference) = reading.differences.get(path) else {
            // The working tree holds what the base holds. Its content can come from either side;
            // an ordinary capture reads the file, which is one open rather than one process.
            let base = reading.base_of(path);
            planned.insert(
                path.clone(),
                Plan::WorkingTree {
                    class: PathClass::Tracked,
                    change: ChangeKind::Present,
                    base_object_id: base.as_ref().map(|(_, object_id)| object_id.clone()),
                    base_mode: base.as_ref().map(|(mode, _)| mode.clone()),
                    index_mode: index.map(|entry| entry.mode.clone()),
                },
            );
            continue;
        };
        planned.insert(
            path.clone(),
            plan_difference(
                reading,
                path,
                difference,
                index,
                status.get(path.as_str()),
                request,
            ),
        );
    }

    // Everything the status reports that neither the index nor the base holds: untracked and
    // ignored paths.
    for entry in &reading.status {
        if planned.contains_key(&entry.path) {
            continue;
        }
        if let Some(refusal) = refused_here(request, &entry.path) {
            planned.insert(entry.path.clone(), refusal);
            continue;
        }
        let class = class_of(entry.class);
        if class == PathClass::Submodule {
            planned.insert(entry.path.clone(), unsupported_submodule());
            continue;
        }
        if choice_for(request.policy, class) == InclusionChoice::Exclude {
            planned.insert(
                entry.path.clone(),
                Plan::Exclude {
                    reason: ExclusionReason::Policy,
                    detail: format!(
                        "the policy excludes {}, and the base revision does not hold this path",
                        class.as_str()
                    ),
                },
            );
            continue;
        }
        planned.insert(
            entry.path.clone(),
            Plan::WorkingTree {
                class,
                change: entry.change,
                base_object_id: None,
                base_mode: None,
                index_mode: None,
            },
        );
    }
    planned
}

/// Decides what to do about one path whose working tree differs from the base revision.
fn plan_difference(
    reading: &Reading,
    path: &str,
    difference: &BaseDifference,
    index: Option<&IndexEntry>,
    status: Option<&&kr_project::workspace::StatusEntry>,
    request: Scope<'_>,
) -> Plan {
    if difference.status == 'U' || status.is_some_and(|entry| entry.change == ChangeKind::Unmerged)
    {
        return unresolved_merge();
    }
    let base = reading.base_of(path);
    // A path the index lost while the working tree kept a file of that name is not a deletion,
    // and the class it became decides it rather than the dirty-file policy.
    if difference.status == 'D'
        && let Some(entry) = status.filter(|entry| entry.change != ChangeKind::Deleted)
    {
        return plan_recreated(entry, base, request);
    }
    if request.policy.dirty_files == InclusionChoice::Exclude {
        // Excluding a dirty tracked file means the captured tree holds the **base's** version, not
        // that the path is absent. A path the base does not hold at all is simply absent, which is
        // what a staged or unstaged addition is.
        return match base {
            Some((mode, object_id)) => {
                if REGULAR_MODES.contains(&mode.as_str()) {
                    Plan::GitObject {
                        class: PathClass::Tracked,
                        object_id,
                        mode,
                    }
                } else {
                    unsupported_mode(&mode)
                }
            }
            None => Plan::Exclude {
                reason: ExclusionReason::Policy,
                detail: "the policy excludes uncommitted changes, and the base revision does not \
                         hold this path"
                    .to_owned(),
            },
        };
    }
    if difference.status == 'D' {
        let (base_mode, base_object_id) = base.map_or((None, None), |(mode, object_id)| {
            (Some(mode), Some(object_id))
        });
        return Plan::Deleted {
            base_object_id,
            base_mode,
        };
    }
    let (base_mode, base_object_id) = base.map_or((None, None), |(mode, object_id)| {
        (Some(mode), Some(object_id))
    });
    Plan::WorkingTree {
        class: PathClass::DirtyFile,
        change: status.map_or(ChangeKind::Present, |entry| entry.change),
        base_object_id,
        base_mode,
        index_mode: index.map(|entry| entry.mode.clone()),
    }
}

/// Returns the plan for a path the index no longer holds but the working tree still does.
///
/// `D` in a diff against the commit says the **index** lost the path, not that the file is gone:
/// `git rm --cached` leaves the file there, now untracked, and status reports the path twice, once
/// as a staged deletion and once as untracked. Recording a deletion for it would throw away
/// content that is sitting in the working tree, so the class the status gives decides instead, and
/// the base object travels with it so a revert still has somewhere to go back to.
fn plan_recreated(
    entry: &kr_project::workspace::StatusEntry,
    base: Option<(String, String)>,
    request: Scope<'_>,
) -> Plan {
    let class = class_of(entry.class);
    if class == PathClass::Submodule {
        return unsupported_submodule();
    }
    if choice_for(request.policy, class) == InclusionChoice::Exclude {
        // Excluding the change does not take the path away: the base still holds it, and what a
        // capture without uncommitted work holds for it is the commit's own content. Only a path
        // the base never held at all is absent.
        return match base {
            Some((mode, object_id)) => {
                if REGULAR_MODES.contains(&mode.as_str()) {
                    Plan::GitObject {
                        class: PathClass::Tracked,
                        object_id,
                        mode,
                    }
                } else {
                    unsupported_mode(&mode)
                }
            }
            None => Plan::Exclude {
                reason: ExclusionReason::Policy,
                detail: format!(
                    "the policy excludes {}, and the base revision does not hold this path",
                    class.as_str()
                ),
            },
        };
    }
    let (base_mode, base_object_id) = base.map_or((None, None), |(mode, object_id)| {
        (Some(mode), Some(object_id))
    });
    Plan::WorkingTree {
        class,
        change: entry.change,
        base_object_id,
        base_mode,
        index_mode: None,
    }
}

/// Returns what one path's class is called in a captured tree.
fn class_of(class: InclusionClass) -> PathClass {
    match class {
        InclusionClass::UntrackedFile => PathClass::UntrackedFile,
        InclusionClass::GeneratedArtefact => PathClass::GeneratedArtefact,
        InclusionClass::Submodule => PathClass::Submodule,
        _ => PathClass::DirtyFile,
    }
}

/// Returns the policy's decision about one class.
fn choice_for(policy: &InclusionPolicy, class: PathClass) -> InclusionChoice {
    match class {
        PathClass::DirtyFile => policy.dirty_files,
        PathClass::UntrackedFile => policy.untracked_files,
        PathClass::GeneratedArtefact => policy.generated_artefacts,
        _ => InclusionChoice::Exclude,
    }
}

fn unsupported_submodule() -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: "a submodule's own working tree is not captured, because this host never reads \
                 inside one"
            .to_owned(),
    }
}

fn unresolved_merge() -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: "this path has an unresolved merge, so there is no single content a version could \
                 hold for it"
            .to_owned(),
    }
}

fn unsupported_mode(mode: &str) -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: format!(
            "this path is recorded with mode {}, which is not file content: writing its object \
             out as a regular file would make a materialisation a different tree",
            kr_project::git::redact(mode)
        ),
    }
}

/// Stores what the base revision held for one deleted path, so a revert can put it back.
///
/// Only file content is stored. A link's object holds a target and a submodule's is not content at
/// all: writing either out as a regular file would restore the wrong kind of object, so neither
/// carries content and the revert that meets one refuses instead.
fn store_base_content(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    budget: &mut Budget,
    base_object_id: Option<&str>,
    base_mode: Option<&str>,
) -> Result<Option<Digest256>> {
    let (Some(object_id), Some(mode)) = (base_object_id, base_mode) else {
        return Ok(None);
    };
    if !REGULAR_MODES.contains(&mode) {
        return Ok(None);
    }
    budget.read_object()?;
    let bytes = read_object(profile, repository, object_id)?;
    budget.charge(bytes.len() as u64)?;
    store.put(&bytes).map(Some)
}

/// Returns every repository nested in this tree, as paths relative to it.
///
/// **Identity decides, never spelling.** A directory this capture names is another repository's
/// business when the object it is, not the name it has, is one this host found behind a nested
/// `.git`. A nested repository is found by its `.git`: a directory beside its tree, or a file
/// naming where its data really is. That name is resolved by **descending from this working tree's
/// own handle, one component at a time**, refusing a link and refusing anything that leaves the
/// tree, and what is kept is the identity of the directory the descent reached. Every directory
/// the capture names is then compared with those identities, so no spelling of any of them,
/// through a link, through `..`, relative or absolute, reaches one under another name.
///
/// A target this host cannot resolve that way refuses the whole capture. A target that is not
/// there excludes nothing, because there is nothing of it to capture. A repository that also keeps
/// its configuration, references and objects somewhere else says so in a `commondir`, and that
/// place is resolved and compared the same way.
///
/// **And inside each of them**. The content walk stops where a nested repository begins,
/// so a repository nested inside *that* one is named by no reading of this capture, while the
/// directory it keeps its own data in can be anywhere this tree reaches: an ordinary directory to
/// everything else here. So every nested tree is walked for `.git` entries and for nothing else,
/// through the same opener, and each repository found that way is placed by the same descent. That
/// walk spends the same entry budget the administrative scan does, and a set of trees that
/// exhausts it refuses the capture rather than being half searched.
///
/// What a reading does not name and no nested tree holds, this does not find: a repository in a
/// directory of this tree that no path of this capture goes near is one the capture never reaches
/// either.
fn nested_repositories<'a>(
    repository: &OpenedRepository,
    paths: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<String>> {
    let mut directories: BTreeSet<&str> = BTreeSet::new();
    for path in paths {
        let path = path.trim_end_matches('/');
        directories.insert(path);
        let mut at = path;
        while let Some((parent, _)) = at.rsplit_once('/') {
            if !directories.insert(parent) {
                break;
            }
            at = parent;
        }
    }
    let tree = &confined_tree(repository)?;
    let mut budget = MAX_WALK_ENTRIES;
    let mut charge = |directory: &str| -> Result<()> {
        budget = budget
            .checked_sub(1)
            .ok_or_else(|| ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture names more than {MAX_WALK_ENTRIES} directories to ask about, \
                     which is more than one capture reads"
                )
                .into(),
            })?;
        let _ = directory;
        Ok(())
    };

    // What each directory this capture names **is**, so the later passes can compare objects
    // rather than names, and so a repository found behind one spelling is refused under every
    // other.
    //
    // Each one is reached by a descent that keeps every handle it opens, and the directory that
    // descent **ended at** is the one asked whether it holds a `.git`; where one does, that whole
    // chain of handles is what places its data and what the search of its tree goes on from.
    // Nothing resolves the name a second time: two directories renamed under this host between
    // one resolution and the next would have it ask about one place and look inside another, and
    // a tree it never looked in would keep its own repositories.
    let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
    let mut opened: Vec<(&str, AuthorisedDirectory)> = Vec::new();
    let mut repositories: Vec<(&str, Vec<AuthorisedDirectory>, ObjectKind)> = Vec::new();
    let mut links: Vec<&str> = Vec::new();
    for directory in directories {
        if directory.is_empty() {
            continue;
        }
        charge(directory)?;
        let Ok(name) = RelativeName::parse(directory) else {
            // A name this host cannot carry beneath the handle is a directory it cannot ask
            // about, and it will not say a tree is free of another repository it could not look
            // for.
            return Err(unplaceable(directory));
        };
        // What kind of thing is at that name, asked before anything is opened: a file and an
        // absent name have nothing in them to be a repository; a link is not followed to capture
        // anything but is followed to **look**, because what it names can be a repository whose
        // own data is a directory of this tree; and everything else is a directory this
        // host has to be able to look into.
        match tree.probe(&name) {
            Ok(ObjectKind::Directory) => {}
            Ok(ObjectKind::Link) => {
                links.push(directory);
                continue;
            }
            Ok(_) | Err(kr_transfer::Escape::NotFound { .. }) => continue,
            Err(_) => return Err(unplaceable(directory)),
        }
        // It was a directory a moment ago and this host cannot descend to it. It will not say a
        // tree is free of another repository it could not look for.
        let chain = descend_to(tree, directory)?;
        let held = chain.last().ok_or_else(|| unplaceable(directory))?;
        let kind = match held.probe(&administrative) {
            Ok(kind) => Some(kind),
            // No `.git` in it: an ordinary directory of this repository's own content.
            Err(kr_transfer::Escape::NotFound { .. }) => None,
            Err(_) => return Err(unplaceable(directory)),
        };
        opened.push((directory, clone_of(held)?));
        if let Some(kind) = kind {
            repositories.push((directory, chain, kind));
        }
    }

    // What each nested repository **is**: its own tree, the directory its data is in, and the
    // directory it keeps its common data in when it keeps one. **This** repository's own data is
    // in the set too, so a directory that is that object reaches the same refusal whatever it is
    // called here.
    let mut refused: BTreeSet<(u64, u64)> = BTreeSet::new();
    // What this host has looked inside, which is not the same question as what it excludes. The
    // mount is part of the answer: one directory reached on two mounts is two sets of children,
    // and a scan that took the second for the first would not see what is mounted inside it.
    let mut inspected: BTreeSet<((u64, u64), Option<kr_transfer::MountId>)> = BTreeSet::new();
    // **Every administrative directory Git itself reports for this working tree**, each
    // entered by what it is rather than by what it is called. There can be two: the common one,
    // which holds the configuration, the references and the objects, and this worktree's own,
    // which holds its `HEAD` and its index. An ordinary repository keeps them in one place and a
    // split one does not, and both hold administrative data.
    //
    // A reported directory that **is** this working tree refuses the capture: a tree whose
    // administrative data is its own root has no content for a version to hold. So does one this
    // host cannot reach through its own handle for any reason but absence.
    let here = (tree.identity().device, tree.identity().file_id);
    let reported = repository.identity().git_dir;
    if (reported.device, reported.file_id) == here {
        return Err(unplaceable("this working tree"));
    }
    refused.insert((reported.device, reported.file_id));
    // Both administrative directories, reached from the tree's own `.git` rather than taken from
    // a pathname, and required to be the objects Git reported.
    let ((own, own_hops), (common, common_hops)) = administrative_directories(tree, repository)?;
    for (held, hops) in [(&common, common_hops), (&own, own_hops)] {
        // Outside this working tree or inside it, the object is the object, and it goes in
        // unconditionally: what decides anything later is whether a directory this capture opens
        // **is** it, and holding one that nothing reaches costs nothing.
        let identity = identity_of(held);
        if identity == here {
            return Err(unplaceable("this working tree"));
        }
        refused.insert(identity);
        // And **everything under it**. A directory inside a repository's own data can be put in
        // the tree under another name, by a link or by a mount, and then the bytes Git keeps there
        // are reachable as ordinary content under a path that crosses neither. What answers that
        // is the same thing that answers the rest: the object. So every directory beneath this one
        // is asked what it is, and the capture compares what it opens with all of them.
        //
        // Each step of that descent is compared with the directory it is opened beneath, not with
        // the working tree: a repository can keep its data on another filesystem altogether, and
        // an ordinary directory of that data is then on neither the tree's mount nor anything
        // near it. What this refuses is a mount **inside** the administrative tree.
        let mut stack = vec![clone_of(held)?];
        administrative_descendants(
            tree,
            "this repository's own data",
            &mut stack,
            &mut refused,
            &mut inspected,
            &mut budget,
            0,
            hops,
        )?;
    }
    // What this walk has already looked through for the repositories inside it, which is its own
    // question and not the administrative scan's: that scan is looking for links and mounts in a
    // repository's own data, and this one is looking for `.git` entries in a tree whose content
    // nothing reads. Keeping them apart means neither answer stands in for the other.
    let mut searched: BTreeSet<((u64, u64), Option<kr_transfer::MountId>)> = BTreeSet::new();
    for (directory, chain, kind) in &repositories {
        let held = chain.last().ok_or_else(|| unplaceable(directory))?;
        refused.insert(identity_of(held));
        // The handles from this working tree's root down to the directory the data is in, kept so
        // a `commondir` beside that data is resolved from **there** rather than from the tree the
        // repository happens to sit in.
        nested_data(
            tree,
            directory,
            held,
            *kind,
            clone_stack(chain)?,
            &mut refused,
            &mut inspected,
            &mut budget,
            1,
        )?;
        // And now **inside** it. The content walk stops where a nested repository begins,
        // so a repository nested inside *that* one is named by no reading of this capture, while
        // the directory it keeps its own data in can be anywhere this tree reaches: an ordinary
        // directory to everything else here, and one an apply would write into. Discovery
        // therefore goes on where content reading stops, looking for a `.git` entry and for
        // nothing else.
        if searched.insert((identity_of(held), held.mount())) {
            let mut stack = clone_stack(chain)?;
            nested_trees(
                tree,
                directory,
                &mut stack,
                &mut searched,
                &mut refused,
                &mut inspected,
                &mut budget,
                0,
                0,
            )?;
        }
    }
    // And every link this capture's readings named. A link is never followed to capture
    // anything — what a version holds for one is its target as text — but what it names can be a
    // repository's tree, and **that** repository's own data can be an ordinary directory of this
    // tree. Looking is the only way to find it, so discovery looks, and reads nothing of what it
    // finds.
    for link in links {
        search_link(
            tree,
            link,
            &mut searched,
            &mut refused,
            &mut inspected,
            &mut budget,
        )?;
    }

    // And now by identity: every directory this capture names that **is** one of those objects,
    // whatever it is called here.
    let mut found = BTreeSet::new();
    for (directory, held) in &opened {
        if refused.contains(&identity_of(held)) {
            found.insert((*directory).to_owned());
        }
    }
    Ok(found)
}

/// Records, by identity, where one directory holding a `.git` keeps its own data.
///
/// `from` is the chain of handles this working tree reaches that directory through, so what the
/// `.git` names is resolved from **there** rather than from the tree the repository happens to sit
/// in, and a `commondir` beside the data is resolved from the data's own place. Both the directory
/// the descent reached and every directory beneath it are accounted for, which is what makes a
/// second name for any of them excluded wherever it turns up.
///
/// # Errors
///
/// Refuses the capture when the data cannot be reached by descending to it, when what it reached
/// **is** this working tree, or when the data holds something this host cannot account for.
#[allow(clippy::too_many_arguments)]
fn nested_data(
    tree: &AuthorisedDirectory,
    directory: &str,
    held: &AuthorisedDirectory,
    kind: kr_transfer::authority::ObjectKind,
    from: Vec<AuthorisedDirectory>,
    refused: &mut BTreeSet<(u64, u64)>,
    inspected: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    budget: &mut usize,
    hops: usize,
) -> Result<()> {
    if hops > MAX_REFERENCE_HOPS {
        return Err(unplaceable_because(
            directory,
            "following where these repositories say their own data is went further than this \
             host follows",
        ));
    }
    let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
    let stack = match kind {
        // Its data is beside its tree, which is the ordinary nested repository.
        kr_transfer::authority::ObjectKind::Directory => {
            let mut stack = from;
            let data = open_beneath(held, &administrative, directory)?
                .map_err(|_| unplaceable(directory))?;
            stack.push(data);
            stack
        }
        // Its data is wherever its own file says, reached by descending rather than by reading
        // the name as arithmetic.
        _ => match resolve_target(from, directory, held, &administrative, tree)? {
            Some(stack) => stack,
            // Nothing is there, so there is nothing of it to capture either.
            None => return Ok(()),
        },
    };
    let data = stack.last().ok_or_else(|| unplaceable(directory))?;
    // Its data **is** this working tree, which is not something this host captures around. What
    // decides that is the place, not how many steps the descent took: a name that walks out of
    // the tree and back into it arrives at the same directory by a longer road.
    if same_place(data, tree) {
        return Err(unplaceable(directory));
    }
    refused.insert(identity_of(data));
    // Its own mount, before anything inside it is looked at: a nested repository's data is read
    // under the same rule as this repository's, so a mount **inside** it is refused wherever the
    // data itself happens to be.
    let data = clone_of(data)?
        .confined_to_one_mount()
        .map_err(|_| unplaceable(directory))?;
    let common = RelativeName::parse("commondir")?;
    let beside = match data.probe(&common) {
        // It keeps everything in one place.
        Err(kr_transfer::Escape::NotFound { .. }) => None,
        Ok(_) => {
            // A reference of its own, charged and checked like every other: where a repository
            // keeps what its worktrees share is another name, and another place to go and look.
            if hops + 1 > MAX_REFERENCE_HOPS {
                return Err(unplaceable_because(
                    directory,
                    "following where these repositories say their own data is went further than \
                     this host follows",
                ));
            }
            resolve_target(clone_stack(&stack)?, directory, &data, &common, tree)?
        }
        Err(_) => return Err(unplaceable(directory)),
    };
    // The chain that reached the data is what the scan stands on, with the mount-confined handle
    // in place of the one it ended with: a `.git` found inside this data names its own place from
    // **here**, and a name that climbs out and back into the working tree is read as the tree's
    // own because the chain still reaches it.
    let mut here = stack;
    here.pop();
    here.push(data);
    administrative_descendants(
        tree, directory, &mut here, refused, inspected, budget, 0, hops,
    )?;
    if let Some(elsewhere) = beside {
        let last = elsewhere.last().ok_or_else(|| unplaceable(directory))?;
        if same_place(last, tree) {
            return Err(unplaceable(directory));
        }
        refused.insert(identity_of(last));
        let last = clone_of(last)?
            .confined_to_one_mount()
            .map_err(|_| unplaceable(directory))?;
        let mut shared = elsewhere;
        shared.pop();
        shared.push(last);
        administrative_descendants(
            tree,
            directory,
            &mut shared,
            refused,
            inspected,
            budget,
            0,
            hops + 1,
        )?;
    }
    Ok(())
}

/// Walks one nested repository's tree for the repositories inside it.
///
/// Everything else here reads a tree to capture it, and stops where another repository begins.
/// That is what leaves a gap: a repository nested inside a nested one is named by no reading of
/// this capture, and its `.git` file can put its data anywhere this tree reaches — a directory
/// that is then ordinary content to the capture and an ordinary destination to an apply, while it
/// holds that repository's configuration, its remotes and its object database.
///
/// So this walk goes where the content walk stops, and looks for one thing. **Nothing of the tree
/// it walks is read**: each entry is asked what kind of thing it is, each directory is opened
/// through the same opener as every other directory of this capture — which follows no link and
/// refuses another mount — and each one is asked whether it holds a `.git`. One that does is
/// another repository, placed by the same descent as the rest, and the walk goes on inside it,
/// because a repository can hold one just as this tree does.
///
/// Each directory is looked through once, by what it **is** and where it was reached: the same
/// object on another mount holds different children, so it is a second place to look rather than a
/// repeat. Every entry is charged against the same budget the administrative scan spends, and a
/// set of trees that exhausts it refuses the capture instead of being half searched, because a
/// tree this host stopped searching is one it cannot say is free of a repository.
///
/// # Errors
///
/// Refuses the capture when a tree cannot be read or opened into, when it is deeper than this host
/// reads, or when these trees hold more entries than it looks through.
#[allow(clippy::too_many_arguments)]
fn nested_trees(
    tree: &AuthorisedDirectory,
    directory: &str,
    stack: &mut Vec<AuthorisedDirectory>,
    searched: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    refused: &mut BTreeSet<(u64, u64)>,
    inspected: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    budget: &mut usize,
    depth: usize,
    hops: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(unsearchable(
            directory,
            format!("it holds a tree more than {MAX_WALK_DEPTH} levels deep"),
        ));
    }
    let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
    let entries = {
        let here = stack.last().ok_or_else(|| unplaceable(directory))?;
        here.handle().entries().map_err(|_| {
            unsearchable(
                directory,
                "this host could not read what is in it".to_owned(),
            )
        })?
    };
    for entry in entries {
        let entry = entry.map_err(|_| {
            unsearchable(
                directory,
                "this host could not read what is in it".to_owned(),
            )
        })?;
        *budget = budget.checked_sub(1).ok_or_else(|| {
            unsearchable(
                directory,
                format!(
                    "the trees this host walks to find the repositories in them hold more than \
                     {MAX_WALK_ENTRIES} entries"
                ),
            )
        })?;
        let kind = entry.file_type().map_err(|_| {
            unsearchable(
                directory,
                "this host could not read what is in it".to_owned(),
            )
        })?;
        // A file holds no repository. A **link** names one as easily as a directory does, and
        // what it names is followed for this one question and never for content.
        if !kind.is_dir() && !kind.is_symlink() {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            return Err(unsearchable(
                directory,
                "it holds a name this host cannot read as text".to_owned(),
            ));
        };
        if name == grant::ADMINISTRATIVE_DIRECTORY {
            // Where the repository whose tree this is keeps its own data, which was placed when
            // that repository was found and is looked through by the scan that reads such data —
            // and that scan places every `.git` it meets itself, so nothing below it is skipped.
            //
            // The name matches **exactly**, because that is the entry Git reads and the entry
            // this walk asked about. The rule that covers every case of it decides what is left
            // out of a version, which is a different question: a directory called `.GIT` on a
            // filesystem that keeps the two apart is an ordinary directory nothing has accounted
            // for, and one a repository can sit in. Where a filesystem folds case the two names
            // are one entry, and looking through it a second time costs a walk and finds nothing.
            continue;
        }
        let below = format!("{directory}/{name}");
        if kind.is_symlink() {
            let target = {
                let here = stack.last().ok_or_else(|| unplaceable(directory))?;
                match here.handle().read_link_contents(&name) {
                    Ok(target) => target,
                    // Gone, or not a link any more: nothing here to follow.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        return Err(unsearchable(
                            &below,
                            "this host could not read what the link names".to_owned(),
                        ));
                    }
                }
            };
            let Some(target) = target.to_str() else {
                return Err(unsearchable(
                    &below,
                    "it names a target this host cannot read as text".to_owned(),
                ));
            };
            let hops = hops + 1;
            if hops > MAX_REFERENCE_HOPS {
                return Err(unsearchable(
                    &below,
                    format!(
                        "following where these repositories say their own data is went more than \
                         {MAX_REFERENCE_HOPS} references deep"
                    ),
                ));
            }
            let reached = resolve_name(
                clone_stack(stack.as_slice())?,
                &below,
                target,
                tree,
                Elsewhere::Nothing,
            )?;
            if let Some(reached) = reached {
                search_reached(
                    tree, &below, reached, searched, refused, inspected, budget, hops,
                )?;
            }
            continue;
        }
        let name = RelativeName::parse(&name)?;
        let held = {
            let here = stack.last().ok_or_else(|| unplaceable(directory))?;
            match open_beneath(here, &name, &below)? {
                Ok(held) => held,
                // Gone between the listing and the open, so there is no tree here to look in.
                Err(kr_transfer::Escape::NotFound { .. }) => continue,
                // It was a directory a moment ago and this host cannot open it. It will not say a
                // tree is free of a repository it could not look for.
                Err(_) => return Err(unplaceable(&below)),
            }
        };
        if !searched.insert((identity_of(&held), held.mount())) {
            continue;
        }
        stack.push(held);
        {
            let held = stack.last().ok_or_else(|| unplaceable(&below))?;
            match held.probe(&administrative) {
                // Another repository, whose own data is placed the same way every other one's is.
                Ok(kind) => {
                    refused.insert(identity_of(held));
                    let from = clone_stack(stack.as_slice())?;
                    nested_data(
                        tree,
                        &below,
                        held,
                        kind,
                        from,
                        refused,
                        inspected,
                        budget,
                        hops + 1,
                    )?;
                }
                // An ordinary directory of the tree this walk is looking through.
                Err(kr_transfer::Escape::NotFound { .. }) => {}
                Err(_) => return Err(unplaceable(&below)),
            }
        }
        nested_trees(
            tree,
            &below,
            stack,
            searched,
            refused,
            inspected,
            budget,
            depth + 1,
            hops,
        )?;
        stack.pop();
    }
    Ok(())
}

/// Follows one link of the working tree, for discovery and for nothing else.
///
/// A link is not content this host reads through and never will be: what a version holds for one
/// is its target as text. What a link **does** do is name a directory, and that directory can be a
/// repository's tree whose own data is an ordinary directory of this tree — bytes a capture would
/// take and an apply would write over, with no `.git` anywhere inside this tree naming them. So
/// discovery follows it, and the only thing it does at the other end is look for `.git` entries.
///
/// The target is resolved the way every other name here is: from the handles that reach the
/// directory the link is in, one component at a time, refusing a link on the way. A target that
/// names nothing, or something that is not a directory, is nothing to look through.
///
/// # Errors
///
/// Refuses the capture when the link cannot be read, when its target cannot be resolved this way,
/// or when what it reaches cannot be looked through.
fn search_link(
    tree: &AuthorisedDirectory,
    link: &str,
    searched: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    refused: &mut BTreeSet<(u64, u64)>,
    inspected: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    budget: &mut usize,
) -> Result<()> {
    let (above, name) = match link.rsplit_once('/') {
        Some((above, name)) => (above, name),
        None => ("", link),
    };
    let stack = if above.is_empty() {
        vec![clone_of(tree)?]
    } else {
        descend_to(tree, above)?
    };
    let here = stack.last().ok_or_else(|| unplaceable(link))?;
    let step = RelativeName::parse(name)?;
    // The link's own target, exactly as it was written, read through the handle the link is in.
    // A name given in full is a target like any other here: what decides where it leads is the
    // descent that follows, not this read.
    let target = match here.handle().read_link_contents(step.as_str()) {
        Ok(target) => target,
        // Gone, or not a link any more: there is nothing here to follow.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(unsearchable(
                link,
                "this host could not read what the link names".to_owned(),
            ));
        }
    };
    let Some(target) = target.to_str() else {
        return Err(unsearchable(
            link,
            "it names a target this host cannot read as text".to_owned(),
        ));
    };
    let hops = 1;
    if hops > MAX_REFERENCE_HOPS {
        return Err(unsearchable(
            link,
            format!(
                "following where these repositories say their own data is went more than \
                 {MAX_REFERENCE_HOPS} references deep"
            ),
        ));
    }
    let Some(reached) = resolve_name(clone_stack(&stack)?, link, target, tree, Elsewhere::Nothing)?
    else {
        return Ok(());
    };
    search_reached(
        tree, link, reached, searched, refused, inspected, budget, hops,
    )
}

/// Looks through one directory a link named, and through the repositories inside it.
///
/// It is asked the same question every directory of a nested tree is asked — does it hold a
/// `.git` — and then looked through the same way, once per object and mount, against the same
/// budget.
#[allow(clippy::too_many_arguments)]
fn search_reached(
    tree: &AuthorisedDirectory,
    directory: &str,
    reached: Vec<AuthorisedDirectory>,
    searched: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    refused: &mut BTreeSet<(u64, u64)>,
    inspected: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    budget: &mut usize,
    hops: usize,
) -> Result<()> {
    if hops > MAX_REFERENCE_HOPS {
        return Err(unsearchable(
            directory,
            format!(
                "following where these repositories say their own data is went more than \
                 {MAX_REFERENCE_HOPS} references deep"
            ),
        ));
    }
    let mut stack = reached;
    // Which mount the target is on, asked of the handle the descent ended at, before it is
    // recorded or looked into. Outside this tree there is no mount to hold the walk to, so a
    // handle that arrives here carries no rule and would answer "no mount" for every one of
    // them: two views of one directory — the same object on two mounts, each with different
    // children — would then be one entry in the record of what has been looked through, and the
    // second would be passed over. Confining it to **its own** mount makes the record name the
    // place rather than the object, and makes every directory under it compared with that mount
    // as the tree's own are.
    let held = stack.last().ok_or_else(|| unplaceable(directory))?;
    let held = clone_of(held)?
        .confined_to_one_mount()
        .map_err(|_| unplaceable(directory))?;
    stack.pop();
    stack.push(held);
    let held = stack.last().ok_or_else(|| unplaceable(directory))?;
    if !searched.insert((identity_of(held), held.mount())) {
        return Ok(());
    }
    let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
    match held.probe(&administrative) {
        // The link names a repository's tree. Where that repository keeps its own data is placed
        // by the same descent as every other one's, so a directory of **this** tree that holds it
        // is excluded by what it is.
        Ok(kind) => {
            refused.insert(identity_of(held));
            let from = clone_stack(stack.as_slice())?;
            nested_data(
                tree,
                directory,
                held,
                kind,
                from,
                refused,
                inspected,
                budget,
                hops + 1,
            )?;
        }
        // An ordinary directory, which can still hold a repository deeper in.
        Err(kr_transfer::Escape::NotFound { .. }) => {}
        Err(_) => return Err(unplaceable(directory)),
    }
    nested_trees(
        tree, directory, &mut stack, searched, refused, inspected, budget, 0, hops,
    )
}

/// The refusal for a tree this host could not look through for the repositories inside it.
fn unsearchable(directory: &str, why: String) -> ChangeSetError {
    ChangeSetError::Unsupported {
        detail: format!(
            "this host does not capture a tree holding a repository whose own tree it could not \
             look through for the repositories inside that one: {why}, at {}",
            kr_project::git::redact(directory)
        )
        .into(),
    }
}

/// Returns this repository's two administrative directories, reached from the working tree's own
/// `.git` and then required to be the objects Git reported.
///
/// Nothing here starts from a pathname Git handed over. A path is a name, and a name can be made
/// to reach a different object between one open and the next: a directory covered while this host
/// opened it would be the object a scan accounted for, while the data it covered went unexamined
/// and its files were captured as ordinary content. So this host walks to both directories itself,
/// from the one entry every working tree has, and each step is an open of one component against
/// the handle above it with no link followed:
///
/// * `.git` is a directory — that is this worktree's own administrative directory;
/// * `.git` is a file naming a place **inside** this tree — descended from the tree's own handle,
///   which compares every step with the tree's mount, as a content read does;
/// * `.git` is a file naming a place outside it — walked from the root of that name, component by
///   component, refusing a link at each. Outside the tree there is no mount to compare with, so
///   what stands in its place is the identity: it has to be the object Git reported.
///
/// Where the shared directory is is then read from the private one's own `commondir`, resolved the
/// same way, and it too has to be the object Git reported — which for the shared directory is the
/// object this repository's recorded identity names, so an open that reached anything else refused
/// before this capture began.
///
/// # Errors
///
/// Refuses the capture when either directory cannot be reached this way, when a step is a link or
/// crosses a mount inside the tree, or when what was reached is not what Git reported.
fn administrative_directories(
    tree: &AuthorisedDirectory,
    repository: &OpenedRepository,
) -> Result<((AuthorisedDirectory, usize), (AuthorisedDirectory, usize))> {
    let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
    let stack = match tree.probe(&administrative) {
        Ok(kr_transfer::authority::ObjectKind::Directory) => {
            let mut stack = vec![clone_of(tree)?];
            stack.push(
                open_beneath(tree, &administrative, ".git")?
                    .map_err(|_| unplaceable("this repository's own data"))?,
            );
            stack
        }
        Ok(kr_transfer::authority::ObjectKind::File) => {
            resolve_target(vec![clone_of(tree)?], ".git", tree, &administrative, tree)?
                .ok_or_else(|| unplaceable("this repository's own data"))?
        }
        // A tree whose own data this host cannot find from the tree is one it does not read
        // around: it would be excluding what it was handed rather than what is there.
        _ => return Err(unplaceable("this repository's own data")),
    };
    let own = stack
        .last()
        .ok_or_else(|| unplaceable("this repository's own data"))?;
    if identity_of(own) != identity_of(repository.own_dir()) {
        return Err(unplaceable("this repository's own data"));
    }
    let own_hops = 1;
    // And what every worktree of this repository shares, named by the private directory itself.
    let commondir = RelativeName::parse("commondir")?;
    let (common, common_hops) = match own.probe(&commondir) {
        // It keeps everything in the one place.
        Err(kr_transfer::Escape::NotFound { .. }) => (clone_of(own)?, own_hops),
        Ok(_) => {
            let reached = resolve_target(clone_stack(&stack)?, "commondir", own, &commondir, tree)?
                .ok_or_else(|| unplaceable("this repository's own data"))?;
            let last = reached
                .last()
                .ok_or_else(|| unplaceable("this repository's own data"))?;
            (clone_of(last)?, own_hops + 1)
        }
        Err(_) => return Err(unplaceable("this repository's own data")),
    };
    if identity_of(&common) != identity_of(repository.git_dir()) {
        return Err(unplaceable("this repository's own data"));
    }
    // Each one's own mount, so a mount **inside** either of them is refused when it is walked.
    let own = clone_of(own)?
        .confined_to_one_mount()
        .map_err(|_| unplaceable("this repository's own data"))?;
    let common = common
        .confined_to_one_mount()
        .map_err(|_| unplaceable("this repository's own data"))?;
    Ok(((own, own_hops), (common, common_hops)))
}

/// Adds the identity of every directory beneath one administrative directory, places every
/// repository whose tree it finds there, and refuses a repository whose own data holds a link, a
/// mount or anything that is not a plain file or a plain directory.
///
/// The one way a repository's own data can be reached as ordinary content, once the content side
/// refuses links and other mounts and the identity set holds the same objects, is a link or a
/// mount **inside** the administrative tree, pointing out at a directory of the tree. Then the
/// captured path crosses nothing. So an administrative tree that holds one is a repository this
/// host does not read around at all, and it says so.
///
/// A `.git` **beneath** administrative data is another repository's tree kept there, and where
/// that repository keeps its own data is a name that can reach an ordinary directory of the
/// working tree. Excluding the administrative tree this one sits in says nothing about that
/// directory, so the reference is resolved here exactly as discovery resolves one in the working
/// tree, from the handles this scan is standing in. Nothing below administrative data is
/// skipped.
///
/// Each directory is opened through the same authority as the rest, so each is compared with the
/// directory it is opened beneath rather than with the working tree: a repository whose data sits
/// on another filesystem is an ordinary repository, and what this refuses is a mount **inside**
/// that data.
///
/// Every entry is charged against the budget, not only the directories, and the descent is bounded
/// in depth as the rest of this capture's reading is. Exceeding either refuses rather than skips.
#[allow(clippy::too_many_arguments)]
fn administrative_descendants(
    tree: &AuthorisedDirectory,
    where_it_is: &str,
    stack: &mut Vec<AuthorisedDirectory>,
    into: &mut BTreeSet<(u64, u64)>,
    inspected: &mut BTreeSet<((u64, u64), Option<kr_transfer::MountId>)>,
    budget: &mut usize,
    depth: usize,
    hops: usize,
) -> Result<()> {
    // Looked inside once, by what it **is** and the mount it was reached on, whether it was
    // reached as a child of another administrative directory or named as one by a `.git` line
    // somewhere. A repository whose data names itself would otherwise start this scan again at
    // every turn, and nothing about the depth of one walk would ever end it.
    let directory = stack
        .last()
        .ok_or_else(|| unreadable_data("this host could not read what is in it".to_owned()))?;
    let key = (identity_of(directory), directory.mount());
    if inspected.contains(&key) {
        return Ok(());
    }
    if depth >= MAX_WALK_DEPTH {
        return Err(unreadable_data(format!(
            "this repository's own data is more than {MAX_WALK_DEPTH} levels deep, which is \
             deeper than this host reads to know what is in it"
        )));
    }
    inspected.insert(key);
    // Whether the directory this scan is standing in is **another repository's tree**, kept
    // inside this one's data. Where that repository keeps its own data is a name this scan would
    // otherwise never read, and it can reach an ordinary directory of the working tree: excluding
    // the data this `.git` sits inside says nothing about that directory, whose bytes a capture
    // would take and an apply would write over. So it is placed here, by the same descent that
    // places one found in the working tree.
    //
    // Asked of the directory rather than read off the listing, because the entry Git reads and
    // the name a listing returns are not the same string: a filesystem that folds case reaches
    // this entry through `.GIT` as well, and comparing the name a listing gave would miss it.
    {
        let holder = stack
            .last()
            .ok_or_else(|| unreadable_data("this host could not read what is in it".to_owned()))?;
        let administrative = RelativeName::parse(grant::ADMINISTRATIVE_DIRECTORY)?;
        match holder.probe(&administrative) {
            Ok(kind) => {
                let kind = match kind {
                    ObjectKind::Directory => ObjectKind::Directory,
                    _ => ObjectKind::File,
                };
                into.insert(identity_of(holder));
                let from = clone_stack(stack.as_slice())?;
                nested_data(
                    tree,
                    where_it_is,
                    holder,
                    kind,
                    from,
                    into,
                    inspected,
                    budget,
                    hops + 1,
                )?;
            }
            // Ordinary data of the repository this scan belongs to.
            Err(kr_transfer::Escape::NotFound { .. }) => {}
            Err(_) => {
                return Err(unreadable_data(
                    "this host could not say whether it holds another repository's tree".to_owned(),
                ));
            }
        }
    }
    let entries = {
        let directory = stack
            .last()
            .ok_or_else(|| unreadable_data("this host could not read what is in it".to_owned()))?;
        directory
            .handle()
            .entries()
            .map_err(|_| unreadable_data("this host could not read what is in it".to_owned()))?
    };
    for entry in entries {
        let entry = entry
            .map_err(|_| unreadable_data("this host could not read what is in it".to_owned()))?;
        *budget = budget.checked_sub(1).ok_or_else(|| {
            unreadable_data(format!(
                "this repository's own data holds more than {MAX_WALK_ENTRIES} entries, which is \
                 more than this host reads to know what they are"
            ))
        })?;
        let kind = entry
            .file_type()
            .map_err(|_| unreadable_data("this host could not read what is in it".to_owned()))?;
        let Ok(name) = entry.file_name().into_string() else {
            return Err(unreadable_data(
                "it holds a name this host cannot read as text".to_owned(),
            ));
        };
        if kind.is_symlink() {
            return Err(unreadable_data(format!(
                "it holds a link at {}, which could name a directory of this tree and make that \
                 directory's content this repository's own data under another path",
                kr_project::git::redact(&name)
            )));
        }
        if kind.is_file() {
            // A plain file, opened rather than taken on trust. A file mounted here is a second
            // name for a file of the tree, and then what Git writes through this name is that
            // file's content: the bytes under an ordinary path of the tree are this repository's
            // own data, and the path crosses nothing to get there. The open compares the mount
            // the way every other open this capture makes does.
            //
            // What it does not see is a second *hard link*. Git gives one file several names as a
            // matter of course — a local clone and a shared object store are built out of that —
            // so the number of names a file has says nothing here, and a link from this data to a
            // file of the tree is recorded as a limit rather than guessed at.
            let name = RelativeName::parse(&name)?;
            let directory = stack.last().ok_or_else(|| {
                unreadable_data("this host could not read what is in it".to_owned())
            })?;
            match directory.open_read(&name, ObjectPolicy::ReadableFile) {
                Ok(_) => continue,
                Err(kr_transfer::Escape::CrossedMount { .. }) => {
                    return Err(unreadable_data(format!(
                        "it holds a mount at {}, which makes a file of this tree part of this \
                         repository's own data",
                        kr_project::git::redact(name.as_str())
                    )));
                }
                // Gone between the listing and the open, which is nothing of this repository's
                // data to account for.
                Err(kr_transfer::Escape::NotFound { .. }) => continue,
                Err(_) => {
                    return Err(unreadable_data(format!(
                        "this host could not look at {}, so it cannot say what it is",
                        kr_project::git::redact(name.as_str())
                    )));
                }
            }
        }
        if !kind.is_dir() {
            return Err(unreadable_data(format!(
                "it holds {}, which is neither a plain file nor a plain directory",
                kr_project::git::redact(&name)
            )));
        }
        let name = RelativeName::parse(&name)?;
        // Through the same opener as everything else, which compares each directory with the one
        // it is opened beneath. Inside a repository's own data that comparison is what finds a
        // mount, and a mount here puts a directory of this tree inside the data.
        let directory = stack
            .last()
            .ok_or_else(|| unreadable_data("this host could not read what is in it".to_owned()))?;
        let held = match directory.subdirectory(&name) {
            Ok(held) => held,
            Err(kr_transfer::Escape::CrossedMount { .. }) => {
                return Err(unreadable_data(format!(
                    "it holds a mount at {}, which puts a directory of this tree inside this \
                     repository's own data",
                    kr_project::git::redact(name.as_str())
                )));
            }
            Err(_) => {
                return Err(unreadable_data(
                    "this host could not read what is in it".to_owned(),
                ));
            }
        };
        // Two sets, because "already excluded" is not "already looked at": a directory can be in
        // the exclusion set because it is a nested repository's tree and still hold a link this
        // host has not seen. What stops the descent running away is having **inspected** it.
        into.insert(identity_of(&held));
        // Excluded by what it **is**; looked inside by what it is *and where it was reached*. The
        // same directory on another mount holds different children, and one of them can be a mount
        // this host has not seen.
        let below = format!("{where_it_is}/{}", name.as_str());
        stack.push(held);
        administrative_descendants(
            tree,
            &below,
            stack,
            into,
            inspected,
            budget,
            depth + 1,
            hops,
        )?;
        stack.pop();
    }
    Ok(())
}

/// The refusal for a repository whose own data this host will not read around.
fn unreadable_data(why: String) -> ChangeSetError {
    ChangeSetError::Unsupported {
        detail: format!(
            "this host does not capture a tree whose repository's own data it cannot account for: \
             {why}"
        )
        .into(),
    }
}

/// Opens one directory beneath another, the one way this capture opens a directory at all.
///
/// Three things are refused here rather than at each caller: a link, which the authority refuses
/// for every open it makes; a directory **on another mount** than the directory it was opened
/// beneath, which the authority compares because a mount is the other way a path reaches content
/// the path does not name; and everything else the name could break. A mount refuses the whole
/// capture: what is under such a directory is not what the tree's own path says, and this host
/// does not guess which of the two it was asked for.
fn open_beneath(
    parent: &AuthorisedDirectory,
    name: &RelativeName,
    what: &str,
) -> Result<std::result::Result<AuthorisedDirectory, kr_transfer::Escape>> {
    match parent.subdirectory(name) {
        Ok(held) => Ok(Ok(held)),
        Err(kr_transfer::Escape::CrossedMount { .. }) => Err(ChangeSetError::Unsupported {
            detail: format!(
                "{} is on a different mount from the directory it is in, and a tree that holds \
                 one is not one this host reads: what is under it is not what the tree's own path \
                 says",
                kr_project::git::redact(what)
            )
            .into(),
        }),
        Err(escape) => Ok(Err(escape)),
    }
}

/// Returns the object one open directory is.
fn identity_of(directory: &AuthorisedDirectory) -> (u64, u64) {
    let identity = directory.identity();
    (identity.device, identity.file_id)
}

/// Returns whether two open handles are one place.
///
/// The object **and** the mount, because two handles can be on one directory and still lead to
/// different children: a directory mounted over one of them and not over the other holds one thing
/// under a name and another thing under the same name. Anything that treats the two as one place
/// would read one and answer for the other.
fn same_place(one: &AuthorisedDirectory, other: &AuthorisedDirectory) -> bool {
    identity_of(one) == identity_of(other) && one.mount() == other.mount()
}

/// Returns the handles from this working tree's root down to one directory it names.
///
/// Every step is taken with the handle above it, so nothing is resolved twice and nothing follows
/// a link. The components come from this capture's own readings rather than from any file.
fn descend_to(tree: &AuthorisedDirectory, directory: &str) -> Result<Vec<AuthorisedDirectory>> {
    let mut stack = vec![clone_of(tree)?];
    for component in directory.split('/') {
        let step = RelativeName::parse(component)?;
        let here = stack.last().ok_or_else(|| unplaceable(directory))?;
        let next = open_beneath(here, &step, directory)?.map_err(|_| unplaceable(directory))?;
        stack.push(next);
    }
    Ok(stack)
}

/// Returns every path one reading names, in the tree's own spelling.
fn reading_paths(reading: &Reading) -> impl Iterator<Item = &str> {
    reading
        .index
        .keys()
        .chain(reading.differences.keys())
        .chain(reading.staged.keys())
        .map(String::as_str)
        .chain(reading.status.iter().map(|entry| entry.path.as_str()))
}

/// Returns which of these paths **this** repository holds its own administrative data at, or a
/// repository nested in this tree does.
///
/// A path is content or administrative data because of the tree it is in, not because of the
/// version it came from: a directory that is ordinary content in the workspace a version was
/// captured from can be a repository's own data in the workspace it is applied to. A caller that
/// writes into a tree asks this about the tree it is writing to.
///
/// # Errors
///
/// Returns whatever this host's own accounting of the tree refuses.
pub fn administrative_here(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    paths: &[String],
) -> Result<Vec<String>> {
    // The whole tree, not only the paths the caller named. A repository nested here can keep its
    // own data under a name **no requested path goes near**: the directory that holds the data is
    // one the request never mentions, and the repository that owns it is found by looking at the
    // tree rather than at the request. So discovery sees everything this repository's own reading
    // sees, with the requested paths added to it.
    let reading = Reading::take(profile, repository, &FileGrant::default(), None)?;
    let nested = nested_repositories(
        repository,
        reading_paths(&reading).chain(paths.iter().map(String::as_str)),
    )?;
    Ok(paths
        .iter()
        .filter(|path| {
            crate::grant::is_administrative(path)
                || nested.iter().any(|prefix| grant::under(path, prefix))
        })
        .cloned()
        .collect())
}

/// Returns what one of Git's own files names, exactly as Git wrote it.
///
/// One line, with the line ending taken off and nothing else touched: trimming by what a language
/// calls whitespace would change the name, because a filename may hold characters a trim would
/// take away.
fn read_target(
    directory: &str,
    holder: &AuthorisedDirectory,
    file: &RelativeName,
) -> Result<String> {
    use std::io::Read as _;

    let mut open = holder
        .open_read(file, ObjectPolicy::ReadableFile)
        .map_err(|_| unplaceable(directory))?;
    if open.byte_len() > MAX_GIT_FILE_BYTES {
        return Err(unplaceable(directory));
    }
    let mut text = String::new();
    open.handle_mut()
        .take(MAX_GIT_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|_| unplaceable(directory))?;
    let line = text
        .strip_suffix('\n')
        .unwrap_or(&text)
        .strip_suffix('\r')
        .unwrap_or_else(|| text.strip_suffix('\n').unwrap_or(&text));
    let target = match line.strip_prefix("gitdir:") {
        Some(rest) => rest.strip_prefix(' ').unwrap_or(rest),
        None => line,
    };
    if target.is_empty() {
        return Err(unplaceable(directory));
    }
    Ok(target.to_owned())
}

/// Returns a second set of handles over the same directories.
fn clone_stack(stack: &[AuthorisedDirectory]) -> Result<Vec<AuthorisedDirectory>> {
    stack.iter().map(clone_of).collect()
}

/// Resolves what one `gitdir:` or `commondir` file names, by descending to it.
///
/// Nothing here is arithmetic on a path. The descent starts from the handles that reach the
/// directory the file is in, and takes the file's own components one at a time: `.` is nothing,
/// `..` steps back to the directory the descent actually came from, and every other component is
/// **asked about first** and has to be a directory. A link anywhere along the way ends it, because
/// a `..` after a link means something this descent cannot reproduce, and so does a `..` inside a
/// name given in full, which is arithmetic on a name this walk did not take. Each of those refuses
/// the whole capture.
///
/// A name that climbs above where the walk started is followed the same way: each `..` gives back
/// a handle the walk already holds, and at the bottom the directory the last handle is **in** is
/// opened from that handle rather than resolved from outside. A name given in full climbs to the
/// root of its filesystem that way and comes back down its own components. Both climbs are
/// bounded, because the directory a handle is in is not something this host can hold still.
///
/// What comes back is the whole descent, so a file **beside** what it found is resolved from there
/// rather than from where this one started. A descent that arrives at this working tree continues
/// through the tree's own handle from that step on, so a name that walks out of the tree and back
/// into it is still read as the tree's own; outside the tree there is no mount to compare with and
/// none is claimed.
fn resolve_target(
    from: Vec<AuthorisedDirectory>,
    directory: &str,
    holder: &AuthorisedDirectory,
    file: &RelativeName,
    tree: &AuthorisedDirectory,
) -> Result<Option<Vec<AuthorisedDirectory>>> {
    let target = read_target(directory, holder, file)?;
    resolve_name(from, directory, &target, tree, Elsewhere::Refuse)
}

/// What a resolution does when a name reaches something that is not a directory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Elsewhere {
    /// Refuse the capture. Where a repository keeps its own data is a directory or it is a layout
    /// this host does not read around.
    Refuse,
    /// There is no tree there to look through, and that is an answer rather than a fault. A link
    /// of the working tree names a file as often as a directory.
    Nothing,
}

/// Resolves one name from the handles a walk is standing in, as [`resolve_target`] describes.
fn resolve_name(
    from: Vec<AuthorisedDirectory>,
    directory: &str,
    target: &str,
    tree: &AuthorisedDirectory,
    elsewhere: Elsewhere,
) -> Result<Option<Vec<AuthorisedDirectory>>> {
    let path = std::path::Path::new(target);
    let mut stack = from;
    let steps: Vec<String> = if path.is_absolute() {
        // A name given in full is still walked from a handle this host holds: it climbs to the
        // root of the filesystem through the directories the walk is standing in, and comes back
        // down the name from there. Nothing is opened from outside, so the one way into this tree
        // is the same descent every other name takes.
        let base = stack.first().ok_or_else(|| unplaceable(directory))?;
        // Outside this tree there is no mount to hold a walk to, so the climb is made with plain
        // handles; what the mount is used for here is knowing when the climb has ended.
        let mut root = plain_clone(base)?;
        let mut below = mount_reading(&root)?;
        let mut climbed = 0;
        let mut stood_on: BTreeSet<((u64, u64), Option<kr_transfer::MountId>)> = BTreeSet::new();
        stood_on.insert((identity_of(&root), below));
        loop {
            let above = root.parent().map_err(|_| {
                unplaceable_because(directory, "this host could not open the directory above it")
            })?;
            let above_mount = mount_reading(&above)?;
            // The root of a filesystem is the one directory that **is** what it is in, on the
            // mount it is on. The object alone would not do: a directory mounted over itself has
            // the identity of what it came from, and a climb that stopped there would come back
            // down a name that means something else.
            if identity_of(&above) == identity_of(&root) && above_mount == below {
                break;
            }
            // Bounded twice, because the directory a handle is in is not something this host can
            // hold still: an account that can rename two directories above this one can hand the
            // climb a new parent for as long as it likes. A climb that goes further than any
            // ancestry this host is asked about, or that arrives where it has already stood, is
            // one it refuses rather than one it keeps taking. The count is of the levels this
            // climb actually goes up, so an ancestry of exactly that many levels is reached: the
            // open that confirms the root is not one of them.
            climbed += 1;
            if climbed > MAX_CLIMB_HOPS {
                return Err(unplaceable_because(
                    directory,
                    &format!(
                        "it is more than {MAX_CLIMB_HOPS} levels below the root of its filesystem"
                    ),
                ));
            }
            // Asked after the root, so an ordinary root — which is what it is in — ends the climb
            // rather than being taken for a repeat.
            if !stood_on.insert((identity_of(&above), above_mount)) {
                return Err(unplaceable_because(
                    directory,
                    "the climb to the root of its filesystem arrived where it had already stood, \
                     which is what a directory renamed under it looks like",
                ));
            }
            root = above;
            below = above_mount;
        }
        stack = vec![root];
        let mut steps = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::Prefix(_) | std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let Some(name) = name.to_str() else {
                        return Err(unplaceable(directory));
                    };
                    steps.push(name.to_owned());
                }
                std::path::Component::CurDir | std::path::Component::ParentDir => {
                    return Err(unplaceable(directory));
                }
            }
        }
        steps
    } else {
        target.split('/').map(str::to_owned).collect()
    };
    for component in steps {
        match component.as_str() {
            "" | "." => continue,
            ".." => {
                if stack.len() > 1 {
                    stack.pop();
                } else {
                    // Above where this walk started. The directory that holds it is opened from
                    // the handle rather than by name, and the walk goes on **outside** this tree:
                    // there is nothing to compare a mount with out here, and a directory that is
                    // the tree again puts the tree's own rule back on — whether the walk arrived
                    // at it by opening a component or by climbing into it, because a climb that
                    // stepped over the tree and went on unconfined would read the tree without
                    // its own rule.
                    let here = stack.last().ok_or_else(|| unplaceable(directory))?;
                    let above = here.parent().map_err(|_| unplaceable(directory))?;
                    stack.clear();
                    if identity_of(&above) == identity_of(tree) {
                        if mount_reading(&above)? != tree.mount() {
                            return Err(unplaceable_because(
                                directory,
                                "the climb arrives at this working tree on another mount, which \
                                 holds different children under the same object",
                            ));
                        }
                        stack.push(clone_of(tree)?);
                    } else {
                        stack.push(above);
                    }
                }
            }
            _ => {
                let step = RelativeName::parse(&component)?;
                let here = stack.last().ok_or_else(|| unplaceable(directory))?;
                match here.probe(&step) {
                    // A directory, asked about before it is entered.
                    Ok(kr_transfer::authority::ObjectKind::Directory) => {}
                    // Nothing there: nothing of it to capture.
                    Err(kr_transfer::Escape::NotFound { .. }) => return Ok(None),
                    // Something that is not a directory. Where a repository keeps its own data
                    // has to be one, and a name of the working tree may reach anything at all.
                    Ok(
                        kr_transfer::authority::ObjectKind::File
                        | kr_transfer::authority::ObjectKind::Other,
                    ) if elsewhere == Elsewhere::Nothing => {
                        return Ok(None);
                    }
                    // A link, which this descent will not follow whatever it was asked to
                    // resolve, or something this host could not ask about.
                    _ => return Err(unplaceable(directory)),
                }
                let next =
                    open_beneath(here, &step, directory)?.map_err(|_| unplaceable(directory))?;
                // A descent that arrives at this working tree continues as one of the tree's own,
                // whatever it walked through to get here: from this step on every component is
                // compared with the tree's mount, as a content read is.
                //
                // The object **and** the mount, because two handles can be on one directory and
                // still lead to different children: a directory mounted over one of them and not
                // over the other is under one name and not under the other. Taking the tree's own
                // handle in place of a step that is the same object somewhere else would read the
                // tree's children for a name that means the other's, so this host refuses rather
                // than choosing between them.
                if identity_of(&next) == identity_of(tree) {
                    if mount_reading(&next)? != tree.mount() {
                        return Err(unplaceable_because(
                            directory,
                            "the name arrives at this working tree on another mount, which holds \
                             different children under the same object",
                        ));
                    }
                    stack.push(clone_of(tree)?);
                } else {
                    stack.push(next);
                }
            }
        }
    }
    Ok(Some(stack))
}

/// Returns this working tree's own handle with the capture's rule on it: one mount.
///
/// Everything a capture reads goes through this rather than through the repository's own handle.
/// A mount is the one way a path reaches content the path does not name without crossing a link,
/// and a capture that reads around one would put another tree's bytes under this repository's
/// name. Other readers of the same tree — a download, a measurement, a copy — ask no such thing
/// and are not confined, because an intentionally mounted directory of a project is ordinary to
/// them.
fn confined_tree(repository: &OpenedRepository) -> Result<AuthorisedDirectory> {
    Ok(clone_of(repository.work_tree())?.confined_to_one_mount()?)
}

/// Returns a second authority over the same open directory, with **no** rule on it.
fn plain_clone(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let handle = directory
        .handle()
        .try_clone()
        .map_err(ChangeSetError::storage)?;
    Ok(AuthorisedDirectory::from_handle(
        directory.environment_id(),
        handle,
        directory.display_path().to_path_buf(),
    )?)
}

/// Returns which mount one open directory is on, whatever rule it carries.
fn mount_reading(directory: &AuthorisedDirectory) -> Result<Option<kr_transfer::MountId>> {
    Ok(plain_clone(directory)?.confined_to_one_mount()?.mount())
}

/// Returns a second authority over the same open directory, with the same rule on it.
fn clone_of(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let handle = directory
        .handle()
        .try_clone()
        .map_err(ChangeSetError::storage)?;
    let held = AuthorisedDirectory::from_handle(
        directory.environment_id(),
        handle,
        directory.display_path().to_path_buf(),
    )?;
    if directory.mount().is_some() {
        return Ok(held.confined_to_one_mount()?);
    }
    Ok(held)
}

/// The refusal for a nested repository whose own data this host could not place.
fn unplaceable(directory: &str) -> ChangeSetError {
    ChangeSetError::Unsupported {
        detail: format!(
            "a repository nested at {} keeps its own data somewhere this host could not reach by \
             descending to it, so it did not read the tree at all",
            kr_project::git::redact(directory)
        )
        .into(),
    }
}

/// The same refusal, saying which step of the descent ended it.
///
/// Every one of these is "this host could not reach it", and which of them it was is what tells
/// somebody holding an ordinary repository whether they have hit a limit or a layout this host
/// will not read.
fn unplaceable_because(directory: &str, why: &str) -> ChangeSetError {
    ChangeSetError::Unsupported {
        detail: format!(
            "a repository nested at {} keeps its own data somewhere this host could not reach by \
             descending to it ({why}), so it did not read the tree at all",
            kr_project::git::redact(directory)
        )
        .into(),
    }
}

/// The most a `.git` or `commondir` file is read for the one line it holds.
const MAX_GIT_FILE_BYTES: u64 = 4096;

/// Returns true when one path is this repository's own administrative data.
///
/// Two rules: any `.git` component, whatever its case, and the directory this repository actually
/// keeps its administrative data in, which a `.git` file can point anywhere inside the tree.
fn administrative(request: Scope<'_>, path: &str) -> bool {
    // The name rule alone. **Where** this repository keeps its own data is decided by identity, in
    // `nested_repositories`, which opens every directory this capture names and compares the
    // object rather than the spelling; a case-sensitive prefix comparison could not do that. This
    // rule stays because `.git` in a path is administrative whatever is at it, and excluding one
    // more directory that happens to be called that is a refusal, never an admission.
    let _ = request;
    crate::grant::is_administrative(path)
}

/// Returns the refusal a grant or a secret rule makes, when it makes one.
fn refused_here(request: Scope<'_>, path: &str) -> Option<Plan> {
    if request
        .nested
        .iter()
        .any(|prefix| grant::under(path, prefix))
    {
        return Some(Plan::Exclude {
            reason: ExclusionReason::Unsupported,
            detail: "this path is a repository nested in this tree, or its own administrative \
                     data, rather than this repository's content: this host never reads inside one"
                .to_owned(),
        });
    }
    if administrative(request, path) {
        return Some(Plan::Exclude {
            reason: ExclusionReason::Unsupported,
            detail: "this path is this repository's own administrative data rather than its \
                     content"
                .to_owned(),
        });
    }
    refused(request.grant, path)
}

/// Returns the refusal a grant or a secret rule makes, when it makes one.
fn refused(granted: &FileGrant, path: &str) -> Option<Plan> {
    match grant::decide(granted, path) {
        GrantDecision::Permitted => None,
        GrantDecision::Refused(ExclusionReason::SecretRule) => Some(Plan::Exclude {
            reason: ExclusionReason::SecretRule,
            detail: "a secret rule covers this path, so this host did not open it".to_owned(),
        }),
        GrantDecision::Refused(ExclusionReason::Unsupported) => Some(Plan::Exclude {
            reason: ExclusionReason::Unsupported,
            detail: "this path is a repository's own administrative data rather than its content"
                .to_owned(),
        }),
        GrantDecision::Refused(reason) => Some(Plan::Exclude {
            reason,
            detail: "the file grant does not select this path".to_owned(),
        }),
    }
}

/// How much of the capture's budget is left.
struct Budget {
    bytes: u64,
    objects: usize,
}

impl Budget {
    /// Charges one Git object read, refusing when this capture has had its share of them.
    fn read_object(&mut self) -> Result<()> {
        self.objects =
            self.objects
                .checked_sub(1)
                .ok_or_else(|| {
                    ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would read more than {MAX_OBJECT_READS} paths from Git objects \
                     and one capture reads at most that many; narrow the grant, or capture the \
                     working tree as the source"
                )
                .into(),
            }
                })?;
        Ok(())
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.bytes =
            self.bytes
                .checked_sub(bytes)
                .ok_or_else(|| {
                    ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would hold more than {MAX_CAPTURE_BYTES} bytes, which is more \
                     than one capture holds"
                )
                .into(),
            }
                })?;
        Ok(())
    }
}

/// Reads the content of every planned path and builds the manifest.
fn read_content(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    planned: &BTreeMap<String, Plan>,
    request: Scope<'_>,
    rewritten: &mut bool,
) -> Result<Manifest> {
    // Every read of a Git object counts, whichever plan asks for it: a deletion reads the base's
    // own blob so the version can restore it, exactly as a path the policy takes from the commit
    // reads one.
    let object_reads = planned
        .values()
        .filter(|plan| matches!(plan, Plan::GitObject { .. } | Plan::Deleted { .. }))
        .count();
    if object_reads > MAX_OBJECT_READS {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "this capture would read {object_reads} paths from Git objects and one capture \
                 reads at most {MAX_OBJECT_READS}; narrow the grant, or capture the working tree \
                 as the source"
            )
            .into(),
        });
    }
    let mut budget = Budget {
        bytes: MAX_CAPTURE_BYTES,
        objects: MAX_OBJECT_READS,
    };
    let mut manifest = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
        deletions: Vec::new(),
    };
    for (path, plan) in planned {
        match plan {
            Plan::Exclude { reason, detail } => manifest.exclusions.push(Exclusion {
                path: path.clone(),
                reason: *reason,
                detail: detail.clone(),
            }),
            Plan::Deleted {
                base_object_id,
                base_mode,
            } => {
                let content_digest = store_base_content(
                    profile,
                    repository,
                    store,
                    &mut budget,
                    base_object_id.as_deref(),
                    base_mode.as_deref(),
                )?;
                manifest.deletions.push(crate::version::DeletedPath {
                    path: path.clone(),
                    base_object_id: base_object_id.clone(),
                    base_mode: base_mode.clone(),
                    content_digest,
                });
            }
            Plan::GitObject {
                class,
                object_id,
                mode,
            } => {
                if !REGULAR_MODES.contains(&mode.as_str()) {
                    manifest
                        .exclusions
                        .push(exclusion(path, &unsupported_mode(mode)));
                    continue;
                }
                budget.read_object()?;
                let bytes = read_object(profile, repository, object_id)?;
                let content = classify_content(&bytes);
                if leave_out_binary(request, *class, content) {
                    manifest.exclusions.push(binary_exclusion(path));
                    continue;
                }
                budget.charge(bytes.len() as u64)?;
                let digest = store.put(&bytes)?;
                manifest.paths.push(CapturedPath {
                    path: path.clone(),
                    content_digest: digest,
                    byte_len: U64::new(bytes.len() as u64),
                    executable: mode == "100755",
                    content,
                    origin: ContentOrigin::GitObject,
                    class: *class,
                    change: ChangeKind::Present,
                    base_object_id: Nullable(Some(object_id.clone())),
                    base_mode: Nullable(Some(mode.clone())),
                });
            }
            Plan::WorkingTree {
                class,
                change,
                base_object_id,
                base_mode,
                index_mode,
            } => {
                let reading = read_working_tree(repository, path)?;
                *rewritten |= reading.changed_while_reading;
                match reading.read {
                    // The status said the path was there and it is not any more. That is a deletion
                    // the working tree holds, recorded with whatever the base has for it.
                    WorkingRead::Gone => {
                        let content_digest = store_base_content(
                            profile,
                            repository,
                            store,
                            &mut budget,
                            base_object_id.as_deref(),
                            base_mode.as_deref(),
                        )?;
                        manifest.deletions.push(crate::version::DeletedPath {
                            path: path.clone(),
                            base_object_id: base_object_id.clone(),
                            base_mode: base_mode.clone(),
                            content_digest,
                        });
                    }
                    WorkingRead::Unsupported(detail) => manifest.exclusions.push(Exclusion {
                        path: path.clone(),
                        reason: ExclusionReason::Unsupported,
                        detail,
                    }),
                    WorkingRead::Unreadable(detail) => manifest.exclusions.push(Exclusion {
                        path: path.clone(),
                        reason: ExclusionReason::Unreadable,
                        detail,
                    }),
                    WorkingRead::Content { bytes, executable } => {
                        let content = classify_content(&bytes);
                        if leave_out_binary(request, *class, content) {
                            manifest.exclusions.push(binary_exclusion(path));
                            continue;
                        }
                        budget.charge(bytes.len() as u64)?;
                        let digest = store.put(&bytes)?;
                        manifest.paths.push(CapturedPath {
                            path: path.clone(),
                            content_digest: digest,
                            byte_len: U64::new(bytes.len() as u64),
                            // The bit the file actually has. A platform with none answers from the
                            // mode Git records, which is the only thing there is to answer from.
                            executable: executable
                                .unwrap_or_else(|| index_mode.as_deref() == Some("100755")),
                            content,
                            origin: ContentOrigin::WorkingTree,
                            class: *class,
                            change: *change,
                            base_object_id: Nullable(base_object_id.clone()),
                            base_mode: Nullable(base_mode.clone()),
                        });
                    }
                }
            }
        }
    }
    manifest.canonicalise();
    Ok(manifest)
}

/// Turns one exclusion plan into the record a version carries.
fn exclusion(path: &str, plan: &Plan) -> Exclusion {
    let Plan::Exclude { reason, detail } = plan else {
        unreachable!("only an exclusion plan becomes an exclusion");
    };
    Exclusion {
        path: path.to_owned(),
        reason: *reason,
        detail: detail.clone(),
    }
}

fn binary_exclusion(path: &str) -> Exclusion {
    Exclusion {
        path: path.to_owned(),
        reason: ExclusionReason::Policy,
        detail: "the policy excludes binary content".to_owned(),
    }
}

/// Returns true when the policy excludes this path for holding binary content.
///
/// A binary exclusion cuts across the other classes: a dirty file may be binary, and a policy that
/// includes dirty files and excludes binaries leaves that one out. An ordinary tracked file is not
/// subject to it, because leaving it out would make the captured tree short of the base rather
/// than short of a change.
fn leave_out_binary(request: Scope<'_>, class: PathClass, content: ContentClass) -> bool {
    class.is_change()
        && content == ContentClass::Binary
        && request.policy.binary_files == InclusionChoice::Exclude
}

/// What reading one working-tree path came to.
pub enum WorkingRead {
    /// The content, and the executable bit where the platform has one.
    Content {
        /// The bytes, exactly as the file holds them.
        bytes: Vec<u8>,
        /// Whether the file is executable, or nothing on a platform with no such bit.
        executable: Option<bool>,
    },
    /// The path is not there.
    Gone,
    /// It is not file content: a link, a device, a socket, or a name this host cannot carry.
    Unsupported(String),
    /// This host could not read it.
    Unreadable(String),
}

/// One reading of one working-tree path, and what this host saw while it read.
pub struct WorkingReading {
    /// What the path held, as far as this host could read it.
    pub read: WorkingRead,
    /// True when the file changed while this host was reading it and a later attempt read it
    /// whole.
    ///
    /// The content is then a complete reading of one version of the file. What it is not is
    /// evidence that the file was still: something wrote it during the capture, and a capture
    /// that would otherwise call its source a quiesced one has to know that its own reading
    /// contradicts the reservation.
    pub changed_while_reading: bool,
}

/// What a test runs immediately after one path's content has been read and before this host reads
/// its metadata back, named by that path and given the attempt.
///
/// A file written in that window is what a change under a capture looks like from inside the
/// read: this attempt is discarded and the next one reads the file whole. Both readings go
/// through one open handle, so nothing outside this host can reach between them.
#[cfg(feature = "fault-injection")]
pub type WhileReading = std::sync::Arc<dyn Fn(&str, u32) + Send + Sync>;

#[cfg(feature = "fault-injection")]
thread_local! {
    static WHILE_READING: std::cell::RefCell<Option<WhileReading>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` on this thread inside every working-tree read, until it is taken away again.
///
/// Compiled with the fault-injection feature; nothing in the service sets it.
#[cfg(feature = "fault-injection")]
pub fn interpose_working_tree_reads(hook: Option<WhileReading>) {
    WHILE_READING.with(|installed| *installed.borrow_mut() = hook);
}

/// Reads one path from the working tree through the authorised handle.
///
/// The file's identity, length and modification instant are read before and after its content. A
/// file that changed while this host was reading it is re-read up to [`MAX_PATH_RETRIES`] times
/// and then rejected, because a captured tree that held half of one version and half of another
/// would be a tree that never existed.
///
/// A change a later attempt read past is reported as well as retried: the content is whole, and
/// the file was written while this host was reading the tree. Only the caller knows what that
/// means for the class it is about to record.
///
/// # Errors
///
/// Returns [`ChangeSetError::SourceChanged`] when the file kept changing past the bound, and
/// [`ChangeSetError::QuotaExceeded`] when it is larger than [`MAX_CAPTURE_FILE_BYTES`].
pub fn read_working_tree(repository: &OpenedRepository, path: &str) -> Result<WorkingReading> {
    let Ok(name) = RelativeName::parse(path) else {
        return Ok(WorkingReading {
            read: WorkingRead::Unsupported(
                "this host cannot name this path beneath the working tree's own handle, so it \
                 cannot read it and does not guess at it"
                    .to_owned(),
            ),
            changed_while_reading: false,
        });
    };
    let tree = confined_tree(repository)?;
    let mut changed_while_reading = false;
    for attempt in 0..=MAX_PATH_RETRIES {
        let mut file = match tree.open_read(&name, ObjectPolicy::ReadableFile) {
            Ok(file) => file,
            Err(kr_transfer::Escape::NotFound { .. }) => {
                return Ok(WorkingReading {
                    read: WorkingRead::Gone,
                    changed_while_reading,
                });
            }
            Err(
                error @ (kr_transfer::Escape::Link { .. } | kr_transfer::Escape::WrongKind { .. }),
            ) => {
                return Ok(WorkingReading {
                    read: WorkingRead::Unsupported(error.to_string()),
                    changed_while_reading,
                });
            }
            // A mount where this path was an ordinary file or directory when the capture looked.
            // It is not excluded and read around: what is under it is not what the tree's own
            // path said a moment ago, and a capture that carried on would put another tree's
            // bytes under this repository's name.
            Err(error @ kr_transfer::Escape::CrossedMount { .. }) => {
                return Err(ChangeSetError::Unsupported {
                    detail: format!(
                        "a path of this working tree is on a different mount from the tree \
                         itself, which it was not when this capture looked at it: {error}"
                    )
                    .into(),
                });
            }
            Err(error) => {
                return Ok(WorkingReading {
                    read: WorkingRead::Unreadable(error.to_string()),
                    changed_while_reading,
                });
            }
        };
        let before_identity = file.identity();
        let before_len = file.byte_len();
        if before_len > MAX_CAPTURE_FILE_BYTES {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "one file of this working tree is {before_len} bytes and this host reads at \
                     most {MAX_CAPTURE_FILE_BYTES} into a captured tree"
                )
                .into(),
            });
        }
        let before_written = modified_at(&file);
        let executable = is_executable(&file);
        let mut bytes = Vec::with_capacity(usize::try_from(before_len).unwrap_or(0));
        // Bounded by one more byte than the bound, so a file that grows while it is being read is
        // refused rather than read without end.
        let mut bounded = file.handle_mut().take(MAX_CAPTURE_FILE_BYTES + 1);
        if let Err(error) = bounded.read_to_end(&mut bytes) {
            return Ok(WorkingReading {
                read: WorkingRead::Unreadable(error.to_string()),
                changed_while_reading,
            });
        }
        // The one window a test cannot reach from outside: both readings of this file's metadata
        // go through the handle already open above.
        #[cfg(feature = "fault-injection")]
        {
            let hook = WHILE_READING.with(|installed| installed.borrow().clone());
            if let Some(hook) = hook {
                hook(path, attempt);
            }
        }
        if bytes.len() as u64 > MAX_CAPTURE_FILE_BYTES {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "one file of this working tree grew past {MAX_CAPTURE_FILE_BYTES} bytes while \
                     this host was reading it"
                )
                .into(),
            });
        }
        // The same open handle is asked again, so what is compared is the object this host read
        // rather than whatever the name now resolves to. The modification instant is compared
        // beside the length, because an overwrite in place of the same number of bytes changes
        // neither the identity nor the length and is exactly the change a reader would miss.
        let after_len = match file.revalidate() {
            Ok(length) => length,
            Err(error) => {
                return Ok(WorkingReading {
                    read: WorkingRead::Unreadable(error.to_string()),
                    changed_while_reading,
                });
            }
        };
        if file.identity() == before_identity
            && after_len == before_len
            && after_len == bytes.len() as u64
            && modified_at(&file) == before_written
        {
            return Ok(WorkingReading {
                read: WorkingRead::Content { bytes, executable },
                changed_while_reading,
            });
        }
        // Whatever the next attempt reads, this file was written while this host was reading the
        // tree. A reading that is discarded is still a reading, and it is the only evidence this
        // host has that something was writing here.
        changed_while_reading = true;
        if attempt == MAX_PATH_RETRIES {
            return Err(ChangeSetError::SourceChanged {
                detail: format!(
                    "a path changed while this host was reading it, {} times in a row",
                    MAX_PATH_RETRIES + 1
                )
                .into(),
            });
        }
    }
    unreachable!("the loop returns on its last attempt")
}

/// Returns when a file was last written, as far as the platform will say.
fn modified_at(file: &kr_transfer::AuthorisedFile) -> Option<cap_std::time::SystemTime> {
    file.handle()
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

/// Returns whether a file the working tree holds is executable.
#[cfg(unix)]
fn is_executable(file: &kr_transfer::AuthorisedFile) -> Option<bool> {
    use cap_std::fs::PermissionsExt as _;
    file.handle()
        .metadata()
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Returns nothing: this platform has no executable bit on a file.
///
/// The mode Git records is what decides there, and the caller uses it.
#[cfg(not(unix))]
fn is_executable(_file: &kr_transfer::AuthorisedFile) -> Option<bool> {
    None
}

/// Refuses an identifier that is not one.
///
/// It reaches an argument vector, so it is checked rather than trusted: a name that is not
/// hexadecimal is not an object identifier, and a leading `-` is an option.
fn check_object_id(object_id: &str) -> Result<()> {
    // A whole identifier, not an abbreviation: forty characters for SHA-1 and sixty-four for
    // SHA-256. An abbreviation is ambiguous in a repository that grows and means something else
    // in a repository that is not the one it came from, and a version records exact content
    // revisions.
    if !matches!(object_id.len(), 40 | 64)
        || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ChangeSetError::InvalidArgument(
            "this repository reported something that is not a whole object identifier".into(),
        ));
    }
    Ok(())
}

/// Reads one immutable Git object's content.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the identifier is not one, and whatever the
/// project service returns for a failed invocation.
pub fn read_object(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    object_id: &str,
) -> Result<Vec<u8>> {
    check_object_id(object_id)?;
    let arguments: [&OsStr; 3] = [
        OsStr::new("cat-file"),
        OsStr::new("blob"),
        OsStr::new(object_id),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    if output.stdout.len() as u64 > MAX_CAPTURE_FILE_BYTES {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "one object of this repository is larger than the {MAX_CAPTURE_FILE_BYTES} bytes \
                 this host reads into a captured tree"
            )
            .into(),
        });
    }
    Ok(output.stdout.clone())
}

/// One entry of one Git tree object.
#[derive(Clone, Debug)]
struct TreeEntry {
    mode: String,
    kind: String,
    object_id: String,
    name: String,
}

/// Reads one immutable Git tree object.
fn read_tree(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    object_id: &str,
) -> Result<Vec<TreeEntry>> {
    check_object_id(object_id)?;
    let arguments: [&OsStr; 3] = [
        OsStr::new("cat-file"),
        OsStr::new("-p"),
        OsStr::new(object_id),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(&output.stdout, "one of this repository's own trees")?;
    let mut entries = Vec::new();
    for line in text.lines() {
        // `<mode> <type> <object>\t<name>`
        let Some((fields, name)) = line.split_once('\t') else {
            continue;
        };
        // Git quotes a name in this display format when it holds a tab, a newline, a quote or a
        // byte outside ASCII, and the quoted form is a different string from the name. This host
        // does not unquote it and guess: a repository whose commit names a path it cannot read
        // exactly is one it will not claim to have snapshotted.
        if name.starts_with('"') {
            return Err(ChangeSetError::InvalidArgument(
                "this repository's own tree names a path in a quoted form this host does not \
                 read back, so it cannot capture that commit's tree exactly"
                    .into(),
            ));
        }
        let parts: Vec<&str> = fields.split(' ').collect();
        if parts.len() < 3 || name.is_empty() {
            continue;
        }
        entries.push(TreeEntry {
            mode: parts[0].to_owned(),
            kind: parts[1].to_owned(),
            object_id: parts[2].to_owned(),
            name: name.to_owned(),
        });
    }
    Ok(entries)
}

/// Captures the base commit's own tree, from immutable objects and nothing else.
///
/// This is what [`SourceConsistency::AtomicSnapshot`] rests on. The commit names one tree, that
/// tree names its children, and every one of them is immutable, so the whole listing is one
/// instant by construction. Nothing of the working tree or the index is read.
fn snapshot(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    request: Scope<'_>,
) -> Result<Captured> {
    // A policy that would include uncommitted work cannot be served from a commit, and serving it
    // a weaker class under the name it asked for is exactly what section 14 forbids.
    for (choice, what) in [
        (request.policy.dirty_files, "uncommitted changes"),
        (request.policy.untracked_files, "untracked files"),
        (request.policy.generated_artefacts, "ignored files"),
    ] {
        if choice == InclusionChoice::Include {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "an atomic snapshot is a capture of the base commit's own tree, and {what} \
                     are in no Git object of it; ask for a per-file capture, or exclude them"
                )
                .into(),
            ));
        }
    }
    let (revision, reference) = repository.head(profile)?;
    let Some(revision) = revision else {
        return Err(ChangeSetError::InvalidArgument(
            "this repository has no commit yet, so there is no base revision a version could be \
             captured against; commit once and capture again"
                .into(),
        ));
    };
    let root = format!("{revision}^{{tree}}");
    let arguments: [&OsStr; 3] = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new(&root),
    ];
    let reported = profile.run_checked(&repository.read(&arguments))?;
    let tree_id = reported.trim().to_owned();
    check_object_id(&tree_id)?;
    let mut manifest = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
        deletions: Vec::new(),
    };
    let mut budget = Budget {
        bytes: MAX_CAPTURE_BYTES,
        objects: MAX_OBJECT_READS,
    };
    descend(
        profile,
        repository,
        store,
        &tree_id,
        "",
        request,
        &mut manifest,
        &mut budget,
        0,
    )?;
    manifest.canonicalise();
    // The commit is immutable, and this confirms that what was walked is the commit the version
    // names: a reference that moved under the capture would otherwise leave a version whose base
    // is one commit and whose tree is another's.
    let (again, _) = repository.head(profile)?;
    if again.as_deref() != Some(revision.as_str()) {
        return Err(changed(
            "a commit landed while this host was reading the base revision's own tree",
        ));
    }
    let objects = distinct_objects(&manifest);
    Ok(Captured {
        manifest,
        base_revision: revision,
        base_reference: reference,
        consistency: SourceConsistency::AtomicSnapshot,
        consistency_detail:
            "every captured path came from the base commit's own tree: the commit names one \
             immutable tree object, each tree names its children, and every blob under them is \
             immutable, so the whole listing is one instant by construction. Nothing of the \
             working tree or the index was read"
                .to_owned(),
        objects,
    })
}

/// Walks one immutable tree object and everything beneath it.
#[allow(clippy::too_many_arguments)]
fn descend(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    tree_id: &str,
    prefix: &str,
    request: Scope<'_>,
    manifest: &mut Manifest,
    budget: &mut Budget,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "the base revision's own tree is more than {MAX_WALK_DEPTH} levels deep, and this \
                 host does not capture a tree it cannot walk to the bottom of"
            )
            .into(),
        });
    }
    for entry in read_tree(profile, repository, tree_id)? {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        if entry.kind == "tree" {
            // Another repository's own tree or data, whichever side the content is read from.
            if request
                .nested
                .iter()
                .any(|prefix| grant::under(&path, prefix))
            {
                manifest.exclusions.push(Exclusion {
                    path,
                    reason: ExclusionReason::Unsupported,
                    detail: "this path is a repository nested in this tree, or its own \
                             administrative data, rather than this repository's content: this \
                             host never reads inside one"
                        .to_owned(),
                });
                continue;
            }
            // A directory is walked into when anything the grant selects can lie beneath it, and
            // its own exclusion is recorded when nothing can.
            if !grant::may_traverse(request.grant, &path) || administrative(request, &path) {
                manifest.exclusions.push(Exclusion {
                    path,
                    reason: ExclusionReason::Grant,
                    detail: "the file grant selects nothing beneath this directory".to_owned(),
                });
                continue;
            }
            descend(
                profile,
                repository,
                store,
                &entry.object_id,
                &path,
                request,
                manifest,
                budget,
                depth + 1,
            )?;
            continue;
        }
        if let Some(plan) = refused_here(request, &path) {
            manifest.exclusions.push(exclusion(&path, &plan));
            continue;
        }
        if !REGULAR_MODES.contains(&entry.mode.as_str()) {
            manifest
                .exclusions
                .push(exclusion(&path, &unsupported_mode(&entry.mode)));
            continue;
        }
        if budget.objects == 0 {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "the base revision's own tree holds more than {MAX_OBJECT_READS} paths, and \
                     one capture reads at most that many Git objects; narrow the grant"
                )
                .into(),
            });
        }
        budget.objects -= 1;
        let bytes = read_object(profile, repository, &entry.object_id)?;
        let content = classify_content(&bytes);
        if content == ContentClass::Binary
            && request.policy.binary_files == InclusionChoice::Exclude
        {
            manifest.exclusions.push(binary_exclusion(&path));
            continue;
        }
        budget.charge(bytes.len() as u64)?;
        let digest = store.put(&bytes)?;
        manifest.paths.push(CapturedPath {
            path,
            content_digest: digest,
            byte_len: U64::new(bytes.len() as u64),
            executable: entry.mode == "100755",
            content,
            origin: ContentOrigin::GitObject,
            class: PathClass::Tracked,
            change: ChangeKind::Present,
            base_mode: Nullable(Some(entry.mode.clone())),
            base_object_id: Nullable(Some(entry.object_id)),
        });
    }
    Ok(())
}

/// Returns what one path's content is, by Git's own test.
///
/// A null byte in the first eight thousand bytes of the content as it is stored. A
/// `.gitattributes` declaration is not consulted, because what the repository declares must not
/// decide what this host reads.
#[must_use]
pub fn classify_content(bytes: &[u8]) -> ContentClass {
    let window = &bytes[..bytes.len().min(kr_project::workspace::BINARY_SCAN_BYTES)];
    if window.contains(&0) {
        ContentClass::Binary
    } else {
        ContentClass::Text
    }
}

/// Decides the consistency class from what the capture actually did.
///
/// [`SourceConsistency::QuiescedCapture`] is assigned for one reason and no other: a reservation
/// over this very working tree was granted before the first reading and was still holding after
/// the last one. Everything else a caller can say about quiescence is recorded beside the class
/// rather than deciding it, because a declaration and a reading of who holds the workspace both
/// describe instants and the class is a claim about an interval.
fn classify(
    request: Scope<'_>,
    reservation: Reservation,
    quiet: bool,
) -> (SourceConsistency, String) {
    match reservation {
        Reservation::Held => {
            return (
                SourceConsistency::QuiescedCapture,
                "a quiescence reservation over this working tree was granted before the first \
                 reading and was still holding after the last one, so every file this host read \
                 was read out of one tree that nothing was writing to"
                    .to_owned(),
            );
        }
        Reservation::Lapsed => {
            return (
                SourceConsistency::PerFileCapture,
                "the quiescence reservation stopped holding this workspace before the read \
                 finished, so the files were read one at a time from a live working tree with \
                 concurrent-change detection instead"
                    .to_owned(),
            );
        }
        Reservation::Contradicted => {
            return (
                SourceConsistency::PerFileCapture,
                "a file of this working tree was written while this host was reading it, \
                 although a reservation was supposed to be holding the tree still, so nothing \
                 held it still and the files were read one at a time from a live working tree \
                 with concurrent-change detection instead"
                    .to_owned(),
            );
        }
        Reservation::Refused => {
            return (
                SourceConsistency::PerFileCapture,
                "this workspace could not be reserved at the moment this host asked, so the \
                 files were read one at a time from a live working tree with concurrent-change \
                 detection instead"
                    .to_owned(),
            );
        }
        Reservation::NotAsked => {}
    }
    let mut detail = "files were read one at a time from a live working tree; each one was the \
                      same object of the same length written at the same instant after its read \
                      as before it, and the base revision, the index and the status were \
                      unchanged at the end, which is detection rather than one instant"
        .to_owned();
    if request.quiescence_declared {
        detail.push_str(if quiet {
            ". The caller declared the working tree quiesced and no session and no automation run \
             this host knows of held the workspace before or after the read. That is recorded and \
             it does not make this a quiesced capture: nothing here held the tree still for the \
             whole read, and an editor outside KalaReach is outside what this host can see"
        } else {
            ". The caller declared the working tree quiesced and this host found a session or an \
             automation run holding the workspace, so the declaration describes something that \
             was not the case"
        });
    }
    (SourceConsistency::PerFileCapture, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        path: &str,
        class: InclusionClass,
        change: ChangeKind,
    ) -> kr_project::workspace::StatusEntry {
        kr_project::workspace::StatusEntry {
            path: path.to_owned(),
            class,
            change,
        }
    }

    fn index(items: &[(&str, &str, &str, u32)]) -> BTreeMap<String, IndexEntry> {
        items
            .iter()
            .map(|(path, mode, object_id, stage)| {
                (
                    (*path).to_owned(),
                    IndexEntry {
                        mode: (*mode).to_owned(),
                        object_id: (*object_id).to_owned(),
                        stage: *stage,
                    },
                )
            })
            .collect()
    }

    fn differences(
        items: &[(&str, Option<&str>, Option<&str>, char)],
    ) -> BTreeMap<String, BaseDifference> {
        items
            .iter()
            .map(|(path, mode, object_id, status)| {
                (
                    (*path).to_owned(),
                    BaseDifference {
                        base_mode: mode.map(std::string::ToString::to_string),
                        base_object_id: object_id.map(std::string::ToString::to_string),
                        status: *status,
                    },
                )
            })
            .collect()
    }

    fn reading(
        index: BTreeMap<String, IndexEntry>,
        differences: BTreeMap<String, BaseDifference>,
        status: Vec<kr_project::workspace::StatusEntry>,
    ) -> Reading {
        staged_reading(index, differences, BTreeMap::new(), status)
    }

    fn staged_reading(
        index: BTreeMap<String, IndexEntry>,
        differences: BTreeMap<String, BaseDifference>,
        staged: BTreeMap<String, BaseDifference>,
        status: Vec<kr_project::workspace::StatusEntry>,
    ) -> Reading {
        Reading {
            revision: "abcdef".to_owned(),
            reference: Some("refs/heads/main".to_owned()),
            index,
            differences,
            staged,
            status,
        }
    }

    fn request<'a>(policy: &'a InclusionPolicy, granted: &'a FileGrant) -> CaptureRequest<'a> {
        CaptureRequest {
            policy,
            grant: granted,
            quiescence_declared: false,
            required_consistency: None,
            quiescence: None,
        }
    }

    fn scope<'a>(request: &'a CaptureRequest<'a>) -> Scope<'a> {
        static NESTED: std::sync::LazyLock<BTreeSet<String>> =
            std::sync::LazyLock::new(BTreeSet::new);
        Scope {
            request,
            administrative_prefix: None,
            nested: &NESTED,
        }
    }

    #[test]
    fn a_name_that_leaves_this_tree_and_comes_back_is_read_as_the_tree_s_own() {
        // Two properties in one walk. A name that climbs above the tree is followed through the
        // handles this host holds rather than resolved from outside, and the moment a component
        // **is** the tree again the rest of it carries the tree's own rule — the mount comparison
        // a content read carries. Outside the tree there is nothing to compare with, and the walk
        // says so by holding no rule there.
        let host = kr_ipc::testing::TempHost::create();
        let root = std::fs::canonicalize(host.environment().state_dir()).expect("a name to walk");
        let inside = root.join("tree");
        std::fs::create_dir_all(inside.join("meta")).expect("the tree and a directory in it");
        std::fs::create_dir_all(inside.join("common")).expect("and another");
        let environment_id = host.environment_id();
        let tree = kr_transfer::AuthorisedDirectory::open_root(environment_id, &inside)
            .and_then(kr_transfer::AuthorisedDirectory::confined_to_one_mount)
            .expect("the tree opens, confined to its own mount");

        // What the walk stands in when it starts, which is a directory of the tree.
        let held = clone_of(&tree).expect("a second handle on the tree");
        let start = vec![
            clone_of(&tree).expect("one more"),
            open_beneath(&held, &RelativeName::parse("meta").expect("a name"), "meta")
                .expect("it opens")
                .expect("it is there"),
        ];
        let name = RelativeName::parse("commondir").expect("a name");
        std::fs::write(inside.join("meta/commondir"), b"../../tree/common\n").expect("the file");
        let holder = start.last().expect("the directory it is in");
        let stack = resolve_target(
            clone_stack(&start).expect("a second set"),
            "commondir",
            holder,
            &name,
            &tree,
        )
        .expect("the name is followed")
        .expect("it names something that is there");
        let reached = stack.last().expect("what it reached");
        let directly =
            kr_transfer::AuthorisedDirectory::open_root(environment_id, &inside.join("common"))
                .expect("the same directory opens");
        assert_eq!(
            identity_of(reached),
            identity_of(&directly),
            "it reached the directory the name is for, out of the tree and back into it"
        );
        assert!(
            reached.mount().is_some(),
            "and it came back under the tree's own rule"
        );
    }

    #[test]
    fn the_directory_this_host_looks_through_is_the_one_it_asked_about() {
        // Why discovery keeps the handles its descent opened and never resolves the same name
        // twice. A name is not a place: two directories renamed under this host between one
        // resolution and the next put a different directory at the name it asked about, so a
        // walk that asked about one and then enumerated the other would report on a tree it never
        // looked in — and the repositories in the one it did ask about would go unfound.
        let host = kr_ipc::testing::TempHost::create();
        let root = std::fs::canonicalize(host.environment().state_dir()).expect("a name");
        let inside = root.join("tree");
        std::fs::create_dir_all(inside.join("one")).expect("one directory");
        std::fs::create_dir_all(inside.join("two")).expect("and another");
        std::fs::write(inside.join("one/in-one"), b"").expect("something only the first holds");
        std::fs::write(inside.join("two/in-two"), b"").expect("and only the second");
        let tree = kr_transfer::AuthorisedDirectory::open_root(host.environment_id(), &inside)
            .and_then(kr_transfer::AuthorisedDirectory::confined_to_one_mount)
            .expect("the tree opens");
        let name = RelativeName::parse("one").expect("a name");

        // The descent this host keeps.
        let held = open_beneath(&tree, &name, "one")
            .expect("an ordinary directory is not refused")
            .expect("it opens");

        // And the swap: the directory that was at the name is somewhere else, and another is at
        // the name now.
        std::fs::rename(inside.join("one"), inside.join("three")).expect("the first moves");
        std::fs::rename(inside.join("two"), inside.join("one")).expect("the second takes its name");

        let again = open_beneath(&tree, &name, "one")
            .expect("the name still opens")
            .expect("something is there");
        assert_ne!(
            identity_of(&held),
            identity_of(&again),
            "the name reaches a different directory than the handle does"
        );
        assert!(
            !same_place(&held, &again),
            "and they are not one place, so neither stands in for the other"
        );
        assert!(
            held.probe(&RelativeName::parse("in-one").expect("a name"))
                .is_ok(),
            "the handle still reaches what it opened, wherever its name went"
        );
        assert!(
            again
                .probe(&RelativeName::parse("in-two").expect("a name"))
                .is_ok(),
            "while the name reaches the other directory's children"
        );
    }

    #[test]
    fn an_ordinary_directory_is_opened_beneath_a_confined_one() {
        // What the mount rule rests on, through the opener this capture actually uses: an
        // ordinary subdirectory is not refused. Its other half, the boundary, is the test below.
        let host = kr_ipc::testing::TempHost::create();
        let environment_id = host.environment_id();
        let state = host.environment().state_dir().to_path_buf();
        std::fs::create_dir_all(state.join("ordinary")).expect("a directory is made");
        let here = kr_transfer::AuthorisedDirectory::open_root(environment_id, &state)
            .and_then(kr_transfer::AuthorisedDirectory::confined_to_one_mount)
            .expect("the directory opens");
        let ordinary = RelativeName::parse("ordinary").expect("a name");
        open_beneath(&here, &ordinary, "ordinary")
            .expect("an ordinary directory is not refused")
            .expect("it opens");
    }

    /// A boundary this host has is refused, through the opener this capture actually uses.
    ///
    /// The boundary is a mount every Unix host carries, asked for through the root that holds it.
    /// Where the host does not have it this fails and says so, because a check that returned early
    /// would be counted as one that passed.
    #[cfg(unix)]
    #[test]
    fn a_directory_on_another_mount_is_not_opened_beneath_a_confined_one() {
        let host = kr_ipc::testing::TempHost::create();
        let top = kr_transfer::AuthorisedDirectory::open_root(
            host.environment_id(),
            std::path::Path::new("/"),
        )
        .and_then(kr_transfer::AuthorisedDirectory::confined_to_one_mount)
        .unwrap_or_else(|error| {
            panic!(
                "this host would not open its root directory, so this check cannot run \
                         here: {error}"
            )
        });
        let name = RelativeName::parse("dev").expect("a name");
        match top.subdirectory(&name) {
            Err(kr_transfer::Escape::CrossedMount { .. }) => {
                let refusal = open_beneath(&top, &name, "dev")
                    .expect_err("a directory on another mount refuses the capture");
                assert!(
                    format!("{refusal}").contains("different mount"),
                    "the refusal names the mount: {refusal}"
                );
            }
            Ok(_) => panic!(
                "this host puts /dev on the mount that holds /, so this check cannot run here"
            ),
            Err(other) => {
                panic!("this host would not open /dev, so this check cannot run here: {other}")
            }
        }
    }

    #[test]
    fn a_secret_is_left_out_before_anything_is_opened() {
        // The plan is built from the index, the base difference and the status alone. A secret's
        // entry is an exclusion there, so nothing downstream ever names it as something to read.
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Include,
            submodules: InclusionChoice::Include,
            binary_files: InclusionChoice::Include,
            generated_artefacts: InclusionChoice::Include,
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[
                    ("src/main.rs", "100644", "aaaa", 0),
                    (".env", "100644", "bbbb", 0),
                ]),
                differences(&[(".env", Some("100644"), Some("bbbb"), 'M')]),
                vec![entry(
                    ".env",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(
            planned[".env"],
            Plan::Exclude {
                reason: ExclusionReason::SecretRule,
                ..
            }
        ));
        assert!(matches!(planned["src/main.rs"], Plan::WorkingTree { .. }));
    }

    #[test]
    fn excluding_uncommitted_changes_holds_the_base_commit_rather_than_the_index() {
        // The whole of the base-is-the-commit rule: what an exclusion falls back to is the object
        // the **revision** holds, which `git diff --raw` reports, and never the index's.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                // The index holds `staged`, which is neither the commit's content nor the working
                // tree's.
                index(&[("README.md", "100644", "staged", 0)]),
                differences(&[("README.md", Some("100644"), Some("committed"), 'M')]),
                vec![entry(
                    "README.md",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        match &planned["README.md"] {
            Plan::GitObject {
                class, object_id, ..
            } => {
                assert_eq!(*class, PathClass::Tracked);
                assert_eq!(
                    object_id, "committed",
                    "the base is the commit, not the index"
                );
            }
            other => panic!("the base's own object is what is read: {other:?}"),
        }
    }

    #[test]
    fn a_staged_addition_is_absent_when_uncommitted_changes_are_excluded() {
        // The base never held it, so excluding uncommitted changes leaves nothing to fall back to.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("added.txt", "100644", "staged", 0)]),
                differences(&[("added.txt", None, None, 'A')]),
                vec![entry(
                    "added.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(
            planned["added.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Policy,
                ..
            }
        ));
    }

    #[test]
    fn a_staged_deletion_keeps_the_base_version_when_uncommitted_changes_are_excluded() {
        // The path is gone from the index and from the working tree, and the base holds it, so an
        // exclusion of the deletion means the captured tree holds what the commit has.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("gone.txt", Some("100644"), Some("committed"), 'D')]),
                vec![entry(
                    "gone.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Deleted,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        match &planned["gone.txt"] {
            Plan::GitObject { object_id, .. } => assert_eq!(object_id, "committed"),
            other => panic!("the base's own object is what is read: {other:?}"),
        }
    }

    #[test]
    fn an_excluded_untracked_path_is_absent_because_the_base_never_held_it() {
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[]),
                vec![entry(
                    "notes.txt",
                    InclusionClass::UntrackedFile,
                    ChangeKind::Present,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(
            planned["notes.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Policy,
                ..
            }
        ));
    }

    #[test]
    fn a_deletion_the_policy_includes_is_carried_by_absence_and_named() {
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("gone.txt", Some("100644"), Some("committed"), 'D')]),
                vec![entry(
                    "gone.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Deleted,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        // A deletion is an operation of its own, and it carries what the base held so a revert has
        // somewhere to put back.
        match &planned["gone.txt"] {
            Plan::Deleted {
                base_object_id,
                base_mode,
            } => {
                assert_eq!(base_object_id.as_deref(), Some("committed"));
                assert_eq!(base_mode.as_deref(), Some("100644"));
            }
            other => panic!("a deletion is planned as one: {other:?}"),
        }
    }

    #[test]
    fn a_path_the_index_lost_is_captured_when_the_working_tree_still_holds_it() {
        // `git rm --cached` leaves the file where it is and takes it out of the index. The diff
        // against the commit calls that `D`, and status reports the path twice: once as a staged
        // deletion and once as untracked. Recording a deletion for it would throw away a file that
        // is sitting there, so what the working tree holds is what decides.
        let policy = InclusionPolicy {
            untracked_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("kept.txt", Some("100644"), Some("committed"), 'D')]),
                vec![
                    entry("kept.txt", InclusionClass::DirtyFile, ChangeKind::Deleted),
                    entry(
                        "kept.txt",
                        InclusionClass::UntrackedFile,
                        ChangeKind::Present,
                    ),
                ],
            ),
            scope(&request(&policy, &granted)),
        );
        match &planned["kept.txt"] {
            Plan::WorkingTree {
                class,
                base_object_id,
                ..
            } => {
                assert_eq!(*class, PathClass::UntrackedFile);
                assert_eq!(
                    base_object_id.as_deref(),
                    Some("committed"),
                    "the base object travels with it, so a revert has somewhere to go back to"
                );
            }
            other => panic!("the working tree's file is what is captured: {other:?}"),
        }
    }

    #[test]
    fn a_path_the_index_lost_and_the_working_tree_lost_too_is_a_deletion() {
        let policy = InclusionPolicy {
            untracked_files: InclusionChoice::Include,
            dirty_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("gone.txt", Some("100644"), Some("committed"), 'D')]),
                vec![entry(
                    "gone.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Deleted,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(planned["gone.txt"], Plan::Deleted { .. }));
    }

    #[test]
    fn an_unresolved_merge_is_never_captured_as_one_content() {
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("merged.txt", "100644", "abcdef", 2)]),
                differences(&[("merged.txt", Some("100644"), Some("committed"), 'U')]),
                vec![entry(
                    "merged.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Unmerged,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(
            planned["merged.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Unsupported,
                ..
            }
        ));
    }

    #[test]
    fn a_submodule_is_never_entered_whatever_the_policy_says() {
        let policy = InclusionPolicy {
            submodules: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("vendor/lib", "160000", "abcdef", 0)]),
                differences(&[]),
                Vec::new(),
            ),
            scope(&request(&policy, &granted)),
        );
        assert!(matches!(
            planned["vendor/lib"],
            Plan::Exclude {
                reason: ExclusionReason::Unsupported,
                ..
            }
        ));
    }

    #[test]
    fn a_mode_that_is_not_file_content_is_named_rather_than_written_out_as_a_file() {
        // A symbolic link's object holds its target. Writing that out as a regular file would make
        // a materialisation a different tree, so it is left out and said.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("link", "120000", "target", 0)]),
                differences(&[("link", Some("120000"), Some("committed"), 'M')]),
                vec![entry(
                    "link",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            scope(&request(&policy, &granted)),
        );
        match &planned["link"] {
            Plan::Exclude { reason, detail } => {
                assert_eq!(*reason, ExclusionReason::Unsupported);
                assert!(
                    detail.contains("not file content"),
                    "the exclusion says why: {detail}"
                );
            }
            other => panic!("a link is not captured as a file: {other:?}"),
        }
    }

    #[test]
    fn a_path_whose_only_change_is_staged_names_the_commit_s_object_and_not_the_index_s() {
        // The working tree matches the commit and the index does not. The index's object is
        // therefore not the commit's, and the index-against-commit diff is where the commit's own
        // object for such a path comes from.
        let staged = staged_reading(
            index(&[("README.md", "100644", "staged", 0)]),
            differences(&[]),
            differences(&[("README.md", Some("100644"), Some("committed"), 'M')]),
            vec![entry(
                "README.md",
                InclusionClass::DirtyFile,
                ChangeKind::Present,
            )],
        );
        assert_eq!(
            staged.base_of("README.md"),
            Some(("100644".to_owned(), "committed".to_owned()))
        );
        // With nothing staged, the index's object is the base's.
        let clean = reading(
            index(&[("README.md", "100644", "committed", 0)]),
            differences(&[]),
            Vec::new(),
        );
        assert_eq!(
            clean.base_of("README.md"),
            Some(("100644".to_owned(), "committed".to_owned()))
        );
    }

    #[test]
    fn only_a_reservation_that_held_makes_a_quiesced_capture() {
        // Section 14 forbids advertising a stronger source-consistency class without a real
        // mechanism. The reservation is that mechanism, and it is the only thing that assigns the
        // class: a declaration, and a reading of who holds the workspace, are recorded beside the
        // class rather than deciding it.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let declared = CaptureRequest {
            quiescence_declared: true,
            ..request(&policy, &granted)
        };
        for quiet in [true, false] {
            let (class, detail) = classify(scope(&declared), Reservation::NotAsked, quiet);
            assert_eq!(class, SourceConsistency::PerFileCapture);
            assert!(
                detail.contains("detection rather than one instant"),
                "the detail says what it is: {detail}"
            );
        }
        let (class, detail) = classify(scope(&declared), Reservation::NotAsked, true);
        assert_eq!(class, SourceConsistency::PerFileCapture);
        assert!(
            detail.contains("it does not make this a quiesced capture"),
            "and says plainly that the declaration did not decide it: {detail}"
        );
        // Without the declaration the detail says nothing about one.
        let (class_without, detail_without) = classify(
            scope(&request(&policy, &granted)),
            Reservation::NotAsked,
            true,
        );
        assert_eq!(class_without, SourceConsistency::PerFileCapture);
        assert!(!detail_without.contains("quiesced"));

        // A grant that held through every reading is the one case that assigns the class.
        let (held, held_detail) = classify(scope(&declared), Reservation::Held, true);
        assert_eq!(held, SourceConsistency::QuiescedCapture);
        assert!(
            held_detail.contains("still holding after the last one"),
            "the detail says what held it: {held_detail}"
        );

        // A grant that stopped holding, and a workspace nothing would hold, are both the weaker
        // class, and neither detail describes one instant.
        for (state, says) in [
            (Reservation::Lapsed, "stopped holding"),
            (
                Reservation::Contradicted,
                "was written while this host was reading it",
            ),
            (Reservation::Refused, "could not be reserved"),
        ] {
            let (class, detail) = classify(scope(&declared), state, true);
            assert_eq!(class, SourceConsistency::PerFileCapture);
            assert!(detail.contains(says), "{state:?} says why: {detail}");
            assert!(detail.contains("concurrent-change detection"));
        }
    }

    #[test]
    fn content_is_binary_by_the_same_test_git_uses() {
        assert_eq!(classify_content(b"ordinary text\n"), ContentClass::Text);
        assert_eq!(classify_content(b"before\0after"), ContentClass::Binary);
        assert_eq!(classify_content(b""), ContentClass::Text);
        // A null byte past the scan window is past it, exactly as Git's own test has it.
        let mut far = vec![b'a'; kr_project::workspace::BINARY_SCAN_BYTES];
        far.push(0);
        assert_eq!(classify_content(&far), ContentClass::Text);
    }

    #[test]
    fn an_identifier_that_is_not_one_is_refused_before_it_reaches_an_argument_vector() {
        for value in [
            "--upload-pack=sh",
            "-c",
            "",
            "refs/heads/main",
            "zzzz",
            // An abbreviation is not an identifier either: it means one thing in the repository
            // it came from today and can mean another there tomorrow.
            "abcdef0123456789",
            "0123456789abcdef0123456789abcdef0123456",
        ] {
            assert!(
                check_object_id(value).is_err(),
                "{value} is not a whole object identifier"
            );
        }
        assert!(check_object_id("0123456789abcdef0123456789abcdef01234567").is_ok());
        assert!(
            check_object_id("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .is_ok()
        );
    }

    #[test]
    fn a_capture_larger_than_the_bound_is_refused_as_it_goes() {
        let mut budget = Budget {
            bytes: 10,
            objects: 4,
        };
        budget.charge(6).expect("the first file fits");
        let failure = budget
            .charge(6)
            .expect_err("the second takes it past the bound");
        assert!(
            failure.to_string().contains("more than"),
            "the refusal names the bound: {failure}"
        );
    }
}
