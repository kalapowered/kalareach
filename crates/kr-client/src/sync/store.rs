//! This device's own synchronisation state, on this device's disk.
//!
//! Four things live here, and they are separate because privacy mode treats them differently:
//!
//! | What | Why it is here | What privacy mode does with it |
//! | --- | --- | --- |
//! | Requests | One record of each publication this device admitted, settings, a client's position and drafts alike, and where it got to | **It depends on where it got to.** Work that never left is removed; a request that reached the service is an account of what left, and stays. |
//! | Conflict copies | What the service held when a write of this device's lost | Removed. It is content another device produced. |
//! | Checkpoints | Where each object reached on the service | Removed. It is production state, not content, and losing it costs a comparison. |
//! | Publications | That this device published a collection, and where the write landed | **Kept.** It is the only account of what left, and section 24 shows what left rather than pretending it did not. |
//! | Pinned labels | The labels a person pinned | **Kept**, and excluded from what is published while privacy mode is on. |
//!
//! # One request, one record
//!
//! Everything this device knows about one publication is in one file, named by the request's own
//! identity, and every step of that request replaces the whole of it. A device that stops between
//! two steps therefore comes back to one file saying where the request had got to, never to two
//! files each describing part of it. That is what makes an account of what left this device single:
//! there is no arrangement of a crash that can leave one request counted twice, because there is
//! never more than one record of it to count.
//!
//! What a settled request still owes the store is derived from that record and written afterwards:
//! an accepted write becomes the object's publication record. A device that stops between the two
//! comes back with the record still saying "applied", and the next read finishes the step before it
//! reports anything, which is deterministic and needs no service answer.
//!
//! # Drafts
//!
//! A draft publication keeps its one record here too, beside the settings, so the barrier, the
//! fence and privacy mode's cleanup reach a draft the way they reach a setting and
//! [`SyncStore::unsettled`] counts both. What is not here is the draft itself and the note beside
//! it: both are the draft store's, and a settlement that moves a draft's note is handed the draft
//! store to write it in. A draft store's lock is only ever taken inside this store's hold and
//! never the other way round, so the two cannot wait on each other.
//!
//! # One store, one lock
//!
//! Every change takes an exclusive lock on the store's own `store.lock`, so reading a checkpoint,
//! comparing it and replacing it is one step against every other window of the application and
//! against another process. The lock is the operating system's, so it is as good as the filesystem
//! holding it. A sync store belongs on the device, beside the draft store it works with.
//!
//! # One dispatch, one owner
//!
//! A dispatch is a transition this store owns as well. [`SyncStore::begin_dispatch`] marks the work
//! sent and takes a second operating-system lock, on the request itself, and anything that wants to
//! decide what became of that request claims the same lock first. So a client value holds no
//! authority this store has not recorded: two windows over one store cannot each conclude about the
//! other's live call, and a claim that succeeds because the owner died permits asking the service,
//! never concluding. The request's lock is taken **before** the store's wherever both are held and
//! one of them is waited for, which is what keeps the two orders from crossing. The one place it is
//! taken inside the store's hold, an attempt at a draft publication, only tries it: a try waits on
//! nothing, so it cannot close a cycle with a holder of the request's lock that is waiting for the
//! store's.
//!
//! Each file is written to a temporary name, flushed, and renamed over its name, so a reader never
//! sees one half written, and the directory entry is flushed afterwards, so a name this store
//! acknowledged survives losing power. On Windows a directory is flushed through a handle opened
//! with the backup semantics that let a program open one at all.

use std::path::{Path, PathBuf};

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DraftId, DraftRevision, SyncConflictId, SyncObjectId, SyncRevisionId};
use kr_protocol::mailbox::mailbox_size_bucket;
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::sync::{MAX_SYNC_CONFLICT_COPIES, SyncObjectKind};
use serde::{Deserialize, Serialize};

use super::SyncObject;
use crate::drafts::{DraftStore, SyncCheckpoint as DraftCheckpoint};
use crate::retry::UserAction;
use crate::services::SyncPosition;

/// The extension of a stored object this device holds.
const OBJECT_EXTENSION: &str = "object";
/// The extension of the note recording where an object reached on the service.
const CHECKPOINT_EXTENSION: &str = "note";
/// The extension of the one record of one publication request.
const REQUEST_EXTENSION: &str = "request";
/// The extension of a copy kept because a comparison was lost.
const CONFLICT_EXTENSION: &str = "conflict";
/// The extension of the record that this device published a collection.
const PUBLICATION_EXTENSION: &str = "published";
/// The extension of the lock one dispatch is owned through.
const CALLOUT_EXTENSION: &str = "callout";
/// The extension of a file being written, which is not yet a file.
const PARTIAL_EXTENSION: &str = "partial";
/// The name of the store's lock.
const LOCK_NAME: &str = "store.lock";
/// The name the pinned labels are kept under.
const LABELS_NAME: &str = "pinned.labels";
/// The name this device's privacy state is kept under.
const PRIVACY_NAME: &str = "privacy.state";

/// What this device's own notes on a copy may add to the object inside it.
///
/// A copy carries its own identity, the revision this device held, two positions and the instant
/// it arrived. Allowing for those separately is what keeps a copy that arrived at the service's
/// limit storable, rather than refusing to keep content the service was already carrying.
const CONFLICT_NOTE_BYTES: u64 = 512;

/// The most a stored conflict copy may carry, in bytes.
const MAX_CONFLICT_COPY_BYTES: u64 = super::MAX_OBJECT_BYTES + CONFLICT_NOTE_BYTES;

/// How far apart the attempts under one identity may be signed, in milliseconds.
///
/// A later attempt is a replay only while the service still holds the receipt of any attempt that
/// ran. Once that receipt is gone, the same identity with the same bytes is a new request: it can
/// run a second time, or be refused in a way that says nothing about the first attempt.
///
/// An attempt that ran was admitted at a service reading within one freshness window of the
/// instant it was signed at, and section 9 keeps its receipt for
/// [`kr_protocol::limits::DEDUPLICATION_RETENTION`] from that reading. Any other attempt is
/// admitted, if at all, at a reading within one window of its own signing time. With every attempt
/// signed within one window of every other, the second reading is within three windows of the
/// first, so the receipt is still there unless the service's clock went back by nearly the whole
/// retention between the two readings, which is the fault a fence of the request already rests on
/// the service not having. That holds in whichever order the attempts arrive.
///
/// Every term is an instant this device signed with or a bound the service enforces on its own
/// clock, so nothing here assumes this device's clock is right. An attempt signed on a wrong clock
/// is refused by the service as outside its window, or it spreads the attempts past this span, and
/// then nothing is attempted under that identity again.
const REPLAY_SPAN_MS: u64 = kr_protocol::service::SERVICE_REQUEST_FRESHNESS_MS;

/// How many links the walk over a store's path follows before it gives up.
///
/// A backstop rather than the rule. Every kernel this runs on applies a limit of its own, usually
/// lower, and refuses to open through a longer chain before the walk ever sees it.
#[cfg(any(unix, windows))]
const MAX_PATH_LINKS: usize = 40;

/// Where an object has reached on the synchronisation service.
///
/// A note, not content: losing it costs a comparison and a fetch, never a setting. It is written
/// beside the object rather than inside it, and an object's own revision is never the position a
/// comparison names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCheckpoint {
    /// Where the service holds the object.
    pub position: SyncPosition,
    /// The revision *this device* published at that position.
    ///
    /// Null when the position came from another device's write, which this device only fetched.
    pub published_revision: Nullable<SyncRevisionId>,
}

/// This device's whole account of one publication request.
///
/// One request identity, one file, replaced whole at every step. A device that stops part way
/// through a settlement comes back to one record saying where the request had got to, so nothing
/// can describe one request twice, whatever the timing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    /// The piece of work this is, which is the identity every exchange for it presents.
    pub work_id: Uuid,
    /// The object it publishes.
    ///
    /// A draft's own identity, for a draft: one collection holds one draft, under its identity.
    pub object_id: SyncObjectId,
    /// What kind of object it is.
    pub kind: SyncObjectKind,
    /// The revision it carries.
    pub revision: RequestRevision,
    /// The position it expects to replace.
    ///
    /// Null when this device believes nothing is there yet, which is the comparison a first
    /// publication makes. There is no position that stands for an empty collection.
    pub expected: Nullable<SyncPosition>,
    /// The host's privacy generation this work was admitted under.
    ///
    /// A result carries it back, and the publication is accepted only when it is still the
    /// generation in force. An older one belongs to work privacy mode cancelled.
    pub produced_under: U64,
    /// The earliest instant any attempt under this identity was signed at.
    ///
    /// Null while the work is admitted and not sent, and written in the same replacement that
    /// records the dispatch, so every state after [`RequestState::Admitted`] carries it. It says
    /// when this device signed the content away, not that the service stored it.
    ///
    /// It is the **earliest** attempt's rather than the first one recorded, because a device's
    /// clock can be corrected between two attempts and a later attempt signed before this instant
    /// moves it back. The service admits a request only within its freshness window of the signing
    /// time it carries, so no attempt under this identity can have run more than a window before
    /// this instant: it is the earliest moment a receipt for this identity could bear, and the
    /// service reads it to say whether such a receipt could have been swept.
    pub first_signed_at_ms: Nullable<TimestampMs>,
    /// The latest instant any attempt under this identity was signed at.
    ///
    /// Equal to the earliest until a further attempt is made, and never earlier than it. Where the
    /// earliest bounds the past, this bounds the future: an attempt can become fresh up to a window
    /// after it was signed, so the service keeps a fence of this identity until this instant and
    /// its window have gone by, and nothing this device signed can outlive the fence that ended it.
    pub last_signed_at_ms: Nullable<TimestampMs>,
    /// Where the request has got to.
    pub state: RequestState,
}

/// The revision one request carries, in the terms of what it publishes.
///
/// A settings object and a client's position name each write with a fresh revision of their own;
/// a draft counts its own edits. Both are this device's, and neither is the position the service
/// gives the write. The record says which it is rather than leaving the kind to imply it, because
/// what a settlement writes from it differs: a setting's note lives in this store and a draft's in
/// the draft store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestRevision {
    /// The revision this device gave a settings object or a client's position.
    Object(SyncRevisionId),
    /// This device's own revision of a draft.
    Draft(DraftRevision),
}

impl RequestRevision {
    /// Returns the object's revision, when the request publishes a settings object or a client's
    /// position.
    #[must_use]
    pub const fn object(self) -> Option<SyncRevisionId> {
        match self {
            Self::Object(revision) => Some(revision),
            Self::Draft(_) => None,
        }
    }
}

impl std::fmt::Display for RequestRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(revision) => std::fmt::Display::fmt(revision, formatter),
            Self::Draft(revision) => std::fmt::Display::fmt(revision, formatter),
        }
    }
}

/// Returns the collection one object is published in.
///
/// A draft is named by the draft store's own rule and everything else by the synchronised half's,
/// so a request, a publication and the service agree on one name whichever kind the object is.
pub(crate) fn collection_of(kind: SyncObjectKind, object_id: SyncObjectId) -> String {
    match kind {
        SyncObjectKind::Draft => crate::drafts::draft_collection(DraftId::new(object_id.get())),
        SyncObjectKind::Settings | SyncObjectKind::ClientSelection => {
            super::sync_collection(kind, object_id)
        }
    }
}

/// Where one request has got to.
///
/// The two states that may still be sent carry the ciphertext, because they are the two that still
/// have something to send. A request the service has answered about carries none: what is left of
/// it is the account of what left this device, and an account carries no content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestState {
    /// Admitted for publication and not sent.
    ///
    /// Content on its way out and nothing more: nothing of it has left the device, so a cleanup
    /// takes it back and no account of it is owed to anybody.
    Admitted {
        /// The sealed object.
        ///
        /// A byte string on disk, not a list of numbers: the reader bounds a collection at four
        /// thousand members, so a sealed object above that written as a list would be a record this
        /// device could never open again, and a record it cannot open is work it can never settle.
        ciphertext: Bytes,
    },
    /// Sent, with nothing yet established about what became of it.
    ///
    /// Written durably **before** the call leaves, so a device that stops between the write and the
    /// answer still knows this may have reached the service. It counts as outstanding until an
    /// answer about the request itself says otherwise.
    Dispatched {
        /// The sealed object, kept so that every attempt presents the same bytes under the same
        /// identity and the service can answer a retry from its receipt.
        ciphertext: Bytes,
    },
    /// The service applied the write, leaving the object at this position.
    Applied {
        /// Where the write left the object.
        position: SyncPosition,
    },
    /// The service refused the comparison, so this write did not replace the object.
    ///
    /// The request carried its ciphertext to the service all the same, and `retained` names the
    /// copy a service that stores a rejected write kept of it.
    Refused {
        /// What the service called the copy it kept of the refused write, when it kept one.
        retained: Nullable<SyncConflictId>,
    },
    /// The service kept a copy of this refused write, and the person has since chosen about the
    /// conflict it was part of, or asked for the copy to go, so it is to leave the service.
    ///
    /// The choice is recorded here before the service is asked, so a service that cannot be asked
    /// leaves the choice where it was and the next pass asks again. The record goes once the
    /// service says it no longer holds the copy: from then on there is nothing on the service for
    /// it to account for. Until then it is the account it always was, because the ciphertext is
    /// still on the service.
    Resolving {
        /// What the service called the copy it kept of the refused write.
        retained: SyncConflictId,
    },
    /// The service applied the write into a history this device's records do not follow.
    ///
    /// One write sequence names one write for the life of a collection, and a write takes the next
    /// place after the one it replaced. So an answer at the place the write replaced, or behind it,
    /// is not a later state of the history the request was made against, and two answers claiming
    /// one place in the order come from two histories of which the object's record can name only
    /// one. This write left this device all the same, and this record is what accounts for it; it is
    /// never recorded as applied.
    ///
    /// It is written once, when the settlement finds the answer behind what the request replaced
    /// or the object's record already given to another history, and nothing reclassifies it
    /// afterwards: a later publication of the object moves that record on, and an account that was
    /// re-decided against it would be dropped for looking like ordinary older news.
    Diverged {
        /// Where the service put this write, in the order of the history that took it.
        position: SyncPosition,
    },
    /// The request was ended at the service too late for the answer to say whether it had run.
    ///
    /// A fence ends a request in every case: nothing executes under the identity afterwards, so the
    /// barrier this device holds for the request is released. What the fence could not establish is
    /// the past. It says the service held no outcome for the identity, and a receipt swept after
    /// its retention says exactly the same thing as a request that never arrived, so from here the
    /// ciphertext may be on the service and may never have reached it.
    ///
    /// The record therefore stays, with no content, as the account of what left this device.
    /// Section 24 shows what left rather than pretending it did not, and an account this device
    /// deleted because it could not tell which had happened would be the pretending.
    Unaccounted,
}

impl RequestRecord {
    /// Returns the collection this request publishes in, which is what every call about it names.
    #[must_use]
    pub fn collection(&self) -> String {
        collection_of(self.kind, self.object_id)
    }

    /// Returns true when the work has been admitted and not sent.
    #[must_use]
    pub const fn admitted(&self) -> bool {
        matches!(self.state, RequestState::Admitted { .. })
    }

    /// Returns true when the work has been sent and nothing has answered about it.
    #[must_use]
    pub const fn dispatched(&self) -> bool {
        matches!(self.state, RequestState::Dispatched { .. })
    }

    /// Returns true when nothing more can happen to this request.
    ///
    /// Every state the service has answered about is an end: the two answers it gave, and the
    /// fence that ended a request too late to say which of them it would have been. A refusal the
    /// person has since chosen about is still a refusal.
    #[must_use]
    pub const fn ended(&self) -> bool {
        matches!(
            self.state,
            RequestState::Applied { .. }
                | RequestState::Diverged { .. }
                | RequestState::Refused { .. }
                | RequestState::Resolving { .. }
                | RequestState::Unaccounted
        )
    }

    /// Returns the sealed object, while this request still carries one.
    #[must_use]
    pub fn ciphertext(&self) -> Option<&[u8]> {
        match &self.state {
            RequestState::Admitted { ciphertext } | RequestState::Dispatched { ciphertext } => {
                Some(ciphertext.as_slice())
            }
            RequestState::Applied { .. }
            | RequestState::Diverged { .. }
            | RequestState::Refused { .. }
            | RequestState::Resolving { .. }
            | RequestState::Unaccounted => None,
        }
    }

    /// Returns when this device first signed the content away.
    ///
    /// Every record that has been sent carries the instant, because the dispatch writes the state
    /// and the instant in one replacement. A record that names none has not been sent, and the
    /// epoch is what the account of what left says of an instant nothing recorded.
    #[must_use]
    pub fn left_at(&self) -> TimestampMs {
        self.first_signed_at_ms
            .as_ref()
            .copied()
            .unwrap_or_else(|| TimestampMs::new(0))
    }

    /// Returns the two signing times a fence of this identity is decided from.
    ///
    /// Nothing while the record names neither, which is work that has not been sent: there is no
    /// attempt for a fence to be about, so there is nothing to ask the service.
    #[must_use]
    pub fn signing_times(&self) -> Option<(TimestampMs, TimestampMs)> {
        let first = self.first_signed_at_ms.as_ref().copied()?;
        let last = self.last_signed_at_ms.as_ref().copied()?;
        Some((first, last))
    }

    /// Returns true when an attempt signed at `signed_at` may still be made under this request's
    /// identity: when any receipt an earlier attempt of it left is certain to be at the service
    /// still, so whichever attempt runs first, every other is answered from its receipt rather than
    /// run a second time.
    ///
    /// Every attempt counts, this one included, and the whole span of their signing times is what
    /// is bounded, because an attempt signed ahead of the others can arrive after them. A record
    /// that names no signing time has not been sent, and nothing may be attempted again under it.
    #[must_use]
    pub fn may_attempt_again(&self, signed_at: TimestampMs) -> bool {
        let Some((first, last)) = self.signing_times() else {
            return false;
        };
        let earliest = first.get().min(signed_at.get());
        let latest = last.get().max(signed_at.get());
        latest - earliest <= REPLAY_SPAN_MS
    }

    /// Returns this record with one more attempt's signing time in it.
    ///
    /// The rule for every attempt in one place: the earliest instant any attempt was signed at, and
    /// the latest. They are what lets a fence say both the things it has to say, because the
    /// earliest bounds how far back a receipt of a run could go and the latest bounds how long an
    /// attempt can still become fresh.
    ///
    /// Earliest and latest rather than first written and last written, because an attempt is signed
    /// with the clock this device had at the time and that clock can be corrected between two of
    /// them. A pair taken in the order the attempts happened would then put the earliest after the
    /// latest, and each instant would have stopped bounding the thing it is there to bound.
    #[must_use]
    pub fn attempted_at(mut self, signed_at: TimestampMs) -> Self {
        let earliest = self
            .first_signed_at_ms
            .as_ref()
            .map_or(signed_at, |first| (*first).min(signed_at));
        let latest = self
            .last_signed_at_ms
            .as_ref()
            .map_or(signed_at, |last| (*last).max(signed_at));
        self.first_signed_at_ms = Nullable::some(earliest);
        self.last_signed_at_ms = Nullable::some(latest);
        self
    }

    /// Returns this record with one state in place of another.
    fn in_state(&self, state: RequestState) -> Self {
        Self {
            state,
            ..self.clone()
        }
    }
}

/// A copy kept because a comparison was lost.
///
/// Section 20 keeps a conflicting copy for the person to choose from instead of resolving it by
/// whichever clock was further ahead. What is kept is what the service held; this device's own
/// content is where it was, untouched, which is the direction section 24 makes the rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictCopy {
    /// The copy.
    pub conflict_id: SyncConflictId,
    /// The object the refused write was about.
    pub object_id: SyncObjectId,
    /// The revision this device held when the copy arrived.
    pub offered_revision: SyncRevisionId,
    /// The copy the service kept of the refused write this copy answers, when there was one.
    ///
    /// A copy kept after a refusal stands for one choice: the content this device offered, which
    /// the service kept as this copy of its own, against the content that beat it. Choosing about
    /// this copy is choosing about that one refused write and no other, so this is the one copy on
    /// the service the choice takes with it. Null for a copy a fetch brought down, which answers no
    /// refusal, and for a refusal the service kept nothing of.
    pub retained: Nullable<SyncConflictId>,
    /// The position this device expected to replace, when it made a comparison.
    ///
    /// Null for a copy that came from a fetch, which compares nothing: it asked what was there and
    /// was told, and null equally for a comparison this device made against an empty collection.
    pub expected: Nullable<SyncPosition>,
    /// Where the service held the object when the copy was taken.
    pub current: SyncPosition,
    /// What the service held, unchanged.
    pub other: SyncObject,
    /// When this device recorded the refusal.
    pub recorded_at_ms: TimestampMs,
}

/// That this device published one collection, and when.
///
/// It carries no content. It is the account of what left this device, which privacy mode keeps:
/// section 24 shows an artefact that has already been uploaded rather than claiming it was erased.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    /// The object that was published.
    pub object_id: SyncObjectId,
    /// What kind of object it was.
    pub kind: SyncObjectKind,
    /// Where the newest publication of it left the object.
    ///
    /// An applied write always has one: the service assigns the position as it applies the write
    /// and its receipt records it, so an accepted write this device learns about late still says
    /// where it landed.
    pub position: SyncPosition,
    /// When this device let the content go.
    pub published_at_ms: TimestampMs,
}

impl Publication {
    /// Returns the collection the object was published in.
    #[must_use]
    pub fn collection(&self) -> String {
        collection_of(self.kind, self.object_id)
    }
}

/// The privacy state this device records, durably.
///
/// Durably, because section 24 records the generation before any subsystem is touched: a boundary
/// a restart could not see would be a boundary a late result could cross. It lives in the store
/// rather than in memory for a second reason: every transition that has to be atomic against the
/// fence, admitting work, cancelling it and settling it, already takes the store's lock, so one
/// lock decides all of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyRecord {
    /// The host's privacy generation in force.
    pub generation: U64,
    /// Whether sync production is fenced.
    pub fenced: bool,
}

/// What the service said about one publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It accepted the write, leaving the object here. The content has left this device.
    Accepted {
        /// Where the service put the write.
        position: SyncPosition,
    },
    /// It refused the comparison, so this write did not replace the object.
    ///
    /// The request carried its ciphertext to the service, so the content did leave the device. What
    /// the refusal establishes is that the comparison did not hold, and **not** that the service
    /// kept nothing: `retained` names the copy a service that stores a rejected write kept of it.
    ///
    /// The refusal is settled on its own, before anything is fetched. What the service holds
    /// instead is brought down afterwards and kept beside this device's content; a fetch that fails
    /// costs a copy, not the knowledge that the write did not land.
    Refused {
        /// What the service called the copy it kept of the refused write, when it kept one.
        retained: Option<SyncConflictId>,
    },
}

/// What settling one publication did, and where its answer stood against what this device held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// Whether the answer was applied under the generation in force.
    pub settlement: Settlement,
    /// Where this device's own records put the object, when the answer does not follow from it.
    ///
    /// One write sequence names one write for the life of a collection, and a write takes the next
    /// place after the one it replaced, so an answer this device's records cannot follow comes from
    /// another history. Three of those records can find that, and the caller is owed it whichever
    /// did. The request's own record names the place the write replaced, and an answer at that place
    /// or behind it did not advance the object: the same write sequence is two histories claiming
    /// one place, and a smaller one is a service that went back. The note beside the object and the
    /// object's publication record each name a place another write already holds, and an answer
    /// claiming that place under another name is two histories as well. The note and the
    /// publication record are not the same comparison, because a fetch moves the note while a
    /// publication is still out and a fenced generation writes no note at all.
    ///
    /// Which of the two it is follows from the two positions: a smaller write sequence in the
    /// answer than here is a service that went back, and the same one is a fork.
    ///
    /// Nothing where none found one, including where there was nothing to compare: a refusal
    /// replaced nothing, and a request something else had already settled has nothing left.
    pub diverged: Option<SyncPosition>,
}

/// What applying one fetch's answer did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// Whether the answer was applied under the generation in force.
    pub settlement: Settlement,
    /// The copy kept beside this device's own content, when one was kept.
    pub copy: Option<SyncConflictId>,
    /// Where the answer stood against the note this device held.
    pub note: Standing,
}

/// Where one answer stands against a position this device already established.
///
/// Four answers because a rejected write is not one thing. An answer about an earlier write of the
/// same history is older news and costs nothing; an answer under the same place in the order but
/// another name is a second history, which is not a state of this one at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A later write of the object. It replaces the record this device held.
    Later,
    /// The same write, said again. The record already names it.
    Same,
    /// An earlier write of the same history, which a later answer has already overtaken.
    Earlier,
    /// Another write under the same place in the order: two histories, and neither replaces the
    /// other.
    Forked {
        /// What the record this device holds names that place in the order.
        held: SyncPosition,
    },
}

/// What ending one request at the service left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The request never ran, so nothing of it is anywhere and its record is gone.
    ///
    /// The service said so from its own records: it held no receipt for the identity, and no
    /// receipt that could have belonged to this request has ever been removed. There is nothing on
    /// the service to account for and nothing here to keep.
    NeverRan,
    /// It will never run, and whether it ran is not something the service could establish.
    ///
    /// The barrier releases, because nothing more can happen. The account stays: the ciphertext
    /// left this device, and the service may be holding it.
    Unaccounted,
    /// There was nothing to end: the work never left, or something had already ended it.
    Nothing,
}

/// What running one step under the late-result rule did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InGeneration<T> {
    /// The generation the work was started under is in force, and the step ran.
    Applied(T),
    /// Privacy mode fenced production or moved past that generation, so nothing ran.
    Discarded {
        /// The generation the work was started under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
}

/// What settling one publication did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The result was applied under the generation in force.
    Published,
    /// There was no such work to settle, because something had already settled it.
    ///
    /// Settling twice would write an effect twice. A second answer about work that is gone is
    /// therefore an answer about nothing, and it changes nothing.
    AlreadySettled,
    /// The result belonged to an earlier generation, so nothing was applied.
    ///
    /// An accepted write is still recorded as a publication, because it left this device and
    /// section 24 shows what left rather than pretending it did not. Nothing else is written: no
    /// checkpoint moves and no copy is kept, because both are retained content the cleanup that
    /// opened this generation has already removed.
    Discarded {
        /// The generation the work was produced under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
}

/// A label the person pinned.
///
/// Section 24 retains a pinned label locally unless it is explicitly cleared, and excludes it from
/// subsequent sync while privacy mode is on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedLabel {
    /// The label.
    pub label: String,
    /// When the person pinned it.
    pub pinned_at_ms: TimestampMs,
}

/// Why a synchronisation store refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The directory, the lock or a stored file could not be read or written.
    #[error("the sync store at {path} could not be used: {source}")]
    Storage {
        /// What was being read or written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// No object with that identity is stored here.
    #[error("no synchronised object {object_id} is stored")]
    Unknown {
        /// The identity that was asked for.
        object_id: SyncObjectId,
    },
    /// A restore offered an object this store already holds, or holds a note of.
    ///
    /// A restore puts an object back only where there is none: section 20 leaves the choice between
    /// two versions of one object to the person, never to whichever arrived last.
    #[error(
        "synchronised object {object_id} is already held here, or where it stood on the service is"
    )]
    AlreadyHeld {
        /// The object the restore offered.
        object_id: SyncObjectId,
    },
    /// A stored file is not something this build can read.
    #[error("the stored file at {path} could not be read: {reason}")]
    Corrupt {
        /// Which file.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// The object is larger than the contract carries.
    #[error("the object encodes to {len} bytes; the limit is {limit}")]
    TooLarge {
        /// The encoded size.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The object that came down is not the one this collection was asked for.
    #[error("collection {collection} holds object {found}, not {expected}")]
    NotThatObject {
        /// The collection that was read.
        collection: String,
        /// The object it turned out to hold.
        found: SyncObjectId,
        /// The object that was asked for.
        expected: SyncObjectId,
    },
    /// The work has already been sent once.
    ///
    /// One piece of staged work leaves this device once. What a request whose owner is gone needs
    /// is a claim and a question about it, never a second departure under one account of it.
    #[error("request {work_id} has already been dispatched")]
    AlreadyDispatched {
        /// The request.
        work_id: Uuid,
    },
    /// A call for this publication is out, and its answer is what settles it.
    ///
    /// A later attempt presents the same identity and the same bytes, so two attempts at once would
    /// be one request sent twice with nobody able to say which answer came back. The attempt that
    /// is out finishes first, and asking again afterwards either finds the publication settled or
    /// makes the next attempt.
    #[error("a call for request {work_id} is out; its answer settles it")]
    InFlight {
        /// The request the call is out for.
        work_id: Uuid,
    },
    /// The dispatch that was presented is another request's.
    ///
    /// A settlement and a discard are decided under the dispatch they belong to, so the store can
    /// refuse a decision no owner is holding. A claim on one request says nothing about another.
    #[error("that dispatch is for request {holding}, not {wanted}")]
    OtherRequest {
        /// The request the dispatch is held for.
        holding: Uuid,
        /// The request the caller named.
        wanted: Uuid,
    },
    /// A draft arrived where a settings object was expected.
    ///
    /// A draft belongs to the device's draft store and is published by its own synchronised half.
    /// Nothing here applies one, which is what keeps one way of writing a draft.
    #[error("collection {collection} holds a draft; drafts are synchronised by the draft store")]
    DraftElsewhere {
        /// The collection that was read.
        collection: String,
    },
    /// Sync production is fenced, because privacy mode is on.
    #[error("sync production is fenced at privacy generation {generation}")]
    Fenced {
        /// The generation it was fenced at.
        generation: u64,
    },
    /// The answer belonged to a privacy generation that is no longer in force.
    ///
    /// Nothing it brought down was written. Section 24 publishes no late old-generation result,
    /// and a copy or a note written now would be content the cleanup had already removed.
    #[error("that answer was produced under generation {produced_under}; {current} is in force")]
    LateResult {
        /// The generation the work was produced under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
    /// The service holds an earlier write of the object than this device's note names.
    ///
    /// A service that was reset or replaced leaves one, and so does one restored from a backup.
    /// Write sequences only ever go forward, so a smaller one is provable rather than guessed at,
    /// whether a fetch shows it or the answer to one of this device's own writes puts the write
    /// behind the place it replaced. The publication is refused and there is nothing to fetch;
    /// forgetting the checkpoint is the explicit recovery, and nothing does it automatically.
    #[error(
        "object {object_id} reached write {expected} on the service, which now holds write {found}; forget its checkpoint to start again"
    )]
    StaleCheckpoint {
        /// The object.
        object_id: SyncObjectId,
        /// The write sequence the note names.
        expected: u64,
        /// The write sequence the service answered with.
        found: u64,
    },
    /// The service answered with a position no write of this object could be at.
    ///
    /// A place in the order counts from one, and a write that produced content is named by a
    /// revision; a position with neither is the removal of the object, which is not something a
    /// write of it can have produced. Nothing here invents the missing part: an answer this device
    /// cannot read is an answer it declines rather than one it guesses at.
    #[error(
        "object {object_id} was answered with {found}, which is not where a write of it can be"
    )]
    NotAWrite {
        /// The object.
        object_id: SyncObjectId,
        /// The position the service answered with.
        found: SyncPosition,
    },
    /// The service holds a different write of the object under the same place in its order.
    ///
    /// Two devices cannot produce this: one write sequence names one write for the life of a
    /// collection, and a write takes the next place after the one it replaced, so an answer that
    /// puts one of this device's writes at the very place that write replaced is this case too. A service whose history forked can, and so can a collection rebuilt from
    /// somewhere else, and neither is something this device may write a note from. The recovery is
    /// the same as for a service that went back: forget the checkpoint and start the object again.
    #[error(
        "object {object_id} reached {expected} on the service, which now holds {found} in that same place; forget its checkpoint to start again"
    )]
    ForkedHistory {
        /// The object.
        object_id: SyncObjectId,
        /// The position the note names.
        expected: SyncPosition,
        /// The position the service answered with, under the same write sequence.
        found: SyncPosition,
    },
    /// The client failed.
    #[error("{0}")]
    Client(#[from] Box<crate::ClientError>),
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("the stored value was not canonical: {0}")]
    Encoding(#[from] kr_cbor::CborError),
    /// The sealing or opening of an object failed.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
}

impl From<crate::ClientError> for SyncError {
    fn from(error: crate::ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

impl SyncError {
    /// Returns the stable protocol code this refusal is reported under.
    ///
    /// A local store is not a host, and the codes are a vocabulary rather than a claim about one.
    /// What a person is told comes from [`Self::user_action`].
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Storage { .. } => ErrorCode::StorageUnavailable,
            Self::Unknown { .. }
            | Self::Corrupt { .. }
            | Self::TooLarge { .. }
            | Self::NotThatObject { .. }
            | Self::AlreadyDispatched { .. }
            | Self::OtherRequest { .. }
            | Self::DraftElsewhere { .. }
            | Self::NotAWrite { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => ErrorCode::InvalidArgument,
            Self::Fenced { .. } | Self::LateResult { .. } => ErrorCode::PermissionDenied,
            Self::StaleCheckpoint { .. } | Self::ForkedHistory { .. } => ErrorCode::DraftConflict,
            // What became of the publication is not known yet, and what makes it known is the
            // answer to the call that is out rather than another one beside it.
            Self::InFlight { .. } => ErrorCode::OutcomeUnknown,
            Self::AlreadyHeld { .. } => ErrorCode::IdConflict,
            Self::Client(error) => error.code(),
        }
    }

    /// Returns the direct action a user interface offers for this refusal.
    #[must_use]
    pub fn user_action(&self) -> UserAction {
        match self {
            Self::Storage { .. } => UserAction::FixConfiguration,
            Self::Client(error) => error.user_action(),
            // The message is the whole of it: choose a copy, shorten the settings, turn privacy
            // mode off, start the object again against the service this device now uses, or keep
            // the settings this device already holds.
            Self::Unknown { .. }
            | Self::AlreadyHeld { .. }
            | Self::Corrupt { .. }
            | Self::TooLarge { .. }
            | Self::NotThatObject { .. }
            | Self::AlreadyDispatched { .. }
            | Self::InFlight { .. }
            | Self::OtherRequest { .. }
            | Self::DraftElsewhere { .. }
            | Self::NotAWrite { .. }
            | Self::Fenced { .. }
            | Self::LateResult { .. }
            | Self::StaleCheckpoint { .. }
            | Self::ForkedHistory { .. }
            | Self::Encoding(_)
            | Self::Crypto(_) => UserAction::Nothing,
        }
    }
}

/// The result of a synchronisation call.
pub type Result<T> = std::result::Result<T, SyncError>;

/// What a listing found, including what it could not read.
///
/// A damaged file is named rather than dropped and rather than deleted. A conflict copy is content
/// a person is meant to choose between and a publication record is the only account of what left
/// this device; neither is a cache this store may throw away because a byte went wrong.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing<T> {
    /// What was read, oldest first.
    pub items: Vec<T>,
    /// The files that are not records this build reads.
    pub unreadable: Vec<PathBuf>,
}

impl<T> Listing<T> {
    /// Returns how many records were read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when nothing was read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Every account of what has left this device, read together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhatLeft {
    /// The collections this device published, and where each write landed.
    pub publications: Listing<Publication>,
    /// Every request this device holds a record of, wherever each one got to.
    ///
    /// What each one says about content that left is decided by its state: work that was admitted
    /// and never sent left nothing, a dispatch with no answer may have left everything, and a
    /// refusal the service kept a copy of left ciphertext the service still holds.
    pub requests: Listing<RequestRecord>,
}

/// This device's own synchronisation state, on this device's disk.
///
/// The directory is the caller's, as the draft store's is: a desktop application puts it under its
/// own support directory, a command line under the user's state directory, a test under a
/// temporary one. The store creates it owner-only where the platform expresses that, and writes
/// every file whole or not at all.
///
/// Every method blocks, on the filesystem and on the store's lock.
#[derive(Debug)]
pub struct SyncStore {
    directory: PathBuf,
}

impl SyncStore {
    /// Opens or creates the store.
    ///
    /// A file left behind by a process that died while writing is swept away here, because a
    /// partial name is not a record and the next writer would otherwise walk past it for ever.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be created, made owner-only or
    /// read.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        private_directory(&directory).map_err(|source| storage(&directory, source))?;
        // Every name on the way here, not only the levels this call created. Another opener may
        // have created one a moment ago and not yet flushed it, and a store that returned success
        // under such a name would be a store whose own path a crash could lose. A failure is
        // reported rather than ignored: a store that cannot open the directories its path is made
        // of cannot establish that the path survives a crash.
        flush_path_names(&directory).map_err(|source| storage(&directory, source))?;
        let store = Self { directory };
        let guard = store.lock()?;
        let swept = store.sweep_partials();
        drop(guard);
        swept?;
        Ok(store)
    }

    /// Returns the directory this store keeps its files in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    // -- objects this device holds ------------------------------------------------------------

    /// Returns the object this device holds, when it holds one.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn object(&self, object_id: SyncObjectId) -> Result<Option<SyncObject>> {
        let guard = self.lock()?;
        let outcome = self.read_object(object_id);
        drop(guard);
        outcome
    }

    /// Reads an object and the note beside it under one hold of the lock.
    ///
    /// Together, because a publication decides from both: the revision it is sending and the
    /// generation it expects to replace. Read separately, another writer could advance the object
    /// between them, and this one would send an older revision against the newer position, which
    /// is a comparison it would win, replacing content it had never seen.
    ///
    /// # Errors
    ///
    /// As [`Self::object`] and [`Self::checkpoint`].
    pub fn object_and_checkpoint(
        &self,
        object_id: SyncObjectId,
    ) -> Result<(Option<SyncObject>, Option<SyncCheckpoint>)> {
        let guard = self.lock()?;
        let outcome = self
            .read_object(object_id)
            .and_then(|object| Ok((object, self.read_checkpoint(object_id)?)));
        drop(guard);
        outcome
    }

    /// Reads one stored object and checks that it is the object its own name says it is.
    ///
    /// The caller holds the lock.
    fn read_object(&self, object_id: SyncObjectId) -> Result<Option<SyncObject>> {
        let path = self.path(object_id, OBJECT_EXTENSION);
        let Some(object): Option<SyncObject> = self.read_optional(&path)? else {
            return Ok(None);
        };
        if object.object_id != object_id {
            return Err(SyncError::Corrupt {
                path,
                reason: format!("it holds object {}, not {object_id}", object.object_id),
            });
        }
        Ok(Some(object))
    }

    /// Replaces the object this device holds.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::TooLarge`] when the record is past what one synchronised object
    /// carries, and [`SyncError::Storage`] when it cannot be written.
    pub fn put_object(&self, object: &SyncObject) -> Result<()> {
        let bytes = encode_within(object)?;
        let guard = self.lock()?;
        let outcome = self.write_bytes(&self.path(object.object_id, OBJECT_EXTENSION), &bytes.0);
        drop(guard);
        outcome
    }

    /// Reads an object for a backup, with the privacy generation it was read under.
    ///
    /// The privacy state and the object are read under one hold of the lock, as an admission reads
    /// them: section 24 disables backup production as it disables sync production, and a fence
    /// that landed between the two reads would let a backup carry an object read after it. The
    /// generation goes with the object so that whatever produces the backup can publish it only
    /// under the generation still in force.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::Unknown`] when no such
    /// object is stored, and [`SyncError::Storage`] or [`SyncError::Corrupt`] otherwise.
    pub fn read_for_backup(&self, object_id: SyncObjectId) -> Result<(SyncObject, u64)> {
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced {
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            let object = self
                .read_object(object_id)?
                .ok_or(SyncError::Unknown { object_id })?;
            Ok((object, privacy.generation.get()))
        })();
        drop(guard);
        outcome
    }

    /// Puts back an object a restore took out of a backup, as this device's own.
    ///
    /// Only into a store that holds neither the object nor a note of where it stood. Replacing an
    /// object this device holds would choose between two versions of it by which arrived last,
    /// which section 20 leaves to the person; and an object written beside a note would compare
    /// against a place on a service the restored object never reached. Nothing is written beside
    /// it, so its first publication compares against nothing and learns from the service where the
    /// object stands. The check and the write are one hold of the lock.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::AlreadyHeld`] when the store holds the object or a note of it,
    /// [`SyncError::TooLarge`] when the record is past what one synchronised object carries, and
    /// [`SyncError::Storage`] or [`SyncError::Corrupt`] otherwise.
    pub fn put_restored(&self, object: &SyncObject) -> Result<()> {
        let bytes = encode_within(object)?;
        let guard = self.lock()?;
        let outcome = (|| {
            let object_id = object.object_id;
            if self.read_object(object_id)?.is_some() || self.read_checkpoint(object_id)?.is_some()
            {
                return Err(SyncError::AlreadyHeld { object_id });
            }
            self.write_bytes(&self.path(object_id, OBJECT_EXTENSION), &bytes.0)
        })();
        drop(guard);
        outcome
    }

    // -- checkpoints --------------------------------------------------------------------------

    /// Returns where an object last reached on the service, when it has.
    ///
    /// A note this build cannot read is removed and reported as absent. It is a cache: the next
    /// publication compares against nothing, learns where the object stands from the service, and
    /// writes the note again.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be read or removed.
    pub fn checkpoint(&self, object_id: SyncObjectId) -> Result<Option<SyncCheckpoint>> {
        let guard = self.lock()?;
        let outcome = self.read_checkpoint(object_id);
        drop(guard);
        outcome
    }

    /// Records where an object reached on the service.
    ///
    /// A note that already names a later generation stands, and this returns false. Two answers can
    /// arrive out of order: a publication is accepted, another device writes, a fetch brings that
    /// down, and only then does the first answer come back naming the write before it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be read or written.
    pub fn record_checkpoint(
        &self,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
    ) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = self.write_checkpoint(object_id, checkpoint);
        drop(guard);
        Ok(matches!(outcome?, Standing::Later | Standing::Same))
    }

    /// Writes a checkpoint unless the note that stands does not follow from this answer.
    ///
    /// Later is decided by the write sequence alone, which is the service's own order, because two
    /// answers can arrive out of order and the revision beside the sequence names the write rather
    /// than ordering it. A note naming a later write therefore stands.
    ///
    /// A note naming the *same* write under another name stands as well, and that is the second
    /// rule rather than a corner of the first. One write sequence names one write for the life of
    /// a collection, so two answers claiming one place in the order come from two histories, and
    /// replacing a note this device established with one from the other history would leave it
    /// comparing against a state the service it is talking to may never have held.
    ///
    /// The caller holds the lock.
    fn write_checkpoint(
        &self,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
    ) -> Result<Standing> {
        if checkpoint.position.write_sequence == 0 {
            // A place in the order counts from one. Nought is what the service says of an object it
            // has never held, and this contract says that by carrying no position at all.
            return Err(SyncError::NotAWrite {
                object_id,
                found: checkpoint.position,
            });
        }
        let bytes = kr_cbor::to_canonical_vec(&checkpoint)?;
        let stands = match self.read_checkpoint(object_id)? {
            Some(held) => standing(held.position, checkpoint.position),
            None => Standing::Later,
        };
        if matches!(stands, Standing::Earlier | Standing::Forked { .. }) {
            return Ok(stands);
        }
        self.write_bytes(&self.path(object_id, CHECKPOINT_EXTENSION), &bytes)?;
        Ok(stands)
    }

    /// Forgets where an object reached on the service.
    ///
    /// A device signed out of the service, or starting again against a different one, has a note
    /// naming a write nothing holds. Forgetting it costs the next publication a comparison and
    /// a fetch; keeping it costs a comparison against a number that means nothing. Nothing does it
    /// automatically, because a note that looks stale and is not is a note whose object another
    /// device has just written.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the note cannot be removed.
    pub fn forget_checkpoint(&self, object_id: SyncObjectId) -> Result<()> {
        let guard = self.lock()?;
        let outcome = self.remove_file(&self.path(object_id, CHECKPOINT_EXTENSION));
        drop(guard);
        outcome
    }

    // -- staged ciphertext --------------------------------------------------------------------

    /// Reads this device's privacy state.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn privacy(&self) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = self.read_privacy();
        drop(guard);
        outcome
    }

    /// Records the privacy generation and whether production is fenced.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when it cannot be written. A generation this device cannot
    /// record is not one it claims to be in: the caller is told rather than left believing a
    /// boundary exists.
    pub fn record_privacy(&self, record: PrivacyRecord) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = (|| {
            // A generation never goes backwards. Two control steps that overlap would otherwise
            // let the older one restore a boundary a newer one had already moved past, and every
            // result admitted under the newer generation would become acceptable again.
            let held = self.read_privacy()?;
            if held.generation.get() > record.generation.get() {
                return Ok(held);
            }
            let bytes = kr_cbor::to_canonical_vec(&record)?;
            self.write_bytes(&self.directory.join(PRIVACY_NAME), &bytes)?;
            Ok(record)
        })();
        drop(guard);
        outcome
    }

    /// Moves the generation forward, leaving the fence where it is, under one hold.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read or written.
    pub fn advance_privacy(&self, generation: u64) -> Result<PrivacyRecord> {
        let guard = self.lock()?;
        let outcome = (|| {
            let held = self.read_privacy()?;
            if held.generation.get() >= generation {
                return Ok(held);
            }
            let record = PrivacyRecord {
                generation: U64::new(generation),
                fenced: held.fenced,
            };
            let bytes = kr_cbor::to_canonical_vec(&record)?;
            self.write_bytes(&self.directory.join(PRIVACY_NAME), &bytes)?;
            Ok(record)
        })();
        drop(guard);
        outcome
    }

    /// Admits one object for publication, under one hold of the lock.
    ///
    /// The fence check, the object and its note, the sealing and the staged record are one step.
    /// Split apart, a fence could land between the check and the record, and the work would be
    /// admitted under a generation privacy mode had already closed.
    ///
    /// `seal` is given the object to encrypt. It runs inside the hold, which is what makes the
    /// generation the record names the generation that was in force when the ciphertext was made.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::Unknown`] when no such
    /// object is stored, whatever `seal` failed with, and [`SyncError::Storage`] when the record
    /// cannot be written.
    pub fn admit(
        &self,
        object_id: SyncObjectId,
        seal: impl FnOnce(&SyncObject) -> Result<Vec<u8>>,
    ) -> Result<RequestRecord> {
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced {
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            let object = self
                .read_object(object_id)?
                .ok_or(SyncError::Unknown { object_id })?;
            let note = self.read_checkpoint(object_id)?;
            let ciphertext = seal(&object)?;
            let record = RequestRecord {
                // A fresh identity nothing else can know yet, which is why admission needs no claim
                // on the request: there is no request to claim until this record exists.
                work_id: self.fresh_id()?,
                object_id,
                kind: object.kind(),
                revision: RequestRevision::Object(object.revision),
                // No note is no position, which is the comparison a first publication makes: it
                // says nothing is there rather than naming a place nothing occupies.
                expected: note.map_or(Nullable::null(), |note| Nullable::some(note.position)),
                produced_under: privacy.generation,
                first_signed_at_ms: Nullable::null(),
                last_signed_at_ms: Nullable::null(),
                state: RequestState::Admitted {
                    ciphertext: Bytes::new(ciphertext),
                },
            };
            self.write_request(&record)?;
            Ok(record)
        })();
        drop(guard);
        outcome
    }

    /// Returns every request this device holds a record of, oldest identifier first.
    ///
    /// What a stop left half finished is completed first, under the same hold, so a caller never
    /// sees a request in a state something else was in the middle of leaving.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn requests(&self) -> Result<Listing<RequestRecord>> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.finish_settlements()?;
            self.read_requests()
        })();
        drop(guard);
        outcome
    }

    /// Takes ownership of one dispatch and records that the work has been sent, under the instant
    /// the attempt is signed at.
    ///
    /// What goes to the service comes back out of the record this call wrote: the bytes, which were
    /// sealed once at admission so that every attempt under that identity carries the same ones and
    /// a service can answer a retry from its receipt, and the signing time, which is what a fence is
    /// later read against. A caller that signed with an instant of its own would be concluding from
    /// a reading nothing wrote down.
    ///
    /// The record is written before the call leaves, so a device that stops between the write and
    /// the answer still knows this may have reached the service. The fence is checked here too: a
    /// fence that lands after admission still reaches work that has not gone, and it takes the
    /// record back rather than letting the queue empty itself.
    ///
    /// Ownership is the store's and not the caller's. The returned [`Dispatch`] holds an exclusive
    /// operating-system lock on the request, so another client value, another window and another
    /// process all meet it, and none of them may decide what became of this request while somebody
    /// is still waiting for the answer. Releasing it says this device's call is over, never that
    /// the request stopped at the service.
    ///
    /// The request's own lock is taken **before** the store's, as it is everywhere that waits for
    /// both, so two of them can never wait on each other.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] when privacy mode reached this work before it left,
    /// [`SyncError::Storage`] when the record or the lock cannot be read or written, and
    /// [`SyncError::Unknown`] when nothing is recorded under that work identifier.
    pub fn begin_dispatch(
        &self,
        work_id: Uuid,
        object_id: SyncObjectId,
        signed_at: TimestampMs,
    ) -> Result<(Dispatch, Bytes, TimestampMs)> {
        let owned = Lock::take(&self.named(work_id, CALLOUT_EXTENSION))?;
        let path = self.named(work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            let Some(held) = self.read_request(&path)? else {
                // Nothing is recorded under that identity, so there is no dispatch to own and the
                // lock this call took names nothing.
                self.retire(work_id)?;
                return Err(SyncError::Unknown { object_id });
            };
            // One piece of work leaves this device once. A second dispatch of a record that has
            // already gone would be a second departure under one account of it, and what a request
            // whose owner is gone needs is a claim and a question rather than another call.
            let RequestState::Admitted { ciphertext } = held.state.clone() else {
                return Err(SyncError::AlreadyDispatched { work_id });
            };
            // The fence is checked here as well as at admission, because a fence can land between
            // the two. This work has not left, so the fence still reaches it: the record is taken
            // back rather than sent, which is exactly what the cancellation would have done to it.
            if privacy.fenced || privacy.generation.get() != held.produced_under.get() {
                self.retire(work_id)?;
                self.remove_file(&path)?;
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            // The state and the instant the content is signed away are one replacement, so a
            // record that says it was sent always says when it was signed. The rule for which
            // instant a further attempt moves lives on the record itself.
            let sent = RequestRecord {
                state: RequestState::Dispatched { ciphertext },
                ..held.attempted_at(signed_at)
            };
            self.write_request(&sent)?;
            let signed_at = sent.left_at();
            let RequestState::Dispatched { ciphertext } = sent.state else {
                // The state was written two statements above and it is the only one this reaches.
                unreachable!("the record this call wrote says it was dispatched");
            };
            Ok((ciphertext, signed_at))
        })();
        drop(guard);
        let (ciphertext, signed_at) = outcome?;
        Ok((
            Dispatch {
                directory: self.directory.clone(),
                work_id,
                _lock: owned,
            },
            ciphertext,
            signed_at,
        ))
    }

    /// Claims one dispatched request, so that this device may decide what became of it.
    ///
    /// A claim is what the store grants instead of a client deciding for itself. It succeeds only
    /// when nobody holds the request: a process that died released its lock, which is why a claim
    /// can succeed after a crash, and what the claim then permits is **asking** the service, never
    /// concluding. The service's answer is what settles the request.
    ///
    /// The record comes back as the store holds it, not as a caller remembers it, and the claim is
    /// held for as long as the returned [`Dispatch`] lives, so a settlement decided under it cannot
    /// race a fresh dispatch of the same request.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the lock or the record cannot be read.
    pub fn claim_dispatched(&self, work_id: Uuid) -> Result<Claimed> {
        let Some(owned) = Lock::try_take(&self.named(work_id, CALLOUT_EXTENSION))? else {
            return Ok(Claimed::InHand);
        };
        let path = self.named(work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let held = self.read_request(&path);
        drop(guard);
        Ok(match held? {
            Some(record) if record.dispatched() => Claimed::Taken(
                Dispatch {
                    directory: self.directory.clone(),
                    work_id,
                    _lock: owned,
                },
                Box::new(record),
            ),
            _ => Claimed::Gone,
        })
    }

    /// Claims one request, whether or not this store still holds a staged record for it.
    ///
    /// A late answer is a decision about a request as much as a settlement is, and a request whose
    /// staged record has gone can still receive one: it was discarded, or something else settled
    /// it. Deciding about it takes the same lock, so a claim here is what a caller holding no
    /// dispatch of its own presents.
    ///
    /// Returns nothing when somebody has a call out for the request.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the lock cannot be taken.
    pub fn claim_request(&self, work_id: Uuid) -> Result<Option<Dispatch>> {
        Ok(
            Lock::try_take(&self.named(work_id, CALLOUT_EXTENSION))?.map(|owned| Dispatch {
                directory: self.directory.clone(),
                work_id,
                _lock: owned,
            }),
        )
    }

    /// Makes one attempt at publishing a draft: the first, which admits the publication, or a later
    /// one, which presents the publication already out for that revision again.
    ///
    /// A publication is one piece of work. Its identity is chosen when it is admitted and never
    /// again, and its bytes are sealed once, so every attempt at it presents the same identity, the
    /// same bytes and the same comparison, and a service that already ran it answers the later
    /// attempt from its receipt rather than running it twice. Which publication an attempt belongs
    /// to is the draft and the revision it carries. A draft edited since is other content, and so
    /// another publication. So is one admitted under a privacy generation that is no longer in
    /// force: no attempt now could publish its answer, and ending it is a reconciliation's work.
    ///
    /// A later attempt is made only while it is a replay, which is while every attempt under the
    /// identity is signed within one freshness window of every other
    /// ([`RequestRecord::may_attempt_again`]). Past that, presenting the identity again could run
    /// the work a second time, or be refused in a way that says nothing about the first attempt
    /// and overwrites the account of it. So the earlier publication is left as it is, counted and
    /// with its own account, for a reconciliation to end, and this admits a new publication of the
    /// same content under an identity of its own. The service's comparison is what keeps the two
    /// from both landing.
    ///
    /// Each attempt records the instant it is signed at, through [`RequestRecord::attempted_at`], in
    /// the same replacement that writes the record, so a record that says it was sent always says
    /// when, and the two instants a fence carries bound every attempt that was made.
    ///
    /// Admission and the first attempt are one step, under the hold the fence is decided in, so no
    /// draft publication waits between the two for a fence to find: a fence that lands first refuses
    /// the publication, and one that lands afterwards finds it recorded as sent. Nothing here sends
    /// anything, and nothing makes an attempt on its own: section 23 retries nothing whose outcome is
    /// unknown, so a later attempt is always a caller asking for one.
    ///
    /// The returned [`Attempt`] owns the dispatch. The request's lock is tried rather than waited
    /// for, inside this store's hold, and a try waits on nothing, so the order the two locks are
    /// taken in elsewhere is kept: a call already out for the publication refuses this attempt
    /// instead of queueing behind it.
    ///
    /// `seal` runs only for a publication admitted here, inside the hold, so the ciphertext is made
    /// under the generation the record names.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::InFlight`] when a call
    /// for the publication is out, whatever `seal` failed with, and [`SyncError::Storage`] when a
    /// record or a lock cannot be read or written.
    pub fn attempt_draft(
        &self,
        draft_id: DraftId,
        revision: DraftRevision,
        expected: Option<SyncPosition>,
        signed_at: TimestampMs,
        seal: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Attempt> {
        let object_id = SyncObjectId::new(draft_id.get());
        let revision = RequestRevision::Draft(revision);
        let guard = self.lock()?;
        let outcome = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced {
                return Err(SyncError::Fenced {
                    generation: privacy.generation.get(),
                });
            }
            // The publication already out for this revision, under the generation in force. A
            // record this build cannot read is not one an attempt can be made from, so it is left
            // where it is and counted, as it is everywhere else.
            let out =
                self.read_requests()?
                    .items
                    .into_iter()
                    .find_map(|record| match &record.state {
                        RequestState::Dispatched { ciphertext }
                            if record.kind == SyncObjectKind::Draft
                                && record.object_id == object_id
                                && record.revision == revision
                                && record.produced_under == privacy.generation
                                && record.may_attempt_again(signed_at) =>
                        {
                            Some((ciphertext.clone(), record))
                        }
                        _ => None,
                    });
            if let Some((ciphertext, held)) = out {
                let Some(lock) = Lock::try_take(&self.named(held.work_id, CALLOUT_EXTENSION))?
                else {
                    return Err(SyncError::InFlight {
                        work_id: held.work_id,
                    });
                };
                let sent = held.attempted_at(signed_at);
                self.write_request(&sent)?;
                return Ok((sent, ciphertext, lock));
            }

            let ciphertext = Bytes::new(seal()?);
            // A fresh identity nothing else can know yet, and its lock taken before its record is
            // written, so there is no moment at which the record is on disk and nobody holds it.
            let work_id = self.fresh_id()?;
            let Some(lock) = Lock::try_take(&self.named(work_id, CALLOUT_EXTENSION))? else {
                return Err(SyncError::InFlight { work_id });
            };
            let sent = RequestRecord {
                work_id,
                object_id,
                kind: SyncObjectKind::Draft,
                revision,
                // No note is no position, which is the comparison a first publication makes.
                expected: Nullable::from(expected),
                produced_under: privacy.generation,
                first_signed_at_ms: Nullable::null(),
                last_signed_at_ms: Nullable::null(),
                state: RequestState::Dispatched {
                    ciphertext: ciphertext.clone(),
                },
            }
            .attempted_at(signed_at);
            if let Err(error) = self.write_request(&sent) {
                // Nothing names this identity, so the lock it was given names nothing either.
                drop(lock);
                self.retire(work_id)?;
                return Err(error);
            }
            Ok((sent, ciphertext, lock))
        })();
        drop(guard);
        let (record, ciphertext, lock) = outcome?;
        Ok(Attempt {
            dispatch: Dispatch {
                directory: self.directory.clone(),
                work_id: record.work_id,
                _lock: lock,
            },
            record,
            ciphertext,
            signed_at,
        })
    }

    /// Closes one dispatched request the service will never execute, leaving no account.
    ///
    /// Two answers establish that, and only these two. A **fence** the service honoured says it
    /// recorded no outcome for the identity and will refuse one afterwards. An identity refused
    /// because a different request already wore it says the same thing about this payload: the
    /// service compared the content against the receipt it holds and declined to run this one.
    /// Neither is a guess about a request that might still be on its way, which is why nothing
    /// else may use this.
    ///
    /// No account is left because nothing of this request is on the service: it executed nothing
    /// and never will. That is the one case where removing a dispatched record loses nothing, and
    /// it is what lets a privacy cleanup finish instead of counting a request for ever.
    ///
    /// One sealing per piece of work is what makes the second case safe. The ciphertext is sealed
    /// once, at admission, and every attempt sends those same bytes, so an identity refused for
    /// carrying different content is refused for content this device never sent under it.
    ///
    /// Returns true when a record was closed, false when the work was never sent or something had
    /// already settled it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::OtherRequest`] when the dispatch is held for a different request, and
    /// [`SyncError::Storage`] when a record cannot be read or removed.
    pub fn close_unexecuted(&self, dispatch: &Dispatch, work_id: Uuid) -> Result<bool> {
        dispatch.owns(&self.directory, work_id)?;
        let path = self.named(work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            // The record on disk decides, never the copy a caller holds: a record that is gone is
            // work something else settled while this call was out.
            let Some(held) = self.read_request(&path)? else {
                return Ok(false);
            };
            // Work that was never sent is [`Self::take_back_undispatched`]'s, and work the service
            // has already answered about has an account of its own.
            if !held.dispatched() {
                return Ok(false);
            }
            self.remove_file(&path)?;
            self.retire(work_id)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    /// Ends one dispatched request the service has fenced, and says what that leaves behind.
    ///
    /// A fence always ends the request: nothing executes under the identity afterwards, so this
    /// device stops waiting for it either way. What it leaves behind is what the service said about
    /// the past, which the caller passes in as `never_ran`.
    ///
    /// Where the service established that the request never ran, nothing of it is anywhere and the
    /// record goes with no account kept. Where it could not, the ciphertext may be on the service
    /// and may never have arrived, and a device that deleted the account because it could not tell
    /// which would be hiding an upload rather than undoing one. The record stays, with no content
    /// in it.
    ///
    /// **No clock is read here and no instants are compared.** The service holds every receipt and
    /// knows how far back its own reach; a device comparing its reading with the service's could be
    /// wrong in the direction that deletes the account of an upload that happened.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::OtherRequest`] when the dispatch is held for a different request, and
    /// [`SyncError::Storage`] when a record cannot be read, written or removed.
    pub fn close_fenced(&self, dispatch: &Dispatch, work_id: Uuid, never_ran: bool) -> Result<End> {
        dispatch.owns(&self.directory, work_id)?;
        let path = self.named(work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            // The record on disk decides, never the copy a caller holds.
            let Some(held) = self.read_request(&path)? else {
                return Ok(End::Nothing);
            };
            if !held.dispatched() {
                return Ok(End::Nothing);
            }
            if never_ran {
                self.remove_file(&path)?;
                self.retire(work_id)?;
                return Ok(End::NeverRan);
            }
            self.write_request(&held.in_state(RequestState::Unaccounted))?;
            self.retire(work_id)?;
            Ok(End::Unaccounted)
        })();
        drop(guard);
        outcome
    }

    /// Returns true when privacy mode has moved past the generation that admitted this work.
    ///
    /// It is the question a reconciliation asks before it fences a request: under the generation
    /// in force the work is still wanted and the next pass asks about it again, and past that
    /// generation no answer to it could ever be published, so ending it at the service is the only
    /// thing that can complete the cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the privacy record cannot be read.
    pub fn beyond_its_generation(&self, record: &RequestRecord) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = self.read_privacy();
        drop(guard);
        Ok(outcome?.generation.get() > record.produced_under.get())
    }

    /// Takes back every piece of work that was admitted and never sent.
    ///
    /// Reading which records are undispatched and deleting them is one step, so a publication that
    /// marks itself dispatched cannot have its record taken away as though it had never gone.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be read or removed.
    pub fn take_back_undispatched(&self, generation: u64) -> Result<u64> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.owns_cleanup(generation)?;
            let mut taken = 0_u64;
            for item in self.read_requests()?.items {
                // Work admitted under a later generation belongs to a later cleanup, not this one.
                if !item.admitted() || item.produced_under.get() > generation {
                    continue;
                }
                self.remove_file(&self.named(item.work_id, REQUEST_EXTENSION))?;
                taken = taken.saturating_add(1);
            }
            Ok(taken)
        })();
        drop(guard);
        outcome
    }

    /// Returns how much dispatched work has no settled outcome.
    ///
    /// A record this build cannot read counts too. A store cannot say that nothing is outstanding
    /// on the strength of a record it could not open.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn unsettled(&self) -> Result<u64> {
        let requests = self.requests()?;
        let dispatched = requests
            .items
            .iter()
            .filter(|item| item.dispatched())
            .count() as u64;
        Ok(dispatched.saturating_add(requests.unreadable.len() as u64))
    }

    /// Applies what the service answered, under the late-result rule, in one step.
    ///
    /// The generation is read and the effects are written under one hold, so a fence cannot land
    /// between deciding that a result may be applied and applying it. Settling the same work twice
    /// writes nothing the second time, because the answer is applied to the one record of the
    /// request and that record says it is already settled.
    ///
    /// An accepted write always records the publication, whatever generation is in force, because
    /// the content left this device and section 24 shows what left rather than pretending it did
    /// not. Under a late generation nothing else is written: the checkpoint would move on the
    /// strength of work privacy mode had already cancelled.
    ///
    /// It settles **this** request and nothing else. An answer about the object says what the
    /// service holds; it does not say what became of another request that is still out, and a
    /// request that had no answer can still be accepted afterwards. Retiring one on the strength of
    /// the other would be claiming knowledge this contract cannot give.
    ///
    /// An answer to work a reconciliation discarded corrects the account of what left rather than
    /// changing nothing: the generation that admitted it has been fenced either way, so nothing is
    /// published, but an accepted write becomes a publication record instead of a dispatch nothing
    /// could account for.
    ///
    /// It is decided under the dispatch the request is claimed by, so a second caller cannot settle
    /// a request somebody is still waiting on, and an answer is applied only where the record the
    /// store holds still expects one.
    ///
    /// A draft's note is the draft store's rather than this store's, so an accepted draft
    /// publication under the generation in force is [`Self::settle_draft`]'s to settle. This refuses
    /// one rather than leave the note behind; every other answer about a draft it settles as it
    /// settles a setting, because none of them writes a note.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::OtherRequest`] when the dispatch is held for a different request,
    /// [`SyncError::DraftElsewhere`] for an accepted draft publication under the generation in
    /// force, and [`SyncError::Storage`] when a record cannot be written or removed.
    pub fn settle(
        &self,
        dispatch: &Dispatch,
        record: &RequestRecord,
        outcome: Outcome,
    ) -> Result<Settled> {
        self.settle_noting(dispatch, record, outcome, None)
    }

    /// Applies what the service answered about one draft publication, and moves the draft's note in
    /// the draft store it belongs to.
    ///
    /// Everything [`Self::settle`] does, with the note written where a draft's note lives. It is
    /// written inside this store's hold and before the record that ends the request, for the reason
    /// a setting's is: a stop between the two leaves the note ahead of a request that is still
    /// counted, and the next settlement writes it again. It moves only for an accepted write, under
    /// the generation in force, that this device's records can follow, and a note that already names
    /// a later write stands, so an answer that is older news never takes it back.
    ///
    /// # Errors
    ///
    /// As [`Self::settle`], and whatever the draft store failed with when the note could not be
    /// written, in which case the request is left where it was.
    pub fn settle_draft(
        &self,
        dispatch: &Dispatch,
        record: &RequestRecord,
        outcome: Outcome,
        drafts: &DraftStore,
    ) -> Result<Settled> {
        self.settle_noting(dispatch, record, outcome, Some(drafts))
    }

    /// Settles one request, writing its note in this store or in the draft store it is handed.
    fn settle_noting(
        &self,
        dispatch: &Dispatch,
        record: &RequestRecord,
        outcome: Outcome,
        drafts: Option<&DraftStore>,
    ) -> Result<Settled> {
        dispatch.owns(&self.directory, record.work_id)?;
        let path = self.named(record.work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let settled = (|| {
            // The record on disk decides, never the copy the caller is holding. Settling twice
            // would write an effect twice, and a record that is gone is work something else has
            // already settled, so this answer is an answer about that instead.
            let Some(held) = self.read_request(&path)? else {
                return self.settle_elsewhere(record);
            };
            // Work that was never sent has no answer to apply: nothing left the device under it,
            // and a cleanup is what takes it back. Work that has been answered about already has
            // its account, and a second answer writes nothing over it.
            if !held.dispatched() {
                return self.settle_elsewhere(&held);
            }
            let privacy = self.read_privacy()?;
            let in_force = privacy.generation.get() == held.produced_under.get();

            let (settled, diverged) = match outcome {
                Outcome::Accepted { position } => {
                    // An accepted write of this object was produced by a write of it, so it names
                    // one. A position that names none is the removal of the object, and a place in
                    // the order counts from one; neither is somewhere a write this device sent can
                    // have landed, and an answer this device cannot read is one it declines.
                    a_write_landed_at(held.object_id, position)?;
                    // A write takes the next place after the one it replaced, so an answer at that
                    // place or behind it is not a later state of the history this request was
                    // made against: a smaller write sequence is a service that went back, and the
                    // same one is two histories claiming one place. It is recorded as that and
                    // never as applied. The request's own record is the account of what left, and
                    // nothing else is written from it: no note and no publication record, because
                    // both would describe a history this device cannot follow.
                    if let Some(replaced) = not_past(held.expected.as_ref().copied(), position) {
                        (RequestState::Diverged { position }, Some(replaced))
                    } else {
                        self.accepted_at(&held, position, in_force, drafts)?
                    }
                }
                Outcome::Refused { retained } => (
                    RequestState::Refused {
                        retained: retained.map_or_else(Nullable::null, Nullable::some),
                    },
                    None,
                ),
            };
            // One replacement of one file ends the request. Everything the answer still owes the
            // store is derived from this record afterwards, so a stop anywhere from here leaves
            // the request settled exactly once.
            let held = held.in_state(settled);
            self.write_request(&held)?;
            self.finish_settlement(&held)?;
            self.retire(held.work_id)?;

            Ok(Settled {
                settlement: if in_force {
                    Settlement::Published
                } else {
                    Settlement::Discarded {
                        produced_under: held.produced_under.get(),
                        current: privacy.generation.get(),
                    }
                },
                diverged,
            })
        })();
        drop(guard);
        settled
    }

    /// Decides what one accepted write that follows the place it replaced becomes, and moves the
    /// note when the generation that admitted it is still in force.
    ///
    /// Returns the terminal state and the place this device's records already give to another
    /// write, when either of them does.
    ///
    /// The caller holds the lock.
    fn accepted_at(
        &self,
        held: &RequestRecord,
        position: SyncPosition,
        in_force: bool,
        drafts: Option<&DraftStore>,
    ) -> Result<(RequestState, Option<SyncPosition>)> {
        // The note first, because it is the one thing here that is not an account. It
        // is production state a fenced generation has already had removed, so the
        // generation rule gates it; a stop between the two leaves the note ahead of a
        // request that is still counted, and the next reconciliation writes it again.
        let note = if in_force {
            Some(self.write_note(held, position, drafts)?)
        } else {
            None
        };
        // Whether this write went into a history the object's record already gives to
        // another write is decided **here**, in the same hold and written into the same
        // replacement. Deciding it after the terminal state was durable left a window
        // where a stop, and then a later publication of the object, turned the fork
        // into ordinary older news and dropped the account of what left.
        //
        // Both of this device's records are asked, because they answer at different
        // times: a fetch can move the note past a publication that is still out, so the
        // note reads this answer as ordinary older news while the publication record
        // still holds the place another write took.
        let publication = self.publication_standing(held, position)?;
        let state = if matches!(publication, Standing::Forked { .. }) {
            RequestState::Diverged { position }
        } else {
            RequestState::Applied { position }
        };
        Ok((state, forked_at([note, Some(publication)])))
    }

    /// Moves the note beside the object one accepted write published, wherever that note lives, and
    /// says where the answer stood against it.
    ///
    /// A setting's note is this store's. A draft's is the draft store's, and it is written there
    /// under the same rule: a note that names a later write, or the same place under another name,
    /// stands. A draft publication with no draft store to write in is refused rather than settled
    /// without its note, because the next comparison would then name a place the object has left.
    ///
    /// The caller holds the lock.
    fn write_note(
        &self,
        held: &RequestRecord,
        position: SyncPosition,
        drafts: Option<&DraftStore>,
    ) -> Result<Standing> {
        match held.revision {
            RequestRevision::Object(revision) => self.write_checkpoint(
                held.object_id,
                SyncCheckpoint {
                    position,
                    published_revision: Nullable::some(revision),
                },
            ),
            RequestRevision::Draft(revision) => {
                let Some(drafts) = drafts else {
                    return Err(SyncError::DraftElsewhere {
                        collection: held.collection(),
                    });
                };
                drafts
                    .record_checkpoint(
                        DraftId::new(held.object_id.get()),
                        DraftCheckpoint {
                            position,
                            published_revision: Nullable::some(revision),
                        },
                    )
                    .map_err(SyncError::from)
            }
        }
    }

    /// Finishes one settled request, writing what its answer still owes the store.
    ///
    /// An accepted write becomes the object's publication record, which is the account of what left
    /// this device and is kept whatever generation is in force. A refusal the service kept nothing
    /// of leaves no account at all, so its record goes. A refusal the service kept a copy of **is**
    /// its own account: the record carries no content, it names ciphertext that is on the service
    /// rather than here, and section 24 shows what left rather than pretending it did not.
    ///
    /// It is derived from the record and from nothing else, so running it twice writes the same
    /// thing and running it late writes it late. That is what makes a stop part way through a
    /// settlement harmless: the record says the request is settled, and this finishes the step
    /// before anything reports.
    ///
    /// The caller holds the lock.
    fn finish_settlement(&self, record: &RequestRecord) -> Result<()> {
        match &record.state {
            RequestState::Applied { position } => {
                let stands = self.write_publication(&Publication {
                    object_id: record.object_id,
                    kind: record.kind,
                    position: *position,
                    // When this device let the content go, which is what an account of what left
                    // says. A reconciliation twenty days later settles the same departure, and
                    // writing its own instant here would say the content left twenty days later
                    // than it did.
                    published_at_ms: record.left_at(),
                })?;
                // A write under a place in the order that the object's record already gives to
                // another write is a second history, and the object's record can hold only one of
                // them. The request's own record is therefore what accounts for this write, and it
                // says so from now on: deciding it again against a later publication would read it
                // as ordinary older news and drop the account of ciphertext that left this device.
                if matches!(stands, Standing::Forked { .. }) {
                    self.write_request(&record.in_state(RequestState::Diverged {
                        position: *position,
                    }))?;
                    return self.retire(record.work_id);
                }
                self.remove_file(&self.named(record.work_id, REQUEST_EXTENSION))?;
                self.retire(record.work_id)
            }
            RequestState::Refused { retained } if retained.as_ref().is_none() => {
                self.remove_file(&self.named(record.work_id, REQUEST_EXTENSION))?;
                self.retire(record.work_id)
            }
            RequestState::Admitted { .. }
            | RequestState::Dispatched { .. }
            | RequestState::Diverged { .. }
            | RequestState::Refused { .. }
            | RequestState::Resolving { .. }
            | RequestState::Unaccounted => Ok(()),
        }
    }

    /// Finishes every settlement a stop left half done.
    ///
    /// Every read that reports runs it first, so nothing ever sees a request in a state something
    /// else was in the middle of leaving. It needs no service answer and no clock: what to do is
    /// written in the record.
    ///
    /// It takes no claim on the requests it finishes. A settled request is one nothing may decide
    /// about any more, and the store's own lock is what orders this against the settlement that
    /// wrote the record.
    ///
    /// The caller holds the lock.
    fn finish_settlements(&self) -> Result<()> {
        for path in self.paths_with(REQUEST_EXTENSION)? {
            match self.read_request(&path) {
                // A record this build cannot read is left exactly where it is, and counted.
                Ok(None) | Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {}
                Ok(Some(record)) => self.finish_settlement(&record)?,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Answers about a request this store is not the one holding the record of.
    ///
    /// Three things look like this, and none of them has anything to write. Something else
    /// **settled** the request, which is what another window of the application reconciling the
    /// same store looks like, and the effects of that answer are already on disk. Or the request
    /// was **ended** because the service will never execute it, and there is nothing for an answer
    /// to say about a request that did not run. Or the work was taken back before it ever left.
    ///
    /// The privacy generation is read under the same hold all the same, because what the caller is
    /// told differs: a request settled under a generation privacy mode has since moved past is
    /// still a request no answer may be published for, and reporting it as an accepted publication
    /// would publish a late old-generation result in the caller's own words.
    ///
    /// The caller holds the lock.
    fn settle_elsewhere(&self, record: &RequestRecord) -> Result<Settled> {
        let privacy = self.read_privacy()?;
        Ok(Settled {
            settlement: if privacy.generation.get() == record.produced_under.get() {
                Settlement::AlreadySettled
            } else {
                Settlement::Discarded {
                    produced_under: record.produced_under.get(),
                    current: privacy.generation.get(),
                }
            },
            diverged: None,
        })
    }

    /// Returns where one accepted write stands against the object's publication record.
    ///
    /// The caller holds the lock.
    fn publication_standing(
        &self,
        record: &RequestRecord,
        position: SyncPosition,
    ) -> Result<Standing> {
        let path = self.path(record.object_id, PUBLICATION_EXTENSION);
        Ok(match self.read_optional::<Publication>(&path)? {
            Some(held) => standing(held.position, position),
            None => Standing::Later,
        })
    }

    /// Applies what a fetch brought down, under the late-result rule, in one step.
    ///
    /// A fetch writes a copy and a note, and both are retained sync content. Checking the
    /// generation, deciding the copy and writing them is one hold, so a cleanup cannot land between
    /// the check and the writes and leave behind content it had just removed, and no other window
    /// can change what this device holds between the decision and the copy that follows from it.
    ///
    /// `copy` is given the object this device holds, inside the hold, and answers with the copy to
    /// keep beside it. It answers with nothing when the two are the same content, and a caller
    /// settling a refusal answers with a copy whatever is held, because the service refused the
    /// comparison and what it holds is another device's.
    ///
    /// # Errors
    ///
    /// Returns whatever `copy` failed with, and [`SyncError::Storage`] when a record cannot be
    /// written.
    pub fn apply_fetch(
        &self,
        produced_under: u64,
        object_id: SyncObjectId,
        checkpoint: SyncCheckpoint,
        copy: impl FnOnce(Option<&SyncObject>) -> Result<Option<ConflictCopy>>,
    ) -> Result<Fetched> {
        let guard = self.lock()?;
        let applied = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced || privacy.generation.get() != produced_under {
                return Ok(Fetched {
                    settlement: Settlement::Discarded {
                        produced_under,
                        current: privacy.generation.get(),
                    },
                    copy: None,
                    note: Standing::Later,
                });
            }
            // What this device holds is read inside the hold and handed to the decision, because a
            // copy is a choice between two versions of one object: deciding against an object read
            // before the answer came back would keep a copy of content this device now holds, or
            // keep none beside content another window stored while the call was out.
            let kept = copy(self.read_object(object_id)?.as_ref())?;
            if let Some(kept) = &kept {
                self.write_conflict(kept)?;
            }
            // Where the answer stood against the note, decided here and reported rather than left
            // for a later comparison to notice: a note that is not moved because two histories
            // claim one place in the order is exactly the thing a caller has to be told about, and
            // the next comparison may never meet it.
            let note = self.write_checkpoint(object_id, checkpoint)?;
            Ok(Fetched {
                settlement: Settlement::Published,
                copy: kept.map(|copy: ConflictCopy| copy.conflict_id),
                note,
            })
        })();
        drop(guard);
        applied
    }

    /// Runs one step under the late-result rule: only while production is not fenced and the
    /// generation `produced_under` names is the one in force.
    ///
    /// It is what a fetch of a draft applies its answer through. The copy it keeps beside the draft
    /// and the note it writes belong to the generation the fetch was started under, and both are in
    /// the draft store, so the generation is read and `apply` runs under one hold of this store's
    /// lock: a cleanup cannot land between the check and the writes. The draft store's own lock is
    /// taken inside that hold, which is the one order the two are ever taken in.
    ///
    /// Returns what `apply` produced, or, under a generation privacy mode has fenced or moved past,
    /// that nothing ran and which generation is in force instead.
    ///
    /// # Errors
    ///
    /// Returns whatever `apply` failed with, and [`SyncError::Storage`] when the privacy record
    /// cannot be read.
    pub fn apply_under_generation<T>(
        &self,
        produced_under: u64,
        apply: impl FnOnce() -> Result<T>,
    ) -> Result<InGeneration<T>> {
        let guard = self.lock()?;
        let applied = (|| {
            let privacy = self.read_privacy()?;
            if privacy.fenced || privacy.generation.get() != produced_under {
                return Ok(InGeneration::Discarded {
                    produced_under,
                    current: privacy.generation.get(),
                });
            }
            Ok(InGeneration::Applied(apply()?))
        })();
        drop(guard);
        applied
    }

    // -- conflict copies ----------------------------------------------------------------------

    /// Keeps a copy beside this device's own content, bounded by section 20's limit.
    ///
    /// The oldest copy is dropped first when the limit is reached, so the newest refusal is always
    /// the one that is kept: a device that never resolves its conflicts cannot spend a person's
    /// storage without bound, and the copy that matters most is the one that just arrived.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::TooLarge`] or [`SyncError::Storage`].
    pub fn keep_conflict(&self, copy: &ConflictCopy) -> Result<()> {
        let guard = self.lock()?;
        let outcome = self.write_conflict(copy);
        drop(guard);
        outcome
    }

    /// Writes one copy and prunes the object's oldest, keeping the one just written.
    ///
    /// The caller holds the lock.
    fn write_conflict(&self, copy: &ConflictCopy) -> Result<()> {
        // A copy is held to the storage bound rather than to the publishable bound. Content the
        // service was already carrying is content this device keeps: refusing it because this
        // device's own note around it costs a few hundred bytes would lose the very thing the
        // person is meant to choose from. A copy that arrived at the service's limit may therefore
        // be a few bytes too large to publish again from here.
        let bytes = encode_within_limit(copy, MAX_CONFLICT_COPY_BYTES)?;
        let bytes = &bytes.0;
        // The new copy is written first. Dropping an old one before the replacement is durable
        // would lose a choice the person had and keep nothing in its place.
        self.write_bytes(
            &self.named(copy.conflict_id.get(), CONFLICT_EXTENSION),
            bytes,
        )?;
        let mut held = self.read_all::<ConflictCopy>(CONFLICT_EXTENSION)?.items;
        // The copy just admitted is never the one pruned. Ordering is by a timestamp the caller
        // supplied, and a clock that stepped back, or two answers that finished out of order,
        // would otherwise make the newest refusal delete itself and leave a caller holding an
        // identity nothing is stored under.
        held.retain(|kept| {
            kept.object_id == copy.object_id && kept.conflict_id != copy.conflict_id
        });
        held.sort_by_key(|kept| (kept.recorded_at_ms.get(), kept.conflict_id.get()));
        while held.len() as u64 >= MAX_SYNC_CONFLICT_COPIES {
            let oldest = held.remove(0);
            self.remove_file(&self.named(oldest.conflict_id.get(), CONFLICT_EXTENSION))?;
        }
        Ok(())
    }

    /// Returns every copy kept for one object, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn conflicts(&self, object_id: SyncObjectId) -> Result<Listing<ConflictCopy>> {
        let guard = self.lock()?;
        let outcome = self.read_all::<ConflictCopy>(CONFLICT_EXTENSION);
        drop(guard);
        let mut listing = outcome?;
        listing.items.retain(|copy| copy.object_id == object_id);
        listing.items.sort_by_key(|copy| copy.recorded_at_ms.get());
        Ok(listing)
    }

    /// Takes one copy out of the store, which is how a person's choice is recorded.
    ///
    /// The choice itself is the caller's: it publishes what was chosen through the ordinary path.
    /// This library never decides between two copies, because section 20 says a person does.
    ///
    /// A copy kept after a refusal is one side of one choice, and the service kept the other side:
    /// the refused write itself, which [`ConflictCopy::retained`] names. That copy, and no other, is
    /// marked in the same hold as one that is to leave the service, which [`Self::resolutions`]
    /// lists and [`Self::close_resolution`] ends once the service has dropped it. Another refused
    /// write of the same object is another version of this device's content that the person has not
    /// decided about, so it stays where it is. A service that cannot be asked straight away leaves
    /// the choice recorded rather than undone.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the copy or a request record cannot be read, written or
    /// removed.
    pub fn resolve_conflict(&self, conflict_id: SyncConflictId) -> Result<Option<ConflictCopy>> {
        let path = self.named(conflict_id.get(), CONFLICT_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let Some(copy) = self.read_optional::<ConflictCopy>(&path)? else {
                return Ok(None);
            };
            // The service's copy first, so a stop between the two leaves the person with a copy to
            // choose from again rather than with a choice the service never hears of.
            if let Some(retained) = copy.retained.as_ref().copied() {
                self.mark_resolving(retained)?;
            }
            self.remove_file(&path)?;
            Ok(Some(copy))
        })();
        drop(guard);
        outcome
    }

    /// Marks one copy the service kept of this device's refused write as one to drop, because the
    /// person asked for exactly that.
    ///
    /// It is the way to a copy that has nothing on this device to choose about: a refusal whose
    /// other content could not be brought down, or whose copy here was later pruned or removed by
    /// privacy mode. What has left this device names every such copy by the identity the service
    /// gave it, and this is the deletion section 24 offers for a retained artefact, asked for
    /// explicitly and for that artefact alone.
    ///
    /// Returns false when this device holds no refusal the service kept that copy of, which
    /// includes one already on its way out.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be read or written.
    pub fn drop_kept_copy(&self, retained: SyncConflictId) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = self.mark_resolving(retained);
        drop(guard);
        outcome
    }

    /// Marks the refusal whose copy the service kept as `retained` as one to drop, when this device
    /// still holds it as a refusal.
    ///
    /// The caller holds the lock.
    fn mark_resolving(&self, retained: SyncConflictId) -> Result<bool> {
        for record in self.read_requests()?.items {
            if let RequestState::Refused { retained: kept } = &record.state
                && kept.as_ref() == Some(&retained)
            {
                self.write_request(&record.in_state(RequestState::Resolving { retained }))?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns every copy the person has chosen about that the service has not yet dropped.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn resolutions(&self) -> Result<Vec<RequestRecord>> {
        let guard = self.lock()?;
        let outcome = self.read_requests();
        drop(guard);
        let mut resolving = outcome?.items;
        resolving.retain(|record| matches!(record.state, RequestState::Resolving { .. }));
        Ok(resolving)
    }

    /// Ends one resolution the service has answered: the copy it names is no longer there.
    ///
    /// The record goes, because it was the account of a copy the service held and the service
    /// holds it no longer. Returns false when there was nothing to end, which is another window of
    /// the application having ended it first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read or removed.
    pub fn close_resolution(&self, work_id: Uuid) -> Result<bool> {
        let path = self.named(work_id, REQUEST_EXTENSION);
        let guard = self.lock()?;
        let outcome = (|| {
            let Some(record) = self.read_request(&path)? else {
                return Ok(false);
            };
            if !matches!(record.state, RequestState::Resolving { .. }) {
                return Ok(false);
            }
            self.remove_file(&path)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    // -- publications -------------------------------------------------------------------------

    /// Records that this device published one collection.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be written.
    pub fn record_publication(&self, publication: &Publication) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = self.write_publication(publication);
        drop(guard);
        Ok(matches!(outcome?, Standing::Later | Standing::Same))
    }

    /// Writes a publication record unless a later one already stands.
    ///
    /// The caller holds the lock.
    fn write_publication(&self, publication: &Publication) -> Result<Standing> {
        let bytes = kr_cbor::to_canonical_vec(publication)?;
        let path = self.path(publication.object_id, PUBLICATION_EXTENSION);
        // A record already naming a later write stands, for the reason a checkpoint does: two
        // answers can arrive out of order, and writing the older one would say this device
        // published less recently than it did. The service's own order decides it, so there is one
        // comparison and no case where this device has to guess which answer came second. A record
        // naming the same write under another name stands too: two histories claiming one place in
        // the order is not a later publication, and the caller is told so rather than left to read
        // it as one.
        let stands = match self.read_optional::<Publication>(&path)? {
            Some(held) => standing(held.position, publication.position),
            None => Standing::Later,
        };

        if matches!(stands, Standing::Earlier | Standing::Forked { .. }) {
            return Ok(stands);
        }
        self.write_bytes(&path, &bytes)?;
        Ok(stands)
    }

    /// Returns every account of what has left this device, under one hold of the lock.
    ///
    /// Under one hold because a reconciliation moves a record from one list to another: it settles
    /// a dispatch or discards one nothing can account for, and a reader that took the lists
    /// separately could look at the staged work before that move and at the rest after it, and see
    /// the record in neither.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn what_left(&self) -> Result<WhatLeft> {
        let guard = self.lock()?;
        let outcome = (|| {
            // What a stop left half done is finished before anything is read, so an accepted write
            // is named once: as the publication it became, never as that and a request as well.
            self.finish_settlements()?;
            let mut publications = self.read_all::<Publication>(PUBLICATION_EXTENSION)?;
            publications
                .items
                .sort_by_key(|record| record.published_at_ms.get());
            Ok(WhatLeft {
                publications,
                requests: self.read_requests()?,
            })
        })();
        drop(guard);
        outcome
    }

    /// Returns what this device has published, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the directory cannot be read.
    pub fn publications(&self) -> Result<Listing<Publication>> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.finish_settlements()?;
            self.read_all::<Publication>(PUBLICATION_EXTENSION)
        })();
        drop(guard);
        let mut listing = outcome?;
        listing
            .items
            .sort_by_key(|record| record.published_at_ms.get());
        Ok(listing)
    }

    // -- pinned labels ------------------------------------------------------------------------

    /// Returns the labels the person pinned, in order.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] or [`SyncError::Corrupt`].
    pub fn pinned_labels(&self) -> Result<Vec<PinnedLabel>> {
        let guard = self.lock()?;
        let outcome = self.read_labels();
        drop(guard);
        outcome
    }

    /// Pins a label, or moves an existing one to this instant.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels cannot be written.
    pub fn pin_label(&self, label: impl Into<String>, now: TimestampMs) -> Result<()> {
        let label = label.into();
        let guard = self.lock()?;
        let outcome = (|| {
            let mut labels = self.read_labels()?;
            labels.retain(|held| held.label != label);
            labels.push(PinnedLabel {
                label,
                pinned_at_ms: now,
            });
            labels.sort();
            self.write_labels(&labels)
        })();
        drop(guard);
        outcome
    }

    /// Clears one pinned label, which is the only thing that removes one.
    ///
    /// Section 24 keeps a pinned label unless it is explicitly cleared, so privacy mode does not
    /// reach it and neither does anything else in this store.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels cannot be written.
    pub fn clear_pinned_label(&self, label: &str) -> Result<bool> {
        let guard = self.lock()?;
        let outcome = (|| {
            let mut labels = self.read_labels()?;
            let before = labels.len();
            labels.retain(|held| held.label != label);
            if labels.len() == before {
                return Ok(false);
            }
            self.write_labels(&labels)?;
            Ok(true)
        })();
        drop(guard);
        outcome
    }

    // -- privacy ------------------------------------------------------------------------------

    /// Removes the staged ciphertext, the conflict copies and the checkpoints, and says what went.
    ///
    /// The figure is what this call actually removed, counted from the files it deleted, so a
    /// report cannot claim a removal that did not happen. What stays is named rather than left out:
    /// the pinned labels, the objects this device holds, the record of what has already been
    /// published and the record of a dispatch nothing could account for. The last two carry no
    /// content and are the only account of what left.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a file cannot be removed. What was removed before the
    /// failure stays removed; the caller asks again.
    pub fn remove_content(&self, generation: u64) -> Result<(u64, u64)> {
        let guard = self.lock()?;
        let outcome = (|| {
            self.owns_cleanup(generation)?;
            let mut bytes = 0_u64;
            let mut records = 0_u64;
            let mut remove = |path: &Path| -> Result<()> {
                let size = std::fs::metadata(path).map(|data| data.len()).unwrap_or(0);
                self.remove_file(path)?;
                bytes = bytes.saturating_add(size);
                records = records.saturating_add(1);
                Ok(())
            };
            // A partial holds whatever a writer that died was putting down, which may be staged
            // ciphertext or a conflict copy, so it goes with them rather than waiting for the next
            // time the store is opened.
            for extension in [CONFLICT_EXTENSION, CHECKPOINT_EXTENSION, PARTIAL_EXTENSION] {
                for path in self.paths_with(extension)? {
                    remove(&path)?;
                }
            }
            // A request is not all alike. What was admitted and never sent is content on its way
            // out and goes; what was sent is not here any more, and its record is the only thing
            // that says so, so it stays and keeps counting as outstanding. A record this build
            // cannot read stays too, because a record it could not open is not one it may call
            // nothing. Work admitted under a *later* generation is another cleanup's, not this
            // one's.
            for path in self.paths_with(REQUEST_EXTENSION)? {
                match self.read_request(&path) {
                    Ok(Some(record)) => {
                        if record.admitted() && record.produced_under.get() <= generation {
                            remove(&path)?;
                        }
                    }
                    Ok(None) => {}
                    Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok((bytes, records))
        })();
        drop(guard);
        outcome
    }

    // -- the filesystem -----------------------------------------------------------------------

    fn lock(&self) -> Result<Lock> {
        Lock::take(&self.directory.join(LOCK_NAME))
    }

    /// Refuses a cleanup step that a later generation has overtaken.
    ///
    /// It is checked here, inside the hold that does the deleting, rather than before it: two
    /// control steps can overlap, and the later one has already decided what is retained, so an
    /// earlier step finishing afterwards would delete copies and notes that belong to the
    /// generation now in force.
    ///
    /// The caller holds the lock.
    fn owns_cleanup(&self, generation: u64) -> Result<()> {
        let privacy = self.read_privacy()?;
        if privacy.generation.get() > generation {
            return Err(SyncError::LateResult {
                produced_under: generation,
                current: privacy.generation.get(),
            });
        }
        Ok(())
    }

    /// Reads the privacy state, or the state of a device that has never enabled privacy mode.
    ///
    /// The caller holds the lock.
    fn read_privacy(&self) -> Result<PrivacyRecord> {
        Ok(self
            .read_optional(&self.directory.join(PRIVACY_NAME))?
            .unwrap_or_default())
    }

    /// Returns a fresh identity for a record this store is about to write.
    fn fresh_id(&self) -> Result<Uuid> {
        kr_transport::random::fresh_uuid_v4().map_err(|error| SyncError::Corrupt {
            path: self.directory.clone(),
            reason: error.to_string(),
        })
    }

    fn path(&self, object_id: SyncObjectId, extension: &str) -> PathBuf {
        self.named(object_id.get(), extension)
    }

    fn named(&self, id: Uuid, extension: &str) -> PathBuf {
        self.directory.join(format!("{id}.{extension}"))
    }

    /// Reads a checkpoint, removing and reporting as absent one this build cannot read.
    ///
    /// The caller holds the lock.
    fn read_checkpoint(&self, object_id: SyncObjectId) -> Result<Option<SyncCheckpoint>> {
        let path = self.path(object_id, CHECKPOINT_EXTENSION);
        match self.read_optional::<SyncCheckpoint>(&path) {
            Ok(checkpoint) => Ok(checkpoint),
            Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                self.remove_file(&path)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Reads one request's record.
    ///
    /// A record this build cannot read is reported as it was, never replaced: it is the only
    /// account of work that may have left this device, and a store that rewrote one it did not
    /// understand would be guessing at what left.
    ///
    /// The caller holds the lock.
    fn read_request(&self, path: &Path) -> Result<Option<RequestRecord>> {
        self.read_optional::<RequestRecord>(path)
    }

    /// Writes one request's record, whole.
    ///
    /// Under the reader's own limits, so a record this device could not open again is refused
    /// rather than written: a record the store cannot read is work it can never settle.
    ///
    /// The caller holds the lock.
    fn write_request(&self, record: &RequestRecord) -> Result<()> {
        let bytes = encode_readable(record)?;
        self.write_bytes(&self.named(record.work_id, REQUEST_EXTENSION), &bytes.0)
    }

    /// Reads every request's record, naming what it could not read.
    ///
    /// The caller holds the lock.
    fn read_requests(&self) -> Result<Listing<RequestRecord>> {
        let mut listing = Listing {
            items: Vec::new(),
            unreadable: Vec::new(),
        };
        for path in self.paths_with(REQUEST_EXTENSION)? {
            match self.read_request(&path) {
                Ok(Some(value)) => listing.items.push(value),
                Ok(None) => {}
                Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                    listing.unreadable.push(path);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(listing)
    }

    /// Reads one stored value, or nothing when the name is not there.
    ///
    /// The caller holds the lock.
    fn read_optional<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        path: &Path,
    ) -> Result<Option<T>> {
        let bytes = match std::fs::read(path) {
            // The file holds a record in the clear, so the buffer is cleared when it goes out of
            // scope rather than dropped as an ordinary vector.
            Ok(bytes) => super::Zeroising(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage(path, error)),
        };
        let value = kr_cbor::from_canonical_slice(&bytes.0, &kr_cbor::Limits::DEFAULT).map_err(
            |error| SyncError::Corrupt {
                path: path.to_path_buf(),
                reason: super::cbor_fault(&error),
            },
        )?;
        Ok(Some(value))
    }

    /// Returns every path with one extension, in name order.
    ///
    /// The caller holds the lock.
    fn paths_with(&self, extension: &str) -> Result<Vec<PathBuf>> {
        let suffix = format!(".{extension}");
        let mut paths = Vec::new();
        for entry in
            std::fs::read_dir(&self.directory).map_err(|source| storage(&self.directory, source))?
        {
            let entry = entry.map_err(|source| storage(&self.directory, source))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(&suffix) {
                paths.push(entry.path());
            }
        }
        paths.sort();
        Ok(paths)
    }

    /// Reads every stored value with one extension, naming what it could not read.
    ///
    /// A damaged file is kept and named. Only a checkpoint is a cache this store throws away: a
    /// conflict copy is content a person is meant to choose between and a publication record is the
    /// only account of what left this device, so reading a list is never a reason to lose one.
    ///
    /// The caller holds the lock.
    fn read_all<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        extension: &str,
    ) -> Result<Listing<T>> {
        let mut listing = Listing {
            items: Vec::new(),
            unreadable: Vec::new(),
        };
        for path in self.paths_with(extension)? {
            match self.read_optional::<T>(&path) {
                Ok(Some(value)) => listing.items.push(value),
                Ok(None) => {}
                Err(SyncError::Corrupt { .. } | SyncError::Encoding(_)) => {
                    listing.unreadable.push(path);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(listing)
    }

    fn read_labels(&self) -> Result<Vec<PinnedLabel>> {
        Ok(self
            .read_optional::<Vec<PinnedLabel>>(&self.directory.join(LABELS_NAME))?
            .unwrap_or_default())
    }

    fn write_labels(&self, labels: &[PinnedLabel]) -> Result<()> {
        let bytes = encode_within_limit(&labels.to_vec(), MAX_CONFLICT_COPY_BYTES)?;
        self.write_bytes(&self.directory.join(LABELS_NAME), &bytes.0)
    }

    /// Writes one file whole and makes its name durable.
    ///
    /// The caller holds the lock.
    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let partial = self.directory.join(format!(
            "{}.{PARTIAL_EXTENSION}",
            kr_transport::random::fresh_uuid_v4().map_err(|error| SyncError::Corrupt {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?
        ));
        write_whole(&partial, bytes).map_err(|source| storage(&partial, source))?;
        if let Err(source) = std::fs::rename(&partial, path) {
            let _ = std::fs::remove_file(&partial);
            return Err(storage(path, source));
        }
        sync_directory(&self.directory).map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Removes one file and makes its absence durable.
    ///
    /// The caller holds the lock.
    fn remove_file(&self, path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(storage(path, error)),
        }
        sync_directory(&self.directory).map_err(|source| storage(&self.directory, source))?;
        Ok(())
    }

    /// Removes the lock one dispatch was owned through, once the request is retired.
    ///
    /// Nothing waits on that lock afterwards: a claim tries it without blocking rather than queuing
    /// behind it, and a request is dispatched once, so there is no second call to take it.
    ///
    /// The caller holds the lock.
    fn retire(&self, work_id: Uuid) -> Result<()> {
        self.remove_file(&self.named(work_id, CALLOUT_EXTENSION))
    }

    /// Removes what a process that died while writing left behind.
    ///
    /// The caller holds the lock.
    fn sweep_partials(&self) -> Result<()> {
        for path in self.paths_with(PARTIAL_EXTENSION)? {
            self.remove_file(&path)?;
        }
        Ok(())
    }
}

/// The store's lock, held for as long as this value is, and not a moment longer.
#[derive(Debug)]
pub(super) struct Lock {
    file: std::fs::File,
}

impl Drop for Lock {
    /// Releases the lock itself, rather than leaving the release to the file's closing.
    ///
    /// Closing a file releases its lock only once every descriptor of that open file is closed,
    /// and descriptors are copied without this store taking part: a process that any thread of the
    /// application starts receives one of each until it replaces its own image. A lock left to the
    /// closing would outlive the value that held it for as long as that took, and a claim in
    /// between would find a request nobody is waiting on still in somebody's hand. An explicit
    /// release ends the lock on the open file whatever else still refers to it, so dropping this
    /// value is releasing the lock, at that moment, on every platform: Windows, which copies no
    /// handle this store opens, releases the locks of a closed handle only when it gets round to
    /// it.
    fn drop(&mut self) {
        // A release the system refused leaves the lock to the closing that follows, which is the
        // most that can be done from a destructor; there is nobody to report the refusal to.
        let _ = self.file.unlock();
    }
}

impl Lock {
    pub(super) fn take(path: &Path) -> Result<Self> {
        let file = Self::open(path)?;
        file.lock().map_err(|source| storage(path, source))?;
        Ok(Self { file })
    }

    /// Takes the lock when it is free, and answers rather than waiting when it is not.
    pub(super) fn try_take(path: &Path) -> Result<Option<Self>> {
        let file = Self::open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(source)) => Err(storage(path, source)),
        }
    }

    fn open(path: &Path) -> Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| storage(path, source))
    }
}

/// One dispatch, owned for as long as this value lives, and the request it is for.
///
/// Holding it is what makes this device the owner of a request. The lock underneath is the
/// operating system's, so another client value, another window of the application and another
/// process over the same store all meet it, and none of them may decide what became of the request
/// while somebody is still waiting for its answer. Releasing it says this device's call is over; it
/// never says the request stopped at the service, which is why what a released request needs is a
/// claim and a question rather than a conclusion.
#[derive(Debug)]
pub struct Dispatch {
    directory: PathBuf,
    work_id: Uuid,
    _lock: Lock,
}

impl Dispatch {
    /// Returns the request this dispatch is held for.
    #[must_use]
    pub const fn request(&self) -> Uuid {
        self.work_id
    }

    /// Refuses a decision this dispatch does not cover.
    ///
    /// The store as well as the request, because the lock is one file in one store: a dispatch
    /// taken from another store holds nothing here, whoever is holding this one.
    fn owns(&self, directory: &Path, work_id: Uuid) -> Result<()> {
        if self.work_id == work_id && self.directory == directory {
            return Ok(());
        }
        Err(SyncError::OtherRequest {
            holding: self.work_id,
            wanted: work_id,
        })
    }
}

/// What a claim on one dispatched request found.
#[derive(Debug)]
pub enum Claimed {
    /// The claim was taken. The record is the one the store holds, under the dispatch it is held
    /// by, and it stays claimed for as long as that dispatch lives.
    ///
    /// The record is behind a pointer because it is the only variant that carries anything, and a
    /// value every caller moves about should not be the size of the largest thing it might hold.
    Taken(Dispatch, Box<RequestRecord>),
    /// Somebody has a call out for the request, so nothing here may decide about it.
    ///
    /// A service writes its receipt when it commits a write, so a request still on the wire looks
    /// exactly like one that never arrived. The device making the call is the only thing that can
    /// tell the two apart, and this is that device saying so.
    InHand,
    /// Nothing under that identity is waiting for an answer, so there is nothing to decide: the
    /// record is gone, the work never left, or something has already settled it.
    Gone,
}

/// One attempt at a publication, and the dispatch it is made under.
///
/// Holding it is holding the dispatch: nothing else may decide what became of the request until it
/// is dropped, and dropping it says this call is over, never that the request stopped at the
/// service.
#[derive(Debug)]
pub struct Attempt {
    /// The dispatch this attempt is made under.
    pub dispatch: Dispatch,
    /// The request's record as this attempt left it: the identity and the comparison every attempt
    /// presents, and the earliest and the latest instant any attempt so far was signed at.
    pub record: RequestRecord,
    /// The sealed object every attempt at this publication carries, byte for byte.
    pub ciphertext: Bytes,
    /// The instant this attempt is signed at, which the record's two signing times now bound.
    pub signed_at: TimestampMs,
}

/// Encodes an object and holds it to the size the service will actually take.
///
/// The bound is on the **padded** length, because padding is what is sealed and what a service
/// measures. An object that encodes to exactly the plaintext limit pads to the bucket above it,
/// which is a size no synchronised object may be, so accepting it locally would mean accepting one
/// that could never be published.
fn encode_within(object: &SyncObject) -> Result<super::Zeroising> {
    // The reader's own limits, not only a byte count. A value this store accepted and its own
    // decoder then refused would be a value a person could write and never read back, and the byte
    // bound does not catch it: four thousand short labels are small and are past the decoder's
    // bound on how many members one collection may have.
    let bytes = super::Zeroising(kr_cbor::to_canonical_vec_within(
        object,
        &kr_cbor::Limits::DEFAULT,
    )?);
    if mailbox_size_bucket(bytes.0.len() as u64) > super::MAX_OBJECT_BYTES {
        return Err(SyncError::TooLarge {
            len: bytes.0.len(),
            limit: largest_publishable_object() as usize,
        });
    }
    Ok(bytes)
}

/// Encodes one record this store must be able to read back.
///
/// Under the reader's own limits and not only a byte count: a record written past them would be one
/// this device could never open again. That matters most for staged work, because a staged record
/// the store cannot read is a dispatch it can never settle and a barrier it can never lift.
fn encode_readable<T: Serialize>(value: &T) -> Result<super::Zeroising> {
    Ok(super::Zeroising(kr_cbor::to_canonical_vec_within(
        value,
        &kr_cbor::Limits::DEFAULT,
    )?))
}

/// Encodes one record and holds it to a byte bound, under the reader's own structural limits.
fn encode_within_limit<T: Serialize>(value: &T, limit: u64) -> Result<super::Zeroising> {
    let bytes = super::Zeroising(kr_cbor::to_canonical_vec_within(
        value,
        &kr_cbor::Limits::DEFAULT,
    )?);
    if bytes.0.len() as u64 > limit {
        return Err(SyncError::TooLarge {
            len: bytes.0.len(),
            limit: limit as usize,
        });
    }
    Ok(bytes)
}

/// Returns the largest encoded object whose padded length is still one a service will take.
fn largest_publishable_object() -> u64 {
    let mut len = super::MAX_OBJECT_BYTES;
    while len > 0 && mailbox_size_bucket(len) > super::MAX_OBJECT_BYTES {
        len -= 1;
    }
    len
}

/// Returns where `offered` stands against a position this device already established.
///
/// The service's order decides it. A larger write sequence is a later write; the same write
/// sequence under the same name is the same write said again; a smaller one is older news, which
/// happens whenever two answers arrive out of order. The same write sequence under **another** name
/// is none of those: one write sequence names one write for the life of a collection, so two
/// answers claiming one place in the order come from two histories, and neither is a later state of
/// the other.
///
/// A removal takes a place in the order like any other answer, and the comparison reads it the same
/// way: two answers that both remove the object at one place in the order are one removal said
/// twice, and a removal and a write claiming one place are two histories.
///
/// A draft's note is held to this rule as well, so there is one answer to where a position stands
/// whichever store keeps the note.
pub(crate) fn standing(held: SyncPosition, offered: SyncPosition) -> Standing {
    match offered.write_sequence.cmp(&held.write_sequence) {
        std::cmp::Ordering::Greater => Standing::Later,
        std::cmp::Ordering::Equal if offered.revision == held.revision => Standing::Same,
        std::cmp::Ordering::Equal => Standing::Forked { held },
        std::cmp::Ordering::Less => Standing::Earlier,
    }
}

/// Returns the place another write already holds, where any of these comparisons found one.
///
/// A caller is owed a fork whichever of this device's records found it. They answer at different
/// times, so one of them can read an answer as ordinary older news while the other still holds the
/// place another write took, and reporting only the first would lose a fork this device has already
/// written down.
fn forked_at(comparisons: impl IntoIterator<Item = Option<Standing>>) -> Option<SyncPosition> {
    comparisons
        .into_iter()
        .flatten()
        .find_map(|stood| match stood {
            Standing::Forked { held } => Some(held),
            Standing::Later | Standing::Same | Standing::Earlier => None,
        })
}

/// Refuses a position no write of this object can have landed at.
///
/// Two answers are not places a write went. A position that names no revision is the **removal** of
/// the object, which is a place in the order and not a state a write of the object produced; and a
/// write sequence of nought is what a service says of an object it has never held, which this
/// contract states by carrying no position at all. This client publishes writes and never removals,
/// so either answer is one it declines rather than reads as its own.
fn a_write_landed_at(object_id: SyncObjectId, position: SyncPosition) -> Result<()> {
    if position.is_removal() || position.write_sequence == 0 {
        return Err(SyncError::NotAWrite {
            object_id,
            found: position,
        });
    }
    Ok(())
}

/// Returns the place a write replaced, when the answer says the write landed at it or behind it.
///
/// A write takes the next place after the one it replaced, so an accepted answer has to be past
/// it. The same write sequence is two histories claiming one place, and a smaller one is a
/// service that went back; neither is the write this device sent advancing the object. A write
/// that replaced nothing can land anywhere in the order, so there is nothing to hold it to.
///
/// It is a rule about a write's own answer and nothing else. An answer to a read may name exactly
/// the place this device already holds, which is the same write said again.
fn not_past(replaced: Option<SyncPosition>, landed: SyncPosition) -> Option<SyncPosition> {
    replaced.filter(|replaced| landed.write_sequence <= replaced.write_sequence)
}

fn storage(path: &Path, source: std::io::Error) -> SyncError {
    SyncError::Storage {
        path: path.to_path_buf(),
        source,
    }
}

/// Creates the directory owner-only, and makes an existing one owner-only.
///
/// A person's settings and the labels they pinned. A directory anything on the machine could read
/// would be one this store had no business writing into, so an existing directory is narrowed
/// rather than accepted. On Windows the directory takes whatever access list it inherits, which
/// this store does not narrow: what protects it there is the access list of the directory the
/// caller chose.
pub(super) fn private_directory(directory: &Path) -> std::io::Result<()> {
    // Each missing level is created in turn rather than all at once, because a directory is a name
    // in the directory above it and a name is durable only once that directory's entry is flushed.
    let mut missing = Vec::new();
    let mut level = Some(directory);
    while let Some(path) = level {
        if path.as_os_str().is_empty() || path.is_dir() {
            break;
        }
        missing.push(path);
        level = path.parent();
    }
    for path in missing.iter().rev() {
        #[cfg_attr(
            not(unix),
            expect(unused_mut, reason = "only Unix sets a mode on the builder")
        )]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            sync_new_level(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(directory)?.permissions();
        if permissions.mode() & 0o777 != 0o700 {
            permissions.set_mode(0o700);
            std::fs::set_permissions(directory, permissions)?;
        }
    }
    Ok(())
}

/// Flushes the directory entry of every name this store's path is made of.
///
/// A path is a chain of names, and losing any one of them leaves a store nothing reaches. The chain
/// is not only the components a caller spelled: a link is a name in a directory, it leads
/// somewhere, and the rest of the path continues from there. So this resolves the path the way the
/// kernel does, one component at a time, flushing the directory each name lives in and continuing
/// from a link's target when it meets one.
#[cfg(unix)]
pub(super) fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    use std::collections::VecDeque;
    use std::ffi::OsString;

    let start = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    let mut remaining: VecDeque<OsString> = start
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let mut resolved = PathBuf::new();
    let mut flushed: Vec<PathBuf> = Vec::new();
    let mut followed = 0_usize;

    while let Some(name) = remaining.pop_front() {
        // A file cannot be called `.` or `..`, and only the root component is `/`, so what a name
        // means is not ambiguous.
        if name == std::path::MAIN_SEPARATOR_STR {
            resolved.push(&name);
            continue;
        }
        if name == "." {
            continue;
        }
        if name == ".." {
            resolved.pop();
            continue;
        }
        let parent = if resolved.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            resolved.clone()
        };
        if !flushed.contains(&parent) {
            sync_directory(&parent)?;
            flushed.push(parent);
        }
        resolved.push(&name);
        let metadata = std::fs::symlink_metadata(&resolved)?;
        if metadata.file_type().is_symlink() {
            followed += 1;
            if followed > MAX_PATH_LINKS {
                return Err(std::io::Error::other(
                    "the store's path passes through too many links to follow",
                ));
            }
            let target = std::fs::read_link(&resolved)?;
            resolved.pop();
            if target.is_absolute() {
                resolved = PathBuf::new();
            }
            for component in target.components().rev() {
                remaining.push_front(component.as_os_str().to_os_string());
            }
        }
    }
    sync_directory(&resolved)?;
    Ok(())
}

/// Flushes the directory entry of every name this store's path is made of that this account could
/// have made.
///
/// The walk is the one Unix takes: one component at a time, continuing from a link's target when
/// it meets a symbolic link or a junction, flushing the directory each name lives in and, at the
/// end, the store's own directory. What differs is what a flush asks of a directory. Windows
/// flushes a directory only through a handle that may change it, and a directory this account may
/// not add a directory to, such as `C:\Users` for an account that does not administer the machine,
/// holds no name an opener of this store made: every opener runs as this account. So a directory
/// whose flush is refused for want of that right is passed over, and every other failure is
/// reported, as it is on Unix.
#[cfg(windows)]
pub(super) fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    let resolved = walk_path_names(directory, &sync_new_level)?;
    sync_directory(&resolved)
}

/// The walk behind [`flush_path_names`]: flushes the directory each name on the path lives in with
/// `flush_holder`, passing over one it refuses for want of the right, and returns the directory the
/// path resolves to.
#[cfg(windows)]
fn walk_path_names(
    directory: &Path,
    flush_holder: &dyn Fn(&Path) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    use std::collections::VecDeque;
    use std::path::Component;

    /// One component of a path, owned, so a link's target can be spliced into the walk.
    enum Part {
        /// The drive, share or root a path starts from, which is nobody's name.
        Root(std::ffi::OsString),
        /// `.`, which names nothing.
        Current,
        /// `..`, which leaves the directory reached so far.
        Parent,
        /// A name in the directory reached so far.
        Name(std::ffi::OsString),
    }

    fn parts(path: &Path) -> Vec<Part> {
        path.components()
            .map(|component| match component {
                Component::Prefix(_) | Component::RootDir => {
                    Part::Root(component.as_os_str().to_os_string())
                }
                Component::CurDir => Part::Current,
                Component::ParentDir => Part::Parent,
                Component::Normal(name) => Part::Name(name.to_os_string()),
            })
            .collect()
    }

    let mut remaining: VecDeque<Part> = parts(&std::path::absolute(directory)?).into();
    let mut resolved = PathBuf::new();
    let mut flushed: Vec<PathBuf> = Vec::new();
    let mut followed = 0_usize;

    while let Some(part) = remaining.pop_front() {
        let name = match part {
            Part::Root(root) => {
                resolved.push(root);
                continue;
            }
            Part::Current => continue,
            Part::Parent => {
                resolved.pop();
                continue;
            }
            Part::Name(name) => name,
        };
        let holder = resolved.clone();
        if !flushed.contains(&holder) {
            match flush_holder(&holder) {
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                other => other?,
            }
            flushed.push(holder.clone());
        }
        resolved.push(&name);
        if !std::fs::symlink_metadata(&resolved)?
            .file_type()
            .is_symlink()
        {
            continue;
        }
        followed += 1;
        if followed > MAX_PATH_LINKS {
            return Err(std::io::Error::other(
                "the store's path passes through too many links to follow",
            ));
        }
        // The target is read the way the link names it: an absolute one starts again at its own
        // root, one that starts at the root of a drive starts at the root of the link's drive, and
        // a relative one continues from the directory the link lives in.
        let target = holder.join(std::fs::read_link(&resolved)?);
        resolved = PathBuf::new();
        for part in parts(&target).into_iter().rev() {
            remaining.push_front(part);
        }
    }
    Ok(resolved)
}

/// Flushes nothing, because this platform has no directory a program can flush.
#[cfg(not(any(unix, windows)))]
pub(super) fn flush_path_names(directory: &Path) -> std::io::Result<()> {
    let _ = directory;
    Ok(())
}

/// Writes a new file whole, and flushes it to the device before anything renames it into place.
pub(super) fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        // Only this call could have created the file, because `create_new` refused an existing
        // name, so removing it here removes nothing another writer is using.
        let _ = std::fs::remove_file(path);
    }
    written
}

/// Flushes a directory entry, so a file name that was created, replaced or removed survives a
/// crash.
///
/// The new contents are written and flushed before anything renames them into place, so a reader
/// never sees a file half written; this is what makes the name itself durable. On Windows the
/// handle holds the right to add a file, which this store holds in the directory it writes its
/// files in.
pub(super) fn sync_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()?;
    }
    #[cfg(windows)]
    {
        flush_directory(directory, FILE_ADD_FILE)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
    }
    Ok(())
}

/// Flushes the entry of a directory just made inside `holder`, so the new level survives a crash.
///
/// On Windows the handle holds the right to add a directory, which is the right that made the
/// level: an account may hold it without the right to add a file, as every account does at the root
/// of the system drive.
fn sync_new_level(holder: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        flush_directory(holder, FILE_ADD_SUBDIRECTORY)
    }
    #[cfg(not(windows))]
    {
        sync_directory(holder)
    }
}

/// The flag that lets a program open a directory at all, rather than a file.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// The right to add a file to a directory.
#[cfg(windows)]
const FILE_ADD_FILE: u32 = 0x0002;

/// The right to add a directory to a directory.
#[cfg(windows)]
const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;

/// Flushes one directory through a handle that holds one right to change it.
///
/// A directory opens only with the backup semantics that say it is one, and `FlushFileBuffers`,
/// which is what synchronising a handle calls, flushes only through a handle that may write. The
/// handle asks for the one right the change being flushed used and for nothing more: more could be
/// refused, and it could collide with another program's handle on the same directory, such as the
/// one a process holds on the directory it is working in.
#[cfg(windows)]
fn flush_directory(directory: &Path, right: u32) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .access_mode(right)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)?
        .sync_all()
}

/// The one test here is about how Unix shares a lock between the descriptors of one open file, so
/// the module is built on Unix alone.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::{SyncBody, SyncSettings};
    use kr_protocol::ids::DeviceId;

    /// A dispatch this store granted, and a second descriptor of the lock it holds.
    ///
    /// The second descriptor is what a process started at that moment holds: every process an
    /// application starts receives a copy of each of its descriptors and keeps it until it replaces
    /// its own image, whichever thread started it. Made here with a duplicate rather than a process,
    /// so the case is deterministic rather than a matter of timing.
    fn a_dispatch_and_a_copy_of_its_lock(store: &SyncStore) -> (Dispatch, Uuid, std::fs::File) {
        let object_id = SyncObjectId::new(Uuid::from_bytes([0x11; 16]));
        store
            .put_object(&SyncObject {
                object_id,
                revision: SyncRevisionId::new(Uuid::from_bytes([0x22; 16])),
                device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                updated_at_ms: TimestampMs::new(1_764_000_000_000),
                body: SyncBody::Settings(SyncSettings::default()),
            })
            .expect("stored");
        let staged = store
            .admit(object_id, |object| Ok(kr_cbor::to_canonical_vec(object)?))
            .expect("admitted");
        let (dispatch, _, _) = store
            .begin_dispatch(
                staged.work_id,
                object_id,
                TimestampMs::new(1_764_000_000_000),
            )
            .expect("dispatched");
        let copy = dispatch
            ._lock
            .file
            .try_clone()
            .expect("a second descriptor of the same open file");
        (dispatch, staged.work_id, copy)
    }

    #[test]
    fn a_dispatch_that_ends_releases_its_claim_whatever_else_shares_its_lock() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = SyncStore::open(directory.path().join("one")).expect("a store");
        let (dispatch, work_id, inherited) = a_dispatch_and_a_copy_of_its_lock(&store);

        // While the call is out, nobody else may decide about the request.
        assert!(matches!(
            store.claim_dispatched(work_id).expect("a claim"),
            Claimed::InHand
        ));

        // The call ends. The request is claimable from that moment, however many other
        // descriptors of the lock's file are still open somewhere: a claim that found it still
        // held would count a request nobody is waiting on as one somebody is.
        drop(dispatch);
        assert!(
            matches!(
                store.claim_dispatched(work_id).expect("a claim"),
                Claimed::Taken(_, _)
            ),
            "a dispatch that has ended is a request this device may ask about"
        );
        drop(inherited);
    }
}

/// On Windows every flush opens the directory it flushes, and these check that it does: nothing
/// else in this store would notice a flush that did nothing.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// Runs one command-line tool and fails the test when it fails.
    fn run(program: &str, arguments: &[&std::ffi::OsStr]) -> String {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} starts: {error}"));
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{program} failed: {printed}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        printed
    }

    #[test]
    fn a_directory_is_flushed_through_a_handle_of_its_own() {
        let root = tempfile::tempdir().expect("a directory");
        sync_directory(root.path()).expect("a directory this account adds files to is flushed");
        sync_new_level(root.path()).expect("and one it adds directories to");
        // A flush that did nothing would pass both of the above. One that opens the directory it
        // flushes cannot open one that is not there.
        let missing = root.path().join("missing");
        assert_eq!(
            sync_directory(&missing)
                .expect_err("nothing to flush")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            sync_new_level(&missing)
                .expect_err("nothing to flush")
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn the_flush_itself_is_asked_of_the_operating_system() {
        /// The right to read a file's attributes, which opens a directory and permits no flush.
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;

        // The operating system flushes only through a handle that may write, and says so when it
        // is asked through one that may not. A directory opened with nothing more than the right to
        // read its attributes opens, as the first reading shows, so what refuses in the second is
        // the flush: a helper that opened the directory and never asked for the flush would return
        // success instead.
        let root = tempfile::tempdir().expect("a directory");
        {
            use std::os::windows::fs::OpenOptionsExt as _;

            std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(root.path())
                .expect("the directory opens with the right to read its attributes");
        }
        assert_eq!(
            flush_directory(root.path(), FILE_READ_ATTRIBUTES)
                .expect_err("a flush through a handle that may not write")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        flush_directory(root.path(), FILE_ADD_FILE)
            .expect("and through one that may add a file, the flush is made");
    }

    #[test]
    fn a_store_path_is_flushed_through_a_junction_to_its_end() {
        let root = tempfile::tempdir().expect("a directory");
        let target = root.path().join("elsewhere");
        std::fs::create_dir(&target).expect("a directory to link to");
        let link = root.path().join("linked");
        // A junction needs no privilege to make, unlike a symbolic link.
        run(
            "cmd.exe",
            &[
                "/d".as_ref(),
                "/c".as_ref(),
                "mklink".as_ref(),
                "/J".as_ref(),
                link.as_os_str(),
                target.as_os_str(),
            ],
        );
        let store = link.join("store").join("inner");
        private_directory(&store).expect("the levels are made and flushed through the junction");
        flush_path_names(&store).expect("every name on the way is flushed");
        assert!(
            target.join("store").join("inner").is_dir(),
            "the levels are where the junction leads"
        );
    }

    #[test]
    fn the_walk_passes_over_a_directory_refused_for_want_of_the_right_and_reports_anything_else() {
        // Whether this account is refused a directory is a matter of the directory's list and of
        // the privileges the account holds, which override the list for an account that has them
        // turned on. So the refusal is given to the walk here rather than asked of a list: what is
        // under test is what the walk makes of it.
        let root = tempfile::tempdir().expect("a directory");
        let refused = std::path::absolute(root.path().join("refused")).expect("an absolute path");
        let store = refused.join("store");
        std::fs::create_dir_all(&store).expect("two levels");
        let asked = std::cell::RefCell::new(Vec::new());
        let resolved = walk_path_names(&store, &|holder: &Path| {
            asked.borrow_mut().push(holder.to_path_buf());
            if holder == refused {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        })
        .expect("a directory refused for want of the right is passed over");
        assert_eq!(
            resolved, store,
            "the walk reaches the store's own directory"
        );
        let asked = asked.into_inner();
        assert!(
            asked.contains(&refused),
            "the refused directory was asked: {asked:?}"
        );
        assert!(
            asked.iter().any(|holder| holder.as_path() == root.path()),
            "and the directory above it was flushed: {asked:?}"
        );

        // Any other failure is reported, as it is on Unix.
        let failed = walk_path_names(&store, &|holder: &Path| {
            if holder == refused {
                Err(std::io::Error::other("the device did not answer"))
            } else {
                Ok(())
            }
        });
        assert!(
            failed.is_err_and(|error| error.kind() == std::io::ErrorKind::Other),
            "a failure that is not a refusal is the answer"
        );
    }
}
