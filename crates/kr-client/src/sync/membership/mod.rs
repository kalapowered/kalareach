//! Who holds a settings collection's key, and what this device does when that changes.
//!
//! A settings collection two or more devices share lives in the namespace of the device that
//! started it, its **home**, and is sealed under one independent random key per **epoch**. The
//! signed key record (`kr_protocol::collection_keys`) names the members and carries the epoch's
//! key wrapped to each member's stored-envelope key. This module is a member's side of that
//! record: it checks the records the service holds, keeps the key it is given, and issues the next
//! record when the owner adds or removes a device or a host reports one revoked.
//!
//! # A key arrives through a wrap, and only through one
//!
//! A device holds a collection key only by opening its own wrap in a record it accepted. It
//! accepts a record when:
//!
//! 1. its own entry carries both of its own public keys, and the issuer is listed;
//! 2. the record follows, link by link, the one it holds, each link signed by an issuer the record
//!    before it named;
//! 3. at least one of its hosts reports the issuer paired, holding the right to manage the host,
//!    with the same stored-envelope key, and nothing it has recorded, from a host or from an
//!    authority feed, reports the issuer revoked; the issuer of the record that opened the
//!    record's epoch passes this check too;
//! 4. the signature verifies under the issuer's authorisation key;
//! 5. its wrap opens against the issuer's stored-envelope key, and the key it carries is the one
//!    held for an epoch this device holds, or, for a new epoch, a key that differs from every key
//!    it holds and every key it opened from an earlier record of another epoch since it joined;
//!    and it is never the key of a candidate this device sent since it joined that never applied,
//!    whose wraps a service could have handed out.
//!
//! Nothing is sealed to a device before its host committed its pairing: a device is added only
//! with the keys its hosts report and only after the owner confirmed it on a member, and it takes
//! its first record only after the owner confirmed the join on the device itself ([`Plan`]).
//!
//! # Revocation
//!
//! Removing a device gives the remaining members a fresh key at the next epoch. The member that
//! removes it issues the record; the service keeps every revision for the collection's life. What
//! a removed device already held stays readable to it: a rotation takes nothing back, and no
//! retroactive secrecy is claimed.
//!
//! Every record this device issues takes the next epoch and a freshly drawn key, an addition
//! included: it wraps the key in use only for the devices its installed record lists, so a record
//! that is sent and never applies has exposed no key anybody writes with. The write that settles
//! such a record withdraws its key, since its wraps may be out: check 5 refuses any record that
//! carries it, whoever issued it. A new member reads the settings once a member seals them again
//! under the new epoch. Records other members issue at an unchanged epoch, which only add members,
//! are accepted as before.
//!
//! # The reconciler
//!
//! The membership file holds ten facts: the join record, the installed record, the head, the host
//! answers, the pending removals, at most one pending addition, at most one candidate record with
//! its request identity and dispatch mark, whether a join awaits the owner, the outcomes not yet
//! shown, and the keys of candidates sent since the join that never applied; each pending change
//! also records whether the head was fetched after it. A dispatched candidate leaves the file
//! only through its settlement, which a device that is out still runs first. Every step
//! makes at most one durable write, and each fact is written before the action that depends on
//! it, so a restart resumes where the file says. [`SyncMembership::step`] runs the first of these
//! rows that applies:
//!
//! | Row | When | What it does |
//! | --- | --- | --- |
//! | 1 | A dispatched candidate | Takes its answer, or settles it by status and then fence; when the fence cannot say it never ran, reads the record after its base, makes it the head and drops the candidate. A candidate that did not apply leaves with its key withdrawn |
//! | 2 | A record after the installed one leaves this device out, or the service answers the collection as absent, with a chain this device cannot follow, or put back without this device's head | Out at once: every pending change ends as refused and an undispatched candidate goes. A dispatched one stays, and is settled first, by status and fence, with nothing sent and no head moved; then the collection's keys are forgotten, one epoch a write |
//! | 3 | A join awaits the owner | Nothing until the owner confirms the join on this device, once row 2's settling and forgetting are done |
//! | 4 | A record after the installed one is accepted | Stores its key when its epoch is new, then records it as installed |
//! | 5 | No candidate, the head installed, and a pending change it carries out | Ends the change as done when the head was fetched after it was recorded; otherwise waits for a fetch |
//! | 6 | An undispatched candidate that row 8 would not build now | Drops it with its key |
//! | 7 | An undispatched candidate that is valid | Marks it dispatched, then sends it once |
//! | 8 | A pending change not carried out, or a head refused while it lists this device | Builds a candidate on the head from the installed record's members, at the head's epoch plus one with a freshly drawn key |
//!
//! Publication into the collection is open only while no removal is pending, no candidate stands,
//! no join awaits the owner and the head is installed ([`SyncMembership::publishes`]).
//!
//! # A collection put back
//!
//! A service restored from an archive puts every collection back as the archive held it, under a
//! recovery identity of its own, and every key-record answer names the history it is in.
//! Revisions compare only within one history, so the file records the one its records were read
//! in: the history a claim applied in, for a collection this device starts; the history of the
//! chain a join verified; and none for a collection never put back, and for a file written before
//! histories were recorded, which is how this device read the collection then.
//!
//! An answer from another history changes nothing until this device reads the collection again
//! there, in the same step and under the same hold of the file: the record at its head and the
//! records after it, both in that history. Found there with its own bytes, the head proves that
//! the records up to it are the ones this device holds, since each names the digest of the one
//! before it, so the file moves to that history and takes the records after the head as a refresh
//! takes them. Missing, or another record in its place, the head is one the archive did not keep,
//! and a record the restore lost may have removed a device: this device is out at once, as row 2
//! leaves, with a dispatched candidate kept for settlement, until the owner confirms a join. Two
//! reads answered from two histories record nothing, and the operation is asked again. Row 1
//! settles only from answers in the history the file records: an answer to the one send that
//! arrives from another is dropped, and the status is asked instead.
//!
//! A membership listing is the service's index, and each entry names a history too. An entry in
//! another history than the one this device holds, whatever revision it names, or at a later
//! revision in the same one, is news: a reason to refresh, and nothing more
//! ([`crate::services::MembershipListing::names_news`]).
//!
//! # Stated limits
//!
//! * A device revoked at a host but not yet removed by a record this device accepted is still a
//!   member: a device that has not received a revocation cannot act on it, and a hostile service
//!   can widen that window by withholding a removal. It can deny service; it cannot keep a key
//!   an honest member rotated away from it.
//! * A member that passes check 3 and reuses key bytes where this device cannot see them, in an
//!   epoch it was not a member of or one before its current join, is not detected. Such a member
//!   could as well hand the key or the settings themselves to a removed device.
//! * The membership file's durability on each platform is [`file`]'s.

mod environment;
mod facts;
mod file;
mod plans;
mod reconciler;

#[cfg(test)]
mod exhaustive;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::collection_keys::{CollectionKeyRecord, CollectionMember};
use kr_protocol::ids::{InstallationId, SyncCollectionId};
use kr_protocol::scalars::{AuthorisationKey, StoredEnvelopeKey, TimestampMs, Uuid};
use kr_protocol::service::installation_id;
use serde::{Deserialize, Serialize};

pub use facts::{Change, Ended, Outcome};
pub use plans::{PLAN_LIFETIME_MS, Plan, PlanRefusal, PlannedOperation};

use environment::{DeviceEnvironment, DeviceKinds};
use facts::{Kinds, View};
use file::MembershipFile;
use plans::Plans;
use reconciler::Reconciler;

use crate::error::ClientError;
use crate::services::{ServiceFuture, SyncRecoveryId};
use crate::sync::keys::StoredCollectionKeys;

/// A collection two or more devices share: the service's collection in its home's namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionRef {
    /// The installation whose namespace the collection lives in: the one that started it.
    pub home: InstallationId,
    /// The collection.
    pub collection_id: SyncCollectionId,
}

/// One device a key record names: its authorisation key and its stored-envelope key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// The Ed25519 authorisation key, from which its installation identifier derives.
    pub authorisation: AuthorisationKey,
    /// The X25519 stored-envelope key its wrap is sealed to.
    pub stored_envelope: StoredEnvelopeKey,
}

impl Device {
    /// The device one record entry names.
    #[must_use]
    pub const fn of(member: &CollectionMember) -> Self {
        Self {
            authorisation: member.authorisation,
            stored_envelope: member.stored_envelope,
        }
    }

    /// The device one key pair set is.
    #[must_use]
    pub const fn from_keys(keys: &DeviceKeys) -> Self {
        Self {
            authorisation: *keys.authorisation.public(),
            stored_envelope: *keys.stored_envelope.public(),
        }
    }

    /// The installation identifier its authorisation key derives.
    #[must_use]
    pub fn installation_id(&self) -> InstallationId {
        installation_id(&self.authorisation)
    }
}

/// One device as one host's device list reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDevice {
    /// Its authorisation key, as the host recorded it when the owner committed its pairing.
    pub authorisation: AuthorisationKey,
    /// Its stored-envelope key, recorded the same way.
    pub stored_envelope: StoredEnvelopeKey,
    /// Whether its grant holds the right to manage the host.
    pub manages_host: bool,
    /// Whether the host reports it revoked.
    pub revoked: bool,
}

/// What one host answered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReport {
    /// Every device the host lists, revoked ones included.
    pub devices: Vec<HostDevice>,
}

/// What this device's hosts answered, one report per host that answered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAnswers {
    /// The reports.
    pub reports: Vec<HostReport>,
}

/// The host answers as this device recorded them, with every revocation it verified from an
/// authority feed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedAnswers {
    /// The hosts' answers at the last refresh.
    pub hosts: HostAnswers,
    /// The devices a verified authority feed revoked, by authorisation key. A refresh keeps
    /// them: a host that has not received a revocation yet does not undo it.
    pub verified: BTreeSet<AuthorisationKey>,
}

impl RecordedAnswers {
    /// Check 3 for a device other than this one.
    #[must_use]
    pub fn passes(&self, device: &Device) -> bool {
        let listed = self.hosts.reports.iter().any(|report| {
            report.devices.iter().any(|reported| {
                reported.authorisation == device.authorisation
                    && reported.stored_envelope == device.stored_envelope
                    && reported.manages_host
                    && !reported.revoked
            })
        });
        let revoked = self.verified.contains(&device.authorisation)
            || self.hosts.reports.iter().any(|report| {
                report.devices.iter().any(|reported| {
                    reported.authorisation == device.authorisation && reported.revoked
                })
            });
        listed && !revoked
    }

    /// The device a host reports with this authorisation key, when one passes check 3.
    #[must_use]
    pub fn committed(&self, authorisation: &AuthorisationKey) -> Option<Device> {
        self.hosts
            .reports
            .iter()
            .flat_map(|report| report.devices.iter())
            .map(|reported| Device {
                authorisation: reported.authorisation,
                stored_envelope: reported.stored_envelope,
            })
            .find(|device| &device.authorisation == authorisation && self.passes(device))
    }
}

/// This device's hosts, asked about the devices they have paired.
pub trait DeviceDirectory: Send + Sync + std::fmt::Debug {
    /// Asks every host this device is paired with for its device list.
    ///
    /// Returns one report per host that answered, and nothing when none did: check 3 cannot run
    /// then, and a refresh records nothing.
    fn answers(&self) -> ServiceFuture<'_, Option<HostAnswers>>;
}

/// The records after a revision, or the collection answered as absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRecords<R = CollectionKeyRecord> {
    /// The records after the revision asked about, in order.
    Records {
        /// The records.
        records: Vec<R>,
        /// The history they are records of: the recovery the collection named, or none for a
        /// collection never put back.
        recovery: Option<SyncRecoveryId>,
    },
    /// The collection does not exist, or this device is not a member: the service answers both
    /// the same way.
    Absent,
}

/// The record at one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordAt<R = CollectionKeyRecord> {
    /// The record.
    Record {
        /// The record.
        record: R,
        /// The history it is a record of.
        recovery: Option<SyncRecoveryId>,
    },
    /// The collection holds no record at that revision yet.
    Missing {
        /// The history that holds none.
        recovery: Option<SyncRecoveryId>,
    },
    /// The collection does not exist, or this device is not a member.
    Absent,
}

/// What the service did with one `rekey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyAnswer {
    /// The record was applied at this revision.
    Applied {
        /// The record's revision.
        revision: u64,
        /// The history that revision is in, as the collection stands when it answers.
        recovery: Option<SyncRecoveryId>,
    },
    /// The record was refused; the service names its own revision.
    Refused {
        /// The collection's revision.
        revision: u64,
        /// The history that revision is in.
        recovery: Option<SyncRecoveryId>,
    },
}

impl RekeyAnswer {
    /// Returns the history this answer came from: the recovery it named, or none for a
    /// collection never put back.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Applied { recovery, .. } | Self::Refused { recovery, .. } => *recovery,
        }
    }
}

/// What the service recorded about one `rekey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyStatus {
    /// Applied at this revision.
    Applied {
        /// The record's revision.
        revision: u64,
        /// The history that revision is in, as the collection stands now: a restored collection's
        /// history begins with what the archive held, its receipts included.
        recovery: Option<SyncRecoveryId>,
    },
    /// Refused.
    Refused {
        /// The collection's revision when it was refused.
        revision: u64,
        /// The history that revision is in.
        recovery: Option<SyncRecoveryId>,
    },
    /// The service holds no receipt for it.
    Unknown {
        /// The history that holds none.
        recovery: Option<SyncRecoveryId>,
    },
    /// It was fenced before it ran.
    Fenced {
        /// Whether the service also established that it never ran.
        never_ran: bool,
        /// The history the fence is recorded in.
        recovery: Option<SyncRecoveryId>,
    },
}

impl RekeyStatus {
    /// Returns the history this answer came from.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Applied { recovery, .. }
            | Self::Refused { recovery, .. }
            | Self::Unknown { recovery }
            | Self::Fenced { recovery, .. } => *recovery,
        }
    }
}

/// What the service answered when asked to fence one `rekey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyFence {
    /// It had already been applied at this revision.
    Applied {
        /// The record's revision.
        revision: u64,
        /// The history that revision is in.
        recovery: Option<SyncRecoveryId>,
    },
    /// It had already been refused.
    Refused {
        /// The collection's revision when it was refused.
        revision: u64,
        /// The history that revision is in.
        recovery: Option<SyncRecoveryId>,
    },
    /// It is fenced: nothing will run under its identity.
    Fenced {
        /// Whether the service also established that it never ran. False when a receipt it
        /// would have had has passed the service's retention, and for thirty days after a
        /// restore for anything signed before it.
        never_ran: bool,
        /// The history the fence is recorded in.
        recovery: Option<SyncRecoveryId>,
    },
}

impl RekeyFence {
    /// Returns the history this answer came from.
    #[must_use]
    pub const fn recovery(&self) -> Option<SyncRecoveryId> {
        match self {
            Self::Applied { recovery, .. }
            | Self::Refused { recovery, .. }
            | Self::Fenced { recovery, .. } => *recovery,
        }
    }
}

/// Where a collection's key records are kept, beside the collection, for the collection's life.
///
/// A `rekey` carries a request identity and has receipts, a status and a fence exactly as an
/// exchange does, so a device whose answer was lost can establish what became of it without
/// sending it again.
pub trait KeyRecordService: Send + Sync + std::fmt::Debug {
    /// The records after a revision, in order: every one of them, from `after + 1` to the newest.
    fn records_after<'a>(
        &'a self,
        collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords>;

    /// The record at one revision.
    fn record_at<'a>(
        &'a self,
        collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt>;

    /// Offers the record that follows the collection's newest, under a request identity.
    fn rekey<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
        signed_at_ms: u64,
        record: &'a CollectionKeyRecord,
    ) -> ServiceFuture<'a, RekeyAnswer>;

    /// What the service recorded about one `rekey`.
    fn rekey_status<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus>;

    /// Ends one `rekey` and says what became of it; `first_signed_at_ms` and `last_signed_at_ms`
    /// are the earliest and latest instants any attempt of it was signed at.
    fn rekey_fence<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, RekeyFence>;
}

/// How row 1 settled a dispatched candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Settlement {
    /// Applied at this revision.
    Applied {
        /// The record's revision.
        revision: u64,
    },
    /// Refused; this device fetches before it builds again.
    Refused {
        /// The collection's revision the refusal named.
        revision: u64,
    },
    /// Fenced before it ran.
    Fenced,
    /// Settled by the record after the candidate's base, which became the head.
    ReadAfterBase {
        /// That record's revision, or nothing when there was none yet.
        revision: Option<u64>,
    },
}

/// What one step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    /// Nothing is left to do until something changes.
    Nothing,
    /// A change the installed head carries out waits for a fetch: refresh, then step again.
    FetchNeeded,
    /// The candidate was sent once, after its dispatch mark. The answer arrived, or was lost and
    /// row 1 settles it.
    Sent {
        /// Whether the answer arrived.
        answered: bool,
    },
    /// Row 1 settled the dispatched candidate.
    Settled(Settlement),
    /// Row 1 met an answer from a collection put back under another recovery that holds this
    /// device's head: the records it holds are read in that history now, and the next step
    /// settles the candidate there.
    Followed,
    /// Row 2: this device is out of the collection; a join awaits the owner.
    Left,
    /// This device forgot one epoch's key of a collection it left.
    ForgotKeys {
        /// The epoch.
        epoch: u64,
    },
    /// Row 4 stored the key of an accepted record's epoch.
    Stored {
        /// The epoch.
        epoch: u64,
        /// The record whose key it is.
        revision: u64,
    },
    /// Row 4 recorded an accepted record as installed.
    Installed {
        /// The record's revision.
        revision: u64,
    },
    /// Row 4: the join ended as refused, and this device is out again.
    JoinRefused,
    /// Row 5 ended one or more changes as done.
    Done,
    /// Row 6 dropped an undispatched candidate.
    Dropped,
    /// Row 7 marked the candidate dispatched; the next step sends it.
    Dispatched,
    /// Row 8 refused an addition whose device fails check 3, built a candidate, or both.
    Built {
        /// Whether a candidate was built.
        built: bool,
    },
}

/// What a refresh did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refreshed {
    /// The head and the host answers are recorded.
    Recorded,
    /// No host answered, so nothing was recorded.
    NoHostAnswered,
    /// The service answered the collection as absent: this device is out.
    Left,
    /// The service answered with a chain this device cannot follow: it is out until the owner
    /// confirms a join.
    BrokenChain,
    /// The collection was put back under another recovery without the record this device holds
    /// as its head: it is out until the owner confirms a join.
    PutBack,
    /// This device is out of the collection; a join awaits the owner.
    Out,
    /// This device holds no collection.
    NoMembership,
}

/// Why a membership operation did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipError {
    /// The membership directory, its lock or its file could not be used.
    #[error("the membership store at {path} could not be used: {source}")]
    Storage {
        /// What was being read or written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The membership file is not something this build can read.
    #[error("the membership file at {path} could not be read: {reason}")]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// A value could not be encoded.
    #[error("a membership value could not be encoded: {0}")]
    Encoding(#[from] kr_cbor::CborError),
    /// A service or a host could not be asked.
    #[error("a service could not answer: {0}")]
    Service(#[source] ClientError),
    /// This device's collection keys could not be used.
    #[error("this device's collection keys could not be used: {0}")]
    Keys(#[source] ClientError),
    /// A key operation failed.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// The key an epoch this device installed is not in the store.
    #[error("this device does not hold the key of the epoch it installed, epoch {epoch}")]
    KeyMissing {
        /// The epoch.
        epoch: u64,
    },
    /// This device holds no settings collection.
    #[error("this device holds no settings collection")]
    NoMembership,
    /// This device already holds a settings collection it has not left.
    #[error("this device already holds a settings collection")]
    AlreadyMember,
    /// This device is out of its collection until the owner confirms a join on it.
    #[error("this device is out of its settings collection until the owner confirms a join on it")]
    Out,
    /// This device has not installed a record of its collection yet.
    #[error("this device has not installed a record of its settings collection yet")]
    NotInstalled,
    /// A member never removes itself: it would draw the next key. Another member removes it.
    #[error("a member cannot remove itself; another member removes it")]
    CannotRemoveSelf,
    /// The device is not a member of this collection.
    #[error("that device is not a member of this collection")]
    NotAMember,
    /// The device is already a member of this collection.
    #[error("that device is already a member of this collection")]
    AlreadyListed,
    /// No host reports the device paired and able to manage it with the keys it would be added
    /// under, so nothing may be sealed to it.
    #[error("no host this device is paired with reports that device committed")]
    NotCommitted,
    /// No host answered, so check 3 cannot run.
    #[error("no host this device is paired with answered")]
    NoHostAnswered,
    /// The collection's newest record does not list this device, or the collection answers as
    /// absent.
    #[error("the collection's newest key record does not list this device")]
    NotListed,
    /// The service's records do not form a chain this device can follow.
    #[error("the service's key records do not form a chain this device can follow")]
    BrokenChain,
    /// A plan handed back was refused.
    #[error("{0}")]
    Plan(#[from] PlanRefusal),
    /// Another handle on this membership is in the middle of an operation; try again.
    #[error("another operation on this device's membership is under way")]
    Busy,
    /// The collection was put back again while this device read it, so two of its answers came
    /// from two histories. Nothing was recorded; try again.
    #[error("the collection was put back again while this device read it")]
    PutBackWhileRead,
    /// The keys of a collection this device left are still being forgotten, a step each; a new
    /// membership is recorded only after them.
    #[error("the keys of the collection this device left are not all forgotten yet")]
    KeysStillHeld,
    /// A request this device dispatched in the collection it left is not settled yet, or can
    /// never be because a refused membership file no longer names it; a new membership is
    /// recorded only after it is settled.
    #[error("a request sent in the collection this device left is not settled")]
    UnsettledRequest,
    /// The head is at the last epoch or revision a counter holds, which has no successor, so no
    /// further record can follow it.
    #[error("this collection's key records are at their last epoch or revision")]
    Exhausted,
}

impl From<ClientError> for MembershipError {
    fn from(error: ClientError) -> Self {
        Self::Service(error)
    }
}

/// One member as the status screen shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberStatus {
    /// The device.
    pub device: Device,
    /// Whether it passes check 3 at the recorded host answers.
    pub passes: bool,
    /// Whether it is this device.
    pub is_self: bool,
}

/// The candidate record that stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateStatus {
    /// The identity its one `rekey` is sent under.
    pub request: Uuid,
    /// Its epoch.
    pub epoch: u64,
    /// Its revision.
    pub revision: u64,
    /// Whether it was marked dispatched.
    pub dispatched: bool,
}

/// What the status screen shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipStatus {
    /// The collection.
    pub collection: CollectionRef,
    /// The installed record's epoch and revision, when one is installed.
    pub installed: Option<(u64, u64)>,
    /// The head's revision.
    pub head: u64,
    /// The history the records this device holds were read in: the recovery the collection
    /// named, or none for a collection never put back.
    pub recovery: Option<SyncRecoveryId>,
    /// The installed record's members.
    pub members: Vec<MemberStatus>,
    /// The pending removals.
    pub removals: Vec<Device>,
    /// The pending addition.
    pub addition: Option<Device>,
    /// The candidate record that stands, when one does.
    pub candidate: Option<CandidateStatus>,
    /// Whether this device may publish into the collection now.
    pub publishes: bool,
    /// Whether this device is out and a join awaits the owner.
    pub out: bool,
    /// The outcomes not yet shown.
    pub outcomes: Vec<Outcome<Device>>,
}

/// This device's membership of its settings collection.
///
/// Every method takes the membership file's lock for its whole length, so two windows or two
/// processes over one directory never interleave.
pub struct SyncMembership {
    reconciler: Reconciler<DeviceEnvironment>,
    plans: Plans,
}

impl std::fmt::Debug for SyncMembership {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncMembership")
            .field("environment", &self.reconciler.env)
            .finish_non_exhaustive()
    }
}

impl SyncMembership {
    /// Opens this device's membership store in `directory`.
    ///
    /// `device` is this device's own keys: the authorisation key signs the records it issues and
    /// the stored-envelope key opens its wraps. `keys` is where collection keys are kept,
    /// `service` holds the key records and `hosts` answers check 3.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::Storage`] when the directory cannot be created or locked.
    pub fn open(
        directory: impl Into<PathBuf>,
        device: &DeviceKeys,
        keys: StoredCollectionKeys,
        service: Arc<dyn KeyRecordService>,
        hosts: Arc<dyn DeviceDirectory>,
    ) -> Result<Self, MembershipError> {
        let env = DeviceEnvironment {
            authorisation: device.authorisation.clone(),
            envelope: device.stored_envelope.clone(),
            keys,
            file: MembershipFile::open(directory)?,
            service,
            hosts,
        };
        Ok(Self {
            reconciler: Reconciler::new(env),
            plans: Plans::default(),
        })
    }

    /// This device, as a record names it.
    #[must_use]
    pub fn me(&self) -> Device {
        use environment::Environment as _;
        self.reconciler.env.me()
    }

    /// The directory the membership file is kept in.
    #[must_use]
    pub fn directory(&self) -> &std::path::Path {
        self.reconciler.env.file.directory()
    }

    /// Turns settings sync on here: a new collection, with this device's own first record as its
    /// first candidate. The key lives only in that record's wrap until the claim applies and row 4
    /// installs it.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::AlreadyMember`] when this device holds a collection it has not
    /// left, and a storage or key error otherwise.
    pub async fn start(
        &mut self,
        collection_id: SyncCollectionId,
        now: TimestampMs,
    ) -> Result<CollectionRef, MembershipError> {
        let collection = CollectionRef {
            home: self.me().installation_id(),
            collection_id,
        };
        // A collection this device left is settled first: a request it dispatched there, then
        // its keys, one write each.
        while self.reconciler.settle_left().await? {}
        self.reconciler.start(collection, now)?;
        Ok(collection)
    }

    /// Runs the first row that applies. See the module's table.
    ///
    /// # Errors
    ///
    /// A storage, key or service failure, or [`MembershipError::PutBackWhileRead`] when the
    /// collection was put back again between two of the step's reads. Nothing was written when a
    /// step fails.
    pub async fn step(&mut self, now: TimestampMs) -> Result<Step, MembershipError> {
        self.reconciler.step(now).await
    }

    /// Refreshes, then steps until nothing is left to do: after a refusal and whenever a change
    /// waits only for a fetch, it refreshes before it steps again.
    ///
    /// # Errors
    ///
    /// As [`Self::step`] and [`Self::refresh`].
    pub async fn reconcile(&mut self, now: TimestampMs) -> Result<Vec<Step>, MembershipError> {
        let mut steps = Vec::new();
        self.refresh().await?;
        // Every row either ends a pending change, installs, moves a candidate on, or leaves, so a
        // bounded number of steps settles; the bound only stops a service that keeps answering
        // with something new.
        for _ in 0..256 {
            let step = self.step(now).await?;
            steps.push(step);
            if step == Step::Nothing {
                break;
            }
            // A refresh clears every change's wait for a fetch, so the step after it moves on;
            // after a refusal, a newer record may exist. A refresh no host answers changes
            // nothing, so the steps stop there; one that ends the membership goes on to what a
            // device that is out still owes.
            let fetch = matches!(
                step,
                Step::FetchNeeded | Step::Settled(Settlement::Refused { .. } | Settlement::Fenced)
            );
            if fetch
                && matches!(
                    self.refresh().await?,
                    Refreshed::NoHostAnswered | Refreshed::NoMembership
                )
            {
                break;
            }
        }
        Ok(steps)
    }

    /// Asks the hosts and fetches the records after the head, recording both in one write with
    /// the removals the answers require.
    ///
    /// # Errors
    ///
    /// A storage or service failure, or [`MembershipError::PutBackWhileRead`] when the collection
    /// was put back again between two of the refresh's reads; nothing was written then.
    pub async fn refresh(&mut self) -> Result<Refreshed, MembershipError> {
        self.reconciler.refresh().await
    }

    /// The devices the recorded host answers report committed that are not members: those the
    /// owner may add.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn candidates(&self) -> Result<Vec<Device>, MembershipError> {
        let Some((facts, _)) = self.reconciler.read()? else {
            return Ok(Vec::new());
        };
        let members: BTreeSet<Device> = facts
            .installed_record()
            .map(DeviceKinds::members)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut found = BTreeSet::new();
        for report in &facts.answers.hosts.reports {
            for reported in &report.devices {
                let device = Device {
                    authorisation: reported.authorisation,
                    stored_envelope: reported.stored_envelope,
                };
                if !members.contains(&device) && facts.answers.passes(&device) {
                    found.insert(device);
                }
            }
        }
        Ok(found.into_iter().collect())
    }

    /// Plans sharing this collection with a device its hosts report committed, for the owner to
    /// confirm on this device ("share settings with *name*").
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::NotCommitted`] when no recorded host answer reports the device
    /// paired and able to manage the host, so its keys come from nowhere else.
    pub fn plan_share(
        &mut self,
        device: &AuthorisationKey,
        now: TimestampMs,
    ) -> Result<Plan, MembershipError> {
        let (facts, _) = self
            .reconciler
            .read()?
            .ok_or(MembershipError::NoMembership)?;
        let installed = facts
            .installed_record()
            .ok_or(MembershipError::NotInstalled)?;
        let recipient = facts
            .answers
            .committed(device)
            .ok_or(MembershipError::NotCommitted)?;
        let id = self.fresh_id()?;
        Ok(self.plans.make(
            id,
            PlannedOperation::Share {
                collection: facts.collection,
                epoch: DeviceKinds::epoch(installed),
                device: recipient,
            },
            now,
        )?)
    }

    /// Adds the device a confirmed plan names. The plan is consumed once.
    ///
    /// Returns [`Ended::Refused`] when the addition was refused and reported, because a removal
    /// of the device is pending or another addition is (I3).
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::Plan`] for a plan that is unknown, swapped, expired or stale.
    pub fn authorise(&mut self, plan: &Plan, now: TimestampMs) -> Result<Ended, MembershipError> {
        let plan = self.plans.consume(plan, now)?;
        let PlannedOperation::Share {
            collection,
            epoch,
            device,
        } = plan.operation
        else {
            return Err(PlanRefusal::Substituted.into());
        };
        self.reconciler.add(device, collection, epoch)
    }

    /// Plans joining a collection another device shares, for the owner to confirm on this device
    /// ("join settings shared by *name*").
    ///
    /// # Errors
    ///
    /// When a plan identity cannot be drawn.
    pub fn plan_join(
        &mut self,
        collection: CollectionRef,
        now: TimestampMs,
    ) -> Result<Plan, MembershipError> {
        let id = self.fresh_id()?;
        Ok(self
            .plans
            .make(id, PlannedOperation::Join { collection }, now)?)
    }

    /// Joins the collection a confirmed plan names: the newest record that lists this device
    /// becomes its join record, checked as a new member. The plan is consumed once.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::Plan`] for a refused plan, [`MembershipError::NotListed`] when
    /// the newest record does not list this device, and [`MembershipError::AlreadyMember`] when
    /// this device holds a collection it has not left.
    pub async fn join(&mut self, plan: &Plan, now: TimestampMs) -> Result<(), MembershipError> {
        // A collection this device left is settled first: a request it dispatched there, then
        // its keys, one write each.
        while self.reconciler.settle_left().await? {}
        let plan = self.plans.consume(plan, now)?;
        let PlannedOperation::Join { collection } = plan.operation else {
            return Err(PlanRefusal::Substituted.into());
        };
        self.reconciler.join(collection).await
    }

    /// Withdraws a plan the owner did not confirm.
    pub fn cancel(&mut self, plan: &Plan) {
        self.plans.cancel(plan.id);
    }

    /// Removes a device from the collection. No new ceremony: the owner's use of this member is
    /// enough to take rights away.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipError::CannotRemoveSelf`] for this device and
    /// [`MembershipError::NotAMember`] for a device the collection does not list.
    pub fn remove(&mut self, device: &AuthorisationKey) -> Result<(), MembershipError> {
        if *device == self.me().authorisation {
            return Err(MembershipError::CannotRemoveSelf);
        }
        let (facts, _) = self
            .reconciler
            .read()?
            .ok_or(MembershipError::NoMembership)?;
        let listed = [facts.installed_record(), facts.head_record()]
            .into_iter()
            .flatten()
            .flat_map(DeviceKinds::members)
            .chain(facts.addition)
            .chain(facts.removals.iter().copied())
            .find(|member| member.authorisation == *device)
            .ok_or(MembershipError::NotAMember)?;
        self.reconciler.remove(listed)
    }

    /// Records a revocation this device verified from an authority feed, with the removals it
    /// requires, before any host answers.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn feed_revocation(&mut self, device: &AuthorisationKey) -> Result<(), MembershipError> {
        self.reconciler.feed_revocation(*device)
    }

    /// Whether this device may publish into the collection now.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn publishes(&self) -> Result<bool, MembershipError> {
        use environment::Environment as _;
        let Some((facts, held)) = self.reconciler.read()? else {
            return Ok(false);
        };
        let view = View {
            facts: &facts,
            me: self.reconciler.env.me(),
            held: &held,
        };
        Ok(view.publishes())
    }

    /// What the status screen shows, or nothing when this device holds no collection.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn members(&self) -> Result<Option<MembershipStatus>, MembershipError> {
        use environment::Environment as _;
        let Some((facts, held)) = self.reconciler.read()? else {
            return Ok(None);
        };
        let me = self.reconciler.env.me();
        let view = View {
            facts: &facts,
            me,
            held: &held,
        };
        let installed = facts.installed_record();
        let members = installed
            .map(DeviceKinds::members)
            .unwrap_or_default()
            .into_iter()
            .map(|device| MemberStatus {
                device,
                passes: view.passes(&device),
                is_self: device == me,
            })
            .collect();
        Ok(Some(MembershipStatus {
            collection: facts.collection,
            installed: installed
                .map(|record| (DeviceKinds::epoch(record), DeviceKinds::revision(record))),
            head: facts.head,
            recovery: facts.recovery.0,
            members,
            removals: facts.removals.iter().copied().collect(),
            addition: facts.addition,
            candidate: facts.candidate.as_ref().map(|candidate| CandidateStatus {
                request: candidate.request,
                epoch: DeviceKinds::epoch(&candidate.record),
                revision: DeviceKinds::revision(&candidate.record),
                dispatched: candidate.dispatched.is_some(),
            }),
            publishes: view.publishes(),
            out: facts.out,
            outcomes: facts.outcomes.clone(),
        }))
    }

    /// The outcomes not yet shown.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn outcomes(&self) -> Result<Vec<Outcome<Device>>, MembershipError> {
        Ok(self
            .reconciler
            .read()?
            .map(|(facts, _)| facts.outcomes)
            .unwrap_or_default())
    }

    /// Clears the first `shown` outcomes, once the screen has shown them.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn acknowledge_outcomes(&mut self, shown: usize) -> Result<(), MembershipError> {
        self.reconciler.acknowledge(shown)
    }

    /// A fresh identity for a plan.
    fn fresh_id(&self) -> Result<Uuid, MembershipError> {
        kr_transport::random::fresh_uuid_v4()
            .map_err(|error| MembershipError::Service(error.into()))
    }
}
