//! The membership file's facts, and the decisions the reconciler takes from them alone.
//!
//! Everything here is pure: a decision reads the facts, the host answers they hold and which
//! epochs' keys the store holds, and a transition returns the facts the next write replaces the
//! file with. Nothing here signs, opens, stores or asks anything; [`super::reconciler`] does that
//! around these functions, one durable write per step.
//!
//! The rows are those of the table in the module documentation, in its order, and each function
//! says which one it is. They are written over [`Kinds`], so the same code decides on a device,
//! over signed records, and in this library's exhaustive test, over stand-in records small enough
//! to enumerate every reachable combination of the facts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::Hash;

use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::CollectionRef;
use crate::services::{SyncRecoveryId, names_no_recovery};

/// The shapes a reconciler works over, and the questions about a record that need no key.
///
/// A device's own implementation reads signed key records; the exhaustive test's reads records
/// made of a few small numbers. Everything that needs a key is on
/// [`super::environment::Environment`] instead.
pub(crate) trait Kinds:
    Clone + fmt::Debug + PartialEq + Eq + Hash + Default + Send + Sync + 'static
{
    /// One device a record names.
    type Member: Copy + Ord + Hash + fmt::Debug + Serialize + DeserializeOwned + Send + Sync;
    /// One key record.
    type Record: Clone + PartialEq + Eq + fmt::Debug + Serialize + DeserializeOwned + Send + Sync;
    /// What stands for a collection key where only equality matters. Never the key.
    type Mark: Copy + Ord + Hash + fmt::Debug + Serialize + DeserializeOwned + Send + Sync;
    /// Check 3's answers as this device last recorded them.
    type Answers: Clone
        + PartialEq
        + Eq
        + fmt::Debug
        + Default
        + Serialize
        + DeserializeOwned
        + Send
        + Sync;
    /// What a revocation verified from an authority feed names.
    type Revocation: Copy + Ord + fmt::Debug + Send + Sync;

    /// Returns a record's revision.
    fn revision(record: &Self::Record) -> u64;
    /// Returns the epoch of the key a record carries.
    fn epoch(record: &Self::Record) -> u64;
    /// Returns the member that issued a record, when the record names it among its members.
    fn issuer(record: &Self::Record) -> Option<Self::Member>;
    /// Returns every member a record names.
    fn members(record: &Self::Record) -> Vec<Self::Member>;
    /// Returns true when a record names this member, with every key the member is known by.
    fn lists(record: &Self::Record, member: &Self::Member) -> bool;
    /// Check 3 for a device other than this one: at least one host reports it paired and holding
    /// the right to manage the host with the keys it is named by, and nothing reports it revoked.
    fn passes(answers: &Self::Answers, member: &Self::Member) -> bool;
    /// Records a revocation this device verified from an authority feed.
    fn revoke(answers: &mut Self::Answers, revocation: Self::Revocation);
    /// Returns the answers a refresh records: the hosts' answers now, and every revocation this
    /// device verified from a feed, which a host that has not caught up yet does not undo.
    fn refreshed(previous: &Self::Answers, fresh: Self::Answers) -> Self::Answers;
}

/// The format of the membership file this build writes and reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum MembershipFormat {
    /// Version 1.
    #[serde(rename = "kr-sync-membership/1")]
    V1,
}

/// A pending change the owner or the host answers asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Change<M> {
    /// Remove this device from the collection.
    Removal(M),
    /// Add this device to the collection.
    Addition(M),
}

/// How a pending change ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ended {
    /// The installed record carries it out, at a head fetched after it was recorded.
    Done,
    /// A newer intent of the owner's replaced it: a removal of the device it would have added.
    Cancelled,
    /// It could not be carried out: the device fails check 3, a removal of it is pending, or this
    /// device is no longer a member.
    Refused,
}

/// A change that ended, kept until the screen has shown it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome<M> {
    /// A removal ended.
    Removal {
        /// The device.
        device: M,
        /// How it ended.
        ended: Ended,
    },
    /// An addition ended.
    Addition {
        /// The device.
        device: M,
        /// How it ended.
        ended: Ended,
    },
    /// A join the owner confirmed ended: refused when this device accepts no record from the one
    /// it joined at on.
    Join {
        /// How it ended.
        ended: Ended,
    },
}

impl<M: Copy> Outcome<M> {
    /// Returns the outcome of one pending change.
    pub(crate) const fn of(change: Change<M>, ended: Ended) -> Self {
        match change {
            Change::Removal(device) => Self::Removal { device, ended },
            Change::Addition(device) => Self::Addition { device, ended },
        }
    }
}

/// One record this device opened since its current join, by the mark of the key it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Opened<A> {
    /// The record's revision.
    pub revision: u64,
    /// The record's epoch.
    pub epoch: u64,
    /// The mark of the key this device opened from its own wrap in it.
    pub mark: A,
}

/// The member whose record opened one epoch, which check 3 applies to as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Opener<M> {
    /// The epoch.
    pub epoch: u64,
    /// The issuer of the first record at that epoch.
    pub issuer: M,
}

/// The one successor record this device may have standing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidate<R, A> {
    /// The record, signed, with the key wrapped for every member it names. Its key lives only
    /// inside this device's own wrap until row 4 stores it.
    pub record: R,
    /// The mark of that key, taken when the key was drawn: what is withdrawn when the record
    /// settles without applying.
    pub mark: A,
    /// The identity the one `rekey` of it is sent under.
    pub request: Uuid,
    /// The dispatch mark: written before the one send, with the signing time of that attempt.
    pub dispatched: Option<TimestampMs>,
}

/// Everything the membership file holds, replaced whole at every write.
///
/// The ten facts of the reconciler, plus what they are read with: the records between the
/// installed one and the head (the chain check 2 accepted), the issuer that opened each epoch,
/// the mark of every key this device opened since its current join (check 5), and the history
/// those records were read in.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub(crate) struct Facts<K: Kinds> {
    /// The file format.
    pub format: MembershipFormat,
    /// The collection.
    pub collection: CollectionRef,
    /// The revision of the join record: the record the owner confirmed this device into, which is
    /// the first one for a collection this device started.
    pub join: u64,
    /// The installed record: the newest record this device accepted, whose epoch's key it holds as
    /// current. Zero until it installs one after its join.
    pub installed: u64,
    /// The head: the newest record whose chain from the installed one passes check 2, accepted or
    /// not. Zero until this device knows a record.
    pub head: u64,
    /// The records from the installed one (or the join record, before an installation) to the
    /// head, in order and without a gap.
    pub records: Vec<K::Record>,
    /// The member whose record opened each epoch from the join record's epoch on, by epoch.
    pub openers: Vec<Opener<K::Member>>,
    /// Every record since the join this device opened, with the mark of the key it carried.
    pub opened: BTreeSet<Opened<K::Mark>>,
    /// The marks of the keys of candidates this device sent since its join that never applied.
    /// A service can hand out the wraps of such a candidate, so no record carrying one of these
    /// keys is accepted (check 5), and the device rotates away from one as from any refused head.
    pub withdrawn: BTreeSet<K::Mark>,
    /// Check 3's answers as last recorded.
    pub answers: K::Answers,
    /// The pending removals.
    pub removals: BTreeSet<K::Member>,
    /// The one pending addition the owner confirmed.
    pub addition: Option<K::Member>,
    /// The one candidate successor record.
    pub candidate: Option<Candidate<K::Record, K::Mark>>,
    /// True when this device is out of the collection and a join awaits the owner (row 3).
    pub out: bool,
    /// The outcomes not yet shown to the person.
    pub outcomes: Vec<Outcome<K::Member>>,
    /// The pending changes recorded since the head was last fetched.
    pub unfetched: BTreeSet<Change<K::Member>>,
    /// The history the records were read in: the recovery the collection named, or none for a
    /// collection never put back. A file written before histories were recorded names none,
    /// which is how this device read the collection then, and it is written without the member
    /// while it names none, so such a file keeps its shape.
    #[serde(default = "Nullable::null", skip_serializing_if = "names_no_recovery")]
    pub recovery: Nullable<SyncRecoveryId>,
}

impl<K: Kinds> std::fmt::Debug for Facts<K> {
    /// Where the membership stands and how much it holds. Never a record, a member or an answer.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Facts")
            .field("join", &self.join)
            .field("installed", &self.installed)
            .field("head", &self.head)
            .field("records", &self.records.len())
            .field("out", &self.out)
            .field("recovery", &self.recovery)
            .finish_non_exhaustive()
    }
}

/// Why a file's facts are not ones any sequence of writes produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Inconsistent(pub &'static str);

impl<K: Kinds> Facts<K> {
    /// The facts of a collection this device starts: its own first record as the only candidate.
    pub(crate) fn genesis(
        collection: CollectionRef,
        record: K::Record,
        mark: K::Mark,
        request: Uuid,
        answers: K::Answers,
    ) -> Self {
        Self {
            format: MembershipFormat::V1,
            collection,
            join: 1,
            installed: 0,
            head: 0,
            records: Vec::new(),
            openers: Vec::new(),
            opened: BTreeSet::new(),
            withdrawn: BTreeSet::new(),
            answers,
            removals: BTreeSet::new(),
            addition: None,
            candidate: Some(Candidate {
                record,
                mark,
                request,
                dispatched: None,
            }),
            out: false,
            outcomes: Vec::new(),
            unfetched: BTreeSet::new(),
            // A collection this device starts has no history until its claim applies in one.
            recovery: Nullable::null(),
        }
    }

    /// Whether an answer from this history may change the facts: one from the history the
    /// records were read in, or any while this device holds no record, when there is nothing to
    /// hold it to.
    pub(crate) fn follows(&self, answered: Option<SyncRecoveryId>) -> bool {
        self.head == 0 || self.recovery.0 == answered
    }

    /// The revision the record window starts at.
    pub(crate) const fn window_start(&self) -> u64 {
        if self.installed > 0 {
            self.installed
        } else {
            self.join
        }
    }

    /// Returns the record at a revision, when it is in the window.
    pub(crate) fn record(&self, revision: u64) -> Option<&K::Record> {
        let start = self.window_start();
        if revision < start || self.records.is_empty() {
            return None;
        }
        let index = usize::try_from(revision - start).ok()?;
        self.records.get(index)
    }

    /// Returns the installed record.
    pub(crate) fn installed_record(&self) -> Option<&K::Record> {
        if self.installed == 0 {
            return None;
        }
        self.record(self.installed)
    }

    /// Returns the head record.
    pub(crate) fn head_record(&self) -> Option<&K::Record> {
        if self.head == 0 {
            return None;
        }
        self.record(self.head)
    }

    /// Returns the records after the installed one: from the join record on before an
    /// installation, and after the installed record once there is one.
    pub(crate) fn after_installed(&self) -> &[K::Record] {
        if self.installed > 0 {
            self.records.get(1..).unwrap_or(&[])
        } else {
            &self.records
        }
    }

    /// Returns the epochs this device may hold a key for: those of every record it opened since
    /// its join.
    pub(crate) fn epochs(&self) -> BTreeSet<u64> {
        self.opened.iter().map(|opened| opened.epoch).collect()
    }

    /// Returns the member whose record opened an epoch.
    pub(crate) fn opener(&self, epoch: u64) -> Option<K::Member> {
        self.openers
            .iter()
            .find(|opener| opener.epoch == epoch)
            .map(|opener| opener.issuer)
    }

    /// Returns the mark of the key this device opened from a record, when it opened one.
    pub(crate) fn mark(&self, revision: u64) -> Option<K::Mark> {
        self.opened
            .iter()
            .find(|opened| opened.revision == revision)
            .map(|opened| opened.mark)
    }

    /// Takes one record into the window as the new head.
    ///
    /// The caller has checked that it follows the head (check 2) and computed the mark of the key
    /// this device opens from it, when it lists this device.
    pub(crate) fn push(&mut self, record: K::Record, mark: Option<K::Mark>) {
        let revision = K::revision(&record);
        let epoch = K::epoch(&record);
        let opens = self
            .head_record()
            .is_none_or(|head| K::epoch(head) != epoch);
        if opens
            && let Some(issuer) = K::issuer(&record)
            && self.opener(epoch).is_none()
        {
            self.openers.push(Opener { epoch, issuer });
            self.openers.sort();
        }
        if let Some(mark) = mark {
            self.opened.insert(Opened {
                revision,
                epoch,
                mark,
            });
        }
        self.records.push(record);
        self.head = revision;
    }

    /// Moves the head back to a revision, forgetting the records after it. Only a weakened rule
    /// of the exhaustive test does this.
    pub(crate) fn truncate(&mut self, head: u64) {
        let keep = usize::try_from(head.saturating_sub(self.window_start()) + 1).unwrap_or(0);
        self.records.truncate(keep);
        self.head = head;
    }

    /// Row 4: records a record as installed, which drops the records before it from the window.
    pub(crate) fn install(&mut self, revision: u64) {
        let start = self.window_start();
        let drop = usize::try_from(revision - start).unwrap_or(0);
        self.records.drain(..drop.min(self.records.len()));
        self.installed = revision;
    }

    /// Ends one pending change with its outcome, in the write that ends it.
    pub(crate) fn end(&mut self, change: Change<K::Member>, ended: Ended) {
        match change {
            Change::Removal(member) => {
                self.removals.remove(&member);
            }
            Change::Addition(member) => {
                if self.addition == Some(member) {
                    self.addition = None;
                }
            }
        }
        self.unfetched.remove(&change);
        self.outcomes.push(Outcome::of(change, ended));
    }

    /// Records a pending change, waiting for a fetch unless the head was fetched in this write.
    pub(crate) fn begin(&mut self, change: Change<K::Member>, fetched: bool) {
        match change {
            Change::Removal(member) => {
                self.removals.insert(member);
            }
            Change::Addition(member) => self.addition = Some(member),
        }
        if !fetched {
            self.unfetched.insert(change);
        }
    }

    /// Applies the recorded host answers, as every write that records them or moves the head
    /// does: a pending addition of a device that fails check 3 is refused, and a removal is
    /// recorded for every device that fails it and is listed in the installed record or the head,
    /// and for every issuer after the installed record that fails it.
    pub(crate) fn record_answers(&mut self, me: &K::Member, fetched: bool) {
        let passes =
            |answers: &K::Answers, member: &K::Member| member == me || K::passes(answers, member);
        if let Some(addition) = self.addition
            && !passes(&self.answers, &addition)
        {
            self.end(Change::Addition(addition), Ended::Refused);
        }
        let mut listed = BTreeSet::new();
        for record in [self.installed_record(), self.head_record()]
            .into_iter()
            .flatten()
        {
            listed.extend(K::members(record));
        }
        let mut failing: BTreeSet<K::Member> = listed
            .into_iter()
            .filter(|member| !passes(&self.answers, member))
            .collect();
        failing.extend(
            self.after_installed()
                .iter()
                .filter_map(K::issuer)
                .filter(|issuer| !passes(&self.answers, issuer)),
        );
        failing.remove(me);
        if weakened(Rule::RefreshRecordsNoRemoval) {
            failing.clear();
        }
        let new: Vec<K::Member> = failing.difference(&self.removals).copied().collect();
        for member in new {
            if self.addition == Some(member) {
                self.end(Change::Addition(member), Ended::Cancelled);
            }
            self.begin(Change::Removal(member), fetched);
        }
    }

    /// Row 2's action: this device is out. Every pending change ends as refused, an undispatched
    /// candidate goes with its key, and a join awaits the owner. A dispatched candidate stays: it
    /// leaves the file only through row 1's settlement, which a device that is out still runs
    /// before anything else. The collection's keys are forgotten by the steps that follow, never
    /// before this write.
    pub(crate) fn leave(&mut self) {
        let removals: Vec<K::Member> = self.removals.iter().copied().collect();
        for member in removals {
            self.end(Change::Removal(member), Ended::Refused);
        }
        if let Some(addition) = self.addition {
            self.end(Change::Addition(addition), Ended::Refused);
        }
        if self.candidate.as_ref().is_some_and(|candidate| {
            candidate.dispatched.is_none() || weakened(Rule::LeaveDropsDispatched)
        }) {
            self.candidate = None;
        }
        self.unfetched.clear();
        self.out = true;
    }

    /// Whether a dispatched candidate stands, which nothing but row 1's settlement removes.
    pub(crate) fn dispatched(&self) -> bool {
        self.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.dispatched.is_some())
    }

    /// Whether the dispatched candidate is one a refused file no longer names: out, dispatched,
    /// and without a request identity. Its request may have been sent and may still run, and no
    /// status or fence can answer for a request nobody can name, so it is never settled and no new
    /// membership is recorded while it stands.
    pub(crate) fn unsettleable(&self) -> bool {
        self.out
            && self.candidate.as_ref().is_some_and(|candidate| {
                candidate.dispatched.is_some() && candidate.request == Uuid::NIL
            })
    }

    /// Facts the load check refused, read as this device being out of the collection with a join
    /// awaiting the owner (row 3). The records go, since nothing about them can be trusted; a
    /// rejoin reads the chain again from the service. What is kept is the collection, the
    /// outcomes, the epochs of the keys the store may still hold, so the steps that follow can
    /// forget them, and a dispatched candidate, whose request row 1 still settles first. One
    /// whose request identity the file lost stays too: nothing can settle a request nobody can
    /// name, so no new membership is recorded while it stands (see [`Self::unsettleable`]).
    pub(crate) fn refused(mut self) -> Self {
        self.leave();
        self.join = 1;
        self.installed = 0;
        self.head = 0;
        self.records.clear();
        self.openers.clear();
        self
    }

    /// The load check: refuses facts no sequence of writes produces.
    pub(crate) fn check(&self, me: &K::Member) -> Result<(), Inconsistent> {
        if self.join == 0 {
            return Err(Inconsistent("a join record at revision zero"));
        }
        if self.installed > self.head {
            return Err(Inconsistent("an installed record after the head"));
        }
        if self.installed > 0 && self.installed < self.join {
            return Err(Inconsistent("an installed record before the join record"));
        }
        if self.head == 0 {
            if self.join != 1 || !self.records.is_empty() {
                return Err(Inconsistent("records without a head"));
            }
        } else {
            if self.head < self.join {
                return Err(Inconsistent("a head before the join record"));
            }
            let expected = self.head - self.window_start() + 1;
            if u64::try_from(self.records.len()) != Ok(expected) {
                return Err(Inconsistent("a record window with a gap"));
            }
            for (offset, record) in self.records.iter().enumerate() {
                let offset = u64::try_from(offset).unwrap_or(u64::MAX);
                if K::revision(record) != self.window_start().saturating_add(offset) {
                    return Err(Inconsistent("a record window out of order"));
                }
                if self.opener(K::epoch(record)).is_none() {
                    return Err(Inconsistent("an epoch with no record that opened it"));
                }
            }
            // The installed record, and before an installation the join record, is one this
            // device accepted or was confirmed into, so it lists this device.
            if !self.out
                && self
                    .records
                    .first()
                    .is_some_and(|record| !K::lists(record, me))
            {
                return Err(Inconsistent("a held record that does not list this device"));
            }
        }
        if self.removals.contains(me) || self.addition.as_ref() == Some(me) {
            return Err(Inconsistent("a pending change of this device itself"));
        }
        if let Some(addition) = &self.addition
            && self.removals.contains(addition)
        {
            return Err(Inconsistent("an addition pending beside its removal"));
        }
        for change in &self.unfetched {
            let pending = match change {
                Change::Removal(member) => self.removals.contains(member),
                Change::Addition(member) => self.addition.as_ref() == Some(member),
            };
            if !pending {
                return Err(Inconsistent("a wait for a fetch of no pending change"));
            }
        }
        if self.out
            && (!self.removals.is_empty()
                || self.addition.is_some()
                || self
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.dispatched.is_none()))
        {
            return Err(Inconsistent(
                "pending work in a collection this device left",
            ));
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.request == Uuid::NIL)
            && !self.unsettleable()
        {
            return Err(Inconsistent("a candidate without a request identity"));
        }
        if let Some(candidate) = self.candidate.as_ref().filter(|_| !self.out) {
            let revision = K::revision(&candidate.record);
            if revision == 0 || revision - 1 > self.head {
                return Err(Inconsistent("a candidate built on a record after the head"));
            }
            if !K::lists(&candidate.record, me) {
                return Err(Inconsistent("a candidate that leaves this device out"));
            }
        }
        if self.opened.iter().any(|opened| opened.revision < self.join) {
            return Err(Inconsistent("a key opened before the join record"));
        }
        Ok(())
    }
}

/// What row 8 builds now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Desired<M> {
    /// The revision it is built on: the head, or zero for the first record.
    pub base: u64,
    /// Its epoch.
    pub epoch: u64,
    /// Its members.
    pub members: BTreeSet<M>,
    /// True when it keeps the installed record's epoch and key, which only a weakened rule of the
    /// exhaustive test does.
    pub same_epoch: bool,
}

/// The facts, read against the host answers they hold and the keys the store holds.
pub(crate) struct View<'a, K: Kinds> {
    /// The facts.
    pub facts: &'a Facts<K>,
    /// This device.
    pub me: K::Member,
    /// The mark of the key the store holds for each epoch it holds one for.
    pub held: &'a BTreeMap<u64, K::Mark>,
}

impl<K: Kinds> View<'_, K> {
    /// Check 3 as the recorded answers give it. This device does not check itself.
    pub(crate) fn passes(&self, member: &K::Member) -> bool {
        *member == self.me || K::passes(&self.facts.answers, member)
    }

    /// Checks 1 to 5 against the recorded answers and the held keys, the epoch's opener included.
    ///
    /// Checks 2 and 4 held when the record entered the window: it follows the record before it,
    /// signed by an issuer that record named, whose signature this device verified when it opened
    /// its own wrap. What is left is check 1 (its own entry), check 3 for the issuer and for the
    /// issuer of the record that opened its epoch, and check 5: the key it opened is the one held
    /// for an epoch this device holds, and for another epoch differs from every key it holds and
    /// every key it opened from an earlier record of another epoch since its join.
    pub(crate) fn accepted(&self, record: &K::Record) -> bool {
        if !K::lists(record, &self.me) {
            return false;
        }
        let Some(mark) = self.facts.mark(K::revision(record)) else {
            return false;
        };
        // A key this device drew for a candidate that never applied was wrapped for its members
        // all the same, and a service can hand those wraps out: it is never the key in use.
        if !weakened(Rule::NoWithdrawnCheck) && self.facts.withdrawn.contains(&mark) {
            return false;
        }
        let Some(issuer) = K::issuer(record) else {
            return false;
        };
        if !self.passes(&issuer) {
            return false;
        }
        let epoch = K::epoch(record);
        if !weakened(Rule::NoOpenerCheck) {
            let opener_passes = self
                .facts
                .opener(epoch)
                .is_some_and(|opener| self.passes(&opener));
            if !opener_passes {
                return false;
            }
        }
        if let Some(held) = self.held.get(&epoch) {
            return *held == mark;
        }
        if weakened(Rule::NoFreshKeyCheck) {
            return true;
        }
        let revision = K::revision(record);
        let earlier = self.facts.opened.iter().any(|opened| {
            opened.revision >= self.facts.join
                && opened.revision < revision
                && opened.epoch != epoch
                && opened.mark == mark
        });
        !earlier && !self.held.values().any(|held| *held == mark)
    }

    /// Row 2: a record after the installed one, from the join record on, leaves this device out.
    pub(crate) fn left_out(&self) -> bool {
        if weakened(Rule::GapKeepsMembership) {
            return self
                .facts
                .head_record()
                .is_some_and(|head| !K::lists(head, &self.me));
        }
        self.facts
            .after_installed()
            .iter()
            .any(|record| !K::lists(record, &self.me))
    }

    /// Row 4: the newest record after the installed one this device accepts.
    pub(crate) fn newest_accepted(&self) -> Option<&K::Record> {
        self.facts
            .after_installed()
            .iter()
            .rev()
            .find(|record| self.accepted(record))
    }

    /// The pending changes the installed record and the head carry out, which row 5 ends as done
    /// when the head was fetched after each was recorded.
    pub(crate) fn done(&self) -> Vec<Change<K::Member>> {
        let (Some(installed), Some(head)) =
            (self.facts.installed_record(), self.facts.head_record())
        else {
            return Vec::new();
        };
        let fetched = |change: &Change<K::Member>| {
            weakened(Rule::DoneWithoutFetch) || !self.facts.unfetched.contains(change)
        };
        let mut done: Vec<Change<K::Member>> = self
            .facts
            .removals
            .iter()
            .filter(|member| !K::lists(installed, member) && !K::lists(head, member))
            .map(|member| Change::Removal(*member))
            .filter(fetched)
            .collect();
        if let Some(addition) = self.facts.addition
            && K::lists(installed, &addition)
            && K::lists(head, &addition)
            && fetched(&Change::Addition(addition))
        {
            done.push(Change::Addition(addition));
        }
        done
    }

    /// The candidate row 8 builds now, or nothing when the head is at the last epoch or revision a
    /// counter can hold, which has no successor.
    ///
    /// Every candidate takes the head's epoch plus one and a freshly drawn key, wrapped only for
    /// its members: this device wraps the key in use only for the devices its installed record
    /// lists, so a candidate that is sent and never applied exposes no key anybody writes with.
    pub(crate) fn desired(&self) -> Option<Desired<K::Member>> {
        let (Some(installed), Some(head)) =
            (self.facts.installed_record(), self.facts.head_record())
        else {
            return Some(Desired {
                base: 0,
                epoch: 0,
                members: BTreeSet::from([self.me]),
                same_epoch: false,
            });
        };
        let start = if weakened(Rule::BuildFromHead) {
            K::members(head)
        } else {
            K::members(installed)
        };
        let mut members: BTreeSet<K::Member> = start
            .into_iter()
            .filter(|member| !self.facts.removals.contains(member) && self.passes(member))
            .collect();
        if let Some(addition) = self.facts.addition
            && self.passes(&addition)
        {
            members.insert(addition);
        }
        let head_members: BTreeSet<K::Member> = K::members(head).into_iter().collect();
        let same_epoch = weakened(Rule::SameEpochCandidate)
            && self.facts.head == self.facts.installed
            && members.is_superset(&head_members);
        self.facts.head.checked_add(1)?;
        Some(Desired {
            base: self.facts.head,
            epoch: if same_epoch {
                K::epoch(head)
            } else {
                K::epoch(head).checked_add(1)?
            },
            members,
            same_epoch,
        })
    }

    /// A pending change the installed record and the head do not yet carry out. One they carry
    /// out waits only for a fetch (row 5), and building for it again would rotate for nothing.
    pub(crate) fn unsatisfied(&self) -> bool {
        if weakened(Rule::BuildWhileWaiting) {
            return !self.facts.removals.is_empty() || self.facts.addition.is_some();
        }
        let (Some(installed), Some(head)) =
            (self.facts.installed_record(), self.facts.head_record())
        else {
            return false;
        };
        if self
            .facts
            .removals
            .iter()
            .any(|member| K::lists(installed, member) || K::lists(head, member))
        {
            return true;
        }
        self.facts
            .addition
            .is_some_and(|addition| !K::lists(installed, &addition) || !K::lists(head, &addition))
    }

    /// The head is a record this device refuses while it lists this device.
    pub(crate) fn head_refused_listing_me(&self) -> bool {
        self.facts.head != self.facts.installed
            && self
                .facts
                .head_record()
                .is_some_and(|head| K::lists(head, &self.me) && !self.accepted(head))
    }

    /// Whether a candidate has a cause: the first record, until the claim applies, or a pending
    /// change not yet carried out, or a head this device refuses while listed in it (I6).
    pub(crate) fn needs_candidate(&self) -> bool {
        if self.facts.installed == 0 {
            return self.facts.join == 1 && self.facts.head == 0;
        }
        self.unsatisfied() || self.head_refused_listing_me()
    }

    /// Rows 6 and 7: an undispatched candidate is still what row 8 would build now.
    pub(crate) fn still_wanted(&self, candidate: &Candidate<K::Record, K::Mark>) -> bool {
        if !self.needs_candidate() {
            return false;
        }
        let Some(desired) = self.desired() else {
            return false;
        };
        let members: BTreeSet<K::Member> = K::members(&candidate.record).into_iter().collect();
        Some(K::revision(&candidate.record)) == desired.base.checked_add(1)
            && desired.base == self.facts.head
            && K::epoch(&candidate.record) == desired.epoch
            && members == desired.members
    }

    /// I1's fence: publication only while no removal is pending, no candidate stands, no join
    /// awaits the owner and the head is installed.
    pub(crate) fn publishes(&self) -> bool {
        !self.facts.out
            && self.facts.installed != 0
            && self.facts.removals.is_empty()
            && self.facts.candidate.is_none()
            && self.facts.installed == self.facts.head
    }
}

/// One rule of the reconciler that the exhaustive test weakens, to show that it catches the
/// weakening. Outside this library's own tests every rule holds, and [`weakened`] is constant
/// false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Accept a record whose epoch was opened by an issuer that fails check 3.
    NoOpenerCheck,
    /// Accept a new epoch's key without comparing it with the keys already seen.
    NoFreshKeyCheck,
    /// Build a candidate from the head's members rather than the installed record's.
    BuildFromHead,
    /// Settle an applied candidate without moving the head.
    SettleKeepsHead,
    /// Settle an applied candidate by moving the head to its record even when that is back.
    SettleWithoutMax,
    /// Send a dispatched candidate again after a restart (I4).
    ResendAfterRestart,
    /// End a change as done when the installed record and the head both carry it out, whether or
    /// not the head is installed.
    DoneByBothRecords,
    /// Record no removal for a device the host answers fail.
    RefreshRecordsNoRemoval,
    /// Look only at the head for a record that leaves this device out.
    GapKeepsMembership,
    /// Leave a verified feed revocation for the next refresh.
    FeedWaitsForRefresh,
    /// Keep the outcomes of ended changes where a crash loses them.
    VolatileReports,
    /// Read the record after a candidate's base and not make it the head.
    ReadNotRecorded,
    /// End a change as done at a head fetched before it was recorded.
    DoneWithoutFetch,
    /// Confirm a join without recording the removals the host answers require.
    JoinSkipsAnswers,
    /// Build a candidate for a change the installed head already carries out.
    BuildWhileWaiting,
    /// Make the record read after a candidate's base the head without the host answers.
    ReadSkipsAnswers,
    /// Keep the installed record's epoch and key for a candidate that adds a device, so a sent
    /// candidate that never applies has wrapped the key in use for a device no record lists.
    SameEpochCandidate,
    /// Accept a record carrying the key of a candidate this device sent that never applied.
    NoWithdrawnCheck,
    /// Drop a dispatched candidate on leaving, before its request is settled.
    LeaveDropsDispatched,
}

#[cfg(test)]
thread_local! {
    /// The rule this thread's reconciler runs weakened, when the exhaustive test weakens one.
    static WEAKENED: std::cell::Cell<Option<Rule>> = const { std::cell::Cell::new(None) };
}

/// Returns true when this thread runs with `rule` weakened.
#[cfg(test)]
pub(crate) fn weakened(rule: Rule) -> bool {
    WEAKENED.with(|weakened| weakened.get() == Some(rule))
}

/// Returns false: outside this library's own tests every rule holds.
#[cfg(not(test))]
pub(crate) const fn weakened(_rule: Rule) -> bool {
    false
}

/// Runs this thread's reconciler with one rule weakened, or none.
#[cfg(test)]
pub(crate) fn weaken(rule: Option<Rule>) {
    WEAKENED.with(|weakened| weakened.set(rule));
}
