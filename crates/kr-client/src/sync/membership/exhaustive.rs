//! The exhaustive invariant test of the reconciler.
//!
//! This runs [`Reconciler`] itself, row for row and write for write, against a model environment:
//! one device D, two other members A and X that append records at an honest service, a fourth
//! device B, the owner's removals and additions on D, a host revocation, a revocation D verifies
//! from an authority feed, D's refreshes, the owner confirming a join, a lost request, a lost
//! reply, a receipt the service no longer holds, a refresh a hostile service answers as if the
//! collection were gone, and a crash, which loses what the membership file does not hold (the
//! send that follows a dispatch mark, and an answer not yet taken). The service answers a device
//! its newest record does not list as a missing collection, and goes on taking a request in
//! flight after D is out. X also misbehaves: it wraps another key at the same epoch, reuses a key
//! in a new epoch, or carries the key of any candidate D sent into a record of its own.
//!
//! Records here are a few small numbers rather than signed records, so every reachable state
//! within the budgets can be visited; the checks that need keys (the chain, the signature, the
//! opening of a wrap) are the device environment's and have their own tests. Every state and every
//! step is checked against the invariants by their exact predicates:
//!
//! * I1: publication only when no removal is pending, no candidate stands and the head is
//!   installed; then everyone who can open the current key through a record D knows, directly at
//!   its own epoch, is listed in the installed record, and none of them is one D knows revoked.
//!   Holders through another epoch's record that reused the key are the stated limit, counted per
//!   key, and only while no such record since D's join lists D.
//! * I2: every pending change ends as done, cancelled or refused by the exact predicate, done only
//!   at an installed head fetched after the change was recorded, with each outcome recorded in the
//!   write that ends the change and none lost by a crash.
//! * I3: the owner's newest intent wins.
//! * I4: a request identity is sent once, by the send that follows its dispatch mark, and never
//!   while another is live; and a request still in flight is the standing dispatched candidate's,
//!   or one the service already answered or fenced.
//! * I5: a key reaches the store only through row 4, for a record that passes checks 1 to 5,
//!   the issuer of the record that opened its epoch among them; no key leaves the store while D
//!   is a member; and the key of every candidate D sent that settled without applying is recorded
//!   as withdrawn, so check 5 refuses any record that carries it.
//! * I6: a candidate is built only for a cause, and lists only the installed record's members and
//!   the addition the owner confirmed.
//! * I7: publication only while every record from D's join record to the installed one lists D.
//! * Liveness: once events stop, every state settles: nothing pending, the newest record installed
//!   and publication open, or D out of the collection with its request settled and its keys
//!   forgotten.
//!
//! Every visited membership file passes the load check and survives the file's own encoding. Each
//! rule the test weakens ([`Rule`]) must make a run fail.
//!
//! Each operation of the reconciler here is built afresh from the durable state (the file and the
//! key store) and the two volatile facts (the send that follows a dispatch mark, and an answer not
//! yet taken), so every visited state with neither volatile fact is exactly the state a restart
//! comes back to: a crash between any two writes, the clearing write of row 1 and the installing
//! write of row 4 among them, is visited wherever it can fall. The crash event itself drops the
//! volatile facts where there are any.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use kr_protocol::ids::{InstallationId, SyncCollectionId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use serde::{Deserialize, Serialize};

use super::environment::Environment;
use super::facts::{
    Candidate, Change, Ended, Facts, Kinds, Opened, Opener, Outcome, Rule, View, weaken,
};
use super::reconciler::Reconciler;
use super::{
    CollectionRef, KeyRecords, MembershipError, RecordAt, RekeyAnswer, RekeyFence, RekeyStatus,
    Settlement, Step,
};
use crate::error::ClientError;
use crate::services::ServiceFuture;

/// A device of the model.
type Dev = u8;
/// This device.
const D: Dev = 0;
/// A member that intends well.
const A: Dev = 1;
/// A device that starts outside the collection.
const B: Dev = 2;
/// A member that also misbehaves.
const X: Dev = 3;
/// The other members that append records.
const OTHER_ISSUERS: [Dev; 2] = [A, X];
/// Every device but D.
const DEVICES: [Dev; 3] = [A, B, X];

/// The signing time every step of the model uses: time decides nothing here.
const NOW: TimestampMs = TimestampMs::new(1);

const fn bit(device: Dev) -> u8 {
    1 << device
}

fn devices_in(mask: u8) -> impl Iterator<Item = Dev> {
    (0..4).filter(move |device| mask & bit(*device) != 0)
}

fn mask_of<'a>(devices: impl IntoIterator<Item = &'a Dev>) -> u8 {
    devices
        .into_iter()
        .fold(0, |mask, device| mask | bit(*device))
}

/// A key, by where it came from. Equal labels are one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
enum KeyLabel {
    /// A key D drew for a candidate. Real keys are random, so two candidates never share one:
    /// the attempt counts the keys D drew before with the same epoch, base and members that could
    /// have left it.
    Fresh {
        /// Its epoch.
        epoch: u64,
        /// The candidate's base.
        base: u64,
        /// The candidate's members.
        members: u8,
        /// How many such keys D drew before this one.
        attempt: u8,
    },
    /// A key another member drew for a new epoch.
    FreshBy {
        /// Its epoch.
        epoch: u64,
        /// The issuer.
        issuer: Dev,
        /// The record's revision.
        revision: u64,
    },
    /// Another key X wrapped at an unchanged epoch.
    Other {
        /// The record's revision.
        revision: u64,
    },
    /// Every key D withdrew that nothing carries any more, kept as one (`spend_withdrawn`).
    Withdrawn,
}

/// A key record of the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct ModelRecord {
    revision: u64,
    epoch: u64,
    members: u8,
    issuer: Dev,
    key: KeyLabel,
}

/// Check 3's answers of the model: the devices the hosts report revoked, and those D verified
/// from a feed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct ModelAnswers {
    hosts: u8,
    verified: u8,
}

/// The model's kinds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ModelKinds;

impl Kinds for ModelKinds {
    type Member = Dev;
    type Record = ModelRecord;
    type Mark = KeyLabel;
    type Answers = ModelAnswers;
    type Revocation = Dev;

    fn revision(record: &ModelRecord) -> u64 {
        record.revision
    }

    fn epoch(record: &ModelRecord) -> u64 {
        record.epoch
    }

    fn issuer(record: &ModelRecord) -> Option<Dev> {
        Some(record.issuer)
    }

    fn members(record: &ModelRecord) -> Vec<Dev> {
        devices_in(record.members).collect()
    }

    fn lists(record: &ModelRecord, member: &Dev) -> bool {
        record.members & bit(*member) != 0
    }

    fn passes(answers: &ModelAnswers, member: &Dev) -> bool {
        (answers.hosts | answers.verified) & bit(*member) == 0
    }

    fn revoke(answers: &mut ModelAnswers, revocation: Dev) {
        answers.verified |= bit(revocation);
    }

    fn refreshed(previous: &ModelAnswers, fresh: ModelAnswers) -> ModelAnswers {
        ModelAnswers {
            hosts: fresh.hosts,
            verified: previous.verified | fresh.verified,
        }
    }
}

/// What the service recorded about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Receipt {
    Applied(u64),
    Refused,
    Fenced,
    FencedUnknown,
}

/// An answer that reached D.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Answer {
    Applied(u64),
    Refused(u64),
}

impl From<Answer> for RekeyAnswer {
    fn from(answer: Answer) -> Self {
        match answer {
            Answer::Applied(revision) => Self::Applied { revision },
            Answer::Refused(revision) => Self::Refused { revision },
        }
    }
}

impl From<RekeyAnswer> for Answer {
    fn from(answer: RekeyAnswer) -> Self {
        match answer {
            RekeyAnswer::Applied { revision } => Self::Applied(revision),
            RekeyAnswer::Refused { revision } => Self::Refused(revision),
        }
    }
}

/// The honest service.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Service {
    chain: Vec<ModelRecord>,
    receipts: BTreeSet<(u64, Receipt)>,
    /// Requests sent and not yet taken.
    transit: BTreeSet<(u64, ModelRecord)>,
    /// The live request is past the service's receipt horizon.
    expired: bool,
}

/// The budgets, one for each kind of event.
const OWNER: usize = 0;
const OTHERS: usize = 1;
const REVOKE: usize = 2;
const CRASH: usize = 3;
const DROP: usize = 4;
const LOSS: usize = 5;
const EXPIRE: usize = 6;
const FEED: usize = 7;
const JOIN: usize = 8;
/// A refresh a hostile service answers as if the collection were gone.
const ABSENT: usize = 9;

/// One state of the whole model.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct World {
    service: Service,
    /// D's membership file.
    facts: Facts<ModelKinds>,
    /// D's key store.
    store: BTreeMap<u64, KeyLabel>,
    /// D's volatile state: the send that follows the dispatch mark, and an answer not yet taken.
    sending: Option<u64>,
    inbox: Option<(u64, Answer)>,
    /// Outcomes a weakened rule keeps where a crash loses them.
    volatile_outcomes: Vec<Outcome<Dev>>,
    /// What D's hosts would answer now.
    revoked: u8,
    /// Revocations D verified from a feed.
    verified: u8,
    /// History: the newest revision D has read.
    seen: u64,
    /// History: the chain's length when each pending change was recorded.
    recorded_at: BTreeSet<(Change<Dev>, u64)>,
    /// History: the pending changes recorded since the head was last fetched, kept apart from
    /// D's own record of them so the two can be compared.
    fetch_waits: BTreeSet<Change<Dev>>,
    /// History: every candidate D sent, by epoch and key, with the devices it wrapped that key
    /// for. A service may pass a device its wrap whether or not the candidate ever applies, so
    /// each of them counts as holding that key.
    sent: BTreeMap<(u64, KeyLabel), u8>,
    next_request: u64,
    budget: [u8; 10],
}

fn collection() -> CollectionRef {
    CollectionRef {
        home: InstallationId::new(Uuid::from_bytes([0x0d; 16])),
        collection_id: SyncCollectionId::new(Uuid::from_bytes([0xc0; 16])),
    }
}

fn uuid_of(request: u64) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[8..].copy_from_slice(&request.to_be_bytes());
    Uuid::from_bytes(bytes)
}

fn request_of(uuid: Uuid) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&uuid.as_bytes()[8..]);
    u64::from_be_bytes(bytes)
}

/// The model environment one operation runs against.
struct ModelEnv {
    /// The service answers every read of records as a missing collection.
    absent: bool,
    file: Mutex<Facts<ModelKinds>>,
    store: Mutex<BTreeMap<u64, KeyLabel>>,
    service: Mutex<Service>,
    revoked: u8,
    next_request: Mutex<u64>,
    /// The newest revision a read returned.
    read: Mutex<u64>,
    /// The request this operation sent.
    sent: Mutex<Option<(u64, ModelRecord)>>,
    /// The keys of every candidate D sent since its join, so a key it draws is a new one.
    sent_keys: Vec<KeyLabel>,
    /// Durable writes this operation made: the file, or the key store.
    writes: Mutex<u32>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("a model lock nobody poisoned")
}

fn ready<'a, T: Send + 'a>(value: T) -> ServiceFuture<'a, T> {
    Box::pin(std::future::ready(Ok(value)))
}

impl Environment for ModelEnv {
    type Kinds = ModelKinds;
    type Key = KeyLabel;
    type Guard = ();

    fn me(&self) -> Dev {
        D
    }

    fn lock(&self) -> Result<(), MembershipError> {
        Ok(())
    }

    fn load(&self) -> Result<Option<Facts<ModelKinds>>, MembershipError> {
        Ok(Some(locked(&self.file).clone()))
    }

    fn replace(&self, facts: &Facts<ModelKinds>) -> Result<(), MembershipError> {
        *locked(&self.file) = facts.clone();
        *locked(&self.writes) += 1;
        Ok(())
    }

    fn follows(&self, previous: &ModelRecord, next: &ModelRecord) -> bool {
        next.revision == previous.revision + 1
    }

    fn first(&self, _collection: &CollectionRef, record: &ModelRecord) -> bool {
        record.revision == 1
    }

    fn valid(&self, _collection: &CollectionRef, _record: &ModelRecord) -> bool {
        true
    }

    fn mark_of(&self, record: &ModelRecord) -> Option<KeyLabel> {
        ModelKinds::lists(record, &D).then_some(record.key)
    }

    fn open_key(
        &self,
        record: &ModelRecord,
        answers: &ModelAnswers,
    ) -> Result<KeyLabel, MembershipError> {
        // The sender must pass the recorded answers, as a device's own environment requires.
        if record.issuer != D && !ModelKinds::passes(answers, &record.issuer) {
            return Err(MembershipError::NotCommitted);
        }
        self.mark_of(record).ok_or(MembershipError::NotListed)
    }

    fn mark(&self, key: &KeyLabel) -> KeyLabel {
        *key
    }

    fn draw_key(
        &self,
        epoch: u64,
        base: u64,
        members: &[Dev],
    ) -> Result<KeyLabel, MembershipError> {
        let members = mask_of(members);
        // Every key D drew that could have left it: the candidates it sent, and those it
        // withdrew, which include a dispatched one that never went out.
        let drawn: BTreeSet<KeyLabel> = self
            .sent_keys
            .iter()
            .chain(locked(&self.file).withdrawn.iter())
            .copied()
            .collect();
        let attempt = drawn
            .iter()
            .filter(|key| {
                matches!(key, KeyLabel::Fresh { epoch: e, base: b, members: m, .. }
                    if (*e, *b, *m) == (epoch, base, members))
            })
            .count();
        Ok(KeyLabel::Fresh {
            epoch,
            base,
            members,
            attempt: u8::try_from(attempt).expect("a few attempts"),
        })
    }

    fn issue(
        &self,
        _collection: &CollectionRef,
        base: Option<&ModelRecord>,
        epoch: u64,
        members: &[Dev],
        key: &KeyLabel,
        _now: TimestampMs,
    ) -> Result<ModelRecord, MembershipError> {
        Ok(ModelRecord {
            revision: base.map_or(1, |base| base.revision + 1),
            epoch,
            members: mask_of(members),
            issuer: D,
            key: *key,
        })
    }

    fn held_key(
        &self,
        _collection: &CollectionRef,
        epoch: u64,
    ) -> Result<Option<KeyLabel>, MembershipError> {
        Ok(locked(&self.store).get(&epoch).copied())
    }

    fn store_key(
        &self,
        _collection: &CollectionRef,
        epoch: u64,
        key: &KeyLabel,
    ) -> Result<(), MembershipError> {
        locked(&self.store).insert(epoch, *key);
        *locked(&self.writes) += 1;
        Ok(())
    }

    fn forget_key(&self, _collection: &CollectionRef, epoch: u64) -> Result<(), MembershipError> {
        if locked(&self.store).remove(&epoch).is_some() {
            *locked(&self.writes) += 1;
        }
        Ok(())
    }

    fn fresh_request(&self) -> Result<Uuid, MembershipError> {
        let mut next = locked(&self.next_request);
        let request = *next;
        *next += 1;
        Ok(uuid_of(request))
    }

    fn records_after<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords<ModelRecord>> {
        let service = locked(&self.service);
        if self.absent || !member(&service) {
            return ready(KeyRecords::Absent);
        }
        let records: Vec<ModelRecord> = service
            .chain
            .iter()
            .filter(|record| record.revision > after)
            .copied()
            .collect();
        if let Some(newest) = records.last() {
            let mut read = locked(&self.read);
            *read = (*read).max(newest.revision);
        }
        ready(KeyRecords::Records(records))
    }

    fn record_at<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt<ModelRecord>> {
        let service = locked(&self.service);
        if !member(&service) {
            return ready(RecordAt::Absent);
        }
        let found = usize::try_from(revision)
            .ok()
            .and_then(|revision| revision.checked_sub(1))
            .and_then(|index| service.chain.get(index))
            .copied();
        if found.is_some() {
            let mut read = locked(&self.read);
            *read = (*read).max(revision);
        }
        ready(found.map_or(RecordAt::Missing, RecordAt::Record))
    }

    fn rekey<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        request: Uuid,
        _signed_at: TimestampMs,
        record: &'a ModelRecord,
    ) -> ServiceFuture<'a, RekeyAnswer> {
        let request = request_of(request);
        locked(&self.service).transit.insert((request, *record));
        *locked(&self.sent) = Some((request, *record));
        // The answer comes later, when the service takes the request, or never.
        Box::pin(std::future::ready(Err(ClientError::ConnectionEnded)))
    }

    fn rekey_status<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        request: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus> {
        let request = request_of(request);
        let service = locked(&self.service);
        let status = match receipt(&service, request) {
            Some(Receipt::Applied(revision)) => RekeyStatus::Applied { revision },
            Some(Receipt::Refused) => RekeyStatus::Refused {
                revision: service.chain.len() as u64,
            },
            Some(Receipt::Fenced) => RekeyStatus::Fenced { never_ran: true },
            Some(Receipt::FencedUnknown) => RekeyStatus::Fenced { never_ran: false },
            None => RekeyStatus::Unknown,
        };
        ready(status)
    }

    fn rekey_fence<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        request: Uuid,
        _first_signed_at: TimestampMs,
        _last_signed_at: TimestampMs,
    ) -> ServiceFuture<'a, RekeyFence> {
        let request = request_of(request);
        let mut service = locked(&self.service);
        let fence = match receipt(&service, request) {
            Some(Receipt::Applied(revision)) => RekeyFence::Applied { revision },
            Some(Receipt::Refused) => RekeyFence::Refused {
                revision: service.chain.len() as u64,
            },
            Some(Receipt::Fenced) => RekeyFence::Fenced { never_ran: true },
            Some(Receipt::FencedUnknown) => RekeyFence::Fenced { never_ran: false },
            None if !service.expired => {
                service.receipts.insert((request, Receipt::Fenced));
                RekeyFence::Fenced { never_ran: true }
            }
            None => {
                service.receipts.insert((request, Receipt::FencedUnknown));
                RekeyFence::Fenced { never_ran: false }
            }
        };
        ready(fence)
    }

    fn answers(&self) -> ServiceFuture<'_, Option<ModelAnswers>> {
        ready(Some(ModelAnswers {
            hosts: self.revoked,
            verified: 0,
        }))
    }
}

/// Whether the service's newest record lists D: it answers anyone else's reads exactly as a
/// missing collection.
fn member(service: &Service) -> bool {
    service
        .chain
        .last()
        .is_some_and(|newest| ModelKinds::lists(newest, &D))
}

fn receipt(service: &Service, request: u64) -> Option<Receipt> {
    service
        .receipts
        .iter()
        .find(|(id, _)| *id == request)
        .map(|(_, receipt)| *receipt)
}

/// Runs a future every model call of which is ready at once.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a model call waited"),
    }
}

/// What one operation of the reconciler did to the world.
struct Ran<T> {
    value: T,
    world: World,
    sent: Option<(u64, ModelRecord)>,
    writes: u32,
}

/// Runs one operation of the reconciler against the world. `fetch` says whether the operation is
/// a fetch of the head, which a refresh and a join are.
fn run<T>(
    world: &World,
    fetch: bool,
    operation: impl FnOnce(&mut Reconciler<ModelEnv>) -> T,
) -> Ran<T> {
    run_with(world, fetch, false, operation)
}

/// Runs one operation, with the service answering every read of records as a missing collection
/// when `absent` is set.
fn run_with<T>(
    world: &World,
    fetch: bool,
    absent: bool,
    operation: impl FnOnce(&mut Reconciler<ModelEnv>) -> T,
) -> Ran<T> {
    let env = ModelEnv {
        absent,
        file: Mutex::new(world.facts.clone()),
        store: Mutex::new(world.store.clone()),
        service: Mutex::new(world.service.clone()),
        revoked: world.revoked,
        next_request: Mutex::new(world.next_request),
        read: Mutex::new(0),
        sent: Mutex::new(None),
        sent_keys: world.sent.keys().map(|(_, key)| *key).collect(),
        writes: Mutex::new(0),
    };
    let mut reconciler = Reconciler {
        env,
        sending: world.sending.map(uuid_of),
        inbox: world
            .inbox
            .map(|(request, answer)| (uuid_of(request), answer.into())),
        volatile_outcomes: world.volatile_outcomes.clone(),
    };
    let value = operation(&mut reconciler);
    let Reconciler {
        env,
        sending,
        inbox,
        volatile_outcomes,
    } = reconciler;
    let mut next = world.clone();
    next.facts = env.file.into_inner().expect("unpoisoned");
    next.store = env.store.into_inner().expect("unpoisoned");
    next.service = env.service.into_inner().expect("unpoisoned");
    next.next_request = env.next_request.into_inner().expect("unpoisoned");
    next.seen = next.seen.max(env.read.into_inner().expect("unpoisoned"));
    next.sending = sending.map(request_of);
    next.inbox = inbox.map(|(request, answer)| (request_of(request), answer.into()));
    next.volatile_outcomes = volatile_outcomes;
    let sent = env.sent.into_inner().expect("unpoisoned");
    if let Some((_, record)) = sent {
        *next.sent.entry((record.epoch, record.key)).or_default() |= record.members;
    }
    history(world, &mut next, fetch);
    Ran {
        value,
        world: next,
        sent,
        writes: env.writes.into_inner().expect("unpoisoned"),
    }
}

fn pending(world: &World) -> BTreeSet<Change<Dev>> {
    let mut changes: BTreeSet<Change<Dev>> = world
        .facts
        .removals
        .iter()
        .map(|member| Change::Removal(*member))
        .collect();
    if let Some(addition) = world.facts.addition {
        changes.insert(Change::Addition(addition));
    }
    changes
}

/// Records when each pending change was recorded (the chain's length then) and whether the head
/// was fetched after it: a fetch clears every wait, and a change recorded in the same write as a
/// fetch does not wait for one.
fn history(before: &World, after: &mut World, fetch: bool) {
    let was = pending(before);
    let is = pending(after);
    if fetch {
        after.fetch_waits.clear();
    }
    for change in is.difference(&was) {
        after
            .recorded_at
            .insert((*change, after.service.chain.len() as u64));
        if !fetch {
            after.fetch_waits.insert(*change);
        }
    }
    for change in was.difference(&is) {
        after.recorded_at.retain(|(recorded, _)| recorded != change);
        after.fetch_waits.remove(change);
    }
}

/// What one transition was, for the trace and the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Label {
    Step(Step),
    /// The step taken as if the answer in D's inbox had not arrived yet.
    StepWithoutAnswer(Step),
    Deliver(u64),
    DeliverReplyLost(u64),
    RequestLost(u64),
    ReceiptExpired,
    Refresh,
    RefreshAbsent,
    Crash,
    OwnerRemove(Dev),
    OwnerAdd(Dev),
    Join,
    Other(ModelRecord),
    Revoke(Dev),
    Feed(Dev),
}

/// One transition: the label, the world after it, and what D sent in it.
struct Transition {
    label: Label,
    world: World,
    sent: Option<(u64, ModelRecord)>,
    writes: u32,
}

fn use_budget(world: &mut World, which: usize) {
    world.budget[which] -= 1;
}

fn has(world: &World, which: usize) -> bool {
    world.budget[which] > 0
}

fn record(world: &World, revision: u64) -> Option<&ModelRecord> {
    usize::try_from(revision)
        .ok()
        .and_then(|revision| revision.checked_sub(1))
        .and_then(|index| world.service.chain.get(index))
}

fn installed(world: &World) -> Option<&ModelRecord> {
    record(world, world.facts.installed)
}

fn head(world: &World) -> Option<&ModelRecord> {
    record(world, world.facts.head)
}

fn step_of(world: &World, hide_answer: bool) -> Option<Transition> {
    let mut from = world.clone();
    if hide_answer {
        from.inbox = None;
    }
    let ran = run(&from, false, |reconciler| block_on(reconciler.step(NOW)));
    let step = ran
        .value
        .unwrap_or_else(|error| panic!("a model step failed: {error}"));
    if matches!(step, Step::Nothing | Step::FetchNeeded) {
        return None;
    }
    let mut next = ran.world;
    // An answer that says D's own record applied tells D that revision exists: from then on it
    // is a record D knows, and its head may not stay behind it.
    if let Step::Settled(Settlement::Applied { revision }) = step {
        next.seen = next.seen.max(revision);
    }
    Some(Transition {
        label: if hide_answer {
            Label::StepWithoutAnswer(step)
        } else {
            Label::Step(step)
        },
        world: next,
        sent: ran.sent,
        writes: ran.writes,
    })
}

fn refresh_of(world: &World) -> Option<Transition> {
    let ran = run(world, true, |reconciler| block_on(reconciler.refresh()));
    ran.value
        .unwrap_or_else(|error| panic!("a model refresh failed: {error}"));
    (ran.world != *world).then_some(Transition {
        label: Label::Refresh,
        world: ran.world,
        sent: None,
        writes: ran.writes,
    })
}

/// The service takes one request from transit.
fn deliver(world: &World, request: u64, candidate: &ModelRecord) -> (World, Receipt) {
    let mut next = world.clone();
    next.service.transit.remove(&(request, *candidate));
    if let Some(receipt) = receipt(&next.service, request) {
        return (next, receipt);
    }
    let live = next
        .facts
        .candidate
        .as_ref()
        .map(|candidate| request_of(candidate.request));
    if next.service.expired && live == Some(request) {
        // Outside its freshness window: nothing applies, and no receipt is kept.
        return (next, Receipt::Refused);
    }
    let receipt = if successor_ok(&next, candidate) {
        let revision = next.service.chain.len() as u64 + 1;
        next.service.chain.push(ModelRecord {
            revision,
            ..*candidate
        });
        Receipt::Applied(revision)
    } else {
        Receipt::Refused
    };
    next.service.receipts.insert((request, receipt));
    (next, receipt)
}

fn successor_ok(world: &World, candidate: &ModelRecord) -> bool {
    let Some(current) = world.service.chain.last() else {
        return candidate.revision == 1 && candidate.epoch == 0 && candidate.members == bit(D);
    };
    if candidate.revision != current.revision + 1
        || !ModelKinds::lists(current, &D)
        || !ModelKinds::lists(candidate, &D)
    {
        return false;
    }
    if candidate.epoch == current.epoch {
        return candidate.members & current.members == current.members;
    }
    candidate.epoch == current.epoch + 1
}

/// What another current member may append.
fn other_records(world: &World) -> Vec<ModelRecord> {
    let Some(current) = world.service.chain.last() else {
        return Vec::new();
    };
    let revision = current.revision + 1;
    let mut out = Vec::new();
    for issuer in OTHER_ISSUERS {
        if !ModelKinds::lists(current, &issuer) {
            continue;
        }
        let fresh = KeyLabel::FreshBy {
            epoch: current.epoch + 1,
            issuer,
            revision,
        };
        for added in [D, A, B, X] {
            if !ModelKinds::lists(current, &added) {
                out.push(ModelRecord {
                    revision,
                    epoch: current.epoch,
                    members: current.members | bit(added),
                    issuer,
                    key: current.key,
                });
            }
        }
        for removed in devices_in(current.members & !bit(issuer)) {
            out.push(ModelRecord {
                revision,
                epoch: current.epoch + 1,
                members: current.members & !bit(removed),
                issuer,
                key: fresh,
            });
        }
        out.push(ModelRecord {
            revision,
            epoch: current.epoch + 1,
            members: current.members,
            issuer,
            key: fresh,
        });
        if issuer == X {
            for added in DEVICES {
                if !ModelKinds::lists(current, &added) {
                    out.push(ModelRecord {
                        revision,
                        epoch: current.epoch,
                        members: current.members | bit(added),
                        issuer: X,
                        key: KeyLabel::Other { revision },
                    });
                }
            }
            for removed in devices_in(current.members & !bit(X)) {
                out.push(ModelRecord {
                    revision,
                    epoch: current.epoch + 1,
                    members: current.members & !bit(removed),
                    issuer: X,
                    key: current.key,
                });
            }
            // A service can hand X the wraps of any candidate D sent, applied or not, and X can
            // carry such a key into a record of its own.
            let exposed: BTreeSet<KeyLabel> = world
                .sent
                .keys()
                .map(|(_, key)| *key)
                .filter(|key| *key != current.key)
                .collect();
            for key in exposed {
                out.push(ModelRecord {
                    revision,
                    epoch: current.epoch + 1,
                    members: current.members,
                    issuer: X,
                    key,
                });
                for removed in devices_in(current.members & !bit(X)) {
                    out.push(ModelRecord {
                        revision,
                        epoch: current.epoch + 1,
                        members: current.members & !bit(removed),
                        issuer: X,
                        key,
                    });
                }
            }
        }
    }
    out
}

/// Every transition the world can take.
fn transitions(world: &World) -> Vec<Transition> {
    let mut out = Vec::new();
    if let Some(step) = step_of(world, false) {
        out.push(step);
    }
    let dispatched = world
        .facts
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.dispatched.is_some());
    if dispatched
        && world.sending.is_none()
        && world.inbox.is_some()
        && let Some(step) = step_of(world, true)
    {
        out.push(step);
    }
    // The network and the service go on whether D is a member or not: a request D sent before
    // it went out is still taken, or lost, and its receipt may still expire.
    {
        for (request, candidate) in world.service.transit.clone() {
            let (delivered, receipt) = deliver(world, request, &candidate);
            let answer = match receipt {
                Receipt::Applied(revision) => Some(Answer::Applied(revision)),
                Receipt::Refused => Some(Answer::Refused(delivered.service.chain.len() as u64)),
                Receipt::Fenced | Receipt::FencedUnknown => None,
            };
            let mut answered = delivered.clone();
            if let Some(answer) = answer {
                answered.inbox = Some((request, answer));
            }
            out.push(Transition {
                label: Label::Deliver(request),
                world: answered,
                sent: None,
                writes: 0,
            });
            if has(world, LOSS) {
                let mut lost = delivered;
                use_budget(&mut lost, LOSS);
                out.push(Transition {
                    label: Label::DeliverReplyLost(request),
                    world: lost,
                    sent: None,
                    writes: 0,
                });
            }
            if has(world, DROP) {
                let mut dropped = world.clone();
                dropped.service.transit.remove(&(request, candidate));
                use_budget(&mut dropped, DROP);
                out.push(Transition {
                    label: Label::RequestLost(request),
                    world: dropped,
                    sent: None,
                    writes: 0,
                });
            }
        }
        if has(world, EXPIRE) && dispatched && !world.service.expired {
            let live = world
                .facts
                .candidate
                .as_ref()
                .map(|candidate| request_of(candidate.request));
            let mut expired = world.clone();
            expired.service.expired = true;
            expired
                .service
                .receipts
                .retain(|(request, _)| Some(*request) != live);
            use_budget(&mut expired, EXPIRE);
            out.push(Transition {
                label: Label::ReceiptExpired,
                world: expired,
                sent: None,
                writes: 0,
            });
        }
        if has(world, CRASH) && (world.sending.is_some() || world.inbox.is_some()) {
            let mut crashed = world.clone();
            crashed.sending = None;
            crashed.inbox = None;
            crashed.volatile_outcomes.clear();
            use_budget(&mut crashed, CRASH);
            out.push(Transition {
                label: Label::Crash,
                world: crashed,
                sent: None,
                writes: 0,
            });
        }
    }
    if !world.facts.out {
        if !world.service.chain.is_empty()
            && let Some(refresh) = refresh_of(world)
        {
            out.push(refresh);
        }
        // A hostile service answers a refresh as if the collection were gone, whatever its
        // chain: D is out at once, with a candidate it dispatched still to settle.
        if has(world, ABSENT) && !world.service.chain.is_empty() {
            let ran = run_with(world, true, true, |reconciler| {
                block_on(reconciler.refresh())
            });
            ran.value
                .unwrap_or_else(|error| panic!("a model refresh failed: {error}"));
            if ran.world != *world {
                let mut next = ran.world;
                use_budget(&mut next, ABSENT);
                out.push(Transition {
                    label: Label::RefreshAbsent,
                    world: next,
                    sent: None,
                    writes: ran.writes,
                });
            }
        }
        if has(world, OWNER) && world.facts.installed != 0 {
            let installed_members = installed(world).map_or(0, |record| record.members);
            let head_members = head(world).map_or(0, |record| record.members);
            let addition = world.facts.addition.map_or(0, bit);
            let removals = mask_of(&world.facts.removals);
            let listed = (installed_members | head_members | addition) & !bit(D) & !removals;
            for member in devices_in(listed) {
                let ran = run(world, false, |reconciler| reconciler.remove(member));
                ran.value
                    .unwrap_or_else(|error| panic!("a model removal failed: {error}"));
                let mut next = ran.world;
                use_budget(&mut next, OWNER);
                out.push(Transition {
                    label: Label::OwnerRemove(member),
                    world: next,
                    sent: None,
                    writes: ran.writes,
                });
            }
            // The owner's plan names the collection and the epoch installed when it was made.
            let epoch = installed(world).map_or(0, |record| record.epoch);
            for member in DEVICES {
                if installed_members & bit(member) != 0 {
                    continue;
                }
                let ran = run(world, false, |reconciler| {
                    reconciler.add(member, collection(), epoch)
                });
                ran.value
                    .unwrap_or_else(|error| panic!("a model addition failed: {error}"));
                let mut next = ran.world;
                use_budget(&mut next, OWNER);
                out.push(Transition {
                    label: Label::OwnerAdd(member),
                    world: next,
                    sent: None,
                    writes: ran.writes,
                });
            }
        }
    } else if has(world, JOIN)
        && world
            .service
            .chain
            .last()
            .is_some_and(|newest| ModelKinds::lists(newest, &D))
    {
        let ran = run(world, true, |reconciler| {
            block_on(reconciler.join(collection()))
        });
        match ran.value {
            Ok(()) => {
                let mut next = ran.world;
                use_budget(&mut next, JOIN);
                // A join starts a new membership. What D sent in the one it left reaches the
                // new one only through the records that applied, which count as every record
                // from before the join does.
                next.sent.clear();
                out.push(Transition {
                    label: Label::Join,
                    world: next,
                    sent: None,
                    writes: ran.writes,
                });
            }
            // The request and the keys of the membership D left are settled and forgotten
            // first, a step each; the join waits for them.
            Err(MembershipError::UnsettledRequest | MembershipError::KeysStillHeld) => {}
            Err(error) => panic!("a model join failed: {error}"),
        }
    }
    if has(world, OTHERS) {
        for record in other_records(world) {
            let mut next = world.clone();
            next.service.chain.push(record);
            use_budget(&mut next, OTHERS);
            out.push(Transition {
                label: Label::Other(record),
                world: next,
                sent: None,
                writes: 0,
            });
        }
    }
    if has(world, REVOKE) {
        for member in DEVICES {
            if world.revoked & bit(member) == 0 {
                let mut next = world.clone();
                next.revoked |= bit(member);
                use_budget(&mut next, REVOKE);
                out.push(Transition {
                    label: Label::Revoke(member),
                    world: next,
                    sent: None,
                    writes: 0,
                });
            }
        }
    }
    if has(world, FEED) {
        for member in DEVICES {
            if world.verified & bit(member) != 0 {
                continue;
            }
            let mut revoked = world.clone();
            revoked.revoked |= bit(member);
            revoked.verified |= bit(member);
            let ran = run(&revoked, false, |reconciler| {
                reconciler.feed_revocation(member)
            });
            ran.value
                .unwrap_or_else(|error| panic!("a model feed revocation failed: {error}"));
            let mut next = ran.world;
            use_budget(&mut next, FEED);
            out.push(Transition {
                label: Label::Feed(member),
                world: next,
                sent: None,
                writes: ran.writes,
            });
        }
    }
    out
}

/// Forgets what cannot matter any more, so equal futures are one state.
///
/// Only the standing candidate's identity is live: every earlier one was settled by a receipt, by
/// the record after its base, or never sent, so its receipts, answers and any copy in transit
/// change nothing. The live identity is renamed 1. A change's recording point matters only until
/// the head reaches it, and of the outcomes only whether one is waiting to be shown.
fn canon(mut world: World) -> World {
    let head = world.facts.head;
    world.recorded_at.retain(|(_, length)| *length > head);
    // Nothing decides from an outcome, so only whether one waits to be shown is kept, under a
    // value the reconciler never records itself.
    for outcomes in [&mut world.facts.outcomes, &mut world.volatile_outcomes] {
        if !outcomes.is_empty() {
            *outcomes = vec![WAITING];
        }
    }
    let live = world
        .facts
        .candidate
        .as_ref()
        .map(|candidate| request_of(candidate.request));
    match live {
        None => {
            world.service.receipts.clear();
            world.service.transit.clear();
            world.service.expired = false;
            world.inbox = None;
            world.sending = None;
            world.next_request = 1;
        }
        Some(live) => {
            world.service.receipts = world
                .service
                .receipts
                .iter()
                .filter(|(request, _)| *request == live)
                .map(|(_, receipt)| (1, *receipt))
                .collect();
            world.service.transit = world
                .service
                .transit
                .iter()
                .filter(|(request, _)| *request == live)
                .map(|(_, record)| (1, *record))
                .collect();
            world.inbox = world
                .inbox
                .filter(|(request, _)| *request == live)
                .map(|(_, answer)| (1, answer));
            world.sending = world.sending.filter(|request| *request == live).map(|_| 1);
            if let Some(candidate) = &mut world.facts.candidate {
                candidate.request = uuid_of(1);
            }
            world.next_request = 2;
        }
    }
    spend_withdrawn(&mut world);
    world
}

/// Keeps as one key every withdrawn key nothing carries any more: no record at the service, not
/// the standing candidate, not the store.
///
/// Such a key matters only as one D refuses, and one X may carry into a record of its own; which
/// of them X carries changes nothing, since D refuses each alike and none ever becomes current.
/// They are kept as [`KeyLabel::Withdrawn`], with every device any of them was wrapped for, in
/// D's withdrawn keys and in the send history alike. Without this, a candidate the service keeps
/// refusing, drawn again each time with a new key, would make a new state at every attempt.
fn spend_withdrawn(world: &mut World) {
    let carried: BTreeSet<KeyLabel> = world
        .service
        .chain
        .iter()
        .map(|record| record.key)
        .chain(
            world
                .facts
                .candidate
                .iter()
                .map(|candidate| candidate.record.key),
        )
        .chain(world.store.values().copied())
        .collect();
    let spent: BTreeSet<KeyLabel> = world
        .facts
        .withdrawn
        .iter()
        .copied()
        .filter(|key| *key != KeyLabel::Withdrawn && !carried.contains(key))
        .collect();
    if spent.is_empty() {
        return;
    }
    let mut wrapped = None;
    world.sent.retain(|(_, key), members| {
        if spent.contains(key) {
            *wrapped.get_or_insert(0) |= *members;
            return false;
        }
        true
    });
    if let Some(members) = wrapped {
        *world.sent.entry((0, KeyLabel::Withdrawn)).or_default() |= members;
    }
    world.facts.withdrawn.retain(|key| !spent.contains(key));
    world.facts.withdrawn.insert(KeyLabel::Withdrawn);
}

/// What a canonical state keeps of the outcomes waiting to be shown: that there are some.
const WAITING: Outcome<Dev> = Outcome::Join { ended: Ended::Done };

/// A broken invariant, with what broke it.
#[derive(Debug)]
struct Violation(String);

fn violation<T>(message: impl Into<String>) -> Result<T, Violation> {
    Err(Violation(message.into()))
}

fn passes3(world: &World, device: Dev) -> bool {
    device == D || ModelKinds::passes(&world.facts.answers, &device)
}

fn opener(world: &World, record: &ModelRecord) -> Option<ModelRecord> {
    world
        .service
        .chain
        .iter()
        .find(|candidate| candidate.epoch == record.epoch)
        .copied()
}

/// Checks 1 to 5, the epoch's opener included, as the invariants state them, over the service's
/// own chain.
fn acceptable(world: &World, record: &ModelRecord) -> bool {
    if !ModelKinds::lists(record, &D) {
        return false;
    }
    if withdrawn(world).contains(&record.key) {
        return false;
    }
    let Some(first) = opener(world, record) else {
        return false;
    };
    if !passes3(world, record.issuer) || !passes3(world, first.issuer) {
        return false;
    }
    if let Some(held) = world.store.get(&record.epoch) {
        return *held == record.key;
    }
    let floor = world.facts.join;
    let earlier: BTreeSet<KeyLabel> = world
        .service
        .chain
        .iter()
        .filter(|earlier| {
            earlier.revision >= floor
                && earlier.revision < record.revision
                && earlier.epoch != record.epoch
                && ModelKinds::lists(earlier, &D)
        })
        .map(|earlier| earlier.key)
        .collect();
    !earlier.contains(&record.key) && world.store.values().all(|held| *held != record.key)
}

/// What D can know of: every record it has read, and every record it issued itself.
fn horizon(world: &World) -> u64 {
    let own = world
        .service
        .chain
        .iter()
        .filter(|record| record.issuer == D)
        .map(|record| record.revision)
        .max()
        .unwrap_or(0);
    world.seen.max(own)
}

/// Who can open the installed record's key through the records up to `upto`: directly, at its own
/// epoch, and through another epoch's record that reused it. The stated limit covers the second
/// kind per key, and only while no such record since D's join lists D.
fn holders(world: &World, upto: u64) -> (u8, u8) {
    let Some(installed) = installed(world) else {
        return (0, 0);
    };
    let mut direct = 0;
    let mut reuse = 0;
    let mut seen_by_d = false;
    for record in world
        .service
        .chain
        .iter()
        .filter(|record| record.revision <= upto)
    {
        if record.key != installed.key {
            continue;
        }
        if record.epoch == installed.epoch {
            direct |= record.members;
        } else {
            reuse |= record.members;
            if ModelKinds::lists(record, &D) && record.revision >= world.facts.join {
                seen_by_d = true;
            }
        }
    }
    // Every candidate D sent, applied or not: a service may have passed each device its wrap.
    // D issued them, so it knows them all.
    for ((epoch, key), members) in &world.sent {
        if *key != installed.key {
            continue;
        }
        if *epoch == installed.epoch {
            direct |= members;
        } else {
            reuse |= members;
            seen_by_d = true;
        }
    }
    if seen_by_d {
        return (direct | reuse, 0);
    }
    (direct, reuse & !direct)
}

fn publishes(world: &World) -> bool {
    !world.facts.out
        && world.facts.installed != 0
        && world.facts.removals.is_empty()
        && world.facts.candidate.is_none()
        && world.facts.installed == world.facts.head
}

fn recorded_when(world: &World, change: Change<Dev>) -> u64 {
    world
        .recorded_at
        .iter()
        .find(|(recorded, _)| *recorded == change)
        .map_or(0, |(_, length)| *length)
}

/// The fence as the reconciler itself decides it, from the facts and the keys the store holds.
fn reconciler_publishes(world: &World) -> bool {
    let held: BTreeMap<u64, KeyLabel> = world
        .facts
        .epochs()
        .into_iter()
        .filter_map(|epoch| world.store.get(&epoch).map(|key| (epoch, *key)))
        .collect();
    View {
        facts: &world.facts,
        me: D,
        held: &held,
    }
    .publishes()
}

/// Checks one state.
fn check_state(world: &World) -> Result<(), Violation> {
    let facts = &world.facts;
    if facts.installed > facts.head {
        return violation("installed beyond the head");
    }
    if facts.check(&D).is_err() {
        return violation(format!(
            "a file the load check refuses: {:?}",
            facts.check(&D)
        ));
    }
    // I4: a request still in flight is the standing dispatched candidate's, or one the service
    // already answered or fenced, which never runs again. Anything else would run with nothing
    // left in the file to settle it.
    let live = facts
        .candidate
        .as_ref()
        .filter(|candidate| candidate.dispatched.is_some())
        .map(|candidate| request_of(candidate.request));
    if let Some((request, _)) =
        world.service.transit.iter().find(|(request, _)| {
            Some(*request) != live && receipt(&world.service, *request).is_none()
        })
    {
        return violation(format!(
            "request {request} is in flight with nothing in the file to settle it"
        ));
    }
    if facts.unfetched != world.fetch_waits {
        return violation(format!(
            "D records {:?} as waiting for a fetch, where the history has {:?}",
            facts.unfetched, world.fetch_waits
        ));
    }
    if reconciler_publishes(world) != publishes(world) {
        return violation(format!(
            "the reconciler's fence says {}, where the invariant's says {}",
            reconciler_publishes(world),
            publishes(world)
        ));
    }
    // D's window holds exactly the service's records.
    for held in &facts.records {
        if record(world, held.revision) != Some(held) {
            return violation(format!(
                "D's window holds a record the service does not: {held:?}"
            ));
        }
    }
    if facts.installed != 0 && !facts.out {
        let Some(installed) = installed(world) else {
            return violation("an installed record the service does not hold");
        };
        if world.store.get(&installed.epoch) != Some(&installed.key) {
            return violation("the installed record's key is not the one held for its epoch");
        }
    }
    if !facts.out && world.seen > facts.head {
        return violation("a record D has read is not recorded as its head");
    }
    // Every key D sent that never applied is withdrawn, but the standing candidate's, which is
    // still settling; and while D is a member it never withdraws a key that applied.
    let mut owed = withdrawn(world);
    if let Some(candidate) = &facts.candidate {
        owed.remove(&candidate.record.key);
    }
    if !owed.is_subset(&facts.withdrawn) {
        return violation(format!(
            "keys D sent that never applied are not recorded as withdrawn: {:?}",
            owed.difference(&facts.withdrawn).collect::<Vec<_>>()
        ));
    }
    if !facts.out
        && world
            .service
            .chain
            .iter()
            .any(|record| record.issuer == D && facts.withdrawn.contains(&record.key))
    {
        return violation("a key of a record D issued that applied is recorded as withdrawn");
    }
    if publishes(world) {
        let Some(installed) = installed(world) else {
            return violation("publication open without an installed record");
        };
        let (direct, _reuse) = holders(world, horizon(world));
        let excess = direct & !installed.members;
        if excess != 0 {
            return violation(format!(
                "publication open while {:?} hold the key",
                devices_in(excess).collect::<Vec<_>>()
            ));
        }
        let known = facts.answers.hosts | facts.answers.verified | world.verified;
        let revoked = direct & known & !bit(D);
        if revoked != 0 {
            return violation(format!(
                "publication open while {:?}, known revoked, hold the key",
                devices_in(revoked).collect::<Vec<_>>()
            ));
        }
        if world
            .service
            .chain
            .iter()
            .filter(|record| record.revision >= facts.join && record.revision <= facts.installed)
            .any(|record| !ModelKinds::lists(record, &D))
        {
            return violation("publication open although a record since D's join left it out");
        }
    }
    Ok(())
}

/// Checks one step from `before` to `after`.
fn check_step(before: &World, transition: &Transition) -> Result<(), Violation> {
    let after = &transition.world;
    let label = transition.label;
    // I4: one send, by the send that follows the dispatch mark, never while another is live.
    if let Some((request, _)) = transition.sent {
        let standing = before
            .facts
            .candidate
            .as_ref()
            .filter(|candidate| candidate.dispatched.is_some())
            .map(|candidate| request_of(candidate.request));
        if standing != Some(request) || before.sending != Some(request) {
            return violation(format!(
                "request {request} sent outside the send that follows its dispatch mark"
            ));
        }
        if !before.service.transit.is_empty() {
            return violation(format!("request {request} sent while another is live"));
        }
    }
    // One durable write per step, every step: so every state between two writes is a state the
    // search visits, and a restart can come back to.
    if transition.writes > 1 {
        return violation(format!(
            "{label:?} made {} durable writes",
            transition.writes
        ));
    }
    // I5: a key reaches the store only through row 4, from the one record it names, which passes
    // the checks.
    let new_keys: Vec<(u64, KeyLabel)> = after
        .store
        .iter()
        .filter(|(epoch, key)| before.store.get(epoch) != Some(key))
        .map(|(epoch, key)| (*epoch, *key))
        .collect();
    if !new_keys.is_empty() {
        let (Label::Step(Step::Stored { epoch, revision })
        | Label::StepWithoutAnswer(Step::Stored { epoch, revision })) = label
        else {
            return violation(format!("a key stored by {label:?}"));
        };
        let Some(stored) = record(before, revision).copied() else {
            return violation(format!(
                "a key stored from revision {revision}, which no record has"
            ));
        };
        if new_keys != [(epoch, stored.key)]
            || stored.epoch != epoch
            || revision > before.facts.head
            || !acceptable(before, &stored)
        {
            return violation(format!(
                "the key {new_keys:?} stored from record {stored:?}, which does not pass the checks"
            ));
        }
    }
    // Keys leave the store only after the write that records D out.
    if before
        .store
        .iter()
        .any(|(epoch, key)| after.store.get(epoch) != Some(key))
        && !(before.facts.out && after.facts.out)
    {
        return violation("a key left the store while D is a member");
    }
    // I6.
    let built = matches!(
        label,
        Label::Step(Step::Built { built: true })
            | Label::StepWithoutAnswer(Step::Built { built: true })
    );
    if built && let Some(candidate) = &after.facts.candidate {
        if let Some(installed_before) = installed(before) {
            let head_before = head(before).copied().unwrap_or(*installed_before);
            let removals = &before.facts.removals;
            let addition = before.facts.addition;
            let cause = removals.iter().any(|member| {
                ModelKinds::lists(installed_before, member)
                    || ModelKinds::lists(&head_before, member)
            }) || addition.is_some_and(|addition| {
                passes3(before, addition)
                    && (!ModelKinds::lists(installed_before, &addition)
                        || !ModelKinds::lists(&head_before, &addition))
            }) || (before.facts.head != before.facts.installed
                && ModelKinds::lists(&head_before, &D)
                && !acceptable(before, &head_before));
            if !cause {
                return violation(
                    "a candidate built for a change the installed record and the head already carry out",
                );
            }
        }
        let mut allowed = installed(before).map_or(bit(D), |record| record.members);
        if let Some(addition) = before.facts.addition {
            allowed |= bit(addition);
        }
        if candidate.record.members & !allowed != 0 {
            return violation(format!(
                "a candidate lists {:?}, which neither the installed record nor the owner authorised",
                devices_in(candidate.record.members & !allowed).collect::<Vec<_>>()
            ));
        }
    }
    // I2's durable record: exactly the changes this step ended are recorded, in this write, and a
    // crash loses none. Only the file counts: an outcome held anywhere else is one a crash loses.
    let before_outcomes = &before.facts.outcomes;
    let after_outcomes = &after.facts.outcomes;
    if after_outcomes.len() < before_outcomes.len()
        || after_outcomes[..before_outcomes.len()] != before_outcomes[..]
    {
        return violation(format!(
            "{label:?} lost an outcome: had {before_outcomes:?}, now {after_outcomes:?}"
        ));
    }
    let new = &after_outcomes[before_outcomes.len()..];
    let mut how: BTreeMap<Change<Dev>, Ended> = BTreeMap::new();
    let mut joins = 0;
    for outcome in new {
        match *outcome {
            Outcome::Removal { device, ended } => {
                how.insert(Change::Removal(device), ended);
            }
            Outcome::Addition { device, ended } => {
                how.insert(Change::Addition(device), ended);
            }
            Outcome::Join { .. } => joins += 1,
        }
    }
    let ended: BTreeSet<Change<Dev>> = pending(before)
        .difference(&pending(after))
        .copied()
        .collect();
    let mut expected = ended.len();
    if let Label::OwnerAdd(member) = label
        && how.get(&Change::Addition(member)) == Some(&Ended::Refused)
        && !ended.contains(&Change::Addition(member))
    {
        expected += 1;
    }
    let join_refused = matches!(
        label,
        Label::Step(Step::JoinRefused) | Label::StepWithoutAnswer(Step::JoinRefused)
    );
    if new.len() != expected + joins || (joins > 0 && !join_refused) {
        return violation(format!(
            "{label:?} did not record exactly the changes it ended: ended {ended:?}, recorded {new:?}"
        ));
    }
    // I2 and I3, by the exact predicate.
    let installed_after = installed(after);
    for change in &ended {
        let Some(outcome) = how.get(change) else {
            return violation(format!("{change:?} lost by {label:?}"));
        };
        match (change, outcome) {
            (Change::Removal(member), Ended::Done) => {
                let when = recorded_when(before, *change);
                if before.facts.candidate.is_some()
                    || after.facts.candidate.is_some()
                    || after.facts.installed != after.facts.head
                    || installed_after.is_none_or(|record| ModelKinds::lists(record, member))
                    || after.facts.head < when
                    || before.fetch_waits.contains(change)
                {
                    return violation(format!(
                        "the removal of {member} done outside the exact predicate"
                    ));
                }
                let (direct, _) = holders(after, horizon(after).max(when));
                if direct & bit(*member) != 0 {
                    return violation(format!(
                        "the removal of {member} done while it holds the current key"
                    ));
                }
            }
            (Change::Removal(member), Ended::Refused) => {
                if !after.facts.out {
                    return violation(format!(
                        "the removal of {member} refused while D is a member"
                    ));
                }
            }
            (Change::Addition(member), Ended::Done) => {
                if before.facts.candidate.is_some()
                    || after.facts.candidate.is_some()
                    || after.facts.installed != after.facts.head
                    || installed_after.is_none_or(|record| !ModelKinds::lists(record, member))
                    || after.facts.head < recorded_when(before, *change)
                    || before.fetch_waits.contains(change)
                {
                    return violation(format!(
                        "the addition of {member} done outside the exact predicate"
                    ));
                }
            }
            (Change::Addition(member), Ended::Cancelled) => {
                if !after.facts.removals.contains(member) {
                    return violation(format!(
                        "the addition of {member} cancelled without its removal"
                    ));
                }
            }
            (Change::Addition(member), Ended::Refused) => {
                if !(after.facts.out || !passes3(after, *member)) {
                    return violation(format!("the addition of {member} refused without a cause"));
                }
            }
            (change, outcome) => {
                return violation(format!("{change:?} ended as {outcome:?}"));
            }
        }
    }
    if let Some(addition) = after.facts.addition
        && after.facts.removals.contains(&addition)
    {
        return violation(format!(
            "an addition of {addition} pending beside its removal"
        ));
    }
    Ok(())
}

/// A 128-bit fingerprint of a canonical world.
fn fingerprint(world: &World) -> u128 {
    let mut first = std::hash::DefaultHasher::new();
    0u8.hash(&mut first);
    world.hash(&mut first);
    let mut second = std::hash::DefaultHasher::new();
    1u8.hash(&mut second);
    world.hash(&mut second);
    (u128::from(first.finish()) << 64) | u128::from(second.finish())
}

/// Checks that a file survives its own encoding.
fn round_trips(facts: &Facts<ModelKinds>) -> Result<(), Violation> {
    let bytes = kr_cbor::to_canonical_vec(facts)
        .map_err(|error| Violation(format!("a file that does not encode: {error}")))?;
    let decoded: Facts<ModelKinds> =
        kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| Violation(format!("a file that does not decode: {error}")))?;
    if decoded != *facts {
        return violation("a file that decodes to other facts");
    }
    Ok(())
}

/// Liveness: every message delivered, nothing lost, no further event; D must settle.
fn settles(world: &World, settled: &mut HashSet<u128>) -> Result<(), Violation> {
    let mut path = Vec::new();
    let mut current = world.clone();
    for _ in 0..500 {
        let print = fingerprint(&current);
        if settled.contains(&print) {
            settled.extend(path);
            return Ok(());
        }
        path.push(print);
        // A device that is out has settled once its dispatched request is settled and its keys
        // are forgotten.
        if current.facts.out && current.facts.candidate.is_none() && current.store.is_empty() {
            settled.extend(path);
            return Ok(());
        }
        // A pending send goes first, then the service takes what is in transit.
        let sending = current.sending.is_some()
            && current
                .facts
                .candidate
                .as_ref()
                .map(|c| request_of(c.request))
                == current.sending;
        if sending && let Some(step) = step_of(&current, false) {
            check_step(&current, &step)?;
            check_state(&step.world)?;
            current = canon(step.world);
            continue;
        }
        if let Some((request, candidate)) = current.service.transit.iter().next().copied() {
            let (mut delivered, receipt) = deliver(&current, request, &candidate);
            match receipt {
                Receipt::Applied(revision) => {
                    delivered.inbox = Some((request, Answer::Applied(revision)));
                }
                Receipt::Refused => {
                    delivered.inbox = Some((
                        request,
                        Answer::Refused(delivered.service.chain.len() as u64),
                    ));
                }
                Receipt::Fenced | Receipt::FencedUnknown => {}
            }
            current = canon(delivered);
            continue;
        }
        if !current.service.chain.is_empty()
            && let Some(refresh) = refresh_of(&current)
        {
            check_step(&current, &refresh)?;
            check_state(&refresh.world)?;
            current = canon(refresh.world);
            continue;
        }
        let Some(step) = step_of(&current, false) else {
            if current.facts.out {
                return violation(format!(
                    "stuck out with a request unsettled or keys held: candidate {:?}, keys {:?}",
                    current.facts.candidate, current.store
                ));
            }
            let newest = current.service.chain.last().map(|record| record.revision);
            if !current.facts.removals.is_empty()
                || current.facts.addition.is_some()
                || current.facts.candidate.is_some()
            {
                return violation(format!(
                    "stuck with work left: removals {:?}, addition {:?}, candidate {:?}",
                    current.facts.removals, current.facts.addition, current.facts.candidate
                ));
            }
            if newest != Some(current.facts.installed) {
                return violation(format!(
                    "stuck behind the service: installed {}, newest {newest:?}",
                    current.facts.installed
                ));
            }
            if !publishes(&current) {
                return violation("stuck fenced");
            }
            settled.extend(path);
            return Ok(());
        };
        check_step(&current, &step)?;
        check_state(&step.world)?;
        current = canon(step.world);
    }
    violation("no settlement within 500 steps")
}

/// How one exploration ended.
#[derive(Debug)]
enum Explored {
    /// Every reachable state was visited and every check held.
    Complete { states: usize, steps: usize },
    /// A check failed; the trace leads to it from the start.
    Violated {
        violation: String,
        trace: Vec<String>,
    },
    /// The search stopped at its cap.
    Capped { states: usize },
}

/// Visits every state reachable from `initial`, checking each state and each step.
fn explore(initial: World, max_states: usize) -> Explored {
    let initial = canon(initial);
    let mut parents: HashMap<u128, Option<(u128, Label)>> = HashMap::new();
    let mut settled: HashSet<u128> = HashSet::new();
    let mut files: HashSet<u128> = HashSet::new();
    let mut queue: VecDeque<World> = VecDeque::new();
    parents.insert(fingerprint(&initial), None);
    queue.push_back(initial);
    let mut steps = 0usize;
    let trace = |parents: &HashMap<u128, Option<(u128, Label)>>, mut at: u128| {
        let mut labels = Vec::new();
        while let Some(Some((parent, label))) = parents.get(&at) {
            labels.push(format!("{label:?}"));
            at = *parent;
        }
        labels.reverse();
        labels
    };
    while let Some(world) = queue.pop_front() {
        if parents.len() > max_states {
            return Explored::Capped {
                states: parents.len(),
            };
        }
        let print = fingerprint(&world);
        let checked = (|| {
            check_state(&world)?;
            let mut file_print = std::hash::DefaultHasher::new();
            world.facts.hash(&mut file_print);
            if files.insert(u128::from(file_print.finish())) {
                round_trips(&world.facts)?;
            }
            settles(&world, &mut settled)?;
            let mut next = Vec::new();
            for transition in transitions(&world) {
                check_step(&world, &transition).map_err(|Violation(violation)| {
                    Violation(format!("{:?}: {violation}", transition.label))
                })?;
                check_state(&transition.world).map_err(|Violation(violation)| {
                    Violation(format!("after {:?}: {violation}", transition.label))
                })?;
                next.push((transition.label, canon(transition.world)));
            }
            Ok::<_, Violation>(next)
        })();
        match checked {
            Err(Violation(violation)) => {
                let mut labels = trace(&parents, print);
                labels.push(format!(
                    "at: join {}, installed {}, head {}, removals {:?}, addition {:?}, candidate {:?}, answers {:?}, revoked {:#b}, out {}, store {:?}",
                    world.facts.join,
                    world.facts.installed,
                    world.facts.head,
                    world.facts.removals,
                    world.facts.addition,
                    world.facts.candidate,
                    world.facts.answers,
                    world.revoked,
                    world.facts.out,
                    world.store,
                ));
                for record in &world.service.chain {
                    labels.push(format!("record {record:?}"));
                }
                return Explored::Violated {
                    violation,
                    trace: labels,
                };
            }
            Ok(next) => {
                for (label, successor) in next {
                    steps += 1;
                    let successor_print = fingerprint(&successor);
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        parents.entry(successor_print)
                    {
                        entry.insert(Some((print, label)));
                        queue.push_back(successor);
                    }
                }
            }
        }
    }
    Explored::Complete {
        states: parents.len(),
        steps,
    }
}

/// The first record, D's own claim at epoch 0.
fn first_key() -> KeyLabel {
    KeyLabel::Fresh {
        epoch: 0,
        base: 0,
        members: bit(D),
        attempt: 0,
    }
}

/// The keys of the candidates D sent since its join that no record of D's own carries: the
/// candidates that never applied, and the one still standing.
fn withdrawn(world: &World) -> BTreeSet<KeyLabel> {
    let applied: BTreeSet<KeyLabel> = world
        .service
        .chain
        .iter()
        .filter(|record| record.issuer == D)
        .map(|record| record.key)
        .collect();
    world
        .sent
        .keys()
        .map(|(_, key)| *key)
        .filter(|key| !applied.contains(key))
        .collect()
}

fn start(
    facts: Facts<ModelKinds>,
    chain: Vec<ModelRecord>,
    store: BTreeMap<u64, KeyLabel>,
    budget: [u8; 10],
) -> World {
    let seen = facts.head;
    let next_request = if facts.candidate.is_some() { 2 } else { 1 };
    World {
        service: Service {
            chain,
            receipts: BTreeSet::new(),
            transit: BTreeSet::new(),
            expired: false,
        },
        facts,
        store,
        sending: None,
        inbox: None,
        volatile_outcomes: Vec::new(),
        revoked: 0,
        verified: 0,
        seen,
        recorded_at: BTreeSet::new(),
        fetch_waits: BTreeSet::new(),
        sent: BTreeMap::new(),
        next_request,
        budget,
    }
}

/// D turns settings sync on: its own first record is its only candidate.
fn genesis(budget: [u8; 10]) -> World {
    let record = ModelRecord {
        revision: 1,
        epoch: 0,
        members: bit(D),
        issuer: D,
        key: first_key(),
    };
    let facts = Facts::genesis(
        collection(),
        record,
        first_key(),
        uuid_of(1),
        ModelAnswers::default(),
    );
    start(facts, Vec::new(), BTreeMap::new(), budget)
}

/// D holds the collection with A and X at revision 2, epoch 0.
fn steady(budget: [u8; 10]) -> World {
    let first = ModelRecord {
        revision: 1,
        epoch: 0,
        members: bit(D),
        issuer: D,
        key: first_key(),
    };
    let second = ModelRecord {
        revision: 2,
        epoch: 0,
        members: bit(D) | bit(A) | bit(X),
        issuer: D,
        key: first_key(),
    };
    let mut facts = Facts::genesis(
        collection(),
        first,
        first_key(),
        uuid_of(1),
        ModelAnswers::default(),
    );
    facts.candidate = None;
    facts.installed = 2;
    facts.head = 2;
    facts.records = vec![second];
    facts.openers = vec![Opener {
        epoch: 0,
        issuer: D,
    }];
    facts.opened = BTreeSet::from([
        Opened {
            revision: 1,
            epoch: 0,
            mark: first_key(),
        },
        Opened {
            revision: 2,
            epoch: 0,
            mark: first_key(),
        },
    ]);
    start(
        facts,
        vec![first, second],
        BTreeMap::from([(0, first_key())]),
        budget,
    )
}

/// The model's configurations: owner, others, revoke, crash, lost request, lost reply, expired
/// receipt, feed, join, and a refresh answered as if the collection were gone.
fn configuration(name: &str) -> World {
    match name {
        "genesis" => genesis([2, 1, 1, 1, 1, 1, 1, 0, 0, 0]),
        "steady-owner" => steady([2, 1, 1, 1, 0, 1, 1, 0, 0, 0]),
        "steady-others" => steady([1, 2, 1, 1, 0, 1, 0, 0, 0, 0]),
        "steady-churn" => steady([2, 2, 1, 0, 0, 0, 0, 0, 0, 0]),
        "feed" => steady([2, 1, 0, 1, 0, 1, 0, 1, 0, 0]),
        "gap" => steady([1, 3, 0, 0, 0, 0, 0, 0, 1, 0]),
        "expiry" => steady([2, 1, 0, 0, 0, 0, 1, 0, 0, 0]),
        "join-feed" => steady([0, 2, 0, 0, 0, 0, 0, 1, 1, 0]),
        "absent" => steady([2, 1, 0, 1, 0, 1, 1, 0, 1, 1]),
        other => panic!("no configuration {other}"),
    }
}

/// Every configuration of the model.
const CONFIGURATIONS: [&str; 9] = [
    "genesis",
    "steady-owner",
    "steady-others",
    "steady-churn",
    "feed",
    "gap",
    "expiry",
    "join-feed",
    "absent",
];

/// Each weakened rule and the configurations most likely to catch it.
const WEAKENED: [(Rule, &[&str]); 19] = [
    (Rule::NoOpenerCheck, &["steady-others", "genesis"]),
    (Rule::NoFreshKeyCheck, &["genesis", "steady-others"]),
    (Rule::BuildFromHead, &["genesis", "steady-owner"]),
    (Rule::SettleKeepsHead, &["genesis", "steady-owner"]),
    (
        Rule::SettleWithoutMax,
        &["genesis", "steady-owner", "steady-others"],
    ),
    (Rule::ResendAfterRestart, &["genesis"]),
    (Rule::DoneByBothRecords, &["steady-others", "steady-owner"]),
    (Rule::RefreshRecordsNoRemoval, &["genesis", "steady-owner"]),
    (Rule::GapKeepsMembership, &["gap"]),
    (Rule::FeedWaitsForRefresh, &["feed"]),
    (Rule::VolatileReports, &["genesis", "steady-owner"]),
    (
        Rule::ReadNotRecorded,
        &["expiry", "steady-owner", "genesis"],
    ),
    (
        Rule::DoneWithoutFetch,
        &["expiry", "steady-owner", "steady-others"],
    ),
    (Rule::JoinSkipsAnswers, &["join-feed", "gap"]),
    (
        Rule::BuildWhileWaiting,
        &["expiry", "steady-owner", "genesis"],
    ),
    (
        Rule::ReadSkipsAnswers,
        &["genesis", "expiry", "steady-owner"],
    ),
    (
        Rule::SameEpochCandidate,
        &["steady-owner", "expiry", "genesis"],
    ),
    (
        Rule::NoWithdrawnCheck,
        &["steady-owner", "genesis", "expiry"],
    ),
    (Rule::LeaveDropsDispatched, &["absent"]),
];

/// The largest search a configuration gets; one that reaches it fails as incomplete.
const MAX_STATES: usize = 40_000_000;

/// The largest search a weakened rule gets before it counts as not caught.
const WEAKENED_MAX_STATES: usize = 3_000_000;

/// Runs each named configuration on its own thread, each with the rule given weakened.
fn run_configurations(
    names: &[&'static str],
    rule: Option<Rule>,
    max_states: usize,
) -> Vec<(&'static str, Explored)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = names
            .iter()
            .map(|name| {
                scope.spawn(move || {
                    weaken(rule);
                    let explored = explore(configuration(name), max_states);
                    weaken(None);
                    (*name, explored)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a configuration's thread"))
            .collect()
    })
}

/// Explores the named configurations and fails on any violation or any search left incomplete.
fn every_state_of(names: &[&'static str]) {
    let mut failed = Vec::new();
    for (name, explored) in run_configurations(names, None, MAX_STATES) {
        match explored {
            Explored::Complete { states, steps } => {
                println!("[{name}] ok: {states} states, {steps} steps checked");
            }
            Explored::Violated { violation, trace } => {
                println!("[{name}] VIOLATION: {violation}");
                for line in trace {
                    println!("    {line}");
                }
                failed.push(name);
            }
            Explored::Capped { states } => {
                println!("[{name}] INCOMPLETE: stopped at {states} states");
                failed.push(name);
            }
        }
    }
    assert!(failed.is_empty(), "configurations that failed: {failed:?}");
}

/// A bounded model of the reconciler's world, run over this reconciler itself: every reachable
/// combination of the recorded facts within the configurations' budgets, every state between two
/// writes, every
/// invariant by its exact predicate, and every state settling once events stop.
///
/// Its eight configurations visit some twenty million states, which takes about three minutes in
/// a release build and far longer in a debug one, so it runs on request:
/// `cargo test --release -p kr-client --lib membership::exhaustive -- --ignored`. A run may name
/// a subset in `KR_MEMBERSHIP_CONFIGURATIONS`, comma-separated.
#[test]
#[ignore = "explores every model configuration; run it in a release build with --ignored"]
fn every_combination_of_recorded_facts_keeps_the_invariants() {
    let chosen = std::env::var("KR_MEMBERSHIP_CONFIGURATIONS").ok();
    let names: Vec<&'static str> = CONFIGURATIONS
        .iter()
        .copied()
        .filter(|name| {
            chosen
                .as_deref()
                .is_none_or(|chosen| chosen.split(',').any(|chosen| chosen == *name))
        })
        .collect();
    every_state_of(&names);
}

/// The two smallest configurations of the model, complete, in every build: an expired receipt
/// with two owner changes, and a feed revocation while out followed by a confirmed join.
#[test]
fn the_smallest_model_configurations_keep_the_invariants() {
    every_state_of(&["expiry", "join-feed"]);
}

/// Each rule the test can weaken makes a run fail, so the test above would notice it.
#[test]
fn every_weakened_rule_makes_the_exhaustive_test_fail() {
    let mut survivors = Vec::new();
    for (rule, names) in WEAKENED {
        let mut caught = None;
        for name in names.iter().copied() {
            let [(_, explored)] = run_configurations(&[name], Some(rule), WEAKENED_MAX_STATES)
                .try_into()
                .expect("one configuration");
            if let Explored::Violated { violation, .. } = explored {
                caught = Some(format!("{name}: {violation}"));
                break;
            }
        }
        match caught {
            Some(how) => println!("{rule:?} caught in {how}"),
            None => {
                println!("{rule:?} NOT caught");
                survivors.push(rule);
            }
        }
    }
    assert!(
        survivors.is_empty(),
        "weakened rules nothing caught: {survivors:?}"
    );
}

/// A file whose facts no sequence of writes produces is refused on load: the device reads it as
/// being out of the collection with a join awaiting the owner, in facts that pass the load check.
/// A dispatched candidate with a request identity is settled first, by status and fence, and its
/// key withdrawn; then the keys the store may still hold are forgotten, one epoch a step and one
/// write a step.
#[test]
fn a_file_no_sequence_of_writes_produces_is_refused_and_a_rejoin_offered() {
    let mut installed_after_the_head = steady([0; 10]);
    installed_after_the_head.facts.installed = 3;
    let mut without_an_identity = genesis([0; 10]);
    if let Some(candidate) = &mut without_an_identity.facts.candidate {
        candidate.request = Uuid::NIL;
    }
    let mut dispatched_without_an_identity = without_an_identity.clone();
    if let Some(candidate) = &mut dispatched_without_an_identity.facts.candidate {
        candidate.dispatched = Some(NOW);
    }
    let withdrawn_key = KeyLabel::Fresh {
        epoch: 1,
        base: 2,
        members: bit(D) | bit(A) | bit(X),
        attempt: 0,
    };
    let mut dispatched_in_a_bad_file = installed_after_the_head.clone();
    dispatched_in_a_bad_file.facts.candidate = Some(Candidate {
        record: ModelRecord {
            revision: 3,
            epoch: 1,
            members: bit(D) | bit(A) | bit(X),
            issuer: D,
            key: withdrawn_key,
        },
        mark: withdrawn_key,
        request: uuid_of(1),
        dispatched: Some(NOW),
    });
    dispatched_in_a_bad_file.next_request = 2;
    for (world, settles) in [
        (installed_after_the_head, false),
        (without_an_identity, false),
        (dispatched_without_an_identity, false),
        (dispatched_in_a_bad_file, true),
    ] {
        assert!(world.facts.check(&D).is_err());
        let read = run(&world, false, |reconciler| reconciler.read());
        let (facts, _) = read
            .value
            .expect("readable")
            .expect("a membership, refused");
        assert!(facts.out, "a join awaits the owner");
        assert!(facts.check(&D).is_ok());
        assert_eq!(facts.dispatched(), settles);
        assert_eq!(read.writes, 0, "reading writes nothing");

        let mut current = world;
        let mut steps = Vec::new();
        for _ in 0..4 {
            let ran = run(&current, false, |reconciler| block_on(reconciler.step(NOW)));
            let step = ran.value.expect("a step");
            assert!(ran.writes <= 1, "{step:?} made {} writes", ran.writes);
            assert_eq!(ran.sent, None, "a device that is out sends nothing");
            current = ran.world;
            if step == Step::Nothing {
                break;
            }
            steps.push(step);
        }
        if settles {
            // The settling write is the first write, and it carries the refused facts with it.
            assert_eq!(steps.remove(0), Step::Settled(Settlement::Fenced));
            assert!(current.facts.check(&D).is_ok());
            assert!(current.facts.withdrawn.contains(&withdrawn_key));
        }
        assert!(
            steps
                .iter()
                .all(|step| matches!(step, Step::ForgotKeys { .. })),
            "{steps:?}"
        );
        let read = run(&current, false, |reconciler| reconciler.read());
        let (facts, _) = read
            .value
            .expect("readable")
            .expect("a membership, refused");
        assert!(facts.out && facts.candidate.is_none());
        assert!(
            current.store.is_empty(),
            "the collection's keys are forgotten"
        );
    }
}

/// A device installed at the last epoch, or the last revision, a counter holds, with a removal
/// pending: no successor exists, so the step says so and draws, records and writes nothing.
#[test]
fn the_last_epoch_or_revision_has_no_successor_and_nothing_is_built() {
    for (revision, epoch) in [(2, u64::MAX), (u64::MAX, 3)] {
        let mut world = steady([0; 10]);
        let last = ModelRecord {
            revision,
            epoch,
            members: bit(D) | bit(A) | bit(X),
            issuer: D,
            key: first_key(),
        };
        world.facts.join = revision.min(world.facts.join);
        world.facts.installed = revision;
        world.facts.head = revision;
        world.facts.records = vec![last];
        world.facts.openers = vec![Opener { epoch, issuer: D }];
        world.facts.opened = BTreeSet::from([Opened {
            revision,
            epoch,
            mark: first_key(),
        }]);
        world.store = BTreeMap::from([(epoch, first_key())]);
        world.facts.removals.insert(A);
        world.facts.unfetched.insert(Change::Removal(A));
        assert!(world.facts.check(&D).is_ok());

        let ran = run(&world, false, |reconciler| block_on(reconciler.step(NOW)));
        assert!(
            matches!(ran.value, Err(MembershipError::Exhausted)),
            "{:?}",
            ran.value
        );
        assert_eq!(ran.writes, 0);
        assert!(ran.world.facts.candidate.is_none());
        assert_eq!(ran.world.next_request, world.next_request, "nothing drawn");
    }
}
