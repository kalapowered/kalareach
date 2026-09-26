//! The host's own policy: what is true of this host rather than of one grant.
//!
//! Three things live here, and each is a rule section 10, 17 or 24 states directly.
//!
//! * **Organisation leases (section 17).** "A signed membership lease lasts at most 15 minutes...
//!   Expired membership blocks further organisation-mediated reads and mutations even if the
//!   transport remains connected." So a lease is checked on every request against the clock, not
//!   against whether a socket is open, and a grant that requires membership is refused the moment
//!   its lease lapses. "Personal local owner access continues unless the host was explicitly
//!   enrolled as exclusively organisation-managed", so a grant with no organisation requirement is
//!   untouched by a lapse unless the host was enrolled that way.
//! * **The bounded offline-validity policy (section 10).** Optional, and off by default: "the
//!   default non-expiring owner grant remains account-free and usable without an authority-feed
//!   dependency." An owner who chooses a bound gets exactly that bound, measured from the last
//!   successful feed synchronisation, and the stale status and last sync are visible.
//! * **Revalidation after wake and reboot (section 24).** "Revalidate expiry after wake/reboot; no
//!   restored old policy can revive authority." Two halves. Expiry is re-read against the clock
//!   the moment this host wakes or starts, which [`HostPolicy::revalidate`] does; and a policy
//!   document restored from a backup cannot put back an authority the host has already moved past,
//!   which [`HostPolicy::accept_policy`] refuses by keeping the highest revision this host has
//!   ever accepted.
//!
//! The third rule is the one an implementation loses by accident: a host that simply loads
//! whatever its policy file holds will happily load last month's file. The floor is separate from
//! the loaded document for that reason, and it only ever goes up.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::account::{MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease, PolicyAuthority};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{Grant, GrantExpiry};
use kr_protocol::ids::{AccountId, AuthorityRevision, DeviceId, OrganisationId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet};
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};
use kr_transport::clock::ContinuousInstant;

use super::durable::StoredPolicy;
use super::organisation::{
    self, ChainOutcome, ChainRefused, Enrolment, LeaseHolder, LeaseInstalled, LeasePresentation,
    LeaseRecord, LeaseRefused, LeaseTime, MemberLease, VerifiedEnrolment,
};
use super::{AccessRequest, Refusal};
use crate::service::net::devices::ObservedUtc;

/// What the intersection of one grant with this host's policy produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyIntersection {
    /// The rights both the grant and the policy allow.
    pub rights: CanonicalSet<ActionRight>,
    /// The organisation whose lease narrowed them, when one did.
    pub organisation_id: Option<OrganisationId>,
    /// The membership lease the intersection was taken under, when a lease answered for it: it
    /// holds only while both of its deadlines are ahead.
    pub lease: Option<HeldBound>,
    /// The bounded offline validity the intersection was taken under, when it applied.
    pub offline: Option<HeldBound>,
}

/// Which time bound on authority a snapshot is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundIdentity {
    /// A membership lease, by the digest of its signing input.
    Lease(kr_protocol::scalars::Digest256),
    /// The bounded offline validity, by the synchronisation it is measured from, when it has one.
    Offline {
        /// When that synchronisation happened, in UTC milliseconds.
        synchronised_at_ms: Option<u64>,
    },
}

/// One time bound on authority as it stands: which bound it is, when it ends on the continuous
/// clock and in UTC, and whether a restrictive change has ended it.
///
/// A snapshot never changes once it is published; a change publishes a new one, with a new
/// version, through the bound's [`BoundCell`]. Every decision and every copy is taken from one
/// snapshot of each bound it reads, so no reader pairs one snapshot's continuous deadline with
/// another's UTC deadline. Between barriers a snapshot's deadlines never move earlier: a renewal
/// that does not narrow ends no earlier on either clock, and anything that ends a bound sooner is a
/// restrictive change, which a barrier follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundSnapshot {
    /// Which publication of its cell this is. Versions only rise, across every cell of this host.
    pub version: u64,
    /// The bound it is of.
    pub identity: BoundIdentity,
    /// When it ends on the continuous clock, when it does.
    pub continuous_deadline: Option<ContinuousInstant>,
    /// When it ends in UTC milliseconds, when it does: the first moment outside it.
    pub utc_deadline_ms: Option<u64>,
    /// Whether a restrictive change ended it: a lease dropped or withdrawn, or an offline bound
    /// with nothing to show it holding.
    pub ended: bool,
}

impl BoundSnapshot {
    /// Whether the bound has ended at `now` on the continuous clock, or at `utc_ms`, this host's
    /// reading of UTC through its floor.
    ///
    /// Both clocks only move forward, so a reader that finds an end finds one every later reader
    /// finds too: an end takes effect without being written anywhere.
    #[must_use]
    pub fn ended_at(&self, now: ContinuousInstant, utc_ms: u64) -> bool {
        self.ended
            || self
                .continuous_deadline
                .is_some_and(|deadline| now >= deadline)
            || self
                .utc_deadline_ms
                .is_some_and(|deadline| utc_ms >= deadline)
    }

    /// Whether it has ended on the continuous clock at `now`, whatever UTC says: the half no
    /// wall clock can move.
    #[must_use]
    pub fn ended_on_the_continuous_clock(&self, now: ContinuousInstant) -> bool {
        self.continuous_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    /// Whether this snapshot states the same bound as `other`, whatever their versions.
    fn states(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.continuous_deadline == other.continuous_deadline
            && self.utc_deadline_ms == other.utc_deadline_ms
            && self.ended == other.ended
    }
}

/// The versions every cell's snapshots are numbered from.
static BOUND_VERSIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One time bound's cell: the snapshot in force, published whole through one atomic pointer.
///
/// A writer builds the whole new snapshot and swaps the pointer; a reader loads it once and decides
/// from that value. The swap is one atomic store, so wherever a writer stops, a reader gets the old
/// snapshot or the new one, whole. Loading takes no lock and never waits, which is what a check
/// deciding inside a poll needs. Every publication is made under the host policy's lock.
#[derive(Debug)]
pub struct BoundCell(arc_swap::ArcSwap<BoundSnapshot>);

impl BoundCell {
    /// A cell publishing its first snapshot.
    #[must_use]
    pub fn new(
        identity: BoundIdentity,
        continuous_deadline: Option<ContinuousInstant>,
        utc_deadline_ms: Option<u64>,
        ended: bool,
    ) -> Arc<Self> {
        Arc::new(Self(arc_swap::ArcSwap::from_pointee(BoundSnapshot {
            version: BOUND_VERSIONS.fetch_add(1, Ordering::SeqCst),
            identity,
            continuous_deadline,
            utc_deadline_ms,
            ended,
        })))
    }

    /// The snapshot in force.
    #[must_use]
    pub fn load(&self) -> Arc<BoundSnapshot> {
        self.0.load_full()
    }

    /// Publishes a new snapshot stating `identity`, its deadlines and whether it has ended, unless
    /// the one in force already states exactly that. Called under the host policy's lock.
    pub(crate) fn publish(
        &self,
        identity: BoundIdentity,
        continuous_deadline: Option<ContinuousInstant>,
        utc_deadline_ms: Option<u64>,
        ended: bool,
    ) {
        let next = BoundSnapshot {
            version: 0,
            identity,
            continuous_deadline,
            utc_deadline_ms,
            ended,
        };
        if self.0.load().states(&next) {
            return;
        }
        let next = Arc::new(BoundSnapshot {
            version: BOUND_VERSIONS.fetch_add(1, Ordering::SeqCst),
            ..next
        });
        #[cfg(test)]
        publishing::before_the_swap();
        self.0.store(next);
        #[cfg(test)]
        publishing::after_the_swap();
    }

    /// Ends the bound: a restrictive change dropped or withdrew it.
    pub(crate) fn end(&self) {
        let current = self.load();
        self.publish(
            current.identity,
            current.continuous_deadline,
            current.utc_deadline_ms,
            true,
        );
    }
}

/// One bound a decision was taken under: its cell, and the snapshot the decision loaded from it.
///
/// What was decided stands on the snapshot, once loaded. What is asked afterwards asks the cell:
/// a relayed batch whether the cell still publishes the snapshot it was decided under, and a
/// response whether the bound, as it stands when the response is written, still holds.
#[derive(Clone, Debug)]
pub struct HeldBound {
    cell: Arc<BoundCell>,
    snapshot: Arc<BoundSnapshot>,
}

impl HeldBound {
    /// Loads `cell` once.
    #[must_use]
    pub fn load(cell: &Arc<BoundCell>) -> Self {
        let snapshot = cell.load();
        #[cfg(test)]
        publishing::after_a_load();
        Self {
            cell: Arc::clone(cell),
            snapshot,
        }
    }

    /// The snapshot the decision was taken under.
    #[must_use]
    pub fn snapshot(&self) -> &BoundSnapshot {
        &self.snapshot
    }

    /// When it ends on the continuous clock, as the decision loaded it.
    #[must_use]
    pub fn continuous_deadline(&self) -> Option<ContinuousInstant> {
        self.snapshot.continuous_deadline
    }

    /// When it ends in UTC milliseconds, as the decision loaded it.
    #[must_use]
    pub fn utc_deadline_ms(&self) -> Option<u64> {
        self.snapshot.utc_deadline_ms
    }

    /// Whether the bound, as its cell publishes it now, still holds at these readings: what a
    /// response is written under.
    #[must_use]
    pub fn stands_at(&self, now: ContinuousInstant, utc_ms: u64) -> Stands {
        judged(&self.cell.load(), now, utc_ms)
    }

    /// Whether the cell still publishes the snapshot the decision was taken under, and it still
    /// holds at these readings: what a relayed batch is written under. A renewal publishes a new
    /// snapshot, so a batch decided before it is decided again.
    #[must_use]
    pub fn holds_as_decided(&self, now: ContinuousInstant, utc_ms: u64) -> Stands {
        let current = self.cell.load();
        if current.version != self.snapshot.version {
            return Stands::Moved;
        }
        judged(&current, now, utc_ms)
    }
}

impl PartialEq for HeldBound {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cell, &other.cell) && self.snapshot == other.snapshot
    }
}

impl Eq for HeldBound {}

/// Whether a bound still holds where a check reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stands {
    /// It holds.
    Holds,
    /// Its cell published another snapshot since the decision.
    Moved,
    /// It has ended on the continuous clock, or a restrictive change ended it.
    EndedOnTheContinuousClock,
    /// It has ended at this host's reading of UTC, which is owed its record.
    EndedInUtc,
}

fn judged(snapshot: &BoundSnapshot, now: ContinuousInstant, utc_ms: u64) -> Stands {
    if snapshot.ended || snapshot.ended_on_the_continuous_clock(now) {
        Stands::EndedOnTheContinuousClock
    } else if snapshot
        .utc_deadline_ms
        .is_some_and(|deadline| utc_ms >= deadline)
    {
        Stands::EndedInUtc
    } else {
        Stands::Holds
    }
}

/// Where this host's own tests stop a publication, or a reader between two loads.
#[cfg(test)]
pub(crate) mod publishing {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut()>;

    thread_local! {
        static BEFORE_THE_SWAP: RefCell<Option<Hook>> = RefCell::new(None);
        static AFTER_THE_SWAP: RefCell<Option<Hook>> = RefCell::new(None);
        static AFTER_A_LOAD: RefCell<Option<Hook>> = RefCell::new(None);
    }

    fn run(hook: &'static std::thread::LocalKey<RefCell<Option<Hook>>>) {
        let taken = hook.with(|hook| hook.borrow_mut().take());
        if let Some(mut run) = taken {
            run();
        }
    }

    pub(super) fn before_the_swap() {
        run(&BEFORE_THE_SWAP);
    }

    pub(super) fn after_the_swap() {
        run(&AFTER_THE_SWAP);
    }

    pub(super) fn after_a_load() {
        run(&AFTER_A_LOAD);
    }

    /// Runs `hook` once, on this thread, the next time a publication has built its snapshot and
    /// not yet swapped it in.
    pub(crate) fn stop_before_the_swap(hook: impl FnMut() + 'static) {
        BEFORE_THE_SWAP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Runs `hook` once, on this thread, the next time a publication has swapped its snapshot in.
    pub(crate) fn stop_after_the_swap(hook: impl FnMut() + 'static) {
        AFTER_THE_SWAP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Runs `hook` once, on this thread, the next time a reader has loaded a cell.
    pub(crate) fn stop_after_a_load(hook: impl FnMut() + 'static) {
        AFTER_A_LOAD.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }
}

/// The highest UTC reading this host has decided anything from, and whether that reading is on
/// disk.
///
/// Expiry is decided from the later of this and the clock. Without it, a clock wound back past a
/// deadline would revive a grant this host has already refused: section 24 asks for expiry to be
/// revalidated after a wake, and a revalidation that trusts a smaller number than the last one is
/// not a revalidation. It only ever rises.
///
/// There is one of it for the whole host. Its words are the environment's shared clock floor
/// ([`kr_ipc::floor::SharedFloor`]), which every process of the environment maps: a reading this
/// daemon publishes is the floor every worker decides from, and a reading a worker publishes is
/// the floor every later decision here stands on. So there is no copy of it anywhere that could
/// fall behind, in this process or another. A raise lands at its source, whoever makes it and
/// whatever lock it holds, and a reading is taken from the word whoever takes it: the write
/// boundary deciding inside a poll whether a relayed batch may still go reads the floor a decision
/// raised a moment ago under the policy's lock.
///
/// # What a decision may stand on
///
/// The floor is only as good as its record. A daemon that stops before a raised floor is written
/// down starts again on the older one, and after a clock wound back it would decide the other way.
/// So the floor also keeps what is owed a record: the highest floor a decision stood on that has
/// to outlive this process, in this daemon or in a worker, beside the highest floor written down.
/// While the first is ahead of the second, or while a start could not write the floor at all, the
/// floor is **owed its record**. [`Self::bound`] is the one rule every decision about a time bound
/// is taken through: a bound that can pass is not decided while the floor is owed its record, and
/// a bound that has passed says whether the floor on disk already covers the moment it passed. An
/// effect in the grant store refuses a lapse the floor does not cover yet and owes its record; a
/// decision on a request answers the lapse and its caller writes the record straight after. A
/// bound that never passes stands on no floor and is decided as before, so a personal grant that
/// never expires is untouched by any of this.
///
/// # A boot whose clock continuity was lost
///
/// A daemon that starts in a boot whose floor's file has gone creates a new one, and a reading
/// published only in the lost file may have passed a deadline that nothing on record shows as
/// passed. Until the owner establishes the clock again, every bound that can pass is answered as
/// unproven ([`Bound::unproven`]), whatever its continuous deadline says.
#[derive(Debug)]
pub struct UtcFloor {
    /// The floor, the highest floor owed its record and the highest floor written down.
    words: Arc<kr_ipc::floor::SharedFloor>,
    /// True while no write of the floor is known to have landed since this daemon started.
    unwritten: AtomicBool,
    /// True while this boot's clock continuity is lost and the owner has not established the clock
    /// again.
    continuity_lost: AtomicBool,
}

impl Default for UtcFloor {
    /// A floor of this process's own at zero.
    fn default() -> Self {
        Self::at(0)
    }
}

/// What one time bound comes to at one reading of this host's clock ([`UtcFloor::bound`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The reading it was decided at: the later of the clock and the floor.
    pub at_ms: u64,
    /// Whether the bound has passed at that reading.
    pub passed: bool,
    /// Whether the floor on disk covers the moment it passed. A bound that has not passed has
    /// nothing to cover.
    pub recorded: bool,
    /// Whether the floor is owed its record, so that no bound which can pass is decided now.
    /// Never set for a bound that never passes. Also set, with [`Self::unproven`], while this
    /// boot's clock continuity is lost, so a caller that asks only this refuses too.
    pub owed: bool,
    /// Whether this boot's clock continuity is lost, so nothing proves where a bound that can pass
    /// stands until the owner establishes the clock. Never set for a bound that never passes.
    pub unproven: bool,
}

impl Bound {
    /// Whether this may be answered as it stands: nothing is owed a record, and a bound that has
    /// passed did so at a moment the floor on disk covers.
    ///
    /// A caller that writes its own durable record of the lapse in the same commit as its answer,
    /// as a redemption that marks its invitation expired does, may answer a lapse without it.
    #[must_use]
    pub const fn answerable(&self) -> bool {
        !self.owed && self.recorded
    }
}

impl UtcFloor {
    /// A floor of this process's own at `floor_ms`, read back from where it was written down.
    ///
    /// For a caller with no runtime directory: a unit test of something that decides from a
    /// floor. The daemon decides from the environment's shared floor ([`Self::on`]).
    #[must_use]
    pub fn at(floor_ms: u64) -> Self {
        Self::on(
            Arc::new(kr_ipc::floor::SharedFloor::in_process(floor_ms)),
            floor_ms,
        )
    }

    /// The floor whose words are `words`, raised to `durable_ms`, the floor this host last wrote
    /// down, with that much of it recorded.
    ///
    /// A floor file created in this boot already holds at least that; one created by this start
    /// holds exactly that. Either way the boot's floor starts where the host's record stands.
    #[must_use]
    pub fn on(words: Arc<kr_ipc::floor::SharedFloor>, durable_ms: u64) -> Self {
        words.raise(durable_ms);
        words.record(durable_ms);
        Self {
            words,
            unwritten: AtomicBool::new(false),
            continuity_lost: AtomicBool::new(false),
        }
    }

    /// The shared words this floor is, for a caller that hands them to a worker or checks their
    /// name.
    #[must_use]
    pub const fn words(&self) -> &Arc<kr_ipc::floor::SharedFloor> {
        &self.words
    }

    /// Raises the floor to `now_ms` when that is later, and returns the reading this host decides
    /// from: the later of the two, the word as the raise left it.
    ///
    /// Only ever forward. A reading below the floor is a clock that went backwards, and section 9
    /// already says what a host does about that; what this guarantees is that it does not become a
    /// second chance for something already expired. It never waits, so a poll may call it.
    pub fn observe(&self, now_ms: u64) -> u64 {
        self.words.raise(now_ms)
    }

    /// The reading this host decides from at `now_ms`, without raising the floor.
    #[must_use]
    pub fn settled(&self, now_ms: u64) -> u64 {
        now_ms.max(self.get())
    }

    /// The floor.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.words.load()
    }

    /// Records that a decision stood on the floor at `at_ms` and is owed its record.
    pub fn owe(&self, at_ms: u64) {
        self.words.owe(at_ms);
    }

    /// Records that the floor has been written down up to `floor_ms`.
    pub fn wrote(&self, floor_ms: u64) {
        self.words.record(floor_ms);
        self.unwritten.store(false, Ordering::SeqCst);
    }

    /// Records that a start could not write the floor down, so it is owed its record until a write
    /// lands.
    pub fn could_not_write(&self) {
        self.unwritten.store(true, Ordering::SeqCst);
    }

    /// The highest floor written down.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.words.recorded()
    }

    /// Whether the floor is owed its record: by a start that could not write it, or by a lapse any
    /// process of this host decided on a floor that is not written down yet.
    #[must_use]
    pub fn is_owed(&self) -> bool {
        self.unwritten.load(Ordering::SeqCst) || self.words.owed() > self.words.recorded()
    }

    /// Records that this boot's clock continuity is lost: a start found this boot's floor gone.
    pub fn lose_continuity(&self) {
        self.continuity_lost.store(true, Ordering::SeqCst);
    }

    /// Records that the owner established the clock again, which ends a lost continuity.
    pub fn establish_continuity(&self) {
        self.continuity_lost.store(false, Ordering::SeqCst);
    }

    /// Whether this boot's clock continuity is lost, so no bound that can pass is decided.
    #[must_use]
    pub fn continuity_lost(&self) -> bool {
        self.continuity_lost.load(Ordering::SeqCst)
    }

    /// Decides one time bound at `now_ms`, the later of it and the floor, raising the floor.
    ///
    /// This is the rule the floor's record imposes, in one place. A bound that never passes stands
    /// on no floor. One that can pass is not decided while the floor is owed its record: the
    /// answer says so, and the caller refuses rather than decides. Nor is it while this boot's
    /// clock continuity is lost: the answer is unproven, and owed as well, so a caller that asks
    /// only whether it is owed refuses too. One that has passed at a moment the floor on disk does
    /// not cover yet is a refusal whose record is still to be written: the caller owes the floor
    /// at [`Bound::at_ms`], and answers the lapse only once that record is written, or answers it
    /// and writes it straight after, as a paired device's decision does.
    pub fn bound(&self, expiry: GrantExpiry, now_ms: u64) -> Bound {
        let at_ms = self.observe(now_ms);
        let GrantExpiry::At { expires_at_ms } = expiry else {
            return Bound {
                at_ms,
                passed: false,
                recorded: true,
                owed: false,
                unproven: false,
            };
        };
        if self.continuity_lost() {
            return Bound {
                at_ms,
                passed: false,
                recorded: true,
                owed: true,
                unproven: true,
            };
        }
        let passed = !expiry.is_valid_at(at_ms);
        Bound {
            at_ms,
            passed,
            recorded: !passed || self.written() >= expires_at_ms.get(),
            owed: self.is_owed(),
            unproven: false,
        }
    }
}

/// This host's policy.
///
/// A copy shares the clock floor with the policy it was copied from, because the floor is a fact
/// about this host's clock rather than a setting of one policy: a candidate change that is never
/// accepted cannot take back a reading this host has already decided from.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    authority_revision: AuthorityRevision,
    /// The highest authority revision this host has ever accepted.
    ///
    /// Separate from [`Self::authority_revision`] because a restored old policy would otherwise
    /// put the revision back. This only ever rises.
    accepted_floor: AuthorityRevision,
    enrolments: BTreeMap<OrganisationId, Enrolment>,
    /// The newest lease this host installed for each member device, kept across a withdrawal.
    lease_records: BTreeMap<LeaseHolder, LeaseRecord>,
    /// True when this host was enrolled as exclusively organisation-managed, so personal local
    /// owner access stops with the organisation's.
    ///
    /// Its own restriction rather than a side effect of enrolling, because it is a host-level
    /// decision: enrolling in a second organisation must not undo it.
    exclusively_managed: bool,
    offline: Option<OfflineValidityPolicy>,
    /// The bounded offline validity as it stands, on both clocks, published whole: its UTC end
    /// from the policy above and its continuous end from the anchor the daemon took for the
    /// synchronisation it is measured from. Shared by every copy of this policy, and published
    /// only once the policy holding a change is written down.
    offline_cell: Arc<BoundCell>,
    /// When the host last woke or started, in UTC milliseconds.
    revalidated_at_ms: u64,
    /// The highest UTC reading this host has decided anything from.
    utc_floor: Arc<UtcFloor>,
}

/// The offline cell a policy starts with, before the daemon has anchored anything: a bound that has
/// synchronised shows nothing holding it until its anchor is published, and one that never has is
/// outside its bound from the moment it is chosen.
fn offline_cell(offline: Option<&OfflineValidityPolicy>) -> Arc<BoundCell> {
    match offline {
        None => BoundCell::new(
            BoundIdentity::Offline {
                synchronised_at_ms: None,
            },
            None,
            None,
            false,
        ),
        Some(offline) => {
            let synchronised_at_ms = offline.last_synchronised_at_ms.as_ref().map(|at| at.get());
            BoundCell::new(
                BoundIdentity::Offline { synchronised_at_ms },
                None,
                offline_utc_end(offline),
                true,
            )
        }
    }
}

/// The first UTC moment outside an offline bound, when there is one: its last synchronisation
/// plus the maximum, plus one, when the clock can represent it. One it cannot is a bound every
/// representable moment is inside, and a bound that never synchronised has no end to state here
/// because it never began.
#[must_use]
pub fn offline_utc_end(offline: &OfflineValidityPolicy) -> Option<u64> {
    offline.last_synchronised_at_ms.as_ref().and_then(|last| {
        last.get()
            .checked_add(offline.maximum_offline_ms.get())?
            .checked_add(1)
    })
}

impl HostPolicy {
    /// A host with no organisation enrolment and no offline bound: the personal default.
    #[must_use]
    pub fn personal(authority_revision: AuthorityRevision) -> Self {
        Self {
            authority_revision,
            accepted_floor: authority_revision,
            enrolments: BTreeMap::new(),
            lease_records: BTreeMap::new(),
            exclusively_managed: false,
            offline: None,
            offline_cell: offline_cell(None),
            revalidated_at_ms: 0,
            utc_floor: Arc::new(UtcFloor::default()),
        }
    }

    /// The reading this host decides expiry from: the later of `now_ms` and its own floor.
    #[must_use]
    pub fn settled_now(&self, now_ms: u64) -> u64 {
        self.utc_floor.settled(now_ms)
    }

    /// Raises the floor to a reading this host has decided from ([`UtcFloor::observe`]).
    pub fn observe_utc(&mut self, now_ms: u64) {
        self.utc_floor.observe(now_ms);
    }

    /// The highest UTC reading this host has decided from.
    #[must_use]
    pub fn utc_floor_ms(&self) -> u64 {
        self.utc_floor.get()
    }

    /// Whether deciding `grant` for a caller on `ingress` reads this host's clock.
    ///
    /// A grant that expires does, and so does one whose use this policy bounds by time: an
    /// organisation's grant, which answers to a lease; any personal grant on a host enrolled as
    /// exclusively organisation-managed, which answers to a lease too; and a personal grant used
    /// remotely under a bounded offline validity. A personal grant that never expires, used from
    /// this machine or where the owner chose no offline bound, reads no clock, which is what
    /// section 9 keeps usable while this host cannot vouch for its clock.
    #[must_use]
    pub fn stands_on_the_clock(&self, grant: &Grant, ingress: ActorIngress) -> bool {
        grant.expiry != GrantExpiry::Never
            || grant.organisation.as_ref().is_some()
            || self.exclusively_managed
            || (ingress != ActorIngress::LocalIpc && self.offline.is_some())
    }

    /// The floor itself, for a reader that holds it beside the policy rather than behind its lock.
    #[must_use]
    pub const fn utc_floor(&self) -> &Arc<UtcFloor> {
        &self.utc_floor
    }

    /// The authority revision in force.
    #[must_use]
    pub const fn authority_revision(&self) -> AuthorityRevision {
        self.authority_revision
    }

    /// The highest authority revision this host has ever accepted.
    #[must_use]
    pub const fn accepted_floor(&self) -> AuthorityRevision {
        self.accepted_floor
    }

    /// Advances the authority revision.
    ///
    /// The floor rises with it, so nothing can put the revision back afterwards.
    pub const fn advance_authority_revision(&mut self, revision: AuthorityRevision) {
        if revision.get() > self.authority_revision.get() {
            self.authority_revision = revision;
        }
        if revision.get() > self.accepted_floor.get() {
            self.accepted_floor = revision;
        }
    }

    /// Accepts an authority revision this host has been told about.
    ///
    /// Section 24: a restored old policy cannot revive authority. A revision at or below the floor
    /// is refused, whatever document carried it and however well signed that document is, because
    /// a signature proves who wrote a policy and not that the policy is the current one.
    ///
    /// Returns whether it was accepted.
    pub const fn accept_policy(&mut self, revision: AuthorityRevision) -> bool {
        if revision.get() <= self.accepted_floor.get() {
            return false;
        }
        self.authority_revision = revision;
        self.accepted_floor = revision;
        true
    }

    /// Verifies a whole published chain for enrolling this host in its organisation.
    ///
    /// Everything [`organisation::verify_enrolment`] checks, at this host's reading of UTC. The
    /// clock must be trusted, which is what a reading's presence says, and the floor that reading
    /// raises must not be owed its record, since a head's currency is a bound that can pass.
    ///
    /// # Errors
    ///
    /// Returns the rule the chain or the clock breaks, or [`ChainRefused::AlreadyEnrolled`] when
    /// this host is enrolled in that organisation already.
    pub fn verify_enrolment(
        &self,
        authority: &PolicyAuthority,
        reading: Option<&ObservedUtc>,
    ) -> std::result::Result<VerifiedEnrolment, ChainRefused> {
        if self.enrolments.contains_key(&authority.organisation_id) {
            return Err(ChainRefused::AlreadyEnrolled);
        }
        let settled_ms = self.head_reading(authority, reading)?;
        organisation::verify_enrolment(authority, settled_ms)
    }

    /// Enrols this host in a verified organisation, at the authority revision in force.
    ///
    /// Enrolling says nothing about whether this host is exclusively organisation-managed. That is
    /// [`Self::set_exclusively_managed`], because it is a decision about the *host* and a second
    /// enrolment must not be able to undo it.
    ///
    /// # Errors
    ///
    /// Returns [`ChainRefused::AlreadyEnrolled`] when this host is enrolled in that organisation
    /// already: an enrolment is replaced only by withdrawing it first.
    pub fn enrol(&mut self, verified: VerifiedEnrolment) -> std::result::Result<(), ChainRefused> {
        let organisation_id = verified.organisation_id();
        if self.enrolments.contains_key(&organisation_id) {
            return Err(ChainRefused::AlreadyEnrolled);
        }
        self.enrolments.insert(
            organisation_id,
            Enrolment::new(verified, self.authority_revision),
        );
        Ok(())
    }

    /// Withdraws this host from an organisation.
    ///
    /// The enrolment goes, and every lease installed under it ends with it. The lease records stay,
    /// so a lease installed before is never installed again after a new enrolment. Returns whether
    /// this host was enrolled.
    pub fn withdraw(&mut self, organisation_id: OrganisationId) -> bool {
        self.enrolments.remove(&organisation_id).is_some()
    }

    /// The enrolment this host holds for an organisation.
    #[must_use]
    pub fn enrolment(&self, organisation_id: OrganisationId) -> Option<&Enrolment> {
        self.enrolments.get(&organisation_id)
    }

    /// Whether `device_id` is bound to a member account in any organisation this host is enrolled
    /// in.
    #[must_use]
    pub fn is_bound(&self, device_id: DeviceId) -> bool {
        self.enrolments
            .values()
            .any(|enrolment| enrolment.binding(device_id).is_some())
    }

    /// Removes `device_id`'s bindings from every enrolment: the device was revoked, so no lease
    /// answers for it again. Returns whether it was bound anywhere.
    pub fn unbind_device(&mut self, device_id: DeviceId) -> bool {
        // Every enrolment, not only the first that held one: each keeps its own binding.
        let mut unbound = false;
        for enrolment in self.enrolments.values_mut() {
            unbound |= enrolment.unbind(device_id);
        }
        unbound
    }

    /// Follows a published chain forward for an organisation this host is enrolled in.
    ///
    /// A head this host already accepted does no signature work and reads no clock, and an older
    /// one is stale; either leaves everything as it was. A newer one is accepted only through links
    /// the anchor's key signed ([`Enrolment`]), and then every installed lease is judged again.
    ///
    /// # Errors
    ///
    /// Returns the rule a newer head's chain, or the clock, breaks. Nothing changes then.
    pub fn accept_chain(
        &mut self,
        authority: &PolicyAuthority,
        reading: Option<&ObservedUtc>,
    ) -> std::result::Result<ChainOutcome, ChainRefused> {
        let accepted = self
            .enrolments
            .get(&authority.organisation_id)
            .ok_or(ChainRefused::NotEnrolled)?
            .accepted_head();
        if authority.head.payload.key_revision.get() <= accepted.get() {
            return Ok(if authority.head.payload.key_revision == accepted {
                ChainOutcome::Unchanged
            } else {
                ChainOutcome::Stale { held: accepted }
            });
        }
        let settled_ms = self.head_reading(authority, reading)?;
        self.enrolments
            .get_mut(&authority.organisation_id)
            .ok_or(ChainRefused::NotEnrolled)?
            .accept(authority, settled_ms)
    }

    /// This host's reading of UTC for a head: trusted, through the floor, with nothing owed.
    fn head_reading(
        &self,
        authority: &PolicyAuthority,
        reading: Option<&ObservedUtc>,
    ) -> std::result::Result<u64, ChainRefused> {
        let reading = reading.ok_or(ChainRefused::ClockUntrusted)?;
        let bound = self.utc_floor.bound(
            GrantExpiry::At {
                expires_at_ms: authority.head.payload.expires_at_ms,
            },
            reading.now.get(),
        );
        if bound.owed {
            return Err(ChainRefused::FloorUnrecorded);
        }
        Ok(bound.at_ms)
    }

    /// Decides a presented membership lease and installs it when it is new.
    ///
    /// Everything [`organisation`] states about a lease is checked here, on the raw lease and the
    /// key the presenting connection proved, so there is no path that installs a lease it did not
    /// verify, and nothing else inserts into the installed set. The time is this host's reading of
    /// UTC through its floor, and only while the clock is trusted.
    ///
    /// The caller runs this on a copy of the policy and writes the copy down before it publishes
    /// it, so the lease's record is on disk before the lease is installed.
    ///
    /// # Errors
    ///
    /// Returns the first rule the lease breaks. Nothing is installed or recorded then.
    pub fn install_lease(
        &mut self,
        presentation: LeasePresentation<'_>,
    ) -> std::result::Result<LeaseInstalled, LeaseRefused> {
        let payload = &presentation.lease.payload;
        let time = match presentation.reading {
            None => LeaseTime::Untrusted,
            Some(reading) => {
                let bound = self.utc_floor.bound(
                    GrantExpiry::At {
                        expires_at_ms: payload.expires_at_ms,
                    },
                    reading.now.get(),
                );
                if bound.owed {
                    LeaseTime::Unrecorded
                } else {
                    LeaseTime::At {
                        settled_ms: bound.at_ms,
                        expired: bound.passed,
                    }
                }
            }
        };
        let enrolment = self
            .enrolments
            .get_mut(&payload.organisation_id)
            .ok_or(LeaseRefused::NotEnrolled)?;
        organisation::install(enrolment, &mut self.lease_records, presentation, time)
    }

    /// The lease recorded as the newest this host installed for one member's device.
    #[must_use]
    pub fn lease_record(
        &self,
        organisation_id: OrganisationId,
        account_id: &AccountId,
        device_key: &AuthorisationKey,
    ) -> Option<&LeaseRecord> {
        self.lease_records
            .get(&(organisation_id, account_id.clone(), *device_key))
    }

    /// The lease installed for one member's device, when it is in force at both readings: before
    /// its continuous deadline at `now`, and inside its signed window at `utc_ms`, this host's
    /// reading of UTC through its floor.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipRefusal::NoLease`] when this host holds no lease for that device in that
    /// organisation, and [`MembershipRefusal::LeaseExpired`] when the one it holds has ended on
    /// either clock.
    pub fn lease_in_force(
        &self,
        organisation_id: OrganisationId,
        account_id: &AccountId,
        device_key: &AuthorisationKey,
        now: ContinuousInstant,
        utc_ms: u64,
    ) -> std::result::Result<&MembershipLease, MembershipRefusal> {
        let installed = self
            .enrolments
            .get(&organisation_id)
            .and_then(|enrolment| enrolment.installed(account_id, device_key))
            .ok_or(MembershipRefusal::NoLease)?;
        if installed.in_force(now, utc_ms) {
            Ok(installed.lease())
        } else {
            Err(MembershipRefusal::LeaseExpired)
        }
    }

    /// Records that this host is, or is no longer, exclusively organisation-managed.
    pub const fn set_exclusively_managed(&mut self, exclusively_managed: bool) {
        self.exclusively_managed = exclusively_managed;
    }

    /// Returns true when this host is exclusively organisation-managed.
    #[must_use]
    pub const fn is_exclusively_managed(&self) -> bool {
        self.exclusively_managed
    }

    /// The longest a lease this host will install may last.
    #[must_use]
    pub const fn maximum_lease_lifetime_ms() -> u64 {
        MEMBERSHIP_LEASE_MAX_LIFETIME_MS
    }

    /// This policy, as it is written down.
    ///
    /// The leases are deliberately not in it. A lease lasts at most fifteen minutes and is
    /// refreshed every five; restoring one across a restart would be restoring a deadline the
    /// organisation may have withdrawn in the meantime. Their records are, and a record is kept
    /// until the floor written beside it shows every lease it could stand for has expired.
    #[must_use]
    pub fn snapshot(&self) -> StoredPolicy {
        let floor_ms = self.utc_floor.get();
        StoredPolicy {
            accepted_floor: self.accepted_floor,
            utc_floor_ms: kr_protocol::scalars::TimestampMs::new(floor_ms),
            exclusively_managed: self.exclusively_managed,
            offline: kr_protocol::scalars::Nullable(self.offline),
            enrolments: self
                .enrolments
                .iter()
                .map(|(organisation_id, enrolment)| enrolment.stored(*organisation_id))
                .collect(),
            lease_records: organisation::stored_records(&self.lease_records, floor_ms),
        }
    }

    /// Rebuilds a policy from what was written down, at the revision now in force.
    ///
    /// The floor is the higher of what was stored and what the registry holds, so neither half can
    /// take the other back: a restored policy file cannot lower the revision the daemon has
    /// reached, and a registry read cannot lower the floor the policy recorded.
    ///
    /// The clock floor is the host's, not the policy's: `utc_floor` is the one the daemon opened
    /// for this boot, already raised to `stored`'s record of it ([`UtcFloor::on`]).
    #[must_use]
    pub fn restore(
        stored: &StoredPolicy,
        authority_revision: AuthorityRevision,
        utc_floor: Arc<UtcFloor>,
    ) -> Self {
        let floor =
            AuthorityRevision::new(stored.accepted_floor.get().max(authority_revision.get()));
        Self {
            authority_revision: floor,
            accepted_floor: floor,
            enrolments: stored
                .enrolments
                .iter()
                .map(|enrolment| (enrolment.organisation_id, Enrolment::restore(enrolment)))
                .collect(),
            lease_records: organisation::restored_records(&stored.lease_records),
            exclusively_managed: stored.exclusively_managed,
            offline: stored.offline.0,
            offline_cell: offline_cell(stored.offline.0.as_ref()),
            revalidated_at_ms: 0,
            utc_floor,
        }
    }

    /// Chooses a bounded offline-validity policy for personal remote access.
    pub const fn set_offline_validity(&mut self, offline: Option<OfflineValidityPolicy>) {
        self.offline = offline;
    }

    /// The bounded offline-validity policy, when the owner chose one.
    #[must_use]
    pub const fn offline_validity(&self) -> Option<&OfflineValidityPolicy> {
        self.offline.as_ref()
    }

    /// The bounded offline validity's cell ([`BoundCell`]).
    #[must_use]
    pub const fn offline_cell(&self) -> &Arc<BoundCell> {
        &self.offline_cell
    }

    /// Publishes this policy's leases in their cells, as the policy stands once it is written down
    /// in place of `previous`: each installed lease's own snapshot, and an end for each lease
    /// `previous` held that this policy does not, dropped at a rotation or withdrawn with its
    /// enrolment. Called under the host policy's lock, after the write and before the policy is
    /// put in force, so a reader that loads a cell sees what the policy it could read says.
    pub(crate) fn publish_leases(&self, previous: &Self) {
        for installed in self.installed_leases() {
            installed.publish();
        }
        for earlier in previous.installed_leases() {
            if !self
                .installed_leases()
                .any(|kept| Arc::ptr_eq(kept.cell(), earlier.cell()))
            {
                earlier.cell().end();
            }
        }
    }

    /// Publishes every bound this policy states in its cell, as a daemon does once the policy is
    /// written down in place of `previous`, for a caller that decides under a policy of its own
    /// outside a daemon: its leases as [`Self::publish_leases`] does, and its offline bound with no
    /// continuous end, which only a daemon's anchor measures, so its UTC end alone decides it.
    #[cfg(any(test, feature = "testing"))]
    pub fn publish_unanchored(&self, previous: &Self) {
        self.publish_leases(previous);
        match self.offline.as_ref() {
            None => self.offline_cell.publish(
                BoundIdentity::Offline {
                    synchronised_at_ms: None,
                },
                None,
                None,
                false,
            ),
            Some(offline) => {
                let synchronised_at_ms =
                    offline.last_synchronised_at_ms.as_ref().map(|at| at.get());
                self.offline_cell.publish(
                    BoundIdentity::Offline { synchronised_at_ms },
                    None,
                    offline_utc_end(offline),
                    synchronised_at_ms.is_none(),
                );
            }
        }
    }

    fn installed_leases(&self) -> impl Iterator<Item = &organisation::InstalledLease> {
        self.enrolments
            .values()
            .flat_map(Enrolment::installed_leases)
    }

    /// Records a successful authority-feed synchronisation.
    pub const fn note_feed_synchronised(&mut self, at_ms: u64) {
        if let Some(offline) = self.offline.as_mut() {
            offline.last_synchronised_at_ms =
                kr_protocol::scalars::Nullable::some(kr_protocol::scalars::TimestampMs::new(at_ms));
        }
    }

    /// Revalidates this host's policy after a wake or a reboot.
    ///
    /// Nothing is cached across the gap. Expiry is decided from `now_ms` on the next request, and
    /// this records the moment so a caller can see that the revalidation happened rather than
    /// assuming it. The authority floor is untouched, which is the point: waking up is not a
    /// reason to accept an older policy.
    pub const fn revalidate(&mut self, now_ms: u64) {
        self.revalidated_at_ms = now_ms;
    }

    /// When this host last revalidated after a wake or a reboot.
    #[must_use]
    pub const fn revalidated_at_ms(&self) -> u64 {
        self.revalidated_at_ms
    }

    /// Intersects one grant with this policy for one request.
    ///
    /// # Errors
    ///
    /// Returns the rule that refused: an organisation lease this host cannot use, a grant whose
    /// recipient this host cannot attribute to a member, or a lapsed offline bound.
    pub fn intersect(
        &self,
        grant: &Grant,
        request: &AccessRequest,
        now_ms: u64,
    ) -> std::result::Result<PolicyIntersection, Refusal> {
        match grant.organisation.as_ref() {
            Some(requirement) => {
                let Some(enrolment) = self.enrolments.get(&requirement.organisation_id) else {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::NoLease,
                    });
                };
                // The grant names the enrolment revision it answers to. A grant issued under an
                // enrolment this host has since withdrawn is not this host's to honour.
                if requirement.policy_revision != enrolment.enrolment_revision() {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::WrongAuthority,
                    });
                }
                // Whose lease answers for this grant: the lease of the account and key its
                // recipient device is bound to, and no other. Any other member's lease would
                // sustain a disabled member's access, which is the whole of what section 17's
                // per-member disablement is for. The binding holds everything the lookup needs, so
                // a decision with no presenting connection resolves it alike, and no caller can
                // supply an account or a key of its own. Both clocks decide, and nothing else
                // does: an open transport is not a lease.
                let (installed, held) = enrolment
                    .lease_for_device(grant.recipient_device_id, request.continuous_now, now_ms)
                    .map_err(|missing| match missing {
                        MemberLease::Unbound => Refusal::MembershipUnattributed,
                        MemberLease::NoLease => Refusal::MembershipUnusable {
                            refusal: MembershipRefusal::NoLease,
                        },
                        MemberLease::Expired => Refusal::MembershipUnusable {
                            refusal: MembershipRefusal::LeaseExpired,
                        },
                    })?;
                let lease = installed.lease();
                let rights = grant
                    .actions
                    .iter()
                    .copied()
                    .filter(|right| lease.payload.maximum_grants.contains(right))
                    .collect();
                Ok(PolicyIntersection {
                    rights,
                    organisation_id: Some(requirement.organisation_id),
                    lease: Some(held),
                    offline: None,
                })
            }
            None => {
                // Personal authority. It continues through an organisation outage, unless this
                // host is exclusively organisation-managed, in which case there is no personal
                // path left to continue on.
                let lease = if self.exclusively_managed {
                    Some(self.managed_lease(
                        grant.recipient_device_id,
                        request.continuous_now,
                        now_ms,
                    )?)
                } else {
                    None
                };
                // The bounded offline policy is for *remote* personal access. Section 10 puts it
                // there in so many words, and a person at the keyboard of their own machine is not
                // the case it is about: refusing them because a cloud feed is unreachable would be
                // the cloud dependency the default is written to avoid. It is decided from one load
                // of its cell, in UTC here; the caller holds the decision to the same snapshot's
                // continuous end.
                let offline = match self.offline.as_ref() {
                    Some(offline) if request.ingress != ActorIngress::LocalIpc => {
                        let held = HeldBound::load(&self.offline_cell);
                        let snapshot = held.snapshot();
                        if snapshot.ended
                            || snapshot
                                .utc_deadline_ms
                                .is_some_and(|deadline| now_ms >= deadline)
                        {
                            return Err(Refusal::OfflineValidityLapsed {
                                last_synchronised_at_ms: offline
                                    .last_synchronised_at_ms
                                    .as_ref()
                                    .map(|at| at.get()),
                            });
                        }
                        Some(held)
                    }
                    _ => None,
                };
                Ok(PolicyIntersection {
                    rights: grant.actions.clone(),
                    organisation_id: None,
                    lease,
                    offline,
                })
            }
        }
    }

    /// The lease that answers for a personal grant on a host enrolled as exclusively
    /// organisation-managed: the one of the account and key the grant's recipient device is bound
    /// to, in any organisation this host is enrolled in.
    ///
    /// The question is about **this** device's member, not about every member. One member's lease
    /// lapsing must not stop another member working, and a host with no enrolment at all that is
    /// nevertheless marked exclusively managed has no organisation to answer for it, which is its
    /// own refusal rather than a pass. A device bound to nobody is unattributed, as it is for an
    /// organisation's own grant.
    fn managed_lease(
        &self,
        device_id: DeviceId,
        now: ContinuousInstant,
        now_ms: u64,
    ) -> std::result::Result<HeldBound, Refusal> {
        let mut seen = None;
        for enrolment in self.enrolments.values() {
            match enrolment.lease_for_device(device_id, now, now_ms) {
                // One usable lease is enough: this device's member is in good standing somewhere
                // this host answers to.
                Ok((_, held)) => return Ok(held),
                Err(MemberLease::Unbound) => {}
                Err(MemberLease::NoLease) => {
                    seen.get_or_insert(MembershipRefusal::NoLease);
                }
                Err(MemberLease::Expired) => seen = Some(MembershipRefusal::LeaseExpired),
            }
        }
        Err(match seen {
            Some(refusal) => Refusal::MembershipUnusable { refusal },
            None if self.enrolments.is_empty() => Refusal::MembershipUnusable {
                refusal: MembershipRefusal::NoLease,
            },
            None => Refusal::MembershipUnattributed,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kr_ipc::floor::SharedFloor;
    use kr_protocol::grant::GrantExpiry;
    use kr_protocol::ids::{BootEpoch, EnvironmentId};
    use kr_protocol::scalars::TimestampMs;

    use super::UtcFloor;

    /// A floor file, and a second mapping of it as a worker of the host holds one.
    fn two_mappings(name: &str) -> (std::path::PathBuf, Arc<SharedFloor>, Arc<SharedFloor>) {
        let suffix = kr_ipc::new_uuid().to_string();
        let root = std::env::temp_dir().join(format!("kr-policy-{name}-{}", &suffix[..8]));
        kr_ipc::paths::create_private_tree(&root, &root).expect("a private directory");
        let path = root.join("utc-floor");
        let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
        let boot_epoch = BootEpoch::new(5);
        let first =
            Arc::new(SharedFloor::create(&path, environment_id, boot_epoch, 0).expect("created"));
        let second =
            Arc::new(SharedFloor::open(&path, environment_id, boot_epoch).expect("mapped"));
        (root, first, second)
    }

    /// The daemon's floor is the host's shared word: a reading another process publishes is the
    /// reading every decision here stands on, a lapse another process owes is owed here, and the
    /// record rule is the one it was. There is one floor, not a copy beside the word.
    #[test]
    fn the_shared_floor_keeps_the_record_rule_of_the_daemons_floor() {
        let (root, words, second) = two_mappings("record");
        let floor = UtcFloor::on(Arc::clone(&words), 1_000);
        assert_eq!(
            second.load(),
            1_000,
            "the floor starts at the host's record"
        );
        assert_eq!(second.recorded(), 1_000);
        let expiry = GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        };

        // The control: nothing raised past the expiry, so the bound is live and nothing is owed.
        let bound = floor.bound(expiry, 2_000);
        assert!(!bound.passed && bound.answerable(), "{bound:?}");
        // A raise that decides no lapse owes nothing.
        second.raise(4_000);
        assert!(!floor.is_owed());
        assert_eq!(floor.get(), second.load());

        // Another process's reading passes the expiry. This process's own clock is behind it, and
        // the bound has passed all the same, at a moment the record does not cover yet.
        second.raise(6_000);
        let bound = floor.bound(expiry, 2_000);
        assert!(
            bound.passed && !bound.recorded && !bound.answerable(),
            "{bound:?}"
        );
        assert_eq!(bound.at_ms, 6_000);
        assert_eq!(floor.get(), second.load());

        // A lapse that process decided on it is owed its record here too.
        second.owe(6_000);
        assert!(floor.is_owed());
        let bound = floor.bound(expiry, 2_000);
        assert!(bound.owed, "{bound:?}");

        // Written down: the record covers the lapse, in the word every process reads.
        floor.wrote(6_000);
        assert!(!floor.is_owed());
        assert_eq!(second.recorded(), 6_000);
        let bound = floor.bound(expiry, 2_000);
        assert!(
            bound.passed && bound.recorded && bound.answerable(),
            "{bound:?}"
        );

        // A start whose write failed owes its record until a write lands.
        floor.could_not_write();
        assert!(floor.is_owed());
        floor.wrote(floor.get());
        assert!(!floor.is_owed());
        // Every mapping ends before the file goes: on Windows a mapped file cannot be removed.
        drop((floor, words, second));
        std::fs::remove_dir_all(&root).expect("removed");
    }

    /// While this boot's clock continuity is lost, every bound that can pass is unproven, and owed
    /// as well, so a caller that asks only whether it is owed refuses too; a bound that never
    /// passes is decided as before.
    #[test]
    fn a_lost_clock_continuity_leaves_every_bound_that_can_pass_unproven() {
        let floor = UtcFloor::at(1_000);
        let expiry = GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        };
        floor.lose_continuity();
        let bound = floor.bound(expiry, 2_000);
        assert!(bound.unproven && bound.owed && !bound.passed && !bound.answerable());
        let never = floor.bound(GrantExpiry::Never, 2_000);
        assert!(!never.unproven && never.answerable());
        // The control: once the owner establishes the clock, the bound is decided again.
        floor.establish_continuity();
        let bound = floor.bound(expiry, 2_000);
        assert!(!bound.unproven && bound.answerable() && !bound.passed);
    }
}

#[cfg(test)]
mod one_snapshot_of_each_bound {
    //! Every decision about a time bound is taken from one snapshot of it, published whole.

    use std::sync::Arc;
    use std::time::Duration;

    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement,
        SessionSelector,
    };
    use kr_protocol::ids::{
        AccountId, AuthorityRevision, ControllerGeneration, DeviceId, EnvironmentId, GrantId,
    };
    use kr_protocol::method::Method;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
    use kr_protocol::sharing::MembershipRefusal;
    use kr_transport::clock::{ContinuousClock as _, ManualClock};

    use super::{BoundCell, BoundIdentity, HostPolicy, publishing};
    use crate::grants::organisation::LeasePresentation;
    use crate::grants::organisation::testing::TestOrganisation;
    use crate::grants::{AccessRequest, Refusal};
    use crate::service::net::devices::ObservedUtc;

    const NOW_MS: u64 = 1_800_000_000_000;
    const MINUTE: Duration = Duration::from_secs(60);

    /// A host enrolled in one organisation, holding a lease it installed and published for a
    /// member's device, and that device's organisation grant.
    struct Leased {
        policy: HostPolicy,
        organisation: TestOrganisation,
        key: AuthorisationKeyPair,
        account: AccountId,
        grant: Grant,
        clock: ManualClock,
    }

    impl Leased {
        fn new() -> Self {
            let clock = ManualClock::new();
            let organisation = TestOrganisation::new(0x31, NOW_MS - 60 * 60 * 1000);
            let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
            let verified = policy
                .verify_enrolment(&organisation.authority(NOW_MS), Some(&reading(NOW_MS)))
                .expect("the chain verifies");
            policy.enrol(verified).expect("the host enrols");
            let device_id = DeviceId::new(kr_ipc::new_uuid());
            let grant = Grant {
                grant_id: GrantId::new(kr_ipc::new_uuid()),
                parent_grant_id: Nullable::null(),
                issuer_device_id: device_id,
                recipient_device_id: device_id,
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: [ActionRight::SessionView].into_iter().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::some(OrganisationRequirement {
                    organisation_id: organisation.organisation_id,
                    policy_revision: AuthorityRevision::new(1),
                }),
            };
            let mut leased = Self {
                policy,
                organisation,
                key: AuthorisationKeyPair::generate().expect("a device key"),
                account: AccountId::new("ada").expect("an account"),
                grant,
                clock,
            };
            leased.present(NOW_MS, NOW_MS);
            leased
        }

        /// Presents a lease issued at `issued_ms` at the UTC reading `at_ms`, and publishes the
        /// policy that holds it.
        fn present(&mut self, issued_ms: u64, at_ms: u64) {
            let lease = self.organisation.lease(
                &self.account,
                *self.key.public(),
                issued_ms,
                &[ActionRight::SessionView],
            );
            let before = self.policy.clone();
            self.policy
                .install_lease(LeasePresentation {
                    lease: &lease,
                    device_id: self.grant.recipient_device_id,
                    proven_key: self.key.public(),
                    reading: Some(reading(at_ms)),
                    now: self.clock.now(),
                    generation: ControllerGeneration::new(1),
                })
                .expect("the lease installs");
            self.policy.publish_leases(&before);
        }

        /// The member device's cell.
        fn cell(&self) -> Arc<BoundCell> {
            Arc::clone(
                self.policy
                    .enrolment(self.organisation.organisation_id)
                    .and_then(|enrolment| enrolment.installed(&self.account, self.key.public()))
                    .expect("a lease is installed")
                    .cell(),
            )
        }

        /// The member device's request at the UTC reading `at_ms`.
        fn decide(&self, at_ms: u64) -> Result<super::PolicyIntersection, Refusal> {
            let request = AccessRequest {
                method: Method::SessionList,
                ingress: ActorIngress::PairedDevice,
                environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                session_id: None,
                claims_geometry: false,
                own_subject: None,
                now_ms: at_ms,
                continuous_now: self.clock.now(),
            };
            self.policy.intersect(&self.grant, &request, at_ms)
        }
    }

    fn reading(at_ms: u64) -> ObservedUtc {
        ObservedUtc {
            now: TimestampMs::new(at_ms),
            behind_ms: 0,
        }
    }

    fn lease_expired() -> Result<super::PolicyIntersection, Refusal> {
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired,
        })
    }

    /// A lease is decided from one snapshot of its cell. A publication made after the reader
    /// loaded the cell, moving the continuous deadline earlier and the UTC deadline later, is not
    /// what the decision stands on: it carries the snapshot it loaded, whole, and the next reader
    /// takes the new one, whole.
    #[test]
    fn a_lease_is_decided_from_one_snapshot_of_its_cell() {
        let leased = Leased::new();
        let cell = leased.cell();
        let loaded = cell.load();
        let (continuous, utc) = (
            loaded.continuous_deadline.expect("a continuous end"),
            loaded.utc_deadline_ms.expect("a UTC end"),
        );
        let earlier = leased
            .clock
            .now()
            .checked_add(MINUTE)
            .expect("a minute out");
        assert!(earlier < continuous);
        let publishing_to = Arc::clone(&cell);
        let identity = loaded.identity;
        publishing::stop_after_a_load(move || {
            publishing_to.publish(identity, Some(earlier), Some(utc + 60_000), false);
        });

        let decided = leased.decide(NOW_MS).expect("the lease answers");
        let held = decided.lease.expect("a lease answered for it");
        assert_eq!(
            (held.continuous_deadline(), held.utc_deadline_ms()),
            (Some(continuous), Some(utc)),
            "the decision carries the snapshot it loaded, whole"
        );
        let published = cell.load();
        assert_ne!(published.version, loaded.version, "the publication landed");
        assert_eq!(
            (published.continuous_deadline, published.utc_deadline_ms),
            (Some(earlier), Some(utc + 60_000))
        );

        // The next reader takes the new snapshot whole: past its continuous end, with UTC well
        // inside both, the lease is refused.
        leased.clock.advance(MINUTE * 2);
        assert_eq!(leased.decide(NOW_MS + 120_000), lease_expired());

        // The control: with no publication, a reader at the same moment decides as the one
        // snapshot says.
        let unmoved = Leased::new();
        unmoved.clock.advance(MINUTE * 2);
        let decided = unmoved
            .decide(NOW_MS + 120_000)
            .expect("inside the one snapshot");
        assert_eq!(
            decided.lease.map(|held| *held.snapshot()),
            Some(*unmoved.cell().load())
        );
    }

    /// An end a reader finds while a renewal is being published is the snapshot it loaded, and it
    /// leaves the renewal live for the reader after it: finding an end writes nothing into the
    /// cell.
    #[test]
    fn an_end_found_during_a_renewal_is_the_old_snapshots_and_the_renewal_stays_live() {
        let leased = Leased::new();
        let cell = leased.cell();
        let loaded = cell.load();
        // Past the installed lease's continuous end.
        leased.clock.advance(MINUTE * 15);
        let renewed = leased
            .clock
            .now()
            .checked_add(MINUTE * 10)
            .expect("ten minutes out");
        let publishing_to = Arc::clone(&cell);
        let identity = loaded.identity;
        let utc = loaded.utc_deadline_ms;
        publishing::stop_after_a_load(move || {
            publishing_to.publish(identity, Some(renewed), utc, false);
        });

        assert_eq!(
            leased.decide(NOW_MS),
            lease_expired(),
            "the end is the loaded snapshot's"
        );
        let after = cell.load();
        assert_eq!(after.continuous_deadline, Some(renewed));
        assert!(!after.ended, "and nothing was written into the cell");
        let decided = leased
            .decide(NOW_MS)
            .expect("the renewal answers the next reader");
        assert_eq!(
            decided.lease.map(|held| held.continuous_deadline()),
            Some(Some(renewed))
        );
    }

    /// A renewal that does not narrow keeps the installed continuous deadline when its own
    /// conversion is earlier, as when it is presented after UTC ran ahead of the continuous clock,
    /// and publishes it through the device's one cell.
    #[test]
    fn a_renewal_that_does_not_narrow_keeps_the_installed_continuous_deadline() {
        let mut leased = Leased::new();
        let cell = leased.cell();
        let installed = cell.load();
        // UTC reads ten minutes on while the continuous clock moved one second: the renewal's own
        // conversion is under six minutes, far earlier than the installed deadline.
        leased.clock.advance(Duration::from_secs(1));
        leased.present(NOW_MS + 60_000, NOW_MS + 10 * 60_000);

        assert!(
            Arc::ptr_eq(&leased.cell(), &cell),
            "the renewal publishes through the device's cell"
        );
        let published = cell.load();
        assert_ne!(published.version, installed.version);
        assert_ne!(published.identity, installed.identity, "another lease");
        assert_eq!(
            published.continuous_deadline, installed.continuous_deadline,
            "the installed continuous deadline is kept"
        );
        assert_eq!(
            published.utc_deadline_ms,
            Some(NOW_MS + 60_000 + kr_protocol::account::MEMBERSHIP_LEASE_MAX_LIFETIME_MS),
            "and the renewal's own signed expiry is its UTC end"
        );
        assert!(matches!(published.identity, BoundIdentity::Lease(_)));
    }
}
