//! The one lock-free value of a request's standing, and its one question.
//!
//! A check that is asked again before a landing takes locks of its own, so a wait can always stand
//! after the last check. A [`Footing`] holds, for one request, copies that a reader reads with no
//! lock and that each writer sets under the lock that orders it:
//!
//! * the registration's **latch**, set by the removal of the registration, under the connection
//!   table's write lock ([`super::admission::AdmittedConnection`]);
//! * the **owed-fence flag**, set at each of the four places that change the debts a fence is
//!   owed for, before each lets go of the debts' mutex ([`Copies::note_debts`]);
//! * the **revision in memory**, raised by a barrier after the registrations and the issuer have
//!   taken it ([`Copies::raise_revision`]);
//! * the request's absolute **deadline**, and the **exact target** it was admitted for: the
//!   connection, the revision and the latch of that registration;
//! * for a method held to the local owner's lease, the lease's **held bound**
//!   ([`crate::grants::policy::HeldBound`]), whose cell a policy commit ends. A footing that holds
//!   a bound is a type of its own ([`LeasedFooting`]), whose question alone says that the bound's
//!   cell has moved: there is no plain reading of it that gives yes or a refusal.
//!
//! The question ([`Footing::ask`]) reads those copies and the clocks and nothing else: it takes no
//! lock, awaits nothing and writes nothing, so it can be asked immediately before the landing
//! call, in a poll, and from a blocking thread. What it needs from the lease's bound is taken
//! before its first read, so that after the first read of a member or of a clock nothing in it
//! allocates, frees, takes a lock or waits. Every variant of the question ([`Ask`]) is the one
//! code path with some members masked out, and a refused member answers with the words of the
//! door's own check for that condition ([`Lapse`]); the question has no text of its own.
//!
//! The members are read in one order everywhere: the flag, then the revision, then the latch. A
//! barrier writes them in the opposite order (registrations, issuer, revision, flag), so a reader
//! that finds the flag clear after a barrier finds the revision raised and the latches set.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kr_protocol::ids::{AuthorityRevision, ConnectionId};
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use super::WallClock;
use crate::authority::AdmissionLapse;
use crate::error::ControllerError;
use crate::grants::policy::{HeldBound, Stands, UtcFloor};

/// The copies of this daemon's authority that every [`Footing`] reads: whether a fence is owed,
/// the authority revision in force, and the clocks.
pub(crate) struct Copies {
    /// Whether any debt of a fence is published ([`super::barrier::Debts::published`]).
    fence_owed: AtomicBool,
    /// The authority revision in force, in memory. It starts from the persisted revision and is
    /// only ever raised.
    revision: AtomicU64,
    /// The continuous clock every deadline of this daemon is measured on.
    clock: Arc<dyn ContinuousClock>,
    /// The wall clock this daemon reads UTC on.
    wall: WallClock,
    /// The floor under this daemon's readings of UTC.
    floor: Arc<UtcFloor>,
}

impl std::fmt::Debug for Copies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Copies")
            .field("fence_owed", &self.fence_owed.load(Ordering::SeqCst))
            .field("revision", &self.revision.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Copies {
    /// The copies at a daemon's start: no fence published yet, and the revision the registry holds.
    pub(super) fn new(
        revision: AuthorityRevision,
        clock: Arc<dyn ContinuousClock>,
        wall: WallClock,
        floor: Arc<UtcFloor>,
    ) -> Self {
        Self {
            fence_owed: AtomicBool::new(false),
            revision: AtomicU64::new(revision.get()),
            clock,
            wall,
            floor,
        }
    }

    /// Whether a fence is owed. Takes no lock.
    pub(crate) fn fence_is_owed(&self) -> bool {
        self.fence_owed.load(Ordering::SeqCst)
    }

    /// Sets the flag to whether any debt is published. Called under the mutex that holds the debts,
    /// before it is let go, at each place that changes which debts are published.
    pub(super) fn note_debts(&self, published_any: bool) {
        self.fence_owed.store(published_any, Ordering::SeqCst);
    }

    /// The authority revision in force. Takes no lock.
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    /// Raises the revision in memory to `revision`, where a barrier has moved it. A revision that
    /// is not above the one in memory changes nothing.
    pub(super) fn raise_revision(&self, revision: AuthorityRevision) {
        self.revision.fetch_max(revision.get(), Ordering::SeqCst);
    }

    /// The continuous clock now.
    pub(crate) fn now(&self) -> ContinuousInstant {
        self.clock.now()
    }

    /// This host's reading of UTC: the later of the wall clock and the floor, which the reading
    /// raises. Never waits.
    fn settled_utc_now(&self) -> u64 {
        self.floor.observe(self.wall.now_ms())
    }
}

/// The registration a request was admitted for, exactly.
#[derive(Clone)]
struct Target {
    connection_id: ConnectionId,
    /// The authority revision the request was admitted under.
    admitted_revision: AuthorityRevision,
    /// The latch of that registration, set when it is removed. A registration that has no latch
    /// to give leaves the member to the connection table that was read when the value was made.
    latch: Option<Arc<AtomicBool>>,
}

/// The standing of one request: the one value that every landing asks immediately before it
/// lands. It is `Clone + Send + Sync`, so it moves into tasks, blocking closures and callbacks.
#[derive(Clone)]
pub(crate) struct Footing {
    copies: Arc<Copies>,
    /// The registration the request was admitted for, when it has one: a sign-in's footing has none.
    target: Option<Target>,
    /// The accepted deadline, absolute on the continuous clock.
    deadline: Option<ContinuousInstant>,
}

/// A [`Footing`] that also holds the held bound of the local owner's lease that the request's
/// method is held to. Its question is [`Self::ask`] alone: a bound whose cell moved to another
/// lineage is neither a lease that holds nor one that ended, so it reaches the caller as
/// [`LeasedLapse::BoundMoved`] and is never turned into a refusal or a pass.
#[derive(Clone)]
pub(crate) struct LeasedFooting {
    footing: Footing,
    bound: HeldBound,
}

impl std::fmt::Debug for Footing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Footing")
            .field("connection_id", &self.connection_id())
            .field("admitted_revision", &self.admitted_revision())
            .finish_non_exhaustive()
    }
}

/// Which members one asking of the question reads.
///
/// Every variant is a set of members of the same question, so a member that is masked out is the
/// only difference between two variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ask {
    flag: bool,
    revision: Revision,
    latch: bool,
    deadline: bool,
    bound: bool,
}

/// How the revision member is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Revision {
    /// Not asked.
    Unasked,
    /// Refused when the revision in force is above the one the request was admitted under.
    Admitted,
    /// Refused unless the revision in force is exactly this one.
    Exactly(AuthorityRevision),
}

impl Ask {
    /// A mutation: every member.
    pub(crate) const MUTATION: Self = Self {
        flag: true,
        revision: Revision::Admitted,
        latch: true,
        deadline: true,
        bound: true,
    };

    /// A kept answer: the original deadline is not asked, since a receipt outlives it, and no
    /// bound. A caller whose kept answer is also held to the local owner's lease asks it with
    /// [`Self::and_the_lease`].
    pub(crate) const KEPT_ANSWER: Self = Self {
        deadline: false,
        bound: false,
        ..Self::MUTATION
    };

    /// A read: the registration and the lease. A read asks no fence and holds no revision, since
    /// it changes nothing.
    pub(crate) const READ: Self = Self {
        flag: false,
        revision: Revision::Unasked,
        latch: true,
        deadline: false,
        bound: true,
    };

    /// The local close: the registration, the fence and the revision. A deadline that has run out
    /// passes, since the worker that owns the session knows whether it holds the close's receipt.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the local close asks it from landing C, which converts the close's checks"
        )
    )]
    pub(crate) const LOCAL_CLOSE: Self = Self {
        flag: true,
        revision: Revision::Admitted,
        latch: true,
        deadline: false,
        bound: false,
    };

    /// The network close's claim of its route: the latch alone, which is what its admission asked.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the network close's claim of its route asks it from landing C"
        )
    )]
    pub(crate) const NETWORK_CLOSE_CLAIM: Self = Self {
        flag: false,
        revision: Revision::Unasked,
        latch: true,
        deadline: false,
        bound: false,
    };

    /// A request that withdrew the host's authority by its own barrier, answered under it: no fence
    /// owed, and the revision in force is the one that barrier set. The registration is no member:
    /// the request's own barrier took it.
    pub(crate) const fn own_withdrawal(revision: AuthorityRevision) -> Self {
        Self {
            flag: true,
            revision: Revision::Exactly(revision),
            latch: false,
            deadline: false,
            bound: false,
        }
    }

    /// A sign-in's keep: the fence and the lease's bound alone. The revision the sign-in began
    /// under is not asked, since a barrier in its wait does not end it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the sign-in's keep asks it from landing B, which converts the account actions"
        )
    )]
    pub(crate) const SIGN_IN: Self = Self {
        flag: true,
        revision: Revision::Unasked,
        latch: false,
        deadline: false,
        bound: true,
    };

    /// A mutation's own reply as the local door tells it: the registration and the fence. The
    /// revision the request was admitted under is not asked, since a reply carries what the
    /// request itself did, and another device's withdrawal that moves the revision takes none of
    /// that back; and no deadline, since the effect has run.
    pub(crate) const FRESH_REPLY: Self = Self {
        flag: true,
        revision: Revision::Unasked,
        latch: true,
        deadline: false,
        bound: false,
    };

    /// This question, with the lease's bound also asked, for a request whose method is held to the
    /// local owner's lease.
    #[must_use]
    pub(crate) const fn and_the_lease(self) -> Self {
        Self {
            bound: true,
            ..self
        }
    }
}

/// Which member refused, with the words of the door's own check for that condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lapse {
    /// A fence is owed: the refusal [`super::barrier`]'s fence check gives.
    FenceOwed,
    /// The admission's own lapse: its authority was withdrawn, its registration went, or its
    /// deadline passed.
    Admission(AdmissionLapse),
    /// The revision in force is not the one the request's own barrier set.
    Withdrawn,
    /// The local owner's lease has ended: its bound's cell ended it, or its time has come.
    LeaseEnded,
}

impl Lapse {
    /// The refusal this lapse is told as, in the words of the door's own check for that condition.
    pub(crate) fn refusal(self) -> ControllerError {
        match self {
            Self::FenceOwed => super::barrier::fence_owed_refusal(),
            Self::Admission(lapse) => admission_refusal(lapse),
            Self::Withdrawn => ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            },
            Self::LeaseEnded => super::local_access::lease_not_live().into(),
        }
    }
}

/// What the question of a [`LeasedFooting`] answers when it does not let the request through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeasedLapse {
    /// A member refused.
    Lapse(Lapse),
    /// The bound's cell published another lineage: the lease was ended and established again,
    /// which is neither a lease that holds nor one that ended. It has no refusal: what a landing
    /// does with it is that landing's own decision.
    BoundMoved,
}

impl From<Lapse> for LeasedLapse {
    fn from(lapse: Lapse) -> Self {
        Self::Lapse(lapse)
    }
}

/// The refusal an admission's lapse is told as.
pub(crate) fn admission_refusal(lapse: AdmissionLapse) -> ControllerError {
    match lapse {
        AdmissionLapse::Expired => ControllerError::WindowExpired {
            detail: lapse.to_string(),
        },
        AdmissionLapse::Revoked | AdmissionLapse::Deregistered => {
            ControllerError::PermissionDenied {
                detail: lapse.to_string(),
            }
        }
    }
}

impl Footing {
    /// The standing of a request admitted for `connection_id` under `admitted_revision`, with the
    /// latch of that registration and the deadline it was accepted with.
    pub(super) fn admitted(
        copies: Arc<Copies>,
        connection_id: ConnectionId,
        admitted_revision: AuthorityRevision,
        latch: Option<Arc<AtomicBool>>,
        deadline: Option<ContinuousInstant>,
    ) -> Self {
        Self {
            copies,
            target: Some(Target {
                connection_id,
                admitted_revision,
                latch,
            }),
            deadline,
        }
    }

    /// The standing of a step that has no registration of its own to name: the fence and a lease's
    /// bound can be asked of it, and a member that names a registration refuses it.
    pub(super) fn untargeted(copies: Arc<Copies>) -> Self {
        Self {
            copies,
            target: None,
            deadline: None,
        }
    }

    /// This standing, with the held bound of the local owner's lease that the request's method is
    /// held to.
    #[must_use]
    pub(crate) fn holding(self, bound: HeldBound) -> LeasedFooting {
        LeasedFooting {
            footing: self,
            bound,
        }
    }

    /// The connection the request arrived on, when it has one.
    pub(crate) fn connection_id(&self) -> Option<ConnectionId> {
        self.target.as_ref().map(|target| target.connection_id)
    }

    /// The revision the request was admitted under, when it has a registration.
    pub(crate) fn admitted_revision(&self) -> Option<AuthorityRevision> {
        self.target.as_ref().map(|target| target.admitted_revision)
    }

    /// The question: whether the request still stands at this moment, for the members `ask` reads,
    /// the bound excepted: this footing holds none, whatever the `ask` says of it.
    ///
    /// **Every leaf this calls, and nothing else:** `Copies::fence_is_owed` and `Copies::revision`
    /// (atomic loads), `AtomicBool::load` of the registration's latch and `ContinuousClock::now`
    /// (the daemon's continuous clock). Nothing is allocated or freed, no lock is taken, nothing is
    /// awaited and nothing is written.
    ///
    /// The order is the flag, the revision, the latch and the deadline. The first three are read
    /// in the order the barrier's writes make true: a reader that finds the flag clear after a
    /// barrier finds the revision raised and the latches of the registrations it removed set.
    ///
    /// # Errors
    ///
    /// Returns the first member that refuses.
    pub(crate) fn ask(&self, ask: Ask) -> Result<(), Lapse> {
        if ask.flag && self.copies.fence_is_owed() {
            return Err(Lapse::FenceOwed);
        }
        match ask.revision {
            Revision::Unasked => {}
            Revision::Admitted => {
                let Some(target) = &self.target else {
                    return Err(Lapse::Admission(AdmissionLapse::Deregistered));
                };
                if self.copies.revision() > target.admitted_revision.get() {
                    return Err(Lapse::Admission(AdmissionLapse::Revoked));
                }
            }
            Revision::Exactly(revision) => {
                if self.copies.revision() != revision.get() {
                    return Err(Lapse::Withdrawn);
                }
            }
        }
        if ask.latch {
            match &self.target {
                None => return Err(Lapse::Admission(AdmissionLapse::Deregistered)),
                Some(Target {
                    latch: Some(latch), ..
                }) if latch.load(Ordering::Acquire) => {
                    return Err(Lapse::Admission(AdmissionLapse::Deregistered));
                }
                Some(_) => {}
            }
        }
        if ask.deadline
            && self
                .deadline
                .is_some_and(|deadline| self.copies.now() >= deadline)
        {
            return Err(Lapse::Admission(AdmissionLapse::Expired));
        }
        Ok(())
    }

    /// [`Self::ask`], with the refusal told as the door's own. A footing that holds a bound has no
    /// such reading ([`LeasedFooting::ask`]).
    ///
    /// # Errors
    ///
    /// Returns the refusal of the first member that refuses.
    pub(crate) fn stands(&self, ask: Ask) -> crate::error::Result<()> {
        self.ask(ask).map_err(Lapse::refusal)
    }
}

impl LeasedFooting {
    /// The question: [`Footing::ask`] and then the bound, for the members `ask` reads.
    ///
    /// **Before the first read:** the bound's cell is loaded once and its snapshot copied out
    /// (`HeldBound::published`), because loading a cell can allocate (the first use of a thread)
    /// and lets go of a reference. **After the first read** (the flag, the revision or the latch;
    /// a clock) nothing allocates, frees, takes a lock or waits: the leaves are those of
    /// [`Footing::ask`], `ContinuousClock::now`, `Copies::settled_utc_now` (the wall clock and
    /// `UtcFloor::observe`, an atomic raise of the floor that never waits) and
    /// `HeldBound::stands_in` (comparisons of the copy). Nothing is written but the floor's own
    /// raise.
    ///
    /// The order is the flag, the revision, the latch, the deadline and the bound.
    ///
    /// # Errors
    ///
    /// Returns the first member that refuses, and the bound that moved as itself.
    pub(crate) fn ask(&self, ask: Ask) -> Result<(), LeasedLapse> {
        // Everything the bound's comparison needs is taken before the first read below.
        let published = ask.bound.then(|| self.bound.published());
        self.footing.ask(ask)?;
        if let Some(published) = &published {
            // The continuous clock first and the wall clock after it, as every reader of a bound
            // reads them.
            let now = self.footing.copies.now();
            let utc_ms = self.footing.copies.settled_utc_now();
            match self.bound.stands_in(published, now, utc_ms) {
                Stands::Holds => {}
                Stands::Moved => return Err(LeasedLapse::BoundMoved),
                Stands::EndedOnTheContinuousClock | Stands::EndedInUtc => {
                    return Err(LeasedLapse::Lapse(Lapse::LeaseEnded));
                }
            }
        }
        Ok(())
    }
}

/// What the question of a lease was asked with. The writer of an answer holds it from the question
/// until the transport has taken what the question let through, so that letting go of it, which
/// can free memory, never stands between the question and the write.
#[derive(Default)]
pub struct LeaseAsked {
    _leased: Option<LeasedFooting>,
}

impl LeaseAsked {
    /// What a question was asked with where the lease's bound was read.
    pub(crate) const fn with(leased: LeasedFooting) -> Self {
        Self {
            _leased: Some(leased),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kr_transport::clock::ManualClock;

    use super::*;
    use crate::grants::policy::{BoundCell, BoundIdentity};

    fn is_clone_send_sync<T: Clone + Send + Sync>() {}

    /// A footing on a clock the case moves, admitted at revision 3 under a deadline a minute away,
    /// holding a lease bound that lasts an hour.
    struct Rig {
        copies: Arc<Copies>,
        clock: ManualClock,
        latch: Arc<AtomicBool>,
        cell: Arc<BoundCell>,
        footing: LeasedFooting,
    }

    /// The refusal of the member `lapse`, as the leased question gives it.
    fn refused(lapse: Lapse) -> Result<(), LeasedLapse> {
        Err(LeasedLapse::Lapse(lapse))
    }

    fn rig() -> Rig {
        let clock = ManualClock::new();
        let copies = Arc::new(Copies::new(
            AuthorityRevision::new(3),
            Arc::new(clock.clone()),
            WallClock::from_fn(|| 1_000),
            Arc::new(UtcFloor::default()),
        ));
        let latch = Arc::new(AtomicBool::new(false));
        let deadline = clock.now().checked_add(Duration::from_secs(60));
        let cell = BoundCell::new(
            BoundIdentity::Unbounded,
            clock.now().checked_add(Duration::from_secs(3600)),
            None,
            false,
        );
        let footing = Footing::admitted(
            Arc::clone(&copies),
            ConnectionId::new(kr_ipc::new_uuid()),
            AuthorityRevision::new(3),
            Some(Arc::clone(&latch)),
            deadline,
        )
        .holding(HeldBound::load(&cell));
        Rig {
            copies,
            clock,
            latch,
            cell,
            footing,
        }
    }

    const EVERY_VARIANT: [Ask; 6] = [
        Ask::MUTATION,
        Ask::KEPT_ANSWER,
        Ask::READ,
        Ask::LOCAL_CLOSE,
        Ask::NETWORK_CLOSE_CLAIM,
        Ask::SIGN_IN,
    ];

    #[test]
    fn a_footing_is_clone_send_and_sync() {
        is_clone_send_sync::<Footing>();
        is_clone_send_sync::<Ask>();
    }

    #[test]
    fn nothing_changing_between_the_door_and_the_question_lets_every_variant_through() {
        let rig = rig();
        for ask in EVERY_VARIANT {
            assert_eq!(rig.footing.ask(ask), Ok(()), "{ask:?}");
        }
        assert_eq!(
            rig.footing
                .ask(Ask::own_withdrawal(AuthorityRevision::new(3))),
            Ok(())
        );
    }

    #[test]
    fn a_latch_that_is_set_alone_refuses_the_variants_that_ask_the_registration() {
        let rig = rig();
        rig.latch.store(true, Ordering::Release);
        let deregistered = refused(Lapse::Admission(AdmissionLapse::Deregistered));
        for ask in [
            Ask::MUTATION,
            Ask::KEPT_ANSWER,
            Ask::READ,
            Ask::LOCAL_CLOSE,
            Ask::NETWORK_CLOSE_CLAIM,
        ] {
            assert_eq!(rig.footing.ask(ask), deregistered, "{ask:?}");
        }
        // The sign-in has no registration, and an own withdrawal's registration went with its barrier.
        assert_eq!(rig.footing.ask(Ask::SIGN_IN), Ok(()));
        assert_eq!(
            rig.footing
                .ask(Ask::own_withdrawal(AuthorityRevision::new(3))),
            Ok(())
        );
    }

    #[test]
    fn a_fence_that_is_published_alone_refuses_every_variant_that_asks_the_fence() {
        let rig = rig();
        rig.copies.note_debts(true);
        for ask in [
            Ask::MUTATION,
            Ask::KEPT_ANSWER,
            Ask::LOCAL_CLOSE,
            Ask::SIGN_IN,
        ] {
            assert_eq!(rig.footing.ask(ask), refused(Lapse::FenceOwed), "{ask:?}");
        }
        assert_eq!(
            rig.footing
                .ask(Ask::own_withdrawal(AuthorityRevision::new(3))),
            refused(Lapse::FenceOwed)
        );
        // A read asks no fence, and the network close's claim asks the latch alone.
        assert_eq!(rig.footing.ask(Ask::READ), Ok(()));
        assert_eq!(rig.footing.ask(Ask::NETWORK_CLOSE_CLAIM), Ok(()));
        rig.copies.note_debts(false);
        assert_eq!(rig.footing.ask(Ask::MUTATION), Ok(()));
    }

    #[test]
    fn a_revision_that_is_raised_alone_refuses_the_variants_that_hold_the_revision() {
        let rig = rig();
        rig.copies.raise_revision(AuthorityRevision::new(4));
        let revoked = refused(Lapse::Admission(AdmissionLapse::Revoked));
        for ask in [Ask::MUTATION, Ask::KEPT_ANSWER, Ask::LOCAL_CLOSE] {
            assert_eq!(rig.footing.ask(ask), revoked, "{ask:?}");
        }
        for ask in [Ask::READ, Ask::NETWORK_CLOSE_CLAIM, Ask::SIGN_IN] {
            assert_eq!(rig.footing.ask(ask), Ok(()), "{ask:?}");
        }
        // An own withdrawal stands only at the revision its own barrier set.
        assert_eq!(
            rig.footing
                .ask(Ask::own_withdrawal(AuthorityRevision::new(4))),
            Ok(())
        );
        assert_eq!(
            rig.footing
                .ask(Ask::own_withdrawal(AuthorityRevision::new(3))),
            refused(Lapse::Withdrawn)
        );
        // The revision in memory is never lowered.
        rig.copies.raise_revision(AuthorityRevision::new(2));
        assert_eq!(rig.copies.revision(), 4);
    }

    #[test]
    fn a_deadline_that_passes_alone_refuses_a_mutation_and_no_other_variant() {
        let rig = rig();
        rig.clock.advance(Duration::from_secs(61));
        assert_eq!(
            rig.footing.ask(Ask::MUTATION),
            refused(Lapse::Admission(AdmissionLapse::Expired))
        );
        for ask in [
            Ask::KEPT_ANSWER,
            Ask::READ,
            Ask::LOCAL_CLOSE,
            Ask::NETWORK_CLOSE_CLAIM,
            Ask::SIGN_IN,
        ] {
            assert_eq!(rig.footing.ask(ask), Ok(()), "{ask:?}");
        }
    }

    #[test]
    fn a_bound_whose_cell_ends_alone_refuses_the_variants_that_hold_the_lease() {
        let rig = rig();
        rig.cell.end();
        for ask in [
            Ask::MUTATION,
            Ask::KEPT_ANSWER.and_the_lease(),
            Ask::READ,
            Ask::SIGN_IN,
        ] {
            assert_eq!(rig.footing.ask(ask), refused(Lapse::LeaseEnded), "{ask:?}");
        }
        // A kept answer reads no bound unless its caller asks the lease with it.
        for ask in [Ask::KEPT_ANSWER, Ask::LOCAL_CLOSE, Ask::NETWORK_CLOSE_CLAIM] {
            assert_eq!(rig.footing.ask(ask), Ok(()), "{ask:?}");
        }
    }

    #[test]
    fn a_bound_whose_cell_moved_to_another_lineage_is_reported_as_moved_and_not_as_ended() {
        let rig = rig();
        // Ended and established again: another lineage, which the held bound does not continue.
        rig.cell.end();
        rig.cell
            .publish(BoundIdentity::Unbounded, None, None, false, false);
        for ask in [
            Ask::MUTATION,
            Ask::KEPT_ANSWER.and_the_lease(),
            Ask::READ,
            Ask::SIGN_IN,
        ] {
            assert_eq!(
                rig.footing.ask(ask),
                Err(LeasedLapse::BoundMoved),
                "{ask:?}"
            );
        }
        assert_eq!(rig.footing.ask(Ask::KEPT_ANSWER), Ok(()));
        assert_eq!(rig.footing.ask(Ask::LOCAL_CLOSE), Ok(()));
    }

    #[test]
    fn a_bound_that_runs_out_on_the_continuous_clock_refuses_the_lease_variants() {
        let rig = rig();
        rig.clock.advance(Duration::from_secs(3601));
        // The deadline of the request passed first, so the mutation names it; the read, which asks
        // no deadline, names the lease.
        assert_eq!(
            rig.footing.ask(Ask::MUTATION),
            refused(Lapse::Admission(AdmissionLapse::Expired))
        );
        assert_eq!(rig.footing.ask(Ask::READ), refused(Lapse::LeaseEnded));
    }

    #[test]
    fn the_members_are_read_in_the_order_flag_revision_latch_deadline_bound() {
        let rig = rig();
        rig.latch.store(true, Ordering::Release);
        rig.clock.advance(Duration::from_secs(3601));
        assert_eq!(
            rig.footing.ask(Ask::MUTATION),
            refused(Lapse::Admission(AdmissionLapse::Deregistered))
        );
        rig.copies.raise_revision(AuthorityRevision::new(4));
        assert_eq!(
            rig.footing.ask(Ask::MUTATION),
            refused(Lapse::Admission(AdmissionLapse::Revoked))
        );
        rig.copies.note_debts(true);
        assert_eq!(rig.footing.ask(Ask::MUTATION), refused(Lapse::FenceOwed));
    }

    #[test]
    fn a_refused_member_is_told_in_the_words_of_the_doors_own_check() {
        let revoked = Lapse::Admission(AdmissionLapse::Revoked).refusal();
        assert!(
            matches!(revoked, ControllerError::PermissionDenied { ref detail }
            if *detail == AdmissionLapse::Revoked.to_string())
        );
        let expired = Lapse::Admission(AdmissionLapse::Expired).refusal();
        assert!(
            matches!(expired, ControllerError::WindowExpired { ref detail }
            if *detail == AdmissionLapse::Expired.to_string())
        );
        assert!(matches!(
            Lapse::LeaseEnded.refusal(),
            ControllerError::PermissionDenied { .. }
        ));
    }

    /// A clock that ends a lease's bound at its first reading, as a policy commit on another
    /// thread can between two reads of one question.
    #[derive(Debug)]
    struct EndsTheBoundWhenRead {
        clock: ManualClock,
        cell: Arc<BoundCell>,
        ended: AtomicBool,
    }

    impl ContinuousClock for EndsTheBoundWhenRead {
        fn now(&self) -> ContinuousInstant {
            if !self.ended.swap(true, Ordering::SeqCst) {
                self.cell.end();
            }
            self.clock.now()
        }
    }

    /// A footing, on a clock that ends its bound at its first reading, that holds a lease bound of
    /// an hour: with a registration and a deadline a minute away when `admitted`, with neither
    /// otherwise.
    fn a_footing_on_a_clock_that_ends_its_bound(admitted: bool) -> LeasedFooting {
        let clock = ManualClock::new();
        let deadline = clock.now().checked_add(Duration::from_secs(60));
        let cell = BoundCell::new(
            BoundIdentity::Unbounded,
            clock.now().checked_add(Duration::from_secs(3600)),
            None,
            false,
        );
        let held = HeldBound::load(&cell);
        let copies = Arc::new(Copies::new(
            AuthorityRevision::new(3),
            Arc::new(EndsTheBoundWhenRead {
                clock,
                cell,
                ended: AtomicBool::new(false),
            }),
            WallClock::from_fn(|| 1_000),
            Arc::new(UtcFloor::default()),
        ));
        if admitted {
            Footing::admitted(
                copies,
                ConnectionId::new(kr_ipc::new_uuid()),
                AuthorityRevision::new(3),
                Some(Arc::new(AtomicBool::new(false))),
                deadline,
            )
        } else {
            Footing::untargeted(copies)
        }
        .holding(held)
    }

    #[test]
    fn a_question_compares_the_bound_it_took_before_the_bounds_own_clock_read() {
        let footing = a_footing_on_a_clock_that_ends_its_bound(false);
        // The cell ends while the question reads the clock for the bound, after its first read:
        // that question goes by the bound it took before, and does not load the cell again. The
        // next one finds the end.
        assert_eq!(footing.ask(Ask::SIGN_IN), Ok(()));
        assert_eq!(footing.ask(Ask::SIGN_IN), refused(Lapse::LeaseEnded));
    }

    #[test]
    fn a_question_compares_the_bound_it_took_before_the_deadlines_clock_read() {
        let footing = a_footing_on_a_clock_that_ends_its_bound(true);
        // The cell ends while the question reads the clock for the deadline, which is read before
        // the bound is compared.
        assert_eq!(footing.ask(Ask::MUTATION), Ok(()));
        assert_eq!(footing.ask(Ask::MUTATION), refused(Lapse::LeaseEnded));
    }

    #[test]
    fn a_footing_without_a_registration_refuses_a_variant_that_names_one() {
        let rig = rig();
        let bare = Footing::untargeted(Arc::clone(&rig.copies));
        assert_eq!(
            bare.ask(Ask::MUTATION),
            Err(Lapse::Admission(AdmissionLapse::Deregistered))
        );
        assert_eq!(bare.ask(Ask::SIGN_IN), Ok(()));
    }
}
