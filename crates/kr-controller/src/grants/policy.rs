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
    self, ChainOutcome, ChainRefused, Enrolment, LeaseBound, LeaseHolder, LeaseInstalled,
    LeasePresentation, LeaseRecord, LeaseRefused, LeaseTime, MemberLease, VerifiedEnrolment,
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
    /// The deadlines of the membership lease the intersection was taken under, when a lease
    /// answered for it: it holds only while both are ahead.
    pub lease: Option<LeaseBound>,
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
    /// When the host last woke or started, in UTC milliseconds.
    revalidated_at_ms: u64,
    /// The highest UTC reading this host has decided anything from.
    utc_floor: Arc<UtcFloor>,
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
                let installed = enrolment
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
                    lease: Some(installed.bound()),
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
                // the cloud dependency the default is written to avoid.
                if request.ingress != ActorIngress::LocalIpc
                    && let Some(offline) = self.offline.as_ref()
                    && !offline.is_inside_bound(now_ms)
                {
                    return Err(Refusal::OfflineValidityLapsed {
                        last_synchronised_at_ms: offline
                            .last_synchronised_at_ms
                            .as_ref()
                            .map(|at| at.get()),
                    });
                }
                Ok(PolicyIntersection {
                    rights: grant.actions.clone(),
                    organisation_id: None,
                    lease,
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
    ) -> std::result::Result<LeaseBound, Refusal> {
        let mut seen = None;
        for enrolment in self.enrolments.values() {
            match enrolment.lease_for_device(device_id, now, now_ms) {
                // One usable lease is enough: this device's member is in good standing somewhere
                // this host answers to.
                Ok(installed) => return Ok(installed.bound()),
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
