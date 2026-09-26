//! When a grant runs out, under the host's one time contract.
//!
//! Section 9 measures every expiry the same way: a deadline on the machine's suspend-aware
//! continuous clock, anchored once per grant and boot; a wall clock the host decides against only
//! while it has not gone backwards past what the host has already recorded; and a tombstone for
//! every expiry observed, so nothing that ran out comes back. Every grant with an expiry is
//! anchored here by its identity: a paired device's pairing grant, whose deadline in this boot and
//! whose tombstone are kept with the device's record, and a grant in the grant store, whose
//! deadline and tombstone are kept beside it there. Every part of the host that decides a grant's
//! time asks here: the network, when it admits a device's connection and bounds what that
//! connection may do; owner confirmation; workflows; push; and the grant store's own effects. So
//! no two of them can disagree about one grant.
//!
//! A grant holds while both of its deadlines are ahead: its anchor on the continuous clock, and its
//! expiry in UTC, read through this host's clock floor, which the reading raises.
//!
//! **Lock order.** A check made inside a transaction on the device directory's connection reads
//! the anchors, so the anchors are never held while anything waits for that connection.
//! Deriving an anchor, which reads and writes a directory, is serialised by a lock of its own
//! that nothing inside a transaction takes.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_protocol::grant::{Grant, GrantExpiry};
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{DeviceId, GrantId};
use kr_protocol::scalars::TimestampMs;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use super::devices::{ClockTrust, DeviceDirectory, DeviceRecord, PendingExpiry};
use super::{AnchorSources, OfflineAnchor};
use crate::error::{ControllerError, Result};
use crate::grants::policy::{HeldBound, UtcFloor};
use crate::grants::{GrantDirectory, GrantRecord, HostPolicy};

/// When one grant runs out on the continuous clock.
#[derive(Clone, Copy, Debug)]
pub struct GrantDeadline {
    /// The moment on the continuous clock, absent for a grant that does not expire.
    pub deadline: Option<ContinuousInstant>,
}

/// What one grant's lifetime is in this boot, as this host has anchored it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchored {
    /// It does not expire.
    Unlimited,
    /// It runs out at this moment on the continuous clock.
    Until(ContinuousInstant),
    /// It has run out, and that is on record or owed to the record.
    Over,
}

/// Whether a grant is in force now, on both of its deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStanding {
    /// It is in force on both clocks.
    InForce,
    /// It is not, and nothing about that is owed a record: its end is written down, or nothing
    /// proves it in force.
    OutOfForce,
    /// It is not in force, and the end that decides it is not written down yet, or it cannot be
    /// decided while the clock floor is owed its record. Answered as neither, because a daemon
    /// started in a new boot could decide the other way.
    Unrecorded,
}

impl Anchored {
    /// Whether it still holds at `now` on the continuous clock.
    #[must_use]
    pub fn holds_at(self, now: ContinuousInstant) -> bool {
        match self {
            Self::Unlimited => true,
            Self::Until(deadline) => now < deadline,
            Self::Over => false,
        }
    }

    const fn of(anchored: GrantDeadline) -> Self {
        match anchored.deadline {
            Some(deadline) => Self::Until(deadline),
            None => Self::Unlimited,
        }
    }
}

/// Every grant's lifetime on this host.
pub struct GrantLifetimes {
    devices: Arc<DeviceDirectory>,
    /// The suspend-aware continuous clock every deadline is measured on.
    clock: Arc<dyn ContinuousClock>,
    /// The machine's boot-scoped clock, which a recorded deadline is written in.
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    boot_identity: BootIdentity,
    /// One anchor per grant, shared by every connection and every check that asks about it.
    ///
    /// Anchored the first time anything asks, so a wall clock stepped backwards between two
    /// questions cannot give the same grant a longer life the second time.
    anchored: Mutex<BTreeMap<GrantId, GrantDeadline>>,
    /// Held while an anchor is derived, and never inside a directory transaction.
    anchoring: Mutex<()>,
    /// Paired devices' expiry records this host owes its directory and has not yet written.
    pending_expiry: Arc<PendingExpiry>,
    /// Stored grants' expiry records this host owes the grant store and has not yet written.
    pending_stored: Mutex<BTreeMap<GrantId, TimestampMs>>,
    /// Whether this host may decide a grant's expiry from its own wall clock.
    clock_trust: Arc<ClockTrust>,
    /// The daemon's wall clock, which dates an expiry this host observes.
    wall: crate::service::WallClock,
    /// This host's clock floor, which a grant's expiry in UTC is read through.
    floor: Arc<UtcFloor>,
    /// The time the bounded offline validity has spent, kept on the continuous clock
    /// ([`OfflineAnchor`]).
    ///
    /// Measured in UTC alone, the bound would be lengthened by a wall clock wound back while it
    /// runs: the floor holds UTC still until the clock catches up. Taken when the policy holding
    /// the bound is restored, accepted or synchronised, and changed only under the policy's lock.
    /// It is kept here, beside the grants' own anchors, so every decision that can find the bound
    /// run out writes down the same time: a paired device's, a workflow's and push's.
    offline_anchor: Mutex<Option<OfflineAnchor>>,
    /// True while the time the offline bound has spent is owed its record: a poll found the bound
    /// run out, or a write of the time failed. The next step that settles the clock floor writes
    /// it.
    offline_time_owed: AtomicBool,
}

impl std::fmt::Debug for GrantLifetimes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantLifetimes")
            .finish_non_exhaustive()
    }
}

impl GrantLifetimes {
    /// Builds the lifetimes of the grants this host holds, measured on `clock` in this boot, with
    /// UTC read on `wall` through `floor`.
    #[must_use]
    pub fn new(
        devices: Arc<DeviceDirectory>,
        clock: Arc<dyn ContinuousClock>,
        shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
        boot_identity: BootIdentity,
        wall: crate::service::WallClock,
        floor: Arc<UtcFloor>,
    ) -> Self {
        Self {
            devices,
            clock,
            shared_clock,
            boot_identity,
            anchored: Mutex::new(BTreeMap::new()),
            anchoring: Mutex::new(()),
            pending_expiry: Arc::new(PendingExpiry::default()),
            pending_stored: Mutex::new(BTreeMap::new()),
            clock_trust: Arc::new(ClockTrust::new(wall.clone(), Arc::clone(&floor))),
            wall,
            floor,
            offline_anchor: Mutex::new(None),
            offline_time_owed: AtomicBool::new(false),
        }
    }

    fn wall_now(&self) -> TimestampMs {
        TimestampMs::new(self.wall.now_ms())
    }

    /// The continuous clock now, on the clock every anchor here is measured on.
    #[must_use]
    pub fn continuous_now(&self) -> ContinuousInstant {
        self.clock.now()
    }

    /// This host's reading of UTC through its floor, which the reading raises.
    #[must_use]
    pub fn settled_utc_now(&self) -> u64 {
        self.floor.observe(self.wall.now_ms())
    }

    /// Whether a grant anchored as `lifetime`, expiring at `expiry`, holds now on both clocks.
    fn holds(&self, lifetime: Anchored, expiry: GrantExpiry) -> bool {
        lifetime.holds_at(self.clock.now()) && expiry.is_valid_at(self.settled_utc_now())
    }

    /// Returns when this device's grant runs out, anchoring it the first time it is asked.
    ///
    /// Behind the anchor is a deadline on the machine's own continuous clock, written down and
    /// bound to this boot:
    ///
    /// * Within the boot it was derived in, that deadline is the answer. A restart of this daemon
    ///   does not re-derive it, so a device that comes back after a restart is refused rather than
    ///   given a fresh lifetime from a wall clock that has since been stepped backwards.
    /// * In a new boot there is nothing to reuse, so the lifetime comes from the grant's UTC
    ///   expiry, decided against a moment that is never earlier than the latest this host has
    ///   recorded. A wall clock that is behind that mark by more than
    ///   [`super::devices::CLOCK_TOLERANCE_MS`] is not a clock this host decides an expiry against.
    ///
    /// Either way the continuous instant is sampled *before* the moment it is measured against:
    /// sampling the other way round would count the time between the two samples, and a machine
    /// suspended there would wake with a longer grant than it went to sleep with.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` when the grant has run out, `CLOCK_UNTRUSTED` when the wall
    /// clock cannot be trusted to say whether it has, and an error when the deadline or an observed
    /// expiry cannot be written down. A grant whose end this host cannot record is not served: the
    /// alternative is a device that keeps reconnecting on a grant this host has already decided is
    /// over.
    pub fn deadline(&self, record: &DeviceRecord) -> Result<Option<ContinuousInstant>> {
        match self.lifetime(record)? {
            Anchored::Unlimited => Ok(None),
            Anchored::Until(deadline) => Ok(Some(deadline)),
            Anchored::Over => Err(ControllerError::PermissionDenied {
                detail: "this device's grant has run out; pair again".to_owned(),
            }),
        }
    }

    /// Returns what `record`'s grant's lifetime is in this boot, anchoring it the first time it is
    /// asked ([`Self::deadline`]).
    ///
    /// # Errors
    ///
    /// Returns `CLOCK_UNTRUSTED` when the wall clock cannot be trusted to anchor it, and an error
    /// when the deadline or an observed expiry cannot be read or written.
    pub fn paired(&self, record: &DeviceRecord) -> Result<Anchored> {
        self.lifetime(record)
    }

    /// Returns whether `record`'s grant is in force now, on both clocks: before its anchor on the
    /// continuous clock, and before its expiry at this host's reading of UTC through the floor.
    ///
    /// An expiry this finds is recorded, the first time it finds it, so the answer never changes
    /// back. A wall clock this host will not decide against leaves an expiring grant out of force:
    /// section 9 rejects what cannot be proved valid, and a grant that does not expire is never
    /// affected by it.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifetime or an observed expiry cannot be read or written.
    pub fn in_force(&self, record: &DeviceRecord) -> Result<bool> {
        Ok(self.paired_standing(record)? == GrantStanding::InForce)
    }

    /// Returns whether `record`'s grant is in force now on both clocks, and whether an end found is
    /// on record ([`Self::in_force`]).
    ///
    /// # Errors
    ///
    /// Returns an error when the lifetime cannot be read or written.
    pub fn paired_standing(&self, record: &DeviceRecord) -> Result<GrantStanding> {
        let lifetime = match self.lifetime(record) {
            Ok(lifetime) => lifetime,
            Err(ControllerError::ClockUntrusted { .. }) => return Ok(GrantStanding::OutOfForce),
            Err(error) => return Err(error),
        };
        if self.holds(lifetime, record.grant.expiry) {
            return Ok(GrantStanding::InForce);
        }
        if lifetime != Anchored::Over {
            // Observed here, so it is written here: the tombstone is what a later boot reads,
            // where this boot's deadline means nothing any more.
            let moment = self
                .clock_trust
                .observe(&self.devices)
                .unwrap_or_else(|_| self.wall_now());
            self.pending_expiry.owe(record.device_id, moment);
            self.pending_expiry.settle(&self.devices);
        }
        Ok(if self.pending_expiry.is_owed(record.device_id) {
            GrantStanding::Unrecorded
        } else {
            GrantStanding::OutOfForce
        })
    }

    /// Returns whether a paired device's grant is in force now, from memory alone, on both clocks.
    ///
    /// For a check made inside a transaction on the directory's connection, where nothing else may
    /// touch that connection: the anchor was taken before the transaction began, by
    /// [`Self::in_force`] or [`Self::deadline`]; the continuous clock and the wall clock are read
    /// now, after every wait, and the wall clock through the floor, which touches no connection. An
    /// expiring grant with no anchor in this boot is not in force here, because nothing proves it
    /// is. An expiry found here is owed to the record, and written by [`Self::settle`] or the
    /// host's own task.
    #[must_use]
    pub fn in_force_now(&self, device_id: DeviceId, grant: &Grant) -> bool {
        if matches!(grant.expiry, GrantExpiry::Never) {
            return true;
        }
        // Nothing proves an expiring grant in force while this boot's clock continuity is lost,
        // whatever its anchor says, and nothing is owed to the record either: it has not ended.
        if self.floor.continuity_lost() {
            return false;
        }
        let Some(anchored) = self.anchored().get(&grant.grant_id).copied() else {
            return false;
        };
        if self.holds(Anchored::of(anchored), grant.expiry) {
            return true;
        }
        self.pending_expiry.owe(device_id, self.wall_now());
        false
    }

    /// Returns what a stored grant's lifetime is in this boot, anchoring it the first time anything
    /// asks, as a paired device's is.
    ///
    /// An end written down for it in any boot stands, whatever the clock says now. Within the boot
    /// its deadline was derived in, that deadline is read back from the grant store, a restart of
    /// this daemon included. Otherwise it is derived from the grant's expiry against this host's
    /// reading of UTC through its floor, under a clock this host trusts, and written down for the
    /// boot. A grant that does not expire has no deadline and never reads a clock.
    ///
    /// # Errors
    ///
    /// Returns `CLOCK_UNTRUSTED` when an expiring grant has no anchor in this boot and the wall
    /// clock cannot be trusted to give it one, a `STORAGE_UNAVAILABLE` refusal while the floor it
    /// would be derived on is owed its record or while an end it found cannot be written down, and
    /// an error when the store cannot be read or written.
    pub fn stored(&self, store: &GrantDirectory, record: &GrantRecord) -> Result<Anchored> {
        let grant_id = record.grant.grant_id;
        self.provable(record.grant.expiry)?;
        if let Some(anchored) = self.anchored().get(&grant_id).copied() {
            return Ok(Anchored::of(anchored));
        }
        let _anchoring = self
            .anchoring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(anchored) = self.anchored().get(&grant_id).copied() {
            return Ok(Anchored::of(anchored));
        }
        let GrantExpiry::At { expires_at_ms } = record.grant.expiry else {
            self.anchor(grant_id, None);
            return Ok(Anchored::Unlimited);
        };
        if store.grant_expired_at(grant_id)?.is_some() {
            return Ok(Anchored::Over);
        }
        let anchor = self.clock.now();
        let boot_now = self.shared_clock.boot_elapsed_ms();
        let remaining = match store.grant_deadline_in(grant_id, &self.boot_identity)? {
            Some(deadline) => deadline.saturating_sub(boot_now),
            None => {
                let Some(observed) = self.clock_trust.sample(&self.devices)? else {
                    return Err(ControllerError::ClockUntrusted {
                        detail: "this host's clock went backwards and has not been established \
                                 again, so it cannot say whether this grant has run out"
                            .to_owned(),
                    });
                };
                // Decided through the floor, as every time bound on this host is, and not while
                // the floor is owed its record.
                let bound = self.floor.bound(record.grant.expiry, observed.now.get());
                if bound.owed {
                    return Err(crate::grants::store::unrecorded());
                }
                let remaining = expires_at_ms.get().saturating_sub(bound.at_ms);
                if remaining > 0 {
                    store.record_grant_deadline(
                        grant_id,
                        &self.boot_identity,
                        boot_now.saturating_add(remaining),
                    )?;
                }
                remaining
            }
        };
        if remaining == 0 {
            // Run out. Its end is written down as the grant's tombstone before it is answered:
            // until that record lands, a clock wound back before the next start could decide the
            // other way, so the lapse is answered as unrecorded.
            self.owe_stored_expiry(grant_id);
            self.settle_stored(store);
            if self.stored_expiry_owed(grant_id) {
                return Err(crate::grants::store::unrecorded());
            }
            return Ok(Anchored::Over);
        }
        let deadline = anchor.checked_add(Duration::from_millis(remaining));
        self.anchor(grant_id, deadline);
        Ok(deadline.map_or(Anchored::Unlimited, Anchored::Until))
    }

    /// Whether a stored grant's tombstone is owed to the store and not written yet.
    #[must_use]
    pub fn stored_expiry_owed(&self, grant_id: GrantId) -> bool {
        self.pending_stored
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&grant_id)
    }

    /// Returns whether a stored grant is in force now, on both clocks, anchoring it the first time
    /// anything asks ([`Self::stored`]).
    ///
    /// An expiry this finds is written down as the grant's tombstone, and owed to the store when
    /// the write cannot happen at once. An expiring grant with no anchor in this boot while the
    /// clock is distrusted is not in force: nothing proves it.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or written.
    pub fn stored_in_force(&self, store: &GrantDirectory, record: &GrantRecord) -> Result<bool> {
        Ok(self.stored_standing(store, record)? == GrantStanding::InForce)
    }

    /// Returns whether a stored grant is in force now on both clocks, and whether an end found is
    /// on record ([`Self::stored_in_force`]).
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or written.
    pub fn stored_standing(
        &self,
        store: &GrantDirectory,
        record: &GrantRecord,
    ) -> Result<GrantStanding> {
        let lifetime = match self.stored(store, record) {
            Ok(lifetime) => lifetime,
            Err(ControllerError::ClockUntrusted { .. }) => return Ok(GrantStanding::OutOfForce),
            Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::StorageUnavailable,
                ..
            }) => return Ok(GrantStanding::Unrecorded),
            Err(error) => return Err(error),
        };
        if self.holds(lifetime, record.grant.expiry) {
            return Ok(GrantStanding::InForce);
        }
        if lifetime != Anchored::Over {
            self.owe_stored_expiry(record.grant.grant_id);
            self.settle_stored(store);
        }
        Ok(if self.stored_expiry_owed(record.grant.grant_id) {
            GrantStanding::Unrecorded
        } else {
            GrantStanding::OutOfForce
        })
    }

    /// Records that a stored grant was found to have run out, for the grant store to write down.
    ///
    /// The first moment observed stays: a later observation of the same expiry is the same fact.
    pub fn owe_stored_expiry(&self, grant_id: GrantId) {
        let moment = self.wall_now();
        self.pending_stored
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(grant_id)
            .or_insert(moment);
    }

    /// Writes down every stored grant's expiry this host owes `store`, keeping whatever cannot be
    /// written.
    pub fn settle_stored(&self, store: &GrantDirectory) {
        let owed: Vec<(GrantId, TimestampMs)> = self
            .pending_stored
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(grant_id, at)| (*grant_id, *at))
            .collect();
        for (grant_id, at) in owed {
            match store.record_grant_expiry(grant_id, at.get()) {
                Ok(()) => {
                    self.pending_stored
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&grant_id);
                }
                Err(error) => eprintln!(
                    "kr-controller: could not record that grant {grant_id} has run out: {error}"
                ),
            }
        }
    }

    /// Writes down every paired device's expiry this host owes its directory, keeping whatever
    /// cannot be written.
    pub fn settle(&self) {
        self.pending_expiry.settle(&self.devices);
    }

    /// Returns the expiry records this host owes its directory.
    #[must_use]
    pub const fn pending_expiry(&self) -> &Arc<PendingExpiry> {
        &self.pending_expiry
    }

    /// Returns this host's decision about its own wall clock.
    #[must_use]
    pub const fn clock_trust(&self) -> &Arc<ClockTrust> {
        &self.clock_trust
    }

    /// Refuses an expiring grant while this boot's clock continuity is lost.
    ///
    /// A reading published only in the floor this boot lost may have passed the grant's expiry,
    /// and its anchor on the continuous clock proves nothing about that, so until the owner
    /// establishes the clock no expiring grant is in force. Nothing is written: the grant has not
    /// been found run out, only unproven.
    fn provable(&self, expiry: GrantExpiry) -> Result<()> {
        if expiry != GrantExpiry::Never && self.floor.continuity_lost() {
            return Err(crate::grants::continuity_lost());
        }
        Ok(())
    }

    fn lifetime(&self, record: &DeviceRecord) -> Result<Anchored> {
        let grant_id = record.grant.grant_id;
        self.provable(record.grant.expiry)?;
        if let Some(anchored) = self.anchored().get(&grant_id).copied() {
            return Ok(Anchored::of(anchored));
        }
        // One derivation at a time, so a grant is anchored once and its recorded deadline is
        // written once. The anchors themselves are not held while the directory is read.
        let _anchoring = self
            .anchoring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(anchored) = self.anchored().get(&grant_id).copied() {
            return Ok(Anchored::of(anchored));
        }
        let GrantExpiry::At { expires_at_ms } = record.grant.expiry else {
            self.anchor(grant_id, None);
            return Ok(Anchored::Unlimited);
        };
        let anchor = self.clock.now();
        let boot_now = self.shared_clock.boot_elapsed_ms();
        let recorded = self
            .devices
            .grant_deadline_in(record.device_id, &self.boot_identity)?;
        let remaining = match recorded {
            Some(deadline) => deadline.saturating_sub(boot_now),
            None => self.derive_lifetime(record, expires_at_ms, boot_now)?,
        };
        if remaining == 0 {
            // Run out. The tombstone is owed to the directory before anything tries to write it:
            // a write that fails here is retried by the host's own task rather than forgotten.
            self.pending_expiry.owe(record.device_id, self.wall_now());
            self.pending_expiry.settle(&self.devices);
            return Ok(Anchored::Over);
        }
        let deadline = anchor.checked_add(Duration::from_millis(remaining));
        self.anchor(grant_id, deadline);
        Ok(deadline.map_or(Anchored::Unlimited, Anchored::Until))
    }

    /// Derives how much of one grant's life is left, and writes the deadline down.
    ///
    /// Only reached in a boot that has no deadline for this device yet. The wall clock decides,
    /// against the latest moment this host has recorded, and the answer is written as a moment on
    /// the machine's continuous clock so nothing has to ask the wall clock again.
    fn derive_lifetime(
        &self,
        record: &DeviceRecord,
        expires_at_ms: TimestampMs,
        boot_now: u64,
    ) -> Result<u64> {
        // One boundary, and one answer from it: the reading and the decision about the reading
        // are taken together, so a grant's life cannot be measured from a moment the host had
        // already decided it could not trust. Distrust stands until something authenticates the
        // clock again; reaching a moment this host had already written down is not that evidence,
        // and only an owner's approval of the clock clears it.
        let Some(observed) = self.clock_trust.sample(&self.devices)? else {
            return Err(ControllerError::ClockUntrusted {
                detail: "this host's clock went backwards and has not been established again, so \
                         it cannot say whether this device's grant has run out"
                    .to_owned(),
            });
        };
        let remaining = expires_at_ms.get().saturating_sub(observed.now.get());
        if remaining > 0 {
            self.devices.record_grant_deadline(
                record.device_id,
                &self.boot_identity,
                boot_now.saturating_add(remaining),
            )?;
        }
        Ok(remaining)
    }

    /// The readings and the record an offline anchor on this host is taken from: this host's
    /// clocks, its boot, its device directory and its floor.
    pub(crate) fn anchor_sources(&self) -> AnchorSources<'_> {
        AnchorSources {
            clock: &*self.clock,
            boot_clock: &*self.shared_clock,
            wall_clock: &*self.wall,
            boot: &self.boot_identity,
            devices: &self.devices,
            floor: &self.floor,
        }
    }

    /// The anchor the offline bound is measured with now, when the policy in force has one.
    pub(crate) fn offline_anchor(&self) -> Option<OfflineAnchor> {
        *self
            .offline_anchor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts `anchor` in force for the offline bound, with the policy's lock held: the anchor of the
    /// policy that has just been restored, accepted or synchronised.
    pub(crate) fn hold_offline_anchor(
        &self,
        anchor: Option<OfflineAnchor>,
        _policy: &MutexGuard<'_, HostPolicy>,
    ) {
        *self
            .offline_anchor
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = anchor;
    }

    /// Whether the offline bound a decision loaded, `offline`, has run out at `now` on the
    /// continuous clock, the one clock that cannot be wound back, with the policy's lock held.
    ///
    /// The time the bound has spent is written down before this answers that it has, so the
    /// refusal the caller makes of it stands after a restart or a reboot; a write that fails stays
    /// owed. Every decision that holds the bound to its continuous end asks here, so none can find
    /// it run out and leave that time unwritten.
    pub(crate) fn offline_bound_ended(
        &self,
        offline: Option<&HeldBound>,
        now: ContinuousInstant,
        policy: &MutexGuard<'_, HostPolicy>,
    ) -> bool {
        let ended =
            offline.is_some_and(|offline| offline.snapshot().ended_on_the_continuous_clock(now));
        if ended {
            self.write_offline_time(policy);
        }
        ended
    }

    /// Writes down the time the offline bound has spent by now, with the policy's lock held.
    ///
    /// A write that fails leaves the record owed, and the next step that settles the clock floor
    /// writes it; meanwhile the anchor held here still holds the time.
    pub(crate) fn write_offline_time(&self, _policy: &MutexGuard<'_, HostPolicy>) {
        self.offline_time_owed.store(false, Ordering::SeqCst);
        let Some(anchor) = self.offline_anchor() else {
            return;
        };
        if let Err(error) = self.anchor_sources().record(&anchor) {
            self.offline_time_owed.store(true, Ordering::SeqCst);
            eprintln!(
                "kr-controller: could not record the time the offline bound has spent: {error}"
            );
        }
    }

    /// Records that the offline bound was found run out where nothing may wait, a poll among
    /// them, so the next step that settles the clock floor writes the time spent down.
    pub(crate) fn owe_offline_time(&self) {
        self.offline_time_owed.store(true, Ordering::SeqCst);
    }

    /// Whether the time the offline bound has spent is owed its record.
    pub(crate) fn offline_time_owed(&self) -> bool {
        self.offline_time_owed.load(Ordering::SeqCst)
    }

    fn anchor(&self, grant_id: GrantId, deadline: Option<ContinuousInstant>) {
        self.anchored()
            .entry(grant_id)
            .or_insert(GrantDeadline { deadline });
    }

    fn anchored(&self) -> MutexGuard<'_, BTreeMap<GrantId, GrantDeadline>> {
        self.anchored.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_ipc::clock::ManualSharedClock;
    use kr_protocol::grant::{EnvironmentSelector, Grant, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceKeyRevision, GrantId};
    use kr_protocol::pairing::{DeviceName, DevicePlatform};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, EndpointKey, Nullable, Uuid};
    use kr_transport::clock::ManualClock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A device holding host management under `expiry`.
    fn owner(byte: u8, expiry: GrantExpiry) -> DeviceRecord {
        DeviceRecord {
            device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
            endpoint_id: EndpointKey::from_bytes([byte; 32]),
            device_key_revision: DeviceKeyRevision::new(1),
            authorisation: AuthorisationKey::from_bytes([byte ^ 0xff; 32]),
            stored_envelope: None,
            notification_preview: None,
            device_name: DeviceName::new("A phone").expect("a name"),
            platform: DevicePlatform::Ios,
            grant: Grant {
                grant_id: GrantId::new(Uuid::from_bytes([byte; 16])),
                parent_grant_id: Nullable::null(),
                issuer_device_id: DeviceId::new(Uuid::from_bytes([0; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: [ActionRight::HostManage].into_iter().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: true,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry,
                organisation: Nullable::null(),
            },
            paired_at_ms: TimestampMs::new(1),
            revoked_at_ms: None,
            expired_at_ms: None,
            committed_invitation_id: None,
        }
    }

    fn in_a_minute() -> GrantExpiry {
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(kr_ipc::now_ms().get().saturating_add(60_000)),
        }
    }

    fn lifetimes(devices: &Arc<DeviceDirectory>, clock: &ManualClock) -> GrantLifetimes {
        GrantLifetimes::new(
            Arc::clone(devices),
            Arc::new(clock.clone()),
            Arc::new(ManualSharedClock::new()),
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            crate::service::WallClock::system(),
            Arc::new(UtcFloor::default()),
        )
    }

    /// KR-REQ-10.05, KR-REQ-10.06: an owner device's grant that runs out is out of force from
    /// that moment on the continuous clock, whichever check finds it, and the expiry is recorded,
    /// so the device is never an owner device again.
    #[test]
    fn a_grant_that_runs_out_stays_out() {
        let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
        let device = owner(1, in_a_minute());
        devices.commit(&device).expect("the device");
        let clock = ManualClock::new();
        let lifetimes = lifetimes(&devices, &clock);

        assert!(lifetimes.in_force(&device).expect("decided"));
        assert!(lifetimes.in_force_now(device.device_id, &device.grant));
        clock.advance(Duration::from_secs(61));
        assert!(
            !lifetimes.in_force_now(device.device_id, &device.grant),
            "the anchor is compared with the clock read now"
        );
        lifetimes.settle();
        assert!(!lifetimes.in_force(&device).expect("decided"));
        let recorded = devices
            .record_for_device(device.device_id)
            .expect("readable")
            .expect("the device");
        assert!(recorded.expired_at_ms.is_some(), "the expiry is on record");
        assert!(!recorded.is_paired());
    }

    /// KR-REQ-10.05: a wall clock that has gone backwards past what this host recorded proves no
    /// expiring grant. One never anchored in this boot is out of force, and a grant that does not
    /// expire is not affected.
    #[test]
    fn a_clock_that_went_backwards_proves_no_expiring_grant() {
        let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
        let expiring = owner(2, in_a_minute());
        let lasting = owner(3, GrantExpiry::Never);
        devices.commit(&expiring).expect("the device");
        devices.commit(&lasting).expect("the device");
        // This host has already recorded a moment an hour ahead of the wall clock, which is what a
        // clock stepped back an hour looks like to it.
        devices
            .utc_at_least(TimestampMs::new(
                kr_ipc::now_ms().get().saturating_add(3_600_000),
            ))
            .expect("the mark");
        let lifetimes = lifetimes(&devices, &ManualClock::new());

        assert!(!lifetimes.in_force(&expiring).expect("decided"));
        assert!(
            !lifetimes.in_force_now(expiring.device_id, &expiring.grant),
            "nothing anchored it, so nothing proves it"
        );
        assert!(lifetimes.in_force(&lasting).expect("decided"));
        assert!(lifetimes.in_force_now(lasting.device_id, &lasting.grant));
    }

    /// A grant written into `store`, redeemed, with `expiry`.
    fn stored_grant(store: &GrantDirectory, byte: u8, expiry: GrantExpiry) -> GrantRecord {
        let record = GrantRecord {
            grant: owner(byte, expiry).grant,
            session_id: None,
            issued_at_ms: 1,
            activated_at_ms: Some(1),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        store
            .issue(&record, || Ok(()))
            .expect("the grant is written");
        record
    }

    /// Lifetimes on `clock` and a wall clock reading `wall`, in the boot `boot`, under `floor`.
    fn lifetimes_at(
        devices: &Arc<DeviceDirectory>,
        clock: &ManualClock,
        wall: &Arc<AtomicU64>,
        boot: BootIdentity,
        floor: &Arc<UtcFloor>,
    ) -> GrantLifetimes {
        let wall = Arc::clone(wall);
        GrantLifetimes::new(
            Arc::clone(devices),
            Arc::new(clock.clone()),
            Arc::new(ManualSharedClock::new()),
            boot,
            crate::service::WallClock::from_fn(move || wall.load(Ordering::SeqCst)),
            Arc::clone(floor),
        )
    }

    /// Rule C's grant snapshots: a stored grant with an expiry is anchored once per boot, and a
    /// daemon restarted in the same boot reads its anchor back rather than deriving it again. With
    /// UTC moved past its expiry and its continuous deadline still ahead it is out of force, and
    /// the end it was found at is written down, so a new boot refuses it whatever the wall clock
    /// says. A stored grant with no anchor in this boot is out of force while the clock is
    /// distrusted. Controls: before either deadline it is in force, and a grant that does not
    /// expire is in force under a distrusted clock.
    #[test]
    fn a_grant_is_one_snapshot_whoever_asks() {
        let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
        let store = GrantDirectory::in_memory().expect("a grant store");
        let now = kr_ipc::now_ms().get();
        let wall = Arc::new(AtomicU64::new(now));
        let clock = ManualClock::new();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let floor = Arc::new(UtcFloor::default());
        let expiring = stored_grant(
            &store,
            4,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
        );
        let lasting = stored_grant(&store, 5, GrantExpiry::Never);

        let first = lifetimes_at(&devices, &clock, &wall, boot.clone(), &floor);
        let anchored = first.stored(&store, &expiring).expect("anchored");
        assert!(matches!(anchored, Anchored::Until(_)), "{anchored:?}");
        assert!(
            store
                .grant_deadline_in(expiring.grant.grant_id, &boot)
                .expect("readable")
                .is_some(),
            "the anchor is written down for this boot"
        );
        assert!(
            first.stored_in_force(&store, &expiring).expect("decided"),
            "the control: before either deadline it is in force"
        );

        // The daemon restarts in the same boot with the wall clock ten seconds on. The anchor is
        // read back rather than derived again, so its deadline is the same instant.
        wall.store(now + 10_000, Ordering::SeqCst);
        let restarted = lifetimes_at(&devices, &clock, &wall, boot.clone(), &floor);
        assert_eq!(
            restarted.stored(&store, &expiring).expect("read back"),
            anchored
        );

        // UTC runs past the expiry while the continuous deadline is still ahead.
        wall.store(now + 61_000, Ordering::SeqCst);
        assert!(
            !restarted
                .stored_in_force(&store, &expiring)
                .expect("decided"),
            "out of force by UTC alone"
        );
        assert!(
            store
                .grant_expired_at(expiring.grant.grant_id)
                .expect("readable")
                .is_some(),
            "and its end is written down"
        );

        // A new boot, the wall clock wound back before the expiry, a floor that never saw past it.
        wall.store(now, Ordering::SeqCst);
        let rebooted = lifetimes_at(
            &devices,
            &clock,
            &wall,
            BootIdentity {
                value: kr_protocol::scalars::Bytes::new(vec![0x5a; 16]),
                ..boot
            },
            &Arc::new(UtcFloor::default()),
        );
        assert_eq!(
            rebooted.stored(&store, &expiring).expect("decided"),
            Anchored::Over,
            "the end written down stands in any boot"
        );
        assert!(
            !rebooted
                .stored_in_force(&store, &expiring)
                .expect("decided")
        );

        // A grant never anchored in this boot, while the clock is distrusted: nothing proves it.
        let fresh = stored_grant(
            &store,
            6,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
        );
        devices
            .utc_at_least(TimestampMs::new(now + 3_600_000))
            .expect("the mark");
        assert!(matches!(
            rebooted.stored(&store, &fresh),
            Err(ControllerError::ClockUntrusted { .. })
        ));
        assert!(!rebooted.stored_in_force(&store, &fresh).expect("decided"));
        // The control: a grant that does not expire reads no clock.
        assert!(rebooted.stored_in_force(&store, &lasting).expect("decided"));
    }

    /// An owner device's pairing grant that runs out by UTC while its continuous deadline is still
    /// ahead is out of force for every owner check, the one made inside a transaction included,
    /// and its expiry goes on record. The control: before its expiry it is in force.
    #[test]
    fn a_pairing_grant_that_runs_out_by_utc_first_is_out_of_force() {
        let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
        let now = kr_ipc::now_ms().get();
        let wall = Arc::new(AtomicU64::new(now));
        let device = owner(
            7,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
        );
        devices.commit(&device).expect("the device");
        let lifetimes = lifetimes_at(
            &devices,
            &ManualClock::new(),
            &wall,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            &Arc::new(UtcFloor::default()),
        );
        assert!(lifetimes.in_force(&device).expect("decided"));
        assert!(lifetimes.in_force_now(device.device_id, &device.grant));

        wall.store(now + 61_000, Ordering::SeqCst);
        assert!(
            !lifetimes.in_force_now(device.device_id, &device.grant),
            "inside a transaction, by UTC through the floor"
        );
        lifetimes.settle();
        assert!(!lifetimes.in_force(&device).expect("decided"));
        let recorded = devices
            .record_for_device(device.device_id)
            .expect("readable")
            .expect("the device");
        assert!(recorded.expired_at_ms.is_some(), "the expiry is on record");
    }

    /// While this boot's clock continuity is lost, nothing proves an expiring grant in force,
    /// whatever its anchor on the continuous clock says, and nothing about it is written as an
    /// end: once the owner establishes the clock it stands again. A grant that does not expire is
    /// never affected.
    #[test]
    fn a_lost_clock_continuity_proves_no_expiring_grant_and_ends_none() {
        let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
        let expiring = owner(4, in_a_minute());
        let lasting = owner(5, GrantExpiry::Never);
        devices.commit(&expiring).expect("the device");
        devices.commit(&lasting).expect("the device");
        let floor = Arc::new(UtcFloor::default());
        let lifetimes = GrantLifetimes::new(
            Arc::clone(&devices),
            Arc::new(ManualClock::new()),
            Arc::new(ManualSharedClock::new()),
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            crate::service::WallClock::system(),
            Arc::clone(&floor),
        );
        assert!(lifetimes.in_force(&expiring).expect("decided"), "anchored");

        floor.lose_continuity();
        assert!(!lifetimes.in_force(&expiring).expect("decided"));
        assert!(!lifetimes.in_force_now(expiring.device_id, &expiring.grant));
        assert!(
            matches!(
                lifetimes.deadline(&expiring),
                Err(ControllerError::ClockUntrusted { .. })
            ),
            "the refusal is the clock's, not the grant's end"
        );
        assert!(lifetimes.in_force(&lasting).expect("decided"));
        lifetimes.settle();
        let recorded = devices
            .record_for_device(expiring.device_id)
            .expect("readable")
            .expect("the device");
        assert!(recorded.expired_at_ms.is_none(), "no end was written");
        assert!(!lifetimes.pending_expiry().is_owed(expiring.device_id));

        // The control: the owner's word ends the lost continuity, and the grant stands on its
        // anchor again.
        floor.establish_continuity();
        assert!(lifetimes.in_force(&expiring).expect("decided"));
        assert!(lifetimes.in_force_now(expiring.device_id, &expiring.grant));
    }

    /// A lifetime derived in this boot is measured from the reading published in the host's floor,
    /// not from the raw sample: when another process has published a later reading, the grant has
    /// that much less left.
    #[test]
    fn a_derived_lifetime_is_measured_from_the_published_reading() {
        let now = kr_ipc::now_ms().get();
        let expiry = GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now + 60_000),
        };
        for (raised, holds_after_31_seconds) in [(true, false), (false, true)] {
            let devices = Arc::new(DeviceDirectory::in_memory().expect("a directory"));
            let device = owner(6, expiry);
            devices.commit(&device).expect("the device");
            let floor = Arc::new(UtcFloor::default());
            if raised {
                // Another process read the clock thirty seconds ahead of this one.
                floor.observe(now + 30_000);
            }
            let clock = ManualClock::new();
            let lifetimes = GrantLifetimes::new(
                Arc::clone(&devices),
                Arc::new(clock.clone()),
                Arc::new(ManualSharedClock::new()),
                kr_ipc::identity::boot_identity().expect("a boot identity"),
                crate::service::WallClock::from_fn(move || now),
                Arc::clone(&floor),
            );
            assert!(lifetimes.in_force(&device).expect("decided"));
            clock.advance(Duration::from_secs(31));
            assert_eq!(
                lifetimes.in_force_now(device.device_id, &device.grant),
                holds_after_31_seconds,
                "raised: {raised}"
            );
        }
    }
}
