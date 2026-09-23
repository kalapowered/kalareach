//! When a paired device's grant runs out, under the host's one time contract.
//!
//! Section 9 measures every expiry the same way: a deadline on the machine's suspend-aware
//! continuous clock, anchored once per device and boot; a wall clock the host decides against only
//! while it has not gone backwards past what the host has already recorded; and a tombstone for
//! every expiry observed, so nothing that ran out comes back. Two parts of the host ask: the
//! network, when it admits a device's connection and bounds what that connection may do, and owner
//! confirmation, when it decides whether the device that answered a challenge is still an owner
//! device. Both ask here, so they cannot disagree about one grant.
//!
//! **Lock order.** A check made inside a transaction on the device directory's connection reads
//! the anchors, so the anchors are never held while anything waits for that connection.
//! Deriving an anchor, which reads and writes the directory, is serialised by a lock of its own
//! that nothing inside a transaction takes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_protocol::grant::GrantExpiry;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::DeviceId;
use kr_protocol::scalars::TimestampMs;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use super::devices::{ClockTrust, DeviceDirectory, DeviceRecord, PendingExpiry};
use crate::error::{ControllerError, Result};

/// When one device's grant runs out.
#[derive(Clone, Copy, Debug)]
pub struct GrantDeadline {
    /// The moment on the continuous clock, absent for a grant that does not expire.
    pub deadline: Option<ContinuousInstant>,
}

/// What one grant's lifetime is, as this host has decided it.
enum Lifetime {
    /// It does not expire.
    Unlimited,
    /// It runs out at this moment on the continuous clock.
    Until(ContinuousInstant),
    /// It has run out, and that is on record or owed to the record.
    Over,
}

/// Every paired device's grant lifetime on this host.
pub struct GrantLifetimes {
    devices: Arc<DeviceDirectory>,
    /// The suspend-aware continuous clock every deadline is measured on.
    clock: Arc<dyn ContinuousClock>,
    /// The machine's boot-scoped clock, which a recorded deadline is written in.
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    boot_identity: BootIdentity,
    /// One anchor per device, shared by every connection and every check that asks about it.
    ///
    /// Anchored the first time anything asks, so a wall clock stepped backwards between two
    /// questions cannot give the same grant a longer life the second time.
    anchored: Mutex<BTreeMap<DeviceId, GrantDeadline>>,
    /// Held while an anchor is derived, and never inside a directory transaction.
    anchoring: Mutex<()>,
    /// Expiry records this host owes its directory and has not yet written.
    pending_expiry: Arc<PendingExpiry>,
    /// Whether this host may decide a grant's expiry from its own wall clock.
    clock_trust: Arc<ClockTrust>,
}

impl std::fmt::Debug for GrantLifetimes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantLifetimes")
            .finish_non_exhaustive()
    }
}

impl GrantLifetimes {
    /// Builds the lifetimes of the devices in `devices`, measured on `clock` in this boot.
    #[must_use]
    pub fn new(
        devices: Arc<DeviceDirectory>,
        clock: Arc<dyn ContinuousClock>,
        shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
        boot_identity: BootIdentity,
    ) -> Self {
        Self {
            devices,
            clock,
            shared_clock,
            boot_identity,
            anchored: Mutex::new(BTreeMap::new()),
            anchoring: Mutex::new(()),
            pending_expiry: Arc::new(PendingExpiry::default()),
            clock_trust: Arc::new(ClockTrust::default()),
        }
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
            Lifetime::Unlimited => Ok(None),
            Lifetime::Until(deadline) => Ok(Some(deadline)),
            Lifetime::Over => Err(ControllerError::PermissionDenied {
                detail: "this device's grant has run out; pair again".to_owned(),
            }),
        }
    }

    /// Returns whether `record`'s grant is in force now.
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
        let deadline = match self.lifetime(record) {
            Ok(Lifetime::Unlimited) => return Ok(true),
            Ok(Lifetime::Until(deadline)) => deadline,
            Ok(Lifetime::Over) | Err(ControllerError::ClockUntrusted { .. }) => return Ok(false),
            Err(error) => return Err(error),
        };
        if self.clock.now() < deadline {
            return Ok(true);
        }
        // Observed here, so it is written here: the tombstone is what a later boot reads, where
        // this boot's deadline means nothing any more.
        let moment = self
            .clock_trust
            .observe(&self.devices)
            .unwrap_or_else(|_| kr_ipc::now_ms());
        self.pending_expiry.owe(record.device_id, moment);
        self.pending_expiry.settle(&self.devices);
        Ok(false)
    }

    /// Returns whether a device's grant is in force now, from memory alone.
    ///
    /// For a check made inside a transaction on the directory's connection, where nothing else may
    /// touch that connection: the anchor was taken before the transaction began, by
    /// [`Self::in_force`] or [`Self::deadline`], and the moment compared with it is read now, after
    /// every wait. An expiring grant with no anchor in this boot is not in force here, because
    /// nothing proves it is. An expiry found here is owed to the record, and written by
    /// [`Self::settle`] or the host's own task.
    #[must_use]
    pub fn in_force_now(&self, device_id: DeviceId, expiry: GrantExpiry) -> bool {
        if matches!(expiry, GrantExpiry::Never) {
            return true;
        }
        let anchored = self.anchored().get(&device_id).copied();
        match anchored {
            Some(GrantDeadline { deadline: None }) => true,
            Some(GrantDeadline {
                deadline: Some(deadline),
            }) => {
                if self.clock.now() < deadline {
                    return true;
                }
                self.pending_expiry.owe(device_id, kr_ipc::now_ms());
                false
            }
            None => false,
        }
    }

    /// Writes down every expiry this host owes its directory, keeping whatever cannot be written.
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

    fn lifetime(&self, record: &DeviceRecord) -> Result<Lifetime> {
        if let Some(anchored) = self.anchored().get(&record.device_id).copied() {
            return Ok(anchored
                .deadline
                .map_or(Lifetime::Unlimited, Lifetime::Until));
        }
        // One derivation at a time, so a device is anchored once and its recorded deadline is
        // written once. The anchors themselves are not held while the directory is read.
        let _anchoring = self
            .anchoring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(anchored) = self.anchored().get(&record.device_id).copied() {
            return Ok(anchored
                .deadline
                .map_or(Lifetime::Unlimited, Lifetime::Until));
        }
        let GrantExpiry::At { expires_at_ms } = record.grant.expiry else {
            self.anchor(record.device_id, None);
            return Ok(Lifetime::Unlimited);
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
            self.pending_expiry.owe(record.device_id, kr_ipc::now_ms());
            self.pending_expiry.settle(&self.devices);
            return Ok(Lifetime::Over);
        }
        let deadline = anchor.checked_add(Duration::from_millis(remaining));
        self.anchor(record.device_id, deadline);
        Ok(deadline.map_or(Lifetime::Unlimited, Lifetime::Until))
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

    fn anchor(&self, device_id: DeviceId, deadline: Option<ContinuousInstant>) {
        self.anchored()
            .entry(device_id)
            .or_insert(GrantDeadline { deadline });
    }

    fn anchored(&self) -> MutexGuard<'_, BTreeMap<DeviceId, GrantDeadline>> {
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
        assert!(lifetimes.in_force_now(device.device_id, device.grant.expiry));
        clock.advance(Duration::from_secs(61));
        assert!(
            !lifetimes.in_force_now(device.device_id, device.grant.expiry),
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
            !lifetimes.in_force_now(expiring.device_id, expiring.grant.expiry),
            "nothing anchored it, so nothing proves it"
        );
        assert!(lifetimes.in_force(&lasting).expect("decided"));
        assert!(lifetimes.in_force_now(lasting.device_id, lasting.grant.expiry));
    }
}
