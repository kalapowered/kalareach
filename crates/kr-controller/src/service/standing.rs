//! Whether a grant stands now: membership leases, grant lifetimes and lapses, the clock floor.

use kr_protocol::scalars::{CanonicalSet, TimestampMs};

use crate::error::{ControllerError, Result};

use super::{Controller, net};

/// Whether a device may present a membership lease for an organisation
/// ([`Controller::present_membership_lease`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// It holds a live grant that requires the organisation, and its pairing stands.
    Holds,
    /// It does not.
    Lacks,
    /// A lapse decides it, and the clock floor that lapse was found on is not on disk yet.
    Unrecorded,
}

/// Whose clock anchor holds a grant's end on the continuous clock when it is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Anchor {
    /// This host's own record of the grant, anchored the first time anything asks.
    Host,
    /// The connection that presents the grant, which anchored it when it was admitted and checks
    /// it before every request.
    Connection,
}

impl Controller {
    /// Arms the pause a lease presentation stops at once it has read the clock, before it waits
    /// for the policy's lock. Returns the end that says the presentation has arrived, and the end
    /// that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_presentation_before_lock(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.before_presentation_lock.arm()
    }

    /// Decides a membership lease a device presents to this host, and installs it when it is new.
    ///
    /// A paired device presents on its pairing's standing: paired, and its grant in force on both
    /// clocks. The device has to hold a live grant on this host that requires the lease's
    /// organisation: its pairing grant, or a redeemed grant naming it as recipient that is neither
    /// revoked nor expired. Both are decided under the policy's lock, which is held until the lease
    /// is published; a revocation records the device revoked before it removes the device's
    /// bindings under the same lock, so a presentation either finds the device revoked or makes a
    /// binding the revocation then removes. Everything the lease itself states is then
    /// [`crate::grants::HostPolicy::install_lease`]'s, at this host's reading of UTC while its
    /// clock is trusted and on the continuous clock every deadline here is measured on. The first
    /// lease a device presents in an organisation binds it to that lease's account and key; a lease
    /// for another member on a bound device is refused, and the attempt is logged.
    ///
    /// The lease is decided on a copy of the policy, and the copy is written down before it is
    /// published, so a lease's record and a new binding are on disk before anything decides from
    /// them; a binding is written in the same transaction as its retained event. A repeat that
    /// binds nothing writes nothing and publishes nothing. An expired lease is answered as expired
    /// only once the floor it was found expired on is written down.
    ///
    /// `proven_key` is the authorisation key the presenting connection proved.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the device's grants, the clock's record or the policy cannot be
    /// read or written; nothing is installed or bound then. A lease a rule refuses is the inner
    /// error.
    pub fn present_membership_lease(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        proven_key: &kr_protocol::scalars::AuthorisationKey,
        lease: &kr_protocol::account::MembershipLease,
    ) -> Result<
        std::result::Result<
            crate::grants::organisation::LeaseInstalled,
            crate::grants::LeaseRefused,
        >,
    > {
        use crate::grants::LeaseRefused;
        use crate::grants::organisation::{LeaseChange, LeasePresentation};

        let organisation_id = lease.payload.organisation_id;
        let reading = self.lifetimes.clock_trust().sample(&self.devices)?;
        #[cfg(feature = "testing")]
        self.before_presentation_lock.wait();
        let mut held = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The lease is judged at a reading no older than the lock it is decided under: a fresh
        // one, raised into the floor its judgement reads, so a lease that ran out while this
        // waited is found run out.
        self.settled_utc_now();
        match self.organisation_standing(device_id, organisation_id)? {
            Standing::Holds => {}
            Standing::Lacks => return Ok(Err(LeaseRefused::NoOrganisationGrant)),
            Standing::Unrecorded => return Ok(Err(LeaseRefused::FloorUnrecorded)),
        }
        let mut candidate = held.clone();
        let installed = match candidate.install_lease(LeasePresentation {
            lease,
            device_id,
            proven_key,
            reading,
            now: self.clock.now(),
            generation: self.generation,
        }) {
            Ok(installed) => installed,
            Err(LeaseRefused::Expired) => {
                // The clock decided it, so it is answered only once the floor it stood on is on
                // disk: a clock wound back before the next start would otherwise decide the other
                // way.
                let floor = held.utc_floor_ms();
                self.sharing.grants().record_floor(&held);
                return Ok(Err(if self.utc_floor.written() < floor {
                    LeaseRefused::FloorUnrecorded
                } else {
                    LeaseRefused::Expired
                }));
            }
            Err(refused) => {
                if refused == LeaseRefused::AccountMismatch {
                    eprintln!(
                        "kr-controller: device {device_id} presented a lease for another member of \
                         an organisation than the one it is bound to"
                    );
                }
                return Ok(Err(refused));
            }
        };
        if !installed.bound && installed.change == LeaseChange::Repeat {
            return Ok(Ok(installed));
        }
        let snapshot = candidate.snapshot();
        let binding = installed
            .bound
            .then(|| {
                candidate
                    .enrolment(organisation_id)
                    .and_then(|enrolment| enrolment.binding(device_id))
            })
            .flatten();
        match binding {
            Some(binding) => self.sharing.grants().store_policy_with_event(
                &snapshot,
                &crate::grants::store::BindingEvent {
                    organisation_id,
                    device_id,
                    account_id: binding.account_id.clone(),
                    device_key: binding.device_key,
                    lease_digest: binding.lease_digest,
                    bound_at_ms: binding.bound_at_ms,
                },
            )?,
            None => self.sharing.grants().store_policy(&snapshot)?,
        }
        self.utc_floor.wrote(snapshot.utc_floor_ms.get());
        // The lease's snapshot in its cell, under the policy's lock, before the policy holding it
        // is put in force.
        candidate.publish_leases(&held);
        *held = candidate;
        // Published with the policy, under its lock, as every change of the policy is.
        self.advance_authority_epoch();
        Ok(Ok(installed))
    }

    /// Whether `device_id` may present a lease for `organisation_id`, decided while the caller holds
    /// the policy's lock.
    ///
    /// A paired device needs its pairing to stand: paired, and its grant in force on both clocks
    /// (UTC through this host's floor, the continuous clock through the grant's anchor in this
    /// boot). Then it needs a live grant that requires the organisation: its pairing grant, or a
    /// redeemed grant naming it as recipient that is not revoked and is in force on both clocks by
    /// its own anchor, and has no end on record. An end found here is written down before it is
    /// answered, and answered as unrecorded until it is.
    fn organisation_standing(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        organisation_id: kr_protocol::ids::OrganisationId,
    ) -> Result<Standing> {
        use net::lifetimes::GrantStanding;

        let requires = |grant: &kr_protocol::grant::Grant| {
            grant
                .organisation
                .as_ref()
                .is_some_and(|requirement| requirement.organisation_id == organisation_id)
        };
        if let Some(record) = self.devices.record_for_device(device_id)? {
            if !record.is_paired() {
                return Ok(Standing::Lacks);
            }
            match self.lifetimes.paired_standing(&record)? {
                GrantStanding::InForce => {}
                GrantStanding::OutOfForce => return Ok(Standing::Lacks),
                GrantStanding::Unrecorded => return Ok(Standing::Unrecorded),
            }
            if requires(&record.grant) {
                return Ok(Standing::Holds);
            }
        }
        let grants = self.sharing.grants();
        let mut unrecorded = false;
        for stored in grants.records_for_device(device_id)? {
            if stored.revoked_at_ms.is_some() || !stored.is_active() || !requires(&stored.grant) {
                continue;
            }
            match self.lifetimes.stored_standing(grants, &stored)? {
                GrantStanding::InForce => return Ok(Standing::Holds),
                GrantStanding::OutOfForce => {}
                GrantStanding::Unrecorded => unrecorded = true,
            }
        }
        Ok(if unrecorded {
            Standing::Unrecorded
        } else {
            Standing::Lacks
        })
    }

    /// A grant's own bound in this boot, anchoring it the first time anything asks: a grant in the
    /// grant store through that store, a paired device's pairing grant through its record. A grant
    /// neither holds is not this host's, and nothing is in force under it.
    fn grant_anchor(
        &self,
        record: &crate::grants::GrantRecord,
    ) -> Result<net::lifetimes::Anchored> {
        // A grant that does not expire has no deadline on either clock.
        if record.grant.expiry == kr_protocol::grant::GrantExpiry::Never {
            return Ok(net::lifetimes::Anchored::Unlimited);
        }
        let grants = self.sharing.grants();
        if let Some(stored) = grants.record(record.grant.grant_id)? {
            return self.lifetimes.stored(grants, &stored);
        }
        match self
            .devices
            .devices()?
            .into_iter()
            .find(|device| device.grant.grant_id == record.grant.grant_id)
        {
            Some(device) => self.lifetimes.paired(&device),
            None => Ok(net::lifetimes::Anchored::Over),
        }
    }

    /// Writes down that a grant ran out on the continuous clock: a stored grant's tombstone in the
    /// grant store, a paired device's in its record, each owed until the write lands. Returns
    /// whether the end is on disk.
    fn note_grant_lapse(&self, record: &crate::grants::GrantRecord) -> bool {
        let grants = self.sharing.grants();
        if matches!(grants.record(record.grant.grant_id), Ok(Some(_))) {
            self.lifetimes.owe_stored_expiry(record.grant.grant_id);
            self.lifetimes.settle_stored(grants);
            !self.lifetimes.stored_expiry_owed(record.grant.grant_id)
        } else {
            let device_id = record.grant.recipient_device_id;
            self.lifetimes
                .pending_expiry()
                .owe(device_id, TimestampMs::new(self.wall_now_ms()));
            self.lifetimes.settle();
            !self.lifetimes.pending_expiry().is_owed(device_id)
        }
    }

    /// The reading this daemon's own requests start from, written down before it is used.
    ///
    /// The later of this machine's clock and the highest reading this host has already decided
    /// from, and the floor rises with it. A clock wound back past a deadline therefore does not
    /// revive a grant this host has already refused. The floor is written down here, before the
    /// caller decides anything from it, so a grant found expired at this reading is found expired
    /// by every later start too.
    ///
    /// A write that fails leaves the floor raised in memory, because a floor only moves forward
    /// and keeping it is the stricter answer, and leaves it owed its record. The reading still
    /// dates what the caller writes: a revocation takes authority away whatever the clock says.
    /// What it no longer does is decide a time bound. Every decision that reads the clock goes
    /// through [`crate::grants::policy::UtcFloor::bound`], which refuses while the floor is owed
    /// its record, so a store that cannot take the floor stops expiry decisions rather than
    /// letting them stand on a floor the next start will not find.
    pub(crate) fn settled_now_ms(&self) -> u64 {
        let now_ms = self.wall_now_ms();
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        policy.observe_utc(now_ms);
        let settled = policy.settled_now(now_ms);
        self.sharing.grants().record_floor(&policy);
        settled
    }

    /// Writes the clock floor down when a decision taken on it is still owed that record.
    ///
    /// Nothing is written when nothing is owed, so the ordinary decision costs no write. A write
    /// that fails leaves the debt for the next caller: every decision on the floor tries again,
    /// and so does the network's record task, so storage that recovers settles it.
    pub(crate) fn write_owed_floor(
        &self,
        policy: &std::sync::MutexGuard<'_, crate::grants::HostPolicy>,
    ) {
        if !self.utc_floor.is_owed() {
            return;
        }
        // The floor as it stands is never below what is owed: the debt was taken from it, and it
        // only rises.
        let snapshot = policy.snapshot();
        match self.sharing.grants().store_policy(&snapshot) {
            Ok(()) => self.utc_floor.wrote(snapshot.utc_floor_ms.get()),
            Err(error) => eprintln!(
                "kr-controller: could not record the clock floor this host decided from: {error}"
            ),
        }
    }

    /// This host's reading of UTC for a caller that cannot wait: the later of the wall clock and
    /// the policy's floor.
    ///
    /// The reading raises the floor, so whatever the caller decides from it holds for every later
    /// decision. It never waits, so it may be called from inside a poll.
    pub(crate) fn settled_utc_now(&self) -> u64 {
        self.utc_floor.observe(self.wall_now_ms())
    }

    /// The wall clock this daemon reads UTC on, in milliseconds. A decision raises the floor with
    /// the reading before it stands on it ([`Self::settled_utc_now`]).
    pub(crate) fn wall_now_ms(&self) -> u64 {
        self.wall.now_ms()
    }

    /// Records a lapse found at `at_ms`: this host's reading of UTC is at least that from here
    /// on, and a floor that says so is owed its record.
    ///
    /// It never waits, so a poll may call it. The record is written by the next caller that can
    /// write: the relay once its batch is refused, the next decision, or the network's record
    /// task. What is owed is the moment itself, so a lapse found again once it is written down
    /// owes nothing more.
    pub(crate) fn keep_lapse(&self, at_ms: u64) {
        self.utc_floor.observe(at_ms);
        self.utc_floor.owe(at_ms);
    }

    /// The epoch a paired device's authority is decided at now.
    pub(crate) fn authority_epoch(&self) -> u64 {
        self.authority_epoch
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Moves the epoch, after a change to something a paired device's authority is decided from.
    pub(crate) fn advance_authority_epoch(&self) {
        self.authority_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Writes down a clock floor still owed its record, and the time the offline bound has spent
    /// when that is owed, for a caller holding no decision of its own.
    pub(crate) fn settle_floor(&self) {
        let policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.write_owed_floor(&policy);
        if self.lifetimes.offline_time_owed() {
            self.lifetimes.write_offline_time(&policy);
        }
    }

    /// Decides whether the grant a workflow names stands for one of its dispatches, the way a
    /// paired device's request is decided.
    ///
    /// The grant is narrowed to the rights this host's configuration lets a grant carry before
    /// anything else is decided, then intersected with this host's policy
    /// ([`crate::grants::standing_at_dispatch`]). A holder that reaches this host over the network
    /// under a personal grant is held to the bounded offline validity on the continuous clock the
    /// bound was anchored on as well as in UTC, so a wall clock wound back after the bound ran out
    /// does not bring it back, and a lapse found there is written down as a device's is.
    ///
    /// `now_ms` is the wall clock as the caller read it at `read_at` on the continuous clock. A
    /// workflow runs unattended, so nothing that reads the clock is decided while the clock floor
    /// is still owed its record: that write is made first, and while it cannot be, the answer is
    /// that authority is unavailable. A personal grant that never expires, under no time bound of
    /// this host's policy, reads no clock and is decided as before
    /// ([`crate::grants::HostPolicy::stands_on_the_clock`]). Every wait is therefore over before the decision, and the
    /// decision is taken at the caller's reading advanced by the time those waits took, so a
    /// deadline that passed while this waited for the policy or for storage is decided as passed.
    /// Nothing waits between a permission and the caller's use of it. A refusal the clock decided
    /// owes its own floor, and is answered only once that is written.
    ///
    /// # Errors
    ///
    /// Returns [`kr_automation::AutomationError::PermissionDenied`] naming the rule that refused,
    /// and [`kr_automation::AutomationError::AuthorityUnavailable`] while a floor a refusal stood on
    /// cannot be written down.
    pub(crate) fn decide_for_workflow(
        &self,
        record: &crate::grants::GrantRecord,
        ingress: kr_protocol::actor::ActorIngress,
        now_ms: u64,
        read_at: kr_transport::clock::ContinuousInstant,
    ) -> kr_automation::Result<CanonicalSet<kr_protocol::rights::ActionRight>> {
        self.decide_standing(record, ingress, now_ms, read_at, Anchor::Host)
            .map(|intersection| intersection.rights)
    }

    /// Decides whether a paired device's pairing grant stands under this host's policy, for a
    /// request decided under a share the device holds, and returns what it was decided under.
    ///
    /// The same decision as [`Self::decide_for_workflow`], except that the grant's own end on the
    /// continuous clock is the connection's: it anchored the deadline when it was admitted and
    /// checks it before every request, so this neither reads the grant store nor the device
    /// directory again while the policy is locked. What comes back carries the membership lease
    /// and the bounded offline validity the grant stands under, which bound the request as they
    /// bound one decided under the pairing grant itself.
    ///
    /// # Errors
    ///
    /// As [`Self::decide_for_workflow`].
    pub(crate) fn decide_pairing_standing(
        &self,
        record: &crate::grants::GrantRecord,
        now_ms: u64,
        read_at: kr_transport::clock::ContinuousInstant,
    ) -> kr_automation::Result<crate::grants::policy::PolicyIntersection> {
        self.decide_standing(
            record,
            kr_protocol::actor::ActorIngress::PairedDevice,
            now_ms,
            read_at,
            Anchor::Connection,
        )
    }

    /// The decision behind [`Self::decide_for_workflow`] and [`Self::decide_pairing_standing`].
    fn decide_standing(
        &self,
        record: &crate::grants::GrantRecord,
        ingress: kr_protocol::actor::ActorIngress,
        now_ms: u64,
        read_at: kr_transport::clock::ContinuousInstant,
        anchor: Anchor,
    ) -> kr_automation::Result<crate::grants::policy::PolicyIntersection> {
        let grant_id = record.grant.grant_id;
        let unwritten = || {
            kr_automation::AutomationError::AuthorityUnavailable(
                crate::grants::FLOOR_UNRECORDED.to_owned(),
            )
        };
        let ceiling = self
            .rights_ceiling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // The ceiling narrows the grant itself, as it does before a device's request is decided: a
        // right this host's configuration removed is not one the workflow may use, whatever the
        // grant was issued with.
        let narrowed = ceiling.map(|ceiling| crate::grants::GrantRecord {
            grant: kr_protocol::grant::Grant {
                actions: record
                    .grant
                    .actions
                    .iter()
                    .copied()
                    .filter(|right| ceiling.contains(right))
                    .collect(),
                ..record.grant.clone()
            },
            ..record.clone()
        });
        let record = narrowed.as_ref().unwrap_or(record);
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.write_owed_floor(&policy);
        if self.utc_floor.is_owed() && policy.stands_on_the_clock(&record.grant, ingress) {
            return Err(unwritten());
        }
        // The grant's own bound in this boot, anchored the first time anything asks, on the floor
        // just written. It is read against the continuous clock after every wait.
        let anchored = match anchor {
            Anchor::Host => Some(self.grant_anchor(record).map_err(|error| match error {
                ControllerError::ClockUntrusted { detail } => {
                    kr_automation::AutomationError::PermissionDenied(format!(
                        "grant {grant_id}: {detail}"
                    ))
                }
                other => kr_automation::AutomationError::AuthorityUnavailable(other.to_string()),
            })?),
            Anchor::Connection => None,
        };
        // The decision stands on a reading no older than the lock it is taken under: the caller's,
        // carried forward by the time it waited on the continuous clock, and never earlier than
        // the wall clock read now.
        let waited = self.clock.now().saturating_duration_since(read_at);
        let now_ms = now_ms
            .saturating_add(u64::try_from(waited.as_millis()).unwrap_or(u64::MAX))
            .max(self.wall_now_ms());
        let decided = crate::grants::standing_at_dispatch(
            record,
            &mut policy,
            self.paths.environment_id(),
            ingress,
            now_ms,
            self.clock.now(),
        );
        // Its anchor on the continuous clock, read now: a grant that ran out there is refused
        // whatever the wall clock says, once its end is written down. Until then authority is
        // unavailable, because a daemon started in a new boot, where this anchor means nothing,
        // could find the grant in force by UTC.
        let decided = match decided {
            Ok(_) if anchored.is_some_and(|anchored| !anchored.holds_at(self.clock.now())) => {
                if !self.note_grant_lapse(record) {
                    return Err(unwritten());
                }
                Err(crate::grants::Refusal::Expired {
                    expired_at_ms: match record.grant.expiry {
                        kr_protocol::grant::GrantExpiry::At { expires_at_ms } => {
                            expires_at_ms.get()
                        }
                        kr_protocol::grant::GrantExpiry::Never => now_ms,
                    },
                })
            }
            decided => decided,
        };
        // The offline bound the decision loaded, held to its continuous end as well, as a paired
        // device's request is: run out on the clock that cannot be wound back, it is refused, and
        // the time it spent is written down.
        let decided = match decided {
            Ok(intersection)
                if self.lifetimes.offline_bound_ended(
                    intersection.offline.as_ref(),
                    self.clock.now(),
                    &policy,
                ) =>
            {
                Err(crate::grants::Refusal::OfflineValidityLapsed {
                    last_synchronised_at_ms: policy
                        .offline_validity()
                        .and_then(|offline| offline.last_synchronised_at_ms.as_ref())
                        .map(|at| at.get()),
                })
            }
            decided => decided,
        };
        decided.map_err(|refusal| {
            if refusal.is_clock_decided() {
                // A refusal the clock decided is one a clock wound back before the next start
                // would otherwise revive, so it is answered only once its floor is on disk.
                let floor = policy.utc_floor_ms();
                self.sharing.grants().record_floor(&policy);
                if self.utc_floor.written() < floor {
                    return unwritten();
                }
            }
            kr_automation::AutomationError::PermissionDenied(format!(
                "grant {grant_id}: {}",
                refusal.detail()
            ))
        })
    }

    /// Runs `effect` while this daemon's registry is held and no fence is owed, for work that
    /// stands on a grant rather than on a connection's admission.
    ///
    /// A workflow node's effect is admitted by the grant its definition names, and the change-set
    /// service asks for that admission around each transaction that commits the effect. A
    /// revocation completes by advancing the authority revision, which takes the registry, so one
    /// that begins while `effect` runs finishes after it; `effect` reads the grant as it stands, so
    /// one that finished before is refused there. Nothing inside `effect` may wait on this daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] while a fence is owed, in which case `effect`
    /// did not run.
    pub(crate) async fn hold_registry<T>(&self, effect: impl FnOnce() -> T) -> Result<T> {
        let _registry = self.registry.lock().await;
        self.check_fence()?;
        Ok(effect())
    }
}
