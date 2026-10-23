//! What this host does with a revocation request a remote owner published in its authority feed.
//!
//! Section 10 makes the target host the judge of owner authority: the feed stores the request and
//! decides nothing about who may make it. So the host checks, from its own records, that the
//! request is addressed to it, that the device that signed it is paired, signed what it published
//! and is, now, a device this host would let manage it (decided as a paired device's own call of
//! [`MANAGEMENT_PROBE`] is, by its grant, this host's policy and its configuration), and that it
//! names something this host knows and has not withdrawn. A request that passes is carried out as
//! the owner at this machine's own revocation is, through the same barrier, so the revision it
//! takes is the one the registry allocates and the completion it reports is the barrier's.

use kr_client::services::authority::RejectionReason;
use std::sync::Arc;

use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::pairing::{KeyPurpose, RevocationCompletion, RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{KeyId, Nullable, TimestampMs, U64};

use super::Controller;
use super::revocation::Audience;
use crate::config::ceilings::CeilingRefusal;
use crate::error::Result;
use crate::grants::{AccessRequest, GrantRecord, Refusal, StoredRemoval};
use crate::service::net::devices::DeviceRecord;

/// The method whose decision stands for "this device holds `host.manage` at the paired-device
/// door". It is not asked for to list devices.
///
/// `device.revoke` is the owner's at this machine and is not listed for a paired device, so a
/// paired device's right to manage the host cannot be asked of it, and a remote owner's revocation
/// reaches the host through the feed instead. `device.list` is listed at the paired-device door
/// and requires `host.manage` and no other right, so the decision made for it is the grant's
/// rights, its selectors, this host's policy, the ceiling and the clock, and nothing else. A test
/// holds it to that.
pub const MANAGEMENT_PROBE: Method = Method::DeviceList;

/// The most keys a host may name as permitted to remove its feed.
pub const MOST_REMOVAL_KEYS: usize = kr_client::services::authority::MAX_REMOVAL_KEYS;

/// A task that ends when the value that holds it is dropped.
#[derive(Debug)]
pub(crate) struct EndsWithTheDaemon(tokio::task::JoinHandle<()>);

impl Drop for EndsWithTheDaemon {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a request is carried out as: the devices and the grants it names that this host knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    devices: Vec<DeviceId>,
    grants: Vec<GrantId>,
}

/// What this host decided about a request it read from the feed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Judged {
    /// This host will not apply it, for a reason the feed's publisher can read.
    Refuse(RejectionReason),
    /// This host applies it.
    Apply(Plan),
}

/// Whether a paired device may, now, manage this host.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Standing {
    /// It may.
    Holds,
    /// It may not.
    Not,
    /// This host cannot say: the clock reading the decision stands on is not written down, or this
    /// boot's clock is not proven. Nothing about the device decides it, so the pass stops and asks
    /// again, and a device is not named as one that may remove the feed meanwhile.
    Undecided(Refusal),
}

/// What carrying a request out came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Applied {
    /// The revision the registry allocated for it, or the one in force when nothing was withdrawn.
    pub revision: AuthorityRevision,
    /// Whether the dispatch barrier has held for every worker it affected.
    pub completion: RevocationCompletion,
}

/// What carrying out again a request the feed shows complete came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replay {
    /// Nothing more is to be done for the request: what it names is withdrawn here, or its owner is
    /// known and it is not a request this host could have carried out.
    Done,
    /// The request names something live here, and its owner is not one this host knows.
    Unverified,
}

impl Controller {
    /// Judges a request read from the feed: whether this host applies it, and to what.
    ///
    /// # Errors
    ///
    /// Returns an error when the device directory cannot be read.
    pub(crate) fn judge_feed_request(
        &self,
        request: &RevocationRequest,
        now_ms: u64,
    ) -> Result<Judged> {
        let host = self.host_device_id();
        if request.host_device_id != host {
            return Ok(Judged::Refuse(RejectionReason::UnknownTarget));
        }
        let Some(issuer) = self
            .devices
            .record_for_device(request.issuer_device_id)?
            .filter(DeviceRecord::is_paired)
        else {
            return Ok(Judged::Refuse(RejectionReason::NoOwnerAuthority));
        };
        if kr_pairing::grants::verify_revocation_request(request, host, &issuer.authorisation)
            .is_err()
        {
            return Ok(Judged::Refuse(RejectionReason::NoOwnerAuthority));
        }
        match self.standing_to_manage(&issuer, now_ms) {
            Standing::Holds => {}
            Standing::Not => return Ok(Judged::Refuse(RejectionReason::NoOwnerAuthority)),
            Standing::Undecided(Refusal::ClockUnproven) => {
                return Err(crate::grants::continuity_lost());
            }
            Standing::Undecided(refusal) => {
                return Err(crate::error::ControllerError::Storage {
                    operation: "decide who may manage this host",
                    detail: refusal.detail(),
                });
            }
        }
        let plan = self.plan_of(request)?;
        if plan.devices.is_empty() && plan.grants.is_empty() {
            return Ok(Judged::Refuse(RejectionReason::UnknownTarget));
        }
        Ok(Judged::Apply(plan))
    }

    /// Whether `device` may manage this host now, decided as its own call of [`MANAGEMENT_PROBE`]
    /// is: by its grant, this host's policy and the rights ceiling this host's configuration put
    /// in force.
    ///
    /// Two things differ. A bounded offline validity is what stops personal remote access while
    /// the authority feed cannot be reached, and the caller has just read the feed, so the bound is
    /// left out of this decision; and the refusal a withdrawal the host cannot verify puts on remote
    /// grants is left out, because the feed is how a known owner reaches the host then. Everything
    /// else, the rights, the selectors, an organisation's lease, an exclusive management, the
    /// ceiling and the clock, is decided as it is for the device's own request.
    fn standing_to_manage(&self, device: &DeviceRecord, now_ms: u64) -> Standing {
        let ceiling = self
            .rights_ceiling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // A device whose grant, narrowed by this host's ceiling, holds no right to manage this host
        // is turned away whatever the clock says. Asking the clock first would leave the pass
        // unable to say anything about it while the clock is unproven, and stop every request
        // behind it for a device that could never have been heard.
        if !device.grant.actions.contains(&ActionRight::HostManage)
            || ceiling
                .as_ref()
                .is_some_and(|ceiling| !ceiling.contains(&ActionRight::HostManage))
        {
            return Standing::Not;
        }
        let record = GrantRecord {
            grant: device.grant.clone(),
            session_id: None,
            issued_at_ms: device.paired_at_ms.get(),
            activated_at_ms: Some(device.paired_at_ms.get()),
            revoked_at_ms: device.revoked_at_ms.map(|at| at.get()),
            revoked_by_parent: None,
        };
        let request = AccessRequest {
            method: MANAGEMENT_PROBE,
            ingress: ActorIngress::PairedDevice,
            environment_id: self.paths().environment_id(),
            session_id: None,
            claims_geometry: false,
            own_subject: None,
            now_ms: now_ms.max(self.wall_now_ms()),
            continuous_now: self.clock.now(),
        };
        let live = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A floor still owed its record is written before anything is decided on it.
        self.write_owed_floor(&live);
        let mut policy = live.clone();
        policy.set_offline_validity(None);
        // A withdrawal the host cannot verify refuses remote grants, and a device that manages the
        // host acts by this decision on the feed it reads, which the refusal does not close.
        policy.set_withdrawal_unverified(false);
        let decided = crate::config::ceilings::decide_with_ceiling(
            ceiling.as_ref(),
            &device.grant,
            &record,
            &mut policy,
            request,
        );
        match decided {
            Ok(_) => Standing::Holds,
            Err(CeilingRefusal::RemovedByConfiguration { .. }) => Standing::Not,
            Err(CeilingRefusal::Refused(refusal)) => {
                if refusal.is_clock_decided() {
                    // A refusal the clock decided stands only once the floor it stood on is on
                    // disk: before that, a clock wound back before the next start would decide
                    // the other way.
                    let floor = live.utc_floor_ms();
                    self.sharing.grants().record_floor(&live);
                    if self.utc_floor.written() < floor {
                        return Standing::Undecided(Refusal::FloorUnrecorded);
                    }
                }
                match refusal {
                    Refusal::FloorUnrecorded
                    | Refusal::ExpiryUnrecorded { .. }
                    | Refusal::ClockUnproven => Standing::Undecided(refusal),
                    _ => Standing::Not,
                }
            }
        }
    }

    /// What a request names that this host knows.
    ///
    /// A grant a paired device holds in its pairing record is revoked by revoking the device,
    /// because the grant store has no row for it.
    ///
    /// # Errors
    ///
    /// Returns an error when the device directory or the grant store cannot be read.
    pub(crate) fn plan_of(&self, request: &RevocationRequest) -> Result<Plan> {
        let held = self.devices.devices()?;
        let mut plan = Plan {
            devices: Vec::new(),
            grants: Vec::new(),
        };
        match &request.target {
            RevocationTarget::Devices { device_ids } => {
                plan.devices = device_ids
                    .iter()
                    .copied()
                    .filter(|id| held.iter().any(|record| record.device_id == *id))
                    .collect();
            }
            RevocationTarget::Grants { grant_ids } => {
                for grant_id in grant_ids.iter().copied() {
                    if let Some(record) =
                        held.iter().find(|record| record.grant.grant_id == grant_id)
                    {
                        if !plan.devices.contains(&record.device_id) {
                            plan.devices.push(record.device_id);
                        }
                    } else if self.sharing.grants().record(grant_id)?.is_some() {
                        plan.grants.push(grant_id);
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Carries a plan out through the same revocations the owner at this machine makes.
    ///
    /// A revocation of what is already revoked withdraws nothing and advances no revision, so a
    /// plan carried out twice is carried out once, and the second time reports the barrier as it
    /// stands.
    ///
    /// # Errors
    ///
    /// Returns an error when a revocation cannot be written or the barrier cannot be raised.
    pub(crate) async fn apply_feed_plan(&self, plan: &Plan) -> Result<Applied> {
        // The carrier does not wake itself with the revocations it makes: the scope is the plan's,
        // so no caller can carry a plan out without it.
        crate::authority_feed::CARRYING_OUT
            .scope((), self.apply_feed_plan_unwoken(plan))
            .await
    }

    async fn apply_feed_plan_unwoken(&self, plan: &Plan) -> Result<Applied> {
        let mut revision = self.authority_revision().await?;
        let mut pending = 0_u64;
        for device_id in &plan.devices {
            let result = self.revoke_device_authority(*device_id, None, None).await?;
            revision = revision.max(result.authority_revision);
            pending += result.barrier.pending().len() as u64;
        }
        for grant_id in &plan.grants {
            let result = self
                .revoke_grant(*grant_id, Audience::Host, None, None)
                .await?;
            revision = revision.max(result.authority_revision);
            pending += result.barrier.pending().len() as u64;
        }
        Ok(Applied {
            revision,
            completion: if pending == 0 {
                RevocationCompletion::Complete
            } else {
                RevocationCompletion::Pending {
                    pending_workers: U64::new(pending),
                }
            },
        })
    }

    /// The identifiers of the keys this host names to its feed as permitted to remove it: the
    /// owners it is paired with, the oldest pairings first, up to what the feed takes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device directory cannot be read.
    pub(crate) fn owner_key_ids(&self) -> Result<(Vec<KeyId>, usize)> {
        let now_ms = self.wall_now_ms();
        let mut owners: Vec<_> = self
            .devices
            .devices()?
            .into_iter()
            .filter(|record| {
                record.is_paired() && self.standing_to_manage(record, now_ms) == Standing::Holds
            })
            .collect();
        owners.sort_by_key(|record| (record.paired_at_ms, record.device_id));
        let beyond = owners.len().saturating_sub(MOST_REMOVAL_KEYS);
        let named = owners
            .into_iter()
            .take(MOST_REMOVAL_KEYS)
            .map(|record| {
                kr_crypto::keys::key_id(KeyPurpose::Authorisation, record.authorisation.as_bytes())
            })
            .collect();
        Ok((named, beyond))
    }

    /// The stored-envelope key of the paired device `device`, when its pairing is in force and the
    /// key is recorded: the key an announcement to that device is sealed to.
    ///
    /// # Errors
    ///
    /// Returns an error when the device directory cannot be read.
    pub(crate) fn paired_stored_envelope_key(
        &self,
        device: DeviceId,
    ) -> Result<Option<kr_protocol::scalars::StoredEnvelopeKey>> {
        Ok(self
            .devices
            .record_for_device(device)?
            .filter(DeviceRecord::is_paired)
            .and_then(|record| record.stored_envelope))
    }

    /// Writes the feed's record down when anything in it is unwritten, so a host that stops
    /// anywhere finds it as it was, and a write that failed is made again by the next caller.
    pub(super) fn keep_feed(&self, feed: &mut crate::grants::AuthorityFeed) -> Result<()> {
        if !feed.is_unwritten() {
            return Ok(());
        }
        self.sharing.grants().store_feed(&feed.snapshot())?;
        feed.written();
        Ok(())
    }

    /// What this host holds of one request it took from the feed.
    pub(crate) fn authority_feed_record(
        &self,
        request_id: kr_protocol::ids::RevocationRequestId,
    ) -> Option<crate::grants::feed::RetainedRevocation> {
        self.authority_feed().record(request_id).cloned()
    }

    /// Writes down that this host begins to apply a request, before it does.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is not one this host may take or the record cannot be
    /// written.
    pub(crate) async fn authority_feed_begin(
        &self,
        request: RevocationRequest,
        origin: &str,
        previous: AuthorityRevision,
        now_ms: u64,
    ) -> Result<crate::grants::feed::RetainedRevocation> {
        let registry = self.authority_revision().await?;
        let mut feed = self.authority_feed();
        let held = feed
            .begin(
                request,
                crate::grants::feed::Basis {
                    origin,
                    previous,
                    registry,
                    at_ms: now_ms,
                },
            )
            .map_err(|refusal| {
                crate::error::ControllerError::InvalidArgument(format!(
                    "the feed's request cannot be taken: {refusal:?}"
                ))
            })?
            .clone();
        self.keep_feed(&mut feed)?;
        Ok(held)
    }

    /// Stops the carrier of the authority feed where a request has been carried out and not yet
    /// written down as having taken effect. Returns the end that says it has arrived, and the end
    /// that lets it go. For a suite that stops the daemon there.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn pause_after_a_feed_request_was_carried_out(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_a_feed_request_was_carried_out.arm()
    }

    /// Waits here when a suite armed the pause above.
    #[cfg(feature = "testing")]
    pub(crate) async fn feed_request_was_carried_out(&self) {
        self.after_a_feed_request_was_carried_out.wait().await;
    }

    /// Writes down the revision a request took effect under.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written or does not hold the request.
    pub(crate) fn authority_feed_took_effect(
        &self,
        request_id: kr_protocol::ids::RevocationRequestId,
        revision: AuthorityRevision,
    ) -> Result<crate::grants::feed::RetainedRevocation> {
        let mut feed = self.authority_feed();
        feed.took_effect(request_id, revision);
        self.keep_feed(&mut feed)?;
        feed.record(request_id).cloned().ok_or_else(|| {
            crate::error::ControllerError::InvalidArgument(
                "the request was not written down before it took effect".to_owned(),
            )
        })
    }

    /// Writes down that this host refuses a request it began to take, before it says so to the
    /// feed.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub(crate) fn authority_feed_refusal_noted(
        &self,
        request_id: kr_protocol::ids::RevocationRequestId,
        host: DeviceId,
    ) -> Result<()> {
        let mut feed = self.authority_feed();
        feed.note_refusal(request_id, host);
        self.keep_feed(&mut feed)
    }

    /// Writes down that this host has nothing more to do for a request the feed holds: it was
    /// acknowledged as complete.
    pub(crate) fn authority_feed_settled(
        &self,
        request_id: kr_protocol::ids::RevocationRequestId,
        host: DeviceId,
    ) {
        let mut feed = self.authority_feed();
        feed.acknowledge(request_id, host);
        if let Err(error) = self.keep_feed(&mut feed) {
            eprintln!("kr-controller: could not write the authority feed's record down: {error}");
        }
    }

    /// Writes down a successful synchronisation, and, for a host under a bounded offline-validity
    /// policy, extends the bound from it.
    pub(crate) fn authority_feed_synchronised(&self) {
        let now = self.wall_now_ms();
        {
            let mut feed = self.authority_feed();
            feed.synchronised(now);
            if let Err(error) = self.keep_feed(&mut feed) {
                eprintln!(
                    "kr-controller: could not write the authority feed's record down: {error}"
                );
            }
        }
        if self.policy().offline_validity().is_some()
            && let Err(error) = self.update_policy(|policy| policy.note_feed_synchronised(now))
        {
            eprintln!(
                "kr-controller: could not extend the bounded offline validity from the feed: \
                 {error}"
            );
        }
    }

    /// Notes that the feed could not be reached or read through, so what is shown is stale.
    pub(crate) fn authority_feed_unreachable(&self) {
        self.authority_feed().unreachable();
    }

    /// Refuses the grants that rest on the authority feed, from this moment: an organisation's
    /// lease, and personal remote access under a bounded offline-validity policy or on a host
    /// that is exclusively organisation-managed. A restriction does not wait for its record to be
    /// written, so a registry that cannot take a write restricts all the same.
    fn refuse_the_grants_that_rest_on_the_feed(&self) {
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !policy.feed_removed() {
            policy.set_feed_removed(true);
            self.advance_authority_epoch();
        }
    }

    /// Compares the revision the authority feed holds for this host with the registry's, and
    /// refuses every grant but the owner's at this machine from this moment when the feed is
    /// ahead. Returns whether the host is behind its feed: now, or since an earlier comparison
    /// that has not been lifted ([`Self::authority_feed_caught_up`]).
    ///
    /// A registry restored together with its mirror is one earlier state this host accepts, and
    /// the feed is the one record outside both that still holds the highest revision the host
    /// issued. Nothing is stored for the refusal: a start or a pass compares again.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(crate) async fn authority_feed_behind(&self, feed_revision: u64) -> Result<bool> {
        let registry = self.authority_revision().await?;
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if feed_revision > registry.get() && !policy.behind_its_feed() {
            policy.set_behind_its_feed(true);
            drop(policy);
            self.advance_authority_epoch();
            return Ok(true);
        }
        Ok(policy.behind_its_feed())
    }

    /// Carries out again a request the feed shows this host completed, for what the registry does
    /// not show withdrawn: a registry restored to a state from before it was carried out, or put
    /// back to one whose counter stands at the feed's, has lost it.
    ///
    /// The feed is not trusted to say that this host approved a request, so only a request this host
    /// could have carried out is: one an owner signed with a key the registry holds for a device
    /// whose pairing grant holds the right to manage this host, and which this host did not refuse.
    /// The owner is the device the request names, or, when the registry holds no such device, the
    /// device that holds the key the request names, which is how an owner paired again is found.
    /// What is already withdrawn is left alone, so a request the registry shows done raises no
    /// barrier, and carrying one out twice is carrying it out once.
    ///
    /// A request that names a device or grant the registry holds live, and whose owner the registry
    /// does not know at all, can be neither carried out nor dismissed: it comes back as
    /// [`Replay::Unverified`], and the host refuses every grant but the owner's at this machine
    /// until the owner at this machine has revoked what it names or paired the owner again.
    ///
    /// # Errors
    ///
    /// Returns an error when a record cannot be read, a revocation cannot be written or its barrier
    /// cannot be raised.
    pub(crate) async fn replay_feed_request(&self, request: &RevocationRequest) -> Result<Replay> {
        let host = self.host_device_id();
        if request.host_device_id != host {
            return Ok(Replay::Done);
        }
        let named = self.plan_of(request)?;
        let held = self.devices.devices()?;
        let mut plan = Plan {
            devices: named
                .devices
                .into_iter()
                .filter(|id| {
                    held.iter()
                        .any(|record| record.device_id == *id && record.revoked_at_ms.is_none())
                })
                .collect(),
            grants: Vec::new(),
        };
        for grant_id in named.grants {
            if self
                .sharing
                .grants()
                .record(grant_id)?
                .is_some_and(|record| record.revoked_at_ms.is_none())
            {
                plan.grants.push(grant_id);
            }
        }
        if plan.devices.is_empty() && plan.grants.is_empty() {
            return Ok(Replay::Done);
        }
        let issuer = held
            .iter()
            .find(|record| record.device_id == request.issuer_device_id)
            .or_else(|| {
                held.iter().find(|record| {
                    kr_crypto::keys::key_id(
                        KeyPurpose::Authorisation,
                        record.authorisation.as_bytes(),
                    ) == request.issuer_key_id
                })
            });
        let Some(issuer) = issuer else {
            return Ok(Replay::Unverified);
        };
        if !issuer.grant.actions.contains(&ActionRight::HostManage)
            || kr_pairing::grants::verify_revocation_request(request, host, &issuer.authorisation)
                .is_err()
            || self
                .authority_feed_record(request.request_id)
                .is_some_and(|noted| noted.is_refused_by(host))
        {
            return Ok(Replay::Done);
        }
        self.apply_feed_plan(&plan).await?;
        Ok(Replay::Done)
    }

    /// Records whether the feed shows complete a withdrawal this host cannot verify, and moves the
    /// authority epoch when that changes what a remote grant is decided to be.
    pub(crate) fn authority_feed_withdrawal_unverified(&self, unverified: bool) {
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if policy.withdrawal_unverified() != unverified {
            policy.set_withdrawal_unverified(unverified);
            drop(policy);
            self.advance_authority_epoch();
        }
    }

    /// Raises the registry to the revision the feed holds, in one barrier, and then lets the host
    /// decide again: it has applied what the feed shows completed and numbers what it issues next
    /// above everything it has issued.
    ///
    /// # Errors
    ///
    /// Returns the barrier's error. The refusal stands then, and the next pass finds the registry
    /// still behind and does this again.
    pub(crate) async fn authority_feed_caught_up(&self, feed_revision: u64) -> Result<()> {
        self.catch_up_with_the_feed(AuthorityRevision::new(feed_revision))
            .await?;
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if policy.behind_its_feed() {
            policy.set_behind_its_feed(false);
            drop(policy);
            self.advance_authority_epoch();
        }
        Ok(())
    }

    /// Records that the feed at `origin` answered that this host was removed from it: refuses the
    /// grants that rest on the feed at once, writes the removal down, and tells the owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the removal could not be written. The grants are refused whatever
    /// happens, and the caller asks again, so the removal reaches the registry when it can take
    /// it. A notice the attention store cannot take is given again, apart from the carrier. An
    /// attention store that cannot be read does not keep the removal from being written: the
    /// notice is numbered without the store's cursor, and the next start numbers it again if the
    /// cursor stands above it.
    pub(crate) async fn authority_feed_removed(&self, origin: &str) -> Result<()> {
        let now = self.wall_now_ms();
        self.refuse_the_grants_that_rest_on_the_feed();
        // A feed that was removed shows nothing to compare, so it cannot keep a withdrawal unverified.
        self.authority_feed_withdrawal_unverified(false);
        {
            let mut feed = self.authority_feed();
            feed.removed_from(origin, now);
            if let Err(error) = self.keep_feed(&mut feed) {
                eprintln!(
                    "kr-controller: could not write the authority feed's record down: {error}"
                );
            }
        }
        let grants = self.sharing.grants();
        let held = grants.stored_feed_removal()?;
        if held
            .as_ref()
            .is_none_or(|held| held.origin.0.as_deref() != Some(origin))
        {
            // The removal is the one durable record that a restart finds, so it is written whether
            // or not the attention store can be read.
            let notice = match self.next_feed_notice(held.as_ref()).await {
                Ok(notice) => notice,
                Err(error) => {
                    eprintln!("kr-controller: {error}");
                    held.as_ref().map_or(1, |held| held.notice + 1)
                }
            };
            grants.store_feed_removal(&StoredRemoval {
                origin: Nullable::some(origin.to_owned()),
                at_ms: TimestampMs::new(now),
                notice,
            })?;
        }
        self.feed_notice_wake.notify_one();
        if let Err(error) = self.tell_the_owner_of_the_feed().await {
            eprintln!("kr-controller: {error}");
        }
        Ok(())
    }

    /// The number of the newest notice about the feed that the attention store has taken.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read. A notice is not numbered above the cursor
    /// without it: a number at or below the cursor is a notice the store drops.
    async fn feed_notice_cursor(&self) -> Result<u64> {
        #[cfg(feature = "testing")]
        if self
            .notice_cursor_unreadable
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::ControllerError::Storage {
                operation: "read the notices the attention store has taken",
                detail: "the attention store could not be read".to_owned(),
            });
        }
        let attention = Arc::clone(self.attention());
        match tokio::task::spawn_blocking(move || attention.authority_cursor()).await {
            Ok(Ok(taken)) => Ok(taken),
            Ok(Err(refusal)) => Err(crate::error::ControllerError::Storage {
                operation: "read the notices the attention store has taken",
                detail: refusal.message,
            }),
            Err(error) => Err(crate::error::ControllerError::Storage {
                operation: "read the notices the attention store has taken",
                detail: error.to_string(),
            }),
        }
    }

    /// Makes the attention store's cursor unreadable to the numbering of feed notices, as a store
    /// another owner took or a lock that panicked would. For a suite that checks a removal is
    /// written down all the same.
    #[cfg(feature = "testing")]
    pub fn make_the_notice_cursor_unreadable(&self, unreadable: bool) {
        self.notice_cursor_unreadable
            .store(unreadable, std::sync::atomic::Ordering::SeqCst);
    }

    /// The number of the next notice about the feed: above the one this host last recorded and
    /// above every one the attention store has taken, so a registry that lost its row cannot
    /// number a notice behind the store's cursor. A start numbers again a notice that was numbered
    /// without the cursor and stands below it.
    async fn next_feed_notice(&self, held: Option<&StoredRemoval>) -> Result<u64> {
        let taken = self.feed_notice_cursor().await?;
        Ok(held.map_or(0, |held| held.notice).max(taken) + 1)
    }

    /// Puts the authority feed's removal right at start: kept for the origin that answered it,
    /// forgotten for any other, with the item that told the owner ended with it. `selected` is the
    /// feed this host's configuration selects, and `unusable` is whether the document could not be
    /// used: a document that cannot be read is no choice of another feed, so the removal and what
    /// it refuses stand until a start reads one that selects another feed or none.
    ///
    /// Returns whether the feed this host reads removed it.
    pub(crate) async fn authority_feed_at_start(
        &self,
        selected: Option<&str>,
        unusable: bool,
    ) -> Result<bool> {
        let grants = self.sharing.grants();
        let Some(mut held) = grants.stored_feed_removal()? else {
            return Ok(false);
        };
        // A row behind the store's cursor means the registry was put back to an earlier copy than
        // the store: it is numbered again above the cursor, so that the notice it holds is given.
        let taken = self.feed_notice_cursor().await?;
        if taken > held.notice {
            held = StoredRemoval {
                notice: taken + 1,
                ..held
            };
            grants.store_feed_removal(&held)?;
        }
        let mut removed = false;
        match held.origin.0.as_deref() {
            Some(origin) if unusable || selected == Some(origin) => {
                self.authority_feed()
                    .restore_removal(origin, held.at_ms.get());
                self.refuse_the_grants_that_rest_on_the_feed();
                removed = true;
            }
            // The owner pointed the host at another feed, or at none: the removal is no removal
            // from that one, and the notice that ends the owner's item is recorded.
            Some(_) => grants.store_feed_removal(&StoredRemoval {
                origin: Nullable::null(),
                at_ms: TimestampMs::new(self.wall_now_ms()),
                notice: self.next_feed_notice(Some(&held)).await?,
            })?,
            None => {}
        }
        // A notice the attention store cannot take is not a reason to stop the start: it is given
        // again by the task that sees to the notices.
        if let Err(error) = self.tell_the_owner_of_the_feed().await {
            eprintln!("kr-controller: {error}");
        }
        Ok(removed)
    }

    /// Gives the attention store the newest notice about the authority feed, unless the store has
    /// taken it already. Whether it has is the store's own cursor, so a store that was reset or put
    /// back to an earlier copy is given the notice again, and a notice already taken is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or the attention store cannot take the
    /// notice. The next call tries again.
    pub(crate) async fn tell_the_owner_of_the_feed(&self) -> Result<()> {
        let Some(held) = self.sharing.grants().stored_feed_removal()? else {
            return Ok(());
        };
        let kind = if held.origin.0.is_some() {
            kr_attention::EventKind::AuthorityFeedRemoved
        } else {
            kr_attention::EventKind::AuthorityFeedLeft
        };
        let event = kr_attention::SourceEvent::new(
            kr_attention::EventCursor::new(
                kr_protocol::attention::AttentionSource::Authority,
                held.notice,
            ),
            held.at_ms,
            kind,
        );
        let attention = Arc::clone(self.attention());
        let notice = held.notice;
        let given = tokio::task::spawn_blocking(move || -> crate::attention::Answer<()> {
            if attention.authority_cursor()? >= notice {
                return Ok(());
            }
            attention.observe(&[event])
        })
        .await;
        match given {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(crate::error::ControllerError::Storage {
                operation: "tell the owner of the authority feed",
                detail: format!("the attention store could not take the notice: {error}"),
            }),
            Err(error) => Err(crate::error::ControllerError::Storage {
                operation: "tell the owner of the authority feed",
                detail: format!("the task that gives the notice did not finish: {error}"),
            }),
        }
    }

    /// Starts the task that sees to the notices about the authority feed, which runs for as long
    /// as the daemon does whether or not it reads a feed: it gives the newest notice, and gives it
    /// again after a wait for as long as the attention store refuses it. It holds the daemon
    /// weakly, and ends with it.
    pub(crate) fn start_feed_notices(self: &Arc<Self>, timer: Arc<dyn crate::quiet::Timer>) {
        let daemon = Arc::downgrade(self);
        let wake = Arc::clone(&self.feed_notice_wake);
        let task = tokio::spawn(async move {
            let mut backoff = kr_transport::reconnect::Backoff::default();
            loop {
                // Interest is registered before the notice is read, so one recorded in between
                // wakes the wait.
                let woken = wake.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                let Some(controller) = daemon.upgrade() else {
                    return;
                };
                let result = controller.tell_the_owner_of_the_feed().await;
                controller
                    .feed_notice_attempts
                    .send_modify(|attempts| *attempts += 1);
                drop(controller);
                match result {
                    Ok(()) => {
                        backoff = kr_transport::reconnect::Backoff::default();
                        woken.await;
                    }
                    Err(error) => {
                        eprintln!("kr-controller: {error}");
                        tokio::select! {
                            () = &mut woken => {}
                            () = timer.sleep(backoff.next_delay()) => {}
                        }
                    }
                }
            }
        });
        // The task ends with the daemon that holds it, wherever it is waiting.
        let _ = self.feed_notice_task.set(EndsWithTheDaemon(task));
    }

    /// How many times the task that sees to the notices has tried to give one. For a suite that
    /// waits for the next try.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn feed_notice_attempts(&self) -> tokio::sync::watch::Receiver<u64> {
        self.feed_notice_attempts.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::MANAGEMENT_PROBE;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::authority::{AuthorityDecision, RequiredAuthority, RightCondition};
    use kr_protocol::method::MethodVersion;
    use kr_protocol::rights::ActionRight;

    /// The decision that stands for a paired device's right to manage the host is the right and
    /// nothing else: if the method it is asked for stops being listed at the paired-device door,
    /// or starts to require another right or a condition, the feed would turn every owner away or
    /// ask more of one than managing the host. The decision reads only whether the method is
    /// reachable from the door and which rights it requires; a change that makes it read more of
    /// the method's entry needs this test to say so.
    #[test]
    fn the_method_that_stands_for_managing_the_host_requires_that_right_alone_at_the_paired_door() {
        let AuthorityDecision::Listed(entry) = kr_protocol::method::decide(
            MANAGEMENT_PROBE.as_str(),
            MethodVersion::V1,
            ActorIngress::PairedDevice,
        ) else {
            panic!(
                "{} is not listed at the paired-device door",
                MANAGEMENT_PROBE.as_str()
            );
        };
        let required: Vec<_> = entry
            .required_rights
            .iter()
            .map(|required| (required.authority, required.when))
            .collect();
        assert_eq!(
            required,
            vec![(
                RequiredAuthority::Right {
                    right: ActionRight::HostManage
                },
                RightCondition::Always
            )]
        );
    }
}
