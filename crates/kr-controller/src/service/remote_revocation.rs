//! What this host does with a revocation request a remote owner published in its authority feed.
//!
//! Section 10 makes the target host the judge of owner authority: the feed stores the request and
//! decides nothing about who may make it. So the host checks, from its own records, that the
//! request is addressed to it, that the device that signed it is paired, signed what it published
//! and is, now, a device this host would let manage it (decided as the same device's own
//! `device.revoke` is, by its grant, this host's policy and its configuration), and that it names
//! something this host knows and has not withdrawn. A request that passes is carried out as the
//! owner at this machine's own revocation is, through the same barrier, so the revision it takes
//! is the one the registry allocates and the completion it reports is the barrier's.

use kr_client::services::authority::RejectionReason;
use std::sync::Arc;

use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::pairing::{KeyPurpose, RevocationCompletion, RevocationRequest, RevocationTarget};
use kr_protocol::scalars::{KeyId, U64};

use super::Controller;
use crate::config::ceilings::CeilingRefusal;
use crate::error::Result;
use crate::grants::{AccessRequest, GrantRecord, Refusal};
use crate::service::net::devices::DeviceRecord;

/// The most keys a host may name as permitted to remove its feed.
pub const MOST_REMOVAL_KEYS: usize = kr_client::services::authority::MAX_REMOVAL_KEYS;

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
    /// Whether the revocation advanced the revision, which is whether it withdrew anything.
    pub changed: bool,
    /// Whether the dispatch barrier has held for every worker it affected.
    pub completion: RevocationCompletion,
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

    /// Whether `device` may manage this host now, decided as its own `device.revoke` is: by its
    /// grant, this host's policy and the rights ceiling this host's configuration put in force.
    ///
    /// One thing differs. A bounded offline validity is what stops personal remote access while
    /// the authority feed cannot be reached, and the caller has just read the feed, so the bound is
    /// left out of this decision. Everything else, the rights, the selectors, an organisation's
    /// lease, an exclusive management, the ceiling and the clock, is decided as it is for the
    /// device's own request.
    fn standing_to_manage(&self, device: &DeviceRecord, now_ms: u64) -> Standing {
        let record = GrantRecord {
            grant: device.grant.clone(),
            session_id: None,
            issued_at_ms: device.paired_at_ms.get(),
            activated_at_ms: Some(device.paired_at_ms.get()),
            revoked_at_ms: device.revoked_at_ms.map(|at| at.get()),
            revoked_by_parent: None,
        };
        let request = AccessRequest {
            method: Method::DeviceRevoke,
            ingress: ActorIngress::PairedDevice,
            environment_id: self.paths().environment_id(),
            session_id: None,
            claims_geometry: false,
            own_subject: None,
            now_ms: now_ms.max(self.wall_now_ms()),
            continuous_now: self.clock.now(),
        };
        let ceiling = self
            .rights_ceiling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let live = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A floor still owed its record is written before anything is decided on it.
        self.write_owed_floor(&live);
        let mut policy = live.clone();
        policy.set_offline_validity(None);
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
        let before = self.authority_revision().await?;
        let mut revision = before;
        let mut pending = 0_u64;
        for device_id in &plan.devices {
            let result = self.revoke_device_authority(*device_id, None, None).await?;
            revision = revision.max(result.authority_revision);
            pending += result.barrier.pending().len() as u64;
        }
        for grant_id in &plan.grants {
            let result = self.revoke_grant(*grant_id, None, None).await?;
            revision = revision.max(result.authority_revision);
            pending += result.barrier.pending().len() as u64;
        }
        Ok(Applied {
            revision,
            changed: revision > before,
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
        let now_ms = kr_ipc::now_ms().get();
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

    /// Writes the feed's record down, so a host that stops anywhere finds it as it was.
    fn keep_feed(&self, feed: &crate::grants::AuthorityFeed) -> Result<()> {
        self.sharing.grants().store_feed(&feed.snapshot())
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
    pub(crate) fn authority_feed_begin(
        &self,
        request: RevocationRequest,
        previous: AuthorityRevision,
        now_ms: u64,
    ) -> Result<crate::grants::feed::Beginning> {
        let mut feed = self.authority_feed();
        let beginning = feed.begin(request, previous, now_ms).map_err(|refusal| {
            crate::error::ControllerError::InvalidArgument(format!(
                "the feed's request cannot be taken: {refusal:?}"
            ))
        })?;
        self.keep_feed(&feed)?;
        Ok(beginning)
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
        self.keep_feed(&feed)?;
        feed.record(request_id).cloned().ok_or_else(|| {
            crate::error::ControllerError::InvalidArgument(
                "the request was not written down before it took effect".to_owned(),
            )
        })
    }

    /// Writes down that this host refuses a request it began to take, before it says so to the feed.
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
        self.keep_feed(&feed)
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
        if let Err(error) = self.keep_feed(&feed) {
            eprintln!("kr-controller: could not write the authority feed's record down: {error}");
        }
    }

    /// Writes down a successful synchronisation, and, for a host under a bounded offline-validity
    /// policy, extends the bound from it.
    pub(crate) fn authority_feed_synchronised(&self) {
        let now = kr_ipc::now_ms().get();
        {
            let mut feed = self.authority_feed();
            feed.synchronised(now);
            if let Err(error) = self.keep_feed(&feed) {
                eprintln!(
                    "kr-controller: could not write the authority feed's record down: {error}"
                );
            }
        }
        if self.policy().offline_validity().is_some()
            && let Err(error) = self.update_policy(|policy| policy.note_feed_synchronised(now))
        {
            eprintln!(
                "kr-controller: could not extend the bounded offline validity from the feed: {error}"
            );
        }
    }

    /// Notes that the feed could not be reached or read through, so what is shown is stale.
    pub(crate) fn authority_feed_unreachable(&self) {
        self.authority_feed().unreachable();
    }

    /// Refuses the grants that rest on the authority feed, from this moment: an organisation's
    /// lease, and personal remote access under a bounded offline-validity policy. A restriction
    /// does not wait for its record to be written, so a registry that cannot take a write
    /// restricts all the same.
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

    /// Records that the feed at `origin` answered that this host was removed from it: refuses the
    /// grants that rest on the feed at once, writes the removal down, and tells the owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the removal or the notice to the owner could not be written. The
    /// grants are refused whatever happens, and the caller asks again, so the removal reaches the
    /// registry when it can take it.
    pub(crate) async fn authority_feed_removed(&self, origin: &str) -> Result<()> {
        let now = kr_ipc::now_ms().get();
        self.refuse_the_grants_that_rest_on_the_feed();
        let removal = {
            let mut feed = self.authority_feed();
            feed.removed_from(origin, now);
            if let Err(error) = self.keep_feed(&feed) {
                eprintln!(
                    "kr-controller: could not write the authority feed's record down: {error}"
                );
            }
            feed.removal()
        };
        let Some(removal) = removal else {
            return Ok(());
        };
        self.sharing.grants().store_feed_removal(Some(&removal))?;
        self.tell_the_owner_of_the_feed(
            kr_attention::EventKind::AuthorityFeedRemoved,
            removal.at_ms.get(),
        )
        .await
    }

    /// Puts the authority feed's removal right at start: kept for the origin that answered it,
    /// forgotten for any other, with the item that told the owner ended with it.
    pub(crate) async fn authority_feed_at_start(&self, configured: Option<&str>) -> Result<bool> {
        let Some(removal) = self.sharing.grants().stored_feed_removal()? else {
            return Ok(false);
        };
        if configured == Some(removal.origin.as_str()) {
            self.authority_feed().restore_removal(&removal);
            self.refuse_the_grants_that_rest_on_the_feed();
            // A notice the attention store cannot take is not a reason to stop the start; the
            // item stands in the inbox from the earlier run.
            if let Err(error) = self
                .tell_the_owner_of_the_feed(
                    kr_attention::EventKind::AuthorityFeedRemoved,
                    removal.at_ms.get(),
                )
                .await
            {
                eprintln!("kr-controller: {error}");
            }
            return Ok(true);
        }
        // The owner pointed the host at another feed, or at none: the removal is no removal from
        // that one.
        self.sharing.grants().store_feed_removal(None)?;
        if let Err(error) = self
            .tell_the_owner_of_the_feed(
                kr_attention::EventKind::AuthorityFeedLeft,
                kr_ipc::now_ms().get(),
            )
            .await
        {
            eprintln!("kr-controller: {error}");
        }
        Ok(false)
    }

    /// Gives the attention store one notice about the feed, numbered by the moment it concerns.
    async fn tell_the_owner_of_the_feed(
        &self,
        kind: kr_attention::EventKind,
        at_ms: u64,
    ) -> Result<()> {
        let event = kr_attention::SourceEvent::new(
            kr_attention::EventCursor::new(
                kr_protocol::attention::AttentionSource::Authority,
                at_ms,
            ),
            kr_protocol::scalars::TimestampMs::new(at_ms),
            kind,
        );
        let attention = Arc::clone(self.attention());
        match tokio::task::spawn_blocking(move || attention.observe(&[event])).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(crate::error::ControllerError::Storage {
                operation: "tell the owner of the authority feed",
                detail: "the attention store could not take the notice".to_owned(),
            }),
        }
    }
}
