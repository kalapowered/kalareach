//! The grant seam: this host's one authority store, read through its public interface.
//!
//! A voice grant is a grant in the store section 10 already defines, because section 19 makes
//! content never authority and a second store would be a second answer. Nothing here writes a
//! record of its own.

use std::sync::Arc;

use kr_protocol::grant::Grant;
use kr_protocol::ids::{DeviceId, GrantId, SessionId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::AuthorisationKey;
use kr_voice::seams::{Replaced, Revoked, VoiceAuthority};
use kr_voice::{VoiceError, VoiceGrantPlan};

use crate::grants::{GrantRecord, GrantRevocation};
use crate::service::net::devices::DeviceDirectory;
use crate::service::net::lifetimes::{GrantLifetimes, GrantStanding};
use crate::sharing::SharingService;

/// The coordinator's view of this host's grants and devices.
#[derive(Debug)]
pub struct GrantAuthority {
    sharing: Arc<SharingService>,
    devices: Arc<DeviceDirectory>,
    host_device_id: DeviceId,
    /// The daemon that publishes and fences a debt a voice revocation's cascade wrote. Weak,
    /// because the daemon owns the voice service, and a counted reference the other way would
    /// keep a daemon, and its environment lock, alive.
    daemon: std::sync::Weak<crate::service::Controller>,
}

impl GrantAuthority {
    /// Builds the seam over the stores this host already keeps.
    #[must_use]
    pub const fn new(
        sharing: Arc<SharingService>,
        devices: Arc<DeviceDirectory>,
        host_device_id: DeviceId,
        daemon: std::sync::Weak<crate::service::Controller>,
    ) -> Self {
        Self {
            sharing,
            devices,
            host_device_id,
            daemon,
        }
    }

    /// What decides whether a grant stands: its anchor on the continuous clock and its expiry in
    /// UTC read through this host's clock floor, which the reading raises and which is written
    /// down. The same decision every other reader of a grant's time takes, and the daemon's own,
    /// so a daemon that has gone has nothing to decide with and answers with a refusal.
    fn lifetimes(&self) -> kr_voice::Result<Arc<GrantLifetimes>> {
        Ok(Arc::clone(self.daemon()?.lifetimes()))
    }

    /// The daemon this seam answers for, or the refusal of a host that is stopping: one that has
    /// gone has nothing to decide with.
    fn daemon(&self) -> kr_voice::Result<Arc<crate::service::Controller>> {
        self.daemon.upgrade().ok_or_else(|| {
            VoiceError::Host(kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "this host is stopping, so it cannot say whether a grant still stands".to_owned(),
            ))
        })
    }

    /// The moment before which a spent delegation identifier may be forgotten at `now_ms`, or none
    /// while this host cannot prove where its clock stands.
    ///
    /// A spend is kept for the retention section 9 gives a de-duplication record, and forgetting
    /// one on a deadline is taken like every forgetting on this host, through the one check they
    /// all pass ([`crate::service::net::lifetimes::GrantLifetimes::may_forget_at`]). The retention
    /// is counted from `now_ms`, the reading that check covers. A spend that cannot be shown to
    /// have outlived its retention is kept, because forgetting it lets the same delegation be
    /// submitted as a new action.
    fn forget_before(&self, now_ms: u64) -> Option<u64> {
        self.daemon
            .upgrade()?
            .lifetimes()
            .may_forget_at(now_ms)
            .then(|| now_ms.saturating_sub(kr_protocol::limits::DEDUPLICATION_RETENTION.get()))
    }

    /// The host device that issues a voice grant.
    #[must_use]
    pub const fn host_device_id(&self) -> DeviceId {
        self.host_device_id
    }

    /// The records this device holds that stand now, and whether one that does not stand is not
    /// settled.
    ///
    /// Standing means every one of the three: redeemed, not revoked, and not expired, and expiry is
    /// decided as every stored grant's is, on both clocks and with UTC read through this host's
    /// floor at the moment of the question rather than when the record was written, so a grant
    /// that ran out during a call stops authorising the next request in it and a wall clock wound
    /// back does not bring it back. A record whose end is found and not on record yet does not
    /// stand and says so: a daemon started in a new boot could decide the other way.
    fn standing_records(&self, device_id: DeviceId) -> kr_voice::Result<Standing> {
        let grants = self.sharing.grants();
        let lifetimes = self.lifetimes()?;
        let mut standing = Standing::default();
        for record in grants.records_for_device(device_id).map_err(store)? {
            if record.revoked_at_ms.is_some() || !record.is_active() {
                continue;
            }
            match lifetimes.stored_standing(grants, &record).map_err(store)? {
                GrantStanding::InForce => standing.records.push(record),
                GrantStanding::OutOfForce => {}
                GrantStanding::Unrecorded => standing.unrecorded = true,
            }
        }
        Ok(standing)
    }
}

/// What a device's records come to on this host's clocks: those that stand, and whether the end of
/// one that does not is not on record yet.
#[derive(Default)]
struct Standing {
    records: Vec<GrantRecord>,
    unrecorded: bool,
}

impl Standing {
    /// What a decision that found `answer` among the grants that stand is told: the grant, or
    /// nothing, or the refusal that gives the reason nothing could be said while an end that decides
    /// it is not on record.
    fn answer(&self, answer: Option<Grant>) -> kr_voice::Result<Option<Grant>> {
        match answer {
            Some(grant) => Ok(Some(grant)),
            None if self.unrecorded => Err(store(crate::grants::store::unrecorded())),
            None => Ok(None),
        }
    }
}

/// The store's own admission hook for one voice change: the admission it arrived under, asked
/// inside the transaction that writes, once the store's lock is held and immediately before the
/// record changes.
///
/// The refusal is the one the admission gave, a fence this host owes, a registration it has
/// replaced or a deadline that has passed, under its own code and in its own words.
fn at_the_write(
    admission: &dyn kr_voice::Admission,
) -> impl FnOnce() -> crate::error::Result<()> + '_ {
    move || {
        admission
            .still_admitted()
            .map_err(|refusal| crate::error::ControllerError::refused(&refusal))
    }
}

/// The record a voice grant plan is written as.
///
/// Written active: a voice grant is not an invitation somebody redeems later. The device it is
/// issued to is the one that asked for it on an authenticated connection, which is the redemption
/// an invitation exists to perform.
fn voice_record(plan: &VoiceGrantPlan) -> GrantRecord {
    let grant = plan.grant(GrantId::new(kr_ipc::new_uuid()));
    let now_ms = now_ms();
    GrantRecord {
        grant,
        session_id: match &plan.session_selector {
            kr_protocol::grant::SessionSelector::These { session_ids } => {
                session_ids.iter().copied().next()
            }
            _ => None,
        },
        issued_at_ms: now_ms,
        activated_at_ms: Some(now_ms),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

/// A store failure the coordinator reports rather than swallows.
fn store(error: crate::error::ControllerError) -> VoiceError {
    VoiceError::Host(kr_protocol::error::ProtocolError::new(
        error.code(),
        error.to_string(),
    ))
}

impl VoiceAuthority for GrantAuthority {
    fn device_grant(
        &self,
        device_id: DeviceId,
        session_id: Option<SessionId>,
    ) -> kr_voice::Result<Option<Grant>> {
        // The device's ordinary grant: the widest live one it holds that is not a voice grant. A
        // voice grant narrows this one rather than standing beside it, so the intersection the
        // coordinator takes is against the authority the device already had.
        //
        // Two places hold that authority, and both are asked. Pairing writes the grant a device
        // was paired under into its own device record, with the record and the consumed invitation
        // in one transaction; the grant store holds what has been shared with the device since. A
        // host that looked only at the store would find nothing for a device that has only ever
        // been paired, which is every device before anything is shared with it.
        let standing = self.standing_records(device_id)?;
        let lifetimes = self.lifetimes()?;
        // The grant a device was paired under, while it stands. A request under a share needs this
        // grant to stand, so a device that has been revoked, or whose pairing grant has run out and
        // is recorded as having, has no grant, and neither has one whose pairing grant runs out as
        // it is read; one whose end is not on record yet is refused with the host's reason. It may
        // carry the voice right (an owner is paired with every right), which is a voice grant's
        // marker everywhere else and is taken out of it here, as the door takes it out before it
        // decides a request: the voice right comes from a voice grant alone.
        let paired = match self.devices.record_for_device(device_id).map_err(store)? {
            None => None,
            Some(record) if !super::authority::DeviceRecordExt::is_paired_record(&record) => {
                return Ok(None);
            }
            Some(record) => match lifetimes.paired_standing(&record).map_err(store)? {
                GrantStanding::InForce => Some(Grant {
                    actions: record
                        .grant
                        .actions
                        .iter()
                        .copied()
                        .filter(|right| *right != ActionRight::VoiceUse)
                        .collect(),
                    ..record.grant
                }),
                GrantStanding::OutOfForce => return Ok(None),
                GrantStanding::Unrecorded => {
                    return Err(store(crate::grants::store::unrecorded()));
                }
            },
        };
        // As this host lets it be used: a right the rights ceiling takes away from every grant, or
        // that an organisation's lease does not give, is not one a spoken action may use, whichever
        // grant it was written in. A request under a share needs the grant the device was paired
        // under to stand under the host's policy, so that grant is read first and its refusal is the
        // answer: no share answers for a device whose pairing the policy refuses. Each share is then
        // read the same way before the widest is chosen, so a share the policy refuses does not stand
        // in the way of a grant it allows, and one the policy narrows is not chosen for rights it no
        // longer has. A share the host cannot yet decide on, because the clock it reads is not
        // proven, is no answer while another grant is, and is the answer when none is. The
        // coordinator reads the device's authority here before it asks for a confirmation, and the
        // host reads it again immediately before a close is forwarded, so both are under what is in
        // force when they read.
        let daemon = self.daemon()?;
        let read = |grant: Grant| {
            daemon
                .as_this_host_lets_it_be_used(grant)
                .map_err(|refusal| refusal.to_protocol_error())
        };
        let reaches = |grant: &Grant| {
            !grant.permits(ActionRight::VoiceUse)
                && session_id.is_none_or(|id| grant.session_selector.admits(id))
        };
        let mut widest: Option<Grant> = None;
        if let Some(pairing) = paired {
            let covers = reaches(&pairing);
            let usable = read(pairing).map_err(VoiceError::Host)?;
            if covers {
                widest = Some(usable);
            }
        }
        let mut refused = None;
        for record in &standing.records {
            if !reaches(&record.grant) {
                continue;
            }
            match read(record.grant.clone()) {
                Ok(usable) => {
                    if widest
                        .as_ref()
                        .is_none_or(|held| usable.actions.len() >= held.actions.len())
                    {
                        widest = Some(usable);
                    }
                }
                Err(error) => {
                    refused.get_or_insert(error);
                }
            }
        }
        match (widest, refused) {
            (None, Some(error)) => Err(VoiceError::Host(error)),
            (widest, _) => standing.answer(widest),
        }
    }

    fn grant(&self, grant_id: GrantId) -> kr_voice::Result<Option<Grant>> {
        let grants = self.sharing.grants();
        let Some(record) = grants.record(grant_id).map_err(store)? else {
            return Ok(None);
        };
        if record.revoked_at_ms.is_some() || !record.is_active() {
            return Ok(None);
        }
        match self
            .lifetimes()?
            .stored_standing(grants, &record)
            .map_err(store)?
        {
            // As this host lets it be used, as the device's own grant is: this is the grant a
            // spoken action is decided against, and a right the configuration or a lease takes
            // away is not one it carries. A grant is recognised as a voice grant by the voice right
            // in the store's record (see [`Self::standing_voice_grant`]), not by this answer.
            GrantStanding::InForce => self
                .daemon()?
                .as_this_host_lets_it_be_used(record.grant)
                .map(Some)
                .map_err(|refusal| VoiceError::Host(refusal.to_protocol_error())),
            GrantStanding::OutOfForce => Ok(None),
            GrantStanding::Unrecorded => Err(store(crate::grants::store::unrecorded())),
        }
    }

    fn standing_voice_grant(&self, device_id: DeviceId) -> kr_voice::Result<Option<Grant>> {
        let standing = self.standing_records(device_id)?;
        let held = standing
            .records
            .iter()
            .map(|record| &record.grant)
            .rfind(|grant| {
                grant.permits(ActionRight::VoiceUse) && grant.parent_grant_id.0.is_none()
            })
            .cloned();
        standing.answer(held)
    }

    fn issue(
        &self,
        plan: &VoiceGrantPlan,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<Grant> {
        let record = voice_record(plan);
        let grant = record.grant.clone();
        // The admission is asked inside the store's own transaction, once its lock is held and the
        // parent has been read, immediately before the record is written: the wait for that lock
        // can outlast it. The admission a voice mutation carries is the check every service asks
        // from inside its work, so a fence this host owes, a registration it has replaced and a
        // deadline that has passed each stop the write.
        self.sharing
            .grants()
            .issue(&record, at_the_write(admission))
            .map_err(store)?;
        Ok(grant)
    }

    fn replace(
        &self,
        replaced: GrantId,
        plan: &VoiceGrantPlan,
        now_ms: u64,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<Replaced> {
        let record = voice_record(plan);
        let grant = record.grant.clone();
        // The withdrawal and the new grant are one transaction of the store, with the admission
        // asked inside it once both have been read and before either is written. A voice grant's
        // withdrawal owes a fence only while a close is outstanding under it or when the cascade
        // withdrew a grant that is not a voice grant, and the debt it wrote is published once the
        // transaction has committed and not before (see [`Self::revoke`]).
        let revocation = self
            .sharing
            .grants()
            .replace(Some(replaced), now_ms, &record, at_the_write(admission))
            .map_err(store)?;
        let fence = revocation.and_then(|revocation| {
            self.daemon
                .upgrade()
                .and_then(|daemon| daemon.fence_voice_revocation(&revocation))
        });
        Ok(Replaced { grant, fence })
    }

    fn revoke(
        &self,
        grant_id: GrantId,
        now_ms: u64,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<Revoked> {
        // The store's own cascade: revoking a parent revokes its descendants, which is what makes
        // withdrawing a standing voice grant end the calls running under it.
        // The admission check inside the transaction is the caller's authority to revoke, which
        // the coordinator has already decided: it revokes only the grant of a voice session this
        // device holds, and it has just taken that session out of its own registry.
        // The store's own admission hook, inside the transaction that performs the revocation and
        // after it has read the subtree: the admission this change arrived under is asked at the
        // moment the record changes rather than before the read that precedes it.
        let revocation: GrantRevocation = self
            .sharing
            .grants()
            .revoke(grant_id, now_ms, at_the_write(admission))
            .map_err(store)?;
        // A voice grant's withdrawal owes a fence only while a close forwarded under it can still
        // run at a worker, so stopping a call with no close outstanding writes no debt and raises
        // no barrier. The store writes a debt when a close is outstanding under the grant, or when
        // the cascade also withdrew a grant delegated from a voice grant that is not one itself,
        // and that debt is published here, the moment the transaction that is its restriction has
        // committed, and the wait for its fence goes back to the caller.
        let fence = self
            .daemon
            .upgrade()
            .and_then(|daemon| daemon.fence_voice_revocation(&revocation));
        Ok(Revoked {
            at_ms: now_ms,
            fence,
        })
    }

    fn device_identity_key(
        &self,
        device_id: DeviceId,
    ) -> kr_voice::Result<Option<AuthorisationKey>> {
        Ok(self
            .devices
            .record_for_device(device_id)
            .map_err(store)?
            .filter(super::authority::DeviceRecordExt::is_paired_record)
            .map(|record| record.authorisation))
    }

    fn spend_delegation(
        &self,
        device_id: DeviceId,
        delegation_id: &kr_protocol::voice::VoiceDelegationId,
        action_id: kr_protocol::ids::ActionId,
        now_ms: u64,
    ) -> kr_voice::Result<bool> {
        self.sharing
            .grants()
            .spend_delegation(
                device_id,
                delegation_id.as_str(),
                action_id,
                now_ms,
                self.forget_before(now_ms),
            )
            .map_err(store)
    }

    fn release_delegation(
        &self,
        device_id: DeviceId,
        delegation_id: &kr_protocol::voice::VoiceDelegationId,
        action_id: kr_protocol::ids::ActionId,
    ) -> kr_voice::Result<()> {
        self.sharing
            .grants()
            .release_delegation(device_id, delegation_id.as_str(), action_id)
            .map_err(store)
    }
}

/// Whether a device record still authorises anything.
trait DeviceRecordExt {
    /// Returns true when the device may still open an authorised connection.
    fn is_paired_record(&self) -> bool;
}

impl DeviceRecordExt for crate::service::net::devices::DeviceRecord {
    fn is_paired_record(&self) -> bool {
        self.is_paired()
    }
}

/// This machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
