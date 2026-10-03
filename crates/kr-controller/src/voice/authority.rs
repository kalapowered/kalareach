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
use kr_voice::seams::VoiceAuthority;
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
        self.daemon
            .upgrade()
            .map(|daemon| Arc::clone(daemon.lifetimes()))
            .ok_or_else(|| {
                VoiceError::Host(kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    "this host is stopping, so it cannot say whether a grant still stands"
                        .to_owned(),
                ))
            })
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
        let mut standing = self.standing_records(device_id)?;
        let lifetimes = self.lifetimes()?;
        let paired = self
            .devices
            .record_for_device(device_id)
            .map_err(store)?
            .filter(super::authority::DeviceRecordExt::is_paired_record)
            .and_then(
                |record| match lifetimes.paired_standing(&record).map_err(store) {
                    Ok(GrantStanding::InForce) => Some(Ok(record.grant)),
                    Ok(GrantStanding::OutOfForce) => None,
                    Ok(GrantStanding::Unrecorded) => {
                        standing.unrecorded = true;
                        None
                    }
                    Err(error) => Some(Err(error)),
                },
            )
            .transpose()?;
        let widest = paired
            .into_iter()
            .chain(standing.records.iter().map(|record| record.grant.clone()))
            .filter(|grant| !grant.permits(ActionRight::VoiceUse))
            .filter(|grant| session_id.is_none_or(|id| grant.session_selector.admits(id)))
            .max_by_key(|grant| grant.actions.len());
        standing.answer(widest)
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
            GrantStanding::InForce => Ok(Some(record.grant)),
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
    ) -> kr_voice::Result<Grant> {
        let record = voice_record(plan);
        let grant = record.grant.clone();
        // The withdrawal and the new grant are one transaction of the store, with the admission
        // asked inside it once both have been read and before either is written. A voice grant's
        // withdrawal owes no fence, and this publishes what the cascade found it must (see
        // [`Self::revoke`]), once the transaction has committed and not before.
        let revocation = self
            .sharing
            .grants()
            .replace(Some(replaced), now_ms, &record, at_the_write(admission))
            .map_err(store)?;
        if let Some(debt) = revocation.and_then(|revocation| revocation.debt)
            && let Some(daemon) = self.daemon.upgrade()
        {
            daemon.publish_and_fence(debt);
        }
        Ok(grant)
    }

    fn revoke(
        &self,
        grant_id: GrantId,
        now_ms: u64,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<u64> {
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
        // A voice grant's withdrawal owes no fence: no worker holds work under a grant that
        // carries `voice.use`, so stopping a call or replacing a standing grant writes no debt and
        // raises no barrier. The store writes one only when the cascade also withdrew a grant
        // delegated from a voice grant that is not one itself, and that debt is published here,
        // the moment the transaction that is its restriction has committed, and fenced.
        if let Some(debt) = revocation.debt
            && let Some(daemon) = self.daemon.upgrade()
        {
            daemon.publish_and_fence(debt);
        }
        Ok(now_ms)
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
