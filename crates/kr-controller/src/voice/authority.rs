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

    /// The host device that issues a voice grant.
    #[must_use]
    pub const fn host_device_id(&self) -> DeviceId {
        self.host_device_id
    }

    /// The live records this device holds.
    ///
    /// Live means every one of the three: redeemed, not revoked, and not expired. Expiry is read
    /// from the grant at the moment of the question rather than when the record was written, so a
    /// grant that ran out during a call stops authorising the next request in it.
    fn live_records(&self, device_id: DeviceId, now_ms: u64) -> kr_voice::Result<Vec<GrantRecord>> {
        Ok(self
            .sharing
            .grants()
            .records_for_device(device_id)
            .map_err(store)?
            .into_iter()
            .filter(|record| record.state(now_ms) == kr_protocol::sharing::GrantState::Active)
            .collect())
    }
}

/// The store's own admission hook for one voice change: the admission it arrived under, asked
/// inside the transaction that writes, once the store's lock is held and immediately before the
/// record changes.
///
/// The seam only says no, so the refusal here is a generic one. The daemon's own admission keeps
/// the refusal its check gave, a fence this host owes, a registration it has replaced or a
/// deadline that has passed, and that is what the daemon tells the caller in place of this.
fn at_the_write(
    admission: &dyn kr_voice::Admission,
) -> impl FnOnce() -> crate::error::Result<()> + '_ {
    move || {
        if admission.still_admitted() {
            Ok(())
        } else {
            Err(crate::error::ControllerError::PermissionDenied {
                detail: "the admission this change arrived under no longer stands".to_owned(),
            })
        }
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
        now_ms: u64,
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
        let paired = self
            .devices
            .record_for_device(device_id)
            .map_err(store)?
            .filter(super::authority::DeviceRecordExt::is_paired_record)
            .map(|record| record.grant)
            .filter(|grant| grant.expiry.is_valid_at(now_ms));
        Ok(paired
            .into_iter()
            .chain(
                self.live_records(device_id, now_ms)?
                    .into_iter()
                    .map(|record| record.grant),
            )
            .filter(|grant| !grant.permits(ActionRight::VoiceUse))
            .filter(|grant| session_id.is_none_or(|id| grant.session_selector.admits(id)))
            .max_by_key(|grant| grant.actions.len()))
    }

    fn grant(&self, grant_id: GrantId, now_ms: u64) -> kr_voice::Result<Option<Grant>> {
        Ok(self
            .sharing
            .grants()
            .record(grant_id)
            .map_err(store)?
            .filter(|record| record.state(now_ms) == kr_protocol::sharing::GrantState::Active)
            .map(|record| record.grant))
    }

    fn standing_voice_grant(
        &self,
        device_id: DeviceId,
        now_ms: u64,
    ) -> kr_voice::Result<Option<Grant>> {
        Ok(self
            .live_records(device_id, now_ms)?
            .into_iter()
            .map(|record| record.grant)
            .rfind(|grant| {
                grant.permits(ActionRight::VoiceUse) && grant.parent_grant_id.0.is_none()
            }))
    }

    fn issue(
        &self,
        plan: &VoiceGrantPlan,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<Grant> {
        let grant_id = GrantId::new(kr_ipc::new_uuid());
        let grant = plan.grant(grant_id);
        let now_ms = now_ms();
        // Written active: a voice grant is not an invitation somebody redeems later. The device it
        // is issued to is the one that asked for it on an authenticated connection, which is the
        // redemption an invitation exists to perform.
        let record = GrantRecord {
            grant: grant.clone(),
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
        };
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

    fn now_ms(&self) -> u64 {
        now_ms()
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
