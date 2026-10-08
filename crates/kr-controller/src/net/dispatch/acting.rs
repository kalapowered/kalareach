//! The grant a connection acts under for a session.
//!
//! A paired device holds the grant its pairing recorded, and may hold others: a session shared
//! with it is a grant issued to it and activated when it redeemed the invitation. A request is
//! decided under **one** of them, never under a combination, because rights, selectors, history
//! scope and lifetime belong together and mixing two grants would give a device what neither of
//! them gives.
//!
//! Which one is decided by the request, and then fixed:
//!
//! 1. A mutation names the grant it is acting under. It may name only a grant this device holds.
//! 2. A request that names none is decided under the pairing grant when that grant's selectors
//!    admit the session, and otherwise under the one live share that admits it. Several shares and
//!    no pairing grant that admits the session leave nothing to choose by, and the request is
//!    refused with the way out: name the grant.
//! 3. A request that names no session is decided under the pairing grant.
//!
//! Once a connection has a link to a session's worker, the grant it opened that link under is the
//! grant it acts under for that session until the connection ends. The worker keeps state that
//! belongs to the grant a request was decided under (the history scope a subscription carries, the
//! lease an attachment holds), so deciding a later request under another grant would leave that
//! state outliving the grant it was made under.

use std::sync::PoisonError;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{GrantId, SessionId};
use kr_protocol::rights::ActionRight;

use crate::grants::GrantRecord;
use crate::grants::policy::{BoundCell, BoundIdentity, HeldBound};
use crate::service::net::lifetimes::{Anchored, GrantStanding};

use super::RemoteConnection;

/// The longest a connection waits for a grant to end before it looks at the grants again, which a
/// clock stepped forward can have ended sooner than the time they had left.
#[cfg(not(test))]
const GRANT_WATCH: std::time::Duration = std::time::Duration::from_secs(15);
/// A test moves its clocks by hand and waits for the connection to notice.
#[cfg(test)]
const GRANT_WATCH: std::time::Duration = std::time::Duration::from_millis(10);

/// Where a grant a request is decided under comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Held {
    /// The grant this device's pairing recorded.
    Pairing,
    /// A grant issued to this device and activated when it redeemed an invitation.
    Share,
}

/// The grant one request is decided under.
#[derive(Clone, Debug)]
pub(super) struct Acting {
    /// The grant itself.
    pub(super) grant: Grant,
    /// Where it comes from, which is where its standing is read.
    pub(super) held: Held,
}

impl Acting {
    fn pairing(grant: &Grant) -> Self {
        Self {
            grant: grant.clone(),
            held: Held::Pairing,
        }
    }
}

/// What a device is told about a grant it does not hold, however it came to name it: that one is
/// another device's, one that does not admit the session, one that is not a share, and one that
/// does not exist all read the same.
fn not_held() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "this device holds no such grant for this session",
    )
}

/// What a connection is told when the host has withdrawn its registration.
pub(super) fn withdrawn() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "the authority this connection was admitted under has been withdrawn; open a new connection",
    )
}

impl RemoteConnection {
    /// The grant this device's pairing recorded, as a test decides a request under it.
    #[cfg(test)]
    pub(super) fn pairing_acting(&self) -> Acting {
        Acting::pairing(&self.device.grant)
    }

    /// The grant this device acts under for `session_id`, when it names `named` or none.
    ///
    /// # Errors
    ///
    /// Refuses a grant this device does not hold for the session, a grant other than the one this
    /// connection already acts under for it, and a session several of this device's shares admit
    /// when nothing names one.
    pub(super) fn acting_for(
        &self,
        session_id: Option<SessionId>,
        named: Option<GrantId>,
    ) -> std::result::Result<Acting, ProtocolError> {
        let pairing = &self.device.grant;
        let Some(session_id) = session_id else {
            return match named {
                Some(named) if named != pairing.grant_id => Err(not_held()),
                _ => Ok(Acting::pairing(pairing)),
            };
        };
        let fixed = *self.fixed.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((fixed_session, fixed_grant)) = fixed
            && fixed_session == session_id
        {
            if named.is_some_and(|named| named != fixed_grant) {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this connection acts for this session under another grant; open another \
                     connection to act under the one named",
                ));
            }
            return self.held_grant(fixed_grant, session_id);
        }
        match named {
            Some(named) => self.held_grant(named, session_id),
            None => self.selected(session_id),
        }
    }

    /// The grant this connection acts under, once `acting` has opened its link to `session_id`.
    ///
    /// Taken under the lock that guards the link, so two requests that open it at once do not fix
    /// two grants. A share is noted on the connection's registration first and its record is read
    /// after, so a revocation of it either withdraws this connection or has committed already and
    /// the record says so.
    ///
    /// # Errors
    ///
    /// Refuses a grant other than the one already fixed for the connection, a second session, and a
    /// share that has been revoked or whose connection has been withdrawn.
    pub(super) fn fix(
        &self,
        session_id: SessionId,
        acting: &Acting,
    ) -> std::result::Result<(), ProtocolError> {
        let mut fixed = self.fixed.lock().unwrap_or_else(PoisonError::into_inner);
        match *fixed {
            Some((fixed_session, _)) if fixed_session != session_id => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "this connection already serves another session; open another connection",
                ));
            }
            Some((_, fixed_grant)) if fixed_grant != acting.grant.grant_id => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this connection acts for this session under another grant; open another \
                     connection to act under the one named",
                ));
            }
            Some(_) => return Ok(()),
            None => {}
        }
        if acting.held == Held::Share {
            let record = self.noted_share_record(acting.grant.grant_id)?;
            self.hold_share_bound(acting.grant.grant_id, self.share_bound(&record)?);
        }
        *fixed = Some((session_id, acting.grant.grant_id));
        drop(fixed);
        self.acting_changed.notify_waiters();
        Ok(())
    }

    /// A share this connection is about to decide a request under, read from the grant store.
    ///
    /// The share is noted on the connection's registration **before** its record is read, and
    /// every place that decides under a share reads it here, so the order is one rule and not a
    /// habit of each caller: a revocation of the share either withdraws this connection, because
    /// the share is noted, or has committed already, and the record says so. Read the other way
    /// round, a revocation could land between the two and withdraw nothing.
    ///
    /// A share noted for a request that is then refused stays on the registration. A later
    /// revocation of it fences this connection too, which is the safe direction.
    ///
    /// # Errors
    ///
    /// Refuses a connection the host has withdrawn, a grant this device does not hold, and a
    /// share that has been revoked.
    pub(super) fn noted_share_record(
        &self,
        grant_id: GrantId,
    ) -> std::result::Result<GrantRecord, ProtocolError> {
        if !self.controller.note_acting(self.connection_id, grant_id) {
            return Err(withdrawn());
        }
        let record = self.share_record(grant_id)?;
        if record.revoked_at_ms.is_some() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this grant has been revoked",
            ));
        }
        Ok(record)
    }

    /// Takes up the end of a share this connection decided a request under, so the connection is
    /// ended when the share is, whether or not it ever opened a link to a worker under it.
    pub(super) fn hold_share_bound(&self, grant_id: GrantId, bound: HeldBound) {
        self.share_bounds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(grant_id, bound);
        self.acting_changed.notify_waiters();
    }

    /// Resolves once a grant this connection stands on has ended: the pairing grant that lets the
    /// device in, or the share it acts under for its session.
    ///
    /// A connection that sends nothing is served nothing after its grant ends, because the
    /// connection ends with it. The share's end is a time bound of its own, so ending it writes
    /// nothing on the device's record; the pairing grant's end is written down as it is wherever
    /// it is found. A revocation does not wait for this: it fences the connections acting under
    /// the grants it withdrew when it takes effect.
    pub(in crate::service::net) async fn grant_ended(&self) {
        loop {
            // Asked for before the grants are looked at, so a share fixed while they are looked at
            // is not missed.
            let changed = self.acting_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.grant_is_current() {
                return;
            }
            let shares: Vec<HeldBound> = self
                .share_bounds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect();
            if !super::output::bounds_hold(
                &self.controller,
                &shares,
                crate::grants::policy::HeldBound::stands_at,
            ) {
                return;
            }
            let now = self.controller.clock.now();
            let settled = self.controller.settled_utc_now();
            let until_utc = |end: Option<u64>| {
                end.map(|end| std::time::Duration::from_millis(end.saturating_sub(settled)))
            };
            let soonest = [
                self.authority
                    .grant_deadline
                    .map(|deadline| deadline.saturating_duration_since(now)),
                until_utc(self.authority.grant_expires_at_ms),
            ]
            .into_iter()
            .flatten()
            .chain(shares.iter().flat_map(|share| {
                [
                    share
                        .continuous_deadline()
                        .map(|deadline| deadline.saturating_duration_since(now)),
                    until_utc(share.utc_deadline_ms()),
                ]
                .into_iter()
                .flatten()
            }))
            .min();
            match soonest {
                // A clock can step forward and end a grant sooner than the time it has left, so
                // the wait is bounded and the grants are looked at again.
                Some(left) => {
                    tokio::select! {
                        () = tokio::time::sleep(left.min(GRANT_WATCH)) => {}
                        () = &mut changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }

    /// The named grant, when this device holds it for `session_id`.
    fn held_grant(
        &self,
        grant_id: GrantId,
        session_id: SessionId,
    ) -> std::result::Result<Acting, ProtocolError> {
        if grant_id == self.device.grant.grant_id {
            return Ok(Acting::pairing(&self.device.grant));
        }
        let record = self.share_record(grant_id)?;
        if self.admits(&record.grant, session_id) {
            Ok(Acting {
                grant: record.grant,
                held: Held::Share,
            })
        } else {
            Err(not_held())
        }
    }

    /// The grant a request that names none is decided under.
    fn selected(&self, session_id: SessionId) -> std::result::Result<Acting, ProtocolError> {
        let pairing = &self.device.grant;
        if self.admits(pairing, session_id) {
            return Ok(Acting::pairing(pairing));
        }
        let lifetimes = self.controller.lifetimes();
        let grants = self.controller.sharing().grants();
        let mut shares: Vec<Grant> = Vec::new();
        for record in grants
            .records_for_device(self.device.device_id)
            .map_err(|error| error.to_protocol_error())?
        {
            if record.is_active()
                && record.revoked_at_ms.is_none()
                && !record.grant.permits(ActionRight::VoiceUse)
                && self.admits(&record.grant, session_id)
                // A share that has ended on either clock is not one to choose among. A store that
                // cannot say is a refusal of its own, not a share that has ended.
                && lifetimes
                    .stored_standing(grants, &record)
                    .map_err(|error| error.to_protocol_error())?
                    == GrantStanding::InForce
            {
                shares.push(record.grant);
            }
        }
        match shares.len() {
            // Nothing admits it, and the decision under the pairing grant says so.
            0 => Ok(Acting::pairing(pairing)),
            1 => Ok(Acting {
                grant: shares.remove(0),
                held: Held::Share,
            }),
            _ => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "several grants this device holds admit this session; name the one to act under \
                 in the request, or in session.attach before any read",
            )),
        }
    }

    /// Whether a grant's selectors admit this session in this environment.
    fn admits(&self, grant: &Grant, session_id: SessionId) -> bool {
        grant
            .environment_selector
            .admits(self.controller.paths().environment_id())
            && grant.session_selector.admits(session_id)
    }

    /// A share of this device's, as the grant store holds it now.
    ///
    /// Whether it is in force is the decision's; this finds the record and refuses one that is not
    /// this device's or is a voice grant, which the voice coordinator selects for itself.
    pub(super) fn share_record(
        &self,
        grant_id: GrantId,
    ) -> std::result::Result<GrantRecord, ProtocolError> {
        self.controller
            .sharing()
            .grants()
            .record(grant_id)
            .map_err(|error| error.to_protocol_error())?
            .filter(|record| {
                record.grant.recipient_device_id == self.device.device_id
                    && !record.grant.permits(ActionRight::VoiceUse)
            })
            .ok_or_else(not_held)
    }

    /// The time bound a share stands under, as the host anchors it on the continuous clock and
    /// reads it in UTC, or the refusal that it has run out.
    ///
    /// A bound of its own, beside the pairing grant's and the policy's, so the write boundary that
    /// holds a response or a relayed batch to the bounds it was decided under holds it to the
    /// share's end as well, and a share that runs out under a live subscription ends that
    /// subscription without touching the pairing grant.
    pub(super) fn share_bound(
        &self,
        record: &GrantRecord,
    ) -> std::result::Result<HeldBound, ProtocolError> {
        let lifetimes = self.controller.lifetimes();
        let grants = self.controller.sharing().grants();
        match lifetimes
            .stored_standing(grants, record)
            .map_err(|error| error.to_protocol_error())?
        {
            GrantStanding::InForce => {}
            GrantStanding::OutOfForce => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this grant has expired",
                ));
            }
            GrantStanding::Unrecorded => {
                return Err(crate::grants::Refusal::FloorUnrecorded.to_protocol_error());
            }
        }
        let continuous_deadline = match lifetimes
            .stored(grants, record)
            .map_err(|error| error.to_protocol_error())?
        {
            Anchored::Until(deadline) => Some(deadline),
            Anchored::Unlimited => None,
            Anchored::Over => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this grant has expired",
                ));
            }
        };
        let utc_deadline_ms = match record.grant.expiry {
            kr_protocol::grant::GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
            kr_protocol::grant::GrantExpiry::Never => None,
        };
        Ok(HeldBound::load(&BoundCell::new(
            BoundIdentity::Share {
                grant_id: record.grant.grant_id,
            },
            continuous_deadline,
            utc_deadline_ms,
            false,
        )))
    }
}
