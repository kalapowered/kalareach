//! Voice sessions, which are not shell sessions.
//!
//! Section 15 ¶1 states it twice over: "a voice session is not a shell session; voice can stop
//! while the agent continues." This module is where that is true rather than said. A voice session
//! has its own identity, its own grant and its own end, and the terminal sessions it reached are
//! named in the answer to a stop so nobody has to take it on trust that they are still running.
//!
//! The other rule is section 15 ¶8's: ending the native voice session revokes its voice grant
//! immediately, independently of provider billing finalisation. [`VoiceSessions::stop`] therefore
//! takes the revocation from the authority store first and tells the broker afterwards, and a
//! broker that cannot be reached does not hold the revocation open.

use std::collections::BTreeMap;

use kr_protocol::ids::{DeviceId, GrantId, SessionId, VoiceSessionId};
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::voice::{VoiceDelegationId, VoiceRefusal};

use crate::error::{Result, VoiceError};

/// One voice session, as the coordinator holds it.
#[derive(Clone, Debug)]
pub struct VoiceSessionRecord {
    /// Its own identity.
    pub voice_session_id: VoiceSessionId,
    /// The paired device holding the call.
    pub device_id: DeviceId,
    /// The session-bound voice grant it runs under. Stopping revokes it.
    pub grant_id: GrantId,
    /// The standing voice grant that one was delegated from.
    pub parent_grant_id: GrantId,
    /// The terminal sessions it may reach. They outlive it.
    pub session_ids: CanonicalSet<SessionId>,
    /// The broker's identifier for the call, when a managed call is behind it.
    ///
    /// Absent for a voice session running on a provider of the person's own, which is the same
    /// voice session with a different provider behind it.
    pub call_id: Option<String>,
    /// The provider that created the call, so the same one is told when it ends.
    ///
    /// Held rather than looked up: the coordinator's provider can be replaced while a call runs,
    /// and telling a different service to close a call it never created would leave the real one
    /// metering.
    pub provider: Option<std::sync::Arc<dyn kr_client::services::voice::ManagedVoiceService>>,
    /// When it started, in UTC milliseconds.
    pub started_at_ms: u64,
    /// When the call's own deadline falls, in UTC milliseconds.
    pub closes_at_ms: u64,
    /// The delegations the provider has announced to this call, in the order they arrived.
    ///
    /// A delegation identifier is correlation data. An identifier nobody announced correlates with
    /// nothing, which is why submitting one is refused rather than interpreted.
    announced: Vec<VoiceDelegationId>,
}

impl VoiceSessionRecord {
    /// Records a delegation the provider announced to this call.
    pub fn announce(&mut self, delegation_id: VoiceDelegationId) {
        if !self.announced.contains(&delegation_id) {
            self.announced.push(delegation_id);
        }
    }

    /// Returns true when the provider announced this delegation to this call.
    #[must_use]
    pub fn announced(&self, delegation_id: &VoiceDelegationId) -> bool {
        self.announced.contains(delegation_id)
    }

    /// Takes one delegation back out of this call's announced set.
    ///
    /// One delegation is one action, so submitting a delegation spends it. An answer that admitted
    /// nothing — a challenge this host issued so the device can confirm the action — has to leave
    /// the delegation where it was, or the same delegation carrying the proof would be refused as
    /// one that had already been submitted.
    pub fn forget(&mut self, delegation_id: &VoiceDelegationId) {
        self.announced.retain(|held| held != delegation_id);
    }

    /// The delegations announced so far, oldest first.
    #[must_use]
    pub fn delegations(&self) -> &[VoiceDelegationId] {
        &self.announced
    }

    /// Returns true when this voice session may reach `session_id`.
    #[must_use]
    pub fn reaches(&self, session_id: SessionId) -> bool {
        self.session_ids.contains(&session_id)
    }
}

/// What stopping one voice session did.
#[derive(Clone, Debug)]
pub struct Stopped {
    /// The voice session that ended.
    pub voice_session_id: VoiceSessionId,
    /// The grant revoked with it.
    pub revoked_grant_id: GrantId,
    /// When the grant was revoked, in UTC milliseconds.
    pub revoked_at_ms: u64,
    /// The broker's call identifier, for the caller to finalise afterwards.
    pub call_id: Option<String>,
    /// The provider that created it.
    pub provider: Option<std::sync::Arc<dyn kr_client::services::voice::ManagedVoiceService>>,
    /// The terminal sessions it reached, which keep running.
    pub sessions_left_running: CanonicalSet<SessionId>,
}

/// A voice session that is about to start.
#[derive(Clone, Debug)]
pub struct NewVoiceSession {
    /// Its own identity.
    pub voice_session_id: VoiceSessionId,
    /// The paired device holding the call.
    pub device_id: DeviceId,
    /// The session-bound voice grant it runs under.
    pub grant_id: GrantId,
    /// The standing voice grant that one was delegated from.
    pub parent_grant_id: GrantId,
    /// The terminal sessions it may reach.
    pub session_ids: CanonicalSet<SessionId>,
    /// The broker's identifier for the call, when a managed call is behind it.
    pub call_id: Option<String>,
    /// The provider that created it, so the same one is told when it ends.
    pub provider: Option<std::sync::Arc<dyn kr_client::services::voice::ManagedVoiceService>>,
    /// When it started, in UTC milliseconds.
    pub started_at_ms: u64,
    /// When the call's own deadline falls, in UTC milliseconds.
    pub closes_at_ms: u64,
}

/// The voice sessions this host holds.
#[derive(Debug, Default)]
pub struct VoiceSessions {
    live: BTreeMap<[u8; 16], VoiceSessionRecord>,
}

impl VoiceSessions {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a voice session that has just started.
    pub fn start(&mut self, started: NewVoiceSession) -> VoiceSessionRecord {
        let NewVoiceSession {
            voice_session_id,
            device_id,
            grant_id,
            parent_grant_id,
            session_ids,
            call_id,
            provider,
            started_at_ms,
            closes_at_ms,
        } = started;
        let record = VoiceSessionRecord {
            voice_session_id,
            device_id,
            grant_id,
            parent_grant_id,
            session_ids,
            call_id,
            provider,
            started_at_ms,
            closes_at_ms,
            announced: Vec::new(),
        };
        self.live
            .insert(*voice_session_id.get().as_bytes(), record.clone());
        record
    }

    /// The voice session with this identity, when this device holds it.
    ///
    /// The device is part of the question rather than checked afterwards: a lookup that answered
    /// about somebody else's call and left the caller to compare would be a lookup somebody
    /// forgets to compare.
    ///
    /// # Errors
    ///
    /// Returns a refusal when there is no such voice session, or it belongs to another device.
    pub fn of_device(
        &self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
    ) -> Result<&VoiceSessionRecord> {
        match self.live.get(voice_session_id.get().as_bytes()) {
            Some(record) if record.device_id == device_id => Ok(record),
            // One answer for a call that is not this device's and one that does not exist, so the
            // identifier cannot be used to ask whether a call exists.
            _ => Err(VoiceError::refused(
                VoiceRefusal::UnknownVoiceSession,
                "there is no such voice session on this host",
            )),
        }
    }

    /// The same, mutably, for recording an announced delegation.
    ///
    /// # Errors
    ///
    /// Returns a refusal when there is no such voice session, or it belongs to another device.
    pub fn of_device_mut(
        &mut self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
    ) -> Result<&mut VoiceSessionRecord> {
        match self.live.get_mut(voice_session_id.get().as_bytes()) {
            Some(record) if record.device_id == device_id => Ok(record),
            _ => Err(VoiceError::refused(
                VoiceRefusal::UnknownVoiceSession,
                "there is no such voice session on this host",
            )),
        }
    }

    /// Ends one voice session and reports what to revoke.
    ///
    /// The record leaves the registry here; revoking the grant is the caller's next step, because
    /// the store is the caller's. What this guarantees is that nothing can use the voice session
    /// after this returns, whatever the broker does afterwards.
    ///
    /// # Errors
    ///
    /// Returns a refusal when there is no such voice session, or it belongs to another device.
    pub fn stop(
        &mut self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
    ) -> Result<VoiceSessionRecord> {
        let record = self.of_device(voice_session_id, device_id)?.clone();
        self.live.remove(voice_session_id.get().as_bytes());
        Ok(record)
    }

    /// Ends every voice session running under one grant, and returns them.
    ///
    /// Revoking a standing voice grant revokes its descendants, so the calls running under it stop
    /// being authorised at the same moment. This is the registry's half of that.
    pub fn stop_under(&mut self, grant_id: GrantId) -> Vec<VoiceSessionRecord> {
        let ending: Vec<VoiceSessionRecord> = self
            .live
            .values()
            .filter(|record| record.grant_id == grant_id || record.parent_grant_id == grant_id)
            .cloned()
            .collect();
        for record in &ending {
            self.live.remove(record.voice_session_id.get().as_bytes());
        }
        ending
    }

    /// How many voice sessions are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Returns true when none is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Every live voice session, oldest identity first.
    pub fn iter(&self) -> impl Iterator<Item = &VoiceSessionRecord> {
        self.live.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn voice_session(byte: u8) -> VoiceSessionId {
        VoiceSessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn device(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn grant(byte: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([byte; 16]))
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn started(sessions: &mut VoiceSessions) -> VoiceSessionRecord {
        sessions.start(NewVoiceSession {
            voice_session_id: voice_session(1),
            device_id: device(2),
            grant_id: grant(3),
            parent_grant_id: grant(4),
            session_ids: [session(5), session(6)].into_iter().collect(),
            call_id: Some("call-1".to_owned()),
            provider: None,
            started_at_ms: 1_000,
            closes_at_ms: 2_000,
        })
    }

    #[test]
    fn a_voice_session_belongs_to_the_device_that_started_it() {
        let mut sessions = VoiceSessions::new();
        started(&mut sessions);
        assert!(sessions.of_device(voice_session(1), device(2)).is_ok());
        let error = sessions
            .of_device(voice_session(1), device(9))
            .expect_err("another device gets nothing");
        assert_eq!(error.reason(), Some(VoiceRefusal::UnknownVoiceSession));
        assert!(
            !error.to_string().contains("another device"),
            "a refusal does not say whose call it is"
        );
    }

    #[test]
    fn stopping_a_voice_session_leaves_its_terminal_sessions_alone() {
        let mut sessions = VoiceSessions::new();
        started(&mut sessions);
        let stopped = sessions.stop(voice_session(1), device(2)).expect("stopped");
        assert_eq!(stopped.session_ids.len(), 2);
        assert!(sessions.is_empty());
        // Nothing in this registry closes a terminal session, and nothing here can.
        assert!(sessions.of_device(voice_session(1), device(2)).is_err());
    }

    #[test]
    fn an_unannounced_delegation_correlates_with_nothing() {
        let mut sessions = VoiceSessions::new();
        started(&mut sessions);
        let announced = VoiceDelegationId::new("item_announced").expect("an identifier");
        let invented = VoiceDelegationId::new("item_invented").expect("an identifier");
        sessions
            .of_device_mut(voice_session(1), device(2))
            .expect("the session")
            .announce(announced.clone());
        let record = sessions
            .of_device(voice_session(1), device(2))
            .expect("the session");
        assert!(record.announced(&announced));
        assert!(!record.announced(&invented));
    }

    #[test]
    fn revoking_the_standing_grant_ends_the_calls_under_it() {
        let mut sessions = VoiceSessions::new();
        started(&mut sessions);
        sessions.start(NewVoiceSession {
            voice_session_id: voice_session(7),
            device_id: device(2),
            grant_id: grant(8),
            parent_grant_id: grant(4),
            session_ids: [session(5)].into_iter().collect(),
            call_id: None,
            provider: None,
            started_at_ms: 1_000,
            closes_at_ms: 2_000,
        });
        let ended = sessions.stop_under(grant(4));
        assert_eq!(ended.len(), 2);
        assert!(sessions.is_empty());
    }
}
