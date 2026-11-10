//! The unlocked-screen confirmation of a spoken request, as this phone carries it out.
//!
//! Section 15 ¶8: an action in one of the five classes that need an unlocked screen is admitted
//! only with a confirmation the paired device signs over the exact action. The host answers the
//! first submission of such a delegation with a challenge, and the same delegation comes back under
//! the same action, carrying the signature. What this module decides is the first half of that:
//! whether the challenge the host sent is one to put to the person at all. The host is not trusted
//! with that. A challenge is shown only when everything it says agrees with what this device made
//! of the call itself:
//!
//! * it answers the request this device sent, under the action that request carried, for the
//!   delegation that request named;
//! * the host that issued it is the host this call belongs to, and it is for this device;
//! * it is for this voice session, and the class of action it names is one of the classes this
//!   call's grant says still need a confirmation on the unlocked screen;
//! * the session the host says the words named is one this call may reach;
//! * the digest it asks to be signed over is the digest of the plan this device computes itself,
//!   from the delegation it sent and the action and session the host named, so that a host that
//!   asked to confirm one thing and meant another has nothing to sign.
//!
//! A challenge that fails any of them is put to nobody: the person is never asked to confirm what
//! this device cannot show they said.

use kr_client::session::ComposedMutation;
use kr_protocol::ids::DeviceId;
use kr_protocol::voice::{
    VoiceAction, VoiceActionPlan, VoiceConfirmationRequest, VoiceDelegateParams,
    VoiceDelegateResult, VoiceSessionDescriptor,
};

/// A delegation whose first answer was a challenge, with everything its confirmation is checked
/// against.
pub(super) struct Challenge {
    /// The request as it was composed and first sent, whole: what the digest is recomputed from.
    pub unsigned: ComposedMutation,
    /// What the host answered, which names the action it read and the session it read it to name.
    pub result: VoiceDelegateResult,
    /// The challenge itself.
    pub request: VoiceConfirmationRequest,
}

/// What this device knows of the call, which a challenge is compared with.
pub(super) struct Known<'a> {
    /// The host this call belongs to.
    pub host_device_id: DeviceId,
    /// The identity this host gave this device.
    pub device_id: DeviceId,
    /// What the host said the call is.
    pub descriptor: &'a VoiceSessionDescriptor,
}

/// The first thing in a challenge that does not agree with the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mismatch {
    /// The request this device sent cannot be read back.
    Retained,
    /// The challenge is for another action than the one the request carried.
    ActionId,
    /// The answer names another delegation than the one sent.
    Delegation,
    /// The challenge names a class of action other than the one the host read the words to ask for.
    Action,
    /// Another host issued it.
    Host,
    /// It is for another device.
    Device,
    /// It is for another voice session.
    VoiceSession,
    /// The call's grant does not say that action needs a confirmation on the unlocked screen.
    NotAnUnlockedScreenAction,
    /// The host named no session, or one this call does not reach.
    Session,
    /// The digest is not the one this device computes from what it sent.
    Digest,
}

impl Challenge {
    /// The delegation as this device sent it, read back from the request it kept.
    pub(super) fn sent(&self) -> Option<VoiceDelegateParams> {
        self.unsigned.request().params.to_typed().ok()
    }

    /// Whether this challenge is one to put to the person.
    ///
    /// # Errors
    ///
    /// Returns the first check that fails.
    pub(super) fn check(&self, known: &Known<'_>) -> Result<(), Mismatch> {
        let sent = self.sent().ok_or(Mismatch::Retained)?;
        let request = &self.request;
        if request.action_id != self.unsigned.action_id() {
            return Err(Mismatch::ActionId);
        }
        if self.result.delegation_id != sent.delegation_id {
            return Err(Mismatch::Delegation);
        }
        if self.result.action.0 != Some(request.action) {
            return Err(Mismatch::Action);
        }
        if request.host_device_id != known.host_device_id {
            return Err(Mismatch::Host);
        }
        if request.device_id != known.device_id {
            return Err(Mismatch::Device);
        }
        if request.voice_session_id != known.descriptor.voice_session_id
            || sent.voice_session_id != known.descriptor.voice_session_id
        {
            return Err(Mismatch::VoiceSession);
        }
        if !known
            .descriptor
            .statement
            .unlocked_screen_actions
            .contains(&request.action)
        {
            return Err(Mismatch::NotAnUnlockedScreenAction);
        }
        let session = match self.result.session_id.0 {
            Some(session) if known.descriptor.session_ids.contains(&session) => session,
            _ => return Err(Mismatch::Session),
        };
        let plan = VoiceActionPlan {
            voice_session_id: known.descriptor.voice_session_id,
            action: request.action,
            session_id: kr_protocol::scalars::Nullable::some(session),
            delegation_id: kr_protocol::scalars::Nullable::some(sent.delegation_id.clone()),
            payload_digest: sent.payload_digest().map_err(|_| Mismatch::Retained)?,
        };
        match plan.digest() {
            Ok(digest) if digest == request.action_digest => Ok(()),
            _ => Err(Mismatch::Digest),
        }
    }

    /// The signed request: what was sent, with the confirmation on it.
    pub(super) fn signed(
        &self,
        confirmation: kr_protocol::voice::VoiceConfirmationProof,
    ) -> Option<VoiceDelegateParams> {
        let mut params = self.sent()?;
        params.confirmation = kr_protocol::scalars::Nullable::some(confirmation);
        Some(params)
    }
}

/// What the platform's own dialog is told to print: what is being confirmed, of which session, and
/// at which host. The session is always named by its number: a confirmation of a target the person
/// cannot tell is not asked for.
pub(super) fn reason(action: VoiceAction, session_number: u64, host: Option<&str>) -> String {
    let what = match action {
        VoiceAction::CloseSession => "Close".to_owned(),
        other => format!("Confirm {}", other.as_str().replace('_', " ")),
    };
    format!(
        "{what} session {session_number} on {}",
        host.unwrap_or("your computer")
    )
}
