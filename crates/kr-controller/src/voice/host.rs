//! This daemon's own half of the two remaining seams.
//!
//! The coordinator reads through [`ControllerFacts`] and proposes through [`ControllerDispatch`].
//! Both hold a weak reference to the daemon, because the daemon owns the voice service and a
//! counted reference the other way would keep a daemon, and its environment lock, alive.

use std::sync::Weak;

use kr_protocol::ids::{ApprovalRequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Digest256;
use kr_voice::seams::{HostReceipt, VoiceFuture};
use kr_voice::{Proposal, VoiceError};

use super::context::{SessionFacts, SessionSnapshot};
use super::submit::HostDispatch;
use crate::service::Controller;

/// The session facts this daemon can answer with.
#[derive(Debug)]
pub struct ControllerFacts {
    daemon: Weak<Controller>,
}

impl ControllerFacts {
    /// Builds the seam over one daemon.
    #[must_use]
    pub const fn new(daemon: Weak<Controller>) -> Self {
        Self { daemon }
    }
}

/// The daemon has gone, which is what a request that outlived it sees.
fn gone() -> VoiceError {
    VoiceError::Host(kr_protocol::error::ProtocolError::new(
        kr_protocol::error::ErrorCode::SessionClosed,
        "this host is shutting down".to_owned(),
    ))
}

impl SessionFacts for ControllerFacts {
    fn snapshot<'a>(&'a self, session_id: SessionId) -> VoiceFuture<'a, SessionSnapshot> {
        let daemon = self.daemon.clone();
        Box::pin(async move {
            let daemon = daemon.upgrade().ok_or_else(gone)?;
            daemon
                .voice_session_snapshot(session_id)
                .await
                .map_err(|error| {
                    VoiceError::Host(kr_protocol::error::ProtocolError::new(
                        error.code(),
                        error.to_string(),
                    ))
                })
        })
    }

    fn approval_digest<'a>(
        &'a self,
        _session_id: SessionId,
        _approval_request_id: &'a ApprovalRequestId,
    ) -> VoiceFuture<'a, Option<Digest256>> {
        // This daemon holds no approval requests: they belong to the worker's agent binding,
        // which it does not dispatch. Answering "none" refuses the decision, which is the safe
        // answer: a coordinator that invented the details would be verifying them against itself.
        Box::pin(async move { Ok(None) })
    }
}

/// Where a proposal reaches this daemon's own dispatch.
#[derive(Debug)]
pub struct ControllerDispatch {
    daemon: Weak<Controller>,
}

impl ControllerDispatch {
    /// Builds the seam over one daemon.
    #[must_use]
    pub const fn new(daemon: Weak<Controller>) -> Self {
        Self { daemon }
    }
}

impl HostDispatch for ControllerDispatch {
    fn perform<'a>(
        &'a self,
        method: Method,
        proposal: &'a Proposal,
    ) -> VoiceFuture<'a, HostReceipt> {
        let daemon = self.daemon.clone();
        Box::pin(async move {
            let daemon = daemon.upgrade().ok_or_else(gone)?;
            // The whole proposal, not a copy of three of its fields: the device whose authority it
            // runs under, the grant it was admitted under and the plan the confirmation was bound
            // to are all part of what the effect is checked against.
            daemon
                .voice_perform(method, proposal)
                .await
                .map_err(|error| {
                    VoiceError::Host(kr_protocol::error::ProtocolError::new(
                        error.code(),
                        error.to_string(),
                    ))
                })
        })
    }
}
