//! The proposing seam: a spoken proposal becomes an ordinary host request.
//!
//! Section 15 ¶7: the coordinator proposes and the worker validates normally. This module is the
//! joint, and it is deliberately thin: it names the host method the registry already lists for the
//! effect and hands the proposal to this host's own dispatch. Nothing here decides whether the
//! effect may happen, because that decision belongs to the method's own entry and the checks that
//! run behind it.
//!
//! Section 15 ¶10: a host that accepted a proposal and did not perform it answers with
//! `performed` false, which the coordinator reports as admitted rather than done. The receipt the
//! answer names is the authority.

use std::sync::Arc;

use kr_protocol::method::Method;
use kr_protocol::voice::VoiceAction;
use kr_voice::seams::{ActionSubmitter, HostReceipt, VoiceFuture};
use kr_voice::{Proposal, VoiceError};

/// Where a proposal reaches this host's own dispatch.
pub trait HostDispatch: Send + Sync + std::fmt::Debug {
    /// Performs one proposal under the method the registry lists for its effect.
    fn perform<'a>(
        &'a self,
        method: Method,
        proposal: &'a Proposal,
    ) -> VoiceFuture<'a, HostReceipt>;
}

/// The submitting seam.
#[derive(Debug)]
pub struct ProposalSubmitter {
    dispatch: Arc<dyn HostDispatch>,
}

impl ProposalSubmitter {
    /// Builds the seam over this host's dispatch.
    #[must_use]
    pub const fn new(dispatch: Arc<dyn HostDispatch>) -> Self {
        Self { dispatch }
    }
}

/// The host method one voice action is performed under.
///
/// Read from the effect rather than chosen: every voice action names an ordinary action right, and
/// this is the method that right belongs to. A voice action with no host method in this release
/// resolves to nothing, and the coordinator has already refused it before this is called.
#[must_use]
pub const fn method_for(action: VoiceAction) -> Option<Method> {
    match action {
        VoiceAction::Navigate | VoiceAction::Status | VoiceAction::Brief => {
            Some(Method::SessionRead)
        }
        // Composing a draft is the device's own; the host is asked only to read the session it is
        // composed against, so nothing is written for it.
        VoiceAction::ComposePrompt => Some(Method::SessionRead),
        VoiceAction::SubmitPrompt => Some(Method::AgentPromptSubmit),
        VoiceAction::AnswerApproval => Some(Method::AgentApprovalRespond),
        VoiceAction::CancelTurn => Some(Method::AgentTurnCancel),
        VoiceAction::CloseSession => Some(Method::SessionClose),
        VoiceAction::ChangeGrant => Some(Method::GrantCreate),
        VoiceAction::ShellInput => Some(Method::InputWrite),
        VoiceAction::ApplyDiff => Some(Method::DiffApply),
        VoiceAction::DeliverExternally => None,
    }
}

impl ActionSubmitter for ProposalSubmitter {
    fn submit<'a>(&'a self, proposal: &'a Proposal) -> VoiceFuture<'a, HostReceipt> {
        Box::pin(async move {
            let Some(method) = method_for(proposal.action) else {
                return Err(VoiceError::refused(
                    kr_protocol::voice::VoiceRefusal::NoSuchEffect,
                    "this host has no method for that effect",
                ));
            };
            self.dispatch.perform(method, proposal).await
        })
    }
}
