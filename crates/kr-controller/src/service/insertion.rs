//! A worker's questions about a draft: what it holds, a claim of one binding for an offer to the
//! agent, and the report of the offer.
//!
//! They arrive on the rendezvous endpoint, one exchange to a connection, and are answered only to
//! the process this daemon recorded for the session they name. The worker names the actor the
//! action is for, and the transfer service looks for the draft among that actor's; the daemon
//! decides nothing about the draft itself, which is the transfer service's.

use kr_ipc::peer::PeerIdentity;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::insertion::{DraftAnswer, DraftWanted};

use super::Controller;
use super::plugin_runtime::Asker;

impl Controller {
    /// Answers one question about a draft.
    ///
    /// A process that is not the session's worker is refused, and one that asks before the daemon
    /// has recorded the worker is told to ask again, so an answer is never given on a weaker proof.
    pub(super) async fn draft_wanted(
        &self,
        wanted: DraftWanted,
        peer: &PeerIdentity,
    ) -> DraftAnswer {
        if let Err(refusal) = self.recorded_worker(wanted.session_id, peer).await {
            let code = match refusal {
                Asker::NotYet(_) => ErrorCode::ResourceUnavailable,
                Asker::NotTheWorker(_) => ErrorCode::PermissionDenied,
            };
            return DraftAnswer::Refused(ProtocolError::new(code, refusal.reason()));
        }
        self.transfer()
            .draft_step(wanted.session_id, wanted.actor_id, wanted.step)
            .await
    }
}
