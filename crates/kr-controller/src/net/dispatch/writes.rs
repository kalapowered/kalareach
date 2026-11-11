//! Which service answers each mutation a paired device sends, and the transfer service's arm.

use std::sync::Arc;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::EffectClass;
use kr_protocol::envelope::{ControlFrame, MutationRequest};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActorId, AuthorityRevision};
use kr_protocol::method::Method;

use super::forwarding::OwnClaim;
use super::routes::Unserved;
use super::{RemoteConnection, failure, outcome_unknown};
use crate::given::Given;

/// How this host answers one mutation a paired device may send: which service performs it, or the
/// reason it is refused.
///
/// [`DeviceWrite::of`] is the whole of the decision, one arm per method, and
/// [`RemoteConnection::serve_mutation`] does what it says once the grant has decided the request.
/// A write the method table admits for a paired device is either served or refused by name here,
/// and a test walks the table to hold it so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeviceWrite {
    /// `session.create`: the daemon launches the session itself.
    SessionCreate,
    /// `session.close`: dispatched to the worker over a link of its own.
    SessionClose,
    /// The project and workspace mutations, performed by the project service.
    Project,
    /// `changeset.materialize`: a private directory written from a version's stored content.
    Materialisation,
    /// `changeset.capture`, `diff.apply` and `diff.revert`, which touch a working tree.
    WorkingTree,
    /// The other change-set mutations.
    ChangeSet,
    /// The catalogue and plugin mutations.
    Catalogue,
    /// The review and attention mutations.
    Attention,
    /// The voice coordinator's mutations.
    Voice,
    /// `session.rename`.
    Rename,
    /// `grant.redeem`.
    Redemption,
    /// `grant.create` and `grant.revoke`.
    Delegation,
    /// The machine group's steps.
    MachineGroup,
    /// `membership.present`.
    Membership,
    /// `device.preview_key.update`.
    PreviewKey,
    /// `device.push.register`.
    PushRegistration,
    /// `device.keys.complete`.
    KeysComplete,
    /// The workflow mutations, performed by the automation service.
    Automation,
    /// The pairing and owner-confirmation mutations.
    Pairing,
    /// The draft writes, performed by the transfer service under the device's own principal.
    Transfer,
    /// Forwarded to the worker that owns the session, which serves the method.
    Worker,
    /// Refused by name, for the reason [`Unserved::refusal`] gives.
    Refused(Unserved),
}

impl DeviceWrite {
    /// Decides one method as a mutation from a paired device.
    ///
    /// `None` is a method the method table does not admit as one: not a write, or not one a paired
    /// device may make. Every write it does admit has an answer here: the worker takes a method
    /// only when its own table lists it, and a method nothing serves is refused by name, so no
    /// write reaches a refusal that names no reason.
    pub(super) fn of(method: Method) -> Option<Self> {
        let entry = method.entry();
        if entry.effect != EffectClass::Write
            || !entry.ingress.contains(&ActorIngress::PairedDevice)
        {
            return None;
        }
        Some(match method {
            Method::SessionCreate => Self::SessionCreate,
            Method::SessionClose => Self::SessionClose,
            Method::ChangesetMaterialize => Self::Materialisation,
            Method::ChangesetCapture | Method::DiffApply | Method::DiffRevert => Self::WorkingTree,
            Method::SessionRename => Self::Rename,
            Method::GrantRedeem => Self::Redemption,
            Method::GrantCreate | Method::GrantRevoke => Self::Delegation,
            Method::MachineJoin | Method::MachineMerge | Method::MachineSplit => Self::MachineGroup,
            Method::MembershipPresent => Self::Membership,
            Method::DevicePreviewKeyUpdate => Self::PreviewKey,
            Method::DevicePushRegister => Self::PushRegistration,
            Method::DeviceKeysComplete => Self::KeysComplete,
            Method::DraftCreate
            | Method::DraftUpdate
            | Method::DraftDiscard
            | Method::AgentDraftAddAttachment => Self::Transfer,
            Method::UploadBegin | Method::UploadFinish | Method::UploadCancel => {
                Self::Refused(Unserved::Upload)
            }
            Method::UploadChunk => Self::Refused(Unserved::Chunk),
            Method::TerminalPaletteSet => Self::Refused(Unserved::Palette),
            Method::InputWrite => Self::Refused(Unserved::RawInput),
            _ if crate::project::ProjectModule::serves(method) => Self::Project,
            _ if crate::changeset::ChangeSetModule::serves(method) => Self::ChangeSet,
            _ if crate::catalogue::CatalogueModule::serves(method) => Self::Catalogue,
            _ if crate::attention::AttentionModule::serves(method) => Self::Attention,
            _ if crate::voice::VoiceModule::serves(method) => Self::Voice,
            _ if crate::automation::AutomationModule::serves(method) => Self::Automation,
            _ if super::super::methods::serves(method) => Self::Pairing,
            _ if kr_protocol::worker_surface::serves(method) => Self::Worker,
            _ => return None,
        })
    }
}

impl RemoteConnection {
    /// Performs one draft write under this device's own principal, in the transfer service.
    ///
    /// The service scopes every draft by the principal that made it, so nothing the request names
    /// reaches the owner's drafts or another device's. The stored subject is read first, because
    /// reading it waits: for a blocking thread and for the journal's lock; the admission is asked
    /// after it, inside the service's own work, so that check is the last thing between the
    /// mutation and its effect. The action claims its route with this host named as the owner of
    /// what it produces, because the transfer service keeps its receipt.
    ///
    /// The effect runs on a task that outlives this connection, because dropping a future is a
    /// cancellation and a durable commit cannot be left half done because a peer went away. The
    /// answer says whether the service read it from its record of an earlier submission.
    pub(super) async fn transfer_write(
        &self,
        mutation: &MutationRequest,
        method: Method,
        actor_id: ActorId,
        validated: AuthorityRevision,
        accepted: &kr_transport::window::AcceptedDeadline,
        own_claim: &OwnClaim,
    ) -> std::result::Result<Given<ControlFrame>, ProtocolError> {
        self.controller
            .transfer
            .check_subject_of_record(&actor_id, mutation, method)
            .await?;
        if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
            return Err(refusal.into_error());
        }
        let carried = crate::authority::AdmittedMutation {
            connection_id: self.connection_id(),
            admitted_revision: validated,
            deadline: Some(accepted.deadline),
        };
        let controller = Arc::clone(&self.controller);
        let mutation = mutation.clone();
        let request_id = mutation.request_id;
        let effect = tokio::spawn(async move {
            if matches!(
                method,
                Method::DraftCreate | Method::AgentDraftAddAttachment
            ) {
                controller
                    .transfer
                    .settle_closures_of_open_drafts(&controller, &actor_id)
                    .await;
            }
            let admission =
                crate::transfer::TransferAdmission::new(Arc::clone(&controller), carried);
            controller
                .transfer
                .write_frame(
                    &actor_id,
                    &mutation,
                    method,
                    admission,
                    Some(crate::transfer::DEVICE_OPEN_DRAFTS),
                )
                .await
        });
        Ok(match self.controller.within_effect_wait(effect).await {
            Ok(Ok(given)) => given,
            // The effect is still running, so a wait that ended says the outcome is not known
            // rather than that the action failed.
            Ok(Err(_)) | Err(_) => Given::Fresh(failure(request_id, outcome_unknown())),
        })
    }
}
