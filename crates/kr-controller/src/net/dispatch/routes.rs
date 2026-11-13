//! The door's routes: which service answers each frame, read and mutation a paired device sends.

use std::sync::Arc;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{EffectClass, MethodEntry};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::RequestId;
use kr_protocol::method::Method;

use super::super::proxy::Vouched;
use crate::error::Result;
use crate::given::network_door::{self, noting};
use crate::given::{Given, Origin};

use super::super::Retained;
use super::super::chunks::ChunkAdmission;
use super::decision::{Answered, Asked, unserved_change_set_method};
use super::forwarding::{OwnClaim, RouteRefusal};
use super::writes::{Arrival, DeviceWrite};
use super::{RemoteConnection, failure, outcome_not_shown, outcome_unknown};

/// How long a caller waits for an effect the daemon owns before it is told the outcome is unknown.
///
/// The effect runs on a task that outlives the connection, so this bounds what the *caller* waits
/// for rather than the work: a device holding a request slot for a session that has stopped
/// answering is told, and the effect goes on to whatever end it reaches.
pub const EFFECT_WAIT: std::time::Duration = std::time::Duration::from_secs(45);

/// How this host answers one read a paired device may make: which service answers it, or the
/// reason it is refused.
///
/// [`DeviceRead::of`] is the whole of the decision, one arm per method, and
/// [`RemoteConnection::read`] does what it says after the grant has decided the request. A read
/// the method table admits for a paired device is either served or refused by name here, and a
/// test walks the table to hold it so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeviceRead {
    /// The daemon's own answer, out of the call the owner's own client reaches.
    ///
    /// The four host-and-environment reads leave in their export form: the daemon decides the
    /// form by who asked, in the one function every such answer leaves through, so a device is
    /// told which environments these are, what they run on and what they can do, and never an
    /// account name, a local path or what the platform said. `device.list` is the devices this
    /// host paired and the keys their pairing bound, which an owner's other device reads to learn
    /// a device's keys from the pairing the owner approved rather than from anything the device
    /// says of itself; the registry requires `host.manage` for it.
    Daemon,
    /// The daemon's own answer, narrowed to what the grant admits ([`RemoteConnection::narrow`]).
    ///
    /// A listing is every session, repository or working copy this actor may observe, not every
    /// one this host has. A read of one repository or working copy names its subject, so it is
    /// refused rather than narrowed when the grant does not reach that subject's environment, and
    /// the session content it carries is narrowed as the listing's is. A session read and a
    /// change-set read carry content the grant's lower bound decides.
    Narrowed,
    /// `diff.read`. A diff of a **recorded version** is answered from this host's own store, with
    /// no Git, for a version inside the device's grant: its environment, its session and the
    /// moment its history reaches back to ([`RemoteConnection::check_version`]). A diff of a
    /// **working copy** reads the working tree by running the Git program, so it is served only
    /// on a host that has proved the boundary, through the location the owner authorised for the
    /// device's grant ([`RemoteConnection::working_copy_diff`]).
    Diff,
    /// A receipt. One of an action this host performed itself is kept by the service that
    /// performed it, and the catalogue's are answered here; any other goes to the session whose
    /// journal holds it.
    Receipt,
    /// Forwarded to the worker of the session the read names, under this device's envelope and
    /// with its grant's history scope, and answered there by the rules the worker holds a paired
    /// device's envelope to: the state recovery reads, raw input, the questions and the agent
    /// reads. The worker holds the three that carry retained content, the questions, an agent's
    /// snapshot and an approval's record, to that scope through section 10's shared filter, and
    /// its answer is the device's: this daemon keeps no second filter to disagree with it. A
    /// question read goes only to a worker that says it holds one to the scope
    /// ([`super::super::proxy::WorkerProxy::forward_read`]).
    Worker,
    /// The automation group's read. A device is shown the workflows that act under the grant it
    /// holds, their runs and receipts, and the budgets and alerts of the chains those runs belong
    /// to; a workflow under another grant is not this device's to see.
    Workflow,
    /// The voice coordinator's own reads. A selection is built from what this daemon holds about
    /// the session, filtered under this device's own grant, a preparation reads this device's
    /// grants and the managed service's published terms, and what comes back goes to this device
    /// and nowhere else.
    Voice,
    /// The catalogue and plugin reads. A catalogue belongs to the environment rather than to a
    /// session, so there is no worker to forward them to and no session content to narrow: the
    /// grant's environment selector and `host.manage` are the whole of what admits them, and the
    /// module decides each at this connection's ingress.
    Catalogue,
    /// The review and attention reads, from this host's own store: the sessions the grant's
    /// selector admits with `session.view`, the automation of its own grant with
    /// `automation.manage`, the host's own items with `host.manage`, and no session text.
    Attention,
    /// The pairing and owner-confirmation reads. A device is the issuing owner of nothing, because
    /// invitations are issued over local IPC, so its `pair.status` is refused by the pairing
    /// service; an owner device reads the confirmations it can approve.
    Pairing,
    /// `grant.list`: the grants this device issued and everything delegated from them, which is
    /// the set its own delegation authority reaches. The registry requires `session.share`; the
    /// issuer this host lists for is the device itself.
    Grants,
    /// `grant.held`: what is offered to this device and what it holds, from the grant store. The
    /// device is the one this connection authenticated as, and nothing in the request names a
    /// device.
    Held,
    /// `session.open`: scopes the connection and says under what ([`RemoteConnection::session_open`]).
    Opening,
    /// `session.describe`: the session's name from the environment's metadata store, filtered for
    /// this device. Generated text is answered only when the grant's history reaches back to the
    /// session's start, because a description can summarise anything the session did.
    Description,
    /// `transfer.streams`: the stream kinds this host takes from a paired device. The answer is
    /// the list the listener is configured with, and reads nothing from the store.
    Transfer,
    /// `upload.status`: the chunks and the state of one of this device's own uploads, decided over
    /// the session the stored upload is bound to, or under the pairing grant for an upload that is
    /// bound to none ([`RemoteConnection::upload_session`]). The answer is a read of recorded state,
    /// so it goes through the end check a recorded answer is owed.
    UploadStatus,
    /// Refused by name, for the reason [`Unserved::refusal`] gives.
    Refused(Unserved),
}

impl DeviceRead {
    /// Decides one method as a request from a paired device.
    ///
    /// `None` is a method the method table does not admit as one: not a read, or not one a paired
    /// device may make. Raw input is the one write that travels as a request, because section 9
    /// makes it an ordered stream with no action identity.
    pub(super) fn of(method: Method) -> Option<Self> {
        let entry = method.entry();
        let request = entry.effect == EffectClass::Read || method == Method::InputWrite;
        if !request || !entry.ingress.contains(&ActorIngress::PairedDevice) {
            return None;
        }
        Some(match method {
            Method::HostInfo
            | Method::EnvironmentList
            | Method::EnvironmentCapabilities
            | Method::HostDoctor
            | Method::DeviceList
            | Method::OrganisationList
            | Method::PrivacyStatus
            | Method::DescriptionSetup => Self::Daemon,
            Method::ProjectList
            | Method::ProjectRead
            | Method::WorkspaceList
            | Method::WorkspaceRead
            | Method::ChangesetRead
            | Method::SessionList
            | Method::SessionRead => Self::Narrowed,
            Method::DiffRead => Self::Diff,
            Method::ActionRead => Self::Receipt,
            Method::EventsSubscribe
            | Method::EventsSnapshot
            | Method::HistoryPage
            | Method::InputWrite
            | Method::AgentCapabilities
            | Method::AgentSnapshot
            | Method::AgentCommands
            | Method::AgentApprovalInspect
            | Method::AgentInstances
            | Method::ShellLaunchSurface
            | Method::QuestionRead => Self::Worker,
            Method::WorkflowRead => Self::Workflow,
            Method::VoiceContext | Method::VoicePrepare => Self::Voice,
            Method::PairStatus | Method::OwnerConfirmationPending => Self::Pairing,
            Method::GrantList => Self::Grants,
            Method::GrantHeld => Self::Held,
            Method::SessionDescribe => Self::Description,
            Method::SessionOpen => Self::Opening,
            Method::TransferStreams => Self::Transfer,
            Method::UploadStatus => Self::UploadStatus,
            Method::DownloadBegin | Method::DownloadChunk => Self::Refused(Unserved::Transfer),
            _ if crate::catalogue::CatalogueModule::serves(method) => Self::Catalogue,
            _ if crate::attention::AttentionModule::serves(method) => Self::Attention,
            _ => return None,
        })
    }
}

/// Why this host refuses a paired device a method the method table admits for one, by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unserved {
    /// `download.begin` and `download.chunk`, which this host does not serve to a paired device on
    /// its control stream: a download begun for one would stage a copy nothing can read.
    Transfer,
    /// `upload.chunk` on the control stream. A chunk is as large as a control frame may not be, and
    /// travels on an attachment-chunk stream.
    Chunk,
    /// `terminal.palette.set`, which no part of this host performs for a paired device.
    Palette,
    /// `input.write` sent as a mutation. Raw input is an ordered stream with no action identity,
    /// so it travels as a request.
    RawInput,
}

impl Unserved {
    /// The refusal a device is given, naming the method and saying why.
    pub(super) fn refusal(self, entry: &MethodEntry) -> ProtocolError {
        let name = entry.name;
        match self {
            Self::Transfer => ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                format!("{name} is not served to a paired device by this host yet"),
            ),
            Self::Chunk => ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                format!(
                    "{name} is not served on the control stream: a transfer's chunks travel on an \
                     attachment-chunk stream"
                ),
            ),
            Self::Palette => ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                format!("{name} is not served to a paired device by this host yet"),
            ),
            Self::RawInput => ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{name} is raw input: it travels as a request and carries no action"),
            ),
        }
    }
}

impl RemoteConnection {
    /// Answers one frame from the device, which the listener read when `received` says.
    ///
    /// A mutation's requested lifetime is measured from then: the frame can have waited behind
    /// the answer to an earlier one, and section 9 measures from its receipt, not from the moment
    /// this turn begins.
    ///
    /// Returns `None` for a frame that does not belong on this ingress, which ends the connection:
    /// the union is closed so that a receiver can name what arrived, and naming it is only worth
    /// anything if it then refuses it.
    pub async fn answer(
        &self,
        received: kr_transport::listener::ReceivedFrame,
    ) -> Option<Answered> {
        self.answer_via(received, None).await
    }

    /// As [`Self::answer`], for a frame that arrived on a data stream when `on_stream` carries the
    /// stream's admission, and for one that arrived on the control stream when it does not.
    pub(super) async fn answer_via(
        &self,
        received: kr_transport::listener::ReceivedFrame,
        on_stream: Option<&Arc<ChunkAdmission>>,
    ) -> Option<Answered> {
        let mut asked = None;
        let mut received = received;
        let hold = received.take_hold();
        let (frame, received_at) = received.into_parts();
        let frame = match frame {
            ControlFrame::Request(request) => self.read_decided(&request, &mut asked).await,
            ControlFrame::Mutation(mutation) => {
                self.mutate_decided(&mutation, &mut asked, received_at, hold, on_stream)
                    .await
            }
            // A host does not call a client, and none of the daemon's own local frames belongs on
            // a network ingress. They are named rather than swept up, so a variant added later has
            // to be decided here.
            ControlFrame::Response(_)
            | ControlFrame::Receipt(_)
            | ControlFrame::Notification(_)
            | ControlFrame::Event(_)
            | ControlFrame::Hello(_)
            | ControlFrame::HelloAck(_)
            | ControlFrame::Rendezvous(_)
            | ControlFrame::LaunchSpec(_)
            | ControlFrame::WorkerReady(_)
            | ControlFrame::WorkerFailed(_)
            | ControlFrame::VerifyChallenge(_)
            | ControlFrame::VerifyProof(_)
            | ControlFrame::ControllerRole(_)
            | ControlFrame::GenerationChallenge(_)
            | ControlFrame::GenerationToken(_)
            | ControlFrame::GenerationAccepted(_)
            | ControlFrame::AuthorityRevision(_)
            | ControlFrame::AuthorityRevisionAck(_)
            | ControlFrame::LocalAccess(_)
            | ControlFrame::LocalAccessAck(_)
            | ControlFrame::PluginAdmissions(_)
            | ControlFrame::PluginAdmissionsAck(_)
            | ControlFrame::PluginRuntimeWanted(_)
            | ControlFrame::PluginRuntimeState(_)
            | ControlFrame::DraftWanted(_)
            | ControlFrame::DraftAnswer(_)
            | ControlFrame::Forwarded(_)
            | ControlFrame::ForwardedRead(_)
            | ControlFrame::RetainedResponse(_)
            | ControlFrame::AcceptanceDelivered(_)
            | ControlFrame::AttentionSources(_)
            | ControlFrame::AttentionSourcePage(_)
            | ControlFrame::AttentionText(_)
            | ControlFrame::AttentionTextAnswer(_)
            | ControlFrame::AttentionBarrier(_)
            | ControlFrame::AttentionBarrierAcknowledged(_)
            | ControlFrame::PrivacyGeneration(_)
            | ControlFrame::PrivacyGenerationAck(_)
            | ControlFrame::DescriptionFacts(_)
            | ControlFrame::DescriptionFactsPage(_)
            | ControlFrame::DesktopChecks(_)
            | ControlFrame::DesktopChecksAnswer(_) => return None,
        };
        Some(Answered { frame, asked })
    }

    /// Answers one frame that has just arrived, for a test that asks for no more than the answer.
    #[cfg(test)]
    pub(super) async fn answer_now(&self, frame: ControlFrame) -> Option<Answered> {
        let received_at = self.controller.clock.now();
        self.answer(kr_transport::listener::ReceivedFrame::at(
            frame,
            received_at,
        ))
        .await
    }

    /// Serves one read, for a test that asks for no more than the answer.
    #[cfg(test)]
    pub(super) async fn read(&self, request: &Request) -> ControlFrame {
        self.read_decided(request, &mut None).await
    }

    /// Serves one read, and keeps the decision it was taken under in `asked`.
    async fn read_decided(&self, request: &Request, asked: &mut Option<Asked>) -> ControlFrame {
        let entry = match self.admit(request.method.as_str(), request.method_version) {
            Ok(entry) => entry,
            Err(error) => return failure(request.request_id, error),
        };
        // Raw input is the one write that does not carry an action: section 9 makes it a separate
        // ordered stream with no durable de-duplication. Everything else that writes arrives as a
        // mutation, because a write needs an action identity and a freshness context.
        if entry.effect != EffectClass::Read && entry.method != Method::InputWrite {
            return failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is a mutation and carries an action", entry.name),
                ),
            );
        }
        // Before the read, not only after it. A registration withdrawn before this request arrived
        // must stop it, and a read that is refused must not have reached the subject first. The
        // revision comes from the same critical section, so a request can never be stamped with a
        // revision the registration was not still standing at.
        let validated = match self.admitted_at().await {
            Ok(validated) => validated,
            Err(error) => return failure(request.request_id, error),
        };
        // An open decides its own request: it names the grant to act under, which a generic
        // decision cannot, and its answer may be that the share is over.
        if entry.method == Method::SessionOpen {
            return self.session_open(request, entry, asked).await;
        }
        // An `action.read` that names an action only is decided over the session the action was
        // performed on, so what the decision carries at the write boundary is the authority over
        // that session.
        // An `upload.status` names an upload and no session: it is decided over the session the
        // stored upload is bound to, so a device that holds `files.upload` over that session alone
        // reads it, and an upload that is no one's of this device's is unknown.
        let named = if entry.method == Method::UploadStatus {
            match self.upload_session(request).await {
                Ok(named) => named,
                Err(error) => return failure(request.request_id, error),
            }
        } else {
            self.read_session(request, entry)
        };
        // A read never claims geometry: the condition on `terminal.geometry` is about a request
        // that claims or adds a claim, and only a mutation does either.
        let decided = match self.ask(named, entry, false) {
            Ok(decided) => decided,
            Err(error) => return failure(request.request_id, error),
        };
        *asked = Some(decided.clone());
        // The daemon's own reads are served as this device, not as the daemon: a module that keeps
        // its own subjects decides them against the actor that asked, and a read served under the
        // host's own principal would be answered about the host's own objects.
        let actor_id = self.device.principal();
        // One decision per method, and it is [`DeviceRead::of`]'s: every read the method table
        // admits for a paired device is served below or refused by name, and a test walks the table
        // to hold it so. Only a method the table does not admit for a device has no decision, and
        // the registry and the effect check above have refused every such method already.
        let Some(route) = DeviceRead::of(entry.method) else {
            return failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is not a read this host serves", entry.name),
                ),
            );
        };
        let answer = match route {
            DeviceRead::Daemon => {
                // What the host measured about itself goes to a device whose decision holds
                // `host.manage`, and the workers are asked for their counts only for one.
                let manages_host = decided
                    .decision
                    .decided
                    .permitted
                    .rights
                    .contains(&kr_protocol::rights::ActionRight::HostManage);
                self.controller
                    .read_method(&actor_id, request, manages_host)
                    .await
            }
            DeviceRead::Narrowed => {
                // A recorded version is read only inside the grant: its environment, its session
                // and the moment its history reaches back to, the check `changeset.materialize`
                // and `diff.read` of a recorded version are held to.
                let pinned;
                let request = if entry.method == Method::ChangesetRead {
                    match self.pinned_change_set_read(request).await {
                        Ok(request) => {
                            pinned = request;
                            &pinned
                        }
                        Err(error) => return failure(request.request_id, error),
                    }
                } else {
                    request
                };
                let mut answer = self.controller.read_method(&actor_id, request, false).await;
                if entry.method == Method::ChangesetRead {
                    answer = self.within_the_grant(answer).await;
                }
                let narrowed = self.narrow(answer, &decided.acting);
                if entry.method == Method::ChangesetRead {
                    super::narrowing::without_host_text(narrowed)
                } else {
                    narrowed
                }
            }
            DeviceRead::Diff => match request
                .params
                .to_typed::<kr_protocol::changeset::DiffReadParams>()
            {
                Ok(params) if params.change_set_id.is_present() => {
                    self.recorded_diff(request, &params).await
                }
                // A working copy's diff runs Git on its working tree, so it is held to the rule
                // the repository operations are, and is read through the location this device's
                // grant holds.
                _ => self.working_copy_diff(request, &decided.acting).await,
            },
            DeviceRead::Receipt => {
                // A catalogue action's receipt is decided again under the right its method
                // required, and the answer is written under that decision.
                let mut held = None;
                match self.host_receipt(request, &mut held).await {
                    Some(answer) => {
                        if let Some(under) = held {
                            *asked = Some(under);
                        }
                        answer
                    }
                    None => self.proxied_read(request, entry, validated, &decided).await,
                }
            }
            DeviceRead::Worker => {
                // A page of retained output is released only under the privacy state it was read
                // under, which is taken before the worker is asked.
                let read_under = if entry.method == Method::HistoryPage {
                    match super::output::ReadUnder::now(&self.controller).await {
                        Ok(read_under) => Some(read_under),
                        Err(error) => return failure(request.request_id, error),
                    }
                } else {
                    None
                };
                let answer = self.proxied_read(request, entry, validated, &decided).await;
                if let Some(asked) = asked.as_mut() {
                    asked.read_under = read_under;
                }
                answer
            }
            DeviceRead::Workflow => {
                self.controller
                    .automation()
                    .read_frame(request, Some(self.device.grant.grant_id))
                    .await
            }
            DeviceRead::Voice => {
                self.controller
                    .voice()
                    .read_frame(self.device.device_id, request)
                    .await
            }
            DeviceRead::Catalogue => {
                self.controller
                    .catalogue_read_frame(kr_protocol::actor::ActorIngress::PairedDevice, request)
                    .await
            }
            DeviceRead::Attention => {
                let caller = crate::attention::Caller::device(
                    &decided.acting.grant,
                    self.started_at_ms(&decided.acting),
                );
                let reach = self.controller.attention_reach();
                self.controller
                    .attention()
                    .read_frame(reach.as_ref(), &caller, &actor_id, request)
                    .await
            }
            DeviceRead::Pairing => {
                let caller = super::super::owner::Caller::device(self.device.clone())
                    .confirming_the_clock_only(
                        decided.decision.decided.permitted.confirms_the_clock_only,
                    )
                    .confirming_recovery_only(
                        decided.decision.decided.permitted.confirms_recovery_only,
                    );
                match self
                    .controller
                    .pairing_read(caller, entry.method, &request.params)
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(request.request_id, error.to_protocol_error()),
                }
            }
            DeviceRead::Grants => {
                match self
                    .controller
                    .grant_list(self.device.device_id, &request.params)
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(request.request_id, error.to_protocol_error()),
                }
            }
            DeviceRead::Held => {
                match self
                    .controller
                    .grant_held(self.device.device_id, &request.params)
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(request.request_id, error.to_protocol_error()),
                }
            }
            DeviceRead::Description => {
                let described = async {
                    let params: kr_protocol::describe::SessionDescribeParams =
                        request.params.to_typed().map_err(|error| {
                            crate::error::ControllerError::InvalidArgument(error.to_string())
                        })?;
                    let summary = self.controller.session_summary(params.session_id).await?;
                    let reaches_the_session = crate::describe::history_reaches_the_session(
                        &decided.acting.grant.history,
                        Some(self.started_at_ms(&decided.acting)),
                        Some(summary.created_at_ms),
                    );
                    self.controller
                        .session_describe(summary, reaches_the_session)
                        .await
                };
                match described.await {
                    // What a model wrote is answered only while the privacy state it was read
                    // under holds, decided now.
                    Ok(read) => ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: Outcome::Ok(self.controller.attention().settled(read).await),
                    }),
                    Err(error) => failure(request.request_id, error.to_protocol_error()),
                }
            }
            DeviceRead::Transfer => framed(
                request.request_id,
                ParamsValue::from_typed(&kr_protocol::transfer::TransferStreamsResult {
                    accepted_streams: super::super::chunks::ACCEPTED_STREAMS.to_vec(),
                })
                .map_err(|error| crate::error::ControllerError::InvalidArgument(error.to_string())),
            ),
            DeviceRead::UploadStatus => {
                let answer = self
                    .controller
                    .transfer
                    .read_frame(&actor_id, request)
                    .await;
                // A recorded answer is owed the check every recorded answer is: a fence this host
                // owes, or a registration withdrawn or replaced while the record was read, stops
                // it, and the device is told the answer is not shown.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: None,
                };
                let held = self.controller.check_retained_in_hand(&carried).await;
                // An upload that no session holds takes the session of the first draft it is bound
                // to and keeps it. This read was decided over the session the upload belonged to
                // before it was read, so an upload that belongs to another by the end of the read
                // is not shown under that decision: the device reads it again and is decided over
                // the session it is bound to now.
                let rebound = !self
                    .upload_session(request)
                    .await
                    .is_ok_and(|now| now == named);
                match held {
                    Ok(()) if !rebound => answer,
                    _ => failure(request.request_id, outcome_not_shown()),
                }
            }
            // Answered before the routes are read, so a request cannot arrive here.
            DeviceRead::Opening => {
                return failure(
                    request.request_id,
                    ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "session.open is answered before it is routed",
                    ),
                );
            }
            DeviceRead::Refused(unserved) => {
                return failure(request.request_id, unserved.refusal(entry));
            }
        };
        // Checked again now the read has finished. A read that passed its check and then waited
        // for a worker can complete after the authority behind it was withdrawn, and what the
        // contract forbids is *serving* that state rather than reading it.
        if let Err(error) = self.authorised().await {
            return failure(request.request_id, error);
        }
        answer
    }

    /// Serves one mutation, for a test that asks for no more than the answer.
    #[cfg(test)]
    pub(super) async fn mutate(&self, mutation: &MutationRequest) -> ControlFrame {
        let received_at = self.controller.clock.now();
        self.mutate_decided(mutation, &mut None, received_at, None, None)
            .await
    }

    /// Serves one mutation, and keeps the decision it was taken under in `asked`.
    ///
    /// A refusal this host makes on its own account is worded here, once, for the request that
    /// asked: a repeat of an action the host had already routed is not told it was refused
    /// ([`Self::told_of_a_repeat`]). What a service, a record or a worker answers is the answer.
    async fn mutate_decided(
        &self,
        mutation: &MutationRequest,
        asked: &mut Option<Asked>,
        received_at: kr_transport::clock::ContinuousInstant,
        hold: Option<kr_transport::listener::FrameHold>,
        on_stream: Option<&Arc<ChunkAdmission>>,
    ) -> ControlFrame {
        // Entered among the calls that have not claimed the route of their action from the moment
        // the transport read it, until it claims it or ends, so a refusal of a copy of it that
        // arrives meanwhile is worded as a repeat's.
        let own_claim = self
            .arrival_of(mutation, hold)
            .map_or_else(OwnClaim::none, OwnClaim::arrived);
        match self
            .serve_mutation(mutation, asked, received_at, &own_claim, on_stream)
            .await
        {
            Ok(answer) => answer,
            Err(refusal) => {
                #[cfg(test)]
                self.controller.before_a_refusal_is_worded.wait().await;
                failure(
                    mutation.request_id,
                    self.told_of_a_repeat(&own_claim, mutation, refusal),
                )
            }
        }
    }

    /// Serves one mutation. `Err` is a refusal this host made on its own account, before or around
    /// the lookup of the action's record or in the checks of its route; `Ok` is an answer, whether
    /// it comes from a record, a service or a worker, and it is the answer's own word.
    async fn serve_mutation(
        &self,
        mutation: &MutationRequest,
        asked: &mut Option<Asked>,
        received_at: kr_transport::clock::ContinuousInstant,
        own_claim: &OwnClaim,
        on_stream: Option<&Arc<ChunkAdmission>>,
    ) -> std::result::Result<ControlFrame, ProtocolError> {
        // Section 9 measures a requested lifetime from *receipt* time, which is when the listener
        // read the frame ([`kr_transport::listener::ReceivedFrame`]), before anything that can
        // wait: the frame's wait behind an earlier turn of this connection, the registry's lock, a
        // retained lookup, a worker's answer about a receipt. Deriving the deadline from a reading
        // taken after those waits would hand a request its whole lifetime back after it had
        // already spent part of it.
        let entry = match self.admit(mutation.method.as_str(), mutation.method_version) {
            Ok(entry) => entry,
            Err(error) => return Err(error),
        };
        if entry.effect != EffectClass::Write {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{} is a read and carries no action", entry.name),
            ));
        }
        // The registration first, before a retained result is looked up and before any effect is
        // considered. A revoked device gets no further dispatch, and it does not get its own
        // retained results back either: section 9 has the host check current authority before it
        // returns a retained receipt. The revision it is stamped with comes from the same critical
        // section as that check.
        let validated = match self.admitted_at().await {
            Ok(validated) => validated,
            Err(error) => return Err(error),
        };
        // A retained action is answered before anything about a first admission is considered.
        // Applying the freshness window to a retry would refuse a caller its own completed result
        // because the window it was admitted under has since been replaced. Its authority is
        // checked above, and the grant below, because an authority that has gone does not entitle
        // a caller to a result it once produced.
        let actor_id = self.device.principal();
        // The rights this request was decided with: the grant as this host's policy and its
        // configured ceiling leave it. They are what the worker is told the host checked.
        let decided = match self.ask_mutation(mutation, entry) {
            Ok(decided) => decided,
            Err(error) => return Err(error),
        };
        *asked = Some(decided.clone());
        let rights = decided.decision.decided.permitted.rights.clone();
        // One decision per method, and it is [`DeviceWrite::of`]'s: every write the method table
        // admits for a paired device is served below or refused by name, and a test walks the
        // table to hold it so. Only a method the table does not admit for a device has no
        // decision, and the registry and the effect check above have refused every such method
        // already.
        let Some(route) = DeviceWrite::of(entry.method) else {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{} is not a mutation this host serves", entry.name),
            ));
        };
        // A method this host refuses by name is refused here: after the device's rights are asked,
        // so a device that holds none is told so first, and before anything is recorded for it,
        // so the refusal claims no route, looks up no record and stages nothing.
        if let DeviceWrite::Refused(unserved) = route {
            return Err(unserved.refusal(entry));
        }
        // A chunk is served on an attachment-chunk stream and on no other, and a stream serves
        // chunks and nothing else: the stream's policy has held the frame to that already, and this
        // holds the door to it however the door is reached.
        match (route, on_stream.is_some()) {
            (DeviceWrite::Chunk, false) => return Err(Unserved::Chunk.refusal(entry)),
            (DeviceWrite::Chunk, true) => {}
            (_, true) => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    crate::transfer::WRONG_ENDPOINT,
                ));
            }
            (_, false) => {}
        }
        // Every store that retains an action is asked in turn, in the order the local ingress asks
        // them: the daemon's own reservations first, then the project service's own record. A
        // project mutation's receipt lives with the project service, so a retry of one that lost
        // its reply is answered there rather than dispatched again.
        let mut held = self
            .controller
            .retained(&actor_id, mutation, entry.method)
            .await;
        if held.is_none() && crate::project::ProjectModule::serves(entry.method) {
            held = self
                .controller
                .project
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        // A draft write's record is the transfer service's own, written in the transaction that
        // performed it, so a device that lost its reply is answered from it.
        if held.is_none() && matches!(route, DeviceWrite::Transfer | DeviceWrite::Chunk) {
            held = self
                .controller
                .transfer
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        // A materialisation's record is the change-set service's own, so a device that lost its
        // reply is answered from it, in the form a device is shown and under what its grant
        // reaches now.
        if held.is_none() && entry.method == Method::ChangesetMaterialize {
            match self.retained_materialisation(&actor_id, mutation).await {
                Ok(retained) => held = retained,
                Err(error) => return Err(error),
            }
        }
        // A capture's, an apply's and a revert's record is the change-set service's own as well,
        // and a repeat of one over a new connection carries a window that is not the new
        // connection's, so it is answered here, in the form a device is shown.
        if held.is_none()
            && matches!(
                entry.method,
                Method::ChangesetCapture | Method::DiffApply | Method::DiffRevert
            )
        {
            match self
                .retained_working_tree_change(&actor_id, mutation, entry.method, &decided.acting)
                .await
            {
                Ok(retained) => held = retained,
                Err(error) => return Err(error),
            }
        }
        // An automation action's record is the workflow journal's, written in the transaction
        // that performed it, so a device that lost its reply is answered from it.
        if held.is_none() && crate::automation::AutomationModule::serves(entry.method) {
            held = self
                .controller
                .automation()
                .retained(
                    &actor_id,
                    mutation,
                    entry.method,
                    Some(self.device.grant.grant_id),
                )
                .await;
        }
        // A catalogue mutation's receipt lives with the catalogue, beside the state the effect
        // changed, so a retry of one that lost its reply is answered there rather than performed a
        // second time.
        if held.is_none() && crate::catalogue::CatalogueModule::serves(entry.method) {
            held = self
                .controller
                .catalogue
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        if held.is_none() && crate::attention::AttentionModule::serves(entry.method) {
            let caller = crate::attention::Caller::device(
                &decided.acting.grant,
                self.started_at_ms(&decided.acting),
            );
            held = self
                .controller
                .attention()
                .retained(&caller, &actor_id, mutation, entry.method);
        }
        // An owner device's own confirmation answers are retained by the pairing service, and a
        // repeat of one over a new connection is answered from there.
        if held.is_none() && super::super::methods::serves(entry.method) {
            held = self
                .controller
                .pairing_retained(
                    super::super::owner::Caller::device(self.device.clone()),
                    entry.method,
                    mutation,
                )
                .await
                .map(|outcome| outcome.respond(mutation.request_id));
        }
        if let Some(retained) = held {
            return self
                .kept_answer(retained, entry.method, mutation, validated, &decided, asked)
                .await;
        }
        // A worker holds the receipts of its own actions, and the route says which worker. Section
        // 9 has an existing receipt readable under current authority after the window that
        // admitted it has expired, and answers a duplicate from a still-authorised actor from that
        // receipt without dispatching anything: so the receipt is asked for before the window is
        // considered, and a reused identifier carrying a different payload is refused here.
        match self.retained_remotely(mutation, validated, &decided).await {
            Ok(Some((answered, read))) => {
                *asked = Some(read);
                #[cfg(feature = "testing")]
                self.controller.after_the_retained_lookup.wait().await;
                return match self.admitted_to_answer(validated) {
                    Ok(()) => Ok(network_door::kept(
                        crate::service::net::AtTheNetworkDoor::here(),
                        answered,
                    )),
                    Err(_) => Err(outcome_not_shown()),
                };
            }
            Ok(None) => {}
            // Storage that cannot say whether this action has been dispatched says nothing about
            // the action. Section 7 does not let that stop an authorised stop, so a close goes on
            // and reports whatever durability it then had; anything else is refused.
            //
            // What a close then loses is this host's own check of `action.read` over the session,
            // because it is the route that would have said the close is a resubmission. The
            // worker's journal still decides idempotently, so a second close can come back from
            // the receipt the first produced. What that returns is the outcome of this device's
            // own close on a session its grant admits closing, and nothing else travels with it,
            // so the stop is allowed to happen and the narrower check is the one that gives way.
            Err(RouteRefusal::Unavailable(error)) => {
                if entry.method != Method::SessionClose {
                    return Err(error);
                }
            }
            Err(RouteRefusal::Conflict(error)) => return Err(error),
        }
        let accepted = {
            let authority = self.check_envelope(mutation, entry, &decided)?;
            match self.accept_in_window(mutation, received_at, authority) {
                Ok(accepted) => accepted,
                // A finish or a cancel is two commits: a claim, and what the claim leads to. An
                // exact repeat of one that an earlier connection began is the original request,
                // window included, and on this connection that window admits nothing; what it is
                // owed is what its claim says.
                Err(refusal)
                    if matches!(entry.method, Method::UploadFinish | Method::UploadCancel) =>
                {
                    return match self
                        .settle_a_repeat(
                            mutation,
                            entry.method,
                            validated,
                            &decided,
                            asked,
                            own_claim,
                        )
                        .await?
                    {
                        Some(frame) => Ok(frame),
                        None => Err(refusal),
                    };
                }
                Err(refusal) => return Err(refusal),
            }
        };
        // The last check this connection's own turn makes before the effect is admitted. It
        // guarantees nothing about what happens next: it releases the connection table before it
        // returns, a revocation runs on a task of its own, and the arms below wait — for a link to
        // a worker, for a dispatch lease, for a blocking thread. What stops a revoked action is
        // where each subject puts it.
        //
        // For a mutation a worker performs, section 9's own rule: every dispatch revalidates
        // current authority and expiry in the worker's serial path immediately before it acts, and
        // durable acceptance preserves neither. For a create or a project mutation, which this
        // host performs itself, the admission it carries is asked about again inside the daemon —
        // at the transition that lets a create launch, and in the project service's own work
        // before the action and inside the transaction that begins it, which is after the
        // service's own preparation.
        //
        // What this check does is keep an already-withdrawn connection from getting that far.
        // What this host reports meanwhile is the revocation as pending for a worker until it
        // acknowledges the revision.
        self.authorised().await?;
        #[cfg(test)]
        self.controller.before_the_effect.wait().await;
        // Whether the service that answered read its answer from the record of an earlier
        // submission of the action, which the device is then told as it is told any such answer,
        // or read that record and withheld it, which the device is told it is not shown.
        let mut origin = Origin::Fresh;
        let answer = match route {
            // The daemon's own effects. They run on a task that outlives this connection, because
            // dropping a future is a cancellation and a durable commit cannot be left half done
            // because a peer went away.
            DeviceWrite::SessionCreate => {
                // A create claims the same action identity every other mutation claims, with this
                // host named as the owner of what it produces. Without it, an identifier spent on
                // a create would be free for a mutation on a worker, and section 9 makes
                // `(verified actor, action)` one operation whoever ends up holding its receipt.
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                // The admission travels with the create: the connection it arrived on, the
                // revision it was admitted under and the deadline this host accepted. A create
                // reserves its identity and then waits for a lock, for a process to start and for
                // that process to report itself, and a revocation that completes during that wait
                // must stop the launch. The daemon checks all three again at the moment the launch
                // becomes possible, which nothing out here can do on its behalf.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .session_create(&actor_id, &mutation, carried)
                        .await
                });
                // A create the daemon answered from the reservation an earlier submission made is
                // the same read of somebody's result as a retained answer anywhere else, whether
                // that attempt launched a session or failed to, and it says so. It is told as any
                // answer read from a record is.
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    settled_by_a_service(
                        request_id,
                        tokio::time::timeout(crate::service::CREATE_WAIT, effect).await,
                    ),
                )
            }
            // A close is dispatched to the worker, so it goes over a bounded link of its own
            // rather than over the connection this host announces authority revisions on: a worker
            // that stopped answering a close would otherwise hold that connection. Opening the
            // link is also what asks the worker for the acknowledgement a dispatch lease needs,
            // which a device closing a session it never attached to has not caused yet.
            DeviceWrite::SessionClose => {
                // A close opens a link of its own to the worker, so the route is refused here,
                // before it claims an action, on a connection that serves the host alone.
                self.check_worker_route()?;
                let Some(session_id) = mutation.target.session_id.as_ref().copied() else {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "this mutation names the session it acts on",
                    ));
                };
                // A conflicting identifier refuses the close; storage that cannot record the
                // route does not. Section 7 has an authorised stop go ahead when storage fails,
                // and the worker reports what its own durability then was.
                match self.claim_route(mutation, Some(session_id), own_claim) {
                    Ok(()) | Err(RouteRefusal::Unavailable(_)) => {}
                    Err(RouteRefusal::Conflict(error)) => {
                        return Err(error);
                    }
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let envelope = self.envelope(decided.acting.grant.grant_id, validated);
                let grant_rights = rights;
                let history = decided.acting.grant.history.clone();
                let receive = self.output.receive();
                let request_id = mutation.request_id;
                // The answer comes back before the link that carried the close is released,
                // because releasing it is what tells the worker the acceptance was delivered.
                let (answer, answered) = tokio::sync::oneshot::channel();
                let (tell, delivered) = tokio::sync::oneshot::channel();
                self.output().on_delivery(request_id, tell);
                let observer = self.expiry_observer();
                // The close runs on a task that outlives this connection, so it takes the standing
                // the feed's refusal is asked of with it, and, when its route could not be recorded,
                // the call's entry among those that have not claimed: a copy that arrives while the
                // close runs finds the entry, as it would find the route.
                let standing = self.feed_standing(&decided.acting.grant);
                let entered = own_claim.shared_with_the_work();
                tokio::spawn(async move {
                    let reached_the_worker = controller
                        .close_remote_session(
                            &mutation,
                            Vouched {
                                actor: &envelope,
                                grant_rights: &grant_rights,
                                history: Some(&history),
                                screen_basis: None,
                                // Stopping owned execution does not depend on the remote lease.
                                lease: None,
                            },
                            &standing,
                            accepted,
                            Some(&observer),
                            answer,
                            delivered,
                            receive,
                        )
                        .await;
                    // The close has no route and its entry goes with this task. A close that was
                    // carried out, or may have been, is kept: a copy that arrives later finds the
                    // request kept as one carried out without a route. A close that never reached
                    // the worker did nothing, and keeps nothing: its copy is refused as any request
                    // the host has not seen.
                    if reached_the_worker && let Some(entered) = entered {
                        entered.settle_without_a_route();
                    }
                });
                match self.controller.within_effect_wait(answered).await {
                    Ok(Ok(Ok(closed))) => {
                        let answer = ControlFrame::Response(Response {
                            request_id,
                            outcome: Outcome::Ok(closed.value),
                        });
                        // A close the worker answered from its journal is a read of that receipt,
                        // and this is the check section 23 wants before either half of a retained
                        // result goes back, under the decision the answer is then written under.
                        // The close itself happened: section 7's stop does not wait on this, and
                        // only the answer does, so a close not shown is not told as one refused.
                        match closed.retained {
                            Retained::Not => {}
                            Retained::Record | Retained::Worker => {
                                match self.may_read_receipts(
                                    Some(session_id),
                                    Method::SessionClose,
                                    &decided.acting,
                                ) {
                                    Ok(read) => *asked = Some(read),
                                    Err(_) => return Err(outcome_not_shown()),
                                }
                            }
                        }
                        answer
                    }
                    Ok(Ok(Err(error))) => return Err(error.to_protocol_error()),
                    // The close is running on a task that outlives this connection, so a wait
                    // that ended says the outcome is not known rather than that it failed.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The project and workspace mutations. Like a create, they are the daemon's own
            // effect: no session owns them, so they go to the project service rather than to a
            // worker proxy, and the admission travels with them so the service can ask about it
            // again after the waiting it does of its own.
            DeviceWrite::Project => {
                self.check_project_authority(entry.method, mutation)?;
                // A project mutation claims its action identity the way every other mutation
                // does, with this host named as the owner of what it produces. Storage that
                // cannot record the route refuses it: only section 7's stop goes on without one.
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                // The service is told this caller is bounded by this device's grant, so nothing
                // the request carries can make it the owner.
                let grant = self.device.grant.grant_id;
                // On a task that outlives this connection, because a clone reaches the network and
                // a materialisation copies files: dropping that future part way through is a
                // cancellation, and what it would leave behind is exactly what an action identity
                // exists to make recoverable.
                let effect = tokio::spawn(async move {
                    controller
                        .project_mutation(&actor_id, &mutation, method, carried, Some(grant))
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given.map(|outcome| framed_protocol(request_id, outcome)),
                    ),
                    // The effect is still running, so a wait that ended says the outcome is not
                    // known rather than that the action failed.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The change-set mutations. Like the project's, they are the daemon's own effect and
            // no session owns them, so a worker proxy is not where they belong either.
            //
            // A materialisation is served: it runs no Git and reads no working tree, it writes a
            // private directory of the change-set service's own from the version's stored content,
            // and every transaction that commits it runs inside the daemon's hold of this
            // connection's admission, so a grant withdrawn while it waits leaves nothing behind.
            // What a device may ask for is a version inside its grant, and what it is told is the
            // materialisation without the host path of its directory.
            DeviceWrite::Materialisation => {
                self.check_materialisation(mutation).await?;
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                // On a task that outlives this connection: a materialisation writes a tree of
                // files, and dropping the future part way is a cancellation.
                let effect = tokio::spawn(async move {
                    let held = Arc::clone(&controller);
                    controller
                        .changesets()
                        .write_frame(&actor_id, &mutation, method, carried, held, None)
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given.map(super::narrowing::shown_materialisation),
                    ),
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // Capture, apply and revert each run Git on a working tree. They are served to a
            // device on a host that has proved it confines what that program reads, for a
            // workspace the owner's location for this device's grant reaches, and the service is
            // told the caller is bounded by that grant, so nothing the request carries can make
            // it the owner. This replaces the refusal these three were given whatever the host
            // and the grant.
            DeviceWrite::WorkingTree => {
                self.check_working_tree_request(
                    entry.method,
                    &mutation.params,
                    &decided.acting,
                    super::narrowing::Earlier::Nothing,
                )
                .await?;
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let grant = self.device.grant.grant_id;
                // On a task that outlives this connection: an apply writes a tree of files, and
                // dropping the future part way is a cancellation.
                let effect = tokio::spawn(async move {
                    let held = Arc::clone(&controller);
                    controller
                        .changesets()
                        .write_frame(&actor_id, &mutation, method, carried, held, Some(grant))
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given.map(|answer| {
                            super::narrowing::shown_working_tree_change(answer, method)
                        }),
                    ),
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // A change-set mutation the registry lists without a route above is refused rather
            // than handed to a worker, which does not own it.
            DeviceWrite::ChangeSet => {
                return Err(unserved_change_set_method(entry.method));
            }
            // The ten catalogue and plugin mutations. They are the daemon's own effect: a catalogue
            // and an installed package belong to the environment, so no worker owns them and the
            // module performs them under its own lock.
            DeviceWrite::Catalogue => {
                // The route is claimed before the effect, the way a project mutation claims its
                // own. It is this host's `(verified actor, action)` uniqueness check, and it is
                // what a device that lost its connection has left to say the daemon owns the
                // receipt. Storage that cannot record it refuses the mutation: only section 7's
                // stop goes on without a route.
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                // The owner's own ceremony, checked by this host's pairing service against its owner
                // devices; a host with none refuses every method that needs the owner's
                // confirmation (adopting a root, a grant, an installation that widens what a
                // package may do) rather than performing it under the identity of whoever asked.
                let pairing = self
                    .controller
                    .network
                    .get()
                    .map(|guard| Arc::clone(guard.pairing()));
                let controller = Arc::clone(&self.controller);
                let admitting = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                // On a task that outlives this connection: a sync writes verified metadata and an
                // installation extracts a package onto disk, and dropping that future part way
                // through is a cancellation. The admission travels with it, because the module
                // waits for its own lock, for the repository's and for downloads, and asks about
                // the registration again where the change becomes durable.
                let effect = tokio::spawn(async move {
                    let confirmations = pairing
                        .as_deref()
                        .map(|host| host as &dyn crate::sharing::OwnerConfirmations);
                    let admission: Arc<dyn crate::catalogue::Admission> =
                        Arc::new(crate::catalogue::DaemonAdmission::new(admitting, carried));
                    controller
                        .catalogue_write(&actor_id, &mutation, method, confirmations, admission)
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given.map(|outcome| framed_protocol(request_id, outcome)),
                    ),
                    // The effect is still running, so a wait that ended says the outcome is not
                    // known rather than that the action failed. The action record the module
                    // settles is what a resubmission is answered from.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The review and attention group's mutations are this host's own store's actions, like
            // a project's: no worker owns them, and the admission travels with them into the
            // store's transaction.
            DeviceWrite::Attention => {
                if let Err(error) =
                    crate::attention::AttentionModule::check_subject(entry.method, mutation)
                {
                    return Err(error.to_protocol_error());
                }
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let caller = crate::attention::Caller::device(
                    &decided.acting.grant,
                    self.started_at_ms(&decided.acting),
                );
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .attention()
                        .write_frame(&controller, &caller, &actor_id, &mutation, method, &carried)
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given,
                    ),
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The four voice mutations. Like a create, they are the daemon's own effect: a voice
            // session belongs to this host rather than to one terminal session, and the
            // coordinator decides each one against the voice grant and this device's ordinary
            // grant, intersected at the moment of the decision.
            DeviceWrite::Voice => {
                // The deadline this mutation was admitted under, checked last: everything between
                // the envelope check and here can wait, and an action whose deadline passed while
                // it queued does not go on to write. A retry of a completed voice change is
                // answered from its own record before the effect.
                if self.controller.clock.now() >= accepted.deadline {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the deadline this action was admitted under passed before it could \
                             run",
                    ));
                }
                let actor_id = self.device.principal();
                // A voice mutation claims its action identity the way every other mutation does,
                // with this host named as the owner of what it produces. The voice service keeps
                // its own record of the answer, and this claim is what makes `(verified actor,
                // action)` one key across every route: an identifier a voice mutation used is not
                // free for a create or a close, and the other way round.
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                // The admission travels with the change, as it does with a project or an
                // automation mutation, and the voice service asks it again where it writes.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let given = self
                    .controller
                    .voice_mutation(
                        crate::service::voice_actions::VoiceIngress {
                            actor_id: actor_id.clone(),
                            actor: crate::voice::VoiceActor::Device(self.device.device_id),
                            route: Some(Arc::new(crate::service::voice_actions::DeviceRoute {
                                devices: Arc::clone(&self.devices),
                                actor_id: actor_id.clone(),
                                mutation: mutation.clone(),
                            })),
                        },
                        mutation,
                        entry.method,
                        validated,
                        carried,
                    )
                    .await;
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    given.map(|answer| framed(mutation.request_id, answer)),
                )
            }
            // A session's pinned name is this daemon's own effect, once per actor's action. The
            // route names this host as the owner of the receipt, the action is claimed in the
            // daemon's store, and the effect runs on a task that outlives this connection and keeps
            // what it came to under the claim before it is answered, so a retry is answered from
            // that record.
            DeviceWrite::Rename => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    let claimed = kr_protocol::digest::mutation_digest(&mutation, &actor_id)
                        .map_err(|error| {
                            crate::error::ControllerError::InvalidArgument(error.to_string())
                        })
                        .and_then(|digest| {
                            controller.sharing.grants().claim_action(
                                &actor_id,
                                mutation.action_id,
                                &digest,
                                kr_ipc::now_ms().get(),
                            )
                        });
                    let mut origin = Origin::Fresh;
                    let hold = match claimed {
                        Ok(crate::grants::ActionClaim::Claimed { hold }) => hold,
                        // An earlier attempt under this identifier claimed the action, and may
                        // have renamed the session: what became of it is not known here, and a
                        // transient word would say nothing took effect. That is said of another
                        // attempt's record, so it is a copy, and goes back only under the
                        // authority this one still has.
                        Ok(crate::grants::ActionClaim::Recorded(_)) => {
                            origin.note(Origin::Copied);
                            let found = crate::error::ControllerError::attempt_still_running();
                            let told = match controller.check_retained_in_hand(&carried).await {
                                Ok(()) => found,
                                Err(lapsed) => {
                                    origin.note(Origin::Withheld);
                                    lapsed
                                }
                            };
                            return Given::from_origin(Err(told), origin);
                        }
                        Err(error) => {
                            let told = controller
                                .conflict_under_authority(&carried, &mut origin, error)
                                .await;
                            return Given::from_origin(Err(told), origin);
                        }
                    };
                    let outcome = match mutation.target.session_id.as_ref().copied() {
                        Some(session_id) => match controller.session_summary(session_id).await {
                            Ok(summary) => {
                                controller
                                    .session_rename(&actor_id, &mutation, summary, carried)
                                    .await
                            }
                            Err(error) => Err(error),
                        },
                        None => Err(crate::error::ControllerError::InvalidArgument(
                            "a rename names the session it renames".to_owned(),
                        )),
                    };
                    // A receipt that cannot be kept does not change what the rename did, and the
                    // device is told that, not that the registry failed: the claim stays
                    // unfinished, and a retry is told the outcome is not known and does not rename
                    // again.
                    if let Err(unrecorded) = controller.settle_claim(&hold, &outcome) {
                        eprintln!(
                            "kr-controller: a rename's receipt could not be kept: {unrecorded}"
                        );
                    }
                    drop(hold);
                    Given::fresh(outcome)
                });
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    settled_by_a_service(
                        request_id,
                        self.controller.within_effect_wait(effect).await,
                    ),
                )
            }
            // A redemption is this daemon's own effect, once per actor's action, for the device
            // that sends it and no other: the invitation names the device that may redeem it. The
            // route names this host as the owner of the receipt, and the redemption is claimed,
            // committed with its answer and answered on a task that outlives this connection, so
            // a retry is answered from that record.
            DeviceWrite::Redemption => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let device_id = self.device.device_id;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .authority_change(
                            &actor_id,
                            crate::service::authority_changes::AuthorityCaller::Device(device_id),
                            &mutation,
                            Method::GrantRedeem,
                            carried,
                        )
                        .await
                        .into_given()
                });
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    settled_by_a_service(
                        request_id,
                        self.controller.within_effect_wait(effect).await,
                    ),
                )
            }
            // A device delegates a narrower grant from a share it holds, and revokes what lies
            // below a share it holds. They are this daemon's own effects, once per actor's action,
            // for the device that sends them and decided under a share: a pairing grant is not a
            // grant to delegate from, and the grant a delegation is made from is the one it acts
            // under.
            DeviceWrite::Delegation => {
                if decided.acting.held != super::acting::Held::Share {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "a device delegates from a share it holds, and its pairing grant is \
                             not one",
                    ));
                }
                if entry.method == Method::GrantCreate {
                    let Ok(params) = mutation
                        .params
                        .to_typed::<kr_protocol::sharing::GrantCreateParams>()
                    else {
                        return Err(ProtocolError::new(
                            ErrorCode::InvalidArgument,
                            "grant.create takes the parameters of a share",
                        ));
                    };
                    if params.parent_grant_id.0 != Some(decided.acting.grant.grant_id) {
                        return Err(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "a delegation names the grant it is made from, and the request \
                                 acts under that grant",
                        ));
                    }
                    // The rights this request was decided with are the grant as this host's
                    // policy leaves it: its configured ceiling, and an organisation's lease where
                    // the grant carries one. A delegation hands on no more than that, so a right
                    // either removed is not delegated, and the session text a share's preview
                    // carries is not read for a device that may not view the session.
                    if !params.selection.actions().is_subset(&rights) {
                        return Err(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "a delegation hands on no right that this host's policy removes \
                                 from the grant it is made from",
                        ));
                    }
                }
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let device_id = self.device.device_id;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .authority_change(
                            &actor_id,
                            crate::service::authority_changes::AuthorityCaller::Device(device_id),
                            &mutation,
                            method,
                            carried,
                        )
                        .await
                        .into_given()
                });
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    settled_by_a_service(
                        request_id,
                        self.controller.within_effect_wait(effect).await,
                    ),
                )
            }
            // A machine group step changes this environment's own record and nothing else: the
            // daemon's own effect, once per actor's action, and never forwarded to a worker or to
            // another environment. The route names this host as the owner of the receipt, and the
            // step is claimed, written and its receipt kept on a task that outlives this
            // connection, so a retry is answered from that record.
            DeviceWrite::MachineGroup => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .machine_step(&actor_id, &mutation, method, carried)
                        .await
                });
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    settled_by_a_service(
                        request_id,
                        self.controller.within_effect_wait(effect).await,
                    ),
                )
            }
            // A device presenting the lease its organisation signed for it: the daemon's own
            // effect, on this device's standing and nothing else. The action claims its route like
            // every other, so one identifier is one request per actor. The lease is installed and
            // the fence it may owe published on a task that outlives this connection, so a
            // connection that ends does not cut a presentation between its policy write and its
            // fence; the device that was not answered presents the same lease again.
            DeviceWrite::Membership => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                if self.controller.clock.now() >= accepted.deadline {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the deadline this action was admitted under passed before it could \
                             run",
                    ));
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let device_id = self.device.device_id;
                let proven_key = self.device.authorisation;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .membership_present(device_id, &proven_key, &mutation, carried)
                        .await
                });
                settled(request_id, self.controller.within_effect_wait(effect).await)
            }
            DeviceWrite::PreviewKey => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let actor_id = self.device.principal();
                // A completed registration is answered from what it produced, before the deadline
                // is looked at: a device whose answer was lost asks again with the same action and
                // is told what it was told, after a later rotation or once its window has closed.
                // The earlier lookup found nothing, and an attempt that finished since is found
                // here; the answer goes back under the admission asked with it in hand, as the
                // earlier lookup's does.
                #[cfg(feature = "testing")]
                self.controller
                    .before_the_second_retained_lookup
                    .wait()
                    .await;
                if let Some(answer) = self
                    .controller
                    .retained_authority_change(&actor_id, mutation)
                {
                    return self
                        .kept_answer(answer, entry.method, mutation, validated, &decided, asked)
                        .await;
                }
                if self.controller.clock.now() >= accepted.deadline {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the deadline this action was admitted under passed before it could \
                             run",
                    ));
                }
                // The admission travels into the writes, as a key declaration's does: the stores
                // ask about it again where they are written.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    self.controller
                        .preview_key_update_action(&actor_id, mutation, carried)
                        .await
                        .map(|answer| framed(mutation.request_id, answer)),
                )
            }
            // A device handing the host the credential its installation was issued: the daemon's
            // own effect, on the destination of the device this connection authenticated as. Its
            // answer is retained like a key registration's, because the gateway is asked before
            // anything is kept and the answer can be lost on the way back: a repeat of a finished
            // registration is answered before the call is admitted, on a later connection and
            // after its window has closed. What reaches this arm is a first request or a copy of
            // one still running, which the claim in `push_register_action` answers.
            DeviceWrite::PushRegistration => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let actor_id = self.device.principal();
                if self.controller.clock.now() >= accepted.deadline {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the deadline this action was admitted under passed before it could \
                             run",
                    ));
                }
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    self.controller
                        .push_register_action(&actor_id, mutation, carried)
                        .await
                        .map(|answer| framed(mutation.request_id, answer)),
                )
            }
            // A device completing its own record: the daemon's own effect, on this device's own
            // row and nothing else. The parameters name no device; the one written is the one this
            // connection authenticated as. The admission travels with the declaration, so the
            // transaction that writes the keys asks about it again and records the outcome beside
            // them, which is what a retry of this action is answered from.
            DeviceWrite::KeysComplete => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    self.controller
                        .device_keys_declared(&actor_id, self.device.device_id, mutation, carried)
                        .await
                        .map(|answer| framed(mutation.request_id, answer)),
                )
            }
            // The automation group. Like a project mutation it is the daemon's own effect: a
            // workflow belongs to this environment rather than to a session, so it goes to the
            // automation service rather than to a worker proxy. The admission travels with it into
            // the workflow journal's own transaction, and the device reaches only the workflows
            // that act under the grant it holds, so a workflow cannot give it rights its grant
            // does not carry.
            DeviceWrite::Automation => {
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let caller_grant = Some(self.device.grant.grant_id);
                // On a task that outlives this connection: a run dispatches its nodes, and
                // dropping that future part way through would be a cancellation.
                let effect = tokio::spawn(async move {
                    controller
                        .automation_mutation(&actor_id, &mutation, method, carried, caller_grant)
                        .await
                });
                match self.controller.within_effect_wait(effect).await {
                    Ok(Ok(given)) => noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given.map(|outcome| framed_protocol(request_id, outcome)),
                    ),
                    // The run is still going, or its task ended without an answer. Whether the
                    // action was committed is the journal's to say: if it was, a repeat is
                    // answered from its record, and if it was not, a repeat performs it.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The pairing and owner-confirmation mutations. An owner device completes the
            // confirmations it signed; `pair.confirm` and `pair.cancel` are the issuing owner's,
            // and a device never issued an invitation, so the pairing service refuses them.
            DeviceWrite::Pairing => {
                // A pairing mutation claims its action identity the way every other mutation does,
                // with this host named as the owner of what it produces.
                if let Err(refusal) = self.claim_route(mutation, None, own_claim) {
                    return Err(refusal.into_error());
                }
                if self.controller.clock.now() >= accepted.deadline {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the deadline this action was admitted under passed before it could \
                             run",
                    ));
                }
                let caller = super::super::owner::Caller::device(self.device.clone())
                    .confirming_the_clock_only(
                        decided.decision.decided.permitted.confirms_the_clock_only,
                    )
                    .confirming_recovery_only(
                        decided.decision.decided.permitted.confirms_recovery_only,
                    );
                let admission = self.controller.pairing_admission(
                    self.connection_id(),
                    Some(validated),
                    Some(accepted.deadline),
                );
                let guard = self.controller.pairing_guard(
                    self.connection_id(),
                    Some(validated),
                    Some(accepted.deadline),
                );
                let life = self.controller.pairing_life(Some(accepted.deadline));
                let retained = self
                    .controller
                    .pairing_standing(self.connection_id(), Some(validated));
                noting(
                    crate::service::net::AtTheNetworkDoor::here(),
                    &mut origin,
                    self.controller
                        .pairing_write(
                            caller,
                            entry.method,
                            mutation,
                            admission,
                            retained,
                            guard,
                            life,
                        )
                        .await
                        .map(|answer| framed(mutation.request_id, answer)),
                )
            }
            // A draft write or a chunk is the transfer service's, performed under this device's own
            // principal.
            DeviceWrite::Transfer | DeviceWrite::Chunk => self
                .transfer_write(
                    mutation,
                    entry.method,
                    actor_id,
                    crate::authority::AdmittedMutation {
                        connection_id: self.connection_id(),
                        admitted_revision: validated,
                        deadline: Some(accepted.deadline),
                    },
                    own_claim,
                    on_stream.map_or(Arrival::Control, Arrival::Stream),
                )
                .await
                .map(|given| {
                    noting(
                        crate::service::net::AtTheNetworkDoor::here(),
                        &mut origin,
                        given,
                    )
                })?,
            // A method this host refuses by name was refused above, before anything was recorded.
            DeviceWrite::Refused(unserved) => return Err(unserved.refusal(entry)),
            // Everything else the worker's own table lists belongs to the worker that owns the
            // session.
            DeviceWrite::Worker => {
                return self
                    .proxied_mutation(
                        mutation,
                        accepted,
                        validated,
                        rights,
                        &decided.acting,
                        asked,
                        own_claim,
                    )
                    .await;
            }
        };
        match origin {
            Origin::Fresh => Ok(answer),
            Origin::Copied => {
                self.kept_copy(answer, entry.method, mutation, validated, &decided, asked)
                    .await
            }
            Origin::Withheld => Err(self.withheld_answer(&decided, asked)),
        }
    }
}

impl RemoteConnection {
    /// Answers an exact repeat of an upload finish or cancel whose window this connection never
    /// issued, from what its action's claim says.
    ///
    /// A claim that is open is finished, and nothing else is begun. A claim that was settled gives
    /// back the answer it was settled with, under the check any recorded answer is owed. An action
    /// with no claim is a first admission, which has no window: the answer is `None`, and the caller
    /// refuses it for the window, told as a repeat's refusal when a copy of the request has been
    /// carried out or is on its way ([`Self::told_of_a_repeat`]).
    async fn settle_a_repeat(
        &self,
        mutation: &MutationRequest,
        method: Method,
        validated: kr_protocol::ids::AuthorityRevision,
        decided: &Asked,
        asked: &mut Option<Asked>,
        own_claim: &OwnClaim,
    ) -> std::result::Result<Option<ControlFrame>, ProtocolError> {
        use crate::transfer::Settling;

        let actor_id = self.device.principal();
        match self
            .controller
            .transfer
            .settles(&actor_id, mutation, method)
            .await
        {
            Settling::No => Ok(None),
            Settling::Answered(answer) => self
                .kept_answer(answer, method, mutation, validated, decided, asked)
                .await
                .map(Some),
            Settling::Open => {
                let mut origin = Origin::Fresh;
                let answer = self
                    .transfer_write(
                        mutation,
                        method,
                        actor_id,
                        crate::authority::AdmittedMutation {
                            connection_id: self.connection_id(),
                            admitted_revision: validated,
                            deadline: None,
                        },
                        own_claim,
                        Arrival::Settling,
                    )
                    .await
                    .map(|given| {
                        noting(
                            crate::service::net::AtTheNetworkDoor::here(),
                            &mut origin,
                            given,
                        )
                    })?;
                match origin {
                    Origin::Fresh => Ok(Some(answer)),
                    Origin::Copied => self
                        .kept_copy(answer, method, mutation, validated, decided, asked)
                        .await
                        .map(Some),
                    Origin::Withheld => Err(self.withheld_answer(decided, asked)),
                }
            }
        }
    }

    /// The session an `upload.status` is decided over: the one the stored upload is bound to, and
    /// none for an upload that is bound to none, which is asked under the pairing grant.
    ///
    /// The upload is looked up under this device's own principal, so another principal's upload and
    /// one that does not exist are the same unknown answer, and a failed look is never a read that
    /// names no session.
    async fn upload_session(
        &self,
        request: &Request,
    ) -> std::result::Result<Option<kr_protocol::ids::SessionId>, ProtocolError> {
        let params: kr_protocol::transfer::UploadStatusParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        self.controller
            .transfer
            .stored_session(&self.device.principal(), params.transfer_id)
            .await
    }
}

/// Returns what one spawned effect settled as.
///
/// The task owns the effect and outlives this connection, so a wait that ran out says the outcome
/// is unknown rather than that the action failed: the effect is still running, and section 9
/// forbids reporting an action that may have happened as refused.
type Effect<Ended, Settled = Result<ParamsValue>> =
    std::result::Result<std::result::Result<Settled, tokio::task::JoinError>, Ended>;

fn settled<Ended>(request_id: RequestId, outcome: Effect<Ended>) -> ControlFrame {
    match outcome {
        Ok(Ok(Ok(value))) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Ok(Ok(Err(error))) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error.to_protocol_error()),
        }),
        Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
    }
}

/// As [`settled`], for a service that says whether it answered from its own record. A wait that
/// ended is not an answer from a record, so it is a fresh word.
fn settled_by_a_service<Ended>(
    request_id: RequestId,
    outcome: Effect<Ended, Given<Result<ParamsValue>>>,
) -> Given<ControlFrame> {
    match outcome {
        Ok(Ok(given)) => given.map(|answer| framed(request_id, answer)),
        Ok(Err(_)) | Err(_) => Given::fresh(failure(request_id, outcome_unknown())),
    }
}

/// The frame a service's answer goes out as.
fn framed(request_id: RequestId, answer: Result<ParamsValue>) -> ControlFrame {
    framed_protocol(
        request_id,
        answer.map_err(|error| error.to_protocol_error()),
    )
}

/// The frame an answer that carries the protocol's own refusal goes out as.
fn framed_protocol(
    request_id: RequestId,
    answer: std::result::Result<ParamsValue, ProtocolError>,
) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match answer {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}
