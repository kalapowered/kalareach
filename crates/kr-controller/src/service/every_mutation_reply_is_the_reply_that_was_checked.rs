//! The reply a local caller reads for a mutation is the reply the door made.
//!
//! Every reply to a mutation is made by `told` or `declined` and written by the one sink that
//! consumes it, which notes each reply it writes for these tests. Through a real local connection
//! this sends one mutation for each local write in the method table, a mutation on a stream of the
//! wrong kind, a mutation before the hello and a mutation whose answer is written while the local
//! owner's lease ends, and requires that for each request the frame the caller reads is the frame
//! the sink consumed, or the lease's own word for the lease case. A reply replaced after the check
//! differs.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue, Response};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, RequestId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::Method;
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::CanonicalSet;

use super::the_fence_at_every_effect::{daemon, mutation_of};
use super::writes::LocalWrite;
use crate::service::{Controller, error_reply};

/// How long a reply may take to arrive.
const REPLY: Duration = Duration::from_secs(60);

/// A local connection to the daemon, as a caller holds it.
struct Caller {
    reader: FrameReader,
    writer: FrameWriter,
    /// The window the daemon issued, once the hello is answered.
    window: Option<ActionWindowId>,
    /// The identifier the next request carries.
    next: u64,
    serving: tokio::task::JoinHandle<()>,
}

impl Caller {
    /// Connects a stream of `kind` and says nothing yet.
    async fn connect(
        temp: &kr_ipc::testing::TempHost,
        controller: &Arc<Controller>,
        listener: &Listener,
        kind: StreamKind,
    ) -> Self {
        let endpoint = temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let dialled = tokio::spawn(async move { Connection::connect(&endpoint).await });
        let (connection, peer) = listener.accept().await.expect("accepts");
        let caller = dialled.await.expect("the task ends").expect("connects");
        let serving = tokio::spawn({
            let controller = Arc::clone(controller);
            async move {
                let _ = controller.client(connection, peer, kind).await;
            }
        });
        let (reader, writer) = split(caller, kind);
        Self {
            reader,
            writer,
            window: None,
            next: 1,
            serving,
        }
    }

    /// Connects and negotiates, and keeps the action window the daemon issues.
    async fn negotiated(
        temp: &kr_ipc::testing::TempHost,
        controller: &Arc<Controller>,
        listener: &Listener,
        kind: StreamKind,
    ) -> Self {
        let mut caller = Self::connect(temp, controller, listener, kind).await;
        caller
            .writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                client: LocalClientKind::Cli,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .expect("writes the hello");
        let ControlFrame::HelloAck(acknowledged) = caller.read().await else {
            panic!("the daemon acknowledges the hello");
        };
        caller.window = Some(acknowledged.action_window.action_window_id);
        caller
    }

    /// The next frame that is not an event the daemon sends of its own accord.
    async fn read(&mut self) -> ControlFrame {
        loop {
            let frame = tokio::time::timeout(REPLY, self.reader.read_message::<ControlFrame>())
                .await
                .expect("the daemon answers")
                .expect("the answer reads");
            if !matches!(frame, ControlFrame::Event(_)) {
                return frame;
            }
        }
    }

    /// A mutation of `method` under the window and the next request identifier.
    fn mutation(
        &mut self,
        temp: &kr_ipc::testing::TempHost,
        method: Method,
        params: ParamsValue,
    ) -> MutationRequest {
        let mut mutation = mutation_of(temp, method, params);
        mutation.request_id = RequestId::new(self.next);
        self.next += 1;
        mutation.action_id = ActionId::new(kr_ipc::new_uuid());
        if let Some(window) = &self.window {
            mutation.action_window_id = window.clone();
        }
        mutation
    }

    async fn send(&mut self, mutation: MutationRequest) {
        self.writer
            .write_message(&ControlFrame::Mutation(Box::new(mutation)))
            .await
            .expect("writes the mutation");
    }

    /// Sends `mutation` and reads the reply to it.
    async fn ask(&mut self, mutation: MutationRequest) -> ControlFrame {
        self.send(mutation).await;
        self.read().await
    }
}

/// The endpoint the daemon would serve clients on.
fn bound(temp: &kr_ipc::testing::TempHost) -> Listener {
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    Listener::bind(&endpoint).expect("binds the endpoint")
}

/// The one reply `told` or `declined` made for `request_id` and whether it was told, which the
/// sink must have consumed unchanged: the two are noted apart, one where a reply is made and one
/// where it is consumed.
fn made(controller: &Controller, request_id: RequestId) -> (bool, ControlFrame) {
    let mut made: Vec<(bool, ControlFrame)> = controller
        .replies_made()
        .into_iter()
        .filter(|(noted_for, _, _)| *noted_for == request_id)
        .map(|(_, told, frame)| (told, frame))
        .collect();
    assert_eq!(
        made.len(),
        1,
        "one reply was made for request {request_id:?}: {made:?}"
    );
    let mut written: Vec<ControlFrame> = controller
        .replies_written()
        .into_iter()
        .filter(|(noted_for, _)| *noted_for == request_id)
        .map(|(_, frame)| frame)
        .collect();
    assert_eq!(
        written.len(),
        1,
        "the sink consumed one reply for request {request_id:?}: {written:?}"
    );
    let (told, frame) = made.remove(0);
    assert_eq!(
        frame,
        written.remove(0),
        "the sink consumed the reply that was made for request {request_id:?}"
    );
    (told, frame)
}

/// The reply the sink consumed for `request_id`, after it has been held equal to the one made.
fn noted(controller: &Controller, request_id: RequestId) -> ControlFrame {
    made(controller, request_id).1
}

/// Parameters that decode for `method`, so that the request passes the envelope and reaches the
/// route of its kind, where the reply is told; none for a method this builds none for, which the
/// envelope declines for its empty parameters.
fn params_for_a_route(
    temp: &kr_ipc::testing::TempHost,
    controller: &Controller,
    method: Method,
) -> Option<ParamsValue> {
    use kr_protocol::organisation::{HostPolicyConfirmParams, OrganisationExclusiveSetParams};
    use kr_protocol::privacy::PrivacyRetainedDeleteParams;
    use kr_protocol::sharing::{DeviceRevokeParams, GrantRevokeParams};

    use super::a_recorded_answer_another_copy_wrote::{
        a_workflow_install, cancellation, capability_request, materialisation, setting_quiet_hours,
    };

    match method {
        Method::AgentToolsInstall => {
            let project = temp.root().join("a-project-the-walk-installs-in");
            std::fs::create_dir_all(&project).expect("a project directory");
            Some(super::the_fence_at_every_effect::installation_in(temp, &project).params)
        }
        Method::ProjectOperationCancel => Some(cancellation(temp).params),
        Method::ChangesetMaterialize => Some(materialisation(temp).params),
        Method::AttentionQuietHours => Some(setting_quiet_hours(temp).params),
        Method::CataloguePin => Some(
            ParamsValue::from_typed(&kr_protocol::catalogue::CataloguePinParams {
                environment_id: temp.environment_id(),
                catalogue_id: "nobody-enrolled-this".to_owned(),
                generation: kr_protocol::scalars::Nullable(Some(
                    kr_protocol::ids::RepositoryGeneration::new(1),
                )),
            })
            .expect("encodes"),
        ),
        Method::SessionClose => Some(
            ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
                session_id: kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
        Method::DraftCreate => Some(
            ParamsValue::from_typed(&kr_protocol::transfer::DraftCreateParams {
                environment_id: temp.environment_id(),
                device_id: kr_protocol::scalars::Nullable::null(),
                session_id: kr_protocol::scalars::Nullable::null(),
                application_instance_id: kr_protocol::scalars::Nullable::null(),
                text: "a draft that belongs to no session".to_owned(),
            })
            .expect("encodes"),
        ),
        Method::MachineSplit => {
            let group = controller
                .machine_report()
                .expect("this daemon serves a machine group record");
            Some(
                ParamsValue::from_typed(&kr_protocol::machine::MachineSplitParams {
                    expected: kr_protocol::machine::MachineExpected {
                        machine_id: group.machine_id,
                        revision: group.revision,
                    },
                })
                .expect("encodes"),
            )
        }
        Method::AccountSignOut => Some(
            ParamsValue::from_typed(&kr_protocol::host_account::AccountSignOutParams {})
                .expect("encodes"),
        ),
        Method::WorkflowEnable => Some(
            ParamsValue::from_typed(&kr_protocol::automation::WorkflowEnableParams {
                workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::scalars::U64::new(1),
            })
            .expect("encodes"),
        ),
        Method::WorkflowPause => Some(
            ParamsValue::from_typed(&kr_protocol::automation::WorkflowPauseParams {
                workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::scalars::U64::new(1),
                reason: kr_protocol::scalars::Nullable::null(),
            })
            .expect("encodes"),
        ),
        Method::UploadCancel => Some(
            ParamsValue::from_typed(&kr_protocol::transfer::UploadCancelParams {
                transfer_id: kr_protocol::ids::TransferId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
        Method::DraftDiscard => Some(
            ParamsValue::from_typed(&kr_protocol::transfer::DraftDiscardParams {
                draft_id: kr_protocol::ids::DraftId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
        Method::EnvironmentForget => Some(
            ParamsValue::from_typed(&kr_protocol::identity::EnvironmentForgetParams {
                environment_id: temp.environment_id(),
            })
            .expect("encodes"),
        ),
        Method::VoiceGrant => Some(
            ParamsValue::from_typed(&kr_protocol::voice::VoiceGrantParams {
                device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
                session_ids: CanonicalSet::new(),
                actions: kr_protocol::scalars::Nullable::null(),
            })
            .expect("encodes"),
        ),
        Method::OwnerConfirmationRequest => Some(
            ParamsValue::from_typed(&kr_protocol::confirmation::OwnerConfirmationRequestParams {
                subject: kr_protocol::confirmation::ConfirmationSubject::SetExclusiveManagement {
                    exclusive: false,
                },
            })
            .expect("encodes"),
        ),
        Method::PrivacySet => {
            Some(ParamsValue::from_typed(&PrivacySetParams { enabled: false }).expect("encodes"))
        }
        Method::PrivacyRetainedDelete => Some(
            ParamsValue::from_typed(&PrivacyRetainedDeleteParams {
                reference: "no such copy".to_owned(),
            })
            .expect("encodes"),
        ),
        Method::HostPolicyConfirm => {
            Some(ParamsValue::from_typed(&HostPolicyConfirmParams {}).expect("encodes"))
        }
        Method::OrganisationExclusiveSet => Some(
            ParamsValue::from_typed(&OrganisationExclusiveSetParams { exclusive: false })
                .expect("encodes"),
        ),
        Method::GrantRevoke => Some(
            ParamsValue::from_typed(&GrantRevokeParams {
                grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
        Method::DeviceRevoke => Some(
            ParamsValue::from_typed(&DeviceRevokeParams {
                device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
        Method::WorkflowInstall => Some(a_workflow_install(temp, controller).params),
        Method::EnvironmentCapabilitiesCheck => Some(capability_request(temp, None, None).params),
        _ => None,
    }
}

/// The local writes the walk sends with parameters that do not reach their route: each needs a
/// fixture of its own that a walk of the whole table cannot build alone, so the envelope declines
/// it for its empty parameters and its reply is the declined one, which `declined` made and the
/// sink consumed. They are listed so that no write passes unnamed; one that gains parameters here
/// leaves the list.
const WITHOUT_A_FIXTURE: &[Method] = &[
    Method::EnvironmentEnrol,
    Method::EnvironmentRefresh,
    Method::DeliveryDestinationConfigure,
    Method::DeliveryDestinationRemove,
    Method::DeliveryDestinationSecretSet,
    Method::AccountSignIn,
    Method::AccountStorageSignIn,
    Method::AccountStorageSignOut,
    Method::BackupEnable,
    Method::BackupBundleWrite,
    Method::HostUpdateHandover,
    Method::DescriptionConfigure,
    Method::DescriptionDownload,
    Method::MachineJoin,
    Method::MachineMerge,
    Method::OrganisationEnrol,
    Method::OrganisationPolicyApply,
    Method::OrganisationWithdraw,
    Method::MembershipPresent,
    Method::PairInvite,
    Method::PairConfirm,
    Method::PairCancel,
    Method::CatalogueAdd,
    Method::CatalogueSync,
    Method::CatalogueRemove,
    Method::PluginInstall,
    Method::PluginRemove,
    Method::PluginPin,
    Method::PluginEnable,
    Method::PluginDisable,
    Method::PluginGrant,
    Method::AgentToolsRemove,
    Method::SessionCreate,
    Method::SessionRename,
    Method::AgentPromptSubmit,
    Method::AgentPromptQueue,
    Method::DraftUpdate,
    Method::AgentDraftAddAttachment,
    Method::UploadBegin,
    Method::UploadChunk,
    Method::UploadFinish,
    Method::ProjectInit,
    Method::ProjectClone,
    Method::ProjectAdopt,
    Method::ProjectLocationAuthorise,
    Method::ProjectLocationWithdraw,
    Method::ProjectLocationAttach,
    Method::WorkspaceCreate,
    Method::WorkspaceRemove,
    Method::DiffApply,
    Method::DiffRevert,
    Method::ChangesetCapture,
    Method::ReviewAcknowledge,
    Method::AttentionAcknowledge,
    Method::VisitAcknowledge,
    Method::OwnerConfirmationComplete,
    Method::HostClockEstablish,
    Method::GrantCreate,
    Method::GrantTransfer,
    Method::WorkflowRun,
    Method::WorkflowRearm,
];

fn code_of(frame: &ControlFrame) -> Option<ErrorCode> {
    match frame {
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => Some(error.code),
        _ => None,
    }
}

/// KR-REQ-09.09: a caller is read the reply the door made for each mutation it sent: one for each
/// local write in the method table, and the same for a mutation on a stream of the wrong kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_mutation_reply_is_the_reply_that_was_checked() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::negotiated(&temp, &controller, &listener, StreamKind::Control).await;
    let mut asked = 0_usize;
    let mut told = Vec::new();
    let mut reaching = Vec::new();
    for method in Method::ALL.iter().copied() {
        if LocalWrite::of(method).is_none() {
            continue;
        }
        let params = params_for_a_route(&temp, &controller, method);
        if params.is_some() {
            reaching.push(method);
        }
        let mut mutation =
            caller.mutation(&temp, method, params.unwrap_or_else(ParamsValue::empty));
        if method == Method::SessionClose && reaching.last() == Some(&method) {
            // A close names its session in its target as well as in its parameters.
            let params: kr_protocol::session::SessionCloseParams =
                mutation.params.to_typed().expect("decodes");
            mutation.target.session_id = kr_protocol::scalars::Nullable::some(params.session_id);
            mutation.target.session_epoch =
                kr_protocol::scalars::Nullable::some(kr_protocol::ids::SessionEpoch::V1);
        }
        let request_id = mutation.request_id;
        let read = caller.ask(mutation).await;
        let (was_told, made) = made(&controller, request_id);
        assert_eq!(
            read, made,
            "{method:?}: the caller is read the reply that was made and the sink consumed"
        );
        if was_told {
            told.push(method);
        }
        asked += 1;
    }
    assert!(asked > 50, "a mutation for each local write: {asked}");
    // The replies of the requests that reach a route are told, and not declined by the envelope.
    let declined: Vec<Method> = reaching
        .iter()
        .copied()
        .filter(|method| !told.contains(method))
        .collect();
    assert!(
        declined.is_empty(),
        "these carry parameters that reach their route, so their replies are told: {declined:?}"
    );
    let without: Vec<Method> = Method::ALL
        .iter()
        .copied()
        .filter(|method| {
            LocalWrite::of(*method).is_some_and(|kind| kind != LocalWrite::NotServed)
                && !reaching.contains(method)
        })
        .collect();
    assert_eq!(
        without, WITHOUT_A_FIXTURE,
        "the writes the walk sends with no parameters that reach their route are the ones listed"
    );
    // Each kind of route is reached by at least one method, so that the arm of `write_method` that
    // serves it has told a reply.
    for method in Method::ALL.iter().copied() {
        let Some(kind) = LocalWrite::of(method) else {
            continue;
        };
        if kind == LocalWrite::NotServed {
            assert!(
                !told.contains(&method),
                "{method:?} is served by nobody here, so the envelope declines it"
            );
            continue;
        }
        if !matches!(kind, LocalWrite::Setup | LocalWrite::SessionCreate) {
            assert!(
                reaching.iter().any(|reached| {
                    LocalWrite::of(*reached).is_some_and(|reached| {
                        std::mem::discriminant(&reached) == std::mem::discriminant(&kind)
                    })
                }),
                "{kind:?}: no method of this kind of route is walked with parameters that reach it"
            );
        }
    }

    // A mutation on a stream that does not carry it is declined, and the caller reads that.
    let mutation = caller.mutation(&temp, Method::UploadChunk, ParamsValue::empty());
    let request_id = mutation.request_id;
    let read = caller.ask(mutation).await;
    assert_eq!(read, noted(&controller, request_id));
    assert_eq!(
        code_of(&read),
        Some(ErrorCode::PermissionDenied),
        "{read:?}"
    );
    caller.serving.abort();

    let mut chunks =
        Caller::negotiated(&temp, &controller, &listener, StreamKind::AttachmentChunks).await;
    // The requests of this connection are numbered apart from the first one's.
    chunks.next = 1_000_000;
    let mutation = chunks.mutation(&temp, Method::PrivacyRetainedDelete, ParamsValue::empty());
    let request_id = mutation.request_id;
    let read = chunks.ask(mutation).await;
    assert_eq!(read, noted(&controller, request_id));
    assert_eq!(
        code_of(&read),
        Some(ErrorCode::PermissionDenied),
        "{read:?}"
    );
    chunks.serving.abort();
}

/// KR-REQ-09.09: a mutation sent before the hello is answered with the constant the loop keeps
/// for it, and the sink writes nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_before_the_hello_is_answered_with_the_constant_for_it() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::connect(&temp, &controller, &listener, StreamKind::Control).await;
    let mutation = caller.mutation(&temp, Method::PrivacyRetainedDelete, ParamsValue::empty());
    let read = caller.ask(mutation).await;
    assert_eq!(
        read,
        error_reply(
            RequestId::new(0),
            ErrorCode::UnsupportedSchema,
            "a local connection negotiates its version before anything else",
        )
    );
    assert!(
        controller.replies_made().is_empty() && controller.replies_written().is_empty(),
        "no reply to a mutation was made before the hello"
    );
    caller.serving.abort();
}

/// KR-REQ-09.09, KR-REQ-09.12: an answer written while the local owner's lease ends is the
/// lease's own word, outcome unknown for a write, and not the answer the door made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_written_while_the_lease_ends_is_the_leases_own_word() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::negotiated(&temp, &controller, &listener, StreamKind::Control).await;
    assert_eq!(
        kr_protocol::method::local_hold(Method::PrivacySet),
        kr_protocol::method::LocalHold::Held,
        "the method this sends is held to the lease"
    );
    let (arrived, release) = controller.pause_before_a_reply_is_told();
    let mutation = caller.mutation(
        &temp,
        Method::PrivacySet,
        ParamsValue::from_typed(&PrivacySetParams { enabled: false }).expect("encodes"),
    );
    let request_id = mutation.request_id;
    caller.send(mutation).await;
    tokio::time::timeout(REPLY, arrived)
        .await
        .expect("the door reaches the place its answer is told")
        .expect("the pause is armed");
    controller
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(true);
    release.send(()).expect("the door goes on");
    let read = caller.read().await;
    assert_eq!(
        read,
        controller.lease_ended_reply(request_id, Some(Method::PrivacySet)),
        "the lease's own word"
    );
    assert_eq!(code_of(&read), Some(ErrorCode::OutcomeUnknown), "{read:?}");
    assert_ne!(
        read,
        noted(&controller, request_id),
        "it is not the answer the door made"
    );
    caller.serving.abort();
}
