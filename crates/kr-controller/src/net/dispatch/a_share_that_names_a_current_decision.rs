//! A share that names the current questions and approvals it permits, and what a device holding it
//! reads of them.
//!
//! Section 10 lets an invitation name active questions and approval resources, previewed to the
//! issuer even when they were created before the history cutoff, permitting those exact current
//! decisions and not their earlier conversation. `grant.create` asks the session's worker what each
//! named one is now and shows the issuer that. The first part here plays the worker, answering the
//! daemon's own reads with what each test gives it. The second part runs a real worker service in
//! this process, in the daemon's directory, holding an approval a Claude Code channel relayed and
//! its connector's table interpreted, and reads through a paired device's door what a device
//! holding the issued grant is told. A device's connection is decided under the grant its record
//! holds, so the second part redeems the invitation and installs the grant it carries in the
//! device's record itself.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.51 | every `kr_req_10_51_` test here |

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::agent::{AgentApprovalInspectParams, AgentApprovalInspectResult};
use kr_protocol::broker::{DecodedProjection, DecoderLedgerEntry, OfferedDecision};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::gateway::{
    DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingResource,
    PendingState,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ApplicationInstanceId, BrokerBindingId, CapabilityId,
    ConnectionId, DeviceId, GatewayConnectionId, PendingResourceId, PluginId, PublisherId,
    QuestionId, QuestionRevision, RequestId, SessionEpoch, SessionId, SourceGeneration,
    UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::local::ForwardedRequest;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::question::{
    Question, QuestionChoice, QuestionKind, QuestionReadParams, QuestionReadResult, QuestionSource,
    QuestionState,
};
use kr_protocol::recovery::EventsSnapshotParams;
use kr_protocol::scalars::{
    Bytes, CanonicalSet, Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid,
};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, NamedApprovalPreview,
    NamedQuestionPreview, RoleSelection, SessionRole,
};
use kr_transport::lease::LeaseRefusal;

use crate::error::ControllerError;
use crate::grants::ActionRecord;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::service::net::devices::DeviceRecord;

// ---------------------------------------------------------------------------------------------
// The worker the first part plays
// ---------------------------------------------------------------------------------------------

/// What the played worker holds for the daemon's own reads, as each test sets it, and what it was
/// asked.
#[derive(Default)]
struct Holding {
    /// The resources the broker arbitrates, in identifier order, as `events.snapshot` pages them.
    resources: Vec<PendingResource>,
    /// How many resources one page carries; nought carries them all in one.
    page: usize,
    /// Which snapshot the pages are cut from; a continuation of any other is answered
    /// `RESYNC_REQUIRED`.
    snapshot_id: u64,
    /// What the resources become once the next continuation is asked for, which ends the snapshot
    /// being read.
    changes_to: Option<Vec<PendingResource>>,
    /// The answer to `agent.approval.inspect` for each resource the broker has a record of, from its
    /// ledger when the live arbitration no longer holds it.
    records: BTreeMap<PendingResourceId, Result<AgentApprovalInspectResult, ProtocolError>>,
    /// The session's questions, by identity.
    questions: BTreeMap<QuestionId, Question>,
    /// Whether the worker ends the link when it is asked for an approval's record.
    ends_on_inspect: bool,
    /// Whether the worker never answers when it is asked for an approval's record.
    silent_on_inspect: bool,
    /// How many connections the daemon has opened to the worker.
    connections: usize,
    /// Every request the daemon made on its own link, in order.
    asked: Vec<Request>,
    /// Every read the daemon forwarded for a device, in order.
    forwarded: Vec<ForwardedRequest>,
}

impl Holding {
    /// Answers one page of `events.snapshot`.
    fn snapshot_page(
        &mut self,
        session_id: SessionId,
        request: &Request,
    ) -> Result<ParamsValue, ProtocolError> {
        let params: EventsSnapshotParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let start = match params.agent_resources_from.as_ref() {
            None => 0,
            Some(from) => {
                if let Some(changed) = self.changes_to.take() {
                    self.resources = changed;
                    self.snapshot_id += 1;
                }
                if from.snapshot_id.get() != self.snapshot_id {
                    return Err(ProtocolError::new(
                        ErrorCode::ResyncRequired,
                        "the snapshot this continues has ended",
                    ));
                }
                self.resources
                    .iter()
                    .position(|resource| resource.resource_id == from.after_resource_id)
                    .map_or(self.resources.len(), |at| at + 1)
            }
        };
        let size = if self.page == 0 {
            self.resources.len()
        } else {
            self.page
        };
        let end = start.saturating_add(size).min(self.resources.len());
        let resources = self.resources[start..end].to_vec();
        let continue_after = if end < self.resources.len() {
            resources.last().map(|resource| resource.resource_id)
        } else {
            None
        };
        Ok(encoded(&kr_protocol::recovery::EventsSnapshotResult {
            cursor: U64::new(1),
            session: fake::read_result(session_id).session,
            geometry: kr_protocol::attachment::GeometryState {
                owner: Nullable::null(),
                epoch: kr_protocol::ids::GeometryEpoch::new(0),
                dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
            },
            lease: kr_protocol::input::InputLeaseState {
                epoch: kr_protocol::ids::InputLeaseEpoch::new(0),
                holder: Nullable::null(),
                connection_id: Nullable::null(),
                next_sequence: kr_protocol::ids::InputSequence::new(0),
            },
            attachments: Vec::new(),
            oldest_retained_cursor: U64::new(0),
            taken_at_ms: kr_ipc::now_ms(),
            agent_resources: kr_protocol::projection::AgentResourceSnapshot {
                snapshot_id: U64::new(self.snapshot_id),
                stream_generation: U64::new(1),
                cursor: U64::new(1),
                resources,
                continue_after: Nullable(continue_after),
            },
            agent_instances: kr_protocol::projection::AgentInstanceList {
                sequence: U64::new(0),
                instances: Vec::new(),
            },
        }))
    }

    /// Answers `agent.approval.inspect`, as a worker does: a resource of another instance, or one
    /// it holds no record of, is refused as unknown. Every played approval is of one instance.
    fn record(&self, request: &Request) -> Result<ParamsValue, ProtocolError> {
        let params: AgentApprovalInspectParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let of_the_instance = params.subject.application_instance_id == instance(0x41);
        match self.records.get(&params.resource_id) {
            Some(Err(error)) => Err(error.clone()),
            Some(Ok(record)) if of_the_instance => Ok(encoded(record)),
            _ => Err(ProtocolError::new(
                ErrorCode::StaleSession,
                "that application instance has no interpreted approval by that identity",
            )),
        }
    }

    /// Answers `question.read`, as a worker answers its own local owner: every question, or the
    /// one named, and an unknown one refused as a worker refuses it.
    fn questions(&self, request: &Request) -> Result<ParamsValue, ProtocolError> {
        let params: QuestionReadParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let questions = match params.question_id.as_ref() {
            Some(question_id) => {
                vec![self.questions.get(question_id).cloned().ok_or_else(|| {
                    ProtocolError::new(ErrorCode::PermissionDenied, "no such question here")
                })?]
            }
            None => self.questions.values().cloned().collect(),
        };
        Ok(encoded(&QuestionReadResult { questions }))
    }
}

/// What the played worker does with one frame after its handshake.
enum Reply {
    /// Answers with this frame.
    Frame(ControlFrame),
    /// Answers nothing.
    Nothing,
    /// Ends the link, as a worker whose connection failed does.
    EndTheLink,
}

/// The played worker's answer to one frame.
fn reply(holding: &Mutex<Holding>, session_id: SessionId, frame: ControlFrame) -> Reply {
    let mut held = holding
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let refused = || {
        ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            "this worker answers only the reads its test gave it",
        )
    };
    match frame {
        ControlFrame::AuthorityRevision(notice) => Reply::Frame(
            ControlFrame::AuthorityRevisionAck(kr_protocol::worker::AuthorityRevisionAck {
                session_id,
                revision: notice.revision,
                fence: None,
            }),
        ),
        ControlFrame::Request(request) => {
            held.asked.push(request.clone());
            let outcome = match request.method.method() {
                Some(Method::SessionRead) => Ok(encoded(&fake::read_result(session_id))),
                Some(Method::EventsSnapshot) => held.snapshot_page(session_id, &request),
                Some(Method::AgentApprovalInspect) if held.ends_on_inspect => {
                    return Reply::EndTheLink;
                }
                Some(Method::AgentApprovalInspect) if held.silent_on_inspect => {
                    return Reply::Nothing;
                }
                Some(Method::AgentApprovalInspect) => held.record(&request),
                Some(Method::QuestionRead) => held.questions(&request),
                _ => Err(refused()),
            };
            Reply::Frame(response(request.request_id, outcome))
        }
        ControlFrame::ForwardedRead(forwarded) => {
            held.forwarded.push(forwarded.as_ref().clone());
            // A question read is answered with every question held, as a worker that holds no
            // question read to a scope answers it; any other forwarded read is refused.
            let outcome = match forwarded.request.method.method() {
                Some(Method::QuestionRead) => Ok(encoded(&QuestionReadResult {
                    questions: held.questions.values().cloned().collect(),
                })),
                _ => Err(refused()),
            };
            Reply::Frame(response(forwarded.request.request_id, outcome))
        }
        ControlFrame::Forwarded(forwarded) => {
            Reply::Frame(response(forwarded.mutation.request_id, Err(refused())))
        }
        _ => Reply::Nothing,
    }
}

/// Serves the played worker on its endpoint: the handshake a daemon makes, stating `stated`
/// about itself, and then [`reply`] for every frame.
fn serving(
    holding: Arc<Mutex<Holding>>,
    stated: CanonicalSet<CapabilityId>,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                holding
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .connections += 1;
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let holding = Arc::clone(&holding);
                let stated = stated.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let replies = match fake::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &stated,
                        ) {
                            Some(replies) => replies,
                            None => match reply(&holding, identity.session_id(), frame) {
                                Reply::Frame(frame) => vec![frame],
                                Reply::Nothing => Vec::new(),
                                Reply::EndTheLink => return,
                            },
                        };
                        for frame in replies {
                            if writer.write_message(&frame).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        })
    }
}

/// What a worker of this build states about a forwarded read's scope: it reads one, and it holds a
/// question read to it.
fn holds_question_reads() -> CanonicalSet<CapabilityId> {
    [
        kr_protocol::local::FORWARDED_HISTORY_SCOPE,
        kr_protocol::local::FORWARDED_QUESTION_SCOPE,
    ]
    .into_iter()
    .map(|capability| CapabilityId::new(capability).expect("a capability identifier"))
    .collect()
}

/// What a worker of an earlier build states: that it reads a scope, and nothing of its question
/// reads.
fn reads_scopes_only() -> CanonicalSet<CapabilityId> {
    [CapabilityId::new(kr_protocol::local::FORWARDED_HISTORY_SCOPE).expect("a capability")]
        .into_iter()
        .collect()
}

/// A daemon whose one worker is the played worker, holding `holding` and stating `stated`.
async fn world(
    holding: Holding,
    stated: CanonicalSet<CapabilityId>,
) -> (fake::Silent, Arc<Mutex<Holding>>) {
    let holding = Arc::new(Mutex::new(holding));
    let world = fake::fake_world(serving(Arc::clone(&holding), stated)).await;
    fake::acknowledged(&world.controller, world.session_id);
    (world, holding)
}

fn encoded<T: serde::Serialize>(value: &T) -> ParamsValue {
    ParamsValue::from_typed(value).expect("encodes")
}

fn response(request_id: RequestId, outcome: Result<ParamsValue, ProtocolError>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

// ---------------------------------------------------------------------------------------------
// What the played worker holds
// ---------------------------------------------------------------------------------------------

/// The instance the played worker's approvals came from, unless a test names another.
fn instance(byte: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
}

fn resource_id(byte: u8) -> PendingResourceId {
    PendingResourceId::new(Uuid::from_bytes([byte; 16]))
}

fn question_id(byte: u8) -> QuestionId {
    QuestionId::new(Uuid::from_bytes([byte; 16]))
}

/// One resource the broker arbitrates, of `kind`, as the snapshot lists it.
fn resource(
    byte: u8,
    kind: PendingKind,
    state: PendingState,
    recorded_at_ms: u64,
    interpreted: bool,
) -> PendingResource {
    PendingResource {
        resource_id: resource_id(byte),
        application_instance_id: instance(0x41),
        request: DownstreamRequestId::new(
            GatewayConnectionId::new(1),
            UpstreamRequestId::new(format!("\"request-{byte}\"")).expect("an identifier"),
        ),
        kind,
        method: UpstreamMethod::new("notifications/claude/channel/permission_request")
            .expect("a method"),
        classification: NativeClassification::declared(NativeMethodClass::Mutation),
        source_generation: SourceGeneration::new(1),
        state,
        durability: kr_protocol::session::Durability::Durable,
        deadline_ms: Nullable::null(),
        recorded_at: TimestampMs::new(recorded_at_ms),
        interpretation_verified: interpreted,
    }
}

/// A pending approval a decoder interpreted.
fn approval(byte: u8, recorded_at_ms: u64) -> PendingResource {
    resource(
        byte,
        PendingKind::Approval,
        PendingState::Pending,
        recorded_at_ms,
        true,
    )
}

/// The record `agent.approval.inspect` answers for `resource`: in `state`, with the decoder's
/// `summary` and the request's `source` bytes.
fn record_of(
    resource: &PendingResource,
    state: PendingState,
    summary: &str,
    source: Vec<u8>,
) -> AgentApprovalInspectResult {
    AgentApprovalInspectResult {
        resource_id: resource.resource_id,
        state,
        recorded_at: resource.recorded_at,
        decoding: DecoderLedgerEntry {
            binding_id: BrokerBindingId::new(Uuid::from_bytes([0x51; 16])),
            plugin_id: PluginId::new("kalareach/claude-code").expect("a plugin"),
            publisher_id: PublisherId::new("kalareach").expect("a publisher"),
            package_digest: Digest256::from_bytes([0x52; 32]),
            method: resource.method.clone(),
            upstream_request_id: resource.request.upstream.clone(),
            source_generation: resource.source_generation,
            source_digest: Digest256::from_bytes([0x53; 32]),
            source_bytes: Bytes::new(source),
            projection: DecodedProjection {
                schema_version: "kalareach.decision/1".to_owned(),
                summary: summary.to_owned(),
                decisions: vec![
                    OfferedDecision {
                        option_id: "allow".to_owned(),
                        label: "Allow".to_owned(),
                    },
                    OfferedDecision {
                        option_id: "deny".to_owned(),
                        label: "Deny".to_owned(),
                    },
                ],
            },
            deadline_ms: Nullable::null(),
            decoded_at: TimestampMs::new(resource.recorded_at.get() + 1),
        },
    }
}

/// A Claude Code channel's relayed tool approval, as the upstream wrote it.
fn relayed_request(request_id: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/claude/channel/permission_request","params":{{"request_id":"{request_id}","tool_name":"Bash","description":"List the files here","input_preview":"ls -la"}}}}"#
    )
    .into_bytes()
}

/// A question an application inside `session_id` asked, in `state`.
fn question(
    session_id: SessionId,
    byte: u8,
    state: QuestionState,
    created_at_ms: u64,
    text: &str,
) -> Question {
    Question {
        question_id: question_id(byte),
        revision: QuestionRevision::new(2),
        state,
        session_id,
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Confirm,
        context: "Two tests fail.".to_owned(),
        question: text.to_owned(),
        choices: vec![QuestionChoice::something_else()],
        source: QuestionSource {
            application_instance_id: instance(0x42),
            process: kr_protocol::identity::ProcessStartIdentity::new(
                42,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                7,
            ),
            executable: Nullable::some("/usr/bin/some-agent".to_owned()),
            agent_label: Nullable::null(),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(created_at_ms),
        expires_at_ms: TimestampMs::new(created_at_ms + 86_400_000),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

// ---------------------------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------------------------

/// The device a test shares with.
fn recipient() -> DeviceId {
    DeviceId::new(Uuid::from_bytes([0xd1; 16]))
}

/// A viewer's selection reaching back to `bound_ms` and naming these questions and approvals.
fn naming(
    bound_ms: u64,
    questions: &[QuestionId],
    approvals: &[PendingResourceId],
) -> RoleSelection {
    RoleSelection {
        history_from_cursor_ms: Nullable::some(TimestampMs::new(bound_ms)),
        named_questions: questions.iter().copied().collect(),
        named_approvals: approvals.iter().copied().collect(),
        ..RoleSelection::plain(SessionRole::Viewer)
    }
}

/// The local owner's `grant.create` of `session_id` with `selection`, as action `action`.
fn share(
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    action: u8,
    selection: RoleSelection,
) -> MutationRequest {
    let params = GrantCreateParams {
        session_id,
        recipient_device_id: recipient(),
        parent_grant_id: Nullable::null(),
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable::null(),
        owner_confirmation: Nullable::null(),
    };
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::GrantCreate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(Uuid::from_bytes([action; 16])),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    }
}

/// Performs a share as the local owner, and returns its answer.
async fn shared(
    world: &fake::Silent,
    mutation: &MutationRequest,
) -> Result<ParamsValue, ControllerError> {
    let carried = fake::admission(&world.controller, world.accepted).await;
    world
        .controller
        .authority_change(
            &ActorId::new("local:test").expect("a principal"),
            mutation,
            Method::GrantCreate,
            carried,
        )
        .await
}

/// A share's result, or a panic naming its refusal.
fn result_of(answer: Result<ParamsValue, ControllerError>) -> GrantCreateResult {
    answer
        .expect("the share is written")
        .to_typed()
        .expect("a share result")
}

/// A share's refusal, or a panic naming its result.
fn refusal_of(answer: Result<ParamsValue, ControllerError>) -> ProtocolError {
    match answer {
        Ok(value) => panic!("the share was written: {value:?}"),
        Err(error) => error.to_protocol_error(),
    }
}

/// How many grants the daemon holds.
fn grants_written(world: &fake::Silent) -> usize {
    world
        .controller
        .sharing()
        .grants()
        .records()
        .expect("the grants read")
        .len()
}

/// Whether the daemon holds the invitation a share written as `action` carries: a share's
/// invitation takes its identity from its action.
fn invitation_written(world: &fake::Silent, action: u8) -> bool {
    let (_, invitation_id) =
        crate::service::Controller::share_identities(Uuid::from_bytes([action; 16]));
    world
        .controller
        .sharing()
        .invitation(invitation_id)
        .expect("the invitations read")
        .is_some()
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.51: what the issuer is shown
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.51: a share naming current questions and approvals from before its history bound
/// shows its issuer each one as the session's worker holds it now: a question's text, revision and
/// the moment it was asked, and what an approval asks and when it was recorded. What an approval
/// asks is its decoder's summary, or where the decoder gave none, as a Claude Code channel's does
/// not, the request as the upstream wrote it. A claimed approval is still current: an answer is on
/// its way, and it can still be decided. The grant written names exactly what was shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_shows_its_issuer_each_current_decision_it_names() {
    let summarised = approval(0x61, 1_500);
    let claimed = resource(
        0x62,
        PendingKind::Approval,
        PendingState::Claimed,
        1_600,
        true,
    );
    let unnamed = approval(0x63, 1_700);
    let (world, holding) = world(Holding::default(), holds_question_reads()).await;
    {
        let mut held = holding.lock().expect("held");
        held.questions.insert(
            question_id(0x71),
            question(
                world.session_id,
                0x71,
                QuestionState::Pending,
                1_000,
                "Push the branch anyway?",
            ),
        );
        held.records.insert(
            summarised.resource_id,
            Ok(record_of(
                &summarised,
                PendingState::Pending,
                "Delete the build directory",
                relayed_request("a"),
            )),
        );
        held.records.insert(
            claimed.resource_id,
            Ok(record_of(
                &claimed,
                PendingState::Claimed,
                "",
                relayed_request("b"),
            )),
        );
        held.resources = vec![summarised.clone(), claimed.clone(), unnamed];
    }

    let answer = shared(
        &world,
        &share(
            world.environment_id,
            world.session_id,
            1,
            naming(
                5_000,
                &[question_id(0x71)],
                &[summarised.resource_id, claimed.resource_id],
            ),
        ),
    )
    .await;
    let result = result_of(answer);
    assert_eq!(
        result.preview.named_questions,
        vec![NamedQuestionPreview {
            question_id: question_id(0x71),
            revision: QuestionRevision::new(2),
            question: "Push the branch anyway?".to_owned(),
            created_at_ms: TimestampMs::new(1_000),
        }]
    );
    assert_eq!(
        result.preview.named_approvals,
        vec![
            NamedApprovalPreview {
                resource_id: summarised.resource_id,
                summary: "Delete the build directory".to_owned(),
                created_at_ms: TimestampMs::new(1_500),
            },
            NamedApprovalPreview {
                resource_id: claimed.resource_id,
                summary: String::from_utf8(relayed_request("b")).expect("text"),
                created_at_ms: TimestampMs::new(1_600),
            },
        ],
        "what each approval asks, as its decoder said or as its upstream wrote it"
    );
    let history = &result.grant.history;
    assert_eq!(
        history.lower_bound_ms,
        Nullable::some(TimestampMs::new(5_000))
    );
    assert_eq!(
        history.named_questions,
        [question_id(0x71)].into_iter().collect()
    );
    assert_eq!(
        history.named_approvals,
        [summarised.resource_id, claimed.resource_id]
            .into_iter()
            .collect()
    );
    assert!(
        world
            .controller
            .sharing()
            .grants()
            .record(result.grant.grant_id)
            .expect("the grants read")
            .is_some(),
        "the grant is written"
    );

    // Each approval was read under the instance that holds it.
    let held = holding.lock().expect("held");
    let inspected: Vec<AgentApprovalInspectParams> = held
        .asked
        .iter()
        .filter(|request| request.method.method() == Some(Method::AgentApprovalInspect))
        .map(|request| request.params.to_typed().expect("inspect parameters"))
        .collect();
    assert_eq!(inspected.len(), 2, "{inspected:?}");
    for asked in &inspected {
        assert_eq!(asked.subject.session_id, world.session_id);
        assert_eq!(asked.subject.application_instance_id, instance(0x41));
    }
    drop(held);
    world.serving.abort();
}

/// KR-REQ-10.51: a share naming a question or an approval the session's worker holds no current
/// record of is refused with one reason per kind, and nothing is written. That covers a question
/// answered, one the worker does not know, an approval the broker does not hold, a resource that
/// is not an interpreted approval, one the broker holds only as a request no decoder interpreted,
/// one that ended between the snapshot and its record, and one whose instance has gone. The
/// refusal is the action's answer from then on: the same request is given it again, and the
/// worker is not asked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_naming_what_is_not_current_is_refused_and_writes_nothing() {
    let answered = question(
        SessionId::new(Uuid::NIL),
        0x72,
        QuestionState::Answered,
        1_000,
        "Answered already?",
    );
    let reverse = resource(
        0x64,
        PendingKind::ReverseRpc,
        PendingState::Pending,
        1_000,
        false,
    );
    let uninterpreted = resource(
        0x65,
        PendingKind::Approval,
        PendingState::Pending,
        1_000,
        false,
    );
    let ended = approval(0x66, 1_000);
    let gone = approval(0x67, 1_000);
    let (world, holding) = world(Holding::default(), holds_question_reads()).await;
    {
        let mut held = holding.lock().expect("held");
        held.questions.insert(
            answered.question_id,
            Question {
                session_id: world.session_id,
                ..answered.clone()
            },
        );
        held.records.insert(
            ended.resource_id,
            Ok(record_of(
                &ended,
                PendingState::Resolved,
                "Ended",
                relayed_request("c"),
            )),
        );
        held.records.insert(
            gone.resource_id,
            Err(ProtocolError::new(
                ErrorCode::StaleSession,
                "that application instance has gone",
            )),
        );
        held.resources = vec![
            reverse.clone(),
            uninterpreted.clone(),
            ended.clone(),
            gone.clone(),
        ];
    }
    let before = grants_written(&world);

    let questions: [(&str, QuestionId); 2] = [
        ("answered", answered.question_id),
        ("unknown", question_id(0x73)),
    ];
    let approvals: [(&str, PendingResourceId); 5] = [
        ("not held", resource_id(0x68)),
        ("not an approval", reverse.resource_id),
        ("never interpreted", uninterpreted.resource_id),
        ("ended", ended.resource_id),
        ("its instance gone", gone.resource_id),
    ];
    let mut action = 0x10;
    for (why, named) in questions {
        action += 1;
        let mutation = share(
            world.environment_id,
            world.session_id,
            action,
            naming(5_000, &[named], &[]),
        );
        let refused = refusal_of(shared(&world, &mutation).await);
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{why}: {refused:?}"
        );
        assert!(
            refused.message.contains("no open record"),
            "{why}: {refused:?}"
        );
        let asked = holding.lock().expect("held").asked.len();
        let again = refusal_of(shared(&world, &mutation).await);
        assert_eq!(again, refused, "{why}: the refusal is the action's answer");
        assert_eq!(
            holding.lock().expect("held").asked.len(),
            asked,
            "{why}: the worker is not asked again"
        );
        assert!(
            !invitation_written(&world, action),
            "{why}: no invitation is written"
        );
    }
    for (why, named) in approvals {
        action += 1;
        let mutation = share(
            world.environment_id,
            world.session_id,
            action,
            naming(5_000, &[], &[named]),
        );
        let refused = refusal_of(shared(&world, &mutation).await);
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{why}: {refused:?}"
        );
        assert!(
            refused.message.contains("no current record"),
            "{why}: {refused:?}"
        );
        let again = refusal_of(shared(&world, &mutation).await);
        assert_eq!(again, refused, "{why}: the refusal is the action's answer");
        assert!(
            !invitation_written(&world, action),
            "{why}: no invitation is written"
        );
    }
    assert_eq!(grants_written(&world), before, "nothing is written");
    world.serving.abort();
}

/// KR-REQ-10.51: where an approval's decoder gave no summary, the issuer is shown the request as
/// its upstream wrote it, whole, when that is text of at most the length a summary may have; a
/// longer one, or one that is not text, cannot be shown, and a share naming it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_request_with_no_summary_is_shown_whole_or_not_named() {
    let limit = kr_protocol::broker::MAX_PROJECTION_SUMMARY_LEN;
    // Text of exactly the limit, one character of it outside ASCII so the count is of bytes.
    let at_the_limit = format!("é{}", "x".repeat(limit - 2));
    assert_eq!(at_the_limit.len(), limit);
    let fits = approval(0x81, 1_000);
    let too_long = approval(0x82, 1_000);
    let not_text = approval(0x83, 1_000);
    let (world, holding) = world(Holding::default(), holds_question_reads()).await;
    {
        let mut held = holding.lock().expect("held");
        for (resource, source) in [
            (&fits, at_the_limit.clone().into_bytes()),
            (&too_long, "x".repeat(limit + 1).into_bytes()),
            (&not_text, vec![0xff, 0xfe, 0xfd]),
        ] {
            held.records.insert(
                resource.resource_id,
                Ok(record_of(resource, PendingState::Pending, "", source)),
            );
        }
        held.resources = vec![fits.clone(), too_long.clone(), not_text.clone()];
    }

    let result = result_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x21,
                naming(5_000, &[], &[fits.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(
        result
            .preview
            .named_approvals
            .iter()
            .map(|preview| preview.summary.clone())
            .collect::<Vec<_>>(),
        vec![at_the_limit]
    );
    for (action, (why, named)) in [
        ("one byte past the limit", too_long.resource_id),
        ("not text", not_text.resource_id),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = refusal_of(
            shared(
                &world,
                &share(
                    world.environment_id,
                    world.session_id,
                    0x22 + u8::try_from(action).expect("small"),
                    naming(5_000, &[], &[named]),
                ),
            )
            .await,
        );
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{why}: {refused:?}"
        );
        assert!(
            refused.message.contains("no preview can show"),
            "{why}: {refused:?}"
        );
    }
    world.serving.abort();
}

/// KR-REQ-10.51: a share names at most 32 questions and approvals together. Thirty-two, each with
/// the longest text it may have, are shown, and the answer fits one control frame and is read back
/// from its record when the same request comes again. Thirty-three are refused, whatever their
/// kinds, before the worker is asked anything, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_names_at_most_thirty_two_decisions() {
    let limit = kr_protocol::sharing::MAX_NAMED_RESOURCES;
    let longest = kr_protocol::question::MAX_QUESTION_BYTES;
    let (world, holding) = world(Holding::default(), holds_question_reads()).await;
    let approvals: Vec<PendingResource> = (0..33_u8)
        .map(|byte| approval(0x90 + byte, 1_000))
        .collect();
    {
        let mut held = holding.lock().expect("held");
        for byte in 0..33_u8 {
            let asked = question(
                world.session_id,
                0xb0 + byte,
                QuestionState::Pending,
                1_000,
                &"q".repeat(longest),
            );
            held.questions.insert(asked.question_id, asked);
        }
        for resource in &approvals {
            held.records.insert(
                resource.resource_id,
                Ok(record_of(
                    resource,
                    PendingState::Pending,
                    &"a".repeat(kr_protocol::broker::MAX_PROJECTION_SUMMARY_LEN),
                    relayed_request("long"),
                )),
            );
        }
        held.resources.clone_from(&approvals);
    }
    let questions = |count: u8| {
        (0..count)
            .map(|byte| question_id(0xb0 + byte))
            .collect::<Vec<_>>()
    };
    let resources = |count: usize| {
        approvals
            .iter()
            .take(count)
            .map(|resource| resource.resource_id)
            .collect::<Vec<_>>()
    };

    // Thirty-three questions, thirty-three approvals, and a mix: each refused before the worker is
    // asked, and nothing written.
    let before = grants_written(&world);
    for (index, (named_questions, named_approvals)) in [
        (questions(33), resources(0)),
        (questions(0), resources(33)),
        (questions(17), resources(16)),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(named_questions.len() + named_approvals.len(), limit + 1);
        let action = 0x31 + u8::try_from(index).expect("small");
        let refused = refusal_of(
            shared(
                &world,
                &share(
                    world.environment_id,
                    world.session_id,
                    action,
                    naming(5_000, &named_questions, &named_approvals),
                ),
            )
            .await,
        );
        assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
        assert!(refused.message.contains("at most 32"), "{refused:?}");
        assert!(
            !invitation_written(&world, action),
            "no invitation is written for {index}"
        );
    }
    assert!(
        holding.lock().expect("held").asked.is_empty(),
        "the worker is asked nothing"
    );
    assert_eq!(grants_written(&world), before, "no grant is written");

    // Thirty-two, sixteen of each, every text as long as it may be.
    let mutation = share(
        world.environment_id,
        world.session_id,
        0x35,
        naming(5_000, &questions(16), &resources(16)),
    );
    let first = shared(&world, &mutation)
        .await
        .expect("thirty-two are shown");
    let result: GrantCreateResult = first.to_typed().expect("a share result");
    assert_eq!(
        result.preview.named_questions.len() + result.preview.named_approvals.len(),
        limit
    );
    let frame = kr_cbor::to_canonical_vec(&response(RequestId::new(u64::MAX), Ok(first.clone())))
        .expect("the answer encodes");
    assert!(
        frame.len() + 4 <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
        "the answer is {} bytes and a control frame carries {}",
        frame.len(),
        kr_protocol::limits::MAX_CONTROL_FRAME_LEN
    );
    assert!(
        invitation_written(&world, 0x35),
        "the invitation of a share that is written is found by its action"
    );
    let asked = holding.lock().expect("held").asked.len();
    let again = shared(&world, &mutation).await.expect("the answer is kept");
    assert_eq!(again, first, "read back from its record");
    assert_eq!(
        holding.lock().expect("held").asked.len(),
        asked,
        "and not shown again"
    );
    world.serving.abort();
}

/// The page each `events.snapshot` the daemon asked for continues after, in the order asked: `None`
/// for a first page.
fn pages_asked(holding: &Mutex<Holding>) -> Vec<Option<(u64, PendingResourceId)>> {
    holding
        .lock()
        .expect("held")
        .asked
        .iter()
        .filter(|request| request.method.method() == Some(Method::EventsSnapshot))
        .map(|request| {
            request
                .params
                .to_typed::<EventsSnapshotParams>()
                .expect("snapshot parameters")
                .agent_resources_from
                .0
                .map(|from| (from.snapshot_id.get(), from.after_resource_id))
        })
        .collect()
}

/// KR-REQ-10.51: the snapshot the named approvals are found in is read to its end, so an approval
/// on its last page is found. A snapshot that ends part way through, because what the broker holds
/// changed, is read again from its first page, as the snapshot it has become, and nothing is
/// decided from the part read before it ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_named_approval_is_found_on_a_later_page_after_a_resynchronisation() {
    let before: Vec<PendingResource> = (0..3_u8).map(|byte| approval(0xc0 + byte, 1_000)).collect();
    let named = approval(0xc5, 1_000);
    let mut after = before[1..].to_vec();
    after.push(named.clone());
    let (world, holding) = world(
        Holding {
            page: 1,
            snapshot_id: 7,
            changes_to: Some(after.clone()),
            ..Holding::default()
        },
        holds_question_reads(),
    )
    .await;
    {
        let mut held = holding.lock().expect("held");
        held.records.insert(
            named.resource_id,
            Ok(record_of(
                &named,
                PendingState::Pending,
                "On the last page",
                relayed_request("d"),
            )),
        );
        held.resources.clone_from(&before);
    }

    let result = result_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x41,
                naming(5_000, &[], &[named.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(result.preview.named_approvals.len(), 1);

    // The first page of snapshot 7, a continuation of it the worker could no longer serve, then
    // the first page of snapshot 8 and each continuation of it to its end.
    assert_eq!(
        pages_asked(&holding),
        vec![
            None,
            Some((7, before[0].resource_id)),
            None,
            Some((8, after[0].resource_id)),
            Some((8, after[1].resource_id)),
        ]
    );
    world.serving.abort();
}

/// KR-REQ-10.51: an approval the part of a snapshot read before it ended held, and the snapshot it
/// became does not, is not current here, even when the broker's ledger still answers for its
/// record: a share naming it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_an_approval_gone_from_the_snapshot_read_again_is_not_current() {
    let gone = approval(0xc6, 1_000);
    let before = vec![gone.clone(), approval(0xc7, 1_000)];
    let after = vec![approval(0xc7, 1_000), approval(0xc8, 1_000)];
    let (world, holding) = world(
        Holding {
            page: 1,
            snapshot_id: 7,
            changes_to: Some(after),
            ..Holding::default()
        },
        holds_question_reads(),
    )
    .await;
    {
        let mut held = holding.lock().expect("held");
        held.records.insert(
            gone.resource_id,
            Ok(record_of(
                &gone,
                PendingState::Pending,
                "Still in the ledger",
                relayed_request("e"),
            )),
        );
        held.resources = before;
    }
    let refused = refusal_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x42,
                naming(5_000, &[], &[gone.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(refused.message.contains("no current record"), "{refused:?}");
    world.serving.abort();
}

/// KR-REQ-10.51: a snapshot is read to its last page even when every named approval was on its
/// first, so the worker keeps no part of it for this daemon's link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_snapshot_is_read_to_its_end_after_the_named_approval() {
    let resources: Vec<PendingResource> =
        (0..3_u8).map(|byte| approval(0xd8 + byte, 1_000)).collect();
    let named = resources[0].clone();
    let (world, holding) = world(
        Holding {
            page: 1,
            snapshot_id: 7,
            ..Holding::default()
        },
        holds_question_reads(),
    )
    .await;
    {
        let mut held = holding.lock().expect("held");
        held.records.insert(
            named.resource_id,
            Ok(record_of(
                &named,
                PendingState::Pending,
                "On the first page",
                relayed_request("f"),
            )),
        );
        held.resources.clone_from(&resources);
    }
    let result = result_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x43,
                naming(5_000, &[], &[named.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(result.preview.named_approvals.len(), 1);
    assert_eq!(
        pages_asked(&holding),
        vec![
            None,
            Some((7, resources[0].resource_id)),
            Some((7, resources[1].resource_id)),
        ]
    );
    world.serving.abort();
}

/// KR-REQ-10.51: a share whose session's worker cannot be asked is not decided. A worker whose
/// link fails leaves the action unfinished, so the same request is told its outcome is not known
/// rather than a refusal it might not deserve, and so does a worker that answers with a transient
/// refusal of its own, which the share is given as the worker gave it. A session with no worker
/// this host knows is refused as unknown, and that is the action's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_whose_worker_cannot_be_asked_is_not_decided() {
    let named = approval(0xd1, 1_000);
    let (world, holding) = world(
        Holding {
            ends_on_inspect: true,
            ..Holding::default()
        },
        holds_question_reads(),
    )
    .await;
    holding.lock().expect("held").resources = vec![named.clone()];
    let before = grants_written(&world);

    let mutation = share(
        world.environment_id,
        world.session_id,
        0x51,
        naming(5_000, &[], &[named.resource_id]),
    );
    let failed = refusal_of(shared(&world, &mutation).await);
    assert_eq!(failed.code, ErrorCode::ResourceUnavailable, "{failed:?}");
    let again = refusal_of(shared(&world, &mutation).await);
    assert_eq!(again.code, ErrorCode::OutcomeUnknown, "{again:?}");

    // A worker that answers, and cannot read its own store: its refusal is the share's, and it
    // says nothing about the action either.
    {
        let mut held = holding.lock().expect("held");
        held.ends_on_inspect = false;
        held.records.insert(
            named.resource_id,
            Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                "the approval ledger could not be read",
            )),
        );
    }
    let mutation = share(
        world.environment_id,
        world.session_id,
        0x53,
        naming(5_000, &[], &[named.resource_id]),
    );
    let failed = refusal_of(shared(&world, &mutation).await);
    assert_eq!(failed.code, ErrorCode::StorageUnavailable, "{failed:?}");
    let again = refusal_of(shared(&world, &mutation).await);
    assert_eq!(again.code, ErrorCode::OutcomeUnknown, "{again:?}");

    let elsewhere = share(
        world.environment_id,
        SessionId::new(kr_ipc::new_uuid()),
        0x52,
        naming(5_000, &[question_id(0x74)], &[]),
    );
    let unknown = refusal_of(shared(&world, &elsewhere).await);
    assert_eq!(unknown.code, ErrorCode::UnknownSession, "{unknown:?}");
    let again = refusal_of(shared(&world, &elsewhere).await);
    assert_eq!(again, unknown, "the refusal is the action's answer");
    assert_eq!(grants_written(&world), before, "nothing is written");
    for action in [0x51, 0x52, 0x53] {
        assert!(
            !invitation_written(&world, action),
            "no invitation is written"
        );
    }
    world.serving.abort();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.51: the daemon's link to the worker, and the lease that rests on it
// ---------------------------------------------------------------------------------------------

/// Why the worker's dispatch lease would not renew now, or `None` when it would.
fn lease_refusal(world: &fake::Silent) -> Option<LeaseRefusal> {
    match world.controller.leases.renew(
        world.session_id,
        world.controller.generation,
        &*world.controller.clock,
    ) {
        Ok(Ok(_)) => None,
        Ok(Err(refusal)) => Some(refusal),
        Err(error) => panic!("no lease could be issued: {error}"),
    }
}

/// Whether the daemon keeps a link to the worker in its slot, for whichever operation comes next.
async fn link_kept(world: &fake::Silent) -> bool {
    let slot = world
        .controller
        .connections
        .lock()
        .await
        .get(&world.session_id)
        .map(Arc::clone);
    match slot {
        Some(slot) => slot.lock().await.is_some(),
        None => false,
    }
}

/// Resolves once the played worker has been asked for an approval's record.
async fn the_worker_is_asked_for_the_record(holding: &Mutex<Holding>) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !holding
            .lock()
            .expect("held")
            .asked
            .iter()
            .any(|request| request.method.method() == Some(Method::AgentApprovalInspect))
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker is asked for the record");
}

/// What the daemon holds about the action of the share `mutation`: its claim, while the attempt is
/// running, and once the attempt has ended.
fn claim_of(world: &fake::Silent, mutation: &MutationRequest) -> Option<ActionRecord> {
    let actor = ActorId::new("local:test").expect("a principal");
    let digest = kr_protocol::digest::mutation_digest(mutation, &actor).expect("a digest");
    world
        .controller
        .sharing()
        .grants()
        .recorded_action(&actor, mutation.action_id, &digest)
        .expect("the claim reads")
}

/// Resolves once a share is waiting for the daemon's link to the worker, which another operation
/// holds. Three hold the slot then: the daemon's map of links, the operation that holds the link,
/// and the share, which took a handle on the slot to wait for it.
async fn a_share_is_waiting_for_the_link(world: &fake::Silent) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting = world
                .controller
                .connections
                .lock()
                .await
                .get(&world.session_id)
                .is_some_and(|slot| Arc::strong_count(slot) == 3);
            if waiting {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a share is waiting for the link");
}

/// A worker that holds `named`, pending, and answers for its record.
fn holding_approval(named: &PendingResource) -> Holding {
    Holding {
        resources: vec![named.clone()],
        records: BTreeMap::from([(
            named.resource_id,
            Ok(record_of(
                named,
                PendingState::Pending,
                "Waiting",
                relayed_request("g"),
            )),
        )]),
        ..Holding::default()
    }
}

/// How a share's exchange with the worker fails to finish.
#[derive(Clone, Copy)]
enum Unfinished {
    /// The worker ends the link when it is asked for the record.
    LinkEnds,
    /// The worker never sends the record, and the share runs out of time.
    RunsOutOfTime,
    /// The worker never sends the record, and the share is abandoned once it has been asked.
    Abandoned,
}

/// A share whose exchange with the worker does not finish, in the way `how` says, gives up the link
/// it was using and the worker's lease with it: the link is not kept for the next caller, the lease
/// is refused, and nothing is written. Once the worker answers again, the next share opens a link
/// of its own and gives it back, which does not restore the lease; the daemon's next announcement
/// of the authority revision is made over that link, and the worker's acknowledgement of it lifts
/// the refusal; and a share after that takes nothing from the lease.
async fn an_unfinished_exchange_gives_up_its_link_and_the_lease(how: Unfinished) {
    let named = approval(0xe8, 1_000);
    let (world, holding) = world(
        Holding {
            ends_on_inspect: matches!(how, Unfinished::LinkEnds),
            silent_on_inspect: !matches!(how, Unfinished::LinkEnds),
            ..holding_approval(&named)
        },
        holds_question_reads(),
    )
    .await;
    assert_eq!(
        lease_refusal(&world),
        None,
        "the lease renews before the share"
    );
    let before = grants_written(&world);

    let unfinished = share(
        world.environment_id,
        world.session_id,
        0x72,
        naming(5_000, &[], &[named.resource_id]),
    );
    match how {
        Unfinished::LinkEnds | Unfinished::RunsOutOfTime => {
            let refused = refusal_of(shared(&world, &unfinished).await);
            assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
        }
        Unfinished::Abandoned => {
            tokio::select! {
                answered = shared(&world, &unfinished) => {
                    panic!("the share was answered: {answered:?}")
                }
                () = the_worker_is_asked_for_the_record(&holding) => {}
            }
            assert_eq!(
                claim_of(&world, &unfinished),
                Some(ActionRecord::Unfinished),
                "the attempt ended without recording what it did"
            );
        }
    }
    assert!(
        holding
            .lock()
            .expect("held")
            .asked
            .iter()
            .any(|request| request.method.method() == Some(Method::AgentApprovalInspect)),
        "the share had the link, and was waiting on the worker's answer"
    );
    assert!(
        !link_kept(&world).await,
        "the link is not kept for the next caller"
    );
    assert!(world.controller.leases.is_fenced(world.session_id));
    assert_eq!(
        lease_refusal(&world),
        Some(LeaseRefusal::RevisionNotAcknowledged),
        "the lease is refused until the worker acknowledges again"
    );
    assert_eq!(grants_written(&world), before, "nothing is written");

    // The worker answers again. The next share opens a link of its own and gives it back once its
    // exchange is whole; that does not restore the lease, which rests on the worker's
    // acknowledgement of the revision.
    {
        let mut held = holding.lock().expect("held");
        held.ends_on_inspect = false;
        held.silent_on_inspect = false;
    }
    let mut action = 0x74;
    let mut next_share = || {
        action += 1;
        share(
            world.environment_id,
            world.session_id,
            action,
            naming(5_000, &[], &[named.resource_id]),
        )
    };
    let result = result_of(shared(&world, &next_share()).await);
    assert_eq!(result.preview.named_approvals.len(), 1);
    assert_eq!(
        holding.lock().expect("held").connections,
        2,
        "the share opened a link of its own"
    );
    assert!(link_kept(&world).await, "and gave it back");
    assert_eq!(
        lease_refusal(&world),
        Some(LeaseRefusal::RevisionNotAcknowledged),
        "a share does not restore the lease"
    );

    // The daemon announces the authority revision over that link, and the worker acknowledges it.
    world
        .controller
        .announce_authority_revision()
        .await
        .expect("the revision is announced");
    assert_eq!(
        holding.lock().expect("held").connections,
        2,
        "the announcement was made over the link the share gave back"
    );
    assert_eq!(
        lease_refusal(&world),
        None,
        "the acknowledgement lifts the refusal"
    );

    // A share after that takes nothing from the lease.
    let result = result_of(shared(&world, &next_share()).await);
    assert_eq!(result.preview.named_approvals.len(), 1);
    assert!(link_kept(&world).await);
    assert_eq!(
        lease_refusal(&world),
        None,
        "a whole exchange takes nothing from the lease"
    );
    world.serving.abort();
}

/// KR-REQ-10.51: a share whose link to the worker fails part way gives up the link and the
/// worker's lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_whose_link_ends_gives_up_the_link_and_the_lease() {
    an_unfinished_exchange_gives_up_its_link_and_the_lease(Unfinished::LinkEnds).await;
}

/// KR-REQ-10.51: a share that runs out of time waiting for the worker's answer gives up the link
/// and the lease as one whose link failed does: an answer may still be on its way over the link,
/// and the lease rests on an acknowledgement made over a link this daemon no longer holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_that_runs_out_of_time_with_the_link_gives_up_the_link_and_the_lease()
{
    an_unfinished_exchange_gives_up_its_link_and_the_lease(Unfinished::RunsOutOfTime).await;
}

/// KR-REQ-10.51: a share abandoned while it waits for the worker's answer, as one is when the
/// request that asked for it goes away, gives up the link and the lease the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_abandoned_with_the_link_gives_up_the_link_and_the_lease() {
    an_unfinished_exchange_gives_up_its_link_and_the_lease(Unfinished::Abandoned).await;
}

/// KR-REQ-10.51: a share that stops waiting for the link, because another operation holds it, or is
/// abandoned while it waits, takes nothing from that operation: its link stays open, the worker's
/// lease still renews, and the next share is served over that same link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_that_stops_waiting_for_the_link_leaves_the_link_and_the_lease() {
    let named = approval(0xe9, 1_000);
    let (world, holding) = world(holding_approval(&named), holds_question_reads()).await;
    let mut held_elsewhere = world
        .controller
        .worker_client_of(world.session_id)
        .await
        .expect("the link opens");

    // Abandoned while it waits.
    let abandoned = share(
        world.environment_id,
        world.session_id,
        0x71,
        naming(5_000, &[], &[named.resource_id]),
    );
    tokio::select! {
        answered = shared(&world, &abandoned) => panic!("the share was answered: {answered:?}"),
        () = a_share_is_waiting_for_the_link(&world) => {}
    }
    assert_eq!(
        claim_of(&world, &abandoned),
        Some(ActionRecord::Unfinished),
        "the attempt ended without recording what it did"
    );
    // Out of time, having waited for the whole bound.
    let waited = refusal_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x72,
                naming(5_000, &[], &[named.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(waited.code, ErrorCode::ResourceUnavailable, "{waited:?}");
    assert!(
        held_elsewhere.holds_the_connection(),
        "the other operation keeps its link"
    );
    assert!(!world.controller.leases.is_fenced(world.session_id));
    assert_eq!(lease_refusal(&world), None, "the lease still renews");
    assert!(
        holding.lock().expect("held").asked.is_empty(),
        "the worker was asked nothing"
    );
    // The other operation's work ended whole, so its link goes back as it came.
    held_elsewhere.give_back();
    drop(held_elsewhere);

    // The next share is served over the link the other operation opened.
    let result = result_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x73,
                naming(5_000, &[], &[named.resource_id]),
            ),
        )
        .await,
    );
    assert_eq!(result.preview.named_approvals.len(), 1);
    assert_eq!(holding.lock().expect("held").connections, 1);
    assert!(link_kept(&world).await);
    assert_eq!(lease_refusal(&world), None);
    world.serving.abort();
}

/// KR-REQ-10.51: a share whose exchange with the worker finishes keeps the link for the next
/// caller and leaves the worker's lease as it was, whatever the share comes to: written, refused
/// because what it names is not current, or refused by the worker itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_whose_exchange_finishes_keeps_its_link_and_the_lease() {
    let named = approval(0xeb, 1_000);
    let unreadable = approval(0xec, 1_000);
    let mut worker = holding_approval(&named);
    worker.resources.push(unreadable.clone());
    worker.records.insert(
        unreadable.resource_id,
        Err(ProtocolError::new(
            ErrorCode::StorageUnavailable,
            "the approval ledger could not be read",
        )),
    );
    let (world, holding) = world(worker, holds_question_reads()).await;

    let shares: [(&str, RoleSelection, Option<ErrorCode>); 4] = [
        ("written", naming(5_000, &[], &[named.resource_id]), None),
        (
            "no current approval",
            naming(5_000, &[], &[resource_id(0x68)]),
            Some(ErrorCode::InvalidArgument),
        ),
        (
            "no open question",
            naming(5_000, &[question_id(0x77)], &[]),
            Some(ErrorCode::InvalidArgument),
        ),
        (
            "the worker's own refusal",
            naming(5_000, &[], &[unreadable.resource_id]),
            Some(ErrorCode::StorageUnavailable),
        ),
    ];
    for (action, (why, selection, refused)) in (0x91_u8..).zip(shares) {
        let answer = shared(
            &world,
            &share(world.environment_id, world.session_id, action, selection),
        )
        .await;
        match refused {
            None => {
                result_of(answer);
            }
            Some(code) => assert_eq!(refusal_of(answer).code, code, "{why}"),
        }
        assert!(link_kept(&world).await, "{why}: the link is kept");
        assert!(
            !world.controller.leases.is_fenced(world.session_id),
            "{why}"
        );
        assert_eq!(lease_refusal(&world), None, "{why}: the lease still renews");
        assert_eq!(
            holding.lock().expect("held").connections,
            1,
            "{why}: one link has served every share"
        );
    }
    world.serving.abort();
}

/// KR-REQ-10.51: what a share's failed exchange gives up is the control path it took its link
/// from. An announcement of an authority revision that begins while the share holds the link binds
/// the worker to a new path, and then waits behind the share for the link: when the share loses its
/// link, the announcement opens a link of its own, its acknowledgement over the new path is
/// accepted and the lease renews, since the loss is news about the path that was replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_share_that_loses_its_link_leaves_a_path_that_replaced_its_own() {
    let named = approval(0xea, 1_000);
    let (world, holding) = world(
        Holding {
            silent_on_inspect: true,
            ..holding_approval(&named)
        },
        holds_question_reads(),
    )
    .await;
    let unfinished = share(
        world.environment_id,
        world.session_id,
        0x76,
        naming(5_000, &[], &[named.resource_id]),
    );
    let path_of_the_link = world.controller.leases.binding(world.session_id);
    // The announcement starts once the worker has been asked for the record, that is once the share
    // holds the link: it binds the worker to a new path, and then waits behind the share for the link.
    let announcing = {
        let controller = Arc::clone(&world.controller);
        let holding = Arc::clone(&holding);
        tokio::spawn(async move {
            the_worker_is_asked_for_the_record(&holding).await;
            controller.announce_authority_revision().await
        })
    };
    tokio::select! {
        answered = shared(&world, &unfinished) => panic!("the share was answered: {answered:?}"),
        () = async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while world.controller.leases.binding(world.session_id) == path_of_the_link {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the announcement binds the worker to a new path");
        } => {}
    }
    // The share has been dropped, with its link, and the announcement goes on over a link of its own.
    announcing
        .await
        .expect("the announcement's task ends")
        .expect("the revision is announced");
    assert!(
        !world.controller.leases.is_fenced(world.session_id),
        "the path in force was not the one the share's link belonged to"
    );
    assert_eq!(
        lease_refusal(&world),
        None,
        "the acknowledgement over the new path was accepted"
    );
    assert_eq!(
        holding.lock().expect("held").connections,
        2,
        "the announcement opened a link of its own"
    );
    world.serving.abort();
}

/// A share that names nothing asks no worker anything, and is written as it always was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_naming_nothing_asks_no_worker() {
    let (world, holding) = world(Holding::default(), holds_question_reads()).await;
    let result = result_of(
        shared(
            &world,
            &share(
                world.environment_id,
                world.session_id,
                0x61,
                naming(5_000, &[], &[]),
            ),
        )
        .await,
    );
    assert!(result.preview.named_questions.is_empty());
    assert!(result.preview.named_approvals.is_empty());
    assert!(holding.lock().expect("held").asked.is_empty());
    world.serving.abort();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.51: a question read goes only to a worker that holds it to its scope
// ---------------------------------------------------------------------------------------------

/// A device committed to `controller`'s records, holding `grant`.
fn holding_grant(
    controller: &crate::service::Controller,
    byte: u8,
    grant: kr_protocol::grant::Grant,
) -> DeviceRecord {
    let device = DeviceRecord {
        device_id: grant.recipient_device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([byte; 32]),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
        stored_envelope: None,
        notification_preview: None,
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant,
        paired_at_ms: TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    };
    controller.devices().commit(&device).expect("paired");
    device
}

/// A device that sees every session, reaching back to `bound_ms` and naming `named`.
fn scoped_device(
    controller: &crate::service::Controller,
    byte: u8,
    bound_ms: u64,
    named: &[QuestionId],
) -> DeviceRecord {
    let (mut grant, _) = crate::service::net::tests::granted(
        kr_protocol::grant::GrantExpiry::Never,
        controller.policy().authority_revision(),
    );
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(bound_ms));
    grant.history.named_questions = named.iter().copied().collect();
    holding_grant(controller, byte, grant)
}

/// One read from a device.
fn device_read<P: serde::Serialize>(request_id: u64, method: Method, params: &P) -> Request {
    Request {
        request_id: RequestId::new(request_id),
        method: method.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(params).expect("encodes"),
    }
}

/// The refusal an answer carries, or a panic naming what it carries instead.
fn refused(answer: ControlFrame) -> ProtocolError {
    match answer {
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => error,
        other => panic!("the read was not refused: {other:?}"),
    }
}

/// KR-REQ-10.51: a device's question read carries its grant's scope, and only the worker holds the
/// answer to it, so it goes only to a worker that says it does. A worker of an earlier build reads
/// a scope and answers a question read with every question it holds; a device's question read is
/// refused before anything reaches it, while its other reads still go to it with their scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_question_read_goes_only_to_a_worker_that_holds_it_to_its_scope() {
    let (world, holding) = world(Holding::default(), reads_scopes_only()).await;
    holding.lock().expect("held").questions.insert(
        question_id(0x75),
        question(
            world.session_id,
            0x75,
            QuestionState::Answered,
            1_000,
            "Before the bound",
        ),
    );
    let device = scoped_device(&world.controller, 21, 5_000, &[]);
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());

    let refusal = refused(
        connection
            .read(&device_read(
                1,
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id: world.session_id,
                    question_id: Nullable::null(),
                    include_resolved: true,
                },
            ))
            .await,
    );
    assert_eq!(
        refusal.code,
        ErrorCode::UnsupportedCapability,
        "{refusal:?}"
    );
    // Another read goes to that worker as it always did, with the grant's scope.
    let _ = connection
        .read(&device_read(
            2,
            Method::AgentCapabilities,
            &kr_protocol::agent::AgentCapabilitiesParams {
                subject: kr_protocol::agent::AgentSubject {
                    session_id: world.session_id,
                    application_instance_id: instance(0x41),
                },
            },
        ))
        .await;
    let held = holding.lock().expect("held");
    assert_eq!(
        held.forwarded
            .iter()
            .map(|forwarded| (forwarded.request.method.method(), forwarded.history.clone()))
            .collect::<Vec<_>>(),
        vec![(
            Some(Method::AgentCapabilities),
            Some(device.grant.history.clone())
        )],
        "the question read reached no worker"
    );
    drop(held);
    world.serving.abort();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.51: a real worker, and a device holding the issued grant
// ---------------------------------------------------------------------------------------------

/// The instance a Claude Code channel speaks for in the real worker.
fn channel_instance() -> ApplicationInstanceId {
    instance(0xe1)
}

/// The application the launch registered for that instance, and the channel server it started.
fn launched() -> kr_protocol::identity::ProcessStartIdentity {
    kr_protocol::identity::ProcessStartIdentity::new(
        1_001,
        kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
        900,
    )
}

fn channel_server() -> kr_protocol::identity::ProcessStartIdentity {
    kr_protocol::identity::ProcessStartIdentity::new(
        2_001,
        kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
        901,
    )
}

/// A daemon with a real worker service in its directory, in this process, whose broker holds one
/// launched Claude Code instance with its connector's channel open.
struct Served {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<crate::service::Controller>,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    service: Arc<kr_worker::service::WorkerService>,
    runtime: Arc<kr_worker::runtime::SessionRuntime>,
    endpoint: kr_ipc::paths::Endpoint,
    accepted: kr_transport::window::AcceptedDeadline,
    /// Where the connector's package was laid out, removed when the test ends.
    package: std::path::PathBuf,
    /// The channel server's end of the channel's connection.
    relays: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    /// What this host wrote on the channel, kept so its writer never waits on a full connection.
    _verdicts: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    /// Ends the channel as the command backend's retirement does.
    retire: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Served {
    /// Starts the daemon and the worker, registers the worker in the daemon's directory as a
    /// worker that reported itself ready is, and opens the instance's channel.
    async fn start() -> Self {
        use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
        use kr_protocol::session::DisplayNumber;
        use kr_worker::broker::bridge::{
            AdmittedBridge, BridgeProcess, BridgeStream, BridgeSurface,
        };
        use kr_worker::broker::connectors::{InstalledConnector, decoding_trust, fixture};

        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let controller = crate::service::Controller::start(fake::setup(&temp))
            .await
            .expect("the daemon starts");
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                controller.boot_identity.clone(),
                kr_ipc::identity::current_process_start_identity().expect("a process identity"),
                kr_protocol::hello::PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let mut session = kr_worker::session::Session::open(kr_worker::session::SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("exec cat"),
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        })
        .expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            kr_worker::runtime::SessionRuntime::start(
                session,
                Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = Arc::new(
            kr_worker::service::WorkerService::new(
                Arc::clone(&runtime),
                Arc::clone(&identity),
                endpoint.clone(),
                kr_worker::service::ServiceBinding {
                    environment_id,
                    boot_identity: controller.boot_identity.clone(),
                    controller_public_key: *controller.identity.public_key(),
                    controller_generation: controller.generation,
                    journal_path: Some(journal_path),
                    build_id: controller.build_id.clone(),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        let descriptor = kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            boot_identity: identity.boot_identity().clone(),
            process_start_identity: identity.process_start_identity().clone(),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        };
        controller.directory.lock().await.insert(
            crate::directory::KnownWorker {
                descriptor,
                endpoint: endpoint.clone(),
            },
            None,
        );
        fake::acknowledged(&controller, session_id);

        // The launched instance, its connector's package bound as the installation's binder binds
        // it, with the approval interpreter's grant, and the channel it opened.
        let broker = service.broker();
        broker
            .register_instance(
                channel_instance(),
                IntegrationMode::NativeBridge,
                None,
                Some(kr_worker::broker::ManagedProcess::new(
                    channel_instance(),
                    launched(),
                    kr_worker::broker::TransportHandle {
                        transport: kr_worker::broker::BrokerTransport::PrivateSocket,
                        application_instance_id: channel_instance(),
                        executable_digest: Digest256::from_bytes([3; 32]),
                        process: launched(),
                    },
                    kr_worker::broker::Credential::from_bytes([9; 32]),
                    false,
                    TimestampMs::new(1),
                )),
            )
            .expect("the launched instance is registered");
        let package = std::env::temp_dir().join(format!("kr-share-channel-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&package).expect("the store's directory");
        let connector = Arc::new(
            InstalledConnector::read(
                fixture::claude_code_package(&package, std::path::Path::new(fixture::FORWARDER))
                    .expect("the package is written"),
            )
            .expect("the installed package reads"),
        );
        broker
            .bind_descriptor(
                BrokerBindingId::new(Uuid::from_bytes([0xe2; 16])),
                channel_instance(),
                connector.plugin_id(),
                PublisherId::new("kalareach").expect("a publisher"),
                connector.package_digest(),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                decoding_trust(&connector, TimestampMs::new(1)),
                TimestampMs::new(1),
            )
            .expect("the package is bound");
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(theirs);
        let admitted = AdmittedBridge {
            surface: BridgeSurface::Channel,
            process: BridgeProcess {
                identity: channel_server(),
                starter: Some(launched()),
                started: None,
            },
            stream: BridgeStream::new(
                Box::new(reader),
                Box::new(writer),
                Vec::new(),
                kr_worker::broker::Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            ),
        };
        let (retire, retired) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(kr_worker::broker::channels::serve(
            kr_worker::broker::channels::ChannelLaunch {
                broker: Arc::clone(broker),
                application_instance_id: channel_instance(),
                connector,
                version: Some(fixture::QUALIFIED_VERSION.to_owned()),
                site: environment_id,
                os_user: "person".to_owned(),
                views: None,
            },
            admitted,
            async move {
                let _ = retired.await;
            },
        ));
        let (verdicts, relays) = tokio::io::split(ours);
        let accepted = kr_transport::window::AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(std::time::Duration::from_secs(300))
                .expect("a deadline five minutes out"),
            bound: kr_transport::window::DeadlineBound::RequestedTtl,
        };
        Self {
            _temp: temp,
            controller,
            environment_id,
            session_id,
            service,
            runtime,
            endpoint,
            accepted,
            package,
            relays,
            _verdicts: verdicts,
            retire: Some(retire),
        }
    }

    /// Relays one tool approval on the channel, as Claude Code's forwarder does, and returns the
    /// resource the broker recorded and its connector's table interpreted.
    async fn relay(&mut self, request_id: &str) -> PendingResource {
        use tokio::io::AsyncWriteExt as _;

        let mut frame = relayed_request(request_id);
        frame.push(b'\n');
        self.relays
            .write_all(&frame)
            .await
            .expect("the channel takes the frame");
        self.relays.flush().await.expect("and it goes");
        let upstream = format!("\"{request_id}\"");
        let started = tokio::time::Instant::now();
        loop {
            if let Some(resource) =
                self.service
                    .broker()
                    .pending_resources()
                    .into_iter()
                    .find(|resource| {
                        resource.request.upstream.as_str() == upstream
                            && resource.interpretation_verified
                    })
            {
                return resource;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "the relayed approval {request_id} is interpreted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Has an application inside the session ask a question now, and returns it.
    fn ask(&self, request: &str) -> Question {
        let source = kr_worker::questions::binding::VerifiedSource {
            process: kr_ipc::identity::current_process_start_identity()
                .expect("a process identity"),
            executable: Some("kr-test-agent".to_owned()),
            session_member: true,
            ancestry: true,
            launch_channel: true,
            connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
        };
        let params = kr_protocol::question::QuestionCreateParams {
            session_id: self.session_id,
            request_id: request.to_owned(),
            agent_name: Nullable::some("kr-test-agent".to_owned()),
            context: "The build finished with two failing tests.".to_owned(),
            question: format!("Push the branch anyway? ({request})"),
            kind: QuestionKind::Confirm,
            choices: Vec::new(),
            requested_expiry_ms: Nullable::some(DurationMs::new(3_600_000)),
            wait_ms: Nullable::null(),
        };
        self.service
            .questions()
            .create(&source, &params, now())
            .expect("the question is asked")
            .0
            .question
    }

    /// The local owner's answer to `question`, now.
    fn answer_question(&self, question: &Question) {
        self.service
            .questions()
            .answer(
                &ActorId::new("local:the-owner").expect("an actor"),
                None,
                &kr_protocol::question::QuestionAnswerParams {
                    session_id: self.session_id,
                    question_id: question.question_id,
                    expected_revision: question.revision,
                    answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
                },
                now(),
            )
            .expect("the question is answered");
    }

    /// The local owner's answer to `approval`, which the channel carries to the application.
    async fn answer_approval(&self, approval: &PendingResource) {
        let (answered, _) = self
            .service
            .broker()
            .agent_approval_respond(
                &kr_worker::broker::Caller {
                    actor_id: ActorId::new("local:the-owner").expect("an actor"),
                    grant_id: None,
                },
                &kr_protocol::agent::AgentApprovalRespondParams {
                    target: kr_protocol::agent::AgentMutationTarget {
                        subject: kr_protocol::agent::AgentSubject {
                            session_id: self.session_id,
                            application_instance_id: channel_instance(),
                        },
                        binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
                    },
                    resource_id: approval.resource_id,
                    option_id: "allow".to_owned(),
                },
                kr_ipc::now_ms(),
            )
            .await
            .expect("the owner answers the approval");
        assert!(answered.state.is_terminal(), "{answered:?}");
    }

    /// Shares the session as the local owner, reaching back to `bound_ms` and naming these.
    async fn share(
        &self,
        bound_ms: u64,
        questions: &[QuestionId],
        approvals: &[PendingResourceId],
    ) -> GrantCreateResult {
        let mutation = share(
            self.environment_id,
            self.session_id,
            0x71,
            naming(bound_ms, questions, approvals),
        );
        let carried = fake::admission(&self.controller, self.accepted).await;
        self.controller
            .authority_change(
                &ActorId::new("local:test").expect("a principal"),
                &mutation,
                Method::GrantCreate,
                carried,
            )
            .await
            .expect("the share is written")
            .to_typed()
            .expect("a share result")
    }

    fn close(mut self) {
        if let Some(retire) = self.retire.take() {
            let _ = retire.send(());
        }
        self.runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
        let _ = std::fs::remove_dir_all(&self.package);
    }
}

/// This moment, as the question ledger reads it.
fn now() -> kr_worker::questions::Now {
    kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

/// The questions a device read is answered with, or a panic naming its refusal.
fn questions_in(answer: ControlFrame) -> Vec<QuestionId> {
    match answer {
        ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) => value
            .to_typed::<QuestionReadResult>()
            .expect("a question read")
            .questions
            .into_iter()
            .map(|question| question.question_id)
            .collect(),
        other => panic!("the questions were not read: {other:?}"),
    }
}

/// KR-REQ-10.51: through a paired device's door and a real worker, a device holding the grant an
/// issuer shared, naming a question and an approval from before its history bound, reads the two
/// while they can still be decided, and neither once they have been. The approval is one a Claude
/// Code channel relayed, whose connector's table gives no summary, so the issuer was shown the
/// request as the upstream wrote it. A question and an approval the grant does not name, from
/// before the bound, are never read; the local owner reads all four throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_device_reads_the_decisions_its_grant_names_while_they_are_current() {
    let mut served = Served::start().await;
    let named_approval = served.relay("named").await;
    let other_approval = served.relay("other").await;
    let named_question = served.ask("named");
    let other_question = served.ask("other");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let bound = kr_ipc::now_ms().get();

    // What the issuer is shown: the question's text and moment, and the request as the channel's
    // upstream wrote it, with the moment the broker recorded it.
    let issued = served
        .share(
            bound,
            &[named_question.question_id],
            &[named_approval.resource_id],
        )
        .await;
    assert_eq!(
        issued.preview.named_questions,
        vec![NamedQuestionPreview {
            question_id: named_question.question_id,
            revision: named_question.revision,
            question: named_question.question.clone(),
            created_at_ms: named_question.created_at_ms,
        }]
    );
    assert_eq!(
        issued.preview.named_approvals,
        vec![NamedApprovalPreview {
            resource_id: named_approval.resource_id,
            summary: String::from_utf8(relayed_request("named")).expect("text"),
            created_at_ms: named_approval.recorded_at,
        }]
    );

    // The device the invitation names holds the grant it carries.
    let redeemed = served
        .controller
        .sharing()
        .redeem(
            issued.preview.invitation_id,
            recipient(),
            kr_ipc::now_ms().get(),
        )
        .expect("the invitation is redeemed");
    let device = holding_grant(&served.controller, 31, redeemed);
    let connection = super::RemoteConnection::for_test(&served.controller, device);
    let questions = |request_id: u64| {
        device_read(
            request_id,
            Method::QuestionRead,
            &QuestionReadParams {
                session_id: served.session_id,
                question_id: Nullable::null(),
                include_resolved: true,
            },
        )
    };
    let record = |request_id: u64, approval: &PendingResource| {
        device_read(
            request_id,
            Method::AgentApprovalInspect,
            &AgentApprovalInspectParams {
                subject: kr_protocol::agent::AgentSubject {
                    session_id: served.session_id,
                    application_instance_id: channel_instance(),
                },
                resource_id: approval.resource_id,
            },
        )
    };

    // While both can be decided: the named two are read, and nothing else from before the bound.
    assert_eq!(
        questions_in(connection.read(&questions(1)).await),
        vec![named_question.question_id]
    );
    let read = match connection.read(&record(2, &named_approval)).await {
        ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) => value
            .to_typed::<AgentApprovalInspectResult>()
            .expect("an approval's record"),
        other => panic!("the named approval's record is not read: {other:?}"),
    };
    assert_eq!(read.resource_id, named_approval.resource_id);
    assert_eq!(read.state, PendingState::Pending);
    assert_eq!(read.recorded_at, named_approval.recorded_at);
    assert_eq!(
        read.decoding.source_bytes.as_slice(),
        relayed_request("named").as_slice(),
        "the request as the channel relayed it"
    );
    let withheld = refused(connection.read(&record(3, &other_approval)).await);
    assert_eq!(withheld.code, ErrorCode::StaleSession, "{withheld:?}");

    // Once each has been decided, the name no longer reaches back past the bound for it.
    served.answer_approval(&named_approval).await;
    served.answer_question(&named_question);
    assert!(questions_in(connection.read(&questions(4)).await).is_empty());
    let ended = refused(connection.read(&record(5, &named_approval)).await);
    assert_eq!(ended.code, ErrorCode::StaleSession, "{ended:?}");

    // The local owner, in a window of its own on the worker's socket, reads all four.
    let mut window = kr_ipc::client::LocalClient::connect(
        &served.endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("the owner's window connects");
    let every: QuestionReadResult = window
        .request(
            Method::QuestionRead,
            &QuestionReadParams {
                session_id: served.session_id,
                question_id: Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the questions are read")
        .to_typed()
        .expect("a question read");
    assert_eq!(
        every
            .questions
            .iter()
            .map(|question| question.question_id)
            .collect::<Vec<_>>(),
        vec![named_question.question_id, other_question.question_id]
    );
    for approval in [&named_approval, &other_approval] {
        let _: AgentApprovalInspectResult = window
            .request(
                Method::AgentApprovalInspect,
                &AgentApprovalInspectParams {
                    subject: kr_protocol::agent::AgentSubject {
                        session_id: served.session_id,
                        application_instance_id: channel_instance(),
                    },
                    resource_id: approval.resource_id,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the owner reads every record")
            .to_typed()
            .expect("a record");
    }
    drop(window);
    served.close();
}
