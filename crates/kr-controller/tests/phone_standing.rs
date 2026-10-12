//! A phone opens a paired host's sessions: the host's half.
//!
//! One real daemon on the loopback network, started the way a host starts one, and the workers it
//! adopts: each worker's own service on its own socket, with its journal, its spool, its shell,
//! its question ledger and its broker, run in this process. The only thing a test supplies in
//! place of the product is an agent's upstream, the transport the broker hands a prompt to.
//!
//! Devices pair over the network and speak to the daemon on connections of their own, so what each
//! test asserts is read from the daemon's answer to a device. A refusal is asserted by its kind,
//! never by its words.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-19.08 | the `kr_req_19_08_` tests here |

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::net::devices::DeviceRecord;
use kr_protocol::agent::{
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentMutationTarget, AgentPromptParams,
    AgentSnapshotParams, AgentSnapshotResult, PromptText,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, AgentBindingRevision, ApplicationInstanceId, GrantId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{QuestionReadParams, QuestionReadResult};
use kr_protocol::recovery::{
    AgentInstancesParams, AgentInstancesResult, EventsSnapshotParams, EventsSnapshotResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{
    OpenedVia, SessionCloseParams, SessionListParams, SessionListResult, SessionOpenParams,
    SessionOpenResult, SessionReadParams, ShareEnd,
};
use kr_protocol::sharing::{RoleSelection, SessionRole};

use net_support::worker::{Adopted, Upstream, Worker, offer, revoke, share};
use net_support::{
    Device, RawDevice, delegated, on_the_session, owned_by, pair_with, proposal, recipient,
};

/// How long a test waits for a connection the host has withdrawn to be seen as ended.
const PATIENCE: Duration = Duration::from_secs(30);

/// A device paired under `rights`, whose history reaches back to the start of time.
async fn viewer(adopted: &Adopted, rights: &[ActionRight]) -> (Device, DeviceRecord) {
    let device = Device::create().await;
    let mut grant = proposal(rights);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    let record = pair_with(&adopted.host, &device, &adopted.owner, grant).await;
    (device, record)
}

/// Opens a connection for a session, or for the host when no session is named.
async fn open(
    connection: &RawDevice,
    session_id: Option<SessionId>,
    grant_id: Option<GrantId>,
) -> Result<SessionOpenResult, ProtocolError> {
    let value = connection
        .read(
            Method::SessionOpen,
            &SessionOpenParams {
                session_id: Nullable(session_id),
                grant_id: Nullable(grant_id),
            },
        )
        .await?;
    Ok(value.to_typed().expect("the answer decodes"))
}

/// What an open that is in force reports.
struct Standing {
    via: OpenedVia,
    actions: Vec<ActionRight>,
    live: bool,
    ends_at_ms: Option<u64>,
}

fn in_force(opened: SessionOpenResult) -> Standing {
    match opened {
        SessionOpenResult::InForce {
            via,
            actions,
            includes_live_screen,
            ends_at_ms,
            ..
        } => {
            let mut actions: Vec<ActionRight> = actions.iter().copied().collect();
            actions.sort();
            Standing {
                via,
                actions,
                live: includes_live_screen,
                ends_at_ms: ends_at_ms.0.map(|at| at.get()),
            }
        }
        SessionOpenResult::Ended { reason } => {
            panic!("the open is in force, but it ended: {reason:?}")
        }
    }
}

/// Attaches `connection` to a session's terminal as a viewer, under the grant it was opened for.
async fn attach(
    adopted: &Adopted,
    connection: &RawDevice,
    session_id: SessionId,
) -> Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
    connection
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_session(&adopted.host, session_id),
            &kr_protocol::attachment::SessionAttachParams {
                session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: [kr_protocol::attachment::AttachmentCapability::ObserveTerminal]
                    .into_iter()
                    .collect(),
            },
        )
        .await
}

/// When a grant expires, in UTC milliseconds.
fn expiry_of(grant: &kr_protocol::grant::Grant) -> u64 {
    match grant.expiry {
        kr_protocol::grant::GrantExpiry::At { expires_at_ms } => expires_at_ms.get(),
        kr_protocol::grant::GrantExpiry::Never => panic!("this grant does not expire"),
    }
}

fn sorted(rights: &[ActionRight]) -> Vec<ActionRight> {
    let mut rights = rights.to_vec();
    rights.sort();
    rights
}

fn code<T>(outcome: Result<T, ProtocolError>) -> ErrorCode {
    match outcome {
        Ok(_) => panic!("this call is refused"),
        Err(error) => error.code,
    }
}

fn questions(session_id: SessionId) -> QuestionReadParams {
    QuestionReadParams {
        session_id,
        question_id: Nullable::null(),
        include_resolved: false,
    }
}

fn listing() -> SessionListParams {
    SessionListParams {
        environment_id: Nullable::null(),
        include_closed: false,
    }
}

fn target(adopted: &Adopted, worker: &Worker, instance: ApplicationInstanceId) -> ActionTarget {
    ActionTarget {
        application_instance_id: Nullable::some(instance),
        agent_binding_revision: Nullable::some(Worker::BINDING),
        ..on_the_session(&adopted.host, worker.session_id)
    }
}

/// A daemon reaches a worker's agent: the device finds the instance in the session's snapshot,
/// reads its capabilities and conversation, and its prompt reaches the upstream the broker
/// dispatches on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_reads_and_prompts_an_agent_on_a_worker_the_daemon_adopted() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    worker
        .service
        .broker()
        .observe(
            instance,
            "message",
            "ready when you are",
            TimestampMs::new(2),
        )
        .expect("the agent has said something");

    let (device, record) = viewer(
        &adopted,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    let subject = kr_worker::broker::subject(worker.session_id, instance);

    let snapshot: EventsSnapshotResult = connection
        .read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id: worker.session_id,
                agent_resources_from: Nullable::null(),
            },
        )
        .await
        .expect("the snapshot is read")
        .to_typed()
        .expect("decodes");
    let found: Vec<_> = snapshot
        .agent_instances
        .instances
        .iter()
        .map(|found| found.application_instance_id)
        .collect();
    assert_eq!(found, vec![instance]);

    let capabilities: AgentCapabilitiesResult = connection
        .read(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams { subject },
        )
        .await
        .expect("the capabilities are read")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        capabilities.binding.binding_revision,
        AgentBindingRevision::new(1)
    );
    let conversation: AgentSnapshotResult = connection
        .read(
            Method::AgentSnapshot,
            &AgentSnapshotParams {
                subject,
                from_node: Nullable::null(),
            },
        )
        .await
        .expect("the conversation is read")
        .to_typed()
        .expect("decodes");
    assert_eq!(conversation.entries.len(), 1);

    let answer = connection
        .mutate(
            Method::AgentPromptSubmit,
            ActionId::new(kr_ipc::new_uuid()),
            target(&adopted, worker, instance),
            &AgentPromptParams {
                target: AgentMutationTarget {
                    subject,
                    binding_revision: AgentBindingRevision::new(1),
                },
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new("run the tests").expect("a prompt")),
            },
        )
        .await
        .expect("the prompt is admitted");
    let result: kr_protocol::agent::AgentMutationResult =
        answer.to_typed().expect("the prompt is answered");
    assert_eq!(
        result.provenance,
        kr_protocol::broker::ActionProvenance::UpstreamTypedRpc
    );
    assert_eq!(upstream.prompts(), vec!["run the tests".to_owned()]);

    connection.close();
    adopted.stop().await;
}

/// The host decides what a connection is opened with: an open reports the rights the host decided
/// it with, which the host's configured ceiling can leave smaller than the grant a pairing
/// proposed, and never a right the grant lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_open_reports_the_rights_the_host_decided_and_not_the_proposal() {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.ceilings.grant_rights = Nullable::some(
        [ActionRight::SessionView, ActionRight::AgentPrompt]
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect(),
    );
    let adopted = Adopted::start_with_document(1, &document).await;
    let session_id = adopted.workers[0].session_id;
    let (device, record) = viewer(
        &adopted,
        &[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::TerminalInput,
        ],
    )
    .await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;

    let standing = in_force(
        open(&connection, Some(session_id), None)
            .await
            .expect("the pairing opens the session"),
    );
    assert_eq!(standing.via, OpenedVia::Pairing);
    assert_eq!(
        standing.actions,
        sorted(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
        "the host's ceiling took terminal.input away"
    );
    assert!(standing.live);
    assert_eq!(
        standing.ends_at_ms,
        Some(expiry_of(&record.grant)),
        "the end is the pairing's own"
    );

    connection.close();
    adopted.stop().await;
}

/// A share opens under the rights its role carries, and a null grant never becomes a share: a
/// device whose pairing admits no session has nothing to open without naming the share.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_share_opens_as_named_and_is_never_chosen_for_the_device() {
    let adopted = Adopted::start(1).await;
    let session_id = adopted.workers[0].session_id;
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let grant = share(
        &adopted.host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;

    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    // The pairing admits no session, and the one share that does is not chosen on its behalf.
    assert_eq!(
        code(open(&connection, Some(session_id), None).await),
        ErrorCode::PermissionDenied
    );
    connection.close();

    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    let standing = in_force(
        open(&connection, Some(session_id), Some(grant.grant_id))
            .await
            .expect("the share opens"),
    );
    let carried: Vec<ActionRight> = grant.actions.iter().copied().collect();
    assert_eq!(standing.via, OpenedVia::Share);
    assert_eq!(standing.actions, sorted(&carried));
    assert!(!standing.live, "a plain share carries no live screen");
    assert_eq!(
        standing.ends_at_ms,
        Some(expiry_of(&grant)),
        "the share ends before the pairing it is held through"
    );
    // The same share, held through a pairing that ends sooner, is scheduled to end with the
    // pairing.
    let mut short = proposal(&[ActionRight::SessionView]);
    short.session_selector = kr_protocol::grant::SessionSelector::None;
    short.expiry = kr_protocol::grant::GrantExpiry::At {
        expires_at_ms: TimestampMs::new(kr_ipc::now_ms().get() + 600_000),
    };
    let sooner = Device::create().await;
    let sooner_record = pair_with(&adopted.host, &sooner, &adopted.owner, short).await;
    let held = share(
        &adopted.host,
        session_id,
        &sooner,
        &sooner_record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    assert!(expiry_of(&held) > expiry_of(&sooner_record.grant));
    let through_it = RawDevice::connect(&adopted.host, &sooner, &sooner_record).await;
    let standing = in_force(
        open(&through_it, Some(session_id), Some(held.grant_id))
            .await
            .expect("the share opens"),
    );
    assert_eq!(standing.ends_at_ms, Some(expiry_of(&sooner_record.grant)));
    through_it.close();
    connection.close();
    adopted.stop().await;
}

/// A share without the live view is served the agent and refused the screen. The conversation is
/// found through `agent.instances`, which carries none of the screen; the snapshot that carries
/// the screen's state is refused to the same grant, and served when the share includes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_share_without_the_live_view_finds_its_agent_and_not_the_screen() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let instance = worker.register_agent(Arc::new(Upstream::default()));
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let dark = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    let lit = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection {
            include_live_screen: true,
            ..RoleSelection::plain(SessionRole::Viewer)
        },
    )
    .await;
    let snapshot = EventsSnapshotParams {
        session_id: worker.session_id,
        agent_resources_from: Nullable::null(),
    };
    let instances = AgentInstancesParams {
        session_id: worker.session_id,
        agent_resources_from: Nullable::null(),
    };

    let without = RawDevice::connect(&adopted.host, &device, &record).await;
    open(&without, Some(worker.session_id), Some(dark.grant_id))
        .await
        .expect("the share opens");
    assert_eq!(
        code(without.read(Method::EventsSnapshot, &snapshot).await),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        code(attach(&adopted, &without, worker.session_id).await),
        ErrorCode::PermissionDenied,
        "and cannot attach to a screen it does not include"
    );
    let found: AgentInstancesResult = without
        .read(Method::AgentInstances, &instances)
        .await
        .expect("the agents are read without the screen")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        found
            .agent_instances
            .instances
            .iter()
            .map(|found| found.application_instance_id)
            .collect::<Vec<_>>(),
        vec![instance]
    );
    without.close();

    let with = RawDevice::connect(&adopted.host, &device, &record).await;
    let standing = in_force(
        open(&with, Some(worker.session_id), Some(lit.grant_id))
            .await
            .expect("the share opens"),
    );
    assert!(standing.live);
    attach(&adopted, &with, worker.session_id)
        .await
        .expect("a share that includes the live screen attaches");
    let drawn: EventsSnapshotResult = with
        .read(Method::EventsSnapshot, &snapshot)
        .await
        .expect("the snapshot is read with the screen")
        .to_typed()
        .expect("decodes");
    assert_eq!(drawn.agent_instances.instances.len(), 1);
    with.close();
    adopted.stop().await;
}

/// A share's end ends its own connection and no other: two shares of one session on two
/// connections, one revoked, the other still served, and the connection opened for the host
/// untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_shares_end_ends_only_the_connection_opened_under_it() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let first = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    let second = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;

    let host_scoped = RawDevice::connect(&adopted.host, &device, &record).await;
    in_force(
        open(&host_scoped, None, None)
            .await
            .expect("the host opens"),
    );
    let under_first = net_support::connect(&adopted.host, &device, &record).await;
    under_first
        .read::<_, SessionOpenResult>(
            Method::SessionOpen,
            &SessionOpenParams {
                session_id: Nullable::some(worker.session_id),
                grant_id: Nullable::some(first.grant_id),
            },
        )
        .await
        .expect("the first share opens");
    let under_second = RawDevice::connect(&adopted.host, &device, &record).await;
    open(
        &under_second,
        Some(worker.session_id),
        Some(second.grant_id),
    )
    .await
    .expect("the second share opens");
    worker.ask("both");
    let read = questions(worker.session_id);
    let listed: QuestionReadResult = under_first
        .read(Method::QuestionRead, &read)
        .await
        .expect("the first share reads the question");
    assert_eq!(listed.questions.len(), 1);
    let listed: QuestionReadResult = under_second
        .read(Method::QuestionRead, &read)
        .await
        .expect("the second share reads the question")
        .to_typed()
        .expect("decodes");
    assert_eq!(listed.questions.len(), 1);

    revoke(&adopted.host, first.grant_id).await;

    // The first connection is withdrawn by the host.
    assert!(
        tokio::time::timeout(PATIENCE, under_first.closed())
            .await
            .is_ok(),
        "the revoked share's connection is withdrawn"
    );

    let listed: QuestionReadResult = under_second
        .read(Method::QuestionRead, &read)
        .await
        .expect("the other share is served")
        .to_typed()
        .expect("decodes");
    assert_eq!(listed.questions.len(), 1);
    let listed: SessionListResult = host_scoped
        .read(Method::SessionList, &listing())
        .await
        .expect("the host-scoped connection is served")
        .to_typed()
        .expect("decodes");
    assert!(
        listed.sessions.is_empty(),
        "a device whose pairing admits no session is listed none"
    );

    under_second.close();
    host_scoped.close();
    adopted.stop().await;
}

/// A share that is over is an answer, and nothing else is: a revoked share is told as revoked, one
/// that ran out as expired, and a grant the device does not hold is refused as any other request
/// is, without a word about whether it exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_only_a_proven_end_is_told_as_an_end() {
    let wall = net_support::MovedWall::new();
    let adopted = Adopted::start_on_clocks(1, wall.clocks()).await;
    let session_id = adopted.workers[0].session_id;
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let revoked = share(
        &adopted.host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    revoke(&adopted.host, revoked.grant_id).await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    assert!(matches!(
        open(&connection, Some(session_id), Some(revoked.grant_id))
            .await
            .expect("an answer"),
        SessionOpenResult::Ended {
            reason: ShareEnd::Revoked
        }
    ));
    connection.close();

    // A share offered and never redeemed is not held, and is not an end, even when it has been
    // withdrawn: the device never held it.
    let (idle, idle_record) = recipient(&adopted.host, &adopted.owner).await;
    let offered = offer(
        &adopted.host,
        session_id,
        &idle_record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    revoke(&adopted.host, offered.grant.grant_id).await;
    let connection = RawDevice::connect(&adopted.host, &idle, &idle_record).await;
    assert_eq!(
        code(open(&connection, Some(session_id), Some(offered.grant.grant_id)).await),
        ErrorCode::PermissionDenied
    );
    connection.close();

    // Another device's share, withdrawn, and a grant nobody issued, read alike.
    let (other, other_record) = recipient(&adopted.host, &adopted.owner).await;
    let theirs = share(
        &adopted.host,
        session_id,
        &other,
        &other_record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    revoke(&adopted.host, theirs.grant_id).await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    assert_eq!(
        code(open(&connection, Some(session_id), Some(theirs.grant_id)).await),
        ErrorCode::PermissionDenied,
        "a revoked share of another device is not this device's to be told of"
    );
    assert_eq!(
        code(
            open(
                &connection,
                Some(session_id),
                Some(GrantId::new(kr_ipc::new_uuid()))
            )
            .await
        ),
        ErrorCode::PermissionDenied
    );
    connection.close();

    // A share the clock has run out is told as expired once the end is on record.
    let expiring = share(
        &adopted.host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    wall.advance(Duration::from_secs(2 * 60 * 60));
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    assert!(
        matches!(
            open(&connection, Some(session_id), Some(expiring.grant_id))
                .await
                .expect("an answer"),
            SessionOpenResult::Ended {
                reason: ShareEnd::Expired
            }
        ),
        "a share past its end is told as expired once the end is on record"
    );
    connection.close();
    adopted.stop().await;
}

/// The host's configuration can take a right away from a share, and an open under it is then
/// refused as a missing right is: nothing about the share has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_right_the_configuration_removed_is_a_refusal_and_not_an_end() {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.ceilings.grant_rights = Nullable::some(
        [ActionRight::AgentPrompt]
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect(),
    );
    let adopted = Adopted::start_with_document(1, &document).await;
    let session_id = adopted.workers[0].session_id;
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let grant = share(
        &adopted.host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    assert_eq!(
        code(open(&connection, Some(session_id), Some(grant.grant_id)).await),
        ErrorCode::PermissionDenied
    );
    connection.close();
    adopted.stop().await;
}

/// A connection opened for one session serves that session under that grant and nothing else,
/// and the host refuses the rest before it decides anything: another session, a read that omits
/// the session an action belongs to, and a second open for something else.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_opened_connection_serves_its_session_and_grant_alone() {
    let adopted = Adopted::start(2).await;
    let (first, second) = (&adopted.workers[0], &adopted.workers[1]);
    first.ask("one");
    second.ask("two");
    let upstream = Arc::new(Upstream::default());
    let instance = first.register_agent(Arc::clone(&upstream));
    let (device, record) = viewer(
        &adopted,
        &[
            ActionRight::SessionView,
            ActionRight::QuestionRespond,
            ActionRight::AgentPrompt,
        ],
    )
    .await;

    // On a connection nothing has opened, the second session cannot be read after the first:
    // one connection serves one session.
    let unopened = RawDevice::connect(&adopted.host, &device, &record).await;
    unopened
        .read(Method::QuestionRead, &questions(first.session_id))
        .await
        .expect("the first session is read");
    assert_eq!(
        code(
            unopened
                .read(Method::QuestionRead, &questions(second.session_id))
                .await
        ),
        ErrorCode::InvalidArgument
    );
    unopened.close();

    // Opened for each, one connection serves each.
    let for_first = RawDevice::connect(&adopted.host, &device, &record).await;
    let for_second = RawDevice::connect(&adopted.host, &device, &record).await;
    open(&for_first, Some(first.session_id), None)
        .await
        .expect("opened for the first");
    open(&for_second, Some(second.session_id), None)
        .await
        .expect("opened for the second");
    for (connection, worker) in [(&for_first, first), (&for_second, second)] {
        let listed: QuestionReadResult = connection
            .read(Method::QuestionRead, &questions(worker.session_id))
            .await
            .expect("each session is served on its own connection")
            .to_typed()
            .expect("decodes");
        assert_eq!(listed.questions.len(), 1);
    }

    // An action performed on the first session is read, by its identifier alone, on the
    // connection opened for it, and is not read on the one opened for the second.
    let subject = kr_worker::broker::subject(first.session_id, instance);
    let action = ActionId::new(kr_ipc::new_uuid());
    for_first
        .mutate(
            Method::AgentPromptSubmit,
            action,
            target(&adopted, first, instance),
            &AgentPromptParams {
                target: AgentMutationTarget {
                    subject,
                    binding_revision: AgentBindingRevision::new(1),
                },
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new("once").expect("a prompt")),
            },
        )
        .await
        .expect("the prompt is performed");
    let by_identifier = kr_protocol::receipt::ActionReadParams {
        action_id: action,
        session_id: None,
    };
    for_first
        .read(Method::ActionRead, &by_identifier)
        .await
        .expect("the connection opened for the session reads its action");
    assert_eq!(
        code(for_second.read(Method::ActionRead, &by_identifier).await),
        ErrorCode::InvalidArgument
    );

    // Another session, by a worker-bound read and by a daemon-served one, is refused.
    assert_eq!(
        code(
            for_first
                .read(Method::QuestionRead, &questions(second.session_id))
                .await
        ),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(
            for_first
                .read(
                    Method::SessionRead,
                    &SessionReadParams {
                        session_id: second.session_id
                    }
                )
                .await
        ),
        ErrorCode::InvalidArgument
    );

    // The same open again is safe; an open for something else is refused.
    open(&for_first, Some(first.session_id), None)
        .await
        .expect("the same open again");
    assert_eq!(
        code(open(&for_first, Some(second.session_id), None).await),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(open(&for_first, None, None).await),
        ErrorCode::InvalidArgument
    );
    // A grant is named with the session it is for.
    let alone = RawDevice::connect(&adopted.host, &device, &record).await;
    assert_eq!(
        code(open(&alone, None, Some(GrantId::new(kr_ipc::new_uuid()))).await),
        ErrorCode::InvalidArgument
    );
    alone.close();
    for_first.close();
    for_second.close();
    adopted.stop().await;
}

/// A connection opened for the host serves the host's own reads and no worker: a session the
/// pairing admits is listed and read, a session only a share admits is not read, every route to a
/// worker is refused by kind, and a close sent there by mistake closes nothing. A guest whose
/// pairing holds no action opens the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_host_scope_serves_the_hosts_reads_and_no_worker() {
    let adopted = Adopted::start(2).await;
    let (admitted, shared) = (&adopted.workers[0], &adopted.workers[1]);
    admitted.ask("admitted");
    shared.ask("shared");

    // A pairing that admits one session, and a share of the other.
    let device = Device::create().await;
    let mut grant = proposal(&[
        ActionRight::SessionView,
        ActionRight::SessionClose,
        ActionRight::QuestionRespond,
    ]);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    grant.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [admitted.session_id].into_iter().collect(),
    };
    let record = pair_with(&adopted.host, &device, &adopted.owner, grant).await;
    let held = share(
        &adopted.host,
        shared.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;

    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    let standing = in_force(open(&connection, None, None).await.expect("the host opens"));
    assert_eq!(standing.via, OpenedVia::Pairing);

    let listed: SessionListResult = connection
        .read(Method::SessionList, &listing())
        .await
        .expect("the host's list is served")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        listed
            .sessions
            .iter()
            .map(|session| session.session_id)
            .collect::<Vec<_>>(),
        vec![admitted.session_id]
    );
    connection
        .read(
            Method::SessionRead,
            &SessionReadParams {
                session_id: admitted.session_id,
            },
        )
        .await
        .expect("a session the pairing admits is read");
    // The other session is the share's, and the host scope decides nothing under a share.
    assert_eq!(
        code(
            connection
                .read(
                    Method::SessionRead,
                    &SessionReadParams {
                        session_id: shared.session_id
                    }
                )
                .await
        ),
        ErrorCode::InvalidArgument
    );

    // Every route to a worker is refused by kind: the worker-bound read of each session, and a
    // close, which opens a link of its own.
    for worker in [admitted, shared] {
        assert_eq!(
            code(
                connection
                    .read(Method::QuestionRead, &questions(worker.session_id))
                    .await
            ),
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(
        code(
            connection
                .mutate(
                    Method::SessionClose,
                    ActionId::new(kr_ipc::new_uuid()),
                    on_the_session(&adopted.host, admitted.session_id),
                    &SessionCloseParams {
                        session_id: admitted.session_id
                    },
                )
                .await
        ),
        ErrorCode::InvalidArgument
    );
    // Nothing was closed, and the connection is still served.
    let read: kr_protocol::session::SessionReadResult = connection
        .read(
            Method::SessionRead,
            &SessionReadParams {
                session_id: admitted.session_id,
            },
        )
        .await
        .expect("the host scope stands")
        .to_typed()
        .expect("decodes");
    assert_eq!(read.session.state, kr_protocol::session::SessionState::Live);

    // The share this connection was refused a read under ends. A connection that is not opened
    // for anything reads under it as the host has always let it, and is ended with it; the host
    // scope decided nothing under it, so it stands.
    let unopened = net_support::connect(&adopted.host, &device, &record).await;
    unopened
        .read::<_, kr_protocol::session::SessionReadResult>(
            Method::SessionRead,
            &SessionReadParams {
                session_id: shared.session_id,
            },
        )
        .await
        .expect("a connection nothing has opened reads under the share");
    revoke(&adopted.host, held.grant_id).await;
    assert!(
        tokio::time::timeout(PATIENCE, unopened.closed())
            .await
            .is_ok(),
        "the connection that read under the share ends with it"
    );
    connection
        .read(Method::SessionList, &listing())
        .await
        .expect("the host scope stands after the share ended");
    connection.close();

    // A guest pairing holds no action, and the host scope needs none.
    let guest = Device::create().await;
    let guest_record = pair_with(&adopted.host, &guest, &adopted.owner, proposal(&[])).await;
    let connection = RawDevice::connect(&adopted.host, &guest, &guest_record).await;
    let standing = in_force(open(&connection, None, None).await.expect("the host opens"));
    assert_eq!(standing.via, OpenedVia::Pairing);
    assert!(standing.actions.is_empty());
    connection.close();
    adopted.stop().await;
}

/// Sends a revocation of `grant_id` on `connection`, as the person at the device would.
async fn revoke_on(
    host: &net_support::Host,
    connection: &RawDevice,
    grant_id: GrantId,
) -> Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
    connection
        .mutate(
            Method::GrantRevoke,
            ActionId::new(kr_ipc::new_uuid()),
            net_support::on_the_host(host),
            &kr_protocol::sharing::GrantRevokeParams { grant_id },
        )
        .await
}

/// A connection scoped to one grant decides nothing under another: a revocation acts under the
/// share its grant was delegated from, and is served only on the connection scoped to that share.
/// Scoped to the host, to the pairing or to a different share of the same device, it is refused
/// and records nothing: when that other share is withdrawn afterwards, the connection that was
/// refused stands. Scoped to the share the grant was delegated from, it is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_revocation_is_served_only_on_the_connection_scoped_to_its_share() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let (colleague, colleague_record) = recipient(&adopted.host, &adopted.owner).await;
    let (own, issuing) = owned_by(&adopted.host, worker.session_id, &device, &record).await;
    let (other, _) = owned_by(&adopted.host, worker.session_id, &device, &record).await;
    let (delegated, _) = delegated(
        &adopted.host,
        worker.session_id,
        &other.grant,
        &issuing,
        &colleague,
        &colleague_record,
    )
    .await;
    let grant_id = delegated.grant_id;
    issuing.close();

    // The host, the pairing's own session and the device's other share each refuse it.
    let host_scoped = RawDevice::connect(&adopted.host, &device, &record).await;
    open(&host_scoped, None, None)
        .await
        .expect("the host opens");
    assert_eq!(
        code(revoke_on(&adopted.host, &host_scoped, grant_id).await),
        ErrorCode::InvalidArgument
    );
    let under_own = RawDevice::connect(&adopted.host, &device, &record).await;
    open(
        &under_own,
        Some(worker.session_id),
        Some(own.grant.grant_id),
    )
    .await
    .expect("the device's other share opens");
    assert_eq!(
        code(revoke_on(&adopted.host, &under_own, grant_id).await),
        ErrorCode::PermissionDenied
    );
    assert!(
        net_support::holds(&adopted.host, grant_id),
        "the delegated grant stands"
    );

    // The share it was delegated from serves it.
    let under_other = RawDevice::connect(&adopted.host, &device, &record).await;
    open(
        &under_other,
        Some(worker.session_id),
        Some(other.grant.grant_id),
    )
    .await
    .expect("the share it was delegated from opens");
    revoke_on(&adopted.host, &under_other, grant_id)
        .await
        .expect("the share it was delegated from revokes it");
    assert!(!net_support::holds(&adopted.host, grant_id));

    // The refusals recorded nothing: the share they were refused under is withdrawn, and the
    // connections that were refused stand while the one opened under it goes.
    revoke(&adopted.host, other.grant.grant_id).await;
    under_own
        .read(Method::QuestionRead, &questions(worker.session_id))
        .await
        .expect("the connection opened for the other share stands");
    host_scoped
        .read(Method::SessionList, &listing())
        .await
        .expect("the host-scoped connection stands");
    under_other.close();
    under_own.close();
    host_scoped.close();
    adopted.stop().await;
}

/// The same refusal on a connection scoped to the device's pairing: it holds no share, so a
/// revocation that acts under one is not served on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_connection_scoped_to_the_pairing_revokes_nothing_under_a_share() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let (holder, holder_record) = viewer(&adopted, &[ActionRight::SessionView]).await;
    let (colleague, colleague_record) = recipient(&adopted.host, &adopted.owner).await;
    let (shared, issuing) =
        owned_by(&adopted.host, worker.session_id, &holder, &holder_record).await;
    let (delegated, _) = delegated(
        &adopted.host,
        worker.session_id,
        &shared.grant,
        &issuing,
        &colleague,
        &colleague_record,
    )
    .await;
    issuing.close();

    let pairing = RawDevice::connect(&adopted.host, &holder, &holder_record).await;
    let standing = in_force(
        open(&pairing, Some(worker.session_id), None)
            .await
            .expect("the pairing opens the session"),
    );
    assert_eq!(standing.via, OpenedVia::Pairing);
    assert_eq!(
        code(revoke_on(&adopted.host, &pairing, delegated.grant_id).await),
        ErrorCode::PermissionDenied
    );
    assert!(net_support::holds(&adopted.host, delegated.grant_id));
    pairing.close();
    adopted.stop().await;
}

/// A connection that already acts for something is not opened for another thing. One that decided
/// a request under a share, with no worker link, is not opened for the host or for another share;
/// one that holds a link under the pairing is not opened for the host. The same session under
/// another grant is refused on a connection opened for it. Each has its control: a fresh
/// connection opens the same thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_connection_that_already_acts_for_something_is_not_opened_for_another_thing()
{
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");

    // A share noted on a connection that holds no link: a daemon-served read decided under it.
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let first = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    let noted = net_support::connect(&adopted.host, &device, &record).await;
    noted
        .read::<_, kr_protocol::session::SessionReadResult>(
            Method::SessionRead,
            &SessionReadParams {
                session_id: worker.session_id,
            },
        )
        .await
        .expect("a connection nothing has opened reads under the one share that admits it");
    let second = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    for (session, grant) in [
        (Some(worker.session_id), Some(second.grant_id)),
        (None, None),
    ] {
        let refused = noted
            .read::<_, SessionOpenResult>(
                Method::SessionOpen,
                &SessionOpenParams {
                    session_id: Nullable(session),
                    grant_id: Nullable(grant),
                },
            )
            .await
            .expect_err("a connection that acts under a share is not opened for something else");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{refused}");
    }
    noted.close();
    let fresh = RawDevice::connect(&adopted.host, &device, &record).await;
    open(&fresh, Some(worker.session_id), Some(second.grant_id))
        .await
        .expect("the control: a fresh connection opens the same share");
    // On it, the same session under another grant is refused, and the same grant again is safe.
    assert_eq!(
        code(open(&fresh, Some(worker.session_id), Some(first.grant_id)).await),
        ErrorCode::PermissionDenied
    );
    open(&fresh, Some(worker.session_id), Some(second.grant_id))
        .await
        .expect("the same open again");
    fresh.close();

    // A link under the pairing: a worker-bound read opens it.
    let (holder, holder_record) = viewer(
        &adopted,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
    )
    .await;
    let linked = RawDevice::connect(&adopted.host, &holder, &holder_record).await;
    linked
        .read(Method::QuestionRead, &questions(worker.session_id))
        .await
        .expect("the read opens the link");
    assert_eq!(
        code(open(&linked, None, None).await),
        ErrorCode::InvalidArgument
    );
    open(&linked, Some(worker.session_id), None)
        .await
        .expect("it may be opened for the session it already serves");
    linked.close();
    let fresh = RawDevice::connect(&adopted.host, &holder, &holder_record).await;
    open(&fresh, None, None)
        .await
        .expect("the control: a fresh connection opens the host");
    fresh.close();
    adopted.stop().await;
}

/// A repeated action reaches a worker through a link the host scope does not have: it is refused
/// by kind, the worker is not asked again, and what it did once stays done once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_repeat_on_the_host_scope_reaches_no_worker() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let (device, record) = viewer(
        &adopted,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let subject = kr_worker::broker::subject(worker.session_id, instance);
    let prompt = AgentPromptParams {
        target: AgentMutationTarget {
            subject,
            binding_revision: AgentBindingRevision::new(1),
        },
        draft_id: Nullable::null(),
        text: Nullable::some(PromptText::new("once").expect("a prompt")),
    };
    let action = ActionId::new(kr_ipc::new_uuid());

    // The session's own connection performs it.
    let session = RawDevice::connect(&adopted.host, &device, &record).await;
    let window = session.action_window_id();
    open(&session, Some(worker.session_id), None)
        .await
        .expect("opened for the session");
    session
        .mutate(
            Method::AgentPromptSubmit,
            action,
            target(&adopted, worker, instance),
            &prompt,
        )
        .await
        .expect("the prompt is performed");
    session.close();
    assert_eq!(upstream.prompts(), vec!["once".to_owned()]);

    // The host-scoped connection, repeating the same action, reaches no worker.
    let host_scoped = RawDevice::connect(&adopted.host, &device, &record).await;
    open(&host_scoped, None, None)
        .await
        .expect("opened for the host");
    assert_eq!(
        code(
            host_scoped
                .mutate_in(
                    window,
                    Method::AgentPromptSubmit,
                    action,
                    target(&adopted, worker, instance),
                    &prompt,
                )
                .await
        ),
        ErrorCode::InvalidArgument
    );
    assert_eq!(upstream.prompts(), vec!["once".to_owned()]);
    host_scoped.close();
    adopted.stop().await;
}
