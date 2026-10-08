//! The grant a paired device acts under when it holds a share beside its pairing grant.
//!
//! A session shared with a device is a grant issued to it and activated when it redeems the
//! invitation. The device's pairing grant is the condition for it to connect at all, and a request
//! is decided under one grant: the one a mutation names, else the pairing grant when its selectors
//! admit the session, else the one share that does. These tests play the session's worker and read
//! what reaches it, which is the grant the host says it decided under: its identity in the actor
//! envelope, its rights, and the history scope its answers are held to.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-25.10 | every `kr_req_25_10_` test here |

use kr_protocol::error::ErrorCode;
use kr_protocol::grant::{Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::{ActionId, GrantId, QuestionRevision, RequestId, SessionEpoch};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::question::{
    QuestionAnswer, QuestionAnswerParams, QuestionReadParams, QuestionState,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs};

use super::a_share_that_names_a_current_decision::{
    Holding, device_read, holding_grant, holds_question_reads, question, question_id, refused,
    serving, world,
};
use crate::grants::GrantRecord;
use crate::service::a_close_a_worker_never_answers as fake;

/// A device paired under a grant that sees every session and can only view, so a share is how it
/// comes to hold anything more.
fn paired(
    controller: &crate::service::Controller,
    byte: u8,
    sessions: SessionSelector,
) -> crate::service::net::devices::DeviceRecord {
    let (mut grant, _) = crate::service::net::tests::granted(
        GrantExpiry::Never,
        controller.policy().authority_revision(),
    );
    grant.session_selector = sessions;
    holding_grant(controller, byte, grant)
}

/// A grant issued to `device` over `session_id`, active, carrying `actions` and naming `named`.
fn share(
    world: &fake::Silent,
    device: &crate::service::net::devices::DeviceRecord,
    actions: &[ActionRight],
    named: &[kr_protocol::ids::QuestionId],
    activated: bool,
    expiry: GrantExpiry,
) -> Grant {
    share_with(world, device, actions, named, activated, expiry, false)
}

/// As [`share`], for a share whose issuer was shown the session's live screen when
/// `includes_the_screen` says so.
fn share_with(
    world: &fake::Silent,
    device: &crate::service::net::devices::DeviceRecord,
    actions: &[ActionRight],
    named: &[kr_protocol::ids::QuestionId],
    activated: bool,
    expiry: GrantExpiry,
    includes_the_screen: bool,
) -> Grant {
    let (mut grant, _) =
        crate::service::net::tests::granted(expiry, world.controller.policy().authority_revision());
    grant.issuer_device_id = world.controller.sharing().host_device_id();
    grant.recipient_device_id = device.device_id;
    grant.session_selector = SessionSelector::These {
        session_ids: [world.session_id].into_iter().collect(),
    };
    grant.actions = actions.iter().copied().collect();
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(1));
    grant.history.include_live_screen = includes_the_screen;
    grant.history.named_questions = named.iter().copied().collect();
    world
        .controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: Some(world.session_id),
                issued_at_ms: 1,
                activated_at_ms: activated.then_some(2),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the share is written");
    grant
}

/// The session a played worker's question belongs to before its test has started the worker; the
/// test gives each question the real one once it exists.
fn unplaced() -> kr_protocol::ids::SessionId {
    kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([0; 16]))
}

/// What a worker of this build states: it reads a scope, holds a question read and the result of a
/// mutation to it.
fn holds_results() -> CanonicalSet<kr_protocol::ids::CapabilityId> {
    [
        kr_protocol::local::FORWARDED_HISTORY_SCOPE,
        kr_protocol::local::FORWARDED_QUESTION_SCOPE,
        kr_protocol::local::FORWARDED_RESULT_SCOPE,
    ]
    .into_iter()
    .map(|capability| {
        kr_protocol::ids::CapabilityId::new(capability).expect("a capability identifier")
    })
    .collect()
}

/// What a worker of this build states when it also draws an attachment under a share the screen
/// its issuer was shown.
fn narrows_to_previewed_screens() -> CanonicalSet<kr_protocol::ids::CapabilityId> {
    [
        kr_protocol::local::FORWARDED_HISTORY_SCOPE,
        kr_protocol::local::FORWARDED_QUESTION_SCOPE,
        kr_protocol::local::FORWARDED_RESULT_SCOPE,
        kr_protocol::local::FORWARDED_PREVIEWED_SCREEN,
    ]
    .into_iter()
    .map(|capability| {
        kr_protocol::ids::CapabilityId::new(capability).expect("a capability identifier")
    })
    .collect()
}

fn questions_of(world: &fake::Silent) -> QuestionReadParams {
    QuestionReadParams {
        session_id: world.session_id,
        question_id: Nullable::null(),
        include_resolved: true,
    }
}

/// An answer to `question`, acting under `grant` when it names one.
fn answering(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    byte: u8,
    grant: Option<GrantId>,
) -> kr_protocol::envelope::MutationRequest {
    let window = connection
        .windows
        .issue(connection.connection_id, world.controller.boot_epoch)
        .expect("a window");
    kr_protocol::envelope::MutationRequest {
        request_id: RequestId::new(u64::from(byte)),
        method: Method::QuestionAnswer.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
        grant_id: Nullable(grant),
        target: kr_protocol::envelope::ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(world.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: kr_protocol::envelope::ParamsValue::empty(),
        action_window_id: window.action_window_id,
        requested_ttl_ms: DurationMs::new(30_000),
        params: kr_protocol::envelope::ParamsValue::from_typed(&QuestionAnswerParams {
            session_id: world.session_id,
            question_id: question_id(0x11),
            expected_revision: QuestionRevision::new(2),
            answer: QuestionAnswer::Decision { decided: true },
        })
        .expect("encodes"),
    }
}

/// An attach of a terminal's observer, acting under `grant` when it names one.
fn attaching(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    byte: u8,
    grant: Option<GrantId>,
) -> kr_protocol::envelope::MutationRequest {
    let mut attach = answering(world, connection, byte, grant);
    attach.method = Method::SessionAttach.into();
    attach.params = kr_protocol::envelope::ParamsValue::from_typed(
        &kr_protocol::attachment::SessionAttachParams {
            session_id: world.session_id,
            mode: kr_protocol::attachment::AttachMode::Semantic,
            claim_geometry: false,
            dimensions: Nullable::null(),
            terminal_profile_id: Nullable::null(),
            requested: [kr_protocol::attachment::AttachmentCapability::ObserveTerminal]
                .into_iter()
                .collect(),
        },
    )
    .expect("encodes");
    attach
}

/// The refusal an answer carries.
fn refusal_of(answer: &kr_protocol::envelope::ControlFrame) -> &kr_protocol::error::ProtocolError {
    super::tests::error_of(answer)
}

/// KR-REQ-25.10: a device whose pairing grant reaches no session reads nothing of one until it
/// holds a share that admits it, and then reads under that share and under nothing else: the
/// worker is told the share's identity and held to the share's history scope. A share nobody
/// redeemed decides nothing, and one that was revoked decides nothing from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_device_reads_under_the_share_that_admits_a_session_its_pairing_grant_does_not()
 {
    let mut held = Holding::default();
    for byte in [0x11, 0x12] {
        held.questions.insert(
            question_id(byte),
            question(
                unplaced(),
                byte,
                QuestionState::Pending,
                3_000,
                "Run the tests?",
            ),
        );
    }
    let (world, holding) = world(held, holds_question_reads()).await;
    // The played worker holds the questions of the session it was started for.
    for question in holding.lock().expect("held").questions.values_mut() {
        question.session_id = world.session_id;
    }
    let device = paired(&world.controller, 21, SessionSelector::None);
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());
    let read =
        |request_id: u64| device_read(request_id, Method::QuestionRead, &questions_of(&world));

    // A control: with nothing shared, the pairing grant decides, and it admits no session.
    let nothing = refused(connection.read(&read(1)).await);
    assert_eq!(nothing.code, ErrorCode::PermissionDenied, "{nothing:?}");

    // A proposal nobody redeemed authorises nothing.
    let pending = share(
        &world,
        &device,
        &[ActionRight::SessionView],
        &[question_id(0x11)],
        false,
        GrantExpiry::Never,
    );
    let still_nothing = refused(connection.read(&read(2)).await);
    assert_eq!(still_nothing.code, ErrorCode::PermissionDenied);
    world
        .controller
        .sharing()
        .grants()
        .revoke(pending.grant_id, 3, || Ok(()))
        .expect("the proposal is withdrawn");

    // Redeemed, a share is what the device reads under.
    let held_share = share(
        &world,
        &device,
        &[ActionRight::SessionView],
        &[question_id(0x11)],
        true,
        GrantExpiry::Never,
    );
    let answered = connection.read(&read(3)).await;
    let kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
        outcome: kr_protocol::envelope::Outcome::Ok(_),
        ..
    }) = &answered
    else {
        panic!("the share admits the read: {answered:?}");
    };
    {
        let held = holding.lock().expect("held");
        let forwarded = held.forwarded.last().expect("the read reached the worker");
        assert_eq!(
            forwarded.actor.grant_id,
            Nullable::some(held_share.grant_id),
            "the worker is told which grant the read was decided under"
        );
        assert_eq!(
            forwarded.history,
            Some(held_share.history.clone()),
            "and holds its answer to that grant's scope"
        );
    }

    // Revoked, it decides nothing from the next request on, on the connection it was fixed on.
    world
        .controller
        .sharing()
        .grants()
        .revoke(held_share.grant_id, 4, || Ok(()))
        .expect("the share is revoked");
    let revoked = refused(connection.read(&read(4)).await);
    assert_eq!(revoked.code, ErrorCode::PermissionDenied, "{revoked:?}");
    world.serving.abort();
}

/// KR-REQ-25.10: a device that holds two shares for a session is asked which to act under; a
/// mutation that names one is decided under that one, and the connection then acts for the session
/// under it alone: a read that names nothing is decided under it, and a mutation that names the
/// other, or the pairing grant, is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_device_holding_two_shares_acts_under_the_one_it_names_and_only_that_one() {
    let mut held = Holding::default();
    held.questions.insert(
        question_id(0x11),
        question(
            unplaced(),
            0x11,
            QuestionState::Pending,
            3_000,
            "Run the tests?",
        ),
    );
    let (world, holding) = world(held, holds_results()).await;
    for question in holding.lock().expect("held").questions.values_mut() {
        question.session_id = world.session_id;
    }
    let device = paired(&world.controller, 22, SessionSelector::None);
    let first = share(
        &world,
        &device,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
        &[question_id(0x11)],
        true,
        GrantExpiry::Never,
    );
    let second = share(
        &world,
        &device,
        &[ActionRight::SessionView],
        &[],
        true,
        GrantExpiry::Never,
    );
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());
    let read =
        |request_id: u64| device_read(request_id, Method::QuestionRead, &questions_of(&world));

    // Nothing says which of the two a read is for.
    let asked = refused(connection.read(&read(1)).await);
    assert_eq!(asked.code, ErrorCode::PermissionDenied);
    assert!(asked.message.contains("name the one"), "{asked:?}");

    // A mutation naming the first is decided under it, and reaches the worker under it with the
    // rights it carries and the scope it holds.
    let answer = connection
        .mutate(&answering(&world, &connection, 31, Some(first.grant_id)))
        .await;
    drop(answer);
    {
        let held = holding.lock().expect("held");
        let forwarded = held
            .mutations
            .last()
            .expect("the mutation reached the worker");
        assert_eq!(forwarded.actor.grant_id, Nullable::some(first.grant_id));
        assert_eq!(forwarded.grant_rights, first.actions);
        assert_eq!(forwarded.history, Some(first.history.clone()));
    }

    // From then on the connection acts for the session under the first, whatever a request names.
    let answered = connection.read(&read(2)).await;
    assert!(
        matches!(
            &answered,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "{answered:?}"
    );
    assert_eq!(
        holding
            .lock()
            .expect("held")
            .forwarded
            .last()
            .expect("the read reached the worker")
            .actor
            .grant_id,
        Nullable::some(first.grant_id)
    );
    for other in [second.grant_id, device.grant.grant_id] {
        let elsewhere = connection
            .mutate(&answering(&world, &connection, 32, Some(other)))
            .await;
        let error = refusal_of(&elsewhere);
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
        assert!(
            error.message.contains("another grant"),
            "the refusal says why: {error:?}"
        );
    }
    world.serving.abort();
}

/// KR-REQ-25.10: a device that names a grant it does not hold is told what it is told of one that
/// does not exist: another device's share, a voice grant and an identifier nobody issued read the
/// same, so a refusal says nothing of what another device holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_grant_another_device_holds_reads_as_one_that_does_not_exist() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let device = paired(&world.controller, 23, SessionSelector::None);
    let other = paired(&world.controller, 24, SessionSelector::None);
    let theirs = share(
        &world,
        &other,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
        &[],
        true,
        GrantExpiry::Never,
    );
    let voice = share(
        &world,
        &device,
        &[ActionRight::VoiceUse, ActionRight::SessionView],
        &[],
        true,
        GrantExpiry::Never,
    );
    let own = share(
        &world,
        &device,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
        &[],
        true,
        GrantExpiry::Never,
    );
    let connection = super::RemoteConnection::for_test(&world.controller, device);
    // The control: the device's own share is held, so naming it is not refused as unheld.
    let held = connection.acting_for(Some(world.session_id), Some(own.grant_id));
    assert!(held.is_ok(), "the device's own share is held: {held:?}");
    let mut told = Vec::new();
    for named in [
        theirs.grant_id,
        voice.grant_id,
        GrantId::new(kr_ipc::new_uuid()),
    ] {
        let answer = connection
            .mutate(&answering(&world, &connection, 41, Some(named)))
            .await;
        let error = refusal_of(&answer);
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
        told.push(error.message.clone());
    }
    assert!(
        told.windows(2).all(|pair| pair[0] == pair[1]),
        "each was told the same: {told:?}"
    );
    world.serving.abort();
}

/// KR-REQ-25.10: a share that has run out refuses what it would decide, and writes nothing on the
/// device's record: the device is paired under a grant of its own, and is served under it
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_share_that_ran_out_does_not_end_the_devices_own_grant() {
    let mut held = Holding::default();
    held.questions.insert(
        question_id(0x11),
        question(
            unplaced(),
            0x11,
            QuestionState::Pending,
            3_000,
            "Run the tests?",
        ),
    );
    let (world, holding) = world(held, holds_question_reads()).await;
    for question in holding.lock().expect("held").questions.values_mut() {
        question.session_id = world.session_id;
    }
    let device = paired(&world.controller, 25, SessionSelector::None);
    // Written already run out: its expiry is long past.
    let expired = share(
        &world,
        &device,
        &[ActionRight::SessionView],
        &[question_id(0x11)],
        true,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5),
        },
    );
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());
    // Nothing selects a share that has run out for a request that names none, so the request names
    // it, which is the way a device would still be acting under one that ended while it did.
    let answer = connection
        .mutate(&answering(&world, &connection, 51, Some(expired.grant_id)))
        .await;
    let refusal = refusal_of(&answer);
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    assert!(refusal.message.contains("expired"), "{refusal:?}");
    assert!(
        connection.is_authorised().await,
        "the connection stands: the device's own grant is untouched"
    );
    let record = world
        .controller
        .devices()
        .record_for_device(device.device_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        record.expired_at_ms, None,
        "a share running out is not the device's grant running out"
    );
    // Its pairing grant still serves a request that names no session.
    let own = connection
        .read(&device_read(
            2,
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        ))
        .await;
    assert!(
        matches!(
            &own,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "{own:?}"
    );
    world.serving.abort();
}

/// KR-REQ-25.10: a share that runs out under a live subscription ends that subscription: the next
/// batch is not written, and the connection that carried it ends. It writes nothing on the device's
/// record, which is paired under a grant of its own, so the device is served under that grant on a
/// new connection straight away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_share_that_runs_out_under_a_subscription_ends_it_and_the_device_stays_paired()
 {
    use std::sync::atomic::Ordering;

    let (continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
    let holding = std::sync::Arc::new(std::sync::Mutex::new(Holding::default()));
    let world = fake::fake_world_on(
        Some(clocks),
        serving(std::sync::Arc::clone(&holding), holds_question_reads()),
    )
    .await;
    fake::acknowledged(&world.controller, world.session_id);
    let device = paired(&world.controller, 26, SessionSelector::None);
    let now = wall.load(Ordering::SeqCst);
    // The share includes the live screen, which is what a subscription needs, and ends a minute on.
    let (mut grant, _) = crate::service::net::tests::granted(
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now + 60_000),
        },
        world.controller.policy().authority_revision(),
    );
    grant.issuer_device_id = world.controller.sharing().host_device_id();
    grant.recipient_device_id = device.device_id;
    grant.session_selector = SessionSelector::These {
        session_ids: [world.session_id].into_iter().collect(),
    };
    grant.history.include_live_screen = true;
    world
        .controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: Some(world.session_id),
                issued_at_ms: now,
                activated_at_ms: Some(now),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the share is written");
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());

    // A forwarded read opens the connection's link to the session under the share.
    let opened = connection
        .read(&device_read(1, Method::QuestionRead, &questions_of(&world)))
        .await;
    assert!(
        matches!(
            &opened,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "{opened:?}"
    );
    let batch =
        kr_protocol::envelope::ControlFrame::Event(kr_protocol::envelope::ControlEvent::Keepalive);
    assert!(
        connection.relay(&batch).await,
        "a batch goes while the share holds"
    );

    // The share ends on both clocks.
    wall.store(now + 120_000, Ordering::SeqCst);
    continuous.advance(std::time::Duration::from_secs(120));
    // The serving loop ends the connection when a batch is not written.
    assert!(
        !connection.relay(&batch).await,
        "no batch goes once the share has run out"
    );
    let record = world
        .controller
        .devices()
        .record_for_device(device.device_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        record.expired_at_ms, None,
        "a share running out is not the device's grant running out"
    );

    // The device is served under its own grant on a new connection.
    let again = super::RemoteConnection::for_test(&world.controller, device);
    let listed = again
        .read(&device_read(
            2,
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        ))
        .await;
    assert!(
        matches!(
            &listed,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "{listed:?}"
    );
    world.serving.abort();
}

/// KR-REQ-25.10: a device whose pairing grant admits a session is decided under it for a request
/// that names no grant, even when it holds shares that admit the session as well. The shares are
/// not a reason to ask it to name one, and a mutation naming one is decided under that share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_the_pairing_grant_decides_what_names_no_grant_when_it_admits_the_session() {
    let mut held = Holding::default();
    held.questions.insert(
        question_id(0x11),
        question(
            unplaced(),
            0x11,
            QuestionState::Pending,
            3_000,
            "Run the tests?",
        ),
    );
    let (world, holding) = world(held, holds_results()).await;
    for question in holding.lock().expect("held").questions.values_mut() {
        question.session_id = world.session_id;
    }
    let device = paired(&world.controller, 27, SessionSelector::Any);
    for _ in 0..2 {
        share(
            &world,
            &device,
            &[ActionRight::SessionView, ActionRight::QuestionRespond],
            &[question_id(0x11)],
            true,
            GrantExpiry::Never,
        );
    }
    let connection = super::RemoteConnection::for_test(&world.controller, device.clone());
    let answered = connection
        .read(&device_read(1, Method::QuestionRead, &questions_of(&world)))
        .await;
    assert!(
        matches!(
            &answered,
            kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "two shares do not make a read that the pairing grant admits ask for a name: {answered:?}"
    );
    assert_eq!(
        holding
            .lock()
            .expect("held")
            .forwarded
            .last()
            .expect("the read reached the worker")
            .actor
            .grant_id,
        Nullable::some(device.grant.grant_id),
        "it was decided under the pairing grant"
    );
    world.serving.abort();
}

/// KR-REQ-25.10: an action that was decided under a share is read back under that share when it is
/// repeated on a connection that has not acted for the session yet. The pairing grant admits the
/// session and carries no right to look at it, so a read back under any grant but the share is
/// refused before it reaches the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_repeated_action_is_read_back_under_the_share_it_was_decided_under() {
    let (world, holding) = world(Holding::default(), holds_results()).await;
    let (mut pairing, _) = crate::service::net::tests::granted(
        GrantExpiry::Never,
        world.controller.policy().authority_revision(),
    );
    pairing.actions = CanonicalSet::new();
    let device = holding_grant(&world.controller, 28, pairing);
    let held_share = share(
        &world,
        &device,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
        &[],
        true,
        GrantExpiry::Never,
    );

    let first = super::RemoteConnection::for_test(&world.controller, device.clone());
    let request = answering(&world, &first, 33, Some(held_share.grant_id));
    drop(first.mutate(&request).await);
    assert!(
        holding.lock().expect("held").mutations.len() == 1,
        "the action reached the worker under the share"
    );

    // The same action again, on a connection that has acted for nothing.
    let second = super::RemoteConnection::for_test(&world.controller, device);
    drop(second.mutate(&request).await);
    let held = holding.lock().expect("held");
    let read_back = held
        .forwarded
        .iter()
        .find(|forwarded| forwarded.request.method == Method::ActionRead.into())
        .expect("the receipt was asked for at the worker");
    assert_eq!(
        read_back.actor.grant_id,
        Nullable::some(held_share.grant_id),
        "under the share the action was decided under"
    );
    drop(held);
    world.serving.abort();
}

/// KR-REQ-25.10: a share ends on the continuous clock whatever the wall clock says. The wall clock
/// is held where it was, a minute before the share's end, and the continuous clock moves past it:
/// the share that decided a request a moment ago refuses the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_share_ends_on_the_continuous_clock_whatever_the_wall_clock_says() {
    use std::sync::atomic::Ordering;

    let (continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
    let holding = std::sync::Arc::new(std::sync::Mutex::new(Holding::default()));
    let world = fake::fake_world_on(
        Some(clocks),
        serving(std::sync::Arc::clone(&holding), holds_question_reads()),
    )
    .await;
    fake::acknowledged(&world.controller, world.session_id);
    let device = paired(&world.controller, 29, SessionSelector::None);
    let now = wall.load(Ordering::SeqCst);
    let held_share = share(
        &world,
        &device,
        &[ActionRight::SessionView],
        &[],
        true,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now + 60_000),
        },
    );
    let connection = super::RemoteConnection::for_test(&world.controller, device);
    let ask = || {
        connection
            .acting_for(Some(world.session_id), Some(held_share.grant_id))
            .and_then(|acting| {
                connection.ask_under(
                    acting,
                    Some(world.session_id),
                    Method::QuestionRead.entry(),
                    false,
                )
            })
    };
    ask().expect("the share holds");

    continuous.advance(std::time::Duration::from_secs(120));
    assert_eq!(
        wall.load(Ordering::SeqCst),
        now,
        "the wall clock did not move"
    );
    let refused = ask().expect_err("the share has run out on the continuous clock");
    assert!(refused.message.contains("expired"), "{refused:?}");
    world.serving.abort();
}

/// Whether a connection's wait for a grant of its to end has finished, without waiting for it to.
async fn has_ended(ended: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>) -> bool {
    tokio::select! {
        biased;
        () = ended.as_mut() => true,
        () = std::future::ready(()) => false,
    }
}

/// KR-REQ-25.10: a connection is ended when a grant it stands on ends, on the clock that ends it
/// and nothing else, and not before. The share's two deadlines each end it alone, and so does the
/// end of the pairing grant that lets the device in; the controls move each clock to just before
/// the end and find the connection standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_connection_is_ended_by_the_clock_that_ends_a_grant_it_stands_on() {
    use std::sync::atomic::Ordering;

    /// Which grant ends, and on which clock.
    #[derive(Clone, Copy, Debug)]
    enum Ends {
        ShareOnTheContinuousClock,
        ShareInUtc,
        PairingGrantOnTheContinuousClock,
        PairingGrantInUtc,
    }

    for ends in [
        Ends::ShareOnTheContinuousClock,
        Ends::ShareInUtc,
        Ends::PairingGrantOnTheContinuousClock,
        Ends::PairingGrantInUtc,
    ] {
        let (continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
        let holding = std::sync::Arc::new(std::sync::Mutex::new(Holding::default()));
        let world = fake::fake_world_on(
            Some(clocks),
            serving(std::sync::Arc::clone(&holding), holds_question_reads()),
        )
        .await;
        fake::acknowledged(&world.controller, world.session_id);
        let now = wall.load(Ordering::SeqCst);
        let minute = |minutes: u64| GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now + minutes * 60_000),
        };
        let (mut pairing, _) = crate::service::net::tests::granted(
            if matches!(
                ends,
                Ends::PairingGrantOnTheContinuousClock | Ends::PairingGrantInUtc
            ) {
                minute(1)
            } else {
                minute(60)
            },
            world.controller.policy().authority_revision(),
        );
        pairing.session_selector = SessionSelector::None;
        let device = holding_grant(&world.controller, 30, pairing);
        let held_share = share(
            &world,
            &device,
            &[ActionRight::SessionView],
            &[],
            true,
            if matches!(ends, Ends::ShareOnTheContinuousClock | Ends::ShareInUtc) {
                minute(1)
            } else {
                minute(60)
            },
        );
        let connection = super::RemoteConnection::for_test(&world.controller, device);
        let acting = connection
            .acting_for(Some(world.session_id), Some(held_share.grant_id))
            .expect("the share is held");
        connection
            .fix(world.session_id, &acting)
            .expect("the connection acts under the share");

        let ended = connection.grant_ended();
        tokio::pin!(ended);
        assert!(
            !has_ended(&mut ended).await,
            "{ends:?}: nothing has ended yet"
        );

        // The control: a clock to just before the end, on the clock that ends it.
        match ends {
            Ends::ShareOnTheContinuousClock | Ends::PairingGrantOnTheContinuousClock => {
                continuous.advance(std::time::Duration::from_secs(59));
            }
            Ends::ShareInUtc | Ends::PairingGrantInUtc => {
                wall.store(now + 59_000, Ordering::SeqCst);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !has_ended(&mut ended).await,
            "{ends:?}: a grant a second short of its end has not ended"
        );

        // Then past it, on that clock alone.
        match ends {
            Ends::ShareOnTheContinuousClock | Ends::PairingGrantOnTheContinuousClock => {
                continuous.advance(std::time::Duration::from_secs(2));
            }
            Ends::ShareInUtc | Ends::PairingGrantInUtc => {
                wall.store(now + 61_000, Ordering::SeqCst);
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), &mut ended)
            .await
            .unwrap_or_else(|_| panic!("{ends:?}: the connection is ended when the grant is"));
        if matches!(ends, Ends::ShareOnTheContinuousClock) {
            // A share that ran out on the clock that cannot be wound back stays run out: its end
            // is owed to the grant store, and once written no boot finds it in force again.
            let grants = world.controller.sharing().grants();
            world.controller.lifetimes().settle_stored(grants);
            assert!(
                grants
                    .grant_expired_at(held_share.grant_id)
                    .expect("readable")
                    .is_some(),
                "the share's end is on record"
            );
        }
        world.serving.abort();
    }
}

/// KR-REQ-25.10: a connection that only read under a share, and opened no link to the session's
/// worker under it, is ended with the share all the same: the share is a grant it stood on for as
/// long as that read could be followed by another. Its pairing grant outlasts the share here, so
/// nothing but the share's own end can end the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_connection_is_ended_with_a_share_it_only_read_under() {
    use std::sync::atomic::Ordering;

    for on_the_continuous_clock in [true, false] {
        let (continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
        let holding = std::sync::Arc::new(std::sync::Mutex::new(Holding::default()));
        let world = fake::fake_world_on(
            Some(clocks),
            serving(std::sync::Arc::clone(&holding), holds_question_reads()),
        )
        .await;
        fake::acknowledged(&world.controller, world.session_id);
        let now = wall.load(Ordering::SeqCst);
        let device = paired(&world.controller, 31, SessionSelector::None);
        let held_share = share(
            &world,
            &device,
            &[ActionRight::SessionView],
            &[],
            true,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
        );
        let connection = super::RemoteConnection::for_test(&world.controller, device);
        // The watch is waiting, as it is from the moment a connection is served, before any
        // request: its pairing grant outlasts the share, so it has no deadline of its own to
        // look at and only a share taken up wakes it.
        let ended = connection.grant_ended();
        tokio::pin!(ended);
        assert!(
            !has_ended(&mut ended).await,
            "nothing has ended yet (continuous clock: {on_the_continuous_clock})"
        );
        let acting = connection
            .acting_for(Some(world.session_id), Some(held_share.grant_id))
            .expect("the share is held");
        connection
            .ask_under(
                acting,
                Some(world.session_id),
                Method::QuestionRead.entry(),
                false,
            )
            .expect("the read is decided under the share");
        assert!(
            !has_ended(&mut ended).await,
            "and nothing has ended once it has read under the share"
        );
        // The control: a second short of the end, on the clock that ends it.
        if on_the_continuous_clock {
            continuous.advance(std::time::Duration::from_secs(59));
        } else {
            wall.store(now + 59_000, Ordering::SeqCst);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !has_ended(&mut ended).await,
            "a share a second short of its end has not ended (continuous clock: {on_the_continuous_clock})"
        );
        if on_the_continuous_clock {
            continuous.advance(std::time::Duration::from_secs(2));
        } else {
            wall.store(now + 61_000, Ordering::SeqCst);
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), &mut ended)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the connection is ended with the share it read under (continuous clock: \
                     {on_the_continuous_clock})"
                )
            });
        world.serving.abort();
    }
}

/// KR-REQ-10.50: an attach decided under a share asks the worker to draw the screen the share's
/// issuer was shown, and an attach decided under the device's pairing grant does not. A worker that
/// does not state it narrows an attachment so is not asked to attach a share, since it would draw
/// more than was shown, and is still asked to attach the device under its pairing grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_an_attach_under_a_share_asks_for_the_previewed_screen_and_one_under_a_pairing_grant_does_not()
 {
    for worker_narrows in [true, false] {
        let (world, holding) = world(
            Holding::default(),
            if worker_narrows {
                narrows_to_previewed_screens()
            } else {
                holds_results()
            },
        )
        .await;
        // A pairing grant that admits the session and its screen, and a share of the same.
        let (mut grant, _) = crate::service::net::tests::granted(
            GrantExpiry::Never,
            world.controller.policy().authority_revision(),
        );
        grant.history.include_live_screen = true;
        let device = holding_grant(&world.controller, 41, grant);
        let viewing = share_with(
            &world,
            &device,
            &[ActionRight::SessionView],
            &[],
            true,
            GrantExpiry::Never,
            true,
        );

        let under_the_pairing_grant =
            super::RemoteConnection::for_test(&world.controller, device.clone());
        drop(
            under_the_pairing_grant
                .mutate(&attaching(&world, &under_the_pairing_grant, 51, None))
                .await,
        );
        let under_the_share = super::RemoteConnection::for_test(&world.controller, device);
        let answer = under_the_share
            .mutate(&attaching(
                &world,
                &under_the_share,
                52,
                Some(viewing.grant_id),
            ))
            .await;

        let held = holding.lock().expect("held");
        let attached: Vec<(Nullable<GrantId>, bool)> = held
            .mutations
            .iter()
            .filter(|forwarded| forwarded.mutation.method == Method::SessionAttach.into())
            .map(|forwarded| (forwarded.actor.grant_id, forwarded.previewed_screen))
            .collect();
        if worker_narrows {
            assert_eq!(
                attached.len(),
                2,
                "both attaches reached the worker: {attached:?}"
            );
            assert!(
                !attached[0].1,
                "a device under its pairing grant is drawn the live screen"
            );
            assert_eq!(
                (attached[1].0, attached[1].1),
                (Nullable::some(viewing.grant_id), true),
                "and the recipient of a share the screen its issuer was shown"
            );
        } else {
            assert_eq!(
                attached.len(),
                1,
                "only the attach under the pairing grant reached an earlier worker: {attached:?}"
            );
            assert!(!attached[0].1);
            let refused = refusal_of(&answer);
            assert_eq!(
                refused.code,
                ErrorCode::UnsupportedCapability,
                "{refused:?}"
            );
        }
        world.serving.abort();
    }
}

/// KR-REQ-19.01: a view-only recipient binds no attachment through `agent.draft.add_attachment`. The
/// call needs the right to upload and the right to prompt an agent, which no share a session is
/// shared with carries and which a call that names no session takes from the device's pairing
/// grant alone: the recipient's pairing grant holds neither, and naming the share does not lend the
/// call anything, since a share is no grant for a call that acts on no session. The control is a
/// device whose pairing grant holds both: its call is not refused for its rights.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_19_01_a_view_only_share_binds_no_attachment_for_its_holder() {
    use kr_protocol::transfer::{
        AgentDraftAddAttachmentParams, AttachmentContribution, InsertionMethod,
    };

    let (world, holding) = world(Holding::default(), holds_results()).await;
    let viewer = paired(&world.controller, 51, SessionSelector::None);
    let viewing = share(
        &world,
        &viewer,
        &[ActionRight::SessionView],
        &[],
        true,
        GrantExpiry::Never,
    );
    let (mut able, _) = crate::service::net::tests::granted(
        GrantExpiry::Never,
        world.controller.policy().authority_revision(),
    );
    able.session_selector = SessionSelector::None;
    able.actions = [ActionRight::FilesUpload, ActionRight::AgentPrompt]
        .into_iter()
        .collect();
    let uploader = holding_grant(&world.controller, 52, able);

    let mut answers = Vec::new();
    for (device, named, byte) in [
        (viewer.clone(), None, 61_u8),
        (viewer, Some(viewing.grant_id), 62),
        (uploader, None, 63),
    ] {
        let connection = super::RemoteConnection::for_test(&world.controller, device);
        let window = connection
            .windows
            .issue(connection.connection_id, world.controller.boot_epoch)
            .expect("a window");
        let mutation = kr_protocol::envelope::MutationRequest {
            request_id: RequestId::new(u64::from(byte)),
            method: Method::AgentDraftAddAttachment.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
            grant_id: Nullable(named),
            target: kr_protocol::envelope::ActionTarget::environment(world.environment_id),
            expected: kr_protocol::envelope::ParamsValue::empty(),
            action_window_id: window.action_window_id,
            requested_ttl_ms: DurationMs::new(30_000),
            params: kr_protocol::envelope::ParamsValue::from_typed(
                &AgentDraftAddAttachmentParams {
                    draft_id: kr_protocol::ids::DraftId::new(
                        kr_protocol::scalars::Uuid::from_bytes([byte; 16]),
                    ),
                    expected_revision: kr_protocol::ids::DraftRevision::new(1),
                    transfer_id: kr_protocol::ids::TransferId::new(
                        kr_protocol::scalars::Uuid::from_bytes([byte; 16]),
                    ),
                    contribution: AttachmentContribution {
                        operation_id: "attach".to_owned(),
                        accepted_media_types: vec!["text/plain".to_owned()],
                        max_byte_len: kr_protocol::scalars::U64::new(1024),
                        max_count: kr_protocol::scalars::U64::new(1),
                        insertion_method: InsertionMethod::TypedSubmission,
                        external_destination: Nullable::null(),
                        model_media_capability: false,
                    },
                },
            )
            .expect("encodes"),
        };
        let answer = connection.mutate(&mutation).await;
        answers.push(refusal_of(&answer).code);
    }
    assert_eq!(
        answers[0],
        ErrorCode::PermissionDenied,
        "the recipient's pairing grant"
    );
    assert_eq!(
        answers[1],
        ErrorCode::PermissionDenied,
        "naming the share lends nothing"
    );
    assert_ne!(
        answers[2],
        ErrorCode::PermissionDenied,
        "a pairing grant that holds the rights is not refused for them"
    );
    assert!(
        holding.lock().expect("held").mutations.is_empty(),
        "and nothing reached the worker"
    );
    world.serving.abort();
}
