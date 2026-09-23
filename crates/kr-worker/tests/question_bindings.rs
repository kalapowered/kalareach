//! A question asked under an agent's binding ends when that binding does.
//!
//! The bridge is the worker's own broker. It launched the agent, knows its process by its start
//! identity and advances the agent's binding revision when the upstream owner or the selected
//! thread changes. The source here is this test process, launched as far as the broker is
//! concerned, and the ledger is the worker's question ledger with that broker attached, which is
//! how the worker service opens it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.62 | every test below |

#![cfg(unix)]

use std::sync::Arc;

use kr_protocol::broker::IntegrationMode;
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, ConnectionId, QuestionId, SessionEpoch,
    SessionId,
};
use kr_protocol::question::{
    CallerToken, Question, QuestionAnswer, QuestionAnswerParams, QuestionCreateParams,
    QuestionEventKind, QuestionKind, QuestionReadOwnParams, QuestionReadParams, QuestionState,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_worker::broker::{
    Broker, BrokerTransport, Credential, InstanceEnding, ManagedProcess, TransportHandle,
};
use kr_worker::ownership::OwnershipBoundary;
use kr_worker::questions::{Now, Questions, SessionBoundary, VerifiedSource};

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([7; 16]))
}

fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

fn this_process() -> ProcessStartIdentity {
    kr_ipc::identity::current_process_start_identity().expect("this process's identity")
}

/// The process that started this test, which is alive for as long as the test is and is not a
/// descendant of it.
fn parent_process() -> ProcessStartIdentity {
    kr_ipc::identity::process_start_identity(std::os::unix::process::parent_id())
        .expect("the parent's identity")
}

fn source(process: ProcessStartIdentity, connection: u8) -> VerifiedSource {
    VerifiedSource {
        process,
        executable: None,
        session_member: true,
        ancestry: true,
        launch_channel: false,
        connection_id: ConnectionId::new(Uuid::from_bytes([connection; 16])),
    }
}

/// Registers `process` with the broker as the agent it launched for `instance`.
fn launched(broker: &Broker, instance: ApplicationInstanceId, process: ProcessStartIdentity) {
    broker
        .register_instance(
            instance,
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance,
                process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance,
                    executable_digest: Digest256::from_bytes([1; 32]),
                    process,
                },
                Credential::generate().expect("a launch credential"),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
}

/// The broker, an agent it launched as this test process, and the ledger with the broker attached.
fn bridged() -> (Arc<Broker>, ApplicationInstanceId, Questions) {
    let broker = Arc::new(Broker::open(None, session()).expect("a broker"));
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([9; 16]));
    launched(&broker, instance, this_process());
    let questions = Questions::open(None, session(), SessionEpoch::V1)
        .expect("a ledger")
        .with_agents(Arc::clone(&broker) as Arc<dyn kr_worker::questions::AgentBindings>);
    (broker, instance, questions)
}

fn ask(request_id: &str) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id: session(),
        request_id: request_id.to_owned(),
        agent_name: Nullable::null(),
        context: String::new(),
        question: "shall I?".to_owned(),
        kind: QuestionKind::Confirm,
        choices: Vec::new(),
        requested_expiry_ms: Nullable::null(),
        wait_ms: Nullable::null(),
    }
}

fn answer(question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: session(),
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

fn person() -> ActorId {
    ActorId::new("local:501").expect("a principal")
}

/// Every question in the session, as any answering client reads it.
fn every_question(questions: &Questions, at: u64) -> Vec<Question> {
    questions
        .read(
            &QuestionReadParams {
                session_id: session(),
                question_id: Nullable::null(),
                include_resolved: true,
            },
            now(at),
        )
        .expect("the answering surface reads")
        .0
        .questions
}

fn state_of(questions: &[Question], question_id: QuestionId) -> QuestionState {
    questions
        .iter()
        .find(|question| question.question_id == question_id)
        .expect("the question")
        .state
}

/// KR-REQ-11.62: a question from an agent the broker bridges records the binding it was asked
/// under; when the bridge detects that the upstream owner or the selected thread changed, the
/// unanswered questions asked under the binding it left are invalidated. Every client reads the
/// invalidation, the feed carries it, a person's answer to it is refused and the agent reads it
/// too; an answered question keeps its answer, a question no bridge describes is application-scoped
/// and untouched, and the next question is asked under the new binding.
#[test]
fn a_detected_switch_invalidates_the_unanswered_questions_asked_under_the_binding_it_left() {
    let (broker, instance, questions) = bridged();
    let agent = source(this_process(), 1);
    let elsewhere = source(parent_process(), 2);

    let (waiting, _) = questions
        .create(&agent, &ask("waiting"), now(1_000))
        .expect("asked");
    let (settled, _) = questions
        .create(&agent, &ask("settled"), now(1_000))
        .expect("asked");
    let (unbridged, _) = questions
        .create(&elsewhere, &ask("unbridged"), now(1_000))
        .expect("asked");
    for created in [&waiting, &settled] {
        assert_eq!(
            created.question.source.application_instance_id, instance,
            "a bridged question names the agent's own instance"
        );
        assert_eq!(
            created.question.source.agent_binding_revision.as_ref(),
            Some(&AgentBindingRevision::new(1)),
            "and the binding it is asked under"
        );
    }
    assert!(
        unbridged
            .question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none(),
        "a source no bridge describes is application-scoped and claims no switch detection"
    );
    assert_ne!(unbridged.question.source.application_instance_id, instance);
    questions
        .answer(&person(), None, &answer(&settled.question), now(1_500))
        .expect("answered before the switch");

    // The agent moves to another thread.
    let revision = broker
        .advance_binding(instance, None, TimestampMs::new(2_000))
        .expect("the binding advances");
    assert_eq!(revision, AgentBindingRevision::new(2));

    // Every client reads the same thing, and the feed says so once.
    let read = every_question(&questions, 2_100);
    assert_eq!(
        state_of(&read, waiting.question.question_id),
        QuestionState::Expired
    );
    assert_eq!(
        state_of(&read, settled.question.question_id),
        QuestionState::Answered,
        "an answer given before the switch stays the answer"
    );
    assert_eq!(
        state_of(&read, unbridged.question.question_id),
        QuestionState::Pending
    );
    let invalidated = read
        .iter()
        .find(|question| question.question_id == waiting.question.question_id)
        .expect("the question");
    assert!(invalidated.answer.as_ref().is_none());
    assert_eq!(
        invalidated.resolved_at_ms.as_ref().map(|at| at.get()),
        Some(2_100)
    );
    let expired: Vec<QuestionId> = questions
        .events_since(0, 64)
        .expect("the feed")
        .into_iter()
        .filter(|(_, event)| event.kind == QuestionEventKind::Expired)
        .map(|(_, event)| event.question.question_id)
        .collect();
    assert_eq!(expired, vec![waiting.question.question_id]);

    // A person answering what they were shown is refused, and nothing changes.
    let refused = questions
        .answer(&person(), None, &answer(&waiting.question), now(2_200))
        .expect_err("an answer to an invalidated question is refused");
    assert_eq!(refused.code(), ErrorCode::QuestionExpired);
    assert!(
        questions
            .check_resolvable(
                waiting.question.question_id,
                waiting.question.revision,
                Some(&QuestionAnswer::Decision { decided: true }),
                now(2_200),
            )
            .is_err(),
        "the worker's check before a dispatch marker refuses it too"
    );

    // The agent that asked reads the same state when it polls.
    let (own, _) = questions
        .read_own(
            &agent,
            &QuestionReadOwnParams {
                session_id: session(),
                question_id: waiting.question.question_id,
                caller_token: CallerToken::new(waiting.caller_token.as_slice().to_vec()),
                wait_ms: Nullable::null(),
            },
            now(2_300),
        )
        .expect("the agent reads its question");
    assert_eq!(own.question.state, QuestionState::Expired);

    // The next question is asked under the binding the agent is on now, and stays open while it
    // does not move.
    let (next, _) = questions
        .create(&agent, &ask("after the switch"), now(3_000))
        .expect("asked");
    assert_eq!(
        next.question.source.agent_binding_revision.as_ref(),
        Some(&AgentBindingRevision::new(2))
    );
    assert!(questions.sweep(now(3_100)).expect("sweeps").is_empty());
    assert_eq!(
        state_of(
            &every_question(&questions, 3_200),
            next.question.question_id
        ),
        QuestionState::Pending
    );
}

/// KR-REQ-11.62: an agent instance that ends takes its binding with it, so the unanswered questions
/// asked under that binding end too, however long their day had left.
#[test]
fn a_question_ends_with_the_agent_instance_it_was_asked_under() {
    let (broker, instance, questions) = bridged();
    let agent = source(this_process(), 1);
    let elsewhere = source(parent_process(), 2);
    let (asked, _) = questions
        .create(&agent, &ask("asked"), now(1_000))
        .expect("asked");
    let (unbridged, _) = questions
        .create(&elsewhere, &ask("unbridged"), now(1_000))
        .expect("asked");

    let ended = broker.end(instance, InstanceEnding::NativeExit);
    assert!(ended.instance_ended);

    let swept = questions.sweep(now(2_000)).expect("sweeps");
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].kind, QuestionEventKind::Expired);
    assert_eq!(swept[0].question.question_id, asked.question.question_id);
    let read = every_question(&questions, 2_100);
    assert_eq!(
        state_of(&read, asked.question.question_id),
        QuestionState::Expired
    );
    assert_eq!(
        state_of(&read, unbridged.question.question_id),
        QuestionState::Pending
    );
}

/// A helper that an agent the broker launched started is bound to the session through the broker,
/// although the backend runs outside the terminal's boundary and the root shell's tree; without the
/// broker's word it is refused as outside the session.
#[test]
fn a_helper_under_an_agent_the_broker_launched_is_bound_through_the_broker() {
    let broker = Broker::open(None, session()).expect("a broker");
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
    let me = this_process();
    // A boundary that holds nothing, and a root shell that is nobody's ancestor.
    let mut stranger = me.clone();
    stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
    let boundary = SessionBoundary {
        boundary: OwnershipBoundary::ControlGroup {
            path: std::path::PathBuf::from("/nonexistent/kalareach-test-group"),
        },
        root: stranger,
    };
    let pid = u32::try_from(me.pid.get()).expect("a process identifier");
    let connection = ConnectionId::new(Uuid::from_bytes([4; 16]));

    let refused = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect_err("nothing admits this process yet");
    assert_eq!(refused.code(), ErrorCode::NotInKrSession);

    // The broker launched this test's parent, so this process is inside that agent's tree.
    launched(&broker, instance, parent_process());
    let admitted = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect("admitted through the broker");
    assert!(!admitted.session_member);
    assert!(!admitted.ancestry);
    assert_eq!(
        kr_worker::questions::AgentBindings::binding_of(&broker, &admitted.process)
            .map(|binding| binding.application_instance_id),
        Some(instance)
    );

    let without = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        None,
    )
    .expect_err("without the broker's word it is outside the session");
    assert_eq!(without.code(), ErrorCode::NotInKrSession);
}
