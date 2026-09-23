//! What the originating agent is told about an answer.
//!
//! Section 25: "Return the verified answering device/actor and question revision to the
//! originating agent with the answer." The three together are the point. An answer on its own is a
//! string an agent will act on; with the device, the actor and the revision beside it, the agent
//! can say which person on which device answered which version of the question it asked.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-25.09 | `the_originating_agent_is_told_the_answering_device_the_actor_and_the_revision` |
//! | KR-REQ-23.32 | `an_answer_to_a_revision_that_is_no_longer_current_is_refused` |
//! | KR-REQ-06.08, KR-REQ-23.32 | `a_pending_question_takes_an_answer_or_a_cancellation_only_for_its_own_revision` |

use kr_protocol::ids::{
    ActorId, ConnectionId, DeviceId, QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::question::{
    CallerToken, QuestionAnswer, QuestionAnswerParams, QuestionCancelParams, QuestionCreateParams,
    QuestionKind, QuestionReadOwnParams, QuestionReadParams, QuestionState,
};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, Uuid};
use kr_worker::questions::{Now, QuestionError, Questions};

fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

fn source() -> kr_worker::questions::binding::VerifiedSource {
    kr_worker::questions::binding::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
    }
}

fn create(session_id: SessionId) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id,
        request_id: "push-after-failures".to_owned(),
        kind: QuestionKind::Confirm,
        context: "The build finished with two failing tests.".to_owned(),
        question: "Push the branch anyway?".to_owned(),
        choices: Vec::new(),
        agent_name: Nullable::some("kr-test-agent".to_owned()),
        requested_expiry_ms: Nullable::some(DurationMs::new(600_000)),
        wait_ms: Nullable::null(),
    }
}

#[test]
fn the_originating_agent_is_told_the_answering_device_the_actor_and_the_revision() {
    let session_id = SessionId::new(Uuid::from_bytes([4; 16]));
    let questions =
        Questions::open(None, session_id, SessionEpoch::V1).expect("the question ledger opens");
    let source = source();

    let (created, _) = questions
        .create(&source, &create(session_id), now(1_000))
        .expect("the agent asks");
    let caller_token: CallerToken = created.caller_token;
    let question_id = created.question.question_id;
    let asked_revision = created.question.revision;

    // A person on a paired device answers it. The actor and the device are the host's, taken from
    // the verified connection: a caller never asserts either.
    let actor_id = ActorId::new("device:phone").expect("a principal");
    let device_id = DeviceId::new(Uuid::from_bytes([9; 16]));
    let (resolved, _) = questions
        .answer(
            &actor_id,
            Some(device_id),
            &QuestionAnswerParams {
                session_id,
                question_id,
                expected_revision: asked_revision,
                answer: QuestionAnswer::Decision { decided: true },
            },
            now(2_000),
        )
        .expect("the person answers");
    assert_eq!(resolved.question.state, QuestionState::Answered);

    // What the originating agent reads back, through its own caller token.
    let (own, _) = questions
        .read_own(
            &source,
            &QuestionReadOwnParams {
                session_id,
                question_id,
                caller_token,
                wait_ms: Nullable::null(),
            },
            now(2_100),
        )
        .expect("the agent reads its own question");

    let record = own
        .question
        .answer
        .as_ref()
        .expect("the answer is returned to the agent that asked");
    assert_eq!(
        record.answer,
        QuestionAnswer::Decision { decided: true },
        "what was answered"
    );
    assert_eq!(
        record.actor_id, actor_id,
        "the verified principal that answered"
    );
    assert_eq!(
        record.device_id.as_ref(),
        Some(&device_id),
        "the paired device it came from"
    );
    assert_eq!(
        record.question_revision, asked_revision,
        "the exact revision the person was shown"
    );
    assert_eq!(record.answered_at_ms, TimestampMs::new(2_000));
}

/// KR-REQ-23.32: an answer names the exact revision, and one that is no longer current is refused.
#[test]
fn an_answer_to_a_revision_that_is_no_longer_current_is_refused() {
    let session_id = SessionId::new(Uuid::from_bytes([4; 16]));
    let questions =
        Questions::open(None, session_id, SessionEpoch::V1).expect("the question ledger opens");
    let source = source();
    let (created, _) = questions
        .create(&source, &create(session_id), now(1_000))
        .expect("the agent asks");
    let question_id = created.question.question_id;

    let actor_id = ActorId::new("device:phone").expect("a principal");
    questions
        .answer(
            &actor_id,
            Some(DeviceId::new(Uuid::from_bytes([9; 16]))),
            &QuestionAnswerParams {
                session_id,
                question_id,
                expected_revision: created.question.revision,
                answer: QuestionAnswer::Decision { decided: true },
            },
            now(2_000),
        )
        .expect("the first answer wins");

    // A second device answering the revision it was shown finds the question resolved. The agent
    // is never told two different people answered the same revision.
    let other = ActorId::new("device:laptop").expect("a principal");
    questions
        .answer(
            &other,
            Some(DeviceId::new(Uuid::from_bytes([10; 16]))),
            &QuestionAnswerParams {
                session_id,
                question_id,
                expected_revision: created.question.revision,
                answer: QuestionAnswer::Decision { decided: false },
            },
            now(2_100),
        )
        .expect_err("a resolved question takes no second answer");
}

/// KR-REQ-06.08, KR-REQ-23.32: answering and cancelling a pending question are bound to its exact
/// revision. An answer or a cancellation naming any other revision is refused and leaves the
/// question pending, the revision it was shown still answers it, and once its deadline has passed
/// even that revision is refused as expired.
#[test]
fn a_pending_question_takes_an_answer_or_a_cancellation_only_for_its_own_revision() {
    let session_id = SessionId::new(Uuid::from_bytes([5; 16]));
    let questions =
        Questions::open(None, session_id, SessionEpoch::V1).expect("the question ledger opens");
    let source = source();
    let actor_id = ActorId::new("device:phone").expect("a principal");
    let device_id = Some(DeviceId::new(Uuid::from_bytes([9; 16])));
    let answer = |question_id, expected_revision, at| {
        questions.answer(
            &actor_id,
            device_id,
            &QuestionAnswerParams {
                session_id,
                question_id,
                expected_revision,
                answer: QuestionAnswer::Decision { decided: true },
            },
            now(at),
        )
    };
    let cancel = |question_id, expected_revision, at| {
        questions.cancel(
            &QuestionCancelParams {
                session_id,
                question_id,
                expected_revision,
            },
            now(at),
        )
    };
    let state = |question_id, at| {
        questions
            .read(
                &QuestionReadParams {
                    session_id,
                    question_id: Nullable::some(question_id),
                    include_resolved: true,
                },
                now(at),
            )
            .expect("the question reads")
            .0
            .questions[0]
            .state
    };

    let (created, _) = questions
        .create(&source, &create(session_id), now(1_000))
        .expect("the agent asks");
    let question_id = created.question.question_id;
    let shown = created.question.revision;
    let other = QuestionRevision::new(shown.get() + 1);

    for refusal in [
        answer(question_id, other, 2_000).map(|_| ()),
        cancel(question_id, other, 2_100).map(|_| ()),
    ] {
        match refusal {
            Err(QuestionError::StaleRevision { named, current }) => {
                assert_eq!((named, current), (other.get(), shown.get()));
            }
            outcome => panic!("another revision is refused as stale, not {outcome:?}"),
        }
        assert_eq!(state(question_id, 2_200), QuestionState::Pending);
    }
    let (resolved, _) = answer(question_id, shown, 2_300).expect("the revision shown answers it");
    assert_eq!(resolved.question.state, QuestionState::Answered);

    // A second question, left until after its deadline, refuses even the revision it was shown.
    let mut later = create(session_id);
    later.request_id = "push-after-deadline".to_owned();
    let (expiring, _) = questions
        .create(&source, &later, now(3_000))
        .expect("the agent asks again");
    let deadline = expiring.question.expires_at_ms.get();
    assert!(matches!(
        answer(
            expiring.question.question_id,
            expiring.question.revision,
            deadline + 1
        ),
        Err(QuestionError::Expired { .. })
    ));
    assert!(matches!(
        cancel(
            expiring.question.question_id,
            expiring.question.revision,
            deadline + 2
        ),
        Err(QuestionError::Expired { .. })
    ));
}
