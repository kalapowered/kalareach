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
//! | KR-REQ-23.31 | `a_caller_token_works_only_for_the_helper_it_was_issued_to` |

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, ConnectionId, DeviceId, QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::question::{
    CallerToken, QuestionAnswer, QuestionAnswerParams, QuestionCancelOwnParams,
    QuestionCancelParams, QuestionCreateParams, QuestionKind, QuestionReadOwnParams,
    QuestionReadParams, QuestionState,
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
/// even that revision is refused as expired, to an answer and to a cancellation alike.
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

    // Past its deadline a question refuses even the revision it was shown, to an answer and to a
    // cancellation alike. Each case runs on a ledger of its own, so the call under test is the first
    // thing to reach the question after its deadline.
    for cancelling in [false, true] {
        let questions =
            Questions::open(None, session_id, SessionEpoch::V1).expect("the question ledger opens");
        let (expiring, _) = questions
            .create(&source, &create(session_id), now(3_000))
            .expect("the agent asks");
        let question_id = expiring.question.question_id;
        let expected_revision = expiring.question.revision;
        let late = now(expiring.question.expires_at_ms.get() + 1);
        let outcome = if cancelling {
            questions
                .cancel(
                    &QuestionCancelParams {
                        session_id,
                        question_id,
                        expected_revision,
                    },
                    late,
                )
                .map(|_| ())
        } else {
            questions
                .answer(
                    &actor_id,
                    device_id,
                    &QuestionAnswerParams {
                        session_id,
                        question_id,
                        expected_revision,
                        answer: QuestionAnswer::Decision { decided: true },
                    },
                    late,
                )
                .map(|_| ())
        };
        assert!(
            matches!(outcome, Err(QuestionError::Expired { .. })),
            "a {} after the deadline: {outcome:?}",
            if cancelling { "cancellation" } else { "answer" }
        );
    }
}

/// KR-REQ-23.31: the private question methods check the helper as well as its caller token. A
/// valid token presented by another verified helper in the same session reads and cancels
/// nothing; the helper that asked, presenting another question's token, cancels nothing; and the
/// question stays pending until the helper that asked cancels it with its own token.
#[test]
fn a_caller_token_works_only_for_the_helper_it_was_issued_to() {
    let session_id = SessionId::new(Uuid::from_bytes([6; 16]));
    let questions =
        Questions::open(None, session_id, SessionEpoch::V1).expect("the question ledger opens");
    let asker = source();
    let (created, _) = questions
        .create(&asker, &create(session_id), now(1_000))
        .expect("the agent asks");
    let question_id = created.question.question_id;
    let token: CallerToken = created.caller_token;

    // Another helper, verified inside the same session, holding the first one's token.
    let mut other = source();
    other.process = ProcessStartIdentity::new(
        other.process.pid.get() + 1,
        other.process.source,
        other.process.start_value.get(),
    );
    other.connection_id = ConnectionId::new(Uuid::from_bytes([2; 16]));
    let own = |caller_token: &CallerToken| QuestionReadOwnParams {
        session_id,
        question_id,
        caller_token: caller_token.clone(),
        wait_ms: Nullable::null(),
    };
    let cancel = |caller_token: &CallerToken| QuestionCancelOwnParams {
        session_id,
        question_id,
        caller_token: caller_token.clone(),
    };
    assert!(matches!(
        questions.read_own(&other, &own(&token), now(1_100)),
        Err(QuestionError::TokenRejected { .. })
    ));
    assert!(matches!(
        questions.cancel_own(&other, &cancel(&token), now(1_200)),
        Err(QuestionError::TokenRejected { .. })
    ));

    // The helper that asked, presenting the token of another of its questions.
    let mut second = create(session_id);
    second.request_id = "push-after-review".to_owned();
    let (another, _) = questions
        .create(&asker, &second, now(1_300))
        .expect("the agent asks again");
    assert!(matches!(
        questions.cancel_own(&asker, &cancel(&another.caller_token), now(1_400)),
        Err(QuestionError::TokenRejected { .. })
    ));

    let (read, _) = questions
        .read_own(&asker, &own(&token), now(1_500))
        .expect("the helper that asked reads its question");
    assert_eq!(
        read.question.state,
        QuestionState::Pending,
        "nothing refused changed it"
    );
    let (cancelled, _) = questions
        .cancel_own(&asker, &cancel(&token), now(1_600))
        .expect("the helper that asked cancels it");
    assert_eq!(cancelled.question.state, QuestionState::Cancelled);
}
