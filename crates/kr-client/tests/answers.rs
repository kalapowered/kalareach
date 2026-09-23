//! Answers given while the host cannot be reached: kept on the device, offered after a reconnect,
//! and never sent to a question that ended meanwhile.
//!
//! The host here is a double that holds one session's questions the way a worker does, takes an
//! answer only for a pending question at the revision it names, and records every answer that
//! reaches it. What these tests check is what reaches it and when.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_client::ClientError;
use kr_client::answers::{
    AnswerDraft, AnswerDrafts, AnswerError, Answered, QuestionHost, Reconciled, Retired, reconcile,
    send,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, ConnectionId, EnvironmentId, QuestionId, QuestionRevision,
    SessionEpoch, SessionId,
};
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionChoice, QuestionKind, QuestionSource,
    QuestionState,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn target() -> ActionTarget {
    ActionTarget {
        environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
        session_id: Nullable::some(session()),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A pending `confirm` question at revision 1, as a person is shown it.
fn question(byte: u8) -> Question {
    Question {
        question_id: QuestionId::new(Uuid::from_bytes([byte; 16])),
        revision: QuestionRevision::new(1),
        state: QuestionState::Pending,
        session_id: session(),
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Confirm,
        context: "two tests fail".to_owned(),
        question: "push anyway?".to_owned(),
        choices: vec![QuestionChoice::something_else()],
        source: QuestionSource {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            process: ProcessStartIdentity::new(42, ProcessStartSource::LinuxProcStat, 7),
            executable: Nullable::some("/usr/bin/some-agent".to_owned()),
            agent_label: Nullable::null(),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(1_000),
        expires_at_ms: TimestampMs::new(86_401_000),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

fn yes() -> QuestionAnswer {
    QuestionAnswer::Decision { decided: true }
}

/// How the double behaves when an answer reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// It answers.
    Up,
    /// It takes the answer and the connection ends before it can say so.
    DropsAfterTaking,
    /// It takes the answer and says it cannot tell what became of it.
    TakesWithoutSaying,
    /// It takes the answer and the local connection ends part way through the reply's frame.
    TakesAndTruncates,
    /// It refuses outright with this code, taking nothing.
    Refuses(ErrorCode),
}

/// A host holding one session's questions.
struct Host {
    questions: Mutex<Vec<Question>>,
    line: Mutex<Line>,
    /// Every answer that reached the host, in order.
    answers: Mutex<Vec<QuestionAnswerParams>>,
    reads: AtomicUsize,
}

impl Host {
    fn with(questions: Vec<Question>) -> Self {
        Self {
            questions: Mutex::new(questions),
            line: Mutex::new(Line::Up),
            answers: Mutex::new(Vec::new()),
            reads: AtomicUsize::new(0),
        }
    }

    fn answers(&self) -> Vec<QuestionAnswerParams> {
        self.answers.lock().expect("the lock").clone()
    }

    /// Moves one question to a terminal state, as another client or the agent would.
    fn resolve(&self, question_id: QuestionId, state: QuestionState) {
        let mut questions = self.questions.lock().expect("the lock");
        let question = questions
            .iter_mut()
            .find(|question| question.question_id == question_id)
            .expect("the question");
        question.state = state;
        question.revision = QuestionRevision::new(question.revision.get() + 1);
    }

    fn take(&self, params: &QuestionAnswerParams) -> Result<Question, ClientError> {
        let mut questions = self.questions.lock().expect("the lock");
        let question = questions
            .iter_mut()
            .find(|question| question.question_id == params.question_id)
            .ok_or_else(|| {
                ClientError::Host(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "no such question",
                ))
            })?;
        if question.state.is_resolved() {
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::QuestionResolved,
                "the question was already answered or cancelled",
            )));
        }
        if question.revision != params.expected_revision {
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::StaleSession,
                "the question moved",
            )));
        }
        question.state = QuestionState::Answered;
        question.revision = QuestionRevision::new(question.revision.get() + 1);
        Ok(question.clone())
    }
}

impl QuestionHost for Host {
    fn questions(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<Question>, ClientError>> + Send {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let found: Vec<Question> = self
            .questions
            .lock()
            .expect("the lock")
            .iter()
            .filter(|question| question.session_id == session_id)
            .cloned()
            .collect();
        async move { Ok(found) }
    }

    fn answer(
        &self,
        _target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> impl Future<Output = Result<Question, ClientError>> + Send {
        self.answers.lock().expect("the lock").push(params.clone());
        let line = *self.line.lock().expect("the lock");
        let outcome = match line {
            Line::Refuses(code) => Err(ClientError::Host(ProtocolError::new(code, "refused"))),
            Line::Up => self.take(&params),
            Line::DropsAfterTaking => {
                self.take(&params)
                    .and(Err(ClientError::SubmissionUncertain {
                        action_id: ActionId::new(Uuid::from_bytes([9; 16])),
                    }))
            }
            Line::TakesWithoutSaying => {
                self.take(&params)
                    .and(Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::OutcomeUnknown,
                        "no result yet",
                    ))))
            }
            Line::TakesAndTruncates => {
                self.take(&params)
                    .and(Err(ClientError::Ipc(kr_ipc::IpcError::TruncatedFrame {
                        received: 3,
                        expected: 90,
                    })))
            }
        };
        async move { outcome }
    }
}

fn store() -> (tempfile::TempDir, AnswerDrafts) {
    let directory = tempfile::TempDir::new().expect("a directory");
    let drafts = AnswerDrafts::open(directory.path().join("answers")).expect("the store opens");
    (directory, drafts)
}

/// Answers `question` with no connection to the host, and returns what was kept.
async fn answer_offline(drafts: &AnswerDrafts, question: &Question) -> AnswerDraft {
    match kr_client::answers::answer(
        None::<&Host>,
        drafts,
        target(),
        question,
        yes(),
        TimestampMs::new(5_000),
    )
    .await
    .expect("the answer is kept")
    {
        Answered::Kept(draft) => draft,
        Answered::Sent(question) => panic!("nothing could have been sent: {question:?}"),
    }
}

/// KR-REQ-11.63: an answer a person gives while the client cannot reach the host stays a draft on
/// this device, readable only by its owner, and survives the client itself: a store opened again
/// reads it back exactly.
#[tokio::test]
async fn an_answer_given_offline_is_kept_as_a_draft_on_this_device() {
    let (directory, drafts) = store();
    let asked = question(5);
    let kept = answer_offline(&drafts, &asked).await;
    assert_eq!(kept.question_id, asked.question_id);
    assert_eq!(kept.question_revision, asked.revision);
    assert_eq!(kept.answer, yes());

    let reopened = AnswerDrafts::open(directory.path().join("answers")).expect("opens again");
    assert_eq!(reopened.drafts().expect("reads"), vec![kept]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file = std::fs::read_dir(directory.path().join("answers"))
            .expect("the directory")
            .next()
            .expect("one file")
            .expect("an entry");
        assert_eq!(
            file.metadata().expect("metadata").permissions().mode() & 0o777,
            0o600,
            "only the owner reads a kept answer"
        );
    }
}

/// KR-REQ-11.63: a reconnect offers a kept answer whose question is still pending at the revision
/// the person answered, and never submits it: the reconnected client reads the session and sends
/// nothing, and the draft is still kept for the person to send or discard.
#[tokio::test]
async fn a_reconnect_offers_a_kept_answer_and_sends_nothing() {
    let (_directory, drafts) = store();
    let asked = question(5);
    let kept = answer_offline(&drafts, &asked).await;
    let host = Host::with(vec![asked.clone()]);

    let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
    assert_eq!(reconciled, vec![Reconciled::Offered(kept.clone())]);
    assert!(host.answers().is_empty(), "a reconnect sends nothing");
    assert_eq!(host.reads.load(Ordering::SeqCst), 1);
    assert_eq!(drafts.drafts().expect("reads"), vec![kept]);
    assert_eq!(
        host.questions.lock().expect("the lock")[0].state,
        QuestionState::Pending
    );
}

/// KR-REQ-11.63: a kept answer is never sent to a question that ended while it was kept, however
/// it ended: somebody else answered it, it was cancelled, it expired, it moved to a revision the
/// person was not shown, or its session is gone. Each is retired unsent, with the reason a person
/// is told, and is no longer kept.
#[tokio::test]
async fn a_kept_answer_is_never_sent_to_a_question_that_ended_meanwhile() {
    for (byte, change, expected) in [
        (
            10,
            Some(QuestionState::Answered),
            Retired::Ended(QuestionState::Answered),
        ),
        (
            11,
            Some(QuestionState::Cancelled),
            Retired::Ended(QuestionState::Cancelled),
        ),
        (
            12,
            Some(QuestionState::Expired),
            Retired::Ended(QuestionState::Expired),
        ),
        (
            13,
            None,
            Retired::Moved {
                revision: QuestionRevision::new(2),
            },
        ),
    ] {
        let (_directory, drafts) = store();
        let asked = question(byte);
        let kept = answer_offline(&drafts, &asked).await;
        let host = Host::with(vec![asked.clone()]);
        match change {
            Some(state) => host.resolve(asked.question_id, state),
            None => {
                host.questions.lock().expect("the lock")[0].revision = QuestionRevision::new(2);
            }
        }

        let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
        assert_eq!(
            reconciled,
            vec![Reconciled::Retired {
                draft: kept,
                reason: expected
            }]
        );
        assert!(host.answers().is_empty(), "{expected:?}: nothing was sent");
        assert!(drafts.drafts().expect("reads").is_empty());
    }

    // A session the host no longer has holds no question to answer.
    let (_directory, drafts) = store();
    let kept = answer_offline(&drafts, &question(14)).await;
    let host = Host::with(Vec::new());
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Retired {
            draft: kept,
            reason: Retired::Gone
        }]
    );
    assert!(host.answers().is_empty());
}

/// KR-REQ-11.63: an offered answer reaches the host only when the person sends it, exactly once,
/// naming the revision the person answered; a second send is refused without reaching the host.
#[tokio::test]
async fn a_person_sends_an_offered_answer_once() {
    let (_directory, drafts) = store();
    let asked = question(20);
    let kept = answer_offline(&drafts, &asked).await;
    let host = Host::with(vec![asked.clone()]);
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Offered(kept.clone())]
    );

    let answered = send(&host, &drafts, &kept).await.expect("sent");
    assert_eq!(answered.state, QuestionState::Answered);
    let sent = host.answers();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].expected_revision, asked.revision);
    assert_eq!(sent[0].answer, yes());
    assert!(drafts.drafts().expect("reads").is_empty());

    let again = send(&host, &drafts, &kept)
        .await
        .expect_err("a second send is refused");
    assert!(matches!(
        again,
        AnswerError::Retired(Retired::Ended(QuestionState::Answered))
    ));
    assert_eq!(host.answers().len(), 1, "the second send reached nothing");
}

/// KR-REQ-11.63: a question that ends between the offer and the send is checked again before
/// anything goes, so the answer is retired rather than sent to a question that ended.
#[tokio::test]
async fn a_question_that_ends_after_the_offer_is_not_sent() {
    let (_directory, drafts) = store();
    let asked = question(30);
    let kept = answer_offline(&drafts, &asked).await;
    let host = Host::with(vec![asked.clone()]);
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Offered(kept.clone())]
    );
    host.resolve(asked.question_id, QuestionState::Cancelled);

    let refused = send(&host, &drafts, &kept).await.expect_err("not sent");
    assert!(matches!(
        refused,
        AnswerError::Retired(Retired::Ended(QuestionState::Cancelled))
    ));
    assert_eq!(refused.code(), ErrorCode::QuestionResolved);
    assert!(host.answers().is_empty());
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: an answer whose connection ended after it went is kept, because its outcome is
/// unknown, and so is one the host itself says it cannot account for; the reconnect then finds the
/// question answered by it and retires the draft, so it is never sent a second time.
#[tokio::test]
async fn an_answer_lost_with_its_connection_is_kept_and_never_sent_twice() {
    let (_directory, drafts) = store();
    let asked = question(40);
    let host = Host::with(vec![asked.clone()]);
    *host.line.lock().expect("the lock") = Line::DropsAfterTaking;

    let outcome = kr_client::answers::answer(
        Some(&host),
        &drafts,
        target(),
        &asked,
        yes(),
        TimestampMs::new(5_000),
    )
    .await
    .expect("kept");
    let Answered::Kept(kept) = outcome else {
        panic!("an answer whose outcome is unknown is kept: {outcome:?}");
    };
    *host.line.lock().expect("the lock") = Line::Up;

    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Retired {
            draft: kept,
            reason: Retired::Ended(QuestionState::Answered)
        }]
    );
    assert_eq!(host.answers().len(), 1, "the answer went once");

    // The host's own word that it cannot tell what became of an answer keeps it the same way, and
    // so does a local connection that ends part way through the reply.
    for (byte, line) in [
        (41, Line::TakesWithoutSaying),
        (42, Line::TakesAndTruncates),
    ] {
        keeps_then_retires(byte, line).await;
    }
}

/// Answers through a host that takes the answer and fails the reply as `line` says, and checks
/// the answer is kept, then retired unsent once the reconnect finds the question answered.
async fn keeps_then_retires(byte: u8, line: Line) {
    let (_directory, drafts) = store();
    let asked = question(byte);
    let host = Host::with(vec![asked.clone()]);
    *host.line.lock().expect("the lock") = line;
    let outcome = kr_client::answers::answer(
        Some(&host),
        &drafts,
        target(),
        &asked,
        yes(),
        TimestampMs::new(5_000),
    )
    .await
    .expect("kept");
    let Answered::Kept(kept) = outcome else {
        panic!("an answer whose outcome is not known is kept ({line:?}): {outcome:?}");
    };
    *host.line.lock().expect("the lock") = Line::Up;
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Retired {
            draft: kept,
            reason: Retired::Ended(QuestionState::Answered)
        }]
    );
    assert_eq!(host.answers().len(), 1, "the answer went once");
}

/// KR-REQ-11.63: while the host can be reached an answer goes at once, and a refusal is the host's
/// to show rather than a draft to keep: an answer to a question that already ended, and one the
/// host refuses outright for this device, are refused and not kept, and an answer that does not
/// fit the question's form is neither sent nor kept.
#[tokio::test]
async fn an_answer_the_host_refuses_or_the_form_forbids_is_not_kept() {
    let (_directory, drafts) = store();
    let asked = question(50);
    let host = Host::with(vec![asked.clone()]);
    let sent = kr_client::answers::answer(
        Some(&host),
        &drafts,
        target(),
        &asked,
        yes(),
        TimestampMs::new(5_000),
    )
    .await
    .expect("answered");
    assert!(
        matches!(sent, Answered::Sent(ref question) if question.state == QuestionState::Answered)
    );

    // The person's view is stale: somebody answered first.
    let refused = kr_client::answers::answer(
        Some(&host),
        &drafts,
        target(),
        &asked,
        QuestionAnswer::Decision { decided: false },
        TimestampMs::new(6_000),
    )
    .await
    .expect_err("refused");
    assert_eq!(refused.code(), ErrorCode::QuestionResolved);

    // A refusal for this device is shown, not kept for later.
    let refusing = Host::with(vec![question(52)]);
    *refusing.line.lock().expect("the lock") = Line::Refuses(ErrorCode::PermissionDenied);
    let denied = kr_client::answers::answer(
        Some(&refusing),
        &drafts,
        target(),
        &question(52),
        yes(),
        TimestampMs::new(6_500),
    )
    .await
    .expect_err("refused");
    assert_eq!(denied.code(), ErrorCode::PermissionDenied);
    assert!(drafts.drafts().expect("reads").is_empty());

    let wrong_form = kr_client::answers::answer(
        None::<&Host>,
        &drafts,
        target(),
        &question(51),
        QuestionAnswer::Choice {
            choice_id: "left".to_owned(),
        },
        TimestampMs::new(7_000),
    )
    .await
    .expect_err("an answer the form does not take is refused");
    assert_eq!(wrong_form.code(), ErrorCode::InvalidArgument);
    assert!(drafts.drafts().expect("reads").is_empty());
    assert_eq!(host.answers().len(), 2);
    assert_eq!(refusing.answers().len(), 1);
}

/// KR-REQ-11.63: the store keeps a draft only its owner can read, in a directory only its owner can
/// read, narrowing one that was looser; a later answer to the same question replaces the earlier
/// one whole and leaves no partial file behind; and a link planted under a kept answer's name is
/// replaced rather than written through.
#[cfg(unix)]
#[tokio::test]
async fn the_store_keeps_one_owner_only_file_per_question_and_writes_through_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::TempDir::new().expect("a directory");
    let answers = directory.path().join("answers");
    std::fs::create_dir(&answers).expect("a loose directory");
    std::fs::set_permissions(&answers, std::fs::Permissions::from_mode(0o755)).expect("loosened");
    let drafts = AnswerDrafts::open(&answers).expect("the store opens");
    assert_eq!(
        std::fs::metadata(&answers)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "an existing directory is narrowed to its owner"
    );

    let asked = question(60);
    // Somebody else's file, and a link to it planted where this question's answer will be kept.
    let victim = directory.path().join("victim");
    std::fs::write(&victim, b"somebody else's").expect("writes");
    std::os::unix::fs::symlink(
        &victim,
        answers.join(format!("{}.answer", asked.question_id)),
    )
    .expect("plants a link");
    // And one under the name a write would use if it wrote to a name of its question's alone.
    let fixed = answers.join(format!(".{}.partial", asked.question_id));
    std::os::unix::fs::symlink(&victim, &fixed).expect("plants a link");

    answer_offline(&drafts, &asked).await;
    let later = kr_client::answers::answer(
        None::<&Host>,
        &drafts,
        target(),
        &asked,
        QuestionAnswer::Decision { decided: false },
        TimestampMs::new(6_000),
    )
    .await
    .expect("kept");
    let Answered::Kept(later) = later else {
        panic!("kept");
    };
    assert_eq!(drafts.drafts().expect("reads"), vec![later]);
    assert_eq!(
        std::fs::read(&victim).expect("reads"),
        b"somebody else's",
        "nothing was written through the link"
    );
    std::fs::remove_file(&fixed).expect("removes the planted link");
    let names: Vec<String> = std::fs::read_dir(&answers)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, vec![format!("{}.answer", asked.question_id)]);
    let kept = answers.join(format!("{}.answer", asked.question_id));
    let metadata = std::fs::symlink_metadata(&kept).expect("metadata");
    assert!(
        metadata.file_type().is_file(),
        "the link was replaced by the answer"
    );
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}
