//! Answers given while the host cannot be reached: kept on the device, offered after a reconnect,
//! and never sent to a question that ended meanwhile. An answer's identifier is recorded before the
//! answer goes, so a reconnect learns whether an answer whose reply was lost was taken.
//!
//! The host here is a double that holds one session's questions the way a worker does, takes an
//! answer only for a pending question at the revision it names, keeps a receipt for what reaches it,
//! and refuses a new answer while an uncertain one stands unless the new one quotes it after it was
//! read. What these tests check is what reaches it and when.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_client::ClientError;
use kr_client::answers::{
    ANSWER_FORMAT, AnswerDraft, AnswerDrafts, AnswerError, AnswerFailure, Answered, Attempt,
    Dispatch, Earlier, Keeper, Leave, QuestionHost, Quoting, Reconciled, Retired, SendState,
    reconcile, send,
};
use kr_client::shown::Shown;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActionId, ActorId, ApplicationInstanceId, ConnectionId, EnvironmentId, QuestionId,
    QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::method::MethodVersion;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionChoice, QuestionKind,
    QuestionResolveResult, QuestionSource, QuestionState,
};
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

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

fn no() -> QuestionAnswer {
    QuestionAnswer::Decision { decided: false }
}

fn action(byte: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([byte; 16]))
}

/// How the double behaves when an answer reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// It answers.
    Up,
    /// The client cannot reach it, and nothing was written.
    Down,
    /// It takes the answer and the connection ends before it can say so.
    DropsAfterTaking,
    /// It takes the answer and says it cannot tell what became of it.
    TakesWithoutSaying,
    /// It takes the answer and the local connection ends part way through the reply's frame.
    TakesAndTruncates,
    /// The request is written and the connection ends before it arrives: the host never sees it.
    Lost,
    /// It refuses outright with this code, taking nothing.
    Refuses(ErrorCode),
}

/// What the host's own record says of the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    /// It holds the session.
    Held,
    /// The session ended.
    Ended,
    /// It cannot be read.
    Unreadable,
}

/// How the host answers a read of a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reads {
    /// It answers from its journal.
    Up,
    /// The connection fails.
    Fails,
    /// The host refuses the read in its own word.
    Refuses,
}

/// A host holding one session's questions.
struct Host {
    questions: Mutex<Vec<Question>>,
    line: Mutex<Line>,
    record: Mutex<Record>,
    reads_of_receipts: Mutex<Reads>,
    /// Every answer that reached the host, in order.
    answers: Mutex<Vec<QuestionAnswerParams>>,
    /// The identifier and quote each of them carried.
    dispatches: Mutex<Vec<Dispatch>>,
    /// The host's receipts, in the order it wrote them.
    journal: Mutex<Vec<(ActionId, ReceiptState)>>,
    /// The receipts a client was shown by a read.
    shown: Mutex<Vec<ActionId>>,
    /// An earlier send that arrives late, just before the next answer is looked at.
    late: Mutex<Option<(ActionId, QuestionAnswerParams)>>,
    /// What another command does to the store while the host is reading the questions, once.
    on_questions: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// What another command does to the store while an answer is on its way to the host, once.
    on_answer: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// What the store held when each answer reached the host: whether its identifier was recorded.
    recorded_first: Mutex<Vec<bool>>,
    watching: Mutex<Option<AnswerDrafts>>,
    /// What the host was told of the earlier sends before each send.
    learned: Mutex<Vec<Earlier>>,
    reads: AtomicUsize,
    /// How often the record was asked whether the session ended.
    records: AtomicUsize,
    receipt_reads: AtomicUsize,
}

impl Host {
    fn with(questions: Vec<Question>) -> Self {
        Self {
            questions: Mutex::new(questions),
            line: Mutex::new(Line::Up),
            record: Mutex::new(Record::Held),
            reads_of_receipts: Mutex::new(Reads::Up),
            answers: Mutex::new(Vec::new()),
            dispatches: Mutex::new(Vec::new()),
            journal: Mutex::new(Vec::new()),
            shown: Mutex::new(Vec::new()),
            late: Mutex::new(None),
            on_questions: Mutex::new(None),
            on_answer: Mutex::new(None),
            recorded_first: Mutex::new(Vec::new()),
            watching: Mutex::new(None),
            learned: Mutex::new(Vec::new()),
            reads: AtomicUsize::new(0),
            records: AtomicUsize::new(0),
            receipt_reads: AtomicUsize::new(0),
        }
    }

    /// A host whose record says `record` of a session that lists no question.
    fn listing_nothing(record: Record) -> Self {
        let host = Self::with(Vec::new());
        *host.record.lock().expect("the lock") = record;
        host
    }

    fn line(&self, line: Line) {
        *self.line.lock().expect("the lock") = line;
    }

    fn answers(&self) -> Vec<QuestionAnswerParams> {
        self.answers.lock().expect("the lock").clone()
    }

    fn dispatches(&self) -> Vec<Dispatch> {
        self.dispatches.lock().expect("the lock").clone()
    }

    /// Writes a receipt the host holds, as it would after a send of that identifier.
    fn holds(&self, action_id: ActionId, state: ReceiptState) {
        self.journal
            .lock()
            .expect("the lock")
            .push((action_id, state));
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

    fn take(&self, params: &QuestionAnswerParams) -> Result<QuestionResolveResult, ClientError> {
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
        Ok(QuestionResolveResult::whole(question.clone()))
    }

    /// The worker's rule: an uncertain outcome of this actor stands in the way of a new answer
    /// unless the new one quotes it and the client was shown it.
    fn admits(&self, dispatch: Dispatch) -> Result<(), AnswerFailure> {
        let newest = self
            .journal
            .lock()
            .expect("the lock")
            .iter()
            .rev()
            .find(|(_, state)| *state == ReceiptState::Unknown)
            .map(|(id, _)| *id);
        match (newest, dispatch.quote) {
            (None, _) => Ok(()),
            (Some(uncertain), Some(quote))
                if quote.action_id == uncertain
                    && self.shown.lock().expect("the lock").contains(&uncertain) =>
            {
                Ok(())
            }
            _ => Err(AnswerFailure::from(ClientError::Host(ProtocolError::new(
                ErrorCode::DraftConflict,
                "an earlier action has an uncertain outcome",
            )))),
        }
    }
}

impl QuestionHost for Host {
    fn questions(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<Question>, ClientError>> + Send {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(meanwhile) = self.on_questions.lock().expect("the lock").take() {
            meanwhile();
        }
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
        dispatch: Dispatch,
    ) -> impl Future<Output = Result<QuestionResolveResult, AnswerFailure>> + Send {
        let line = *self.line.lock().expect("the lock");
        if line == Line::Down {
            return std::future::ready(Err(AnswerFailure::unwritten(ClientError::ConnectionEnded)));
        }
        // What the store held at the moment the request reached the host.
        if let Some(store) = self.watching.lock().expect("the lock").as_ref() {
            let recorded = store
                .basis(params.question_id)
                .is_ok_and(|basis| basis.sends().contains(&dispatch.action_id));
            self.recorded_first.lock().expect("the lock").push(recorded);
        }
        self.answers.lock().expect("the lock").push(params.clone());
        self.dispatches.lock().expect("the lock").push(dispatch);
        // An earlier send that was in flight lands first.
        if let Some((id, late)) = self.late.lock().expect("the lock").take() {
            let _ = self.take(&late);
            self.holds(id, ReceiptState::Applied);
        }
        if let Some(meanwhile) = self.on_answer.lock().expect("the lock").take() {
            meanwhile();
        }
        let outcome = self.admits(dispatch).and_then(|()| match line {
            Line::Refuses(code) => Err(AnswerFailure::from(ClientError::Host(ProtocolError::new(
                code, "refused",
            )))),
            Line::Up => {
                let taken = self.take(&params).map_err(AnswerFailure::from);
                if taken.is_ok() {
                    self.holds(dispatch.action_id, ReceiptState::Applied);
                }
                taken
            }
            Line::DropsAfterTaking => {
                self.take(&params).map_err(AnswerFailure::from)?;
                self.holds(dispatch.action_id, ReceiptState::Applied);
                Err(AnswerFailure::from(ClientError::SubmissionUncertain {
                    action_id: dispatch.action_id,
                }))
            }
            Line::TakesWithoutSaying => {
                self.take(&params).map_err(AnswerFailure::from)?;
                self.holds(dispatch.action_id, ReceiptState::Unknown);
                Err(AnswerFailure::from(ClientError::Host(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "no result yet",
                ))))
            }
            Line::TakesAndTruncates => {
                self.take(&params).map_err(AnswerFailure::from)?;
                self.holds(dispatch.action_id, ReceiptState::Applied);
                Err(AnswerFailure::from(ClientError::Ipc(
                    kr_ipc::IpcError::TruncatedFrame {
                        received: 3,
                        expected: 90,
                    },
                )))
            }
            Line::Lost => Err(AnswerFailure::from(ClientError::SubmissionUncertain {
                action_id: dispatch.action_id,
            })),
            Line::Down => Err(AnswerFailure::unwritten(ClientError::ConnectionEnded)),
        });
        std::future::ready(outcome)
    }

    fn receipt(
        &self,
        _session_id: SessionId,
        action_id: ActionId,
    ) -> impl Future<Output = Result<Receipt, ClientError>> + Send {
        self.receipt_reads.fetch_add(1, Ordering::SeqCst);
        let reads = *self.reads_of_receipts.lock().expect("the lock");
        let held = self
            .journal
            .lock()
            .expect("the lock")
            .iter()
            .enumerate()
            .find(|(_, (id, _))| *id == action_id)
            .map(|(at, (_, state))| (at, *state));
        let outcome = match (reads, held) {
            (Reads::Fails, _) => Err(ClientError::ConnectionEnded),
            (Reads::Refuses, _) => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device may not view the session",
            ))),
            (Reads::Up, Some((at, state))) => {
                self.shown.lock().expect("the lock").push(action_id);
                Ok(Receipt {
                    action_id,
                    actor_id: ActorId::new("local:1").expect("a principal"),
                    method: kr_protocol::method::Method::QuestionAnswer.into(),
                    method_version: MethodVersion::V1,
                    revision: U64::new(3),
                    state,
                    reason: Nullable::null(),
                    payload_digest: Digest256::from_bytes([0; 32]),
                    accepted_deadline_ms: Nullable::null(),
                    error: Nullable::null(),
                    error_withheld: false,
                    updated_at_ms: TimestampMs::new(10 + at as u64),
                })
            }
            (Reads::Up, None) => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("no receipt for action {action_id}"),
            ))),
        };
        std::future::ready(outcome)
    }

    fn session_ended(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        self.records.fetch_add(1, Ordering::SeqCst);
        let record = *self.record.lock().expect("the lock");
        let outcome = match record {
            Record::Held => Ok(false),
            Record::Ended => Ok(true),
            Record::Unreadable => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "the record cannot be read",
            ))),
        };
        std::future::ready(outcome)
    }

    fn learned(&self, earlier: &Earlier) {
        self.learned.lock().expect("the lock").push(earlier.clone());
    }
}

/// A client outside a store, which holds nothing and may write any record.
fn with_leave<R>(work: impl FnOnce(&Leave<'_>) -> R) -> R {
    let writers = kr_ipc::install::hold_writers(
        &kr_ipc::install::Writing::in_roots(std::env::temp_dir(), std::env::temp_dir()),
        &mut || {},
    )
    .expect("a client outside a store holds nothing");
    let leave = Leave {
        answers: writers
            .permit(&kr_client::answers::WRITTEN)
            .expect("permitted"),
        sends: writers
            .permit(&kr_client::sends::WRITTEN)
            .expect("permitted"),
    };
    work(&leave)
}

/// The leave to write, the way a client outside a store has it.
struct Hold;

impl Keeper for Hold {
    fn keep<R>(&self, work: impl FnOnce(&Leave<'_>) -> R) -> Result<R, Shown> {
        Ok(with_leave(work))
    }
}

/// A caller that is refused the leave to write.
struct Refused;

impl Keeper for Refused {
    fn keep<R>(&self, _work: impl FnOnce(&Leave<'_>) -> R) -> Result<R, Shown> {
        Err(Shown::said("an update is switching releases"))
    }
}

fn store() -> (tempfile::TempDir, AnswerDrafts) {
    let directory = tempfile::TempDir::new().expect("a directory");
    let drafts = AnswerDrafts::open(directory.path().join("answers")).expect("the store opens");
    (directory, drafts)
}

/// Answers `asked` through `host`.
async fn answer_via(
    host: &Host,
    drafts: &AnswerDrafts,
    asked: &Question,
    answer: QuestionAnswer,
    at: u64,
) -> Attempt<Answered> {
    kr_client::answers::answer(
        host,
        &Hold,
        drafts,
        target(),
        asked,
        answer,
        TimestampMs::new(at),
        Quoting::Sending,
    )
    .await
}

/// Sends the answer kept for `question_id`, as `kr question send` does.
async fn send_via(
    host: &Host,
    drafts: &AnswerDrafts,
    question_id: QuestionId,
) -> Attempt<Answered> {
    let (draft, basis) = drafts
        .entry(question_id)
        .expect("reads")
        .expect("an answer is kept");
    send(host, &Hold, drafts, &draft, &basis, Quoting::Sending).await
}

/// Answers `question` with no way to reach the host, and returns what was kept.
async fn answer_offline(drafts: &AnswerDrafts, question: &Question) -> AnswerDraft {
    let host = Host::with(Vec::new());
    host.line(Line::Down);
    match answer_via(&host, drafts, question, yes(), 5_000)
        .await
        .outcome
        .expect("the answer is kept")
    {
        Answered::Kept(draft) => draft,
        other => panic!("nothing could have been sent: {other:?}"),
    }
}

/// Records `draft` under a send of its own, as an attempt does before it sends.
fn begin(drafts: &AnswerDrafts, draft: &AnswerDraft) -> Result<(), AnswerError> {
    let basis = drafts.basis(draft.question_id)?;
    let carried: Vec<ActionId> = basis.sends().to_vec();
    with_leave(|leave| {
        drafts.begin(
            draft,
            &basis,
            &carried,
            ActionId::new(kr_ipc::new_uuid()),
            leave,
        )
    })
    .map(|_| ())
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
    assert_eq!(
        reconciled,
        vec![Reconciled::Offered {
            draft: kept.clone(),
            earlier: Earlier::default()
        }]
    );
    assert!(host.answers().is_empty(), "a reconnect sends nothing");
    assert_eq!(host.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        host.records.load(Ordering::SeqCst),
        0,
        "a listed question asks nothing of the record"
    );
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

    // A session the host's record says ended holds no question to answer.
    let (_directory, drafts) = store();
    let kept = answer_offline(&drafts, &question(14)).await;
    let host = Host::listing_nothing(Record::Ended);
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Retired {
            draft: kept,
            reason: Retired::Gone
        }]
    );
    assert!(host.answers().is_empty());
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: a question its session no longer lists does not say the session ended; only the
/// host's own record of the session says that. While the record holds the session, a kept answer
/// whose question is not listed is reported as unlisted and stays kept, and a send neither retires
/// nor sends it; a record that cannot be read retires nothing either. The control is a record that
/// says the session ended, which retires the answer as gone, on a reconnect or on a send.
#[tokio::test]
async fn a_kept_answer_whose_question_is_not_listed_is_not_retired_while_its_session_is_held() {
    let (_directory, drafts) = store();
    let kept = answer_offline(&drafts, &question(15)).await;
    let host = Host::listing_nothing(Record::Held);

    let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
    assert_eq!(reconciled, vec![Reconciled::Unlisted(kept.clone())]);
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
    let refused = send_via(&host, &drafts, kept.question_id)
        .await
        .outcome
        .expect_err("there is no question to send it to");
    assert!(matches!(refused, AnswerError::Unlisted), "{refused:?}");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
    assert_eq!(
        host.records.load(Ordering::SeqCst),
        2,
        "the record was asked once by each"
    );

    *host.record.lock().expect("the lock") = Record::Unreadable;
    let unread = reconcile(&host, &drafts)
        .await
        .expect_err("a record that cannot be read retires nothing");
    assert!(matches!(unread, AnswerError::Host(_)), "{unread:?}");
    let unsent = send_via(&host, &drafts, kept.question_id)
        .await
        .outcome
        .expect_err("not sent");
    assert!(matches!(unsent, AnswerError::Host(_)), "{unsent:?}");
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
    assert!(host.answers().is_empty(), "nothing was sent");

    // The record says the session ended.
    *host.record.lock().expect("the lock") = Record::Ended;
    let retired = send_via(&host, &drafts, kept.question_id)
        .await
        .outcome
        .expect_err("retired");
    assert!(
        matches!(retired, AnswerError::Retired(Retired::Gone)),
        "{retired:?}"
    );
    assert!(drafts.drafts().expect("reads").is_empty());
    assert!(host.answers().is_empty(), "nothing was sent");
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
        vec![Reconciled::Offered {
            draft: kept.clone(),
            earlier: Earlier::default()
        }]
    );

    let (_, read) = drafts
        .entry(kept.question_id)
        .expect("reads")
        .expect("kept");
    let Answered::Sent(answered) = send_via(&host, &drafts, kept.question_id)
        .await
        .outcome
        .expect("sent")
    else {
        panic!("the host took it");
    };
    assert_eq!(answered.state, QuestionState::Answered);
    let sent = host.answers();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].expected_revision, asked.revision);
    assert_eq!(sent[0].answer, yes());
    assert!(drafts.drafts().expect("reads").is_empty());

    let again = send(&host, &Hold, &drafts, &kept, &read, Quoting::Sending)
        .await
        .outcome
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
        vec![Reconciled::Offered {
            draft: kept.clone(),
            earlier: Earlier::default()
        }]
    );
    host.resolve(asked.question_id, QuestionState::Cancelled);

    let refused = send_via(&host, &drafts, kept.question_id)
        .await
        .outcome
        .expect_err("not sent");
    assert!(matches!(
        refused,
        AnswerError::Retired(Retired::Ended(QuestionState::Cancelled))
    ));
    assert_eq!(refused.code(), ErrorCode::QuestionResolved);
    assert!(host.answers().is_empty());
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: an answer whose connection ended after it went is kept, because its outcome is
/// unknown, and so is one the host itself says it cannot account for; the reconnect then asks the
/// host what became of the send, so it is never sent a second time. A send the host took is reported
/// as taken; one it cannot account for is retired once its question reads as answered.
#[tokio::test]
async fn an_answer_lost_with_its_connection_is_kept_and_never_sent_twice() {
    for (byte, line, taken) in [
        (40, Line::DropsAfterTaking, true),
        (41, Line::TakesWithoutSaying, false),
        (42, Line::TakesAndTruncates, true),
    ] {
        let (directory, drafts) = store();
        let asked = question(byte);
        let host = Host::with(vec![asked.clone()]);
        host.line(line);
        let outcome = answer_via(&host, &drafts, &asked, yes(), 5_000)
            .await
            .outcome
            .expect("kept");
        let Answered::Kept(kept) = outcome else {
            panic!("an answer whose outcome is not known is kept ({line:?}): {outcome:?}");
        };
        assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
        host.line(Line::Up);

        let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
        let went = host.dispatches()[0].action_id;
        assert_eq!(
            reconciled,
            vec![if taken {
                Reconciled::Taken {
                    draft: kept,
                    action_id: went,
                }
            } else {
                Reconciled::Retired {
                    draft: kept,
                    reason: Retired::Ended(QuestionState::Answered),
                }
            }],
            "{line:?}"
        );
        assert_eq!(host.answers().len(), 1, "{line:?}: the answer went once");
        assert!(drafts.drafts().expect("reads").is_empty(), "{line:?}");
        assert_eq!(
            std::fs::read_dir(directory.path().join("answers"))
                .expect("lists")
                .count(),
            1,
            "{line:?}: only the lock stays"
        );
    }
}

/// KR-REQ-11.63: while the host can be reached an answer goes at once, and a refusal is the host's
/// to show rather than a draft to keep: an answer to a question that already ended, and one the
/// host refuses outright for this device, are refused and not kept, and an answer that does not
/// fit the question's form is neither sent nor kept.
#[tokio::test]
async fn an_answer_the_host_refuses_or_the_form_forbids_is_not_kept() {
    let (directory, drafts) = store();
    let asked = question(50);
    let host = Host::with(vec![asked.clone()]);
    let sent = answer_via(&host, &drafts, &asked, yes(), 5_000)
        .await
        .outcome
        .expect("answered");
    assert!(
        matches!(sent, Answered::Sent(ref question) if question.state == QuestionState::Answered)
    );

    // The person's view is stale: somebody answered first.
    let refused = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect_err("refused");
    assert_eq!(refused.code(), ErrorCode::QuestionResolved);

    // A refusal for this device is shown, not kept for later.
    let refusing = Host::with(vec![question(52)]);
    *refusing.line.lock().expect("the lock") = Line::Refuses(ErrorCode::PermissionDenied);
    let denied = answer_via(&refusing, &drafts, &question(52), yes(), 6_500)
        .await
        .outcome
        .expect_err("refused");
    assert_eq!(denied.code(), ErrorCode::PermissionDenied);
    assert!(drafts.drafts().expect("reads").is_empty());

    let wrong_form = answer_via(
        &Host::with(Vec::new()),
        &drafts,
        &question(51),
        QuestionAnswer::Choice {
            choice_id: "left".to_owned(),
        },
        7_000,
    )
    .await
    .outcome
    .expect_err("an answer the form does not take is refused");
    assert_eq!(wrong_form.code(), ErrorCode::InvalidArgument);
    assert!(drafts.drafts().expect("reads").is_empty());
    assert_eq!(host.answers().len(), 2);
    assert_eq!(refusing.answers().len(), 1);
    assert_eq!(
        std::fs::read_dir(directory.path().join("answers"))
            .expect("lists")
            .count(),
        1,
        "a refused answer leaves no file but the lock"
    );
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
    let down = Host::with(Vec::new());
    down.line(Line::Down);
    let later = answer_via(&down, &drafts, &asked, no(), 6_000)
        .await
        .outcome
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
        .filter(|name| name != "answers.lock")
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

/// KR-REQ-26.10: a kept answer states the format it is kept in, so that a release which changes the
/// form of what it keeps can say which it reads. One an earlier build kept states none and is read
/// as the format before there was one; one a later release kept is not read as this one.
#[tokio::test]
async fn a_kept_answer_states_its_format_and_one_of_a_later_format_is_not_read() {
    use kr_cbor::{CanonicalMap, CanonicalValue};

    let (directory, drafts) = store();
    let kept = answer_offline(&drafts, &question(5)).await;
    assert_eq!(kept.version, ANSWER_FORMAT);
    let file = std::fs::read_dir(directory.path().join("answers"))
        .expect("the directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "answer")
        })
        .expect("the kept answer's file");
    let CanonicalValue::Map(record) = kr_cbor::decode(
        &std::fs::read(&file).expect("reads"),
        &kr_cbor::Limits::DEFAULT,
    )
    .expect("the record decodes") else {
        panic!("a kept answer is a map");
    };
    assert_eq!(
        record.get("version"),
        Some(&CanonicalValue::integer(i128::from(ANSWER_FORMAT)).expect("an integer")),
        "the record states its format"
    );

    // As an earlier build kept it: the same record, with no member that states a format.
    let rewrite = |version: Option<i128>| {
        let mut entries: Vec<(String, CanonicalValue)> = record
            .entries()
            .iter()
            .filter(|(name, _)| name != "version")
            .cloned()
            .collect();
        if let Some(version) = version {
            entries.push((
                "version".to_owned(),
                CanonicalValue::integer(version).expect("an integer"),
            ));
        }
        let map = CanonicalMap::from_entries(entries).expect("a map");
        std::fs::write(&file, kr_cbor::encode(&CanonicalValue::Map(map))).expect("rewritten");
    };
    rewrite(None);
    let earlier = drafts.drafts().expect("an earlier build's answer is read");
    assert_eq!(earlier.len(), 1);
    assert_eq!(earlier[0].version, 0);
    assert_eq!(earlier[0].question_id, kept.question_id);

    rewrite(Some(i128::from(ANSWER_FORMAT) + 1));
    assert!(
        matches!(drafts.drafts(), Err(AnswerError::Unreadable { .. })),
        "a later release's answer is not read as this one's"
    );
}

/// KR-REQ-26.10: keeping an answer reads the answer it replaces first. One of an earlier format, or
/// of none, is replaced; one of a later format and one that cannot be read are left as they are and
/// the new answer is not kept; a link or a pipe at the name holds no answer this build wrote and is
/// replaced.
#[cfg(unix)]
#[tokio::test]
async fn keeping_an_answer_does_not_replace_one_it_cannot_read() {
    use kr_cbor::{CanonicalMap, CanonicalValue};

    let (directory, drafts) = store();
    let asked = question(7);
    let kept = answer_offline(&drafts, &asked).await;
    let file = directory
        .path()
        .join("answers")
        .join(format!("{}.answer", asked.question_id));
    let CanonicalValue::Map(record) = kr_cbor::decode(
        &std::fs::read(&file).expect("reads"),
        &kr_cbor::Limits::DEFAULT,
    )
    .expect("the record decodes") else {
        panic!("a kept answer is a map");
    };
    let with_version = |version: Option<i128>| {
        let mut entries: Vec<(String, CanonicalValue)> = record
            .entries()
            .iter()
            .filter(|(name, _)| name != "version")
            .cloned()
            .collect();
        if let Some(version) = version {
            entries.push((
                "version".to_owned(),
                CanonicalValue::integer(version).expect("an integer"),
            ));
        }
        kr_cbor::encode(&CanonicalValue::Map(
            CanonicalMap::from_entries(entries).expect("a map"),
        ))
    };
    let new = AnswerDraft {
        answer: QuestionAnswer::Decision { decided: false },
        ..kept.clone()
    };

    for (what, bytes) in [
        (
            "a later format",
            with_version(Some(i128::from(ANSWER_FORMAT) + 1)),
        ),
        ("something that is not a record", b"not a record".to_vec()),
    ] {
        std::fs::write(&file, &bytes).expect("planted");
        assert!(
            matches!(begin(&drafts, &new), Err(AnswerError::Unreadable { .. })),
            "{what} is not replaced"
        );
        assert_eq!(
            std::fs::read(&file).expect("reads"),
            bytes,
            "{what} is left as it is"
        );
    }

    // One of an earlier format, and one of this one, are replaced.
    for (what, bytes) in [
        ("none", with_version(None)),
        ("this format", with_version(Some(i128::from(ANSWER_FORMAT)))),
    ] {
        std::fs::write(&file, bytes).expect("planted");
        begin(&drafts, &new)
            .unwrap_or_else(|error| panic!("an answer of {what} is replaced: {error}"));
        assert_eq!(drafts.drafts().expect("reads"), vec![new.clone()]);
    }

    // A pipe at the name holds no answer, and is replaced by the rename and not opened.
    std::fs::remove_file(&file).expect("removed");
    let made = std::process::Command::new("mkfifo")
        .arg(&file)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    begin(&drafts, &new).expect("a pipe is replaced");
    assert_eq!(drafts.drafts().expect("reads"), vec![new]);
}

/// A symbolic link at `link` to `target`, where the platform lets this user make one.
fn link(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

/// A draft to keep.
fn something_to_keep() -> AnswerDraft {
    let asked = question(9);
    AnswerDraft {
        version: ANSWER_FORMAT,
        target: target(),
        session_id: asked.session_id,
        question_id: asked.question_id,
        question_revision: asked.revision,
        answer: yes(),
        drafted_at_ms: TimestampMs::new(1),
    }
}

/// KR-REQ-26.10: the lock a write of a kept answer holds is opened without following a link. A link
/// at the lock's name refuses the write, which writes nothing, and its target is not created.
#[tokio::test]
async fn keeping_an_answer_refuses_a_lock_that_is_a_link() {
    let (directory, drafts) = store();
    let draft = something_to_keep();
    let lock = directory.path().join("answers").join("answers.lock");
    let _ = std::fs::remove_file(&lock);
    let target_of_the_link = directory.path().join("somebody-elses");
    if let Err(error) = link(&target_of_the_link, &lock) {
        // Windows lets an account make a link only when it holds the privilege to (error 1314, not
        // held); a Unix account always can, and any other failure is the test's.
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            eprintln!("skipped: this account cannot make a symbolic link here: {error}");
            return;
        }
        panic!("a link is made where the lock belongs: {error}");
    }
    let error = begin(&drafts, &draft).expect_err("a link is not a lock");
    assert!(
        matches!(error, AnswerError::Store { .. }),
        "the write names the lock: {error}"
    );
    assert!(!target_of_the_link.exists(), "the link was not followed");
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-26.10: the lock a write of a kept answer holds is opened without waiting for a writer. A
/// pipe at the lock's name refuses the write at once, which writes nothing.
#[cfg(unix)]
#[tokio::test]
async fn keeping_an_answer_refuses_a_lock_that_is_a_pipe() {
    let (directory, drafts) = store();
    let draft = something_to_keep();
    let lock = directory.path().join("answers").join("answers.lock");
    let _ = std::fs::remove_file(&lock);
    let made = std::process::Command::new("mkfifo")
        .arg(&lock)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let error = begin(&drafts, &draft).expect_err("a pipe is not a lock");
    assert!(
        matches!(error, AnswerError::Store { .. }),
        "the write names the lock: {error}"
    );
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-26.10: a listing reads each kept answer through the same bounded, owner-only reader as a
/// write, without following a link or waiting on a pipe: a pipe or a link under an answer's name is
/// refused by name and does not hold the listing open, which blocks for ever on the base.
#[cfg(unix)]
#[tokio::test]
async fn listing_the_kept_answers_refuses_a_pipe_or_a_link_under_an_answer_name() {
    let (directory, drafts) = store();
    let answers = directory.path().join("answers");
    let asked = question(10);
    answer_offline(&drafts, &asked).await;
    let name = |id: &str| answers.join(format!("{id}.answer"));

    // A pipe under another question's name.
    let piped = name("0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f");
    let made = std::process::Command::new("mkfifo")
        .arg(&piped)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let (ended, listed) = std::sync::mpsc::channel();
    std::thread::spawn({
        let answers = answers.clone();
        move || {
            let _ = ended.send(
                AnswerDrafts::open(&answers)
                    .expect("the store opens")
                    .drafts(),
            );
        }
    });
    // The listing ends, or the test says it waits on the pipe. The thread of a listing that waits is
    // left behind with the process.
    let listing = listed
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the listing waits on the pipe");
    let error = listing.expect_err("a pipe is not an answer");
    assert!(matches!(error, AnswerError::Unreadable { .. }), "{error}");
    std::fs::remove_file(&piped).expect("removed");

    // A link under another question's name.
    let linked = name("1f1f1f1f-1f1f-1f1f-1f1f-1f1f1f1f1f1f");
    std::os::unix::fs::symlink(name(&asked.question_id.to_string()), &linked).expect("a link");
    let error = drafts.drafts().expect_err("a link is not an answer");
    assert!(matches!(error, AnswerError::Unreadable { .. }), "{error}");
    std::fs::remove_file(&linked).expect("removed");
    assert_eq!(drafts.drafts().expect("reads").len(), 1);
}

/// Records `draft` under the send `id`, carrying every send the record names, as an attempt does
/// before it sends; a crash right after leaves exactly this.
fn begin_with(drafts: &AnswerDrafts, draft: &AnswerDraft, id: ActionId) {
    let basis = drafts.basis(draft.question_id).expect("reads");
    let carried = basis.sends().to_vec();
    with_leave(|leave| drafts.begin(draft, &basis, &carried, id, leave)).expect("recorded");
}

/// The sends the record names for the answer kept for `question_id`.
fn sends_of(drafts: &AnswerDrafts, question_id: QuestionId) -> Vec<ActionId> {
    drafts.basis(question_id).expect("reads").sends().to_vec()
}

/// KR-REQ-11.63: the identifier an answer goes out under is recorded with the answer before the
/// answer reaches the host, so a lost reply leaves something to ask the host about.
#[tokio::test]
async fn an_answers_identifier_is_recorded_before_the_answer_reaches_the_host() {
    let (_directory, drafts) = store();
    let asked = question(60);
    let host = Host::with(vec![asked.clone()]);
    *host.watching.lock().expect("the lock") = Some(drafts.clone());
    host.line(Line::DropsAfterTaking);

    let outcome = answer_via(&host, &drafts, &asked, yes(), 5_000)
        .await
        .outcome
        .expect("kept");
    assert!(matches!(outcome, Answered::Kept(_)), "{outcome:?}");
    assert_eq!(
        *host.recorded_first.lock().expect("the lock"),
        vec![true],
        "the identifier was in the record when the answer reached the host"
    );
    assert_eq!(
        sends_of(&drafts, asked.question_id),
        vec![host.dispatches()[0].action_id]
    );
}

/// KR-REQ-11.63: a crash between the record and the send leaves a draft whose send the host has no
/// record of. A later connection offers it, says so, and sends nothing; sending it is a new send
/// that carries the old identifier along.
#[tokio::test]
async fn a_crash_between_the_record_and_the_send_offers_the_draft_and_sends_nothing() {
    let (_directory, drafts) = store();
    let asked = question(61);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(9));
    let host = Host::with(vec![asked.clone()]);

    let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
    let [Reconciled::Offered { earlier, .. }] = reconciled.as_slice() else {
        panic!("offered: {reconciled:?}");
    };
    assert_eq!(
        earlier.sends().copied().collect::<Vec<_>>(),
        vec![(action(9), SendState::NoRecord)]
    );
    assert!(host.answers().is_empty(), "a reconnect sends nothing");

    let sent = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect("sent");
    assert!(matches!(sent, Answered::Sent(_)), "{sent:?}");
    assert_eq!(host.answers().len(), 1);
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: an answer given while the host cannot be reached replaces the kept one and is
/// kept, with the earlier send still named, and nothing reaches the host.
#[tokio::test]
async fn an_offline_second_answer_replaces_the_kept_one_and_keeps_its_sends() {
    let (_directory, drafts) = store();
    let asked = question(62);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(9));
    let down = Host::with(vec![asked.clone()]);
    down.line(Line::Down);
    // The host cannot be asked, so what became of the earlier send is not known.
    *down.reads_of_receipts.lock().expect("the lock") = Reads::Fails;

    let outcome = answer_via(&down, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect("kept");
    let Answered::Kept(replacement) = outcome else {
        panic!("kept: {outcome:?}");
    };
    assert_eq!(replacement.answer, no());
    let (on_disk, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(on_disk, replacement);
    assert_eq!(
        basis.sends(),
        [action(9)],
        "the unwritten send is dropped, the earlier stays"
    );
    assert!(down.answers().is_empty());
}

/// KR-REQ-11.63: what the host says of an earlier send decides what a reconnect makes of the
/// draft, and a new send on top of it: taken retires the draft without sending, one the host has
/// and has not finished with waits, an uncertain one is named by the next send, a refused or
/// unrecorded one is reported.
#[tokio::test]
async fn a_reconnect_reads_every_state_an_earlier_send_can_be_in() {
    for (what, state) in [
        ("taken", Some(ReceiptState::Applied)),
        ("received", Some(ReceiptState::Received)),
        ("dispatching", Some(ReceiptState::Dispatching)),
        ("uncertain", Some(ReceiptState::Unknown)),
        ("refused", Some(ReceiptState::Refused)),
        ("rejected", Some(ReceiptState::Rejected)),
        ("unrecorded", None),
    ] {
        let (_directory, drafts) = store();
        let asked = question(63);
        let kept = answer_offline(&drafts, &asked).await;
        begin_with(&drafts, &kept, action(9));
        let host = Host::with(vec![asked.clone()]);
        if let Some(state) = state {
            host.holds(action(9), state);
        }
        if state == Some(ReceiptState::Applied) {
            host.resolve(asked.question_id, QuestionState::Answered);
        }

        let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
        assert!(
            host.answers().is_empty(),
            "{what}: a reconnect sends nothing"
        );
        match state {
            Some(ReceiptState::Applied) => {
                assert_eq!(
                    reconciled,
                    vec![Reconciled::Taken {
                        draft: kept,
                        action_id: action(9)
                    }],
                    "{what}"
                );
                assert!(drafts.drafts().expect("reads").is_empty(), "{what}");
                continue;
            }
            Some(ReceiptState::Received | ReceiptState::Dispatching) => {
                assert_eq!(
                    reconciled,
                    vec![Reconciled::Waiting {
                        draft: kept.clone(),
                        action_id: action(9)
                    }],
                    "{what}"
                );
                // The host has it: nothing is sent, by a new answer or by sending the kept one.
                let waiting = send_via(&host, &drafts, asked.question_id)
                    .await
                    .outcome
                    .expect("nothing sent");
                assert!(
                    matches!(waiting, Answered::Waiting(id) if id == action(9)),
                    "{what}"
                );
                let waiting = answer_via(&host, &drafts, &asked, no(), 7_000)
                    .await
                    .outcome
                    .expect("nothing sent");
                assert!(
                    matches!(waiting, Answered::Waiting(id) if id == action(9)),
                    "{what}"
                );
                assert!(host.answers().is_empty(), "{what}");
                assert_eq!(drafts.drafts().expect("reads"), vec![kept], "{what}");
                continue;
            }
            _ => {}
        }
        let [Reconciled::Offered { earlier, .. }] = reconciled.as_slice() else {
            panic!("{what}: offered, got {reconciled:?}");
        };
        let expected = match state {
            Some(ReceiptState::Unknown) => SendState::Unknown {
                revision: 3,
                updated_at_ms: TimestampMs::new(10),
            },
            Some(_) => SendState::Refused(None),
            None => SendState::NoRecord,
        };
        assert_eq!(
            earlier.sends().copied().collect::<Vec<_>>(),
            vec![(action(9), expected)],
            "{what}"
        );

        // Sending it is a new action that names an uncertain earlier one, and only that one.
        let sent = send_via(&host, &drafts, asked.question_id)
            .await
            .outcome
            .unwrap_or_else(|error| panic!("{what}: {error}"));
        assert!(matches!(sent, Answered::Sent(_)), "{what}");
        let quote = host.dispatches()[0].quote;
        match state {
            Some(ReceiptState::Unknown) => {
                assert_eq!(
                    quote.map(|quote| (quote.action_id, quote.revision)),
                    Some((action(9), 3))
                );
            }
            _ => assert_eq!(quote, None, "{what}: nothing uncertain to name"),
        }
        assert_eq!(
            host.learned.lock().expect("the lock").len(),
            1,
            "{what}: shown before it went"
        );
        assert!(drafts.drafts().expect("reads").is_empty(), "{what}");
    }
}

/// KR-REQ-11.63: an uncertain send followed by a send that was recorded and never went (a chain)
/// is still quoted: the new send names the uncertain one. A replacement answer carries the
/// uncertain send in the record, and a definite refusal of the replacement leaves the pair while
/// the earlier send is unsettled.
#[tokio::test]
async fn a_chain_of_sends_keeps_the_uncertain_one_through_a_replacement() {
    let (_directory, drafts) = store();
    let asked = question(64);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(1));
    begin_with(&drafts, &kept, action(2));
    let host = Host::with(vec![asked.clone()]);
    host.holds(action(1), ReceiptState::Unknown);
    assert_eq!(
        sends_of(&drafts, asked.question_id),
        vec![action(1), action(2)]
    );

    // A replacement answer refused outright by the host: the pair stays while A is unsettled.
    host.line(Line::Refuses(ErrorCode::PermissionDenied));
    let refused = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect_err("refused");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    let quote = host.dispatches()[0]
        .quote
        .expect("the uncertain send is named");
    assert_eq!(quote.action_id, action(1));
    let (on_disk, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(on_disk.answer, no(), "the replacement is what is kept");
    assert_eq!(
        basis.sends(),
        [action(1), action(2)],
        "no earlier send is forgotten"
    );
}

/// KR-REQ-11.63: an earlier send that lands late, after a replacement was recorded and sent, is
/// reported as the one the host took, with nothing attributed to the replacement.
#[tokio::test]
async fn a_send_that_lands_late_is_reported_as_the_one_the_host_took() {
    let (_directory, drafts) = store();
    let asked = question(65);
    let host = Host::with(vec![asked.clone()]);
    host.line(Line::Lost);
    let first = answer_via(&host, &drafts, &asked, yes(), 5_000)
        .await
        .outcome
        .expect("kept");
    assert!(matches!(first, Answered::Kept(_)), "{first:?}");
    let a = host.dispatches()[0].action_id;
    let lost = host.answers()[0].clone();
    assert!(
        host.journal.lock().expect("the lock").is_empty(),
        "the host never saw A"
    );

    // A arrives while B is being sent, and answers the question first.
    *host.late.lock().expect("the lock") = Some((a, lost));
    host.line(Line::Up);
    let second = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect("the earlier send was taken");
    // The second send went out and was refused, which the outcome says: this call did not send
    // nothing.
    let b = host.dispatches()[1].action_id;
    assert!(
        matches!(second, Answered::TakenAfterRefusal { taken, refused } if taken == a && refused == b),
        "{second:?}"
    );
    assert!(
        drafts.drafts().expect("reads").is_empty(),
        "nothing is left to send"
    );
    assert_eq!(
        host.questions.lock().expect("the lock")[0].state,
        QuestionState::Answered
    );
}

/// KR-REQ-11.63: the cleanup after a send the host refused because an earlier one landed removes
/// only the answer this call sent. An answer another command stored while the send was on its way
/// stays, and so does every send it carries; the identifier this call settled leaves the record.
#[tokio::test]
async fn a_cleanup_after_a_late_arrival_leaves_an_answer_stored_meanwhile() {
    let (_directory, drafts) = store();
    let asked = question(70);
    let host = Host::with(vec![asked.clone()]);
    host.line(Line::Lost);
    answer_via(&host, &drafts, &asked, yes(), 5_000)
        .await
        .outcome
        .expect("kept");
    let a = host.dispatches()[0].action_id;
    let lost = host.answers()[0].clone();
    *host.late.lock().expect("the lock") = Some((a, lost));
    host.line(Line::Up);

    // Another command stores its own answer while the second send is on its way.
    let replacement = AnswerDraft {
        version: ANSWER_FORMAT,
        target: target(),
        session_id: asked.session_id,
        question_id: asked.question_id,
        question_revision: asked.revision,
        answer: no(),
        drafted_at_ms: TimestampMs::new(7_000),
    };
    let other = drafts.clone();
    let stored = replacement.clone();
    *host.on_answer.lock().expect("the lock") = Some(Box::new(move || {
        begin(&other, &stored).expect("stored by the other command");
    }));

    let second = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect("the earlier send was taken");
    let b = host.dispatches()[1].action_id;
    assert!(
        matches!(second, Answered::TakenAfterRefusal { taken, refused } if taken == a && refused == b),
        "{second:?}"
    );
    let (kept, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("the other command's answer is still kept");
    assert_eq!(kept, replacement);
    assert!(
        !basis.sends().contains(&b),
        "the send the host refused leaves the record"
    );
    assert!(
        basis.sends().contains(&a),
        "the send the host took stays named"
    );
}

/// KR-REQ-11.63: when the send the host took was made by another command, a refused send is not
/// reported as refused because an earlier send of its own answer landed. The refusal is reported as
/// it is, and the answer the other command stored stays kept with the sends it carries.
#[tokio::test]
async fn a_send_another_command_made_is_not_reported_as_an_earlier_one_the_host_took() {
    let (_directory, drafts) = store();
    let asked = question(72);
    let host = Host::with(vec![asked.clone()]);
    host.line(Line::Lost);
    answer_via(&host, &drafts, &asked, yes(), 5_000)
        .await
        .outcome
        .expect("kept");
    let a = host.dispatches()[0].action_id;
    let lost = host.answers()[0].clone();
    host.line(Line::Up);

    // Another command stores its own answer, and the host takes that command's send first.
    let theirs = action(0xc9);
    *host.late.lock().expect("the lock") = Some((theirs, lost));
    let replacement = AnswerDraft {
        version: ANSWER_FORMAT,
        target: target(),
        session_id: asked.session_id,
        question_id: asked.question_id,
        question_revision: asked.revision,
        answer: no(),
        drafted_at_ms: TimestampMs::new(7_000),
    };
    let other = drafts.clone();
    let stored = replacement.clone();
    *host.on_answer.lock().expect("the lock") = Some(Box::new(move || {
        begin_with(&other, &stored, theirs);
    }));

    let refused = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect_err("the send was refused, and no send of its own answer was taken");
    assert_eq!(refused.code(), ErrorCode::QuestionResolved, "{refused:?}");
    let (kept, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("the other command's answer is still kept");
    assert_eq!(kept, replacement);
    assert!(basis.sends().contains(&a) && basis.sends().contains(&theirs));
}

/// KR-REQ-11.63: two commands send the same kept answer, and the host takes the later command's
/// send while that command's reply is lost. The earlier command's send is refused because the
/// question was answered. It cannot say that the other send came before its own or that a reply was
/// lost, and it does not name the send; it leaves the pair in place, so the next reading names the
/// action the host took.
#[tokio::test]
async fn a_send_the_host_took_for_another_command_is_named_by_the_next_reading() {
    let (_directory, drafts) = store();
    let asked = question(73);
    let kept = answer_offline(&drafts, &asked).await;
    let host = Host::with(vec![asked.clone()]);

    // The other command's send reaches the host just before this command's, and it records itself
    // in the pair first. Nothing reports it: its reply is lost.
    let theirs = action(0xd1);
    let params = kept
        .submission(Some(&asked))
        .expect("the question is pending");
    *host.late.lock().expect("the lock") = Some((theirs, params));
    let other = drafts.clone();
    let question_id = asked.question_id;
    *host.on_answer.lock().expect("the lock") = Some(Box::new(move || {
        let basis = other.basis(question_id).expect("reads");
        let carried = basis.sends().to_vec();
        with_leave(|leave| other.record_send(question_id, &basis, &carried, theirs, leave))
            .expect("recorded by the other command");
    }));

    let refused = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect_err("the send was refused because the question was answered");
    assert_eq!(refused.code(), ErrorCode::QuestionResolved, "{refused:?}");
    assert_eq!(
        sends_of(&drafts, asked.question_id),
        vec![theirs],
        "the pair stays, with the send the host took and without the one it refused"
    );

    // The next reading names the action the host took, and retires the pair.
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Taken {
            draft: kept,
            action_id: theirs
        }]
    );
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: a retirement decided from a reading of the pair that another command has since
/// replaced removes nothing, and the report says the pair changed rather than that the answer is
/// gone.
#[tokio::test]
async fn a_retirement_from_a_stale_reading_is_reported_as_a_change() {
    let (_directory, drafts) = store();
    let asked = question(71);
    let kept = answer_offline(&drafts, &asked).await;
    let (draft, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(draft, kept);

    // The question ends, and another command stores a replacement while this one reads it.
    let host = Host::with(vec![asked.clone()]);
    host.resolve(asked.question_id, QuestionState::Answered);
    let replacement = AnswerDraft {
        drafted_at_ms: TimestampMs::new(9_000),
        answer: no(),
        ..kept
    };
    let other = drafts.clone();
    let stored = replacement.clone();
    *host.on_questions.lock().expect("the lock") = Some(Box::new(move || {
        begin(&other, &stored).expect("stored by the other command");
    }));

    let attempt = send(&host, &Hold, &drafts, &draft, &basis, Quoting::Sending).await;
    assert!(
        matches!(attempt.outcome, Err(AnswerError::Changed)),
        "{:?}",
        attempt.outcome
    );
    let (now, _) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("the replacement is still kept");
    assert_eq!(now, replacement);
}

/// KR-REQ-11.63: a read of the host that fails retires nothing. A kept answer whose question ended
/// is kept and reported unsettled while an earlier send cannot be asked about, reads as taken once
/// it can, and is retired as ended when the host has nothing of it; a read the host refuses in its
/// own word lets the question decide.
#[tokio::test]
async fn a_failed_read_of_an_earlier_send_retires_nothing() {
    let (_directory, drafts) = store();
    let asked = question(66);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(9));
    let host = Host::with(vec![asked.clone()]);
    host.resolve(asked.question_id, QuestionState::Answered);

    *host.reads_of_receipts.lock().expect("the lock") = Reads::Fails;
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Unsettled(kept.clone())]
    );
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
    let unsettled = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect_err("not retired");
    assert!(matches!(unsettled, AnswerError::Unsettled), "{unsettled}");
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);

    // The host says it took the send once it can be asked.
    *host.reads_of_receipts.lock().expect("the lock") = Reads::Up;
    host.holds(action(9), ReceiptState::Applied);
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Taken {
            draft: kept.clone(),
            action_id: action(9)
        }]
    );
    assert!(drafts.drafts().expect("reads").is_empty());

    // A host that refuses the read in its own word lets the question decide.
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(8));
    *host.reads_of_receipts.lock().expect("the lock") = Reads::Refuses;
    assert_eq!(
        reconcile(&host, &drafts).await.expect("reconciles"),
        vec![Reconciled::Retired {
            draft: kept,
            reason: Retired::Ended(QuestionState::Answered)
        }]
    );
}

/// KR-REQ-11.63: a send the host refused in its own word leaves the record at once, so refusals
/// never fill it: eight refused sends of one kept answer leave none, and a ninth send is made.
#[tokio::test]
async fn sends_the_host_refused_do_not_fill_the_record() {
    let (_directory, drafts) = store();
    let asked = question(67);
    let kept = answer_offline(&drafts, &asked).await;
    let host = Host::with(vec![asked.clone()]);
    host.line(Line::Refuses(ErrorCode::DraftConflict));
    for _ in 0..8 {
        let refused = send_via(&host, &drafts, asked.question_id)
            .await
            .outcome
            .expect_err("refused");
        assert_eq!(refused.code(), ErrorCode::DraftConflict);
        assert!(sends_of(&drafts, asked.question_id).is_empty());
    }
    assert_eq!(drafts.drafts().expect("reads"), vec![kept]);
    host.line(Line::Up);
    let sent = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect("a ninth send is made");
    assert!(matches!(sent, Answered::Sent(_)), "{sent:?}");
}

/// KR-REQ-11.63: eight sends the host never settled are the most a record holds; a ninth is
/// refused with nothing sent, and the draft stays.
#[tokio::test]
async fn a_ninth_unsettled_send_is_refused_with_nothing_sent() {
    let (_directory, drafts) = store();
    let asked = question(68);
    let kept = answer_offline(&drafts, &asked).await;
    for byte in 1..=8 {
        begin_with(&drafts, &kept, action(byte));
    }
    let host = Host::with(vec![asked.clone()]);
    let refused = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect_err("refused");
    assert!(matches!(refused, AnswerError::Full), "{refused}");
    let refused = answer_via(&host, &drafts, &asked, no(), 6_000)
        .await
        .outcome
        .expect_err("refused");
    assert!(matches!(refused, AnswerError::Full), "{refused}");
    assert!(host.answers().is_empty());
    assert_eq!(drafts.drafts().expect("reads"), vec![kept]);
}

/// KR-ACC-009: an uncertain outcome is shown before a new send names it. A caller that asks to
/// have it shown first sends nothing until it names the uncertain send it was shown.
#[tokio::test]
async fn an_uncertain_outcome_is_shown_before_a_new_send_when_the_caller_asks() {
    let (_directory, drafts) = store();
    let asked = question(69);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(9));
    let host = Host::with(vec![asked.clone()]);
    host.holds(action(9), ReceiptState::Unknown);
    let (draft, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");

    for held in [
        send(
            &host,
            &Hold,
            &drafts,
            &draft,
            &basis,
            Quoting::AfterShown(None),
        )
        .await
        .outcome,
        send(
            &host,
            &Hold,
            &drafts,
            &draft,
            &basis,
            Quoting::AfterShown(Some(action(5))),
        )
        .await
        .outcome,
        kr_client::answers::answer(
            &host,
            &Hold,
            &drafts,
            target(),
            &asked,
            no(),
            TimestampMs::new(6_000),
            Quoting::AfterShown(None),
        )
        .await
        .outcome,
    ] {
        let held = held.expect("held");
        assert!(
            matches!(held, Answered::Held(quote) if quote.action_id == action(9)),
            "{held:?}"
        );
    }
    assert!(host.answers().is_empty(), "nothing was sent");

    let sent = send(
        &host,
        &Hold,
        &drafts,
        &draft,
        &basis,
        Quoting::AfterShown(Some(action(9))),
    )
    .await
    .outcome
    .expect("sent");
    assert!(matches!(sent, Answered::Sent(_)), "{sent:?}");
    assert_eq!(
        host.dispatches()[0].quote.map(|quote| quote.action_id),
        Some(action(9))
    );
}

/// KR-REQ-11.63: when the leave to write is refused, nothing is recorded and nothing is sent.
#[tokio::test]
async fn nothing_is_sent_when_the_leave_to_write_is_refused() {
    let (_directory, drafts) = store();
    let asked = question(70);
    let host = Host::with(vec![asked.clone()]);
    let refused = kr_client::answers::answer(
        &host,
        &Refused,
        &drafts,
        target(),
        &asked,
        yes(),
        TimestampMs::new(5_000),
        Quoting::Sending,
    )
    .await
    .outcome
    .expect_err("refused");
    assert!(matches!(refused, AnswerError::Keeping(_)), "{refused}");
    assert!(host.answers().is_empty());
    assert!(drafts.drafts().expect("reads").is_empty());
}

/// KR-REQ-11.63: a command that read the pair before another command replaced the answer sends
/// nothing and changes nothing.
#[tokio::test]
async fn a_send_from_a_stale_reading_sends_nothing() {
    let (_directory, drafts) = store();
    let asked = question(71);
    let kept = answer_offline(&drafts, &asked).await;
    let (draft, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    // Another command stores a replacement.
    let replacement = AnswerDraft {
        answer: no(),
        ..kept
    };
    begin_with(&drafts, &replacement, action(3));
    let host = Host::with(vec![asked.clone()]);
    let stale = send(&host, &Hold, &drafts, &draft, &basis, Quoting::Sending)
        .await
        .outcome
        .expect_err("stale");
    assert!(matches!(stale, AnswerError::Changed), "{stale}");
    assert!(host.answers().is_empty());
    assert_eq!(drafts.drafts().expect("reads"), vec![replacement]);
}

/// KR-REQ-26.10: a release that lists the answers alone replaces or removes an answer and leaves the
/// record of sends beside it: the record names an answer that is no longer there, is ignored, and a
/// reconnect sweeps it, also after an update again. An unchanged answer that release failed to
/// send keeps a record that still matches: the next send of this build lacks the identifier that
/// release used, the host refuses it, and the draft stays with the refusal.
#[tokio::test]
async fn a_record_left_by_a_release_that_does_not_list_it_is_ignored_swept_or_refused() {
    let (directory, drafts) = store();
    let asked = question(72);
    let kept = answer_offline(&drafts, &asked).await;
    begin_with(&drafts, &kept, action(9));
    let host = Host::with(vec![asked.clone()]);

    // The older release failed to send the unchanged answer and the host holds its uncertain send.
    host.holds(action(77), ReceiptState::Unknown);
    let refused = send_via(&host, &drafts, asked.question_id)
        .await
        .outcome
        .expect_err("refused without the older release's identifier");
    assert_eq!(refused.code(), ErrorCode::DraftConflict);
    assert_eq!(drafts.drafts().expect("reads"), vec![kept.clone()]);
    assert_eq!(sends_of(&drafts, asked.question_id), vec![action(9)]);

    // The older release replaces the answer with one of its own and leaves the record.
    let replaced = AnswerDraft {
        answer: no(),
        ..kept
    };
    std::fs::write(
        directory
            .path()
            .join("answers")
            .join(format!("{}.answer", asked.question_id)),
        kr_cbor::to_canonical_vec(&replaced).expect("encodes"),
    )
    .expect("replaced");
    assert!(
        sends_of(&drafts, asked.question_id).is_empty(),
        "the record names another answer"
    );
    let fresh = Host::with(vec![asked.clone()]);
    reconcile(&fresh, &drafts).await.expect("reconciles");
    let names: Vec<String> = std::fs::read_dir(directory.path().join("answers"))
        .expect("lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        !names.iter().any(|name| name.ends_with(".send")),
        "the record was swept: {names:?}"
    );
    assert!(fresh.answers().is_empty());
}
