//! Answers a person gives while this client cannot reach the host.
//!
//! Section 11: offline answers remain drafts, and a reconnect never submits them automatically. Two
//! rules make that hold here.
//!
//! * **An answer the host could not take is kept, not queued.** [`answer`] sends an answer when the
//!   host can be reached. When it cannot, including when the connection ended with the answer's
//!   outcome unknown, the answer is kept on this device as an [`AnswerDraft`]: the answer, the
//!   question and the revision of it the person was shown. Nothing retries it.
//! * **A reconnect offers; only a person sends.** [`reconcile`] reads the questions as the host now
//!   reports them and decides what each draft is: offered again when its question is still pending
//!   at the revision the person answered, and retired unsent when the question ended or moved while
//!   this client was away. It reads and nothing else. The one way a kept draft reaches the host is
//!   [`send`], the caller's own step for a person who chose to send it, and it checks the question
//!   once more before it does.
//!
//! A session's worker says what became of its questions, and nothing else does. Whether the session
//! itself ended is the host's own record to say, so a draft whose question its session does not list
//! is retired as gone only when [`QuestionHost::session_ended`] says the session ended. While the
//! record holds the session, the draft stays kept, is reported as unlisted and is not offered.
//!
//! A draft that its question outlived is never sent, whatever became of the question: somebody else
//! answered it, the agent withdrew it or its call was cancelled, its time ran out, or the binding it
//! was asked under changed. An answer whose outcome was unknown when it was kept reconciles the same
//! way: if it did reach the host, the question is answered and the draft is retired as ended.
//!
//! The store is a directory on this device that the caller names, readable only by its owner, with
//! one file per question. An answer can carry anything a person typed, so it does not leave the
//! device except to the host that asked. A kept answer is written the way this crate writes a draft:
//! to a new file of its own, created exclusively and owner-only, flushed, renamed over its name and
//! the directory flushed after, so two writers never share a file and a reader never sees half of
//! one.

use std::path::{Path, PathBuf};

use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_protocol::ids::{QuestionId, QuestionRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    MAX_ANSWER_BYTES, Question, QuestionAnswer, QuestionAnswerParams, QuestionReadParams,
    QuestionReadResult, QuestionResolveResult, QuestionState, check_answer,
};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs};
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::session::Session;
use crate::shown::{IoFault, Said, Shown};

/// The extension every kept answer carries.
const EXTENSION: &str = "answer";

/// How long an answer this client sends asks the host to hold its admission.
const ANSWER_TTL: DurationMs = DurationMs::new(120_000);

/// One answer a person gave that the host has not taken.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerDraft {
    /// Where the answer goes: the environment, the session and its epoch.
    pub target: ActionTarget,
    /// The session the question belongs to.
    pub session_id: SessionId,
    /// The question.
    pub question_id: QuestionId,
    /// The revision of the question the person was shown when they answered.
    pub question_revision: QuestionRevision,
    /// What they answered.
    pub answer: QuestionAnswer,
    /// When they answered, on this device's clock.
    pub drafted_at_ms: TimestampMs,
}

impl std::fmt::Debug for AnswerDraft {
    /// Which question the answer is for and what kind of answer it is, never what it says.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let answer: &'static str = self.answer.kind();
        formatter
            .debug_struct("AnswerDraft")
            .field("session_id", &self.session_id)
            .field("question_id", &self.question_id)
            .field("question_revision", &self.question_revision)
            .field("answer", &answer)
            .field("drafted_at_ms", &self.drafted_at_ms)
            .finish_non_exhaustive()
    }
}

impl AnswerDraft {
    /// Returns the parameters that send this draft, or why it may not be sent.
    ///
    /// `current` is the question as the host reports it now. A draft is sendable only while its
    /// question is still pending at the revision the person was shown.
    ///
    /// # Errors
    ///
    /// Returns the reason the draft is retired instead.
    pub fn submission(
        &self,
        current: Option<&Question>,
    ) -> std::result::Result<QuestionAnswerParams, Retired> {
        let Some(question) = current.filter(|question| question.question_id == self.question_id)
        else {
            return Err(Retired::Gone);
        };
        if question.state.is_resolved() {
            return Err(Retired::Ended(question.state));
        }
        if question.revision != self.question_revision {
            return Err(Retired::Moved {
                revision: question.revision,
            });
        }
        Ok(QuestionAnswerParams {
            session_id: self.session_id,
            question_id: self.question_id,
            expected_revision: self.question_revision,
            answer: self.answer.clone(),
        })
    }
}

/// Why a kept answer will not be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retired {
    /// The question reached a terminal state while the answer was kept: somebody answered it, it
    /// was cancelled or withdrawn, or it expired.
    Ended(QuestionState),
    /// The question is pending at a revision the person was not shown.
    Moved {
        /// The revision it is at now.
        revision: QuestionRevision,
    },
    /// The host no longer has the question, because its session is gone: its session does not list
    /// it, and the host's record of the session says the session ended.
    Gone,
}

impl Said for Retired {
    fn said(&self) -> Shown {
        match self {
            Self::Ended(state) => crate::shown!("the question was {}", *state),
            Self::Moved { revision } => {
                crate::shown!("the question moved to revision {}", *revision)
            }
            Self::Gone => Shown::said("its session is gone"),
        }
    }
}

crate::display_as_said!(Retired);

/// What a reconnect made of one kept answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciled {
    /// Its question is still pending at the revision the person answered. It is offered again, and
    /// nothing has been sent.
    Offered(AnswerDraft),
    /// Its question is not among those its session lists, and the host's record of the session
    /// does not say the session ended. It is still kept, it is not offered, and nothing has been
    /// sent.
    Unlisted(AnswerDraft),
    /// Its question ended or moved while this client was away. It was not sent, and it is no longer
    /// kept.
    Retired {
        /// The answer that was kept.
        draft: AnswerDraft,
        /// Why it will not be sent.
        reason: Retired,
    },
}

/// What became of one answer a person gave.
#[derive(Clone, PartialEq, Eq)]
pub enum Answered {
    /// The host took it. This is the question as it now stands.
    Sent(Box<Question>),
    /// The host could not be reached, so it is kept on this device.
    Kept(AnswerDraft),
}

impl std::fmt::Debug for Answered {
    /// Which question it was and where it stands, never its text.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sent(question) => formatter
                .debug_struct("Sent")
                .field("question_id", &question.question_id)
                .field("revision", &question.revision)
                .field("state", &question.state)
                .finish_non_exhaustive(),
            Self::Kept(draft) => formatter.debug_tuple("Kept").field(draft).finish(),
        }
    }
}

/// A kept answer's file as a failure may name it: whole when this store wrote its name.
fn stored(path: &std::path::Path) -> Shown {
    Shown::stored(path, &[], &[EXTENSION, "partial"])
}

/// A failure of this module.
#[derive(thiserror::Error)]
pub enum AnswerError {
    /// The answer does not fit the question's form.
    ///
    /// It says which rule the answer broke and never what the answer said: an answer is what a
    /// person wrote, and a choice it names is whatever was typed.
    #[error("{0}")]
    Form(Shown),
    /// The draft could not be sent because its question ended or moved.
    #[error("the question ended or moved while the answer was kept: {0}")]
    Retired(Retired),
    /// The draft was not sent because its question is not among those its session lists, and the
    /// host's record of the session does not say the session ended. It is still kept.
    #[error(
        "the question is not among those its session lists, and the host's record of the session \
         does not say the session ended"
    )]
    Unlisted,
    /// The store on this device refused.
    #[error("the answers kept at {path} cannot be used: {fault}")]
    Store {
        /// The file or directory.
        path: Shown,
        /// What the operating system said.
        fault: IoFault,
    },
    /// A kept answer could not be read back.
    #[error("the kept answer at {path} cannot be read: {detail}")]
    Unreadable {
        /// The file, named whole only when its name is one this store writes.
        path: Shown,
        /// Why: the class and the place of the fault, never what the file held.
        detail: Shown,
    },
    /// The host refused, or the connection failed in a way that is not a lost connection.
    #[error("{0}")]
    Host(#[from] ClientError),
}

impl AnswerError {
    /// Returns the stable code a caller reacts to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Form(_) => ErrorCode::InvalidArgument,
            Self::Retired(Retired::Ended(QuestionState::Expired)) => ErrorCode::QuestionExpired,
            Self::Retired(Retired::Ended(_)) => ErrorCode::QuestionResolved,
            Self::Retired(Retired::Moved { .. }) => ErrorCode::StaleSession,
            Self::Retired(Retired::Gone) => ErrorCode::UnknownSession,
            Self::Unlisted => ErrorCode::ResourceUnavailable,
            Self::Store { .. } | Self::Unreadable { .. } => ErrorCode::StorageUnavailable,
            Self::Host(error) => error.code(),
        }
    }
}

crate::debug_as_display!(AnswerError);

/// The result of this module's operations.
pub type Result<T> = std::result::Result<T, AnswerError>;

/// What this module needs from a connection to the host.
///
/// [`Session`] is the connection a client has. The two calls are the answering surface's own
/// `question.read` and `question.answer`, and nothing else is reached.
pub trait QuestionHost {
    /// Reads every question of one session, the resolved ones included.
    fn questions(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = std::result::Result<Vec<Question>, ClientError>> + Send;

    /// Answers one question.
    fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> impl Future<Output = std::result::Result<Question, ClientError>> + Send;

    /// Whether the host's own record of a session says the session ended.
    ///
    /// A worker that does not list a question has said nothing about its session, so a draft is
    /// retired as gone only on this: `Ok(true)` when the record establishes that the session ended,
    /// `Ok(false)` when it does not, and an error when it cannot be read, which retires nothing.
    fn session_ended(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = std::result::Result<bool, ClientError>> + Send;
}

impl QuestionHost for Session {
    async fn questions(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Vec<Question>, ClientError> {
        let result: QuestionReadResult = self
            .read(
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id,
                    question_id: Nullable::null(),
                    include_resolved: true,
                },
            )
            .await?;
        Ok(result.questions)
    }

    async fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> std::result::Result<Question, ClientError> {
        let result: QuestionResolveResult = self
            .mutate(
                Method::QuestionAnswer,
                target,
                None,
                &ParamsValue::empty(),
                &params,
                ANSWER_TTL,
            )
            .await?
            .to_typed()?;
        Ok(result.question)
    }

    async fn session_ended(&self, session_id: SessionId) -> std::result::Result<bool, ClientError> {
        match self
            .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
            .await
        {
            Ok(read) => {
                Ok(read.session.closure.0.is_some() || read.session.state == SessionState::Closed)
            }
            // A closed session's record can answer with the closure itself, and a host with no
            // record of the session at all no longer has it.
            Err(ClientError::Host(refused))
                if matches!(
                    refused.code,
                    ErrorCode::SessionClosed | ErrorCode::UnknownSession
                ) =>
            {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }
}

/// The answers this device keeps, in a directory the caller names.
#[derive(Clone)]
pub struct AnswerDrafts {
    directory: PathBuf,
}

impl AnswerDrafts {
    /// Opens the store, creating its directory, readable only by its owner, when it is missing.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when the directory cannot be created.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        // Created owner-only, and an existing directory narrowed to its owner rather than accepted.
        crate::drafts::private_directory(&directory).map_err(|error| AnswerError::Store {
            path: Shown::root(&directory),
            fault: IoFault::from(error),
        })?;
        Ok(Self { directory })
    }

    /// Keeps one answer, in place of any answer kept earlier for the same question.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be written.
    pub fn keep(&self, draft: &AnswerDraft) -> Result<()> {
        let bytes = kr_cbor::to_canonical_vec(draft).map_err(|error| {
            AnswerError::Form(crate::shown!(
                "the answer cannot be kept: {}",
                Shown::cbor(&error)
            ))
        })?;
        let path = self.path(draft.question_id);
        let store = |error| AnswerError::Store {
            path: stored(&path),
            fault: IoFault::from(error),
        };
        // A name of this write's own, so a second writer of the same question writes a file of its
        // own too, and the last rename is the answer that stays.
        let unique = crate::drafts::fresh_uuid()
            .map_err(|error| store(std::io::Error::other(crate::shown!("{}", error))))?;
        let partial = self
            .directory
            .join(format!(".{}.{unique}.partial", draft.question_id));
        crate::drafts::write_whole(&partial, &bytes).map_err(store)?;
        if let Err(error) = std::fs::rename(&partial, &path) {
            let _ = std::fs::remove_file(&partial);
            return Err(store(error));
        }
        kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(store)
    }

    /// Returns every answer kept on this device, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when the directory cannot be read, and
    /// [`AnswerError::Unreadable`] when a kept answer is not one this build wrote.
    pub fn drafts(&self) -> Result<Vec<AnswerDraft>> {
        let entries = std::fs::read_dir(&self.directory).map_err(|error| AnswerError::Store {
            path: Shown::root(&self.directory),
            fault: IoFault::from(error),
        })?;
        let mut drafts = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| AnswerError::Store {
                path: Shown::root(&self.directory),
                fault: IoFault::from(error),
            })?;
            let path = entry.path();
            // A partial write whose process did not live to rename it is not an answer.
            if path.extension().and_then(|extension| extension.to_str()) != Some(EXTENSION) {
                continue;
            }
            drafts.push(read_draft(&path)?);
        }
        drafts.sort_by_key(|draft| (draft.drafted_at_ms.get(), draft.question_id));
        Ok(drafts)
    }

    /// Forgets the answer kept for one question, when there is one.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be removed.
    pub fn discard(&self, question_id: QuestionId) -> Result<()> {
        let path = self.path(question_id);
        match std::fs::remove_file(&path) {
            Ok(()) => kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(
                |error| AnswerError::Store {
                    path: Shown::root(&self.directory),
                    fault: IoFault::from(error),
                },
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AnswerError::Store {
                path: stored(&path),
                fault: IoFault::from(error),
            }),
        }
    }

    fn path(&self, question_id: QuestionId) -> PathBuf {
        self.directory.join(format!("{question_id}.{EXTENSION}"))
    }
}

/// Reads one kept answer.
///
/// The path is one a listing found, so a failure names it whole only when its name is one this
/// store writes: whatever else is in the directory was put there by something else.
fn read_draft(path: &Path) -> Result<AnswerDraft> {
    let bytes = std::fs::read(path).map_err(|error| AnswerError::Store {
        path: stored(path),
        fault: IoFault::from(error),
    })?;
    kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).map_err(|error| {
        AnswerError::Unreadable {
            path: stored(path),
            detail: Shown::cbor(&error),
        }
    })
}

/// What an answer that does not fit its question's form breaks, in words that carry none of it.
///
/// The two rules about the answer's size are said as they are. Every other one is said as the kind
/// of question the answer does not fit: the form check's own sentence can name the choice an answer
/// gave, which is whatever was typed.
fn form_failure(question: &Question, answer: &QuestionAnswer) -> Shown {
    match answer.text() {
        Some(text) if text.len() > MAX_ANSWER_BYTES => {
            crate::shown!("an answer is at most {} bytes", MAX_ANSWER_BYTES)
        }
        Some("") => Shown::said("an answer carries the text the person wrote"),
        _ => crate::shown!(
            "the answer does not fit the form of this {} question",
            question.kind
        ),
    }
}

/// Returns true when a failure leaves the answer untaken or its fate unknown, rather than refused.
///
/// Two kinds keep the answer. The host could not be reached or stopped answering: a connection that
/// could not be made or that ended, including one that ended part way through a frame, or a host
/// busy or without storage for a moment, which the protocol classifies as transient. And the answer
/// went and what became of it is not known, whether the connection ended before the host's word
/// came back or the host itself said the outcome is unknown; the answer may have been taken, and
/// the next reconcile reads the question and retires the draft if it was, so it is never sent twice.
///
/// Every other failure is the host's own answer and is shown rather than kept: a refused proof, a
/// schema or version this build does not share, a malformed message, an answer to a question that
/// already ended.
fn keeps_the_answer(error: &ClientError) -> bool {
    match error {
        ClientError::ConnectionEnded | ClientError::SubmissionUncertain { .. } => true,
        // A stream that ended part way through a frame is a lost connection, whatever the code its
        // error carries for a frame that is malformed rather than cut short.
        ClientError::Ipc(
            kr_ipc::IpcError::TruncatedFrame { .. }
            | kr_ipc::IpcError::Frame(kr_protocol::frame::FrameError::Incomplete { .. }),
        ) => true,
        other => matches!(
            other.code().retry_category(),
            RetryCategory::Transient | RetryCategory::OutcomeUnknown
        ),
    }
}

/// Sends a person's answer, or keeps it on this device when the host cannot be reached.
///
/// `host` is the connection this client has, or none while it has none. `question` is the question
/// as the person was shown it, and the answer is checked against its form before anything else
/// happens, so what is kept is an answer the host could take.
///
/// # Errors
///
/// Returns [`AnswerError::Form`] for an answer that does not fit the question,
/// [`AnswerError::Host`] when the host refused it (the question already ended, or this device may
/// not answer it), and [`AnswerError::Store`] when it had to be kept and could not be.
pub async fn answer<H: QuestionHost>(
    host: Option<&H>,
    drafts: &AnswerDrafts,
    target: ActionTarget,
    question: &Question,
    answer: QuestionAnswer,
    now: TimestampMs,
) -> Result<Answered> {
    check_answer(question, &answer)
        .map_err(|_| AnswerError::Form(form_failure(question, &answer)))?;
    let draft = AnswerDraft {
        target,
        session_id: question.session_id,
        question_id: question.question_id,
        question_revision: question.revision,
        answer,
        drafted_at_ms: now,
    };
    let Some(host) = host else {
        drafts.keep(&draft)?;
        return Ok(Answered::Kept(draft));
    };
    let params = draft
        .submission(Some(question))
        .map_err(AnswerError::Retired)?;
    match host.answer(draft.target.clone(), params).await {
        Ok(question) => {
            // An answer kept earlier for this question has been superseded by this one.
            drafts.discard(draft.question_id)?;
            Ok(Answered::Sent(Box::new(question)))
        }
        Err(error) if keeps_the_answer(&error) => {
            drafts.keep(&draft)?;
            Ok(Answered::Kept(draft))
        }
        Err(error) => Err(AnswerError::Host(error)),
    }
}

/// Decides, after a reconnect, what every kept answer is, and sends none of them.
///
/// Each session a kept answer names is read once, resolved questions included. A draft whose
/// question is still pending at the revision the person answered is offered again and stays kept.
/// A draft whose question ended or moved is retired: it is not sent and it is no longer kept, and
/// the result says why, so the person can be told that their answer did not go and what happened
/// instead. A draft whose question its session does not list is retired as gone only when the
/// host's record says the session ended, and is otherwise kept and reported as unlisted.
///
/// # Errors
///
/// Returns [`AnswerError::Host`] when a session, or the record of one whose question it does not
/// list, cannot be read, in which case nothing is retired, and [`AnswerError::Store`] when the
/// store cannot be read or a retired answer cannot be removed.
pub async fn reconcile<H: QuestionHost>(
    host: &H,
    drafts: &AnswerDrafts,
) -> Result<Vec<Reconciled>> {
    let kept = drafts.drafts()?;
    let mut sessions: Vec<SessionId> = kept.iter().map(|draft| draft.session_id).collect();
    sessions.sort_unstable();
    sessions.dedup();
    let mut current: Vec<Question> = Vec::new();
    for session_id in sessions {
        match host.questions(session_id).await {
            Ok(questions) => current.extend(questions),
            // A session the host does not have any more lists no question. Whether it ended is
            // its record's to say, below.
            Err(ClientError::Host(refused)) if refused.code == ErrorCode::UnknownSession => {}
            Err(error) => return Err(AnswerError::Host(error)),
        }
    }
    // The record of every session with a draft whose question it does not list, read once each
    // and before anything is retired, so a record that cannot be read retires nothing.
    let mut ended: Vec<(SessionId, bool)> = Vec::new();
    for draft in &kept {
        let listed = current
            .iter()
            .any(|question| question.question_id == draft.question_id);
        if !listed
            && !ended
                .iter()
                .any(|(session_id, _)| *session_id == draft.session_id)
        {
            let record = host
                .session_ended(draft.session_id)
                .await
                .map_err(AnswerError::Host)?;
            ended.push((draft.session_id, record));
        }
    }
    let session_ended = |session_id: SessionId| {
        ended
            .iter()
            .any(|(ended_id, record)| *ended_id == session_id && *record)
    };
    let mut reconciled = Vec::with_capacity(kept.len());
    for draft in kept {
        let question = current
            .iter()
            .find(|question| question.question_id == draft.question_id);
        match draft.submission(question) {
            Ok(_) => reconciled.push(Reconciled::Offered(draft)),
            Err(Retired::Gone) if !session_ended(draft.session_id) => {
                reconciled.push(Reconciled::Unlisted(draft));
            }
            Err(reason) => {
                drafts.discard(draft.question_id)?;
                reconciled.push(Reconciled::Retired { draft, reason });
            }
        }
    }
    Ok(reconciled)
}

/// Sends one kept answer, for a person who chose to send it.
///
/// The question is read again first, so a draft whose question ended or moved since it was offered
/// is retired rather than sent. A draft that is sent, or that the host refuses because its question
/// ended, is no longer kept.
///
/// # Errors
///
/// Returns [`AnswerError::Retired`] when the question ended or moved, [`AnswerError::Unlisted`] when
/// its session does not list the question and the host's record does not say the session ended,
/// [`AnswerError::Host`] when the host refused or could not be reached, and [`AnswerError::Store`]
/// when the store cannot be updated.
pub async fn send<H: QuestionHost>(
    host: &H,
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
) -> Result<Question> {
    let questions = host.questions(draft.session_id).await?;
    let current = questions
        .iter()
        .find(|question| question.question_id == draft.question_id);
    let params = match draft.submission(current) {
        Ok(params) => params,
        // A question its session does not list is gone only when the host's record of the
        // session says the session ended.
        Err(Retired::Gone) if !host.session_ended(draft.session_id).await? => {
            return Err(AnswerError::Unlisted);
        }
        Err(reason) => {
            drafts.discard(draft.question_id)?;
            return Err(AnswerError::Retired(reason));
        }
    };
    match host.answer(draft.target.clone(), params).await {
        Ok(question) => {
            drafts.discard(draft.question_id)?;
            Ok(question)
        }
        Err(ClientError::Host(refused))
            if matches!(
                refused.code,
                ErrorCode::QuestionResolved | ErrorCode::QuestionExpired
            ) =>
        {
            drafts.discard(draft.question_id)?;
            Err(AnswerError::Host(ClientError::Host(refused)))
        }
        Err(error) => Err(AnswerError::Host(error)),
    }
}
