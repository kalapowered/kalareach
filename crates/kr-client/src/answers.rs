//! Answers a person gives while this client cannot reach the host.
//!
//! Section 11: offline answers remain drafts, and a reconnect never submits them automatically. Two
//! rules make that hold here.
//!
//! * **An answer the host could not take is kept, not queued.** [`answer`] records the answer, the
//!   question and the revision of it the person was shown ([`AnswerDraft`]), and the identifier the
//!   answer goes out under ([`crate::sends`]), on this device, and only then sends it. When the
//!   host cannot be reached, including when the connection ended with the answer's outcome
//!   unknown, the answer stays kept ([`Answered::Kept`]). Writing it is a write of stored records,
//!   which the caller's [`Keeper`] gives the leave for. Nothing retries it.
//! * **A reconnect offers; only a person sends.** [`reconcile`] reads the questions as the host now
//!   reports them and decides what each draft is: offered again when its question is still pending
//!   at the revision the person answered, and retired unsent when the question ended or moved while
//!   this client was away. Before it decides, it asks the host what became of each send of the
//!   answer, so an answer whose reply was lost is retired as taken, and an uncertain outcome is
//!   shown before a new send names it. It reads and nothing else. The one way a kept draft reaches
//!   the host is [`send`], the caller's own step for a person who chose to send it, and it checks
//!   the question once more before it does.
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

use std::time::{Duration, Instant};

use kr_ipc::install::{Permit, Written};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, QuestionId, QuestionRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    MAX_ANSWER_BYTES, Question, QuestionAnswer, QuestionAnswerParams, QuestionReadParams,
    QuestionReadResult, QuestionResolveResult, QuestionState, check_answer,
};
use kr_protocol::receipt::{ActionReadParams, Receipt, ReceiptState};
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs};
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::session::Session;
use crate::shown::{IoFault, Said, Shown};

/// The extension every kept answer carries.
pub(crate) const EXTENSION: &str = "answer";

/// The format of a kept answer this build writes, recorded in it as `version`. A kept answer an
/// earlier build wrote states none and is read as format 0, which differs from this format in the
/// member alone.
///
/// Remove the reading of a kept answer that states no version once no supported upgrade starts
/// from one written before the format was recorded.
pub const ANSWER_FORMAT: u32 = 1;

/// The kept answers, as a release's manifest lists them and at the format this build writes them.
pub const WRITTEN: Written = Written::new("kept-answers", ANSWER_FORMAT as u64);

/// The file in the store's directory whose lock a write holds from its look at the answer it
/// replaces until the answer is in place.
pub(crate) const LOCK_NAME: &str = "answers.lock";

/// How long a write waits for another that is under way.
const LOCK_PATIENCE: Duration = Duration::from_secs(2);

/// The most a kept answer can hold, with room for what is kept beside it.
const KEPT_LIMIT: u64 = 4 * MAX_ANSWER_BYTES as u64;

/// Whether a record states no format, which is how an earlier build wrote every one.
const fn unstated(version: &u32) -> bool {
    *version == 0
}

/// How long an answer this client sends asks the host to hold its admission.
pub const ANSWER_TTL: DurationMs = DurationMs::new(120_000);

/// One answer a person gave that the host has not taken.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerDraft {
    /// The format of the record: [`ANSWER_FORMAT`] for one this build writes, 0 for one that states
    /// none. A record of format 0 is written again without the member, so that one an earlier build
    /// wrote reads back as the bytes it came from.
    #[serde(default, skip_serializing_if = "unstated")]
    pub version: u32,
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

/// What the host said when asked about one send of a kept answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendState {
    /// The host took it.
    Applied,
    /// The host has it and has not finished with it: received, accepted or dispatching.
    Pending,
    /// The host dispatched it and cannot say whether it took effect. A later send may name it.
    Unknown {
        /// The revision of the host's record of it, which a later send shows it was read at.
        revision: u64,
        /// When the host last wrote that record, as the host's clock had it.
        updated_at_ms: TimestampMs,
    },
    /// The host refused it, or rejected it before it was dispatched. Nothing took effect.
    Refused(Option<ErrorCode>),
    /// The host has no record of it. That is a report, never "not sent": the send may arrive late.
    NoRecord,
    /// The host could not be asked.
    Unreadable(ReadFailure),
}

/// Why a send's record could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadFailure {
    /// The read was lost or failed in a way that may pass. It decides nothing.
    Failed,
    /// The host refused the read in its own word, which no retry changes, such as a device that may
    /// not view the session.
    Refused(ErrorCode),
}

/// The uncertain send a later send names, and the revision of it that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    /// The send whose outcome the host could not establish.
    pub action_id: ActionId,
    /// The revision of the host's record of it.
    pub revision: u64,
}

/// What the host said of every earlier send of a kept answer, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Earlier {
    sends: Vec<(ActionId, SendState)>,
}

impl Earlier {
    /// Every send asked about, with what the host said.
    pub fn sends(&self) -> impl Iterator<Item = &(ActionId, SendState)> {
        self.sends.iter()
    }

    /// Whether no send was asked about.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sends.is_empty()
    }

    /// The first send the host took.
    #[must_use]
    pub fn taken(&self) -> Option<ActionId> {
        self.sends
            .iter()
            .find_map(|(id, state)| (*state == SendState::Applied).then_some(*id))
    }

    /// The first send the host has and has not finished with.
    #[must_use]
    pub fn waiting(&self) -> Option<ActionId> {
        self.sends
            .iter()
            .find_map(|(id, state)| (*state == SendState::Pending).then_some(*id))
    }

    /// The newest send whose outcome the host could not establish, by the host's record of it and
    /// then its identifier, as the worker orders them.
    #[must_use]
    pub fn quote(&self) -> Option<Quote> {
        self.sends
            .iter()
            .filter_map(|(id, state)| match state {
                SendState::Unknown {
                    revision,
                    updated_at_ms,
                } => Some((updated_at_ms.get(), *id, *revision)),
                _ => None,
            })
            .max_by_key(|(updated, id, _)| (*updated, *id))
            .map(|(_, action_id, revision)| Quote {
                action_id,
                revision,
            })
    }

    /// Whether a read failed in a way that may pass, so what became of a send is not established.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.sends
            .iter()
            .any(|(_, state)| *state == SendState::Unreadable(ReadFailure::Failed))
    }

    /// The sends a record keeps after these reads: every one the host did not settle by refusing
    /// it. A send not asked about is kept.
    #[must_use]
    pub fn carried(&self, recorded: &[ActionId]) -> Vec<ActionId> {
        recorded
            .iter()
            .copied()
            .filter(|id| {
                !self
                    .sends
                    .iter()
                    .any(|(read, state)| read == id && matches!(state, SendState::Refused(_)))
            })
            .collect()
    }
}

/// What a reconnect made of one kept answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciled {
    /// Its question is still pending at the revision the person answered. It is offered again, and
    /// nothing has been sent. `earlier` is what the host said of the sends already made.
    Offered {
        /// The kept answer.
        draft: AnswerDraft,
        /// What the host said of its earlier sends; empty when there were none.
        earlier: Earlier,
    },
    /// Its question is not among those its session lists, and the host's record of the session
    /// does not say the session ended. It is still kept, it is not offered, and nothing has been
    /// sent.
    Unlisted(AnswerDraft),
    /// The host has a send of it and has not finished with it. It is kept, it is not offered, and
    /// nothing has been sent.
    Waiting {
        /// The kept answer.
        draft: AnswerDraft,
        /// The send the host has.
        action_id: ActionId,
    },
    /// The host could not be asked what became of an earlier send and the question has ended or
    /// moved, or the kept answer changed while it was read. It is kept, it is not offered, and
    /// nothing has been sent.
    Unsettled(AnswerDraft),
    /// The host took an earlier send of it while the reply was lost. It was not sent again, and it
    /// is no longer kept.
    Taken {
        /// The kept answer.
        draft: AnswerDraft,
        /// The send the host took.
        action_id: ActionId,
    },
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
    /// The host took it. This is what the host says of the resolution: its own record of it, and
    /// the question as it now stands, which the host leaves out of the answer to a device whose
    /// grant does not reach it ([`QuestionResolveResult::question`]).
    Sent(Box<QuestionResolveResult>),
    /// The host did not confirm that it took the answer: it could not be reached, or the connection
    /// ended with the outcome unknown. The answer and the identifier it went out under are kept on
    /// this device, so a reconnect asks the host what became of it.
    Kept(AnswerDraft),
    /// The host took an earlier send of this question's answer while its reply was lost. This call
    /// stopped before it sent anything.
    Taken(ActionId),
    /// The host took a send of this question's answer, one the record carried when this call began,
    /// and refused the send this call made because the question was answered. It says nothing of
    /// which of the two reached the host first, or whether the reply to the taken send was lost: the
    /// taken send may be one another command made.
    TakenAfterRefusal {
        /// The send the host took.
        taken: ActionId,
        /// This call's own send, which the host refused.
        refused: ActionId,
    },
    /// The host has an earlier send and has not finished with it. Nothing was sent.
    Waiting(ActionId),
    /// An earlier send ended with an outcome the host could not establish, and the caller asked to
    /// have it shown first. Nothing was sent; the quote is what the next send names.
    Held(Quote),
}

impl std::fmt::Debug for Answered {
    /// Which question it was and where it stands, never its text.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sent(resolved) => formatter
                .debug_struct("Sent")
                .field("question_id", &resolved.question_id)
                .field("revision", &resolved.revision)
                .field("state", &resolved.state)
                .finish_non_exhaustive(),
            Self::Kept(draft) => formatter.debug_tuple("Kept").field(draft).finish(),
            Self::Taken(action) => formatter.debug_tuple("Taken").field(action).finish(),
            Self::TakenAfterRefusal { taken, refused } => formatter
                .debug_struct("TakenAfterRefusal")
                .field("taken", taken)
                .field("refused", refused)
                .finish(),
            Self::Waiting(action) => formatter.debug_tuple("Waiting").field(action).finish(),
            Self::Held(quote) => formatter.debug_tuple("Held").field(quote).finish(),
        }
    }
}

/// What a call that sends says, besides its outcome: what the host said of the earlier sends.
#[derive(Debug)]
pub struct Attempt<T> {
    /// What the host said of every earlier send of the answer; empty when there were none or the
    /// call ended before it asked.
    pub earlier: Earlier,
    /// How the call ended.
    pub outcome: Result<T>,
}

/// Whether a send that finds an earlier uncertain one goes at once, or waits to be shown it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quoting {
    /// The send names the earlier uncertain one and goes. The caller shows it, through
    /// [`QuestionHost::learned`], before it goes.
    Sending,
    /// The send goes only if the newest uncertain one is the one the person has been shown, which
    /// this names; otherwise nothing is sent and the call ends with [`Answered::Held`].
    AfterShown(Option<ActionId>),
}

/// A kept answer's file as a failure may name it: whole when this store wrote its name.
fn stored(path: &std::path::Path) -> Shown {
    crate::sends::stored(path)
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
    /// The leave to write a kept answer was given for another record.
    #[error("the leave to write was not for a kept answer")]
    NotPermitted,
    /// The leave to write a kept answer could not be had, and why.
    #[error("{0}")]
    Keeping(Shown),
    /// The kept answer or its record of sends changed while this command ran, so nothing was
    /// written and nothing was sent.
    #[error(
        "the answer kept for that question changed while this command ran, so nothing was sent: \
         read the kept answers again"
    )]
    Changed,
    /// Eight earlier sends of this answer are not settled, so a ninth was not made.
    #[error("eight earlier sends of this answer are not settled by the host, so nothing was sent")]
    Full,
    /// The host could not be asked what became of an earlier send, so the kept answer stays.
    #[error(
        "the host could not be asked what became of an earlier send of this answer, so the kept \
         answer stays"
    )]
    Unsettled,
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
            Self::Unlisted | Self::Full | Self::Unsettled => ErrorCode::ResourceUnavailable,
            Self::Store { .. } | Self::Unreadable { .. } | Self::Keeping(_) => {
                ErrorCode::StorageUnavailable
            }
            Self::Host(error) => error.code(),
            Self::NotPermitted => ErrorCode::InvalidArgument,
            Self::Changed => ErrorCode::DraftConflict,
        }
    }
}

crate::debug_as_display!(AnswerError);

/// The result of this module's operations.
pub type Result<T> = std::result::Result<T, AnswerError>;

/// How an attempt to send an answer failed, and whether the request was written.
///
/// An implementation says that nothing was written only when it is sure. A failure it cannot place
/// is written: the host may have the answer, and the identifier stays in the record until the host
/// says what became of it.
#[derive(Debug)]
pub struct AnswerFailure {
    /// What failed, boxed so that the result of a send stays small.
    pub error: Box<ClientError>,
    /// Whether the request may have reached the host.
    pub written: bool,
}

impl AnswerFailure {
    /// A failure before the request was written.
    #[must_use]
    pub fn unwritten(error: ClientError) -> Self {
        Self {
            error: Box::new(error),
            written: false,
        }
    }

    /// Whether the client holds proof of what became of the send: the host's own definite word, or
    /// that nothing was written. A send so settled leaves the record at once.
    #[must_use]
    pub fn settled(&self) -> bool {
        if !self.written {
            return true;
        }
        match &*self.error {
            ClientError::Host(_) | ClientError::Refused { .. } => !keeps_the_answer(&self.error),
            ClientError::NoActionWindow
            | ClientError::Misdirected { .. }
            | ClientError::OtherHost
            | ClientError::StillAccounting
            | ClientError::Withheld
            | ClientError::TooManyOutstandingMutations { .. }
            | ClientError::TooManyUnresolvedActions { .. }
            | ClientError::WrongEffect { .. }
            | ClientError::UnsupportedVersion { .. } => true,
            _ => false,
        }
    }
}

impl From<ClientError> for AnswerFailure {
    fn from(error: ClientError) -> Self {
        Self {
            error: Box::new(error),
            written: true,
        }
    }
}

/// The send an answer goes out under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    /// The identifier, minted and recorded before the request is written.
    pub action_id: ActionId,
    /// The earlier uncertain send this one names, when the host holds one.
    pub quote: Option<Quote>,
}

/// What this module needs from a connection to the host.
///
/// [`Session`] is the connection a client has. The calls are the answering surface's own
/// `question.read` and `question.answer`, and the read of a send's receipt.
pub trait QuestionHost {
    /// Reads every question of one session, the resolved ones included.
    fn questions(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = std::result::Result<Vec<Question>, ClientError>> + Send;

    /// Answers one question, under the identifier and the quote in `dispatch`.
    fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
        dispatch: Dispatch,
    ) -> impl Future<Output = std::result::Result<QuestionResolveResult, AnswerFailure>> + Send;

    /// Reads the host's receipt of one send.
    fn receipt(
        &self,
        session_id: SessionId,
        action_id: ActionId,
    ) -> impl Future<Output = std::result::Result<Receipt, ClientError>> + Send;

    /// Whether the host's own record of a session says the session ended.
    ///
    /// A worker that does not list a question has said nothing about its session, so a draft is
    /// retired as gone only on this: `Ok(true)` when the record establishes that the session ended,
    /// `Ok(false)` when it does not, and an error when it cannot be read, which retires nothing.
    fn session_ended(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = std::result::Result<bool, ClientError>> + Send;

    /// Called once, after the record of the send is written and before it goes, with what the host
    /// said of the earlier sends, when there were any. A caller that shows the person an earlier
    /// outcome before a new send shows it here.
    fn learned(&self, earlier: &Earlier) {
        let _ = earlier;
    }

    /// Called after the host took a send of the answer, with the earlier sends of it that the
    /// record carried: the send this call made, or one an earlier call made that a reading of the
    /// host found taken.
    ///
    /// The question is answered, so none of those sends can take effect any more, and no reading of
    /// the host will settle the ones whose outcome was not established. A host that holds them as
    /// unsettled, in a book that counts toward a bound, lets go of them here. It lets go of these
    /// sends and of no others: an earlier send of another answer is still its to account for. A
    /// host that keeps no such book has nothing to do.
    fn settle_earlier(
        &self,
        session_id: SessionId,
        sends: &[ActionId],
    ) -> impl Future<Output = ()> + Send {
        let _ = (session_id, sends);
        async {}
    }
}

/// The preconditions of a request that names an uncertain send it supersedes, which is how the
/// request shows the earlier outcome: none when there is nothing to name.
///
/// # Errors
///
/// Returns [`ClientError::Cbor`] when the map does not encode.
pub fn supersession(quote: Option<Quote>) -> std::result::Result<ParamsValue, ClientError> {
    let Some(quote) = quote else {
        return Ok(ParamsValue::empty());
    };
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_ACTION_KEY.to_owned(),
            kr_cbor::to_canonical_value(&quote.action_id)?,
        )
        .map_err(|error| ClientError::Cbor(Shown::cbor(&error)))?;
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_REVISION_KEY.to_owned(),
            kr_cbor::CanonicalValue::integer(i128::from(quote.revision))
                .map_err(|error| ClientError::Cbor(Shown::cbor(&error)))?,
        )
        .map_err(|error| ClientError::Cbor(Shown::cbor(&error)))?;
    Ok(ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)))
}

/// Sends an answer over a connection under the identifier and the quote in `dispatch`, as the
/// share `grant_id` names when there is one.
///
/// The request is composed first, which records nothing and writes nothing, so a failure there sent
/// nothing; the action is recorded in the connection's book when it goes, and stays there until the
/// host's own word settles it.
///
/// # Errors
///
/// The failure, with whether the request was written.
pub async fn answer_over(
    session: &Session,
    grant_id: Option<kr_protocol::ids::GrantId>,
    target: ActionTarget,
    params: QuestionAnswerParams,
    dispatch: Dispatch,
) -> std::result::Result<QuestionResolveResult, AnswerFailure> {
    let expected = supersession(dispatch.quote).map_err(AnswerFailure::unwritten)?;
    let composed = session
        .compose(
            Method::QuestionAnswer,
            dispatch.action_id,
            target,
            grant_id,
            &expected,
            &params,
            ANSWER_TTL,
        )
        .await
        .map_err(AnswerFailure::unwritten)?;
    match session.send(&composed).await {
        Ok(settled) => {
            // A result is the host's word that the action ended. A receipt is not: it says the host
            // holds the action and has not finished with it, or cannot say what became of it, and
            // the action stays on the connection's book for the receipt read to settle.
            if settled.result().is_some() {
                session.settle(dispatch.action_id).await;
            }
            Ok(settled.to_typed()?)
        }
        Err(error) => {
            let failure = AnswerFailure::from(error);
            // The host's own word settles the action here; an outcome it could not give, and a
            // connection that ended, leave it for the receipt read to settle.
            if failure.settled() {
                session.settle(dispatch.action_id).await;
            }
            Err(failure)
        }
    }
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
        dispatch: Dispatch,
    ) -> std::result::Result<QuestionResolveResult, AnswerFailure> {
        answer_over(self, None, target, params, dispatch).await
    }

    async fn receipt(
        &self,
        session_id: SessionId,
        action_id: ActionId,
    ) -> std::result::Result<Receipt, ClientError> {
        let read = self
            .read_receipt(&ActionReadParams {
                action_id,
                session_id: Some(session_id),
            })
            .await?;
        // The connection holds the action of a send until its caller settles it, whatever a receipt
        // says. The host's record of it has ended, so nothing is left to ask: the connection stops
        // holding the answer's parameters and the place the action takes in its book.
        if read.receipt.action_id == action_id && read.receipt.state.is_terminal() {
            self.settle(action_id).await;
        }
        Ok(read.receipt)
    }

    async fn settle_earlier(&self, _session_id: SessionId, sends: &[ActionId]) {
        for send in sends {
            self.settle(*send).await;
        }
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

/// The leave to write the two records of a kept answer: the answer, and the record of its sends.
#[derive(Debug)]
pub struct Leave<'a> {
    /// The leave to write a kept answer ([`WRITTEN`]).
    pub answers: Permit<'a>,
    /// The leave to write a record of sends ([`crate::sends::WRITTEN`]).
    pub sends: Permit<'a>,
}

/// How a caller takes the leave to write kept answers, which it asks for under the writers' lock
/// and lets go of when the write is done.
pub trait Keeper {
    /// Takes the lock, hands `work` the leave, and lets the lock go when `work` returns. When the
    /// lock cannot be taken or the leave is refused, `work` does not run, and the failure is said
    /// in the words the person is shown; the caller keeps the refusal itself.
    ///
    /// # Errors
    ///
    /// The reason the leave could not be had.
    fn keep<R>(&self, work: impl FnOnce(&Leave<'_>) -> R) -> std::result::Result<R, Shown>;
}

/// The pair of files kept for one question as a caller read them, which is what it decided from.
///
/// A write or a removal reads the pair again under the store's lock and does nothing unless it is
/// still this, so a command that decided from a stale reading changes nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Basis {
    draft: Option<Digest256>,
    record: Option<Digest256>,
    sends: Vec<ActionId>,
}

crate::debug_as_name!(Basis);

impl Basis {
    /// The digest of the kept answer's bytes, when an answer is kept, which a settling names the
    /// answer by.
    #[must_use]
    pub fn draft(&self) -> Option<Digest256> {
        self.draft
    }

    /// The sends the record names for the answer on disk, oldest first.
    #[must_use]
    pub fn sends(&self) -> &[ActionId] {
        &self.sends
    }
}

/// What a settling left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// The kept answer stays, with the record as it now is.
    Kept,
    /// The kept answer and its record were removed.
    Removed,
    /// The answer kept now is not the one the caller named, so it stays; the identifiers the caller
    /// held proof of were dropped from its record.
    Changed,
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

    /// Keeps one answer, in place of any answer kept earlier for the same question, and records
    /// the send it is about to go out under, in the format this build writes them.
    ///
    /// `basis` is the pair as the caller's reading of the host was made from, and `carried` the
    /// sends of the answer being replaced that the record keeps. The pair is read again under the
    /// store's lock and nothing is written unless it is still `basis`. The answer replaced is read
    /// first: one of a later format, or one that cannot be read, is left as it is and the new
    /// answer is not kept. A link or a pipe at the answer's name holds no answer this build wrote,
    /// and is replaced.
    ///
    /// The writes are in an order no crash leaves a send forgotten in: when the record carries
    /// sends, it is first written for the answer on disk and the one being written; then the answer
    /// is renamed into place; then the record is written for the new answer alone, with the new
    /// send. A failure or a crash at any step leaves a record that matches the answer on disk and
    /// names no send that was not about to go out. Nothing is sent by this call.
    ///
    /// Returns the digest of the answer now kept, which a later settling names.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Changed`] when the pair is not `basis`, [`AnswerError::Full`] when
    /// `carried` already holds [`crate::sends::MOST_SENDS`], [`AnswerError::Store`] when it cannot be
    /// written, [`AnswerError::Unreadable`] when the answer or the record it would replace is of a
    /// later format or cannot be read, and [`AnswerError::NotPermitted`] when a permit is for
    /// another record.
    pub fn begin(
        &self,
        draft: &AnswerDraft,
        basis: &Basis,
        carried: &[ActionId],
        send: ActionId,
        leave: &Leave<'_>,
    ) -> Result<Digest256> {
        self.permitted(leave)?;
        if carried.len() >= crate::sends::MOST_SENDS {
            return Err(AnswerError::Full);
        }
        let kept = AnswerDraft {
            version: ANSWER_FORMAT,
            ..draft.clone()
        };
        let bytes = kr_cbor::to_canonical_vec(&kept).map_err(|error| {
            AnswerError::Form(crate::shown!(
                "the answer cannot be kept: {}",
                Shown::cbor(&error)
            ))
        })?;
        let new = crate::sends::digest(&bytes);
        let path = self.path(draft.question_id);
        let record_path = self.record_path(draft.question_id);
        let store = |error| AnswerError::Store {
            path: stored(&path),
            fault: IoFault::from(error),
        };
        let _lock = self.hold()?;
        self.unchanged(draft.question_id, basis)?;
        replaceable(&path)?;
        crate::sends::replaceable(&record_path)?;
        // One: the sends already made stay named while the answer they describe is replaced. The
        // new send is not named yet, so a failure from here on records none that never went out.
        if !carried.is_empty()
            && let Some(on_disk) = basis.draft
        {
            self.write_record(draft.question_id, vec![on_disk, new], carried)?;
            crate::sends::reached(crate::sends::Stop::Carried, &self.directory)?;
        }
        // Two: the answer, in a file of its own, renamed over its name.
        let unique = self.unique(&path)?;
        let partial = self
            .directory
            .join(format!(".{}.{unique}.partial", draft.question_id));
        crate::drafts::write_whole(&partial, &bytes).map_err(store)?;
        if let Err(error) = kr_flush::retry_while_held(|| std::fs::rename(&partial, &path)) {
            let _ = std::fs::remove_file(&partial);
            return Err(store(error));
        }
        kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(store)?;
        crate::sends::reached(crate::sends::Stop::Replaced, &self.directory)?;
        // Three: the record names the new answer alone, with every send it carries and this one.
        let mut sends = carried.to_vec();
        sends.push(send);
        self.write_record(draft.question_id, vec![new], &sends)?;
        Ok(new)
    }

    /// Records one more send of the answer kept for a question, which is unchanged.
    ///
    /// The pair is read again under the store's lock, and nothing is written unless it is still
    /// `basis`.
    ///
    /// # Errors
    ///
    /// As [`Self::begin`].
    pub fn record_send(
        &self,
        question_id: QuestionId,
        basis: &Basis,
        carried: &[ActionId],
        send: ActionId,
        leave: &Leave<'_>,
    ) -> Result<()> {
        self.permitted(leave)?;
        if carried.len() >= crate::sends::MOST_SENDS {
            return Err(AnswerError::Full);
        }
        let _lock = self.hold()?;
        self.unchanged(question_id, basis)?;
        let Some(draft) = basis.draft else {
            return Err(AnswerError::Changed);
        };
        crate::sends::replaceable(&self.record_path(question_id))?;
        let mut sends = carried.to_vec();
        sends.push(send);
        self.write_record(question_id, vec![draft], &sends)
    }

    /// Drops sends the caller holds proof of from the record of the answer kept for a question,
    /// and removes the pair too when `remove_when_empty` and the record, read under the store's
    /// lock, then names no other send. A send another command recorded meanwhile stays, and so does
    /// an answer stored meanwhile, which is not the one `draft` names: only the identifiers leave
    /// its record.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be written or removed,
    /// [`AnswerError::Unreadable`] when the record cannot be read, and
    /// [`AnswerError::NotPermitted`] when a permit is for another record.
    pub fn settle(
        &self,
        question_id: QuestionId,
        draft: Digest256,
        settled: &[ActionId],
        remove_when_empty: bool,
        leave: &Leave<'_>,
    ) -> Result<Settled> {
        leave
            .sends
            .require(&crate::sends::WRITTEN)
            .map_err(|_| AnswerError::NotPermitted)?;
        let _lock = self.hold()?;
        let now = self.pair(question_id)?;
        let Some(on_disk) = now.draft else {
            return Ok(Settled::Changed);
        };
        // An answer stored meanwhile is not the one `draft` names and stays, but the identifiers
        // this call holds proof of leave the record all the same: a send that is settled and stays
        // recorded would take a place for ever, since the host has no record of it to say so.
        let same = on_disk == draft;
        let remaining: Vec<ActionId> = now
            .sends
            .iter()
            .copied()
            .filter(|send| !settled.contains(send))
            .collect();
        if remaining.is_empty() {
            if remove_when_empty && same {
                self.remove_pair(question_id)?;
                return Ok(Settled::Removed);
            }
            self.remove_record(question_id)?;
        } else if remaining.len() != now.sends.len() {
            self.write_record(question_id, vec![on_disk], &remaining)?;
        }
        Ok(if same {
            Settled::Kept
        } else {
            Settled::Changed
        })
    }

    /// Removes the pair kept for a question after a send of the answer was taken: the answer and its
    /// record. Only the answer is compared, for the send that resolved the question makes every
    /// other send of it moot; an answer stored meanwhile is not the one `draft` names, and stays.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be removed.
    pub fn remove_after_result(&self, question_id: QuestionId, draft: Digest256) -> Result<()> {
        let _lock = self.hold()?;
        if self.answer_digest(&self.path(question_id))? == Some(draft) {
            self.remove_pair(question_id)?;
        }
        Ok(())
    }

    /// Removes the pair kept for a question when it is still `basis`, which is what a retirement
    /// after a read of the host decided from. Returns whether it was removed.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be removed.
    pub fn remove_if_unchanged(&self, question_id: QuestionId, basis: &Basis) -> Result<bool> {
        let _lock = self.hold()?;
        if self.unchanged(question_id, basis).is_err() {
            return Ok(false);
        }
        self.remove_pair(question_id)?;
        Ok(true)
    }

    /// Reads one kept answer with the pair it was read from, when one is kept.
    ///
    /// # Errors
    ///
    /// As [`Self::entries`].
    pub fn entry(&self, question_id: QuestionId) -> Result<Option<(AnswerDraft, Basis)>> {
        let path = self.path(question_id);
        let Some((draft, digest)) = read_draft_with_digest(&path)? else {
            return Ok(None);
        };
        let basis = self.pair_of(question_id, Some(digest))?;
        Ok(Some((draft, basis)))
    }

    /// Reads the pair kept for a question, whether or not an answer is kept.
    ///
    /// # Errors
    ///
    /// As [`Self::entries`].
    pub fn basis(&self, question_id: QuestionId) -> Result<Basis> {
        self.pair(question_id)
    }

    /// Returns every answer kept on this device with the pair it was read from, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when the directory cannot be read, and
    /// [`AnswerError::Unreadable`] when a kept answer or the record of its sends is not one this
    /// build wrote: the answer it describes is closed, and the failure names the file.
    pub fn entries(&self) -> Result<Vec<(AnswerDraft, Basis)>> {
        let mut entries = Vec::new();
        for path in self.answer_files()? {
            let Some((draft, digest)) = read_draft_with_digest(&path)? else {
                continue;
            };
            let basis = self.pair_of(draft.question_id, Some(digest))?;
            entries.push((draft, basis));
        }
        entries.sort_by_key(|(draft, _)| (draft.drafted_at_ms.get(), draft.question_id));
        Ok(entries)
    }

    /// Returns every answer kept on this device, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when the directory cannot be read, and
    /// [`AnswerError::Unreadable`] when a kept answer is not one this build wrote.
    pub fn drafts(&self) -> Result<Vec<AnswerDraft>> {
        let mut drafts = Vec::new();
        for path in self.answer_files()? {
            if let Some((draft, _)) = read_draft_with_digest(&path)? {
                drafts.push(draft);
            }
        }
        drafts.sort_by_key(|draft| (draft.drafted_at_ms.get(), draft.question_id));
        Ok(drafts)
    }

    /// Removes every record of sends that names no answer on disk, which describes no row. A record
    /// that cannot be read is left: nothing says what it described.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when the directory or a record cannot be removed.
    pub fn sweep(&self) -> Result<()> {
        let entries = std::fs::read_dir(&self.directory).map_err(|error| AnswerError::Store {
            path: Shown::root(&self.directory),
            fault: IoFault::from(error),
        })?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| AnswerError::Store {
                path: Shown::root(&self.directory),
                fault: IoFault::from(error),
            })?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str())
                == Some(crate::sends::EXTENSION)
            {
                records.push(path);
            }
        }
        if records.is_empty() {
            return Ok(());
        }
        let _lock = self.hold()?;
        for record in records {
            let Ok(Some(found)) = crate::sends::read(&record) else {
                continue;
            };
            let answer = record.with_extension(EXTENSION);
            let on_disk = self.answer_digest(&answer)?;
            if on_disk.is_some_and(|digest| found.record.draft.contains(&digest)) {
                continue;
            }
            std::fs::remove_file(&record).map_err(|error| AnswerError::Store {
                path: stored(&record),
                fault: IoFault::from(error),
            })?;
            kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(
                |error| AnswerError::Store {
                    path: Shown::root(&self.directory),
                    fault: IoFault::from(error),
                },
            )?;
        }
        Ok(())
    }

    /// Forgets the answer kept for one question, and its record of sends, when there is one: the
    /// person's own word that nothing more is wanted of them.
    ///
    /// # Errors
    ///
    /// Returns [`AnswerError::Store`] when it cannot be removed.
    pub fn discard(&self, question_id: QuestionId) -> Result<()> {
        let _lock = self.hold()?;
        self.remove_pair(question_id)
    }

    fn path(&self, question_id: QuestionId) -> PathBuf {
        self.directory.join(format!("{question_id}.{EXTENSION}"))
    }

    fn record_path(&self, question_id: QuestionId) -> PathBuf {
        self.directory
            .join(format!("{question_id}.{}", crate::sends::EXTENSION))
    }

    /// Checks the two permits are for the two records a begin or a recording writes.
    fn permitted(&self, leave: &Leave<'_>) -> Result<()> {
        leave
            .answers
            .require(&WRITTEN)
            .map_err(|_| AnswerError::NotPermitted)?;
        leave
            .sends
            .require(&crate::sends::WRITTEN)
            .map_err(|_| AnswerError::NotPermitted)
    }

    /// Takes the store's lock for a write.
    fn hold(&self) -> Result<std::fs::File> {
        let lock_path = self.directory.join(LOCK_NAME);
        Self::lock(&lock_path).map_err(|error| AnswerError::Store {
            path: stored(&lock_path),
            fault: IoFault::from(error),
        })
    }

    /// A name for a file this call writes, of its own.
    fn unique(&self, path: &Path) -> Result<String> {
        crate::drafts::fresh_uuid()
            .map(|unique| unique.to_string())
            .map_err(|error| AnswerError::Store {
                path: stored(path),
                fault: IoFault::from(std::io::Error::other(crate::shown!("{}", error))),
            })
    }

    /// Writes the record of a question's sends.
    fn write_record(
        &self,
        question_id: QuestionId,
        draft: Vec<Digest256>,
        sends: &[ActionId],
    ) -> Result<()> {
        let record_path = self.record_path(question_id);
        let unique = self.unique(&record_path)?;
        crate::sends::write(
            &self.directory,
            &record_path,
            &format!("{question_id}.{unique}"),
            &crate::sends::SendRecord {
                version: crate::sends::SEND_FORMAT,
                draft,
                sends: sends.to_vec(),
                sent_at_ms: kr_ipc::now_ms(),
            },
        )
    }

    /// Removes the answer, flushes, then removes its record. The caller holds the store's lock.
    fn remove_pair(&self, question_id: QuestionId) -> Result<()> {
        let path = self.path(question_id);
        let flush = || {
            kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(|error| {
                AnswerError::Store {
                    path: Shown::root(&self.directory),
                    fault: IoFault::from(error),
                }
            })
        };
        match std::fs::remove_file(&path) {
            Ok(()) => flush()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(AnswerError::Store {
                    path: stored(&path),
                    fault: IoFault::from(error),
                });
            }
        }
        crate::sends::reached(crate::sends::Stop::Removed, &self.directory)?;
        self.remove_record(question_id)
    }

    /// Removes the record of a question's sends, when there is one. The caller holds the lock.
    fn remove_record(&self, question_id: QuestionId) -> Result<()> {
        let record_path = self.record_path(question_id);
        match std::fs::remove_file(&record_path) {
            Ok(()) => kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(
                |error| AnswerError::Store {
                    path: Shown::root(&self.directory),
                    fault: IoFault::from(error),
                },
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AnswerError::Store {
                path: stored(&record_path),
                fault: IoFault::from(error),
            }),
        }
    }

    /// The digest of the kept answer's bytes at `path`, when a regular file is there. A link or a
    /// pipe holds no answer this build wrote.
    fn answer_digest(&self, path: &Path) -> Result<Option<Digest256>> {
        match std::fs::symlink_metadata(path) {
            Ok(about) if about.file_type().is_file() => {}
            Ok(_) => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AnswerError::Store {
                    path: stored(path),
                    fault: IoFault::from(error),
                });
            }
        }
        let bytes = kr_ipc::paths::read_owner_only_file(path, KEPT_LIMIT).map_err(|error| {
            AnswerError::Unreadable {
                path: stored(path),
                detail: Shown::ipc(&error),
            }
        })?;
        Ok(bytes.map(|bytes| crate::sends::digest(&bytes)))
    }

    /// The pair kept for a question as it is on disk now.
    fn pair(&self, question_id: QuestionId) -> Result<Basis> {
        let draft = self.answer_digest(&self.path(question_id))?;
        self.pair_of(question_id, draft)
    }

    /// The pair for an answer whose bytes have the digest `draft`: the record's digest, and the
    /// sends it names for that answer.
    fn pair_of(&self, question_id: QuestionId, draft: Option<Digest256>) -> Result<Basis> {
        let found = crate::sends::read(&self.record_path(question_id))?;
        let record = found.as_ref().map(|found| found.digest);
        let sends = match (draft, found) {
            (Some(draft), Some(found)) if found.record.draft.contains(&draft) => found.record.sends,
            _ => Vec::new(),
        };
        Ok(Basis {
            draft,
            record,
            sends,
        })
    }

    /// Checks, under the lock, that the pair is still the one a caller decided from.
    fn unchanged(&self, question_id: QuestionId, basis: &Basis) -> Result<()> {
        let now = self.pair(question_id)?;
        if now.draft == basis.draft && now.record == basis.record {
            Ok(())
        } else {
            Err(AnswerError::Changed)
        }
    }

    /// The kept answers' files in the directory.
    fn answer_files(&self) -> Result<Vec<PathBuf>> {
        let entries = std::fs::read_dir(&self.directory).map_err(|error| AnswerError::Store {
            path: Shown::root(&self.directory),
            fault: IoFault::from(error),
        })?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| AnswerError::Store {
                path: Shown::root(&self.directory),
                fault: IoFault::from(error),
            })?;
            let path = entry.path();
            // A partial write whose process did not live to rename it is not an answer.
            if path.extension().and_then(|extension| extension.to_str()) == Some(EXTENSION) {
                files.push(path);
            }
        }
        Ok(files)
    }

    /// Takes the store's lock for a write, at `path`, waiting [`LOCK_PATIENCE`] for another that is
    /// under way. Closing the file releases it.
    ///
    /// The lock file is opened without following a link and without waiting for a writer, and the
    /// handle must be a regular file: a link planted at the lock's name would have the open create
    /// its target, and a pipe would hold the open for ever.
    fn lock(path: &Path) -> std::io::Result<std::fs::File> {
        let file = kr_ipc::paths::open_lock_file(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                std::io::Error::other(Shown::said("the lock is not a regular file"))
            } else {
                error
            }
        })?;
        let deadline = Instant::now() + LOCK_PATIENCE;
        loop {
            match kr_flush::lock::try_exclusive(&file) {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
    }
}

/// Checks that the answer at `path`, if there is one, is one this build may replace: nothing there,
/// or a link or a pipe, which holds no answer this build wrote and is replaced by the rename; or a
/// regular file that is an answer of this format or of none. One of a later format, or one that
/// cannot be read, is not replaced.
fn replaceable(path: &Path) -> Result<()> {
    let about = match std::fs::symlink_metadata(path) {
        Ok(about) => about,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AnswerError::Store {
                path: stored(path),
                fault: IoFault::from(error),
            });
        }
    };
    if !about.file_type().is_file() {
        return Ok(());
    }
    let unreadable = |detail: Shown| AnswerError::Unreadable {
        path: stored(path),
        detail,
    };
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(path, KEPT_LIMIT)
        .map_err(|error| unreadable(Shown::ipc(&error)))?
    else {
        return Ok(());
    };
    let earlier: AnswerDraft = kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| unreadable(Shown::cbor(&error)))?;
    if earlier.version > ANSWER_FORMAT {
        return Err(unreadable(Shown::said(
            "it is of a later format than this build reads, so the new answer was not kept",
        )));
    }
    Ok(())
}

/// Reads one kept answer and the digest of its bytes, when one is there.
///
/// The path is one a listing found, so a failure names it whole only when its name is one this
/// store writes: whatever else is in the directory was put there by something else.
fn read_draft_with_digest(path: &Path) -> Result<Option<(AnswerDraft, Digest256)>> {
    // One handle, opened without following a link or waiting for a writer, and owner-only: a pipe
    // or a link under an answer's name is refused here and does not hold a listing open.
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(path, KEPT_LIMIT).map_err(|error| {
        AnswerError::Unreadable {
            path: stored(path),
            detail: Shown::ipc(&error),
        }
    })?
    else {
        return Ok(None);
    };
    let draft: AnswerDraft = kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| AnswerError::Unreadable {
            path: stored(path),
            detail: Shown::cbor(&error),
        })?;
    // A later release's format is not read as this one: the member that says so is the only one
    // this build knows to look at.
    if draft.version > ANSWER_FORMAT {
        return Err(AnswerError::Unreadable {
            path: stored(path),
            detail: Shown::said("it was kept by a later release of this client"),
        });
    }
    Ok(Some((draft, crate::sends::digest(&bytes))))
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
/// the next reconcile reads the host's record of the send, so it is never sent twice.
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
        other => !crate::error::is_definite(other.code()),
    }
}

/// What the host said of one send, from its receipt.
fn state_of(receipt: &Receipt) -> SendState {
    match receipt.state {
        ReceiptState::Applied => SendState::Applied,
        ReceiptState::Received | ReceiptState::Accepted | ReceiptState::Dispatching => {
            SendState::Pending
        }
        ReceiptState::Unknown => SendState::Unknown {
            revision: receipt.revision.get(),
            updated_at_ms: receipt.updated_at_ms,
        },
        ReceiptState::Refused | ReceiptState::Rejected => {
            SendState::Refused(receipt.error.0.as_ref().map(|error| error.code))
        }
    }
}

/// What a failed read of a send's receipt says of the send.
fn unread(error: &ClientError) -> SendState {
    match error {
        // The worker answers an identifier it has no receipt for with this text, and so does a
        // request it cannot place, so the text tells them apart.
        ClientError::Host(refused)
            if refused.code == ErrorCode::InvalidArgument
                && refused.message.starts_with("no receipt for action") =>
        {
            SendState::NoRecord
        }
        ClientError::Host(refused) | ClientError::Refused { error: refused, .. }
            if !keeps_the_answer(error) =>
        {
            SendState::Unreadable(ReadFailure::Refused(refused.code))
        }
        _ => SendState::Unreadable(ReadFailure::Failed),
    }
}

/// Asks the host about every send the record names, and returns what it said of each.
///
/// It decides nothing and removes nothing. It is asked after the question has been read, never
/// before: a worker holds the session from admitting an answer to recording its outcome, so a
/// question read as answered by a send has that send's receipt.
pub async fn learn<H: QuestionHost>(
    host: &H,
    session_id: SessionId,
    recorded: &[ActionId],
) -> Earlier {
    let mut sends = Vec::with_capacity(recorded.len());
    for action_id in recorded {
        let state = match host.receipt(session_id, *action_id).await {
            Ok(receipt) => state_of(&receipt),
            Err(error) => unread(&error),
        };
        sends.push((*action_id, state));
    }
    Earlier { sends }
}

/// Settles the send an attempt just made, from its own failure, when the client holds proof of
/// what became of it. It is a write, so it asks the caller for the leave again; when that is
/// refused the identifier stays. A send the host refused before it was admitted has no receipt for
/// a later reading to settle it by, so it stays until the answer is removed.
fn settle_own<K: Keeper>(
    keeper: &K,
    drafts: &AnswerDrafts,
    question_id: QuestionId,
    draft: Digest256,
    send: ActionId,
    remove_when_empty: bool,
) {
    let _ =
        keeper.keep(|leave| drafts.settle(question_id, draft, &[send], remove_when_empty, leave));
}

/// Sends a person's answer. The identifier it goes out under is recorded, with the answer, before
/// anything is written to the host, so a reconnect can ask the host what became of it.
///
/// `question` is the question as the person was shown it, and the answer is checked against its
/// form before anything else happens, so what is kept is an answer the host could take. When the
/// record holds sends already, the host is asked about each first ([`Attempt::earlier`]): one it
/// took is reported and nothing is sent; one it has and has not finished with waits; one whose
/// outcome it could not establish is named by this send, or, for a caller that asked
/// [`Quoting::AfterShown`], shown first.
///
/// A host that cannot be reached, and a lost, uncertain or transient failure, keep the answer and
/// its record on this device ([`Answered::Kept`]); the host's own word that it did not take the
/// answer settles the send, and removes the pair unless an earlier send is still unsettled, or the
/// host took a send another command recorded meanwhile, which the next reading names.
///
/// # Errors
///
/// Returns [`AnswerError::Form`] for an answer that does not fit the question,
/// [`AnswerError::Keeping`] when the leave to write could not be had,
/// [`AnswerError::Changed`] and [`AnswerError::Full`] when nothing could be recorded,
/// [`AnswerError::Host`] when the host refused it (the question already ended, or this device may
/// not answer it), and [`AnswerError::Store`] when the pair cannot be removed after the host took
/// the answer.
#[allow(clippy::too_many_arguments)]
pub async fn answer<H: QuestionHost + Sync, K: Keeper + Sync>(
    host: &H,
    keeper: &K,
    drafts: &AnswerDrafts,
    target: ActionTarget,
    question: &Question,
    answer: QuestionAnswer,
    now: TimestampMs,
    quoting: Quoting,
) -> Attempt<Answered> {
    let mut earlier = Earlier::default();
    let outcome = answered(
        host,
        keeper,
        drafts,
        target,
        question,
        answer,
        now,
        quoting,
        &mut earlier,
    )
    .await;
    Attempt { earlier, outcome }
}

#[allow(clippy::too_many_arguments)]
async fn answered<H: QuestionHost + Sync, K: Keeper + Sync>(
    host: &H,
    keeper: &K,
    drafts: &AnswerDrafts,
    target: ActionTarget,
    question: &Question,
    answer: QuestionAnswer,
    now: TimestampMs,
    quoting: Quoting,
    earlier: &mut Earlier,
) -> Result<Answered> {
    check_answer(question, &answer)
        .map_err(|_| AnswerError::Form(form_failure(question, &answer)))?;
    let draft = AnswerDraft {
        version: ANSWER_FORMAT,
        target,
        session_id: question.session_id,
        question_id: question.question_id,
        question_revision: question.revision,
        answer,
        drafted_at_ms: now,
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let basis = drafts.basis(draft.question_id)?;
    // What the host says of an earlier send comes before the question's state: a question the
    // person's own send answered is never read as answered by somebody else. A read that failed
    // decides nothing here: the attempt goes on, and the host refuses a send that lacks a quote it
    // needs.
    if !basis.sends().is_empty() {
        *earlier = learn(host, draft.session_id, basis.sends()).await;
        if let Some(taken) = earlier.taken() {
            // The host took it; a copy that cannot be removed now is retired by the next reading.
            let _ = drafts.remove_if_unchanged(draft.question_id, &basis);
            // The question is answered, so the connection stops accounting for the other sends of
            // the answer too.
            host.settle_earlier(draft.session_id, basis.sends()).await;
            return Ok(Answered::Taken(taken));
        }
        if let Some(waiting) = earlier.waiting() {
            return Ok(Answered::Waiting(waiting));
        }
        if let (Quoting::AfterShown(shown), Some(quote)) = (quoting, earlier.quote())
            && shown != Some(quote.action_id)
        {
            return Ok(Answered::Held(quote));
        }
    }
    let params = draft
        .submission(Some(question))
        .map_err(AnswerError::Retired)?;
    let carried = earlier.carried(basis.sends());
    let quote = earlier.quote();
    let kept = keeper
        .keep(|leave| drafts.begin(&draft, &basis, &carried, action_id, leave))
        .map_err(AnswerError::Keeping)??;
    if !earlier.is_empty() {
        host.learned(earlier);
    }
    let dispatch = Dispatch { action_id, quote };
    match host.answer(draft.target.clone(), params, dispatch).await {
        Ok(resolved) => {
            // The earlier sends of this answer are moot, and the connection stops accounting for
            // them whether or not the kept copy can be removed.
            host.settle_earlier(draft.session_id, &carried).await;
            // An answer kept earlier for this question has been superseded by this one.
            drafts.remove_after_result(draft.question_id, kept)?;
            Ok(Answered::Sent(Box::new(resolved)))
        }
        Err(failure) => {
            let keeps = keeps_the_answer(&failure.error);
            if failure.settled() {
                settle_own(keeper, drafts, draft.question_id, kept, action_id, !keeps);
            }
            if keeps {
                return Ok(Answered::Kept(draft));
            }
            if ended(&failure.error)
                && !carried.is_empty()
                && let Some(taken) = ended_after_send(host, drafts, &draft, kept, &carried).await?
            {
                return Ok(Answered::TakenAfterRefusal {
                    taken,
                    refused: action_id,
                });
            }
            Err(AnswerError::Host(*failure.error))
        }
    }
}

/// Whether the host refused a send because its question ended.
fn ended(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Host(refused)
            if matches!(
                refused.code,
                ErrorCode::QuestionResolved | ErrorCode::QuestionExpired
            )
    )
}

/// The host refused a send because its question ended. An earlier send of the answer may be the
/// reason, so every send still in the record is read again: one the host took is reported and the
/// pair removed, and otherwise the pair is removed only when no read failed. `sent` is the digest
/// of the answer this call sent: an answer another command stored meanwhile is not this one, and
/// stays. `carried` are the earlier sends this call knew of: only one of those is reported as the
/// earlier send the host took. A send another command made and the host took is not this call's to
/// report, since it cannot say which came first or whether that command's reply was lost; the pair
/// stays, and the next reading names the send.
async fn ended_after_send<H: QuestionHost>(
    host: &H,
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
    sent: Digest256,
    carried: &[ActionId],
) -> Result<Option<ActionId>> {
    let basis = drafts.basis(draft.question_id)?;
    let ours = basis.draft() == Some(sent);
    let again = if basis.sends().is_empty() {
        Earlier::default()
    } else {
        learn(host, draft.session_id, basis.sends()).await
    };
    match again.taken() {
        Some(taken) if carried.contains(&taken) => {
            if ours {
                let _ = drafts.remove_if_unchanged(draft.question_id, &basis);
            }
            host.settle_earlier(draft.session_id, carried).await;
            return Ok(Some(taken));
        }
        Some(_) => return Ok(None),
        None => {}
    }
    if ours && !again.failed() {
        let _ = drafts.remove_if_unchanged(draft.question_id, &basis)?;
    }
    Ok(None)
}

/// Decides, after a reconnect, what every kept answer is, and sends none of them.
///
/// A record of sends that names no kept answer is removed first, before any worker is read. Each
/// session a kept answer names is read once, resolved questions included. For a kept answer whose
/// question its session lists, the host is asked about every send its record names, after the
/// question was read: a send the host took retires the answer as taken; a send the host has and
/// has not finished with keeps it, waiting; and the question decides the rest. A draft whose
/// question is still pending at the revision the person answered is offered again and stays kept,
/// with what the host said of its earlier sends. A draft whose question ended or moved is retired:
/// it is not sent and it is no longer kept, unless a read of the host failed, in which case it
/// stays and is reported as unsettled. A draft whose question its session does not list is retired
/// as gone only when the host's record says the session ended, and is otherwise kept and reported
/// as unlisted.
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
    drafts.sweep()?;
    let kept = drafts.entries()?;
    let mut sessions: Vec<SessionId> = kept.iter().map(|(draft, _)| draft.session_id).collect();
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
    for (draft, _) in &kept {
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
    for (draft, basis) in kept {
        let question = current
            .iter()
            .find(|question| question.question_id == draft.question_id);
        let earlier = if question.is_some() && !basis.sends().is_empty() {
            learn(host, draft.session_id, basis.sends()).await
        } else {
            Earlier::default()
        };
        if let Some(action_id) = earlier.taken() {
            host.settle_earlier(draft.session_id, basis.sends()).await;
            if drafts.remove_if_unchanged(draft.question_id, &basis)? {
                reconciled.push(Reconciled::Taken { draft, action_id });
            } else {
                reconciled.push(Reconciled::Unsettled(draft));
            }
            continue;
        }
        match draft.submission(question) {
            Ok(_) => match earlier.waiting() {
                Some(action_id) => reconciled.push(Reconciled::Waiting { draft, action_id }),
                None => reconciled.push(Reconciled::Offered { draft, earlier }),
            },
            Err(Retired::Gone) if !session_ended(draft.session_id) => {
                reconciled.push(Reconciled::Unlisted(draft));
            }
            // A read that failed leaves what became of an earlier send open, so the answer is not
            // retired on the question alone.
            Err(_) if earlier.failed() => reconciled.push(Reconciled::Unsettled(draft)),
            Err(reason) => {
                if drafts.remove_if_unchanged(draft.question_id, &basis)? {
                    reconciled.push(Reconciled::Retired { draft, reason });
                } else {
                    reconciled.push(Reconciled::Unsettled(draft));
                }
            }
        }
    }
    Ok(reconciled)
}

/// Sends one kept answer, for a person who chose to send it.
///
/// `draft` and `basis` are the answer and the pair as the caller read them from the store
/// ([`AnswerDrafts::entry`]). The question is read again first, and the host is asked about every
/// send the record names: one it took is reported and nothing is sent; one it has and has not
/// finished with waits; a draft whose question ended or moved is retired rather than sent, unless a
/// read of the host failed; and an uncertain outcome is named by the send, or shown first for a
/// caller that asked [`Quoting::AfterShown`]. The send is recorded before it goes. A draft that is
/// sent, or that the host refuses because its question ended once every send was read, is no longer
/// kept, unless the host took a send another command recorded meanwhile, which the next reading
/// names; any other refusal settles this send and keeps the draft.
///
/// # Errors
///
/// Returns [`AnswerError::Retired`] when the question ended or moved, [`AnswerError::Unlisted`] when
/// its session does not list the question and the host's record does not say the session ended,
/// [`AnswerError::Unsettled`] when the question ended and an earlier send could not be asked about,
/// [`AnswerError::Changed`] and [`AnswerError::Full`] when nothing could be recorded,
/// [`AnswerError::Host`] when the host refused or could not be reached, and [`AnswerError::Store`]
/// when the store cannot be updated.
pub async fn send<H: QuestionHost + Sync, K: Keeper + Sync>(
    host: &H,
    keeper: &K,
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
    basis: &Basis,
    quoting: Quoting,
) -> Attempt<Answered> {
    let mut earlier = Earlier::default();
    let outcome = sent(host, keeper, drafts, draft, basis, quoting, &mut earlier).await;
    Attempt { earlier, outcome }
}

async fn sent<H: QuestionHost + Sync, K: Keeper + Sync>(
    host: &H,
    keeper: &K,
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
    basis: &Basis,
    quoting: Quoting,
    earlier: &mut Earlier,
) -> Result<Answered> {
    let questions = host.questions(draft.session_id).await?;
    let current = questions
        .iter()
        .find(|question| question.question_id == draft.question_id);
    if current.is_some() && !basis.sends().is_empty() {
        *earlier = learn(host, draft.session_id, basis.sends()).await;
        if let Some(taken) = earlier.taken() {
            let _ = drafts.remove_if_unchanged(draft.question_id, basis);
            host.settle_earlier(draft.session_id, basis.sends()).await;
            return Ok(Answered::Taken(taken));
        }
    }
    let params = match draft.submission(current) {
        Ok(params) => params,
        // A question its session does not list is gone only when the host's record of the
        // session says the session ended.
        Err(Retired::Gone) if !host.session_ended(draft.session_id).await? => {
            return Err(AnswerError::Unlisted);
        }
        Err(_) if earlier.failed() => return Err(AnswerError::Unsettled),
        Err(reason) => {
            // An answer another command stored meanwhile is not the one this retires. One that is
            // already gone leaves nothing to report but why the question cannot be answered.
            if !drafts.remove_if_unchanged(draft.question_id, basis)?
                && drafts.basis(draft.question_id)?.draft().is_some()
            {
                return Err(AnswerError::Changed);
            }
            return Err(AnswerError::Retired(reason));
        }
    };
    if let Some(waiting) = earlier.waiting() {
        return Ok(Answered::Waiting(waiting));
    }
    if let (Quoting::AfterShown(shown), Some(quote)) = (quoting, earlier.quote())
        && shown != Some(quote.action_id)
    {
        return Ok(Answered::Held(quote));
    }
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let carried = earlier.carried(basis.sends());
    let quote = earlier.quote();
    let Some(digest) = basis.draft else {
        return Err(AnswerError::Changed);
    };
    keeper
        .keep(|leave| drafts.record_send(draft.question_id, basis, &carried, action_id, leave))
        .map_err(AnswerError::Keeping)??;
    if !earlier.is_empty() {
        host.learned(earlier);
    }
    let dispatch = Dispatch { action_id, quote };
    match host.answer(draft.target.clone(), params, dispatch).await {
        Ok(resolved) => {
            host.settle_earlier(draft.session_id, &carried).await;
            drafts.remove_after_result(draft.question_id, digest)?;
            Ok(Answered::Sent(Box::new(resolved)))
        }
        Err(failure) => {
            if failure.settled() {
                settle_own(keeper, drafts, draft.question_id, digest, action_id, false);
            }
            if ended(&failure.error)
                && let Some(taken) = ended_after_send(host, drafts, draft, digest, &carried).await?
            {
                return Ok(Answered::TakenAfterRefusal {
                    taken,
                    refused: action_id,
                });
            }
            Err(AnswerError::Host(*failure.error))
        }
    }
}

#[cfg(test)]
mod tests;
