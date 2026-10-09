//! The agent's questions, read and answered on the session's own worker.
//!
//! A session's questions belong to its worker: the worker verifies who asked, holds the question
//! through a restart of the host's daemon and resolves it once, for whoever answers first. The
//! daemon on this machine carries neither `question.read` nor `question.answer` for this computer,
//! so the application reaches the worker over the link it already holds for the session's agent
//! calls, as `kr question` does.
//!
//! An answer a person gave while the worker could not be reached is kept on this device and sent
//! only when the person sends it. Section 11: offline answers remain drafts, and a reconnect never
//! submits them. The rules are the client library's ([`kr_client::answers`]); what is here is the
//! connection they run over, the place the answers are kept, and what the page is told.
//!
//! The answers are kept in a directory for each environment, beside the answers the command line
//! keeps and not in them: an answer names the environment it was given to, and a store with one
//! directory per environment cannot be settled against a host it was not given to.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use kr_client::answers::{
    self, AnswerDraft, AnswerDrafts, AnswerError, Answered, QuestionHost, Retired,
};
use kr_client::{ClientError, Session};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{EnvironmentId, QuestionId, QuestionRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{Question, QuestionAnswerParams, QuestionResolveResult, QuestionState};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState};
use serde::{Deserialize, Serialize};

use crate::agent::{Link, WorkerLinks, ends_the_link};
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// A question as the page last read it, with the place an answer to it goes.
///
/// An answer is checked against the question as the person was shown it, and an answer kept while
/// the worker is out of reach is kept against it. The page never supplies the question: it names
/// one by identifier and revision, and this is where the question comes from.
#[derive(Clone, Debug)]
struct Shown {
    question: Question,
    target: ActionTarget,
}

/// The questions this application has read, and the answers it keeps.
#[derive(Debug, Default)]
pub struct QuestionDesk {
    /// Where the answers are kept, once the application's data directory is known.
    root: Mutex<Option<PathBuf>>,
    /// Every question read so far, by identifier.
    shown: Mutex<HashMap<QuestionId, Shown>>,
    /// One operation on the kept answers at a time: an answer is checked, sent and removed under
    /// it, so two presses cannot interleave their steps.
    gate: tokio::sync::Mutex<()>,
}

impl QuestionDesk {
    /// Names the directory the kept answers live in.
    pub fn keep_at(&self, root: PathBuf) {
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
    }

    fn root(&self) -> Result<PathBuf> {
        self.root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unsupported(
                    "answers cannot be kept on this device: it has no place for them",
                )
            })
    }

    /// The store for one environment's answers.
    fn store(
        &self,
        environment_id: EnvironmentId,
    ) -> std::result::Result<AnswerDrafts, AnswerError> {
        let root = self.root().map_err(|error| AnswerError::Store {
            path: kr_client::shown::Shown::said("the answers kept on this device"),
            fault: kr_client::shown::IoFault::from(std::io::Error::other(error.message)),
        })?;
        AnswerDrafts::open(root.join(environment_id.to_string()))
    }

    /// Every environment that has a store of kept answers.
    fn environments(&self) -> Result<Vec<EnvironmentId>> {
        let root = self.root()?;
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(CommandError::local_failure(format!(
                    "the answers kept on this device cannot be listed: {error}"
                )));
            }
        };
        Ok(entries
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse().ok())
            })
            .collect())
    }

    fn remember(&self, questions: &[Question], target: &ActionTarget) {
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        for question in questions {
            shown.insert(
                question.question_id,
                Shown {
                    question: question.clone(),
                    target: target.clone(),
                },
            );
        }
    }

    fn recall(&self, question_id: QuestionId) -> Option<Shown> {
        self.shown
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&question_id)
            .cloned()
    }

    /// Every answer kept on this device, in every environment, oldest first.
    fn kept(&self) -> std::result::Result<Vec<AnswerDraft>, AnswerError> {
        let environments = self.environments().map_err(|error| AnswerError::Store {
            path: kr_client::shown::Shown::said("the answers kept on this device"),
            fault: kr_client::shown::IoFault::from(std::io::Error::other(error.message)),
        })?;
        let mut all = Vec::new();
        for environment_id in environments {
            all.extend(self.store(environment_id)?.drafts()?);
        }
        all.sort_by_key(|draft| (draft.drafted_at_ms.get(), draft.question_id));
        Ok(all)
    }

    /// The kept answer to one question, when there is one.
    fn kept_for(
        &self,
        question_id: QuestionId,
    ) -> std::result::Result<Option<AnswerDraft>, AnswerError> {
        Ok(self
            .kept()?
            .into_iter()
            .find(|draft| draft.question_id == question_id))
    }
}

/// The worker's side of the answers library, over the link held for the session.
struct LinkHost<'a> {
    links: &'a WorkerLinks,
    state: &'a AppState,
    /// What the worker said of the answer it took, when it took one.
    taken: Mutex<Option<QuestionResolveResult>>,
}

impl<'a> LinkHost<'a> {
    fn new(links: &'a WorkerLinks, state: &'a AppState) -> Self {
        Self {
            links,
            state,
            taken: Mutex::new(None),
        }
    }

    fn taken(&self) -> Option<QuestionResolveResult> {
        self.taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The link to the session's worker, with a failure to make one in the library's terms.
    ///
    /// A session whose worker is not running is the host's refusal of an unknown session; a worker
    /// that could not be reached or would not prove its key is a connection that ended. Nothing
    /// else is said, so a short failure never reads as the session having gone.
    async fn link(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<std::sync::Arc<Link>, ClientError> {
        self.links
            .link(session_id)
            .await
            .map_err(|error| match error.code {
                ErrorCode::UnknownSession => {
                    ClientError::Host(ProtocolError::new(ErrorCode::UnknownSession, error.message))
                }
                _ => ClientError::ConnectionEnded,
            })
    }

    fn settle<T>(
        &self,
        session_id: SessionId,
        link: &std::sync::Arc<Link>,
        answer: std::result::Result<T, ClientError>,
    ) -> std::result::Result<T, ClientError> {
        if let Err(error) = &answer
            && ends_the_link(error)
        {
            self.links.forget(session_id, link);
        }
        answer
    }
}

impl QuestionHost for LinkHost<'_> {
    async fn questions(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Vec<Question>, ClientError> {
        let link = self.link(session_id).await?;
        let answer = <Session as QuestionHost>::questions(&link.session, session_id).await;
        self.settle(session_id, &link, answer)
    }

    async fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> std::result::Result<QuestionResolveResult, ClientError> {
        let session_id = params.session_id;
        let link = self.link(session_id).await?;
        let answer = <Session as QuestionHost>::answer(&link.session, target, params).await;
        if let Ok(resolved) = &answer {
            *self.taken.lock().unwrap_or_else(PoisonError::into_inner) = Some(resolved.clone());
        }
        self.settle(session_id, &link, answer)
    }

    /// Whether the host's record of the session says it ended.
    ///
    /// The worker is gone for a session whose descriptor is not published, and that is all a
    /// missing worker says. The daemon's record says more: a closure it holds, or no record of a
    /// session whose descriptor is gone too. A daemon that cannot be asked establishes nothing, and
    /// the error says so: no answer is retired on a short failure.
    async fn session_ended(&self, session_id: SessionId) -> std::result::Result<bool, ClientError> {
        let session = self
            .state
            .session()
            .map_err(|_| ClientError::ConnectionEnded)?;
        match session
            .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
            .await
        {
            Ok(read) => {
                Ok(read.session.closure.0.is_some() || read.session.state == SessionState::Closed)
            }
            Err(ClientError::Host(refused)) if refused.code == ErrorCode::SessionClosed => Ok(true),
            Err(ClientError::Host(refused)) if refused.code == ErrorCode::UnknownSession => {
                match self.links.serves(session_id) {
                    Ok(published) => Ok(!published),
                    Err(_) => Err(ClientError::ConnectionEnded),
                }
            }
            Err(error) => Err(error),
        }
    }
}

/// What a person's answer came to, as the page is told.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Answer {
    /// The worker took the answer. `resolution` is the worker's own record of it. `leftover` is
    /// true when an answer kept earlier for the question could not be removed afterwards: it stays
    /// until the next settling finds the question answered and the person dismisses it, and it is
    /// never sent again.
    Taken {
        /// What the worker recorded.
        resolution: QuestionResolveResult,
        /// Whether a kept copy of an answer to this question could not be removed.
        leftover: bool,
    },
    /// The worker could not take it, so it is kept on this device and nothing has been sent.
    Kept {
        /// The answer, as it is kept.
        draft: AnswerDraft,
    },
}

/// One kept answer and where its question stands now.
#[derive(Debug, Serialize)]
pub struct Settled {
    /// The answer, as it is kept.
    pub draft: AnswerDraft,
    /// Where it stands.
    #[serde(flatten)]
    pub standing: Standing,
}

/// What the worker says of a kept answer's question.
#[derive(Debug, Serialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum Standing {
    /// The question is pending at the revision the person answered. It can be sent.
    Offered,
    /// The session does not list the question, and the host's record does not say the session
    /// ended. The answer stays kept and cannot be sent.
    Unlisted,
    /// The question ended while the answer was kept. The answer is kept, unsent, until the person
    /// dismisses it.
    Ended {
        /// How it ended.
        state: QuestionState,
    },
    /// The question is pending at a revision the person was not shown.
    Moved {
        /// The revision it is at now.
        revision: QuestionRevision,
    },
    /// The session ended, and the question with it.
    Gone,
}

impl From<Retired> for Standing {
    fn from(reason: Retired) -> Self {
        match reason {
            Retired::Ended(state) => Self::Ended { state },
            Retired::Moved { revision } => Self::Moved { revision },
            Retired::Gone => Self::Gone,
        }
    }
}

/// The parameters of the commands that name one kept answer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeptRef {
    /// The question the answer is for.
    pub question_id: QuestionId,
    /// When the answer was given, as the page was shown it. An answer kept again for the same
    /// question since carries another time, and the command that names the old one does nothing.
    pub drafted_at_ms: TimestampMs,
}

/// The parameters of the command that settles the kept answers of one session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SettleParams {
    /// The session.
    pub session_id: SessionId,
}

/// Maps the library's failure to the one the page reads.
fn failure(error: AnswerError) -> CommandError {
    match error {
        AnswerError::Form(shown) => CommandError::invalid(shown.to_string()),
        AnswerError::Host(error) => CommandError::from(error),
        other => CommandError::new(other.code(), other.to_string()),
    }
}

/// Answers a question, or keeps the answer on this device when the worker cannot take it.
///
/// # Errors
///
/// Returns the worker's refusal, a form the question does not take, or a store that failed while
/// the answer had to be kept.
pub async fn answer(
    state: &AppState,
    links: &WorkerLinks,
    params: QuestionAnswerParams,
) -> Result<Answer> {
    let desk = state.questions();
    let _gate = desk.gate.lock().await;
    let Some(shown) = desk.recall(params.question_id) else {
        return Err(CommandError::new(
            ErrorCode::DraftConflict,
            "that question has not been read here, so it cannot be answered: read it again",
        ));
    };
    if shown.question.session_id != params.session_id
        || shown.question.revision != params.expected_revision
    {
        return Err(CommandError::new(
            ErrorCode::DraftConflict,
            "that question changed since it was read: read it again",
        ));
    }
    let store = desk.store(shown.target.environment_id).map_err(failure)?;
    let host = LinkHost::new(links, state);
    let answered = answers::answer(
        Some(&host),
        &store,
        shown.target.clone(),
        &shown.question,
        params.answer,
        kr_ipc::now_ms(),
    )
    .await;
    match (answered, host.taken()) {
        (Ok(Answered::Sent(resolution)), _) => Ok(Answer::Taken {
            resolution: *resolution,
            leftover: false,
        }),
        (Ok(Answered::Kept(draft)), _) => Ok(Answer::Kept { draft }),
        // The worker took it and removing the copy kept earlier failed: the answer was taken, and
        // the page is told so.
        (Err(AnswerError::Store { .. } | AnswerError::Unreadable { .. }), Some(resolution)) => {
            Ok(Answer::Taken {
                resolution,
                leftover: true,
            })
        }
        (Err(error), _) => Err(failure(error)),
    }
}

/// Every answer kept on this device.
///
/// # Errors
///
/// Returns the store's failure when a kept answer cannot be read.
pub async fn kept(state: &AppState) -> Result<Vec<AnswerDraft>> {
    let desk = state.questions();
    let _gate = desk.gate.lock().await;
    desk.kept().map_err(failure)
}

/// Says, for every answer kept for one session, where its question stands now. Sends nothing and
/// removes nothing.
///
/// # Errors
///
/// Returns why the session's questions could not be read. Nothing is then said of any answer.
pub async fn settle(
    state: &AppState,
    links: &WorkerLinks,
    params: &SettleParams,
) -> Result<Vec<Settled>> {
    let desk = state.questions();
    let _gate = desk.gate.lock().await;
    let drafts: Vec<AnswerDraft> = desk
        .kept()
        .map_err(failure)?
        .into_iter()
        .filter(|draft| draft.session_id == params.session_id)
        .collect();
    if drafts.is_empty() {
        return Ok(Vec::new());
    }
    let host = LinkHost::new(links, state);
    let current = match host.questions(params.session_id).await {
        Ok(questions) => questions,
        // A session whose worker is gone lists no question; whether it ended is the record's to say.
        Err(ClientError::Host(refused)) if refused.code == ErrorCode::UnknownSession => Vec::new(),
        Err(error) => return Err(CommandError::from(error)),
    };
    let mut settled = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let question = current
            .iter()
            .find(|question| question.question_id == draft.question_id);
        let standing = match draft.submission(question) {
            Ok(_) => Standing::Offered,
            Err(Retired::Gone) => {
                if host
                    .session_ended(draft.session_id)
                    .await
                    .map_err(CommandError::from)?
                {
                    Standing::Gone
                } else {
                    Standing::Unlisted
                }
            }
            Err(reason) => reason.into(),
        };
        settled.push(Settled { draft, standing });
    }
    Ok(settled)
}

/// Sends one kept answer, which is the one way a kept answer is ever sent.
///
/// The question is read again first. An answer whose question ended or moved is not sent, and it
/// stays kept until the person dismisses it.
///
/// # Errors
///
/// Returns why the answer was not sent: no such kept answer, a question that ended or moved, or
/// the worker's refusal.
pub async fn send(state: &AppState, links: &WorkerLinks, which: &KeptRef) -> Result<Answer> {
    let desk = state.questions();
    let _gate = desk.gate.lock().await;
    let Some(draft) = desk.kept_for(which.question_id).map_err(failure)? else {
        return Err(CommandError::invalid(
            "no answer to that question is kept on this device",
        ));
    };
    if draft.drafted_at_ms != which.drafted_at_ms {
        return Err(CommandError::new(
            ErrorCode::DraftConflict,
            "the answer kept for that question has changed: read the kept answers again",
        ));
    }
    let host = LinkHost::new(links, state);
    let questions = host
        .questions(draft.session_id)
        .await
        .map_err(CommandError::from)?;
    let current = questions
        .iter()
        .find(|question| question.question_id == draft.question_id);
    let params = match draft.submission(current) {
        Ok(params) => params,
        Err(Retired::Gone)
            if !host
                .session_ended(draft.session_id)
                .await
                .map_err(CommandError::from)? =>
        {
            return Err(failure(AnswerError::Unlisted));
        }
        Err(reason) => return Err(failure(AnswerError::Retired(reason))),
    };
    let resolution = host
        .answer(draft.target.clone(), params)
        .await
        .map_err(CommandError::from)?;
    // The worker has the answer. Taking the copy away is the last step, and a failure of it is
    // told rather than hidden: a copy left behind is retired by the next settling.
    let leftover = desk
        .store(draft.target.environment_id)
        .and_then(|store| store.discard(draft.question_id))
        .is_err();
    Ok(Answer::Taken {
        resolution,
        leftover,
    })
}

/// Dismisses one kept answer, if it is still the one the person was shown.
///
/// Answers whether it was removed. An answer kept again for the same question since carries another
/// time and is left where it is.
///
/// # Errors
///
/// Returns the store's failure when the answer cannot be read or removed.
pub async fn dismiss(state: &AppState, which: &KeptRef) -> Result<bool> {
    let desk = state.questions();
    let _gate = desk.gate.lock().await;
    let Some(draft) = desk.kept_for(which.question_id).map_err(failure)? else {
        return Ok(false);
    };
    if draft.drafted_at_ms != which.drafted_at_ms {
        return Ok(false);
    }
    desk.store(draft.target.environment_id)
        .and_then(|store| store.discard(draft.question_id))
        .map_err(failure)?;
    Ok(true)
}

/// Remembers what a read of a session's questions found, with where an answer to each goes.
pub fn remember(state: &AppState, questions: &[Question], target: &ActionTarget) {
    state.questions().remember(questions, target);
}

/// The place for kept answers under an application data directory.
#[must_use]
pub fn kept_in(data: &Path) -> PathBuf {
    data.join("kept-answers")
}

/// The target a session's worker takes a question's answer on: the session at its epoch.
#[must_use]
pub(crate) fn target_of(link: &Link) -> ActionTarget {
    ActionTarget {
        environment_id: link.descriptor.environment_id,
        session_id: Nullable::some(link.descriptor.session_id),
        session_epoch: Nullable::some(link.descriptor.session_epoch),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}
