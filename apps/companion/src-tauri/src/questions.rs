//! The agent's questions, read and answered on the session's own worker.
//!
//! A session's questions belong to its worker: the worker verifies who asked, holds the question
//! through a restart of the host's daemon and resolves it once, for whoever answers first. The
//! daemon on this machine carries neither `question.read` nor `question.answer` for this computer,
//! so on this machine's own host the application reaches the worker over the link it already holds
//! for the session's agent calls, as `kr question` does. On a host this device is paired with, the
//! daemon is the way in: its network ingress serves `question.read` and forwards `question.answer`
//! to the worker, under the rights the pairing granted. Which of the two a question goes by is
//! decided from the connection the application has when the question is read, and an answer is
//! kept or sent only against the host it was given to.
//!
//! An answer a person gave while the worker could not be reached is kept on this device and sent
//! only when the person sends it. Section 11: offline answers remain drafts, and a reconnect never
//! submits them. The rules are the client library's ([`kr_client::answers`]); what is here is the
//! connection they run over, the place the answers are kept, and what the page is told.
//!
//! The answers are kept in a directory for each environment, beside the answers the command line
//! keeps and not in them: an answer names the environment it was given to, and a store with one
//! directory per environment cannot be settled against a host it was not given to. A second window
//! of the application is a second process over the same directory, and what changes the kept
//! answers (answering, sending, dismissing) takes a lock every window holds ([`QuestionDesk::turn`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::answers::{
    self, AnswerDraft, AnswerDrafts, AnswerError, Answered, QuestionHost, Retired,
};
use kr_client::{ClientError, Session};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{EnvironmentId, QuestionId, QuestionRevision, SessionId};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswerParams, QuestionReadParams, QuestionReadResult, QuestionResolveResult,
    QuestionState,
};
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
    /// One operation that changes the kept answers at a time in this process: an answer is checked,
    /// sent and removed under it, so two presses cannot interleave their steps.
    gate: tokio::sync::Mutex<()>,
    /// How long an operation waits for another window of the application that is changing the kept
    /// answers, and how long one exchange with a worker may take, when they are not the defaults.
    patience: Mutex<Patience>,
}

/// The two waits, each the default until a test sets it.
#[derive(Debug, Default, Clone, Copy)]
struct Patience {
    window: Option<Duration>,
    exchange: Option<Duration>,
}

/// How long an operation waits for another window of the application that is changing the kept
/// answers. The longest the other window holds them is an answer that reads the question and then
/// sends the answer, two exchanges of [`DEFAULT_EXCHANGE`] at most.
const DEFAULT_WINDOW_WAIT: Duration = Duration::from_secs(60);

/// How long one exchange with a worker or a host may take. An answer that has not been answered by
/// then has an outcome nobody knows, and is kept as such.
const DEFAULT_EXCHANGE: Duration = Duration::from_secs(20);

/// The file in the kept answers' directory that a window holds while it changes them. A second
/// window of the application is a second process, so the in-process gate cannot order it.
const WINDOWS_LOCK: &str = ".windows.lock";

/// The right to change the kept answers: this process's turn, and every other window's. It ends
/// when the value is dropped.
struct Turn<'a> {
    _process: tokio::sync::MutexGuard<'a, ()>,
    _windows: std::fs::File,
}

impl QuestionDesk {
    /// Names the directory the kept answers live in.
    pub fn keep_at(&self, root: PathBuf) {
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
    }

    /// Sets how long an operation waits for another window that is changing the kept answers.
    pub fn wait_at_most(&self, patience: Duration) {
        self.patience
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .window = Some(patience);
    }

    /// Sets how long one exchange with a worker or a host may take.
    pub fn exchange_within(&self, patience: Duration) {
        self.patience
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .exchange = Some(patience);
    }

    fn exchange(&self) -> Duration {
        self.patience
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .exchange
            .unwrap_or(DEFAULT_EXCHANGE)
    }

    /// Waits for this process's turn to change the kept answers, and then for every other window's.
    ///
    /// An answer is checked against what is kept, sent and removed, and a second window that kept or
    /// removed an answer between those steps would have its answer removed by the first, or sent
    /// again. So no two windows are in the middle of one together. Only what changes the kept
    /// answers takes the turn: listing them and asking where their questions stand change nothing.
    ///
    /// # Errors
    ///
    /// Returns a stated failure when another window still uses the kept answers after the wait, and
    /// nothing has been changed.
    async fn turn(&self) -> Result<Turn<'_>> {
        let process = self.gate.lock().await;
        let root = self.root()?;
        let patience = self
            .patience
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .window
            .unwrap_or(DEFAULT_WINDOW_WAIT);
        let windows = tokio::task::spawn_blocking(move || hold_across_windows(&root, patience))
            .await
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "the kept answers could not be locked: {error}"
                ))
            })??;
        Ok(Turn {
            _process: process,
            _windows: windows,
        })
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

    /// Remembers what a read of a session's questions found, with where an answer to each goes.
    ///
    /// A read of every question replaces what was remembered of the session: a question the worker
    /// no longer lists is not one the page can answer. A read of one question replaces only that
    /// one, so reading a single question does not make the session's others unanswerable until the
    /// next full read.
    fn remember(
        &self,
        session_id: SessionId,
        only: Option<QuestionId>,
        questions: &[Question],
        target_for: impl Fn(&Question) -> ActionTarget,
    ) {
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        match only {
            None => shown.retain(|_, held| held.question.session_id != session_id),
            Some(question_id) => {
                shown.remove(&question_id);
            }
        }
        for question in questions {
            shown.insert(
                question.question_id,
                Shown {
                    question: question.clone(),
                    target: target_for(question),
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

    /// Every answer kept on this device that can be read, in every environment, oldest first, and
    /// how many environments had answers that could not be.
    ///
    /// One environment's unreadable answers do not hide another's.
    fn kept(&self) -> Kept {
        let Ok(environments) = self.environments() else {
            return Kept {
                answers: Vec::new(),
                unreadable: 1,
            };
        };
        let mut answers = Vec::new();
        let mut unreadable = 0;
        for environment_id in environments {
            match self.store(environment_id).and_then(|store| store.drafts()) {
                Ok(held) => answers.extend(held),
                Err(_) => unreadable += 1,
            }
        }
        answers.sort_by_key(|draft| (draft.drafted_at_ms.get(), draft.question_id));
        Kept {
            answers,
            unreadable,
        }
    }

    /// The kept answer to one question, when there is one.
    ///
    /// # Errors
    ///
    /// Returns why the environments' answers could not all be read: an answer that cannot be read
    /// is neither sent nor removed on a guess.
    fn kept_for(
        &self,
        question_id: QuestionId,
    ) -> std::result::Result<Option<AnswerDraft>, AnswerError> {
        let held = self.kept();
        if let Some(found) = held
            .answers
            .into_iter()
            .find(|draft| draft.question_id == question_id)
        {
            return Ok(Some(found));
        }
        if held.unreadable > 0 {
            return Err(AnswerError::Store {
                path: kr_client::shown::Shown::said("the answers kept on this device"),
                fault: kr_client::shown::IoFault::from(std::io::Error::other(
                    "some of them could not be read",
                )),
            });
        }
        Ok(None)
    }
}

/// The kept answers that could be read, and how many environments held some that could not.
#[derive(Debug, Serialize)]
pub struct Kept {
    /// The answers, oldest first.
    pub answers: Vec<AnswerDraft>,
    /// How many environments' answers could not be read. They are left where they are.
    pub unreadable: usize,
}

/// Where a session's questions go from this application now.
#[derive(Clone)]
enum Route {
    /// The host on this machine: the session's worker, over the link held for it.
    Local,
    /// A host this device is paired with: its daemon forwards the question to the worker, under the
    /// rights the pairing granted.
    Paired {
        environment_id: EnvironmentId,
        session: Arc<Session>,
    },
}

impl Route {
    /// The route the connection the application has now gives. With no connection the application
    /// is on its own machine's route, where the worker is reached without the daemon.
    fn of(state: &AppState) -> Self {
        match state.paired_snapshot() {
            Ok((_, environment_id, session)) => Self::Paired {
                environment_id,
                session,
            },
            Err(_) => Self::Local,
        }
    }
}

/// The host's side of the answers library, over whichever route the connection gives.
struct Host<'a> {
    links: &'a WorkerLinks,
    state: &'a AppState,
    route: Route,
    exchange: Duration,
    /// What the worker said of the answer it took, when it took one.
    taken: Mutex<Option<QuestionResolveResult>>,
}

impl<'a> Host<'a> {
    fn new(links: &'a WorkerLinks, state: &'a AppState) -> Self {
        Self {
            links,
            state,
            route: Route::of(state),
            exchange: state.questions().exchange(),
            taken: Mutex::new(None),
        }
    }

    fn taken(&self) -> Option<QuestionResolveResult> {
        self.taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Runs one exchange within its time. One that has not ended by then has no known outcome, which
    /// is what a connection that ended says.
    async fn within<T>(
        &self,
        call: impl std::future::Future<Output = std::result::Result<T, ClientError>>,
    ) -> std::result::Result<T, ClientError> {
        tokio::time::timeout(self.exchange, call)
            .await
            .unwrap_or(Err(ClientError::ConnectionEnded))
    }

    /// The environment the host this route reaches belongs to, for the session.
    async fn environment(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<EnvironmentId, ClientError> {
        match &self.route {
            // The daemon on this machine stamps its environment on the connection, and that is the
            // environment of every session here, so a session whose worker has gone is still
            // known to belong to it. With no daemon connection the worker's own descriptor says.
            Route::Local => match self.state.environment_id() {
                Ok(environment_id) => Ok(environment_id),
                Err(_) => Ok(self.link(session_id).await?.descriptor.environment_id),
            },
            Route::Paired { environment_id, .. } => Ok(*environment_id),
        }
    }

    /// The link to the session's worker on this machine, with a failure to make one in the
    /// library's terms.
    ///
    /// A worker whose descriptor is not published is the host's refusal of an unknown session only
    /// when the daemon's record agrees that the session ended; a worker that is restarting, that
    /// could not be reached or would not prove its key is a connection that ended. Nothing else is
    /// said, so a short failure never reads as the session having gone.
    async fn link(&self, session_id: SessionId) -> std::result::Result<Arc<Link>, ClientError> {
        match self.links.link(session_id).await {
            Ok(link) => Ok(link),
            Err(error) if error.code == ErrorCode::UnknownSession => {
                match self.session_ended(session_id).await {
                    Ok(true) => Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::UnknownSession,
                        error.message,
                    ))),
                    _ => Err(ClientError::ConnectionEnded),
                }
            }
            Err(_) => Err(ClientError::ConnectionEnded),
        }
    }

    fn settle<T>(
        &self,
        session_id: SessionId,
        link: &Arc<Link>,
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

impl QuestionHost for Host<'_> {
    async fn questions(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Vec<Question>, ClientError> {
        match &self.route {
            Route::Local => {
                let link = self.link(session_id).await?;
                let answer = self
                    .within(<Session as QuestionHost>::questions(
                        &link.session,
                        session_id,
                    ))
                    .await;
                self.settle(session_id, &link, answer)
            }
            Route::Paired { session, .. } => {
                self.within(<Session as QuestionHost>::questions(session, session_id))
                    .await
            }
        }
    }

    async fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> std::result::Result<QuestionResolveResult, ClientError> {
        let session_id = params.session_id;
        let answer = match &self.route {
            Route::Local => {
                let link = self.link(session_id).await?;
                // An answer goes only to the host it was given to, and only to a worker whose
                // reply this build can be sure to read.
                if target.environment_id != link.descriptor.environment_id {
                    return Err(ClientError::ConnectionEnded);
                }
                readable_by_this_build(link.build.as_ref(), session_id)?;
                let answer = self
                    .within(<Session as QuestionHost>::answer(
                        &link.session,
                        target,
                        params,
                    ))
                    .await;
                self.settle(session_id, &link, answer)
            }
            Route::Paired {
                environment_id,
                session,
            } => {
                if target.environment_id != *environment_id {
                    return Err(ClientError::ConnectionEnded);
                }
                self.within(<Session as QuestionHost>::answer(session, target, params))
                    .await
            }
        };
        if let Ok(resolved) = &answer {
            *self.taken.lock().unwrap_or_else(PoisonError::into_inner) = Some(resolved.clone());
        }
        answer
    }

    /// Whether the host's record of the session says it ended.
    ///
    /// On this machine, the worker is gone for a session whose descriptor is not published, and that
    /// is all a missing worker says. The daemon's record says more: a closure it holds, or no record
    /// of a session whose descriptor is gone too. On a paired host the daemon's record is all there
    /// is. A daemon that cannot be asked establishes nothing, and the error says so: no answer is
    /// retired on a short failure.
    async fn session_ended(&self, session_id: SessionId) -> std::result::Result<bool, ClientError> {
        let session = match &self.route {
            Route::Local => self
                .state
                .session()
                .map_err(|_| ClientError::ConnectionEnded)?,
            Route::Paired { session, .. } => Arc::clone(session),
        };
        let read = self
            .within(session.read::<_, SessionReadResult>(
                Method::SessionRead,
                &SessionReadParams { session_id },
            ))
            .await;
        match read {
            Ok(read) => {
                Ok(read.session.closure.0.is_some() || read.session.state == SessionState::Closed)
            }
            Err(ClientError::Host(refused)) if refused.code == ErrorCode::SessionClosed => Ok(true),
            Err(ClientError::Host(refused)) if refused.code == ErrorCode::UnknownSession => {
                match &self.route {
                    Route::Local => match self.links.serves(session_id) {
                        Ok(published) => Ok(!published),
                        Err(_) => Err(ClientError::ConnectionEnded),
                    },
                    Route::Paired { .. } => Ok(true),
                }
            }
            Err(error) => Err(error),
        }
    }
}

/// Refuses a worker whose frames this build cannot be sure to read, before an answer goes to it.
///
/// A worker outlives an upgrade, and what it answers an answer with changes from one protocol
/// version to the next, so an answer sent and then not readable would leave the person unsure
/// whether it was taken. A worker states its build in its answer to the hello, and one whose
/// protocol version shares this build's compatibility level reads and writes the same frames.
fn readable_by_this_build(
    stated: Option<&LocalBuild>,
    session_id: SessionId,
) -> std::result::Result<(), ClientError> {
    use kr_protocol::hello::PACKAGE_VERSION;

    match stated {
        Some(build) if build.protocol_version.shares_frames_with(PACKAGE_VERSION) => Ok(()),
        _ => Err(ClientError::Host(ProtocolError::new(
            ErrorCode::UnsupportedSchema,
            format!(
                "session {session_id}'s worker is of another build than this application, which \
                 cannot be sure to read what that worker answers an answer with, so nothing was \
                 sent: update this application or that session"
            ),
        ))),
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
        resolution: Box<QuestionResolveResult>,
        /// Whether a kept copy of an answer to this question could not be removed.
        leftover: bool,
    },
    /// The host did not confirm that it took the answer, so a copy is kept on this device.
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
    /// The question as the worker lists it now, when it lists it: what the answer was given to.
    pub question: Option<Question>,
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

/// Reads a session's questions, on the route the connection gives, and remembers what was read with
/// the place an answer to each goes.
///
/// # Errors
///
/// Returns why the questions could not be read.
pub async fn read(
    state: &AppState,
    links: &WorkerLinks,
    params: QuestionReadParams,
) -> Result<QuestionReadResult> {
    let host = Host::new(links, state);
    let session_id = params.session_id;
    let (result, target_for): (QuestionReadResult, TargetFor) = match &host.route {
        Route::Local => {
            let link = host.link(session_id).await.map_err(CommandError::from)?;
            let answer = host
                .within(link.session.read(Method::QuestionRead, &params))
                .await;
            let result: QuestionReadResult = host
                .settle(session_id, &link, answer)
                .map_err(CommandError::from)?;
            let target = target_of(&link);
            (result, Box::new(move |_: &Question| target.clone()))
        }
        Route::Paired {
            environment_id,
            session,
        } => {
            let result: QuestionReadResult = host
                .within(session.read(Method::QuestionRead, &params))
                .await
                .map_err(CommandError::from)?;
            let environment_id = *environment_id;
            (
                result,
                Box::new(move |question: &Question| target_on(environment_id, question)),
            )
        }
    };
    state.questions().remember(
        session_id,
        params.question_id.0,
        &result.questions,
        target_for,
    );
    Ok(result)
}

/// Answers a question, or keeps the answer on this device when the host did not confirm that it
/// took it.
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
    let _turn = desk.turn().await?;
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
    let host = Host::new(links, state);
    // An answer is named by its question and the time it was kept at, and that name is what a send
    // or a dismissal is held to. So a new answer to a question that already has one kept is kept
    // later than that one, whatever the clock says, and an older name never names a newer answer.
    let now = kr_ipc::now_ms();
    let drafted_at = match desk.kept_for(params.question_id) {
        Ok(Some(earlier)) if earlier.drafted_at_ms >= now => {
            TimestampMs::new(earlier.drafted_at_ms.get().saturating_add(1))
        }
        _ => now,
    };
    let answered = answers::answer(
        Some(&host),
        &store,
        shown.target.clone(),
        &shown.question,
        params.answer,
        drafted_at,
    )
    .await;
    match (answered, host.taken()) {
        (Ok(Answered::Sent(resolution)), _) => Ok(Answer::Taken {
            resolution,
            leftover: false,
        }),
        (Ok(Answered::Unconfirmed(draft)), _) => keep(store, draft).await,
        // The worker took it and removing the copy kept earlier failed: the answer was taken, and
        // the page is told so.
        (Err(AnswerError::Store { .. } | AnswerError::Unreadable { .. }), Some(resolution)) => {
            Ok(Answer::Taken {
                resolution: Box::new(resolution),
                leftover: true,
            })
        }
        (Err(error), _) => Err(failure(error)),
    }
}

/// Keeps an answer the host did not confirm, under the writers' lock and the leave to write a kept
/// answer, the way the command line does.
///
/// An update of the host that is switching releases holds the lock, and a write waits for it for up
/// to [`kr_ipc::install::WRITERS_WAIT_SECONDS`] seconds. When it still cannot write, no copy of the
/// answer is kept, and the page is told that; what the person wrote stays in the form.
async fn keep(store: AnswerDrafts, draft: AnswerDraft) -> Result<Answer> {
    tokio::task::spawn_blocking(move || {
        let not_kept = |why: String| {
            CommandError::unavailable(format!(
                "the host did not confirm your answer, and no copy of it could be kept on this \
                 device: {why}; it is still in the form"
            ))
        };
        let writers = kr_ipc::install::hold_writers(&mut || {})
            .map_err(|refused| not_kept(refused.to_string()))?;
        let permit = writers
            .permit(&answers::WRITTEN)
            .map_err(|refused| not_kept(refused.to_string()))?;
        store.keep(&draft, &permit).map_err(failure)?;
        Ok(Answer::Kept { draft })
    })
    .await
    .map_err(|error| CommandError::local_failure(format!("keeping the answer stopped: {error}")))?
}

/// Every answer kept on this device, in every environment.
///
/// Listing takes no turn and asks no host: an answer another window is changing is read whole or
/// not at all.
pub fn kept(state: &AppState) -> Kept {
    state.questions().kept()
}

/// Says, for every answer kept for one session on the host the application reaches now, where its
/// question stands. Sends nothing and removes nothing.
///
/// An answer given to another host is not settled against this one: nothing is said of it.
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
    let host = Host::new(links, state);
    let mine: Vec<AnswerDraft> = desk
        .kept()
        .answers
        .into_iter()
        .filter(|draft| draft.session_id == params.session_id)
        .collect();
    if mine.is_empty() {
        return Ok(Vec::new());
    }
    let environment = host
        .environment(params.session_id)
        .await
        .map_err(CommandError::from)?;
    let drafts: Vec<AnswerDraft> = mine
        .into_iter()
        .filter(|draft| draft.target.environment_id == environment)
        .collect();
    if drafts.is_empty() {
        return Ok(Vec::new());
    }
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
            .find(|question| question.question_id == draft.question_id)
            .cloned();
        let standing = match draft.submission(question.as_ref()) {
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
        settled.push(Settled {
            draft,
            question,
            standing,
        });
    }
    Ok(settled)
}

/// Sends one kept answer, which is the one way a kept answer is ever sent.
///
/// The question is read again first. An answer whose question ended or moved is not sent, and it
/// stays kept until the person dismisses it. An answer given to another host is not sent to this one.
///
/// # Errors
///
/// Returns why the answer was not sent: no such kept answer, a question that ended or moved, the
/// host it was given to being out of reach, or the worker's refusal.
pub async fn send(state: &AppState, links: &WorkerLinks, which: &KeptRef) -> Result<Answer> {
    let desk = state.questions();
    let _turn = desk.turn().await?;
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
    let host = Host::new(links, state);
    let environment = host
        .environment(draft.session_id)
        .await
        .map_err(CommandError::from)?;
    if draft.target.environment_id != environment {
        return Err(CommandError::unavailable(
            "that answer was given to another host, and this application is not connected to it: \
             connect to that host to send it",
        ));
    }
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
        resolution: Box::new(resolution),
        leftover,
    })
}

/// Dismisses one kept answer, if it is still the one the person was shown.
///
/// Answers whether it was removed. An answer kept again for the same question since carries another
/// time and is left where it is. The comparison and the removal happen under the turn every window
/// of the application takes, so another window cannot keep a new answer between them.
///
/// # Errors
///
/// Returns the store's failure when the answer cannot be read or removed.
pub async fn dismiss(state: &AppState, which: &KeptRef) -> Result<bool> {
    let desk = state.questions();
    let _turn = desk.turn().await?;
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

/// Takes the lock every window holds while it changes the kept answers, waiting up to `patience`
/// for one that has it.
fn hold_across_windows(root: &Path, patience: Duration) -> Result<std::fs::File> {
    let unusable = |error: std::io::Error| {
        CommandError::local_failure(format!(
            "the answers kept on this device cannot be locked: {error}"
        ))
    };
    std::fs::create_dir_all(root).map_err(unusable)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(root.join(WINDOWS_LOCK)).map_err(unusable)?;
    let deadline = std::time::Instant::now() + patience;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(CommandError::unavailable(
                    "another window of this application is changing the answers kept on this \
                     device; try again in a moment",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(unusable(error)),
        }
    }
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

/// The target an answer to a question goes to, for each question a read listed.
type TargetFor = Box<dyn Fn(&Question) -> ActionTarget>;

/// The target a paired host's daemon takes a question's answer on: the session at the epoch the
/// question carries, in the host's environment.
#[must_use]
fn target_on(environment_id: EnvironmentId, question: &Question) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(question.session_id),
        session_epoch: Nullable::some(question.session_epoch),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}
