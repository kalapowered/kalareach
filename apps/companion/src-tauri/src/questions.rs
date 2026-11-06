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
//! answers (answering, sending, dismissing) takes a lock every window holds (`QuestionDesk::turn`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::answers::{
    self, AnswerDraft, AnswerDrafts, AnswerError, AnswerFailure, Answered, Dispatch, Earlier,
    Keeper, Leave, QuestionHost, Quoting, ReadFailure, Retired, SendState,
};
use kr_client::{ClientError, Session};
use kr_ipc::install::Writing;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, EnvironmentId, QuestionId, QuestionRevision, SessionId};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswerParams, QuestionReadParams, QuestionReadResult, QuestionResolveResult,
    QuestionState,
};
use kr_protocol::receipt::Receipt;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState};
use serde::{Deserialize, Serialize};

use crate::agent::{Link, WorkerLinks, ends_the_link};
use crate::error::{CommandError, Result};
use crate::standing::Leased;
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
    /// A host this device is paired with: its daemon forwards the question to the worker, over the
    /// connection the host opened for the session. The connection for the host alone is what
    /// reads a session's record, and it is `None` while that connection is being taken up again:
    /// the session's own link does not wait for it.
    Paired {
        main: Option<(EnvironmentId, Arc<Session>)>,
    },
}

impl Route {
    /// The route the host in use gives. A host this device is paired with is the paired route
    /// whether or not its connection is up; with no host in use the application is on its own
    /// machine's route, where the worker is reached without the daemon.
    fn of(state: &AppState) -> Self {
        if state.paired_context().is_none() {
            return Self::Local;
        }
        Self::Paired {
            main: state
                .paired_snapshot()
                .ok()
                .map(|(_, environment_id, session)| (environment_id, session)),
        }
    }
}

/// The host's side of the answers library, over whichever route the connection gives.
struct Host<'a> {
    links: &'a WorkerLinks,
    state: &'a AppState,
    route: Route,
    /// The session screen the call belongs to, when it comes from one; a call from the inbox or a
    /// kept answer belongs to none.
    opening: Option<&'a str>,
    exchange: Duration,
    /// What the worker said of the answer it took, when it took one.
    taken: Mutex<Option<QuestionResolveResult>>,
    /// Whether a send of this call reached the point where it may be on its way to the host.
    sent: AtomicBool,
    /// The link whose book holds the earlier sends of an answer the worker took: the one the answer
    /// went over, or the one a receipt of an earlier send was read on.
    over: Mutex<Option<Arc<Link>>>,
}

impl<'a> Host<'a> {
    fn new(links: &'a WorkerLinks, state: &'a AppState, opening: Option<&'a str>) -> Self {
        Self {
            links,
            state,
            route: Route::of(state),
            opening,
            exchange: state.questions().exchange(),
            taken: Mutex::new(None),
            sent: AtomicBool::new(false),
            over: Mutex::new(None),
        }
    }

    /// Whether this call sent an answer, or may have: the host may hold it.
    fn sent(&self) -> bool {
        self.sent.load(Ordering::SeqCst)
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
                Err(_) => Ok(self.link(session_id).await?.ids.environment_id),
            },
            Route::Paired {
                main: Some((environment_id, _)),
            } => Ok(*environment_id),
            // The host's environment is the one the session's own link reaches.
            Route::Paired { main: None } => Ok(self.link(session_id).await?.ids.environment_id),
        }
    }

    /// The link to the session's worker on this machine, with a failure to make one in the
    /// library's terms.
    ///
    /// A worker whose descriptor is not published is the host's refusal of an unknown session only
    /// when the daemon's record agrees that the session ended; a worker that is restarting, that
    /// could not be reached or would not prove its key is a connection that ended. Nothing else is
    /// said, so a short failure never reads as the session having gone.
    async fn link(&self, session_id: SessionId) -> std::result::Result<Leased, ClientError> {
        match self.links.link(self.state, session_id, self.opening).await {
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
            // On a paired host every refusal is the host's, or the application's own for a screen
            // that was replaced or a share that has ended, and reaches the person as said: the
            // library keeps an answer for a code that is only transient. On this machine, a
            // screen's opening that is no longer the session's, or a share that has ended, is the
            // application's own refusal, and anything else that kept a link from being made is a
            // connection that ended.
            Err(error)
                if matches!(self.route, Route::Paired { .. })
                    || matches!(
                        error.code,
                        ErrorCode::StaleSession | ErrorCode::PermissionDenied
                    ) =>
            {
                Err(ClientError::Host(ProtocolError::new(
                    error.code,
                    error.message,
                )))
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
            self.links.forget(self.state, session_id, link);
        }
        answer
    }
}

impl QuestionHost for Host<'_> {
    async fn questions(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Vec<Question>, ClientError> {
        // On either route the questions are the session's worker's, read over the link held for
        // the session: this machine's descriptor link, or the connection a paired host opened for
        // the session.
        let link = self.link(session_id).await?;
        let answer = self
            .within(<Session as QuestionHost>::questions(
                &link.session,
                session_id,
            ))
            .await;
        self.settle(session_id, link.link(), answer)
    }

    async fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
        dispatch: Dispatch,
    ) -> std::result::Result<QuestionResolveResult, AnswerFailure> {
        let session_id = params.session_id;
        let link = self
            .link(session_id)
            .await
            .map_err(AnswerFailure::unwritten)?;
        // An answer goes only to the host it was given to.
        if target.environment_id != link.ids.environment_id {
            return Err(AnswerFailure::unwritten(ClientError::ConnectionEnded));
        }
        // On this machine, only to a worker whose reply this build can be sure to read. A paired
        // host's daemon forwards the answer and states no worker build.
        if matches!(self.route, Route::Local) {
            readable_by_this_build(link.build.as_ref(), session_id)
                .map_err(AnswerFailure::unwritten)?;
        }
        // Counted in flight until the worker has answered, so that leaving the screen waits for it.
        let _flying = crate::standing::Flight::enter(link.link());
        self.sent.store(true, Ordering::SeqCst);
        // Under the share the link acts under, which the host checks as it does an agent's
        // mutation. One that has not answered by the time has an outcome nobody knows.
        let answer = tokio::time::timeout(
            self.exchange,
            answers::answer_over(&link.session, link.grant_id, target, params, dispatch),
        )
        .await
        .unwrap_or_else(|_| Err(AnswerFailure::from(ClientError::ConnectionEnded)));
        if let Err(failure) = &answer
            && ends_the_link(&failure.error)
        {
            self.links.forget(self.state, session_id, link.link());
        }
        if let Ok(resolved) = &answer {
            *self.taken.lock().unwrap_or_else(PoisonError::into_inner) = Some(resolved.clone());
            *self.over.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Arc::clone(link.link()));
        }
        answer
    }

    async fn receipt(
        &self,
        session_id: SessionId,
        action_id: ActionId,
    ) -> std::result::Result<Receipt, ClientError> {
        let link = self.link(session_id).await?;
        let answer = self
            .within(<Session as QuestionHost>::receipt(
                &link.session,
                session_id,
                action_id,
            ))
            .await;
        // The sends this call asks about were made on this link, and a send of them the host took
        // is what lets it stop holding the others.
        if answer.is_ok() {
            *self.over.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Arc::clone(link.link()));
        }
        self.settle(session_id, link.link(), answer)
    }

    /// Lets the link whose book holds the earlier sends of an answer the host took stop holding
    /// them: the link the answer went over, or the link a receipt of an earlier send was read on.
    /// A call that sent nothing and read no receipt has no such link, and no link is opened.
    async fn settle_earlier(&self, session_id: SessionId, sends: &[ActionId]) {
        let over = self
            .over
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(link) = over {
            <Session as QuestionHost>::settle_earlier(&link.session, session_id, sends).await;
        }
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
            Route::Paired {
                main: Some((_, session)),
            } => Arc::clone(session),
            // The host's record is the main connection's to read; without it nothing is established.
            Route::Paired { main: None } => return Err(ClientError::ConnectionEnded),
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
    /// The host took a send of an answer to this question, one the kept record carried. When
    /// `refused` is empty this press sent nothing; otherwise this press sent `refused`, and the host
    /// refused it because the question was answered. Nothing here says which of the two reached the
    /// host first. A press of the answer form retires the copy kept; a press of a kept answer's send
    /// leaves it until the person dismisses it.
    Landed {
        /// The send the host took.
        action_id: ActionId,
        /// This press's own send, when it went out and was refused for that reason.
        refused: Option<ActionId>,
    },
    /// The host has an earlier send of an answer to this question and has not finished with it.
    /// This press sent nothing, and the copy stays kept.
    Waiting {
        /// The send the host has.
        action_id: ActionId,
    },
    /// An earlier send of an answer to this question ended with an outcome the host could not
    /// establish, and the page has not been shown it. This press sent nothing and kept nothing: the
    /// page shows the outcome, and the next press carries the send it was shown.
    Held {
        /// The send whose outcome the host could not establish.
        action_id: ActionId,
    },
}

/// What the host said of one earlier send of a kept answer, for the page.
#[derive(Debug, Serialize)]
pub struct EarlierSend {
    /// The send.
    pub action_id: ActionId,
    /// What the host said: `unknown`, `refused`, `no_record` or `unreadable`.
    pub state: &'static str,
    /// The code the host gave, when it gave one.
    pub code: Option<ErrorCode>,
}

/// What the host said of each earlier send worth showing; a send the host took or has is a standing
/// of its own.
fn earlier_sends(earlier: &Earlier) -> Vec<EarlierSend> {
    earlier
        .sends()
        .filter_map(|(action_id, state)| {
            let (state, code) = match state {
                SendState::Unknown { .. } => ("unknown", None),
                SendState::Refused(code) => ("refused", *code),
                SendState::NoRecord => ("no_record", None),
                SendState::Unreadable(ReadFailure::Failed) => ("unreadable", None),
                SendState::Unreadable(ReadFailure::Refused(code)) => ("unreadable", Some(*code)),
                SendState::Applied | SendState::Pending => return None,
            };
            Some(EarlierSend {
                action_id: *action_id,
                state,
                code,
            })
        })
        .collect()
}

/// The leave to write the answers kept on this device and the record of their sends.
///
/// No release of the host ships this application, so it runs outside every store: the hold registers
/// nothing, holds nothing and permits every record, and the roots it is given are never read. They
/// are `root`, the directory the answers are kept in. An update would not find the answers by them
/// if it did: it looks for `kept-answers/*.answer` directly under a state root, and the answers here
/// are kept as `kept-answers/<environment>/*.answer`.
struct Holding {
    root: PathBuf,
    /// Why the leave was last refused.
    refusal: Mutex<String>,
}

impl Holding {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            refusal: Mutex::new(String::new()),
        }
    }

    fn refusal(&self) -> String {
        self.refusal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Keeper for Holding {
    fn keep<R>(
        &self,
        work: impl FnOnce(&Leave<'_>) -> R,
    ) -> std::result::Result<R, kr_client::shown::Shown> {
        let taken = (|| {
            let writing = Writing::in_roots(&self.root, &self.root);
            let writers = kr_ipc::install::hold_writers(&writing, &mut || {})
                .map_err(|refused| refused.to_string())?;
            let answers = writers
                .permit(&answers::WRITTEN)
                .map_err(|refused| refused.to_string())?;
            let sends = writers
                .permit(&kr_client::sends::WRITTEN)
                .map_err(|refused| refused.to_string())?;
            Ok::<R, String>(work(&Leave { answers, sends }))
        })();
        taken.map_err(|why| {
            *self.refusal.lock().unwrap_or_else(PoisonError::into_inner) = why;
            kr_client::shown::Shown::said("the leave to write a kept answer was refused")
        })
    }
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
    /// The question is pending at the revision the person answered. It can be sent. `earlier` is
    /// what the host said of the sends already made, and an uncertain one is what a send names.
    Offered {
        /// What the host said of each earlier send.
        earlier: Vec<EarlierSend>,
        /// The uncertain send a send of this answer names, which is the newest by the host's
        /// record of it; the page acknowledges this one.
        quote: Option<ActionId>,
    },
    /// The host has an earlier send of the answer and has not finished with it. The answer stays
    /// kept and cannot be sent.
    Waiting {
        /// The send the host has.
        action_id: ActionId,
    },
    /// The host took an earlier send of the answer while its reply was lost. It is not sent again,
    /// and stays shown until the person dismisses it.
    Taken {
        /// The send the host took.
        action_id: ActionId,
    },
    /// The question ended and the host could not be asked what became of an earlier send. The
    /// answer stays kept and cannot be sent.
    Unsettled,
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
    /// The send whose outcome the host could not establish that the page showed, when it showed
    /// one. A send that finds another sends nothing.
    #[serde(default)]
    pub acknowledged: Option<ActionId>,
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
    opening: Option<&str>,
    params: QuestionReadParams,
) -> Result<QuestionReadResult> {
    let host = Host::new(links, state, opening);
    let session_id = params.session_id;
    let link = host.link(session_id).await.map_err(CommandError::from)?;
    let answer = host
        .within(link.session.read(Method::QuestionRead, &params))
        .await;
    let result: QuestionReadResult = links.settle(state, session_id, link.link(), answer)?;
    // On this machine an answer goes on the session's own target. On a paired host the target is
    // the session at the epoch the question carries, in the host's environment.
    let target_for: TargetFor = match &host.route {
        Route::Local => {
            let target = target_of(&link);
            Box::new(move |_: &Question| target.clone())
        }
        Route::Paired { .. } => {
            let environment_id = link.ids.environment_id;
            Box::new(move |question: &Question| target_on(environment_id, question))
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
/// took it. The identifier the answer goes out under is kept with it before anything is sent, so a
/// later settling asks the host what became of it.
///
/// An earlier send of an answer to the question that ended with an outcome the host could not
/// establish is shown to the person first: a press that finds one `acknowledged` does not name sends
/// nothing and says [`Answer::Held`], and the next press names it.
///
/// # Errors
///
/// Returns the worker's refusal, a form the question does not take, or a store that failed while
/// the answer had to be kept, in which case nothing was sent.
pub async fn answer(
    state: &AppState,
    links: &WorkerLinks,
    opening: Option<&str>,
    params: QuestionAnswerParams,
    acknowledged: Option<ActionId>,
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
    let host = Host::new(links, state, opening);
    let keeper = Holding::new(desk.root()?);
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
    let attempt = answers::answer(
        &host,
        &keeper,
        &store,
        shown.target.clone(),
        &shown.question,
        params.answer,
        drafted_at,
        Quoting::AfterShown(acknowledged),
    )
    .await;
    match (attempt.outcome, host.taken()) {
        (Ok(Answered::Sent(resolution)), _) => Ok(Answer::Taken {
            resolution,
            leftover: false,
        }),
        (Ok(Answered::Kept(draft)), _) => Ok(Answer::Kept { draft }),
        (Ok(Answered::Taken(action_id)), _) => Ok(Answer::Landed {
            action_id,
            refused: None,
        }),
        (Ok(Answered::TakenAfterRefusal { taken, refused }), _) => Ok(Answer::Landed {
            action_id: taken,
            refused: Some(refused),
        }),
        (Ok(Answered::Waiting(action_id)), _) => Ok(Answer::Waiting { action_id }),
        (Ok(Answered::Held(quote)), _) => Ok(Answer::Held {
            action_id: quote.action_id,
        }),
        // The worker took it and removing the copy kept earlier failed: the answer was taken, and
        // the page is told so.
        (Err(AnswerError::Store { .. } | AnswerError::Unreadable { .. }), Some(resolution)) => {
            Ok(Answer::Taken {
                resolution: Box::new(resolution),
                leftover: true,
            })
        }
        // The answer could not be recorded, so nothing was sent; what the person wrote stays in
        // the form.
        (Err(AnswerError::Keeping(_)), _) => Err(CommandError::unavailable(format!(
            "nothing was sent, and no copy of your answer could be kept on this device: {}; it \
             is still in the form",
            keeper.refusal()
        ))),
        (
            Err(
                error @ (AnswerError::Store { .. }
                | AnswerError::Unreadable { .. }
                | AnswerError::Changed
                | AnswerError::Full
                | AnswerError::NotPermitted),
            ),
            None,
        ) => Err(CommandError::new(
            error.code(),
            if host.sent() {
                // The send reached the host and was refused, and settling it failed afterwards.
                format!(
                    "this press's send reached the host and was refused, and then: {error}; it is \
                     still in the form"
                )
            } else {
                format!("nothing was sent: {error}; it is still in the form")
            },
        )),
        (Err(error), _) => Err(failure(error)),
    }
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
    opening: Option<&str>,
    params: &SettleParams,
) -> Result<Vec<Settled>> {
    let desk = state.questions();
    let host = Host::new(links, state, opening);
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
        // What the host says of the sends already made, asked after the question was read.
        let (_, basis) = desk
            .store(draft.target.environment_id)
            .and_then(|store| store.entry(draft.question_id))
            .map_err(failure)?
            .ok_or_else(|| {
                CommandError::new(
                    ErrorCode::DraftConflict,
                    "the answer kept for that question has changed: read the kept answers again",
                )
            })?;
        let earlier = if question.is_some() && !basis.sends().is_empty() {
            answers::learn(&host, draft.session_id, basis.sends()).await
        } else {
            Earlier::default()
        };
        let standing = if let Some(action_id) = earlier.taken() {
            Standing::Taken { action_id }
        } else {
            match draft.submission(question.as_ref()) {
                Ok(_) => match earlier.waiting() {
                    Some(action_id) => Standing::Waiting { action_id },
                    None => Standing::Offered {
                        earlier: earlier_sends(&earlier),
                        quote: earlier.quote().map(|quote| quote.action_id),
                    },
                },
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
                Err(_) if earlier.failed() => Standing::Unsettled,
                Err(reason) => reason.into(),
            }
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
pub async fn send(
    state: &AppState,
    links: &WorkerLinks,
    opening: Option<&str>,
    which: &KeptRef,
) -> Result<Answer> {
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
    let host = Host::new(links, state, opening);
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
    let store = desk.store(draft.target.environment_id).map_err(failure)?;
    let (_, basis) = store
        .entry(draft.question_id)
        .map_err(failure)?
        .ok_or_else(|| {
            CommandError::new(
                ErrorCode::DraftConflict,
                "the answer kept for that question has changed: read the kept answers again",
            )
        })?;
    // The host is asked what became of every send already made, after the question was read. One it
    // took ends the matter, and nothing is sent.
    let earlier = if current.is_some() && !basis.sends().is_empty() {
        answers::learn(&host, draft.session_id, basis.sends()).await
    } else {
        Earlier::default()
    };
    if let Some(action_id) = earlier.taken() {
        host.settle_earlier(draft.session_id, basis.sends()).await;
        return Ok(Answer::Landed {
            action_id,
            refused: None,
        });
    }
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
        Err(_) if earlier.failed() => return Err(failure(AnswerError::Unsettled)),
        Err(reason) => return Err(failure(AnswerError::Retired(reason))),
    };
    if let Some(action_id) = earlier.waiting() {
        return Ok(Answer::Waiting { action_id });
    }
    // An uncertain earlier send is shown to the person before a send names it.
    let quote = earlier.quote();
    if let Some(quote) = quote
        && which.acknowledged != Some(quote.action_id)
    {
        return Err(CommandError::new(
            ErrorCode::DraftConflict,
            "an earlier send of this answer ended with an outcome the host could not establish: \
             read the kept answers again",
        ));
    }
    let keeper = Holding::new(desk.root()?);
    let send = ActionId::new(kr_ipc::new_uuid());
    let carried = earlier.carried(basis.sends());
    let digest = basis.draft().ok_or_else(|| {
        CommandError::new(
            ErrorCode::DraftConflict,
            "the answer kept for that question has changed: read the kept answers again",
        )
    })?;
    keeper
        .keep(|leave| store.record_send(draft.question_id, &basis, &carried, send, leave))
        .map_err(|_| {
            CommandError::unavailable(format!(
                "nothing was sent, and the send could not be recorded on this device: {}",
                keeper.refusal()
            ))
        })?
        .map_err(|error| CommandError::new(error.code(), format!("nothing was sent: {error}")))?;
    let sent = host
        .answer(
            draft.target.clone(),
            params,
            Dispatch {
                action_id: send,
                quote,
            },
        )
        .await;
    let resolution = match sent {
        Ok(resolution) => resolution,
        Err(failed) => {
            if failed.settled() {
                let _ = keeper
                    .keep(|leave| store.settle(draft.question_id, digest, &[send], false, leave));
            }
            // The question ended: an earlier send may be the reason, and a send the host took is
            // told rather than hidden. The answer stays kept either way, until it is dismissed.
            if let ClientError::Host(refused) = &*failed.error
                && matches!(
                    refused.code,
                    ErrorCode::QuestionResolved | ErrorCode::QuestionExpired
                )
                && !carried.is_empty()
                && let Ok(basis) = store.basis(draft.question_id)
                && let Some(action_id) = answers::learn(&host, draft.session_id, basis.sends())
                    .await
                    .taken()
            {
                host.settle_earlier(draft.session_id, &carried).await;
                return Ok(Answer::Landed {
                    action_id,
                    refused: Some(send),
                });
            }
            return Err(CommandError::from(*failed.error));
        }
    };
    // The worker has the answer. The earlier sends of it are moot, so the link stops holding them.
    // Taking the copy away is the last step, and a failure of it is told rather than hidden: a copy
    // left behind is retired by the next settling.
    host.settle_earlier(draft.session_id, &carried).await;
    let leftover = store.discard(draft.question_id).is_err();
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
        match kr_flush::lock::try_exclusive(&file) {
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
    link.target(None, None)
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
