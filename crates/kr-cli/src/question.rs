//! `kr question`: reading and answering an agent's questions from the terminal.
//!
//! The companion app is the primary place to answer a question: it shows the verified application
//! identity, the context and the form, and it reaches every host a person is paired with. This is
//! the same surface for the machine the session is on, for when the app is not to hand.
//!
//! Two properties matter more than the shape of the output.
//!
//! * **The identity header is the host's.** Every listing leads with the executable the broker
//!   verified. The `agent_name` a caller supplied is shown beside it and labelled unverified,
//!   because a label is not an identity.
//! * **An answer names the revision it answers.** The revision the command read is the revision it
//!   submits, so an answer to a question that moved underneath it is refused rather than applied
//!   to something else.
//!
//! Questions belong to the session, so this reaches the session's worker directly, the way
//! attaching does. It therefore keeps working while the control daemon is restarting, and the
//! authority behind it is the operating-system owner the worker's socket authenticates.
//!
//! An answer the worker could not take is kept rather than lost, because section 11 keeps an
//! offline answer as a draft. When the connection ends before the answer is sent, or after it is
//! sent and before the worker says what became of it, the answer is written to this user's state
//! directory with the question and the revision the person was shown, and the person is told.
//! `kr question drafts` reads the questions again and says of each kept answer whether it can
//! still be sent, or was retired because its question ended or moved; it sends nothing.
//! `kr question send` sends one kept answer, after reading its question once more, and nothing else
//! sends a kept answer. The rules are the client library's own ([`kr_client::answers`]); what this
//! adds is the connection they are sent over: each session's worker, found by its descriptor and
//! proved against it before anything is sent.

use std::collections::BTreeMap;

use kr_client::answers::{
    self, AnswerDraft, AnswerDrafts, AnswerError, Answered, QuestionHost, Reconciled, Retired,
};
use kr_client::error::ClientError;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, QuestionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCancelParams, QuestionReadParams,
    QuestionReadResult, QuestionResolveResult, QuestionState, SOMETHING_ELSE_CHOICE,
};
use kr_protocol::scalars::Nullable;
use kr_protocol::worker::WorkerDescriptor;
use serde_json::{Value, json};

use crate::error::{CliError, Result};
use crate::resolve::{KnownEnvironment, SessionSelector, environments, find, open_worker};

/// The directory, in this user's state directory, the answers kept on this device are in.
pub const KEPT_ANSWERS: &str = "kept-answers";

/// Which sessions a listing covers.
#[derive(Clone, Debug)]
pub enum Scope {
    /// One named session.
    Session(SessionSelector),
    /// Every live session this host has.
    Everything,
}

/// Lists the questions waiting for a person.
///
/// # Errors
///
/// Returns an error when no host is running, or when a named session does not exist.
pub async fn list(
    paths: &HostPaths,
    scope: &Scope,
    include_resolved: bool,
    build_id: BuildId,
) -> Result<Vec<(WorkerDescriptor, Question)>> {
    let mut found = Vec::new();
    for descriptor in descriptors(paths, scope)? {
        let mut client = match open_worker(&descriptor, build_id.clone()).await {
            Ok(client) => client,
            // A worker that cannot be reached is reported by `kr list`, and a listing that stopped
            // at the first one would hide every question after it.
            Err(_) => continue,
        };
        let result: QuestionReadResult = read(
            &mut client,
            &QuestionReadParams {
                session_id: descriptor.session_id,
                question_id: Nullable::null(),
                include_resolved,
            },
        )
        .await?;
        for question in result.questions {
            found.push((descriptor.clone(), question));
        }
    }
    found.sort_by_key(|(_, question)| question.created_at_ms.get());
    Ok(found)
}

/// Reads one question in full.
///
/// # Errors
///
/// Returns an error when no session holds that question.
pub async fn show(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<(WorkerDescriptor, Question)> {
    locate(paths, question_id, build_id)
        .await
        .map(|(descriptor, question, _)| (descriptor, question))
}

/// Answers one question, or keeps the answer on this device when its worker cannot take it.
///
/// The revision this command read is the revision the answer names, so a question that moved while
/// the person was reading it is refused rather than answered as though it had not.
///
/// # Errors
///
/// Returns [`CliError::AnswerKept`] when the answer was kept rather than sent, [`CliError::Usage`]
/// for an answer that does not fit the question's form, [`CliError::Refused`] when the question
/// has already been resolved, has expired, or has moved to a revision this command did not read,
/// and [`CliError::Unfinished`] when the worker took the answer and its reply cannot be read.
pub async fn answer(
    paths: &HostPaths,
    question_id: QuestionId,
    answer: QuestionAnswer,
    build_id: BuildId,
) -> Result<Question> {
    let (descriptor, question, client) = locate(paths, question_id, build_id.clone()).await?;
    let drafts = kept_answers(paths)?;
    let workers = Workers::new(paths, build_id).holding(&descriptor, client);
    let answered = answers::answer(
        Some(&workers),
        &drafts,
        crate::attach::target(&descriptor),
        &question,
        answer,
        kr_ipc::now_ms(),
    )
    .await;
    match answered {
        Ok(Answered::Sent(question)) => Ok(*question),
        Ok(Answered::Kept(draft)) => Err(kept(&workers, draft.question_id, "was kept")),
        // What the failure says of the answer is what the attempt established, not what the
        // failure's kind suggests.
        Err(error) => Err(match workers.delivery() {
            Delivery::Taken => {
                let still_kept = kept_draft(&drafts, question_id)?.is_some();
                taken(
                    &workers,
                    descriptor.session_id,
                    question_id,
                    error,
                    still_kept,
                )
            }
            Delivery::Unknown => unkept(&workers, question_id, error),
            Delivery::NotSent | Delivery::NotTaken => answer_failure(error),
        }),
    }
}

/// Reads the questions of every kept answer again, and says of each whether it can still be sent.
///
/// A kept answer whose question is still pending at the revision it answers is offered and stays
/// kept. Any other is retired: this sends nothing, and it is no longer kept. Nothing is sent, however often
/// this runs.
///
/// # Errors
///
/// Returns a failure when the store cannot be read, and when a session holding a kept answer's
/// question cannot be read, in which case nothing is retired.
pub async fn drafts(paths: &HostPaths, build_id: BuildId) -> Result<Vec<Reconciled>> {
    let drafts = kept_answers(paths)?;
    let workers = Workers::new(paths, build_id).knowing(&drafts.drafts().map_err(answer_failure)?);
    answers::reconcile(&workers, &drafts)
        .await
        .map_err(|error| unreconciled(&workers, error))
}

/// The failure `kr question drafts` reports when a session holding a kept answer could not be
/// read, which retires nothing.
///
/// A worker that could not be reached is named, with what its daemon said of the session, rather
/// than reported as a connection that ended.
fn unreconciled(workers: &Workers, error: AnswerError) -> CliError {
    match (error, workers.failure()) {
        (AnswerError::Host(ClientError::ConnectionEnded), Some(failure)) => {
            CliError::HostUnavailable(format!("{}; no kept answer was retired", failure.why))
        }
        (error, _) => answer_failure(error),
    }
}

/// Sends one kept answer, which is the one way a kept answer is ever sent.
///
/// The question is read again first, and an answer whose question ended or moved is retired rather
/// than sent.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when no answer to the question is kept, [`CliError::AnswerKept`]
/// when the worker could not take it and it stays kept, [`CliError::Refused`] when the question
/// ended or moved, and [`CliError::Unfinished`] when the worker took it and what came after failed.
pub async fn send(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<Question> {
    let drafts = kept_answers(paths)?;
    let draft = kept_draft(&drafts, question_id)?.ok_or_else(|| {
        CliError::Usage(format!(
            "no answer to question {question_id} is kept on this device"
        ))
    })?;
    let workers = Workers::new(paths, build_id).knowing(std::slice::from_ref(&draft));
    match answers::send(&workers, &drafts, &draft).await {
        Ok(question) => Ok(question),
        // The library keeps a draft it could not send for any reason but its question's end, so
        // what is still in the store says whether it stayed kept. The failure is reported as
        // itself, with that beside it.
        Err(error) => {
            let still_kept = !matches!(error, AnswerError::Retired(_))
                && kept_draft(&drafts, question_id)?.is_some();
            Err(if workers.delivery() == Delivery::Taken {
                taken(&workers, draft.session_id, question_id, error, still_kept)
            } else if still_kept {
                still_kept_failure(&workers, question_id, error)
            } else {
                answer_failure(error)
            })
        }
    }
}

/// The failure a kept answer `kr question send` could not send is reported as.
///
/// The failure keeps its own code. What it says about the answer is what sending it established,
/// as the worker connection recorded it step by step: nothing written, refused by the worker, or
/// written with nothing to say whether the worker took it.
fn still_kept_failure(workers: &Workers, question_id: QuestionId, error: AnswerError) -> CliError {
    let retention = format!("the answer to question {question_id} is still kept on this device");
    let delivery = workers.delivery();
    let failure = workers.failure();
    match error {
        AnswerError::Host(
            ClientError::Host(refusal) | ClientError::Refused { error: refusal, .. },
        ) => CliError::Refused(ProtocolError::new(
            refusal.code,
            format!("{}; {}", refusal.message, retained(delivery, &retention)),
        )),
        other => {
            let why = failure.map_or_else(|| other.to_string(), |failure| failure.why);
            CliError::AnswerKept {
                code: other.code(),
                message: kept_message(question_id, delivery, &why, &retention),
            }
        }
    }
}

/// Opens the answers kept on this device, in this user's state directory, readable only by its
/// owner.
///
/// # Errors
///
/// Returns [`CliError::Other`] when the directory cannot be created or narrowed to its owner.
pub fn kept_answers(paths: &HostPaths) -> Result<AnswerDrafts> {
    AnswerDrafts::open(paths.state_root().join(KEPT_ANSWERS)).map_err(answer_failure)
}

/// The answer kept for one question, when there is one.
fn kept_draft(drafts: &AnswerDrafts, question_id: QuestionId) -> Result<Option<AnswerDraft>> {
    Ok(drafts
        .drafts()
        .map_err(answer_failure)?
        .into_iter()
        .find(|draft| draft.question_id == question_id))
}

/// The failure an answer kept rather than delivered is reported as, with why and what to do next.
fn kept(workers: &Workers, question_id: QuestionId, which: &str) -> CliError {
    let failure = workers.failure().unwrap_or_else(|| Failure {
        code: ErrorCode::ResourceUnavailable,
        why: "its session's worker could not take it".to_owned(),
    });
    let retention = format!("the answer to question {question_id} {which} on this device");
    CliError::AnswerKept {
        code: failure.code,
        message: kept_message(question_id, workers.delivery(), &failure.why, &retention),
    }
}

/// The failure reported when a worker took the answer and what came after failed: its reply could
/// not be read, or the copy kept on this device could not be removed.
///
/// The answer is never called unsent, and it is not offered for sending again: the next
/// `kr question drafts` finds its question answered and retires any copy still kept.
fn taken(
    workers: &Workers,
    session_id: SessionId,
    question_id: QuestionId,
    error: AnswerError,
    still_kept: bool,
) -> CliError {
    let after = workers
        .failure()
        .map_or_else(|| error.to_string(), |failure| failure.why);
    let copy = if still_kept {
        format!(
            "an answer to question {question_id} is still kept on this device, and \
             `kr question drafts` retires it once its question reads as answered"
        )
    } else {
        "nothing is kept for it".to_owned()
    };
    CliError::Unfinished {
        code: error.code(),
        message: format!(
            "session {session_id}'s worker took the answer to question {question_id}, but \
             {after}; {copy}"
        ),
    }
}

/// The failure reported for an answer that went out, whose fate is not known, and that the rules
/// do not keep: a reply that is not a message is its worker's own answer, not a lost connection.
fn unkept(workers: &Workers, question_id: QuestionId, error: AnswerError) -> CliError {
    let why = workers
        .failure()
        .map_or_else(|| error.to_string(), |failure| failure.why);
    CliError::Refused(ProtocolError::new(
        error.code(),
        format!(
            "{why}. The answer was not kept: `kr question show {question_id}` says whether its \
             question was answered"
        ),
    ))
}

/// Says what became of a kept answer, claiming no more about its delivery than was established.
///
/// An answer that may have reached its worker is never said to be unsent; the next
/// `kr question drafts` retires it when it did arrive.
fn kept_message(question_id: QuestionId, delivery: Delivery, why: &str, retention: &str) -> String {
    let next = match delivery {
        Delivery::NotSent | Delivery::NotTaken => format!(
            "`kr question drafts` says whether it can still be sent, and \
             `kr question send {question_id}` sends it"
        ),
        Delivery::Unknown => format!(
            "`kr question drafts` retires it if it arrived, and \
             `kr question send {question_id}` sends it if it did not"
        ),
        Delivery::Taken => {
            "`kr question drafts` retires it once its question reads as answered".to_owned()
        }
    };
    format!("{}: {why}. {next}", retained(delivery, retention))
}

/// That an answer is kept, and what this command established about its delivery.
fn retained(delivery: Delivery, retention: &str) -> String {
    match delivery {
        Delivery::NotSent => format!("{retention}, and this command did not send it"),
        Delivery::NotTaken => format!("{retention}, and its session's worker did not take it"),
        Delivery::Unknown => {
            format!("{retention}, and whether its session's worker took it is not known")
        }
        Delivery::Taken => format!("{retention}, and its session's worker took it"),
    }
}

/// What this command's attempt to send an answer established about whether its worker took it.
///
/// It is recorded as the attempt goes, independently of how the attempt failed, so a failure after
/// the answer went out is never read as an answer that did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// Nothing was written to the worker.
    NotSent,
    /// The worker answered that it did not take it.
    NotTaken,
    /// It was written, and nothing says whether the worker took it.
    Unknown,
    /// The worker answered that it took it.
    Taken,
}

/// Why the last answer was not taken, or what failed after it was, as the connection to its
/// worker recorded it.
#[derive(Clone, Debug)]
struct Failure {
    code: ErrorCode,
    why: String,
}

/// Turns a failure of the kept-answer rules into this command's own.
fn answer_failure(error: AnswerError) -> CliError {
    let code = error.code();
    match error {
        AnswerError::Form(message) => CliError::Usage(message),
        AnswerError::Retired(reason) => CliError::Refused(ProtocolError::new(
            code,
            format!(
                "{}, so this command did not send the kept answer, which is no longer kept",
                retired_because(reason)
            ),
        )),
        AnswerError::Host(
            ClientError::Host(refusal) | ClientError::Refused { error: refusal, .. },
        ) => CliError::Refused(refusal),
        AnswerError::Host(ClientError::Ipc(failure)) => {
            CliError::Refused(failure.to_protocol_error())
        }
        AnswerError::Host(other) => CliError::HostUnavailable(other.to_string()),
        AnswerError::Store { .. } | AnswerError::Unreadable { .. } => {
            CliError::Other(error.to_string())
        }
    }
}

/// Why a kept answer will not be sent, in the words a person is shown.
fn retired_because(reason: Retired) -> String {
    match reason {
        Retired::Ended(state) => format!("the question was {state} while the answer was kept"),
        Retired::Moved { revision } => {
            format!("the question moved to revision {revision} while the answer was kept")
        }
        Retired::Gone => "its session is not on this host any more".to_owned(),
    }
}

/// Renders one kept answer, as `kr question drafts` found it, for a script.
#[must_use]
pub fn kept_rendered(reconciled: &Reconciled) -> Value {
    let (draft, state, reason) = match reconciled {
        Reconciled::Offered(draft) => (draft, "offered", None),
        Reconciled::Retired { draft, reason } => (draft, "retired", Some(*reason)),
    };
    json!({
        "question_id": draft.question_id.to_string(),
        "session_id": draft.session_id.to_string(),
        "state": state,
        "reason": reason.map(retired_because),
        "reason_code": reason.map(|reason| AnswerError::Retired(reason).code().as_str()),
        "question_revision": draft.question_revision.get(),
        "answer": answer_document(&draft.answer),
        "drafted_at_ms": draft.drafted_at_ms.get(),
    })
}

/// Renders one kept answer, as `kr question drafts` found it, as a line for a person.
#[must_use]
pub fn kept_line(reconciled: &Reconciled) -> String {
    match reconciled {
        Reconciled::Offered(draft) => format!(
            "{}  offered  {} at revision {}; send it with kr question send {}",
            draft.question_id,
            answer_words(&draft.answer),
            draft.question_revision.get(),
            draft.question_id
        ),
        Reconciled::Retired { draft, reason } => format!(
            "{}  retired  {}; this command did not send it, and it is no longer kept",
            draft.question_id,
            retired_because(*reason)
        ),
    }
}

/// An answer, for a script.
fn answer_document(answer: &QuestionAnswer) -> Value {
    json!({
        "kind": answer.kind(),
        "text": answer.text(),
        "choice_id": match answer {
            QuestionAnswer::Choice { choice_id } => Some(choice_id.clone()),
            _ => None,
        },
        "decided": match answer {
            QuestionAnswer::Decision { decided } => Some(*decided),
            _ => None,
        },
    })
}

/// An answer, in the words a person is shown.
fn answer_words(answer: &QuestionAnswer) -> String {
    match answer {
        QuestionAnswer::Input { text } | QuestionAnswer::Other { text } => format!("{text:?}"),
        QuestionAnswer::Choice { choice_id } => format!("choice {choice_id}"),
        QuestionAnswer::Decision { decided } => if *decided { "yes" } else { "no" }.to_owned(),
    }
}

/// This host's session workers, as the answering rules reach them.
///
/// A session's worker is found by its descriptor and proved against it before anything is sent to
/// it, as every command that reaches a worker proves it, and one connection to it is kept for the
/// length of the command. What became of the last answer that was not taken is remembered, so the
/// person can be told why it was kept.
pub struct Workers {
    paths: HostPaths,
    build_id: BuildId,
    connections: tokio::sync::Mutex<BTreeMap<SessionId, LocalClient>>,
    failure: std::sync::Mutex<Option<Failure>>,
    /// What the attempt to send the answer has established so far. Nothing is written before the
    /// attempt, so it starts as not sent.
    delivery: std::sync::Mutex<Delivery>,
    /// The environment each session ran in: where its descriptor is published, and whose daemon
    /// says whether it ended.
    environments: BTreeMap<SessionId, EnvironmentId>,
}

impl Workers {
    /// Reaches this host's workers with `build_id`.
    #[must_use]
    pub fn new(paths: &HostPaths, build_id: BuildId) -> Self {
        Self {
            paths: paths.clone(),
            build_id,
            connections: tokio::sync::Mutex::new(BTreeMap::new()),
            failure: std::sync::Mutex::new(None),
            delivery: std::sync::Mutex::new(Delivery::NotSent),
            environments: BTreeMap::new(),
        }
    }

    /// Knows the environment each of these kept answers' sessions ran in.
    #[must_use]
    pub fn knowing(mut self, drafts: &[AnswerDraft]) -> Self {
        self.environments.extend(
            drafts
                .iter()
                .map(|draft| (draft.session_id, draft.target.environment_id)),
        );
        self
    }

    /// Starts from a connection already open to the worker `descriptor` names, and proved.
    #[must_use]
    pub fn holding(mut self, descriptor: &WorkerDescriptor, client: LocalClient) -> Self {
        self.environments
            .insert(descriptor.session_id, descriptor.environment_id);
        self.connections
            .get_mut()
            .insert(descriptor.session_id, client);
        self
    }

    /// Why the last answer was not taken, or what failed after it was.
    fn failure(&self) -> Option<Failure> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn failed(&self, code: ErrorCode, why: String) {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Failure { code, why });
    }

    /// What the attempt to send the answer established about whether its worker took it.
    fn delivery(&self) -> Delivery {
        *self
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn delivered(&self, delivery: Delivery) {
        *self
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = delivery;
    }

    /// The connection to the worker of `session_id`, opened and proved when there is none yet.
    async fn connection<'a>(
        &self,
        connections: &'a mut BTreeMap<SessionId, LocalClient>,
        session_id: SessionId,
    ) -> std::result::Result<&'a mut LocalClient, ClientError> {
        Ok(match connections.entry(session_id) {
            std::collections::btree_map::Entry::Occupied(held) => held.into_mut(),
            std::collections::btree_map::Entry::Vacant(missing) => {
                missing.insert(self.open(session_id).await?)
            }
        })
    }

    /// Opens and proves a connection to the worker of `session_id`.
    ///
    /// A session ends only when its environment's daemon says so: a closure its registry keeps, or
    /// no record at all of a session whose descriptor is proved absent. That, and nothing else, is
    /// the host's own `UNKNOWN_SESSION`, which retires a kept answer as gone. A descriptor that is
    /// missing, a descriptor or directory that cannot be read or trusted, and a worker that cannot
    /// be reached, say nothing about whether the session ended; each is a failure that retires
    /// nothing.
    async fn open(&self, session_id: SessionId) -> std::result::Result<LocalClient, ClientError> {
        let Some(descriptor) = self.descriptor(session_id)? else {
            return Err(match self.ended(session_id, true).await {
                Ok(gone) => gone,
                Err(why) => ClientError::Host(ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    format!("session {session_id} has published no descriptor, and {why}"),
                )),
            });
        };
        match open_worker(&descriptor, self.build_id.clone()).await {
            Ok(client) => Ok(client),
            // A worker that cannot be reached may have ended with its session; only a closure
            // its daemon keeps says so.
            Err(error) => match self.ended(session_id, false).await {
                Ok(gone) => Err(gone),
                Err(why) => {
                    self.failed(
                        ErrorCode::ResourceUnavailable,
                        format!(
                            "session {session_id}'s worker could not be reached ({error}), and \
                             {why}"
                        ),
                    );
                    Err(ClientError::ConnectionEnded)
                }
            },
        }
    }

    /// The descriptor `session_id` published in the environment it ran in, or none when that
    /// environment's descriptor directory, read and trusted, holds none for it.
    ///
    /// Only that one environment is read, and by the session's own name, so an answer of none is
    /// the directory's own word that nothing is published there, never a directory that could not
    /// be read.
    ///
    /// # Errors
    ///
    /// An environment this host cannot identify, and a descriptor directory or file that cannot be
    /// read or trusted, are failures: they are no evidence the session is gone, and they are not a
    /// worker to reach.
    fn descriptor(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Option<WorkerDescriptor>, ClientError> {
        let unreadable = |detail: String| {
            ClientError::Host(ProtocolError::new(ErrorCode::ResourceUnavailable, detail))
        };
        let environment = self.environment(session_id).map_err(|why| {
            unreadable(format!(
                "session {session_id}'s descriptor cannot be looked for: {why}"
            ))
        })?;
        kr_ipc::descriptor::read(&environment.paths, session_id).map_err(|error| {
            unreadable(format!(
                "whether session {session_id} has published a descriptor cannot be read: {error}"
            ))
        })
    }

    /// The environment `session_id` ran in, as this host knows it.
    fn environment(&self, session_id: SessionId) -> std::result::Result<KnownEnvironment, String> {
        let Some(environment_id) = self.environments.get(&session_id) else {
            return Err("which environment it ran in is not known".to_owned());
        };
        crate::resolve::select(&self.paths, Some(&environment_id.to_string()))
            .map_err(|error| error.to_string())
    }

    /// Whether the daemon of the environment `session_id` ran in establishes that it ended.
    ///
    /// A closure its registry keeps does, and so, when the session has published no descriptor,
    /// does a registry that never held the session at all: nothing on this host can reach such a
    /// session again. Everything else, a daemon that is not running, a session it reports live, a
    /// registry with no record of a session whose descriptor is still published, an environment
    /// this host does not have, establishes nothing, and what the daemon said is returned.
    async fn ended(
        &self,
        session_id: SessionId,
        unpublished: bool,
    ) -> std::result::Result<ClientError, String> {
        let gone = |detail: String| {
            ClientError::Host(ProtocolError::new(ErrorCode::UnknownSession, detail))
        };
        let Some(environment) = self.environments.get(&session_id) else {
            return Err("which environment it ran in is not known".to_owned());
        };
        let environment = environment.to_string();
        match crate::resolve::registered(
            &self.paths,
            &SessionSelector::Identifier(session_id),
            Some(&environment),
        )
        .await
        {
            Ok(crate::resolve::Registered::Closed { .. }) => {
                Ok(gone(format!("session {session_id} has closed")))
            }
            Err(CliError::UnknownSession(_)) if unpublished => Ok(gone(format!(
                "this host has no record of session {session_id}"
            ))),
            Err(CliError::UnknownSession(_)) => {
                Err("its environment's daemon has no record of it".to_owned())
            }
            Ok(crate::resolve::Registered::Unpublished { state, .. }) => {
                Err(format!("its environment's daemon reports it {state}"))
            }
            Err(error) => Err(format!(
                "whether it has ended cannot be established: {error}"
            )),
        }
    }
}

/// Whether a failure of the connection to a worker is the connection going, rather than something
/// the worker sent or said.
///
/// The drafts library keeps an answer on exactly these and on a transient refusal, and shows every
/// other failure: a malformed message is the worker's own answer, not a lost connection.
fn connection_went(failure: &kr_ipc::IpcError) -> bool {
    matches!(
        failure,
        kr_ipc::IpcError::PeerClosed
            | kr_ipc::IpcError::Socket { .. }
            | kr_ipc::IpcError::TruncatedFrame { .. }
            | kr_ipc::IpcError::Frame(kr_protocol::frame::FrameError::Incomplete { .. })
    )
}

impl QuestionHost for Workers {
    async fn questions(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Vec<Question>, ClientError> {
        let mut connections = self.connections.lock().await;
        let client = self.connection(&mut connections, session_id).await?;
        let outcome = client
            .request(
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id,
                    question_id: Nullable::null(),
                    include_resolved: true,
                },
            )
            .await;
        let value = match outcome {
            Ok(Ok(value)) => value,
            // The host's `UNKNOWN_SESSION` retires a kept answer, and only a session's daemon says
            // a session ended. A worker refusing with that code about its own session is passed on
            // as the refusal it is, one that retires nothing.
            Ok(Err(refusal)) if refusal.code == ErrorCode::UnknownSession => {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    format!(
                        "session {session_id}'s worker answered that it does not know its own \
                         session ({refusal}), and only its daemon says whether a session ended"
                    ),
                )));
            }
            Ok(Err(refusal)) => return Err(ClientError::from(refusal)),
            Err(error) => {
                connections.remove(&session_id);
                return Err(ClientError::Ipc(error));
            }
        };
        let read: QuestionReadResult = value.to_typed()?;
        Ok(read.questions)
    }

    async fn answer(
        &self,
        target: ActionTarget,
        params: QuestionAnswerParams,
    ) -> std::result::Result<Question, ClientError> {
        let session_id = params.session_id;
        // Nothing is written until the mutation goes out, whatever an earlier attempt recorded.
        self.delivered(Delivery::NotSent);
        let mut connections = self.connections.lock().await;
        let client = self.connection(&mut connections, session_id).await?;
        let action_id = ActionId::new(kr_ipc::new_uuid());
        // Composing reads whatever the worker already sent and writes nothing, so a failure here
        // sent nothing.
        let mutation = match client
            .compose(Method::QuestionAnswer, action_id, target, &params)
            .await
        {
            Ok(mutation) => mutation,
            Err(failure) => {
                connections.remove(&session_id);
                self.failed(
                    failure.code(),
                    format!(
                        "the connection to session {session_id}'s worker failed before the answer \
                         was sent ({failure})"
                    ),
                );
                return Err(ClientError::Ipc(failure));
            }
        };
        // From here the answer may be on its way, and only the worker's word says more.
        self.delivered(Delivery::Unknown);
        match client.repeat(&mutation).await {
            Ok(Ok(value)) => {
                self.delivered(Delivery::Taken);
                match value.to_typed::<QuestionResolveResult>() {
                    Ok(resolved) => Ok(resolved.question),
                    Err(unreadable) => {
                        let error = ClientError::from(unreadable);
                        self.failed(error.code(), format!("its reply cannot be read ({error})"));
                        Err(error)
                    }
                }
            }
            // A refusal is the worker not taking the answer, unless the worker itself says it
            // cannot tell what became of it.
            Ok(Err(refusal)) => {
                if refusal.code == ErrorCode::OutcomeUnknown {
                    self.failed(
                        refusal.code,
                        format!(
                            "session {session_id}'s worker could not say what became of it \
                             ({refusal})"
                        ),
                    );
                } else {
                    self.delivered(Delivery::NotTaken);
                    self.failed(
                        refusal.code,
                        format!("session {session_id}'s worker refused it ({refusal})"),
                    );
                }
                Err(ClientError::from(refusal))
            }
            // Sending reads what is pending, writes the answer and waits for the reply, and a
            // connection that goes at any of those points may have carried the answer or not.
            Err(failure) if connection_went(&failure) => {
                connections.remove(&session_id);
                self.failed(
                    ErrorCode::OutcomeUnknown,
                    format!(
                        "the connection to session {session_id}'s worker ended while the answer \
                         was being sent ({failure})"
                    ),
                );
                Err(ClientError::SubmissionUncertain { action_id })
            }
            // A reply this command cannot read came after the answer went out, so the answer may
            // have been taken.
            Err(failure) => {
                connections.remove(&session_id);
                self.failed(
                    failure.code(),
                    format!(
                        "session {session_id}'s worker sent a reply this command cannot read, so \
                         whether it took the answer is not known ({failure})"
                    ),
                );
                Err(ClientError::Ipc(failure))
            }
        }
    }
}

/// Cancels one question.
///
/// # Errors
///
/// As [`answer`].
pub async fn cancel(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<Question> {
    let (descriptor, question, mut client) = locate(paths, question_id, build_id).await?;
    let result: QuestionResolveResult = mutate(
        &mut client,
        &descriptor,
        Method::QuestionCancel,
        &QuestionCancelParams {
            session_id: descriptor.session_id,
            question_id,
            expected_revision: question.revision,
        },
    )
    .await?;
    Ok(result.question)
}

/// Renders one question for a script.
#[must_use]
pub fn rendered(descriptor: &WorkerDescriptor, question: &Question) -> Value {
    json!({
        "question_id": question.question_id.to_string(),
        "revision": question.revision.get(),
        "state": question.state.as_str(),
        "session_id": question.session_id.to_string(),
        "display_number": descriptor.display_number.get(),
        "type": question.kind.as_str(),
        "context": question.context,
        "question": question.question,
        "choices": question
            .choices
            .iter()
            .map(|choice| json!({"choice_id": choice.choice_id, "label": choice.label}))
            .collect::<Vec<_>>(),
        // The identity the broker verified, and the label the caller supplied, kept apart.
        "verified_source": {
            "executable": question.source.executable.as_ref().cloned(),
            "pid": question.source.process.pid.get(),
            "application_instance_id": question.source.application_instance_id.to_string(),
            "session_member": question.source.session_member,
            "ancestry": question.source.ancestry,
            "launch_channel": question.source.launch_channel,
        },
        "unverified_agent_label": question.source.agent_label.as_ref().cloned(),
        "created_at_ms": question.created_at_ms.get(),
        "expires_at_ms": question.expires_at_ms.get(),
        "answer": question.answer.as_ref().map(|record| json!({
            "kind": record.answer.kind(),
            "text": record.answer.text(),
            "choice_id": match &record.answer {
                QuestionAnswer::Choice { choice_id } => Some(choice_id.clone()),
                _ => None,
            },
            "decided": match &record.answer {
                QuestionAnswer::Decision { decided } => Some(*decided),
                _ => None,
            },
            "actor_id": record.actor_id.to_string(),
            "device_id": record.device_id.as_ref().map(ToString::to_string),
            "question_revision": record.question_revision.get(),
            "answered_at_ms": record.answered_at_ms.get(),
        })),
    })
}

/// Renders one question as a line for a person.
#[must_use]
pub fn line(descriptor: &WorkerDescriptor, question: &Question) -> String {
    format!(
        "{:<36} {:>4}  {:<9} {:<8} {}  [{}]",
        question.question_id.to_string(),
        descriptor.display_number.get(),
        question.state.as_str(),
        question.kind.as_str(),
        first_line(&question.question),
        verified_identity(question),
    )
}

/// Renders one question in full, for a person about to answer it.
#[must_use]
pub fn detail(descriptor: &WorkerDescriptor, question: &Question) -> String {
    let mut text = String::new();
    text.push_str(&format!("question  {}\n", question.question_id));
    text.push_str(&format!(
        "session   {} (display {})\n",
        question.session_id,
        descriptor.display_number.get()
    ));
    text.push_str(&format!(
        "asked by  {}  (verified)\n",
        verified_identity(question)
    ));
    if let Some(label) = question.source.agent_label.as_ref() {
        text.push_str(&format!(
            "label     {label}  (unverified, supplied by the caller)\n"
        ));
    }
    text.push_str(&format!(
        "state     {} at revision {}\n",
        question.state.as_str(),
        question.revision.get()
    ));
    text.push_str(&format!("expires   {}\n", question.expires_at_ms.get()));
    text.push('\n');
    if !question.context.trim().is_empty() {
        text.push_str(&format!("{}\n\n", question.context));
    }
    text.push_str(&format!("{}\n", question.question));
    if !question.choices.is_empty() {
        text.push('\n');
        for choice in &question.choices {
            let note = if choice.choice_id == SOMETHING_ELSE_CHOICE {
                "   (--other \"...\")"
            } else {
                ""
            };
            text.push_str(&format!(
                "  {:<20} {}{note}\n",
                choice.choice_id, choice.label
            ));
        }
    }
    if let Some(record) = question.answer.as_ref() {
        text.push('\n');
        text.push_str(&format!(
            "answered  {} by {}\n",
            match &record.answer {
                QuestionAnswer::Input { text } | QuestionAnswer::Other { text } => text.clone(),
                QuestionAnswer::Choice { choice_id } => choice_id.clone(),
                QuestionAnswer::Decision { decided } =>
                    if *decided {
                        "yes".to_owned()
                    } else {
                        "no".to_owned()
                    },
            },
            record.actor_id
        ));
    }
    text
}

/// Returns the verified application identity a person reads before answering.
fn verified_identity(question: &Question) -> String {
    question.source.executable.as_ref().map_or_else(
        || format!("process {}", question.source.process.pid.get()),
        |executable| format!("{executable} ({})", question.source.process.pid.get()),
    )
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default();
    if line.chars().count() > 48 {
        let shortened: String = line.chars().take(47).collect();
        format!("{shortened}…")
    } else {
        line.to_owned()
    }
}

/// Finds the session holding one question, and the connection to it.
async fn locate(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<(WorkerDescriptor, Question, LocalClient)> {
    for descriptor in descriptors(paths, &Scope::Everything)? {
        let Ok(mut client) = open_worker(&descriptor, build_id.clone()).await else {
            continue;
        };
        let outcome: Result<QuestionReadResult> = read(
            &mut client,
            &QuestionReadParams {
                session_id: descriptor.session_id,
                question_id: Nullable::some(question_id),
                include_resolved: true,
            },
        )
        .await;
        if let Ok(result) = outcome
            && let Some(question) = result.questions.into_iter().next()
        {
            return Ok((descriptor, question, client));
        }
    }
    Err(CliError::Usage(format!(
        "no session on this host has question {question_id}"
    )))
}

fn descriptors(paths: &HostPaths, scope: &Scope) -> Result<Vec<WorkerDescriptor>> {
    match scope {
        Scope::Session(selector) => {
            let (_, descriptor) = find(paths, selector, None)?;
            Ok(vec![descriptor])
        }
        Scope::Everything => {
            let mut found = Vec::new();
            for known in environments(paths)? {
                collect(&known, &mut found);
            }
            found.sort_by_key(|descriptor| descriptor.display_number.get());
            Ok(found)
        }
    }
}

fn collect(known: &KnownEnvironment, found: &mut Vec<WorkerDescriptor>) {
    let Ok(entries) = kr_ipc::descriptor::read_all(&known.paths) else {
        return;
    };
    for entry in entries {
        if let Ok(descriptor) = entry.descriptor {
            found.push(descriptor);
        }
    }
}

async fn read<T: kr_protocol::wire::WireMessage>(
    client: &mut LocalClient,
    params: &QuestionReadParams,
) -> Result<T> {
    let outcome = client.request(Method::QuestionRead, params).await?;
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}

async fn mutate<P, T>(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    method: Method,
    params: &P,
) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(method, action_id, crate::attach::target(descriptor), params)
        .await?;
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}

/// Returns whether a question is still waiting for somebody.
#[must_use]
pub const fn is_pending(question: &Question) -> bool {
    matches!(question.state, QuestionState::Pending)
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
    use kr_protocol::ids::{ApplicationInstanceId, ConnectionId, QuestionRevision, SessionEpoch};
    use kr_protocol::question::{QuestionKind, QuestionSource};
    use kr_protocol::scalars::{TimestampMs, Uuid};

    use super::*;

    fn descriptor() -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            display_number: kr_protocol::session::DisplayNumber::new(3),
            boot_identity: kr_protocol::identity::BootIdentity {
                source: kr_protocol::identity::BootIdentitySource::LinuxBootId,
                value: kr_protocol::scalars::Bytes::new(b"boot".to_vec()),
            },
            process_start_identity: ProcessStartIdentity::new(
                9,
                ProcessStartSource::LinuxProcStat,
                1,
            ),
            endpoint: "/tmp/socket".to_owned(),
            worker_public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([0; 32]),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            published_at_ms: TimestampMs::new(1),
        }
    }

    fn question(state: QuestionState) -> Question {
        Question {
            question_id: QuestionId::new(Uuid::from_bytes([4; 16])),
            revision: QuestionRevision::new(1),
            state,
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            session_epoch: SessionEpoch::V1,
            kind: QuestionKind::Select,
            context: "two ways".to_owned(),
            question: "which one?".to_owned(),
            choices: vec![
                kr_protocol::question::QuestionChoice {
                    choice_id: "left".to_owned(),
                    label: "Left".to_owned(),
                },
                kr_protocol::question::QuestionChoice::something_else(),
            ],
            source: QuestionSource {
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([5; 16])),
                process: ProcessStartIdentity::new(42, ProcessStartSource::LinuxProcStat, 7),
                executable: Nullable::some("/usr/bin/some-agent".to_owned()),
                agent_label: Nullable::some("Totally The Host".to_owned()),
                connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
                launch_channel: false,
                session_member: true,
                ancestry: true,
                agent_binding_revision: Nullable::null(),
            },
            created_at_ms: TimestampMs::new(10),
            expires_at_ms: TimestampMs::new(20),
            answer: Nullable::null(),
            resolved_at_ms: Nullable::null(),
        }
    }

    #[test]
    fn the_verified_identity_leads_and_the_caller_label_is_marked_unverified() {
        let question = question(QuestionState::Pending);
        let text = detail(&descriptor(), &question);
        assert!(text.contains("/usr/bin/some-agent (42)  (verified)"));
        assert!(text.contains("Totally The Host  (unverified, supplied by the caller)"));
        let value = rendered(&descriptor(), &question);
        assert_eq!(
            value["verified_source"]["executable"],
            "/usr/bin/some-agent"
        );
        assert_eq!(value["unverified_agent_label"], "Totally The Host");
    }

    #[test]
    fn the_free_text_option_is_shown_with_the_flag_that_answers_it() {
        let text = detail(&descriptor(), &question(QuestionState::Pending));
        assert!(text.contains("something_else"));
        assert!(text.contains("--other"));
    }

    fn kept_draft_for(question: &Question) -> AnswerDraft {
        AnswerDraft {
            target: crate::attach::target(&descriptor()),
            session_id: question.session_id,
            question_id: question.question_id,
            question_revision: question.revision,
            answer: QuestionAnswer::Choice {
                choice_id: "left".to_owned(),
            },
            drafted_at_ms: TimestampMs::new(30),
        }
    }

    #[test]
    fn a_kept_answer_says_whether_it_can_be_sent_and_why_not() {
        let draft = kept_draft_for(&question(QuestionState::Pending));
        let offered = Reconciled::Offered(draft.clone());
        assert!(kept_line(&offered).contains("offered  choice left at revision 1"));
        assert_eq!(kept_rendered(&offered)["state"], "offered");
        assert!(kept_rendered(&offered)["reason"].is_null());
        for (reason, words, code) in [
            (
                Retired::Ended(QuestionState::Expired),
                "the question was expired while the answer was kept",
                "QUESTION_EXPIRED",
            ),
            (
                Retired::Ended(QuestionState::Answered),
                "the question was answered while the answer was kept",
                "QUESTION_RESOLVED",
            ),
            (
                Retired::Moved {
                    revision: QuestionRevision::new(3),
                },
                "the question moved to revision 3 while the answer was kept",
                "STALE_SESSION",
            ),
            (
                Retired::Gone,
                "its session is not on this host any more",
                "UNKNOWN_SESSION",
            ),
        ] {
            let retired = Reconciled::Retired {
                draft: draft.clone(),
                reason,
            };
            let line = kept_line(&retired);
            assert!(line.contains("retired"), "{line}");
            assert!(line.contains(words), "{line}");
            assert!(line.contains("this command did not send it"), "{line}");
            assert!(!line.contains("was not sent"), "{line}");
            let document = kept_rendered(&retired);
            assert_eq!(document["state"], "retired");
            assert_eq!(document["reason_code"], code, "{document}");
            let refused = answer_failure(AnswerError::Retired(reason));
            assert_eq!(refused.code(), code);
            assert!(
                refused
                    .to_string()
                    .contains("this command did not send the kept answer"),
                "{refused}"
            );
            assert!(!refused.to_string().contains("was not sent"), "{refused}");
        }
    }

    #[test]
    fn a_listing_line_carries_the_state_and_the_verified_identity() {
        let text = line(&descriptor(), &question(QuestionState::Pending));
        assert!(text.contains("pending"));
        assert!(text.contains("/usr/bin/some-agent"));
    }
}
