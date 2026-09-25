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
//! still be sent, or was retired unsent because its question ended or moved; it sends nothing.
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
use kr_protocol::ids::{ActionId, BuildId, QuestionId, SessionId};
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
/// for an answer that does not fit the question's form, and [`CliError::Refused`] when the question
/// has already been resolved, has expired, or has moved to a revision this command did not read.
pub async fn answer(
    paths: &HostPaths,
    question_id: QuestionId,
    answer: QuestionAnswer,
    build_id: BuildId,
) -> Result<Question> {
    let (descriptor, question, client) = locate(paths, question_id, build_id.clone()).await?;
    let drafts = kept_answers(paths)?;
    let workers = Workers::new(paths, build_id).holding(descriptor.session_id, client);
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
        Err(error) => Err(answer_failure(error)),
    }
}

/// Reads the questions of every kept answer again, and says of each whether it can still be sent.
///
/// A kept answer whose question is still pending at the revision it answers is offered and stays
/// kept. Any other is retired: it is not sent and no longer kept. Nothing is sent, however often
/// this runs.
///
/// # Errors
///
/// Returns a failure when the store cannot be read, and when a session holding a kept answer's
/// question cannot be read, in which case nothing is retired.
pub async fn drafts(paths: &HostPaths, build_id: BuildId) -> Result<Vec<Reconciled>> {
    let drafts = kept_answers(paths)?;
    let workers = Workers::new(paths, build_id);
    answers::reconcile(&workers, &drafts)
        .await
        .map_err(answer_failure)
}

/// Sends one kept answer, which is the one way a kept answer is ever sent.
///
/// The question is read again first, and an answer whose question ended or moved is retired rather
/// than sent.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when no answer to the question is kept, [`CliError::AnswerKept`]
/// when the worker could not take it and it stays kept, and [`CliError::Refused`] when the question
/// ended or moved.
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
    let workers = Workers::new(paths, build_id);
    match answers::send(&workers, &drafts, &draft).await {
        Ok(question) => Ok(question),
        // The library keeps a draft it could not send for any reason but its question's end, so
        // what is still in the store says which this was.
        Err(error) => match kept_draft(&drafts, question_id) {
            Ok(Some(_)) if !matches!(error, AnswerError::Retired(_)) => {
                Err(kept(&workers, question_id, "is still kept"))
            }
            _ => Err(answer_failure(error)),
        },
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

/// The failure an answer that was not sent is reported as, with why and what to do about it.
fn kept(workers: &Workers, question_id: QuestionId, which: &str) -> CliError {
    let (code, why) = workers.failure().unwrap_or((
        ErrorCode::ResourceUnavailable,
        "its session's worker could not take it".to_owned(),
    ));
    CliError::AnswerKept {
        code,
        message: format!(
            "the answer to question {question_id} {which} on this device and not sent: {why}. \
             `kr question drafts` says whether it can still be sent, and \
             `kr question send {question_id}` sends it"
        ),
    }
}

/// Turns a failure of the kept-answer rules into this command's own.
fn answer_failure(error: AnswerError) -> CliError {
    let code = error.code();
    match error {
        AnswerError::Form(message) => CliError::Usage(message),
        AnswerError::Retired(reason) => CliError::Refused(ProtocolError::new(
            code,
            format!(
                "{}, so the kept answer was not sent",
                retired_because(reason)
            ),
        )),
        AnswerError::Host(
            ClientError::Host(refusal) | ClientError::Refused { error: refusal, .. },
        ) => CliError::Refused(refusal),
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
            "{}  retired  {}; it was not sent and is no longer kept",
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
    failure: std::sync::Mutex<Option<(ErrorCode, String)>>,
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
        }
    }

    /// Starts from a connection already open to one session's worker, and proved.
    #[must_use]
    pub fn holding(mut self, session_id: SessionId, client: LocalClient) -> Self {
        self.connections.get_mut().insert(session_id, client);
        self
    }

    /// Why the last answer was not taken, with the code that says which kind of reason it is.
    fn failure(&self) -> Option<(ErrorCode, String)> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn failed(&self, code: ErrorCode, why: String) {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((code, why));
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
    /// A session no descriptor names is gone as far as this host is concerned, which is the
    /// host's own `UNKNOWN_SESSION`. A worker that cannot be reached has not answered, and that is
    /// a connection that ended.
    async fn open(&self, session_id: SessionId) -> std::result::Result<LocalClient, ClientError> {
        let descriptor = match find(&self.paths, &SessionSelector::Identifier(session_id), None) {
            Ok((_, descriptor)) => descriptor,
            Err(CliError::UnknownSession(_)) => {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::UnknownSession,
                    format!("no session {session_id} is on this host"),
                )));
            }
            Err(error) => {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    error.to_string(),
                )));
            }
        };
        open_worker(&descriptor, self.build_id.clone())
            .await
            .map_err(|error| {
                self.failed(
                    ErrorCode::ResourceUnavailable,
                    format!("session {session_id}'s worker could not be reached ({error})"),
                );
                ClientError::ConnectionEnded
            })
    }
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
        let mut connections = self.connections.lock().await;
        let client = self.connection(&mut connections, session_id).await?;
        let action_id = ActionId::new(kr_ipc::new_uuid());
        // Composing reads whatever the worker already sent, before anything is written. A
        // connection that fails here has sent nothing.
        let mutation = match client
            .compose(Method::QuestionAnswer, action_id, target, &params)
            .await
        {
            Ok(mutation) => mutation,
            Err(error) => {
                connections.remove(&session_id);
                self.failed(
                    ErrorCode::ResourceUnavailable,
                    format!(
                        "the connection to session {session_id}'s worker ended before the answer \
                         was sent ({error})"
                    ),
                );
                return Err(ClientError::ConnectionEnded);
            }
        };
        match client.repeat(&mutation).await {
            Ok(Ok(value)) => {
                let resolved: QuestionResolveResult = value.to_typed()?;
                Ok(resolved.question)
            }
            Ok(Err(refusal)) => {
                self.failed(
                    refusal.code,
                    format!("session {session_id}'s worker did not take it ({refusal})"),
                );
                Err(ClientError::from(refusal))
            }
            // Once the answer is written, a connection that ends leaves what became of it unknown.
            Err(error) => {
                connections.remove(&session_id);
                self.failed(
                    ErrorCode::OutcomeUnknown,
                    format!(
                        "the connection to session {session_id}'s worker ended after the answer \
                         was sent, so whether it arrived is not known ({error})"
                    ),
                );
                Err(ClientError::SubmissionUncertain { action_id })
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
            assert!(line.contains("not sent"), "{line}");
            let document = kept_rendered(&retired);
            assert_eq!(document["state"], "retired");
            assert_eq!(document["reason_code"], code, "{document}");
            let refused = answer_failure(AnswerError::Retired(reason));
            assert_eq!(refused.code(), code);
            assert!(refused.to_string().contains("was not sent"), "{refused}");
        }
    }

    #[test]
    fn a_listing_line_carries_the_state_and_the_verified_identity() {
        let text = line(&descriptor(), &question(QuestionState::Pending));
        assert!(text.contains("pending"));
        assert!(text.contains("/usr/bin/some-agent"));
    }
}
