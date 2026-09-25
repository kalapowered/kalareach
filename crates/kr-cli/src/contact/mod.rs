//! `kr agent-tools --stdio`: the contact tools, spoken over the Model Context Protocol.
//!
//! An agent running inside a KalaReach session reaches its person through four tools and no more:
//!
//! | Tool | What it does |
//! | --- | --- |
//! | `ask_user` | Creates a durable question and returns its identity, its state and a caller token |
//! | `wait_for_answer` | Long-polls that question, returning the same question when the poll times out |
//! | `cancel_question` | Withdraws a question that is no longer needed |
//! | `send_notification` | Raises an alert, which asks for nothing |
//!
//! The tools enumerate nothing, read no history and send no input. What binds a call to a session
//! is the worker's own check of the calling process, made over a private socket the operating
//! system authenticates; this process supplies no credential and asserts no identity. Outside a
//! session every tool answers `NOT_IN_KR_SESSION` and creates nothing.
//!
//! An answer is not an approval. Answering `yes` here resolves this question and nothing else: it
//! cannot produce an upstream approval identifier or widen any grant.
//!
//! A tool call the client cancels takes its question with it. Section 11 makes upstream
//! cancellation cancel the corresponding pending question, so an `ask_user` or a `wait_for_answer`
//! whose call the client cancels, with its own `notifications/cancelled`, cancels the question it
//! was creating or waiting on, rather than leaving a decision in front of the person that nothing
//! will collect. A wait that runs out on its own is not a cancellation and changes nothing, and
//! neither is this server stopping because its transport ended: then the question ends with this
//! process, as expired.

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, CancelledNotificationParam, RequestId, ServerCapabilities, ServerConfig,
};
use rmcp::service::{MaybeSendFuture, NotificationContext, RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{BuildId, QuestionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    AlertCreateParams, AlertCreateResult, AlertSeverity, CallerToken, MAX_CREATE_WAIT, MAX_WAIT,
    Question, QuestionAnswer, QuestionCancelOwnParams, QuestionChoice, QuestionCreateParams,
    QuestionCreateResult, QuestionKind, QuestionOwnResult, QuestionReadOwnParams, WAIT_RENEWAL,
};
use kr_protocol::scalars::{DurationMs, Nullable};

use crate::bind::{self, Bound, SETUP_INSTRUCTION};

/// The variable an installation names this client's tool deadline in.
///
/// It is written into the environment the agent launches this server with, beside the same number
/// in the agent's own configuration, so what a wait is bounded by is the deadline the client
/// actually enforces rather than a guess.
const DEADLINE_VARIABLE: &str = "KR_TOOL_DEADLINE_MS";

/// How long a poll runs when neither the caller nor the installation named a bound.
///
/// Section 11's default is five minutes, shortened to the installed client's qualified tool
/// deadline. Where the installation could not establish one — an agent that lets no server declare
/// a deadline, or a document shared by agents that do not spell it the same way — there is nothing
/// to shorten to, and a client's own default is often a minute. A wait that outlives the client's
/// deadline loses the call, so an unqualified one is kept short.
const UNQUALIFIED_WAIT: DurationMs = DurationMs::new(45 * 1000);

/// What a wait leaves for the answer to travel back in.
const DEADLINE_MARGIN: DurationMs = DurationMs::new(15 * 1000);

/// Returns the client deadline this installation established, when it established one.
fn declared_deadline() -> Option<DurationMs> {
    std::env::var(DEADLINE_VARIABLE)
        .ok()?
        .trim()
        .parse()
        .ok()
        .map(DurationMs::new)
}

/// Returns how long one wait may run, against its own ceiling.
///
/// Three bounds, whichever is shortest: what the caller asked for, the ceiling of the call it is
/// for, and the client deadline the installation established less the room an answer needs to
/// travel back in. Where no deadline was established nothing here knows what the client allows, so
/// the conservative bound applies to what the caller asked for as well as to what it did not: an
/// agent that needs longer asks again, and the question is durable either way. A declared deadline
/// with nothing left in it after that room is a budget of nothing, not an absent one.
fn wait_within(
    asked: Option<DurationMs>,
    declared: Option<DurationMs>,
    ceiling: DurationMs,
) -> DurationMs {
    let Some(declared) = declared else {
        let unqualified = UNQUALIFIED_WAIT.get().min(ceiling.get());
        return DurationMs::new(asked.map_or(unqualified, |asked| asked.get().min(unqualified)));
    };
    let budget = declared.get().saturating_sub(DEADLINE_MARGIN.get());
    let requested = asked.map_or(kr_protocol::question::DEFAULT_WAIT.get(), |asked| {
        asked.get()
    });
    DurationMs::new(requested.min(budget).min(ceiling.get()))
}

/// Returns how long one long poll may run.
fn poll_within(asked: Option<DurationMs>, declared: Option<DurationMs>) -> DurationMs {
    wait_within(asked, declared, MAX_WAIT)
}

/// Returns how long one poll may run, against what this installation declared.
fn poll_duration(asked: Option<DurationMs>) -> DurationMs {
    poll_within(asked, declared_deadline())
}
use crate::error::CliError;

/// One choice an `ask_user` select offers.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct ChoiceInput {
    /// The stable identifier an answer names. It does not change with the label.
    pub choice_id: String,
    /// What the person reads.
    pub label: String,
}

impl std::fmt::Debug for ChoiceInput {
    /// How long its identifier and its label are, never what they say: an agent wrote both.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChoiceInput")
            .field("choice_id_bytes", &self.choice_id.len())
            .field("label_bytes", &self.label.len())
            .finish()
    }
}

/// What kind of answer a question asks for.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AskType {
    /// Free text.
    Input,
    /// One of two to twelve choices, or free text.
    Select,
    /// Yes, no, or free text.
    Confirm,
}

impl From<AskType> for QuestionKind {
    fn from(value: AskType) -> Self {
        match value {
            AskType::Input => Self::Input,
            AskType::Select => Self::Select,
            AskType::Confirm => Self::Confirm,
        }
    }
}

/// The parameters of `ask_user`.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct AskUserParams {
    /// Your own unpredictable identifier for this request. Repeating it with the same payload
    /// returns the same question instead of asking twice.
    pub request_id: String,
    /// What to call you in the form. It is displayed as an unverified label beside the
    /// application identity the host verified.
    #[serde(default)]
    pub agent_name: Option<String>,
    /// Concise decision context: what you are doing, and what turns on the answer.
    pub context: String,
    /// The question itself.
    pub question: String,
    /// `input`, `select` or `confirm`.
    #[serde(rename = "type")]
    pub kind: AskType,
    /// Two to twelve choices, for `select`. "Something else" is added by the host and cannot be
    /// removed.
    #[serde(default)]
    pub choices: Option<Vec<ChoiceInput>>,
    /// How long the question should stay open, in seconds. The default and the maximum are 24
    /// hours, and it also ends when this process does.
    #[serde(default)]
    pub expiry_seconds: Option<u64>,
    /// How long to wait for an answer before returning the pending question, in seconds. At most
    /// 30.
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

impl std::fmt::Debug for AskUserParams {
    /// The kind of question and how long each text is, never what the agent wrote.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AskUserParams")
            .field("request_id_bytes", &self.request_id.len())
            .field(
                "agent_name_bytes",
                &self.agent_name.as_ref().map(String::len),
            )
            .field("context_bytes", &self.context.len())
            .field("question_bytes", &self.question.len())
            .field("kind", &self.kind)
            .field("choices", &self.choices)
            .field("expiry_seconds", &self.expiry_seconds)
            .field("wait_seconds", &self.wait_seconds)
            .finish()
    }
}

/// The parameters of `wait_for_answer`.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct WaitForAnswerParams {
    /// The question `ask_user` returned.
    pub question_id: String,
    /// The caller token `ask_user` returned with it.
    pub caller_token: String,
    /// How long to wait, in seconds: at most 600, and no longer than the client deadline this
    /// installation declared, less the time the answer needs to come back. Where the installation
    /// declared no deadline, a wait runs at most 45 seconds. A wait that times out returns the same
    /// pending question; nothing is asked again.
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

impl std::fmt::Debug for WaitForAnswerParams {
    /// The question and the wait, never the caller token, which is what proves the caller asked.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WaitForAnswerParams")
            .field(
                "question_id",
                &crate::shown::parsed_identifier::<QuestionId>(&self.question_id),
            )
            .field("wait_seconds", &self.wait_seconds)
            .finish_non_exhaustive()
    }
}

/// The parameters of `cancel_question`.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct CancelQuestionParams {
    /// The question `ask_user` returned.
    pub question_id: String,
    /// The caller token `ask_user` returned with it.
    pub caller_token: String,
}

impl std::fmt::Debug for CancelQuestionParams {
    /// The question, never the caller token.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancelQuestionParams")
            .field(
                "question_id",
                &crate::shown::parsed_identifier::<QuestionId>(&self.question_id),
            )
            .finish_non_exhaustive()
    }
}

/// How urgent a notification is.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSeverity {
    /// Something worth knowing.
    Info,
    /// Something that may need attention.
    Warning,
    /// Something that went wrong.
    Error,
}

impl From<NotificationSeverity> for AlertSeverity {
    fn from(value: NotificationSeverity) -> Self {
        match value {
            NotificationSeverity::Info => Self::Info,
            NotificationSeverity::Warning => Self::Warning,
            NotificationSeverity::Error => Self::Error,
        }
    }
}

/// The parameters of `send_notification`.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct SendNotificationParams {
    /// Your own identifier for this alert. Repeating it with the same text raises nothing new.
    pub dedup_id: String,
    /// What to call you in the alert. Unverified.
    #[serde(default)]
    pub agent_name: Option<String>,
    /// The concise text.
    pub text: String,
    /// `info`, `warning` or `error`.
    pub severity: NotificationSeverity,
    /// A link into this host's own session, when there is one.
    #[serde(default)]
    pub safe_session_link: Option<String>,
}

impl std::fmt::Debug for SendNotificationParams {
    /// The severity and how long each text is, never what the agent wrote.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SendNotificationParams")
            .field("dedup_id_bytes", &self.dedup_id.len())
            .field(
                "agent_name_bytes",
                &self.agent_name.as_ref().map(String::len),
            )
            .field("text_bytes", &self.text.len())
            .field("severity", &self.severity)
            .field(
                "safe_session_link_bytes",
                &self.safe_session_link.as_ref().map(String::len),
            )
            .finish()
    }
}

/// How long the server waits, on its way out, for the calls it is still finishing.
const CALLS_FINISH_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// The calls that are running, and which of them the client has cancelled with its own notice.
///
/// A call is here from the moment its handler starts until it returns, so a notice that names it
/// is kept for as long as the call can look for it, however slowly either side runs, and a notice
/// that names no running call is not kept at all.
#[derive(Debug, Default)]
struct Calls {
    /// Each running call, and whether a notice from the client has named it.
    running: std::sync::Mutex<std::collections::HashMap<RequestId, bool>>,
    idle: tokio::sync::Notify,
}

impl Calls {
    fn enter(self: &Arc<Self>, call: RequestId) -> RunningCall {
        if let Ok(mut running) = self.running.lock() {
            running.insert(call.clone(), false);
        }
        RunningCall {
            calls: Arc::clone(self),
            call,
        }
    }

    /// Records the client's notice for a call that is running.
    fn noticed(&self, call: &RequestId) {
        if let Ok(mut running) = self.running.lock()
            && let Some(named) = running.get_mut(call)
        {
            *named = true;
        }
    }

    /// Returns true when the client's notice has named this call.
    fn was_noticed(&self, call: &RequestId) -> bool {
        self.running
            .lock()
            .is_ok_and(|running| running.get(call).copied().unwrap_or(false))
    }

    /// Returns once no call is running.
    async fn finished(&self) {
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self
                .running
                .lock()
                .map_or(true, |running| running.is_empty())
            {
                return;
            }
            idle.await;
        }
    }
}

/// One running call, forgotten when it is dropped.
struct RunningCall {
    calls: Arc<Calls>,
    call: RequestId,
}

impl Drop for RunningCall {
    fn drop(&mut self) {
        let empty = self.calls.running.lock().is_ok_and(|mut running| {
            running.remove(&self.call);
            running.is_empty()
        });
        if empty {
            self.calls.idle.notify_waiters();
        }
    }
}

/// This server's transport, which records that it has ended.
///
/// rmcp's serve loop ends when the transport's `receive` returns nothing, whatever the reason: the
/// input closed, a read failed, or the error reply to a malformed request could not be written.
/// When the loop ends, rmcp fires the token of every call still running, which is the same token
/// the client's own `notifications/cancelled` fires. The end is recorded here as `receive` returns
/// it, before the loop can act on it, so a token that fires while the transport has not ended was
/// fired by the client's notice and by nothing else. The loop has two other ends, a failed task
/// sending a request of this server's own and the service being cancelled, and this server does
/// neither: it sends the client no request, and it holds its service until the loop ends.
struct ServedTransport<T> {
    inner: T,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl<T: rmcp::transport::Transport<RoleServer>> rmcp::transport::Transport<RoleServer>
    for ServedTransport<T>
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<rmcp::service::RxJsonRpcMessage<RoleServer>> {
        let received = self.inner.receive().await;
        if received.is_none() {
            self.ended.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        received
    }

    fn close(&mut self) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

/// How one long poll ended.
enum Polled {
    /// The question as the poll last read it: resolved, or still pending when the wait ran out.
    Read(Box<Question>),
    /// The client cancelled the tool call the poll was for.
    Cancelled,
}

/// The contact tools, bound to whichever session this process is running in.
#[derive(Clone)]
pub struct Contact {
    build_id: BuildId,
    /// The session this process was found to be in, resolved once and reused.
    ///
    /// A helper is inside one session for the whole of its life, and a short disconnection does
    /// not move it. Resolving again on every call would ask the same kernel the same question.
    bound: Arc<tokio::sync::Mutex<Option<Bound>>>,
    /// The calls that are running, and which the client cancelled with a notice of its own.
    calls: Arc<Calls>,
    /// Whether this server's transport has ended.
    transport_ended: Arc<std::sync::atomic::AtomicBool>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Contact")
            .field("build_id", &self.build_id)
            .finish_non_exhaustive()
    }
}

#[tool_router]
impl Contact {
    /// Builds the tool set.
    #[must_use]
    pub fn new(build_id: BuildId) -> Self {
        Self {
            build_id,
            bound: Arc::new(tokio::sync::Mutex::new(None)),
            calls: Arc::new(Calls::default()),
            transport_ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tool_router: Self::tool_router(),
        }
    }

    /// Asks the person a question and returns it, with the token that polls and cancels it.
    #[tool(
        name = "ask_user",
        description = "Ask the person running this KalaReach session for input you are missing. \
                       Give concise decision context. Returns a question_id and a caller_token; \
                       wait for the answer with wait_for_answer and withdraw it with \
                       cancel_question. Cancelling this call cancels the question it asked. An \
                       unanswered question is not approval."
    )]
    pub async fn ask_user(
        &self,
        Parameters(params): Parameters<AskUserParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _running = self.calls.enter(context.id.clone());
        Ok(self
            .create(params, &context.ct, &context.id)
            .await
            .unwrap_or_else(refusal))
    }

    /// Waits for the answer to a question this process asked.
    #[tool(
        name = "wait_for_answer",
        description = "Wait for the answer to a question you asked. Returns the same question \
                       unchanged when the wait times out, which is not an answer and not \
                       approval: wait again, or carry on without it. Cancelling this call \
                       cancels the question."
    )]
    pub async fn wait_for_answer(
        &self,
        Parameters(params): Parameters<WaitForAnswerParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _running = self.calls.enter(context.id.clone());
        Ok(self
            .wait(params, &context.ct, &context.id)
            .await
            .unwrap_or_else(refusal))
    }

    /// Withdraws a question this process asked.
    #[tool(
        name = "cancel_question",
        description = "Withdraw a question you no longer need answered. A question that has \
                       already been answered, cancelled or expired stays as it is."
    )]
    pub async fn cancel_question(
        &self,
        Parameters(params): Parameters<CancelQuestionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Ok(self.withdraw(params).await.unwrap_or_else(refusal))
    }

    /// Tells the person something, without asking for an answer.
    #[tool(
        name = "send_notification",
        description = "Tell the person something without asking for an answer: work finished, an \
                       error you cannot clear. Use ask_user when you need a decision."
    )]
    pub async fn send_notification(
        &self,
        Parameters(params): Parameters<SendNotificationParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Ok(self.notify(params).await.unwrap_or_else(refusal))
    }

    async fn create(
        &self,
        params: AskUserParams,
        cancelled: &CancellationToken,
        call: &RequestId,
    ) -> crate::error::Result<CallToolResult> {
        // A call cancelled before anything was asked asks nothing. Creating the question and
        // cancelling it at once would still put it in front of the person for a moment.
        if cancelled.is_cancelled() {
            return Err(asked_nothing());
        }
        let bound = self.session().await?;
        let mut client = bind::open(&bound, self.build_id.clone()).await?;
        let request = QuestionCreateParams {
            session_id: bound.session_id(),
            request_id: params.request_id,
            agent_name: Nullable(params.agent_name),
            context: params.context,
            question: params.question,
            kind: params.kind.into(),
            choices: params
                .choices
                .unwrap_or_default()
                .into_iter()
                .map(|choice| QuestionChoice {
                    choice_id: choice.choice_id,
                    label: choice.label,
                })
                .collect(),
            requested_expiry_ms: Nullable(params.expiry_seconds.map(seconds)),
            wait_ms: Nullable::null(),
        };
        // Finding the session and reaching its worker take time, and a call cancelled meanwhile
        // still asks nothing.
        if cancelled.is_cancelled() {
            return Err(asked_nothing());
        }
        // The creation is carried through to its answer even when the call is cancelled part way:
        // abandoning the exchange would leave a question that may exist and a token nobody holds.
        let created: QuestionCreateResult = bind::mutate(
            &mut client,
            Method::QuestionCreate,
            bound.target(),
            &request,
        )
        .await?;
        let token = encode_token(&created.caller_token);
        let question_id = created.question.question_id;
        if cancelled.is_cancelled() {
            let question = self
                .cancelled(call, &bound, question_id, &created.caller_token)
                .await?;
            return Ok(CallToolResult::structured(created_value(
                &question,
                &token,
                created.deduplicated,
            )));
        }
        // The wait on a creation is bounded by the same deadline every other wait is, and by its
        // own thirty-second ceiling.
        let wait = params
            .wait_seconds
            .map(|asked| wait_within(Some(seconds(asked)), declared_deadline(), MAX_CREATE_WAIT));
        // The optional wait on creation is the same long poll, bounded to 30 seconds. It reuses
        // the question it just created rather than asking again.
        let question = match wait {
            Some(wait) if wait.get() > 0 => match self
                .poll(
                    &bound,
                    &mut client,
                    question_id,
                    &created.caller_token,
                    wait,
                    cancelled,
                )
                .await?
            {
                Polled::Read(question) => *question,
                Polled::Cancelled => {
                    self.cancelled(call, &bound, question_id, &created.caller_token)
                        .await?
                }
            },
            _ => created.question,
        };
        Ok(CallToolResult::structured(created_value(
            &question,
            &token,
            created.deduplicated,
        )))
    }

    async fn wait(
        &self,
        params: WaitForAnswerParams,
        cancelled: &CancellationToken,
        call: &RequestId,
    ) -> crate::error::Result<CallToolResult> {
        let bound = self.session().await?;
        let question_id = parse_question(&params.question_id)?;
        let token = decode_token(&params.caller_token)?;
        let mut client = bind::open(&bound, self.build_id.clone()).await?;
        let wait = poll_duration(params.wait_seconds.map(seconds));
        let question = match self
            .poll(&bound, &mut client, question_id, &token, wait, cancelled)
            .await?
        {
            Polled::Read(question) => *question,
            Polled::Cancelled => self.cancelled(call, &bound, question_id, &token).await?,
        };
        Ok(CallToolResult::structured(question_value(&question)))
    }

    async fn withdraw(&self, params: CancelQuestionParams) -> crate::error::Result<CallToolResult> {
        let bound = self.session().await?;
        let question_id = parse_question(&params.question_id)?;
        let token = decode_token(&params.caller_token)?;
        let mut client = bind::open(&bound, self.build_id.clone()).await?;
        let result: QuestionOwnResult = bind::mutate(
            &mut client,
            Method::QuestionCancelOwn,
            bound.target(),
            &QuestionCancelOwnParams {
                session_id: bound.session_id(),
                question_id,
                caller_token: token,
            },
        )
        .await?;
        Ok(CallToolResult::structured(question_value(&result.question)))
    }

    async fn notify(&self, params: SendNotificationParams) -> crate::error::Result<CallToolResult> {
        let bound = self.session().await?;
        let mut client = bind::open(&bound, self.build_id.clone()).await?;
        let result: AlertCreateResult = bind::mutate(
            &mut client,
            Method::AlertCreate,
            bound.target(),
            &AlertCreateParams {
                session_id: bound.session_id(),
                dedup_id: params.dedup_id,
                agent_name: Nullable(params.agent_name),
                text: params.text,
                severity: params.severity.into(),
                safe_session_link: Nullable(params.safe_session_link),
            },
        )
        .await?;
        Ok(CallToolResult::structured(json!({
            "session_id": result.alert.session_id.to_string(),
            "dedup_id": result.alert.dedup_id,
            "severity": result.alert.severity.as_str(),
            "created_at_ms": result.alert.created_at_ms.get(),
            "deduplicated": result.deduplicated,
        })))
    }

    /// Long-polls one question until it resolves, the wait runs out, or the client cancels the call.
    ///
    /// The broker wait is renewed in bounded steps rather than held open once, so a client that
    /// cancels its tool call is noticed promptly. A poll that ends without an answer returns the
    /// same durable question: nothing is recreated and nobody is notified again. A cancelled call is
    /// reported as such, and what it means for the question is the caller's to carry out.
    async fn poll(
        &self,
        bound: &Bound,
        client: &mut kr_ipc::client::LocalClient,
        question_id: QuestionId,
        token: &CallerToken,
        wait: DurationMs,
        cancelled: &CancellationToken,
    ) -> crate::error::Result<Polled> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait.get());
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let step = std::time::Duration::from_millis(WAIT_RENEWAL.get()).min(remaining);
            let params = QuestionReadOwnParams {
                session_id: bound.session_id(),
                question_id,
                caller_token: CallerToken::new(token.as_slice().to_vec()),
                wait_ms: Nullable::some(DurationMs::new(
                    u64::try_from(step.as_millis()).unwrap_or(0),
                )),
            };
            // A cancelled call ends the wait at once rather than at the end of the current renewal.
            let result: QuestionOwnResult = tokio::select! {
                biased;
                () = cancelled.cancelled() => {
                    // The read in flight is abandoned part way through its exchange, so this
                    // connection is never used again: its answer would arrive as the answer to
                    // whatever asked next on it.
                    return Ok(Polled::Cancelled);
                }
                result = bind::read(client, Method::QuestionReadOwn, &params) => result?,
            };
            if result.question.state.is_resolved()
                || step.is_zero()
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(Polled::Read(Box::new(result.question)));
            }
        }
    }

    /// Carries out what a fired token means for the question its call was asking or waiting on.
    ///
    /// The client cancelled the call when its notice named the call, or when the token fired while
    /// this server's transport had not ended, which nothing but a notice does; then section 11's
    /// upstream cancellation cancels the question. Otherwise the token fired because the transport
    /// ended and this server is stopping: nothing cancelled the call, the question is left as it
    /// is, and it ends with this process.
    async fn cancelled(
        &self,
        call: &RequestId,
        bound: &Bound,
        question_id: QuestionId,
        token: &CallerToken,
    ) -> crate::error::Result<Question> {
        if self.cancelled_by_the_client(call) {
            return self.cancel_for_the_call(bound, question_id, token).await;
        }
        Err(CliError::Refused(kr_client::error::refusal(
            ErrorCode::ResourceUnavailable,
            Shown::said(
                "the tool server is stopping; the question was not cancelled, and it ends when \
                 this process does",
            ),
        )))
    }

    /// Returns true when a fired token was the client's own cancellation of this call.
    fn cancelled_by_the_client(&self, call: &RequestId) -> bool {
        self.calls.was_noticed(call)
            || !self
                .transport_ended
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Cancels the question a cancelled tool call was creating or waiting on, and returns it.
    ///
    /// This is section 11's upstream cancellation: the call that would have carried the answer is
    /// gone, so the question stops asking. It is asked on a connection of its own, because the
    /// call's connection may have been left part way through an exchange. A question that reached
    /// another state first keeps it, whether a person answered it, the agent withdrew it or its time
    /// ran out: the first transition wins, and a later `wait_for_answer` still reads it.
    async fn cancel_for_the_call(
        &self,
        bound: &Bound,
        question_id: QuestionId,
        token: &CallerToken,
    ) -> crate::error::Result<Question> {
        let mut client = bind::open(bound, self.build_id.clone()).await?;
        let cancelled: crate::error::Result<QuestionOwnResult> = bind::mutate(
            &mut client,
            Method::QuestionCancelOwn,
            bound.target(),
            &QuestionCancelOwnParams {
                session_id: bound.session_id(),
                question_id,
                caller_token: CallerToken::new(token.as_slice().to_vec()),
            },
        )
        .await;
        match cancelled {
            Ok(result) => Ok(result.question),
            Err(CliError::Refused(refused))
                if matches!(
                    refused.code,
                    ErrorCode::QuestionResolved | ErrorCode::QuestionExpired
                ) =>
            {
                let result: QuestionOwnResult = bind::read(
                    &mut client,
                    Method::QuestionReadOwn,
                    &QuestionReadOwnParams {
                        session_id: bound.session_id(),
                        question_id,
                        caller_token: CallerToken::new(token.as_slice().to_vec()),
                        wait_ms: Nullable::null(),
                    },
                )
                .await?;
                Ok(result.question)
            }
            Err(error) => Err(error),
        }
    }

    async fn session(&self) -> crate::error::Result<Bound> {
        let mut held = self.bound.lock().await;
        if let Some(bound) = held.as_ref() {
            return Ok(bound.clone());
        }
        let bound = bind::discover(&self.build_id).await?;
        *held = Some(bound.clone());
        Ok(bound)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Contact {
    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        if let Some(call) = notification.request_id {
            self.calls.noticed(&call);
        }
        std::future::ready(())
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Reach the person running this KalaReach session. Ask for input you are missing with \
             ask_user, wait on the question you already created with wait_for_answer, withdraw it \
             with cancel_question when it stops mattering, and report something that needs no \
             answer with send_notification. An unanswered question is never approval.",
        )
    }
}

/// Runs the contact tools over this process's standard input and output.
///
/// # Errors
///
/// Returns an error when the transport fails.
pub async fn run_stdio(build_id: BuildId) -> crate::error::Result<()> {
    let contact = Contact::new(build_id);
    let calls = Arc::clone(&contact.calls);
    let transport = ServedTransport {
        inner: rmcp::transport::async_rw::AsyncRwTransport::new_server(
            tokio::io::stdin(),
            tokio::io::stdout(),
        ),
        ended: Arc::clone(&contact.transport_ended),
    };
    let service = contact.serve(transport).await.map_err(|error| {
        CliError::Other(shown!(
            "the tool server could not start: {}",
            crate::shown::tool_server(&error)
        ))
    })?;
    let stopped = service.waiting().await.map_err(|error| {
        CliError::Other(shown!(
            "the tool server stopped: {}",
            crate::shown::task(&error)
        ))
    });
    // A call the client cancelled just before the transport ended may still be cancelling its
    // question. It is given a bounded moment to finish, so the process does not exit under it.
    let _ = tokio::time::timeout(CALLS_FINISH_WITHIN, calls.finished()).await;
    stopped?;
    Ok(())
}

/// The refusal a call cancelled before its question was asked is answered with.
fn asked_nothing() -> CliError {
    CliError::Other(Shown::said(
        "the call was cancelled before the question was asked; nothing was created",
    ))
}

/// Renders a refusal as a tool error the agent can read and act on.
///
/// The stable code travels with it, because that is what tells an agent the difference between
/// "you are not in a session", "somebody already answered" and "that request identifier means
/// something else".
fn refusal(error: CliError) -> CallToolResult {
    let protocol = match &error {
        CliError::Refused(refused) => refused.clone(),
        other => kr_client::error::refusal(
            ErrorCode::from_wire(&other.code()).unwrap_or(ErrorCode::ResourceUnavailable),
            other.said(),
        ),
    };
    let mut value = json!({
        "code": protocol.code.as_str(),
        "message": protocol.message,
        "retry": format!("{:?}", protocol.code.retry_category()),
    });
    if protocol.code == ErrorCode::NotInKrSession
        && let Some(object) = value.as_object_mut()
    {
        object.insert("setup".to_owned(), json!(SETUP_INSTRUCTION));
    }
    CallToolResult::structured_error(value)
}

fn created_value(question: &Question, caller_token: &str, deduplicated: bool) -> Value {
    let mut value = question_value(question);
    if let Some(object) = value.as_object_mut() {
        object.insert("caller_token".to_owned(), json!(caller_token));
        object.insert("deduplicated".to_owned(), json!(deduplicated));
    }
    value
}

fn question_value(question: &Question) -> Value {
    json!({
        "question_id": question.question_id.to_string(),
        "revision": question.revision.get(),
        "state": question.state.as_str(),
        "session_id": question.session_id.to_string(),
        "type": question.kind.as_str(),
        "choices": question
            .choices
            .iter()
            .map(|choice| json!({"choice_id": choice.choice_id, "label": choice.label}))
            .collect::<Vec<_>>(),
        "expires_at_ms": question.expires_at_ms.get(),
        "answer": question.answer.as_ref().map(|record| answer_value(&record.answer)),
    })
}

fn answer_value(answer: &QuestionAnswer) -> Value {
    match answer {
        QuestionAnswer::Input { text } => json!({"kind": "input", "text": text}),
        QuestionAnswer::Choice { choice_id } => json!({"kind": "choice", "choice_id": choice_id}),
        QuestionAnswer::Decision { decided } => json!({"kind": "decision", "decided": decided}),
        // Free text stays free text all the way out. Nothing here folds it into a listed choice
        // or into a yes.
        QuestionAnswer::Other { text } => json!({"kind": "other", "text": text}),
    }
}

fn seconds(value: u64) -> DurationMs {
    DurationMs::new(value.saturating_mul(1_000))
}

fn parse_question(text: &str) -> crate::error::Result<QuestionId> {
    text.parse()
        .map_err(|_| CliError::Usage(Shown::said("the text given is not a question identifier")))
}

/// Renders a caller token for the agent to hold.
fn encode_token(token: &CallerToken) -> String {
    hex_of(token.as_slice())
}

/// Reads a caller token the agent presented.
fn decode_token(text: &str) -> crate::error::Result<CallerToken> {
    let trimmed = text.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(CliError::Usage(Shown::said("that is not a caller token")));
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|_| CliError::Usage(Shown::said("that is not a caller token")))?;
        bytes.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| CliError::Usage(Shown::said("that is not a caller token")))?,
        );
    }
    Ok(CallerToken::new(bytes))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tool call's parameters render as their kinds, their numbers and their lengths: never an
    /// agent's text, and never a caller token.
    #[test]
    fn a_tool_calls_parameters_render_without_what_the_agent_sent() {
        use crate::shown::marker::{MARKER, assert_unmarked};

        let ask = AskUserParams {
            request_id: MARKER.to_owned(),
            agent_name: Some(MARKER.to_owned()),
            context: MARKER.to_owned(),
            question: MARKER.to_owned(),
            kind: AskType::Select,
            choices: Some(vec![ChoiceInput {
                choice_id: MARKER.to_owned(),
                label: MARKER.to_owned(),
            }]),
            expiry_seconds: Some(60),
            wait_seconds: None,
        };
        let wait = WaitForAnswerParams {
            question_id: MARKER.to_owned(),
            caller_token: MARKER.to_owned(),
            wait_seconds: Some(30),
        };
        let cancel = CancelQuestionParams {
            question_id: MARKER.to_owned(),
            caller_token: MARKER.to_owned(),
        };
        let notify = SendNotificationParams {
            dedup_id: MARKER.to_owned(),
            agent_name: None,
            text: MARKER.to_owned(),
            severity: NotificationSeverity::Warning,
            safe_session_link: Some(MARKER.to_owned()),
        };
        // The negative control is each field: every one holds the marker, and the derived form
        // printed them all.
        assert_eq!(
            format!("{ask:?}"),
            "AskUserParams { request_id_bytes: 14, agent_name_bytes: Some(14), context_bytes: 14, \
             question_bytes: 14, kind: Select, choices: Some([ChoiceInput { choice_id_bytes: 14, \
             label_bytes: 14 }]), expiry_seconds: Some(60), wait_seconds: None }"
        );
        assert_eq!(
            format!("{wait:?}"),
            "WaitForAnswerParams { question_id: \"[not an identifier]\", wait_seconds: Some(30), \
             .. }"
        );
        assert_eq!(
            format!("{cancel:?}"),
            "CancelQuestionParams { question_id: \"[not an identifier]\", .. }"
        );
        assert_eq!(
            format!("{notify:?}"),
            "SendNotificationParams { dedup_id_bytes: 14, agent_name_bytes: None, text_bytes: 14, \
             severity: Warning, safe_session_link_bytes: Some(14) }"
        );
        assert_unmarked(
            "a tool call's parameters",
            &[
                format!("{ask:#?}"),
                format!("{wait:#?}"),
                format!("{cancel:#?}"),
                format!("{notify:#?}"),
            ],
        );
    }

    #[test]
    fn a_token_survives_the_round_trip_the_agent_holds_it_through() {
        let token = CallerToken::new((0..32).collect());
        let rendered = encode_token(&token);
        assert_eq!(rendered.len(), 64);
        assert_eq!(
            decode_token(&rendered).expect("reads").as_slice(),
            token.as_slice()
        );
    }

    #[test]
    fn anything_that_is_not_a_token_is_refused() {
        assert!(decode_token("not a token").is_err());
        assert!(decode_token("abc").is_err());
    }

    /// KR-REQ-11.54, KR-REQ-19.07: the four tools are the whole surface, and no parameter of any
    /// of them selects a session, an environment, history or input: every call acts on the session
    /// the worker bound this process to, so no call can enumerate another session, read it or send
    /// it input.
    #[test]
    fn no_tool_takes_an_argument_that_reaches_another_session() {
        let tools = Contact::tool_router().list_all();
        let mut names: Vec<String> = tools.iter().map(|tool| tool.name.to_string()).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "ask_user",
                "cancel_question",
                "send_notification",
                "wait_for_answer"
            ]
        );
        for tool in &tools {
            let schema = serde_json::to_value(&*tool.input_schema).expect("a schema");
            let mut parameters: Vec<&str> = schema["properties"]
                .as_object()
                .expect("the tool declares its parameters")
                .keys()
                .map(String::as_str)
                .collect();
            parameters.sort_unstable();
            let expected: &[&str] = match tool.name.as_ref() {
                "ask_user" => &[
                    "agent_name",
                    "choices",
                    "context",
                    "expiry_seconds",
                    "question",
                    "request_id",
                    "type",
                    "wait_seconds",
                ],
                "wait_for_answer" => &["caller_token", "question_id", "wait_seconds"],
                "cancel_question" => &["caller_token", "question_id"],
                "send_notification" => &[
                    "agent_name",
                    "dedup_id",
                    "safe_session_link",
                    "severity",
                    "text",
                ],
                other => panic!("an unexpected tool {other}"),
            };
            assert_eq!(parameters, expected, "{}", tool.name);
        }
    }

    /// KR-REQ-11.53: outside a session the refusal is `NOT_IN_KR_SESSION` with the setup
    /// instruction.
    #[test]
    fn a_refusal_carries_the_stable_code_and_the_setup_instruction() {
        let result = refusal(CliError::Refused(kr_client::error::refusal(
            ErrorCode::NotInKrSession,
            Shown::said("nowhere"),
        )));
        let content = result.structured_content.expect("structured");
        assert_eq!(content["code"], "NOT_IN_KR_SESSION");
        assert_eq!(content["setup"], SETUP_INSTRUCTION);
        assert_eq!(result.is_error, Some(true));
    }

    /// KR-REQ-11.57: with no qualified client deadline installed, the helper caps a wait at its
    /// own limit, however long the caller asked for, and honours a shorter request.
    #[test]
    fn an_unqualified_wait_is_short_however_long_the_caller_asked_for() {
        // Nothing here knows what this client allows, so a request for longer is not honoured.
        assert_eq!(poll_within(None, None), UNQUALIFIED_WAIT);
        assert_eq!(
            poll_within(Some(DurationMs::new(600_000)), None),
            UNQUALIFIED_WAIT
        );
        assert_eq!(
            poll_within(Some(DurationMs::new(5_000)), None),
            DurationMs::new(5_000)
        );
    }

    /// KR-REQ-11.55: the optional wait on `ask_user` is at most thirty seconds, and shorter when the
    /// client's own deadline is.
    #[test]
    fn a_creation_wait_is_bounded_by_its_own_ceiling_and_by_the_client() {
        // Thirty seconds, stated as the number rather than through the constant the tool uses.
        assert_eq!(MAX_CREATE_WAIT, DurationMs::new(30_000));
        assert_eq!(
            wait_within(Some(DurationMs::new(600_000)), None, MAX_CREATE_WAIT),
            DurationMs::new(30_000)
        );
        assert_eq!(
            wait_within(
                Some(DurationMs::new(600_000)),
                Some(DurationMs::new(660_000)),
                MAX_CREATE_WAIT
            ),
            DurationMs::new(30_000)
        );
        assert_eq!(
            wait_within(
                Some(DurationMs::new(12_000)),
                Some(DurationMs::new(660_000)),
                MAX_CREATE_WAIT
            ),
            DurationMs::new(12_000)
        );
        assert_eq!(
            wait_within(
                Some(DurationMs::new(30_000)),
                Some(DurationMs::new(20_000)),
                MAX_CREATE_WAIT
            ),
            DurationMs::new(5_000)
        );
    }

    /// KR-REQ-11.57: a long poll honours the requested duration, defaults to five minutes, stops at
    /// the ten-minute host ceiling, and is shortened to the installed client's qualified deadline.
    #[test]
    fn a_declared_deadline_bounds_both_the_default_and_an_explicit_wait() {
        // Five minutes by default, ten at most, and what was asked for in between, stated as the
        // numbers rather than through the constants the tool uses.
        let generous = Some(DurationMs::new(660_000));
        assert_eq!(poll_within(None, generous), DurationMs::new(300_000));
        assert_eq!(
            poll_within(Some(DurationMs::new(u64::MAX)), generous),
            DurationMs::new(600_000)
        );
        assert_eq!(
            poll_within(Some(DurationMs::new(90_000)), generous),
            DurationMs::new(90_000)
        );
        assert_eq!(
            kr_protocol::question::DEFAULT_WAIT,
            DurationMs::new(300_000)
        );
        assert_eq!(MAX_WAIT, DurationMs::new(600_000));

        // A client with a minute cuts every wait to what is left after the answer's own room.
        let short = Some(DurationMs::new(60_000));
        let expected = DurationMs::new(60_000 - DEADLINE_MARGIN.get());
        assert_eq!(poll_within(None, short), expected);
        assert_eq!(poll_within(Some(DurationMs::new(600_000)), short), expected);

        // A deadline with nothing left in it after the answer's own room is a budget of nothing,
        // not an absent one: the question comes back at once rather than after a wait the client
        // would cut off.
        assert_eq!(
            poll_within(None, Some(DurationMs::new(5_000))),
            DurationMs::new(0)
        );
        assert_eq!(
            poll_within(Some(DurationMs::new(600_000)), Some(DurationMs::new(5_000))),
            DurationMs::new(0)
        );
    }

    /// KR-REQ-11.59: an `other` answer reaches the agent as free text, never as a choice or a yes.
    #[test]
    fn a_free_text_answer_is_reported_as_free_text() {
        let value = answer_value(&QuestionAnswer::Other {
            text: "a third way".to_owned(),
        });
        assert_eq!(value["kind"], "other");
        assert_eq!(value["text"], "a third way");
    }

    /// KR-REQ-11.63: a call the client cancelled before its question was asked asks nothing: it
    /// returns before it looks for a session or reaches a worker, so no question is created only to
    /// be cancelled.
    #[tokio::test]
    async fn a_call_cancelled_before_its_question_is_asked_asks_nothing() {
        let contact = Contact::new(BuildId::new("kr-test/0").expect("a build identifier"));
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let refused = contact
            .create(
                AskUserParams {
                    request_id: "never-asked".to_owned(),
                    agent_name: None,
                    context: String::new(),
                    question: "shall I?".to_owned(),
                    kind: AskType::Confirm,
                    choices: None,
                    expiry_seconds: None,
                    wait_seconds: None,
                },
                &cancelled,
                &RequestId::Number(1),
            )
            .await
            .expect_err("nothing is asked");
        assert!(
            refused.to_string().contains("nothing was created"),
            "{refused}"
        );
        assert!(
            contact.bound.lock().await.is_none(),
            "no session was looked for"
        );
    }

    /// KR-REQ-11.63: a fired token is the client's cancellation when the client's notice named
    /// the call, whenever that notice is recorded, or when it fired while the transport had not
    /// ended; once the transport has ended, a token with no notice behind it fired because the
    /// server is stopping, and nothing is cancelled. A notice for a call that is not running is not
    /// kept.
    #[test]
    fn a_fired_token_is_the_clients_cancellation_unless_the_transport_ended_first() {
        let contact = Contact::new(BuildId::new("kr-test/0").expect("a build identifier"));
        let call = RequestId::Number(7);
        let running = contact.calls.enter(call.clone());
        assert!(
            contact.cancelled_by_the_client(&call),
            "a token that fires while the transport serves fired for a notice, however late"
        );
        contact
            .transport_ended
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            !contact.cancelled_by_the_client(&call),
            "after the transport ended, a token with no notice behind it is the server stopping"
        );
        contact.calls.noticed(&call);
        assert!(
            contact.cancelled_by_the_client(&call),
            "a notice for the call counts even after the transport ended"
        );
        drop(running);
        contact.calls.noticed(&RequestId::Number(8));
        assert!(
            contact.calls.running.lock().expect("the lock").is_empty(),
            "nothing is kept for calls that are not running"
        );
    }

    /// A writer whose every write fails, as standard output does once the client stopped reading.
    struct Broken;

    impl tokio::io::AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The transport records its end as `receive` returns it, both when the input closes and when
    /// the reply to a malformed request cannot be written while the input is still open, and not
    /// before.
    #[tokio::test]
    async fn the_served_transport_records_its_end_however_the_loop_would_end() {
        use rmcp::transport::Transport as _;

        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut closing = ServedTransport {
            inner: rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new_server(
                &request[..],
                tokio::io::sink(),
            ),
            ended: Arc::clone(&ended),
        };
        assert!(closing.receive().await.is_some(), "a request is read");
        assert!(!ended.load(std::sync::atomic::Ordering::SeqCst));
        assert!(closing.receive().await.is_none(), "the input closed");
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));

        // Well-formed JSON of the wrong shape is answered with an error, and that answer cannot be
        // written. The input is still open when the transport ends.
        let (_input, open) = tokio::io::duplex(64);
        let malformed = b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":42}\n";
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut broken = ServedTransport {
            inner: rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new_server(
                tokio::io::AsyncReadExt::chain(&malformed[..], open),
                Broken,
            ),
            ended: Arc::clone(&ended),
        };
        assert!(broken.receive().await.is_none(), "the failed reply ends it");
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
    }
}
