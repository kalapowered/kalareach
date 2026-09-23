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
//! whose call is cancelled cancels the question it was creating or waiting on, rather than leaving
//! a decision in front of the person that nothing will collect. A wait that runs out on its own is
//! not a cancellation and changes nothing.

pub mod bind;

use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{BuildId, QuestionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    AlertCreateParams, AlertCreateResult, AlertSeverity, CallerToken, MAX_CREATE_WAIT, MAX_WAIT,
    Question, QuestionAnswer, QuestionCancelOwnParams, QuestionChoice, QuestionCreateParams,
    QuestionCreateResult, QuestionKind, QuestionOwnResult, QuestionReadOwnParams, WAIT_RENEWAL,
};
use kr_protocol::scalars::{DurationMs, Nullable};

use crate::contact::bind::{Bound, SETUP_INSTRUCTION};

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
use crate::error::{CliError, Result as CliResult};

/// One choice an `ask_user` select offers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ChoiceInput {
    /// The stable identifier an answer names. It does not change with the label.
    pub choice_id: String,
    /// What the person reads.
    pub label: String,
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
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
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

/// The parameters of `wait_for_answer`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
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

/// The parameters of `cancel_question`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct CancelQuestionParams {
    /// The question `ask_user` returned.
    pub question_id: String,
    /// The caller token `ask_user` returned with it.
    pub caller_token: String,
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
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
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

/// How one long poll ended.
enum Polled {
    /// The question as the poll last read it: resolved, or still pending when the wait ran out.
    Read(Question),
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
    ) -> std::result::Result<CallToolResult, McpError> {
        Ok(self
            .create(params, &context.ct)
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
    ) -> std::result::Result<CallToolResult, McpError> {
        Ok(self.wait(params, &context.ct).await.unwrap_or_else(refusal))
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
    ) -> std::result::Result<CallToolResult, McpError> {
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
    ) -> std::result::Result<CallToolResult, McpError> {
        Ok(self.notify(params).await.unwrap_or_else(refusal))
    }

    async fn create(
        &self,
        params: AskUserParams,
        cancelled: &CancellationToken,
    ) -> CliResult<CallToolResult> {
        // A call the client cancelled before anything was asked asks nothing. Creating the question
        // and cancelling it at once would still put it in front of the person for a moment.
        if cancelled.is_cancelled() {
            return Err(CliError::Other(
                "the call was cancelled before the question was asked; nothing was created"
                    .to_owned(),
            ));
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
                .cancel_for_the_call(&bound, question_id, &created.caller_token)
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
                Polled::Read(question) => question,
                Polled::Cancelled => {
                    self.cancel_for_the_call(&bound, question_id, &created.caller_token)
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
    ) -> CliResult<CallToolResult> {
        let bound = self.session().await?;
        let question_id = parse_question(&params.question_id)?;
        let token = decode_token(&params.caller_token)?;
        let mut client = bind::open(&bound, self.build_id.clone()).await?;
        let wait = poll_duration(params.wait_seconds.map(seconds));
        let question = match self
            .poll(&bound, &mut client, question_id, &token, wait, cancelled)
            .await?
        {
            Polled::Read(question) => question,
            Polled::Cancelled => {
                self.cancel_for_the_call(&bound, question_id, &token)
                    .await?
            }
        };
        Ok(CallToolResult::structured(question_value(&question)))
    }

    async fn withdraw(&self, params: CancelQuestionParams) -> CliResult<CallToolResult> {
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

    async fn notify(&self, params: SendNotificationParams) -> CliResult<CallToolResult> {
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
    ) -> CliResult<Polled> {
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
                return Ok(Polled::Read(result.question));
            }
        }
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
    ) -> CliResult<Question> {
        let mut client = bind::open(bound, self.build_id.clone()).await?;
        let cancelled: CliResult<QuestionOwnResult> = bind::mutate(
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

    async fn session(&self) -> CliResult<Bound> {
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
pub async fn run_stdio(build_id: BuildId) -> CliResult<()> {
    let service = Contact::new(build_id)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|error| CliError::Other(format!("the tool server could not start: {error}")))?;
    service
        .waiting()
        .await
        .map_err(|error| CliError::Other(format!("the tool server stopped: {error}")))?;
    Ok(())
}

/// Renders a refusal as a tool error the agent can read and act on.
///
/// The stable code travels with it, because that is what tells an agent the difference between
/// "you are not in a session", "somebody already answered" and "that request identifier means
/// something else".
fn refusal(error: CliError) -> CallToolResult {
    let protocol = match &error {
        CliError::Refused(refused) => refused.clone(),
        other => ProtocolError::new(
            ErrorCode::from_wire(&other.code()).unwrap_or(ErrorCode::ResourceUnavailable),
            other.to_string(),
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

fn parse_question(text: &str) -> CliResult<QuestionId> {
    text.parse()
        .map_err(|_| CliError::Usage(format!("{text} is not a question identifier")))
}

/// Renders a caller token for the agent to hold.
fn encode_token(token: &CallerToken) -> String {
    hex_of(token.as_slice())
}

/// Reads a caller token the agent presented.
fn decode_token(text: &str) -> CliResult<CallerToken> {
    let trimmed = text.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(CliError::Usage("that is not a caller token".to_owned()));
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|_| CliError::Usage("that is not a caller token".to_owned()))?;
        bytes.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| CliError::Usage("that is not a caller token".to_owned()))?,
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
        let result = refusal(CliError::Refused(ProtocolError::new(
            ErrorCode::NotInKrSession,
            "nowhere",
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
}
