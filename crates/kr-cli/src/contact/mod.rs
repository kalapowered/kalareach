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
    bounded_wait,
};
use kr_protocol::scalars::{DurationMs, Nullable};

use crate::contact::bind::{Bound, SETUP_INSTRUCTION};
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
    /// How long to wait, in seconds. The default is 300 and the maximum is 600. A wait that times
    /// out returns the same pending question; nothing is asked again.
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
                       cancel_question. An unanswered question is not approval."
    )]
    pub async fn ask_user(
        &self,
        Parameters(params): Parameters<AskUserParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        Ok(self.create(params).await.unwrap_or_else(refusal))
    }

    /// Waits for the answer to a question this process asked.
    #[tool(
        name = "wait_for_answer",
        description = "Wait for the answer to a question you asked. Returns the same question \
                       unchanged when the wait times out, which is not an answer and not \
                       approval: wait again, or carry on without it."
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

    async fn create(&self, params: AskUserParams) -> CliResult<CallToolResult> {
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
        let created: QuestionCreateResult = bind::mutate(
            &mut client,
            Method::QuestionCreate,
            bound.target(),
            &request,
        )
        .await?;
        let token = encode_token(&created.caller_token);
        let wait = params
            .wait_seconds
            .map(seconds)
            .map(|asked| DurationMs::new(asked.get().min(MAX_CREATE_WAIT.get())));
        // The optional wait on creation is the same long poll, bounded to 30 seconds. It reuses
        // the question it just created rather than asking again.
        let question = match wait {
            Some(wait) if wait.get() > 0 => {
                self.poll(
                    &bound,
                    &mut client,
                    created.question.question_id,
                    &created.caller_token,
                    wait,
                    &CancellationToken::new(),
                )
                .await?
            }
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
        let wait = bounded_wait(params.wait_seconds.map(seconds), MAX_WAIT);
        let question = self
            .poll(&bound, &mut client, question_id, &token, wait, cancelled)
            .await?;
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

    /// Long-polls one question until it resolves, the wait runs out, or the client gives up.
    ///
    /// The broker wait is renewed in bounded steps rather than held open once, so a client that
    /// cancels its tool call is noticed promptly. A poll that ends without an answer returns the
    /// same durable question: nothing is recreated and nobody is notified again.
    async fn poll(
        &self,
        bound: &Bound,
        client: &mut kr_ipc::client::LocalClient,
        question_id: QuestionId,
        token: &CallerToken,
        wait: DurationMs,
        cancelled: &CancellationToken,
    ) -> CliResult<Question> {
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
            // The client giving up ends the wait at once rather than at the end of the current
            // renewal. A wait that ends this way changes nothing: the question is durable, and
            // calling again resumes waiting on the same one.
            let ending = QuestionReadOwnParams {
                wait_ms: Nullable::null(),
                ..params.clone()
            };
            let result: QuestionOwnResult = tokio::select! {
                biased;
                () = cancelled.cancelled() => {
                    // The read in flight is abandoned part way through its exchange, so this
                    // connection is not used again: its answer would arrive as the answer to
                    // whatever asked next on it. A fresh connection reads the question one last
                    // time, and the question itself is untouched either way.
                    let mut fresh = bind::open(bound, self.build_id.clone()).await?;
                    let final_read: QuestionOwnResult =
                        bind::read(&mut fresh, Method::QuestionReadOwn, &ending).await?;
                    return Ok(final_read.question);
                }
                result = bind::read(client, Method::QuestionReadOwn, &params) => result?,
            };
            if result.question.state.is_resolved()
                || step.is_zero()
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(result.question);
            }
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

    #[test]
    fn a_free_text_answer_is_reported_as_free_text() {
        let value = answer_value(&QuestionAnswer::Other {
            text: "a third way".to_owned(),
        });
        assert_eq!(value["kind"], "other");
        assert_eq!(value["text"], "a third way");
    }
}
