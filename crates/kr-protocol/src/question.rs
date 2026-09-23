//! Agent questions, their answers, and the alerts that ask for nothing.
//!
//! An agent that is missing a fact asks for it. The question becomes a durable resource in the
//! worker that owns the session the agent is running in, and a person answers it from the
//! companion app or from the command line. Section 11 fixes what that resource is, and three of
//! its rules decide the shapes here.
//!
//! * **The identity header is the host's, not the caller's.** A source supplies an `agent_name`
//!   for a person to read; what the answering surface shows is [`QuestionSource`], which the
//!   worker builds from the operating system. The label is beside it, marked unverified.
//! * **The free-text way out is never removed.** Every `select` and every `confirm` carries
//!   [`SOMETHING_ELSE_CHOICE`], and an answer given through it is [`QuestionAnswer::Other`] for
//!   the whole of its life. Nothing coerces it into a listed choice or into yes.
//! * **The caller token is the source's alone.** It is returned once, over the private channel
//!   the question was created on, and it appears in no event, no notification and no diagnostic.
//!   [`CallerToken`] redacts itself in debug output so it cannot be logged by accident.
//!
//! An answer is not an approval. Section 11 keeps the two apart: answering `yes` here cannot
//! manufacture an upstream approval identifier or enlarge a grant.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::ProcessStartIdentity;
use crate::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, ConnectionId, DeviceId, QuestionId,
    QuestionRevision, SessionEpoch, SessionId,
};
use crate::scalars::{Bytes, DurationMs, Nullable, TimestampMs};

/// The largest answer a question accepts, in bytes.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The largest decision context a source may supply, in bytes.
pub const MAX_CONTEXT_BYTES: usize = 8 * 1024;

/// The largest question text a source may supply, in bytes.
pub const MAX_QUESTION_BYTES: usize = 4 * 1024;

/// The largest label a choice may carry, in bytes.
pub const MAX_CHOICE_LABEL_BYTES: usize = 256;

/// The largest unverified agent label a source may supply, in bytes.
pub const MAX_AGENT_NAME_BYTES: usize = 128;

/// The largest alert text a source may supply, in bytes.
pub const MAX_ALERT_TEXT_BYTES: usize = 2 * 1024;

/// The fewest choices a `select` question offers, beside the free-text option.
pub const MIN_SELECT_CHOICES: usize = 2;

/// The most choices a `select` question offers, beside the free-text option.
pub const MAX_SELECT_CHOICES: usize = 12;

/// The identifier of the free-text option every `select` and `confirm` carries.
pub const SOMETHING_ELSE_CHOICE: &str = "something_else";

/// The label of that option.
pub const SOMETHING_ELSE_LABEL: &str = "Something else";

/// How long a question lives when the source asks for no particular expiry.
pub const DEFAULT_EXPIRY: DurationMs = DurationMs::new(24 * 60 * 60 * 1000);

/// The longest expiry a source may ask for.
pub const MAX_EXPIRY: DurationMs = DEFAULT_EXPIRY;

/// The longest a creation may wait for an answer before returning the pending question.
pub const MAX_CREATE_WAIT: DurationMs = DurationMs::new(30 * 1000);

/// The long-poll duration a waiting source gets when it asks for none.
pub const DEFAULT_WAIT: DurationMs = DurationMs::new(5 * 60 * 1000);

/// The host's ceiling on one long poll.
pub const MAX_WAIT: DurationMs = DurationMs::new(10 * 60 * 1000);

/// The longest one broker wait inside a long poll runs before it is renewed.
///
/// A long poll is a subscription, not a held transaction, and it is renewed in bounded steps so a
/// client's own deadline, a cancelled call and a worker that stops answering are all noticed
/// promptly rather than at the end of the whole poll.
pub const WAIT_RENEWAL: DurationMs = DurationMs::new(20 * 1000);

/// The length of a caller token, in bytes.
pub const CALLER_TOKEN_BYTES: usize = 32;

/// What a question asks for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    /// Free text.
    Input,
    /// One of the listed choices, or free text.
    Select,
    /// Yes, no, or free text.
    Confirm,
}

impl QuestionKind {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Select => "select",
            Self::Confirm => "confirm",
        }
    }

    /// Returns true when this form carries the free-text option.
    #[must_use]
    pub const fn carries_something_else(self) -> bool {
        matches!(self, Self::Select | Self::Confirm)
    }
}

impl fmt::Display for QuestionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One option a `select` question offers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionChoice {
    /// The stable identifier an answer names. It does not change with the label.
    pub choice_id: String,
    /// What the person reads.
    pub label: String,
}

impl QuestionChoice {
    /// Returns the free-text option every `select` and `confirm` carries.
    #[must_use]
    pub fn something_else() -> Self {
        Self {
            choice_id: SOMETHING_ELSE_CHOICE.to_owned(),
            label: SOMETHING_ELSE_LABEL.to_owned(),
        }
    }
}

/// Where a question is in its life.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuestionState {
    /// Waiting for a person. Dismissing the form leaves it here.
    Pending,
    /// A person answered it. Terminal.
    Answered,
    /// The source or a person withdrew it. Terminal.
    Cancelled,
    /// Its deadline passed, or the application that asked has gone. Terminal.
    Expired,
}

impl QuestionState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Answered => "answered",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    /// Returns the state for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "answered" => Some(Self::Answered),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// Returns true when nothing further can change this question.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

impl fmt::Display for QuestionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What a person answered.
///
/// The four arms stay four arms. Section 11 forbids coercing [`Self::Other`] into a listed choice
/// or into a yes, so an answer that arrived as free text is read as free text by whatever consumes
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuestionAnswer {
    /// Free text, for an `input` question.
    Input {
        /// What the person typed.
        text: String,
    },
    /// One of the listed choices, for a `select` question.
    Choice {
        /// The choice the person selected.
        choice_id: String,
    },
    /// Yes or no, for a `confirm` question.
    Decision {
        /// True for yes.
        decided: bool,
    },
    /// The free-text option, available on every `select` and `confirm`.
    Other {
        /// What the person typed instead of choosing.
        text: String,
    },
}

impl QuestionAnswer {
    /// Returns the stable wire name of this arm.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Input { .. } => "input",
            Self::Choice { .. } => "choice",
            Self::Decision { .. } => "decision",
            Self::Other { .. } => "other",
        }
    }

    /// Returns the text an arm carries, for the two arms that carry text.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Input { text } | Self::Other { text } => Some(text),
            Self::Choice { .. } | Self::Decision { .. } => None,
        }
    }
}

/// The answer, who gave it and against which revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnswerRecord {
    /// What was answered.
    pub answer: QuestionAnswer,
    /// The host-verified principal that answered. A caller never asserts its own.
    pub actor_id: ActorId,
    /// The paired device that answered, when the answer came from one.
    pub device_id: Nullable<DeviceId>,
    /// The revision of the question the person was shown.
    pub question_revision: QuestionRevision,
    /// When the answer was recorded.
    pub answered_at_ms: TimestampMs,
}

/// The application the host verified as the source of a question.
///
/// Everything here except [`Self::agent_label`] comes from the operating system through the
/// worker's private socket. The label comes from the caller and is displayed as unverified, which
/// is the whole of the difference between the two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionSource {
    /// The application instance the worker minted for this verified process.
    pub application_instance_id: ApplicationInstanceId,
    /// The process the kernel reports on the other end of the socket, with its start value.
    pub process: ProcessStartIdentity,
    /// The executable that process is running, where the platform names it.
    pub executable: Nullable<String>,
    /// The caller's own label for itself. Unverified, and never part of authority.
    pub agent_label: Nullable<String>,
    /// The connection the question was created on.
    pub connection_id: ConnectionId,
    /// True when the helper presented the private launch channel it inherited.
    ///
    /// False means the binding rests on the checks below instead; it does not mean the source is
    /// less bound, and it is recorded so a reader can tell which evidence was available.
    pub launch_channel: bool,
    /// True when the process is inside the session's own ownership boundary, as the kernel
    /// reports it. This is what admits a source.
    pub session_member: bool,
    /// True when the process's parent chain reaches the session's root shell.
    ///
    /// A checked hint, recorded for diagnostics. Section 11 is explicit that ancestry is not a
    /// defence against arbitrary code running under the same account, so nothing is admitted on
    /// this alone.
    pub ancestry: bool,
    /// The agent thread or binding revision, when a qualified bridge supplied one.
    ///
    /// Null when no bridge did. A null here is not a claim that the thread never changed: without
    /// a bridge the question is application-scoped and thread-switch detection is not offered.
    pub agent_binding_revision: Nullable<AgentBindingRevision>,
}

/// One durable question.
///
/// This is the whole public view. The caller token is deliberately not a field: it is returned to
/// the source once, in [`QuestionCreateResult`], and never appears in a read, an event or a log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Question {
    /// The question's identity.
    pub question_id: QuestionId,
    /// Its revision. An answer names the exact revision it is answering.
    pub revision: QuestionRevision,
    /// Where it is in its life.
    pub state: QuestionState,
    /// The session that owns it.
    pub session_id: SessionId,
    /// The epoch that session was in when the question was created.
    pub session_epoch: SessionEpoch,
    /// What kind of answer it asks for.
    pub kind: QuestionKind,
    /// The concise decision context the source supplied.
    pub context: String,
    /// The question itself.
    pub question: String,
    /// The options, including the free-text one for `select` and `confirm`.
    pub choices: Vec<QuestionChoice>,
    /// The verified source, and the unverified label beside it.
    pub source: QuestionSource,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it expires if nothing else resolves it.
    pub expires_at_ms: TimestampMs,
    /// The answer, once there is one.
    pub answer: Nullable<AnswerRecord>,
    /// When it reached a terminal state.
    pub resolved_at_ms: Nullable<TimestampMs>,
}

impl Question {
    /// Returns the choice with this identifier.
    #[must_use]
    pub fn choice(&self, choice_id: &str) -> Option<&QuestionChoice> {
        self.choices
            .iter()
            .find(|choice| choice.choice_id == choice_id)
    }
}

/// How urgent an alert is.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Something worth knowing.
    Info,
    /// Something that may need attention.
    Warning,
    /// Something that went wrong.
    Error,
}

impl AlertSeverity {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Returns the severity for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One alert. It reports; it asks for nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    /// The source's own de-duplication identifier.
    pub dedup_id: String,
    /// The session it belongs to.
    pub session_id: SessionId,
    /// The verified source, and the unverified label beside it.
    pub source: QuestionSource,
    /// The concise text.
    pub text: String,
    /// How urgent it is.
    pub severity: AlertSeverity,
    /// A link into this host's own session, when the source supplied one.
    pub safe_session_link: Nullable<String>,
    /// When it was raised.
    pub created_at_ms: TimestampMs,
}

/// The opaque token that lets one verified source poll or cancel its own question.
///
/// It is not authority over a session and it is not an answer: it permits exactly the two reads
/// and the one cancellation that belong to the question it was issued for, and only from the same
/// verified application. Section 11 keeps it out of events, push payloads, backups and logs, so
/// this type prints as a redaction and carries no `Display`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct CallerToken(Bytes);

impl CallerToken {
    /// Wraps token bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(Bytes::new(bytes))
    }

    /// Returns the bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns true when the token is the right length to be one this host issued.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.0.len() == CALLER_TOKEN_BYTES
    }
}

impl fmt::Debug for CallerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallerToken(redacted)")
    }
}

/// Parameters of `question.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCreateParams {
    /// The session the source believes it is in. The host checks the binding regardless.
    pub session_id: SessionId,
    /// The caller's own unpredictable identifier for this request.
    ///
    /// De-duplication is by the verified originating application and this value together. A caller
    /// label is not part of it.
    pub request_id: String,
    /// The caller's label for itself. Unverified.
    pub agent_name: Nullable<String>,
    /// The concise decision context.
    pub context: String,
    /// The question itself.
    pub question: String,
    /// What kind of answer it asks for.
    pub kind: QuestionKind,
    /// The choices, for a `select`. The free-text option is added by the host.
    pub choices: Vec<QuestionChoice>,
    /// How long the question should live. Bounded by [`MAX_EXPIRY`] and by the source's own
    /// lifetime.
    pub requested_expiry_ms: Nullable<DurationMs>,
    /// How long to wait for an answer before returning the pending question. Bounded by
    /// [`MAX_CREATE_WAIT`].
    pub wait_ms: Nullable<DurationMs>,
}

/// The result of `question.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCreateResult {
    /// The durable question.
    pub question: Question,
    /// The token that lets this source poll and cancel it.
    pub caller_token: CallerToken,
    /// True when an exact duplicate returned the existing question rather than creating one.
    pub deduplicated: bool,
}

/// Parameters of `question.read_own`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionReadOwnParams {
    /// The session.
    pub session_id: SessionId,
    /// The question.
    pub question_id: QuestionId,
    /// The token issued when it was created.
    pub caller_token: CallerToken,
    /// How long to wait for a change before answering with the question as it stands.
    ///
    /// A wait that times out returns the same durable question. It does not recreate it, and it
    /// does not notify anybody again.
    pub wait_ms: Nullable<DurationMs>,
}

/// The result of `question.read_own` and `question.cancel_own`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionOwnResult {
    /// The question as it now stands.
    pub question: Question,
}

/// Parameters of `question.cancel_own`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCancelOwnParams {
    /// The session.
    pub session_id: SessionId,
    /// The question.
    pub question_id: QuestionId,
    /// The token issued when it was created.
    pub caller_token: CallerToken,
}

/// Parameters of `alert.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AlertCreateParams {
    /// The session.
    pub session_id: SessionId,
    /// The source's de-duplication identifier.
    pub dedup_id: String,
    /// The caller's label for itself. Unverified.
    pub agent_name: Nullable<String>,
    /// The concise text.
    pub text: String,
    /// How urgent it is.
    pub severity: AlertSeverity,
    /// A link into this host's own session, when there is one.
    pub safe_session_link: Nullable<String>,
}

/// The result of `alert.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AlertCreateResult {
    /// The alert.
    pub alert: Alert,
    /// True when an exact duplicate returned the existing alert rather than raising one.
    pub deduplicated: bool,
}

/// Parameters of `question.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionReadParams {
    /// The session.
    pub session_id: SessionId,
    /// One question, or null for every question this actor may see.
    pub question_id: Nullable<QuestionId>,
    /// True to include questions that have already been resolved.
    pub include_resolved: bool,
}

/// The result of `question.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionReadResult {
    /// The questions, oldest first.
    pub questions: Vec<Question>,
}

/// Parameters of `question.answer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswerParams {
    /// The session.
    pub session_id: SessionId,
    /// The question.
    pub question_id: QuestionId,
    /// The revision the person was shown. A different current revision is refused.
    pub expected_revision: QuestionRevision,
    /// The answer.
    pub answer: QuestionAnswer,
}

/// Parameters of `question.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCancelParams {
    /// The session.
    pub session_id: SessionId,
    /// The question.
    pub question_id: QuestionId,
    /// The revision the person was shown.
    pub expected_revision: QuestionRevision,
}

/// The result of `question.answer` and `question.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionResolveResult {
    /// The question as it now stands.
    pub question: Question,
}

/// What happened to a question, for the attention feed.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuestionEventKind {
    /// A verified source created it.
    Created,
    /// A person answered it.
    Answered,
    /// It was withdrawn.
    Cancelled,
    /// Its deadline passed or its source went.
    Expired,
}

impl QuestionEventKind {
    /// Returns the event type this kind is published as.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Created => "question.created",
            Self::Answered => "question.answered",
            Self::Cancelled => "question.cancelled",
            Self::Expired => "question.expired",
        }
    }
}

/// One question transition, as the attention engine reads it.
///
/// Section 25's idle reminder fires after five minutes of a *verified pending* request, so the
/// event carries the moment the question became pending and whether its source was verified.
/// Nothing here is the reminder itself; the attention engine owns that rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionEvent {
    /// What happened.
    pub kind: QuestionEventKind,
    /// The question at this revision.
    pub question: Question,
    /// When the question first became pending, which is when its idle timer starts.
    pub pending_since_ms: TimestampMs,
    /// When this transition was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// A question payload that failed the contract before it became a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuestionFormError(String);

impl QuestionFormError {
    /// Returns the sentence a caller is shown.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for QuestionFormError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for QuestionFormError {}

fn refuse(message: impl Into<String>) -> QuestionFormError {
    QuestionFormError(message.into())
}

/// Builds the choice list a question of this kind actually carries.
///
/// The free-text option is appended by the host, whatever the source sent, and a source that sends
/// its own copy of it is refused rather than silently corrected: a caller that thought it was
/// naming its own option under that identifier would otherwise get the host's.
///
/// # Errors
///
/// Returns [`QuestionFormError`] when the count, the identifiers or the labels break section 11's
/// rules for this kind.
pub fn build_choices(
    kind: QuestionKind,
    supplied: &[QuestionChoice],
) -> Result<Vec<QuestionChoice>, QuestionFormError> {
    match kind {
        QuestionKind::Input | QuestionKind::Confirm => {
            if !supplied.is_empty() {
                return Err(refuse(format!(
                    "a {kind} question carries no choices of its own"
                )));
            }
        }
        QuestionKind::Select => {
            if supplied.len() < MIN_SELECT_CHOICES || supplied.len() > MAX_SELECT_CHOICES {
                return Err(refuse(format!(
                    "a select question offers {MIN_SELECT_CHOICES} to {MAX_SELECT_CHOICES} \
                     choices, and this one offers {}",
                    supplied.len()
                )));
            }
        }
    }
    let mut choices = Vec::with_capacity(supplied.len() + 1);
    for choice in supplied {
        if choice.choice_id == SOMETHING_ELSE_CHOICE {
            return Err(refuse(format!(
                "{SOMETHING_ELSE_CHOICE} is the free-text option every form carries; it cannot be \
                 one of the listed choices"
            )));
        }
        if choice.choice_id.is_empty() || choice.choice_id.len() > MAX_CHOICE_LABEL_BYTES {
            return Err(refuse(
                "a choice identifier is 1 to 256 bytes of text".to_owned(),
            ));
        }
        if choice.label.trim().is_empty() || choice.label.len() > MAX_CHOICE_LABEL_BYTES {
            return Err(refuse(
                "a choice label is 1 to 256 bytes of text".to_owned(),
            ));
        }
        if choices
            .iter()
            .any(|existing: &QuestionChoice| existing.choice_id == choice.choice_id)
        {
            return Err(refuse(format!(
                "choice {} appears twice, and a choice identifier is stable",
                choice.choice_id
            )));
        }
        choices.push(choice.clone());
    }
    if kind.carries_something_else() {
        choices.push(QuestionChoice::something_else());
    }
    Ok(choices)
}

/// Checks the text a source supplied.
///
/// # Errors
///
/// Returns [`QuestionFormError`] when a field is empty where it must not be, or longer than its
/// bound.
pub fn check_text(params: &QuestionCreateParams) -> Result<(), QuestionFormError> {
    if params.request_id.trim().is_empty() || params.request_id.len() > 256 {
        return Err(refuse(
            "a request identifier is 1 to 256 bytes of text, and is the caller's own \
             unpredictable value",
        ));
    }
    if params.question.trim().is_empty() {
        return Err(refuse("a question asks something"));
    }
    if params.question.len() > MAX_QUESTION_BYTES {
        return Err(refuse(format!(
            "a question is at most {MAX_QUESTION_BYTES} bytes"
        )));
    }
    if params.context.len() > MAX_CONTEXT_BYTES {
        return Err(refuse(format!(
            "decision context is at most {MAX_CONTEXT_BYTES} bytes"
        )));
    }
    if let Some(name) = params.agent_name.as_ref()
        && (name.trim().is_empty() || name.len() > MAX_AGENT_NAME_BYTES)
    {
        return Err(refuse(format!(
            "an agent label is 1 to {MAX_AGENT_NAME_BYTES} bytes of text"
        )));
    }
    Ok(())
}

/// Checks an answer against the question it is for.
///
/// # Errors
///
/// Returns [`QuestionFormError`] when the arm does not belong to this kind, names a choice the
/// question does not offer, or carries more than [`MAX_ANSWER_BYTES`].
pub fn check_answer(question: &Question, answer: &QuestionAnswer) -> Result<(), QuestionFormError> {
    if let Some(text) = answer.text() {
        if text.len() > MAX_ANSWER_BYTES {
            return Err(refuse(format!(
                "an answer is at most {MAX_ANSWER_BYTES} bytes"
            )));
        }
        if text.is_empty() {
            return Err(refuse("an answer carries the text the person wrote"));
        }
    }
    match answer {
        QuestionAnswer::Input { .. } => {
            if question.kind != QuestionKind::Input {
                return Err(refuse(format!(
                    "a {} question is not answered with free text; use the free-text option",
                    question.kind
                )));
            }
        }
        QuestionAnswer::Choice { choice_id } => {
            if question.kind != QuestionKind::Select {
                return Err(refuse(format!(
                    "a {} question offers no listed choices",
                    question.kind
                )));
            }
            if choice_id == SOMETHING_ELSE_CHOICE {
                return Err(refuse(
                    "the free-text option is answered with its own text, not as a listed choice",
                ));
            }
            if question.choice(choice_id).is_none() {
                return Err(refuse(format!(
                    "this question does not offer choice {choice_id}"
                )));
            }
        }
        QuestionAnswer::Decision { .. } => {
            if question.kind != QuestionKind::Confirm {
                return Err(refuse(format!(
                    "a {} question is not answered yes or no",
                    question.kind
                )));
            }
        }
        QuestionAnswer::Other { .. } => {
            if !question.kind.carries_something_else() {
                return Err(refuse(format!(
                    "a {} question has no free-text option beside itself",
                    question.kind
                )));
            }
        }
    }
    Ok(())
}

/// Returns the expiry a creation gets, bounded by the host's own ceiling.
#[must_use]
pub fn bounded_expiry(requested: Option<DurationMs>) -> DurationMs {
    match requested {
        None => DEFAULT_EXPIRY,
        Some(asked) if asked.get() == 0 || asked.get() > MAX_EXPIRY.get() => MAX_EXPIRY,
        Some(asked) => asked,
    }
}

/// Returns how long one call may wait, bounded by the host's ceiling.
#[must_use]
pub fn bounded_wait(requested: Option<DurationMs>, ceiling: DurationMs) -> DurationMs {
    match requested {
        None => DurationMs::new(DEFAULT_WAIT.get().min(ceiling.get())),
        Some(asked) => DurationMs::new(asked.get().min(ceiling.get())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choice(id: &str) -> QuestionChoice {
        QuestionChoice {
            choice_id: id.to_owned(),
            label: format!("Label {id}"),
        }
    }

    /// A pending question of `kind`, carrying the choices the host builds for that kind.
    fn question(kind: QuestionKind, supplied: &[QuestionChoice]) -> Question {
        use crate::identity::ProcessStartSource;
        use crate::scalars::Uuid;

        Question {
            question_id: QuestionId::new(Uuid::from_bytes([1; 16])),
            revision: QuestionRevision::new(1),
            state: QuestionState::Pending,
            session_id: SessionId::new(Uuid::from_bytes([2; 16])),
            session_epoch: SessionEpoch::V1,
            kind,
            context: String::new(),
            question: "which one?".to_owned(),
            choices: build_choices(kind, supplied).expect("a well-formed question"),
            source: QuestionSource {
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
                process: ProcessStartIdentity::new(7, ProcessStartSource::LinuxProcStat, 11),
                executable: Nullable::null(),
                agent_label: Nullable::null(),
                connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
                launch_channel: false,
                session_member: true,
                ancestry: true,
                agent_binding_revision: Nullable::null(),
            },
            created_at_ms: TimestampMs::new(0),
            expires_at_ms: TimestampMs::new(DEFAULT_EXPIRY.get()),
            answer: Nullable::null(),
            resolved_at_ms: Nullable::null(),
        }
    }

    /// KR-REQ-11.59: a question is `input`, `select` or `confirm`, and no other kind is read.
    #[test]
    fn a_question_is_input_select_or_confirm_and_nothing_else() {
        for (kind, wire) in [
            (QuestionKind::Input, "input"),
            (QuestionKind::Select, "select"),
            (QuestionKind::Confirm, "confirm"),
        ] {
            assert_eq!(kind.as_str(), wire);
            assert_eq!(
                serde_json::from_value::<QuestionKind>(serde_json::json!(wire)).expect("a kind"),
                kind
            );
        }
        for unknown in ["multi_select", "approval", "yes_no", ""] {
            assert!(
                serde_json::from_value::<QuestionKind>(serde_json::json!(unknown)).is_err(),
                "{unknown:?} is not a question kind"
            );
        }
    }

    /// KR-REQ-11.59: an answer carries at most 16 KiB of text, whichever text arm it arrives in,
    /// and the free-text arm is answerable on every `select` and `confirm` and on nothing else.
    #[test]
    fn an_answer_is_one_arm_of_the_union_and_at_most_sixteen_kibibytes() {
        let input = question(QuestionKind::Input, &[]);
        let select = question(QuestionKind::Select, &[choice("a"), choice("b")]);
        let confirm = question(QuestionKind::Confirm, &[]);
        let at_limit = "x".repeat(MAX_ANSWER_BYTES);
        let over_limit = "x".repeat(MAX_ANSWER_BYTES + 1);
        assert_eq!(MAX_ANSWER_BYTES, 16 * 1024);

        // The two text arms: exactly the limit is accepted, one byte more is refused.
        let typed = |text: &str| QuestionAnswer::Input {
            text: text.to_owned(),
        };
        let other = |text: &str| QuestionAnswer::Other {
            text: text.to_owned(),
        };
        assert!(check_answer(&input, &typed(&at_limit)).is_ok());
        assert!(check_answer(&input, &typed(&over_limit)).is_err());
        for form in [&select, &confirm] {
            assert!(
                check_answer(form, &other(&at_limit)).is_ok(),
                "{}",
                form.kind
            );
            assert!(
                check_answer(form, &other(&over_limit)).is_err(),
                "{}",
                form.kind
            );
        }
        // The limit is on bytes, not characters: 4,097 four-byte characters are over it.
        assert!(check_answer(&input, &typed(&"\u{1F600}".repeat(4 * 1024 + 1))).is_err());

        // Each arm answers its own kind. A listed choice is the select's; a decision is the
        // confirm's; the free-text arm is never folded into a listed choice.
        let chosen = QuestionAnswer::Choice {
            choice_id: "a".to_owned(),
        };
        let decided = QuestionAnswer::Decision { decided: true };
        assert!(check_answer(&select, &chosen).is_ok());
        assert!(check_answer(&confirm, &chosen).is_err());
        assert!(check_answer(&confirm, &decided).is_ok());
        assert!(check_answer(&select, &decided).is_err());
        assert!(check_answer(&input, &other("free text")).is_err());
        assert!(
            check_answer(
                &select,
                &QuestionAnswer::Choice {
                    choice_id: SOMETHING_ELSE_CHOICE.to_owned()
                }
            )
            .is_err(),
            "the free-text option is answered with its own text, not as a listed choice"
        );
    }

    /// KR-REQ-11.59: "Something else" is on every `select` and `confirm`, added by the host.
    #[test]
    fn every_select_and_confirm_carries_the_free_text_option() {
        let select = build_choices(QuestionKind::Select, &[choice("a"), choice("b")]).expect("ok");
        assert_eq!(select.len(), 3);
        assert_eq!(select[2].choice_id, SOMETHING_ELSE_CHOICE);

        let confirm = build_choices(QuestionKind::Confirm, &[]).expect("ok");
        assert_eq!(confirm, vec![QuestionChoice::something_else()]);

        let input = build_choices(QuestionKind::Input, &[]).expect("ok");
        assert!(input.is_empty());
    }

    /// KR-REQ-11.59: a source cannot supply, and so cannot replace or remove, the free-text option.
    #[test]
    fn a_source_cannot_supply_its_own_free_text_option() {
        let error = build_choices(
            QuestionKind::Select,
            &[choice("a"), QuestionChoice::something_else()],
        )
        .expect_err("refused");
        assert!(error.message().contains(SOMETHING_ELSE_CHOICE));
    }

    /// KR-REQ-11.59: a select offers two to twelve listed choices.
    #[test]
    fn a_select_offers_between_two_and_twelve_choices() {
        assert!(build_choices(QuestionKind::Select, &[choice("a")]).is_err());
        let many: Vec<QuestionChoice> = (0..13).map(|index| choice(&index.to_string())).collect();
        assert!(build_choices(QuestionKind::Select, &many).is_err());
        let twelve: Vec<QuestionChoice> = (0..12).map(|index| choice(&index.to_string())).collect();
        assert!(build_choices(QuestionKind::Select, &twelve).is_ok());
    }

    #[test]
    fn a_caller_token_does_not_print_itself() {
        let token = CallerToken::new(vec![7; CALLER_TOKEN_BYTES]);
        assert_eq!(format!("{token:?}"), "CallerToken(redacted)");
        assert!(token.is_well_formed());
    }

    #[test]
    fn an_expiry_is_bounded_by_a_day() {
        assert_eq!(bounded_expiry(None), DEFAULT_EXPIRY);
        assert_eq!(bounded_expiry(Some(DurationMs::new(0))), MAX_EXPIRY);
        assert_eq!(
            bounded_expiry(Some(DurationMs::new(MAX_EXPIRY.get() + 1))),
            MAX_EXPIRY
        );
        assert_eq!(
            bounded_expiry(Some(DurationMs::new(60_000))),
            DurationMs::new(60_000)
        );
    }

    #[test]
    fn a_wait_is_bounded_by_the_host_ceiling() {
        assert_eq!(bounded_wait(None, MAX_WAIT), DEFAULT_WAIT);
        assert_eq!(
            bounded_wait(None, DurationMs::new(1_000)),
            DurationMs::new(1_000)
        );
        assert_eq!(
            bounded_wait(Some(DurationMs::new(u64::MAX)), MAX_WAIT),
            MAX_WAIT
        );
    }
}
