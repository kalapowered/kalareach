//! The managed voice broker client.
//!
//! Section 15 ¶3: a managed call is created by one HTTPS request carrying the caller's own SDP
//! offer, the account authorisation, the selected host and the budget request, and answered with
//! the provider's SDP answer. Audio then flows directly between the native client and the
//! provider. The project key is never distributed and never appears here.
//!
//! # What this module supplies and what it does not
//!
//! The same division as [`super::relay`]: the HTTP exchange is the embedder's
//! ([`super::ServiceHttp`]) and the account token is the embedder's ([`AccountTokenSource`]).
//! What this module owns is the request shape, the exact bytes, and what each answer means.
//!
//! # What an answer means
//!
//! Three things can be true of a creation and only one of them is a running call, so
//! [`VoiceStart`] has three cases rather than a result and an error:
//!
//! * a call is running;
//! * the broker could not tell whether the provider created a session
//!   ([`VoiceStart::CreationUnknown`]). Section 15 ¶4 and the frozen provider profile both say the
//!   same thing about it: **nothing retries it automatically**, no SDP answer exists for that
//!   attempt, and the reservation is reconciled by the service. It is a state, not an error code;
//! * the broker refused, with a reason in its own vocabulary and the paths that still work.
//!
//! # The control socket
//!
//! The socket belongs to the device that holds the media, not to the host, so this module carries
//! the frames and the rules rather than a connection. Two rules are worth stating where a caller
//! reads them. The client sends **zero** raw provider control events: [`VoiceCommand`] is the
//! whole vocabulary, and the service decides what each becomes on the provider's wire. And an
//! event this build does not know is recorded by type and dropped ([`VoiceControlEvent::Unknown`])
//! rather than being interpreted, because an unknown event never reaches a host action.
//!
//! # The account token
//!
//! [`AccountToken`] holds it. Its [`fmt::Debug`] prints a placeholder, it has no [`fmt::Display`],
//! and the only way to the bytes is [`AccountToken::expose`], which this module calls exactly once
//! per request while building the `Authorization` header.

use std::fmt;
use std::sync::Arc;

use kr_protocol::error::{ErrorCode, ProtocolError};
use serde::{Deserialize, Serialize};

use super::ServiceFuture;
pub use super::{ServiceHttp, ServiceHttpAnswer};
use crate::error::{ClientError, Result};
use crate::retry::UserAction;

/// The scope an account token needs before it can start or control a managed call.
///
/// Authenticating an account is not the same as being entitled to spend its balance, so the scope
/// names the resource. The service refuses a token without it and says so.
pub const VOICE_SCOPE: &str = "voice";

/// Where brokered session creation answers.
pub const VOICE_SESSIONS_PATH: &str = "/api/voice/sessions";

/// Seconds between heartbeats on the control socket while a native call is active.
pub const VOICE_HEARTBEAT_SECONDS: u32 = 20;

/// Seconds without a control socket after which the service closes the call.
pub const VOICE_CLIENT_ABSENT_SECONDS: u32 = 120;

/// Seconds before the reservation ends at which the service closes the call.
pub const VOICE_CLOSE_LEAD_SECONDS: u32 = 15;

/// Shortest call the service will reserve.
pub const VOICE_MINIMUM_REQUEST_SECONDS: u32 = 60;

/// Largest control frame the service will read before refusing it.
pub const VOICE_CONTROL_FRAME_BYTES: usize = 4096;

/// Largest SDP offer the service will forward.
pub const VOICE_OFFER_BYTES: usize = 32_768;

/// Largest context append the service will send, in UTF-8 bytes.
pub const VOICE_CONTEXT_BYTES: usize = 500;

/// Context requests one call may make in a minute.
pub const VOICE_CONTEXT_PER_MINUTE: u32 = 60;

/// Context requests one call may make at once before it has to wait.
pub const VOICE_CONTEXT_BURST: u32 = 10;

/// Returns the control-socket path for one call.
#[must_use]
pub fn voice_control_path(call_id: &str) -> String {
    format!("{VOICE_SESSIONS_PATH}/{}/control", encode_segment(call_id))
}

/// Returns the path that ends one call without a control socket.
#[must_use]
pub fn voice_close_path(call_id: &str) -> String {
    format!("{VOICE_SESSIONS_PATH}/{}/close", encode_segment(call_id))
}

/// Percent-encodes one path segment.
///
/// A call identifier comes from the service and is a UUID today. It is encoded anyway, because a
/// client that trusted a remote value to be path-safe would be trusting the wrong party.
fn encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/* -------------------------------------------------------------------------- */
/* The account token                                                           */
/* -------------------------------------------------------------------------- */

/// An account access token, held so it cannot reach a log by accident.
///
/// The value is never in a [`fmt::Debug`] rendering and there is no [`fmt::Display`]. A caller
/// that needs the bytes asks for them by name, which is one line to find in a review rather than
/// an interpolation to notice.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountToken(String);

impl AccountToken {
    /// Wraps an access token, rejecting one that cannot be sent as a header value.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is empty or carries a character an HTTP header may not.
    /// The refusal never quotes the token.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(local("an account token is not empty"));
        }
        if value.len() > 8192 {
            return Err(local("an account token is at most 8192 bytes"));
        }
        if !value
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ')
        {
            return Err(local(
                "an account token is printable ASCII, as an authorisation header value is",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the token itself, for the one caller that has to send it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountToken(<not printed>)")
    }
}

/// Where the current account token comes from.
///
/// A token expires and is replaced, so a client that was handed one at construction would keep
/// presenting a dead one. The embedder answers with whatever it holds now: a file the operator
/// imported, a keychain entry, or a sign-in the application performed.
pub trait AccountTokenSource: Send + Sync + fmt::Debug {
    /// Returns the token to present.
    ///
    /// # Errors
    ///
    /// Returns an error when no token is configured or the stored one cannot be read. The error
    /// never carries the token.
    fn token(&self) -> Result<AccountToken>;
}

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// What a caller asks for when it starts a managed call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceSessionRequest {
    /// The caller's own SDP offer, as its WebRTC stack produced it.
    ///
    /// It is forwarded unchanged. Nothing here terminates media.
    pub offer_sdp: String,
    /// The host the call is about, as the device selected it. Recorded, never authority.
    pub host_id: String,
    /// Seconds of call the caller is asking to be authorised for.
    pub duration_seconds: u32,
    /// Minor units to hold for reasoning and tools, held separately from the call itself.
    pub reasoning_budget_minor: Option<u64>,
    /// The paired device asking, as the host knows it. Recorded, never authority.
    pub device_id: Option<String>,
}

/// The body of a creation request, in the spelling the service reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreationBody {
    offer_sdp: String,
    host_id: String,
    duration_seconds: u32,
    /// Minor units are decimal strings on this service's wire, as every amount of money is.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

impl VoiceSessionRequest {
    /// Checks what this client can check before spending a request on it.
    ///
    /// The bounds are the service's own, and a caller that respects them is a caller whose
    /// refusals are about capacity rather than shape.
    fn body(&self) -> Result<CreationBody> {
        if !self.offer_sdp.starts_with("v=0") {
            return Err(local(
                "an offer is the SDP a WebRTC stack produced, starting with its version line",
            ));
        }
        if self.offer_sdp.len() > VOICE_OFFER_BYTES {
            return Err(local("an offer is at most 32768 bytes"));
        }
        if self.host_id.is_empty() || self.host_id.len() > 128 {
            return Err(local("a managed call names the host it is about"));
        }
        if self.duration_seconds < VOICE_MINIMUM_REQUEST_SECONDS {
            return Err(local("a managed call lasts at least 60 seconds"));
        }
        if self
            .device_id
            .as_ref()
            .is_some_and(|device| device.len() > 128)
        {
            return Err(local("a device identifier is a short string"));
        }
        Ok(CreationBody {
            offer_sdp: self.offer_sdp.clone(),
            host_id: self.host_id.clone(),
            duration_seconds: self.duration_seconds,
            reasoning_budget: self.reasoning_budget_minor.map(|minor| minor.to_string()),
            device_id: self.device_id.clone(),
        })
    }
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// A reservation as the caller needs to see it: what is held and until when.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceHold {
    /// The reservation.
    pub reservation_id: String,
    /// Seconds held for the call, or minor units held for reasoning.
    pub reserved: String,
    /// Largest charge the accepted quote authorises.
    pub ceiling: String,
    /// When the reservation ends, as an RFC 3339 instant.
    pub deadline: String,
}

/// The rate a call was authorised under. A later price change cannot enlarge it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceRateQuote {
    /// Operator-configured version of the rate table this call accepted.
    pub version: String,
    /// Minor units per second, as a decimal string.
    pub minor_units_per_second: String,
    /// Shortest duration the provider sells, charged whatever the call did.
    pub minimum_seconds: u32,
    /// ISO 4217 code the amounts are in.
    pub currency: String,
}

/// What the service recorded about how long starting the call took.
///
/// Both figures are the service's own. First audio and delegation latency are the client's to
/// measure, because only the client can hear the one and receives the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceStartLatency {
    /// From the request arriving to the answer being releasable.
    pub creation_to_answer_ms: u64,
    /// From the provider session existing to the metering channel being durably ready.
    pub sideband_ready_ms: u64,
}

/// A managed call that is running, and everything the caller needs to use it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceSession {
    /// The service's identifier for the call. The control socket is addressed by it.
    pub call_id: String,
    /// The creation attempt that produced it, recorded before the provider was asked.
    pub attempt_id: String,
    /// The provider's own session identifier. Opaque; never parsed or constructed.
    pub provider_session_id: String,
    /// The provider's SDP answer, to be applied to the caller's own connection.
    pub answer_sdp: String,
    /// The model the call is running on.
    pub model: String,
    /// When the service closes the call, whatever else happens.
    pub closes_at: String,
    /// When the reservation behind it ends.
    pub reservation_ends_at: String,
    /// Path on the service's origin the control socket is opened on.
    pub control_path: String,
    /// Seconds between heartbeats the client is expected to send.
    pub heartbeat_seconds: u32,
    /// The trusted metering channel was ready before this answer was released.
    pub sideband_ready: bool,
    /// The reservation held for the call.
    pub hold: VoiceHold,
    /// The separate reasoning hold, or null when none was asked for.
    pub reasoning_hold: Option<VoiceHold>,
    /// The rate the call was authorised under.
    pub rate: VoiceRateQuote,
    /// What the service recorded about starting it.
    pub latency: VoiceStartLatency,
    /// True when this answer is the one an earlier attempt already produced.
    ///
    /// A caller whose answer was lost asks again with the same offer and receives the same answer
    /// rather than a second metered session. It is not a reason to ask again by itself.
    pub replayed: bool,
    /// What the provider and the service can see, stated where the caller reads it.
    pub disclosure: Vec<String>,
}

/// Why a managed call could not be started, in the service's own terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRefusalReason {
    /// The request was not one the service serves.
    InvalidRequest,
    /// No account token, or one without the scope that names this resource.
    Unauthorised,
    /// The account's own allowance or balance does not cover the call.
    AccountAllowance,
    /// Managed capacity is spent, or an operator has closed this path.
    ServiceCapacity,
    /// This account already has a managed call, and the offer is not that call's.
    SessionInProgress,
    /// The provider refused the creation. Nothing was charged.
    ProviderRefused,
    /// The attempt was given back before it could start. Asking again starts a new one.
    AttemptReconciled,
    /// The provider may or may not have created a session, and the service cannot tell.
    CreationUnknown,
    /// A session was created and never became usable. That session is closed and reconciled.
    ReadinessUnavailable,
    /// This deployment has not been given what managed voice needs.
    NotConfigured,
    /// A reason this build does not know.
    ///
    /// Recorded rather than guessed at. A newer service naming a reason an older client has never
    /// heard of is a refusal it still has to report honestly.
    #[serde(other)]
    Unrecognised,
}

impl VoiceRefusalReason {
    /// Returns the stable wire string, or `unrecognised` for a reason this build does not know.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorised => "unauthorised",
            Self::AccountAllowance => "account_allowance",
            Self::ServiceCapacity => "service_capacity",
            Self::SessionInProgress => "session_in_progress",
            Self::ProviderRefused => "provider_refused",
            Self::AttemptReconciled => "attempt_reconciled",
            Self::CreationUnknown => "creation_unknown",
            Self::ReadinessUnavailable => "readiness_unavailable",
            Self::NotConfigured => "not_configured",
            Self::Unrecognised => "unrecognised",
        }
    }
}

impl fmt::Display for VoiceRefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A refusal, as this client reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceRefusal {
    /// The service's own reason.
    pub reason: VoiceRefusalReason,
    /// What a person is told. Safe to display, and never a provider credential.
    pub message: String,
    /// Paths that still work, when the refusal was about capacity or an allowance.
    pub alternatives: Vec<String>,
    /// The attempt, when one was recorded before the refusal.
    pub attempt_id: Option<String>,
    /// The call, when one was recorded before the refusal.
    pub call_id: Option<String>,
}

/// What a creation request was answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceStart {
    /// A call is running.
    Started(Box<VoiceSession>),
    /// The provider may or may not hold a session for this attempt.
    ///
    /// A typed state rather than an error code. **Never retried automatically**: the provider
    /// creation is not idempotent, so asking again could pay for a second call while the first is
    /// still running. What a caller may do is tell the person and let them ask again.
    CreationUnknown {
        /// The attempt, for a later reconciliation to name. Absent when the service recorded none.
        attempt_id: Option<String>,
        /// What a person is told.
        message: String,
    },
    /// The service refused, and what still works.
    Refused(Box<VoiceRefusal>),
}

impl VoiceStart {
    /// The running call, when there is one.
    #[must_use]
    pub fn session(&self) -> Option<&VoiceSession> {
        match self {
            Self::Started(session) => Some(session),
            Self::CreationUnknown { .. } | Self::Refused(_) => None,
        }
    }

    /// Returns true when asking again with the same offer is safe.
    ///
    /// Only a refusal the service decided before it asked the provider. An unknown creation is
    /// never one of them, which is the whole point of the state.
    #[must_use]
    pub fn may_ask_again(&self) -> bool {
        match self {
            Self::Started(_) | Self::CreationUnknown { .. } => false,
            Self::Refused(refusal) => matches!(
                refusal.reason,
                VoiceRefusalReason::AttemptReconciled
                    | VoiceRefusalReason::ServiceCapacity
                    | VoiceRefusalReason::AccountAllowance
            ),
        }
    }
}

/// What ending a call did.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceClosure {
    /// The call that ended.
    pub call_id: String,
    /// The state the service recorded for it.
    pub state: String,
    /// Seconds metered. Cumulative, never an increment to add to an earlier figure.
    pub usage_seconds: u64,
    /// True while the figure is the last one seen rather than a finalised one.
    ///
    /// Only `session.closed` finalises. A socket closing is not evidence of final usage.
    pub usage_provisional: bool,
}

/* -------------------------------------------------------------------------- */
/* The control socket's vocabulary                                             */
/* -------------------------------------------------------------------------- */

/// The six things a client may ask the service to do to a running call.
///
/// These are the service's names, not the provider's, and they are the whole vocabulary. Section
/// 15 ¶6: the client sends **zero** raw provider control events, and a request naming one is
/// refused by that name. `session.start`, `session.update`, `response.item.create`,
/// `response.create` and fork operations are excluded from this route entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceCommand {
    /// Stop caller audio reaching the model, without ending the call.
    Mute,
    /// Resume caller audio.
    Unmute,
    /// Add application-authored instructions. Never project text or caller text.
    Instructions,
    /// Add context the model may use without speaking it.
    Thinking,
    /// Add a result the model should communicate.
    Commentary,
    /// Finalise the call.
    Close,
}

impl VoiceCommand {
    /// Every command, in a fixed order.
    pub const ALL: &'static [Self] = &[
        Self::Mute,
        Self::Unmute,
        Self::Instructions,
        Self::Thinking,
        Self::Commentary,
        Self::Close,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mute => "mute",
            Self::Unmute => "unmute",
            Self::Instructions => "instructions",
            Self::Thinking => "thinking",
            Self::Commentary => "commentary",
            Self::Close => "close",
        }
    }

    /// Returns the command for a wire string, or nothing.
    ///
    /// A provider event type resolves to nothing here, which is what makes "zero raw provider
    /// control events" a property of the type rather than a promise.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|command| command.as_str() == value)
    }

    /// Returns true when this command carries text. The other three carry none.
    #[must_use]
    pub const fn carries_text(self) -> bool {
        matches!(self, Self::Instructions | Self::Thinking | Self::Commentary)
    }
}

impl fmt::Display for VoiceCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One bounded context request, as it travels on the control socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceContextFrame {
    /// Always `context`.
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    /// The caller's own identifier for this request. Answers quote it.
    pub id: String,
    /// The command.
    pub command: VoiceCommand,
    /// A delegation the provider has announced, or null for context belonging to the call.
    pub delegation_id: Option<String>,
    /// Plain text, bounded at [`VOICE_CONTEXT_BYTES`] UTF-8 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl VoiceContextFrame {
    /// Builds one context request, checking what this client can check.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is empty or over-long, when a command that carries no
    /// text is given some or a command that carries text is given none, or when the content is
    /// longer than the append bound.
    pub fn new(
        id: impl Into<String>,
        command: VoiceCommand,
        delegation_id: Option<String>,
        content: Option<String>,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > 128 {
            return Err(local("a context request identifies itself"));
        }
        if command.carries_text() != content.is_some() {
            return Err(local(
                "instructions, thinking and commentary carry text; mute, unmute and close do not",
            ));
        }
        if content
            .as_ref()
            .is_some_and(|text| text.len() > VOICE_CONTEXT_BYTES)
        {
            return Err(local("an append is at most 500 UTF-8 bytes"));
        }
        if delegation_id.as_ref().is_some_and(String::is_empty) {
            return Err(local("a delegation identifier is not empty"));
        }
        Ok(Self {
            frame_type: "context",
            id,
            command,
            delegation_id,
            content,
        })
    }
}

/// Something the service sent on the control socket.
///
/// The variants are the frames this build knows. Anything else is [`Self::Unknown`], which records
/// the type and carries nothing: section 15 ¶6 says an unknown event is never reflected into a
/// host action, and a variant with no payload is the shortest way to mean it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceControlEvent {
    /// The call is attached and ready to carry context requests.
    Ready {
        /// The call.
        call_id: String,
        /// Delegations the provider has announced so far, oldest first.
        delegations: Vec<String>,
    },
    /// A heartbeat was received. The deadline it reports is unchanged by it.
    HeartbeatAcknowledged {
        /// Seconds left of the authorised call.
        remaining_seconds: u64,
    },
    /// The request was valid and has been sent to the provider.
    ContextAccepted {
        /// The request it answers.
        id: String,
    },
    /// The provider acknowledged the request.
    ///
    /// **Admission is not execution.** It says the context reached the model, and nothing about a
    /// host action having run or audio having been played. Host action receipts are the authority
    /// for that, and [`VOICE_ADMISSION_NOTE`] is the sentence that says so.
    ContextAdmitted {
        /// The request it answers.
        id: String,
        /// What admission does not establish, as the service stated it.
        note: String,
    },
    /// The request was refused. Nothing was sent to the provider.
    ContextRefused {
        /// The request it answers.
        id: String,
        /// The service's reason.
        reason: String,
        /// What a person is told.
        message: String,
    },
    /// What the provider has metered so far. Cumulative, never an increment.
    Usage {
        /// Seconds metered so far.
        seconds: u64,
        /// True while the figure is the last one seen rather than a finalised one.
        provisional: bool,
    },
    /// The call has ended.
    Closed {
        /// Why.
        reason: String,
        /// Seconds finalised, or the last cumulative figure when none was finalised.
        seconds: u64,
        /// True when no finalisation arrived.
        provisional: bool,
    },
    /// Something worth telling the client that is not an answer to a request.
    Notice {
        /// What it is about.
        notice: String,
        /// What a person is told.
        message: String,
    },
    /// The provider announced a delegation. Correlation data, and never authority.
    Delegation {
        /// The opaque provider identifier.
        delegation_id: String,
        /// Where in the call it happened, in milliseconds from the start.
        offset_ms: u64,
    },
    /// A frame this build does not know, recorded by type and dropped.
    Unknown {
        /// The type the service named.
        frame_type: String,
    },
}

/// What a provider append acknowledgement does not establish.
pub const VOICE_ADMISSION_NOTE: &str = "The model received this context. It is not evidence that a host action ran or that audio was \
     played; host action receipts are the authority for that.";

/// Reads one control-socket frame.
///
/// A frame whose type this build does not know becomes [`VoiceControlEvent::Unknown`] with its
/// type and nothing else. A frame whose type is known and whose shape is wrong is not a frame at
/// all, and `None` is that: inventing defaults for a malformed frame would be interpreting it.
#[must_use]
pub fn read_control_event(value: &serde_json::Value) -> Option<VoiceControlEvent> {
    let object = value.as_object()?;
    let frame_type = object.get("type")?.as_str()?;
    let text = |name: &str| object.get(name).and_then(serde_json::Value::as_str);
    let number = |name: &str| object.get(name).and_then(serde_json::Value::as_u64);
    let flag = |name: &str| object.get(name).and_then(serde_json::Value::as_bool);

    let event = match frame_type {
        "ready" => VoiceControlEvent::Ready {
            call_id: text("callId")?.to_owned(),
            delegations: object
                .get("delegations")?
                .as_array()?
                .iter()
                .map(|entry| entry.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()?,
        },
        "heartbeat_ack" => VoiceControlEvent::HeartbeatAcknowledged {
            remaining_seconds: number("remainingSeconds")?,
        },
        "context_accepted" => VoiceControlEvent::ContextAccepted {
            id: text("id")?.to_owned(),
        },
        "context_admitted" => VoiceControlEvent::ContextAdmitted {
            id: text("id")?.to_owned(),
            note: text("note")?.to_owned(),
        },
        "context_refused" => VoiceControlEvent::ContextRefused {
            id: text("id")?.to_owned(),
            reason: text("reason")?.to_owned(),
            message: text("message")?.to_owned(),
        },
        "usage" => VoiceControlEvent::Usage {
            seconds: number("seconds")?,
            provisional: flag("provisional")?,
        },
        "closed" => VoiceControlEvent::Closed {
            reason: text("reason")?.to_owned(),
            seconds: number("seconds")?,
            provisional: flag("provisional")?,
        },
        "notice" => VoiceControlEvent::Notice {
            notice: text("notice")?.to_owned(),
            message: text("message")?.to_owned(),
        },
        "delegation" => VoiceControlEvent::Delegation {
            delegation_id: text("delegationId")?.to_owned(),
            offset_ms: number("offsetMs")?,
        },
        other => VoiceControlEvent::Unknown {
            frame_type: other.to_owned(),
        },
    };
    Some(event)
}

/* -------------------------------------------------------------------------- */
/* The service                                                                 */
/* -------------------------------------------------------------------------- */

/// Where managed voice is brokered.
///
/// The interface is deliberately this small, because it is the seam a BYOK backend, a local voice
/// engine or another provider replaces. Nothing above it knows which one answered.
pub trait ManagedVoiceService: Send + Sync + fmt::Debug {
    /// Creates one managed call from the caller's own SDP offer.
    ///
    /// # Errors
    ///
    /// Returns a transport or protocol error. A refusal by the service is an answer rather than
    /// an error: see [`VoiceStart::Refused`].
    fn start<'a>(&'a self, request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart>;

    /// Ends one call and asks the service to finalise it.
    ///
    /// Idempotent: a repeat finishes whatever the first attempt could not. It never establishes
    /// final usage by itself, which only `session.closed` does.
    ///
    /// # Errors
    ///
    /// Returns a transport or protocol error.
    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure>;

    /// What this provider is, for a caller holding calls from more than one.
    ///
    /// A call identifier means something only to the provider that issued it, and two providers
    /// can name a call the same thing. A host that holds calls from both tells them apart by this
    /// and the identifier together, so it never ends one provider's call because another one
    /// named a call the same way. Two clients of the same service answer the same thing; the
    /// managed broker answers the origin it reaches.
    fn provider(&self) -> String;
}

/// One origin in the spelling this crate compares.
///
/// Lower case, and without the port a scheme implies. Nothing else is touched: an origin is
/// already a scheme, a host and an optional port by the time it is accepted.
fn normalised_origin(origin: &str) -> String {
    let lowered = origin.to_lowercase();
    let Some((scheme, rest)) = lowered
        .split_once("://")
        .map(|(scheme, rest)| (format!("{scheme}://"), rest.to_owned()))
    else {
        return lowered;
    };
    // The port, as a number rather than as the digits somebody wrote: `:0443` and `:443` are one
    // port, and the port a scheme implies is the same origin as no port at all.
    let (host, port) = match rest.rfind(':') {
        Some(at)
            if !rest[at + 1..].is_empty() && rest[at + 1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            (rest[..at].to_owned(), rest[at + 1..].parse::<u32>().ok())
        }
        _ => (rest.clone(), None),
    };
    // A host is a host: nothing that could carry a path, a credential, a query, a fragment or an
    // escape is one, and an empty answer is what the caller refuses.
    if host.is_empty() || host.contains(['/', '?', '#', '@', '%', '\\', ' ']) || !host.is_ascii() {
        return String::new();
    }
    // A host written as an address is the address, not its spelling: `[0:0:0:0:0:0:0:1]` and
    // `[::1]` are one host, and `127.1` is `127.0.0.1` written short. A second spelling of one
    // address would be a second service to a host that tells calls apart by their provider.
    let host = match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(literal) => match literal.parse::<std::net::Ipv6Addr>() {
            Ok(address) => format!("[{address}]"),
            Err(_) => return String::new(),
        },
        None if host
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.') =>
        {
            match host.parse::<std::net::Ipv4Addr>() {
                Ok(address) => address.to_string(),
                Err(_) => return String::new(),
            }
        }
        None => host,
    };
    let implied = match scheme.as_str() {
        "https://" => Some(443),
        "http://" => Some(80),
        _ => None,
    };
    match port {
        Some(port) if Some(port) != implied => format!("{scheme}{host}:{port}"),
        _ => format!("{scheme}{host}"),
    }
}

#[cfg(test)]
mod origin_tests {
    use super::normalised_origin;

    /// KR-REQ-15.01: two clients of one service are one provider, whatever spelling each was
    /// configured with, and a client of another service is not.
    #[test]
    fn one_service_has_one_identity() {
        let canonical = normalised_origin("https://reach.example");
        for spelling in [
            "https://reach.example",
            "https://reach.example:443",
            "https://reach.example:0443",
            "HTTPS://Reach.Example",
        ] {
            assert_eq!(normalised_origin(spelling), canonical, "{spelling}");
        }
        assert_eq!(
            normalised_origin("http://[0:0:0:0:0:0:0:1]"),
            normalised_origin("http://[::1]")
        );
        assert_eq!(
            normalised_origin("http://127.1"),
            String::new(),
            "an address written short is not the one spelling this host compares"
        );
        assert!(normalised_origin("https://%72each.example").is_empty());
        assert!(normalised_origin("https://user@reach.example").is_empty());
        assert!(normalised_origin("https://reach.example/path").is_empty());
        assert_ne!(
            normalised_origin("https://reach.example"),
            normalised_origin("https://other.example")
        );
        assert_ne!(
            normalised_origin("https://reach.example"),
            normalised_origin("https://reach.example:8443")
        );
    }
}

/// The managed voice broker client.
#[derive(Clone, Debug)]
pub struct ManagedVoiceBroker {
    origin: String,
    http: Arc<dyn ServiceHttp>,
    tokens: Arc<dyn AccountTokenSource>,
}

impl ManagedVoiceBroker {
    /// Builds a client against one origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not an absolute HTTPS or HTTP address without a
    /// trailing slash, because a path built from it would otherwise be addressed somewhere else.
    pub fn new(
        origin: impl Into<String>,
        http: Arc<dyn ServiceHttp>,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> Result<Self> {
        let origin = origin.into();
        if !(origin.starts_with("https://") || origin.starts_with("http://"))
            || origin.ends_with('/')
        {
            return Err(local(
                "a broker origin is an absolute address with no trailing slash",
            ));
        }
        // One service, one spelling. A call identifier means something only to the service that
        // issued it, so a host holding calls from more than one tells them apart by the origin;
        // two spellings of one address would be two services to it and one to everybody else.
        // Rather than guess which spellings mean the same address — a host written as a name, as
        // a shortened address literal or in another script all can — this refuses anything but
        // the one spelling it compares.
        if origin != normalised_origin(&origin) {
            return Err(local(
                "a broker origin is written in lower case, without the port its scheme implies \
                 and with an address literal in its canonical form",
            ));
        }
        if origin
            .split_once("://")
            .is_some_and(|(_, host)| !host.is_ascii())
        {
            return Err(local(
                "a broker origin's host is written in ASCII; an internationalised name is given \
                 in its encoded form",
            ));
        }
        Ok(Self {
            origin,
            http,
            tokens,
        })
    }

    /// The origin this client addresses.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Sends one authorised request and returns what came back.
    async fn exchange(&self, path: &str, body: Vec<u8>) -> Result<ServiceHttpAnswer> {
        let token = self.tokens.token()?;
        // The one place the token is read. It goes into a header value and nowhere else: not into
        // the URL, not into the body, and not into any error this function returns.
        let authorisation = format!("Bearer {}", token.expose());
        let url = format!("{}{path}", self.origin);
        self.http
            .post_json(&url, &body, &[("authorization", authorisation.as_str())])
            .await
    }

    /// Sends one authorised request and returns the `data` of its envelope.
    async fn call(&self, path: &str, body: Vec<u8>) -> Result<serde_json::Value> {
        let answer = self.exchange(path, body).await?;
        data_of(&answer)
    }
}

impl ManagedVoiceService for ManagedVoiceBroker {
    fn provider(&self) -> String {
        // The origin this client reaches, in one spelling. Two clients of the same service are the
        // same provider however each was configured, and a client of another service is not, so
        // the spelling a caller happened to write must not decide whose call is whose.
        normalised_origin(&self.origin)
    }

    fn start<'a>(&'a self, request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            let body = serde_json::to_vec(&request.body()?)
                .map_err(|error| local(&format!("a request could not be written: {error}")))?;
            // Read rather than classified into an error: a creation has three outcomes and two of
            // them arrive as refusals on this wire. Turning an unknown creation into an error here
            // would leave a caller with a failure it might retry.
            let answer = self.exchange(VOICE_SESSIONS_PATH, body).await?;
            Ok(read_start_answer(&answer))
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        Box::pin(async move {
            let data = self
                .call(&voice_close_path(call_id), b"{}".to_vec())
                .await?;
            serde_json::from_value(data).map_err(|error| {
                unreadable(
                    200,
                    &format!("this client cannot read its closure answer: {error}"),
                )
            })
        })
    }
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A voice refusal carries the ordinary service code and the voice reason beside it, and the
/// reason is what a caller acts on: an unknown creation is a state rather than a failure, and an
/// exhausted allowance comes with the paths that still work.
fn data_of(answer: &ServiceHttpAnswer) -> Result<serde_json::Value> {
    #[derive(Deserialize)]
    struct Envelope {
        ok: bool,
        #[serde(default)]
        data: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<Refusal>,
    }

    #[derive(Deserialize)]
    struct Refusal {
        code: String,
        message: String,
        #[serde(default)]
        reason: Option<VoiceRefusalReason>,
    }

    let Ok(envelope) = serde_json::from_slice::<Envelope>(&answer.body) else {
        return Err(unreadable(
            answer.status,
            "its answer is not one this client reads",
        ));
    };

    if envelope.ok {
        return envelope
            .data
            .ok_or_else(|| unreadable(answer.status, "its answer carries no data"));
    }

    let Some(refusal) = envelope.error else {
        return Err(unreadable(answer.status, "its refusal names no error"));
    };

    Err(ClientError::Refused {
        error: ProtocolError::new(
            classify(&refusal.code, refusal.reason, answer.status),
            refusal.message,
        ),
        retry_after_seconds: None,
        action: action_for(refusal.reason),
    })
}

/// Reads one creation answer, whichever of the three things it is.
///
/// The service reports an unknown creation and an unavailable service as refusals with a voice
/// reason, and this is where the reason becomes the state a caller branches on. It is separate
/// from [`ManagedVoiceService::start`] so a caller holding an answer from anywhere — a recorded
/// exchange, a self-hosted broker — reads it the same way.
#[must_use]
pub fn read_start_answer(answer: &ServiceHttpAnswer) -> VoiceStart {
    #[derive(Deserialize)]
    struct Envelope {
        ok: bool,
        #[serde(default)]
        data: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<serde_json::Value>,
    }

    let Ok(envelope) = serde_json::from_slice::<Envelope>(&answer.body) else {
        return refused(
            VoiceRefusalReason::Unrecognised,
            "The managed service answered something this client cannot read.".to_owned(),
        );
    };

    if envelope.ok {
        return match envelope
            .data
            .and_then(|data| serde_json::from_value::<VoiceSession>(data).ok())
        {
            Some(session) => VoiceStart::Started(Box::new(session)),
            None => refused(
                VoiceRefusalReason::Unrecognised,
                "The managed service answered a call this client cannot read.".to_owned(),
            ),
        };
    }

    let error = envelope.error.unwrap_or(serde_json::Value::Null);
    let reason = error
        .get("reason")
        .and_then(|value| serde_json::from_value::<VoiceRefusalReason>(value.clone()).ok())
        .unwrap_or(VoiceRefusalReason::Unrecognised);
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Managed voice could not start this call.")
        .to_owned();
    let attempt_id = error
        .get("attemptId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    if reason == VoiceRefusalReason::CreationUnknown {
        // A state, not an error code. Nothing here retries, and the caller may not either.
        return VoiceStart::CreationUnknown {
            attempt_id,
            message,
        };
    }

    VoiceStart::Refused(Box::new(VoiceRefusal {
        reason,
        message,
        alternatives: error
            .get("alternatives")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        attempt_id,
        call_id: error
            .get("callId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }))
}

fn refused(reason: VoiceRefusalReason, message: String) -> VoiceStart {
    VoiceStart::Refused(Box::new(VoiceRefusal {
        reason,
        message,
        alternatives: Vec::new(),
        attempt_id: None,
        call_id: None,
    }))
}

/// The protocol code one refusal means.
fn classify(code: &str, reason: Option<VoiceRefusalReason>, status: u16) -> ErrorCode {
    match reason {
        Some(VoiceRefusalReason::CreationUnknown) => ErrorCode::OutcomeUnknown,
        Some(VoiceRefusalReason::ServiceCapacity) => ErrorCode::ServiceCapacity,
        Some(VoiceRefusalReason::AccountAllowance) => ErrorCode::QuotaExceeded,
        Some(VoiceRefusalReason::NotConfigured) => ErrorCode::HostNotConfigured,
        Some(VoiceRefusalReason::Unauthorised) => ErrorCode::PermissionDenied,
        Some(VoiceRefusalReason::SessionInProgress) => ErrorCode::SessionLimit,
        Some(VoiceRefusalReason::ProviderRefused | VoiceRefusalReason::ReadinessUnavailable) => {
            ErrorCode::UpstreamUnavailable
        }
        _ => match code {
            "UNAUTHENTICATED" | "FORBIDDEN" => ErrorCode::PermissionDenied,
            "RATE_LIMITED" => ErrorCode::RateLimited,
            "QUOTA_EXHAUSTED" => ErrorCode::QuotaExceeded,
            "NOT_CONFIGURED" => ErrorCode::HostNotConfigured,
            "INTERNAL" => ErrorCode::UpstreamUnavailable,
            _ if status >= 500 => ErrorCode::UpstreamUnavailable,
            _ => ErrorCode::InvalidArgument,
        },
    }
}

/// What a person does about one refusal.
fn action_for(reason: Option<VoiceRefusalReason>) -> UserAction {
    match reason {
        Some(VoiceRefusalReason::Unauthorised) => UserAction::SignIn,
        Some(VoiceRefusalReason::NotConfigured) => UserAction::FixConfiguration,
        Some(VoiceRefusalReason::InvalidRequest) => UserAction::Update,
        _ => UserAction::Wait,
    }
}

/// An answer this client could not read, classified by the status that carried it.
fn unreadable(status: u16, what: &str) -> ClientError {
    let code = if (200..300).contains(&status) {
        ErrorCode::OutcomeUnknown
    } else if status >= 500 || status == 408 || status == 429 {
        ErrorCode::UpstreamUnavailable
    } else {
        ErrorCode::HostNotConfigured
    };
    ClientError::Host(ProtocolError::new(
        code,
        format!("the managed service answered {status} and {what}"),
    ))
}

/// A request this client could not build, which is a local fault rather than an answer.
fn local(message: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::InvalidArgument,
        message.to_owned(),
    ))
}

/* -------------------------------------------------------------------------- */
/* The account token on disk                                                   */
/* -------------------------------------------------------------------------- */

/// The file under the runtime root that holds this host's account token.
pub const ACCOUNT_TOKEN_FILE: &str = "account-token.json";

/// Largest account-token file this host will read.
pub const ACCOUNT_TOKEN_FILE_LIMIT: u64 = 16 * 1024;

/// Returns where the account token lives under a runtime root.
#[must_use]
pub fn account_token_path(runtime_root: &std::path::Path) -> std::path::PathBuf {
    runtime_root.join(ACCOUNT_TOKEN_FILE)
}

/// The account token as it is stored, read and written.
///
/// One definition, used by the command that imports the token and by the host that presents it, so
/// the two cannot disagree about the shape of the file. The token itself is an
/// [`AccountToken`], which means no rendering of this structure contains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountToken {
    /// The managed-service origin the token was issued by and may be presented to.
    pub origin: String,
    /// The token.
    pub access_token: AccountToken,
    /// The scopes it carries. Managed voice needs [`VOICE_SCOPE`].
    pub scopes: Vec<String>,
    /// When it stops being accepted, in UTC milliseconds, or null when the issuer did not say.
    pub expires_at_ms: Option<u64>,
}

/// What the file looks like on disk.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TokenDocument {
    origin: String,
    access_token: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

impl StoredAccountToken {
    /// Reads one from the bytes of a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not this document, when the token could not be a header
    /// value, or when the origin is not an absolute address. No refusal quotes the token.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let document: TokenDocument = serde_json::from_slice(bytes).map_err(|error| {
            // Only the position, never the message: a serde message for a string field can quote
            // what it was reading, and what it was reading may be the token.
            local(&format!(
                "that is not an account token document: it stops making sense at line {}, \
                 column {}",
                error.line(),
                error.column()
            ))
        })?;
        if !(document.origin.starts_with("https://") || document.origin.starts_with("http://"))
            || document.origin.ends_with('/')
        {
            return Err(local(
                "an account token names the origin it belongs to, as an absolute address with no                  trailing slash",
            ));
        }
        Ok(Self {
            origin: document.origin,
            access_token: AccountToken::new(document.access_token)?,
            scopes: document.scopes,
            expires_at_ms: document.expires_at_ms,
        })
    }

    /// The bytes to write.
    ///
    /// # Errors
    ///
    /// Returns an error when the document cannot be written, which would be a fault in this build.
    pub fn write(&self) -> Result<Vec<u8>> {
        let document = TokenDocument {
            origin: self.origin.clone(),
            access_token: self.access_token.expose().to_owned(),
            scopes: self.scopes.clone(),
            expires_at_ms: self.expires_at_ms,
        };
        let mut bytes = serde_json::to_vec_pretty(&document)
            .map_err(|error| local(&format!("the token could not be written: {error}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns true when this token carries `scope`.
    #[must_use]
    pub fn carries(&self, scope: &str) -> bool {
        self.scopes.iter().any(|held| held == scope)
    }

    /// What can be said about the token without saying the token.
    ///
    /// The origin, the scopes and the expiry, which is everything an operator needs to see that
    /// the right thing was imported. The value is not here and cannot be derived from what is.
    #[must_use]
    pub fn description(&self) -> String {
        let scopes = if self.scopes.is_empty() {
            "no scopes".to_owned()
        } else {
            self.scopes.join(", ")
        };
        match self.expires_at_ms {
            Some(expires_at_ms) => format!(
                "an account token for {} carrying {scopes}, until {expires_at_ms} in UTC \
                 milliseconds",
                self.origin
            ),
            None => format!(
                "an account token for {} carrying {scopes}, with no stated expiry",
                self.origin
            ),
        }
    }
}

/// An account token read from the runtime root each time it is needed.
///
/// Read each time rather than held: the operator replaces an expired token by importing a new one,
/// and a host that read the file once at startup would keep presenting the old one until it was
/// restarted.
///
/// The origin is part of it. A token is a bearer credential for one service, so this reader
/// refuses to hand one over for an origin it was not issued for: a configuration that named a
/// different service would otherwise disclose the credential to it.
#[derive(Clone, Debug)]
pub struct AccountTokenFile {
    path: std::path::PathBuf,
    origin: Option<String>,
}

impl AccountTokenFile {
    /// Reads the token from this path, for any origin it names.
    #[must_use]
    pub fn at(path: std::path::PathBuf) -> Self {
        Self { path, origin: None }
    }

    /// Reads the token from the ordinary place under a runtime root.
    #[must_use]
    pub fn under(runtime_root: &std::path::Path) -> Self {
        Self::at(account_token_path(runtime_root))
    }

    /// Binds this reader to one origin, which the stored token has to name.
    #[must_use]
    pub fn for_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// The file this reads.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Reads the stored token.
    ///
    /// # Errors
    ///
    /// Returns an error when no token has been imported, when the file is not one this host wrote,
    /// or when it does not parse. No error carries the token.
    pub fn stored(&self) -> Result<StoredAccountToken> {
        let bytes = kr_ipc::paths::read_owner_only_file(&self.path, ACCOUNT_TOKEN_FILE_LIMIT)
            .map_err(|error| {
                ClientError::Host(ProtocolError::new(
                    ErrorCode::HostNotConfigured,
                    format!("the account token could not be read: {error}"),
                ))
            })?
            .ok_or_else(|| {
                ClientError::Host(ProtocolError::new(
                    ErrorCode::HostNotConfigured,
                    format!(
                        "no account token has been imported. Write one with `kr account token \
                         import <path>`; it is read from {}.",
                        self.path.display()
                    ),
                ))
            })?;
        StoredAccountToken::read(&bytes)
    }
}

impl AccountTokenSource for AccountTokenFile {
    fn token(&self) -> Result<AccountToken> {
        let stored = self.stored()?;
        if let Some(origin) = self.origin.as_deref()
            && stored.origin != origin
        {
            // Refused before the request is built, so the token never reaches a service it was not
            // issued for. The refusal names the origins and never the token.
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::HostNotConfigured,
                format!(
                    "the imported account token belongs to {} and this host is configured to \
                     reach {origin}",
                    stored.origin
                ),
            )));
        }
        if !stored.carries(VOICE_SCOPE) {
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the imported account token was not issued with the scope managed voice needs"
                    .to_owned(),
            )));
        }
        Ok(stored.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_token_never_prints_itself() {
        let token = AccountToken::new("a-secret-value").expect("a token");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("a-secret-value"), "{rendered}");
        assert_eq!(token.expose(), "a-secret-value");
    }

    #[test]
    fn a_token_that_could_not_be_a_header_value_is_refused_without_quoting_it() {
        let error = AccountToken::new("line\nbreak").expect_err("refused");
        assert!(!error.to_string().contains("line"));
        assert!(AccountToken::new("").is_err());
    }

    #[test]
    fn an_unknown_creation_is_a_state_and_never_a_retry() {
        let answer = ServiceHttpAnswer {
            status: 503,
            body: br#"{"ok":false,"error":{"code":"INTERNAL","reason":"creation_unknown",
                "message":"The provider may hold a session for that attempt.",
                "attemptId":"attempt-1"}}"#
                .to_vec(),
        };
        let start = read_start_answer(&answer);
        assert!(matches!(
            &start,
            VoiceStart::CreationUnknown { attempt_id, .. }
                if attempt_id.as_deref() == Some("attempt-1")
        ));
        assert!(
            !start.may_ask_again(),
            "an unknown creation is never retried"
        );
    }

    #[test]
    fn a_capacity_refusal_carries_the_paths_that_still_work() {
        let answer = ServiceHttpAnswer {
            status: 503,
            body: br#"{"ok":false,"error":{"code":"INTERNAL","reason":"service_capacity",
                "message":"Managed capacity is spent.",
                "alternatives":["Use your own provider credential."]}}"#
                .to_vec(),
        };
        let VoiceStart::Refused(refusal) = read_start_answer(&answer) else {
            panic!("a refusal");
        };
        assert_eq!(refusal.reason, VoiceRefusalReason::ServiceCapacity);
        assert_eq!(refusal.alternatives.len(), 1);
    }

    #[test]
    fn a_reason_this_build_does_not_know_is_recorded_rather_than_guessed_at() {
        let answer = ServiceHttpAnswer {
            status: 400,
            body: br#"{"ok":false,"error":{"code":"INVALID_REQUEST","reason":"something_new",
                "message":"A newer service."}}"#
                .to_vec(),
        };
        let VoiceStart::Refused(refusal) = read_start_answer(&answer) else {
            panic!("a refusal");
        };
        assert_eq!(refusal.reason, VoiceRefusalReason::Unrecognised);
    }

    #[test]
    fn an_unknown_control_event_is_recorded_by_type_and_carries_nothing() {
        let value: serde_json::Value = serde_json::from_str(
            r#"{"type":"response.item.create","item":{"role":"user","text":"do it"}}"#,
        )
        .expect("a frame");
        let event = read_control_event(&value).expect("an event");
        assert_eq!(
            event,
            VoiceControlEvent::Unknown {
                frame_type: "response.item.create".to_owned()
            },
            "an unknown event carries none of its payload"
        );
    }

    #[test]
    fn an_admission_says_what_it_does_not_establish() {
        let value: serde_json::Value = serde_json::json!({
            "type": "context_admitted",
            "id": "request-1",
            "note": VOICE_ADMISSION_NOTE,
        });
        let event = read_control_event(&value).expect("an event");
        let VoiceControlEvent::ContextAdmitted { note, .. } = event else {
            panic!("an admission");
        };
        assert!(note.contains("not evidence that a host action ran"));
    }

    #[test]
    fn the_command_vocabulary_is_the_services_six_and_nothing_else() {
        for provider_event in [
            "session.start",
            "session.update",
            "response.item.create",
            "response.create",
            "session.instructions.append",
        ] {
            assert_eq!(
                VoiceCommand::from_wire(provider_event),
                None,
                "{provider_event} resolved to a command"
            );
        }
        assert_eq!(VoiceCommand::ALL.len(), 6);
    }

    #[test]
    fn an_append_is_bounded_and_a_silent_command_carries_no_text() {
        assert!(
            VoiceContextFrame::new("r1", VoiceCommand::Mute, None, Some("hello".to_owned()))
                .is_err()
        );
        assert!(VoiceContextFrame::new("r1", VoiceCommand::Thinking, None, None).is_err());
        let long = "x".repeat(VOICE_CONTEXT_BYTES + 1);
        assert!(VoiceContextFrame::new("r1", VoiceCommand::Commentary, None, Some(long)).is_err());
        let frame =
            VoiceContextFrame::new("r1", VoiceCommand::Commentary, None, Some("ok".to_owned()))
                .expect("a frame");
        assert_eq!(frame.frame_type, "context");
    }

    #[test]
    fn a_call_identifier_is_encoded_before_it_becomes_a_path() {
        assert_eq!(
            voice_close_path("a/../b"),
            "/api/voice/sessions/a%2F..%2Fb/close"
        );
    }

    #[test]
    fn a_stored_token_describes_itself_without_saying_itself() {
        let stored = StoredAccountToken::read(
            br#"{"origin":"https://reach.example","accessToken":"a-secret-value",
                 "scopes":["voice"],"expiresAtMs":1700000000000}"#,
        )
        .expect("a token document");
        assert!(stored.carries(VOICE_SCOPE));
        let described = stored.description();
        assert!(!described.contains("a-secret-value"), "{described}");
        assert!(described.contains("reach.example"));
        assert!(!format!("{stored:?}").contains("a-secret-value"));
    }

    #[test]
    fn a_document_this_host_cannot_read_is_refused_without_quoting_it() {
        for bad in [
            &br#"{"origin":"https://reach.example","accessToken":"a-secret-value"#[..],
            &br#"{"origin":"reach.example","accessToken":"a-secret-value","scopes":[]}"#[..],
            &br#"{"origin":"https://reach.example","accessToken":"","scopes":[]}"#[..],
            &br#"{"origin":"https://reach.example","accessToken":"bad\nvalue","scopes":[]}"#[..],
        ] {
            let error = StoredAccountToken::read(bad).expect_err("refused");
            assert!(!error.to_string().contains("a-secret-value"), "{error}");
        }
    }

    #[test]
    fn a_token_is_not_handed_to_an_origin_it_was_not_issued_for() {
        let directory = std::env::temp_dir().join(format!("kr-token-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory on the internal disk");
        let path = account_token_path(&directory);
        let stored = StoredAccountToken::read(
            br#"{"origin":"https://reach.example","accessToken":"a-secret-value",
                 "scopes":["voice"]}"#,
        )
        .expect("a token document");
        kr_ipc::paths::write_owner_only_file(&path, &stored.write().expect("bytes"))
            .expect("the stored token");

        let error = AccountTokenFile::at(path.clone())
            .for_origin("https://elsewhere.example")
            .token()
            .expect_err("a token is not sent to another service");
        assert!(!error.to_string().contains("a-secret-value"), "{error}");
        assert!(error.to_string().contains("elsewhere.example"));

        assert!(
            AccountTokenFile::at(path.clone())
                .for_origin("https://reach.example")
                .token()
                .is_ok()
        );
        std::fs::remove_file(&path).expect("the stored token is removed");
        std::fs::remove_dir(&directory).expect("the directory is removed");
    }

    #[test]
    fn a_token_round_trips_through_the_file_it_is_written_to() {
        let stored = StoredAccountToken::read(
            br#"{"origin":"https://reach.example","accessToken":"a-secret-value",
                 "scopes":["voice"],"expiresAtMs":1}"#,
        )
        .expect("a token document");
        let bytes = stored.write().expect("bytes");
        assert_eq!(StoredAccountToken::read(&bytes).expect("read back"), stored);
    }

    #[test]
    fn an_origin_that_would_build_the_wrong_address_is_refused() {
        #[derive(Debug)]
        struct NoHttp;
        impl ServiceHttp for NoHttp {
            fn post_json<'a>(
                &'a self,
                _url: &'a str,
                _body: &'a [u8],
                _headers: &'a [(&'a str, &'a str)],
            ) -> ServiceFuture<'a, ServiceHttpAnswer> {
                Box::pin(async { panic!("no request is made") })
            }
        }
        #[derive(Debug)]
        struct NoToken;
        impl AccountTokenSource for NoToken {
            fn token(&self) -> Result<AccountToken> {
                panic!("no token is read")
            }
        }
        assert!(
            ManagedVoiceBroker::new("reach.example", Arc::new(NoHttp), Arc::new(NoToken)).is_err()
        );
        assert!(
            ManagedVoiceBroker::new(
                "https://reach.example/",
                Arc::new(NoHttp),
                Arc::new(NoToken)
            )
            .is_err()
        );
        assert!(
            ManagedVoiceBroker::new("https://reach.example", Arc::new(NoHttp), Arc::new(NoToken))
                .is_ok()
        );
        // One service, one spelling: a host that holds calls from more than one provider tells
        // them apart by the origin, so two spellings of one address must not be configurable.
        for refused in [
            "https://reach.example:443",
            "HTTPS://Reach.Example",
            "https://[0:0:0:0:0:0:0:1]",
            "https://bücher.example",
            "http://127.1",
            "https://%72each.example",
            "https://user@reach.example",
        ] {
            assert!(
                ManagedVoiceBroker::new(refused, Arc::new(NoHttp), Arc::new(NoToken)).is_err(),
                "{refused}"
            );
        }
    }
}
