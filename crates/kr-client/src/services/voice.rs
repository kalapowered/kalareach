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
//! * the broker could not tell whether the provider created a session, or a gateway in front of the
//!   broker lost the broker's answer ([`VoiceStart::CreationUnknown`]). Section 15 ¶4 and the
//!   frozen provider profile both say the same thing about it: **nothing retries it
//!   automatically**, no SDP answer exists for that attempt, and the reservation is reconciled by
//!   the service. It is a state, not an error code;
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

use kr_protocol::error::ErrorCode;
use serde::{Deserialize, Serialize};

use super::ServiceFuture;
use super::account::{AccountToken, AccountTokenSource, known_scope, scope_summary};
pub use super::{ServiceHttp, ServiceHttpAnswer};
use crate::error::{ClientError, Result};
use crate::retry::UserAction;
use crate::shown::{ServiceMessage, Shown};

/// The scope an account token needs before it can start or control a managed call.
///
/// Authenticating an account is not the same as being entitled to spend its balance, so the scope
/// names the resource. The service refuses a token without it and says so.
pub const VOICE_SCOPE: &str = "voice";

/// Where brokered session creation answers.
pub const VOICE_SESSIONS_PATH: &str = "/api/voice/sessions";

/// Where the service answers what a call started now would be, before one exists.
///
/// The one voice route that creates nothing: no provider session, no reservation and no call
/// record. A host reads it so a person is shown the model, the disclosure and the rate before they
/// decide whether to speak at all.
pub const VOICE_METADATA_PATH: &str = "/api/voice/metadata";

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

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// What a caller asks for when it starts a managed call.
#[derive(Clone, PartialEq, Eq)]
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
    /// The version of the rate the person was shown, as the metadata read answered it.
    ///
    /// The service starts a call only under the rate its request names, and answers a version that
    /// is no longer current with the rate as it is now ([`VoiceStart::RateChanged`]). A request
    /// that names none is refused here, before it is sent.
    pub expected_rate_version: Option<String>,
}

impl fmt::Debug for VoiceSessionRequest {
    /// What was asked for, and not the offer: a session description carries the connection's ICE
    /// credentials, so it is one of the values this module never renders.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VoiceSessionRequest")
            .field("duration_seconds", &self.duration_seconds)
            .field(
                "expected_rate_version",
                &self.expected_rate_version.as_ref().map(|_| "<present>"),
            )
            .field("offer_sdp_bytes", &self.offer_sdp.len())
            .finish_non_exhaustive()
    }
}

/// The body of a creation request, in the spelling the service reads.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreationBody {
    offer_sdp: String,
    host_id: String,
    duration_seconds: u32,
    expected_rate_version: String,
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
        // A start is accepted only under the rate it names. Sending one that names none would
        // spend a request on a refusal, and choosing a version here on the person's behalf would
        // accept terms they were never shown.
        let Some(expected_rate_version) = self
            .expected_rate_version
            .clone()
            .filter(|version| !version.is_empty())
        else {
            return Err(local(
                "a managed call names the version of the rate the person was shown, as the \
                 metadata read answered it",
            ));
        };
        Ok(CreationBody {
            offer_sdp: self.offer_sdp.clone(),
            host_id: self.host_id.clone(),
            duration_seconds: self.duration_seconds,
            expected_rate_version,
            reasoning_budget: self.reasoning_budget_minor.map(|minor| minor.to_string()),
            device_id: self.device_id.clone(),
        })
    }
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// A reservation as the caller needs to see it: what is held and until when.
#[derive(Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

crate::debug_fields!(VoiceRateQuote { minimum_seconds });

impl VoiceRateQuote {
    /// Minor units per second as a number, when the service wrote one this client can read.
    ///
    /// The service writes every amount as a decimal string of whole minor units. Anything else —
    /// a sign, a fraction, an exponent, digits past what fits — is not a quote this client can
    /// show a person, and a quote a person cannot be shown is one nobody accepted.
    #[must_use]
    pub fn amount_per_second(&self) -> Option<u64> {
        let digits = self.minor_units_per_second.as_str();
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse::<u64>().ok()
    }

    /// Returns true when every figure is one a person can be shown.
    #[must_use]
    pub fn readable(&self) -> bool {
        !self.version.is_empty() && !self.currency.is_empty() && self.amount_per_second().is_some()
    }
}

/// What the service answers about a call started now, before one exists.
///
/// Every value is the deployment's own configuration or a constant of its contract, and nothing in
/// it is about the caller. The wordings are the deployment's own, and a host carries them to a
/// person unchanged rather than keeping a second copy that could drift from them.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceMetadata {
    /// Whether an operator has managed voice open. False is the circuit breaker: a call started
    /// now would be refused, and [`Self::alternatives`] is what still works.
    pub enabled: bool,
    /// The model a call started now would be asked for.
    pub model: String,
    /// What the provider and the service can see.
    pub disclosure: Vec<String>,
    /// What an append acknowledgement does not establish.
    pub admission_note: String,
    /// What a provider delegation identifier is.
    pub delegation_note: String,
    /// Paths that cost no managed credit.
    pub alternatives: Vec<String>,
    /// The rate a call started now would be quoted under.
    pub rate: VoiceRateQuote,
    /// The longest call the deployment authorises, in seconds.
    pub maximum_session_seconds: u32,
    /// The shortest call a caller may ask for, in seconds.
    pub minimum_request_seconds: u32,
    /// Seconds between heartbeats on the control socket.
    pub heartbeat_seconds: u32,
    /// The largest context append the service carries, in UTF-8 bytes.
    pub context_bytes: u32,
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
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

impl fmt::Debug for VoiceSession {
    /// Which call is running and until when, and not the answer: a session description carries the
    /// connection's ICE credentials.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VoiceSession")
            .field("answer_sdp_bytes", &self.answer_sdp.len())
            .field("replayed", &self.replayed)
            .finish_non_exhaustive()
    }
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
    /// The rate the start would run under is not the version the request named.
    ///
    /// Nothing was recorded, held or charged. [`VoiceStart::RateChanged`] carries the quote as it
    /// is now.
    RateChanged,
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
            Self::RateChanged => "rate_changed",
            Self::ProviderRefused => "provider_refused",
            Self::AttemptReconciled => "attempt_reconciled",
            Self::CreationUnknown => "creation_unknown",
            Self::ReadinessUnavailable => "readiness_unavailable",
            Self::NotConfigured => "not_configured",
            Self::Unrecognised => "unrecognised",
        }
    }
}

impl crate::shown::Said for VoiceRefusalReason {
    fn said(&self) -> crate::shown::Shown {
        crate::shown::Shown::said(self.as_str())
    }
}

crate::display_as_said!(VoiceRefusalReason);

/// A refusal, as this client reports it.
#[derive(Clone, PartialEq, Eq)]
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

crate::debug_fields!(VoiceRefusal { reason });

/// What a creation request was answered with.
#[derive(Clone, PartialEq, Eq)]
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
    /// The rate the request named is no longer the one the service would charge.
    ///
    /// Nothing was recorded, held or charged. `rate` is the quote as it is now: a caller shows it
    /// to the person, and a request naming its version is that person's decision to make.
    RateChanged {
        /// The rate as the service quotes it now.
        rate: VoiceRateQuote,
        /// What a person is told.
        message: String,
        /// The running call whose own rate this is, when the same offer was presented again for
        /// a call that already exists.
        call_id: Option<String>,
    },
    /// The service refused, and what still works.
    Refused(Box<VoiceRefusal>),
}

impl fmt::Debug for VoiceStart {
    /// Which answer it is, and the session or the refusal as their own renderings give them. Never
    /// an identifier or a message, which are the service's text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started(session) => formatter.debug_tuple("Started").field(session).finish(),
            Self::CreationUnknown { .. } => formatter
                .debug_struct("CreationUnknown")
                .finish_non_exhaustive(),
            Self::RateChanged { rate, .. } => formatter
                .debug_struct("RateChanged")
                .field("rate", rate)
                .finish_non_exhaustive(),
            Self::Refused(refusal) => formatter.debug_tuple("Refused").field(refusal).finish(),
        }
    }
}

impl VoiceStart {
    /// The running call, when there is one.
    #[must_use]
    pub fn session(&self) -> Option<&VoiceSession> {
        match self {
            Self::Started(session) => Some(session),
            Self::CreationUnknown { .. } | Self::RateChanged { .. } | Self::Refused(_) => None,
        }
    }

    /// Returns true when asking again with the same offer is safe.
    ///
    /// Only a refusal the service decided before it asked the provider. An unknown creation is
    /// never one of them, which is the whole point of the state. Nor is a changed rate: the same
    /// request is refused again, and one naming the new rate accepts terms, which only the person
    /// shown them can do.
    #[must_use]
    pub fn may_ask_again(&self) -> bool {
        match self {
            Self::Started(_) | Self::CreationUnknown { .. } | Self::RateChanged { .. } => false,
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
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

impl crate::shown::Said for VoiceCommand {
    fn said(&self) -> crate::shown::Shown {
        crate::shown::Shown::said(self.as_str())
    }
}

crate::display_as_said!(VoiceCommand);

/// One bounded context request, as it travels on the control socket.
#[derive(Clone, PartialEq, Eq, Serialize)]
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

impl fmt::Debug for VoiceContextFrame {
    /// Which request and which command, and never the text: what a person said to a call is the
    /// content of the request and not a fact about it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VoiceContextFrame")
            .field("command", &self.command)
            .field(
                "delegation",
                &self.delegation_id.as_ref().map(|_| "<present>"),
            )
            .field(
                "content_bytes",
                &self.content.as_ref().map_or(0, String::len),
            )
            .finish_non_exhaustive()
    }
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
#[derive(Clone, PartialEq, Eq)]
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
    /// for that, and `note` is the service's own sentence saying so.
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

impl fmt::Debug for VoiceControlEvent {
    /// Which event it is and its numbers. Never an identifier, a reason, a note or a message,
    /// which are the service's or the provider's text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready { delegations, .. } => formatter
                .debug_struct("Ready")
                .field("delegations", &delegations.len())
                .finish_non_exhaustive(),
            Self::HeartbeatAcknowledged { remaining_seconds } => formatter
                .debug_struct("HeartbeatAcknowledged")
                .field("remaining_seconds", remaining_seconds)
                .finish(),
            Self::ContextAccepted { .. } => formatter
                .debug_struct("ContextAccepted")
                .finish_non_exhaustive(),
            Self::ContextAdmitted { .. } => formatter
                .debug_struct("ContextAdmitted")
                .finish_non_exhaustive(),
            Self::ContextRefused { .. } => formatter
                .debug_struct("ContextRefused")
                .finish_non_exhaustive(),
            Self::Usage {
                seconds,
                provisional,
            } => formatter
                .debug_struct("Usage")
                .field("seconds", seconds)
                .field("provisional", provisional)
                .finish(),
            Self::Closed {
                seconds,
                provisional,
                ..
            } => formatter
                .debug_struct("Closed")
                .field("seconds", seconds)
                .field("provisional", provisional)
                .finish_non_exhaustive(),
            Self::Notice { .. } => formatter.debug_struct("Notice").finish_non_exhaustive(),
            Self::Delegation { offset_ms, .. } => formatter
                .debug_struct("Delegation")
                .field("offset_ms", offset_ms)
                .finish_non_exhaustive(),
            Self::Unknown { .. } => formatter.debug_struct("Unknown").finish_non_exhaustive(),
        }
    }
}

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
    /// What a call started now would be: the model, the disclosure, the rate and the limits.
    ///
    /// Reading it creates nothing and holds nothing. `None` is a provider that is not the managed
    /// service: it publishes no managed terms, and a person is quoted no managed rate for it.
    ///
    /// # Errors
    ///
    /// Returns a transport or protocol error, or the service's refusal, and an answer whose rate
    /// this client could not show a person.
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>>;

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
    // A host is letters, digits, hyphens and dots, or an address literal in brackets. Anything
    // else — an escape, a credential, a path, a space, a tab, another script — is not the spelling
    // this host compares, and an empty answer is what the caller refuses.
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.is_empty()
        || (!bracketed
            && !host.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '-'
                    || character == '.'
            }))
    {
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
        // A host that looks like an address is an address, and an address has one spelling here
        // or none: four decimal parts. Anything else that is only digits, dots and the letters an
        // address can be written with is the same address written another way, and a second
        // spelling would be a second service to a host that tells calls apart by their provider.
        None if host.chars().all(|character| {
            character.is_ascii_hexdigit() || character == '.' || character == 'x'
        }) && host.chars().any(|character| character.is_ascii_digit()) =>
        {
            match host.parse::<std::net::Ipv4Addr>() {
                Ok(address) if address.to_string() == host => host,
                _ => return String::new(),
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
        assert!(normalised_origin("http://0x7f.0.0.1").is_empty());
        assert!(normalised_origin("http://0x7f000001").is_empty());
        assert!(normalised_origin("https://reach.\texample").is_empty());
        assert_eq!(
            normalised_origin("http://127.0.0.1"),
            "http://127.0.0.1".to_owned()
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
#[derive(Clone)]
pub struct ManagedVoiceBroker {
    origin: String,
    http: Arc<dyn ServiceHttp>,
    tokens: Arc<dyn AccountTokenSource>,
}

impl fmt::Debug for ManagedVoiceBroker {
    /// The origin as a diagnostic names one: an address may carry a user name and a password in
    /// front of its host.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedVoiceBroker")
            .field("origin", &Shown::address(&self.origin))
            .finish_non_exhaustive()
    }
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
        let token = self.tokens.token(VOICE_SCOPE).await?;
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
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        Box::pin(async move {
            // An empty object. The service refuses any member, because a member it ignored would
            // leave a caller believing it had asked for something.
            let data = self.call(VOICE_METADATA_PATH, b"{}".to_vec()).await?;
            read_metadata(data).map(Some)
        })
    }

    fn provider(&self) -> String {
        // The origin this client reaches, in one spelling. Two clients of the same service are the
        // same provider however each was configured, and a client of another service is not, so
        // the spelling a caller happened to write must not decide whose call is whose.
        normalised_origin(&self.origin)
    }

    fn start<'a>(&'a self, request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            let body = serde_json::to_vec(&request.body()?).map_err(|error| {
                local(crate::shown!(
                    "a request could not be written: {}",
                    Shown::json(&error)
                ))
            })?;
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
                    crate::shown!(
                        "this client cannot read its closure answer: {}",
                        Shown::json(&error)
                    ),
                )
            })
        })
    }
}

/// A start whose answer a gateway lost: the call may have started, so it is an unknown creation.
fn lost_start() -> VoiceStart {
    VoiceStart::CreationUnknown {
        attempt_id: None,
        message: "The answer to this start was lost on its way back, so the call may have started."
            .to_owned(),
    }
}

/// Reads the service's terms, and refuses a rate this client could not show a person.
///
/// A start names the version of the rate a person was shown, so a quote that cannot be shown is
/// one that could never be accepted: carrying it on would put a Start in front of somebody with
/// nothing to agree to.
fn read_metadata(data: serde_json::Value) -> Result<VoiceMetadata> {
    let metadata: VoiceMetadata = serde_json::from_value(data).map_err(|error| {
        unreadable(
            200,
            crate::shown!("this client cannot read its terms: {}", Shown::json(&error)),
        )
    })?;
    if !metadata.rate.readable() {
        return Err(unreadable(
            200,
            "its terms quote a rate this client cannot show",
        ));
    }
    Ok(metadata)
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A voice refusal carries the ordinary service code and the voice reason beside it, and the
/// reason is what a caller acts on: an unknown creation is a state rather than a failure, and an
/// exhausted allowance comes with the paths that still work. A text that names one member twice
/// anywhere is neither an answer nor a refusal ([`super::json::read`]).
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

    let envelope = super::json::read::<Envelope>(&answer.body).map_err(|fault| {
        unreadable(
            answer.status,
            crate::shown!("its answer is not one this client reads: {}", fault),
        )
    })?;

    if envelope.ok {
        return envelope
            .data
            .ok_or_else(|| unreadable(answer.status, "its answer carries no data"));
    }

    let Some(refusal) = envelope.error else {
        return Err(unreadable(answer.status, "its refusal names no error"));
    };

    Err(ClientError::Refused {
        error: crate::error::refusal(
            classify(&refusal.code, refusal.reason, answer.status),
            Shown::service(&ServiceMessage::from_refusal(refusal.message)),
        ),
        retry_after_seconds: None,
        action: action_for(refusal.reason),
    })
}

/// Reads one creation answer, whichever of the three things it is.
///
/// The service reports an unknown creation and an unavailable service as refusals with a voice
/// reason, and this is where the reason becomes the state a caller branches on. It is separate
/// from [`ManagedVoiceService::start`] so a caller holding an answer from anywhere, a recorded
/// exchange or a self-hosted broker, reads it the same way.
///
/// An answer this client cannot read is a refusal for a reason it does not know, which nothing
/// asks again for. A text that names one member twice anywhere is one of those
/// ([`super::json::read`]): which call is running, or why none is, would depend on the reader.
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

    let Ok(envelope) = super::json::read::<Envelope>(&answer.body) else {
        // A gateway in front of the service answers 502 or 504 when the service's answer did not
        // reach it, which it can say after the service started the call.
        if matches!(answer.status, 502 | 504) {
            return lost_start();
        }
        return refused(
            VoiceRefusalReason::Unrecognised,
            "The managed service answered something this client cannot read.".to_owned(),
        );
    };

    // The service's own refusal names its code. An envelope without one, on the statuses a gateway
    // gives when the service's answer did not reach it, is not the service's answer.
    let refusal_named = !envelope.ok
        && envelope
            .error
            .as_ref()
            .and_then(|error| error.get("code"))
            .is_some_and(serde_json::Value::is_string);
    if matches!(answer.status, 502 | 504) && !refusal_named {
        return lost_start();
    }

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
    let call_id = error
        .get("callId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    if reason == VoiceRefusalReason::CreationUnknown {
        // A state, not an error code. Nothing here retries, and the caller may not either.
        return VoiceStart::CreationUnknown {
            attempt_id,
            message,
        };
    }

    if reason == VoiceRefusalReason::RateChanged {
        // The quote as it is now, which is what a person is shown before they decide again.
        // Without a readable one this stays an ordinary refusal: a rate nobody can be shown is
        // not one anybody can accept.
        if let Some(rate) = error
            .get("rate")
            .and_then(|value| serde_json::from_value::<VoiceRateQuote>(value.clone()).ok())
            .filter(VoiceRateQuote::readable)
        {
            return VoiceStart::RateChanged {
                rate,
                message,
                call_id,
            };
        }
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
        call_id,
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
fn unreadable(status: u16, what: impl Into<Shown>) -> ClientError {
    let code = if (200..300).contains(&status) {
        ErrorCode::OutcomeUnknown
    } else if status >= 500 || status == 408 || status == 429 {
        ErrorCode::UpstreamUnavailable
    } else {
        ErrorCode::HostNotConfigured
    };
    ClientError::refusal(
        code,
        crate::shown!(
            "the managed service answered {} and {}",
            status,
            what.into()
        ),
    )
}

/// A request this client could not build, which is a local fault rather than an answer.
fn local(message: impl Into<Shown>) -> ClientError {
    ClientError::refusal(ErrorCode::InvalidArgument, message.into())
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
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for StoredAccountToken {
    /// The origin without anything in front of the host, the scopes and the expiry.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scopes: Shown = scope_summary(&self.scopes);
        formatter
            .debug_struct("StoredAccountToken")
            .field("origin", &Shown::address(&self.origin))
            .field("scopes", &scopes)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
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
            local(crate::shown!(
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
                "an account token names the origin it belongs to, as an absolute address with no \
                 trailing slash",
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
        let mut bytes = serde_json::to_vec_pretty(&document).map_err(|error| {
            local(crate::shown!(
                "the token could not be written: {}",
                Shown::json(&error)
            ))
        })?;
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
    pub fn description(&self) -> Shown {
        // The origin as a rendering names one, and the scopes as this build knows them. A
        // description is written to be shown, an address may carry a user name and a password in
        // front of the host, and a scope is whatever the file said.
        match self.expires_at_ms {
            Some(expires_at_ms) => crate::shown!(
                "an account token for {} carrying {}, until {} in UTC milliseconds",
                Shown::address(&self.origin),
                scope_summary(&self.scopes),
                expires_at_ms
            ),
            None => crate::shown!(
                "an account token for {} carrying {}, with no stated expiry",
                Shown::address(&self.origin),
                scope_summary(&self.scopes)
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
#[derive(Clone)]
pub struct AccountTokenFile {
    path: std::path::PathBuf,
    origin: Option<String>,
}

impl fmt::Debug for AccountTokenFile {
    /// Where the token is read from, and the origin without anything in front of its host.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountTokenFile")
            .field("path", &Shown::host_path(&self.path))
            .field("origin", &self.origin.as_deref().map(Shown::address))
            .finish()
    }
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
                ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    crate::shown!(
                        "the account token could not be read: {}",
                        Shown::ipc(&error)
                    ),
                )
            })?
            .ok_or_else(|| {
                ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    crate::shown!(
                        "no account token has been imported. Write one with `kr account token \
                         import <path>`; it is read from {}.",
                        Shown::root(&self.path)
                    ),
                )
            })?;
        StoredAccountToken::read(&bytes)
    }
}

impl AccountTokenSource for AccountTokenFile {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            let stored = self.stored()?;
            if let Some(origin) = self.origin.as_deref()
                && stored.origin != origin
            {
                // Refused before the request is built, so the token never reaches a service it was
                // not issued for. Both origins are named the way a rendering names one: an address
                // may carry a user name and a password in front of the host, and the token is not
                // the only credential this refusal could otherwise print.
                return Err(ClientError::refusal(
                    ErrorCode::HostNotConfigured,
                    crate::shown!(
                        "the imported account token belongs to {} and this host is configured to \
                         reach {}",
                        Shown::address(&stored.origin),
                        Shown::address(origin)
                    ),
                ));
            }
            if !stored.carries(scope) {
                return Err(ClientError::refusal(
                    ErrorCode::PermissionDenied,
                    match known_scope(scope) {
                        Some(name) => crate::shown!(
                            "the imported account token was not issued with the {} scope",
                            name
                        ),
                        None => Shown::said(
                            "the imported account token was not issued with a scope this build \
                             does not know",
                        ),
                    },
                ));
            }
            Ok(stored.access_token)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendering_of_a_call_carries_neither_its_offer_its_answer_nor_what_was_said() {
        use crate::services::rendering::{NEVER_RENDERED, renders_only};

        // A session description carries the connection's ICE credentials, and what a person said
        // to a call is the content of the request. Neither is a fact about the call.
        let offer = format!("v=0\r\na=ice-pwd:{NEVER_RENDERED}\r\n");
        let request = VoiceSessionRequest {
            offer_sdp: offer.clone(),
            host_id: "33333333-3333-3333-3333-333333333333".to_owned(),
            duration_seconds: 300,
            reasoning_budget_minor: Some(500),
            device_id: Some("44444444-4444-4444-4444-444444444444".to_owned()),
            expected_rate_version: Some("2026-09-a".to_owned()),
        };
        renders_only(
            &request,
            &format!(
                r#"VoiceSessionRequest{{duration_seconds:300,expected_rate_version:Some("<present>"),offer_sdp_bytes:{},..}}"#,
                offer.len()
            ),
        );

        let answer_sdp = format!("v=0\r\na=ice-pwd:{NEVER_RENDERED}\r\n");
        let session: VoiceSession = serde_json::from_value(serde_json::json!({
            "callId": "call-1",
            "attemptId": "attempt-1",
            "providerSessionId": "provider-1",
            "answerSdp": answer_sdp,
            "model": "a-model",
            "closesAt": "2026-09-21T10:00:00Z",
            "reservationEndsAt": "2026-09-21T10:05:00Z",
            "controlPath": "/api/voice/control",
            "heartbeatSeconds": 10,
            "sidebandReady": true,
            "hold": {
                "reservationId": "res-1", "reserved": "300", "ceiling": "500",
                "deadline": "2026-09-21T10:05:00Z"
            },
            "reasoningHold": serde_json::Value::Null,
            "rate": {
                "version": "1", "minorUnitsPerSecond": "2", "minimumSeconds": 60, "currency": "USD"
            },
            "latency": { "creationToAnswerMs": 120, "sidebandReadyMs": 40 },
            "replayed": false,
            "disclosure": []
        }))
        .expect("a session");
        renders_only(
            &session,
            &format!(
                r#"VoiceSession{{answer_sdp_bytes:{},replayed:false,..}}"#,
                answer_sdp.len()
            ),
        );

        // And the answer that carries the session renders through it rather than round it.
        let started = VoiceStart::Started(Box::new(session));
        assert!(!format!("{started:?}").contains(NEVER_RENDERED));
        assert!(!format!("{started:#?}").contains(NEVER_RENDERED));

        let frame = VoiceContextFrame::new(
            "request-1",
            VoiceCommand::Instructions,
            None,
            Some(NEVER_RENDERED.to_owned()),
        )
        .expect("a context request");
        renders_only(
            &frame,
            &format!(
                r#"VoiceContextFrame{{command:Instructions,delegation:None,content_bytes:{},..}}"#,
                NEVER_RENDERED.len()
            ),
        );
    }

    #[test]
    fn an_address_that_hides_a_credential_in_front_of_its_host_is_not_printed() {
        const HIDDEN: &str = "a-marker-nobody-should-see";

        for address in [
            format!("https://someone:{HIDDEN}@reach.kala.to"),
            format!("https://{HIDDEN}@reach.kala.to"),
            format!("https://someone:{}@reach.kala.to", "a%2Dmarker"),
            format!("https://reach.kala.to/?token={HIDDEN}"),
            format!("not an address at all {HIDDEN}"),
        ] {
            let stored = StoredAccountToken {
                origin: address.clone(),
                access_token: AccountToken::new("a-token").expect("a token"),
                scopes: vec![VOICE_SCOPE.to_owned()],
                expires_at_ms: None,
            };
            let reader = AccountTokenFile::at(std::path::PathBuf::from("/tmp/a-token.json"))
                .for_origin(address.clone());

            for rendering in [
                format!("{stored:?}"),
                format!("{stored:#?}"),
                format!("{reader:?}"),
                format!("{reader:#?}"),
            ] {
                assert!(!rendering.contains(HIDDEN), "{address}: {rendering}");
                assert!(!rendering.contains("a%2Dmarker"), "{address}: {rendering}");
                assert!(!rendering.contains("someone"), "{address}: {rendering}");
            }
        }

        // An ordinary origin is still readable, because a rendering that said nothing would be a
        // rendering nobody could use.
        let stored = StoredAccountToken {
            origin: "https://reach.kala.to".to_owned(),
            access_token: AccountToken::new("a-token").expect("a token"),
            scopes: vec![VOICE_SCOPE.to_owned()],
            expires_at_ms: Some(1_800_000_000_000),
        };
        assert!(format!("{stored:?}").contains("https://reach.kala.to"));
        assert!(!format!("{stored:?}").contains("a-token"));
    }

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

    /// KR-REQ-23.57: a gateway's 502 or 504 with no envelope of the service's can follow the
    /// service starting the call, so the start is an unknown creation, never a refusal a person
    /// could take for nothing having started. The controls: the service's own refusal on a 502 is
    /// read as the service said, and the terms and a closure, which are safe to ask for again,
    /// stay transient on a 503 and on a gateway's 502 or 504 alike.
    #[test]
    fn kr_req_23_57_a_gateway_that_lost_a_starts_answer_leaves_the_creation_unknown() {
        for status in [502, 504] {
            for body in [
                &b"<html><body>Bad Gateway</body></html>"[..],
                &b""[..],
                &br#"{"message":"The upstream did not answer."}"#[..],
                // An envelope with no refusal of the service's in it is not the service's answer.
                &br#"{"ok":false}"#[..],
                &br#"{"ok":false,"error":{"message":"No code."}}"#[..],
                &br#"{"ok":true}"#[..],
            ] {
                let start = read_start_answer(&ServiceHttpAnswer {
                    status,
                    body: body.to_vec(),
                });
                assert!(
                    matches!(
                        start,
                        VoiceStart::CreationUnknown {
                            attempt_id: None,
                            ..
                        }
                    ),
                    "{status}: {start:?}"
                );
                assert!(!start.may_ask_again());
            }
        }

        // The service's own refusal on a 502 is read as the service's.
        let start = read_start_answer(&ServiceHttpAnswer {
            status: 502,
            body: br#"{"ok":false,"error":{"code":"INTERNAL","reason":"provider_refused",
                "message":"The provider refused the call."}}"#
                .to_vec(),
        });
        let VoiceStart::Refused(refusal) = &start else {
            panic!("the service's refusal: {start:?}");
        };
        assert_eq!(refusal.reason, VoiceRefusalReason::ProviderRefused);

        // The terms and a closure are safe to ask for again, whoever gave up.
        for status in [502, 503, 504] {
            let error = data_of(&ServiceHttpAnswer {
                status,
                body: b"<html><body>Unavailable</body></html>".to_vec(),
            })
            .expect_err("no envelope");
            assert_eq!(error.code(), ErrorCode::UpstreamUnavailable, "{status}");
        }
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

    /// A session as the service answers a start with it, in the text it arrives as.
    fn session_answer() -> String {
        serde_json::json!({
            "ok": true,
            "data": {
                "callId": "call-1",
                "attemptId": "attempt-1",
                "providerSessionId": "provider-1",
                "answerSdp": "v=0\r\n",
                "model": "a-model",
                "closesAt": "2026-09-21T10:00:00Z",
                "reservationEndsAt": "2026-09-21T10:05:00Z",
                "controlPath": "/api/voice/control",
                "heartbeatSeconds": 10,
                "sidebandReady": true,
                "hold": {
                    "reservationId": "res-1", "reserved": "300", "ceiling": "500",
                    "deadline": "2026-09-21T10:05:00Z"
                },
                "reasoningHold": serde_json::Value::Null,
                "rate": {
                    "version": "1", "minorUnitsPerSecond": "2", "minimumSeconds": 60,
                    "currency": "USD"
                },
                "latency": { "creationToAnswerMs": 120, "sidebandReadyMs": 40 },
                "replayed": false,
                "disclosure": []
            }
        })
        .to_string()
    }

    /// KR-REQ-04.19: a session answer that names one member twice is not a call this client
    /// reads. Which call is running would depend on the reader, so no call is running here, and
    /// nothing asks again with the same offer.
    #[test]
    fn a_session_answer_that_names_a_member_twice_is_not_a_call_this_client_reads() {
        let answer = session_answer();
        let repeated = answer.replacen(
            r#""callId":"call-1""#,
            r#""callId":"call-1","callId":"call-2""#,
            1,
        );
        assert_ne!(
            repeated, answer,
            "the session names its call once to begin with"
        );
        let start = read_start_answer(&ServiceHttpAnswer {
            status: 200,
            body: repeated.into_bytes(),
        });
        let VoiceStart::Refused(refusal) = &start else {
            panic!("not a call this client reads: {start:?}");
        };
        assert_eq!(refusal.reason, VoiceRefusalReason::Unrecognised);
        assert!(!start.may_ask_again());

        // The control: the same answer naming it once is the call.
        let start = read_start_answer(&ServiceHttpAnswer {
            status: 200,
            body: answer.into_bytes(),
        });
        assert_eq!(
            start.session().map(|session| session.call_id.as_str()),
            Some("call-1")
        );
    }

    /// KR-REQ-04.19: a refusal that names its reason twice is not a refusal this client reads. One
    /// reader would say the capacity is spent and asking again later is safe, another that a call
    /// may exist and must never be asked for again, and the service said neither once.
    #[test]
    fn a_refusal_that_names_its_reason_twice_is_not_one_this_client_reads() {
        let refusal = |reasons: &str| {
            ServiceHttpAnswer {
            status: 503,
            body: format!(
                r#"{{"ok":false,"error":{{"code":"INTERNAL",{reasons},"message":"Not now.","attemptId":"attempt-1"}}}}"#
            )
            .into_bytes(),
        }
        };
        let start = read_start_answer(&refusal(
            r#""reason":"service_capacity","reason":"creation_unknown""#,
        ));
        let VoiceStart::Refused(refused) = &start else {
            panic!("not a refusal this client reads: {start:?}");
        };
        assert_eq!(refused.reason, VoiceRefusalReason::Unrecognised);
        assert!(!start.may_ask_again());

        // The controls: each reason named once is read as itself.
        let VoiceStart::Refused(capacity) =
            read_start_answer(&refusal(r#""reason":"service_capacity""#))
        else {
            panic!("a capacity refusal");
        };
        assert_eq!(capacity.reason, VoiceRefusalReason::ServiceCapacity);
        assert!(matches!(
            read_start_answer(&refusal(r#""reason":"creation_unknown""#)),
            VoiceStart::CreationUnknown { .. }
        ));
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
            "note": "The model received this context. It is not evidence that a host action ran \
                     or that audio was played; host action receipts are the authority for that.",
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
        let described = stored.description().into_string();
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

    #[tokio::test]
    async fn a_token_is_not_handed_to_an_origin_it_was_not_issued_for() {
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
            .token(VOICE_SCOPE)
            .await
            .expect_err("a token is not sent to another service");
        assert!(!error.to_string().contains("a-secret-value"), "{error}");
        assert!(error.to_string().contains("elsewhere.example"));

        // An address may carry a user name and a password in front of the host, so the refusal
        // names both origins the way a rendering names one.
        use crate::services::rendering::NEVER_RENDERED;

        let credentialled = StoredAccountToken::read(
            format!(
                r#"{{"origin":"https://{NEVER_RENDERED}:{NEVER_RENDERED}@reach.example",
                     "accessToken":"a-secret-value","scopes":["voice"]}}"#
            )
            .as_bytes(),
        )
        .expect("a token document");
        kr_ipc::paths::write_owner_only_file(&path, &credentialled.write().expect("bytes"))
            .expect("the stored token");
        let error = AccountTokenFile::at(path.clone())
            .for_origin(format!("https://{NEVER_RENDERED}@elsewhere.example"))
            .token(VOICE_SCOPE)
            .await
            .expect_err("a token is not sent to another service");
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }

        kr_ipc::paths::write_owner_only_file(&path, &stored.write().expect("bytes"))
            .expect("the stored token");
        assert!(
            AccountTokenFile::at(path.clone())
                .for_origin("https://reach.example")
                .token(VOICE_SCOPE)
                .await
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

    /// A service that answers from a script and records what it was sent.
    #[derive(Debug, Default)]
    struct Scripted {
        answers: std::sync::Mutex<std::collections::VecDeque<ServiceHttpAnswer>>,
        sent: std::sync::Mutex<Vec<Sent>>,
    }

    /// One request as the service received it.
    #[derive(Clone, Debug)]
    struct Sent {
        url: String,
        body: serde_json::Value,
        authorisation: Option<String>,
    }

    impl Scripted {
        fn answering(answers: impl IntoIterator<Item = (u16, serde_json::Value)>) -> Arc<Self> {
            let scripted = Self::default();
            for (status, body) in answers {
                scripted
                    .answers
                    .lock()
                    .expect("the script")
                    .push_back(ServiceHttpAnswer {
                        status,
                        body: serde_json::to_vec(&body).expect("an answer"),
                    });
            }
            Arc::new(scripted)
        }

        fn sent(&self) -> Vec<Sent> {
            self.sent.lock().expect("what was sent").clone()
        }
    }

    impl ServiceHttp for Scripted {
        fn post_json<'a>(
            &'a self,
            url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.sent.lock().expect("what was sent").push(Sent {
                url: url.to_owned(),
                body: serde_json::from_slice(body).expect("a JSON body"),
                authorisation: headers
                    .iter()
                    .find(|(name, _)| *name == "authorization")
                    .map(|(_, value)| (*value).to_owned()),
            });
            let answer = self
                .answers
                .lock()
                .expect("the script")
                .pop_front()
                .expect("the script has an answer for every request");
            Box::pin(async move { Ok(answer) })
        }
    }

    #[derive(Debug)]
    struct Token;

    impl AccountTokenSource for Token {
        fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
            assert_eq!(scope, VOICE_SCOPE, "the broker asks for the voice scope");
            Box::pin(async { AccountToken::new("a-voice-token") })
        }
    }

    fn broker(service: &Arc<Scripted>) -> ManagedVoiceBroker {
        ManagedVoiceBroker::new(
            "https://reach.example",
            Arc::clone(service) as Arc<dyn ServiceHttp>,
            Arc::new(Token),
        )
        .expect("a broker client")
    }

    /// The answer `POST /api/voice/metadata` gives, in the spelling the deployed service writes.
    fn published_terms() -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "data": {
                "enabled": true,
                "model": "gpt-live-1",
                "disclosure": ["Audio travels directly between this device and the provider."],
                "admissionNote": "The model received this context.",
                "delegationNote": "A provider delegation identifier is correlation data.",
                "alternatives": ["The coding agent already running on the host."],
                "rate": {
                    "version": "2026-09-a",
                    "minorUnitsPerSecond": "2",
                    "minimumSeconds": 15,
                    "currency": "usd"
                },
                "maximumSessionSeconds": 1800,
                "minimumRequestSeconds": 60,
                "heartbeatSeconds": 20,
                "contextBytes": 500
            }
        })
    }

    fn start_request(version: Option<&str>) -> VoiceSessionRequest {
        VoiceSessionRequest {
            offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
            host_id: "33333333-3333-3333-3333-333333333333".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: None,
            device_id: None,
            expected_rate_version: version.map(str::to_owned),
        }
    }

    /// KR-REQ-15.19: the terms a person is shown come from the service's own read, asked with the
    /// account token and an empty body, and carried in the service's words.
    #[tokio::test]
    async fn the_terms_a_person_is_shown_are_the_ones_the_service_publishes() {
        let service = Scripted::answering([(200, published_terms())]);
        let terms = broker(&service)
            .metadata()
            .await
            .expect("the service answered")
            .expect("the managed service publishes terms");
        assert_eq!(terms.model, "gpt-live-1");
        assert_eq!(terms.rate.version, "2026-09-a");
        assert_eq!(terms.rate.amount_per_second(), Some(2));
        assert_eq!(terms.maximum_session_seconds, 1800);
        assert_eq!(
            terms.disclosure,
            vec!["Audio travels directly between this device and the provider.".to_owned()]
        );

        let sent = service.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, "https://reach.example/api/voice/metadata");
        assert_eq!(sent[0].body, serde_json::json!({}));
        assert_eq!(
            sent[0].authorisation.as_deref(),
            Some("Bearer a-voice-token")
        );
    }

    /// A quote nobody can be shown is one nobody can accept, so it is refused rather than carried.
    #[tokio::test]
    async fn a_rate_this_client_cannot_show_is_refused() {
        for amount in [
            serde_json::json!(2),
            serde_json::json!("-2"),
            serde_json::json!("+2"),
            serde_json::json!("2.5"),
            serde_json::json!(""),
            serde_json::json!("99999999999999999999999"),
        ] {
            let mut terms = published_terms();
            terms["data"]["rate"]["minorUnitsPerSecond"] = amount.clone();
            let service = Scripted::answering([(200, terms)]);
            assert!(
                broker(&service).metadata().await.is_err(),
                "{amount} was read as an amount"
            );
        }
        let mut unversioned = published_terms();
        unversioned["data"]["rate"]["version"] = serde_json::json!("");
        let service = Scripted::answering([(200, unversioned)]);
        assert!(broker(&service).metadata().await.is_err());
    }

    /// A start names the rate version the person was shown, and a start naming none is refused
    /// here without a request being sent.
    #[tokio::test]
    async fn a_start_names_the_rate_the_person_was_shown() {
        let service = Scripted::answering([(
            409,
            serde_json::json!({"ok": false, "error": {
                "code": "CONFLICT", "reason": "rate_changed",
                "message": "The rate changed after it was shown."
            }}),
        )]);
        let client = broker(&service);
        assert!(client.start(&start_request(None)).await.is_err());
        assert!(client.start(&start_request(Some(""))).await.is_err());
        assert!(
            service.sent().is_empty(),
            "a start that names no rate is never sent"
        );

        let _ = client
            .start(&start_request(Some("2026-09-a")))
            .await
            .expect("an answer");
        let sent = service.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, "https://reach.example/api/voice/sessions");
        assert_eq!(sent[0].body["expectedRateVersion"], "2026-09-a");
    }

    /// A refusal for a changed rate is a typed state carrying the rate as it is now, and it is
    /// never something this client asks again about by itself.
    #[test]
    fn a_changed_rate_carries_the_rate_as_it_is_now() {
        let answer = ServiceHttpAnswer {
            status: 409,
            body: br#"{"ok":false,"error":{"code":"CONFLICT","reason":"rate_changed",
                "message":"The rate changed after it was shown.",
                "rate":{"version":"2026-10-b","minorUnitsPerSecond":"3","minimumSeconds":15,
                        "currency":"usd"}}}"#
                .to_vec(),
        };
        let start = read_start_answer(&answer);
        let VoiceStart::RateChanged {
            rate,
            message,
            call_id,
        } = &start
        else {
            panic!("a changed rate is its own state: {start:?}");
        };
        assert_eq!(rate.version, "2026-10-b");
        assert_eq!(rate.amount_per_second(), Some(3));
        assert_eq!(message, "The rate changed after it was shown.");
        assert_eq!(call_id, &None);
        assert!(start.session().is_none());
        assert!(
            !start.may_ask_again(),
            "accepting a new rate is the person's decision"
        );

        // Without a rate that can be shown, it is an ordinary refusal: nothing here can offer a
        // person terms it cannot state.
        let answer = ServiceHttpAnswer {
            status: 409,
            body: br#"{"ok":false,"error":{"code":"CONFLICT","reason":"rate_changed",
                "message":"The rate changed after it was shown.",
                "rate":{"version":"2026-10-b","minorUnitsPerSecond":3,"minimumSeconds":15,
                        "currency":"usd"}}}"#
                .to_vec(),
        };
        let VoiceStart::Refused(refusal) = read_start_answer(&answer) else {
            panic!("a refusal");
        };
        assert_eq!(refusal.reason, VoiceRefusalReason::RateChanged);
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
            fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
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
            "http://0x7f.0.0.1",
            "http://0x7f000001",
            "https://reach.\texample",
        ] {
            assert!(
                ManagedVoiceBroker::new(refused, Arc::new(NoHttp), Arc::new(NoToken)).is_err(),
                "{refused}"
            );
        }
    }
}
