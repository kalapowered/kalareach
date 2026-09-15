//! Protocol error codes, retry categories and the error object.
//!
//! Section 23 requires an error to carry a stable code, a plain message, a retry category and an
//! optional opaque diagnostic identifier. The codes below are the complete required set. A code is
//! a stable wire string: renaming one is a protocol change, not a refactor.
//!
//! Typed resource states such as `permission_required`, `restart_required`, pending revocation and
//! voice `creation_unknown` are **not** error codes. They belong to their own result schemas and
//! must not appear as alternative spellings here.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::DiagnosticId;
use crate::scalars::Nullable;

/// How a client may react to an error.
///
/// Only idempotent reads, transfer chunks and requests whose receipt proves no dispatch may retry
/// automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetryCategory {
    /// Do not retry automatically. A new user action, a new subject version or a new action
    /// identifier is required.
    NoRetry,
    /// A transient condition. Only an idempotent read, a transfer chunk or a request whose receipt
    /// proves no dispatch may retry, under jittered exponential backoff.
    Transient,
    /// The client's view is stale. Request a new snapshot and resume from the returned cursor.
    Resync,
    /// A configuration or software change is required. Retrying the same request cannot succeed.
    ConfigurationChange,
    /// Dispatch may have occurred. Never retry this action identifier; show the unknown result and
    /// require a new identifier for an explicit later user request.
    OutcomeUnknown,
}

impl RetryCategory {
    /// Returns true when an automatic retry of an idempotent request is permitted.
    #[must_use]
    pub const fn permits_automatic_retry(self) -> bool {
        matches!(self, Self::Transient)
    }
}

macro_rules! error_codes {
    ($($variant:ident => $wire:literal, $retry:ident, $doc:literal;)+) => {
        /// A stable protocol error code.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        pub enum ErrorCode {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl ErrorCode {
            /// Every defined code, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Returns the stable wire string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// Returns the code for a wire string.
            #[must_use]
            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($wire => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Returns the retry category the specification assigns to this code.
            #[must_use]
            pub const fn retry_category(self) -> RetryCategory {
                match self {
                    $(Self::$variant => RetryCategory::$retry,)+
                }
            }
        }
    };
}

error_codes! {
    InvalidArgument => "INVALID_ARGUMENT", ConfigurationChange,
        "A field is missing, malformed or outside its permitted range.";
    UnsupportedSchema => "UNSUPPORTED_SCHEMA", ConfigurationChange,
        "The negotiated protocol major version, method version or object schema is not supported.";
    UnsupportedCapability => "UNSUPPORTED_CAPABILITY", ConfigurationChange,
        "The requested capability is not offered by this peer or this binding.";
    PermissionDenied => "PERMISSION_DENIED", ConfigurationChange,
        "The verified actor does not hold the rights this effect requires, or the effect is not listed.";
    PairingExpired => "PAIRING_EXPIRED", NoRetry,
        "The invitation passed its deadline. A new invitation requires another owner action.";
    PairingRejected => "PAIRING_REJECTED", NoRetry,
        "The issuing owner denied or cancelled the pairing candidate.";
    PairingAuthFailed => "PAIRING_AUTH_FAILED", ConfigurationChange,
        "A pairing confirmation tag or proof did not verify. An authentication failure needs a \
         configuration or software change, and the cause stays ambiguous: a wrong secret, a wrong \
         origin and a stale paired key are not distinguished. A failed key confirmation is never \
         retried automatically.";
    PairingAttemptsExhausted => "PAIRING_ATTEMPTS_EXHAUSTED", NoRetry,
        "The invitation consumed its failed-confirmation allowance.";
    RendezvousUnavailable => "RENDEZVOUS_UNAVAILABLE", Transient,
        "The configured rendezvous service could not be reached or has no capacity.";
    RendezvousConfigError => "RENDEZVOUS_CONFIG_ERROR", ConfigurationChange,
        "The local rendezvous configuration is wrong, for example an unusable origin.";
    UnknownSession => "UNKNOWN_SESSION", NoRetry,
        "No session with that identity exists in this environment.";
    AmbiguousSession => "AMBIGUOUS_SESSION", NoRetry,
        "The supplied selector matched more than one session.";
    AmbiguousAttachment => "AMBIGUOUS_ATTACHMENT", NoRetry,
        "The supplied selector matched more than one attachment.";
    TerminalUnavailable => "TERMINAL_UNAVAILABLE", Transient,
        "No terminal could be opened or the requested terminal is not usable.";
    TerminalProbeFailed => "TERMINAL_PROBE_FAILED", Transient,
        "The terminal profile probe did not complete, so the capability set is unknown.";
    InputIncompatible => "INPUT_INCOMPATIBLE", ConfigurationChange,
        "The client's input encoder cannot produce bytes this terminal profile accepts.";
    SessionClosed => "SESSION_CLOSED", NoRetry,
        "The session has closed. A history request never starts execution.";
    SessionLimit => "SESSION_LIMIT", Transient,
        "The environment already holds its maximum number of live or creating sessions.";
    ResourceUnavailable => "RESOURCE_UNAVAILABLE", Transient,
        "A required local resource, such as a pseudoterminal or process slot, is unavailable.";
    HostNotConfigured => "HOST_NOT_CONFIGURED", ConfigurationChange,
        "The per-user controller is not installed or configured; the response names the setup action.";
    EnvironmentUnavailable => "ENVIRONMENT_UNAVAILABLE", Transient,
        "The named execution environment is not running or cannot be reached.";
    DesktopUnavailable => "DESKTOP_UNAVAILABLE", Transient,
        "No usable desktop session exists for a request that needs one.";
    StaleSession => "STALE_SESSION", NoRetry,
        "The named session identity or epoch is no longer current.";
    LeaseLost => "LEASE_LOST", NoRetry,
        "The input lease or dispatch lease is no longer held. Acquire it again explicitly.";
    GeometryNotOwner => "GEOMETRY_NOT_OWNER", NoRetry,
        "The actor is not the current geometry owner for this session.";
    DraftConflict => "DRAFT_CONFLICT", NoRetry,
        "The subject changed under the request: an intervening edit, or a preflight conflict.";
    EditorBusy => "EDITOR_BUSY", Transient,
        "The trusted root editor is not in a state that permits this operation.";
    IdConflict => "ID_CONFLICT", NoRetry,
        "The action identifier was reused with a different payload digest.";
    UpstreamUnavailable => "UPSTREAM_UNAVAILABLE", Transient,
        "The upstream agent or provider interface could not be reached.";
    OutcomeUnknown => "OUTCOME_UNKNOWN", OutcomeUnknown,
        "Dispatch may have occurred without a confirmed outcome. Never retried automatically.";
    ResyncRequired => "RESYNC_REQUIRED", Resync,
        "The client fell behind its stream. Request a new snapshot and resume from its cursor.";
    QuotaExceeded => "QUOTA_EXCEEDED", NoRetry,
        "An allowance is exhausted. A retry cannot succeed until the allowance changes.";
    RateLimited => "RATE_LIMITED", Transient,
        "The caller exceeded a rate limit.";
    ServiceCapacity => "SERVICE_CAPACITY", Transient,
        "A managed service has no capacity. This is not a host failure.";
    ClockUntrusted => "CLOCK_UNTRUSTED", ConfigurationChange,
        "Wall-clock trust is unresolved, so an expiry-dependent object cannot be proved valid.";
    StorageUnavailable => "STORAGE_UNAVAILABLE", Transient,
        "A required durable store is unavailable or full, so no durable mutation is accepted.";
    ShellIntegrationUnsupported => "SHELL_INTEGRATION_UNSUPPORTED", ConfigurationChange,
        "The running shell has no managed integration for this operation.";
    AttachmentIntegrity => "ATTACHMENT_INTEGRITY", NoRetry,
        "A chunk digest, total size or whole-file digest did not match.";
    RepositoryUntrusted => "REPOSITORY_UNTRUSTED", ConfigurationChange,
        "The catalogue root, generation or signature is not trusted by this host.";
    PackageUnavailableOffline => "PACKAGE_UNAVAILABLE_OFFLINE", Transient,
        "The package is not present locally and no repository is reachable.";
    PluginGrantRequired => "PLUGIN_GRANT_REQUIRED", ConfigurationChange,
        "The plugin needs a capability grant that has not been given.";
    PluginDisabled => "PLUGIN_DISABLED", ConfigurationChange,
        "The plugin is installed but disabled in this environment.";
    QuestionResolved => "QUESTION_RESOLVED", NoRetry,
        "The question was already answered or cancelled.";
    QuestionExpired => "QUESTION_EXPIRED", NoRetry,
        "The question passed its expiry before an answer arrived.";
    NotInKrSession => "NOT_IN_KR_SESSION", ConfigurationChange,
        "The caller is not running inside a KalaReach session, so this operation has no subject.";
    OwnerConfirmationRequired => "OWNER_CONFIRMATION_REQUIRED", NoRetry,
        "A fresh owner confirmation bound to this exact action digest is required.";
    CausalLimit => "CAUSAL_LIMIT", NoRetry,
        "The causal budget for this chain of automated runs is exhausted.";
    SourceChanged => "SOURCE_CHANGED", NoRetry,
        "The source revision changed under a staging snapshot or capture.";
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A wire string that is not a defined error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownErrorCode;

impl fmt::Display for UnknownErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown error code")
    }
}

impl std::error::Error for UnknownErrorCode {}

impl FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire(value).ok_or(UnknownErrorCode)
    }
}

/// Maximum length in bytes of an error message.
pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;

/// The error object returned in a response or recorded on a receipt.
///
/// The message is plain text for a person or a log. The user interface translates the code into a
/// direct action and does not display protocol internals by default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    /// The stable code.
    pub code: ErrorCode,
    /// A plain message. It never carries credentials or command text.
    pub message: String,
    /// How the client may react. It must equal [`ErrorCode::retry_category`] for the code.
    pub retry: RetryCategory,
    /// An opaque identifier for correlating this failure with host diagnostics.
    pub diagnostic_id: Nullable<DiagnosticId>,
}

impl ProtocolError {
    /// Builds an error with the retry category the specification assigns to `code`.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry: code.retry_category(),
            diagnostic_id: Nullable::null(),
        }
    }

    /// Attaches an opaque diagnostic identifier.
    #[must_use]
    pub fn with_diagnostic_id(mut self, diagnostic_id: DiagnosticId) -> Self {
        self.diagnostic_id = Nullable::some(diagnostic_id);
        self
    }

    /// Returns true when the retry category matches the code and the message is inside its bound.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.retry == self.code.retry_category() && self.message.len() <= MAX_ERROR_MESSAGE_LEN
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}
