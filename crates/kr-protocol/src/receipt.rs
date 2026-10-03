//! Receipt states and the transition contract of section 9.
//!
//! A receipt is the durable identity of a mutation. Its revision increases monotonically and its
//! state moves only along the permitted edges below.
//!
//! ```text
//! received ──> accepted ──> dispatching ──> applied
//!     │            │              ├───────> refused
//!     └──> rejected└──> rejected  └───────> unknown ──> applied
//!                                                   └─> refused
//! ```
//!
//! `received` is a transient connection acknowledgement, never durable acceptance. There is no
//! `dispatching -> rejected` edge: once a dispatch marker is committed, no later transition may
//! imply that an uncertain side effect did not happen.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use crate::ids::{ActionId, ActorId, RequestId};
use crate::method::{MethodName, MethodVersion};
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};

/// The state of one action receipt.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    /// The connection acknowledged the request. Transient, never durable acceptance.
    Received,
    /// The intent is durably committed. No dispatch marker exists yet.
    Accepted,
    /// A durable dispatch marker was committed before crossing the external-effect boundary.
    Dispatching,
    /// The authoritative interface acknowledged the operation. Terminal for admission and
    /// dispatch; later work completion is separate evidence.
    Applied,
    /// The authoritative interface proved the operation was refused without the requested effect.
    /// Terminal. This is not a local pre-dispatch rejection.
    Refused,
    /// Never dispatched. Admission failure, or later expiry, cancellation, revocation or stale
    /// preconditions before dispatch. Terminal.
    Rejected,
    /// Dispatch may have occurred. This identifier is never dispatched again. Later authoritative
    /// reconciliation may move it to applied or refused; otherwise it stays unknown.
    Unknown,
}

impl ReceiptState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Received,
        Self::Accepted,
        Self::Dispatching,
        Self::Applied,
        Self::Refused,
        Self::Rejected,
        Self::Unknown,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Accepted => "accepted",
            Self::Dispatching => "dispatching",
            Self::Applied => "applied",
            Self::Refused => "refused",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }

    /// Returns true when the state is durable rather than a connection acknowledgement.
    #[must_use]
    pub const fn is_durable(self) -> bool {
        !matches!(self, Self::Received)
    }

    /// Returns true when no further transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Refused | Self::Rejected)
    }

    /// Returns true when a dispatch marker has been committed for this state.
    ///
    /// After a dispatch marker the action can never be dispatched again, whatever the outcome.
    #[must_use]
    pub const fn has_dispatch_marker(self) -> bool {
        matches!(
            self,
            Self::Dispatching | Self::Applied | Self::Refused | Self::Unknown
        )
    }

    /// Returns the states this state may move to.
    #[must_use]
    pub const fn permitted_transitions(self) -> &'static [Self] {
        match self {
            // A transient acknowledgement either commits the intent or fails admission.
            Self::Received => &[Self::Accepted, Self::Rejected],
            // An accepted intent may be dispatched, or rejected before any dispatch marker.
            Self::Accepted => &[Self::Dispatching, Self::Rejected],
            // Past the dispatch marker there is no rejection, only an outcome or uncertainty.
            Self::Dispatching => &[Self::Applied, Self::Refused, Self::Unknown],
            Self::Applied | Self::Refused | Self::Rejected => &[],
            // Only authoritative reconciliation resolves an unknown outcome.
            Self::Unknown => &[Self::Applied, Self::Refused],
        }
    }

    /// Returns true when moving from this state to `next` is permitted.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self.permitted_transitions().contains(&next)
    }
}

impl fmt::Display for ReceiptState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why an action was rejected before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Admission failed: authority, preconditions, limits or schema.
    AdmissionFailed,
    /// The accepted deadline passed before dispatch.
    Expired,
    /// The actor or the host owner cancelled an undispatched intent.
    Cancelled,
    /// A revocation fenced the action before dispatch.
    Revoked,
    /// A subject precondition no longer held in the serial dispatch path.
    StalePreconditions,
}

impl RejectionReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionFailed => "admission_failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Revoked => "revoked",
            Self::StalePreconditions => "stale_preconditions",
        }
    }
}

/// A transition the contract does not permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The edge does not exist in the contract.
    Forbidden {
        /// The current state.
        from: ReceiptState,
        /// The requested state.
        to: ReceiptState,
    },
    /// The revision did not increase.
    RevisionNotIncreasing {
        /// The current revision.
        current: u64,
        /// The requested revision.
        next: u64,
    },
    /// A rejection did not name its reason.
    ReasonRequired,
    /// A state other than `rejected` carried a rejection reason.
    ReasonNotPermitted {
        /// The requested state.
        state: ReceiptState,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forbidden { from, to } => {
                write!(formatter, "receipt cannot move from {from} to {to}")
            }
            Self::RevisionNotIncreasing { current, next } => write!(
                formatter,
                "receipt revision must increase: {current} is not below {next}"
            ),
            Self::ReasonRequired => formatter.write_str("a rejection must name its reason"),
            Self::ReasonNotPermitted { state } => {
                write!(formatter, "state {state} cannot carry a rejection reason")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

/// One action receipt.
///
/// The de-duplication key is `(actor_id, action_id)`. An exact duplicate returns the stored
/// receipt; a reused identifier with a different payload digest is an `ID_CONFLICT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// The durable operation identity.
    pub action_id: ActionId,
    /// The verified actor that submitted it.
    pub actor_id: ActorId,
    /// The method and version the digest covers.
    pub method: MethodName,
    /// The method version the digest covers.
    pub method_version: MethodVersion,
    /// A monotonically increasing revision.
    pub revision: U64,
    /// The current state.
    pub state: ReceiptState,
    /// Why the action was rejected, when the state is `rejected`.
    pub reason: Nullable<RejectionReason>,
    /// The digest of the submitted payload, used to detect a reused identifier.
    pub payload_digest: Digest256,
    /// The deadline the host derived at acceptance: the earliest of window expiry, receipt time
    /// plus the requested time to live, and any applicable authority or subject deadline. An exact
    /// retry never receives a new deadline.
    pub accepted_deadline_ms: Nullable<TimestampMs>,
    /// The failure recorded with a refusal, rejection or unknown outcome.
    pub error: Nullable<ProtocolError>,
    /// True when the host replaced the message of [`Self::error`] with one of its own, because the
    /// reader is not the local owner. An error's message can quote an upstream, a session or a
    /// person, and it carries no date of its own to hold to a history bound, so only the owner is
    /// shown it again. The code, the retry category and the diagnostic identifier stay.
    ///
    /// It is absent from the wire when it is false, so a receipt the host shows in full is byte
    /// for byte what a reader built before this member expects. Remove the default and the omission
    /// once no reader of a build before this member can still be running: a `kr` of another
    /// release reads a worker's receipts directly, and a paired device runs its own release.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub error_withheld: bool,
    /// When this revision was written.
    pub updated_at_ms: TimestampMs,
}

impl Receipt {
    /// Returns this receipt as a reader that may not see an error's text is shown it: the message
    /// is replaced by a sentence the host composes from the code, and [`Self::error_withheld`] says
    /// so. A receipt that records no error is returned as it is.
    #[must_use]
    pub fn with_error_withheld(&self) -> Self {
        let Some(error) = self.error.as_ref() else {
            return self.clone();
        };
        let mut shown = self.clone();
        shown.error = Nullable::some(ProtocolError {
            code: error.code,
            message: format!(
                "the action failed with {}; the host does not show the detail of a failure to this \
                 reader",
                error.code
            ),
            retry: error.retry,
            diagnostic_id: error.diagnostic_id.clone(),
            link_fenced: error.link_fenced,
        });
        shown.error_withheld = true;
        shown
    }

    /// Moves the receipt to `next` at `revision`.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the edge is not permitted, when the revision does not
    /// increase, or when the rejection reason is missing or not permitted for the state.
    pub fn advance(
        &mut self,
        next: ReceiptState,
        revision: U64,
        reason: Option<RejectionReason>,
    ) -> Result<(), TransitionError> {
        if !self.state.can_transition_to(next) {
            return Err(TransitionError::Forbidden {
                from: self.state,
                to: next,
            });
        }
        if revision.get() <= self.revision.get() {
            return Err(TransitionError::RevisionNotIncreasing {
                current: self.revision.get(),
                next: revision.get(),
            });
        }
        match (next, reason) {
            (ReceiptState::Rejected, None) => return Err(TransitionError::ReasonRequired),
            (state, Some(_)) if state != ReceiptState::Rejected => {
                return Err(TransitionError::ReasonNotPermitted { state });
            }
            _ => {}
        }
        self.state = next;
        self.revision = revision;
        self.reason = Nullable(reason);
        Ok(())
    }
}

/// The response to a mutation request.
///
/// A duplicate request from a still-authorised actor returns the retained receipt without
/// dispatch. The host checks current authority before returning it, so a revoked device cannot use
/// an old action identifier to retrieve protected information.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptResponse {
    /// The request this response correlates with.
    pub request_id: RequestId,
    /// The current receipt.
    pub receipt: Receipt,
}

/// What `action.read` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionReadParams {
    /// The action to read.
    pub action_id: ActionId,
    /// The session whose receipts hold it, when it belongs to one.
    ///
    /// A worker serves the receipts of the one session it owns, so a request that reaches a
    /// worker needs no session. The environment archive serves every closed session's, so a
    /// request that reaches the daemon says which one. A receipt for a host effect resolves
    /// against the host scope instead and names none.
    ///
    /// It is absent from the wire when it is absent, so a request built before the archive
    /// existed is byte for byte what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<crate::ids::SessionId>,
}

/// A retained receipt and the result it produced.
///
/// Owning an identifier is not authority: the host checks present view authority over the subject
/// the receipt names before it returns either half, which is why a retained result is carried here
/// rather than handed back from the action identifier alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionReadResult {
    /// The receipt as it currently stands.
    pub receipt: Receipt,
    /// The result the action produced, when it produced one and it is still retained.
    pub result: Nullable<crate::envelope::ParamsValue>,
}

/// What `action.cancel` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionCancelParams {
    /// The action to cancel.
    pub action_id: ActionId,
}

/// The receipt an undispatched action was cancelled into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionCancelResult {
    /// The receipt after the cancellation.
    pub receipt: Receipt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::ids::ActionId;
    use crate::scalars::{Digest256, Uuid};

    fn receipt(error: Option<ProtocolError>) -> Receipt {
        Receipt {
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            actor_id: ActorId::new("device:test").expect("a principal"),
            method: crate::method::Method::AgentPromptSubmit.into(),
            method_version: MethodVersion::V1,
            revision: U64::new(3),
            state: ReceiptState::Refused,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable(error),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(7),
        }
    }

    /// KR-REQ-10.49: a receipt the host shows in full is the frame a reader built before the
    /// marker expects, and a frame without the marker reads as one that shows its error.
    #[test]
    fn a_receipt_shown_in_full_has_no_marker_on_the_wire() {
        let shown = receipt(Some(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "the upstream said the prompt was too long",
        )));
        let json = serde_json::to_value(&shown).expect("encodes");
        assert!(json.get("error_withheld").is_none(), "{json}");
        let decoded: Receipt = serde_json::from_value(json).expect("decodes");
        assert_eq!(decoded, shown);
        assert!(!decoded.error_withheld);
    }

    /// KR-REQ-10.49: an error's text is replaced for a reader that may not see it, the marker says
    /// so, and what a client acts on stays: the state, the code, the retry category and the
    /// diagnostic identifier.
    #[test]
    fn a_receipt_withholding_its_error_keeps_the_code_and_loses_the_text() {
        let error = ProtocolError::new(
            ErrorCode::InvalidArgument,
            "the upstream said: remove the secret in /home/person/notes",
        )
        .with_diagnostic_id(
            crate::ids::DiagnosticId::new("diag-7f3a").expect("a diagnostic identifier"),
        );
        let full = receipt(Some(error.clone()));
        let shown = full.with_error_withheld();

        assert!(shown.error_withheld);
        let kept = shown.error.as_ref().expect("an error is still recorded");
        assert_eq!(kept.code, error.code);
        assert_eq!(kept.retry, error.retry);
        assert_eq!(kept.diagnostic_id, error.diagnostic_id);
        assert!(kept.is_consistent());
        let json = serde_json::to_string(&shown).expect("encodes");
        assert!(!json.contains("secret"), "{json}");
        assert!(!json.contains("/home/person"), "{json}");
        assert!(json.contains("\"error_withheld\":true"), "{json}");
        assert_eq!(shown.state, full.state);
        assert_eq!(shown.revision, full.revision);
        assert_eq!(shown.payload_digest, full.payload_digest);
        assert_eq!(shown.updated_at_ms, full.updated_at_ms);

        let decoded: Receipt = serde_json::from_str(&json).expect("decodes");
        assert_eq!(decoded, shown);
        assert_eq!(decoded.with_error_withheld(), shown);
    }

    /// KR-REQ-10.49: a receipt that records no error has nothing to withhold, and says nothing
    /// was.
    #[test]
    fn a_receipt_with_no_error_is_shown_as_it_is() {
        let applied = receipt(None);
        assert_eq!(applied.with_error_withheld(), applied);
        assert!(!applied.with_error_withheld().error_withheld);
    }
}
