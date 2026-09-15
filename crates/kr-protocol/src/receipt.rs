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
    /// When this revision was written.
    pub updated_at_ms: TimestampMs,
}

impl Receipt {
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
