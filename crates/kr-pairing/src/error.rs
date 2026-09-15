//! Typed pairing failures.
//!
//! Section 10 is explicit about what a failure may say. The user interface distinguishes a known
//! local configuration error, an unreachable service, an expired invitation, a denied approval and
//! exhausted attempts, but **an ambiguous authentication failure stays ambiguous**: a failed
//! confirmation tag does not tell anyone whether the code or the origin was wrong, and there is no
//! cheap locator-existence answer. [`PairingError::AuthenticationFailed`] carries no reason for
//! exactly that reason.

use kr_protocol::error::ErrorCode;

/// The result of a pairing step.
pub type Result<T> = core::result::Result<T, PairingError>;

/// A pairing failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    /// The entered text was not ten Base58 characters.
    #[error("a pairing code is ten characters from the Bitcoin Base58 alphabet")]
    MalformedCode,

    /// The two devices did not derive the same key, or a tag did not verify.
    ///
    /// This is deliberately one variant. Which half of the code was wrong, whether the origin was
    /// wrong, and whether the peer was an impostor are all indistinguishable from here, and saying
    /// more would be guessing on the user's behalf.
    #[error("the pairing could not be authenticated")]
    AuthenticationFailed,

    /// The invitation passed its deadline.
    #[error("the invitation expired")]
    Expired,

    /// The invitation was already consumed: approved, denied, cancelled or exhausted.
    #[error("the invitation is no longer open ({reason:?})")]
    Consumed {
        /// How it was consumed.
        reason: kr_protocol::pairing::PairingConsumedReason,
    },

    /// The invitation was already committed, and a retry retrieves that result.
    ///
    /// A transport retry can retrieve the committed result for the same device, but it cannot
    /// replace the public keys or the grant, so a second commit is refused rather than repeated.
    #[error("the invitation was already committed")]
    AlreadyCommitted,

    /// A pairing mutation arrived in QUIC early data.
    ///
    /// Version 1 accepts no application mutation in 0-RTT, and a pairing mutation least of all:
    /// early data is replayable by anyone who captured it.
    #[error("a pairing mutation cannot arrive in early data")]
    EarlyData,

    /// The host's failed-confirmation allowance for this invitation ran out.
    #[error("the invitation has no confirmation attempts left")]
    AttemptsExhausted,

    /// The client's own allowance for this entered code ran out.
    #[error("this code has no attempts left on this device; ask for a new one")]
    ClientAttemptsExhausted,

    /// A candidate already holds the invitation and owner approval is pending.
    #[error("another candidate is already awaiting owner approval")]
    CandidateLocked,

    /// A step arrived out of order.
    #[error("a pairing message arrived in the {actual} phase, which expects {expected}")]
    WrongPhase {
        /// What the state machine expected.
        expected: &'static str,
        /// What it was in.
        actual: &'static str,
    },

    /// A sequence number was reused or skipped.
    #[error("a pairing message repeated or skipped sequence number {sequence}")]
    ReplayedSequence {
        /// The sequence number that arrived.
        sequence: u64,
    },

    /// A message or the whole exchange exceeded its bound.
    #[error("{what} is {actual} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// What was too large.
        what: &'static str,
        /// The limit.
        limit: usize,
        /// The actual size.
        actual: usize,
    },

    /// A value both devices construct themselves did not match.
    #[error("{what} does not match")]
    ContextMismatch {
        /// Which value disagreed.
        what: &'static str,
    },

    /// The live transport peer was not the endpoint the authenticated bundle named.
    #[error("the live {side} endpoint is not the one the pairing authenticated")]
    EndpointMismatch {
        /// Which side disagreed.
        side: &'static str,
    },

    /// The caller is not the owner that issued the invitation.
    #[error("only the issuing owner can confirm or cancel this invitation")]
    NotIssuingOwner,

    /// An owner confirmation was missing, or arrived through a channel that cannot carry one.
    #[error("this action needs a fresh owner confirmation")]
    OwnerConfirmationRequired,

    /// A proposed grant asked for more than an invitation may carry.
    #[error("the proposed grant is not permitted: {reason}")]
    GrantNotPermitted {
        /// Why it was refused.
        reason: &'static str,
    },

    /// The rendezvous service could not be reached, or answered in a way it should not.
    ///
    /// This is a transport failure, never an authentication result. Section 10 keeps them apart:
    /// a local configuration or transport failure consumes admission budget but not the host's
    /// failed-confirmation allowance.
    #[error("the rendezvous service is unavailable: {reason}")]
    RendezvousUnavailable {
        /// What the transport reported.
        reason: String,
    },

    /// The locally configured rendezvous origin is wrong or missing.
    #[error("the rendezvous origin is not configured correctly: {reason}")]
    RendezvousConfiguration {
        /// What is wrong with it.
        reason: String,
    },

    /// A store this state machine depends on failed.
    #[error("the pairing store failed: {reason}")]
    Store {
        /// What the store reported.
        reason: String,
    },

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] kr_crypto::CryptoError),

    /// A value could not be represented in KR-CBOR-1.
    #[error(transparent)]
    Encoding(#[from] kr_cbor::CborError),
}

impl PairingError {
    /// Returns the protocol error code this failure is reported as.
    ///
    /// Section 23 lists the codes; this is the mapping, in one place, so two call sites cannot
    /// report the same failure differently. Every authentication outcome maps to the one ambiguous
    /// code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::MalformedCode | Self::GrantNotPermitted { .. } => ErrorCode::InvalidArgument,
            Self::AuthenticationFailed
            | Self::ContextMismatch { .. }
            | Self::EndpointMismatch { .. }
            | Self::ReplayedSequence { .. }
            | Self::EarlyData
            | Self::WrongPhase { .. } => ErrorCode::PairingAuthFailed,
            Self::Expired => ErrorCode::PairingExpired,
            Self::Consumed { .. } | Self::CandidateLocked | Self::AlreadyCommitted => {
                ErrorCode::PairingRejected
            }
            Self::AttemptsExhausted | Self::ClientAttemptsExhausted => {
                ErrorCode::PairingAttemptsExhausted
            }
            Self::TooLarge { .. } => ErrorCode::InvalidArgument,
            Self::NotIssuingOwner => ErrorCode::PermissionDenied,
            Self::OwnerConfirmationRequired => ErrorCode::OwnerConfirmationRequired,
            Self::RendezvousUnavailable { .. } => ErrorCode::RendezvousUnavailable,
            Self::RendezvousConfiguration { .. } => ErrorCode::RendezvousConfigError,
            Self::Store { .. } => ErrorCode::StorageUnavailable,
            Self::Crypto(_) | Self::Encoding(_) => ErrorCode::PairingAuthFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_authentication_outcome_reports_one_ambiguous_code() {
        for error in [
            PairingError::AuthenticationFailed,
            PairingError::ContextMismatch {
                what: "the context",
            },
            PairingError::EndpointMismatch { side: "client" },
            PairingError::ReplayedSequence { sequence: 1 },
            PairingError::WrongPhase {
                expected: "a",
                actual: "b",
            },
            PairingError::EarlyData,
        ] {
            assert_eq!(error.code(), ErrorCode::PairingAuthFailed, "{error}");
        }
    }

    #[test]
    fn a_failure_never_says_which_half_of_the_code_was_wrong() {
        // The message is the contract: it names no cause a host cannot establish.
        let rendered = PairingError::AuthenticationFailed.to_string();
        assert_eq!(rendered, "the pairing could not be authenticated");
        assert!(!rendered.contains("code"));
        assert!(!rendered.contains("origin"));
    }
}
