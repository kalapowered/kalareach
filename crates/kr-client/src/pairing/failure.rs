//! Why a pairing attempt ended, as a person is told it.
//!
//! Section 10 asks for a known local configuration error, an unreachable service, an expired
//! invitation, a denied approval and exhausted attempts to be told apart, for an authentication
//! failure to stay ambiguous, and for nothing to become a cheap answer to whether a locator
//! exists. What an outcome may claim depends on how far the attempt got, because the evidence
//! changes on the way: before the host has spoken, a closed room says nothing about the
//! invitation; before the host's confirmation tag verifies, what the host reported travelled
//! through a relay nothing authenticates; afterwards it is the host's own word.
//!
//! [`FailureKind`] is the whole vocabulary. An interface holds the words for each kind, so they can
//! be localised; this module holds which kind an outcome is.

use kr_protocol::error::ErrorCode;
use kr_protocol::pairing::PairingConsumedReason;
use serde::Serialize;

/// Which of the outcomes a person is told apart an attempt ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The code is not ten characters of the pairing alphabet.
    Malformed,
    /// This device has used its five tries with this code.
    DeviceTriesUsed,
    /// The pairing service could not be reached, or could not serve this attempt now.
    ServiceUnreachable,
    /// The origin answered, and does not serve pairing: the device's configuration to fix.
    ServiceNotPairing,
    /// The room ended the attempt before any host spoke, which says nothing about the invitation.
    NoHostAnswered,
    /// The code, the origin or the peer was wrong; which of them is not knowable.
    NotAuthenticated,
    /// The host reports that too many wrong codes were tried, so it ended the invitation.
    HostTriesUsed,
    /// The host reports that the invitation expired.
    Expired,
    /// The host did not finish the exchange within the attempt's own deadline.
    TimedOut,
    /// The attempt ended for a reason the evidence does not let a person act on more precisely.
    DidNotFinish,
    /// The owner declined this device.
    Declined,
    /// The owner withdrew the invitation.
    Withdrawn,
    /// The host restarted before pairing finished.
    HostRestarted,
    /// Another device already holds the invitation, awaiting approval.
    AnotherDeviceWaiting,
    /// The host could not be reached over the network.
    HostUnreachable,
    /// The host did not match its invitation, so nothing was sent to it.
    HostMismatch,
    /// This device is already paired with the host the invitation is for.
    AlreadyPaired,
    /// What was read is not a KalaReach invitation.
    NotAnInvitation,
    /// The invitation is of a version this release does not read.
    NewerInvitation,
    /// The pasteboard holds no invitation.
    NothingToPaste,
    /// This device could not keep its pairing records safely, so it stopped.
    StoreFailed,
    /// The host may have approved this device while it could not ask, and that cannot be
    /// confirmed now.
    ApprovalUnknown,
}

/// How an attempt ended, with the tries this device has left when the attempt was charged.
///
/// `detail` says what happened in terms a log can keep. It never holds a secret, and an interface
/// shows the kind's own words rather than it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingFailure {
    /// Which outcome it was.
    pub kind: FailureKind,
    /// How many tries this device has left with the code, when the attempt was charged.
    pub tries_left: Option<u32>,
    /// What happened, for a log.
    #[serde(skip)]
    pub detail: String,
}

impl PairingFailure {
    /// A failure of `kind`, with `detail` for a log.
    #[must_use]
    pub fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            tries_left: None,
            detail: detail.into(),
        }
    }

    /// The same failure, with the tries this device has left.
    #[must_use]
    pub const fn with_tries(mut self, tries_left: Option<u32>) -> Self {
        self.tries_left = tries_left;
        self
    }
}

impl std::fmt::Display for PairingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for PairingFailure {}

/// What a host's refusal says, once the host's word can be trusted.
///
/// A candidate that holds the invitation learns how it ended through `pair.status`, which names
/// the reason; a refusal carries only its code, and a rejection covers an owner's decision, a
/// withdrawal and another device holding the invitation alike, so it says no more than that the
/// attempt did not finish.
#[must_use]
pub fn refused_by_host(code: ErrorCode, direct: bool) -> FailureKind {
    match code {
        ErrorCode::PairingAuthFailed => FailureKind::NotAuthenticated,
        ErrorCode::PairingAttemptsExhausted if !direct => FailureKind::HostTriesUsed,
        ErrorCode::PairingExpired => FailureKind::Expired,
        _ => FailureKind::DidNotFinish,
    }
}

/// What a consumed invitation's reason means for the device that held it.
#[must_use]
pub const fn consumed(reason: PairingConsumedReason) -> FailureKind {
    match reason {
        PairingConsumedReason::Denied => FailureKind::Declined,
        PairingConsumedReason::Expired => FailureKind::Expired,
        PairingConsumedReason::Cancelled => FailureKind::Withdrawn,
        PairingConsumedReason::AttemptsExhausted => FailureKind::HostTriesUsed,
        PairingConsumedReason::HostRestarted => FailureKind::HostRestarted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-10.19: an authentication failure stays one ambiguous kind, and the host's own
    /// reasons map to the kinds a person can act on.
    #[test]
    fn a_hosts_word_maps_to_what_a_person_can_act_on() {
        assert_eq!(
            refused_by_host(ErrorCode::PairingAuthFailed, false),
            FailureKind::NotAuthenticated
        );
        assert_eq!(
            refused_by_host(ErrorCode::PairingAttemptsExhausted, false),
            FailureKind::HostTriesUsed
        );
        assert_eq!(
            refused_by_host(ErrorCode::PairingExpired, true),
            FailureKind::Expired
        );
        assert_eq!(
            refused_by_host(ErrorCode::PairingRejected, false),
            FailureKind::DidNotFinish
        );
        assert_eq!(
            consumed(PairingConsumedReason::Denied),
            FailureKind::Declined
        );
        assert_eq!(
            consumed(PairingConsumedReason::Cancelled),
            FailureKind::Withdrawn
        );
        assert_eq!(
            consumed(PairingConsumedReason::HostRestarted),
            FailureKind::HostRestarted
        );
    }

    /// A failure's detail is for a log: it never reaches what an interface is sent.
    #[test]
    fn the_detail_stays_out_of_what_an_interface_reads() {
        let failure = PairingFailure::new(
            FailureKind::HostMismatch,
            "the live peer was another endpoint",
        )
        .with_tries(Some(3));
        let sent = serde_json::to_value(&failure).expect("serialises");
        assert_eq!(
            sent,
            serde_json::json!({"kind": "host_mismatch", "tries_left": 3})
        );
    }
}
