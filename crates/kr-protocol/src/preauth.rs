//! The request and answer shapes of the bounded pre-authorisation pairing surface.
//!
//! Section 23 lets an unpaired connection reach `pair.redeem`, `pair.finish` and a
//! candidate-authenticated `pair.status`, and nothing else. The ceremonies behind those three
//! names live in the pairing crate; what lives here is what travels on the wire, because an
//! unpaired connection has no other way to ask for anything.
//!
//! A direct redemption is two steps rather than one, and the reason is in section 10: the
//! challenge is the *host's*, single use and bound to the connection it was issued on, so a
//! candidate cannot prepare a proof before the host has agreed to serve one. Both steps are
//! `pair.redeem` because both are the same method on the same invitation; which step this is comes
//! from the shape of the parameters rather than from a second method name that an unpaired
//! connection would also have to be allowed to reach.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{AttemptId, InvitationId};
use crate::pairing::{DirectChallenge, DirectRedeemProof, PairStatus};

/// The parameters of `pair.redeem`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PairRedeemParams {
    /// Ask the host for a fresh single-use challenge for this invitation.
    Challenge {
        /// The invitation the candidate scanned.
        invitation_id: InvitationId,
    },
    /// Answer that challenge with the direct route's proof.
    Direct(Box<DirectRedeemProof>),
}

/// The result of `pair.redeem`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PairRedeemResult {
    /// The challenge to answer. It is single use and expires with the invitation.
    Challenge(Box<DirectChallenge>),
    /// The candidate now holds the invitation, and both devices show this value.
    ///
    /// Holding it is not being paired. The owner still has to approve the value both devices
    /// display, and the candidate learns that it happened through `pair.status`.
    Locked {
        /// The attempt the host locked to this candidate.
        attempt_id: AttemptId,
        /// The eight hexadecimal characters both devices display.
        verification_value: String,
    },
}

/// The parameters of `pair.status`.
///
/// The invitation is named; the candidate is not, and cannot be. The host answers about the
/// attempt the *authenticated endpoint* of this connection is party to, so a caller cannot ask
/// about another candidate's attempt by naming it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairStatusParams {
    /// The invitation the candidate is party to.
    pub invitation_id: InvitationId,
}

/// The result of `pair.status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairStatusResult {
    /// What the invitation is doing.
    pub status: PairStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    #[test]
    fn a_challenge_request_and_a_proof_are_distinguishable_on_the_wire() {
        let request = PairRedeemParams::Challenge {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
        };
        let bytes = kr_cbor::to_canonical_vec(&request).expect("encodes");
        let decoded: PairRedeemParams =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, request);
    }

    #[test]
    fn a_status_answer_round_trips_through_the_canonical_encoding() {
        let answer = PairStatusResult {
            status: PairStatus::Locked {
                attempt_id: AttemptId::new(Uuid::from_bytes([2; 16])),
                expires_at_ms: crate::scalars::TimestampMs::new(1_764_003_600_000),
            },
        };
        let bytes = kr_cbor::to_canonical_vec(&answer).expect("encodes");
        let decoded: PairStatusResult =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, answer);
    }
}
