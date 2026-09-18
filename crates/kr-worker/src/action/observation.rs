//! Additive evidence about an action.
//!
//! Section 9 is careful about what an observation is: additive evidence, not a competing execution
//! state. Three consequences, and this module is the one place that holds all three.
//!
//! * An observation never creates a receipt. Evidence about an action this host never admitted is
//!   evidence about somebody else's action, and recording it under an identifier nothing here owns
//!   would invent an action rather than observe one.
//! * An observation of an action that already has an outcome is recorded and changes nothing. The
//!   receipt contract permits no edge out of a terminal state, and evidence is not a way around it.
//! * Only an authoritative answer resolves an uncertain outcome. An inferred screen cannot turn
//!   `unknown` into `applied`, however clearly the screen reads, because a screen is what the host
//!   parsed and not what the interface that owns the subject said.
//!
//! [`kr_protocol::action::ActionObservation::resolution`] is the rule itself, shared with every
//! other reader of a receipt. What is here is what the worker does with the answer.

use kr_protocol::action::ActionObservation;
use kr_protocol::receipt::ReceiptState;

/// What recording an observation does to an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The observation is recorded beside the receipt, which does not move.
    Recorded,
    /// The observation is recorded and the receipt is reconciled to this state.
    ///
    /// The only reconciliation the receipt contract has: an uncertain outcome, resolved by an
    /// authoritative answer, into applied or refused.
    Reconciled(ReceiptState),
}

impl Effect {
    /// Returns the state the receipt moves to, when it moves.
    #[must_use]
    pub const fn reconciliation(self) -> Option<ReceiptState> {
        match self {
            Self::Recorded => None,
            Self::Reconciled(state) => Some(state),
        }
    }
}

/// Decides what an observation does to an action in a given state.
#[must_use]
pub fn effect(observation: &ActionObservation, current: ReceiptState) -> Effect {
    match observation.resolution(current) {
        Some(state) => Effect::Reconciled(state),
        None => Effect::Recorded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::action::{ObservationProvenance, ObservedResult};
    use kr_protocol::ids::ActionId;
    use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

    fn observation(
        provenance: ObservationProvenance,
        claimed_result: ObservedResult,
    ) -> ActionObservation {
        ActionObservation {
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            provenance,
            subject: "agent.approval:upstream-opaque-request-id".to_owned(),
            subject_revision: Nullable::some(U64::new(3)),
            source_cursor: Nullable::some(U64::new(4_096)),
            claimed_result,
            observed_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    #[test]
    fn an_inferred_screen_is_recorded_and_moves_nothing() {
        let screen = observation(
            ObservationProvenance::InferredScreen,
            ObservedResult::Applied,
        );
        assert_eq!(effect(&screen, ReceiptState::Unknown), Effect::Recorded);
        assert_eq!(
            effect(&screen, ReceiptState::Unknown).reconciliation(),
            None,
            "an uncertain outcome stays uncertain"
        );
    }

    #[test]
    fn an_authoritative_answer_reconciles_an_uncertain_outcome() {
        let applied = observation(
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Applied,
        );
        assert_eq!(
            effect(&applied, ReceiptState::Unknown),
            Effect::Reconciled(ReceiptState::Applied)
        );
        let refused = observation(
            ObservationProvenance::UpstreamCorrelation,
            ObservedResult::Refused,
        );
        assert_eq!(
            effect(&refused, ReceiptState::Unknown),
            Effect::Reconciled(ReceiptState::Refused)
        );
    }

    #[test]
    fn an_observation_of_a_settled_action_is_recorded_and_moves_nothing() {
        let applied = observation(
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Refused,
        );
        for state in [
            ReceiptState::Accepted,
            ReceiptState::Dispatching,
            ReceiptState::Applied,
            ReceiptState::Refused,
            ReceiptState::Rejected,
        ] {
            assert_eq!(effect(&applied, state), Effect::Recorded, "{state}");
        }
    }

    #[test]
    fn every_reconciliation_is_an_edge_the_receipt_contract_permits() {
        for provenance in ObservationProvenance::ALL {
            for claimed in [
                ObservedResult::Applied,
                ObservedResult::Refused,
                ObservedResult::Indeterminate,
            ] {
                let observation = observation(*provenance, claimed);
                for state in ReceiptState::ALL.iter().copied() {
                    if let Some(next) = effect(&observation, state).reconciliation() {
                        assert!(state.can_transition_to(next), "{state} to {next}");
                    }
                }
            }
        }
    }
}
