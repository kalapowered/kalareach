//! The bounded visibility predicate grammar.
//!
//! A control states when it is visible as a predicate over facts the host already knows. Section
//! 11 requires a bounded declarative grammar and never a script, for two reasons that matter
//! equally: the host rechecks visibility on invocation, so evaluation must be cheap and total;
//! and a reviewer reads a predicate to decide whether a package is honest about when it appears.
//!
//! The grammar has no variables, no arithmetic, no string matching and no user-supplied text. It
//! is a boolean combination of facts drawn from closed vocabularies, bounded to
//! [`MAX_PREDICATE_DEPTH`] levels and [`MAX_PREDICATE_TERMS`] terms per combinator. Evaluation
//! terminates on every input, which is what makes rechecking on invocation affordable.

use kr_protocol::rights::ActionRight;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityState, PluginCapability};
use crate::ids::NodeId;

/// Maximum nesting depth of a predicate.
pub const MAX_PREDICATE_DEPTH: usize = 4;

/// Maximum number of terms one `all` or `any` may combine.
pub const MAX_PREDICATE_TERMS: usize = 8;

/// The state of the binding a control belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    /// The package matched an application and is instantiated.
    Bound,
    /// The bound upstream execution is running a turn.
    UpstreamBusy,
    /// The bound upstream execution is waiting for a person.
    AwaitingPerson,
    /// The binding is disabled after repeated faults.
    Disabled,
    /// The host is answering native requests without durable receipt storage.
    ///
    /// Rich response controls are hidden in this state. The predicate can say so, which is
    /// clearer to a reader than a control that silently stops working.
    NativeOnlyVolatile,
}

/// A fact about the current presentation that a control can depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PresentationFlag {
    /// A pending approval resource exists in the ledger.
    PendingApproval,
    /// The upstream draft has text in it.
    DraftNotEmpty,
    /// The client is a small screen.
    CompactLayout,
    /// The session has an attachment upload in progress.
    TransferInProgress,
    /// The person holds the input lease.
    HoldsInputLease,
}

/// One term of a visibility predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    /// Always visible.
    Always {},
    /// Never visible.
    Never {},
    /// True when the inner predicate is false.
    Not {
        /// The inner predicate.
        term: Box<Predicate>,
    },
    /// True when every term is true.
    All {
        /// The terms.
        terms: Vec<Predicate>,
    },
    /// True when at least one term is true.
    Any {
        /// The terms.
        terms: Vec<Predicate>,
    },
    /// True when the named capability is in the named state.
    Capability {
        /// The capability.
        capability: PluginCapability,
        /// The state it must be in.
        state: CapabilityState,
    },
    /// True when the actor currently holds the named right.
    ///
    /// This hides a control the actor could not use. It never grants anything: the host checks
    /// the right again at dispatch, and a predicate that lies only makes a control appear that
    /// then fails the check.
    Grant {
        /// The right.
        right: ActionRight,
    },
    /// True when the binding is in the named state.
    Binding {
        /// The state.
        state: BindingState,
    },
    /// True when the named node is present in the current document.
    NodePresent {
        /// The node.
        node_id: NodeId,
    },
    /// True when the named presentation fact holds.
    Flag {
        /// The fact.
        flag: PresentationFlag,
    },
}

/// Why a predicate is not a valid visibility rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PredicateError {
    /// The predicate nested deeper than [`MAX_PREDICATE_DEPTH`].
    #[error("the predicate nests {depth} levels, over the {MAX_PREDICATE_DEPTH} level limit")]
    TooDeep {
        /// The observed depth.
        depth: usize,
    },
    /// A combinator had more than [`MAX_PREDICATE_TERMS`] terms.
    #[error("a combinator has {count} terms, over the {MAX_PREDICATE_TERMS} term limit")]
    TooManyTerms {
        /// The observed term count.
        count: usize,
    },
    /// A combinator had no terms at all.
    #[error("an 'all' or 'any' with no terms has no meaning; use 'always' or 'never'")]
    EmptyCombinator,
}

impl Predicate {
    /// Checks the depth and width bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PredicateError`] when the predicate nests too deeply, combines too many terms, or
    /// combines none.
    pub fn validate(&self) -> Result<(), PredicateError> {
        self.check(1)
    }

    fn check(&self, depth: usize) -> Result<(), PredicateError> {
        if depth > MAX_PREDICATE_DEPTH {
            return Err(PredicateError::TooDeep { depth });
        }
        match self {
            Self::Not { term } => term.check(depth + 1),
            Self::All { terms } | Self::Any { terms } => {
                if terms.is_empty() {
                    return Err(PredicateError::EmptyCombinator);
                }
                if terms.len() > MAX_PREDICATE_TERMS {
                    return Err(PredicateError::TooManyTerms { count: terms.len() });
                }
                for term in terms {
                    term.check(depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Returns the nesting depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Not { term } => 1 + term.depth(),
            Self::All { terms } | Self::Any { terms } => {
                1 + terms.iter().map(Self::depth).max().unwrap_or(0)
            }
            _ => 1,
        }
    }

    /// Evaluates the predicate against what the host currently knows.
    ///
    /// Evaluation is total: every predicate returns a decision for every context, and an unknown
    /// fact is false rather than an error, so a control whose condition cannot be established is
    /// hidden rather than shown.
    #[must_use]
    pub fn evaluate(&self, context: &PredicateContext<'_>) -> bool {
        match self {
            Self::Always {} => true,
            Self::Never {} => false,
            Self::Not { term } => !term.evaluate(context),
            Self::All { terms } => terms.iter().all(|term| term.evaluate(context)),
            Self::Any { terms } => terms.iter().any(|term| term.evaluate(context)),
            Self::Capability { capability, state } => context
                .capability_states
                .iter()
                .any(|(name, current)| name == capability && current == state),
            Self::Grant { right } => context.rights.contains(right),
            Self::Binding { state } => context.binding_state == *state,
            Self::NodePresent { node_id } => context.present_nodes.contains(node_id),
            Self::Flag { flag } => context.flags.contains(flag),
        }
    }
}

/// What the host knows when it evaluates a visibility predicate.
#[derive(Clone, Copy, Debug)]
pub struct PredicateContext<'a> {
    /// The current state of each capability the host has evidence for.
    pub capability_states: &'a [(PluginCapability, CapabilityState)],
    /// The rights the actor currently holds.
    pub rights: &'a [ActionRight],
    /// The binding's current state.
    pub binding_state: BindingState,
    /// The nodes present in the current document.
    pub present_nodes: &'a [NodeId],
    /// The presentation facts that currently hold.
    pub flags: &'a [PresentationFlag],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(
        rights: &'a [ActionRight],
        binding_state: BindingState,
        flags: &'a [PresentationFlag],
    ) -> PredicateContext<'a> {
        PredicateContext {
            capability_states: &[],
            rights,
            binding_state,
            present_nodes: &[],
            flags,
        }
    }

    #[test]
    fn a_predicate_is_a_boolean_combination_of_known_facts() {
        let predicate = Predicate::All {
            terms: vec![
                Predicate::Grant {
                    right: ActionRight::AgentPrompt,
                },
                Predicate::Not {
                    term: Box::new(Predicate::Binding {
                        state: BindingState::Disabled,
                    }),
                },
                Predicate::Flag {
                    flag: PresentationFlag::DraftNotEmpty,
                },
            ],
        };
        assert_eq!(predicate.validate(), Ok(()));
        assert!(predicate.evaluate(&context(
            &[ActionRight::AgentPrompt],
            BindingState::Bound,
            &[PresentationFlag::DraftNotEmpty],
        )));
        assert!(!predicate.evaluate(&context(
            &[ActionRight::AgentPrompt],
            BindingState::Disabled,
            &[PresentationFlag::DraftNotEmpty],
        )));
        assert!(!predicate.evaluate(&context(
            &[],
            BindingState::Bound,
            &[PresentationFlag::DraftNotEmpty]
        )));
    }

    #[test]
    fn depth_and_width_are_bounded() {
        let mut predicate = Predicate::Always {};
        for _ in 0..MAX_PREDICATE_DEPTH {
            predicate = Predicate::Not {
                term: Box::new(predicate),
            };
        }
        assert!(matches!(
            predicate.validate(),
            Err(PredicateError::TooDeep { .. })
        ));

        let wide = Predicate::Any {
            terms: vec![Predicate::Always {}; MAX_PREDICATE_TERMS + 1],
        };
        assert_eq!(
            wide.validate(),
            Err(PredicateError::TooManyTerms {
                count: MAX_PREDICATE_TERMS + 1
            })
        );

        assert_eq!(
            Predicate::All { terms: Vec::new() }.validate(),
            Err(PredicateError::EmptyCombinator)
        );
    }

    #[test]
    fn the_grammar_has_no_script_form() {
        // A script, an expression string or a regular expression is not representable: every
        // variant is a fixed shape over a closed vocabulary. The closest a manifest can come is a
        // JSON object with an unknown `op`, which serde rejects.
        let attempt = serde_json::json!({"op": "eval", "source": "1 == 1"});
        assert!(serde_json::from_value::<Predicate>(attempt).is_err());
        let with_extra = serde_json::json!({"op": "always", "source": "1 == 1"});
        assert!(serde_json::from_value::<Predicate>(with_extra).is_err());
    }

    #[test]
    fn evaluation_is_total_over_unknown_facts() {
        let predicate = Predicate::Capability {
            capability: PluginCapability::ApprovalRespond,
            state: CapabilityState::QualifiedAvailable,
        };
        assert!(!predicate.evaluate(&context(&[], BindingState::Bound, &[])));
    }
}
