//! Deciding what a client shows, and what it lets a person invoke.
//!
//! Section 11: controls carry stable identifiers and revisions, labels, standard icons, accessible
//! descriptions, registered action identifiers, parameter schemas, semantic priority and disabled
//! reasons. Visibility uses a bounded declarative predicate grammar, never scripts. Clients render
//! standard components; packages cannot inject JavaScript, CSS, React or arbitrary WebViews. An
//! unknown node renders an unsupported-content block and cannot invoke a hidden action. The host
//! rechecks conditions on invocation.
//!
//! The document union, the control model and the predicate grammar are the package contract's, in
//! `kr-plugin-sdk`. What is here is the client's half of the same contract:
//!
//! * [`read_document`] turns what arrived into things this build can draw, and anything it cannot
//!   read into an [`kr_plugin_sdk::presentation::UnsupportedNode`] that carries no control;
//! * [`visibility`] decides whether a control is shown, from what this client actually knows;
//! * [`invoke`] produces the invocation, carrying the control's revision so the host can recheck.
//!
//! # Why the evaluation here is not the host's
//!
//! `kr_plugin_sdk::predicate::Predicate::evaluate` is total: every fact it has no evidence for is
//! false. That is right for a host, which knows everything a predicate can ask about. A client does
//! not: it may have a document and no lease state, or a binding whose capabilities it has not been
//! told. Treating what it does not know as false would be a guess, and under a `not` the guess
//! *shows* a control the package meant to hide. So this evaluation has three answers rather than
//! two, and a control whose visibility turns on something this client cannot see is hidden and says
//! which fact it was.
//!
//! Hiding is a courtesy either way. The host rechecks the condition and the actor's rights when the
//! action arrives, so a control that appears when it should not is a control that then fails.

use kr_plugin_sdk::capability::{CapabilityState, PluginCapability};
use kr_plugin_sdk::effect::ActionRight;
use kr_plugin_sdk::ids::{ActionName, ControlId, NodeId};
use kr_plugin_sdk::predicate::{BindingState, Predicate, PredicateError, PresentationFlag};
use kr_plugin_sdk::presentation::{
    Control, DocumentNode, NodeRevision, UnsupportedNode, read_node,
};
use kr_protocol::ids::ApprovalRequestId;

/// What a client knows about the facts a visibility predicate can name.
///
/// Absent is not false. A client that has not been told whether the person holds the input lease
/// does not know, and a predicate that turns on it is hidden rather than guessed at.
///
/// Rights, present nodes and pending approvals are supplied as whole sets, because a client that
/// has them has all of them: the question is whether it was told at all, which is what the option
/// answers.
#[derive(Clone, Debug, Default)]
pub struct ControlState {
    capabilities: Vec<(PluginCapability, CapabilityState)>,
    rights: Option<Vec<ActionRight>>,
    binding_state: Option<BindingState>,
    present_nodes: Option<Vec<NodeId>>,
    flags: Vec<(PresentationFlag, bool)>,
    pending_approvals: Option<Vec<ApprovalRequestId>>,
}

impl ControlState {
    /// A state that knows nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the state of one capability.
    #[must_use]
    pub fn with_capability(mut self, capability: PluginCapability, state: CapabilityState) -> Self {
        self.capabilities.retain(|(held, _)| *held != capability);
        self.capabilities.push((capability, state));
        self
    }

    /// Records every right the actor holds.
    #[must_use]
    pub fn with_rights(mut self, rights: impl IntoIterator<Item = ActionRight>) -> Self {
        self.rights = Some(rights.into_iter().collect());
        self
    }

    /// Records the binding's state.
    #[must_use]
    pub fn in_binding_state(mut self, state: BindingState) -> Self {
        self.binding_state = Some(state);
        self
    }

    /// Records every node present in the document being rendered.
    #[must_use]
    pub fn with_present_nodes(mut self, nodes: impl IntoIterator<Item = NodeId>) -> Self {
        self.present_nodes = Some(nodes.into_iter().collect());
        self
    }

    /// Records whether one presentation fact holds.
    #[must_use]
    pub fn with_flag(mut self, flag: PresentationFlag, holds: bool) -> Self {
        self.flags.retain(|(held, _)| *held != flag);
        self.flags.push((flag, holds));
        self
    }

    /// Records every approval request pending for the binding, by its upstream identifier.
    #[must_use]
    pub fn with_pending_approvals(
        mut self,
        requests: impl IntoIterator<Item = ApprovalRequestId>,
    ) -> Self {
        self.pending_approvals = Some(requests.into_iter().collect());
        self
    }

    fn capability(&self, capability: PluginCapability, state: CapabilityState) -> Truth {
        self.capabilities
            .iter()
            .find(|(held, _)| *held == capability)
            .map_or(Truth::Unknown, |(_, current)| {
                Truth::from(*current == state)
            })
    }

    fn right(&self, right: ActionRight) -> Truth {
        self.rights
            .as_ref()
            .map_or(Truth::Unknown, |held| Truth::from(held.contains(&right)))
    }

    fn binding(&self, state: BindingState) -> Truth {
        self.binding_state
            .map_or(Truth::Unknown, |current| Truth::from(current == state))
    }

    fn node_present(&self, node_id: &NodeId) -> Truth {
        self.present_nodes
            .as_ref()
            .map_or(Truth::Unknown, |nodes| Truth::from(nodes.contains(node_id)))
    }

    fn flag(&self, flag: PresentationFlag) -> Truth {
        self.flags
            .iter()
            .find(|(held, _)| *held == flag)
            .map_or(Truth::Unknown, |(_, holds)| Truth::from(*holds))
    }

    fn pending_approval(&self, request_id: &ApprovalRequestId) -> Truth {
        self.pending_approvals
            .as_ref()
            .map_or(Truth::Unknown, |pending| {
                Truth::from(pending.contains(request_id))
            })
    }
}

/// A predicate's answer when the client may not know everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Unknown,
}

impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl Truth {
    /// Negation: an unknown fact stays unknown rather than becoming its opposite.
    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Why a control is not shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hidden {
    /// The predicate is false for what this client knows.
    PredicateFalse,
    /// The predicate turns on a fact this client has no value for.
    UnknownFact {
        /// Which fact, so a client can say what it is missing rather than only that it is.
        fact: String,
    },
    /// The predicate is outside the grammar's bounds.
    ///
    /// A predicate that nests too deeply or combines too many terms is not one this contract
    /// admits. The control is hidden and the failure is reported, because a package whose
    /// visibility rule cannot be read is a package whose controls nobody can vouch for.
    OutsideTheGrammar(PredicateError),
}

impl core::fmt::Display for Hidden {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PredicateFalse => formatter.write_str("its condition is not met"),
            Self::UnknownFact { fact } => {
                write!(formatter, "this client does not know {fact}")
            }
            Self::OutsideTheGrammar(error) => {
                write!(formatter, "its condition is not a valid one: {error}")
            }
        }
    }
}

/// Whether a control is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// It is shown.
    Shown,
    /// It is not shown, for this reason.
    Hidden(Hidden),
}

impl Visibility {
    /// Returns true when the control is shown.
    #[must_use]
    pub const fn is_shown(&self) -> bool {
        matches!(self, Self::Shown)
    }

    /// Returns why it is hidden, when it is.
    #[must_use]
    pub const fn hidden(&self) -> Option<&Hidden> {
        match self {
            Self::Hidden(reason) => Some(reason),
            Self::Shown => None,
        }
    }
}

/// Evaluates one predicate against what this client knows.
///
/// The bounds are checked first, so a predicate outside the grammar is reported rather than walked.
#[must_use]
pub fn evaluate(predicate: &Predicate, state: &ControlState) -> Visibility {
    if let Err(error) = predicate.validate() {
        return Visibility::Hidden(Hidden::OutsideTheGrammar(error));
    }
    match truth(predicate, state) {
        Truth::True => Visibility::Shown,
        Truth::False => Visibility::Hidden(Hidden::PredicateFalse),
        Truth::Unknown => Visibility::Hidden(Hidden::UnknownFact {
            fact: unknown_fact(predicate, state).unwrap_or_else(|| "one of its facts".to_owned()),
        }),
    }
}

/// Returns whether a control is shown.
#[must_use]
pub fn visibility(control: &Control, state: &ControlState) -> Visibility {
    evaluate(&control.visible_when, state)
}

fn truth(predicate: &Predicate, state: &ControlState) -> Truth {
    match predicate {
        Predicate::Always {} => Truth::True,
        Predicate::Never {} => Truth::False,
        Predicate::Not { term } => truth(term, state).not(),
        // A false term settles an `all` and a true term settles an `any`, whatever the client does
        // not know about the rest. Only a combination that turns on the unknown is unknown.
        Predicate::All { terms } => {
            let mut answer = Truth::True;
            for term in terms {
                match truth(term, state) {
                    Truth::False => return Truth::False,
                    Truth::Unknown => answer = Truth::Unknown,
                    Truth::True => {}
                }
            }
            answer
        }
        Predicate::Any { terms } => {
            let mut answer = Truth::False;
            for term in terms {
                match truth(term, state) {
                    Truth::True => return Truth::True,
                    Truth::Unknown => answer = Truth::Unknown,
                    Truth::False => {}
                }
            }
            answer
        }
        Predicate::Capability {
            capability,
            state: wanted,
        } => state.capability(*capability, *wanted),
        Predicate::Grant { right } => state.right(*right),
        Predicate::Binding { state: wanted } => state.binding(*wanted),
        Predicate::NodePresent { node_id } => state.node_present(node_id),
        Predicate::Flag { flag } => state.flag(*flag),
        Predicate::PendingApprovalFor { request_id } => state.pending_approval(request_id),
    }
}

/// Names the first fact the client has no value for *that the answer turned on*.
///
/// Only a branch whose own truth is unknown is followed. A branch a known term already settled can
/// still contain an unknown leaf, and naming that leaf would tell a person the control is waiting on
/// something it is not waiting on.
fn unknown_fact(predicate: &Predicate, state: &ControlState) -> Option<String> {
    match predicate {
        Predicate::Always {} | Predicate::Never {} => None,
        Predicate::Not { term } => unknown_fact(term, state),
        Predicate::All { terms } | Predicate::Any { terms } => terms
            .iter()
            .filter(|term| truth(term, state) == Truth::Unknown)
            .find_map(|term| unknown_fact(term, state)),
        Predicate::Capability { capability, .. } => (state
            .capabilities
            .iter()
            .all(|(held, _)| held != capability))
        .then(|| format!("the state of the {capability:?} capability")),
        Predicate::Grant { right } => state
            .rights
            .is_none()
            .then(|| format!("whether the actor holds {right:?}")),
        Predicate::Binding { .. } => state
            .binding_state
            .is_none()
            .then(|| "the binding's state".to_owned()),
        Predicate::NodePresent { node_id } => state
            .present_nodes
            .is_none()
            .then(|| format!("whether node {node_id} is present")),
        Predicate::Flag { flag } => (state.flags.iter().all(|(held, _)| held != flag))
            .then(|| format!("whether {flag:?} holds")),
        Predicate::PendingApprovalFor { request_id } => state
            .pending_approvals
            .is_none()
            .then(|| format!("whether approval request {request_id} is pending")),
    }
}

/// What a person's press becomes.
///
/// It carries the control's revision, which is what lets the host recheck the condition against the
/// control the person actually saw rather than against whatever the package has published since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The control that was pressed.
    pub control_id: ControlId,
    /// The revision of the control the person saw.
    pub control_revision: NodeRevision,
    /// The registered action it names.
    pub action_id: ActionName,
}

/// Why a control cannot be invoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotInvocable {
    /// It is not shown, so there was nothing to press.
    Hidden(Hidden),
    /// It is shown and not usable.
    Disabled {
        /// Why the predicate did not hold.
        because: Hidden,
        /// The reason the package gives a person, when it gave one.
        reason: Option<String>,
    },
}

impl core::fmt::Display for NotInvocable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hidden(reason) => write!(formatter, "the control is not shown: {reason}"),
            Self::Disabled { because, reason } => match reason {
                Some(reason) => write!(formatter, "the control is disabled: {reason}"),
                None => write!(formatter, "the control is disabled: {because}"),
            },
        }
    }
}

/// Builds the invocation a person's press produces.
///
/// A hidden control produces nothing: section 11 says an unknown node cannot invoke a hidden
/// action, and the same holds for a control this client decided not to draw. A disabled one
/// produces nothing either, and says what the package gave as the reason.
///
/// # Errors
///
/// Returns [`NotInvocable`] when the control is hidden or disabled.
pub fn invoke(
    control: &Control,
    state: &ControlState,
) -> std::result::Result<Invocation, NotInvocable> {
    if let Visibility::Hidden(reason) = visibility(control, state) {
        return Err(NotInvocable::Hidden(reason));
    }
    if let Visibility::Hidden(because) = evaluate(&control.enabled_when, state) {
        return Err(NotInvocable::Disabled {
            because,
            reason: control
                .disabled_reason
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
        });
    }
    Ok(Invocation {
        control_id: control.id.clone(),
        control_revision: control.revision,
        action_id: control.action_id.clone(),
    })
}

/// One thing a client draws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rendered {
    /// A node this build knows, drawn with the client's own standard components.
    Node(Box<DocumentNode>),
    /// A node this build does not know, drawn as an unsupported-content block.
    Unsupported(UnsupportedNode),
}

impl Rendered {
    /// Returns the controls this thing offers.
    ///
    /// An unsupported block offers none. That is the whole of section 11's rule: a newer package
    /// cannot reach an action through a node an older client cannot read, because the node it could
    /// not read carries nothing to invoke.
    #[must_use]
    pub fn controls(&self) -> &[Control] {
        match self {
            Self::Node(node) => node.body.controls(),
            Self::Unsupported(_) => &[],
        }
    }

    /// Returns true when this is an unsupported-content block.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }
}

/// Reads a document, turning anything this build cannot read into an unsupported-content block.
///
/// One node a client does not know never discards the document around it, and never becomes an
/// error a person sees instead of their conversation.
#[must_use]
pub fn read_document(nodes: &[serde_json::Value]) -> Vec<Rendered> {
    nodes
        .iter()
        .map(|value| match read_node(value) {
            Ok(node) => Rendered::Node(Box::new(node)),
            Err(unsupported) => Rendered::Unsupported(unsupported),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::effect::ParameterSchema;
    use kr_plugin_sdk::presentation::{SemanticPriority, StandardIcon};
    use kr_plugin_sdk::text::{AccessibleDescription, Label};
    use kr_protocol::scalars::{Nullable, U64};

    fn control(visible_when: Predicate, enabled_when: Predicate) -> Control {
        Control {
            id: ControlId::new("send").expect("a literal identifier"),
            revision: U64::new(7),
            label: Label::new("Send").expect("a literal label"),
            icon: StandardIcon::Play,
            accessible_description: AccessibleDescription::new("Send the draft")
                .expect("a literal description"),
            action_id: ActionName::new("prompt.send").expect("a literal action name"),
            parameters: ParameterSchema::default(),
            priority: SemanticPriority::Primary,
            visible_when,
            enabled_when,
            disabled_reason: Nullable::null(),
        }
    }

    #[test]
    fn a_predicate_is_a_predicate_and_never_a_script() {
        // Anything that is not one of the grammar's terms is not a predicate. A string that looks
        // like an expression is a string, and a document carrying one does not parse at all.
        for text in [
            "\"state.draft_not_empty == true\"",
            "\"() => true\"",
            "{\"op\":\"eval\",\"source\":\"1\"}",
            "{\"op\":\"flag\",\"flag\":\"draft_not_empty\",\"script\":\"alert(1)\"}",
            "{\"op\":\"always\",\"then\":\"<script>\"}",
            "{\"javascript\":\"true\"}",
            "true",
            "1",
        ] {
            assert!(
                serde_json::from_str::<Predicate>(text).is_err(),
                "{text} parsed as a predicate"
            );
        }
        // The grammar's own terms do parse, so the refusals above are about the grammar rather
        // than about the parser refusing everything.
        assert_eq!(
            serde_json::from_str::<Predicate>("{\"op\":\"always\"}").expect("a predicate"),
            Predicate::Always {}
        );
    }

    #[test]
    fn a_predicate_outside_the_bounds_hides_the_control_and_says_so() {
        // Deeper than the grammar admits.
        let mut deep = Predicate::Always {};
        for _ in 0..8 {
            deep = Predicate::Not {
                term: Box::new(deep),
            };
        }
        let hidden = evaluate(&deep, &ControlState::new());
        assert!(matches!(
            hidden.hidden(),
            Some(Hidden::OutsideTheGrammar(PredicateError::TooDeep { .. }))
        ));

        // Wider than the grammar admits.
        let wide = Predicate::Any {
            terms: vec![Predicate::Always {}; 32],
        };
        assert!(matches!(
            evaluate(&wide, &ControlState::new()).hidden(),
            Some(Hidden::OutsideTheGrammar(
                PredicateError::TooManyTerms { .. }
            ))
        ));

        // A combinator with nothing in it means nothing.
        assert!(matches!(
            evaluate(&Predicate::All { terms: Vec::new() }, &ControlState::new()).hidden(),
            Some(Hidden::OutsideTheGrammar(PredicateError::EmptyCombinator))
        ));

        // Exactly at the depth bound is inside it, and one level past is not. The grammar admits
        // four levels, so the deepest legal shape nests three combinators over a leaf.
        // Wrapped rather than negated, so the nesting is what is under test rather than the
        // parity of the negations.
        let nested = |levels: usize| {
            let mut predicate = Predicate::Always {};
            for _ in 0..levels {
                predicate = Predicate::All {
                    terms: vec![predicate],
                };
            }
            predicate
        };
        assert_eq!(nested(3).depth(), 4);
        assert_eq!(
            evaluate(&nested(3), &ControlState::new()),
            Visibility::Shown
        );
        assert_eq!(nested(4).depth(), 5);
        assert!(matches!(
            evaluate(&nested(4), &ControlState::new()).hidden(),
            Some(Hidden::OutsideTheGrammar(PredicateError::TooDeep { .. }))
        ));

        // Exactly at the width bound is inside it.
        let at_the_limit = Predicate::All {
            terms: vec![
                Predicate::Any {
                    terms: vec![Predicate::Always {}; 8],
                };
                8
            ],
        };
        assert_eq!(
            evaluate(&at_the_limit, &ControlState::new()),
            Visibility::Shown
        );

        // The bounds are checked before the truth, so a predicate a term would have settled as
        // false is still reported as outside the grammar. A package whose visibility rule cannot
        // be read is not one whose controls are hidden for an ordinary reason.
        let false_and_over_budget = Predicate::All {
            terms: vec![Predicate::Never {}; 32],
        };
        assert!(matches!(
            evaluate(&false_and_over_budget, &ControlState::new()).hidden(),
            Some(Hidden::OutsideTheGrammar(
                PredicateError::TooManyTerms { .. }
            ))
        ));
    }

    #[test]
    fn the_fact_a_control_is_waiting_on_is_the_one_the_answer_turned_on() {
        // `never` settles the first branch, so the unknown inside it is not what this control is
        // waiting for. What it is waiting for is the second branch.
        let predicate = Predicate::Any {
            terms: vec![
                Predicate::All {
                    terms: vec![
                        Predicate::Never {},
                        Predicate::Flag {
                            flag: PresentationFlag::HoldsInputLease,
                        },
                    ],
                },
                Predicate::Flag {
                    flag: PresentationFlag::DraftNotEmpty,
                },
            ],
        };
        let hidden = evaluate(&predicate, &ControlState::new());
        let Some(Hidden::UnknownFact { fact }) = hidden.hidden() else {
            panic!("the answer turned on something the client does not know: {hidden:?}");
        };
        assert!(fact.contains("DraftNotEmpty"), "{fact}");
        assert!(!fact.contains("HoldsInputLease"), "{fact}");
    }

    #[test]
    fn a_fact_this_client_does_not_know_hides_the_control_rather_than_guessing() {
        let state = ControlState::new();
        let hidden = evaluate(
            &Predicate::Flag {
                flag: PresentationFlag::HoldsInputLease,
            },
            &state,
        );
        assert!(matches!(hidden.hidden(), Some(Hidden::UnknownFact { .. })));
        assert!(
            hidden
                .hidden()
                .expect("hidden")
                .to_string()
                .contains("know")
        );

        // Negating an unknown fact does not turn it into a shown control, which is the whole point
        // of not guessing: `not(unknown)` would otherwise show what the package meant to hide.
        let negated = evaluate(
            &Predicate::Not {
                term: Box::new(Predicate::Flag {
                    flag: PresentationFlag::HoldsInputLease,
                }),
            },
            &state,
        );
        assert!(matches!(negated.hidden(), Some(Hidden::UnknownFact { .. })));

        // Told the fact, it decides.
        let told = ControlState::new().with_flag(PresentationFlag::HoldsInputLease, true);
        assert_eq!(
            evaluate(
                &Predicate::Flag {
                    flag: PresentationFlag::HoldsInputLease
                },
                &told
            ),
            Visibility::Shown
        );
        assert_eq!(
            evaluate(
                &Predicate::Flag {
                    flag: PresentationFlag::HoldsInputLease
                },
                &ControlState::new().with_flag(PresentationFlag::HoldsInputLease, false)
            ),
            Visibility::Hidden(Hidden::PredicateFalse)
        );
    }

    /// KR-REQ-11.46: a control drawn for one approval request is shown while the client knows
    /// that request is pending, hidden once only another one is, and hidden as unknown, with the
    /// fact named, when the client was never told which requests are pending.
    #[test]
    fn a_control_for_one_approval_request_follows_that_request() {
        let request =
            |text: &str| ApprovalRequestId::new(text).expect("a valid request identifier");
        let for_one = Predicate::PendingApprovalFor {
            request_id: request("abcde"),
        };

        let untold = evaluate(&for_one, &ControlState::new());
        let Some(Hidden::UnknownFact { fact }) = untold.hidden() else {
            panic!("an untold pending set is not a guess: {untold:?}");
        };
        assert!(fact.contains("abcde"), "{fact}");
        // Negated, it stays unknown rather than showing the control.
        assert!(matches!(
            evaluate(
                &Predicate::Not {
                    term: Box::new(for_one.clone())
                },
                &ControlState::new()
            )
            .hidden(),
            Some(Hidden::UnknownFact { .. })
        ));

        let waiting = ControlState::new()
            .with_flag(PresentationFlag::PendingApproval, true)
            .with_pending_approvals([request("abcde"), request("fghij")]);
        assert_eq!(evaluate(&for_one, &waiting), Visibility::Shown);

        // Another request is still waiting, so the untargeted flag holds; this one is not.
        let answered = ControlState::new()
            .with_flag(PresentationFlag::PendingApproval, true)
            .with_pending_approvals([request("fghij")]);
        assert_eq!(
            evaluate(&for_one, &answered),
            Visibility::Hidden(Hidden::PredicateFalse)
        );
        assert_eq!(
            evaluate(
                &Predicate::Flag {
                    flag: PresentationFlag::PendingApproval
                },
                &answered
            ),
            Visibility::Shown
        );

        // Told that nothing is pending is knowing, not an unknown.
        assert_eq!(
            evaluate(&for_one, &ControlState::new().with_pending_approvals([])),
            Visibility::Hidden(Hidden::PredicateFalse)
        );
    }

    #[test]
    fn what_is_known_settles_a_combination_without_the_rest() {
        let state = ControlState::new().with_flag(PresentationFlag::CompactLayout, false);
        // One false term settles an `all`, whatever else the client cannot see.
        assert_eq!(
            evaluate(
                &Predicate::All {
                    terms: vec![
                        Predicate::Flag {
                            flag: PresentationFlag::CompactLayout
                        },
                        Predicate::Flag {
                            flag: PresentationFlag::HoldsInputLease
                        },
                    ]
                },
                &state
            ),
            Visibility::Hidden(Hidden::PredicateFalse)
        );
        // One true term settles an `any`.
        let told = ControlState::new().with_flag(PresentationFlag::CompactLayout, true);
        assert_eq!(
            evaluate(
                &Predicate::Any {
                    terms: vec![
                        Predicate::Flag {
                            flag: PresentationFlag::CompactLayout
                        },
                        Predicate::Flag {
                            flag: PresentationFlag::HoldsInputLease
                        },
                    ]
                },
                &told
            ),
            Visibility::Shown
        );
    }

    #[test]
    fn an_invocation_carries_the_revision_and_a_hidden_control_produces_none() {
        let state = ControlState::new().with_flag(PresentationFlag::DraftNotEmpty, true);
        let shown = control(
            Predicate::Flag {
                flag: PresentationFlag::DraftNotEmpty,
            },
            Predicate::Always {},
        );
        let invocation = invoke(&shown, &state).expect("a press");
        assert_eq!(invocation.control_revision, shown.revision);
        assert_eq!(invocation.control_id, shown.id);
        assert_eq!(invocation.action_id, shown.action_id);

        // Hidden: nothing to press, so nothing is produced. The host rechecks anyway, which is what
        // makes this a client-side courtesy rather than the check.
        let hidden = control(Predicate::Never {}, Predicate::Always {});
        assert!(matches!(
            invoke(&hidden, &state),
            Err(NotInvocable::Hidden(Hidden::PredicateFalse))
        ));

        // Shown and disabled: the package's own reason is what a person is told.
        let disabled = Control {
            enabled_when: Predicate::Never {},
            disabled_reason: Nullable::some(
                kr_plugin_sdk::text::DisabledReason::new("The agent is busy")
                    .expect("a literal reason"),
            ),
            ..shown
        };
        let refusal = invoke(&disabled, &state).expect_err("a disabled control");
        assert!(refusal.to_string().contains("The agent is busy"));
    }

    #[test]
    fn a_node_this_build_cannot_read_becomes_a_block_that_carries_no_action() {
        let known = serde_json::json!({
            "id": "greeting",
            "revision": "1",
            "body": { "kind": "markdown", "source": "Hello." }
        });
        // Every shape a package might reach for to get code or markup onto a screen.
        let injected = [
            serde_json::json!({
                "id": "script",
                "revision": "1",
                "body": { "kind": "script", "source": "alert(1)" }
            }),
            serde_json::json!({
                "id": "style",
                "revision": "1",
                "body": { "kind": "css", "stylesheet": "body{display:none}" }
            }),
            serde_json::json!({
                "id": "react",
                "revision": "1",
                "body": { "kind": "react_component", "module": "./evil.js" }
            }),
            serde_json::json!({
                "id": "webview",
                "revision": "1",
                "body": { "kind": "webview", "url": "https://example.invalid" }
            }),
            serde_json::json!({
                "id": "html",
                "revision": "1",
                "body": { "kind": "html", "html": "<script>alert(1)</script>" }
            }),
        ];

        let mut document = vec![known];
        document.extend(injected);
        let rendered = read_document(&document);
        assert_eq!(rendered.len(), 6);
        assert!(!rendered[0].is_unsupported(), "a known node still reads");

        for block in &rendered[1..] {
            let Rendered::Unsupported(unsupported) = block else {
                panic!("a kind this build does not know was rendered: {block:?}");
            };
            // The block names the kind so a person is told what is missing, and carries nothing
            // else: no source, no stylesheet, no module, no address, no markup.
            assert!(!unsupported.kind.is_empty());
            assert!(block.controls().is_empty());
            assert!(unsupported.action_ids().is_empty());
            let encoded = serde_json::to_string(unsupported).expect("an unsupported block");
            for smuggled in [
                "alert(1)",
                "display:none",
                "./evil.js",
                "example.invalid",
                "<script>",
            ] {
                assert!(
                    !encoded.contains(smuggled),
                    "{smuggled} survived into {encoded}"
                );
            }
        }
    }

    #[test]
    fn an_invocation_cannot_be_reached_through_a_node_this_build_cannot_read() {
        // A newer package puts a control inside a kind this build does not know. The block that
        // stands in its place offers no control, so there is nothing for `invoke` to be called on.
        let smuggled = serde_json::json!({
            "id": "trojan",
            "revision": "1",
            "body": {
                "kind": "custom_panel",
                "controls": [{
                    "id": "wipe",
                    "revision": "1",
                    "label": "Tidy up",
                    "icon": "play",
                    "accessible_description": "Tidy up",
                    "action_id": "repository.delete",
                    "parameters": { "parameters": [] },
                    "priority": "primary",
                    "visible_when": { "op": "always" },
                    "enabled_when": { "op": "always" },
                    "disabled_reason": null
                }]
            }
        });
        // The same control inside a kind this build does know, so an implementation that simply
        // never found a control anywhere would pass neither half of this test.
        let ordinary = serde_json::json!({
            "id": "buttons",
            "revision": "1",
            "body": {
                "kind": "action_button",
                "control": {
                    "id": "wipe",
                    "revision": "1",
                    "label": "Tidy up",
                    "icon": "play",
                    "accessible_description": "Tidy up",
                    "action_id": "repository.delete",
                    "parameters": { "parameters": [] },
                    "priority": "primary",
                    "visible_when": { "op": "always" },
                    "enabled_when": { "op": "always" },
                    "disabled_reason": null
                }
            }
        });

        let rendered = read_document(&[smuggled, ordinary]);
        assert!(rendered[0].is_unsupported());
        assert!(rendered[0].controls().is_empty());

        assert!(!rendered[1].is_unsupported());
        let controls = rendered[1].controls();
        assert_eq!(controls.len(), 1);
        let invocation = invoke(&controls[0], &ControlState::new()).expect("a press");
        assert_eq!(
            invocation.action_id,
            ActionName::new("repository.delete").expect("a literal action name")
        );
    }
}
