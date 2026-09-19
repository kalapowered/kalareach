//! The action-right vocabulary of section 10.
//!
//! A right is what a grant permits. A capability is what a binding can currently do. The two are
//! never interchangeable: capability evidence never creates authority, and a configuration or role
//! label never short-circuits a rights check.
//!
//! The vocabulary is closed. A method that needs an effect not covered here is denied, not
//! approximated under a neighbouring name.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! action_rights {
    ($($variant:ident => $wire:literal, $doc:literal;)+) => {
        /// One permitted action in a grant.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum ActionRight {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl ActionRight {
            /// Every right in the vocabulary, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Returns the stable wire string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// Returns the right for a wire string.
            #[must_use]
            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($wire => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

action_rights! {
    SessionView => "session.view",
        "Observe a session: metadata, filtered history, snapshots and events.";
    TerminalInput => "terminal.input",
        "Send bytes to the terminal. This effectively exposes the shell user's account.";
    TerminalGeometry => "terminal.geometry",
        "Claim geometry ownership and resize the terminal.";
    TerminalGeometryTransfer => "terminal.geometry.transfer",
        "Hand geometry ownership to another attachment.";
    TerminalPalette => "terminal.palette",
        "Set the terminal palette.";
    AgentPrompt => "agent.prompt",
        "Submit, queue or steer an upstream agent prompt.";
    AgentCancel => "agent.cancel",
        "Cancel the upstream agent's current turn.";
    AgentApprovalRespond => "agent.approval.respond",
        "Answer an upstream agent approval request.";
    QuestionRespond => "question.respond",
        "Answer or cancel an agent-to-user question.";
    FilesRead => "files.read",
        "Read file, diff and change-set content.";
    FilesUpload => "files.upload",
        "Upload attachment bytes into the environment.";
    FilesApplyDiff => "files.apply_diff",
        "Apply or revert a diff against a destination.";
    ProjectCreate => "project.create",
        "Initialise, clone or adopt a source repository.";
    WorkspaceManage => "workspace.manage",
        "Create, remove or materialise a workspace.";
    ChangesetCreate => "changeset.create",
        "Capture an immutable change set.";
    SessionCreate => "session.create",
        "Create a session.";
    SessionRename => "session.rename",
        "Rename a session.";
    SessionClose => "session.close",
        "Close a session.";
    SessionShare => "session.share",
        "Issue, list and revoke grants that share a session.";
    AutomationManage => "automation.manage",
        "Install, enable, pause and run automation definitions.";
    HostManage => "host.manage",
        "Change host configuration: devices, catalogues, plugins and installation state.";
    VoiceUse => "voice.use",
        "Hold a voice session on this host, delegate through it and read its selected context.";
}

/// Ordered by the wire string, so a set of rights encodes in an order a reader can verify from the
/// encoded values alone rather than from this file's declaration order.
impl Ord for ActionRight {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for ActionRight {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ActionRight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A wire string that is not part of the action vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownActionRight;

impl fmt::Display for UnknownActionRight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown action right")
    }
}

impl std::error::Error for UnknownActionRight {}

impl FromStr for ActionRight {
    type Err = UnknownActionRight;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire(value).ok_or(UnknownActionRight)
    }
}

/// The right a grant must carry for one attachment capability.
///
/// Section 8 says an attachment's granted capabilities are the requested ones intersected with the
/// actor's rights, and section 10 says what the rights are. This is that intersection's table, and
/// it lives beside the vocabulary so a right added there has to be decided for the capabilities
/// too rather than defaulting into one.
///
/// A request is not a grant: an attachment identifier is never permission on its own, and asking
/// for a capability the grant does not carry gets an attachment without it rather than a refusal.
#[must_use]
pub const fn attachment_capability_right(
    capability: crate::attachment::AttachmentCapability,
) -> ActionRight {
    use crate::attachment::AttachmentCapability;
    match capability {
        // Observing a session, in either mode, is what `session.view` is: section 23's attachment
        // row is "view for observation", and the mode is a presentation choice rather than a
        // second authority.
        AttachmentCapability::ObserveTerminal | AttachmentCapability::ObserveSemantic => {
            ActionRight::SessionView
        }
        // Holding the input lease and writing input. Section 10 says this effectively exposes the
        // shell user's account, which is why it is never implied by observation.
        AttachmentCapability::Input => ActionRight::TerminalInput,
        // Registering a geometry claim and resizing while owner.
        AttachmentCapability::Geometry => ActionRight::TerminalGeometry,
    }
}

/// Narrows requested attachment capabilities to the ones a set of rights permits.
///
/// This is the host's side of section 8's intersection. It is applied where an attachment is
/// admitted, against the rights of the grant the host has already checked the request against; a
/// caller whose authority is not a grant has none to be narrowed by and keeps what it asked for.
#[must_use]
pub fn permitted_attachment_capabilities(
    requested: &crate::scalars::CanonicalSet<crate::attachment::AttachmentCapability>,
    rights: &crate::scalars::CanonicalSet<ActionRight>,
) -> crate::scalars::CanonicalSet<crate::attachment::AttachmentCapability> {
    requested
        .iter()
        .copied()
        .filter(|capability| rights.contains(&attachment_capability_right(*capability)))
        .collect()
}

#[cfg(test)]
mod attachment_capability_tests {
    use super::{ActionRight, attachment_capability_right, permitted_attachment_capabilities};
    use crate::attachment::AttachmentCapability;
    use crate::scalars::CanonicalSet;

    /// The four default session roles of section 25, as the rights they compile to.
    ///
    /// A role is a way of choosing rights and nothing else: the host decides from the rights, so
    /// these are here as the four grants a person actually issues rather than as a type.
    const VIEWER: &[ActionRight] = &[ActionRight::SessionView];
    const REVIEWER: &[ActionRight] = &[ActionRight::SessionView, ActionRight::FilesRead];
    const CONTROLLER: &[ActionRight] = &[
        ActionRight::SessionView,
        ActionRight::FilesRead,
        ActionRight::TerminalInput,
        ActionRight::TerminalGeometry,
        ActionRight::AgentPrompt,
        ActionRight::AgentCancel,
        ActionRight::AgentApprovalRespond,
        ActionRight::QuestionRespond,
    ];
    const OWNER: &[ActionRight] = &[
        ActionRight::SessionView,
        ActionRight::FilesRead,
        ActionRight::TerminalInput,
        ActionRight::TerminalGeometry,
        ActionRight::TerminalGeometryTransfer,
        ActionRight::TerminalPalette,
        ActionRight::AgentPrompt,
        ActionRight::AgentCancel,
        ActionRight::AgentApprovalRespond,
        ActionRight::QuestionRespond,
        ActionRight::SessionRename,
        ActionRight::SessionClose,
        ActionRight::SessionShare,
    ];

    fn rights(of: &[ActionRight]) -> CanonicalSet<ActionRight> {
        of.iter().copied().collect()
    }

    fn everything() -> CanonicalSet<AttachmentCapability> {
        AttachmentCapability::ALL.iter().copied().collect()
    }

    /// KR-REQ-08.68 and KR-REQ-23.35: every capability against the four roles a person issues.
    #[test]
    fn each_role_receives_the_capabilities_its_rights_carry_and_no_others() {
        for (role, name, expected) in [
            (
                VIEWER,
                "viewer",
                vec![
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::ObserveSemantic,
                ],
            ),
            (
                REVIEWER,
                "reviewer",
                vec![
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::ObserveSemantic,
                ],
            ),
            (CONTROLLER, "controller", AttachmentCapability::ALL.to_vec()),
            (OWNER, "owner", AttachmentCapability::ALL.to_vec()),
        ] {
            let granted = permitted_attachment_capabilities(&everything(), &rights(role));
            let expected: CanonicalSet<AttachmentCapability> = expected.into_iter().collect();
            assert_eq!(
                granted, expected,
                "a {name} grant asking for everything receives what its rights carry"
            );
        }
    }

    /// A request is not a grant, and it is not a floor either: what is asked for bounds the answer.
    #[test]
    fn nothing_is_granted_that_was_not_asked_for() {
        let asked: CanonicalSet<AttachmentCapability> = [AttachmentCapability::ObserveSemantic]
            .into_iter()
            .collect();
        let granted = permitted_attachment_capabilities(&asked, &rights(OWNER));
        assert_eq!(granted, asked, "an owner grant adds nothing to the request");
    }

    /// Capabilities describe feasibility, never authority: an empty grant grants none of them.
    #[test]
    fn a_grant_that_carries_nothing_receives_no_capability() {
        let granted = permitted_attachment_capabilities(&everything(), &CanonicalSet::new());
        assert!(granted.is_empty());
    }

    /// The table itself, written out rather than derived, so a swapped pair is a failure.
    ///
    /// Section 8 gives observation to `session.view`, section 10 gives typing to `terminal.input`
    /// because it exposes the shell user's account, and section 23's attachment row gives claims
    /// and resizing to `terminal.geometry`. Reading the expected right out of the function under
    /// test would let the input and geometry rows be exchanged without a failure.
    const TABLE: [(AttachmentCapability, ActionRight); 4] = [
        (
            AttachmentCapability::ObserveTerminal,
            ActionRight::SessionView,
        ),
        (
            AttachmentCapability::ObserveSemantic,
            ActionRight::SessionView,
        ),
        (AttachmentCapability::Input, ActionRight::TerminalInput),
        (
            AttachmentCapability::Geometry,
            ActionRight::TerminalGeometry,
        ),
    ];

    /// Each capability is decided by exactly one right, and the table covers the whole enumeration.
    #[test]
    fn one_right_decides_each_capability() {
        let listed: Vec<AttachmentCapability> =
            TABLE.iter().map(|(capability, _)| *capability).collect();
        assert_eq!(
            listed,
            AttachmentCapability::ALL.to_vec(),
            "the table covers every capability, in the enumeration's own order"
        );
        for (capability, right) in TABLE {
            assert_eq!(
                attachment_capability_right(capability),
                right,
                "{} is carried by {}",
                capability.as_str(),
                right.as_str()
            );
            let asked: CanonicalSet<AttachmentCapability> = [capability].into_iter().collect();
            assert_eq!(
                permitted_attachment_capabilities(&asked, &rights(&[right])),
                asked,
                "and that right on its own carries it"
            );
            // And every other right on its own carries none of it.
            for other in ActionRight::ALL {
                if *other == right {
                    continue;
                }
                assert!(
                    permitted_attachment_capabilities(&asked, &rights(&[*other])).is_empty(),
                    "{} does not carry {}",
                    other.as_str(),
                    capability.as_str()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 10 lists the vocabulary. This is that list, in the section's own order, so a right
    /// added or renamed has to be reconciled with the specification rather than with this file.
    const SECTION_TEN: [&str; 22] = [
        "session.view",
        "terminal.input",
        "terminal.geometry",
        "terminal.geometry.transfer",
        "terminal.palette",
        "agent.prompt",
        "agent.cancel",
        "agent.approval.respond",
        "question.respond",
        "files.read",
        "files.upload",
        "files.apply_diff",
        "project.create",
        "workspace.manage",
        "changeset.create",
        "session.create",
        "session.rename",
        "session.close",
        "session.share",
        "automation.manage",
        "host.manage",
        "voice.use",
    ];

    #[test]
    fn the_vocabulary_is_exactly_the_one_section_ten_declares() {
        let declared: Vec<&str> = ActionRight::ALL
            .iter()
            .map(|right| right.as_str())
            .collect();
        assert_eq!(declared, SECTION_TEN);
    }

    #[test]
    fn the_vocabulary_is_closed() {
        // A name that is not in the list resolves to nothing. A method that needs an effect the
        // vocabulary does not cover is denied, not approximated under a neighbouring name.
        for near_miss in [
            "terminal.write",
            "session.admin",
            "files.write",
            "agent.respond",
            "TERMINAL.INPUT",
            "",
        ] {
            assert_eq!(
                ActionRight::from_wire(near_miss),
                None,
                "{near_miss} resolved to a right"
            );
            assert!(near_miss.parse::<ActionRight>().is_err());
        }
    }

    #[test]
    fn every_right_round_trips_through_its_wire_string() {
        for right in ActionRight::ALL {
            assert_eq!(ActionRight::from_wire(right.as_str()), Some(*right));
            assert_eq!(right.as_str().parse::<ActionRight>(), Ok(*right));
            assert_eq!(right.to_string(), right.as_str());
        }
    }

    #[test]
    fn a_set_of_rights_encodes_in_wire_order_rather_than_declaration_order() {
        // The order a reader can verify from the encoded values alone. Section 10 declares
        // `session.view` first and `host.manage` last; sorted by wire string, `agent.cancel` comes
        // before both.
        let mut rights = vec![
            ActionRight::HostManage,
            ActionRight::SessionView,
            ActionRight::AgentCancel,
        ];
        rights.sort_unstable();
        assert_eq!(
            rights,
            vec![
                ActionRight::AgentCancel,
                ActionRight::HostManage,
                ActionRight::SessionView
            ]
        );
    }
}
