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
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
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
