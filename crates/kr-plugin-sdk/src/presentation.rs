//! The portable document node union and declarative controls.
//!
//! A package contributes a document, not an interface. The node union is closed and rendered by
//! standard client components: a package cannot inject JavaScript, CSS, React or a WebView, and a
//! node kind a client does not know renders as an unsupported-content block that carries no
//! action. Adding a transport primitive or a node kind is a core change, which is the point of
//! keeping the union here rather than in each package.
//!
//! Every node and control carries a stable identifier and a revision. A snapshot or delta names
//! the base revision it applies to, so a client that misses an update resynchronises rather than
//! rendering a document nobody produced.

use kr_protocol::ids::{ApprovalRequestId, AttachmentId, SessionId};
use kr_protocol::scalars::Nullable;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effect::ParameterSchema;
use crate::ids::{ActionName, ControlId, NodeId};
use crate::predicate::Predicate;
use crate::scalars::{Count, U64};
use crate::text::{AccessibleDescription, DisabledReason, Label, Summary};

/// The revision of one node or control.
pub type NodeRevision = kr_protocol::scalars::U64;

/// Maximum number of nodes in one presentation document.
pub const MAX_DOCUMENT_NODES: usize = 256;

/// Maximum number of controls in one presentation document.
pub const MAX_CONTROLS: usize = 128;

/// An icon from the standard set every client ships.
///
/// Packages choose from this list rather than shipping artwork. A standard icon renders at the
/// platform's own size and weight, survives a theme change and means the same thing in every
/// package, which a bundled image cannot do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardIcon {
    /// Run, start or send.
    Play,
    /// Stop or cancel.
    Stop,
    /// Pause.
    Pause,
    /// Approve.
    Check,
    /// Reject.
    Cross,
    /// Retry.
    Retry,
    /// Open a detail view.
    Open,
    /// Copy to the clipboard.
    Copy,
    /// Attach a file.
    Attachment,
    /// A file.
    File,
    /// A folder.
    Folder,
    /// A difference between two versions.
    Diff,
    /// A terminal.
    Terminal,
    /// A tool call.
    Tool,
    /// A warning.
    Warning,
    /// Information.
    Info,
    /// An error.
    Error,
    /// A setting.
    Settings,
    /// Search.
    Search,
    /// A person.
    Person,
    /// A question awaiting an answer.
    Question,
    /// Send upstream.
    Send,
}

impl StandardIcon {
    /// Every standard icon, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Play,
        Self::Stop,
        Self::Pause,
        Self::Check,
        Self::Cross,
        Self::Retry,
        Self::Open,
        Self::Copy,
        Self::Attachment,
        Self::File,
        Self::Folder,
        Self::Diff,
        Self::Terminal,
        Self::Tool,
        Self::Warning,
        Self::Info,
        Self::Error,
        Self::Settings,
        Self::Search,
        Self::Person,
        Self::Question,
        Self::Send,
    ];
}

impl JsonSchema for StandardIcon {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "StandardIcon".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::StandardIcon".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<String> = Self::ALL
            .iter()
            .map(|icon| {
                serde_json::to_value(icon)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default()
            })
            .collect();
        schemars::json_schema!({
            "type": "string",
            "enum": names,
            "description": "An icon from the standard set every client ships."
        })
    }
}

/// How prominently a client presents a control.
///
/// Priority is semantic, not visual: it says how important the action is, and each client decides
/// what that looks like on its own platform.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SemanticPriority {
    /// The action a person came here to take.
    Primary,
    /// A common alternative.
    Secondary,
    /// Rarely needed; a client may place it behind a menu.
    Overflow,
    /// Destructive or irreversible; a client presents it as such.
    Destructive,
}

/// One declarative control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Control {
    /// The stable identifier.
    pub id: ControlId,
    /// The revision of this control.
    pub revision: NodeRevision,
    /// The label a person reads.
    pub label: Label,
    /// The standard icon.
    pub icon: StandardIcon,
    /// The description a screen reader announces.
    pub accessible_description: AccessibleDescription,
    /// The registered action this control invokes.
    pub action_id: ActionName,
    /// The parameters this control supplies.
    ///
    /// A control may narrow its action's parameters but never widen them. The host checks the
    /// invocation against the action's own schema regardless.
    pub parameters: ParameterSchema,
    /// How prominently a client presents it.
    pub priority: SemanticPriority,
    /// When the control is visible.
    pub visible_when: Predicate,
    /// When the control is present but not usable.
    pub enabled_when: Predicate,
    /// The reason shown while the control is disabled.
    pub disabled_reason: Nullable<DisabledReason>,
}

/// How far along a progress node is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgressState {
    /// A known fraction of a known total.
    Determinate {
        /// Completed units.
        completed: U64,
        /// Total units.
        total: U64,
    },
    /// Work is happening and its extent is unknown.
    Indeterminate {},
    /// Work finished.
    Complete {},
    /// Work failed.
    Failed {},
}

/// One entry in a diff node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DiffFile {
    /// The path as the upstream reported it.
    pub path: String,
    /// Lines added.
    pub added: Count,
    /// Lines removed.
    pub removed: Count,
}

/// The outcome of a tool call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolOutcome {
    /// Running.
    Running,
    /// Finished successfully.
    Succeeded,
    /// Finished with an error.
    Failed,
    /// Cancelled before it finished.
    Cancelled,
}

/// What one document node is.
///
/// The union is closed. Adding a kind is a core version, because every client renders these with
/// its own standard components and a client that does not know a kind cannot render it safely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeBody {
    /// A message from the upstream execution or the person.
    Message {
        /// Who wrote it.
        author: Label,
        /// The text.
        text: Summary,
    },
    /// Formatted prose.
    Markdown {
        /// The Markdown source, rendered by the client's own renderer.
        source: String,
    },
    /// One upstream tool call.
    Tool {
        /// The tool name as the upstream reported it.
        name: Label,
        /// Its outcome.
        outcome: ToolOutcome,
        /// A one-line summary of what it did.
        summary: Summary,
    },
    /// A set of file changes.
    Diff {
        /// The files.
        files: Vec<DiffFile>,
    },
    /// Work in progress.
    Progress {
        /// What is happening.
        label: Label,
        /// How far along it is.
        state: ProgressState,
    },
    /// A set of fields a person fills in.
    Form {
        /// What the form asks for.
        title: Label,
        /// The fields.
        fields: ParameterSchema,
        /// The control that submits the completed form.
        ///
        /// Submission is an action invocation like any other, so it carries a control rather than
        /// a bare action name: the same label, icon, accessible description, priority, visibility
        /// and disabled reason every other way of invoking an action carries.
        submit: Control,
    },
    /// A file the session carries.
    Attachment {
        /// The attachment.
        attachment_id: AttachmentId,
        /// Its name.
        name: Label,
        /// Its size in bytes.
        size_bytes: U64,
    },
    /// A reference to an approval resource in the ledger.
    ///
    /// The identifier must name a ledger resource. A package cannot create an approval by drawing
    /// one: a pending opaque request is not an actionable approval until its interpretation is
    /// verified under the granted decoder.
    ApprovalRef {
        /// The ledger resource.
        approval_request_id: ApprovalRequestId,
    },
    /// A reference to a live terminal.
    TerminalRef {
        /// The session whose terminal this is.
        session_id: SessionId,
    },
    /// One control presented on its own.
    ActionButton {
        /// The control.
        control: Control,
    },
    /// Several related controls presented together.
    ActionGroup {
        /// What the group is for.
        label: Label,
        /// The controls.
        controls: Vec<Control>,
    },
    /// Controls reachable from the client's command palette.
    CommandPalette {
        /// The controls.
        controls: Vec<Control>,
    },
    /// An entry point for contributing an attachment.
    AttachmentEntry {
        /// What it accepts.
        label: Label,
        /// The control that receives the completed handle.
        contribute: Control,
    },
}

impl NodeBody {
    /// Returns the wire name of this node kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Message { .. } => "message",
            Self::Markdown { .. } => "markdown",
            Self::Tool { .. } => "tool",
            Self::Diff { .. } => "diff",
            Self::Progress { .. } => "progress",
            Self::Form { .. } => "form",
            Self::Attachment { .. } => "attachment",
            Self::ApprovalRef { .. } => "approval_ref",
            Self::TerminalRef { .. } => "terminal_ref",
            Self::ActionButton { .. } => "action_button",
            Self::ActionGroup { .. } => "action_group",
            Self::CommandPalette { .. } => "command_palette",
            Self::AttachmentEntry { .. } => "attachment_entry",
        }
    }

    /// Every node kind in the union, in declaration order.
    pub const KINDS: &'static [&'static str] = &[
        "message",
        "markdown",
        "tool",
        "diff",
        "progress",
        "form",
        "attachment",
        "approval_ref",
        "terminal_ref",
        "action_button",
        "action_group",
        "command_palette",
        "attachment_entry",
    ];

    /// Returns every control this node carries.
    ///
    /// Every way a node can invoke an action is a control, so this is the complete list. Nothing
    /// invokes an action from outside it, which is what lets one pass over the document count the
    /// controls, check their predicates and check their parameters.
    #[must_use]
    pub fn controls(&self) -> &[Control] {
        match self {
            Self::ActionButton { control } => std::slice::from_ref(control),
            Self::Form { submit, .. } => std::slice::from_ref(submit),
            Self::AttachmentEntry { contribute, .. } => std::slice::from_ref(contribute),
            Self::ActionGroup { controls, .. } | Self::CommandPalette { controls } => controls,
            _ => &[],
        }
    }

    /// Returns every action identifier this node can invoke.
    #[must_use]
    pub fn action_ids(&self) -> Vec<ActionName> {
        self.controls()
            .iter()
            .map(|control| control.action_id.clone())
            .collect()
    }
}

/// One document node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DocumentNode {
    /// The stable identifier.
    pub id: NodeId,
    /// The revision of this node.
    pub revision: NodeRevision,
    /// What the node is.
    pub body: NodeBody,
}

/// A node whose kind this build does not know.
///
/// A client renders it as an unsupported-content block. It carries no body and therefore no
/// action: a newer package cannot reach a hidden action through a node an older client cannot
/// read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UnsupportedNode {
    /// The stable identifier.
    pub id: NodeId,
    /// The revision of the node that could not be read.
    pub revision: NodeRevision,
    /// The kind the document claimed, for the unsupported-content block to name.
    pub kind: String,
}

impl UnsupportedNode {
    /// Returns the action identifiers an unsupported node can invoke, which is none.
    #[must_use]
    pub fn action_ids(&self) -> Vec<ActionName> {
        Vec::new()
    }
}

/// Reads one node, falling back to an unsupported-content block.
///
/// A client on an older core reads a document a newer package produced. Anything it cannot
/// understand becomes an [`UnsupportedNode`] rather than an error, so one unknown node does not
/// discard a document a person is reading.
///
/// # Errors
///
/// Returns the node's stable identity as an [`UnsupportedNode`] when the kind, or anything inside
/// it, is not part of this build's union.
pub fn read_node(value: &serde_json::Value) -> Result<DocumentNode, UnsupportedNode> {
    if let Ok(node) = serde_json::from_value::<DocumentNode>(value.clone()) {
        return Ok(node);
    }
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| NodeId::new(text).ok())
        .unwrap_or_else(|| NodeId::new("unreadable").expect("a literal slug"));
    let revision = value
        .get("revision")
        .and_then(|revision| serde_json::from_value::<NodeRevision>(revision.clone()).ok())
        .unwrap_or_default();
    let kind = value
        .get("body")
        .and_then(|body| body.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .chars()
        .filter(|character| !crate::text::is_forbidden_text_char(*character))
        .take(64)
        .collect();
    Err(UnsupportedNode { id, revision, kind })
}

/// The presentation manifest of one package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PresentationManifest {
    /// The manifest format version.
    pub manifest_version: u32,
    /// The revision this document as a whole is at.
    ///
    /// A delta names this revision as its base, so a client knows whether it can apply the delta
    /// or must ask for a fresh snapshot.
    pub base_revision: NodeRevision,
    /// The document nodes, in presentation order.
    pub nodes: Vec<DocumentNode>,
    /// The bounded projection a voice client receives.
    pub voice: VoiceProjection,
}

/// What a voice client receives.
///
/// Voice gets status, pending choices and references to detail, never the whole document. A
/// spoken interface that reads an arbitrary document out loud is both unusable and a disclosure
/// nobody asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct VoiceProjection {
    /// The nodes whose status voice announces.
    pub status_nodes: Vec<NodeId>,
    /// The controls voice offers as choices.
    pub choice_controls: Vec<ControlId>,
    /// The nodes voice refers to without reading out.
    pub detail_nodes: Vec<NodeId>,
}

impl PresentationManifest {
    /// The manifest format version this crate reads and writes.
    pub const CURRENT_VERSION: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect::ParameterSchema;
    use crate::predicate::Predicate;

    fn control(id: &str, action: &str) -> Control {
        Control {
            id: ControlId::new(id).expect("valid control id"),
            revision: NodeRevision::new(1),
            label: Label::new("Send").expect("valid label"),
            icon: StandardIcon::Send,
            accessible_description: AccessibleDescription::new("Send the prompt upstream")
                .expect("valid description"),
            action_id: ActionName::new(action).expect("valid action name"),
            parameters: ParameterSchema::default(),
            priority: SemanticPriority::Primary,
            visible_when: Predicate::Always {},
            enabled_when: Predicate::Always {},
            disabled_reason: Nullable(None),
        }
    }

    #[test]
    fn the_union_holds_the_thirteen_specified_kinds() {
        assert_eq!(NodeBody::KINDS.len(), 13);
        for kind in NodeBody::KINDS {
            assert!(!kind.is_empty());
        }
    }

    #[test]
    fn an_unknown_kind_becomes_an_unsupported_block_with_no_action() {
        let value = serde_json::json!({
            "id": "future-node",
            "revision": "7",
            "body": {"kind": "hologram", "action_id": "secret", "controls": []}
        });
        let unsupported = read_node(&value).expect_err("the kind is not in this build's union");
        assert_eq!(unsupported.id.as_str(), "future-node");
        assert_eq!(unsupported.revision.get(), 7);
        assert_eq!(unsupported.kind, "hologram");
        assert!(unsupported.action_ids().is_empty());
    }

    #[test]
    fn a_known_node_reads_normally() {
        let node = DocumentNode {
            id: NodeId::new("greeting").expect("valid node id"),
            revision: NodeRevision::new(1),
            body: NodeBody::Markdown {
                source: "# Hello".to_owned(),
            },
        };
        let value = serde_json::to_value(&node).expect("serialisable");
        assert_eq!(read_node(&value), Ok(node));
    }

    #[test]
    fn a_form_and_an_attachment_entry_carry_controls() {
        let form = NodeBody::Form {
            title: Label::new("Ask").expect("valid label"),
            fields: ParameterSchema::default(),
            submit: control("submit", "prompt.send"),
        };
        assert_eq!(form.controls().len(), 1);
        assert_eq!(form.action_ids().len(), 1);

        let entry = NodeBody::AttachmentEntry {
            label: Label::new("Attach").expect("valid label"),
            contribute: control("attach", "prompt.attach"),
        };
        assert_eq!(entry.controls().len(), 1);
        assert_eq!(entry.action_ids().len(), 1);
    }

    #[test]
    fn a_node_reports_the_actions_it_can_invoke() {
        let group = NodeBody::ActionGroup {
            label: Label::new("Prompt").expect("valid label"),
            controls: vec![
                control("send", "prompt.send"),
                control("stop", "prompt.stop"),
            ],
        };
        let ids: Vec<String> = group.action_ids().iter().map(|id| id.to_string()).collect();
        assert_eq!(ids, vec!["prompt.send", "prompt.stop"]);
        assert!(
            NodeBody::Markdown {
                source: String::new()
            }
            .action_ids()
            .is_empty()
        );
    }

    #[test]
    fn a_package_cannot_inject_markup_as_a_node_kind() {
        for kind in ["html", "script", "webview", "react", "style"] {
            let value = serde_json::json!({
                "id": "n", "revision": "1", "body": {"kind": kind, "source": "<script>"}
            });
            assert!(read_node(&value).is_err(), "{kind} was accepted");
        }
    }
}
