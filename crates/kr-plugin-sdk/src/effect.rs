//! Effect classes and the actions a package registers.
//!
//! An action declares its effect class in the manifest. The broker validates the prepared effect
//! against that class, so a shell write cannot acquire read-only rights by calling itself a
//! preview. The class is what a reviewer reads and what the host enforces; the label beside it is
//! only text.
//!
//! Each class resolves to the rights the broker intersects at dispatch. That resolution lives
//! here, in one table, rather than in each call site, so "what does this action need" has one
//! answer.

use kr_protocol::scalars::{CanonicalSet, Nullable};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::PluginCapability;
use crate::ids::{ActionName, ParameterName};
use crate::text::{Label, Summary};

pub use kr_protocol::rights::ActionRight;

/// What an action does.
///
/// The vocabulary is closed. An effect the broker cannot name is denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectClass {
    /// Presents information the binding may already observe. No effect leaves the host.
    #[serde(rename = "observe")]
    Observe,
    /// Prepares a prompt for the bound upstream execution.
    #[serde(rename = "upstream.prompt")]
    UpstreamPrompt,
    /// Requests cancellation of the bound upstream execution's current turn.
    #[serde(rename = "upstream.cancel")]
    UpstreamCancel,
    /// Contributes a completed attachment handle to the upstream draft.
    #[serde(rename = "upstream.attachment")]
    UpstreamAttachment,
    /// Interprets native request bytes into a proposed approval resource.
    #[serde(rename = "approval.decode")]
    ApprovalDecode,
    /// Encodes a validated decision as a response to a pending native request.
    #[serde(rename = "approval.respond")]
    ApprovalRespond,
    /// Writes bytes into the terminal.
    #[serde(rename = "terminal.input")]
    TerminalInput,
}

impl EffectClass {
    /// Every effect class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Observe,
        Self::UpstreamPrompt,
        Self::UpstreamCancel,
        Self::UpstreamAttachment,
        Self::ApprovalDecode,
        Self::ApprovalRespond,
        Self::TerminalInput,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::UpstreamPrompt => "upstream.prompt",
            Self::UpstreamCancel => "upstream.cancel",
            Self::UpstreamAttachment => "upstream.attachment",
            Self::ApprovalDecode => "approval.decode",
            Self::ApprovalRespond => "approval.respond",
            Self::TerminalInput => "terminal.input",
        }
    }

    /// Returns the effect class for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|class| class.as_str() == value)
    }

    /// Returns true when the effect changes something outside the host's own presentation.
    ///
    /// An observation callback cannot submit input merely because it can read output, so this is
    /// the boundary the broker checks before it accepts a prepared effect.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(self, Self::Observe | Self::ApprovalDecode)
    }

    /// Returns the rights the broker intersects at dispatch.
    ///
    /// `ApprovalDecode` returns no right on purpose: decoding proposes a resource, it does not
    /// answer one. The trust to decode is recorded against the publisher and its methods,
    /// separately from the action vocabulary, and answering still needs
    /// [`ActionRight::AgentApprovalRespond`].
    #[must_use]
    pub const fn required_rights(self) -> &'static [ActionRight] {
        match self {
            Self::Observe => &[ActionRight::SessionView],
            Self::UpstreamPrompt => &[ActionRight::AgentPrompt],
            Self::UpstreamCancel => &[ActionRight::AgentCancel],
            Self::UpstreamAttachment => &[ActionRight::AgentPrompt, ActionRight::FilesUpload],
            Self::ApprovalDecode => &[],
            Self::ApprovalRespond => &[ActionRight::AgentApprovalRespond],
            Self::TerminalInput => &[ActionRight::TerminalInput],
        }
    }

    /// Returns the capability the package must request before it may declare this class.
    #[must_use]
    pub const fn required_capability(self) -> PluginCapability {
        match self {
            Self::Observe => PluginCapability::BrokerSemanticEvents,
            Self::UpstreamPrompt | Self::UpstreamCancel | Self::UpstreamAttachment => {
                PluginCapability::UpstreamAction
            }
            Self::ApprovalDecode => PluginCapability::ApprovalDecode,
            Self::ApprovalRespond => PluginCapability::ApprovalRespond,
            Self::TerminalInput => PluginCapability::TerminalInput,
        }
    }
}

impl core::fmt::Display for EffectClass {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl JsonSchema for EffectClass {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EffectClass".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::EffectClass".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|value| value.as_str()).collect();
        schemars::json_schema!({
            "type": "string",
            "enum": names,
            "description": "What an action does. The broker validates the prepared effect against this class."
        })
    }
}

/// What one action parameter accepts.
///
/// The grammar is bounded rather than an arbitrary JSON Schema. A bounded parameter list can be
/// checked completely before dispatch and hashed into the action token, which is what binds a
/// callback to the exact parameters a person saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterKind {
    /// Free text.
    Text {
        /// Maximum length in characters.
        max_length: u32,
        /// Whether the client offers a multi-line field.
        multiline: bool,
    },
    /// A whole number inside an inclusive range.
    Integer {
        /// Lowest accepted value.
        minimum: i64,
        /// Highest accepted value.
        maximum: i64,
    },
    /// A yes or no.
    Boolean {},
    /// One of a fixed list.
    Choice {
        /// The choices, each a stable identifier and its label.
        choices: Vec<ParameterChoice>,
    },
    /// A completed attachment handle from the shared transfer service.
    ///
    /// The package never receives bytes: the transfer completes first and the action receives the
    /// opaque handle.
    AttachmentHandle {},
    /// A node in the package's own presentation document.
    NodeRef {},
}

/// One choice in a [`ParameterKind::Choice`] parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ParameterChoice {
    /// The stable identifier submitted with the action.
    pub id: ParameterName,
    /// The label a person reads.
    pub label: Label,
}

/// One parameter of an action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ParameterDeclaration {
    /// The parameter name.
    pub name: ParameterName,
    /// What it accepts.
    pub kind: ParameterKind,
    /// The label a person reads.
    pub label: Label,
    /// Whether the action can be invoked without it.
    pub required: bool,
}

/// The complete parameter list of one action.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ParameterSchema {
    /// The parameters, in the order a client presents them.
    pub parameters: Vec<ParameterDeclaration>,
}

/// Maximum number of parameters one action may declare.
pub const MAX_PARAMETERS: usize = 16;

/// Maximum number of choices one choice parameter may offer.
pub const MAX_PARAMETER_CHOICES: usize = 24;

/// An action registered in the package manifest.
///
/// Registration is what makes an action invocable. A control may name only a registered action,
/// so the effect class the broker enforces is always the one the publisher declared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionDeclaration {
    /// The action identifier a control names.
    pub id: ActionName,
    /// The label a person reads.
    pub label: Label,
    /// What the action does.
    pub effect: EffectClass,
    /// The parameters it accepts.
    pub parameters: ParameterSchema,
    /// Why the action exists, shown in the installation grant beside its effect class.
    pub description: Summary,
    /// Whether the host asks the person to confirm before dispatch.
    pub confirmation_required: bool,
}

impl ActionDeclaration {
    /// Returns the rights the broker intersects when this action is dispatched.
    #[must_use]
    pub fn required_rights(&self) -> CanonicalSet<ActionRight> {
        self.effect.required_rights().iter().copied().collect()
    }
}

/// An action invocation the host has not yet checked.
///
/// The host rechecks the effect class, the parameters and the grant on every invocation, so a
/// control that was visible when it was rendered cannot dispatch after the state it depended on
/// changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionInvocation {
    /// The action being invoked.
    pub action_id: ActionName,
    /// The supplied parameter values, keyed by parameter name.
    pub arguments: Vec<ActionArgument>,
}

/// One supplied parameter value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionArgument {
    /// The parameter name.
    pub name: ParameterName,
    /// The supplied value.
    pub value: ArgumentValue,
}

/// A supplied parameter value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgumentValue {
    /// Text for a [`ParameterKind::Text`] parameter.
    Text {
        /// The text.
        text: String,
    },
    /// A number for an [`ParameterKind::Integer`] parameter.
    Integer {
        /// The number.
        value: i64,
    },
    /// A decision for a [`ParameterKind::Boolean`] parameter.
    Boolean {
        /// The decision.
        value: bool,
    },
    /// A selected choice for a [`ParameterKind::Choice`] parameter.
    Choice {
        /// The chosen identifier.
        choice_id: ParameterName,
    },
    /// A completed attachment handle.
    AttachmentHandle {
        /// The opaque handle.
        handle: String,
    },
    /// A node in the package's presentation document.
    NodeRef {
        /// The node identifier.
        node_id: crate::ids::NodeId,
    },
}

/// Why an argument list does not satisfy a parameter schema.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArgumentError {
    /// A required parameter was absent.
    #[error("the required parameter {name} is absent")]
    MissingRequired {
        /// The absent parameter.
        name: ParameterName,
    },
    /// An argument named a parameter the action does not declare.
    #[error("the action does not declare a parameter named {name}")]
    UnknownParameter {
        /// The undeclared parameter.
        name: ParameterName,
    },
    /// The same parameter was supplied twice.
    #[error("the parameter {name} is supplied more than once")]
    DuplicateParameter {
        /// The repeated parameter.
        name: ParameterName,
    },
    /// The value did not match the declared kind.
    #[error("the parameter {name} does not accept this value")]
    WrongKind {
        /// The parameter whose value was wrong.
        name: ParameterName,
    },
    /// The value was outside the declared bound.
    #[error("the value of {name} is outside its declared bound")]
    OutOfBounds {
        /// The parameter whose value was out of bounds.
        name: ParameterName,
    },
}

impl ParameterSchema {
    /// Checks an argument list against this schema.
    ///
    /// # Errors
    ///
    /// Returns the first [`ArgumentError`] that applies.
    pub fn check(&self, invocation: &ActionInvocation) -> Result<(), ArgumentError> {
        let mut seen: Vec<&ParameterName> = Vec::new();
        for argument in &invocation.arguments {
            if seen.contains(&&argument.name) {
                return Err(ArgumentError::DuplicateParameter {
                    name: argument.name.clone(),
                });
            }
            seen.push(&argument.name);
            let declaration = self
                .parameters
                .iter()
                .find(|parameter| parameter.name == argument.name)
                .ok_or_else(|| ArgumentError::UnknownParameter {
                    name: argument.name.clone(),
                })?;
            check_value(declaration, &argument.value)?;
        }
        for parameter in &self.parameters {
            if parameter.required && !seen.contains(&&parameter.name) {
                return Err(ArgumentError::MissingRequired {
                    name: parameter.name.clone(),
                });
            }
        }
        Ok(())
    }
}

fn check_value(
    declaration: &ParameterDeclaration,
    value: &ArgumentValue,
) -> Result<(), ArgumentError> {
    let name = declaration.name.clone();
    match (&declaration.kind, value) {
        (ParameterKind::Text { max_length, .. }, ArgumentValue::Text { text }) => {
            if text.chars().count() > *max_length as usize {
                return Err(ArgumentError::OutOfBounds { name });
            }
            Ok(())
        }
        (ParameterKind::Integer { minimum, maximum }, ArgumentValue::Integer { value }) => {
            if value < minimum || value > maximum {
                return Err(ArgumentError::OutOfBounds { name });
            }
            Ok(())
        }
        (ParameterKind::Boolean {}, ArgumentValue::Boolean { .. })
        | (ParameterKind::AttachmentHandle {}, ArgumentValue::AttachmentHandle { .. })
        | (ParameterKind::NodeRef {}, ArgumentValue::NodeRef { .. }) => Ok(()),
        (ParameterKind::Choice { choices }, ArgumentValue::Choice { choice_id }) => {
            if choices.iter().any(|choice| &choice.id == choice_id) {
                Ok(())
            } else {
                Err(ArgumentError::OutOfBounds { name })
            }
        }
        _ => Err(ArgumentError::WrongKind { name }),
    }
}

/// How a package contributes attachments to an upstream draft.
///
/// Transfer, draft insertion, submission and upstream acceptance stay separate. The package
/// declares what it accepts and where anything leaves the host; it never receives the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AttachmentContribution {
    /// The MIME types the upstream accepts, as exact types or `type/*` families.
    pub accepted_media_types: Vec<String>,
    /// Maximum bytes per attachment for the selected upstream model.
    pub max_bytes: u64,
    /// Maximum attachments per draft.
    pub max_count: u32,
    /// How the attachment reaches the draft.
    pub insertion: AttachmentInsertion,
    /// The external service the bytes are uploaded to, where one is involved.
    ///
    /// A destination outside the host is disclosed before anything is submitted, because an
    /// upload that leaves the machine is not made private by encrypted KalaReach routing.
    pub external_destination: Nullable<Label>,
}

/// How an attachment reaches the upstream draft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentInsertion {
    /// The connector's native composer API takes the handle.
    NativeComposer,
    /// The connector's upstream protocol takes an upload reference.
    UpstreamUpload,
    /// A path is written into the terminal draft.
    ///
    /// Shell quoting is not assumed to be the composer's syntax, so the host quotes for the shell
    /// it is writing to and nothing else.
    TerminalDraftPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> ParameterName {
        ParameterName::new(text).expect("valid parameter name")
    }

    #[test]
    fn every_class_resolves_to_rights_and_a_capability() {
        for class in EffectClass::ALL {
            assert_eq!(EffectClass::from_wire(class.as_str()), Some(*class));
            let capability = class.required_capability();
            if class.is_mutation() {
                assert!(
                    !class.required_rights().is_empty(),
                    "{class} is a mutation with no required right"
                );
                assert!(
                    !capability.within_default_ceiling(),
                    "{class} is a mutation inside the default ceiling"
                );
            }
        }
    }

    #[test]
    fn observation_carries_no_input_right() {
        assert_eq!(
            EffectClass::Observe.required_rights(),
            &[kr_protocol::rights::ActionRight::SessionView]
        );
        assert!(!EffectClass::Observe.is_mutation());
        assert!(
            !EffectClass::Observe
                .required_rights()
                .contains(&kr_protocol::rights::ActionRight::TerminalInput)
        );
    }

    #[test]
    fn decoding_never_answers() {
        assert!(EffectClass::ApprovalDecode.required_rights().is_empty());
        assert_eq!(
            EffectClass::ApprovalRespond.required_rights(),
            &[kr_protocol::rights::ActionRight::AgentApprovalRespond]
        );
    }

    #[test]
    fn an_unknown_effect_class_has_no_meaning() {
        assert_eq!(EffectClass::from_wire("shell.exec"), None);
        assert_eq!(EffectClass::from_wire("Observe"), None);
    }

    #[test]
    fn arguments_are_checked_against_the_declared_kinds() {
        let schema = ParameterSchema {
            parameters: vec![
                ParameterDeclaration {
                    name: name("prompt"),
                    kind: ParameterKind::Text {
                        max_length: 8,
                        multiline: false,
                    },
                    label: Label::new("Prompt").expect("valid label"),
                    required: true,
                },
                ParameterDeclaration {
                    name: name("queue"),
                    kind: ParameterKind::Boolean {},
                    label: Label::new("Queue").expect("valid label"),
                    required: false,
                },
            ],
        };
        let ok = ActionInvocation {
            action_id: ActionName::new("send").expect("valid action"),
            arguments: vec![ActionArgument {
                name: name("prompt"),
                value: ArgumentValue::Text {
                    text: "hello".to_owned(),
                },
            }],
        };
        assert_eq!(schema.check(&ok), Ok(()));

        let too_long = ActionInvocation {
            action_id: ActionName::new("send").expect("valid action"),
            arguments: vec![ActionArgument {
                name: name("prompt"),
                value: ArgumentValue::Text {
                    text: "far too long".to_owned(),
                },
            }],
        };
        assert_eq!(
            schema.check(&too_long),
            Err(ArgumentError::OutOfBounds {
                name: name("prompt")
            })
        );

        let missing = ActionInvocation {
            action_id: ActionName::new("send").expect("valid action"),
            arguments: Vec::new(),
        };
        assert_eq!(
            schema.check(&missing),
            Err(ArgumentError::MissingRequired {
                name: name("prompt")
            })
        );

        let unknown = ActionInvocation {
            action_id: ActionName::new("send").expect("valid action"),
            arguments: vec![
                ActionArgument {
                    name: name("prompt"),
                    value: ArgumentValue::Text {
                        text: "hello".to_owned(),
                    },
                },
                ActionArgument {
                    name: name("extra"),
                    value: ArgumentValue::Boolean { value: true },
                },
            ],
        };
        assert_eq!(
            schema.check(&unknown),
            Err(ArgumentError::UnknownParameter {
                name: name("extra")
            })
        );

        let wrong_kind = ActionInvocation {
            action_id: ActionName::new("send").expect("valid action"),
            arguments: vec![ActionArgument {
                name: name("prompt"),
                value: ArgumentValue::Boolean { value: true },
            }],
        };
        assert_eq!(
            schema.check(&wrong_kind),
            Err(ArgumentError::WrongKind {
                name: name("prompt")
            })
        );
    }
}
