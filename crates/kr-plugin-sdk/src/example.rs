//! A complete example package.
//!
//! This is the smallest package that does something useful: it recognises an application, it
//! contributes a document, and it registers one action a control invokes. It ships no Wasm,
//! because a declarative package needs none.
//!
//! The example is here rather than only in a fixture directory so it stays correct. The fixture
//! files under `fixtures/plugins/` are written from these values, the tests validate the result,
//! and a package author reading the SDK sees the same package the tests use.

use kr_protocol::scalars::Nullable;

use crate::capability::{CapabilityRequest, PluginCapability};
use crate::digest::{ByteSize, PayloadDigest};
use crate::effect::{
    ActionDeclaration, EffectClass, ParameterDeclaration, ParameterKind, ParameterSchema,
};
use crate::ids::{ActionName, ControlId, NodeId, ParameterName, PluginName, PublisherId};
use crate::matching::{
    Architecture, DistributionMatch, ExecutableMatch, MatchConfidence, MatchRule, OperatingSystem,
    PlatformSupport,
};
use crate::package::PRESENTATION_FILE;
use crate::paths::PackagePath;
use crate::plugin::{PayloadRef, PayloadRole, PluginManifest, SourcePin};
use crate::predicate::{BindingState, Predicate, PresentationFlag};
use crate::presentation::{
    Control, DocumentNode, NodeBody, NodeRevision, PresentationManifest, ProgressState,
    SemanticPriority, StandardIcon, VoiceProjection,
};
use crate::text::{AccessibleDescription, CompactDescription, Label, Summary};
use crate::version::{PackageVersion, VersionRange};

/// The example publisher.
pub const PUBLISHER: &str = "kalareach";

/// The example plugin name.
pub const PLUGIN_NAME: &str = "example-declarative";

fn label(text: &str) -> Label {
    Label::new(text).expect("a literal label is within bounds")
}

fn summary(text: &str) -> Summary {
    Summary::new(text).expect("a literal summary is within bounds")
}

/// Returns the example presentation document.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label, which is a
/// compile-time mistake rather than a runtime condition.
#[must_use]
pub fn example_presentation() -> PresentationManifest {
    let refresh = Control {
        id: ControlId::new("refresh").expect("a literal control id"),
        revision: NodeRevision::new(1),
        label: label("Refresh status"),
        icon: StandardIcon::Retry,
        accessible_description: AccessibleDescription::new(
            "Read the current status of the bound application again",
        )
        .expect("a literal description"),
        action_id: ActionName::new("status.refresh").expect("a literal action name"),
        parameters: ParameterSchema {
            parameters: vec![ParameterDeclaration {
                name: ParameterName::new("detail").expect("a literal parameter name"),
                kind: ParameterKind::Choice {
                    choices: vec![
                        crate::effect::ParameterChoice {
                            id: ParameterName::new("summary").expect("a literal choice id"),
                            label: label("Summary"),
                        },
                        crate::effect::ParameterChoice {
                            id: ParameterName::new("full").expect("a literal choice id"),
                            label: label("Everything"),
                        },
                    ],
                },
                label: label("Detail"),
                required: false,
            }],
        },
        priority: SemanticPriority::Secondary,
        visible_when: Predicate::Not {
            term: Box::new(Predicate::Binding {
                state: BindingState::Disabled,
            }),
        },
        enabled_when: Predicate::All {
            terms: vec![
                Predicate::Binding {
                    state: BindingState::Bound,
                },
                Predicate::Not {
                    term: Box::new(Predicate::Flag {
                        flag: PresentationFlag::TransferInProgress,
                    }),
                },
            ],
        },
        disabled_reason: Nullable(None),
    };

    PresentationManifest {
        manifest_version: 1,
        base_revision: NodeRevision::new(1),
        nodes: vec![
            DocumentNode {
                id: NodeId::new("intro").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Markdown {
                    source:
                        "The example package recognises an application and presents its status."
                            .to_owned(),
                },
            },
            DocumentNode {
                id: NodeId::new("status").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::Progress {
                    label: label("Waiting for the application"),
                    state: ProgressState::Indeterminate {},
                },
            },
            DocumentNode {
                id: NodeId::new("controls").expect("a literal node id"),
                revision: NodeRevision::new(1),
                body: NodeBody::ActionGroup {
                    label: label("Status"),
                    controls: vec![refresh],
                },
            },
        ],
        voice: VoiceProjection {
            status_nodes: vec![NodeId::new("status").expect("a literal node id")],
            choice_controls: vec![ControlId::new("refresh").expect("a literal control id")],
            detail_nodes: vec![NodeId::new("intro").expect("a literal node id")],
        },
    }
}

/// Returns the example manifest, with the presentation payload's digest and size filled in.
///
/// # Panics
///
/// Panics when a literal in this function is not a valid identifier or label.
#[must_use]
pub fn example_manifest_for(presentation_bytes: &[u8]) -> PluginManifest {
    PluginManifest {
        manifest_version: PluginManifest::CURRENT_VERSION,
        publisher_id: PublisherId::new(PUBLISHER).expect("a literal publisher id"),
        plugin_name: PluginName::new(PLUGIN_NAME).expect("a literal plugin name"),
        version: PackageVersion::parse("0.1.0").expect("a literal version"),
        display_name: label("Example declarative package"),
        description: CompactDescription::new(
            "Recognises the example agent and presents its status with one declarative control.",
        )
        .expect("a literal description"),
        sdk_range: VersionRange::parse(">=0.1.0, <0.2.0").expect("a literal range"),
        wit_range: VersionRange::parse(">=0.1.0, <0.2.0").expect("a literal range"),
        source: SourcePin {
            repository: "https://github.com/kalapowered/kalareach-plugins".to_owned(),
            revision: "refs/tags/example-declarative-0.1.0".to_owned(),
        },
        match_rules: vec![MatchRule {
            id: PluginName::new("example-agent").expect("a literal rule id"),
            executable: ExecutableMatch {
                file_stem: "example-agent".to_owned(),
                path_suffix: Vec::new(),
                version_range: Nullable(None),
            },
            distribution: Nullable(Some(DistributionMatch::Npm {
                package: "@kalareach/example-agent".to_owned(),
            })),
            confidence: MatchConfidence::Exact,
        }],
        platforms: vec![
            PlatformSupport {
                os: OperatingSystem::Linux,
                architectures: vec![Architecture::X86_64, Architecture::Aarch64],
            },
            PlatformSupport {
                os: OperatingSystem::MacOs,
                architectures: vec![Architecture::Aarch64],
            },
            PlatformSupport {
                os: OperatingSystem::Windows,
                architectures: vec![Architecture::X86_64],
            },
        ],
        payloads: vec![PayloadRef {
            role: PayloadRole::Presentation,
            path: PackagePath::new(PRESENTATION_FILE).expect("a literal path"),
            digest: PayloadDigest::of(presentation_bytes),
            size_bytes: ByteSize::new(presentation_bytes.len() as u64),
        }],
        capabilities: vec![
            CapabilityRequest {
                capability: PluginCapability::MetadataMatch,
                reason: summary("Recognise the example agent from its executable name"),
            },
            CapabilityRequest {
                capability: PluginCapability::DeclarativePresentation,
                reason: summary("Present the application's status and one control"),
            },
            CapabilityRequest {
                capability: PluginCapability::BrokerSemanticEvents,
                reason: summary("Update the status from events the actor may already see"),
            },
        ],
        actions: vec![ActionDeclaration {
            id: ActionName::new("status.refresh").expect("a literal action name"),
            label: label("Refresh status"),
            effect: EffectClass::Observe,
            parameters: ParameterSchema {
                parameters: vec![ParameterDeclaration {
                    name: ParameterName::new("detail").expect("a literal parameter name"),
                    kind: ParameterKind::Choice {
                        choices: vec![
                            crate::effect::ParameterChoice {
                                id: ParameterName::new("summary").expect("a literal choice id"),
                                label: label("Summary"),
                            },
                            crate::effect::ParameterChoice {
                                id: ParameterName::new("full").expect("a literal choice id"),
                                label: label("Everything"),
                            },
                        ],
                    },
                    label: label("Detail"),
                    required: false,
                }],
            },
            description: summary("Read the bound application's status again and redraw it"),
            confirmation_required: false,
        }],
        attachments: Nullable(None),
        native_bridge: Nullable(None),
    }
}

/// Returns the example manifest against the canonical rendering of the example presentation.
///
/// # Panics
///
/// Panics when the example presentation cannot be serialised.
#[must_use]
pub fn example_manifest() -> PluginManifest {
    example_manifest_for(example_presentation_json().as_bytes())
}

/// Returns the canonical rendering of the example presentation document.
///
/// # Panics
///
/// Panics when the example presentation cannot be serialised.
#[must_use]
pub fn example_presentation_json() -> String {
    render(&example_presentation())
}

/// Returns the canonical rendering of the example manifest.
///
/// # Panics
///
/// Panics when the example manifest cannot be serialised.
#[must_use]
pub fn example_manifest_json() -> String {
    render(&example_manifest())
}

fn render<T: serde::Serialize>(value: &T) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("the example is serialisable");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_stays_inside_the_default_repository_ceiling() {
        let manifest = example_manifest();
        for request in &manifest.capabilities {
            assert!(
                request.capability.within_default_ceiling(),
                "{} needs a grant the example should not require",
                request.capability
            );
        }
        assert!(!manifest.has_component());
    }

    #[test]
    fn every_control_names_a_registered_action() {
        let manifest = example_manifest();
        let presentation = example_presentation();
        let registered: Vec<_> = manifest.actions.iter().map(|a| a.id.clone()).collect();
        for node in &presentation.nodes {
            for action_id in node.body.action_ids() {
                assert!(
                    registered.contains(&action_id),
                    "{action_id} is not registered"
                );
            }
        }
    }

    #[test]
    fn the_rendering_is_stable() {
        assert_eq!(example_manifest_json(), example_manifest_json());
        assert_eq!(example_presentation_json(), example_presentation_json());
    }
}
