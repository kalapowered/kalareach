//! Requested capabilities and capability evidence.
//!
//! Two different things share the word "capability" in section 11, and keeping them apart is the
//! point of this module.
//!
//! A **requested capability** is what a package asks a repository and an installation to permit.
//! The vocabulary is closed: [`PluginCapability`]. Enrolling a repository sets a ceiling, so
//! thousands of passive downloads do not become thousands of permission prompts, and the default
//! ceiling is metadata matching, declarative presentation and already-authorised broker semantic
//! events. Everything else needs an explicit package or repository grant, and a new executable
//! bridge or an increase in privilege needs an explicit installation grant.
//!
//! **Capability evidence** is what a host currently knows about whether something works here:
//! [`CapabilityEvidence`]. Evidence is never authority. A signed compatibility record says a
//! version behaves a certain way; it does not say this host has permission, and it does not
//! establish a live binding. The validator enforces that distinction rather than leaving it to
//! prose.

use kr_protocol::ids::{CapabilityId, CapabilityRevision, EnvironmentId};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::digest::PayloadDigest;
use crate::effect::ActionRight;
use crate::ids::{PluginId, PublisherId};
use crate::text::{DisabledReason, Label, Summary};
use crate::version::PackageVersion;

/// One capability a package may request.
///
/// The vocabulary is closed. A package that needs an effect not listed here is rejected, not
/// approximated under a neighbouring name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PluginCapability {
    /// Match installed executables and distributions against the manifest's rules.
    #[serde(rename = "metadata.match")]
    MetadataMatch,
    /// Contribute declarative document nodes and controls.
    #[serde(rename = "presentation.declarative")]
    DeclarativePresentation,
    /// Receive broker semantic events the actor is already authorised to see.
    #[serde(rename = "broker.semantic_events")]
    BrokerSemanticEvents,
    /// Read the raw terminal byte stream.
    #[serde(rename = "terminal.stream")]
    TerminalStream,
    /// Read the retained transcript tail.
    #[serde(rename = "terminal.transcript_tail")]
    TranscriptTail,
    /// Write bytes into the terminal.
    #[serde(rename = "terminal.input")]
    TerminalInput,
    /// Read files through the broker's file grant.
    #[serde(rename = "filesystem.read")]
    FilesystemRead,
    /// Open outbound network connections through the broker.
    #[serde(rename = "network.outbound")]
    NetworkOutbound,
    /// Observe process state through the broker.
    #[serde(rename = "process.observe")]
    ProcessObserve,
    /// Prepare prompts, cancellations and attachments against the bound upstream execution.
    #[serde(rename = "upstream.action")]
    UpstreamAction,
    /// Interpret native requests from the bound upstream into proposed approval resources.
    #[serde(rename = "approval.decode")]
    ApprovalDecode,
    /// Encode a validated decision as a response to a pending native request.
    #[serde(rename = "approval.respond")]
    ApprovalRespond,
    /// Install files into an application's documented native plugin or hook location.
    #[serde(rename = "native_bridge.install")]
    NativeBridgeInstall,
}

impl PluginCapability {
    /// Every capability, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::MetadataMatch,
        Self::DeclarativePresentation,
        Self::BrokerSemanticEvents,
        Self::TerminalStream,
        Self::TranscriptTail,
        Self::TerminalInput,
        Self::FilesystemRead,
        Self::NetworkOutbound,
        Self::ProcessObserve,
        Self::UpstreamAction,
        Self::ApprovalDecode,
        Self::ApprovalRespond,
        Self::NativeBridgeInstall,
    ];

    /// The capabilities a newly enrolled repository permits without any further grant.
    pub const DEFAULT_REPOSITORY_CEILING: &'static [Self] = &[
        Self::MetadataMatch,
        Self::DeclarativePresentation,
        Self::BrokerSemanticEvents,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataMatch => "metadata.match",
            Self::DeclarativePresentation => "presentation.declarative",
            Self::BrokerSemanticEvents => "broker.semantic_events",
            Self::TerminalStream => "terminal.stream",
            Self::TranscriptTail => "terminal.transcript_tail",
            Self::TerminalInput => "terminal.input",
            Self::FilesystemRead => "filesystem.read",
            Self::NetworkOutbound => "network.outbound",
            Self::ProcessObserve => "process.observe",
            Self::UpstreamAction => "upstream.action",
            Self::ApprovalDecode => "approval.decode",
            Self::ApprovalRespond => "approval.respond",
            Self::NativeBridgeInstall => "native_bridge.install",
        }
    }

    /// Returns true when the default repository ceiling already permits this capability.
    #[must_use]
    pub fn within_default_ceiling(self) -> bool {
        Self::DEFAULT_REPOSITORY_CEILING.contains(&self)
    }

    /// Returns true when granting this capability needs an explicit installation grant.
    ///
    /// Installing an executable bridge and raising privilege are the two cases section 11 names.
    /// Everything that runs outside Wasmtime under the application's own permissions is in the
    /// first case.
    #[must_use]
    pub fn requires_installation_grant(self) -> bool {
        matches!(
            self,
            Self::NativeBridgeInstall
                | Self::TerminalInput
                | Self::FilesystemRead
                | Self::NetworkOutbound
                | Self::ApprovalRespond
        )
    }

    /// Returns the grant right the host must hold before this capability can do anything.
    ///
    /// `None` means the capability adds no action right of its own: it either stays inside the
    /// default ceiling or it is an interpretation trust that the broker records separately from
    /// the action vocabulary.
    #[must_use]
    pub const fn required_right(self) -> Option<ActionRight> {
        match self {
            Self::MetadataMatch
            | Self::DeclarativePresentation
            | Self::BrokerSemanticEvents
            | Self::ProcessObserve
            | Self::ApprovalDecode
            | Self::NativeBridgeInstall => None,
            Self::TerminalStream | Self::TranscriptTail => Some(ActionRight::SessionView),
            Self::TerminalInput => Some(ActionRight::TerminalInput),
            Self::FilesystemRead => Some(ActionRight::FilesRead),
            Self::NetworkOutbound => Some(ActionRight::HostManage),
            Self::UpstreamAction => Some(ActionRight::AgentPrompt),
            Self::ApprovalRespond => Some(ActionRight::AgentApprovalRespond),
        }
    }
}

impl core::fmt::Display for PluginCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl JsonSchema for PluginCapability {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PluginCapability".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::PluginCapability".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|value| value.as_str()).collect();
        schemars::json_schema!({
            "type": "string",
            "enum": names,
            "description": "One capability a package may request. The vocabulary is closed."
        })
    }
}

/// A capability a package asks for, with the reason a reviewer and a user read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CapabilityRequest {
    /// The requested capability.
    pub capability: PluginCapability,
    /// Why the package needs it. Shown in the installation grant.
    pub reason: Summary,
}

/// What a host currently knows about one capability on one subject.
///
/// Runtime states distinguish the reasons something does not work, because "unavailable" alone
/// sends a person to the wrong fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Tested here and working.
    QualifiedAvailable,
    /// The application, bridge or component is not installed.
    MissingInstallation,
    /// The operating system or the user has not granted the permission it needs.
    PermissionRequired,
    /// The installed version cannot support it.
    Incompatible,
    /// It worked before and does not right now.
    TemporarilyUnavailable,
    /// No evidence has been gathered.
    NotTested,
}

impl CapabilityState {
    /// Returns true when the host may dispatch an action that depends on this capability.
    ///
    /// Only the qualified state is usable, and being usable still says nothing about authority.
    /// The grant check happens separately and always.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::QualifiedAvailable)
    }
}

/// Where a capability record came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// A bounded disclosed probe with declared effects, run on this host.
    HostProbe,
    /// A live binding that performed the operation on this host.
    LiveBinding,
    /// A signed compatibility record shipped in the catalogue.
    ///
    /// This is evidence about a version. It is not proof that this host has permission, and it
    /// cannot by itself establish [`CapabilityState::QualifiedAvailable`].
    SignedRecord,
    /// The package's own declaration, believed only for negative states.
    PackageDeclaration,
}

impl EvidenceSource {
    /// Returns true when this source can establish that a capability works on this host.
    #[must_use]
    pub const fn can_establish_qualified(self) -> bool {
        matches!(self, Self::HostProbe | Self::LiveBinding)
    }
}

/// What the evidence is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EvidenceSubject {
    /// The environment the evidence was gathered in.
    pub environment_id: EnvironmentId,
    /// The application the evidence is about, where it is about one.
    pub application: Nullable<Label>,
    /// The terminal profile the evidence is about, where it is about one.
    pub terminal: Nullable<Label>,
    /// The desktop session generation the evidence is bound to, where it is bound to one.
    pub desktop_generation: Nullable<Label>,
}

/// The exact identity the evidence was gathered against.
///
/// An installed upgrade does not invalidate an old running process's correctly pinned identity,
/// which is only expressible if the record names the identity rather than the product.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SubjectIdentity {
    /// The digest of the tested binary, where the subject is a binary.
    pub binary_digest: Nullable<PayloadDigest>,
    /// The version of the tested schema or protocol, where the subject is one.
    pub schema_version: Nullable<PackageVersion>,
    /// The package the evidence is about, where it is about one.
    pub plugin_id: Nullable<PluginId>,
    /// The digest of that package's manifest.
    pub package_digest: Nullable<PayloadDigest>,
    /// The publisher whose signed record supplied the evidence, where one did.
    pub publisher_id: Nullable<PublisherId>,
}

/// What makes a capability record stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationTrigger {
    /// The tested binary changed.
    BinaryChanged,
    /// The active binding changed.
    BindingChanged,
    /// The upstream schema or protocol version changed.
    SchemaChanged,
    /// An operating-system permission changed.
    OsPermissionChanged,
    /// The desktop session generation changed.
    DesktopGenerationChanged,
    /// A signed profile in the catalogue changed.
    ProfileChanged,
}

impl JsonSchema for InvalidationTrigger {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "InvalidationTrigger".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::InvalidationTrigger".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": [
                "binary_changed",
                "binding_changed",
                "schema_changed",
                "os_permission_changed",
                "desktop_generation_changed",
                "profile_changed"
            ],
            "description": "What makes a capability record stale."
        })
    }
}

/// One capability evidence record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CapabilityEvidence {
    /// The versioned capability this record is about.
    pub capability_id: CapabilityId,
    /// The capability version.
    pub capability_version: PackageVersion,
    /// What the record is about.
    pub subject: EvidenceSubject,
    /// The exact identity the evidence was gathered against.
    pub identity: SubjectIdentity,
    /// The current revision of this record.
    pub revision: CapabilityRevision,
    /// The current state.
    pub state: CapabilityState,
    /// Where the record came from.
    pub source: EvidenceSource,
    /// What makes it stale.
    pub invalidated_by: CanonicalSet<InvalidationTrigger>,
    /// The user-facing reason, required whenever the state is not usable.
    pub disabled_reason: Nullable<DisabledReason>,
    /// When the record was gathered.
    pub observed_at: TimestampMs,
}

/// A capability evidence record that breaks one of the section 11 rules.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// A signed catalogue record or a package declaration claimed the capability works here.
    #[error("{source_name} evidence cannot establish that a capability is qualified on this host")]
    UnqualifiedSource {
        /// The source that overreached.
        source_name: &'static str,
    },
    /// An unusable state carried no reason for a person to read.
    #[error("state {state:?} needs a user-facing disabled reason")]
    MissingDisabledReason {
        /// The state that needed a reason.
        state: CapabilityState,
    },
    /// The record named nothing that could make it stale.
    #[error("a capability record must name at least one invalidation trigger")]
    NoInvalidationTrigger,
}

impl CapabilityEvidence {
    /// Checks the rules a capability record must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when a signed or declared record claims a host result it cannot
    /// establish, when an unusable state carries no user-facing reason, or when nothing would ever
    /// invalidate the record.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.state.is_usable() && !self.source.can_establish_qualified() {
            return Err(EvidenceError::UnqualifiedSource {
                source_name: match self.source {
                    EvidenceSource::SignedRecord => "signed catalogue",
                    EvidenceSource::PackageDeclaration => "package declaration",
                    EvidenceSource::HostProbe | EvidenceSource::LiveBinding => unreachable!(
                        "a host probe and a live binding can establish a qualified state"
                    ),
                },
            });
        }
        if !self.state.is_usable() && self.disabled_reason.0.is_none() {
            return Err(EvidenceError::MissingDisabledReason { state: self.state });
        }
        if self.invalidated_by.is_empty() {
            return Err(EvidenceError::NoInvalidationTrigger);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(state: CapabilityState, source: EvidenceSource) -> CapabilityEvidence {
        CapabilityEvidence {
            capability_id: CapabilityId::new("agent.approval.respond/1").expect("valid id"),
            capability_version: PackageVersion::parse("1.0.0").expect("valid version"),
            subject: EvidenceSubject {
                environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::NIL),
                application: Nullable(Some(Label::new("Codex").expect("valid label"))),
                terminal: Nullable(None),
                desktop_generation: Nullable(None),
            },
            identity: SubjectIdentity {
                binary_digest: Nullable(Some(PayloadDigest::of(b"codex"))),
                schema_version: Nullable(None),
                plugin_id: Nullable(None),
                package_digest: Nullable(None),
                publisher_id: Nullable(None),
            },
            revision: CapabilityRevision::new(4),
            state,
            source,
            invalidated_by: [InvalidationTrigger::BinaryChanged].into_iter().collect(),
            disabled_reason: Nullable(match state {
                CapabilityState::QualifiedAvailable => None,
                _ => Some(DisabledReason::new("Codex is not installed").expect("valid reason")),
            }),
            observed_at: TimestampMs::new(1_760_000_000_000),
        }
    }

    #[test]
    fn a_signed_record_cannot_claim_a_host_result() {
        let record = evidence(
            CapabilityState::QualifiedAvailable,
            EvidenceSource::SignedRecord,
        );
        assert!(matches!(
            record.validate(),
            Err(EvidenceError::UnqualifiedSource { .. })
        ));
        let probed = evidence(
            CapabilityState::QualifiedAvailable,
            EvidenceSource::HostProbe,
        );
        assert_eq!(probed.validate(), Ok(()));
    }

    #[test]
    fn a_signed_record_may_still_report_incompatibility() {
        let record = evidence(CapabilityState::Incompatible, EvidenceSource::SignedRecord);
        assert_eq!(record.validate(), Ok(()));
    }

    #[test]
    fn an_unusable_state_needs_a_reason_a_person_can_read() {
        let mut record = evidence(
            CapabilityState::MissingInstallation,
            EvidenceSource::HostProbe,
        );
        record.disabled_reason = Nullable(None);
        assert!(matches!(
            record.validate(),
            Err(EvidenceError::MissingDisabledReason { .. })
        ));
    }

    #[test]
    fn a_record_that_nothing_invalidates_is_rejected() {
        let mut record = evidence(
            CapabilityState::QualifiedAvailable,
            EvidenceSource::LiveBinding,
        );
        record.invalidated_by = CanonicalSet::new();
        assert_eq!(record.validate(), Err(EvidenceError::NoInvalidationTrigger));
    }

    #[test]
    fn the_default_ceiling_is_the_three_passive_capabilities() {
        assert_eq!(PluginCapability::DEFAULT_REPOSITORY_CEILING.len(), 3);
        for capability in PluginCapability::ALL {
            assert_eq!(
                capability.within_default_ceiling(),
                PluginCapability::DEFAULT_REPOSITORY_CEILING.contains(capability)
            );
        }
        assert!(!PluginCapability::TerminalInput.within_default_ceiling());
        assert!(PluginCapability::NativeBridgeInstall.requires_installation_grant());
    }
}
