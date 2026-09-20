//! The plugin catalogue and plugin method groups.
//!
//! Section 23 gives these thirteen methods two rows of the method table, and each row states what
//! the host checks before it acts. The types here carry exactly what those checks need and nothing
//! a caller could assert instead of the host deciding it.
//!
//! * A catalogue is named by the identifier this host gave it, never by a URL a caller supplies at
//!   the point of use. `catalogue.add` is where a location is accepted, and it is the one method
//!   in the group that always needs the owner's confirmation.
//! * A package is named by its identity and, where the method acts on bytes, by the exact package
//!   hash. Pinning and rollback operate on immutable hashes, so a hash is a parameter rather than
//!   something resolved from a version at the time of the effect.
//! * A capability read reports what the package asks for, who has to permit it and whether it is
//!   permitted as things stand. It reports no grant of its own: the answer is derived from the
//!   repository's ceiling and the installation grant, and reading it changes neither.
//!
//! # Capability vocabulary
//!
//! [`PluginCapabilityState`] is the section 11 runtime-state vocabulary as the wire carries it,
//! and it is the same seven states `kr_plugin_sdk::capability::CapabilityState` uses, spelled the
//! same way. The two are proved identical by a test in the crate that holds both, so a host cannot
//! report a state a client has no name for.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{CapabilityId, EnvironmentId, PluginId, RepositoryGeneration};
use crate::pairing::OwnerConfirmationProof;
use crate::scalars::{Nullable, TimestampMs, U64};

/// The kind of repository an enrolment is.
///
/// The kind is descriptive and changes nothing about verification: every repository's metadata is
/// verified against the root this host adopted for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogueKind {
    /// The repository KalaReach ships the root for.
    Official,
    /// A vendor's own repository.
    Vendor,
    /// A community repository with its own root.
    Community,
    /// A directory on this machine.
    Local,
    /// A mirror of another repository, carrying that repository's root.
    Mirror,
}

/// The budgets one repository runs inside.
///
/// Enrolment sets these before the first fetch. Exceeding one leaves the previous generation
/// usable and reports which allowance ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueBudgets {
    /// Maximum bytes of catalogue metadata.
    pub metadata_bytes: U64,
    /// Maximum number of index entries.
    pub metadata_entries: U64,
    /// Maximum bytes of cached payloads.
    pub payload_cache_bytes: U64,
    /// Whether every referenced payload is fetched rather than only what is installed.
    ///
    /// A larger full mirror is this setting plus a payload budget that admits it. It is never
    /// reached by syncing more often.
    pub full_offline_mirror: bool,
}

/// One enrolled repository as `catalogue.list` reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueSummary {
    /// This host's identifier for the repository.
    pub catalogue_id: String,
    /// What kind of repository it is.
    pub kind: CatalogueKind,
    /// Where its metadata lives.
    pub metadata_url: String,
    /// Where its targets live.
    pub targets_url: String,
    /// The digest of the trust root this host adopted for it.
    ///
    /// A repository verified against a different root is a different trust anchor, whatever it is
    /// called, so the digest is shown rather than a name.
    pub root_digest: String,
    /// The generation currently active, where one is.
    pub generation: Nullable<RepositoryGeneration>,
    /// The generation the owner pinned, where one is pinned.
    pub pinned_generation: Nullable<RepositoryGeneration>,
    /// The budgets it runs inside.
    pub budgets: CatalogueBudgets,
    /// What its packages may do without a further grant.
    pub ceiling: Vec<String>,
    /// How many entries its index carries.
    pub entries: U64,
    /// When it last synchronised, where it has.
    pub synced_at_ms: Nullable<TimestampMs>,
}

/// Parameters of `catalogue.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueListParams {
    /// The environment whose catalogues are listed.
    pub environment_id: EnvironmentId,
}

/// Result of `catalogue.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueListResult {
    /// The enrolled repositories, ordered by identifier.
    pub catalogues: Vec<CatalogueSummary>,
}

/// Parameters of `catalogue.add`.
///
/// Adding a catalogue adopts a trust root, which is always the owner's decision. The root travels
/// with the request because a host that fetched it from the location it is meant to verify would
/// be trusting the thing it is checking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueAddParams {
    /// The environment the repository is enrolled in.
    pub environment_id: EnvironmentId,
    /// This host's identifier for the repository.
    pub catalogue_id: String,
    /// What kind of repository it is.
    pub kind: CatalogueKind,
    /// Where its metadata lives.
    pub metadata_url: String,
    /// Where its targets live.
    pub targets_url: String,
    /// The trust root, as its bytes, base64 encoded.
    pub root: String,
    /// The budgets it runs inside.
    pub budgets: CatalogueBudgets,
    /// Capabilities its packages may hold without a further grant, beyond the default ceiling.
    pub ceiling: Vec<String>,
    /// The owner's confirmation of this exact enrolment.
    ///
    /// Adopting a root is one of the actions section 10 requires a fresh confirmation for, bound
    /// to the exact action digest and consumed once. It is not optional here: a caller's
    /// operating-system identity is explicitly not that confirmation, so there is no shape of this
    /// request that carries none.
    pub owner_confirmation: OwnerConfirmationProof,
}

/// Result of `catalogue.add`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueAddResult {
    /// The repository as it was enrolled.
    pub catalogue: CatalogueSummary,
}

/// Parameters of `catalogue.sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueSyncParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The repository to synchronise.
    pub catalogue_id: String,
}

/// Result of `catalogue.sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueSyncResult {
    /// The generation now active.
    pub generation: RepositoryGeneration,
    /// How many entries its index carries.
    pub entries: U64,
    /// How many bytes the index is.
    pub index_bytes: U64,
    /// How many payloads a full mirror fetched.
    pub mirrored_payloads: U64,
    /// The vendor delegations the generation carries, each scoped to one publisher.
    pub delegations: Vec<CatalogueDelegation>,
}

/// One vendor delegation beneath a repository's root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueDelegation {
    /// The delegated role's name.
    pub role: String,
    /// The one publisher it may sign for.
    pub publisher_id: String,
}

/// Parameters of `catalogue.pin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CataloguePinParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The repository to pin.
    pub catalogue_id: String,
    /// The generation to hold it at, or nothing to remove the pin.
    pub generation: Nullable<RepositoryGeneration>,
}

/// Result of `catalogue.pin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CataloguePinResult {
    /// The repository as it now stands.
    pub catalogue: CatalogueSummary,
}

/// Parameters of `catalogue.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueRemoveParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The repository to remove.
    pub catalogue_id: String,
}

/// Result of `catalogue.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogueRemoveResult {
    /// The repository that was removed.
    pub catalogue_id: String,
    /// The packages still installed from it, which removing a repository does not uninstall.
    pub installed_packages: Vec<PluginId>,
}

/// The section 11 runtime-state vocabulary.
///
/// Seven states, because "unavailable" alone sends a person to the wrong fix. The one that is easy
/// to miss is [`Self::VersionQualified`]: a signed catalogue artifact says how a release behaved
/// where it was tested, which is not the same as saying it works on this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapabilityState {
    /// Tested here and working.
    QualifiedAvailable,
    /// This release was qualified, and this host has not been checked.
    VersionQualified,
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

impl PluginCapabilityState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::QualifiedAvailable,
        Self::VersionQualified,
        Self::MissingInstallation,
        Self::PermissionRequired,
        Self::Incompatible,
        Self::TemporarilyUnavailable,
        Self::NotTested,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedAvailable => "qualified_available",
            Self::VersionQualified => "version_qualified",
            Self::MissingInstallation => "missing_installation",
            Self::PermissionRequired => "permission_required",
            Self::Incompatible => "incompatible",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::NotTested => "not_tested",
        }
    }
}

/// Where a capability answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginEvidenceSource {
    /// A bounded disclosed probe with declared effects, run on this host.
    HostProbe,
    /// A live binding that performed the operation on this host.
    LiveBinding,
    /// A signed compatibility record shipped in the catalogue.
    SignedRecord,
    /// The package's own declaration, believed only for negative states.
    PackageDeclaration,
}

impl PluginEvidenceSource {
    /// Every source, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::HostProbe,
        Self::LiveBinding,
        Self::SignedRecord,
        Self::PackageDeclaration,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostProbe => "host_probe",
            Self::LiveBinding => "live_binding",
            Self::SignedRecord => "signed_record",
            Self::PackageDeclaration => "package_declaration",
        }
    }
}

/// What makes a capability answer stale.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvalidationTrigger {
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

impl PluginInvalidationTrigger {
    /// Every trigger, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::BinaryChanged,
        Self::BindingChanged,
        Self::SchemaChanged,
        Self::OsPermissionChanged,
        Self::DesktopGenerationChanged,
        Self::ProfileChanged,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryChanged => "binary_changed",
            Self::BindingChanged => "binding_changed",
            Self::SchemaChanged => "schema_changed",
            Self::OsPermissionChanged => "os_permission_changed",
            Self::DesktopGenerationChanged => "desktop_generation_changed",
            Self::ProfileChanged => "profile_changed",
        }
    }
}

/// Who has to permit one capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginGrantRequirement {
    /// The repository's ceiling already permits it.
    WithinCeiling,
    /// An explicit package or repository grant is needed.
    RepositoryGrant,
    /// An explicit installation grant is needed.
    InstallationGrant,
    /// An installation grant the owner confirms, because the code runs outside the sandbox.
    ConfirmedInstallationGrant,
}

/// One capability a package asks for, and where it stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilityGrant {
    /// The capability, in the shared versioned namespace.
    pub capability: CapabilityId,
    /// Who has to permit it.
    pub requirement: PluginGrantRequirement,
    /// Whether it is permitted as things stand.
    pub permitted: bool,
    /// What the package said it needs it for.
    pub reason: String,
}

/// What this host currently knows about one capability of one installed package.
///
/// Evidence describes feasibility and never creates authority. An action still checks its grant,
/// and it rechecks this record's revision independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilityEvidence {
    /// The capability, in the shared versioned namespace.
    pub capability: CapabilityId,
    /// What the answer is.
    pub state: PluginCapabilityState,
    /// Where it came from.
    pub source: PluginEvidenceSource,
    /// The exact package hash the answer is about.
    ///
    /// A live binding stays on the hash it was made against, so a record for another release is
    /// about another release and never moves it.
    pub package_digest: String,
    /// The digest of the signed qualification profile the answer came from, where one did.
    pub profile_digest: Nullable<String>,
    /// What makes the answer stale.
    pub invalidated_by: Vec<PluginInvalidationTrigger>,
    /// What a person is told when the capability is not available.
    pub disabled_reason: Nullable<String>,
    /// When the answer was established.
    pub observed_at_ms: TimestampMs,
}

/// One installed plugin as `plugin.list` reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSummary {
    /// The package.
    pub plugin_id: PluginId,
    /// The repository it came from.
    pub catalogue_id: String,
    /// The installed release.
    pub version: String,
    /// The exact package hash installed.
    pub package_digest: String,
    /// The environment it is installed in.
    pub environment_id: EnvironmentId,
    /// Whether it is enabled here.
    pub enabled: bool,
    /// Whether the owner pinned this exact hash.
    pub pinned: bool,
    /// Whether the catalogue has revoked this release.
    pub revoked: bool,
    /// How many live bindings hold it.
    pub live_bindings: U64,
}

/// Parameters of `plugin.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginListParams {
    /// The environment whose installations are listed.
    pub environment_id: EnvironmentId,
}

/// Result of `plugin.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginListResult {
    /// The installations, ordered by package identifier.
    pub plugins: Vec<PluginSummary>,
}

/// Parameters of `plugin.install`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginInstallParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The repository to install from.
    pub catalogue_id: String,
    /// The package.
    pub plugin_id: PluginId,
    /// The release.
    pub version: String,
    /// The exact package hash the caller expects.
    ///
    /// Installation verifies the signature before it installs, and the hash makes the caller's
    /// expectation explicit: a repository that published something else between the caller reading
    /// the index and this request arriving is a refusal rather than a surprise.
    pub package_digest: String,
    /// Capabilities the owner is granting this installation.
    pub grant: Vec<String>,
}

/// Result of `plugin.install`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginInstallResult {
    /// The installation as it now stands.
    pub plugin: PluginSummary,
    /// What each requested capability needs, and whether it has it.
    pub capabilities: Vec<PluginCapabilityGrant>,
}

/// Parameters of `plugin.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRemoveParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
}

/// Result of `plugin.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRemoveResult {
    /// The package that was removed.
    pub plugin_id: PluginId,
    /// How many live bindings it had, which removal closed.
    pub closed_bindings: U64,
}

/// Parameters of `plugin.pin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginPinParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
    /// The exact package hash to hold it at, or nothing to remove the pin.
    pub package_digest: Nullable<String>,
}

/// Result of `plugin.pin`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginPinResult {
    /// The installation as it now stands.
    pub plugin: PluginSummary,
}

/// Parameters of `plugin.enable` and `plugin.disable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginEnableParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
}

/// Result of `plugin.enable` and `plugin.disable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginEnableResult {
    /// The installation as it now stands.
    pub plugin: PluginSummary,
}

/// Parameters of `plugin.grant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginGrantParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
    /// The exact package hash the grant is for.
    ///
    /// A grant is decided about a release the owner was shown. Naming the hash is what stops a
    /// decision made about one release reaching whatever is installed by the time it arrives.
    pub package_digest: String,
    /// The capabilities the installation is to hold after this change.
    ///
    /// The whole set, not an addition: an increase over what the installation already had is a new
    /// decision, and a host that received only additions could not tell one from a removal.
    pub grant: Vec<String>,
    /// The owner's confirmation of this exact grant.
    ///
    /// Bound to the package hash and the capability set above, so a confirmation cannot be carried
    /// to another release or a wider set.
    pub owner_confirmation: OwnerConfirmationProof,
}

/// Result of `plugin.grant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginGrantResult {
    /// The installation as it now stands.
    pub plugin: PluginSummary,
    /// What each requested capability needs, and whether it has it.
    pub capabilities: Vec<PluginCapabilityGrant>,
}

/// Parameters of `plugin.capabilities`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilitiesParams {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
}

/// Result of `plugin.capabilities`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilitiesResult {
    /// The installation the answer is about.
    pub plugin: PluginSummary,
    /// What each requested capability needs, and whether it has it.
    pub capabilities: Vec<PluginCapabilityGrant>,
    /// What this host currently knows about each of them.
    pub evidence: Vec<PluginCapabilityEvidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_state_vocabulary_is_the_seven_section_eleven_states() {
        assert_eq!(PluginCapabilityState::ALL.len(), 7);
        let rendered: Vec<String> = PluginCapabilityState::ALL
            .iter()
            .map(|state| {
                serde_json::to_string(state)
                    .expect("serialisable")
                    .trim_matches('"')
                    .to_owned()
            })
            .collect();
        assert_eq!(
            rendered,
            vec![
                "qualified_available",
                "version_qualified",
                "missing_installation",
                "permission_required",
                "incompatible",
                "temporarily_unavailable",
                "not_tested",
            ]
        );
        for state in PluginCapabilityState::ALL {
            assert_eq!(
                serde_json::to_string(state)
                    .expect("serialisable")
                    .trim_matches('"'),
                state.as_str()
            );
        }
    }

    #[test]
    fn every_source_and_trigger_renders_as_its_own_name() {
        for source in PluginEvidenceSource::ALL {
            assert_eq!(
                serde_json::to_string(source)
                    .expect("serialisable")
                    .trim_matches('"'),
                source.as_str()
            );
        }
        for trigger in PluginInvalidationTrigger::ALL {
            assert_eq!(
                serde_json::to_string(trigger)
                    .expect("serialisable")
                    .trim_matches('"'),
                trigger.as_str()
            );
        }
    }
}
