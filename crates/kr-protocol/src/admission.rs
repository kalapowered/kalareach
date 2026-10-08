//! The plugin admissions a control daemon hands the workers it runs, and what each worker reports
//! back about its live bindings.
//!
//! The daemon decides what is admitted, from its catalogue's records: which installed packages new
//! bindings may use, with their exact hashes, origins, effective grants and signed builds, and what
//! each release a live binding holds is now (its revocation, the most it may use, and whether it
//! ends). A worker reads each admitted package from its checked copy itself and binds only what it
//! was admitted, at the frame it holds. Nothing here states a package's command integration, its
//! match rules or its tables: those are the verified manifest's, and the worker takes them from
//! there.
//!
//! A snapshot travels as `parts` frames of one [`FrameId`], every part holding whole records, and
//! is applied only once every part has arrived; the worker's answer is paged the same way. The
//! first snapshot follows a worker's launch specification on the rendezvous connection, which
//! [`AdmissionsHeader`] announces; every later one travels on the daemon's authority connection to
//! the worker, which answers each complete snapshot with [`PluginAdmissionsAck`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ApplicationInstanceId, BrokerBindingId, ControllerGeneration, EnvironmentId, PluginId,
    PublisherId, SessionId,
};
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};

/// Which admissions frame this is: the daemon generation that sent it, the admission revision it
/// carries, and the round.
///
/// Frames are ordered by generation, then revision, then round, and a worker applies only a frame
/// above the one it holds. The daemon raises the round on every frame it sends a worker, from one
/// in each generation, so a frame sent again at an unchanged revision is still newer than the last.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct FrameId {
    /// The daemon generation whose connection carried the frame.
    pub generation: ControllerGeneration,
    /// The admission revision the frame carries.
    pub revision: U64,
    /// The round, raised on every frame this generation sends the worker.
    pub round: U64,
}

/// What follows a launch specification: the first snapshot of admissions, in `parts` frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionsHeader {
    /// The snapshot's frame.
    pub frame: FrameId,
    /// How many [`PluginAdmissions`] frames follow the specification, at least one.
    pub parts: u32,
}

/// What the administrator's policy does to a live binding whose release is revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationPolicy {
    /// The binding keeps serving, and warns.
    WarnOnly,
    /// The binding keeps observing, and every rich admission through it is refused.
    DisableAtNextAdmission,
    /// The binding closes at its next admission boundary.
    DisableAtOnce,
}

/// Where a release came from: the repository's name and the enrolment it came through.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ReleaseOrigin {
    /// The repository's name.
    pub repository_id: String,
    /// This host's identity for the enrolment the release came through.
    pub enrolment_key: String,
}

/// The native bridge an installation put in place for a package, as the host applied it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedBridge {
    /// The application name the installed registration starts the forwarder for.
    pub application: String,
    /// The registrations the installed recipe wrote, by wire name.
    pub surfaces: Vec<String>,
    /// The forwarder executable the installed registration starts, as an absolute path.
    pub forwarder: String,
}

/// One executable a signed build record of the release names for this host's platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedBuild {
    /// The SHA-256 digest of the executable.
    pub executable_digest: Digest256,
    /// The version the record says it is.
    pub version: String,
}

/// A package's component, by its path below the directory that holds every repository's store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedComponent {
    /// The component's path relative to that directory, with `/` between its parts.
    pub path: String,
    /// The component's digest.
    pub digest: Digest256,
    /// Its exact size.
    pub bytes: U64,
}

/// One package new bindings may use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedPackage {
    /// The package.
    pub plugin_id: PluginId,
    /// Its publisher.
    pub publisher_id: PublisherId,
    /// The installed release.
    pub version: String,
    /// The exact installed package hash: the digest of its manifest.
    pub package_digest: Digest256,
    /// Where it came from.
    pub origin: ReleaseOrigin,
    /// The absolute directory its checked, extracted copy is in.
    pub package_dir: String,
    /// What the installation may use, by capability wire name.
    pub grants: Vec<String>,
    /// The native bridge the installation put in place, where it put one.
    pub bridge: Nullable<AdmittedBridge>,
    /// The builds the release's signed record names for this host's platform.
    pub builds: Vec<AdmittedBuild>,
    /// Its component, where it ships one.
    pub component: Nullable<AdmittedComponent>,
}

/// A revocation the release's own repository published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRevocation {
    /// Why, as the repository states it.
    pub reason: String,
    /// When it was published.
    pub revoked_at: TimestampMs,
    /// What a person reads about it.
    pub statement: String,
}

/// What one release a binding may hold is now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseState {
    /// The package.
    pub plugin_id: PluginId,
    /// The exact package hash.
    pub package_digest: Digest256,
    /// Where it came from.
    pub origin: ReleaseOrigin,
    /// The revocation its own repository publishes, where it publishes one.
    pub revocation: Nullable<AdmissionRevocation>,
    /// The most a binding on it may use, by capability wire name.
    pub grant_cap: Vec<String>,
    /// Whether a binding on it ends at its next admission boundary.
    pub ends_at_next_boundary: bool,
}

/// One part of a snapshot of admissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginAdmissions {
    /// The environment the admissions are for.
    pub environment_id: EnvironmentId,
    /// The snapshot's frame, the same in every part.
    pub frame: FrameId,
    /// Which part this is, from one.
    pub part: u32,
    /// How many parts the snapshot has.
    pub parts: u32,
    /// The administrator's revocation policy.
    pub policy: RevocationPolicy,
    /// This part's share of the packages new bindings may use.
    pub packages: Vec<AdmittedPackage>,
    /// This part's share of the release states.
    pub releases: Vec<ReleaseState>,
}

/// One release a live binding holds.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct LiveRelease {
    /// The package.
    pub plugin_id: PluginId,
    /// Its publisher.
    pub publisher_id: PublisherId,
    /// The release's version.
    pub version: String,
    /// The exact package hash the binding holds.
    pub package_digest: Digest256,
    /// Where it came from.
    pub origin: ReleaseOrigin,
}

/// Where a binding's component stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Not registered with a plugin runtime yet.
    Pending,
    /// Registered and running.
    Registered,
    /// No plugin runtime can run it now.
    Unavailable,
    /// Disabled after its faults, for the binding's life.
    Disabled,
}

/// What a binding's component is doing, where the package ships one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentReport {
    /// Where it stands.
    pub state: ComponentState,
    /// Why, where the state has a reason, cut to the report's bound.
    pub reason: Nullable<String>,
    /// True when the reason was cut.
    pub reason_cut: bool,
}

/// A worker's request that the plugin runtime be running, sent to the control daemon on its
/// rendezvous endpoint.
///
/// The runtime is started when a binding first needs a component and not before, so this is what a
/// worker sends when one of its bindings holds a package that ships one. The daemon accepts it only
/// from the process it recorded for the session, as the kernel names that process; the reply is a
/// [`PluginRuntimeState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRuntimeWanted {
    /// The session whose worker asks.
    pub session_id: SessionId,
}

/// The control daemon's answer to a [`PluginRuntimeWanted`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginRuntimeState {
    /// The runtime is running and its descriptor is published: the worker connects to it and
    /// registers its bindings.
    Running,
    /// The runtime cannot be reached now.
    Unavailable(PluginRuntimeUnavailable),
}

/// Why the plugin runtime cannot be reached, and when to ask again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginRuntimeUnavailable {
    /// Why, cut to the report's bound.
    pub reason: String,
    /// How long the worker leaves before it asks again, in milliseconds.
    pub retry_after_ms: U64,
}

/// One live binding, as a worker reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveBinding {
    /// The binding.
    pub binding_id: BrokerBindingId,
    /// The instance it is bound to.
    pub application_instance_id: ApplicationInstanceId,
    /// The release it holds.
    pub release: LiveRelease,
    /// True while it is due to end and its admitted requests finish.
    pub ending: bool,
    /// Its component, where the package ships one.
    pub component: Nullable<ComponentReport>,
}

/// An admitted package a worker would not read or bind, or would use only in part, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageRefusal {
    /// The package's exact hash.
    pub package_digest: Digest256,
    /// Why, cut to the report's bound.
    pub detail: String,
    /// True when the detail was cut.
    pub detail_cut: bool,
}

/// One part of a worker's answer to a complete snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginAdmissionsAck {
    /// The session whose worker answers.
    pub session_id: SessionId,
    /// The frame the worker holds, which it applied before answering.
    pub frame: FrameId,
    /// The report's number, which rises with every report this worker process makes.
    pub report_seq: U64,
    /// Which part this is, from one.
    pub part: u32,
    /// How many parts the report has.
    pub parts: u32,
    /// This part's share of the live bindings.
    pub bindings: Vec<LiveBinding>,
    /// This part's share of the packages refused or used only in part.
    pub refusals: Vec<PackageRefusal>,
}

/// A live release no installation describes any more, as `plugin.list` reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveReleaseSummary {
    /// The package.
    pub plugin_id: PluginId,
    /// The release's version.
    pub version: String,
    /// The exact package hash.
    pub package_digest: String,
    /// The repository it came from.
    pub catalogue_id: String,
    /// How many live bindings hold it, counted from reports every worker made after the read
    /// began; null while a worker has not reported.
    pub live_bindings: Nullable<U64>,
    /// True while its bindings are due to end.
    pub ending: bool,
    /// True when its repository revoked it.
    pub revoked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(generation: u64, revision: u64, round: u64) -> FrameId {
        FrameId {
            generation: ControllerGeneration::new(generation),
            revision: U64::new(revision),
            round: U64::new(round),
        }
    }

    /// Frames are ordered by generation, then revision, then round.
    #[test]
    fn frames_order_by_generation_then_revision_then_round() {
        assert!(frame(1, 9, 9) < frame(2, 0, 1));
        assert!(frame(2, 3, 9) < frame(2, 4, 1));
        assert!(frame(2, 4, 1) < frame(2, 4, 2));
        assert_eq!(frame(2, 4, 2), frame(2, 4, 2));
    }
}
