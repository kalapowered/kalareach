//! Host and environment reads, and read-only diagnostics.
//!
//! `host.doctor` reports; it does not repair unless an individual repair is requested, and it
//! redacts credentials rather than printing an environment snapshot.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::hello::ProtocolVersion;
use crate::identity::{BootIdentity, WorkerProfile};
use crate::ids::{BuildId, ControllerGeneration, EnvironmentId};
use crate::scalars::{Nullable, TimestampMs, U64};

/// The result of `host.info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostInfoResult {
    /// The controller build.
    pub build_id: BuildId,
    /// The protocol version this build implements.
    pub protocol_version: ProtocolVersion,
    /// The environment this controller owns.
    pub environment_id: EnvironmentId,
    /// The controller's current generation. A replacement controller uses a strictly higher one.
    pub generation: ControllerGeneration,
    /// The boot this host is running.
    pub boot_identity: BootIdentity,
    /// When this controller process started serving.
    pub started_at_ms: TimestampMs,
    /// How many sessions are live or creating.
    pub live_sessions: U64,
    /// The configured admission limit.
    pub session_limit: U64,
    /// The worker profile this host creates sessions with unless the request says otherwise.
    pub default_worker_profile: WorkerProfile,
}

/// One environment this host serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSummary {
    /// The environment identity. It binds one installation and one OS user.
    pub environment_id: EnvironmentId,
    /// A label for people.
    pub label: String,
    /// The operating system.
    pub os: String,
    /// The processor architecture.
    pub arch: String,
    /// The OS user the environment belongs to.
    pub os_user: String,
    /// The runtime directory holding sockets and worker descriptors.
    pub runtime_directory: String,
    /// The state directory holding the registry, journals and spools.
    pub state_directory: String,
    /// How many sessions are live or creating.
    pub live_sessions: U64,
}

/// The result of `environment.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentListResult {
    /// The environments.
    pub environments: Vec<EnvironmentSummary>,
}

/// What one diagnostic check found.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    /// The check passed.
    Ok,
    /// The check passed with something worth knowing.
    Warning,
    /// The check failed.
    Failed,
    /// The check does not apply to this platform or configuration.
    NotApplicable,
}

impl DoctorStatus {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Returns true when the check should stop an exit code from being zero.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// One diagnostic check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    /// A stable identifier for the check.
    pub id: String,
    /// What it examines.
    pub title: String,
    /// What it found.
    pub status: DoctorStatus,
    /// A plain description of the finding. Credentials are redacted.
    pub detail: String,
    /// What the user should do, when the check did not pass.
    pub remedy: Nullable<String>,
}

/// The result of `host.doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostDoctorResult {
    /// Every check, in the order they ran.
    pub checks: Vec<DoctorCheck>,
    /// True when no check failed.
    pub healthy: bool,
}
