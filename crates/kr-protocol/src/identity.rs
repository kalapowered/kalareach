//! Host, process, worker and environment identities.
//!
//! A filename or a bare process identifier is a hint. What binds a running worker to the session
//! the controller reserved is the pair of identities here: the boot the host is currently running
//! and the kernel's own record of when that process started. Both are compared against the values
//! the launcher recorded, and both are covered by the worker's verification signature, so a reused
//! process identifier after a crash cannot pass as the original worker.
//!
//! Each identity names the source it came from. The values are only ever compared with another
//! value from the same source on the same host; they are not a portable measurement of time.
//!
//! The same rule decides what identifies an *environment*. Section 3 gives each installation in
//! one OS execution environment and one OS user identity its own `environment_id`, and says that a
//! reused human container name is not an identity. So an enrolment records the identity the
//! platform issues beside the name a person selects it by, and every check compares the identity.
//! The enrolment, the owner-approved cached inventory built from it, and the handshake the local
//! process bridge opens with are all below.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::actor::ActorIngress;
use crate::envelope::ControlFrame;
use crate::error::ProtocolError;
use crate::hello::{ActionWindow, ProtocolVersion};
use crate::ids::{BuildId, ConnectionId, DesktopSessionId, EnvironmentId, SessionId};
use crate::local::LocalRole;
use crate::scalars::{Bytes, Nullable, TimestampMs, U64};

/// Where a boot identity came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BootIdentitySource {
    /// Linux `/proc/sys/kernel/random/boot_id`: a fresh identifier for each boot.
    LinuxBootId,
    /// macOS `kern.bootsessionuuid`: a fresh identifier for each boot.
    MacosBootSessionUuid,
    /// The host's recorded boot time, used where the kernel offers no boot identifier.
    BootTime,
}

/// The identity of the host's current boot.
///
/// A worker is bound to the boot it started in. After a reboot every previous session is closed,
/// so a descriptor naming an older boot is stale whatever its file says.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct BootIdentity {
    /// Where the value came from.
    pub source: BootIdentitySource,
    /// The opaque value. Compared for equality, never interpreted.
    pub value: Bytes,
}

/// Where a process start identity came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStartSource {
    /// Linux `/proc/<pid>/stat` field 22: start time in clock ticks since boot.
    LinuxProcStat,
    /// macOS `proc_pidinfo(PROC_PIDTBSDINFO)`: start time in microseconds since the epoch.
    MacosProcBsdInfo,
    /// Windows: the process creation time in whole seconds since the epoch.
    ///
    /// The kernel records 100-nanosecond intervals, and the safe reader this host uses reports
    /// whole seconds. Two processes that share an identifier within one second are therefore
    /// indistinguishable by this value alone, which is why a Windows worker also owns a per-session
    /// Job Object that a recycled identifier cannot join.
    WindowsProcessStartSeconds,
}

/// A process and the kernel's record of when it started.
///
/// Every ownership check compares both fields. A process identifier alone can be reused by an
/// unrelated program within milliseconds of the original exiting, so the host never terminates,
/// adopts or trusts a process on its identifier alone.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartIdentity {
    /// The operating-system process identifier.
    pub pid: U64,
    /// Where the start value came from.
    pub source: ProcessStartSource,
    /// The kernel's start value in the source's own units.
    pub start_value: U64,
}

impl ProcessStartIdentity {
    /// Builds an identity.
    #[must_use]
    pub const fn new(pid: u64, source: ProcessStartSource, start_value: u64) -> Self {
        Self {
            pid: U64::new(pid),
            source,
            start_value: U64::new(start_value),
        }
    }

    /// Returns true when both the identifier and the start value match.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// How long a worker's execution context lasts.
///
/// The profile is recorded on every worker. It decides what a logout means: a desktop-bound worker
/// is closed with `desktop_lost` when its login-session generation ends, while a headless worker
/// survives logout where the platform's user service manager does.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProfile {
    /// Bound to the boot identity and the current graphical login-session generation.
    DesktopBound,
    /// Bound to the boot identity and the OS user, independently of a graphical login.
    HeadlessUser,
}

impl WorkerProfile {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesktopBound => "desktop_bound",
            Self::HeadlessUser => "headless_user",
        }
    }
}

/// The login session a desktop-bound worker is tied to.
///
/// `desktop_session_id` binds the OS user, the boot identity and the login-session generation. A
/// reusable console or session number alone is not an identity, so a new login never rebinds a
/// worker that lost its desktop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DesktopBinding {
    /// The desktop session this worker is bound to, for a desktop-bound profile.
    pub desktop_session_id: Nullable<DesktopSessionId>,
    /// The login-session generation the binding was taken at.
    pub login_generation: Nullable<U64>,
}

impl DesktopBinding {
    /// A binding for a worker that is not desktop-bound.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            desktop_session_id: Nullable::null(),
            login_generation: Nullable::null(),
        }
    }
}

/// How this host reaches one enrolled environment.
///
/// Section 3 keeps two of these apart on purpose. A WSL distribution and an enrolled container are
/// reached by a **local process bridge**: a child process started inside the target that speaks
/// this protocol over its own standard streams. An SSH login and a paired remote host are not.
/// An SSH user runs the destination command line under their own login, which is genuinely local
/// operating-system access there, and a named remote host in the application uses that
/// environment's paired endpoint. Neither is a bridge, and neither becomes one by forwarding a
/// socket.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentAccess {
    /// A WSL distribution on this Windows installation, reached by a local process bridge.
    WslDistribution,
    /// An enrolled container on this host, reached by a local process bridge.
    Container,
    /// A host an SSH login reaches, where the destination command line runs under that login.
    SshHost,
    /// A remote host the application reaches through that environment's own paired endpoint.
    PairedHost,
}

impl EnvironmentAccess {
    /// Every access class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::WslDistribution,
        Self::Container,
        Self::SshHost,
        Self::PairedHost,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WslDistribution => "wsl_distribution",
            Self::Container => "container",
            Self::SshHost => "ssh_host",
            Self::PairedHost => "paired_host",
        }
    }

    /// Returns true when this class is reached by a local process bridge.
    ///
    /// An access class that is not a process bridge never starts a helper: the bridge is the one
    /// path a request may cross, so anything else has to be refused by name rather than served
    /// through a launcher that happens to accept it.
    #[must_use]
    pub const fn is_process_bridge(self) -> bool {
        matches!(self, Self::WslDistribution | Self::Container)
    }
}

/// One enrolled environment, as its owner approved it.
///
/// Enrolment is what section 3 requires to be recorded: the distribution or container identity,
/// the operating-system user inside it, and the absolute path of the helper installed there. The
/// label is what a person types; it selects a record and is never compared as an identity, which
/// is why a container that is destroyed and recreated under the same name does not inherit this
/// row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEnrolment {
    /// The environment this record names. One installation, one OS user identity.
    pub environment_id: EnvironmentId,
    /// How this host reaches it.
    pub access: EnvironmentAccess,
    /// The name a person selects this record by. A label, never an identity.
    pub label: String,
    /// The identity the platform issues: the distribution name WSL registered, the container
    /// identifier the runtime issued, or the SSH destination. Compared exactly.
    pub target: String,
    /// The operating-system user the helper runs as inside the target.
    pub os_user: String,
    /// The absolute path of the helper installed in the target.
    pub helper_path: String,
    /// Where this environment's clipboard writes go, when the owner named a destination.
    ///
    /// Section 18 asks for explicit clipboard destinations. Absent means this environment has
    /// none, not that it inherits this host's.
    pub clipboard_destination: Nullable<String>,
    /// When the owner approved this record.
    pub approved_at_ms: TimestampMs,
}

/// Why an enrolment is not a well-formed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolmentError {
    /// The label is empty.
    EmptyLabel,
    /// The platform identity is empty.
    EmptyTarget,
    /// The operating-system user is empty.
    EmptyUser,
    /// The helper path is empty or not absolute.
    HelperPathNotAbsolute,
    /// A container target is a reusable name rather than a container identifier.
    ContainerTargetNotIdentifier,
}

impl core::fmt::Display for EnrolmentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyLabel => formatter.write_str("an enrolment carries the label people use"),
            Self::EmptyTarget => {
                formatter.write_str("an enrolment carries the identity the platform issued")
            }
            Self::EmptyUser => {
                formatter.write_str("an enrolment carries the operating-system user it runs as")
            }
            Self::HelperPathNotAbsolute => {
                formatter.write_str("an enrolment carries the absolute path of the helper")
            }
            Self::ContainerTargetNotIdentifier => formatter.write_str(
                "a container enrolment requires the container identifier, never a reusable \
                 container name",
            ),
        }
    }
}

/// The length of the identifier a container runtime issues, in hexadecimal digits.
pub const CONTAINER_IDENTIFIER_LEN: usize = 64;

/// Returns whether `target` is the identifier a container runtime issued.
///
/// Section 3: a reused human container name is not an identity. Nor is a short prefix of one: a
/// runtime resolves a prefix to whichever container carries it now, which is the same weakness a
/// name has. So a record carries the whole identifier the runtime issued, and anything else is
/// resolved to one before it is recorded.
#[must_use]
pub fn is_container_identifier(target: &str) -> bool {
    target.len() == CONTAINER_IDENTIFIER_LEN && target.chars().all(|c| c.is_ascii_hexdigit())
}

impl std::error::Error for EnrolmentError {}

impl EnvironmentEnrolment {
    /// Checks that this record carries everything an enrolment has to record.
    ///
    /// # Errors
    ///
    /// Returns [`EnrolmentError`] naming the first field that is missing or not absolute.
    pub fn validate(&self) -> Result<(), EnrolmentError> {
        if self.label.trim().is_empty() {
            return Err(EnrolmentError::EmptyLabel);
        }
        validate_destination(self.access, &self.target, &self.os_user, &self.helper_path)
    }

    /// Returns true when `selector` selects this record.
    ///
    /// A person types the label; the environment identifier selects the one record that carries
    /// it, which is how two records that share a label are told apart. Neither is authority: the
    /// caller still compares [`Self::environment_id`] against what the environment itself reports
    /// before it acts on anything.
    #[must_use]
    pub fn selected_by(&self, selector: &str) -> bool {
        self.label == selector || self.environment_id.to_string() == selector
    }
}

/// Checks the destination a process bridge is started against.
///
/// This is the part of an enrolment that names where the helper runs: the platform identity, the
/// operating-system user inside it and the absolute helper path. Enrolment discovery has those
/// three before it has an identity for the record, so the check lives here rather than only on the
/// whole record.
///
/// # Errors
///
/// Returns [`EnrolmentError`] naming the first field that is missing, not absolute, or a reusable
/// container name where an identifier is required.
pub fn validate_destination(
    access: EnvironmentAccess,
    target: &str,
    os_user: &str,
    helper_path: &str,
) -> Result<(), EnrolmentError> {
    if target.trim().is_empty() {
        return Err(EnrolmentError::EmptyTarget);
    }
    if os_user.trim().is_empty() {
        return Err(EnrolmentError::EmptyUser);
    }
    if !helper_path_is_absolute(helper_path) {
        return Err(EnrolmentError::HelperPathNotAbsolute);
    }
    if access == EnvironmentAccess::Container && !is_container_identifier(target) {
        return Err(EnrolmentError::ContainerTargetNotIdentifier);
    }
    Ok(())
}

/// Whether a helper path names an absolute location in the target environment.
///
/// The target is not always this platform, so this is decided on the text rather than by asking
/// this operating system. A POSIX absolute path begins with `/`; a Windows one begins with a
/// drive letter and a separator, or with a UNC prefix.
fn helper_path_is_absolute(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with("\\\\") {
        return true;
    }
    let mut characters = path.chars();
    match (characters.next(), characters.next(), characters.next()) {
        (Some(drive), Some(':'), Some('\\' | '/')) => drive.is_ascii_alphabetic(),
        _ => false,
    }
}

/// What this host last observed about an enrolled environment.
///
/// Section 3: a listing carries an explicit `stale` or `environment_stopped` status, and a cached
/// row is not evidence that a process is currently live.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentPresence {
    /// The environment was running when it was last observed.
    Running,
    /// The environment was stopped when it was last observed.
    EnvironmentStopped,
    /// Nothing recent enough to describe the present has been observed.
    Stale,
}

impl EnvironmentPresence {
    /// Every presence value, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Running, Self::EnvironmentStopped, Self::Stale];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::EnvironmentStopped => "environment_stopped",
            Self::Stale => "stale",
        }
    }
}

/// Where the observation in a row came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// Read from this host's cache. Nothing was contacted or started to produce it.
    Cache,
    /// Observed by asking the platform, as part of an explicit refresh.
    Refresh,
}

/// What a named environment still needs before the bridge can serve it.
///
/// Section 18: an SSH or container integration still needs a suitable helper and scoped
/// credentials in the target environment, and socket forwarding alone does not install it. So the
/// two conditions are reported separately and neither is inferred from the other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentReadiness {
    /// Whether the enrolment names a helper this host would run.
    pub helper_enrolled: bool,
    /// Whether the owner has granted this environment its own scoped local channel.
    pub channel_scoped: bool,
    /// What a person should do when either is missing.
    pub detail: String,
}

impl EnvironmentReadiness {
    /// Returns true when the environment carries both halves of the integration.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.helper_enrolled && self.channel_scoped
    }
}

/// One row of the owner-approved cached inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInventoryRow {
    /// The enrolment this row describes.
    pub enrolment: EnvironmentEnrolment,
    /// When the presence below was observed.
    pub last_observed_at_ms: TimestampMs,
    /// What was observed then.
    pub status: EnvironmentPresence,
    /// Whether that observation was read from the cache or made by asking the platform.
    pub observation: ObservationSource,
    /// What this environment still needs.
    pub readiness: EnvironmentReadiness,
}

impl EnvironmentInventoryRow {
    /// Returns true when this row is evidence that a process is currently live.
    ///
    /// Only a refresh that found the environment running is. A cached row never is, whatever it
    /// says, which is the distinction section 3 draws: listing reports what was last seen and
    /// starts nothing, and only a refresh, a create or an attach may start the selected one.
    #[must_use]
    pub const fn is_evidence_of_a_live_process(&self) -> bool {
        matches!(self.observation, ObservationSource::Refresh)
            && matches!(self.status, EnvironmentPresence::Running)
    }
}

/// What a bridge helper is asked to reach inside its own environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeTarget {
    /// That environment's control daemon.
    Controller,
    /// The worker that owns one session there.
    Session {
        /// The session.
        session_id: SessionId,
    },
}

/// The first frame an invoker writes to a bridge helper's standard input.
///
/// Section 3 restricts the process bridges to locally authenticated command-line invocations. The
/// ingress below is the one the request *originally* arrived on, not the local IPC hop the helper
/// itself makes, and a helper refuses anything but a local one before it opens a connection. An
/// invoker that declared a remote ingress would be refused; an invoker that lied about it would
/// gain nothing, because the declaration can never widen what the helper's own operating-system
/// credentials already establish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeHello {
    /// The protocol version the invoker speaks.
    pub protocol_version: ProtocolVersion,
    /// The invoker's build.
    pub build_id: BuildId,
    /// The environment the invoker runs in. It is recorded, never trusted for authority.
    pub origin_environment_id: EnvironmentId,
    /// The ingress the request originally arrived on.
    pub origin_ingress: ActorIngress,
    /// Whether the request had already crossed a bridge before this one.
    ///
    /// Section 3 puts a federated proxy outside version 1, so a request crosses at most one
    /// bridge. A second hop is refused rather than chained.
    pub already_bridged: bool,
    /// What to reach inside the destination environment.
    pub target: BridgeTarget,
}

/// The helper's answer, once it has reached what the invoker asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeHelloAck {
    /// The protocol version both sides will use.
    pub protocol_version: ProtocolVersion,
    /// The destination environment. Its own identity, never the invoker's.
    pub environment_id: EnvironmentId,
    /// The operating-system user the helper runs as there.
    pub os_user: String,
    /// Which host process the helper reached.
    pub role: LocalRole,
    /// The connection identity that host assigned the helper.
    pub connection_id: ConnectionId,
    /// The boot the destination is running.
    pub boot_identity: BootIdentity,
    /// The largest complete frame either side may write, in bytes.
    pub max_frame_len: U64,
    /// The first action window of this connection, issued by the destination.
    pub action_window: ActionWindow,
}

/// One frame on a bridge's standard input or output.
///
/// Standard error stays diagnostic: nothing a person or a log reads there is part of this union,
/// so a helper that writes a warning cannot corrupt the stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFrame {
    /// The invoker's opening frame.
    Hello(Box<BridgeHello>),
    /// The helper's answer to it.
    HelloAck(Box<BridgeHelloAck>),
    /// The helper's refusal. Nothing follows it.
    Refused(ProtocolError),
    /// One protocol frame, carried unchanged in either direction.
    Control(Box<ControlFrame>),
}

/// The parameters of `environment.enrol`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEnrolParams {
    /// The record the owner is approving.
    pub enrolment: EnvironmentEnrolment,
}

/// The result of `environment.enrol`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEnrolResult {
    /// The row this enrolment now has in the inventory.
    pub row: EnvironmentInventoryRow,
}

/// The parameters of `environment.forget`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentForgetParams {
    /// The environment to remove.
    pub environment_id: EnvironmentId,
}

/// The result of `environment.forget`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentForgetResult {
    /// Whether a record was there to remove.
    pub forgotten: bool,
}

/// The parameters of `environment.inventory`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInventoryParams {
    /// Report only this access class, when one is named.
    pub access: Nullable<EnvironmentAccess>,
}

/// The result of `environment.inventory`.
///
/// Every row here was read from the cache. Nothing was contacted and nothing was started to
/// produce this answer, which is what section 3 requires of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInventoryResult {
    /// The rows, in enrolment order.
    pub rows: Vec<EnvironmentInventoryRow>,
}

/// The parameters of `environment.refresh`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRefreshParams {
    /// The environment to observe.
    pub environment_id: EnvironmentId,
    /// Whether this refresh may start the environment it selected.
    ///
    /// A listing never starts anything. A refresh may, and says so here rather than deciding for
    /// the caller.
    pub start: bool,
}

/// What a destination environment said about itself over a process bridge.
///
/// Section 18 asks for connection diagnostics, and section 25 asks helpers to register explicit
/// environment identities and scoped local channels rather than inferring authority from a
/// forwarded environment variable. This is what one opened bridge established: the helper ran
/// inside the destination, authenticated to that environment's own daemon over its own local
/// channel, and answered with the identity, the user and the bounds below.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeVerification {
    /// The environment that answered. Compared against the enrolment before anything is recorded.
    pub environment_id: EnvironmentId,
    /// The operating-system user the helper runs as inside that environment.
    pub os_user: String,
    /// The role that answered: the destination's control daemon, or one session's worker.
    pub role: LocalRole,
    /// The protocol version the destination selected.
    pub protocol_version: ProtocolVersion,
    /// The largest frame that destination will carry, in bytes.
    pub max_frame_len: U64,
}

/// The result of `environment.refresh`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRefreshResult {
    /// The row as this refresh observed it.
    pub row: EnvironmentInventoryRow,
    /// Whether this refresh started the environment.
    pub started: bool,
    /// What the destination answered when this refresh opened a bridge to it.
    ///
    /// Absent when no bridge was opened, which is the case for an environment that is not running
    /// and for an access class that is not a process bridge. [`Self::connection`] says which.
    pub verification: Nullable<BridgeVerification>,
    /// What opening that bridge did, in one line a person can act on.
    pub connection: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reused_process_identifier_does_not_match_the_original() {
        let original = ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 100);
        let reused = ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 900);
        assert!(!original.matches(&reused));
        assert!(original.matches(&original.clone()));
    }

    #[test]
    fn identities_round_trip_through_the_canonical_encoding() {
        let identity = BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: Bytes::new(vec![1, 2, 3, 4]),
        };
        let bytes = kr_cbor::to_canonical_vec(&identity).expect("encodes");
        let decoded: BootIdentity =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, identity);
    }

    #[test]
    fn an_enrolment_records_the_identity_the_user_and_the_helper() {
        let enrolment = wsl_enrolment();
        enrolment.validate().expect("a complete record");
        assert_eq!(enrolment.target, "Ubuntu-24.04");
        assert_eq!(enrolment.os_user, "kala");
        assert_eq!(enrolment.helper_path, "/usr/local/bin/kr");
    }

    #[test]
    fn an_enrolment_missing_any_of_the_three_is_refused() {
        let mut missing_target = wsl_enrolment();
        missing_target.target = String::new();
        assert_eq!(missing_target.validate(), Err(EnrolmentError::EmptyTarget));

        let mut missing_user = wsl_enrolment();
        missing_user.os_user = "  ".to_owned();
        assert_eq!(missing_user.validate(), Err(EnrolmentError::EmptyUser));

        let mut relative_helper = wsl_enrolment();
        relative_helper.helper_path = "bin/kr".to_owned();
        assert_eq!(
            relative_helper.validate(),
            Err(EnrolmentError::HelperPathNotAbsolute)
        );
    }

    #[test]
    fn a_helper_path_is_absolute_in_the_target_platform_s_own_terms() {
        for absolute in [
            "/usr/local/bin/kr",
            "C:\\Program Files\\KalaReach\\kr.exe",
            "D:/kala/kr.exe",
            "\\\\host\\share\\kr.exe",
        ] {
            assert!(helper_path_is_absolute(absolute), "{absolute}");
        }
        for relative in ["", "kr", "bin/kr", "./kr", "C:kr.exe", "1:/kr.exe"] {
            assert!(!helper_path_is_absolute(relative), "{relative:?}");
        }
    }

    #[test]
    fn a_label_selects_a_record_and_never_identifies_it() {
        let first = wsl_enrolment();
        let mut recreated = wsl_enrolment();
        // The same human name, a different environment: a container destroyed and recreated, or a
        // distribution unregistered and installed again.
        recreated.environment_id = EnvironmentId::new(crate::scalars::Uuid::from_bytes([9; 16]));
        assert!(first.selected_by("ubuntu"));
        assert!(recreated.selected_by("ubuntu"));
        assert_ne!(first.environment_id, recreated.environment_id);
    }

    #[test]
    fn a_cached_row_is_never_evidence_of_a_live_process() {
        for status in EnvironmentPresence::ALL.iter().copied() {
            let row = row_with(status, ObservationSource::Cache);
            assert!(
                !row.is_evidence_of_a_live_process(),
                "a cached {} row",
                status.as_str()
            );
        }
        assert!(
            row_with(EnvironmentPresence::Running, ObservationSource::Refresh)
                .is_evidence_of_a_live_process()
        );
        for status in [
            EnvironmentPresence::EnvironmentStopped,
            EnvironmentPresence::Stale,
        ] {
            assert!(!row_with(status, ObservationSource::Refresh).is_evidence_of_a_live_process());
        }
    }

    #[test]
    fn only_a_wsl_distribution_and_a_container_are_process_bridges() {
        assert!(EnvironmentAccess::WslDistribution.is_process_bridge());
        assert!(EnvironmentAccess::Container.is_process_bridge());
        assert!(!EnvironmentAccess::SshHost.is_process_bridge());
        assert!(!EnvironmentAccess::PairedHost.is_process_bridge());
    }

    #[test]
    fn readiness_reports_the_helper_and_the_scoped_channel_separately() {
        // Section 18: a suitable helper and scoped credentials are both needed, and neither is
        // inferred from the other. Forwarding a socket installs nothing.
        let forwarded_socket_only = EnvironmentReadiness {
            helper_enrolled: false,
            channel_scoped: true,
            detail: "install the helper in the target environment".to_owned(),
        };
        assert!(!forwarded_socket_only.is_ready());
        let helper_without_a_channel = EnvironmentReadiness {
            helper_enrolled: true,
            channel_scoped: false,
            detail: "grant this environment its own scoped channel".to_owned(),
        };
        assert!(!helper_without_a_channel.is_ready());
    }

    #[test]
    fn the_bridge_handshake_round_trips_through_the_canonical_encoding() {
        let hello = BridgeFrame::Hello(Box::new(BridgeHello {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            build_id: BuildId::new("kr/0.1.0").expect("a build"),
            origin_environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([3; 16])),
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            target: BridgeTarget::Controller,
        }));
        let bytes = kr_cbor::to_canonical_vec(&hello).expect("encodes");
        let decoded: BridgeFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, hello);
    }

    #[test]
    fn the_bridge_acknowledgement_round_trips_through_the_canonical_encoding() {
        let ack = BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([4; 16])),
            os_user: "kala".to_owned(),
            role: LocalRole::Controller,
            connection_id: ConnectionId::new(crate::scalars::Uuid::from_bytes([5; 16])),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"boot-123".to_vec()),
            },
            max_frame_len: U64::new(65536),
            action_window: ActionWindow {
                action_window_id: crate::ids::ActionWindowId::new("w-test").expect("a window"),
                connection_id: ConnectionId::new(crate::scalars::Uuid::from_bytes([5; 16])),
                boot_epoch: crate::ids::BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(100),
                valid_for_ms: crate::scalars::DurationMs::new(120_000),
            },
        }));
        let bytes = kr_cbor::to_canonical_vec(&ack).expect("encodes");
        let decoded: BridgeFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, ack);
    }

    fn wsl_enrolment() -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([7; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: "ubuntu".to_owned(),
            target: "Ubuntu-24.04".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(1),
        }
    }

    fn row_with(
        status: EnvironmentPresence,
        observation: ObservationSource,
    ) -> EnvironmentInventoryRow {
        EnvironmentInventoryRow {
            enrolment: wsl_enrolment(),
            last_observed_at_ms: TimestampMs::new(10),
            status,
            observation,
            readiness: EnvironmentReadiness {
                helper_enrolled: true,
                channel_scoped: true,
                detail: String::new(),
            },
        }
    }

    #[test]
    fn a_container_enrolment_rejects_reusable_human_names_as_identities() {
        let mut enrolment = wsl_enrolment();
        enrolment.access = EnvironmentAccess::Container;
        for name in [
            "build",
            "my-container",
            // A name may be hexadecimal, and a short identifier is a prefix a runtime resolves to
            // whichever container carries it now. Neither is the identity of one container.
            "deadbeefcafe",
            "8f3c1d2e4a5b",
        ] {
            enrolment.target = name.to_owned();
            assert_eq!(
                enrolment.validate().expect_err("rejected"),
                EnrolmentError::ContainerTargetNotIdentifier,
                "{name}"
            );
        }

        // The identifier the runtime issued, whole.
        enrolment.target = "a".repeat(CONTAINER_IDENTIFIER_LEN);
        enrolment.validate().expect("the whole identifier is one");
    }

    #[test]
    fn an_environment_identifier_selects_the_record_a_shared_label_cannot() {
        let first = wsl_enrolment();
        let mut second = wsl_enrolment();
        second.environment_id = EnvironmentId::new(crate::scalars::Uuid::from_bytes([9; 16]));
        // Both answer to the label they share, and each answers to its own identity alone.
        assert!(first.selected_by(&first.environment_id.to_string()));
        assert!(!first.selected_by(&second.environment_id.to_string()));
        assert!(second.selected_by(&second.environment_id.to_string()));
    }
}
