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
use crate::error::{ErrorCode, ProtocolError};
use crate::hello::{ActionWindow, ProtocolVersion};
use crate::hostinfo::export::Sentence;
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
    /// Windows `GetProcessTimes`: the process creation time in hundreds of nanoseconds since the
    /// Unix epoch, 1970-01-01 00:00:00 UTC.
    ///
    /// That is the unit the kernel records a creation time in, and the value is the kernel's own
    /// with the epoch moved from 1601 to 1970: a `FILETIME` less 116 444 736 000 000 000. So a
    /// process created after another under the same identifier carries a different value, as it
    /// does on the other platforms, rather than one it would share for the rest of the second.
    WindowsProcessCreationTime,
    /// Windows, as a worker of the previous build states its identity: the creation time in whole
    /// seconds since the epoch.
    ///
    /// Nothing in this build reads a process into this source. It is here because a worker of the
    /// previous build keeps running across an upgrade and signs its identity, in this source, into
    /// its rendezvous and its every verification answer, and the records that worker and its
    /// controller wrote carry it too. This build reads such an identity the way the previous build
    /// did: the process holding the identifier now, with its creation time cut to whole seconds.
    /// Two processes that share an identifier within one second are one identity this way, which
    /// is the weakness [`Self::WindowsProcessCreationTime`] removes.
    ///
    /// Remove this source, and every reader of it, in the first release after one in which every
    /// running worker states [`Self::WindowsProcessCreationTime`].
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
    /// none, not that it inherits this host's. The one destination there is to name is
    /// [`CLIPBOARD_DESTINATION_TERMINAL`]: the terminal the attaching `kr` is running in, which
    /// writes it. Any other text names no destination, and a record that holds one is read as
    /// having none.
    pub clipboard_destination: Nullable<String>,
    /// When the owner approved this record.
    pub approved_at_ms: TimestampMs,
}

/// The clipboard destination that is the terminal an attachment is made from.
pub const CLIPBOARD_DESTINATION_TERMINAL: &str = "terminal";

/// Why an enrolment is not a well-formed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolmentError {
    /// The clipboard destination is not one this host delivers to.
    ClipboardDestinationUnknown,
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
    /// An SSH destination is not a plain host name or address.
    SshTargetNotPlain,
    /// An SSH user is not a plain account name.
    SshUserNotPlain,
    /// An SSH helper path is not a plain absolute path.
    SshHelperPathNotPlain,
}

impl EnrolmentError {
    /// Every reason, in the order they are declared.
    pub const ALL: [Self; 9] = [
        Self::ClipboardDestinationUnknown,
        Self::EmptyLabel,
        Self::EmptyTarget,
        Self::EmptyUser,
        Self::HelperPathNotAbsolute,
        Self::ContainerTargetNotIdentifier,
        Self::SshTargetNotPlain,
        Self::SshUserNotPlain,
        Self::SshHelperPathNotPlain,
    ];

    /// Returns the sentence that says why, which is the same words for the same cause.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::ClipboardDestinationUnknown => {
                "the only clipboard destination an enrolment can name is the terminal an \
                 attachment is made from: terminal"
            }
            Self::EmptyLabel => "an enrolment carries the label people use",
            Self::EmptyTarget => "an enrolment carries the identity the platform issued",
            Self::EmptyUser => "an enrolment carries the operating-system user it runs as",
            Self::HelperPathNotAbsolute => "an enrolment carries the absolute path of the helper",
            Self::ContainerTargetNotIdentifier => {
                "a container enrolment requires the container identifier, never a reusable \
                 container name"
            }
            Self::SshTargetNotPlain => {
                "an SSH enrolment names a host by a plain name or address: letters, digits, dots, \
                 colons, underscores and hyphens, not beginning with a hyphen, with no user in it"
            }
            Self::SshUserNotPlain => {
                "an SSH enrolment names the account by a plain name: letters, digits, dots, \
                 underscores and hyphens, not beginning with a hyphen"
            }
            Self::SshHelperPathNotPlain => {
                "an SSH enrolment names the helper by a plain absolute path: letters, digits, \
                 dots, underscores, hyphens and slashes, because the remote login's shell reads \
                 whatever else it holds"
            }
        }
    }
}

impl core::fmt::Display for EnrolmentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.describe())
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

    /// Checks that a record about to be made names a clipboard destination this host delivers to,
    /// or none.
    ///
    /// This is a check of a record being made and not of one being read: a record that names
    /// another destination is still a record of an environment this host reaches, and is read as
    /// having no destination.
    ///
    /// # Errors
    ///
    /// Returns [`EnrolmentError::ClipboardDestinationUnknown`] for any other name.
    pub fn validate_clipboard_destination(&self) -> Result<(), EnrolmentError> {
        match self.clipboard_destination.as_ref() {
            None => Ok(()),
            Some(name) if name == CLIPBOARD_DESTINATION_TERMINAL => Ok(()),
            Some(_) => Err(EnrolmentError::ClipboardDestinationUnknown),
        }
    }

    /// Whether the terminal an attachment to this environment is made from takes the clipboard
    /// writes its sessions ask for: only where the owner named the terminal as the destination.
    ///
    /// A record that names nothing, or names text this host does not deliver to, takes none.
    #[must_use]
    pub fn takes_clipboard_writes(&self) -> bool {
        self.clipboard_destination
            .as_ref()
            .is_some_and(|name| name == CLIPBOARD_DESTINATION_TERMINAL)
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
    if access == EnvironmentAccess::SshHost {
        // The login's shell reads what follows the host on the remote side, joined with spaces, so
        // anything a shell would read is refused here and nothing needs quoting later. The user
        // comes from its own option and never from the target.
        let plain = |character: char, extra: &[char]| {
            character.is_ascii_alphanumeric() || extra.contains(&character)
        };
        if !target
            .chars()
            .all(|character| plain(character, &['.', ':', '_', '-']))
            || target.starts_with('-')
        {
            return Err(EnrolmentError::SshTargetNotPlain);
        }
        if !os_user
            .chars()
            .all(|character| plain(character, &['.', '_', '-']))
            || os_user.starts_with('-')
        {
            return Err(EnrolmentError::SshUserNotPlain);
        }
        if !helper_path.starts_with('/')
            || !helper_path
                .chars()
                .all(|character| plain(character, &['.', '_', '-', '/']))
        {
            return Err(EnrolmentError::SshHelperPathNotPlain);
        }
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
        /// Whether the terminal the invoker attaches from takes the clipboard writes the session
        /// asks for.
        ///
        /// The invoker says it from the enrolment it holds for the destination: yes where the owner
        /// named the terminal as the environment's clipboard destination
        /// ([`EnvironmentEnrolment::takes_clipboard_writes`]), and no otherwise. It only narrows: a
        /// session's clipboard write reaches the attachment holding the input lease and nobody else
        /// whatever this says, and a terminal that says no is sent none. The destination's worker
        /// enforces it; nothing between filters the bytes.
        clipboard_writes: bool,
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
    /// Whether this invocation may start what it needs inside the destination.
    ///
    /// Section 3 leaves starting an environment to refresh, create and attach, and a listing, an
    /// enrolment or a verification starts nothing. A create or an attach says `true`, and the
    /// helper then reaches the destination's control daemon through that environment's own
    /// configured startup when none is running. Everything else says `false`, and a destination
    /// with no daemon answers that it has none.
    pub start: bool,
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
    /// The build of the process the helper reached, stated as that process stated it.
    ///
    /// An invoker refuses a destination whose protocol version does not share its compatibility
    /// level before it sends a request, because the frames that follow are closed schemas. A
    /// process of a build before this member states none, and is refused the same way.
    ///
    /// Remove the default and the omission once no process of a build before this member can
    /// still be running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<crate::local::LocalBuild>,
    /// The destination's own starting point for a session created through this bridge.
    pub base: DestinationBase,
}

/// The variables a destination offers as the base of a session created through a bridge.
///
/// The names an invoker will take from a destination, and no others: what a create sends in its
/// snapshot becomes the shell's whole environment, and nothing of the invoking host's belongs in
/// it.
pub const DESTINATION_BASE_VARIABLES: &[&str] = &[
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_TIME",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TZ",
    "USER",
];

/// The most bytes one offered variable's value may hold.
pub const DESTINATION_BASE_VALUE_LIMIT: usize = 8 * 1024;

/// Where a session created through a bridge starts, and what it starts with, as the destination's
/// own helper states it.
///
/// A person creating a session from another environment has no working directory or variables of
/// the destination to send: the invoking host's mean nothing there. The helper runs as the
/// destination's user inside the destination, so what it reads of its own environment is what a
/// `kr new` run there would have sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DestinationBase {
    /// The destination user's home directory, where a session starts unless it is told otherwise.
    pub home: String,
    /// The helper's own values of [`DESTINATION_BASE_VARIABLES`], in that order, where it has them.
    pub variables: Vec<crate::session::EnvironmentVariable>,
}

impl DestinationBase {
    /// Checks what a destination offered before an invoker builds a create from it.
    ///
    /// # Errors
    ///
    /// Returns the first reason it is not a base this protocol allows: a home that is not an
    /// absolute path of the destination, a variable outside [`DESTINATION_BASE_VARIABLES`], a name
    /// offered twice, or a value past [`DESTINATION_BASE_VALUE_LIMIT`].
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.home.is_empty() || !helper_path_is_absolute(&self.home) {
            return Err("the destination's home directory is not an absolute path");
        }
        if self.home.len() > DESTINATION_BASE_VALUE_LIMIT {
            return Err("the destination's home directory is longer than a variable may be");
        }
        let mut seen = std::collections::BTreeSet::new();
        for variable in &self.variables {
            if !DESTINATION_BASE_VARIABLES.contains(&variable.name.as_str()) {
                return Err("the destination offered a variable this protocol does not take");
            }
            if !seen.insert(variable.name.as_str()) {
                return Err("the destination offered one variable twice");
            }
            if variable.value.len() > DESTINATION_BASE_VALUE_LIMIT {
                return Err("the destination offered a value longer than a variable may be");
            }
        }
        Ok(())
    }
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
    //
    // The host composes it from its own words, numbers and closed terms: the program it ran for
    // the environment and how that failed (it could not start, it ended with a code, a signal
    // ended it, it said nothing within its bound, or the environment refused), with anything that
    // arrived at the host, such as the operating system's message, given as its class and length.
    // This is a plain comment so that the published schema's description stays as it was.
    pub connection: Sentence,
}

impl EnvironmentRefreshResult {
    /// Returns whether [`Self::connection`] is one of the sentences a host of this release
    /// composes. A host of an earlier release wrote the refusal's own words there, and the user's
    /// name, which this release's does not: its text is not one of them.
    #[must_use]
    pub fn connection_is_composed(&self) -> bool {
        is_composed_connection(self.connection.as_str())
    }
}

/// The programs the host runs for an environment, each with the step it is in a connection
/// sentence: its role, then its name. A person who does not know the program's name reads the role.
const CONNECTION_STEPS: [(&str, &str); 3] = [
    ("podman", "the container runtime (podman)"),
    ("ssh", "the SSH client (ssh)"),
    ("wsl.exe", "the WSL launcher (wsl.exe)"),
];

/// What a connection sentence says of the program when the host runs none for the access class.
const UNNAMED_STEP: &str = "the helper program";

/// Returns how a connection sentence names `program`, the one the host runs for an environment:
/// the step it is, by its role and then its name, or the words for no program when there is none.
#[must_use]
pub fn connection_step(program: Option<&str>) -> &'static str {
    program
        .and_then(|program| {
            CONNECTION_STEPS
                .iter()
                .find_map(|(name, step)| (*name == program).then_some(*step))
        })
        .unwrap_or(UNNAMED_STEP)
}

/// What the host says when opening a bridge was refused, each as the words it is composed of and
/// its placeholders: `{program}` for the step the host ran ([`connection_step`]), `{n}` for a number, `{id}` for an environment identifier, a
/// closed word of its own set (`{code}` for an error code, `{role}`, `{access}` and `{ingress}`),
/// and `{message}` and `{name}` for a value that arrived, as its class and length.
const REFUSAL_FORMS: &[&str] = &[
    "a process bridge carries locally authenticated invocations only, and this request arrived as \
     {ingress}; reach that environment through its own paired endpoint",
    "a request crosses at most one process bridge",
    "{access} is not reached by a process bridge; an SSH user runs the command line on the \
     destination host and a paired host is reached through its own endpoint",
    "{program} was not found",
    "{program} could not be started: {message}",
    "{program} ended with exit code {n} before the environment answered",
    "{program} ran, and the helper ended with exit code {n} before the environment answered",
    "{program} ran, and the helper could not be run before the environment answered",
    "{program} ran, and the helper ended with exit code {n} after the environment acknowledged the bridge, \
     before it answered the read",
    "{program} ended with exit code {n} when asked whether the environment is running",
    "{program} ended with exit code {n} when asked to start the environment",
    "{program} was ended by signal {n} when asked whether the environment is running",
    "{program} was ended by signal {n} when asked to start the environment",
    "{program} did not answer within {n} seconds when asked whether the environment is running, so it \
     was ended",
    "{program} did not answer within {n} seconds when asked to start the environment, so it was \
     ended",
    "{program} did not answer within {n} seconds when asked whether the environment is running, and \
     this host could not confirm that it ended; it may still be running",
    "{program} did not answer within {n} seconds when asked to start the environment, and this host \
     could not confirm that it ended; it may still be running",
    "{program} ran, and this host could not read what it printed when asked whether the environment \
     is running: {message}",
    "{program} ran, and this host could not read what it printed when asked to start the \
     environment: {message}",
    "{program} could not be waited for when asked whether the environment is running: {message}",
    "{program} could not be waited for when asked to start the environment: {message}",
    "{program} gave an answer that could not be read when asked whether the environment is running",
    "{program} was ended by signal {n} before the environment answered",
    "{program} ended the connection before the environment answered",
    "{program} ended with exit code {n} after the environment acknowledged the bridge, before it \
     answered the read",
    "{program} was ended by signal {n} after the environment acknowledged the bridge, before it \
     answered the read",
    "{program} ended the connection after the environment acknowledged the bridge, before it \
     answered the read",
    "{program} ran, and the environment that answered wrote a frame this host cannot read \
     ({message})",
    "{program} ran, and the environment's first frame was not an acknowledgement of the opening",
    "{program} ran, and the environment answered the read with something that is not an answer",
    "{program} ran, and the environment that answered speaks protocol major {n}, and this host \
     speaks {n}",
    "{program} ran, and the environment that answered is the {role}, where the opening asked for \
     the {role}",
    "{program} ran, and the environment that answered is environment {id}, and the enrolment names \
     environment {id}; enrol the environment that is installed there rather than reusing this \
     record",
    "{program} ran, and the environment refused the bridge: {code} ({message})",
    "{program} ran, and the environment answered the read with an error: {code} ({message})",
    "{program} ran, and the environment says that session is closed",
    "{program} said nothing for {n} seconds, so it was ended",
    "{program} ran, and the helper that answered ran as {name}, not as the user {name} the \
     enrolment names",
    "{program} ran, and the environment that answered is this host's own environment, so it is \
     not another one: a socket forwarded from here does not register an environment",
    "{program} ran, and the environment that answered runs {name} with protocol {n}.{n}.{n}, and \
     this host speaks protocol {n}.{n}.{n}: update kr in the destination or here so both are of \
     one release",
    "{program} ran, and the environment that answered is of a build that states no protocol \
     version, and this host speaks protocol {n}.{n}.{n}: update kr in the destination",
    "{program} ran, and the environment that answered sent more than {n} bytes this host had not \
     yet been asked for, so the bridge was ended",
    "{program} process {n} could not be ended: {message}; it may still be running, and this host \
     no longer waits for it",
    "{program} could not be ended: {message}; it may still be running, and this host no longer \
     waits for it",
];

/// What else the host says about opening a bridge, in the same notation as [`REFUSAL_FORMS`].
const OTHER_FORMS: &[&str] = &[
    "{access} is not reached by a process bridge, so none was opened",
    "no bridge was opened, because this environment is not running; refresh with --start to start \
     it",
    "no bridge was opened, because {message}",
    "environment {id} answered as {name} over its own local channel",
    "environment {id} answered as {name} on the helper installed there, over ssh; no request \
     crosses ssh",
    "this environment's record changed while the bridge was open, so what answered says nothing \
     about what is recorded now",
    "this environment's record changed while its helper was asked, so what answered says nothing \
     about what is recorded now",
    "the bridge answered, and this host did not record that, because {message}",
];

/// What the host appends to a refusal when it could not record it either.
const NOT_RECORDED: &str = "; and this host did not record that, because ";

/// Returns whether `text` is one of the sentences a host composes for what opening a bridge did:
/// fixed words, a program by name, numbers, closed words, an environment identifier, and any
/// value that arrived only as its class and length. Any other text, such as the refusal's own
/// words that a host of an earlier release wrote, is not.
#[must_use]
pub fn is_composed_connection(text: &str) -> bool {
    if OTHER_FORMS.iter().any(|form| matches_form(form, text)) {
        return true;
    }
    if is_refusal(text) {
        return true;
    }
    text.rfind(NOT_RECORDED).is_some_and(|at| {
        is_refusal(&text[..at]) && matches_form("{message}", &text[at + NOT_RECORDED.len()..])
    })
}

/// Returns whether `text` is one of the sentences for a refusal of the bridge.
fn is_refusal(text: &str) -> bool {
    if REFUSAL_FORMS.iter().any(|form| matches_form(form, text)) {
        return true;
    }
    text.strip_prefix("no helper was started, because ")
        .is_some_and(|reason| {
            EnrolmentError::ALL
                .iter()
                .any(|error| error.describe() == reason)
        })
}

/// Returns whether `text` is exactly `form`, with each placeholder taken by the shape it names.
fn matches_form(form: &str, text: &str) -> bool {
    let (mut form, mut text) = (form, text);
    while let Some(open) = form.find('{') {
        let Some(after_words) = text.strip_prefix(&form[..open]) else {
            return false;
        };
        let Some(length) = form[open..].find('}') else {
            return false;
        };
        let Some(rest) = take_placeholder(&form[open + 1..open + length], after_words) else {
            return false;
        };
        form = &form[open + length + 1..];
        text = rest;
    }
    form == text
}

/// Takes the shape a placeholder names off the front of `text`.
fn take_placeholder<'a>(placeholder: &str, text: &'a str) -> Option<&'a str> {
    let run = |keep: fn(char) -> bool| {
        let end = text.find(|c: char| !keep(c)).unwrap_or(text.len());
        (end > 0).then(|| &text[end..])
    };
    match placeholder {
        "program" => CONNECTION_STEPS
            .iter()
            .map(|(_, step)| *step)
            .chain([UNNAMED_STEP])
            .find_map(|step| text.strip_prefix(step)),
        "n" => run(|c| c.is_ascii_digit()),
        "code" => take_word(text, |word| ErrorCode::from_wire(word).is_some()),
        "role" => take_word(text, |word| {
            LocalRole::ALL.iter().any(|role| role.as_str() == word)
        }),
        "access" => take_word(text, |word| {
            EnvironmentAccess::ALL
                .iter()
                .any(|access| access.as_str() == word)
        }),
        "ingress" => take_word(text, |word| {
            ActorIngress::ALL
                .iter()
                .any(|ingress| ingress.as_str() == word)
        }),
        "id" => take_identifier(text),
        "message" => take_withheld("message", text),
        "name" => take_withheld("name", text),
        _ => None,
    }
}

/// Takes the run of letters, digits and underscores at the front of `text` when `closed` says it
/// is a word of the set the slot takes. Any other run is not one, whatever it looks like.
fn take_word(text: &str, closed: impl Fn(&str) -> bool) -> Option<&str> {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    closed(&text[..end]).then(|| &text[end..])
}

/// Takes an environment identifier, thirty-six characters in groups of 8, 4, 4, 4 and 12
/// hexadecimal digits.
fn take_identifier(text: &str) -> Option<&str> {
    let head = text.get(..36)?;
    head.bytes()
        .enumerate()
        .all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
        .then(|| &text[36..])
}

/// Takes a value that arrived at the host, as the host says it: its class and its length.
fn take_withheld<'a>(class: &str, text: &'a str) -> Option<&'a str> {
    let after_class = text
        .strip_prefix('[')?
        .strip_prefix(class)?
        .strip_prefix(" withheld, ")?;
    let digits = after_class
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_class.len());
    if digits == 0 {
        return None;
    }
    after_class[digits..].strip_prefix(" bytes]")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-18.11: the sentences the host composes are told from the text a host of an earlier
    /// release wrote into the same field, which carried the refusal's own words and the user's
    /// name.
    #[test]
    fn a_connection_is_composed_only_when_it_is_one_of_the_hosts_sentences() {
        let id = "18d3ba9f-df2d-43ec-84a3-83475d614273";
        for composed in [
            "the container runtime (podman) could not be started: [message withheld, 38 bytes]".to_owned(),
            "the container runtime (podman) was not found".to_owned(),
            "the SSH client (ssh) was not found".to_owned(),
            "the container runtime (podman) process 4242 could not be ended: [message withheld, 9 bytes]; it may still be running, and this host no longer waits for it".to_owned(),
            "the container runtime (podman) ended with exit code 125 before the environment answered".to_owned(),
            "the SSH client (ssh) ended the connection before the environment answered".to_owned(),
            "the WSL launcher (wsl.exe) ran, and the environment refused the bridge: PERMISSION_DENIED ([message withheld, 41 bytes])".to_owned(),
            format!("environment {id} answered as [name withheld, 1 bytes] over its own local channel"),
            "no bridge was opened, because [message withheld, 12 bytes]".to_owned(),
            "the container runtime (podman) said nothing for 20 seconds, so it was ended; and this host did not record that, because [message withheld, 9 bytes]".to_owned(),
            "no helper was started, because an enrolment carries the label people use".to_owned(),
        ] {
            assert!(is_composed_connection(&composed), "{composed}");
        }
        for raw in [
            "the destination refused the bridge: kr-test-destination-words",
            "the container runtime (podman) could not be started: No such file or directory (os error 2)",
            "the bridge stream failed: unexpected end of file",
            // A host of an earlier release named the program and not the step it is.
            "podman ended with exit code 125 before the environment answered",
            "ssh said nothing for 20 seconds, so it was ended",
            "the container runtime (docker) was not found",
            "environment 18d3ba9f-df2d-43ec-84a3-83475d614273 answered as kala over its own local channel",
            "the enrolment names user kala and the helper ran as root",
            "the container runtime (podman) ran, and the environment refused the bridge: PERMISSION_DENIED (kr-test-words)",
            "the container runtime (podman) ended with exit code 125 before the environment answered. kr-test-words",
            "no bridge was opened, because the fence says so",
            "",
        ] {
            assert!(!is_composed_connection(raw), "{raw}");
        }
    }

    /// KR-REQ-18.11: each word slot of a connection sentence takes the words of its own closed
    /// set and no other, so a sentence the host did not compose cannot carry a word of someone
    /// else's through the slot.
    #[test]
    fn each_word_slot_of_a_connection_takes_only_the_words_of_its_own_set() {
        let ingress_sentence = |word: &str| {
            format!(
                "a process bridge carries locally authenticated invocations only, and this \
                 request arrived as {word}; reach that environment through its own paired endpoint"
            )
        };
        let access_sentence = |word: &str| {
            format!(
                "{word} is not reached by a process bridge; an SSH user runs the command line on \
                 the destination host and a paired host is reached through its own endpoint"
            )
        };
        let access_other =
            |word: &str| format!("{word} is not reached by a process bridge, so none was opened");
        let role_sentence = |answered: &str, expected: &str| {
            format!(
                "the container runtime (podman) ran, and the environment that answered is the {answered}, where the \
                 opening asked for the {expected}"
            )
        };
        let opening_refused = |word: &str| {
            format!(
                "the container runtime (podman) ran, and the environment refused the bridge: {word} ([message withheld, 41 bytes])"
            )
        };
        let read_refused = |word: &str| {
            format!(
                "the container runtime (podman) ran, and the environment answered the read with an error: {word} ([message withheld, 41 bytes])"
            )
        };

        // Every word of each set is accepted in its own slot.
        for ingress in ActorIngress::ALL {
            let text = ingress_sentence(ingress.as_str());
            assert!(is_composed_connection(&text), "{text}");
        }
        for access in EnvironmentAccess::ALL {
            for text in [
                access_sentence(access.as_str()),
                access_other(access.as_str()),
            ] {
                assert!(is_composed_connection(&text), "{text}");
            }
        }
        for answered in LocalRole::ALL {
            for expected in LocalRole::ALL {
                let text = role_sentence(answered.as_str(), expected.as_str());
                assert!(is_composed_connection(&text), "{text}");
            }
        }
        for code in ErrorCode::ALL {
            for text in [opening_refused(code.as_str()), read_refused(code.as_str())] {
                assert!(is_composed_connection(&text), "{text}");
            }
        }

        // A word that is in no set is refused in every slot: the first two are the shapes of a
        // word that arrived (a name, a token) and the third is one that merely looks like a code.
        for unknown in [
            "kr_test_private_text",
            "hunter2",
            "PERMISSION_DENIED_FOR_KALA",
        ] {
            for text in [
                ingress_sentence(unknown),
                access_sentence(unknown),
                access_other(unknown),
                role_sentence(unknown, "controller"),
                role_sentence("worker", unknown),
                opening_refused(unknown),
                read_refused(unknown),
            ] {
                assert!(!is_composed_connection(&text), "{text}");
            }
        }

        // A word of another set is refused as well: each of these is a word of the host, in the
        // wrong place.
        for text in [
            ingress_sentence("controller"),
            ingress_sentence("container"),
            ingress_sentence("PERMISSION_DENIED"),
            access_sentence("local_ipc"),
            access_other("worker"),
            access_other("PERMISSION_DENIED"),
            role_sentence("local_ipc", "controller"),
            role_sentence("worker", "container"),
            role_sentence("PERMISSION_DENIED", "worker"),
            opening_refused("worker"),
            opening_refused("local_ipc"),
            read_refused("container"),
            read_refused("permission_denied"),
        ] {
            assert!(!is_composed_connection(&text), "{text}");
        }
    }

    /// The reasons an enrolment can fail for, each named once. The match has no arm for anything
    /// else, so a reason added to [`EnrolmentError`] does not compile here until it is named in
    /// the list the macro is given.
    macro_rules! every_enrolment_error {
        ($($variant:ident),+ $(,)?) => {{
            #[allow(dead_code)]
            fn exhaustive(error: EnrolmentError) {
                match error {
                    $(EnrolmentError::$variant => {})+
                }
            }
            [$(EnrolmentError::$variant),+]
        }};
    }

    /// KR-REQ-18.11: the recogniser accepts a reason only when it is in [`EnrolmentError::ALL`],
    /// so a reason missing from the list would be one the host composes and the command line
    /// withholds. This fails for a reason that is not in it.
    #[test]
    fn every_reason_an_enrolment_can_fail_for_is_in_the_list_the_recogniser_reads() {
        let declared = every_enrolment_error!(
            ClipboardDestinationUnknown,
            EmptyLabel,
            EmptyTarget,
            EmptyUser,
            HelperPathNotAbsolute,
            ContainerTargetNotIdentifier,
            SshTargetNotPlain,
            SshUserNotPlain,
            SshHelperPathNotPlain,
        );
        for error in declared {
            assert!(
                EnrolmentError::ALL.contains(&error),
                "{error:?} is not in EnrolmentError::ALL"
            );
            let text = format!("no helper was started, because {}", error.describe());
            assert!(is_composed_connection(&text), "{text}");
        }
        assert_eq!(
            EnrolmentError::ALL.len(),
            declared.len(),
            "EnrolmentError::ALL names a reason twice or one that is not declared"
        );
    }

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

    /// KR-REQ-03.16: an enrolment record holds the distribution's identity, its Linux user and the
    /// installed helper's path.
    #[test]
    fn an_enrolment_records_the_identity_the_user_and_the_helper() {
        let enrolment = wsl_enrolment();
        enrolment.validate().expect("a complete record");
        assert_eq!(enrolment.target, "Ubuntu-24.04");
        assert_eq!(enrolment.os_user, "kala");
        assert_eq!(enrolment.helper_path, "/usr/local/bin/kr");
    }

    /// KR-REQ-03.16: a record missing the distribution, the user or an absolute helper path is
    /// refused.
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
            start: true,
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
            build: Some(crate::local::LocalBuild::this(
                BuildId::new("kr/0.1.0").expect("a build"),
            )),
            base: DestinationBase {
                home: "/home/kala".to_owned(),
                variables: vec![crate::session::EnvironmentVariable {
                    name: "HOME".to_owned(),
                    value: "/home/kala".to_owned(),
                }],
            },
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

    /// The bridge's opening and acknowledgement as an invoker and a helper of a build before the
    /// start, build and base members declare them, member for member. Frames are closed schemas, so
    /// each build refuses what the other writes, and neither reads the other's as something else.
    #[test]
    fn the_bridge_handshake_is_refused_both_ways_between_builds_with_and_without_the_new_members() {
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EarlierHello {
            protocol_version: crate::hello::ProtocolVersion,
            build_id: BuildId,
            origin_environment_id: EnvironmentId,
            origin_ingress: ActorIngress,
            already_bridged: bool,
            target: BridgeTarget,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EarlierAck {
            protocol_version: crate::hello::ProtocolVersion,
            environment_id: EnvironmentId,
            os_user: String,
            role: LocalRole,
            connection_id: ConnectionId,
            boot_identity: BootIdentity,
            max_frame_len: U64,
            action_window: ActionWindow,
        }

        let limits = kr_cbor::Limits::DEFAULT;
        let connection_id = ConnectionId::new(crate::scalars::Uuid::from_bytes([5; 16]));
        let window = ActionWindow {
            action_window_id: crate::ids::ActionWindowId::new("w-test").expect("a window"),
            connection_id,
            boot_epoch: crate::ids::BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(100),
            valid_for_ms: crate::scalars::DurationMs::new(120_000),
        };
        let origin = EnvironmentId::new(crate::scalars::Uuid::from_bytes([3; 16]));

        // The opening: an earlier invoker's has no `start`, and this helper refuses it; this
        // invoker's has one, and an earlier helper refuses that.
        let earlier_hello = kr_cbor::to_canonical_vec(&EarlierHello {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            build_id: BuildId::new("kr/0.0.9").expect("a build"),
            origin_environment_id: origin,
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            target: BridgeTarget::Controller,
        })
        .expect("encodes");
        assert!(
            kr_cbor::from_canonical_slice::<BridgeHello>(&earlier_hello, &limits).is_err(),
            "this helper does not read an opening without `start`"
        );
        let hello = kr_cbor::to_canonical_vec(&BridgeHello {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            build_id: BuildId::new("kr/0.1.0").expect("a build"),
            origin_environment_id: origin,
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            start: false,
            target: BridgeTarget::Controller,
        })
        .expect("encodes");
        assert!(
            kr_cbor::from_canonical_slice::<EarlierHello>(&hello, &limits).is_err(),
            "an earlier helper does not read an opening with `start`"
        );
        // The controls: each build reads what it writes, so the refusals above are of the member
        // and of nothing else about the frame.
        assert!(kr_cbor::from_canonical_slice::<BridgeHello>(&hello, &limits).is_ok());
        assert!(kr_cbor::from_canonical_slice::<EarlierHello>(&earlier_hello, &limits).is_ok());

        // The acknowledgement: the same, for `build` and `base`.
        let boot_identity = BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: Bytes::new(b"boot-123".to_vec()),
        };
        let earlier_ack = kr_cbor::to_canonical_vec(&EarlierAck {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            environment_id: origin,
            os_user: "kala".to_owned(),
            role: LocalRole::Controller,
            connection_id,
            boot_identity: boot_identity.clone(),
            max_frame_len: U64::new(65536),
            action_window: window.clone(),
        })
        .expect("encodes");
        assert!(
            kr_cbor::from_canonical_slice::<BridgeHelloAck>(&earlier_ack, &limits).is_err(),
            "this invoker does not read an acknowledgement without `base`"
        );
        let ack = kr_cbor::to_canonical_vec(&BridgeHelloAck {
            protocol_version: crate::hello::PROTOCOL_VERSION,
            environment_id: origin,
            os_user: "kala".to_owned(),
            build: None,
            base: DestinationBase {
                home: "/home/kala".to_owned(),
                variables: Vec::new(),
            },
            role: LocalRole::Controller,
            connection_id,
            boot_identity,
            max_frame_len: U64::new(65536),
            action_window: window,
        })
        .expect("encodes");
        assert!(
            kr_cbor::from_canonical_slice::<EarlierAck>(&ack, &limits).is_err(),
            "an earlier invoker does not read an acknowledgement with `base`"
        );
        assert!(kr_cbor::from_canonical_slice::<BridgeHelloAck>(&ack, &limits).is_ok());
        assert!(kr_cbor::from_canonical_slice::<EarlierAck>(&earlier_ack, &limits).is_ok());
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

    /// KR-REQ-18.11: the one clipboard destination a record being made can name is the terminal an
    /// attachment is made from, or none; any other name is refused. A record that already names
    /// another is not refused as a record of an environment this host reaches, and takes no
    /// clipboard writes, which is what keeps it from delivering anywhere it was not told to.
    #[test]
    fn a_clipboard_destination_is_the_terminal_or_none() {
        let mut enrolment = wsl_enrolment();
        enrolment
            .validate_clipboard_destination()
            .expect("none is a destination");
        assert!(!enrolment.takes_clipboard_writes(), "none takes no write");

        enrolment.clipboard_destination = Nullable::some(CLIPBOARD_DESTINATION_TERMINAL.to_owned());
        enrolment
            .validate_clipboard_destination()
            .expect("the terminal is one");
        assert!(enrolment.takes_clipboard_writes());

        for other in [
            "Terminal",
            "terminal ",
            "clipboard-sync",
            "ssh://elsewhere",
            "",
        ] {
            enrolment.clipboard_destination = Nullable::some(other.to_owned());
            assert_eq!(
                enrolment.validate_clipboard_destination(),
                Err(EnrolmentError::ClipboardDestinationUnknown),
                "{other:?}"
            );
            assert!(!enrolment.takes_clipboard_writes(), "{other:?}");
            enrolment.validate().expect(
                "a record that names it is still a record of an environment this host reaches",
            );
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
