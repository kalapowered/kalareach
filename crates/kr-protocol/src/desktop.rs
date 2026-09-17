//! The desktop execution context, its capability evidence and the host power setting.
//!
//! Section 3 separates two things a terminal makes look like one: where a session is *shown* and
//! where its processes *run*. The presentation is `attach_here`, `open_terminal` or `invisible`.
//! The execution context is a desktop or a headless user context, and it is what decides which
//! display, message bus and operating-system permissions a command inside the session actually
//! has. Changing the first never changes the second.
//!
//! # The desktop a session is bound to
//!
//! [`DesktopContext`] is that context. Four things identify it, and all four are part of the
//! identity rather than decoration:
//!
//! | Part | Why it is in the identity |
//! | --- | --- |
//! | the operating-system user | two users logged in at once are two desktops |
//! | the platform login-session identifier | the platform's own name for one login |
//! | the host boot identity | a session number from before a reboot names nothing |
//! | the login-session generation | a platform that reuses session numbers needs it |
//!
//! [`DesktopContext::desktop_session_id`] is the derived name of that whole context, which is why
//! a reused platform session number is never the same desktop: the generation, or the boot, has
//! moved with it. Nothing rebinds a session to a new login. A session whose desktop ends is closed
//! with `desktop_lost`, and the user creates a new one.
//!
//! # Capability evidence
//!
//! Selecting a desktop proves nothing about what may be done on it. Screen capture and input
//! injection each need an operating-system permission that a desktop selection does not carry, so
//! each is a separate [`CapabilityRecord`] in the shared section 11 shape: what the capability is,
//! which subject it is about, what evidence produced it, which state it is in, what invalidates it
//! and what a person is told when it is unavailable. A capability that has not been probed says
//! [`CapabilityState::NotTested`] rather than claiming either answer.
//!
//! # The power setting
//!
//! Automatic sleep is the host's own policy and KalaReach does not change it silently. The owner
//! may enable [`SleepInhibitionSetting::MainsOnly`] or, as a separate choice,
//! [`SleepInhibitionSetting::BatteryToo`], and then the host holds the platform's own sleep
//! assertion while verified foreground work or pending requests exist, and releases it when that
//! ends. [`SleepInhibitionState`] is what host status and `kr status` report, including the reason
//! an assertion is held and the mechanism holding it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::{BootIdentity, WorkerProfile};
use crate::ids::{CapabilityId, CapabilityRevision, DesktopSessionId, EnvironmentId, SessionId};
use crate::scalars::{Nullable, TimestampMs, U64};

/// Which platform facility named a login session.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DesktopSessionKind {
    /// macOS: the Aqua security session of the user's graphical login.
    MacosSecuritySession,
    /// Linux: the login-manager session the user's graphical login runs in.
    LinuxLogind,
    /// Windows: the interactive logon session a per-user host agent starts workers in.
    WindowsInteractive,
    /// No graphical login session was named. A headless user context reads this way.
    None,
}

impl DesktopSessionKind {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacosSecuritySession => "macos_security_session",
            Self::LinuxLogind => "linux_logind",
            Self::WindowsInteractive => "windows_interactive",
            Self::None => "none",
        }
    }
}

/// What the login-session generation was read from.
///
/// The generation is the part of a desktop identity that distinguishes two logins which happen to
/// share a platform session number. Every platform answers it the same way, through the process
/// that owns the login session, and each names a different process. The source is recorded because
/// the value is only ever comparable with another value from the same source on the same host.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DesktopGenerationSource {
    /// macOS: the kernel's start value for the process that created the Aqua login session.
    MacosSessionCreator,
    /// Linux: the kernel's start value for the login session's leader process.
    LinuxSessionLeader,
    /// Windows: the kernel's start value for the interactive session's logon process.
    WindowsSessionLogon,
    /// The platform offered no generation. The identifier and the boot identity carry the identity
    /// alone, which is sound only where the platform does not reuse a session number within a
    /// boot.
    Unavailable,
}

impl DesktopGenerationSource {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacosSessionCreator => "macos_session_creator",
            Self::LinuxSessionLeader => "linux_session_leader",
            Self::WindowsSessionLogon => "windows_session_logon",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Whether the desktop is usable right now.
///
/// This is reported separately from process life on purpose. A locked screen or a switched-away
/// user makes a desktop temporarily unusable; it does not end the session or the processes it
/// owns. Only [`DesktopAvailability::Ended`] does that.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAvailability {
    /// The login session is present and in the foreground.
    Available,
    /// The login session is present and its screen is locked.
    Locked,
    /// The login session is present and not currently displayed, as after a user switch.
    Background,
    /// The login session has gone. A desktop-bound session closes with `desktop_lost`.
    Ended,
    /// This host cannot say. A headless context reads this way, and so does a platform that
    /// answers no question about another login.
    Unknown,
}

impl DesktopAvailability {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Locked => "locked",
            Self::Background => "background",
            Self::Ended => "ended",
            Self::Unknown => "unknown",
        }
    }

    /// Returns whether the desktop is there at all.
    ///
    /// A locked or backgrounded desktop still exists, so a session bound to it keeps running.
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self, Self::Ended)
    }
}

/// Whether this execution context is inside a container or a Windows Subsystem for Linux
/// distribution.
///
/// Both have their own process namespace and their own idea of a display. Neither silently gains
/// control of the desktop of the machine hosting it, so a worker created in one reports it and its
/// capability records say why the parent desktop is not available.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ContainerEnvironment {
    /// The context runs directly on the host.
    Host,
    /// The context runs in a container.
    Container,
    /// The context runs in a Windows Subsystem for Linux distribution.
    Wsl,
}

impl ContainerEnvironment {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
            Self::Wsl => "wsl",
        }
    }

    /// Returns whether a context of this kind can reach the desktop of the machine hosting it.
    #[must_use]
    pub const fn reaches_parent_desktop(self) -> bool {
        matches!(self, Self::Host)
    }
}

/// The display server a desktop presents.
///
/// Linux is the reason this is a field rather than an assumption: the same distribution can run
/// X11 or Wayland, the tools that work differ between them, and a capability answer that did not
/// say which one it was about would be useless.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DisplayServer {
    /// macOS Quartz, through the user's Aqua login session.
    Quartz,
    /// The Windows interactive desktop.
    WindowsDesktop,
    /// An X11 server.
    X11,
    /// A Wayland compositor.
    Wayland,
    /// A graphical login session whose display server this host could not name.
    Unknown,
    /// No display server. A headless user context reads this way.
    None,
}

impl DisplayServer {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quartz => "quartz",
            Self::WindowsDesktop => "windows_desktop",
            Self::X11 => "x11",
            Self::Wayland => "wayland",
            Self::Unknown => "unknown",
            Self::None => "none",
        }
    }
}

/// The desktop execution context a worker runs in.
///
/// The identity is the whole record, not the identifier: two contexts are the same desktop only
/// when the user, the platform session, the generation and the boot all agree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DesktopContext {
    /// The derived name of this whole context, absent when there is no desktop.
    pub desktop_session_id: Nullable<DesktopSessionId>,
    /// Which platform facility named the login session.
    pub kind: DesktopSessionKind,
    /// The platform's own login-session identifier, exactly as the platform prints it.
    pub platform_session: Nullable<String>,
    /// The login-session generation, where the platform offers one.
    pub login_generation: Nullable<U64>,
    /// What the generation was read from.
    pub generation_source: DesktopGenerationSource,
    /// The operating-system user the desktop belongs to.
    pub os_user: String,
    /// That user's numeric identifier, where the platform uses one.
    pub uid: Nullable<U64>,
    /// The boot this desktop belongs to.
    pub boot_identity: BootIdentity,
    /// Whether this context has the login session's graphical access.
    ///
    /// An invisible session keeps it: presentation does not decide it. A headless user context
    /// does not have it, because it is not in a graphical login at all.
    pub graphic_access: bool,
    /// Whether the login session is a remote one, such as a Windows RDP session.
    pub remote: bool,
    /// Whether the desktop is usable right now, separately from process life.
    pub availability: DesktopAvailability,
    /// Whether this context is inside a container or a WSL distribution.
    pub container: ContainerEnvironment,
    /// The display server, where there is one.
    pub display_server: DisplayServer,
    /// The desktop environment or compositor the login session runs, where the platform names it.
    pub compositor: Nullable<String>,
    /// How long a worker in this context lasts.
    pub worker_profile: WorkerProfile,
}

impl DesktopContext {
    /// Returns whether this context and another name the same desktop.
    ///
    /// Every part is compared. A platform session number that came back the same after a new login
    /// is not the same desktop, because the generation or the boot moved with it.
    #[must_use]
    pub fn is_same_desktop(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.platform_session == other.platform_session
            && self.login_generation == other.login_generation
            && self.os_user == other.os_user
            && self.uid == other.uid
            && self.boot_identity == other.boot_identity
    }

    /// Returns whether this context names a desktop at all.
    #[must_use]
    pub fn is_desktop(&self) -> bool {
        self.kind != DesktopSessionKind::None && self.desktop_session_id.is_present()
    }
}

/// What produced a capability answer.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceSource {
    /// A bounded operation with declared effects, run in the subject's own context.
    DisclosedProbe,
    /// A platform query about the context itself, with no effect outside this host.
    PlatformQuery,
    /// A signed compatibility record about a version. Evidence about a version is not proof that
    /// this host has the permission or a live binding.
    SignedCompatibilityRecord,
    /// Nothing has been run. The state is `not_tested`.
    NotProbed,
}

impl CapabilityEvidenceSource {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisclosedProbe => "disclosed_probe",
            Self::PlatformQuery => "platform_query",
            Self::SignedCompatibilityRecord => "signed_compatibility_record",
            Self::NotProbed => "not_probed",
        }
    }
}

/// What one capability can currently do.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Qualified and available in this subject now.
    QualifiedAvailable,
    /// The tool or component is not installed.
    MissingInstallation,
    /// An operating-system permission is required. A tool-specific permission stays visible here
    /// rather than becoming a false global success.
    PermissionRequired,
    /// The installed version cannot serve this capability.
    Incompatible,
    /// Available in principle and not right now, as on a locked desktop.
    TemporarilyUnavailable,
    /// Nothing has established either answer.
    NotTested,
}

impl CapabilityState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedAvailable => "qualified_available",
            Self::MissingInstallation => "missing_installation",
            Self::PermissionRequired => "permission_required",
            Self::Incompatible => "incompatible",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::NotTested => "not_tested",
        }
    }

    /// Returns whether an action may be attempted on this capability.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::QualifiedAvailable)
    }
}

/// What makes a capability record stale.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInvalidation {
    /// The probed binary changed.
    BinaryIdentity,
    /// The live binding changed.
    BindingIdentity,
    /// The schema or package identity changed.
    PackageSchema,
    /// An operating-system permission changed.
    OsPermission,
    /// The desktop generation changed, which a new login always does.
    DesktopGeneration,
    /// The execution profile changed.
    WorkerProfile,
}

impl CapabilityInvalidation {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryIdentity => "binary_identity",
            Self::BindingIdentity => "binding_identity",
            Self::PackageSchema => "package_schema",
            Self::OsPermission => "os_permission",
            Self::DesktopGeneration => "desktop_generation",
            Self::WorkerProfile => "worker_profile",
        }
    }
}

/// What a capability record is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySubject {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The desktop, where the subject is one.
    pub desktop_session_id: Nullable<DesktopSessionId>,
    /// The session, where the subject is one.
    pub session_id: Nullable<SessionId>,
    /// The application the record is about, where it is one.
    pub application: Nullable<String>,
    /// The terminal the record is about, where it is one.
    pub terminal: Nullable<String>,
}

/// The exact thing a capability record was established about.
///
/// An installed upgrade does not invalidate a correctly pinned identity in a process that is
/// already running, which is why the identity is recorded rather than looked up again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityIdentity {
    /// The binary that was probed, by absolute path.
    pub binary: Nullable<String>,
    /// That binary's version, as it reported it.
    pub version: Nullable<String>,
    /// The package the capability belongs to.
    pub package: Nullable<String>,
    /// The schema the binding speaks.
    pub schema: Nullable<String>,
    /// The execution profile the probe ran under.
    pub profile: Nullable<WorkerProfile>,
}

impl CapabilityIdentity {
    /// An identity for a capability that names no binary, package or schema.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            binary: Nullable::null(),
            version: Nullable::null(),
            package: Nullable::null(),
            schema: Nullable::null(),
            profile: Nullable::null(),
        }
    }
}

/// One capability, one subject, one answer.
///
/// This is the shared section 11 record. Capability evidence describes feasibility and never
/// creates authority: every action still checks its grant, and it rechecks this record's revision
/// independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRecord {
    /// The capability, in the shared versioned namespace.
    pub capability: CapabilityId,
    /// The version of that capability's contract.
    pub version: U64,
    /// What the record is about.
    pub subject: CapabilitySubject,
    /// This record's revision. An action binds to it and rechecks it.
    pub revision: CapabilityRevision,
    /// What the capability can currently do.
    pub state: CapabilityState,
    /// What produced the answer.
    pub evidence_source: CapabilityEvidenceSource,
    /// The exact thing the answer was established about.
    pub identity: CapabilityIdentity,
    /// What makes this record stale, in the order it is written.
    pub invalidation: Vec<CapabilityInvalidation>,
    /// What a person is told when the capability is not available.
    pub disabled_reason: Nullable<String>,
    /// When the answer was established.
    pub observed_at_ms: TimestampMs,
}

/// Every capability record for one desktop, with the context they are about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DesktopCapabilityReport {
    /// The desktop the records are about.
    pub desktop: DesktopContext,
    /// The records, ordered by capability name.
    pub records: Vec<CapabilityRecord>,
}

impl DesktopCapabilityReport {
    /// Returns the record for one capability, where there is one.
    #[must_use]
    pub fn record(&self, capability: &str) -> Option<&CapabilityRecord> {
        self.records
            .iter()
            .find(|record| record.capability.as_str() == capability)
    }
}

/// The capability namespace this section owns.
///
/// Each name is a capability in the shared namespace, and each has its own record. There is no
/// aggregate "desktop automation" capability, because a desktop selection is not evidence for any
/// of them.
pub mod capabilities {
    /// Obtaining a screen image from the selected desktop.
    pub const SCREEN_CAPTURE: &str = "desktop.screen_capture";
    /// Sending synthetic input to the selected desktop.
    pub const INPUT_INJECTION: &str = "desktop.input_injection";
    /// Reading the desktop's accessibility tree.
    pub const ACCESSIBILITY: &str = "desktop.accessibility";
    /// Launching an application on the selected desktop.
    pub const APPLICATION_LAUNCH: &str = "desktop.application_launch";
    /// The display server the desktop presents.
    pub const DISPLAY_SERVER: &str = "desktop.display_server";
}

/// The owner's sleep-inhibition choice.
///
/// Off by default. Setup offers the mains-only choice and never enables it; using battery power as
/// well is a second, separate choice.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SleepInhibitionSetting {
    /// KalaReach does not change this host's sleep policy.
    #[default]
    Off,
    /// Inhibit automatic sleep while work justifies it, and only on mains power.
    MainsOnly,
    /// Inhibit automatic sleep while work justifies it, on mains or battery power.
    BatteryToo,
}

impl SleepInhibitionSetting {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::MainsOnly => "mains_only",
            Self::BatteryToo => "battery_too",
        }
    }

    /// Returns the setting for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "mains_only" => Some(Self::MainsOnly),
            "battery_too" => Some(Self::BatteryToo),
            _ => None,
        }
    }

    /// Returns whether this setting permits inhibition on the given power source.
    #[must_use]
    pub const fn permits(self, power: PowerSource) -> bool {
        match self {
            Self::Off => false,
            // An unknown power source is not treated as mains: a setting that says "only on mains"
            // must not hold an assertion on a host that will not say what it is running on.
            Self::MainsOnly => matches!(power, PowerSource::Mains),
            Self::BatteryToo => true,
        }
    }
}

/// What the host is running on.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    /// Mains power.
    Mains,
    /// Battery power.
    Battery,
    /// This host does not say.
    Unknown,
}

impl PowerSource {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mains => "mains",
            Self::Battery => "battery",
            Self::Unknown => "unknown",
        }
    }
}

/// Why an assertion is being held.
///
/// Both are verified conditions rather than a guess about activity: work the host has admitted,
/// and requests it has accepted and not yet answered.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InhibitionReason {
    /// A session has verified foreground work.
    ForegroundWork,
    /// The host has accepted requests it has not answered.
    PendingRequests,
    /// Both of the above.
    ForegroundWorkAndPendingRequests,
}

impl InhibitionReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundWork => "foreground_work",
            Self::PendingRequests => "pending_requests",
            Self::ForegroundWorkAndPendingRequests => "foreground_work_and_pending_requests",
        }
    }

    /// Returns the reason for a pair of conditions, or none when neither holds.
    #[must_use]
    pub const fn of(foreground_work: bool, pending_requests: bool) -> Option<Self> {
        match (foreground_work, pending_requests) {
            (true, true) => Some(Self::ForegroundWorkAndPendingRequests),
            (true, false) => Some(Self::ForegroundWork),
            (false, true) => Some(Self::PendingRequests),
            (false, false) => None,
        }
    }

    /// Returns the sentence host status and `kr status` print.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::ForegroundWork => "a session has verified foreground work",
            Self::PendingRequests => "the host has requests it has not answered",
            Self::ForegroundWorkAndPendingRequests => {
                "a session has verified foreground work and the host has requests it has not \
                 answered"
            }
        }
    }
}

/// Which platform facility holds the assertion.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InhibitionMechanism {
    /// macOS: a power-management assertion against automatic sleep.
    MacosPowerAssertion,
    /// Linux: a login-manager sleep inhibitor held for as long as its holder lives.
    LinuxLogindInhibitor,
    /// Windows: an execution-state request made by the per-user host agent.
    WindowsExecutionState,
    /// This host has no facility for it.
    None,
}

impl InhibitionMechanism {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacosPowerAssertion => "macos_power_assertion",
            Self::LinuxLogindInhibitor => "linux_logind_inhibitor",
            Self::WindowsExecutionState => "windows_execution_state",
            Self::None => "none",
        }
    }
}

/// What the host's sleep inhibition is doing.
///
/// Reported by host status and by `kr status`, whether it is active or not: a setting that is on
/// and holding nothing is as much a fact as one that is holding an assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SleepInhibitionState {
    /// The owner's choice.
    pub setting: SleepInhibitionSetting,
    /// Whether an assertion is held right now.
    pub active: bool,
    /// Why it is held, when it is.
    pub reason: Nullable<InhibitionReason>,
    /// The facility holding it.
    pub mechanism: InhibitionMechanism,
    /// What the host is running on.
    pub power_source: PowerSource,
    /// How many live sessions have verified foreground work.
    pub sessions_with_work: U64,
    /// How many accepted requests the host has not answered.
    pub pending_requests: U64,
    /// When the current assertion was taken.
    pub since_ms: Nullable<TimestampMs>,
    /// The name the platform shows for the assertion, so a person can find it in the operating
    /// system's own listing.
    pub holder: Nullable<String>,
    /// Why no assertion is held although the setting is on, when that is the case.
    pub withheld_reason: Nullable<String>,
}

impl SleepInhibitionState {
    /// The state of a host that has not been asked to inhibit sleep.
    #[must_use]
    pub const fn off(mechanism: InhibitionMechanism, power_source: PowerSource) -> Self {
        Self {
            setting: SleepInhibitionSetting::Off,
            active: false,
            reason: Nullable::null(),
            mechanism,
            power_source,
            sessions_with_work: U64::new(0),
            pending_requests: U64::new(0),
            since_ms: Nullable::null(),
            holder: Nullable::null(),
            withheld_reason: Nullable::null(),
        }
    }

    /// Returns the line host status and `kr status` print.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.active {
            let reason = self
                .reason
                .as_ref()
                .map_or("work the host has admitted", |reason| reason.describe());
            return format!(
                "sleep inhibited ({}): {reason}, held as {} on {} power",
                self.setting.as_str(),
                self.holder.as_ref().map_or("an assertion", String::as_str),
                self.power_source.as_str()
            );
        }
        match self.setting {
            SleepInhibitionSetting::Off => "sleep policy unchanged (off)".to_owned(),
            setting => format!(
                "sleep policy unchanged ({}): {}",
                setting.as_str(),
                self.withheld_reason
                    .as_ref()
                    .map_or("nothing currently justifies an assertion", String::as_str)
            ),
        }
    }
}

/// The host power setting as it is kept on disk.
///
/// The setting is per-user host configuration rather than a wire message: the owner chooses it
/// once, through setup or through the command line, and the control daemon reads it. Its format
/// has one definition, here, because both the daemon that reads it and the command that writes it
/// have to agree about what a file that says nothing means — and what it means is off.
pub mod setting {
    use super::SleepInhibitionSetting;

    /// The file the setting is kept in, inside the environment's own state directory.
    pub const FILE_NAME: &str = "power.json";

    /// The key the setting is written under.
    pub const KEY: &str = "sleep_inhibition";

    /// The key the document's own version is written under.
    pub const VERSION_KEY: &str = "version";

    /// The version this build writes and reads.
    ///
    /// A document that declares a version this build does not know is left alone and read as off.
    /// Guessing at a newer document's meaning is how a host ends up holding an assertion its owner
    /// did not ask for.
    pub const VERSION: u64 = 1;

    /// The longest setting file this host reads.
    ///
    /// The document holds one choice. A file larger than this is not one of ours, and reading it
    /// would be reading something else.
    pub const MAX_LEN: u64 = 4_096;

    /// Returns the setting a file's contents ask for.
    ///
    /// Anything this build does not recognise reads as off: a document it cannot parse, a version
    /// it does not know, a value outside the three choices. An unrecognised file is not consent:
    /// the setting exists because the owner chose it, so the absence of a choice this build
    /// understands is the absence of the setting.
    #[must_use]
    pub fn parse(contents: &[u8]) -> SleepInhibitionSetting {
        let Ok(document) = serde_json::from_slice::<serde_json::Value>(contents) else {
            return SleepInhibitionSetting::Off;
        };
        // A document with no version is this version: the first one, which wrote none.
        let version = document
            .get(VERSION_KEY)
            .map_or(Some(VERSION), serde_json::Value::as_u64);
        if version != Some(VERSION) {
            return SleepInhibitionSetting::Off;
        }
        document
            .get(KEY)
            .and_then(serde_json::Value::as_str)
            .and_then(SleepInhibitionSetting::from_wire)
            .unwrap_or(SleepInhibitionSetting::Off)
    }

    /// Returns the file contents that record one setting.
    #[must_use]
    pub fn document(setting: SleepInhibitionSetting) -> String {
        format!(
            "{{\n  \"{VERSION_KEY}\": {VERSION},\n  \"{KEY}\": \"{}\"\n}}\n",
            setting.as_str()
        )
    }
}

/// Whether a per-user service survives the user logging out, on this platform.
///
/// The answer is a platform fact, not a preference, and it is reported rather than assumed. Setup
/// enables persistence only through an explicit choice, and only where the service configuration
/// qualifies for it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LogoutPersistence {
    /// The service ends with the login session.
    EndsAtLogout,
    /// The service survives logout as configured.
    SurvivesLogout,
    /// The service can survive logout, and the configuration that would let it has not been
    /// chosen.
    AvailableByChoice,
    /// This host has no per-user service manager to ask.
    NoServiceManager,
    /// The service mechanism is known and what the platform does to it at logout is not.
    ///
    /// This is an answer rather than an omission. A definite answer this host has not established
    /// would be worse than none: somebody would plan around it.
    NotEstablished,
}

impl LogoutPersistence {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndsAtLogout => "ends_at_logout",
            Self::SurvivesLogout => "survives_logout",
            Self::AvailableByChoice => "available_by_choice",
            Self::NoServiceManager => "no_service_manager",
            Self::NotEstablished => "not_established",
        }
    }
}

/// What the host's per-user service arrangement does at logout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfilePersistence {
    /// The profile this answer is about.
    pub profile: WorkerProfile,
    /// What happens to a worker of that profile at logout.
    pub persistence: LogoutPersistence,
    /// The service mechanism the answer is about.
    pub mechanism: String,
    /// What a person is told, including the explicit choice that would change the answer.
    pub detail: String,
}

/// The result of `environment.capabilities`.
///
/// One document: the desktop this environment currently has, what may actually be done on it, the
/// execution profile a session gets when the request does not choose one, what logout does to each
/// profile, and the host's sleep-inhibition state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCapabilitiesResult {
    /// The environment this describes.
    pub environment_id: EnvironmentId,
    /// The desktop and its capability records.
    pub desktop: DesktopCapabilityReport,
    /// The profile a create request gets when it does not choose one.
    pub default_worker_profile: WorkerProfile,
    /// What logout does to each profile on this platform, in profile order.
    pub persistence: Vec<ProfilePersistence>,
    /// The host's sleep-inhibition state.
    pub power: SleepInhibitionState,
}

/// Parameters of `environment.capabilities`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCapabilitiesParams {
    /// The environment to describe.
    pub environment_id: EnvironmentId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::BootIdentitySource;
    use crate::scalars::{Bytes, Uuid};

    fn boot(value: u8) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::MacosBootSessionUuid,
            value: Bytes::new(vec![value; 4]),
        }
    }

    fn context(session: &str, generation: Option<u64>, boot: BootIdentity) -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new(format!("macos-aqua:501:{session}")).expect("an identifier"),
            ),
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Nullable::some(session.to_owned()),
            login_generation: Nullable(generation.map(U64::new)),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(501)),
            boot_identity: boot,
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: DisplayServer::Quartz,
            compositor: Nullable::null(),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    #[test]
    fn a_reused_platform_session_number_is_a_different_desktop() {
        let first = context("100019", Some(1_000), boot(1));
        let relogin = context("100019", Some(2_000), boot(1));
        let after_reboot = context("100019", Some(1_000), boot(2));

        assert!(first.is_same_desktop(&first.clone()));
        assert!(
            !first.is_same_desktop(&relogin),
            "the same session number with a new generation is a new desktop"
        );
        assert!(
            !first.is_same_desktop(&after_reboot),
            "the same session number from before a reboot names nothing"
        );
    }

    #[test]
    fn a_mains_only_setting_withholds_the_assertion_on_battery_and_on_an_unknown_source() {
        assert!(SleepInhibitionSetting::MainsOnly.permits(PowerSource::Mains));
        assert!(!SleepInhibitionSetting::MainsOnly.permits(PowerSource::Battery));
        assert!(!SleepInhibitionSetting::MainsOnly.permits(PowerSource::Unknown));
        assert!(SleepInhibitionSetting::BatteryToo.permits(PowerSource::Battery));
        assert!(!SleepInhibitionSetting::Off.permits(PowerSource::Mains));
        assert_eq!(
            SleepInhibitionSetting::default(),
            SleepInhibitionSetting::Off,
            "the setting is off until the owner chooses otherwise"
        );
    }

    #[test]
    fn a_container_never_reaches_the_desktop_of_the_machine_hosting_it() {
        assert!(ContainerEnvironment::Host.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Container.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Wsl.reaches_parent_desktop());
    }

    #[test]
    fn a_locked_desktop_is_still_there() {
        assert!(DesktopAvailability::Locked.is_present());
        assert!(DesktopAvailability::Background.is_present());
        assert!(DesktopAvailability::Available.is_present());
        assert!(!DesktopAvailability::Ended.is_present());
    }

    #[test]
    fn the_inhibition_line_says_what_is_held_and_why() {
        let mut state =
            SleepInhibitionState::off(InhibitionMechanism::MacosPowerAssertion, PowerSource::Mains);
        assert!(state.describe().contains("unchanged"));
        state.setting = SleepInhibitionSetting::MainsOnly;
        state.active = true;
        state.reason = Nullable::some(InhibitionReason::PendingRequests);
        state.holder = Nullable::some("KalaReach pending work".to_owned());
        let line = state.describe();
        assert!(line.contains("mains_only"), "{line}");
        assert!(line.contains("requests it has not answered"), "{line}");
        assert!(line.contains("KalaReach pending work"), "{line}");
    }

    #[test]
    fn a_setting_file_round_trips_and_anything_else_reads_as_off() {
        for chosen in [
            SleepInhibitionSetting::Off,
            SleepInhibitionSetting::MainsOnly,
            SleepInhibitionSetting::BatteryToo,
        ] {
            let document = setting::document(chosen);
            assert_eq!(setting::parse(document.as_bytes()), chosen);
        }
        assert_eq!(
            setting::parse(b"{\"sleep_inhibition\": \"mains_only\"}"),
            SleepInhibitionSetting::MainsOnly,
            "a document from before the version key is this version"
        );
        for damaged in [
            b"".as_slice(),
            b"not a document".as_slice(),
            b"{}".as_slice(),
            b"{\"sleep_inhibition\": \"always\"}".as_slice(),
            b"{\"sleep_inhibition\": true}".as_slice(),
            b"{\"version\": 2, \"sleep_inhibition\": \"battery_too\"}".as_slice(),
            b"{\"version\": \"1\", \"sleep_inhibition\": \"battery_too\"}".as_slice(),
        ] {
            assert_eq!(
                setting::parse(damaged),
                SleepInhibitionSetting::Off,
                "a file this build does not recognise is not consent"
            );
        }
    }

    #[test]
    fn a_capability_report_round_trips_through_the_canonical_encoding() {
        let report = DesktopCapabilityReport {
            desktop: context("100019", Some(7), boot(3)),
            records: vec![CapabilityRecord {
                capability: CapabilityId::new(capabilities::SCREEN_CAPTURE).expect("a capability"),
                version: U64::new(1),
                subject: CapabilitySubject {
                    environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                    desktop_session_id: Nullable::null(),
                    session_id: Nullable::null(),
                    application: Nullable::null(),
                    terminal: Nullable::null(),
                },
                revision: CapabilityRevision::new(1),
                state: CapabilityState::PermissionRequired,
                evidence_source: CapabilityEvidenceSource::DisclosedProbe,
                identity: CapabilityIdentity::none(),
                invalidation: vec![
                    CapabilityInvalidation::OsPermission,
                    CapabilityInvalidation::DesktopGeneration,
                ],
                disabled_reason: Nullable::some("Screen Recording is not granted".to_owned()),
                observed_at_ms: TimestampMs::new(12),
            }],
        };
        let bytes = kr_cbor::to_canonical_vec(&report).expect("encodes");
        let decoded: DesktopCapabilityReport =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, report);
        assert!(
            decoded
                .record(capabilities::SCREEN_CAPTURE)
                .is_some_and(|record| !record.state.is_available()),
            "a permission that is not granted is not available"
        );
        assert!(
            decoded.record(capabilities::INPUT_INJECTION).is_none(),
            "a capability nothing probed has no record here"
        );
    }
}
