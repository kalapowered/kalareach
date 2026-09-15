//! Host, process and worker identities.
//!
//! A filename or a bare process identifier is a hint. What binds a running worker to the session
//! the controller reserved is the pair of identities here: the boot the host is currently running
//! and the kernel's own record of when that process started. Both are compared against the values
//! the launcher recorded, and both are covered by the worker's verification signature, so a reused
//! process identifier after a crash cannot pass as the original worker.
//!
//! Each identity names the source it came from. The values are only ever compared with another
//! value from the same source on the same host; they are not a portable measurement of time.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::DesktopSessionId;
use crate::scalars::{Bytes, Nullable, U64};

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
    /// Windows `GetProcessTimes`: creation time in 100-nanosecond intervals.
    WindowsProcessTimes,
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
}
