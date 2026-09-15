//! Reading the host's boot identity and a process's start identity from the operating system.
//!
//! Both answers come from the kernel, not from a file the host wrote earlier. That is the point:
//! a stale descriptor, a recycled process identifier and a restored backup all look plausible on
//! disk, and only the kernel can say whether this is the same boot and the same process.
//!
//! | Platform | Boot identity | Process start identity |
//! | --- | --- | --- |
//! | Linux | `/proc/sys/kernel/random/boot_id` | `/proc/<pid>/stat` field 22 |
//! | macOS | `kern.bootsessionuuid` | `proc_pidinfo(PROC_PIDTBSDINFO)` |
//! | Windows | the recorded boot time | `GetProcessTimes` creation time |

use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource,
};

use crate::error::{IpcError, Result};

/// Reads the identity of the host's current boot.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system does not answer.
pub fn boot_identity() -> Result<BootIdentity> {
    platform::boot_identity()
}

/// Reads one process's start identity.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the process does not exist or the operating
/// system does not answer.
pub fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
    platform::process_start_identity(pid)
}

/// Reads this process's own start identity.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system does not answer.
pub fn current_process_start_identity() -> Result<ProcessStartIdentity> {
    process_start_identity(std::process::id())
}

/// Returns true when the process named by this identity is still the process that was recorded.
///
/// A process identifier on its own proves nothing: the kernel reuses them, and an unrelated
/// program can hold the number within milliseconds. This re-reads the start identity and compares
/// both halves, so a recycled identifier reads as absent.
#[must_use]
pub fn process_still_running(identity: &ProcessStartIdentity) -> bool {
    let pid = u32::try_from(identity.pid.get()).unwrap_or(u32::MAX);
    process_start_identity(pid).is_ok_and(|current| current.matches(identity))
}

fn unavailable(what: &'static str, detail: impl Into<String>) -> IpcError {
    IpcError::IdentityUnavailable {
        what,
        detail: detail.into(),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, Result,
        unavailable,
    };

    const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        let text = std::fs::read_to_string(BOOT_ID_PATH)
            .map_err(|error| unavailable("boot identity", format!("{BOOT_ID_PATH}: {error}")))?;
        Ok(BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: kr_protocol::scalars::Bytes::new(text.trim().as_bytes().to_vec()),
        })
    }

    pub(super) fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
        let path = format!("/proc/{pid}/stat");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| unavailable("process start identity", format!("{path}: {error}")))?;
        let start_ticks = parse_start_ticks(&text).ok_or_else(|| {
            unavailable(
                "process start identity",
                format!("{path}: field 22 is missing"),
            )
        })?;
        Ok(ProcessStartIdentity::new(
            u64::from(pid),
            ProcessStartSource::LinuxProcStat,
            start_ticks,
        ))
    }

    /// Reads field 22 of a `/proc/<pid>/stat` line.
    ///
    /// Field 2 is the executable name in parentheses and may itself contain spaces and closing
    /// parentheses, so the fields after it are found from the *last* `)` rather than by splitting
    /// the whole line.
    fn parse_start_ticks(text: &str) -> Option<u64> {
        let close = text.rfind(')')?;
        let rest = text.get(close + 1..)?;
        // After the name comes field 3, so field 22 is the twentieth value here.
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    #[cfg(test)]
    mod tests {
        use super::parse_start_ticks;

        #[test]
        fn a_name_containing_spaces_and_parentheses_does_not_shift_the_fields() {
            let mut line =
                String::from("42 (od d) ne) S 1 42 42 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 ");
            line.push_str("987654 0 0 0 0 0");
            assert_eq!(parse_start_ticks(&line), Some(987_654));
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libproc::bsd_info::BSDInfo;
    use libproc::proc_pid::pidinfo;
    use sysctl::Sysctl as _;

    use super::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, Result,
        unavailable,
    };

    const BOOT_SESSION_CONTROL: &str = "kern.bootsessionuuid";
    const BOOT_TIME_CONTROL: &str = "kern.boottime";

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        if let Ok(control) = sysctl::Ctl::new(BOOT_SESSION_CONTROL)
            && let Ok(sysctl::CtlValue::String(value)) = control.value()
            && !value.trim().is_empty()
        {
            return Ok(BootIdentity {
                source: BootIdentitySource::MacosBootSessionUuid,
                value: kr_protocol::scalars::Bytes::new(value.trim().as_bytes().to_vec()),
            });
        }
        // Older kernels do not publish a boot session identifier. The boot time changes with every
        // boot too, so it answers the same question with a different unit.
        let control = sysctl::Ctl::new(BOOT_TIME_CONTROL).map_err(|error| {
            unavailable("boot identity", format!("{BOOT_TIME_CONTROL}: {error}"))
        })?;
        let value = control.value().map_err(|error| {
            unavailable("boot identity", format!("{BOOT_TIME_CONTROL}: {error}"))
        })?;
        let sysctl::CtlValue::Struct(bytes) = value else {
            return Err(unavailable(
                "boot identity",
                format!("{BOOT_TIME_CONTROL} did not return a structure"),
            ));
        };
        Ok(BootIdentity {
            source: BootIdentitySource::BootTime,
            value: kr_protocol::scalars::Bytes::new(bytes),
        })
    }

    pub(super) fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
        let pid = i32::try_from(pid).map_err(|_| {
            unavailable(
                "process start identity",
                format!("{pid} is not a process identifier"),
            )
        })?;
        let info: BSDInfo = pidinfo(pid, 0).map_err(|error| {
            unavailable("process start identity", format!("pid {pid}: {error}"))
        })?;
        // Microseconds since the epoch, exactly as the kernel recorded them at execution.
        let start = info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec);
        Ok(ProcessStartIdentity::new(
            u64::from(info.pbi_pid),
            ProcessStartSource::MacosProcBsdInfo,
            start,
        ))
    }
}

#[cfg(windows)]
mod platform {
    use super::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, Result,
        unavailable,
    };

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        let boot = sysinfo::System::boot_time();
        if boot == 0 {
            return Err(unavailable("boot identity", "boot time is not available"));
        }
        Ok(BootIdentity {
            source: BootIdentitySource::BootTime,
            value: kr_protocol::scalars::Bytes::new(boot.to_be_bytes().to_vec()),
        })
    }

    pub(super) fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};

        let mut system = sysinfo::System::new();
        let target = sysinfo::Pid::from_u32(pid);
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing(),
        );
        let process = system
            .process(target)
            .ok_or_else(|| unavailable("process start identity", format!("pid {pid} is gone")))?;
        Ok(ProcessStartIdentity::new(
            u64::from(pid),
            ProcessStartSource::WindowsProcessTimes,
            process.start_time(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_reports_a_boot_identity() {
        let identity = boot_identity().expect("the kernel answers");
        assert!(!identity.value.is_empty());
    }

    #[test]
    fn this_process_reports_a_start_identity_that_is_stable() {
        let first = current_process_start_identity().expect("the kernel answers");
        let second = current_process_start_identity().expect("the kernel answers");
        assert_eq!(first, second);
        assert_eq!(first.pid.get(), u64::from(std::process::id()));
        assert!(process_still_running(&first));
    }

    #[test]
    fn a_different_start_value_reads_as_a_different_process() {
        let mut altered = current_process_start_identity().expect("the kernel answers");
        altered.start_value = kr_protocol::scalars::U64::new(altered.start_value.get() + 1);
        assert!(!process_still_running(&altered));
    }
}
