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
//! | Windows | the recorded boot time | the process creation time in whole seconds |
//!
//! The Windows values come from `sysinfo`, which reports the boot time as the wall clock minus the
//! uptime and the creation time in whole seconds. Both are coarser than the kernel's own values;
//! the Windows qualification pass narrows them, and a Windows worker's per-session Job Object
//! carries the ownership a recycled identifier could otherwise confuse.

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

/// Returns the process identifiers currently in one process group.
///
/// A terminal session's processes normally stay in the group the shell leads, which is what makes
/// this the set a worker can act on. It is not a complete ownership boundary: a process that calls
/// `setsid` leaves the group and stops appearing here, which is exactly why a host built on this
/// alone never claims complete coverage.
///
/// # Errors
///
/// Returns an error when the platform will not enumerate processes.
pub fn processes_in_group(group: u32) -> Result<Vec<u32>> {
    platform::processes_in_group(group)
}

/// Reads this process's own start identity.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system does not answer.
pub fn current_process_start_identity() -> Result<ProcessStartIdentity> {
    process_start_identity(std::process::id())
}

/// What the kernel says about a process the host recorded earlier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is running and its start identity matches the recorded one.
    Running,
    /// The process is gone, or its identifier now belongs to a different process.
    Ended,
    /// The operating system did not answer, so neither answer is established.
    ///
    /// This is not "ended". A recovery path that treated a denied or failed query as death would
    /// complete a revocation, take over a journal or release a session identity while the original
    /// process was still running.
    Unknown {
        /// Why the query failed.
        detail: String,
    },
}

/// Asks the kernel whether a recorded process is still the process that was recorded.
///
/// A process identifier on its own proves nothing: the kernel reuses them, and an unrelated
/// program can hold the number within milliseconds. Both halves are compared, so a recycled
/// identifier reads as [`ProcessState::Ended`] rather than as the original process.
#[must_use]
pub fn process_state(identity: &ProcessStartIdentity) -> ProcessState {
    let Ok(pid) = u32::try_from(identity.pid.get()) else {
        return ProcessState::Ended;
    };
    match process_start_identity(pid) {
        Ok(current) if current.matches(identity) => ProcessState::Running,
        Ok(_) => ProcessState::Ended,
        Err(error) if platform::is_absent(&error) => ProcessState::Ended,
        Err(error) => ProcessState::Unknown {
            detail: error.to_string(),
        },
    }
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

    pub(super) fn processes_in_group(group: u32) -> Result<Vec<u32>> {
        let entries = std::fs::read_dir("/proc")
            .map_err(|error| unavailable("process group", format!("/proc: {error}")))?;
        let mut members = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            // Field five of the statistics line is the process group. The command name before it
            // can contain spaces and brackets, so the fields are counted from after its closing
            // bracket rather than from the start of the line.
            let Ok(line) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some(rest) = line.rsplit_once(')').map(|(_, rest)| rest) else {
                continue;
            };
            if rest
                .split_whitespace()
                .nth(3)
                .and_then(|field| field.parse::<u32>().ok())
                == Some(group)
            {
                members.push(pid);
            }
        }
        members.sort_unstable();
        Ok(members)
    }

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        let text = std::fs::read_to_string(BOOT_ID_PATH)
            .map_err(|error| unavailable("boot identity", format!("{BOOT_ID_PATH}: {error}")))?;
        Ok(BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: kr_protocol::scalars::Bytes::new(text.trim().as_bytes().to_vec()),
        })
    }

    pub(super) fn is_absent(error: &crate::error::IpcError) -> bool {
        // The only failure that proves absence on Linux is a missing /proc entry.
        error.to_string().contains("No such file or directory")
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
    use libproc::processes::{ProcFilter, pids_by_type};
    use sysctl::Sysctl as _;

    pub(super) fn processes_in_group(group: u32) -> super::Result<Vec<u32>> {
        pids_by_type(ProcFilter::ByProgramGroup { pgrpid: group })
            .map_err(|error| super::unavailable("process group", format!("group {group}: {error}")))
    }

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

    pub(super) fn is_absent(error: &crate::error::IpcError) -> bool {
        // `proc_pidinfo` reports a process that is not there as "No such process"; every other
        // failure leaves the question open.
        let message = error.to_string();
        message.contains("No such process") || message.contains("not a process identifier")
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

    pub(super) fn processes_in_group(_group: u32) -> Result<Vec<u32>> {
        // Windows has no process group to enumerate. A worker's descendants are held by its job
        // object instead, which is a complete boundary rather than a partial one, so nothing here
        // needs to guess at group membership.
        Ok(Vec::new())
    }

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

    pub(super) fn is_absent(error: &crate::error::IpcError) -> bool {
        error.to_string().contains("is gone")
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
            ProcessStartSource::WindowsProcessStartSeconds,
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
        assert_eq!(process_state(&first), ProcessState::Running);
    }

    #[test]
    fn a_different_start_value_reads_as_a_different_process() {
        let mut altered = current_process_start_identity().expect("the kernel answers");
        altered.start_value = kr_protocol::scalars::U64::new(altered.start_value.get() + 1);
        assert_eq!(process_state(&altered), ProcessState::Ended);
    }

    #[test]
    fn a_process_identifier_that_cannot_exist_reads_as_ended() {
        let impossible = ProcessStartIdentity::new(
            u64::from(u32::MAX) + 1,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            1,
        );
        assert_eq!(process_state(&impossible), ProcessState::Ended);
    }
}
