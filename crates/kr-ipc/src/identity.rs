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
use kr_protocol::ids::BootEpoch;

use crate::error::{IpcError, Result};

/// Reads the identity of the host's current boot.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system does not answer.
pub fn boot_identity() -> Result<BootIdentity> {
    platform::boot_identity()
}

/// Returns the compact boot epoch that binds a continuous-time deadline to one boot.
///
/// A [`BootIdentity`] is an opaque value of whatever length its source produces, and the wire
/// carries the boot inside an action window as a single number. This derives that number from the
/// identity, so the two can never disagree about which boot the host is in: it is the first eight
/// bytes of the SHA-256 of the identity's canonical encoding, read big-endian.
///
/// The value is only ever compared for equality. It is not a count of boots and it does not
/// increase from one boot to the next; what matters is that a different boot produces a different
/// number, which a 64-bit digest of the kernel's own boot identifier does.
///
/// # Errors
///
/// Returns an error when the identity cannot be encoded canonically.
pub fn boot_epoch(identity: &BootIdentity) -> Result<BootEpoch> {
    let encoded =
        kr_cbor::to_canonical_vec(identity).map_err(|error| IpcError::IdentityUnavailable {
            what: "the boot identity could not be encoded",
            detail: error.to_string(),
        })?;
    let digest = kr_cbor::sha256(&encoded);
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    Ok(BootEpoch::new(u64::from_be_bytes(head)))
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

/// Returns the processes attached to one controlling terminal.
///
/// This is the boundary a terminal session actually has. An interactive shell puts each job in its
/// own process group, so enumerating the shell's group finds the shell and nothing it started;
/// every one of those jobs keeps the terminal. A process that calls `setsid` gives the terminal up
/// and leaves this set, which is why a host built on it never claims complete coverage.
///
/// # Errors
///
/// Returns an error when the platform will not enumerate processes.
pub fn processes_on_terminal(terminal: u32) -> Result<Vec<u32>> {
    platform::processes_on_terminal(terminal)
}

/// Returns the controlling terminal of one process, when it has one.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system does not answer.
pub fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
    platform::controlling_terminal(pid)
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

    pub(super) fn processes_on_terminal(terminal: u32) -> Result<Vec<u32>> {
        // Field seven of the statistics line is the controlling terminal's device number.
        stat_field_matches(6, terminal, "controlling terminal")
    }

    pub(super) fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            unavailable("controlling terminal", format!("/proc/{pid}/stat: {error}"))
        })?;
        Ok(stat_field(&text, 6))
    }

    /// Returns one numeric field of a `/proc/<pid>/stat` line, counted after the command name.
    fn stat_field(text: &str, index: usize) -> Option<u32> {
        let tail = text.rfind(')').map(|end| &text[end + 1..])?;
        tail.split_whitespace().nth(index)?.parse::<u32>().ok()
    }

    fn stat_field_matches(index: usize, wanted: u32, what: &'static str) -> Result<Vec<u32>> {
        let entries = std::fs::read_dir("/proc")
            .map_err(|error| unavailable(what, format!("/proc: {error}")))?;
        let mut members = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            if stat_field(&text, index) == Some(wanted) {
                members.push(pid);
            }
        }
        Ok(members)
    }

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

    pub(super) fn processes_on_terminal(terminal: u32) -> super::Result<Vec<u32>> {
        pids_by_type(ProcFilter::ByTTY { tty: terminal }).map_err(|error| {
            super::unavailable(
                "controlling terminal",
                format!("terminal {terminal}: {error}"),
            )
        })
    }

    pub(super) fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
        let pid = i32::try_from(pid).map_err(|_| {
            unavailable(
                "controlling terminal",
                format!("{pid} is not a process identifier"),
            )
        })?;
        let info: BSDInfo = pidinfo(pid, 0)
            .map_err(|error| unavailable("controlling terminal", format!("pid {pid}: {error}")))?;
        // `NODEV` on a process with no controlling terminal.
        Ok((info.e_tdev != u32::MAX).then_some(info.e_tdev))
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

    pub(super) fn processes_on_terminal(_terminal: u32) -> Result<Vec<u32>> {
        // Nor a controlling terminal; the job object is the boundary here.
        Ok(Vec::new())
    }

    pub(super) fn controlling_terminal(_pid: u32) -> Result<Option<u32>> {
        Ok(None)
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
