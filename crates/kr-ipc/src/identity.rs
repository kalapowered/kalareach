//! Reading the host's boot identity and a process's start identity from the operating system.
//!
//! Both answers come from the kernel, not from a file the host wrote earlier. That is the point:
//! a stale descriptor, a recycled process identifier and a restored backup all look plausible on
//! disk, and only the kernel can say whether this is the same boot and the same process.
//!
//! | Platform | Boot identity | Process start identity |
//! | --- | --- | --- |
//! | Linux, Android | `/proc/sys/kernel/random/boot_id` | `/proc/<pid>/stat` field 22 |
//! | macOS | `kern.bootsessionuuid` | `proc_pidinfo(PROC_PIDTBSDINFO)` |
//! | Windows | the recorded boot time | the process creation time in whole seconds |
//! | iOS and the other Apple mobile systems | refused by name | refused by name |
//!
//! Android is Linux and reads the same two files. The Apple mobile systems are the one case where
//! the facility is not there at all: an application runs in a sandbox that cannot enumerate
//! processes, cannot read another process's start time, and cannot read the boot session
//! identifier. Every call there refuses and says so, because a host that is handed a stub is a
//! host that believes something nobody established.
//!
//! The Windows values come from `sysinfo`, which reports the boot time as the wall clock minus the
//! uptime and the creation time in whole seconds. Both are coarser than the kernel's own values;
//! the Windows qualification pass narrows them, and a Windows worker's per-session Job Object
//! carries the ownership a recycled identifier could otherwise confuse.

use kr_protocol::identity::{BootIdentity, ProcessStartIdentity, ProcessStartSource};
// Only a platform that produces a boot identity names where it came from. The Apple mobile
// systems refuse instead, so on those targets nothing here has a source to name.
#[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
use kr_protocol::identity::BootIdentitySource;
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

/// The start value an identity carries when the kernel would not describe the process.
///
/// No platform's start value can reach it. Linux counts clock ticks since the boot, macOS counts
/// microseconds since the epoch and Windows counts whole seconds since the epoch; a machine that
/// had been running for as many ticks as this, or a clock this far past 1970, is not a machine this
/// host will meet. Reserving the value is what lets [`ended_process_identity`] name a process
/// without claiming a reading nobody took.
pub const START_VALUE_UNREAD: u64 = u64::MAX;

/// Returns the identity of a process that had already ended before the kernel would describe it.
///
/// A process this host started can exit before the host has read its start identity, and on macOS
/// the kernel then refuses to describe it at all: `proc_pidinfo` answers "No such process" for a
/// process that has exited, whether or not its status has been collected. There is no reading left
/// to take, so this names what is known - the identifier, and that the process has ended - and
/// carries [`START_VALUE_UNREAD`] where the kernel's value would have been.
///
/// [`process_state`] answers [`ProcessState::Ended`] for such an identity without asking the
/// kernel, so a recycled identifier can never make it read as running. What the identity cannot do
/// is prove *which* process ended: it is the identifier of a process this host started and watched
/// leave, and a closure record carrying it says exactly that much.
#[must_use]
pub fn ended_process_identity(pid: u32) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        u64::from(pid),
        platform::START_IDENTITY_SOURCE,
        START_VALUE_UNREAD,
    )
}

/// Reads the start identity of a process this host has just started.
///
/// The process can be gone before this reads it, and often is: a shell whose startup file says
/// `exit`, a program that cannot open what it needs, a command that is not there. On macOS the
/// kernel refuses to describe a process that has exited even before its status is collected, so the
/// reading fails outright. That is not a failure to start a process, and this does not report it as
/// one: an absent process is named by [`ended_process_identity`], and what it started is left for
/// the caller to collect and record.
///
/// Every other failure is still a failure. A kernel that will not answer is not a process that has
/// gone, and a host that treated the two alike would report a live process as ended.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the operating system neither describes the
/// process nor says it is absent.
pub fn started_process_identity(pid: u32) -> Result<ProcessStartIdentity> {
    match process_start_identity(pid) {
        Ok(identity) => Ok(identity),
        Err(error) if platform::is_absent(&error) => Ok(ended_process_identity(pid)),
        Err(error) => Err(error),
    }
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
    // An identity the kernel never described belongs to a process that had already ended when it
    // was made. Asking about the identifier now would be asking about whoever holds it next.
    if identity.start_value.get() == START_VALUE_UNREAD {
        return ProcessState::Ended;
    }
    let Ok(pid) = u32::try_from(identity.pid.get()) else {
        return ProcessState::Ended;
    };
    match process_start_identity(pid) {
        // The identifier and the start value are the process that was recorded. Whether it is
        // still running is a second question on a platform that describes a process after it has
        // exited: Linux keeps the `/proc` entry of a process whose status nobody has collected, and
        // a process waiting to be collected has ended. The recorded start value goes with the
        // question, because a platform that has to look again has to know whether what it is
        // looking at is still the same process.
        Ok(current) if current.matches(identity) => {
            platform::liveness(pid, identity.start_value.get())
        }
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

// Android is Linux underneath: the same `/proc` entries, in the same format, with the same
// meaning. It is named beside it rather than left to fall through, because a target with no
// platform module at all is a target that does not compile.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, Result,
        unavailable,
    };

    const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

    /// Where each field of `/proc/<pid>/stat` sits *after* the command name.
    ///
    /// The line begins `pid (comm) state ...` and the command name can contain spaces and brackets,
    /// so the fields are counted from after its closing bracket. Counting from there, index 0 is
    /// the state, which is field 3 of the line: a field's index here is its number minus three.
    const STAT_PROCESS_GROUP: usize = 2;
    /// The controlling terminal's device number, field 7 of the line.
    const STAT_TERMINAL: usize = 4;

    /// Where this platform's start value comes from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource = ProcessStartSource::LinuxProcStat;

    /// The number of threads the thread group still has, field 20 of the line.
    const STAT_THREADS: usize = 17;

    /// Returns whether a process whose identity still matches is running or waiting to be collected.
    ///
    /// Linux keeps the `/proc` entry of a process that has exited until its parent collects its
    /// status, and the state character says so: `Z` is a thread-group leader that has ended and
    /// whose exit status nobody has taken. Reporting it as running would put it in a closure record
    /// as a surviving resource, and it is not surviving; it is waiting.
    ///
    /// `Z` alone is not the whole answer, because a leader that calls `pthread_exit` is `Z` while
    /// the rest of its threads carry on running: the kernel keeps the leader as a zombie so the
    /// identifier stays valid for the group. Such a process is running, and signalling it still
    /// reaches the threads that are. So the thread count goes with the state, and only a zombie
    /// leader whose group has nothing left is reported as ended.
    ///
    /// Everything this needs comes from one reading of one line, so the answer is about one
    /// process. Reading the state and the start value separately would leave room for the
    /// identifier to be collected and given to something else in between, and the state of that
    /// something else is not an answer about this process.
    pub(super) fn liveness(pid: u32, start_value: u64) -> super::ProcessState {
        let path = format!("/proc/{pid}/stat");
        match std::fs::read_to_string(&path) {
            Ok(text) => decide(&text, start_value),
            // A missing entry is a process that has gone. Every other failure - a descriptor limit,
            // a permission, a kernel that would not answer - proves nothing, and answering "ended"
            // to it would retire a live worker or leave a survivor out of a closure record.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                super::ProcessState::Ended
            }
            Err(error) => super::ProcessState::Unknown {
                detail: format!("{path}: {error}"),
            },
        }
    }

    /// Reads one `/proc/<pid>/stat` line and says what it says about the process that was recorded.
    fn decide(text: &str, start_value: u64) -> super::ProcessState {
        let Some(start) = parse_start_ticks(text) else {
            return super::ProcessState::Unknown {
                detail: "a /proc stat line without a start time".to_owned(),
            };
        };
        if start != start_value {
            // The identifier belongs to something else now, which means the process that was
            // recorded has gone.
            return super::ProcessState::Ended;
        }
        let Some(state) = state_character(text) else {
            return super::ProcessState::Unknown {
                detail: "a /proc stat line without a state".to_owned(),
            };
        };
        match state {
            // A zombie leader is the group's only remaining thread or it is not. One is a process
            // waiting to be collected; the other is a process still running under a leader that
            // has left.
            'Z' => match stat_field(text, STAT_THREADS) {
                Some(1) => super::ProcessState::Ended,
                Some(_) => super::ProcessState::Running,
                None => super::ProcessState::Unknown {
                    detail: "a /proc stat line without a thread count".to_owned(),
                },
            },
            // A state no reader of `/proc` should meet, and one that does not prove what it looks
            // like it proves: during an `exec` the kernel lets another thread take the leader's
            // identifier and start time and marks the old leader dead, so a reading that catches
            // that moment can say `X` of a process that is carrying on. Nothing here concludes a
            // death from it.
            'X' | 'x' => super::ProcessState::Unknown {
                detail: format!("a /proc stat line whose state is `{state}`"),
            },
            // Running, sleeping, waiting on disk, stopped, traced or idle: all of them are a
            // process that is there. A letter this reader has never heard of is not a death, but it
            // is not something to claim either.
            'R' | 'S' | 'D' | 'T' | 't' | 'W' | 'P' | 'I' | 'K' => super::ProcessState::Running,
            other => super::ProcessState::Unknown {
                detail: format!("a /proc stat line whose state is `{other}`"),
            },
        }
    }

    /// Returns the state character of a `/proc/<pid>/stat` line, which is the field after the name.
    fn state_character(text: &str) -> Option<char> {
        let tail = text.rfind(')').map(|end| &text[end + 1..])?;
        tail.split_whitespace().next()?.chars().next()
    }

    pub(super) fn processes_on_terminal(terminal: u32) -> Result<Vec<u32>> {
        stat_field_matches(STAT_TERMINAL, terminal, "controlling terminal")
    }

    pub(super) fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            unavailable("controlling terminal", format!("/proc/{pid}/stat: {error}"))
        })?;
        // Zero is no controlling terminal at all, which is not a terminal to enumerate by.
        Ok(stat_field(&text, STAT_TERMINAL).filter(|terminal| *terminal != 0))
    }

    /// Returns one numeric field of a `/proc/<pid>/stat` line, counted after the command name.
    ///
    /// The kernel prints `tty_nr` as a signed value, so it is read as one and kept as the same bit
    /// pattern: comparing two of these is comparing the kernel's own device number with itself.
    fn stat_field(text: &str, index: usize) -> Option<u32> {
        let tail = text.rfind(')').map(|end| &text[end + 1..])?;
        let field = tail.split_whitespace().nth(index)?;
        field
            .parse::<i32>()
            .ok()
            .map(i32::cast_unsigned)
            .or_else(|| field.parse::<u32>().ok())
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
            let Ok(line) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            if stat_field(&line, STAT_PROCESS_GROUP) == Some(group) {
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
        use super::{decide, parse_start_ticks};
        use crate::identity::ProcessState;

        /// Builds a `/proc/<pid>/stat` line with the state, thread count and start time given.
        ///
        /// The fields between them are a real line's, so the indices this module counts are the
        /// indices the kernel writes.
        fn line(state: &str, threads: u32, start: u64) -> String {
            format!(
                "42 (od d) ne) {state} 1 42 42 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 {threads} 0 \
                 {start} 0 0 0 0 0"
            )
        }

        #[test]
        fn a_name_containing_spaces_and_parentheses_does_not_shift_the_fields() {
            let mut line =
                String::from("42 (od d) ne) S 1 42 42 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 ");
            line.push_str("987654 0 0 0 0 0");
            assert_eq!(parse_start_ticks(&line), Some(987_654));
        }

        #[test]
        fn a_live_state_is_running_and_a_dead_one_establishes_nothing() {
            assert_eq!(
                decide(&line("S", 1, 987_654), 987_654),
                ProcessState::Running
            );
            assert_eq!(
                decide(&line("R", 8, 987_654), 987_654),
                ProcessState::Running
            );
            // `X` looks like proof and is not: an `exec` hands the leader's identifier and start
            // time to another thread and marks the old leader dead, so this can be the state of a
            // process that is carrying on. One thread or many, the answer is that nothing is known.
            for threads in [1, 4] {
                assert!(
                    matches!(
                        decide(&line("X", threads, 987_654), 987_654),
                        ProcessState::Unknown { .. }
                    ),
                    "a dead leader with {threads} thread(s) is not a death this reader can claim"
                );
                assert!(matches!(
                    decide(&line("x", threads, 987_654), 987_654),
                    ProcessState::Unknown { .. }
                ));
            }
        }

        #[test]
        fn a_zombie_leader_is_ended_only_when_its_group_has_nothing_left() {
            assert_eq!(
                decide(&line("Z", 1, 987_654), 987_654),
                ProcessState::Ended,
                "a process waiting to be collected has ended"
            );
            assert_eq!(
                decide(&line("Z", 4, 987_654), 987_654),
                ProcessState::Running,
                "a leader that left its threads running has not: the process is still executing, \
                 and signalling it still reaches them"
            );
        }

        #[test]
        fn an_identifier_that_now_belongs_to_something_else_has_ended() {
            assert_eq!(
                decide(&line("R", 1, 987_655), 987_654),
                ProcessState::Ended,
                "the start time is not the one that was recorded"
            );
        }

        #[test]
        fn a_line_this_reader_cannot_account_for_is_not_a_death() {
            // Each of these is a reading that establishes nothing, and nothing must never be
            // reported as ended: a recovery path that took it for death would retire a live worker,
            // and a closure record would leave out a process it should have listed.
            let unaccountable = [
                ("no start time", "42 (sh) S 1 42".to_owned()),
                ("no state", "42 (sh)".to_owned()),
                ("an unknown state", line("Q", 1, 987_654)),
                (
                    "a thread count that is not a number",
                    "42 (sh) Z 1 42 42 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 many 0 987654 0 0 0 0 0"
                        .to_owned(),
                ),
            ];
            for (what, text) in unaccountable {
                assert!(
                    matches!(decide(&text, 987_654), ProcessState::Unknown { .. }),
                    "{what} says nothing, so the answer is that nothing is known"
                );
            }
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

    /// Where this platform's start value comes from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource =
        ProcessStartSource::MacosProcBsdInfo;

    /// Returns whether a process whose identity still matches is running.
    ///
    /// On this platform the question is already answered by the reading that matched: the kernel
    /// refuses to describe a process that has exited, collected or not, so an identity that still
    /// matches belongs to a process that is still there.
    pub(super) const fn liveness(_pid: u32, _start_value: u64) -> super::ProcessState {
        super::ProcessState::Running
    }

    pub(super) fn is_absent(error: &crate::error::IpcError) -> bool {
        // `proc_pidinfo` reports a process that is not there as "No such process"; every other
        // failure leaves the question open. A process that has exited is one of those: this
        // platform stops describing it at once, before its status has been collected.
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

/// The Apple systems that are not macOS: iOS, iPadOS and their siblings.
///
/// Every function here refuses and names what is missing. That is not a gap waiting to be filled:
/// an application on these systems runs in a sandbox with no way to enumerate processes, no way to
/// read another process's start time, and no access to the boot session identifier. A stub that
/// answered would be the worst possible outcome, because every caller in this repository uses
/// these answers to decide whether a process it recorded is still the one it recorded.
///
/// Nothing on these systems runs a host. The module exists so the client library that a phone
/// links compiles, and so that anything which did ask would be told, by name, that the answer is
/// not available rather than handed one that was invented.
#[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
mod platform {
    use super::{BootIdentity, ProcessStartIdentity, ProcessStartSource, Result, unavailable};

    /// What every refusal in this module says, after the name of what was asked for.
    const SANDBOXED: &str = "this Apple system sandboxes an application away from process and boot identity; there is \
         no host on this device to identify";

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        Err(unavailable("boot identity", SANDBOXED))
    }

    pub(super) fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
        Err(unavailable(
            "process start identity",
            format!("pid {pid}: {SANDBOXED}"),
        ))
    }

    pub(super) fn processes_in_group(group: u32) -> Result<Vec<u32>> {
        Err(unavailable(
            "process group",
            format!("group {group}: {SANDBOXED}"),
        ))
    }

    pub(super) fn processes_on_terminal(terminal: u32) -> Result<Vec<u32>> {
        Err(unavailable(
            "controlling terminal",
            format!("terminal {terminal}: {SANDBOXED}"),
        ))
    }

    pub(super) fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
        Err(unavailable(
            "controlling terminal",
            format!("pid {pid}: {SANDBOXED}"),
        ))
    }

    /// Where a start value would come from if this system produced one.
    ///
    /// It never does. The constant exists because [`super::ended_process_identity`] names the
    /// source beside the reserved "nobody read this" value, and the Darwin kernel underneath is
    /// the source such a reading would have come from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource =
        ProcessStartSource::MacosProcBsdInfo;

    /// Unreachable: nothing here ever produces an identity that could match a recorded one.
    pub(super) const fn liveness(_pid: u32, _start_value: u64) -> super::ProcessState {
        super::ProcessState::Unknown {
            detail: String::new(),
        }
    }

    /// Whether a failure means the process is gone. It never does here: nothing was ever read.
    ///
    /// Answering true would turn "this system will not tell me" into "the process has ended",
    /// which is the one conversion section 9 forbids.
    pub(super) const fn is_absent(_error: &crate::error::IpcError) -> bool {
        false
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

    /// Where this platform's start value comes from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource =
        ProcessStartSource::WindowsProcessStartSeconds;

    /// Returns whether a process whose identity still matches is running.
    ///
    /// The reading that matched came from the process table, which does not keep a process that
    /// has exited, so there is nothing further to ask.
    pub(super) const fn liveness(_pid: u32, _start_value: u64) -> super::ProcessState {
        super::ProcessState::Running
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

    /// Waits until a child has ended without collecting its status, using the platform's own view
    /// of it rather than the reading under test.
    ///
    /// On Linux and Android the state character of `/proc/<pid>/stat` becomes `Z`; on macOS the
    /// kernel stops describing the process, which `libproc` reports as "No such process".
    /// Collecting the status is what would remove the case, so nothing here does.
    #[cfg(unix)]
    fn wait_until_it_has_ended(pid: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let ended = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|text| {
                    let tail = text.rfind(')').map(|end| text[end + 1..].to_owned())?;
                    tail.split_whitespace().next()?.chars().next()
                })
                .is_some_and(|state| state == 'Z');
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let ended = process_start_identity(pid).is_err();
            if ended {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a shell told to exit does so"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_process_that_has_ended_is_named_rather_than_left_unavailable() {
        // The case a host meets when what it started leaves at once, and the state each platform
        // describes differently: a process that has ended and whose status nobody has collected.
        // Linux keeps its `/proc` entry until the collection; macOS stops describing it at the
        // exit. Either way the host has to come away with an identity rather than a failure, and
        // with the answer that the process has ended.
        //
        // Nothing here collects the status before the reading, because collecting it is what
        // removes the case: the loop waits for the platform's own answer instead, which is what
        // makes this deterministic on both of them.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawns a child that leaves at once");
        let pid = child.id();
        wait_until_it_has_ended(pid);

        let named = started_process_identity(pid).expect("the host names what it started");
        assert_eq!(named.pid.get(), u64::from(pid));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_ne!(
            named.start_value.get(),
            START_VALUE_UNREAD,
            "this platform still describes a process whose status nobody has collected, so the \
             reading is the kernel's own"
        );
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert_eq!(
            named.start_value.get(),
            START_VALUE_UNREAD,
            "this platform stops describing a process at its exit, so there was no reading to take"
        );
        assert_eq!(
            process_state(&named),
            ProcessState::Ended,
            "either way the answer is that the process has ended"
        );

        // The status is still there to collect, which is what makes the reading above a reading of
        // an uncollected process rather than of one that had already been reaped.
        let status = child.wait().expect("the status was still there to collect");
        assert!(status.success(), "the child exited as it was told to");
        assert_eq!(
            process_state(&named),
            ProcessState::Ended,
            "and it still reads as ended once its status has been collected"
        );
    }

    #[test]
    fn a_process_that_ended_before_it_could_be_described_is_ended_without_asking() {
        // This process is running, and an identity the kernel never described still reads as
        // ended: the reserved start value is what says the reading never happened, so an
        // identifier that has been recycled cannot make a dead process look alive.
        let unread = ended_process_identity(std::process::id());
        assert_eq!(unread.pid.get(), u64::from(std::process::id()));
        assert_eq!(unread.start_value.get(), START_VALUE_UNREAD);
        assert_eq!(process_state(&unread), ProcessState::Ended);
        assert_eq!(
            process_state(&current_process_start_identity().expect("the kernel answers")),
            ProcessState::Running,
            "and the real identity of the same process still reads as running"
        );
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
