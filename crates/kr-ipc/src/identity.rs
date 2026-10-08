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
//! | Windows | the kernel's boot counter and its System process's creation time | `GetProcessTimes`: the creation time in hundreds of nanoseconds |
//! | iOS and the other Apple mobile systems | refused by name | refused by name |
//!
//! A macOS kernel that publishes no boot session identifier is refused by name. Its boot time is not
//! read instead, because the kernel moves that when the clock is set, which would make one boot read
//! as two; macOS 14 and later, the releases a host runs on, publish the identifier.
//!
//! Android is Linux and reads the same two files. The Apple mobile systems are the one case where
//! the facility is not there at all: an application runs in a sandbox that cannot enumerate
//! processes, cannot read another process's start time, and cannot read the boot session
//! identifier. Every call there refuses and says so, because a host that is handed a stub is a
//! host that believes something nobody established.
//!
//! Windows gives an ordinary account no identifier for a boot, so a Windows boot identity is a pair
//! of records the kernel keeps for its boot: the boot counter it publishes in the page it shares
//! with every process, and the time it recorded when it created the System process, which it keeps
//! for as long as it runs. Neither changes while the kernel runs, and `windows_boot::value` says
//! what the pair guarantees across a restart.
//!
//! A process's creation time comes from the kernel, through `GetProcessTimes`, in the hundreds of
//! nanoseconds the kernel records it in, so two processes created under one identifier within one
//! second carry two start values. A worker of the previous build states its start in whole
//! seconds, and [`process_state`] reads such an identity the way that build did, for as long as one
//! can still be running.

use kr_protocol::identity::{BootIdentity, ProcessStartIdentity, ProcessStartSource};
// Only a platform module that produces a boot identity names where it came from here. macOS
// decides its source in `macos_boot`, and the Apple mobile systems refuse instead, so on the Apple
// targets nothing here has a source to name.
#[cfg(not(target_vendor = "apple"))]
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

/// What the operating system says about one process identifier.
///
/// Three answers, and only one of them is "gone". Each platform decides which of the three it has
/// where it reads the process, from the reading itself: a missing `/proc` entry on Linux, the
/// kernel's "no such process" on macOS, and on Windows the kernel's refusal to open an identifier
/// no process holds. A query that failed is never turned into absence afterwards. It
/// establishes nothing, and a host that read it as a process that had ended would release a session
/// identity, take over a journal or pass over a live worker while the process was still running.
#[derive(Debug)]
pub enum ProcessQuery {
    /// A process holds the identifier, and this is its start identity.
    Present(ProcessStartIdentity),
    /// The operating system answered, and no process holds the identifier.
    Gone,
    /// The operating system did not answer, or would not say when the process started, so
    /// neither of the other answers is established.
    CannotEstablish(IpcError),
}

/// Asks the operating system about one process identifier.
///
/// Every other process question in this module is answered from this one, so none of them can
/// read a failed query as a process that has gone.
#[must_use]
pub fn query_process(pid: u32) -> ProcessQuery {
    platform::query_process(pid)
}

/// Reads one process's start identity.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the process does not exist or the operating
/// system does not answer.
pub fn process_start_identity(pid: u32) -> Result<ProcessStartIdentity> {
    match query_process(pid) {
        ProcessQuery::Present(identity) => Ok(identity),
        ProcessQuery::Gone => Err(unavailable(
            "process start identity",
            format!("pid {pid} is gone"),
        )),
        ProcessQuery::CannotEstablish(error) => Err(error),
    }
}

/// Runs `work` and returns what it returned, with every process this thread read a `/proc` entry
/// of meanwhile, in the order read, for the host crates' own tests: what a test counts to know
/// that a question about one session read nothing about any other process.
#[cfg(all(feature = "testing", any(target_os = "linux", target_os = "android")))]
pub fn processes_read_during<T>(work: impl FnOnce() -> T) -> (T, Vec<u32>) {
    platform::processes_read_during(work)
}

/// Returns the processes one process is the parent of now: those it started that have not been
/// collected, and each one it adopted as the child subreaper when that one's own parent exited.
///
/// What it costs follows the one process, not the host: the kernel keeps the list with each of the
/// process's threads, and a reading is at least two passes, each of which, when it reads, lists the
/// threads twice, reads every thread's list and reads the standing of the threads from the first to
/// the first live one, usually one, and of that one again. A process that has gone is the parent of
/// nothing. A kernel that is built without those
/// lists, and a reading that failed for any other reason, is an error here rather than an empty
/// answer, so a caller never reads "no children" into it. So is a process whose threads keep
/// leaving while they are read: a pass in which the listing of them ended early, a listed thread
/// had gone, the thread that takes children began to end, one ahead of it was ending, or the threads
/// were not the same after the pass, is made again, since the children of such a thread are in a
/// list the pass may have read already or never reached.
///
/// What the kernel lists is not a promise: its list of a thread's children can skip one that was
/// there throughout when children ahead of it are collected while it is read. So a process is read
/// again until two passes agree, and a process whose threads or children keep changing is an error
/// here, not a guess. Two passes can still agree on a wrong answer when a thread of the process
/// calls `exec` while it is read, since that thread takes the identifier of the one it replaces, or
/// when the kernel gives a thread's identifier to a new thread, and nothing a pass reads tells the
/// two apart, and the next pass that reads any children misses the same ones, by the same again or
/// by a skip of the kernel's list as another child is collected.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the process cannot be read, when the kernel
/// keeps no list of children, or when its threads or children never hold still long enough to be
/// read, which includes a thread ahead of the one that takes children that stays ending.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn children_of(pid: u32) -> Result<Vec<u32>> {
    platform::children_of(pid)
}

/// Runs `work`, and `then` after each read it makes on this thread with the process read about and
/// the file, for the host crates' own tests: what a test uses to change the process tree at a
/// chosen point in a reading of it.
#[cfg(all(feature = "testing", any(target_os = "linux", target_os = "android")))]
pub fn after_each_read<T>(then: impl FnMut(u32, &str) + 'static, work: impl FnOnce() -> T) -> T {
    platform::after_each_read(then, work)
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

/// A process's identity together with the facts that tie it to a session, read from one reading.
///
/// A process identifier is a hint. A list of the processes on a terminal, in a group or below a
/// parent names identifiers, and an identifier read from such a list may belong to a different
/// process by the time its start is read. So the start and the facts that put the process in a
/// session are taken from the one reading of the process, and the caller keeps the process only
/// when those facts agree with the list it came from: a process that took an identifier after the
/// one listed under it ended does not agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lineage {
    /// The process and its start.
    pub identity: ProcessStartIdentity,
    /// The process that is its parent now.
    pub parent: u32,
    /// The process group it is in.
    pub group: u32,
    /// The session it is in, where the platform names one.
    pub session: Option<u32>,
    /// The controlling terminal it holds, if any.
    pub terminal: Option<u32>,
}

/// Reads a process's identity and lineage from one reading.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the process does not exist or the operating
/// system does not answer, and on a platform that has no process groups or terminals to name.
pub fn process_lineage(pid: u32) -> Result<Lineage> {
    platform::lineage(pid)
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
/// microseconds since the epoch and Windows counts hundreds of nanoseconds since the epoch; a
/// machine that had been running for as many ticks as this, or a clock this far past 1970, is not a
/// machine this host will meet. Reserving the value is what lets [`ended_process_identity`] name a
/// process without claiming a reading nobody took.
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
    started_from(pid, query_process(pid))
}

/// What a query about a process this host has just started says about it.
fn started_from(pid: u32, query: ProcessQuery) -> Result<ProcessStartIdentity> {
    match query {
        ProcessQuery::Present(identity) => Ok(identity),
        ProcessQuery::Gone => Ok(ended_process_identity(pid)),
        ProcessQuery::CannotEstablish(error) => Err(error),
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
    current_process(identity).into()
}

/// How hard to stop a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Ask it to end: terminate, hang up and continue, which a stopped process needs to see the
    /// other two. A platform with no such request ([`Stopped::Unsupported`]) is waited on instead.
    Terminate,
    /// End it, with no chance to refuse.
    Kill,
}

/// What stopping one recorded process came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// The signal was delivered to the process that was recorded.
    Signalled,
    /// The recorded process is not there: it has ended, or its identifier belongs to a different
    /// process now, which is left alone.
    Gone,
    /// The system refused to let this process signal that one.
    Refused(String),
    /// The recorded process could not be told apart from a stranger by this system, so it was not
    /// signalled: a system that cannot hold a process by more than its number does not get to
    /// signal by the number.
    Unsafe(String),
    /// This platform has no such request.
    Unsupported,
}

/// Stops one process that was recorded by its identifier and start, and no other.
///
/// The process is held by something other than its number for the length of the check and the
/// signal, so a number that passes to a different process between the two is never signalled:
/// Linux holds it by a process descriptor, macOS by the kernel's own version of the process
/// (which the kernel checks again as it signals) and Windows by an open handle. Where a system
/// offers none of these, the process is not signalled at all, and the answer says so.
///
/// This process is never stopped by it.
#[must_use]
pub fn stop_process(identity: &ProcessStartIdentity, stop: Stop) -> Stopped {
    if identity.pid.get() == u64::from(std::process::id()) {
        return Stopped::Refused("that is the process asking".to_owned());
    }
    platform::stop(identity, stop)
}

/// What the kernel says now about a recorded process, with the identity this build reads for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurrentProcess {
    /// The process is running, and this is its identity as this build reads it.
    Running(ProcessStartIdentity),
    /// The process is gone, or its identifier now belongs to a different process.
    Ended,
    /// The operating system did not answer, so neither answer is established.
    Unknown {
        /// Why the query failed.
        detail: String,
    },
}

impl From<CurrentProcess> for ProcessState {
    fn from(current: CurrentProcess) -> Self {
        match current {
            CurrentProcess::Running(_) => Self::Running,
            CurrentProcess::Ended => Self::Ended,
            CurrentProcess::Unknown { detail } => Self::Unknown { detail },
        }
    }
}

/// Asks the kernel about a recorded process, as [`process_state`] does, and names it as this build
/// reads it when it is running.
///
/// For an identity this build read, the name is the identity itself. For one a worker of the
/// previous build stated in whole seconds, it is the same process at the resolution this build
/// reads, which is what lets a record of it be written at that resolution.
#[must_use]
pub fn current_process(identity: &ProcessStartIdentity) -> CurrentProcess {
    // An identity the kernel never described belongs to a process that had already ended when it
    // was made. Asking about the identifier now would be asking about whoever holds it next.
    if identity.start_value.get() == START_VALUE_UNREAD {
        return CurrentProcess::Ended;
    }
    let Ok(pid) = u32::try_from(identity.pid.get()) else {
        return CurrentProcess::Ended;
    };
    current_from(identity, pid, query_process(pid))
}

/// What a query about `pid` says about the process `identity` recorded, named as this build reads
/// it.
fn current_from(identity: &ProcessStartIdentity, pid: u32, query: ProcessQuery) -> CurrentProcess {
    match query {
        // The identifier and the start value are the process that was recorded. Whether it is
        // still running is a second question on a platform that describes a process after it has
        // exited: Linux keeps the `/proc` entry of a process whose status nobody has collected,
        // Windows describes an exited process for as long as anything holds it open, and a process
        // in either state has ended. The start value this build read goes with the question,
        // because a platform that has to look again has to know whether what it is looking at is
        // still the same process.
        ProcessQuery::Present(current)
            if current.matches(identity) || named_in_whole_seconds(identity, &current) =>
        {
            match platform::liveness(pid, current.start_value.get()) {
                ProcessState::Running => CurrentProcess::Running(current),
                ProcessState::Ended => CurrentProcess::Ended,
                ProcessState::Unknown { detail } => CurrentProcess::Unknown { detail },
            }
        }
        // Another process holds the identifier now, or none does: either way the recorded one has
        // gone.
        ProcessQuery::Present(_) | ProcessQuery::Gone => CurrentProcess::Ended,
        ProcessQuery::CannotEstablish(error) => CurrentProcess::Unknown {
            detail: error.to_string(),
        },
    }
}

/// Whether `current`, as this build reads a Windows process, is the process a worker of the
/// previous build named as `recorded` in whole seconds.
///
/// A worker of the previous build keeps running across an upgrade and states its identity in whole
/// seconds, signed, and so do the records it and its controller wrote. This is how the previous
/// build read such an identity - the same identifier, and a creation time in the same second - so
/// such a worker is judged exactly as it was before the upgrade: no worse, and no better, since two
/// processes created under one identifier within one second are one identity this way.
///
/// Remove it with [`ProcessStartSource::WindowsProcessStartSeconds`], in the first release after
/// one in which every running worker states [`ProcessStartSource::WindowsProcessCreationTime`].
fn named_in_whole_seconds(recorded: &ProcessStartIdentity, current: &ProcessStartIdentity) -> bool {
    recorded.source == ProcessStartSource::WindowsProcessStartSeconds
        && current.source == ProcessStartSource::WindowsProcessCreationTime
        && recorded.pid == current.pid
        && current.start_value.get() / FILETIME_UNITS_PER_SECOND == recorded.start_value.get()
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

    /// Reads one of a process's own `/proc` files, `/proc/<pid>/<file>`.
    ///
    /// Every question this module asks about one process reads through here, so a test can see
    /// which processes a question read about.
    fn read_process_file(pid: u32, file: &str) -> std::io::Result<String> {
        let read = std::fs::read_to_string(format!("/proc/{pid}/{file}"));
        #[cfg(feature = "testing")]
        {
            PROCESS_READS.with(|reads| {
                if let Some(reads) = reads.borrow_mut().as_mut() {
                    reads.push(pid);
                }
            });
            // Taken out while it runs, so that it can read about processes itself.
            if let Some(mut then) = AFTER_READ.with(|then| then.borrow_mut().take()) {
                then(pid, file);
                AFTER_READ.with(|slot| *slot.borrow_mut() = Some(then));
            }
        }
        read
    }

    /// What a test runs after each read on this thread: the process read about, and the file.
    #[cfg(feature = "testing")]
    type AfterRead = Box<dyn FnMut(u32, &str)>;

    #[cfg(feature = "testing")]
    thread_local! {
        /// The processes this thread has read about since a test began counting, or none when
        /// no test is.
        static PROCESS_READS: std::cell::RefCell<Option<Vec<u32>>> =
            const { std::cell::RefCell::new(None) };
        /// What a test runs after each read on this thread, where one is.
        static AFTER_READ: std::cell::RefCell<Option<AfterRead>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Runs `work`, and `then` after each read it makes on this thread, with the process read
    /// about and the file.
    #[cfg(feature = "testing")]
    pub fn after_each_read<T>(
        then: impl FnMut(u32, &str) + 'static,
        work: impl FnOnce() -> T,
    ) -> T {
        AFTER_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(then)));
        let done = work();
        AFTER_READ.with(|slot| *slot.borrow_mut() = None);
        done
    }

    /// Runs `work` and returns what it returned, with every process this thread read a `/proc`
    /// entry of meanwhile, in the order read.
    #[cfg(feature = "testing")]
    pub fn processes_read_during<T>(work: impl FnOnce() -> T) -> (T, Vec<u32>) {
        PROCESS_READS.with(|reads| *reads.borrow_mut() = Some(Vec::new()));
        let done = work();
        let read = PROCESS_READS.with(|reads| reads.borrow_mut().take().unwrap_or_default());
        (done, read)
    }

    /// Where each field of `/proc/<pid>/stat` sits *after* the command name.
    ///
    /// The line begins `pid (comm) state ...` and the command name can contain spaces and brackets,
    /// so the fields are counted from after its closing bracket. Counting from there, index 0 is
    /// the state, which is field 3 of the line: a field's index here is its number minus three.
    const STAT_PROCESS_GROUP: usize = 2;
    /// The controlling terminal's device number, field 7 of the line.
    const STAT_TERMINAL: usize = 4;
    /// The parent's identifier, field 4 of the line.
    const STAT_PARENT: usize = 1;
    /// The session's identifier, field 6 of the line.
    const STAT_SESSION: usize = 3;

    /// Where this platform's start value comes from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource = ProcessStartSource::LinuxProcStat;

    /// The number of threads the thread group still has, field 20 of the line.
    const STAT_THREADS: usize = 17;
    /// The kernel's flags of a thread, field 9 of the line.
    const STAT_FLAGS: usize = 6;
    /// The flag a thread carries from the moment it begins to end, which is before it hands its
    /// children on, and from when the kernel hands it no more.
    const FLAG_ENDING: u32 = 0x4;

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
        match read_process_file(pid, "stat") {
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

    /// How many passes over a process's threads and children are made while they keep changing
    /// under the reading, before it is given up as one that does not hold still: threads that come
    /// and go, or children that do.
    const PASSES: usize = 100;

    /// The most bytes one thread's entry takes in a `getdents64` buffer: a header of 19 bytes, the
    /// thread identifier's digits (seven at most) and their end, rounded up to eight.
    const ENTRY_BYTES: usize = 32;

    /// How many threads beyond the process's count a buffer has room for, which is how many may
    /// start between the count being read and the listing.
    const ROOM_FOR_NEW_THREADS: usize = 64;

    /// The most entries a buffer for a listing is grown to, which no process's threads reach.
    const MOST_ENTRIES: usize = 1 << 22;

    /// What one listing of a process's threads came to.
    pub(super) enum ThreadListing {
        /// The process has gone.
        Gone,
        /// The process's threads: every one that stayed while the listing was made, and any that
        /// started meanwhile.
        Whole(Vec<u32>),
        /// A listing that may have ended before a thread that stayed.
        Partial,
    }

    /// Lists the threads of a process once, from one `getdents64` call.
    ///
    /// The kernel makes a listing one thread at a time, and ends it at the first thread that has
    /// gone by the time it moves on, so a listing made while threads exit can end before a thread
    /// that is still running; the children of that thread are in no other thread's list. What the
    /// call returns is then a prefix of the threads in the order they were made. A further call does
    /// not carry on from it: it finds its place again by counting threads from the first, and that
    /// count lands after a thread that stayed when the ones ahead of it have gone, and takes in
    /// threads made since. So the whole listing is one call's, and a buffer that cannot take it in
    /// one call is made larger and the listing begun again, never read on.
    ///
    /// The process's thread count, read just before the listing, tells a prefix: a thread that
    /// stayed and is missing from one has every listed thread made before it, so each of them was
    /// there when the count was read and the listing is shorter than the count. A listing as long as
    /// the count holds every thread that stayed. `entries` is how many entries the first buffer
    /// has room for, where a test sets it, and otherwise the count and room for new threads.
    pub(super) fn list_threads(pid: u32, entries: Option<usize>) -> Result<ThreadListing> {
        let task = format!("/proc/{pid}/task");
        let stat = match read_process_file(pid, "stat") {
            Ok(stat) => stat,
            // A process that has gone is the parent of nothing: its children went to whoever
            // adopts them when it exited.
            Err(error) if gone(&error) => return Ok(ThreadListing::Gone),
            Err(error) => {
                return Err(unavailable(
                    "children of a process",
                    format!("/proc/{pid}/stat: {error}"),
                ));
            }
        };
        let Some(count) = stat_field(&stat, STAT_THREADS) else {
            return Err(unavailable(
                "children of a process",
                format!("/proc/{pid}/stat has no thread count"),
            ));
        };
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        // Two more for `.` and `..`.
        let mut room = entries.unwrap_or_else(|| count.saturating_add(2 + ROOM_FOR_NEW_THREADS));
        loop {
            if room > MOST_ENTRIES {
                return Err(unavailable(
                    "children of a process",
                    format!("{task} has more threads than a listing is made for"),
                ));
            }
            let directory = match std::fs::File::open(&task) {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(ThreadListing::Gone);
                }
                Err(error) => {
                    return Err(unavailable(
                        "children of a process",
                        format!("{task}: {error}"),
                    ));
                }
            };
            let mut buffer = vec![std::mem::MaybeUninit::<u8>::uninit(); room * ENTRY_BYTES];
            // The reader trims its buffer to the alignment of an entry.
            let capacity = buffer.len() - 8;
            let mut reader = rustix::fs::RawDir::new(&directory, &mut buffer);
            let mut threads = Vec::new();
            let mut used = 0_usize;
            let mut called = false;
            // The first fill only: the buffer is read to its end and never filled again.
            while !called || !reader.is_buffer_empty() {
                called = true;
                match reader.next() {
                    None => break,
                    Some(Err(error)) if error == rustix::io::Errno::NOENT => {
                        return Ok(ThreadListing::Gone);
                    }
                    Some(Err(error)) => {
                        return Err(unavailable(
                            "children of a process",
                            format!("{task}: {}", std::io::Error::from(error)),
                        ));
                    }
                    Some(Ok(entry)) => {
                        let name = entry.file_name().to_bytes();
                        used += (19 + name.len() + 1).next_multiple_of(8);
                        if let Some(tid) = std::str::from_utf8(name)
                            .ok()
                            .and_then(|name| name.parse::<u32>().ok())
                        {
                            threads.push(tid);
                        }
                    }
                }
            }
            // A buffer with no room for one more entry may have ended the call, and a call that
            // is carried on may skip a thread that stayed: take a larger one and begin again.
            if capacity.saturating_sub(used) < ENTRY_BYTES {
                room = room.saturating_mul(2);
                continue;
            }
            return Ok(if threads.len() >= count {
                ThreadListing::Whole(threads)
            } else {
                ThreadListing::Partial
            });
        }
    }

    /// What one pass over a process's threads and their children came to.
    pub(super) enum Pass {
        /// The process has gone.
        Gone,
        /// Every child its threads held.
        Read(Vec<u32>),
        /// A thread left or began to, or the listing of them was short, so the pass says nothing.
        Changed,
    }

    /// Where one thread of a process stands, as far as the handing on of children goes.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub(super) enum ThreadLife {
        /// The kernel hands the children of a thread that ends to it, or may.
        Live,
        /// It is ending, and its own children are being handed on.
        Leaving,
        /// It has ended and handed its children on, and the kernel keeps it for now: the process's
        /// first thread until the rest has gone, and a thread whose end a tracer has yet to collect.
        Ended,
        /// The kernel has taken it away, or is taking it.
        Gone,
    }

    /// Reads where a thread stands from its own `stat` line: the state character, and whether the
    /// flags carry the one a thread has from the moment it begins to end.
    pub(super) fn life_from_stat(text: &str) -> Option<ThreadLife> {
        let state = state_character(text)?;
        let flags = stat_field(text, STAT_FLAGS)?;
        Some(match state {
            'Z' => ThreadLife::Ended,
            'X' | 'x' => ThreadLife::Gone,
            _ if flags & FLAG_ENDING != 0 => ThreadLife::Leaving,
            _ => ThreadLife::Live,
        })
    }

    /// Reads where a thread stands from its own `stat`.
    fn thread_life(pid: u32, tid: u32) -> Result<ThreadLife> {
        match read_process_file(pid, &format!("task/{tid}/stat")) {
            Ok(text) => life_from_stat(&text).ok_or_else(|| {
                unavailable(
                    "children of a process",
                    format!("/proc/{pid}/task/{tid}/stat has no state or no flags"),
                )
            }),
            Err(error) if gone(&error) => Ok(ThreadLife::Gone),
            Err(error) => Err(unavailable(
                "children of a process",
                format!("/proc/{pid}/task/{tid}/stat: {error}"),
            )),
        }
    }

    /// The thread the kernel hands the children of an ending thread to.
    #[derive(Debug, PartialEq)]
    pub(super) enum Heir {
        /// The first live thread of the process in the order the kernel lists them, which is the
        /// order they were made in.
        Thread(u32),
        /// Every listed thread has ended, so none that is listed takes children: a thread made
        /// after the listing may.
        Nobody,
        /// A thread is ending or gone, ahead of the first live one or with no live one after it, so
        /// the children it is handing on are in no list that can be relied on.
        Unsettled,
    }

    /// Finds the heir among the threads in the order the kernel lists them, reading the standing of
    /// one thread at a time and no more than it takes: a thread that has ended and handed its
    /// children on is passed over, and the first live one is the heir. A thread that is ending or
    /// gone before one is found leaves the pass [`Heir::Unsettled`]; threads that have all ended
    /// leave [`Heir::Nobody`].
    pub(super) fn heir_among(
        threads: &[u32],
        mut life: impl FnMut(u32) -> Result<ThreadLife>,
    ) -> Result<Heir> {
        for &tid in threads {
            match life(tid)? {
                ThreadLife::Live => return Ok(Heir::Thread(tid)),
                ThreadLife::Ended => {}
                ThreadLife::Leaving | ThreadLife::Gone => return Ok(Heir::Unsettled),
            }
        }
        Ok(Heir::Nobody)
    }

    /// Whether a read failed because what it read about has gone: its entry is not there, or the
    /// task behind it is not.
    fn gone(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::NotFound
            || rustix::io::Errno::from_io_error(error) == Some(rustix::io::Errno::SRCH)
    }

    /// Whether this kernel keeps a list of children for each thread: whether a thread that is
    /// certainly there, this one, has one. A thread of another process that has no list may be one
    /// that is going, which is not the kernel's doing.
    fn kernel_keeps_children_lists() -> bool {
        std::fs::metadata("/proc/thread-self/children").is_ok()
    }

    /// Reads the children of every thread of a process once.
    ///
    /// A thread that ends hands its children to the first thread in the order the kernel lists them
    /// that is not ending, which is the oldest live one and the only one that takes any, so a child
    /// only ever moves to that thread, the heir. The pass reads the threads youngest first, so the
    /// heir is the last live thread it reads: a child that moves to it before it is read is in its
    /// list, and one that moves after the thread it left was read was in that thread's list, which
    /// the pass has. What can still hide a child is the heir itself ending, which hands its children
    /// to a younger thread already read: its standing is read before the pass and again after it,
    /// and a pass in which it began to end is made again. A thread ahead of the heir that is ending
    /// or gone when its standing is read is handing children on, and the pass is made again. The
    /// threads are listed again after the pass, and a pass in which they are not the same is made
    /// again: a heir that had ended, and been kept, before its standing was read leaves nobody to
    /// look at, and the thread made after the listing that took its children is in no list the pass
    /// read, as is one that took the first thread's identifier by `exec`. Nothing else is read
    /// about a thread. A pass that read lists the threads twice, reads every thread's list, and
    /// reads the standing of the threads from the first to the heir, usually one, and the heir's
    /// again, which a pass with no heir does not: a pass that is made again may stop short of all
    /// of it.
    pub(super) fn children_in_one_pass(pid: u32) -> Result<Pass> {
        pass_over(&mut Process(pid))
    }

    /// What a pass asks the kernel about one process, so that a test can answer from a model of the
    /// kernel's handing on of children and run every order the model's events can fall in.
    pub(super) trait ThreadFacts {
        /// The process's threads, listed once.
        fn list(&mut self) -> Result<ThreadListing>;
        /// Where one thread stands.
        fn life(&mut self, tid: u32) -> Result<ThreadLife>;
        /// One thread's list of children, or none when its list is gone and the kernel does keep
        /// one for a thread that is there.
        fn children(&mut self, tid: u32) -> Result<Option<Vec<u32>>>;
    }

    /// The kernel's own answers about one process, from its `/proc` entries.
    struct Process(u32);

    impl ThreadFacts for Process {
        fn list(&mut self) -> Result<ThreadListing> {
            list_threads(self.0, None)
        }

        fn life(&mut self, tid: u32) -> Result<ThreadLife> {
            thread_life(self.0, tid)
        }

        fn children(&mut self, tid: u32) -> Result<Option<Vec<u32>>> {
            let pid = self.0;
            match read_process_file(pid, &format!("task/{tid}/children")) {
                Ok(list) => Ok(Some(
                    list.split_whitespace()
                        .filter_map(|child| child.parse::<u32>().ok())
                        .collect(),
                )),
                // A thread whose list is not there: one that is going, which another pass sees as
                // changed, or a kernel that keeps no lists, which no pass will change.
                Err(error) if gone(&error) && kernel_keeps_children_lists() => Ok(None),
                Err(error) => Err(unavailable(
                    "children of a process",
                    format!("/proc/{pid}/task/{tid}/children: {error}"),
                )),
            }
        }
    }

    /// One pass, over whatever answers the process's facts.
    pub(super) fn pass_over(process: &mut impl ThreadFacts) -> Result<Pass> {
        let threads = match process.list()? {
            ThreadListing::Gone => return Ok(Pass::Gone),
            ThreadListing::Whole(threads) => threads,
            ThreadListing::Partial => return Ok(Pass::Changed),
        };
        let heir = match heir_among(&threads, |tid| process.life(tid))? {
            Heir::Unsettled => return Ok(Pass::Changed),
            heir => heir,
        };
        let mut children = Vec::new();
        for &tid in threads.iter().rev() {
            match process.children(tid)? {
                Some(list) => children.extend(list),
                None => return Ok(Pass::Changed),
            }
        }
        if let Heir::Thread(heir) = heir
            && process.life(heir)? != ThreadLife::Live
        {
            return Ok(Pass::Changed);
        }
        match process.list()? {
            ThreadListing::Gone => return Ok(Pass::Gone),
            ThreadListing::Whole(mut later) => {
                let mut first = threads;
                first.sort_unstable();
                later.sort_unstable();
                if first != later {
                    return Ok(Pass::Changed);
                }
            }
            ThreadListing::Partial => return Ok(Pass::Changed),
        }
        children.sort_unstable();
        children.dedup();
        Ok(Pass::Read(children))
    }

    pub(super) fn children_of(pid: u32) -> Result<Vec<u32>> {
        // A list is taken once two passes read the same children, the last two that read any.
        // A pass in which the kernel's list of a thread's children skipped a child printed one that
        // was collected while it read, and no later pass prints that identifier again, so such a
        // pass never agrees with the next: two passes that agree hold every child that was there
        // throughout both. What is not closed is a process whose passes go wrong the same way
        // twice: a thread that calls `exec` takes the identifier of the one it replaces, which no
        // comparison of identifiers sees, so a pass that read the replaced thread's list as empty
        // can be followed by another that does the same by another `exec`, or by a skip as
        // another child is collected; the kernel makes no promise about a list it prints while the
        // process runs, no count of passes or time bounds that, and nothing short of freezing the
        // process closes it.
        let mut earlier: Option<Vec<u32>> = None;
        for _ in 0..PASSES {
            match children_in_one_pass(pid)? {
                Pass::Gone => return Ok(Vec::new()),
                Pass::Read(children) => {
                    if earlier.as_ref() == Some(&children) {
                        return Ok(children);
                    }
                    earlier = Some(children);
                }
                Pass::Changed => std::thread::yield_now(),
            }
        }
        // Not an empty answer: a caller that reads "no children" into it would take a process that
        // has some for one that has none.
        Err(unavailable(
            "children of a process",
            format!("/proc/{pid}/task or its children kept changing while they were read"),
        ))
    }

    /// One reading of one `/proc/<pid>/stat` line: the start and the facts that tie the process to
    /// its parent, group, session and terminal are the same process's.
    pub(super) fn lineage(pid: u32) -> Result<super::Lineage> {
        let text = read_process_file(pid, "stat").map_err(|error| {
            unavailable("process lineage", format!("/proc/{pid}/stat: {error}"))
        })?;
        lineage_of(pid, &text)
    }

    /// Reads a lineage from a `/proc/<pid>/stat` line.
    pub(super) fn lineage_of(pid: u32, text: &str) -> Result<super::Lineage> {
        let incomplete = |what: &str| {
            unavailable(
                "process lineage",
                format!("/proc/{pid}/stat: field {what} is missing"),
            )
        };
        let start = parse_start_ticks(text).ok_or_else(|| incomplete("22"))?;
        Ok(super::Lineage {
            identity: ProcessStartIdentity::new(
                u64::from(pid),
                ProcessStartSource::LinuxProcStat,
                start,
            ),
            parent: stat_field(text, STAT_PARENT).ok_or_else(|| incomplete("4"))?,
            group: stat_field(text, STAT_PROCESS_GROUP).ok_or_else(|| incomplete("5"))?,
            session: Some(stat_field(text, STAT_SESSION).ok_or_else(|| incomplete("6"))?),
            terminal: stat_field(text, STAT_TERMINAL).filter(|terminal| *terminal != 0),
        })
    }

    /// Signals the process holding `identity`, through a process descriptor.
    ///
    /// The identity is read before the descriptor is opened and again after, and both readings
    /// must be the recorded one: a process that held the number through both is the one the
    /// descriptor refers to, because the descriptor was opened between them. A kernel that gives
    /// no descriptor (before 5.3, or a seccomp filter) gets no signal by number.
    pub(super) fn stop(identity: &ProcessStartIdentity, stop: super::Stop) -> super::Stopped {
        use rustix::io::Errno;
        use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

        let Some(raw) = u32::try_from(identity.pid.get()).ok() else {
            return super::Stopped::Gone;
        };
        let Some(pid) = i32::try_from(raw).ok().and_then(Pid::from_raw) else {
            return super::Stopped::Gone;
        };
        let held = || match super::query_process(raw) {
            super::ProcessQuery::Present(now) if now.start_value == identity.start_value => Ok(()),
            super::ProcessQuery::Present(_) | super::ProcessQuery::Gone => {
                Err(super::Stopped::Gone)
            }
            super::ProcessQuery::CannotEstablish(error) => {
                Err(super::Stopped::Unsafe(error.to_string()))
            }
        };
        if let Err(answer) = held() {
            return answer;
        }
        let descriptor = match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(descriptor) => descriptor,
            Err(Errno::SRCH) => return super::Stopped::Gone,
            Err(error) => {
                return super::Stopped::Unsafe(format!(
                    "this kernel gave no process descriptor ({error}), so the process is not \
                     signalled by its number"
                ));
            }
        };
        if let Err(answer) = held() {
            return answer;
        }
        let signals: &[Signal] = match stop {
            super::Stop::Terminate => &[Signal::TERM, Signal::HUP, Signal::CONT],
            super::Stop::Kill => &[Signal::KILL],
        };
        for (index, signal) in signals.iter().enumerate() {
            match pidfd_send_signal(&descriptor, *signal) {
                Ok(()) => {}
                Err(Errno::SRCH) if index == 0 => return super::Stopped::Gone,
                // It ended between two of the signals, which is the outcome asked for.
                Err(Errno::SRCH) => break,
                Err(error) => return super::Stopped::Refused(error.to_string()),
            }
        }
        super::Stopped::Signalled
    }

    pub(super) fn controlling_terminal(pid: u32) -> Result<Option<u32>> {
        let text = read_process_file(pid, "stat").map_err(|error| {
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
            let Ok(text) = read_process_file(pid, "stat") else {
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
            let Ok(line) = read_process_file(pid, "stat") else {
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

    pub(super) fn query_process(pid: u32) -> super::ProcessQuery {
        let path = format!("/proc/{pid}/stat");
        let text = match read_process_file(pid, "stat") {
            Ok(text) => text,
            // The only failure that proves absence on Linux is a missing /proc entry. A permission,
            // a descriptor limit or an entry that vanished part way through a read proves nothing.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return super::ProcessQuery::Gone;
            }
            Err(error) => {
                return super::ProcessQuery::CannotEstablish(unavailable(
                    "process start identity",
                    format!("{path}: {error}"),
                ));
            }
        };
        match parse_start_ticks(&text) {
            Some(start_ticks) => super::ProcessQuery::Present(ProcessStartIdentity::new(
                u64::from(pid),
                ProcessStartSource::LinuxProcStat,
                start_ticks,
            )),
            None => super::ProcessQuery::CannotEstablish(unavailable(
                "process start identity",
                format!("{path}: field 22 is missing"),
            )),
        }
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

    /// Signals the process holding `identity` through the kernel's version of it.
    ///
    /// One reading gives the start value and the process's version together, and the signal is
    /// sent against that version, which the kernel checks again as it signals: a number that
    /// passes to a different process, or a process that runs a new program, has a different
    /// version and is refused with no such process rather than signalled. A system that does not
    /// provide the call gets no signal by number.
    pub(super) fn stop(identity: &ProcessStartIdentity, stop: super::Stop) -> super::Stopped {
        use super::macos_signal::{Signalled, read_instance, signal_instance};

        let Ok(pid) = u32::try_from(identity.pid.get()) else {
            return super::Stopped::Gone;
        };
        let instance = match read_instance(pid) {
            Ok(Some(instance)) => instance,
            Ok(None) => return super::Stopped::Gone,
            Err(detail) => return super::Stopped::Unsafe(detail),
        };
        if instance.start_value != identity.start_value.get() {
            return super::Stopped::Gone;
        }
        let signals: &[i32] = match stop {
            super::Stop::Terminate => &[libc::SIGTERM, libc::SIGHUP, libc::SIGCONT],
            super::Stop::Kill => &[libc::SIGKILL],
        };
        let mut instance = instance;
        for (index, signal) in signals.iter().enumerate() {
            // A process that runs a new program between the reading and the signal has the same
            // identifier and start and a new version, and the kernel answers that no process has
            // the old one. So an answer of "none" is checked: the same process again, under its
            // new version, is signalled under that; anything else has ended.
            let mut attempts = 0;
            loop {
                match signal_instance(&instance, *signal) {
                    Signalled::Delivered => break,
                    Signalled::NoSuchProcess => {
                        attempts += 1;
                        match read_instance(instance.pid()) {
                            Ok(Some(now))
                                if now.start_value == identity.start_value.get()
                                    && attempts < 4 =>
                            {
                                instance = now;
                            }
                            Ok(Some(_) | None) if index == 0 => return super::Stopped::Gone,
                            Ok(Some(_) | None) => return super::Stopped::Signalled,
                            Err(detail) => return super::Stopped::Unsafe(detail),
                        }
                    }
                    Signalled::Refused(detail) => return super::Stopped::Refused(detail),
                    Signalled::Unavailable(detail) => return super::Stopped::Unsafe(detail),
                }
            }
        }
        super::Stopped::Signalled
    }

    /// One `proc_pidinfo` reading: the start and the facts that tie the process to its parent,
    /// group and terminal are the same process's. macOS names no session in it.
    pub(super) fn lineage(pid: u32) -> Result<super::Lineage> {
        let raw = i32::try_from(pid).map_err(|_| {
            unavailable(
                "process lineage",
                format!("{pid} is not a process identifier"),
            )
        })?;
        let info: BSDInfo = pidinfo(raw, 0)
            .map_err(|error| unavailable("process lineage", format!("pid {pid}: {error}")))?;
        let start = info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec);
        Ok(super::Lineage {
            identity: ProcessStartIdentity::new(
                u64::from(info.pbi_pid),
                ProcessStartSource::MacosProcBsdInfo,
                start,
            ),
            parent: info.pbi_ppid,
            group: info.pbi_pgid,
            session: None,
            terminal: (info.e_tdev != u32::MAX).then_some(info.e_tdev),
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

    use super::{BootIdentity, ProcessStartIdentity, ProcessStartSource, Result, unavailable};

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        super::macos_boot::boot_identity(&Sysctl)
    }

    /// This kernel, read through `sysctl`.
    struct Sysctl;

    impl super::macos_boot::Kernel for Sysctl {
        fn read(&self, control: &str) -> std::result::Result<Vec<u8>, String> {
            let value = sysctl::Ctl::new(control)
                .and_then(|reading| reading.value())
                .map_err(|error| format!("{control}: {error}"))?;
            match value {
                sysctl::CtlValue::String(text) => Ok(text.into_bytes()),
                sysctl::CtlValue::Struct(bytes) => Ok(bytes),
                _ => Err(format!("{control} holds neither text nor a structure")),
            }
        }
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

    pub(super) fn query_process(pid: u32) -> super::ProcessQuery {
        // The kernel's process identifiers are signed; nothing can hold one past their range.
        let Ok(pid) = i32::try_from(pid) else {
            return super::ProcessQuery::Gone;
        };
        let info: BSDInfo = match pidinfo(pid, 0) {
            Ok(info) => info,
            // `proc_pidinfo` answers a process that is not there with `ESRCH`, and so it answers a
            // process that has exited: this platform stops describing it at once, before its
            // status has been collected. Every other failure leaves the question open.
            Err(message)
                if error_number(&message) == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
            {
                return super::ProcessQuery::Gone;
            }
            Err(message) => {
                return super::ProcessQuery::CannotEstablish(unavailable(
                    "process start identity",
                    format!("pid {pid}: {message}"),
                ));
            }
        };
        // Microseconds since the epoch, exactly as the kernel recorded them at execution.
        let start = info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec);
        super::ProcessQuery::Present(ProcessStartIdentity::new(
            u64::from(info.pbi_pid),
            ProcessStartSource::MacosProcBsdInfo,
            start,
        ))
    }

    /// Returns the error number a `libproc` failure carries.
    ///
    /// `libproc` reports a failed call as text, `return code = …, errno = …, message = '…'`, read
    /// from the thread's error number at the failure. The number is what is compared, rather than
    /// the message, so a reading is never taken for absence because of how a message is worded.
    pub(super) fn error_number(message: &str) -> Option<i32> {
        let (_, after) = message.split_once("errno = ")?;
        let digits = after
            .find(|character: char| !character.is_ascii_digit())
            .map_or(after, |end| &after[..end]);
        digits.parse().ok()
    }
}

/// The one place on macOS that leaves safe Rust to signal a process by its version.
///
/// The crate denies unsafe code and relaxes the rule here, as for the Windows modules below: the
/// kernel's reading that returns a process's start and its version together, and the call that
/// signals a process only while it still has that version, have no safe interface. The layouts
/// are the kernel's own (`proc_bsdinfowithuniqid` and `audit_token_t`); neither is in the public
/// headers' structures, so their sizes are checked below against what the kernel returns.
#[cfg(target_os = "macos")]
mod macos_signal {
    #![expect(
        unsafe_code,
        reason = "the kernel's reading of a process's version and the call that signals by it have \
                  no safe interface"
    )]

    use std::sync::OnceLock;

    use libproc::bsd_info::BSDInfo;

    /// The flavour of `proc_pidinfo` that returns `proc_bsdinfo` and `proc_uniqidentifierinfo`
    /// from one lookup of the process.
    const PROC_PIDT_BSDINFOWITHUNIQID: libc::c_int = 18;

    /// The kernel's `proc_uniqidentifierinfo`.
    #[repr(C)]
    struct UniqueIdentifier {
        uuid: [u8; 16],
        unique_id: u64,
        parent_unique_id: u64,
        /// The process's version: a counter that moves when the process is created and again each
        /// time it runs a new program.
        version: i32,
        reserved_2: i32,
        reserved_3: u64,
        reserved_4: u64,
    }

    /// The kernel's `proc_bsdinfowithuniqid`.
    #[repr(C)]
    struct BsdInfoWithUniqueId {
        bsd: BSDInfo,
        unique: UniqueIdentifier,
    }

    const _: () = assert!(size_of::<BsdInfoWithUniqueId>() == 192);

    /// The kernel's `audit_token_t`: eight words, of which the signal call reads the process
    /// identifier and version and the user and group identifiers.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuditToken {
        value: [u32; 8],
    }

    /// One process as the kernel described it in one reading.
    pub(super) struct Instance {
        pid: u32,
        /// Microseconds since the epoch at which it started.
        pub(super) start_value: u64,
        version: u32,
        uid: u32,
        gid: u32,
        real_uid: u32,
        real_gid: u32,
    }

    impl Instance {
        /// The identifier it was read under.
        pub(super) const fn pid(&self) -> u32 {
            self.pid
        }
    }

    /// What signalling an instance came to.
    pub(super) enum Signalled {
        /// The kernel delivered it.
        Delivered,
        /// No process has that identifier and version.
        NoSuchProcess,
        /// The kernel would not let this process signal that one.
        Refused(String),
        /// The call is not there, or failed in a way that says nothing about the process.
        Unavailable(String),
    }

    /// Reads one process, or none if the kernel has none under the identifier.
    pub(super) fn read_instance(pid: u32) -> Result<Option<Instance>, String> {
        let Ok(raw) = libc::c_int::try_from(pid) else {
            return Ok(None);
        };
        let mut buffer = std::mem::MaybeUninit::<BsdInfoWithUniqueId>::zeroed();
        // SAFETY: `buffer` is a live, writable allocation of exactly the size passed, and the
        // kernel writes at most that many bytes into it and keeps no pointer to it.
        let written = unsafe {
            libc::proc_pidinfo(
                raw,
                PROC_PIDT_BSDINFOWITHUNIQID,
                0,
                buffer.as_mut_ptr().cast(),
                size_of::<BsdInfoWithUniqueId>() as libc::c_int,
            )
        };
        if usize::try_from(written).ok() != Some(size_of::<BsdInfoWithUniqueId>()) {
            let error = std::io::Error::last_os_error();
            return if written <= 0 && error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(format!(
                    "pid {pid}: the kernel's reading of the process failed: {error}"
                ))
            };
        }
        // SAFETY: the kernel wrote the whole structure, which has no invalid bit patterns.
        let read = unsafe { buffer.assume_init() };
        Ok(Some(Instance {
            pid,
            start_value: read
                .bsd
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(read.bsd.pbi_start_tvusec),
            version: read.unique.version.cast_unsigned(),
            uid: read.bsd.pbi_uid,
            gid: read.bsd.pbi_gid,
            real_uid: read.bsd.pbi_ruid,
            real_gid: read.bsd.pbi_rgid,
        }))
    }

    /// `proc_signal_with_audittoken`, looked up when first needed so a system without it links.
    fn signal_call() -> Option<unsafe extern "C" fn(*mut AuditToken, libc::c_int) -> libc::c_int> {
        static CALL: OnceLock<Option<usize>> = OnceLock::new();
        let address = CALL.get_or_init(|| {
            // SAFETY: the name is a NUL-terminated string that outlives the call.
            let found =
                unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
            (!found.is_null()).then_some(found as usize)
        });
        // SAFETY: the symbol is the system's `proc_signal_with_audittoken`, declared in
        // `libproc.h` as `int (audit_token_t *, int)`.
        address.map(|address| unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(*mut AuditToken, libc::c_int) -> libc::c_int,
            >(address)
        })
    }

    /// Signals `instance` only if the kernel still has a process of that identifier and version.
    pub(super) fn signal_instance(instance: &Instance, signal: libc::c_int) -> Signalled {
        let Some(call) = signal_call() else {
            return Signalled::Unavailable(
                "this system has no signal by a process's version, so the process is not \
                 signalled by its number"
                    .to_owned(),
            );
        };
        let mut token = AuditToken { value: [0; 8] };
        token.value[1] = instance.uid;
        token.value[2] = instance.gid;
        token.value[3] = instance.real_uid;
        token.value[4] = instance.real_gid;
        token.value[5] = instance.pid;
        token.value[7] = instance.version;
        // SAFETY: `token` is a live, writable token and the call reads it and nothing else.
        let result = unsafe { call(&raw mut token, signal) };
        if result == 0 {
            return Signalled::Delivered;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Signalled::NoSuchProcess,
            Some(libc::EPERM | libc::EACCES) => Signalled::Refused(error.to_string()),
            _ => Signalled::Unavailable(format!("the signal call failed: {error}")),
        }
    }
}

/// The macOS boot identity, decided from what the kernel says.
///
/// Apart from the platform module, so that a test can stand in for the kernel: a kernel that
/// publishes no boot session identifier, and a clock that is set while the host runs, are not
/// things a test can arrange on the machine it runs on.
#[cfg(any(target_os = "macos", test))]
mod macos_boot {
    use kr_protocol::identity::{BootIdentity, BootIdentitySource};

    use super::{Result, unavailable};

    /// The control that holds the kernel's identifier for its boot.
    pub(super) const BOOT_SESSION_CONTROL: &str = "kern.bootsessionuuid";

    /// The control that holds the kernel's release, such as `23.6.0`.
    const RELEASE_CONTROL: &str = "kern.osrelease";

    /// A macOS kernel's controls.
    pub(super) trait Kernel {
        /// What a control holds, as bytes: a text control's text, and a structure as the kernel
        /// lays it out. Or why it could not be read, a control the kernel does not have among the
        /// reasons.
        fn read(&self, control: &str) -> std::result::Result<Vec<u8>, String>;
    }

    /// The text a control holds, trimmed, when it holds some.
    fn text(kernel: &impl Kernel, control: &str) -> Option<String> {
        let text = String::from_utf8(kernel.read(control).ok()?).ok()?;
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_owned())
    }

    /// Reads the identity of the kernel's current boot: the boot session identifier it publishes.
    ///
    /// A kernel that publishes none is refused, by its release and by what the host needs. Its
    /// boot time is not taken instead: the kernel moves that when the clock is set, so a host
    /// running across a clock set would read one boot as two and take its own sessions for those
    /// of an earlier boot. Every kernel of the macOS releases the host runs on, macOS 14 and
    /// later, publishes the identifier.
    pub(super) fn boot_identity(kernel: &impl Kernel) -> Result<BootIdentity> {
        if let Some(value) = text(kernel, BOOT_SESSION_CONTROL) {
            return Ok(BootIdentity {
                source: BootIdentitySource::MacosBootSessionUuid,
                value: kr_protocol::scalars::Bytes::new(value.into_bytes()),
            });
        }
        let named = text(kernel, RELEASE_CONTROL).map_or_else(
            || "this kernel, which does not say its release,".to_owned(),
            |release| format!("this kernel, Darwin {release},"),
        );
        Err(unavailable(
            "boot identity",
            format!(
                "{named} publishes no boot session identifier ({BOOT_SESSION_CONTROL}), which the \
                 host needs to tell one boot from another; macOS 14 and later publish one"
            ),
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
    use super::{BootIdentity, ProcessStartSource, Result, unavailable};

    /// What every refusal in this module says, after the name of what was asked for.
    const SANDBOXED: &str = "this Apple system sandboxes an application away from process and boot identity; there is \
         no host on this device to identify";

    pub(super) fn boot_identity() -> Result<BootIdentity> {
        Err(unavailable("boot identity", SANDBOXED))
    }

    /// Establishes nothing, and never answers "gone": answering it would turn "this system will not
    /// tell me" into "the process has ended", which is the one conversion section 9 forbids.
    pub(super) fn query_process(pid: u32) -> super::ProcessQuery {
        super::ProcessQuery::CannotEstablish(unavailable(
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

    pub(super) fn lineage(pid: u32) -> Result<super::Lineage> {
        Err(unavailable(
            "process lineage",
            format!("pid {pid}: {SANDBOXED}"),
        ))
    }

    pub(super) fn stop(
        _identity: &kr_protocol::identity::ProcessStartIdentity,
        _stop: super::Stop,
    ) -> super::Stopped {
        super::Stopped::Unsafe(SANDBOXED.to_owned())
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
}

#[cfg(windows)]
mod platform {
    use super::{
        BootIdentity, BootIdentitySource, ProcessQuery, ProcessStartSource, ProcessState, Result,
        WindowsReading, boot_records, process_times, unavailable, windows_boot,
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

    pub(super) fn lineage(pid: u32) -> Result<super::Lineage> {
        // A Windows process is tied to a session by its job object, which is read through the
        // process's own handle by the caller that owns the job.
        Err(unavailable(
            "process lineage",
            format!("pid {pid}: a Windows process belongs to a session by its job, not by a group"),
        ))
    }

    /// Reads the kernel's boot counter and its System process's creation time, the pair
    /// `windows_boot::value` makes this boot's identity of, afresh on every call.
    pub(super) fn boot_identity() -> Result<BootIdentity> {
        let list =
            windows_boot::read_process_list(boot_records::query_process_list).map_err(|why| {
                unavailable("boot identity", format!("the kernel's process list: {why}"))
            })?;
        let created = windows_boot::system_process_created(list.bytes(), list.base())?;
        let value = windows_boot::value(boot_records::boot_count(), created);
        Ok(BootIdentity {
            source: BootIdentitySource::BootTime,
            value: kr_protocol::scalars::Bytes::new(value.to_vec()),
        })
    }

    /// Where this platform's start value comes from.
    pub(super) const START_IDENTITY_SOURCE: ProcessStartSource = super::WINDOWS_START_SOURCE;

    /// Returns whether a process whose identity still matches is running.
    ///
    /// The kernel keeps describing a process that has exited for as long as anything holds it
    /// open, and its identifier stays with it until then, so a reading that matched does not say
    /// the process is still running. It is opened again, this time with the right to wait on it as
    /// well, and the one handle answers both halves: that it is still the process that was
    /// recorded, which a process that ended and was replaced between the two openings is not, and
    /// whether it has exited. A process this account may ask when it started but may not wait on is
    /// one whose exit nothing here can establish, and the answer says so rather than guessing.
    pub(super) fn liveness(pid: u32, start_value: u64) -> ProcessState {
        let (reading, process) = look(pid, process_times::Rights::QueryAndWait);
        match super::windows_answer(pid, reading, process_times::now()) {
            ProcessQuery::Present(current) if current.start_value.get() == start_value => {
                match process.map(|process| process.has_exited()) {
                    Some(Ok(false)) => ProcessState::Running,
                    Some(Ok(true)) => ProcessState::Ended,
                    Some(Err(error)) => ProcessState::Unknown {
                        detail: format!("pid {pid}: whether it has exited: {error}"),
                    },
                    // A reading that described the process came through a handle to it.
                    None => ProcessState::Unknown {
                        detail: format!("pid {pid}: described without a handle"),
                    },
                }
            }
            ProcessQuery::Present(_) | ProcessQuery::Gone => ProcessState::Ended,
            ProcessQuery::CannotEstablish(error) => ProcessState::Unknown {
                detail: error.to_string(),
            },
        }
    }

    /// Ends the process holding `identity` through one open handle: the handle is what ties the
    /// creation time that was compared to the process that is ended.
    ///
    /// There is no request to end a process on this platform that is not also the end of it, so
    /// [`super::Stop::Terminate`] is [`super::Stopped::Unsupported`]: a caller that wants a
    /// grace period waits for the session's job to do its work, and ends what is left.
    pub(super) fn stop(
        identity: &kr_protocol::identity::ProcessStartIdentity,
        stop: super::Stop,
    ) -> super::Stopped {
        use super::Stopped;

        if stop == super::Stop::Terminate {
            return Stopped::Unsupported;
        }
        let Ok(pid) = u32::try_from(identity.pid.get()) else {
            return Stopped::Gone;
        };
        let (reading, process) = look(pid, process_times::Rights::Terminate);
        match super::windows_answer(pid, reading, process_times::now()) {
            ProcessQuery::Present(current) if current.start_value == identity.start_value => {}
            ProcessQuery::Present(_) | ProcessQuery::Gone => return Stopped::Gone,
            ProcessQuery::CannotEstablish(error) => return Stopped::Unsafe(error.to_string()),
        }
        let Some(process) = process else {
            return Stopped::Unsafe(format!("pid {pid}: described without a handle"));
        };
        match process.has_exited() {
            Ok(true) => return Stopped::Gone,
            Ok(false) => {}
            Err(error) => {
                return Stopped::Unsafe(format!("pid {pid}: whether it has exited: {error}"));
            }
        }
        match process.terminate() {
            Ok(()) => Stopped::Signalled,
            Err(error) => {
                // A process that ended between the question and the call is the outcome asked for.
                match process.has_exited() {
                    Ok(true) => Stopped::Gone,
                    _ => Stopped::Refused(error.to_string()),
                }
            }
        }
    }

    pub(super) fn query_process(pid: u32) -> ProcessQuery {
        // Asking when a process started takes the right to ask that and nothing more: a process
        // whose list grants this account that right alone is still one it can identify.
        let (reading, _) = look(pid, process_times::Rights::Query);
        super::windows_answer(pid, reading, process_times::now())
    }

    /// Opens one process with `rights` and reads its creation time, keeping the handle for a
    /// second question.
    fn look(
        pid: u32,
        rights: process_times::Rights,
    ) -> (WindowsReading, Option<process_times::Process>) {
        match process_times::open(pid, rights) {
            process_times::Opened::Absent => (WindowsReading::Absent, None),
            process_times::Opened::Failed(error) => (WindowsReading::Failed(error), None),
            process_times::Opened::Process(process) => match process.created() {
                Ok(created) => (WindowsReading::Created(created), Some(process)),
                Err(error) => (
                    WindowsReading::Failed(format!("its times could not be read: {error}")),
                    None,
                ),
            },
        }
    }
}

/// One of the two places in this module that leave safe Rust: opening a Windows process and reading
/// its times.
///
/// The crate denies unsafe code and relaxes the rule here, beside `clock::windows` and
/// `paths::windows`, because the kernel's record of when a process was created, and whether it has
/// exited, are `kernel32` calls with no safe interface. The handle is owned as soon as it exists,
/// so every path closes it.
#[cfg(windows)]
mod process_times {
    #![expect(
        unsafe_code,
        reason = "a process's creation time and whether it has exited are kernel32 calls, which have \
                  no safe interface"
    )]

    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    /// One process, opened for the questions its rights allow.
    pub(super) struct Process(OwnedHandle);

    /// What a process is opened to be asked.
    #[derive(Clone, Copy)]
    pub(super) enum Rights {
        /// When it was created.
        Query,
        /// When it was created, and whether it has exited.
        QueryAndWait,
        /// When it was created, whether it has exited, and the right to end it.
        Terminate,
    }

    /// What opening a process by its identifier produced.
    pub(super) enum Opened {
        /// The process, open.
        Process(Process),
        /// No process holds the identifier.
        Absent,
        /// The kernel would not open it, for the reason given.
        Failed(String),
    }

    /// Opens the process holding `pid` with `rights`.
    ///
    /// Only one refusal says that nothing holds the identifier: the kernel's invalid-parameter
    /// answer, which is what it gives for an identifier no process has. A refusal of access is a
    /// process that is there, and so is every other failure as far as this can tell. Identifier
    /// zero is the one exception to the first rule, so it is never asked: the kernel gives the same
    /// answer for the system idle process, which holds it and has no start to read.
    pub(super) fn open(pid: u32, rights: Rights) -> Opened {
        if pid == 0 {
            return Opened::Failed(
                "identifier 0 is the system idle process, which has no start to read".to_owned(),
            );
        }
        let access = match rights {
            Rights::Query => PROCESS_QUERY_LIMITED_INFORMATION,
            Rights::QueryAndWait => PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            Rights::Terminate => {
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE
            }
        };
        // SAFETY: the call takes three plain values and returns either a new handle the caller
        // owns or null; it has no other effect.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(code) if u32::try_from(code) == Ok(ERROR_INVALID_PARAMETER) => Opened::Absent,
                _ => Opened::Failed(format!("the process could not be opened: {error}")),
            };
        }
        // SAFETY: the handle was returned open by the call above, and nothing else owns it.
        Opened::Process(Process(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }

    impl Process {
        /// Returns when the kernel recorded the process's creation, as a `FILETIME`: hundreds of
        /// nanoseconds since the start of 1601, UTC.
        pub(super) fn created(&self) -> std::io::Result<u64> {
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            // SAFETY: the handle is open for as long as `self` is, with the right this call needs,
            // and each pointer is to a live local of the structure the call writes.
            let read = unsafe {
                GetProcessTimes(
                    self.0.as_raw_handle(),
                    &raw mut creation,
                    &raw mut exit,
                    &raw mut kernel,
                    &raw mut user,
                )
            };
            if read == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
        }

        /// Ends the process through this handle, which holds the process the handle was opened
        /// on whatever happens to its identifier.
        ///
        /// A handle opened without the right to end it is refused here.
        pub(super) fn terminate(&self) -> std::io::Result<()> {
            // SAFETY: the handle is open for as long as `self` is, and the call takes the handle
            // and an exit code and has no other effect.
            if unsafe { TerminateProcess(self.0.as_raw_handle(), 1) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        /// Returns whether the process has exited, without waiting for it to.
        ///
        /// The handle has the right to wait on the process when it was opened with
        /// [`Rights::QueryAndWait`]; one opened without it is refused here, which the caller
        /// reports as a question it could not answer.
        pub(super) fn has_exited(&self) -> std::io::Result<bool> {
            // SAFETY: the handle is open for as long as `self` is, and a zero timeout returns at
            // once. A handle without the right to wait makes the call fail, which is reported.
            match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }

    /// Returns the wall clock as a `FILETIME`, the unit a creation time is read in.
    pub(super) fn now() -> u64 {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_nanos() / 100).unwrap_or(u64::MAX)
            });
        since.saturating_add(super::UNIX_EPOCH_AS_FILETIME)
    }
}

/// The other place in this module that leaves safe Rust: the kernel's records of a Windows boot,
/// its process list and the boot counter in the page it shares with every process.
///
/// The crate denies unsafe code and relaxes the rule here, as for [`process_times`]: the list is an
/// `ntdll` call and the counter a read of memory the kernel maps, and neither has a safe interface.
/// Each function does one of the two and nothing else; `windows_boot` decides what the answers
/// mean.
#[cfg(windows)]
mod boot_records {
    #![expect(
        unsafe_code,
        reason = "the kernel's process list is an ntdll call and its boot counter lies in the page \
                  it shares with every process, and neither has a safe interface"
    )]

    use windows_sys::Wdk::System::SystemInformation::{
        NtQuerySystemInformation, SystemProcessInformation,
    };
    use windows_sys::Wdk::System::SystemServices::KUSER_SHARED_DATA;

    /// Where the kernel maps `KUSER_SHARED_DATA`, the page it shares read-only with every process:
    /// `MM_SHARED_USER_DATA_VA`, one address in every process on every Windows.
    const SHARED_USER_DATA: usize = 0x7FFE_0000;

    /// Asks the kernel for its process list in `buffer`, which the caller aligns to eight bytes,
    /// and returns its status and the length it wrote, or needed.
    pub(super) fn query_process_list(buffer: &mut [u8]) -> (i32, u32) {
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut returned = 0_u32;
        // SAFETY: `buffer` is at least `capacity` bytes of initialised memory that this call
        // borrows mutably, and `returned` is a live local; the kernel writes at most `capacity`
        // bytes into the one and a length into the other, and keeps neither pointer. A buffer it
        // finds misaligned it refuses with a status rather than writes.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_mut_ptr().cast(),
                capacity,
                &raw mut returned,
            )
        };
        (status, returned)
    }

    /// Returns the boot counter the kernel publishes as `KUSER_SHARED_DATA.BootId`.
    pub(super) fn boot_count() -> u32 {
        let address = SHARED_USER_DATA + std::mem::offset_of!(KUSER_SHARED_DATA, BootId);
        // SAFETY: the kernel maps `KUSER_SHARED_DATA` readable at `SHARED_USER_DATA` into every
        // process for the whole of its life, outside any allocation this program makes, and
        // `BootId` is a four-byte field at the offset the SDK declares for it, which is four-byte
        // aligned. The kernel writes the field before this process starts and not while it runs,
        // so the read races with no write; it is volatile because the page is the kernel's, not
        // memory this program owns.
        unsafe { std::ptr::read_volatile(std::ptr::with_exposed_provenance::<u32>(address)) }
    }
}

/// Where the start value of a Windows reading comes from.
const WINDOWS_START_SOURCE: ProcessStartSource = ProcessStartSource::WindowsProcessCreationTime;

/// The Unix epoch as a `FILETIME`: hundreds of nanoseconds from the start of 1601 to the start of
/// 1970, UTC.
const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// Hundreds of nanoseconds in one second, the unit a `FILETIME` counts.
const FILETIME_UNITS_PER_SECOND: u64 = 10_000_000;

/// How far past the wall clock a Windows creation time may lie and still be a reading, in the unit
/// a `FILETIME` counts.
///
/// A process starts before anyone asks about it, so a creation time after the current time is a
/// clock stepped back since the process started, or a value nobody read. A day covers any ordinary
/// correction of the clock; a value further ahead establishes nothing.
const WINDOWS_START_AHEAD: u64 = 24 * 60 * 60 * FILETIME_UNITS_PER_SECOND;

/// What the Windows kernel said about one process identifier, as it said it.
///
/// The reader on that platform produces one of these for every question it asks, and
/// [`windows_answer`] decides what it means. It is public so that a decision built on a reading can
/// be checked with a reading injected, on any platform: no real kernel gives a failed reading, a
/// creation time of zero, or two processes created within one second under one identifier, on
/// request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowsReading {
    /// The kernel opened the process and gave its creation time, as a `FILETIME`: hundreds of
    /// nanoseconds since the start of 1601, UTC.
    Created(u64),
    /// The kernel has no process under the identifier.
    Absent,
    /// The kernel did not answer, for the reason given, so the reading did not happen.
    Failed(String),
}

/// Decides what one reading of a Windows process says about `pid`.
///
/// A reading that did not happen establishes nothing, and a process it did not find is not taken
/// to have gone. Nor is a creation time that is not one: zero, which the kernel never records for
/// a process it created; one before 1970, which no process this host asks about has; and one past
/// `now`, the wall clock in the same unit, by more than a day, which is a clock stepped back
/// further than any ordinary correction or a value nobody read. Every other creation time is the
/// process's start value.
#[must_use]
pub fn windows_answer(pid: u32, reading: WindowsReading, now: u64) -> ProcessQuery {
    let created = match reading {
        WindowsReading::Absent => return ProcessQuery::Gone,
        WindowsReading::Failed(why) => {
            return ProcessQuery::CannotEstablish(unavailable(
                "process start identity",
                format!("pid {pid}: {why}"),
            ));
        }
        WindowsReading::Created(created) => created,
    };
    if created == 0 {
        return ProcessQuery::CannotEstablish(unavailable(
            "process start identity",
            format!("pid {pid}: the operating system would not say when it started"),
        ));
    }
    let since_epoch = match created.checked_sub(UNIX_EPOCH_AS_FILETIME) {
        Some(since) if created <= now.saturating_add(WINDOWS_START_AHEAD) => since,
        _ => {
            return ProcessQuery::CannotEstablish(unavailable(
                "process start identity",
                format!(
                    "pid {pid}: a creation time of {created} is not a time it could have started"
                ),
            ));
        }
    };
    ProcessQuery::Present(ProcessStartIdentity::new(
        u64::from(pid),
        WINDOWS_START_SOURCE,
        since_epoch,
    ))
}

/// The Windows boot identity, made from what the kernel wrote.
///
/// Nothing here asks the kernel; `boot_records` does, on Windows. What its answers mean, and every
/// check they must pass, is decided here in safe code, so the tests check it on every platform with
/// lists laid out the way the kernel lays them out.
#[cfg(any(windows, test))]
mod windows_boot {
    use super::{Result, unavailable};

    /// The System process's identifier in the kernel's process list, on every Windows this host
    /// runs on.
    pub(super) const SYSTEM_PROCESS: u64 = 4;

    /// The image name the kernel gives the System process.
    pub(super) const SYSTEM_PROCESS_NAME: &str = "System";

    // Where the fields read here lie in one entry of the kernel's process list,
    // `SYSTEM_PROCESS_INFORMATION`, in bytes from the start of the entry, on 64-bit Windows.

    /// The distance to the next entry, or zero after the last: four bytes.
    pub(super) const ENTRY_NEXT: usize = 0;
    /// The process's creation time: a signed eight-byte count of hundreds of nanoseconds since
    /// 1601. The SDK declares these bytes reserved, `Reserved1[24..32]`, and the kernel keeps the
    /// creation time there; the native tests compare it with the one `GetProcessTimes` gives.
    pub(super) const ENTRY_CREATED: usize = 32;
    /// The length in bytes of the image name, a counted UTF-16 string: two bytes.
    pub(super) const ENTRY_NAME_LENGTH: usize = 56;
    /// The capacity in bytes the kernel gives the image name, which its length cannot exceed.
    pub(super) const ENTRY_NAME_CAPACITY: usize = 58;
    /// The address of the image name's characters, which the kernel writes into the same list.
    pub(super) const ENTRY_NAME_ADDRESS: usize = 64;
    /// The process's identifier: eight bytes.
    pub(super) const ENTRY_PROCESS: usize = 80;
    /// The bytes of an entry read here, through the identifier. No entry is shorter.
    pub(super) const ENTRY_READ: usize = 88;
    /// The boundary every entry begins on, that of the entry's eight-byte fields. The assertion
    /// below holds it to the SDK's declaration of an entry; that the kernel begins every entry
    /// there is what the native tests show, by reading a real list with this rule.
    pub(super) const ENTRY_ALIGNMENT: usize = 8;

    // The offsets above are the SDK's own on the target this is built for.
    #[cfg(windows)]
    const _: () = {
        use std::mem::offset_of;

        use windows_sys::Win32::Foundation::UNICODE_STRING;
        use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION as Entry;

        assert!(offset_of!(Entry, NextEntryOffset) == ENTRY_NEXT);
        assert!(offset_of!(Entry, Reserved1) + 24 == ENTRY_CREATED);
        assert!(
            offset_of!(Entry, ImageName) + offset_of!(UNICODE_STRING, Length) == ENTRY_NAME_LENGTH
        );
        assert!(
            offset_of!(Entry, ImageName) + offset_of!(UNICODE_STRING, MaximumLength)
                == ENTRY_NAME_CAPACITY
        );
        assert!(
            offset_of!(Entry, ImageName) + offset_of!(UNICODE_STRING, Buffer) == ENTRY_NAME_ADDRESS
        );
        assert!(offset_of!(Entry, UniqueProcessId) == ENTRY_PROCESS);
        assert!(offset_of!(Entry, UniqueProcessId) + size_of::<usize>() == ENTRY_READ);
        assert!(align_of::<Entry>() == ENTRY_ALIGNMENT);
    };

    /// The kernel's answer that a buffer is too short for its process list,
    /// `STATUS_INFO_LENGTH_MISMATCH`.
    pub(super) const LIST_TOO_SHORT: i32 = 0xC000_0004_u32.cast_signed();

    /// How long the first buffer for the process list is, in bytes: room for a few hundred
    /// processes and their threads.
    pub(super) const LIST_FIRST: usize = 512 * 1024;

    /// The longest buffer the list is read into, in bytes. A list that does not fit is not read.
    pub(super) const LIST_MOST: usize = 64 * 1024 * 1024;

    /// How many times the list is asked for before the answer is that it could not be read.
    pub(super) const LIST_CALLS: usize = 8;

    /// The kernel's process list as one call wrote it.
    pub(super) struct ProcessList {
        /// The allocation the kernel wrote into, kept where it is for as long as this is, since
        /// the addresses inside the list point into it.
        buffer: Vec<u8>,
        /// Where in it the eight-byte-aligned part the kernel was given begins.
        start: usize,
        /// How many bytes the kernel wrote there.
        written: usize,
    }

    impl ProcessList {
        /// The bytes the kernel wrote, and none of the rest of the buffer.
        pub(super) fn bytes(&self) -> &[u8] {
            &self.buffer[self.start..self.start + self.written]
        }

        /// The address the kernel wrote the list at, which the addresses inside it count from.
        pub(super) fn base(&self) -> usize {
            self.bytes().as_ptr().addr()
        }
    }

    /// Reads the kernel's process list through `query`, which fills the eight-byte-aligned
    /// buffer it is given and returns the kernel's status and the length it wrote, or needed.
    ///
    /// The list changes between two calls, so a call the kernel says was too short is followed by
    /// one with room for what it said it needed and half as much again, for at most
    /// [`LIST_CALLS`] calls and a buffer of at most [`LIST_MOST`] bytes. Only a call the kernel
    /// says succeeded is read, and only as far as the length it says it wrote.
    pub(super) fn read_process_list(
        mut query: impl FnMut(&mut [u8]) -> (i32, u32),
    ) -> std::result::Result<ProcessList, String> {
        let mut length = LIST_FIRST;
        for _ in 0..LIST_CALLS {
            // Seven bytes more than the kernel is given, so that what it is given can begin on an
            // eight-byte boundary wherever the allocation begins.
            let mut buffer = vec![0_u8; length + 7];
            let start = buffer.as_ptr().align_offset(8);
            let Some(given) = buffer.get_mut(start..start + length) else {
                return Err("no eight-byte boundary in the buffer".to_owned());
            };
            let (status, reported) = query(given);
            let reported = usize::try_from(reported).unwrap_or(usize::MAX);
            if status == LIST_TOO_SHORT {
                length = reported
                    .saturating_add(reported / 2)
                    .max(length.saturating_mul(2))
                    .min(LIST_MOST);
                continue;
            }
            if status < 0 {
                return Err(format!(
                    "the kernel would not list the processes: status {status:#010x}"
                ));
            }
            if reported > length {
                return Err(format!(
                    "the kernel said it wrote {reported} bytes into a buffer of {length}"
                ));
            }
            return Ok(ProcessList {
                buffer,
                start,
                written: reported,
            });
        }
        Err(format!(
            "the list did not fit in {length} bytes in {LIST_CALLS} calls"
        ))
    }

    /// Returns the creation time the kernel recorded for the System process, from `list`, the
    /// bytes of its process list, which it wrote at the address `base`.
    ///
    /// The whole list is checked, not only the part before the System process. Every entry must
    /// hold the fields read from it; each next entry must begin on an eight-byte boundary, after
    /// this entry's fields and inside the list; and the last entry names no next one. Exactly one
    /// entry carries identifier 4, and it must carry the System process's name, a counted string
    /// inside the list and within the capacity the entry states, and a creation time that is a
    /// time. Anything else establishes nothing, and says why.
    pub(super) fn system_process_created(list: &[u8], base: usize) -> Result<u64> {
        let refused =
            |why: String| unavailable("boot identity", format!("the kernel's process list {why}"));
        let mut created = None;
        let mut at = 0_usize;
        loop {
            let entry = list.get(at..).unwrap_or_default();
            if entry.len() < ENTRY_READ {
                return Err(refused(format!("ends inside the entry at byte {at}")));
            }
            if u64::from_le_bytes(field(entry, ENTRY_PROCESS)) == SYSTEM_PROCESS {
                if created.is_some() {
                    return Err(refused(format!("lists process {SYSTEM_PROCESS} twice")));
                }
                let name = image_name(list, base, entry)
                    .map_err(|why| refused(format!("gives process {SYSTEM_PROCESS} {why}")))?;
                if name != SYSTEM_PROCESS_NAME {
                    return Err(refused(format!(
                        "names process {SYSTEM_PROCESS} {name:?}, not the System process"
                    )));
                }
                let time = i64::from_le_bytes(field(entry, ENTRY_CREATED));
                created = Some(
                    u64::try_from(time)
                        .ok()
                        .filter(|time| *time > 0)
                        .ok_or_else(|| {
                            refused(format!(
                                "gives the System process a creation time of {time}"
                            ))
                        })?,
                );
            }
            let next =
                usize::try_from(u32::from_le_bytes(field(entry, ENTRY_NEXT))).unwrap_or(usize::MAX);
            if next == 0 {
                return created.ok_or_else(|| refused(format!("has no process {SYSTEM_PROCESS}")));
            }
            if next < ENTRY_READ || next % ENTRY_ALIGNMENT != 0 {
                return Err(refused(format!(
                    "has an entry at byte {at} whose next one, {next} bytes on, overlaps it or is \
                     misaligned"
                )));
            }
            at = at
                .checked_add(next)
                .filter(|next_at| *next_at < list.len())
                .ok_or_else(|| {
                    refused(format!(
                        "has an entry at byte {at} whose next one lies past its end"
                    ))
                })?;
        }
    }

    /// The `N` bytes at `at` in `bytes`, which the caller has checked hold them.
    fn field<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
        let mut field = [0_u8; N];
        field.copy_from_slice(&bytes[at..at + N]);
        field
    }

    /// Reads an entry's image name: a counted string of UTF-16 characters, which the kernel writes
    /// into the list itself and points to by address, no longer than the capacity it states.
    fn image_name(list: &[u8], base: usize, entry: &[u8]) -> std::result::Result<String, String> {
        let length = usize::from(u16::from_le_bytes(field(entry, ENTRY_NAME_LENGTH)));
        let capacity = usize::from(u16::from_le_bytes(field(entry, ENTRY_NAME_CAPACITY)));
        if length > capacity {
            return Err(format!(
                "a name of {length} bytes in a capacity of {capacity}"
            ));
        }
        let address = u64::from_le_bytes(field(entry, ENTRY_NAME_ADDRESS));
        let characters = usize::try_from(address)
            .ok()
            .and_then(|address| address.checked_sub(base))
            .filter(|_| length % 2 == 0)
            .and_then(|start| list.get(start..start.checked_add(length)?))
            .ok_or_else(|| {
                format!("a name of {length} bytes at {address:#x}, outside the list at {base:#x}")
            })?;
        let units: Vec<u16> = characters
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| "a name that is not UTF-16".to_owned())
    }

    /// The Windows boot identity's value: the kernel's boot counter, then the creation time it
    /// recorded for its System process, four and eight bytes, most significant first.
    ///
    /// Every read in one boot gives the same value. The kernel publishes the counter once, when it
    /// starts, and records a process's creation time once, when it creates the process; it creates
    /// the System process when it starts and keeps it until it stops. A clock set, a sleep, a
    /// hibernation, or a hypervisor setting the clock after pausing the machine, leaves both as
    /// they were.
    ///
    /// A restart normally gives another value; the pair repeats exactly when both of its records
    /// repeat. The new kernel records its System process's creation as the clock it starts from
    /// plus the time it took to start, to the hundred nanoseconds. Unless the clock went back
    /// between the two starts, that sum is later than the earlier boot's. It repeats whenever the
    /// two sums are equal, whichever start read the earlier clock: as they can be when a dead
    /// battery resets the real-time clock to one instant and two starts take one time. The counter
    /// usually advances at a restart, but nothing guarantees that it does. A repeat would take the
    /// new boot for the old one, and apply the old boot's continuous deadlines to the new boot's
    /// clock.
    pub(super) fn value(boot_count: u32, system_created: u64) -> [u8; 12] {
        let mut value = [0_u8; 12];
        value[..4].copy_from_slice(&boot_count.to_be_bytes());
        value[4..].copy_from_slice(&system_created.to_be_bytes());
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a query about `pid` says about the process `identity` recorded.
    fn state_from(identity: &ProcessStartIdentity, pid: u32, query: ProcessQuery) -> ProcessState {
        current_from(identity, pid, query).into()
    }

    /// A macOS kernel a test stands in for: a boot session identifier or none, a release, and a
    /// boot time that moves when the clock is set, as `kern.boottime` does.
    struct StandInKernel {
        session: Option<&'static str>,
        release: Option<&'static str>,
        /// The boot time the kernel reckons, as seconds and microseconds since 1970.
        boot_time: std::cell::Cell<(i64, i32)>,
    }

    impl StandInKernel {
        /// A kernel that publishes `session`, reckoning its boot at a fixed moment.
        fn publishing(session: Option<&'static str>) -> Self {
            Self {
                session,
                release: Some("16.7.0"),
                boot_time: std::cell::Cell::new((1_700_000_000, 250_000)),
            }
        }

        /// Sets the clock forward: the kernel reckons its boot that much later.
        fn set_the_clock_forward(&self, seconds: i64) {
            let (at, micros) = self.boot_time.get();
            self.boot_time.set((at + seconds, micros));
        }
    }

    impl macos_boot::Kernel for StandInKernel {
        fn read(&self, control: &str) -> std::result::Result<Vec<u8>, String> {
            let text = |value: Option<&str>| {
                value
                    .map(|value| value.as_bytes().to_vec())
                    .ok_or_else(|| format!("{control}: no such control"))
            };
            match control {
                "kern.bootsessionuuid" => text(self.session),
                "kern.osrelease" => text(self.release),
                "kern.boottime" => {
                    // A `struct timeval`: the seconds, the microseconds and the padding after them.
                    let (seconds, micros) = self.boot_time.get();
                    let mut bytes = seconds.to_le_bytes().to_vec();
                    bytes.extend_from_slice(&micros.to_le_bytes());
                    bytes.extend_from_slice(&[0; 4]);
                    Ok(bytes)
                }
                _ => Err(format!("{control}: no such control")),
            }
        }
    }

    /// A macOS kernel that publishes no boot session identifier gives one boot one identity, or a
    /// refusal that names the kernel and what the host needs; the clock set while the host runs
    /// changes neither. What it must not give is two identities for one boot, which is what the
    /// boot time does, because the kernel moves it with the clock.
    #[test]
    fn a_macos_kernel_without_a_boot_session_identifier_gives_one_boot_one_identity_or_a_refusal() {
        let kernel = StandInKernel::publishing(None);
        let before = macos_boot::boot_identity(&kernel);
        kernel.set_the_clock_forward(7);
        let after = macos_boot::boot_identity(&kernel);
        match (before, after) {
            (Ok(before), Ok(after)) => assert_eq!(
                before, after,
                "one boot has one identity, whatever the clock did in between"
            ),
            (Err(before), Err(after)) => {
                for refusal in [before, after] {
                    let said = refusal.to_string();
                    for named in ["kern.bootsessionuuid", "Darwin 16.7.0", "macOS 14"] {
                        assert!(said.contains(named), "the refusal names {named}: {said}");
                    }
                }
            }
            (before, after) => {
                panic!("one boot is read the same way twice: {before:?}, then {after:?}")
            }
        }
    }

    /// The control: a kernel that publishes its boot session identifier gives that identifier,
    /// the same before and after the clock is set.
    #[test]
    fn a_macos_kernel_with_a_boot_session_identifier_gives_it_whatever_the_clock_does() {
        let session = "0D1E5C7A-8F42-4B61-9C3D-2E7A55B0C1F4";
        let kernel = StandInKernel::publishing(Some(session));
        let before = macos_boot::boot_identity(&kernel).expect("an identity");
        kernel.set_the_clock_forward(7);
        let after = macos_boot::boot_identity(&kernel).expect("an identity");
        assert_eq!(before, after);
        assert_eq!(
            before.source,
            kr_protocol::identity::BootIdentitySource::MacosBootSessionUuid
        );
        assert_eq!(before.value.as_slice(), session.as_bytes());
    }

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

    /// A process's children are read from that process alone: what it costs follows the one
    /// process, however many others the host is running.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_process_s_children_are_read_from_that_process_alone() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("a child");
        let me = std::process::id();
        let (children, read) = super::processes_read_during(|| super::children_of(me));
        let _ = child.kill();
        let _ = child.wait();
        let children = children.expect("the kernel lists this process's children");
        assert!(
            children.contains(&child.id()),
            "the child is listed: {children:?}"
        );
        assert!(!read.is_empty(), "the reading is counted");
        assert!(
            read.iter().all(|pid| *pid == me),
            "nothing but this process was read: {read:?}"
        );
    }

    /// The kernel lists a process's threads while they come and go, and a listing ends at a thread
    /// that left while it was made: the threads after it, and the children they hold, are not in
    /// it, and a listing taken up again after it finds its place by counting threads, which lands
    /// after a thread that stayed when the ones ahead of it have gone and takes in the threads made
    /// since. A child that is alive is listed whatever the process's other threads do.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_live_child_is_listed_while_the_process_s_other_threads_come_and_go() {
        use std::sync::{Arc, Condvar, Mutex, mpsc};

        const ROUNDS: usize = 300;
        let me = std::process::id();
        let mut unlisted = Vec::new();
        for round in 0..ROUNDS {
            // Threads made before the one that holds the child, which each make a thread and leave
            // as the child is read: the kernel's listing meets each of them ahead of the thread
            // with the child, and new threads follow it.
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let over = Arc::new((Mutex::new(false), Condvar::new()));
            let leaving: Vec<_> = (0..16)
                .map(|_| {
                    let gate = Arc::clone(&gate);
                    let over = Arc::clone(&over);
                    std::thread::spawn(move || {
                        let (open, opened) = &*gate;
                        drop(
                            opened
                                .wait_while(open.lock().expect("the gate"), |open| !*open)
                                .expect("the gate"),
                        );
                        std::thread::spawn(move || {
                            let (done, ended) = &*over;
                            drop(
                                ended
                                    .wait_while(done.lock().expect("the end"), |done| !*done)
                                    .expect("the end"),
                            );
                        })
                    })
                })
                .collect();
            let (started, child) = mpsc::channel();
            let (finished, release) = mpsc::channel::<()>();
            let owner = std::thread::spawn(move || {
                let mut child = std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .expect("a child");
                started.send(child.id()).expect("the round is read");
                let _ = release.recv();
                let _ = child.kill();
                let _ = child.wait();
            });
            let child = child.recv().expect("the owner started a child");
            {
                let (open, opened) = &*gate;
                *open.lock().expect("the gate") = true;
                opened.notify_all();
            }
            let children =
                super::children_of(me).expect("the kernel lists this process's children");
            if !children.contains(&child) {
                unlisted.push(round);
            }
            finished.send(()).expect("the owner is waiting");
            owner.join().expect("the owner ends");
            {
                let (done, ended) = &*over;
                *done.lock().expect("the end") = true;
                ended.notify_all();
            }
            for thread in leaving {
                thread
                    .join()
                    .expect("a thread ends")
                    .join()
                    .expect("its replacement ends");
            }
        }
        assert!(
            unlisted.is_empty(),
            "a child that was alive went unlisted in {} of {ROUNDS} readings, the first in round {:?}",
            unlisted.len(),
            unlisted.first()
        );
    }

    /// A thread that ends hands its children to another thread of the process, and its own list is
    /// gone with it. A thread younger than the one that holds the child is read first, and when the
    /// holder ends after that, its list is gone when it is read and the pass is made again: the
    /// child is in the list of the thread that took it, which the next pass reads.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_child_whose_thread_ends_while_its_list_is_unread_is_still_listed() {
        use std::sync::mpsc;

        let me = std::process::id();
        let (started, started_child) = mpsc::channel();
        let (leave, leaving) = mpsc::channel::<()>();
        let owner = std::thread::spawn(move || {
            let own = std::fs::read_link("/proc/thread-self").expect("this thread");
            let tid: u32 = own
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse().ok())
                .expect("a thread identifier");
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("a child");
            started
                .send((child.id(), tid))
                .expect("the test is waiting");
            let _ = leaving.recv();
            // The thread ends with the child running, and another thread has it from there.
            child
        });
        let (child_id, owner_tid) = started_child.recv().expect("the owner started a child");
        // A thread younger than the owner, which a reading reads before the owner's list.
        let (release, parked) = mpsc::channel::<()>();
        let younger = std::thread::spawn(move || {
            let _ = parked.recv();
        });
        let owners_task = format!("/proc/{me}/task/{owner_tid}");
        let owners_list = format!("task/{owner_tid}/children");
        let mut leave = Some(leave);
        let children = super::after_each_read(
            move |_, file| {
                // Once the list of a thread other than the owner's has been read, the owner ends,
                // with its own list still to read.
                if file.ends_with("/children")
                    && file != owners_list
                    && let Some(leave) = leave.take()
                {
                    leave.send(()).expect("the owner is waiting");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                    while std::path::Path::new(&owners_task).exists() {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the owner ended within a minute"
                        );
                        std::thread::yield_now();
                    }
                }
            },
            || super::children_of(me),
        );
        release.send(()).expect("the younger thread is waiting");
        younger.join().expect("it ends");
        let mut child = owner.join().expect("the owner ended");
        let _ = child.kill();
        let _ = child.wait();
        let children = children.expect("the kernel lists this process's children");
        assert!(
            children.contains(&child_id),
            "the child is listed after its thread ended: {children:?}"
        );
    }

    /// What a pass costs follows the process's threads: a worker reads its own children on each
    /// observation of the session, and has a thread for each processor. A pass reads every thread's
    /// list of children, youngest thread first, and the standing of the threads from the first to
    /// the one that takes children, not of each one: reading each thread's standing before and after
    /// made a reading about ten times dearer than the one it replaced, and an idle host is allowed
    /// less than a hundredth of a processor for twenty sessions. Other tests' threads come and go
    /// beside this one, so the pass that is held to this is one that read, within a thousand tries.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_pass_reads_every_thread_s_children_youngest_first_and_the_standing_of_only_a_few() {
        use std::sync::{Arc, Condvar, Mutex, mpsc};

        use super::platform::{Pass, ThreadListing, children_in_one_pass, list_threads};

        const THREADS: usize = 48;
        let parked = Arc::new((Mutex::new(false), Condvar::new()));
        let (told, tids) = mpsc::channel();
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let parked = Arc::clone(&parked);
                let told = told.clone();
                std::thread::spawn(move || {
                    let own = std::fs::read_link("/proc/thread-self").expect("this thread");
                    let tid: u32 = own
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| name.parse().ok())
                        .expect("a thread identifier");
                    told.send(tid).expect("the test is listening");
                    let (done, ended) = &*parked;
                    drop(
                        ended
                            .wait_while(done.lock().expect("the end"), |done| !*done)
                            .expect("the end"),
                    );
                })
            })
            .collect();
        drop(told);
        let ours: Vec<u32> = (0..THREADS)
            .map(|_| tids.recv().expect("a thread said its identifier"))
            .collect();
        let me = std::process::id();
        let mut held = None;
        for _ in 0..1_000 {
            let read: Arc<Mutex<Vec<String>>> = Arc::default();
            let pass = super::after_each_read(
                {
                    let read = Arc::clone(&read);
                    move |_, file| read.lock().expect("the record").push(file.to_owned())
                },
                || children_in_one_pass(me),
            )
            .expect("the kernel lists this process's children");
            if matches!(pass, Pass::Read(_)) {
                held = Some(read.lock().expect("the record").clone());
                break;
            }
        }
        // The order the kernel lists this test's threads in, which is the order they were made in:
        // another test's thread that ends while the threads are listed makes a listing short, which
        // is listed again.
        let listed = (0..1_000).find_map(|_| match list_threads(me, None).expect("lists") {
            ThreadListing::Whole(listed) => Some(listed),
            ThreadListing::Partial => None,
            ThreadListing::Gone => panic!("this process has gone"),
        });
        let (done, ended) = &*parked;
        *done.lock().expect("the end") = true;
        ended.notify_all();
        for thread in threads {
            thread.join().expect("a thread ends");
        }
        let read = held.expect("a pass read within a thousand tries");
        let listed = listed.expect("a listing made whole within a thousand tries");
        let youngest_first: Vec<String> = listed
            .iter()
            .rev()
            .filter(|tid| ours.contains(tid))
            .map(|tid| format!("task/{tid}/children"))
            .collect();
        let in_order: Vec<String> = read
            .iter()
            .filter(|file| youngest_first.contains(file))
            .cloned()
            .collect();
        assert_eq!(
            in_order, youngest_first,
            "every thread's children were read, youngest thread first: {read:?}"
        );
        let standings = read
            .iter()
            .filter(|file| file.starts_with("task/") && file.ends_with("/stat"))
            .count();
        assert!(
            standings < THREADS,
            "the standing of {standings} threads was read for {THREADS} threads and the rest: {read:?}"
        );
    }

    /// The thread an ending thread hands its children to is the first live one in the order the
    /// kernel lists the threads, found by reading as few as it takes; a thread that is ending ahead
    /// of it, or gone, leaves the pass unsettled, and one that has ended is passed over.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_heir_is_the_first_live_thread_and_one_ending_ahead_of_it_unsettles_the_pass() {
        use super::platform::{Heir, ThreadLife, heir_among};

        let case = |lives: &[ThreadLife]| {
            let threads: Vec<u32> = (0..u32::try_from(lives.len()).expect("a few")).collect();
            let mut asked = 0;
            let heir = heir_among(&threads, |tid| {
                asked += 1;
                Ok(lives[usize::try_from(tid).expect("an index")])
            })
            .expect("a standing for each");
            (heir, asked)
        };
        use ThreadLife::{Ended, Gone, Leaving, Live};
        assert_eq!(case(&[Live, Live, Live]), (Heir::Thread(0), 1));
        assert_eq!(case(&[Live, Leaving]), (Heir::Thread(0), 1));
        assert_eq!(case(&[Ended, Live, Live]), (Heir::Thread(1), 2));
        assert_eq!(case(&[Ended, Ended, Live]), (Heir::Thread(2), 3));
        assert_eq!(case(&[Ended, Ended]), (Heir::Nobody, 2));
        assert_eq!(case(&[Leaving, Live]), (Heir::Unsettled, 1));
        assert_eq!(case(&[Ended, Gone, Live]), (Heir::Unsettled, 2));
        let refused = heir_among(&[7], |_| {
            Err(super::unavailable(
                "children of a process",
                "no answer".to_owned(),
            ))
        });
        assert!(refused.is_err(), "a refused reading is not a settled one");
    }

    /// What a thread's `stat` line says of where it stands: a zombie has ended, a dead one is going,
    /// and one that carries the flag a thread has from the moment it begins to end, in any state
    /// that is not either, is leaving. The lines are the kernel's own, with the state and the flags
    /// where it prints them.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_thread_s_standing_is_read_from_its_state_and_its_ending_flag() {
        use super::platform::{ThreadLife, life_from_stat};

        let line = |state: &str, flags: u32| {
            format!(
                "42 (od d) ne) {state} 1 42 42 0 -1 {flags} 1 0 0 0 0 0 0 0 20 0 3 0 100 0 0 0 0 0"
            )
        };
        assert_eq!(
            life_from_stat(&line("S", 0x40_0040)),
            Some(ThreadLife::Live)
        );
        assert_eq!(
            life_from_stat(&line("R", 0x40_0000)),
            Some(ThreadLife::Live)
        );
        assert_eq!(
            life_from_stat(&line("S", 0x40_0044)),
            Some(ThreadLife::Leaving)
        );
        assert_eq!(life_from_stat(&line("D", 0x4)), Some(ThreadLife::Leaving));
        assert_eq!(
            life_from_stat(&line("Z", 0x40_000c)),
            Some(ThreadLife::Ended)
        );
        assert_eq!(life_from_stat(&line("X", 0x4)), Some(ThreadLife::Gone));
        assert_eq!(life_from_stat("42 (od d) ne) S 1"), None);
    }

    /// A model of how the kernel keeps a process's threads and their lists of children, for the
    /// pass to be run against every order its events can fall in.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod kernel_model {
        use super::super::platform::{Pass, ThreadFacts, ThreadLife, ThreadListing};
        use crate::error::Result;

        /// One thread of the modelled process.
        struct Thread {
            tid: u32,
            life: ThreadLife,
            /// Kept listed after it ends, empty, as a thread whose end a tracer has not collected
            /// is. The process's first thread is kept whenever it ends.
            retained: bool,
            children: Vec<u32>,
        }

        /// What happens to the process between two of the pass's questions.
        #[derive(Clone, Copy, Debug)]
        pub enum Event {
            /// The thread begins to end: the kernel hands it no more children.
            Begin(u32),
            /// The thread has ended: its children go to the first thread, in the order they are
            /// listed in, that is not ending, and it leaves the list, or stays in it empty.
            End(u32),
            /// A thread is made.
            Make,
        }

        /// The process, with its events and the number of questions answered so far.
        pub struct Kernel {
            threads: Vec<Thread>,
            events: Vec<(usize, Event)>,
            applied: usize,
            asked: usize,
            next: u32,
        }

        impl Kernel {
            /// A process of the given threads, in the order they were made in, each with its
            /// standing, whether it is kept when it ends, and the children it holds.
            pub fn of(threads: &[(ThreadLife, bool, &[u32])], events: Vec<(usize, Event)>) -> Self {
                Self {
                    threads: threads
                        .iter()
                        .zip(1_u32..)
                        .map(|((life, retained, children), tid)| Thread {
                            tid,
                            life: *life,
                            retained: *retained,
                            children: children.to_vec(),
                        })
                        .collect(),
                    events,
                    applied: 0,
                    asked: 0,
                    next: 100,
                }
            }

            fn apply(&mut self, event: Event) {
                match event {
                    Event::Begin(tid) => {
                        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid)
                            && thread.life == ThreadLife::Live
                        {
                            thread.life = ThreadLife::Leaving;
                        }
                    }
                    Event::End(tid) => {
                        let Some(at) = self.threads.iter().position(|t| t.tid == tid) else {
                            return;
                        };
                        if self.threads[at].life != ThreadLife::Leaving {
                            return;
                        }
                        // The last thread that could take children is not made to end: the
                        // children would go to another process, and nothing here follows them.
                        let Some(heir) = self
                            .threads
                            .iter()
                            .position(|t| t.tid != tid && t.life == ThreadLife::Live)
                        else {
                            return;
                        };
                        let handed = std::mem::take(&mut self.threads[at].children);
                        self.threads[heir].children.extend(handed);
                        if at == 0 || self.threads[at].retained {
                            self.threads[at].life = ThreadLife::Ended;
                        } else {
                            self.threads.remove(at);
                        }
                    }
                    Event::Make => {
                        let tid = self.next;
                        self.next += 1;
                        self.threads.push(Thread {
                            tid,
                            life: ThreadLife::Live,
                            retained: false,
                            children: Vec::new(),
                        });
                    }
                }
            }

            /// Answers a question: first what happened before it.
            fn ask(&mut self) {
                while self.applied < self.events.len() && self.events[self.applied].0 <= self.asked
                {
                    let event = self.events[self.applied].1;
                    self.applied += 1;
                    self.apply(event);
                }
                self.asked += 1;
            }

            /// Every child the modelled process holds, in whichever thread.
            pub fn all_children(&self) -> Vec<u32> {
                let mut all: Vec<u32> = self
                    .threads
                    .iter()
                    .flat_map(|thread| thread.children.iter().copied())
                    .collect();
                all.sort_unstable();
                all
            }
        }

        impl ThreadFacts for Kernel {
            fn list(&mut self) -> Result<ThreadListing> {
                self.ask();
                Ok(ThreadListing::Whole(
                    self.threads.iter().map(|thread| thread.tid).collect(),
                ))
            }

            fn life(&mut self, tid: u32) -> Result<ThreadLife> {
                self.ask();
                Ok(self
                    .threads
                    .iter()
                    .find(|thread| thread.tid == tid)
                    .map_or(ThreadLife::Gone, |thread| thread.life))
            }

            fn children(&mut self, tid: u32) -> Result<Option<Vec<u32>>> {
                self.ask();
                Ok(self
                    .threads
                    .iter()
                    .find(|thread| thread.tid == tid)
                    .map(|thread| thread.children.clone()))
            }
        }

        /// Runs a pass over the model with its events, and says whether what it read is wrong: a
        /// pass that read must hold every child the process held throughout, which here is every
        /// child it ever held, since none ends.
        pub fn wrong_read(
            pass: impl Fn(&mut Kernel) -> Result<Pass>,
            mut kernel: Kernel,
        ) -> Option<Vec<u32>> {
            let held = kernel.all_children();
            match pass(&mut kernel).expect("the model answers") {
                Pass::Read(read) if read != held => Some(read),
                _ => None,
            }
        }

        /// Every way `events` can fall among the first `questions` questions of a pass, with the
        /// order of the events among themselves any in which each thread begins to end before it
        /// has ended, and each way handed to `visit`.
        pub fn for_each_schedule(
            events: &[Event],
            questions: usize,
            visit: &mut impl FnMut(&[(usize, Event)]),
        ) {
            fn orders(events: &[Event]) -> Vec<Vec<Event>> {
                if events.len() <= 1 {
                    return vec![events.to_vec()];
                }
                let mut all = Vec::new();
                for (at, first) in events.iter().enumerate() {
                    // An end waits for its beginning.
                    if let Event::End(tid) = first
                        && events
                            .iter()
                            .any(|other| matches!(other, Event::Begin(t) if t == tid))
                    {
                        continue;
                    }
                    let mut rest = events.to_vec();
                    rest.remove(at);
                    for mut order in orders(&rest) {
                        order.insert(0, *first);
                        all.push(order);
                    }
                }
                all
            }
            fn place(
                order: &[Event],
                from: usize,
                questions: usize,
                chosen: &mut Vec<(usize, Event)>,
                visit: &mut impl FnMut(&[(usize, Event)]),
            ) {
                let Some((first, rest)) = order.split_first() else {
                    visit(chosen);
                    return;
                };
                for at in from..=questions {
                    chosen.push((at, *first));
                    place(rest, at, questions, chosen, visit);
                    chosen.pop();
                }
            }
            for order in orders(events) {
                place(&order, 0, questions, &mut Vec::new(), visit);
            }
        }
    }

    /// The pass as the model sees it, with each of its rules to be left out in turn, for the checks
    /// that each rule matters. All of them in is the pass itself.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[derive(Clone, Copy)]
    struct Rules {
        youngest_first: bool,
        heir_after: bool,
        relist: bool,
        leaving_first: bool,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn pass_with(
        rules: Rules,
        kernel: &mut kernel_model::Kernel,
    ) -> crate::error::Result<super::platform::Pass> {
        use super::platform::{Heir, Pass, ThreadFacts, ThreadLife, ThreadListing, heir_among};

        let ThreadListing::Whole(threads) = kernel.list()? else {
            return Ok(Pass::Changed);
        };
        let heir = if rules.leaving_first || rules.heir_after {
            heir_among(&threads, |tid| kernel.life(tid))?
        } else {
            Heir::Nobody
        };
        if rules.leaving_first && heir == Heir::Unsettled {
            return Ok(Pass::Changed);
        }
        let mut children = Vec::new();
        let order: Vec<u32> = if rules.youngest_first {
            threads.iter().rev().copied().collect()
        } else {
            threads.clone()
        };
        for tid in order {
            match kernel.children(tid)? {
                Some(list) => children.extend(list),
                None => return Ok(Pass::Changed),
            }
        }
        if rules.heir_after
            && let Heir::Thread(heir) = heir
            && kernel.life(heir)? != ThreadLife::Live
        {
            return Ok(Pass::Changed);
        }
        if rules.relist {
            match kernel.list()? {
                ThreadListing::Whole(mut later) => {
                    let mut first = threads;
                    first.sort_unstable();
                    later.sort_unstable();
                    if first != later {
                        return Ok(Pass::Changed);
                    }
                }
                _ => return Ok(Pass::Changed),
            }
        }
        children.sort_unstable();
        children.dedup();
        Ok(Pass::Read(children))
    }

    /// Every process of three threads the model starts from, with the one child it holds and
    /// whether its threads are kept listed when they end, as a thread a tracer holds is: the first
    /// thread may have ended already, which it can whether kept or not, or the first two, which
    /// only kept threads can have, and the child is in any thread that has not.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn model_processes() -> Vec<Vec<(super::platform::ThreadLife, bool, Vec<u32>)>> {
        use super::platform::ThreadLife::{Ended, Live};

        let mut all = Vec::new();
        for ended in 0..3 {
            for holder in ended..3 {
                for retained in [false, true] {
                    // A thread that is not the first stays listed after it ends only if it is kept.
                    if ended >= 2 && !retained {
                        continue;
                    }
                    let process = (0..3)
                        .map(|at| {
                            (
                                if at < ended { Ended } else { Live },
                                retained,
                                if at == holder {
                                    vec![9_000]
                                } else {
                                    Vec::new()
                                },
                            )
                        })
                        .collect();
                    all.push(process);
                }
            }
        }
        all
    }

    /// The events the model's searches place among the pass's questions: each way up to two of the
    /// three threads can end, with a thread made or not.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn model_event_sets() -> Vec<Vec<kernel_model::Event>> {
        use kernel_model::Event;

        let mut event_sets = Vec::new();
        for ending in [
            vec![1],
            vec![2],
            vec![3],
            vec![1, 2],
            vec![1, 3],
            vec![2, 3],
        ] {
            for make in [false, true] {
                let mut events = Vec::new();
                for tid in ending.iter().copied() {
                    events.push(Event::Begin(tid));
                    events.push(Event::End(tid));
                }
                if make {
                    events.push(Event::Make);
                }
                event_sets.push(events);
            }
        }
        event_sets
    }

    /// The first process the given pass reads wrongly under any order of up to two threads ending
    /// and a thread being made, among the questions of the pass, or none.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn first_wrong_read(
        pass: impl Fn(&mut kernel_model::Kernel) -> crate::error::Result<super::platform::Pass> + Sync,
    ) -> Option<String> {
        use kernel_model::{Kernel, for_each_schedule, wrong_read};

        const QUESTIONS: usize = 9;
        let event_sets = model_event_sets();
        let (event_sets, pass) = (&event_sets, &pass);
        // One process to a thread: the orders are many, and each answer is independent.
        std::thread::scope(|scope| {
            let searches: Vec<_> = model_processes()
                .into_iter()
                .map(|process| {
                    scope.spawn(move || {
                        let threads: Vec<_> = process
                            .iter()
                            .map(|(life, retained, children)| {
                                (*life, *retained, children.as_slice())
                            })
                            .collect();
                        for events in event_sets {
                            let mut found = None;
                            for_each_schedule(events, QUESTIONS, &mut |schedule| {
                                if found.is_some() {
                                    return;
                                }
                                let kernel = Kernel::of(&threads, schedule.to_vec());
                                if let Some(read) = wrong_read(pass, kernel) {
                                    found = Some(format!(
                                        "{process:?} with {schedule:?} read {read:?}"
                                    ));
                                }
                            });
                            if found.is_some() {
                                return found;
                            }
                        }
                        None
                    })
                })
                .collect();
            searches
                .into_iter()
                .filter_map(|search| search.join().expect("a search ends"))
                .next()
        })
    }

    /// The rule that makes a hand-over of children between threads impossible to miss: a child
    /// only ever moves to the first live thread, the pass reads that thread last, looks at it before
    /// and after, and lists the threads again. Over every order in which up to two threads of a
    /// process of three end, with one made, among the pass's questions, a pass that read has every
    /// child there is; and each rule left out lets one through, so none is idle.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_pass_that_reads_has_every_child_whatever_threads_end_or_are_made_while_it_runs() {
        use super::platform::pass_over;

        let all = Rules {
            youngest_first: true,
            heir_after: true,
            relist: true,
            leaving_first: true,
        };
        assert_eq!(first_wrong_read(pass_over), None, "the pass the code makes");
        for (what, rules) in [
            (
                "reading oldest thread first",
                Rules {
                    youngest_first: false,
                    ..all
                },
            ),
            (
                "looking at the first live thread after the pass",
                Rules {
                    heir_after: false,
                    ..all
                },
            ),
            (
                "listing the threads again",
                Rules {
                    relist: false,
                    ..all
                },
            ),
            (
                "a thread ending ahead of the first live one",
                Rules {
                    leaving_first: false,
                    ..all
                },
            ),
        ] {
            assert!(
                first_wrong_read(|kernel| pass_with(rules, kernel)).is_some(),
                "a pass without {what} reads wrong somewhere in the model"
            );
        }
    }

    /// The model's pass with every rule is the pass the code makes, which is what the variants that
    /// leave a rule out are compared with: over every order in which the first two threads end and
    /// a thread is made, among the pass's questions, they give the same answers.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_model_s_pass_with_every_rule_is_the_pass_the_code_makes() {
        use kernel_model::{Event, Kernel, for_each_schedule};

        use super::platform::{Pass, pass_over};

        let all = Rules {
            youngest_first: true,
            heir_after: true,
            relist: true,
            leaving_first: true,
        };
        let shown = |pass: crate::error::Result<Pass>| match pass.expect("the model answers") {
            Pass::Read(read) => format!("read {read:?}"),
            Pass::Changed => "changed".to_owned(),
            Pass::Gone => "gone".to_owned(),
        };
        let mut compared = 0;
        for process in model_processes() {
            let threads: Vec<_> = process
                .iter()
                .map(|(life, retained, children)| (*life, *retained, children.as_slice()))
                .collect();
            let events = [
                Event::Begin(1),
                Event::End(1),
                Event::Begin(2),
                Event::End(2),
                Event::Make,
            ];
            for_each_schedule(&events, 9, &mut |schedule| {
                let mut real = Kernel::of(&threads, schedule.to_vec());
                let mut model = Kernel::of(&threads, schedule.to_vec());
                assert_eq!(
                    shown(pass_over(&mut real)),
                    shown(pass_with(all, &mut model)),
                    "{process:?} with {schedule:?}"
                );
                compared += 1;
            });
        }
        assert!(compared > 100_000, "{compared} orders compared");
    }

    /// A thread made while a pass runs can be handed children by the oldest thread ending, and its
    /// list is in no pass that listed the threads before it: a pass whose threads, listed again,
    /// are not the ones it began with is made again. Other tests' threads come and go beside this
    /// one, so the control is that a pass can read when nothing is made, within a thousand tries,
    /// and the check is that none of twenty passes in which a thread was made, and that read a
    /// list, reads.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_thread_made_during_a_pass_makes_it_a_pass_to_make_again() {
        use std::sync::{Arc, Mutex, mpsc};

        use super::platform::{Pass, children_in_one_pass};

        let me = std::process::id();
        let reads = (0..1_000).any(|_| {
            matches!(
                children_in_one_pass(me).expect("the kernel lists this process's children"),
                Pass::Read(_)
            )
        });
        assert!(reads, "a pass in which nothing was made reads the children");

        let mut made_during = 0;
        for _ in 0..1_000 {
            let (release, parked) = mpsc::channel::<()>();
            let made: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::default();
            let mut parked = Some(parked);
            let during = super::after_each_read(
                {
                    let made = Arc::clone(&made);
                    move |_, file| {
                        // Once the first thread's list has been read, a thread is made.
                        if file.ends_with("/children")
                            && let Some(parked) = parked.take()
                        {
                            *made.lock().expect("the thread") =
                                Some(std::thread::spawn(move || {
                                    let _ = parked.recv();
                                }));
                        }
                    }
                },
                || children_in_one_pass(me),
            )
            .expect("the kernel lists this process's children");
            // A pass that was made again before it read any list made no thread, and says nothing.
            let Some(thread) = made.lock().expect("the thread").take() else {
                continue;
            };
            release.send(()).expect("the made thread is waiting");
            thread.join().expect("it ends");
            assert!(
                matches!(during, Pass::Changed),
                "a pass in which a thread was made is made again"
            );
            made_during += 1;
            if made_during == 20 {
                break;
            }
        }
        assert_eq!(
            made_during, 20,
            "twenty passes read a list and had a thread made"
        );
    }

    /// A listing whose first buffer has room for four entries is made again with a larger one, and
    /// holds every thread that was there throughout.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_listing_that_outgrows_its_buffer_is_made_again_and_holds_every_thread() {
        use std::sync::{Arc, Condvar, Mutex, mpsc};

        let parked = Arc::new((Mutex::new(false), Condvar::new()));
        let (told, tids) = mpsc::channel();
        let threads: Vec<_> = (0..64)
            .map(|_| {
                let parked = Arc::clone(&parked);
                let told = told.clone();
                std::thread::spawn(move || {
                    let own = std::fs::read_link("/proc/thread-self").expect("this thread");
                    let tid: u32 = own
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| name.parse().ok())
                        .expect("a thread identifier");
                    told.send(tid).expect("the test is listening");
                    let (done, ended) = &*parked;
                    drop(
                        ended
                            .wait_while(done.lock().expect("the end"), |done| !*done)
                            .expect("the end"),
                    );
                })
            })
            .collect();
        drop(told);
        let wanted: Vec<u32> = (0..threads.len())
            .map(|_| tids.recv().expect("a thread said its identifier"))
            .collect();
        // Room for four entries of the sixty-four threads and more.
        // Made again while other tests' threads come and go makes a listing short of its count.
        let listed = (0..1_000).find_map(|_| {
            match super::platform::list_threads(std::process::id(), Some(4)).expect("lists") {
                super::platform::ThreadListing::Whole(listed) => Some(listed),
                super::platform::ThreadListing::Partial => None,
                super::platform::ThreadListing::Gone => panic!("this process has gone"),
            }
        });
        let (done, ended) = &*parked;
        *done.lock().expect("the end") = true;
        ended.notify_all();
        for thread in threads {
            thread.join().expect("a thread ends");
        }
        let listed = listed.expect("a listing made whole within a thousand tries");
        for tid in &wanted {
            assert!(listed.contains(tid), "thread {tid} is listed: {listed:?}");
        }
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

    #[test]
    fn the_operating_system_says_which_of_the_three_it_has() {
        let own = std::process::id();
        assert!(
            matches!(
                query_process(own),
                ProcessQuery::Present(identity) if identity.pid.get() == u64::from(own)
            ),
            "this process is there"
        );
        // No process holds the largest identifier on any of these platforms, and the operating
        // system says so rather than failing to answer.
        assert!(
            matches!(query_process(u32::MAX), ProcessQuery::Gone),
            "an identifier nothing holds is gone"
        );
        // Windows answers identifier zero, which the system idle process holds, the way it answers
        // one nothing holds; the reader does not ask, and says it cannot read a start there.
        #[cfg(windows)]
        assert!(
            matches!(query_process(0), ProcessQuery::CannotEstablish(_)),
            "identifier 0 is held, and has no start to read"
        );
    }

    /// A query the operating system did not answer, as each platform produces one.
    fn failed_query() -> ProcessQuery {
        ProcessQuery::CannotEstablish(unavailable(
            "process start identity",
            "the operating system did not answer",
        ))
    }

    #[test]
    fn a_failed_query_is_never_a_process_that_has_gone() {
        // What a guard that asks whether a recorded worker is still running is told: neither
        // running nor ended. A session guard refuses on this answer, as it does on any reading it
        // could not take, rather than passing over the worker.
        let recorded = current_process_start_identity().expect("the kernel answers");
        let pid = std::process::id();
        assert!(
            matches!(
                state_from(&recorded, pid, failed_query()),
                ProcessState::Unknown { ref detail } if detail.contains("did not answer")
            ),
            "a failed query establishes nothing"
        );
        assert_eq!(
            state_from(&recorded, pid, ProcessQuery::Gone),
            ProcessState::Ended,
            "only an answer that no process holds the identifier is an end"
        );
        // And a process this host has just started is not named as ended on a failed query: the
        // failure is the answer.
        assert!(
            started_from(pid, failed_query()).is_err(),
            "a failed query names nothing"
        );
        assert_eq!(
            started_from(pid, ProcessQuery::Gone)
                .expect("an absent process is named")
                .start_value
                .get(),
            START_VALUE_UNREAD
        );
    }

    /// A `FILETIME` a number of whole seconds after the Unix epoch.
    fn filetime_at(seconds: u64) -> u64 {
        UNIX_EPOCH_AS_FILETIME + seconds * FILETIME_UNITS_PER_SECOND
    }

    /// Two Windows processes created under one identifier within one second: the one a helper that
    /// exited ran, and the one that took its identifier. Each is read as the reader reads it, from
    /// the creation time the kernel gives, because Windows will not give an identifier to a new
    /// process on request.
    #[test]
    fn two_creations_under_one_identifier_within_one_second_are_two_processes() {
        let pid = 4242;
        let now = filetime_at(1_800_000_000);
        let created = filetime_at(1_758_700_000) + 1_000_000;
        let read = |created| match windows_answer(pid, WindowsReading::Created(created), now) {
            ProcessQuery::Present(identity) => identity,
            other => panic!("a creation time is a start value: {other:?}"),
        };
        let first = read(created);
        // The next interval the kernel counts, and the last one in the same second.
        for later in [created + 1, filetime_at(1_758_700_001) - 1] {
            let second = read(later);
            assert_ne!(
                first,
                second,
                "a process created {} hundred-nanosecond intervals after another under the same \
                 identifier is another process",
                later - created
            );
            assert_eq!(
                state_from(&first, pid, ProcessQuery::Present(second.clone())),
                ProcessState::Ended,
                "and the first reads as ended once the second holds the identifier"
            );
            // In whole seconds the two are one value, which is what could not tell them apart.
            assert_eq!(
                (created - UNIX_EPOCH_AS_FILETIME) / FILETIME_UNITS_PER_SECOND,
                (later - UNIX_EPOCH_AS_FILETIME) / FILETIME_UNITS_PER_SECOND
            );
        }
    }

    /// The identity a worker of the previous build states for a Windows process: its creation time
    /// in whole seconds since 1970.
    fn in_whole_seconds(identity: &ProcessStartIdentity) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            identity.pid.get(),
            ProcessStartSource::WindowsProcessStartSeconds,
            identity.start_value.get() / FILETIME_UNITS_PER_SECOND,
        )
    }

    #[test]
    fn an_identity_stated_in_whole_seconds_names_the_process_created_in_that_second() {
        let pid = 4242;
        let now = filetime_at(1_800_000_000);
        let read = |created| match windows_answer(pid, WindowsReading::Created(created), now) {
            ProcessQuery::Present(identity) => identity,
            other => panic!("a creation time is a start value: {other:?}"),
        };
        let current = read(filetime_at(1_758_700_000) + 1_000_000);
        let stated = in_whole_seconds(&current);
        assert!(named_in_whole_seconds(&stated, &current));
        // Every creation in that second is named by it. That is the previous build's own reading,
        // kept for the identities that build stated and for nothing this build reads.
        assert!(named_in_whole_seconds(
            &stated,
            &read(filetime_at(1_758_700_001) - 1)
        ));
        assert!(!named_in_whole_seconds(
            &stated,
            &read(filetime_at(1_758_700_001))
        ));
        let mut elsewhere = current.clone();
        elsewhere.pid = kr_protocol::scalars::U64::new(4243);
        assert!(!named_in_whole_seconds(&stated, &elsewhere));
        assert!(
            !named_in_whole_seconds(&current, &current),
            "an identity this build read is compared whole, never cut to seconds"
        );
        // A process created in another second that holds the identifier now is another process,
        // one that holds nothing is gone, and a reading that failed says nothing.
        assert_eq!(
            current_from(
                &stated,
                pid,
                ProcessQuery::Present(read(filetime_at(1_758_700_002)))
            ),
            CurrentProcess::Ended
        );
        assert_eq!(
            current_from(&stated, pid, ProcessQuery::Gone),
            CurrentProcess::Ended
        );
        assert!(matches!(
            current_from(
                &stated,
                pid,
                windows_answer(pid, WindowsReading::Failed("no".to_owned()), now)
            ),
            CurrentProcess::Unknown { .. }
        ));
    }

    /// A worker of the previous build still running after an upgrade states its identity in whole
    /// seconds; this process stands in for it.
    #[cfg(windows)]
    #[test]
    fn a_running_process_stated_in_whole_seconds_is_read_as_running_under_its_finer_identity() {
        let finer = current_process_start_identity().expect("the kernel answers");
        assert_eq!(finer.source, ProcessStartSource::WindowsProcessCreationTime);
        let stated = in_whole_seconds(&finer);
        assert_eq!(
            current_process(&stated),
            CurrentProcess::Running(finer.clone())
        );
        assert_eq!(process_state(&stated), ProcessState::Running);
        let mut another_second = stated.clone();
        another_second.start_value = kr_protocol::scalars::U64::new(stated.start_value.get() - 1);
        assert_eq!(process_state(&another_second), ProcessState::Ended);
        assert_eq!(current_process(&finer), CurrentProcess::Running(finer));
    }

    #[test]
    fn a_windows_reading_that_did_not_happen_is_not_an_absent_process() {
        let pid = 4242;
        let now = filetime_at(1_800_000_000);
        let started = filetime_at(1_700_000_000);
        // The kernel would not open the process, or would not give its times: the reading did not
        // happen, and a process it did not find is not a process that has gone.
        let unread = windows_answer(
            pid,
            WindowsReading::Failed("Access is denied.".to_owned()),
            now,
        );
        assert!(
            matches!(unread, ProcessQuery::CannotEstablish(ref error) if error.to_string().contains("Access is denied")),
            "a failed reading is not an absent process: {unread:?}"
        );
        // Carried through to what a session guard asks, the failed reading refuses rather than
        // passing over the worker it was asked about.
        let recorded = match windows_answer(pid, WindowsReading::Created(started), now) {
            ProcessQuery::Present(identity) => identity,
            other => panic!("a creation time is a start value: {other:?}"),
        };
        assert_eq!(recorded.pid.get(), u64::from(pid));
        assert_eq!(recorded.source, WINDOWS_START_SOURCE);
        let failed = || WindowsReading::Failed("the kernel did not answer".to_owned());
        assert!(matches!(
            state_from(&recorded, pid, windows_answer(pid, failed(), now)),
            ProcessState::Unknown { .. }
        ));
        assert!(started_from(pid, windows_answer(pid, failed(), now)).is_err());

        // The kernel has no process under the identifier: it has gone.
        assert!(matches!(
            windows_answer(pid, WindowsReading::Absent, now),
            ProcessQuery::Gone
        ));
        assert_eq!(
            state_from(
                &recorded,
                pid,
                windows_answer(pid, WindowsReading::Absent, now)
            ),
            ProcessState::Ended
        );
        // Opened, with a creation time that is not one: zero, which the kernel never records for a
        // process it created, and one before 1970. Neither identifies the process, and nothing is
        // concluded from comparing it.
        for unreadable in [0, UNIX_EPOCH_AS_FILETIME - 1] {
            let answer = || windows_answer(pid, WindowsReading::Created(unreadable), now);
            assert!(
                matches!(answer(), ProcessQuery::CannotEstablish(_)),
                "{unreadable} is not a creation time"
            );
            assert!(matches!(
                state_from(&recorded, pid, answer()),
                ProcessState::Unknown { .. }
            ));
            assert!(started_from(pid, answer()).is_err());
        }
        // The first instant of 1970 is a time a process could have started.
        assert!(matches!(
            windows_answer(pid, WindowsReading::Created(UNIX_EPOCH_AS_FILETIME), now),
            ProcessQuery::Present(_)
        ));
        // Opened with its creation time: the process, and the one recorded when the values agree.
        assert!(matches!(
            windows_answer(pid, WindowsReading::Created(started), now),
            ProcessQuery::Present(identity) if identity == recorded
        ));
        assert_eq!(
            state_from(
                &recorded,
                pid,
                windows_answer(
                    pid,
                    WindowsReading::Created(started + FILETIME_UNITS_PER_SECOND),
                    now
                )
            ),
            ProcessState::Ended,
            "a process created a second later is another process"
        );
        // A clock stepped back since the process started still identifies it, within a day.
        assert!(matches!(
            windows_answer(
                pid,
                WindowsReading::Created(now + 60 * FILETIME_UNITS_PER_SECOND),
                now
            ),
            ProcessQuery::Present(_)
        ));
        assert!(matches!(
            windows_answer(
                pid,
                WindowsReading::Created(now + WINDOWS_START_AHEAD + 1),
                now
            ),
            ProcessQuery::CannotEstablish(_)
        ));
    }

    /// When a System process could have been created: 2026-09-21T08:43:08.6406893Z, in hundreds of
    /// nanoseconds since 1601.
    const SYSTEM_CREATED: i64 = 134_344_537_886_406_893;

    /// Where a built process list is taken to have been written. Any address serves: nothing
    /// follows one, and an address in the list only says where in the list something lies.
    const LIST_BASE: usize = 0x0231_7000_0000;

    /// The length of the fixed part of an entry in the kernel's process list on 64-bit Windows,
    /// before the entry's thread records and its name.
    const ENTRY_FIXED: usize = 256;

    /// A process list laid out the way the kernel lays one out, built entry by entry: each entry's
    /// fixed part, then its name's characters, at an address counted from [`LIST_BASE`].
    struct BuiltList {
        bytes: Vec<u8>,
        last: Option<usize>,
    }

    impl BuiltList {
        const fn new() -> Self {
            Self {
                bytes: Vec::new(),
                last: None,
            }
        }

        /// Adds an entry for `process`, named `name`, created at `created`.
        fn entry(mut self, process: u64, name: &str, created: i64) -> Self {
            use windows_boot::{
                ENTRY_CREATED, ENTRY_NAME_ADDRESS, ENTRY_NAME_CAPACITY, ENTRY_NAME_LENGTH,
                ENTRY_NEXT, ENTRY_PROCESS,
            };
            let start = self.bytes.len();
            if let Some(last) = self.last {
                let next = u32::try_from(start - last).expect("a list this short");
                self.bytes[last + ENTRY_NEXT..last + ENTRY_NEXT + 4]
                    .copy_from_slice(&next.to_le_bytes());
            }
            let characters: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let address = if characters.is_empty() {
                0
            } else {
                u64::try_from(LIST_BASE + start + ENTRY_FIXED).expect("an address")
            };
            let length = u16::try_from(characters.len()).expect("a name this short");
            // The kernel gives a name room for a terminator after its characters.
            let capacity = if characters.is_empty() { 0 } else { length + 2 };
            let mut entry = vec![0_u8; ENTRY_FIXED];
            entry[ENTRY_CREATED..ENTRY_CREATED + 8].copy_from_slice(&created.to_le_bytes());
            entry[ENTRY_NAME_LENGTH..ENTRY_NAME_LENGTH + 2].copy_from_slice(&length.to_le_bytes());
            entry[ENTRY_NAME_CAPACITY..ENTRY_NAME_CAPACITY + 2]
                .copy_from_slice(&capacity.to_le_bytes());
            entry[ENTRY_NAME_ADDRESS..ENTRY_NAME_ADDRESS + 8]
                .copy_from_slice(&address.to_le_bytes());
            entry[ENTRY_PROCESS..ENTRY_PROCESS + 8].copy_from_slice(&process.to_le_bytes());
            entry.extend(&characters);
            entry.resize(entry.len() + usize::from(capacity - length), 0);
            entry.resize(entry.len().next_multiple_of(8), 0);
            self.bytes.extend(entry);
            self.last = Some(start);
            self
        }

        fn bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// A list as a host has it: the idle process, which the kernel names nothing, the System
    /// process, and one more.
    fn host_list(system_created: i64, other_created: i64) -> Vec<u8> {
        BuiltList::new()
            .entry(0, "", 0)
            .entry(4, "System", system_created)
            .entry(128, "Registry", other_created)
            .bytes()
    }

    /// Where the System process's entry starts in [`host_list`]: after the idle process's fixed
    /// part, since it has no name.
    const SYSTEM_ENTRY: usize = ENTRY_FIXED;

    fn created_in(list: &[u8]) -> Result<u64> {
        windows_boot::system_process_created(list, LIST_BASE)
    }

    #[test]
    fn a_windows_boot_identity_is_the_boot_counter_and_the_system_process_creation_time() {
        let created = u64::try_from(SYSTEM_CREATED).expect("a creation time");
        let value = windows_boot::value(3, created);
        assert_eq!(value[..4], 3_u32.to_be_bytes());
        assert_eq!(value[4..], created.to_be_bytes());
        // One boot: the same counter and the same creation time, read again, are the same identity.
        assert_eq!(windows_boot::value(3, created), value);
        // Either part changing is another boot, whether or not the other changed with it: a counter
        // that advanced while the creation time repeated, a creation time that moved while the
        // counter repeated, and both.
        assert_ne!(windows_boot::value(4, created), value);
        assert_ne!(windows_boot::value(3, created + 1), value);
        assert_ne!(windows_boot::value(4, created + 1), value);
        assert_ne!(windows_boot::value(2, created), value);
        assert_ne!(windows_boot::value(3, created - 1), value);
    }

    #[test]
    fn the_system_process_creation_time_is_read_from_its_own_entry() {
        let created = u64::try_from(SYSTEM_CREATED).expect("a creation time");
        assert_eq!(
            created_in(&host_list(SYSTEM_CREATED, SYSTEM_CREATED + 12_345))
                .expect("the System process"),
            created
        );
        // Every other process may start, end or change in between two reads; only the System
        // process's own entry decides.
        let busier = BuiltList::new()
            .entry(0, "", 0)
            .entry(4, "System", SYSTEM_CREATED)
            .entry(812, "svchost.exe", SYSTEM_CREATED + 99)
            .entry(9_000, "pwsh.exe", SYSTEM_CREATED + 5_000_000_000)
            .bytes();
        assert_eq!(created_in(&busier).expect("the System process"), created);
        // Where the System process is not second, it is still found.
        let later = BuiltList::new()
            .entry(0, "", 0)
            .entry(128, "Registry", SYSTEM_CREATED)
            .entry(4, "System", SYSTEM_CREATED + 7)
            .bytes();
        assert_eq!(created_in(&later).expect("the System process"), created + 7);
        // Another boot's System process was created at another time.
        assert_eq!(
            created_in(&host_list(SYSTEM_CREATED + 1, 0)).expect("the System process"),
            created + 1
        );
    }

    #[test]
    fn a_process_list_that_does_not_name_the_system_process_names_no_boot() {
        let without = BuiltList::new()
            .entry(0, "", 0)
            .entry(128, "Registry", SYSTEM_CREATED)
            .bytes();
        assert!(created_in(&without).is_err(), "no process 4");
        let renamed = BuiltList::new()
            .entry(0, "", 0)
            .entry(4, "Registry", SYSTEM_CREATED)
            .bytes();
        assert!(
            created_in(&renamed).is_err(),
            "process 4 under another name"
        );
        let unnamed = BuiltList::new()
            .entry(0, "", 0)
            .entry(4, "", SYSTEM_CREATED)
            .bytes();
        assert!(created_in(&unnamed).is_err(), "process 4 with no name");
        let twice = BuiltList::new()
            .entry(0, "", 0)
            .entry(4, "System", SYSTEM_CREATED)
            .entry(4, "System", SYSTEM_CREATED + 1)
            .bytes();
        assert!(created_in(&twice).is_err(), "process 4 listed twice");
        for created in [0, -1, i64::MIN] {
            assert!(
                created_in(&host_list(created, 1)).is_err(),
                "{created} is not a creation time"
            );
        }
        // The same list read as if written somewhere else: the name's address points at other
        // bytes of the list, before it, or past it.
        let list = host_list(SYSTEM_CREATED, 1);
        for base in [LIST_BASE + 8, LIST_BASE + list.len() * 2, 0] {
            assert!(
                windows_boot::system_process_created(&list, base).is_err(),
                "a list read at {base:#x} rather than where it was written"
            );
        }
    }

    #[test]
    fn a_process_list_that_points_outside_itself_names_no_boot() {
        use windows_boot::{ENTRY_NAME_CAPACITY, ENTRY_NAME_LENGTH, ENTRY_NEXT, ENTRY_READ};

        let list = host_list(SYSTEM_CREATED, 1);
        assert!(created_in(&list).is_ok());
        let with = |at: usize, bytes: &[u8]| {
            let mut changed = list.clone();
            changed[at..at + bytes.len()].copy_from_slice(bytes);
            changed
        };
        // Shorter than an entry's fields, or cut inside the System process's entry.
        assert!(created_in(&[]).is_err());
        assert!(created_in(&list[..ENTRY_READ - 1]).is_err());
        assert!(created_in(&list[..SYSTEM_ENTRY + ENTRY_READ - 1]).is_err());
        // A next entry that overlaps an entry's fields, begins off an eight-byte boundary, or lies
        // past the end: before the System process, at it, and after it, since the whole list is
        // checked.
        let system_next = u32::from_le_bytes(
            list[SYSTEM_ENTRY + ENTRY_NEXT..SYSTEM_ENTRY + ENTRY_NEXT + 4]
                .try_into()
                .expect("four bytes"),
        );
        let last = SYSTEM_ENTRY + usize::try_from(system_next).expect("an offset");
        for entry in [0, SYSTEM_ENTRY, last] {
            for next in [8, system_next + 4, u32::MAX] {
                assert!(
                    created_in(&with(entry + ENTRY_NEXT, &next.to_le_bytes())).is_err(),
                    "the entry at byte {entry} naming its next {next} bytes on"
                );
            }
        }
        assert!(
            created_in(&with(last + ENTRY_NEXT, &1_024_u32.to_le_bytes())).is_err(),
            "a last entry naming a next one past the end"
        );
        // A name whose length is odd, exceeds the capacity its entry states, or runs past the end
        // of the list.
        let name_length = SYSTEM_ENTRY + ENTRY_NAME_LENGTH;
        assert!(created_in(&with(name_length, &11_u16.to_le_bytes())).is_err());
        assert!(
            created_in(&with(
                SYSTEM_ENTRY + ENTRY_NAME_CAPACITY,
                &10_u16.to_le_bytes()
            ))
            .is_err()
        );
        let beyond = [65_534_u16.to_le_bytes(), u16::MAX.to_le_bytes()].concat();
        assert!(created_in(&with(name_length, &beyond)).is_err());
    }

    #[test]
    fn the_process_list_is_asked_for_again_with_room_while_it_grows() {
        use windows_boot::{LIST_FIRST, LIST_TOO_SHORT};

        let list = host_list(SYSTEM_CREATED, 1);
        let needed = LIST_FIRST + 100_000;
        let mut offered = Vec::new();
        let read = windows_boot::read_process_list(|buffer| {
            offered.push(buffer.len());
            if buffer.len() < needed {
                return (LIST_TOO_SHORT, u32::try_from(needed).expect("a length"));
            }
            buffer[..list.len()].copy_from_slice(&list);
            (0, u32::try_from(list.len()).expect("a length"))
        })
        .expect("the list, on the second call");
        assert_eq!(
            offered.len(),
            2,
            "one call too short, one that fits: {offered:?}"
        );
        assert!(
            offered[1] >= needed + needed / 2,
            "the second call has room for what the kernel said it needed, and more: {offered:?}"
        );
        assert_eq!(
            read.bytes(),
            list.as_slice(),
            "only the bytes the kernel wrote are read"
        );
        assert_eq!(
            read.base() % 8,
            0,
            "the kernel is given an eight-byte-aligned buffer"
        );
    }

    #[test]
    fn a_process_list_the_kernel_refuses_or_keeps_outgrowing_is_not_read() {
        use windows_boot::{LIST_CALLS, LIST_MOST, LIST_TOO_SHORT};

        let access_denied = 0xC000_0022_u32.cast_signed();
        assert!(matches!(
            windows_boot::read_process_list(|_| (access_denied, 0)),
            Err(ref why) if why.contains("0xc0000022")
        ));
        let mut calls = 0;
        let mut largest = 0;
        let outgrown = windows_boot::read_process_list(|buffer| {
            calls += 1;
            largest = largest.max(buffer.len());
            (LIST_TOO_SHORT, u32::MAX)
        });
        assert!(outgrown.is_err());
        assert_eq!(calls, LIST_CALLS);
        assert!(largest <= LIST_MOST, "{largest} bytes");
        // A length longer than the buffer is not a length the kernel wrote into it.
        let overlong = windows_boot::read_process_list(|buffer| {
            (0, u32::try_from(buffer.len() + 8).expect("a length"))
        });
        assert!(overlong.is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn libproc_failures_are_told_apart_by_their_error_number() {
        use super::platform::error_number;

        let absent = "return code = 0, errno = 3, message = 'No such process'";
        assert_eq!(
            error_number(absent),
            Some(rustix::io::Errno::SRCH.raw_os_error())
        );
        assert_eq!(
            error_number("return code = -1, errno = 1, message = 'Operation not permitted'"),
            Some(1)
        );
        assert_eq!(
            error_number("No such process"),
            None,
            "a message without the number says nothing"
        );
    }
}
