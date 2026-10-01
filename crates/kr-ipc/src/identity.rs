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
/// process's threads, and nothing else is read. A process that has gone is the parent of nothing.
/// A kernel that is built without those lists, and a reading that failed for any other reason, is
/// an error here rather than an empty answer, so a caller never reads "no children" into it. So is
/// a process whose threads keep leaving while they are read: a pass in which the listing of them
/// ended early, or a listed thread had gone, is made again, since the children of such a thread are
/// in a list the pass may have read already or never reached.
///
/// What the kernel lists is not a promise: its list of a thread's children can skip one that was
/// there throughout when children ahead of it exit while it is read, and a thread that ends or
/// calls `exec` moves children between lists. So a process is read again until two readings agree,
/// and a process whose threads or children keep changing is an error here, not a guess. A process
/// that calls `exec` while it is read can still be read wrong when the next reading that reads
/// any children misses the same ones.
///
/// # Errors
///
/// Returns [`IpcError::IdentityUnavailable`] when the process cannot be read, when the kernel
/// keeps no list of children, or when its threads or children never hold still long enough to be read.
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
    enum Pass {
        /// The process has gone.
        Gone,
        /// Every child its threads held.
        Read(Vec<u32>),
        /// A thread left, or the listing of them was short, so the pass says nothing.
        Changed,
    }

    /// Where one thread of a process stands.
    #[derive(PartialEq)]
    enum ThreadState {
        /// It is running or waiting.
        Alive,
        /// It has ended and handed its children on, and the kernel keeps it for now: the process's
        /// first thread until the rest has gone, and a thread whose end a tracer has yet to collect.
        Ended,
        /// The kernel has taken it away, or is taking it.
        Gone,
    }

    /// Reads where a thread stands from its own `stat`.
    ///
    /// A thread that ends hands its children on and marks itself ended in one step under the
    /// kernel's lock on the process tree, which a read of its children takes too: a thread that is
    /// running when its state is read after its children were had them when they were read. One
    /// that has ended by then has already handed them on, and the pass sees whether they went to a
    /// thread it has not listed.
    fn thread_state(pid: u32, tid: u32) -> Result<ThreadState> {
        match read_process_file(pid, &format!("task/{tid}/stat")) {
            Ok(text) => Ok(match state_character(&text) {
                Some('Z') => ThreadState::Ended,
                Some('X' | 'x') => ThreadState::Gone,
                _ => ThreadState::Alive,
            }),
            Err(error) if gone(&error) => Ok(ThreadState::Gone),
            Err(error) => Err(unavailable(
                "children of a process",
                format!("/proc/{pid}/task/{tid}/stat: {error}"),
            )),
        }
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
    /// A thread that ends hands its children to a thread that is left, and a thread that has ended
    /// before its children are read has none. A pass in which a thread that was running when it
    /// began has ended by its end is made again, since its children may have gone to a thread whose
    /// list was read already; and so is a pass whose threads, listed again at its end, are not the
    /// ones it began with, since they may have gone to a thread made after it began. A thread that
    /// ended before the pass began is as it was throughout: the first thread of a process that left
    /// while the rest run stays in the list with no children, and so does a thread whose end a
    /// tracer has not yet collected.
    fn children_in_one_pass(pid: u32) -> Result<Pass> {
        let threads = match list_threads(pid, None)? {
            ThreadListing::Gone => return Ok(Pass::Gone),
            ThreadListing::Whole(threads) => threads,
            ThreadListing::Partial => return Ok(Pass::Changed),
        };
        let mut running = Vec::new();
        for &tid in &threads {
            match thread_state(pid, tid)? {
                ThreadState::Alive => running.push(tid),
                ThreadState::Ended => {}
                ThreadState::Gone => return Ok(Pass::Changed),
            }
        }
        let mut children = Vec::new();
        for &tid in &threads {
            match read_process_file(pid, &format!("task/{tid}/children")) {
                Ok(list) => children.extend(
                    list.split_whitespace()
                        .filter_map(|child| child.parse::<u32>().ok()),
                ),
                // A thread whose list is not there: one that is going, which another pass sees as
                // changed, or a kernel that keeps no lists, which no pass will change.
                Err(error) if gone(&error) => {
                    if kernel_keeps_children_lists() {
                        return Ok(Pass::Changed);
                    }
                    return Err(unavailable(
                        "children of a process",
                        format!("/proc/{pid}/task/{tid}/children: {error}"),
                    ));
                }
                Err(error) => {
                    return Err(unavailable(
                        "children of a process",
                        format!("/proc/{pid}/task/{tid}/children: {error}"),
                    ));
                }
            }
        }
        for tid in running {
            if thread_state(pid, tid)? != ThreadState::Alive {
                return Ok(Pass::Changed);
            }
        }
        match list_threads(pid, None)? {
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
        // throughout both. The same holds of a thread that ended and handed its children to a list
        // already read, and of one that called `exec` and took the first thread's identifier after
        // that thread's list was read, which no comparison of identifiers sees: the next pass reads
        // the children where they are. What is not closed is a process that calls `exec` while it
        // is read and whose next pass that reads any misses the same children, by another `exec`
        // or by a skip of the kernel's list as another child is collected: no count of passes or
        // time bounds that, and nothing short of freezing the process closes it.
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
        WaitForSingleObject,
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

    /// A thread that leaves hands its children to the first thread of the process. A reading that
    /// has read that thread's list by then, and finds the leaving thread gone, has the child in
    /// neither, so it reads again.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_child_whose_thread_leaves_mid_reading_is_still_listed() {
        use std::sync::{Arc, Mutex, mpsc};

        let me = std::process::id();
        let (started, child) = mpsc::channel();
        let (leave, leaving) = mpsc::channel::<()>();
        let owner = std::thread::spawn(move || {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("a child");
            started.send(child.id()).expect("the test is waiting");
            let _ = leaving.recv();
            // The thread ends with the child running, and the process's first thread has it from
            // there.
            child
        });
        let child_id = child.recv().expect("the owner started a child");
        let held = Arc::new(Mutex::new(None));
        let mut owner = Some((owner, leave));
        let first = format!("task/{me}/children");
        let children = super::after_each_read(
            {
                let held = Arc::clone(&held);
                move |_, file| {
                    // Once the first thread's list has been read, the owner leaves.
                    if file == first
                        && let Some((owner, leave)) = owner.take()
                    {
                        leave.send(()).expect("the owner is waiting");
                        *held.lock().expect("the child") = Some(owner.join().expect("it ends"));
                    }
                }
            },
            || super::children_of(me),
        )
        .expect("the kernel lists this process's children");
        let mut child = held
            .lock()
            .expect("the child")
            .take()
            .expect("the owner's child");
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            children.contains(&child_id),
            "the child is listed after its thread left: {children:?}"
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
        let listed = (0..1_000)
            .find_map(|_| {
                match super::platform::list_threads(std::process::id(), Some(4)).expect("lists") {
                    super::platform::ThreadListing::Whole(listed) => Some(listed),
                    super::platform::ThreadListing::Partial => None,
                    super::platform::ThreadListing::Gone => panic!("this process has gone"),
                }
            })
            .expect("a listing made whole within a thousand tries");
        let (done, ended) = &*parked;
        *done.lock().expect("the end") = true;
        ended.notify_all();
        for thread in threads {
            thread.join().expect("a thread ends");
        }
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
