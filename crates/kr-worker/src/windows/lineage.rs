//! Where a Windows process came from and when it started, read from the kernel and decided here.
//!
//! Windows keeps the identifier of the process that created a process after that process has
//! ended, and gives the identifier to a later one, so a parent link read from the kernel proves
//! nothing on its own. What proves it is the order the kernel recorded the two starts in: a parent
//! was running before its child existed. The wall-clock creation time that identifies a process
//! cannot say that, because the clock can be stepped back, so the order is read from the kernel's
//! interrupt clock instead: `NtQueryInformationProcess`'s `ProcessUptimeInformation` (class 88)
//! answers the interrupt time now and how long ago the process was created, and the difference is
//! the process's start on a clock that counts sleep and never goes back within a boot.
//!
//! Three questions are asked here, and everything that places a launch or a bridge on this
//! platform asks them and nothing else:
//!
//! - [`monotonic_start`]: when a process started, on the interrupt clock.
//! - [`parent_of`]: which process a process was started by, when the kernel's record is still
//!   about that process: the parent is running, was started no later than its child, and nothing
//!   changed while it was read.
//! - [`started_by`]: whether that process is a named one.
//!
//! A reading that cannot be taken, or that the kernel answers implausibly, is an error and never
//! an absent record. The class is documented nowhere, so the first use of this module checks it
//! against a process it creates itself: [`start_clock`].
//!
//! The decisions are written over a table of readings, so that a test can put a replaced parent, a
//! parent that started after its child or a reading that changed exactly where it wants one, which
//! no real kernel will do on request.

use kr_protocol::identity::ProcessStartIdentity;

/// The processes whose start the interrupt clock records: a Windows process's identifier is its
/// 32-bit value.
fn pid_of(identity: &ProcessStartIdentity) -> Option<u32> {
    u32::try_from(identity.pid.get()).ok()
}

/// What the interrupt clock answered for one process, as the kernel's class 88 lays it out.
///
/// The kernel writes this structure through a pointer, so its layout is the C one and its size and
/// the offset of each field the kernel's are checked at compile time below.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Uptime {
    /// The interrupt time now, in hundreds of nanoseconds.
    pub query_interrupt_time: u64,
    /// The interrupt time now that does not count sleep.
    pub query_unbiased_time: u64,
    /// The interrupt time the process ended at, and zero while it runs.
    pub end_interrupt_time: u64,
    /// How long ago the process was created, on the same clock.
    pub time_since_creation: u64,
    /// How long the process has run.
    pub uptime: u64,
    /// How long it has been suspended.
    pub suspended_time: u64,
    /// The class's own flags.
    pub flags: u32,
    /// Padding the kernel writes.
    pub padding: u32,
}

// `PROCESS_UPTIME_INFORMATION`: six 64-bit counters, then a 32-bit union of flags and counts, padded
// to the structure's 8-byte alignment.
const _: () = {
    assert!(std::mem::size_of::<Uptime>() == 56);
    assert!(std::mem::align_of::<Uptime>() == 8);
    assert!(std::mem::offset_of!(Uptime, query_interrupt_time) == 0);
    assert!(std::mem::offset_of!(Uptime, query_unbiased_time) == 8);
    assert!(std::mem::offset_of!(Uptime, end_interrupt_time) == 16);
    assert!(std::mem::offset_of!(Uptime, time_since_creation) == 24);
    assert!(std::mem::offset_of!(Uptime, uptime) == 32);
    assert!(std::mem::offset_of!(Uptime, suspended_time) == 40);
    assert!(std::mem::offset_of!(Uptime, flags) == 48);
};

/// What one reading of a process said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Look {
    /// No process holds the identifier, or the one that did has ended.
    Absent,
    /// The process, and what the kernel records about it.
    Present(Reading),
}

/// What the kernel records about one running process, read together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reading {
    /// The process's start identity, read before and after the rest and equal both times.
    pub identity: ProcessStartIdentity,
    /// The identifier of the process that created it, which survives that process's end.
    pub parent: u32,
    /// When it started, on the interrupt clock.
    pub started: u64,
}

/// The kernel's records, behind a seam a test can script.
pub(crate) trait Table {
    /// Reads one process.
    ///
    /// # Errors
    ///
    /// Returns why the kernel would not answer or answered what cannot be believed. A process that
    /// is not there is [`Look::Absent`], never an error, and an error is never read as absence.
    fn look(&self, pid: u32) -> Result<Look, String>;
}

/// Checks one answer of class 88 and returns the start it carries.
///
/// The answer must be of a process that is still running (the end time is zero), must carry the
/// interrupt time now (an answer the kernel did not fill in reads zero), must say the process was
/// created no earlier than the clock began, and the difference must not overflow: anything else is
/// not a reading of a start. A process read within the interrupt tick it was created in says it
/// was created zero ago, which is a start like any other.
pub(crate) fn start_in(answer: &Uptime) -> Result<Option<u64>, String> {
    if answer.end_interrupt_time != 0 {
        return Ok(None);
    }
    if answer.query_interrupt_time == 0 {
        return Err("the kernel gave no interrupt time with the process's age".to_owned());
    }
    answer
        .query_interrupt_time
        .checked_sub(answer.time_since_creation)
        .filter(|start| *start > 0)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "the kernel says the process was created {} ago, before the clock it says so on \
                 began ({})",
                answer.time_since_creation, answer.query_interrupt_time
            )
        })
}

/// Checks that a start lies between the interrupt times read just before and just after the
/// process was created, which is what a process created between the two readings must satisfy on
/// a clock the readings and the start share.
pub(crate) fn lies_between(start: u64, before: u64, after: u64) -> Result<(), String> {
    if before <= start && start <= after {
        Ok(())
    } else {
        Err(format!(
            "a process created between the interrupt times {before} and {after} reads as having \
             started at {start}"
        ))
    }
}

/// Returns the process that started `child`, as the kernel's record names it, when that record is
/// still about that process.
///
/// `child` is read, then its parent, then `child` again, and the two readings of the child must be
/// equal. The parent must be running and must have started no later than its child: a parent
/// identifier that names an ended process, or one that a later process holds now, fails the
/// second, and a start that was moved by a clock that stepped back fails nothing here because the
/// order is the interrupt clock's.
///
/// # Errors
///
/// Returns why no parent can be named: the child is not there or is not the process described, it
/// has no parent, the parent has ended or started after it, or a reading changed meanwhile.
pub(crate) fn parent_in(
    table: &impl Table,
    child: &ProcessStartIdentity,
) -> Result<ProcessStartIdentity, String> {
    let pid = pid_of(child).ok_or_else(|| format!("{} is not a process identifier", child.pid))?;
    let first = present(table.look(pid)?, "the process")?;
    if !first.identity.matches(child) {
        return Err(format!(
            "process {pid} is not the process described: it started at {} and the description \
             says {}",
            first.identity.start_value, child.start_value
        ));
    }
    if first.parent == 0 {
        return Err(format!("process {pid} records no parent"));
    }
    let parent = present(table.look(first.parent)?, "the parent")?;
    if parent.started > first.started {
        return Err(format!(
            "the process that holds identifier {} started after process {pid} did, so it is not \
             the one that started it",
            first.parent
        ));
    }
    let again = present(table.look(pid)?, "the process")?;
    if again != first {
        return Err(format!("process {pid} changed while it was read"));
    }
    Ok(parent.identity)
}

/// Returns whether `parent` is the process that started `child`.
///
/// # Errors
///
/// Returns why it cannot be said: what [`parent_in`] refuses, or that another process started it.
pub(crate) fn started_by_in(
    table: &impl Table,
    child: &ProcessStartIdentity,
    parent: &ProcessStartIdentity,
) -> Result<(), String> {
    let found = parent_in(table, child)?;
    if found.matches(parent) {
        Ok(())
    } else {
        Err(format!(
            "process {} was started by process {}, not by process {}",
            child.pid, found.pid, parent.pid
        ))
    }
}

/// Returns when `process` started, on the interrupt clock, where it is the process described.
///
/// # Errors
///
/// Returns why it cannot be said: the process has ended or is another one now, or the reading
/// failed.
pub(crate) fn start_in_table(
    table: &impl Table,
    process: &ProcessStartIdentity,
) -> Result<u64, String> {
    let pid =
        pid_of(process).ok_or_else(|| format!("{} is not a process identifier", process.pid))?;
    let reading = present(table.look(pid)?, "the process")?;
    if reading.identity.matches(process) {
        Ok(reading.started)
    } else {
        Err(format!(
            "process {pid} is not the process described: it started at {} and the description \
             says {}",
            reading.identity.start_value, process.start_value
        ))
    }
}

/// Returns the reading of a process that is there, and why it is not otherwise.
fn present(look: Look, what: &str) -> Result<Reading, String> {
    match look {
        Look::Present(reading) => Ok(reading),
        Look::Absent => Err(format!("{what} has ended")),
    }
}

#[cfg(windows)]
pub use platform::{interrupt_now, monotonic_start, parent_of, start_clock, started_by};

/// The kernel's own readings: the calls with no safe form, and the table they make.
#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "asking the kernel about a process is a call with out-parameters that only the \
                  caller can promise"
    )]

    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::os::windows::process::CommandExt as _;
    use std::sync::OnceLock;

    use kr_ipc::identity::ProcessQuery;
    use kr_protocol::identity::ProcessStartIdentity;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE};
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, GetCurrentProcess, OpenProcess,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{
        Look, Reading, Table, Uptime, lies_between, parent_in, start_in, start_in_table,
        started_by_in,
    };

    /// `ProcessBasicInformation`, which names the process that created the one asked about.
    const PROCESS_BASIC_INFORMATION: u32 = 0;
    /// `ProcessUptimeInformation`: the interrupt time now and how long ago the process was
    /// created.
    const PROCESS_UPTIME_INFORMATION: u32 = 88;

    /// `PROCESS_BASIC_INFORMATION`, which the kernel fills in.
    #[repr(C)]
    struct Basic {
        exit_status: i32,
        peb: *mut std::ffi::c_void,
        affinity: usize,
        priority: i32,
        id: usize,
        parent: usize,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: HANDLE,
            class: u32,
            information: *mut std::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    /// Reads class 88 of an open process.
    fn uptime(process: HANDLE) -> Result<Uptime, String> {
        let mut answer = Uptime::default();
        // SAFETY: the handle is open for the call and the answer is a local this thread owns, of
        // the size the call is told.
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_UPTIME_INFORMATION,
                std::ptr::from_mut(&mut answer).cast(),
                u32::try_from(std::mem::size_of::<Uptime>()).unwrap_or(0),
                std::ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(format!(
                "the kernel would not say when the process started (status {status:#x})"
            ));
        }
        Ok(answer)
    }

    /// Reads which process created an open process.
    fn parent(process: HANDLE) -> Result<u32, String> {
        // SAFETY: all zeroes is a structure of integers and a null pointer.
        let mut basic: Basic = unsafe { std::mem::zeroed() };
        // SAFETY: as for the other query: an open handle and a local of the declared size.
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_BASIC_INFORMATION,
                std::ptr::from_mut(&mut basic).cast(),
                u32::try_from(std::mem::size_of::<Basic>()).unwrap_or(0),
                std::ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(format!(
                "the kernel would not say which process created the process (status {status:#x})"
            ));
        }
        u32::try_from(basic.parent).map_err(|_| {
            format!(
                "the kernel names {} as a process's parent, which is not an identifier",
                basic.parent
            )
        })
    }

    /// Opens a process to ask about it, or says it is not there.
    fn open(pid: u32) -> Result<Option<OwnedHandle>, String> {
        // SAFETY: the arguments are values; the call returns a handle this process owns, or null.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            let failure = std::io::Error::last_os_error();
            // The system says "invalid parameter" for an identifier no process holds; every other
            // failure, an access denied among them, is a reading that was not taken.
            return if failure
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
                == Some(ERROR_INVALID_PARAMETER)
            {
                Ok(None)
            } else {
                Err(format!("process {pid} could not be opened: {failure}"))
            };
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        Ok(Some(unsafe { OwnedHandle::from_raw_handle(handle.cast()) }))
    }

    /// The operating system's own process table.
    struct Kernel;

    impl Kernel {
        fn identity(pid: u32) -> Result<Option<ProcessStartIdentity>, String> {
            match kr_ipc::identity::query_process(pid) {
                ProcessQuery::Present(identity) => Ok(Some(identity)),
                ProcessQuery::Gone => Ok(None),
                ProcessQuery::CannotEstablish(error) => {
                    Err(format!("process {pid} cannot be identified: {error}"))
                }
            }
        }
    }

    impl Table for Kernel {
        fn look(&self, pid: u32) -> Result<Look, String> {
            let Some(before) = Self::identity(pid)? else {
                return Ok(Look::Absent);
            };
            let Some(process) = open(pid)? else {
                return Ok(Look::Absent);
            };
            let created_by = parent(process.as_raw_handle().cast())?;
            let answer = uptime(process.as_raw_handle().cast())?;
            drop(process);
            // The identifier is the process's own only if the identity read after is the one read
            // before: one that was ended and given to another between them is not read.
            if Self::identity(pid)?.as_ref() != Some(&before) {
                return Err(format!("process {pid} changed while it was read"));
            }
            Ok(start_in(&answer)?.map_or(Look::Absent, |started| {
                Look::Present(Reading {
                    identity: before,
                    parent: created_by,
                    started,
                })
            }))
        }
    }

    /// Whether the kernel's class 88 can be believed on this machine, decided once.
    static CLOCK: OnceLock<Result<(), String>> = OnceLock::new();

    /// Checks that the interrupt clock this module orders starts by answers plausibly here.
    ///
    /// Class 88 is undocumented, so the first use of it creates a process that never runs and asks
    /// it: the start the kernel gives must lie between the interrupt times this process read just
    /// before and just after creating it, and the answer must pass [`start_in`]. A machine that
    /// fails either has no start this host can order a launch by, and says why.
    ///
    /// # Errors
    ///
    /// Returns what failed: the creation, a reading, or the plausibility of the answer.
    pub fn start_clock() -> Result<(), String> {
        CLOCK.get_or_init(probe).clone()
    }

    fn probe() -> Result<(), String> {
        let failed = |why: String| {
            format!("the kernel's record of when a process started cannot be believed here: {why}")
        };
        // The process never runs, so any program does: one from the system directory, which every
        // machine has.
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let executable = std::path::Path::new(&root).join("System32").join("cmd.exe");
        let before = own()?.query_interrupt_time;
        let mut child = {
            // Created under the lock every launch takes: a process started while a launch's
            // streams are inheritable would hold them.
            let _inheriting = crate::windows::launch::inheriting();
            std::process::Command::new(executable)
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|error| failed(format!("a process could not be created: {error}")))?
        };
        let after = own();
        let read = uptime(child.as_raw_handle().cast());
        // Ended whatever was read, and before any reading that failed is returned: it never ran
        // and nothing may leave it behind, and dropping a child does not end it.
        let _ = child.kill();
        let _ = child.wait();
        let after = after?.query_interrupt_time;
        let started = start_in(&read.map_err(&failed)?)
            .map_err(&failed)?
            .ok_or_else(|| failed("a process that never ran says it ended".to_owned()))?;
        lies_between(started, before, after).map_err(failed)
    }

    /// Reads class 88 of this process.
    fn own() -> Result<Uptime, String> {
        // SAFETY: the call takes nothing and returns the pseudo-handle for this process.
        uptime(unsafe { GetCurrentProcess() })
    }

    /// Returns the interrupt time now, on the clock every start here is ordered by.
    ///
    /// # Errors
    ///
    /// Returns why the clock cannot be believed or read.
    pub fn interrupt_now() -> Result<u64, String> {
        start_clock()?;
        Ok(own()?.query_interrupt_time)
    }

    /// Returns when `process` started, on the interrupt clock.
    ///
    /// # Errors
    ///
    /// Returns why it cannot be said: the clock cannot be believed, the process has ended or is
    /// another process now, or a reading failed. A reading that was not taken is never a start
    /// that is not there.
    pub fn monotonic_start(process: &ProcessStartIdentity) -> Result<u64, String> {
        start_clock()?;
        start_in_table(&Kernel, process)
    }

    /// Returns the process that started `child`, where the kernel's record is still about it.
    ///
    /// # Errors
    ///
    /// Returns why no parent can be named, as [`parent_in`] does.
    pub fn parent_of(child: &ProcessStartIdentity) -> Result<ProcessStartIdentity, String> {
        start_clock()?;
        parent_in(&Kernel, child)
    }

    /// Returns whether `parent` started `child`.
    ///
    /// # Errors
    ///
    /// Returns why it is not shown, as [`started_by_in`] does.
    pub fn started_by(
        child: &ProcessStartIdentity,
        parent: &ProcessStartIdentity,
    ) -> Result<(), String> {
        start_clock()?;
        started_by_in(&Kernel, child, parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::ProcessStartSource;
    use std::collections::BTreeMap;

    fn identity(pid: u64, creation: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            pid,
            ProcessStartSource::WindowsProcessCreationTime,
            creation,
        )
    }

    /// A table of what the kernel says, which a test changes between two readings.
    struct Scripted {
        processes: std::cell::RefCell<BTreeMap<u32, Result<Look, String>>>,
        /// What each read of one identifier answers after its first, for a reading that changes.
        later: std::cell::RefCell<BTreeMap<u32, Look>>,
        reads: std::cell::RefCell<BTreeMap<u32, usize>>,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                processes: std::cell::RefCell::default(),
                later: std::cell::RefCell::default(),
                reads: std::cell::RefCell::default(),
            }
        }

        fn run(self, pid: u32, creation: u64, parent: u32, started: u64) -> Self {
            self.processes.borrow_mut().insert(
                pid,
                Ok(Look::Present(Reading {
                    identity: identity(u64::from(pid), creation),
                    parent,
                    started,
                })),
            );
            self
        }

        fn fail(self, pid: u32, why: &str) -> Self {
            self.processes.borrow_mut().insert(pid, Err(why.to_owned()));
            self
        }

        fn change(self, pid: u32, after: Look) -> Self {
            self.later.borrow_mut().insert(pid, after);
            self
        }
    }

    impl Table for Scripted {
        fn look(&self, pid: u32) -> Result<Look, String> {
            let mut reads = self.reads.borrow_mut();
            let count = reads.entry(pid).or_default();
            *count += 1;
            if *count > 1
                && let Some(after) = self.later.borrow().get(&pid)
            {
                return Ok(after.clone());
            }
            self.processes
                .borrow()
                .get(&pid)
                .cloned()
                .unwrap_or(Ok(Look::Absent))
        }
    }

    /// The child is 200, its parent 100, which started first; the clocks are the interrupt
    /// clock's.
    fn family() -> Scripted {
        Scripted::new()
            .run(100, 5_000, 4, 1_000)
            .run(200, 6_000, 100, 2_000)
    }

    #[test]
    fn a_child_is_started_by_the_running_process_its_record_names() {
        let table = family();
        assert_eq!(
            parent_in(&table, &identity(200, 6_000)),
            Ok(identity(100, 5_000))
        );
        assert_eq!(
            started_by_in(&table, &identity(200, 6_000), &identity(100, 5_000)),
            Ok(())
        );
    }

    #[test]
    fn a_process_that_is_not_the_parent_is_refused_by_name() {
        let table = family().run(300, 7_000, 4, 500);
        let refused = started_by_in(&table, &identity(200, 6_000), &identity(300, 7_000))
            .expect_err("another process did not start it");
        assert!(refused.contains("not by process 300"), "{refused}");
    }

    #[test]
    fn a_parent_that_has_ended_names_nothing() {
        // Windows keeps the identifier of a parent that has ended, and the table says nothing is
        // there now.
        let table = Scripted::new().run(200, 6_000, 100, 2_000);
        let refused = parent_in(&table, &identity(200, 6_000)).expect_err("the parent is gone");
        assert!(refused.contains("the parent has ended"), "{refused}");
    }

    #[test]
    fn an_identifier_a_later_process_holds_is_not_the_parent() {
        // The parent ended and its identifier went to a process that started after the child: the
        // wall clock, stepped back, could say either, and the interrupt clock says the order.
        let table = Scripted::new()
            .run(100, 1, 4, 9_000)
            .run(200, 6_000, 100, 2_000);
        let refused = parent_in(&table, &identity(200, 6_000))
            .expect_err("a process that started later is not the parent");
        assert!(refused.contains("started after"), "{refused}");
    }

    #[test]
    fn a_parent_that_started_in_the_same_tick_is_not_later() {
        let table = Scripted::new()
            .run(100, 5_000, 4, 2_000)
            .run(200, 6_000, 100, 2_000);
        assert!(parent_in(&table, &identity(200, 6_000)).is_ok());
    }

    #[test]
    fn a_child_other_than_the_one_described_is_refused() {
        let table = family();
        let refused = parent_in(&table, &identity(200, 6_001)).expect_err("another start");
        assert!(
            refused.contains("is not the process described"),
            "{refused}"
        );
        let absent = parent_in(&Scripted::new(), &identity(200, 6_000)).expect_err("not there");
        assert!(absent.contains("has ended"), "{absent}");
    }

    #[test]
    fn a_reading_that_changes_while_it_is_read_is_refused() {
        let table = family().change(
            200,
            Look::Present(Reading {
                identity: identity(200, 6_000),
                parent: 300,
                started: 2_000,
            }),
        );
        let refused = parent_in(&table, &identity(200, 6_000)).expect_err("it changed");
        assert!(refused.contains("changed while it was read"), "{refused}");
        let replaced = family().change(200, Look::Absent);
        assert!(parent_in(&replaced, &identity(200, 6_000)).is_err());
    }

    #[test]
    fn a_reading_that_fails_is_never_taken_for_an_absent_process() {
        let table = family().fail(100, "access denied");
        let refused = parent_in(&table, &identity(200, 6_000)).expect_err("it cannot be read");
        assert!(refused.contains("access denied"), "{refused}");
        assert!(!refused.contains("has ended"), "{refused}");
    }

    #[test]
    fn a_process_with_no_recorded_parent_has_none() {
        let table = Scripted::new().run(200, 6_000, 0, 2_000);
        assert!(parent_in(&table, &identity(200, 6_000)).is_err());
    }

    #[test]
    fn the_start_is_what_class_88_says_and_nothing_implausible_is_one() {
        let answer = |now, since, end| Uptime {
            query_interrupt_time: now,
            time_since_creation: since,
            end_interrupt_time: end,
            ..Uptime::default()
        };
        assert_eq!(start_in(&answer(1_000, 400, 0)), Ok(Some(600)));
        assert_eq!(
            start_in(&answer(1_000, 0, 0)),
            Ok(Some(1_000)),
            "a process read within the tick it was created in is as old as the tick"
        );
        assert_eq!(
            start_in(&answer(1_000, 400, 900)),
            Ok(None),
            "a process that has ended has no start to place"
        );
        for implausible in [
            answer(0, 0, 0),
            answer(1_000, 1_000, 0),
            answer(1_000, 2_000, 0),
        ] {
            assert!(start_in(&implausible).is_err(), "{implausible:?}");
        }
    }

    #[test]
    fn a_start_outside_the_two_readings_around_its_creation_is_not_believed() {
        assert_eq!(lies_between(150, 100, 200), Ok(()));
        assert_eq!(lies_between(100, 100, 200), Ok(()));
        assert_eq!(lies_between(200, 100, 200), Ok(()));
        assert!(lies_between(99, 100, 200).is_err());
        assert!(lies_between(201, 100, 200).is_err());
    }

    #[test]
    fn the_start_of_a_process_is_its_own_and_a_replaced_one_is_refused() {
        let table = family();
        assert_eq!(start_in_table(&table, &identity(200, 6_000)), Ok(2_000));
        assert!(start_in_table(&table, &identity(200, 6_001)).is_err());
        assert!(start_in_table(&table, &identity(999, 1)).is_err());
    }
}
