//! A limit on the memory a process may commit, held by the system, and the record of its being
//! reached.
//!
//! Windows has no call that ends a process for the memory it holds. A job object can refuse the
//! commit that would pass a limit, and say that it did: the process's allocation fails, the process
//! deals with that as it does (a runtime that cannot allocate ends, and one that catches the
//! failure answers that it failed and goes on), and the job posts a message to the completion port
//! it was given. [`MemoryLimit`] is that job, with that port, around one process. It is the
//! system's own backstop behind a reading of the process's resident set that somebody else takes at
//! intervals.
//!
//! The message is the only record of a refusal, and Windows does not promise to deliver it for a
//! limit of this kind. A refusal that was not recorded reads as an ordinary end of the process, so
//! an absent message is not proof that no commit was refused.
//!
//! The limit is on committed memory: the private memory the process asked the system to back,
//! touched or not. A file mapped for reading is not committed, so the limit does not count the
//! weights a model maps, and a process may hold more resident than it has committed.
//!
//! A limit that was asked for and a limit the system holds are different facts, so [`around`]
//! reads the limit back from the job, and asks the system whether the process is in the job, before
//! it says it applied anything.
//!
//! A process runs from the moment it is created, and a limit does not reach back to memory it has
//! committed already. So a process that is to be held to a limit is created held ([`start_held`]),
//! put behind the limit, and only then let run ([`resume`]): it does not run before it is behind
//! the limit.
//!
//! The job ends the processes in it when its last handle closes. A process that was created held
//! never runs, so it never reads the end of its input or the end of its owner, and nothing in it
//! would end it: the job is what does, so an owner that ends, or that loses the limit before it
//! lets the process run, does not leave a process that never ran. The owner keeps the limit for as
//! long as the process lives.
//!
//! [`around`]: MemoryLimit::around

#![expect(
    unsafe_code,
    reason = "creating a job object with a completion port and moving a process into it have no safe form"
)]

use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};
use std::os::windows::process::CommandExt as _;
use std::process::Command;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

#[link(name = "ntdll")]
unsafe extern "system" {
    /// `NtResumeProcess`, which the bindings this crate uses do not declare. It lets every thread
    /// of the process run that a count of suspensions holds, which for a process that was created
    /// held is its first thread.
    fn NtResumeProcess(process: HANDLE) -> i32;
}

/// Why a limit was not applied.
pub type Refusal = &'static str;

/// What the job is asked to hold, and what it is read back as holding: the limit on the memory a
/// process commits, and the end of the process when the job closes.
const HELD_FLAGS: u32 = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

/// How far the figure the system holds may be from the one asked for. The system keeps a limit as a
/// whole number of pages, so a figure that is not one reads back a little different, and the
/// allocation granularity of 64 KiB is more than a page on every platform it runs on.
const ROUNDING: usize = 64 * 1024;

/// Makes the process `command` starts begin held: it is created but its first thread does not run
/// until [`resume`] lets it. This sets the command's creation flags, so it replaces any that were
/// set.
pub fn start_held(command: &mut Command) -> &mut Command {
    command.creation_flags(CREATE_SUSPENDED)
}

/// Lets run the process that [`start_held`] began held.
///
/// The handle must be open on the process with the right to suspend and resume it, as the one a
/// parent holds of the child it started is.
///
/// # Errors
///
/// Returns why the process was not let run.
pub fn resume(process: BorrowedHandle<'_>) -> std::result::Result<(), Refusal> {
    let process: HANDLE = process.as_raw_handle().cast();
    // SAFETY: the call takes a handle that the caller holds open and reads no memory of this
    // process.
    let status = unsafe { NtResumeProcess(process) };
    if status < 0 {
        Err("this host would not let the held process run")
    } else {
        Ok(())
    }
}

/// A process memory limit the system holds around one process.
///
/// Dropping it closes the job and its port, and the system ends the process in the job when the
/// job closes, so it is kept for as long as the process is to live.
#[derive(Debug)]
pub struct MemoryLimit {
    /// Kept open for as long as this value lives: the job holds the limit and the process in it.
    _job: OwnedHandle,
    /// Where the job posts that a process in it passed the limit.
    port: OwnedHandle,
    limit_bytes: u64,
}

impl MemoryLimit {
    /// Puts the process behind `process` into a job that refuses it more committed memory than
    /// `limit_bytes` and ends it when the job closes, and reads the limit and the membership back
    /// from the system. The limit read back is allowed to differ from the one asked for by the
    /// rounding the system applies to it.
    ///
    /// The handle must be open on the process with the right to set its quota and to terminate it,
    /// as the one a parent holds of the child it started is, and it stays open for the call. The
    /// right to query the process is needed to ask the system whether it is in the job; without it
    /// the assignment's own success stands.
    ///
    /// # Errors
    ///
    /// Returns why the limit was not applied: the system refused one of the calls, or reported a
    /// limit or a membership other than the one asked for.
    pub fn around(
        process: BorrowedHandle<'_>,
        limit_bytes: u64,
    ) -> std::result::Result<Self, Refusal> {
        let wanted = usize::try_from(limit_bytes)
            .map_err(|_| "the memory limit is more than this platform addresses")?;
        // SAFETY: the call takes no pointer to memory of this process other than two null
        // pointers, and returns a handle or null.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err("this host would not create a job object");
        }
        // SAFETY: the handle was just returned by the call above and nothing else owns it.
        let job = unsafe { OwnedHandle::from_raw_handle(job.cast()) };
        // SAFETY: the call returns a new port, which nothing else owns, or null.
        let port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if port.is_null() {
            return Err("this host would not create a completion port");
        }
        // SAFETY: the handle was just returned by the call above and nothing else owns it.
        let port = unsafe { OwnedHandle::from_raw_handle(port.cast()) };

        let raw_job: HANDLE = job.as_raw_handle().cast();
        let raw_port: HANDLE = port.as_raw_handle().cast();
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: std::ptr::null_mut(),
            CompletionPort: raw_port,
        };
        // SAFETY: the call reads one structure of the size given, from a live local.
        let associated = unsafe {
            SetInformationJobObject(
                raw_job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                size_of(&association),
            )
        };
        if associated == 0 {
            return Err("this host would not tie the job to its completion port");
        }

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = HELD_FLAGS;
        limits.ProcessMemoryLimit = wanted;
        // SAFETY: the call reads one structure of the size given, from a live local.
        let set = unsafe {
            SetInformationJobObject(
                raw_job,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of(&limits),
            )
        };
        if set == 0 {
            return Err("this host refused the process memory limit");
        }

        let mut held = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: the call writes one structure of the size given, through a pointer to a live
        // local, and nothing else of this process.
        let read = unsafe {
            QueryInformationJobObject(
                raw_job,
                JobObjectExtendedLimitInformation,
                (&raw mut held).cast(),
                size_of(&held),
                std::ptr::null_mut(),
            )
        };
        if read == 0
            || held.BasicLimitInformation.LimitFlags & HELD_FLAGS != HELD_FLAGS
            || held.ProcessMemoryLimit.abs_diff(wanted) >= ROUNDING
        {
            return Err("this host did not report the memory limit it was given");
        }

        let process: HANDLE = process.as_raw_handle().cast();
        // SAFETY: the call takes two handles, which the caller and this function hold open.
        if unsafe { AssignProcessToJobObject(raw_job, process) } == 0 {
            return Err("this host would not put the process in the job");
        }
        let mut inside = 0;
        // SAFETY: the call writes one value through a pointer to a live local of that size.
        let asked = unsafe { IsProcessInJob(process, raw_job, &raw mut inside) };
        // The assignment was accepted, so the process is in the job. A system that answers that it
        // is not is believed over that. One that cannot answer (the handle may lack the right to
        // ask) is not: the job holds the process whatever is done with it here, so dropping it now
        // would close the port that records a refusal, and the limit would hold unseen.
        if asked != 0 && inside == 0 {
            return Err("this host did not report the process in the job");
        }
        Ok(Self {
            _job: job,
            port,
            limit_bytes,
        })
    }

    /// The limit asked for, in bytes. The system holds it to a whole number of pages.
    #[must_use]
    pub const fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    /// Whether the job has recorded that the system refused the process a commit because it would
    /// have passed the limit since this was last asked, and forgets it.
    ///
    /// It reads what the job has posted, without waiting. The system posts the message inside the
    /// refused call, before that call returns, so a process that has ended has posted everything it
    /// will. The message is not promised, though: false means none was seen.
    #[must_use]
    pub fn take_refusal(&self) -> bool {
        let raw_port: HANDLE = self.port.as_raw_handle().cast();
        let mut refused = false;
        loop {
            let mut message = 0_u32;
            let mut key = 0_usize;
            let mut process = std::ptr::null_mut();
            // SAFETY: the call writes a value through each of three pointers to live locals of the
            // types it names, and waits for nothing.
            let taken = unsafe {
                GetQueuedCompletionStatus(
                    raw_port,
                    &raw mut message,
                    &raw mut key,
                    &raw mut process,
                    0,
                )
            };
            if taken == 0 {
                return refused;
            }
            if message == JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT {
                refused = true;
            }
        }
    }
}

/// The size of a structure the system is given, as the system counts it.
fn size_of<T>(value: &T) -> u32 {
    u32::try_from(size_of_val(value)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
        WaitForSingleObject,
    };

    use super::{MemoryLimit, resume, start_held};

    const MIB: u64 = 1 << 20;

    /// What the child asks the system to commit, and the variable that makes it ask.
    const ASK: &str = "KR_MEMORY_LIMIT_ASK_BYTES";

    /// How the child says what the system did with its request.
    const REFUSED: i32 = 3;

    /// The child half of the cases below. Run on its own it asks for nothing and passes. Started by
    /// them with the variable set, it asks the system to commit that much as the first thing it
    /// does, and exits with whether the system let it.
    #[test]
    fn the_child_that_asks_the_system_for_memory() {
        let Ok(ask) = std::env::var(ASK) else {
            return;
        };
        let ask: usize = ask.parse().expect("a number of bytes");
        let mut held: Vec<u8> = Vec::new();
        let code = match held.try_reserve_exact(ask) {
            Ok(()) => {
                // Written, so the commit is not only asked for.
                held.resize(ask, 1);
                std::hint::black_box(&held);
                0
            }
            Err(_) => REFUSED,
        };
        std::process::exit(code);
    }

    /// The variable that makes the child half below ask twice, and the size of each request.
    const ASK_TWICE: &str = "KR_MEMORY_LIMIT_ASK_TWICE_BYTES";

    /// What the child says between its two requests, when the system refused the first.
    const REFUSED_FIRST: &str = "the-first-request-was-refused";

    /// The child half of the case that asks twice. Run on its own it asks for nothing and passes.
    /// Started by the case with the variable set, it asks the system to commit that much, says
    /// whether the system refused, waits for a line on its input, asks again, and exits with
    /// whether the system refused the second request.
    #[test]
    fn the_child_that_asks_the_system_for_memory_twice() {
        use std::io::{BufRead as _, Write as _};

        fn refused(ask: usize) -> bool {
            let mut held: Vec<u8> = Vec::new();
            held.try_reserve_exact(ask).is_err()
        }

        let Ok(ask) = std::env::var(ASK_TWICE) else {
            return;
        };
        let ask: usize = ask.parse().expect("a number of bytes");
        if !refused(ask) {
            std::process::exit(0);
        }
        println!("{REFUSED_FIRST}");
        std::io::stdout()
            .flush()
            .expect("the first answer is written");
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("the go-ahead is read");
        std::process::exit(if refused(ask) { REFUSED } else { 0 });
    }

    /// A child a case started, ended when the case lets go of it, so that a case that fails before
    /// it lets the child run does not leave a held process behind.
    struct Started(Child);

    impl std::ops::Deref for Started {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.0
        }
    }

    impl std::ops::DerefMut for Started {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.0
        }
    }

    impl Drop for Started {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Starts the child held, so that it has not run, and tells it to ask for `ask` bytes.
    fn held_child_asking(ask: u64) -> Started {
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args([
                "--exact",
                "memory_limit::tests::the_child_that_asks_the_system_for_memory",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ASK, ask.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        start_held(&mut command);
        Started(command.spawn().expect("the child starts"))
    }

    /// Starts the child behind a limit and lets it run, and says how it ended and whether the limit
    /// recorded being passed, asked twice.
    fn child_asking(ask: u64, limit_bytes: u64) -> (Option<i32>, bool, bool) {
        let mut child = held_child_asking(ask);
        let limit = MemoryLimit::around(child.as_handle(), limit_bytes)
            .expect("the limit is applied to the child");
        assert_eq!(limit.limit_bytes(), limit_bytes);
        resume(child.as_handle()).expect("the child is let run");
        let ended = child.wait().expect("the child ends");
        (ended.code(), limit.take_refusal(), limit.take_refusal())
    }

    /// A process behind the limit that commits more than it allows is refused by the system, and
    /// the limit says so after the process has gone, so that whoever holds it can tell a process
    /// the system stopped from one that failed some other way, and forgets it once it has said.
    /// The child asks as the first thing it does: it was held until it was behind the limit. The
    /// control is the same request under a limit that allows it, which the system grants and does
    /// not record.
    #[test]
    fn a_process_refused_a_commit_by_the_system_leaves_the_limit_saying_so() {
        // A limit that is not a whole number of pages, as a profile's itemised cost is not.
        let (code, reached, again) = child_asking(512 * MIB, 256 * MIB + 123);
        assert_eq!(code, Some(REFUSED), "the system refused the commit");
        assert!(reached, "and the limit recorded that it had");
        assert!(!again, "and says it once");

        let (code, reached, again) = child_asking(512 * MIB, 4096 * MIB + 123);
        assert_eq!(
            code,
            Some(0),
            "the same request under a limit that allows it"
        );
        assert!(!reached, "is not a limit reached");
        assert!(!again);
    }

    /// A held process does not run until it is let: a child that would commit more than the limit
    /// allows, and is given all the time it would need to do it before the limit is applied, is
    /// still refused.
    #[test]
    fn a_held_process_does_not_run_before_it_is_behind_the_limit() {
        let mut child = held_child_asking(512 * MIB);
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            assert!(
                child.try_wait().expect("the child is asked").is_none(),
                "the held process ran"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let limit = MemoryLimit::around(child.as_handle(), 256 * MIB)
            .expect("the limit is applied to the child");
        resume(child.as_handle()).expect("the child is let run");
        let ended = child.wait().expect("the child ends");
        assert_eq!(ended.code(), Some(REFUSED), "the system refused the commit");
        assert!(limit.take_refusal());
    }

    /// A process that is refused a second commit, after it was refused one and the limit said so,
    /// is recorded as refused again. This is another refused allocation by the same process under
    /// the same limit, and not another reading of the first: a limit that said so only once for a
    /// process would leave every refusal after the first reading as an ordinary end.
    #[test]
    fn a_second_commit_the_system_refuses_a_process_is_recorded_as_the_first_was() {
        use std::io::{BufRead as _, Write as _};

        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args([
                "--exact",
                "memory_limit::tests::the_child_that_asks_the_system_for_memory_twice",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ASK_TWICE, (512 * MIB).to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        start_held(&mut command);
        let mut child = Started(command.spawn().expect("the child starts"));
        let limit = MemoryLimit::around(child.as_handle(), 256 * MIB)
            .expect("the limit is applied to the child");
        resume(child.as_handle()).expect("the child is let run");

        let mut input = child.stdin.take().expect("a pipe");
        let mut lines = std::io::BufReader::new(child.stdout.take().expect("a pipe")).lines();
        lines
            .by_ref()
            .map_while(Result::ok)
            .find(|line| line == REFUSED_FIRST)
            .expect("the child says the system refused its first request");
        assert!(limit.take_refusal(), "the first refusal is recorded");
        assert!(!limit.take_refusal(), "and said once");

        writeln!(input, "go").expect("the child is told to ask again");
        drop(input);
        let ended = child.wait().expect("the child ends");
        assert_eq!(
            ended.code(),
            Some(REFUSED),
            "the system refused the second request too"
        );
        assert!(
            limit.take_refusal(),
            "and the limit recorded that refusal as it did the first"
        );
    }

    /// The variable that makes the daemon half below hold a process and end.
    const DAEMON: &str = "KR_MEMORY_LIMIT_DAEMON";

    /// What the daemon half says before it ends, followed by the identifier of the process it held.
    const HELD_PROCESS: &str = "held-process-identifier=";

    /// The daemon half of the case below. Run on its own it does nothing and passes. Started by the
    /// case with the variable set, it starts a process held, puts it behind a limit, names it, and
    /// ends at once, as a daemon killed from outside does: nothing is dropped and the process is
    /// never let run.
    #[test]
    fn the_daemon_that_ends_with_a_process_held() {
        if std::env::var_os(DAEMON).is_none() {
            return;
        }
        let child = held_child_asking(512 * MIB);
        let _limit = MemoryLimit::around(child.as_handle(), 256 * MIB)
            .expect("the limit is applied to the child");
        println!("{HELD_PROCESS}{}", child.id());
        std::io::Write::flush(&mut std::io::stdout()).expect("the name is written");
        std::process::exit(0);
    }

    /// A process that was created held and put behind a limit never runs, so it never reads that
    /// its owner has gone, and without the limit it would stay until the user signs out, holding
    /// the executable it was made from. The system ends it when the last handle of its job closes,
    /// which is what happens to the handles of a daemon that ends. The wait is for that fact, with a
    /// bound for the process that is still there.
    #[test]
    fn a_process_held_by_a_daemon_that_ends_is_ended_with_it() {
        use std::io::BufRead as _;

        let mut daemon = Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "memory_limit::tests::the_daemon_that_ends_with_a_process_held",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DAEMON, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon starts");
        // A line is read and not the whole output: the held process may have been given the pipe
        // the daemon writes to, and the pipe is not closed while it lives.
        let held = std::io::BufReader::new(daemon.stdout.take().expect("a pipe"))
            .lines()
            .map_while(Result::ok)
            .find_map(|line| line.strip_prefix(HELD_PROCESS).map(str::to_owned))
            .expect("the daemon names the process it held");
        let held: u32 = held.parse().expect("a process identifier");
        daemon.wait().expect("the daemon ends");

        // SAFETY: the call takes the identifier of a process and returns a handle or null.
        let opened = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, held) };
        if opened.is_null() {
            // No process has the identifier any more: it is gone.
            return;
        }
        // SAFETY: the handle was just returned by the call above and nothing else owns it.
        let process = unsafe { OwnedHandle::from_raw_handle(opened.cast()) };
        let raw: windows_sys::Win32::Foundation::HANDLE = process.as_raw_handle().cast();
        // SAFETY: the call takes a handle that this function holds open.
        let waited = unsafe { WaitForSingleObject(raw, 20_000) };
        if waited != WAIT_OBJECT_0 {
            // SAFETY: the call takes a handle that this function holds open.
            unsafe { TerminateProcess(raw, 1) };
            panic!("the process the daemon held was still there 20 s after the daemon ended");
        }
    }

    /// A handle that may set a process's quota and end it, and may not query it, cannot be asked
    /// whether the process is in the job. The assignment was accepted, so the process is in the
    /// job: the limit is held, and it records the refusal as one the system could ask about does.
    #[test]
    fn a_limit_whose_membership_the_system_cannot_report_still_holds_and_records() {
        let mut child = held_child_asking(512 * MIB);
        // SAFETY: the call takes the identifier of the child, which is held and not yet ended, and
        // returns a handle or null.
        let opened = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, child.id()) };
        assert!(!opened.is_null(), "a handle with two rights is opened");
        // SAFETY: the handle was just returned by the call above and nothing else owns it.
        let handle = unsafe { OwnedHandle::from_raw_handle(opened.cast()) };
        let limit = MemoryLimit::around(handle.as_handle(), 256 * MIB)
            .expect("a limit that holds is not undone by a question it could not ask");
        resume(child.as_handle()).expect("the child is let run");
        let ended = child.wait().expect("the child ends");
        assert_eq!(ended.code(), Some(REFUSED), "the system refused the commit");
        assert!(limit.take_refusal(), "and the limit recorded it");
    }
}
