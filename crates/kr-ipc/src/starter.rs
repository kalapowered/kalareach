//! What an environment's starter needs from the platform, and what the daemon that hands it a
//! launch needs.
//!
//! On Windows the control daemon does not create a worker. The environment's scheduled task runs a
//! *starter*; the Task Scheduler, not the daemon, creates that starter, and the starter creates the
//! worker. So a worker is never in a job the daemon runs in, at any depth, and no such job closing
//! can end it. That holds however the daemon's own jobs are nested, which is what a breakaway
//! decision made by the daemon cannot promise: breakaway stops at the first job above that forbids
//! it, and the daemon cannot see that job's flags.
//!
//! The parts that need the operating system are here:
//!
//! | Part | Who uses it |
//! | --- | --- |
//! | [`LaunchListener`]: one owner-only instance of the environment's launch pipe per launch, waited on until a deadline | the daemon, to hand one launch to one starter |
//! | [`connect`]: reaching a waiting instance, refusing one served by another account | the starter |
//! | [`PeerProcess`]: the process at the other end of the pipe, its image, its login session and whether it runs as this user | each side, to check the other |
//! | [`start_child`]: a child created suspended and checked before it runs | the starter |
//! | [`StartClaim`]: a request to start the daemon, left by a cold start and taken once | the starter |
//! | [`record_session`]: the login session this environment's work runs in | the daemon |
//!
//! # The starter's own job
//!
//! The Task Scheduler runs the starter inside a job of its own: an `S4U` task's job lets its
//! members break away silently, and an `InteractiveToken` task's job sets no limits at all. That job
//! is never the daemon's, so it does not weaken the rule above. What the starter does about it is
//! decided by [`job_plan`] from the job's limit flags, the one job whose flags it can read:
//!
//! * no job, or a job that permits breakaway: the child is asked to leave it and must then be in no
//!   job at all before it is resumed. A job above that forbids breakaway leaves the child where it
//!   is, and the child is ended rather than run there.
//! * a job that kills its members when it closes and forbids breakaway, as `cargo test` runs its
//!   tests in: the child could not leave a job that would end it with the starter, so nothing is
//!   created.
//! * a job that neither kills on close nor permits breakaway, which is what an `InteractiveToken`
//!   task gives: the child cannot leave it and stays in it. That rests on a platform assumption,
//!   stated rather than proven: the Task Scheduler does not end such a job, or any job above it,
//!   before the user's session ends. The query sees the immediate job only, so it cannot rule out a
//!   job above that kills on close; if the platform ever closed one early, the worker would end by
//!   the Task Scheduler's action, still not by the daemon's.
//!
//! The claim and the session record are plain owner-only files and work on every platform; only
//! Windows has a starter to use them.

use std::path::{Path, PathBuf};

use kr_protocol::identity::BootIdentity;
use kr_protocol::scalars::Uuid;
use serde::{Deserialize, Serialize};

use crate::error::{IpcError, Result};
use crate::paths::EnvironmentPaths;

/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: the job ends its members when its last handle closes.
pub const KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
/// `JOB_OBJECT_LIMIT_BREAKAWAY_OK`: a member may create a process outside the job by asking.
pub const BREAKAWAY_OK: u32 = 0x0000_0800;
/// `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`: every process a member creates is outside the job.
pub const SILENT_BREAKAWAY_OK: u32 = 0x0000_1000;

/// What a starter does about the job it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPlan {
    /// The starter is in no job: the child is created plainly and must be in no job.
    Plain,
    /// The job permits breakaway: the child asks to leave it and must then be in no job.
    BreakAway,
    /// The job kills its members when it closes and forbids breakaway: nothing is created.
    Refuse,
    /// The job neither kills on close nor permits breakaway: the child stays in it.
    StayInJob,
}

/// Decides what a starter does about its own job, from that job's limit flags, or `None` when it
/// runs in no job.
///
/// Breakaway is looked at first: a job that kills on close but permits breakaway is left, which is
/// what makes the kill on close irrelevant to the child.
#[must_use]
pub const fn job_plan(limit_flags: Option<u32>) -> JobPlan {
    match limit_flags {
        None => JobPlan::Plain,
        Some(flags) if flags & (BREAKAWAY_OK | SILENT_BREAKAWAY_OK) != 0 => JobPlan::BreakAway,
        Some(flags) if flags & KILL_ON_JOB_CLOSE != 0 => JobPlan::Refuse,
        Some(_) => JobPlan::StayInJob,
    }
}

/// A request that this environment's starter start the control daemon.
///
/// A cold start leaves one before it runs the environment's task, so the starter that task runs
/// can tell a request to start the daemon from a launch it was meant to take: the absence of a
/// waiting launch says nothing about why the starter was run. The deadline is on the machine's own
/// continuous clock ([`crate::clock`]), counted in the boot the claim names, so a clock step cannot
/// extend it and a claim from an earlier boot has lapsed. A retry of the same request leaves the
/// claim it left before, deadline and all, rather than a later one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartClaim {
    /// Unique to the request, and the claim's name on disk.
    pub request: Uuid,
    /// The boot the deadline is counted in.
    pub boot: BootIdentity,
    /// When the claim lapses, in milliseconds of the continuous clock since that boot.
    pub deadline_boot_ms: u64,
}

impl StartClaim {
    /// Whether a starter may still act on this claim at `now_boot_ms` of `boot`.
    #[must_use]
    pub fn admits(&self, boot: &BootIdentity, now_boot_ms: u64) -> bool {
        self.boot == *boot && now_boot_ms < self.deadline_boot_ms
    }
}

/// A claim one starter took, and no other starter can take.
#[derive(Debug)]
pub struct TakenClaim {
    claim: StartClaim,
    path: PathBuf,
}

impl TakenClaim {
    /// The request that was taken.
    #[must_use]
    pub const fn claim(&self) -> &StartClaim {
        &self.claim
    }

    /// Whether the request may still be acted on at `now_boot_ms` of `boot`.
    ///
    /// A starter asks this immediately before it creates anything: that reading, and not the one
    /// made when the claim was taken, is the point at which a start is admitted.
    #[must_use]
    pub fn admits(&self, boot: &BootIdentity, now_boot_ms: u64) -> bool {
        self.claim.admits(boot, now_boot_ms)
    }

    /// Removes the taken claim, once the starter has acted on it or decided not to.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be removed.
    pub fn discard(self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(IpcError::io("remove", &self.path, error)),
        }
    }
}

/// The largest claim or session record this host reads.
const MAX_RECORD_LEN: u64 = 4096;

/// The suffix of a claim waiting to be taken.
const WAITING: &str = "claim";

/// The suffix of a claim a starter has taken.
const TAKEN: &str = "taken";

/// Leaves `claim` for this environment's starter.
///
/// Leaving the same request twice leaves it once: the file is named for the request and is never
/// replaced, so a retry cannot move the deadline the first attempt set.
///
/// # Errors
///
/// Returns an error when the claims directory cannot be made or the claim cannot be written.
pub fn leave_claim(environment: &EnvironmentPaths, claim: &StartClaim) -> Result<()> {
    let directory = environment.start_claims_dir();
    crate::paths::create_private_tree(environment.runtime_root(), &directory)?;
    let path = directory.join(format!("{}.{WAITING}", claim.request));
    let bytes = kr_cbor::to_canonical_vec(claim).map_err(|error| {
        IpcError::io(
            "encode",
            &path,
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
        )
    })?;
    match crate::paths::create_new_owner_only_file(&path, &bytes) {
        Ok(()) => Ok(()),
        Err(IpcError::Io { source, .. }) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Takes one claim this starter may act on, if there is one.
///
/// Taking is one exclusive link of the claim's file to a taken name, so of any number of starters
/// looking at once, one takes each claim and every other finds it taken or gone. A claim that has lapsed, or that names another
/// boot, is taken and removed rather than returned, so nothing acts on it and it does not wait
/// forever. A name in the directory that is not a waiting claim is left alone.
///
/// # Errors
///
/// Returns an error when the directory cannot be read, or a claim cannot be taken or read for a
/// reason other than another starter taking it first.
pub fn take_claim(
    environment: &EnvironmentPaths,
    boot: &BootIdentity,
    now_boot_ms: u64,
) -> Result<Option<TakenClaim>> {
    let directory = environment.start_claims_dir();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(IpcError::io("read", &directory, error)),
    };
    let mut waiting: Vec<Uuid> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let request: Uuid = name
                .to_str()?
                .strip_suffix(&format!(".{WAITING}"))?
                .parse()
                .ok()?;
            (format!("{request}.{WAITING}") == name.to_str()?).then_some(request)
        })
        .collect();
    waiting.sort();
    for request in waiting {
        let from = directory.join(format!("{request}.{WAITING}"));
        let to = directory.join(format!("{request}.{TAKEN}"));
        // A link refuses a name that exists, so exactly one of the starters that link at once
        // succeeds. A rename would not do: on Windows it works through a handle opened first, and
        // two starters that had both opened the waiting claim would both succeed.
        match std::fs::hard_link(&from, &to) {
            Ok(()) => {}
            // Another starter took it first.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
                ) =>
            {
                continue;
            }
            Err(error) => return Err(IpcError::io("take", &from, error)),
        }
        // Taken: the waiting name goes, so no later starter looks at it again.
        match std::fs::remove_file(&from) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(IpcError::io("remove", &from, error)),
        }
        let taken = TakenClaim {
            claim: read_claim(&to)?,
            path: to,
        };
        if taken.admits(boot, now_boot_ms) {
            return Ok(Some(taken));
        }
        taken.discard()?;
    }
    Ok(None)
}

/// Reads one claim this host wrote.
fn read_claim(path: &Path) -> Result<StartClaim> {
    let bytes = crate::paths::read_owner_only_file(path, MAX_RECORD_LEN)?.ok_or_else(|| {
        IpcError::io(
            "read",
            path,
            std::io::Error::new(std::io::ErrorKind::NotFound, "the claim was removed"),
        )
    })?;
    decode(path, &bytes)
}

/// Decodes one record this host wrote, naming the file when it is not one.
fn decode<T: serde::de::DeserializeOwned + Serialize>(path: &Path, bytes: &[u8]) -> Result<T> {
    kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT).map_err(|error| {
        IpcError::io(
            "decode",
            path,
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
        )
    })
}

/// The login session an environment's work runs in, as its daemon recorded it.
///
/// Windows ends a login session's processes when the user signs out of it, so every worker one
/// environment has must be in one session: a worker in another would outlive the sign-out that
/// ends the rest, or end with the wrong one. The record outlives the daemon that wrote it, so the
/// daemon that replaces it can refuse to take over work in another session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedSession {
    /// The login session's identifier.
    pub session: u32,
    /// The boot the session belongs to: a session identifier is reused after a restart.
    pub boot: BootIdentity,
}

/// Records the login session this environment's work runs in, replacing any earlier record.
///
/// # Errors
///
/// Returns an error when the record cannot be written.
pub fn record_session(environment: &EnvironmentPaths, recorded: &RecordedSession) -> Result<()> {
    let path = environment.session_record();
    let bytes = kr_cbor::to_canonical_vec(recorded).map_err(|error| {
        IpcError::io(
            "encode",
            &path,
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
        )
    })?;
    crate::paths::write_owner_only_file(&path, &bytes)
}

/// Reads the login session this environment's work runs in, when one is recorded.
///
/// # Errors
///
/// Returns an error when a record exists and cannot be read.
pub fn recorded_session(environment: &EnvironmentPaths) -> Result<Option<RecordedSession>> {
    let path = environment.session_record();
    match crate::paths::read_owner_only_file(&path, MAX_RECORD_LEN)? {
        Some(bytes) => decode(&path, &bytes).map(Some),
        None => Ok(None),
    }
}

/// Removes the record of the login session this environment's work runs in.
///
/// # Errors
///
/// Returns an error when a record exists and cannot be removed.
pub fn clear_recorded_session(environment: &EnvironmentPaths) -> Result<()> {
    let path = environment.session_record();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(IpcError::io("remove", &path, error)),
    }
}

#[cfg(windows)]
pub use self::windows::{
    ChildCommand, ChildRefusal, LaunchListener, LaunchStream, MAX_LAUNCH_FRAME, PeerProcess,
    Reached, StartedChild, connect, current_session, process_facts, start_child,
};

#[cfg(all(windows, any(test, feature = "testing")))]
pub use self::windows::Job;

/// The calls into the operating system: the launch pipe, the facts of a process, and the child a
/// starter creates.
///
/// This is one of the five places in this crate that leave safe Rust. A named pipe with a deadline
/// on every wait, a process's image, session and account, and a process created suspended and
/// checked before it runs are `kernel32` and `advapi32` calls with no safe interface. Every handle
/// is owned as soon as it exists, so every path closes it.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "the launch pipe, a process's facts and a suspended child are kernel32 and advapi32 \
                  calls, which have no safe interface"
    )]

    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{
        AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle,
    };
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    use kr_protocol::identity::ProcessStartIdentity;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
        ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
        ERROR_SEM_TIMEOUT, FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        LocalFree, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenSessionId, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW, DETACHED_PROCESS,
        GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    use super::{JobPlan, job_plan};
    use crate::identity::{ProcessQuery, WindowsReading, windows_answer};
    use crate::paths::Endpoint;

    /// The largest frame either end of the launch pipe sends: a launch is a program, its arguments,
    /// a directory and a few variables, and nothing larger is ever read.
    pub const MAX_LAUNCH_FRAME: usize = 64 * 1024;

    /// The launch pipe's list: its owner, with inheritance blocked, as every endpoint of this host.
    const OWNER_ONLY_PIPE: &str = "D:P(A;;GA;;;OW)";

    /// How long a child that is refused is given to end once it is told to.
    const END_BOUND_MS: u32 = 5_000;

    /// One instance of the environment's launch pipe, waiting for the starter that takes one
    /// launch.
    ///
    /// Each launch the daemon hands over has an instance of its own, so the operating system pairs
    /// each connecting starter with exactly one waiting launch, and two launches handed over at
    /// once never cross. Dropping an instance nobody reached removes it: a starter that arrives
    /// afterwards finds no launch waiting rather than a stale one.
    #[derive(Debug)]
    pub struct LaunchListener {
        pipe: OwnedHandle,
    }

    impl LaunchListener {
        /// Creates one fresh, owner-only instance of `endpoint`.
        ///
        /// The pipe namespace is shared by every account on the machine, so the list the instance
        /// ends up with is read back from it and checked: a name another account made first
        /// carries that account's list, and is refused rather than used.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when the instance cannot be created, and a
        /// permission error when its list is not this user's alone.
        pub fn create(endpoint: &Endpoint) -> io::Result<Self> {
            let name = pipe_name(endpoint);
            let descriptor = OwnedDescriptor::parse(OWNER_ONLY_PIPE)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            };
            let frame = u32::try_from(MAX_LAUNCH_FRAME).unwrap_or(u32::MAX);
            // SAFETY: `name` is a terminated wide string and `attributes` points at a descriptor
            // that lives until after the call. Remote clients are refused, the instance is
            // overlapped so every wait on it has a deadline, and it is a byte stream.
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    frame,
                    frame,
                    0,
                    &raw const attributes,
                )
            };
            drop(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            let pipe = unsafe { OwnedHandle::from_raw_handle(handle) };
            match crate::paths::check_access_list(pipe.as_handle(), "the launch pipe", true) {
                Ok(()) => Ok(Self { pipe }),
                Err(crate::paths::AccessListRefusal::Policy(detail)) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("the launch pipe's name is held with another list: {detail}"),
                )),
                Err(crate::paths::AccessListRefusal::Unreadable(detail)) => {
                    Err(io::Error::other(detail))
                }
            }
        }

        /// Waits until `deadline` for a starter to reach this instance.
        ///
        /// `None` is an instance nobody reached in time, or one a process reached and left before
        /// anything was said: either way nothing was handed over. It is removed as this returns,
        /// so no later starter can reach it.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when the wait itself fails.
        pub fn accept(self, deadline: Instant) -> io::Result<Option<LaunchStream>> {
            let pipe = self.pipe.as_raw_handle();
            // SAFETY: the pipe is open for as long as `self` is, and the structure the call is
            // given is live until `complete` has seen the operation finish or be cancelled.
            let connected = complete(pipe, deadline, |overlapped| unsafe {
                ConnectNamedPipe(pipe, overlapped)
            });
            match connected {
                Ok(_) => {}
                // Reached between the instance's creation and the wait, which is still a reach.
                Err(error) if code(&error) == Some(ERROR_PIPE_CONNECTED) => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(None),
                // Reached and left again before anything was said.
                Err(error) if code(&error) == Some(ERROR_NO_DATA) => return Ok(None),
                Err(error) => return Err(error),
            }
            Ok(Some(LaunchStream {
                pipe: self.pipe,
                side: Side::Server,
            }))
        }
    }

    /// Which end of the launch pipe this is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Side {
        /// The daemon's end.
        Server,
        /// The starter's end.
        Client,
    }

    /// One connected launch pipe, on either end, carrying whole frames with a deadline on each.
    #[derive(Debug)]
    pub struct LaunchStream {
        pipe: OwnedHandle,
        side: Side,
    }

    /// What reaching the launch pipe found.
    #[derive(Debug)]
    pub enum Reached {
        /// A waiting launch's instance, served by a process of this user.
        Connected(LaunchStream),
        /// No instance exists: no launch is waiting.
        NoInstance,
        /// Every instance was taken by another starter until the deadline.
        Busy,
    }

    /// Reaches a waiting instance of `endpoint` within `deadline`.
    ///
    /// The instance's server must run as this user: the pipe namespace is shared by every account,
    /// so another account could have made the name first, and a launch it offered is refused
    /// rather than run. The pipe is opened for identification only, so its server cannot act as
    /// the process that opened it.
    ///
    /// # Errors
    ///
    /// Returns a permission error when the server runs as another account, and the operating
    /// system's error when the pipe cannot be opened for any other reason.
    pub fn connect(endpoint: &Endpoint, deadline: Instant) -> io::Result<Reached> {
        let name = pipe_name(endpoint);
        loop {
            // SAFETY: `name` is a terminated wide string, no attributes or template are given, and
            // the call returns a new handle or the invalid value.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                // SAFETY: the call above returned a new handle that nothing else owns.
                let stream = LaunchStream {
                    pipe: unsafe { OwnedHandle::from_raw_handle(handle) },
                    side: Side::Client,
                };
                let server = stream.peer()?;
                if !server.same_user {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "the launch pipe is served by process {}, which runs as another \
                             account, so nothing it offers is run",
                            server.pid
                        ),
                    ));
                }
                return Ok(Reached::Connected(stream));
            }
            let error = io::Error::last_os_error();
            match code(&error) {
                Some(ERROR_FILE_NOT_FOUND) => return Ok(Reached::NoInstance),
                Some(ERROR_PIPE_BUSY) => {
                    let wait = millis_until(deadline);
                    // A wait of zero would ask for the pipe's default, which is not a deadline.
                    if wait == 0 {
                        return Ok(Reached::Busy);
                    }
                    // SAFETY: `name` is a terminated wide string; the call only waits.
                    if unsafe { WaitNamedPipeW(name.as_ptr(), wait) } == 0 {
                        let error = io::Error::last_os_error();
                        match code(&error) {
                            Some(ERROR_SEM_TIMEOUT) => return Ok(Reached::Busy),
                            Some(ERROR_FILE_NOT_FOUND) => return Ok(Reached::NoInstance),
                            _ => return Err(error),
                        }
                    }
                }
                _ => return Err(error),
            }
        }
    }

    impl LaunchStream {
        /// The process at the other end: the starter, seen from the daemon, or the daemon, seen
        /// from the starter.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when the process cannot be named or opened.
        pub fn peer(&self) -> io::Result<PeerProcess> {
            let mut pid = 0_u32;
            let pipe = self.pipe.as_raw_handle();
            // SAFETY: the pipe is open and connected, and `pid` is a live out parameter.
            let asked = unsafe {
                match self.side {
                    Side::Server => GetNamedPipeClientProcessId(pipe, &raw mut pid),
                    Side::Client => GetNamedPipeServerProcessId(pipe, &raw mut pid),
                }
            };
            if asked == 0 {
                return Err(io::Error::last_os_error());
            }
            process_facts(pid)
        }

        /// Sends one frame, whole, by `deadline`.
        ///
        /// # Errors
        ///
        /// Returns an error when the payload is larger than a frame may be, when the other end has
        /// gone, or when the deadline passes first.
        pub fn send(&mut self, payload: &[u8], deadline: Instant) -> io::Result<()> {
            let length = u32::try_from(payload.len())
                .ok()
                .filter(|_| payload.len() <= MAX_LAUNCH_FRAME)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a frame larger than the launch pipe's bound",
                    )
                })?;
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&length.to_le_bytes());
            frame.extend_from_slice(payload);
            self.write_all(&frame, deadline)
        }

        /// Writes `bytes` as they are, by `deadline`. A frame is written through this whole; a
        /// test writes a hostile head through it.
        pub(crate) fn write_all(&mut self, bytes: &[u8], deadline: Instant) -> io::Result<()> {
            let pipe = self.pipe.as_raw_handle();
            let mut written = 0_usize;
            while written < bytes.len() {
                let rest = &bytes[written..];
                let size = u32::try_from(rest.len()).unwrap_or(u32::MAX);
                // SAFETY: `rest` is a live buffer of `size` bytes that outlives the operation,
                // which `complete` waits for before it returns.
                let sent = complete(pipe, deadline, |overlapped| unsafe {
                    WriteFile(pipe, rest.as_ptr(), size, std::ptr::null_mut(), overlapped)
                })
                .map_err(closed_as_eof)?;
                if sent == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the launch pipe took nothing",
                    ));
                }
                written += usize::try_from(sent).unwrap_or(rest.len());
            }
            Ok(())
        }

        /// Receives one frame, whole, by `deadline`.
        ///
        /// # Errors
        ///
        /// Returns an error when the other end has gone, when the frame declares more than a frame
        /// may hold, or when the deadline passes first.
        pub fn receive(&mut self, deadline: Instant) -> io::Result<Vec<u8>> {
            let mut head = [0_u8; 4];
            self.read_exact(&mut head, deadline)?;
            let length = usize::try_from(u32::from_le_bytes(head)).unwrap_or(usize::MAX);
            if length > MAX_LAUNCH_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("a frame of {length} bytes, over the launch pipe's bound"),
                ));
            }
            let mut payload = vec![0_u8; length];
            self.read_exact(&mut payload, deadline)?;
            Ok(payload)
        }

        fn read_exact(&mut self, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
            let pipe = self.pipe.as_raw_handle();
            let mut filled = 0_usize;
            while filled < buffer.len() {
                let rest = &mut buffer[filled..];
                let size = u32::try_from(rest.len()).unwrap_or(u32::MAX);
                let target = rest.as_mut_ptr();
                // SAFETY: `target` points at `size` live bytes that outlive the operation, which
                // `complete` waits for before it returns.
                let read = complete(pipe, deadline, |overlapped| unsafe {
                    ReadFile(pipe, target, size, std::ptr::null_mut(), overlapped)
                })
                .map_err(closed_as_eof)?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the other end of the launch pipe closed part way through a frame",
                    ));
                }
                filled += usize::try_from(read).unwrap_or(rest.len());
            }
            Ok(())
        }
    }

    /// A pipe whose other end has gone reads as the end of the stream.
    fn closed_as_eof(error: io::Error) -> io::Error {
        if code(&error) == Some(ERROR_BROKEN_PIPE) || code(&error) == Some(ERROR_NO_DATA) {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the other end of the launch pipe has gone",
            )
        } else {
            error
        }
    }

    /// The facts of the process at the other end of the launch pipe, read from Windows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PeerProcess {
        /// Its identifier.
        pub pid: u32,
        /// The executable it runs, as Windows names it.
        pub image: PathBuf,
        /// The login session it runs in.
        pub session: u32,
        /// Whether it runs as the account this process runs as.
        pub same_user: bool,
    }

    /// Reads the facts of process `pid`: its image, its login session and whether it runs as this
    /// user.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the process cannot be opened or its token read.
    pub fn process_facts(pid: u32) -> io::Result<PeerProcess> {
        let process = open_process(pid)?;
        let image = image_of(&process)?;
        let token = Token::of(process.as_raw_handle())?;
        let own = Token::of(current_process())?;
        Ok(PeerProcess {
            pid,
            image,
            session: token.session()?,
            same_user: token.same_user_as(&own)?,
        })
    }

    /// Returns the login session this process runs in.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when this process's token cannot be read.
    pub fn current_session() -> io::Result<u32> {
        Token::of(current_process())?.session()
    }

    /// What a starter is asked to run.
    #[derive(Clone, Copy, Debug)]
    pub struct ChildCommand<'a> {
        /// The executable.
        pub application: &'a Path,
        /// The whole command line, the program's own name first, quoted as the program reads it.
        pub command_line: &'a str,
        /// The directory the child runs in.
        pub directory: &'a Path,
        /// Variables set for the child on top of the starter's own environment.
        pub environment: &'a [(String, String)],
        /// The login session the child must run in: the daemon's.
        pub session: u32,
    }

    /// A child the starter created, checked and let run.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StartedChild {
        /// Its identity, read from the handle that created it.
        pub identity: ProcessStartIdentity,
        /// The login session it runs in.
        pub session: u32,
        /// Whether it runs inside the starter's own job, which only a job that neither kills on
        /// close nor permits breakaway leaves it in.
        pub in_job: bool,
    }

    /// Why a starter did not let a child run.
    #[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
    #[error("{detail}")]
    pub struct ChildRefusal {
        /// What went wrong, in words a person can act on.
        pub detail: String,
        /// A child that was created and could not be ended: suspended, never run, but present.
        pub remaining_pid: Option<u32>,
    }

    impl ChildRefusal {
        fn nothing_created(detail: String) -> Self {
            Self {
                detail,
                remaining_pid: None,
            }
        }
    }

    /// Creates the child `command` names, outside the starter's own job where that job permits it,
    /// and lets it run only once it has been checked.
    ///
    /// The child is created suspended, and both of its handles are kept. It is resumed only when
    /// it is where [`job_plan`] says it must be (in no job, unless the starter's job neither kills
    /// on close nor permits breakaway) and in the login session `command` names. A child that
    /// fails either check, or whose membership cannot be read, is ended through its own handle
    /// before it has run an instruction. The identity returned is read from that handle, never
    /// from a process identifier looked up again.
    ///
    /// # Errors
    ///
    /// Returns a [`ChildRefusal`] naming what was wrong. Its `remaining_pid` is set only when a
    /// refused child could not be ended, which is the one case where something may still exist.
    pub fn start_child(command: &ChildCommand<'_>) -> Result<StartedChild, ChildRefusal> {
        let flags = crate::paths::current_job_limit_flags().map_err(|error| {
            ChildRefusal::nothing_created(format!(
                "this starter could not read the job it runs in, so it cannot tell whether a \
                 process it starts would be ended with it: {error}"
            ))
        })?;
        let plan = job_plan(flags);
        if plan == JobPlan::Refuse {
            return Err(ChildRefusal::nothing_created(format!(
                "this starter runs inside a job that ends its members when it closes and does not \
                 let them leave (limit flags {:#x}), so a process started here would end with the \
                 starter; nothing was started",
                flags.unwrap_or(0)
            )));
        }
        let mut creation = CREATE_SUSPENDED
            | CREATE_NEW_PROCESS_GROUP
            | DETACHED_PROCESS
            | CREATE_UNICODE_ENVIRONMENT;
        if plan == JobPlan::BreakAway {
            creation |= CREATE_BREAKAWAY_FROM_JOB;
        }
        let application = wide(command.application.as_os_str());
        let mut line: Vec<u16> = command
            .command_line
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let directory = wide(command.directory.as_os_str());
        let block = environment_block(command.environment);
        // SAFETY: all-zero is the documented initial state of both structures; the size field of
        // the first is set next.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
        let mut created: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every string is terminated and outlives the call, the command line is a mutable
        // buffer as the call requires, the environment is either absent or a terminated block of
        // wide strings, no handle is inherited, and `created` is a live out parameter.
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                creation,
                block
                    .as_ref()
                    .map_or(std::ptr::null(), |block| block.as_ptr().cast()),
                directory.as_ptr(),
                &raw const startup,
                &raw mut created,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            let detail = if plan == JobPlan::BreakAway && code(&error) == Some(ERROR_ACCESS_DENIED)
            {
                format!(
                    "a job above this starter's own does not let a process leave it, so {} was \
                     not started: {error}",
                    command.application.display()
                )
            } else {
                format!("start {}: {error}", command.application.display())
            };
            return Err(ChildRefusal::nothing_created(detail));
        }
        // SAFETY: the call above returned two new handles that nothing else owns.
        let child = Suspended {
            process: unsafe { OwnedHandle::from_raw_handle(created.hProcess) },
            thread: unsafe { OwnedHandle::from_raw_handle(created.hThread) },
            pid: created.dwProcessId,
        };
        let in_job = match child.in_any_job() {
            Ok(in_job) => in_job,
            Err(error) => {
                return Err(child.end(format!(
                    "whether the new process is in a job could not be read, so it was ended: \
                     {error}"
                )));
            }
        };
        if in_job && plan != JobPlan::StayInJob {
            return Err(child.end(
                "the new process is still inside a job after it was started outside this \
                 starter's own: a job above does not let it leave, so it was ended rather than \
                 run there"
                    .to_owned(),
            ));
        }
        let session = match child.session() {
            Ok(session) => session,
            Err(error) => {
                return Err(child.end(format!(
                    "the new process's login session could not be read, so it was ended: {error}"
                )));
            }
        };
        if session != command.session {
            return Err(child.end(format!(
                "the new process is in login session {session}, not {}, the daemon's; it was \
                 ended rather than run in a session whose sign-out would not be the daemon's",
                command.session
            )));
        }
        let identity = match child.identity() {
            Ok(identity) => identity,
            Err(detail) => return Err(child.end(detail)),
        };
        child.resume()?;
        Ok(StartedChild {
            identity,
            session,
            in_job,
        })
    }

    /// A child created suspended, with both of its handles.
    struct Suspended {
        process: OwnedHandle,
        thread: OwnedHandle,
        pid: u32,
    }

    impl Suspended {
        fn in_any_job(&self) -> io::Result<bool> {
            let mut in_job: windows_sys::core::BOOL = 0;
            // SAFETY: the process handle is open, a null job asks about any job, and `in_job` is a
            // live out parameter.
            let asked = unsafe {
                IsProcessInJob(
                    self.process.as_raw_handle(),
                    std::ptr::null_mut(),
                    &raw mut in_job,
                )
            };
            if asked == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(in_job != 0)
        }

        fn session(&self) -> io::Result<u32> {
            Token::of(self.process.as_raw_handle())?.session()
        }

        fn identity(&self) -> Result<ProcessStartIdentity, String> {
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            // SAFETY: the process handle is open with every right its creator has, and each
            // pointer is to a live local of the structure the call writes.
            let read = unsafe {
                GetProcessTimes(
                    self.process.as_raw_handle(),
                    &raw mut creation,
                    &raw mut exit,
                    &raw mut kernel,
                    &raw mut user,
                )
            };
            if read == 0 {
                return Err(format!(
                    "the new process's creation time could not be read, so it was ended: {}",
                    io::Error::last_os_error()
                ));
            }
            let created =
                (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
            match windows_answer(self.pid, WindowsReading::Created(created), filetime_now()) {
                ProcessQuery::Present(identity) => Ok(identity),
                ProcessQuery::Gone => Err(format!(
                    "the new process {} could not be described, so it was ended",
                    self.pid
                )),
                ProcessQuery::CannotEstablish(error) => Err(format!(
                    "the new process's identity could not be established, so it was ended: {error}"
                )),
            }
        }

        /// Lets the child run.
        fn resume(self) -> Result<(), ChildRefusal> {
            // SAFETY: the thread handle is the child's primary thread, open with every right.
            let previous = unsafe { ResumeThread(self.thread.as_raw_handle()) };
            if previous == u32::MAX {
                let error = io::Error::last_os_error();
                return Err(self.end(format!(
                    "the new process could not be let run, so it was ended: {error}"
                )));
            }
            Ok(())
        }

        /// Ends the child before it has run, and says so.
        fn end(self, detail: String) -> ChildRefusal {
            let process = self.process.as_raw_handle();
            // SAFETY: the process handle is open with the right to terminate, which a creator's
            // handle carries; the wait takes the same handle and a bound.
            let ended = unsafe {
                TerminateProcess(process, 1) != 0
                    && WaitForSingleObject(process, END_BOUND_MS) == WAIT_OBJECT_0
            };
            ChildRefusal {
                detail,
                remaining_pid: (!ended).then_some(self.pid),
            }
        }
    }

    /// The wall clock as a `FILETIME`, the unit a creation time is read in.
    fn filetime_now() -> u64 {
        /// The Unix epoch as a `FILETIME`.
        const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_nanos() / 100).unwrap_or(u64::MAX)
            });
        since.saturating_add(UNIX_EPOCH_AS_FILETIME)
    }

    /// The child's environment: the starter's own, with `added` set on top of it, or `None` when
    /// nothing is added and the child simply inherits.
    ///
    /// Windows compares variable names without regard to case, so a name set here replaces the
    /// inherited one of any case, and the block is sorted as the platform keeps it.
    fn environment_block(added: &[(String, String)]) -> Option<Vec<u16>> {
        if added.is_empty() {
            return None;
        }
        let mut variables: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os()
            .filter(|(name, _)| {
                !added.iter().any(|(set, _)| {
                    name.to_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case(set))
                })
            })
            .collect();
        variables.extend(
            added
                .iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        variables.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
        let mut block = Vec::new();
        for (name, value) in variables {
            block.extend(name.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        block.push(0);
        Some(block)
    }

    /// A job for a test to put a process in: nesting, a kill on close, a breakaway rule.
    ///
    /// Dropping it closes it, which ends its members when it kills on close.
    #[cfg(any(test, feature = "testing"))]
    #[derive(Debug)]
    pub struct Job(OwnedHandle);

    #[cfg(any(test, feature = "testing"))]
    impl Job {
        /// Creates an unnamed job with `limit_flags`.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when the job cannot be created or limited.
        pub fn create(limit_flags: u32) -> io::Result<Self> {
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            };

            // SAFETY: no attributes and no name; the call returns a new handle or null.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            // SAFETY: all-zero is the structure's documented initial state.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = limit_flags;
            let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .unwrap_or(0);
            // SAFETY: the job is open, and `limits` is a live structure of the size given.
            let set = unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    size,
                )
            };
            if set == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        /// Puts `process` in this job, nested beneath whatever job it is already in.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when the process cannot be assigned.
        pub fn assign(&self, process: BorrowedHandle<'_>) -> io::Result<()> {
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

            // SAFETY: both handles are open for the length of the call.
            let assigned = unsafe {
                AssignProcessToJobObject(self.0.as_raw_handle(), process.as_raw_handle())
            };
            if assigned == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// This process's own pseudo-handle, which needs no closing.
    fn current_process() -> HANDLE {
        // SAFETY: the call has no preconditions and returns a pseudo-handle.
        unsafe { GetCurrentProcess() }
    }

    /// Opens process `pid` for the questions this module asks of it.
    fn open_process(pid: u32) -> io::Result<OwnedHandle> {
        // SAFETY: three plain values; the call returns a new handle or null.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call above returned a new handle that nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    /// The executable an opened process runs, as Windows names it.
    fn image_of(process: &OwnedHandle) -> io::Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt as _;

        let mut buffer = vec![0_u16; 32_768];
        let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: the process is open with the right this call needs, and the buffer holds
        // `length` wide characters, which the call is told.
        let read = unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &raw mut length,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(usize::try_from(length).unwrap_or(0));
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
    }

    /// One process's token, opened to be asked about.
    struct Token(OwnedHandle);

    impl Token {
        fn of(process: HANDLE) -> io::Result<Self> {
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: the process handle is open or a pseudo-handle, and `token` is a live out
            // parameter.
            let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) };
            if opened == 0 || token.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(token) }))
        }

        fn session(&self) -> io::Result<u32> {
            let mut session = 0_u32;
            let mut returned = 0_u32;
            // SAFETY: the token is open for querying, and `session` is a live four-byte buffer,
            // which is what this class returns.
            let read = unsafe {
                GetTokenInformation(
                    self.0.as_raw_handle(),
                    TokenSessionId,
                    (&raw mut session).cast(),
                    4,
                    &raw mut returned,
                )
            };
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(session)
        }

        /// The buffer holding this token's user, aligned for the structure inside it.
        fn user(&self) -> io::Result<Vec<u64>> {
            let mut needed = 0_u32;
            // SAFETY: a null buffer and a zero length ask for the size, which is all this call is
            // for; its expected failure is ignored.
            let _ = unsafe {
                GetTokenInformation(
                    self.0.as_raw_handle(),
                    TokenUser,
                    std::ptr::null_mut(),
                    0,
                    &raw mut needed,
                )
            };
            let bytes = usize::try_from(needed)
                .unwrap_or(0)
                .max(std::mem::size_of::<TOKEN_USER>());
            let mut buffer = vec![0_u64; bytes.div_ceil(8)];
            let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
            // SAFETY: the buffer holds `length` bytes, at least the size reported above.
            let read = unsafe {
                GetTokenInformation(
                    self.0.as_raw_handle(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &raw mut needed,
                )
            };
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(buffer)
        }

        fn same_user_as(&self, other: &Self) -> io::Result<bool> {
            let mine = self.user()?;
            let theirs = other.user()?;
            // SAFETY: each buffer holds a `TOKEN_USER` the kernel wrote, aligned for it, and each
            // identifier it points at lies inside that buffer, which outlives the comparison.
            let equal = unsafe {
                let mine = std::ptr::read(mine.as_ptr().cast::<TOKEN_USER>()).User.Sid;
                let theirs = std::ptr::read(theirs.as_ptr().cast::<TOKEN_USER>())
                    .User
                    .Sid;
                !mine.is_null() && !theirs.is_null() && EqualSid(mine, theirs) != 0
            };
            Ok(equal)
        }
    }

    /// A security descriptor parsed from its text form, freed when it goes.
    struct OwnedDescriptor(PSECURITY_DESCRIPTOR);

    impl OwnedDescriptor {
        fn parse(text: &str) -> io::Result<Self> {
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: `wide` is a terminated wide string, `descriptor` a live out parameter, and
            // the size is not asked for.
            let parsed = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if parsed == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor))
        }
    }

    impl Drop for OwnedDescriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor came from the conversion above and is freed exactly once.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }

    /// A manual-reset event for one overlapped operation.
    struct Event(OwnedHandle);

    impl Event {
        fn new() -> io::Result<Self> {
            // SAFETY: no attributes and no name: a new, unsignalled, manual-reset event.
            let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
        }
    }

    /// Runs one overlapped operation on `handle` and waits for it until `deadline`.
    ///
    /// `begin` starts the operation with the structure it is given and returns what the call
    /// returned. The structure lives on this frame, and this does not return until the operation
    /// has finished or has been cancelled and has said so, so nothing the operation writes
    /// outlives what it writes into. A cancelled operation is reported as a timeout.
    fn complete(
        handle: HANDLE,
        deadline: Instant,
        begin: impl FnOnce(*mut OVERLAPPED) -> windows_sys::core::BOOL,
    ) -> io::Result<u32> {
        let event = Event::new()?;
        // SAFETY: all-zero is the structure's documented initial state; its event is set next.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0.as_raw_handle();
        if begin(&raw mut overlapped) == 0 {
            let error = io::Error::last_os_error();
            if code(&error) != Some(ERROR_IO_PENDING) {
                return Err(error);
            }
            // SAFETY: the event is open for the whole of this function.
            let waited =
                unsafe { WaitForSingleObject(event.0.as_raw_handle(), millis_until(deadline)) };
            if waited != WAIT_OBJECT_0 {
                // SAFETY: cancels only this operation, whose structure is still live.
                unsafe {
                    CancelIoEx(handle, &raw const overlapped);
                }
            }
        }
        let mut transferred = 0_u32;
        // SAFETY: waits for this one operation to finish, completed or cancelled, before the
        // structure it wrote into goes.
        let finished =
            unsafe { GetOverlappedResult(handle, &raw const overlapped, &raw mut transferred, 1) };
        if finished != 0 {
            return Ok(transferred);
        }
        let error = io::Error::last_os_error();
        if code(&error) == Some(ERROR_OPERATION_ABORTED) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the other end of the launch pipe did not answer in time",
            ));
        }
        Err(error)
    }

    /// The milliseconds left until `deadline`, for a wait: zero once it has passed, and never the
    /// value that means "wait for ever".
    fn millis_until(deadline: Instant) -> u32 {
        let left = deadline.saturating_duration_since(Instant::now());
        u32::try_from(left.as_millis())
            .unwrap_or(u32::MAX)
            .min(u32::MAX - 1)
    }

    /// The operating system's code for an error, when it has one.
    fn code(error: &io::Error) -> Option<u32> {
        error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
    }

    /// The pipe's full name, terminated, for a wide call.
    fn pipe_name(endpoint: &Endpoint) -> Vec<u16> {
        wide(std::ffi::OsStr::new(&format!(
            r"\\.\pipe\{}",
            endpoint.as_text()
        )))
    }

    /// Encodes a path or name for a wide call, with its terminator.
    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::Bytes;

    use super::*;
    use crate::testing::TempHost;

    fn boot(value: u8) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::BootTime,
            value: Bytes::new(vec![value; 8]),
        }
    }

    fn claim(deadline_boot_ms: u64) -> StartClaim {
        StartClaim {
            request: crate::new_uuid(),
            boot: boot(1),
            deadline_boot_ms,
        }
    }

    /// Where a job's limit flags leave a starter: only a job that kills on close and forbids
    /// breakaway refuses, a job that permits breakaway is left, and a job that does neither keeps
    /// the child.
    #[test]
    fn a_starter_refuses_only_a_job_that_kills_on_close_and_will_not_let_go() {
        assert_eq!(job_plan(None), JobPlan::Plain);
        // An `InteractiveToken` task's job, as measured.
        assert_eq!(job_plan(Some(0)), JobPlan::StayInJob);
        // An `S4U` task's job, as measured.
        assert_eq!(job_plan(Some(SILENT_BREAKAWAY_OK)), JobPlan::BreakAway);
        assert_eq!(job_plan(Some(BREAKAWAY_OK)), JobPlan::BreakAway);
        // A job that kills on close but lets its members leave is left.
        assert_eq!(
            job_plan(Some(KILL_ON_JOB_CLOSE | BREAKAWAY_OK)),
            JobPlan::BreakAway
        );
        // `cargo test`'s job, and the same with another limit beside it.
        assert_eq!(job_plan(Some(KILL_ON_JOB_CLOSE)), JobPlan::Refuse);
        assert_eq!(job_plan(Some(KILL_ON_JOB_CLOSE | 0x400)), JobPlan::Refuse);
        // A limit that neither kills nor lets go keeps the child where it is.
        assert_eq!(job_plan(Some(0x400)), JobPlan::StayInJob);
    }

    /// A claim is taken once, and admits a start only before its deadline and only in its boot.
    #[test]
    fn a_claim_is_taken_once_and_admits_only_before_its_deadline() {
        let host = TempHost::create();
        let environment = host.environment();
        let left = claim(10_000);
        leave_claim(&environment, &left).expect("the claim is left");

        let taken = take_claim(&environment, &boot(1), 5_000)
            .expect("the directory is read")
            .expect("the claim is taken");
        assert_eq!(taken.claim(), &left);
        assert!(taken.admits(&boot(1), 9_999));
        assert!(
            !taken.admits(&boot(1), 10_000),
            "the deadline itself has passed"
        );
        assert!(
            !taken.admits(&boot(2), 5_000),
            "another boot's clock says nothing"
        );
        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "a taken claim is not taken again"
        );
        taken.discard().expect("the taken claim is removed");
        assert_eq!(
            std::fs::read_dir(environment.start_claims_dir())
                .expect("the directory")
                .count(),
            0,
            "nothing of the claim is left"
        );
    }

    /// Leaving the same request again keeps the claim, and the deadline, it left the first time.
    #[test]
    fn a_request_left_again_keeps_its_first_deadline() {
        let host = TempHost::create();
        let environment = host.environment();
        let first = claim(10_000);
        leave_claim(&environment, &first).expect("the claim is left");
        let later = StartClaim {
            deadline_boot_ms: 60_000,
            ..first.clone()
        };
        leave_claim(&environment, &later).expect("a retry succeeds");
        let taken = take_claim(&environment, &boot(1), 5_000)
            .expect("the directory is read")
            .expect("the claim is taken");
        assert_eq!(taken.claim().deadline_boot_ms, 10_000);
        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "one request is one claim"
        );
    }

    /// A lapsed claim, or one from another boot, is removed and never handed to a starter; what is
    /// not a claim is left where it is.
    #[test]
    fn a_lapsed_claim_or_another_boots_is_removed_and_not_taken() {
        let host = TempHost::create();
        let environment = host.environment();
        leave_claim(&environment, &claim(1_000)).expect("a claim that lapses");
        let elsewhere = StartClaim {
            boot: boot(9),
            ..claim(60_000)
        };
        leave_claim(&environment, &elsewhere).expect("a claim of another boot");
        let stranger = environment.start_claims_dir().join("notes.txt");
        std::fs::write(&stranger, b"not a claim").expect("a file that is not a claim");

        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "nothing here may be acted on"
        );
        let left: Vec<String> = std::fs::read_dir(environment.start_claims_dir())
            .expect("the directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["notes.txt".to_owned()]);
    }

    /// Of many starters looking at once, one takes a claim.
    #[test]
    fn starters_racing_for_one_claim_take_it_once() {
        let host = TempHost::create();
        let environment = host.environment();
        leave_claim(&environment, &claim(60_000)).expect("the claim is left");
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let takers: Vec<_> = (0..8)
            .map(|_| {
                let environment = environment.clone();
                let start = std::sync::Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    take_claim(&environment, &boot(1), 5_000)
                        .expect("the directory is read")
                        .is_some()
                })
            })
            .collect();
        let taken = takers
            .into_iter()
            .map(|taker| taker.join().expect("the taker finishes"))
            .filter(|taken| *taken)
            .count();
        assert_eq!(taken, 1);
    }

    /// The recorded session survives being read back, is replaced by a later record, and goes when
    /// it is cleared.
    #[test]
    fn the_recorded_session_is_read_back_replaced_and_cleared() {
        let host = TempHost::create();
        let environment = host.environment();
        assert_eq!(
            recorded_session(&environment).expect("nothing recorded"),
            None
        );
        let first = RecordedSession {
            session: 3,
            boot: boot(1),
        };
        record_session(&environment, &first).expect("recorded");
        assert_eq!(
            recorded_session(&environment).expect("read back"),
            Some(first)
        );
        let second = RecordedSession {
            session: 5,
            boot: boot(2),
        };
        record_session(&environment, &second).expect("replaced");
        assert_eq!(
            recorded_session(&environment).expect("read back"),
            Some(second)
        );
        clear_recorded_session(&environment).expect("cleared");
        clear_recorded_session(&environment).expect("clearing twice is not a failure");
        assert_eq!(recorded_session(&environment).expect("gone"), None);
    }

    #[cfg(windows)]
    mod windows {
        use std::io::{BufRead as _, Write as _};
        use std::os::windows::io::AsHandle as _;
        use std::time::{Duration, Instant};

        use super::super::*;
        use crate::paths::Endpoint;

        /// A pipe name of this test's own.
        fn endpoint() -> Endpoint {
            Endpoint::from_name(format!("kalareach-test-{}", crate::new_uuid()))
                .expect("a short name")
        }

        fn soon() -> Instant {
            Instant::now() + Duration::from_secs(20)
        }

        /// A starter reaches the one launch waiting for it, each end reads the other as a process
        /// of this user in this session, and whole frames cross both ways.
        #[test]
        fn a_starter_reaches_a_waiting_launch_and_each_end_knows_the_other() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let reaching = {
                let endpoint = endpoint.clone();
                std::thread::spawn(move || {
                    let Reached::Connected(mut stream) =
                        connect(&endpoint, soon()).expect("the pipe is reached")
                    else {
                        panic!("a waiting instance is reached");
                    };
                    let server = stream.peer().expect("the daemon's end");
                    stream.send(b"hello", soon()).expect("sent");
                    let answer = stream.receive(soon()).expect("received");
                    (server, answer)
                })
            };
            let mut stream = listener
                .accept(soon())
                .expect("the wait")
                .expect("a starter reached it");
            let client = stream.peer().expect("the starter's end");
            assert_eq!(stream.receive(soon()).expect("received"), b"hello");
            stream.send(&[7_u8; 40_000], soon()).expect("sent");
            let (server, answer) = reaching.join().expect("the starter's end finishes");

            let own = std::env::current_exe().expect("this executable");
            let session = current_session().expect("this process's session");
            for (end, facts) in [("starter", &client), ("daemon", &server)] {
                assert_eq!(
                    facts.pid,
                    std::process::id(),
                    "the {end}'s end is this process"
                );
                assert!(facts.same_user, "the {end}'s end runs as this user");
                assert_eq!(facts.session, session, "the {end}'s end is in this session");
                assert_eq!(
                    std::fs::canonicalize(&facts.image).expect("the image"),
                    std::fs::canonicalize(&own).expect("this executable"),
                    "the {end}'s end runs this executable"
                );
            }
            assert_eq!(
                answer,
                vec![7_u8; 40_000],
                "a frame larger than one read arrives whole"
            );
        }

        /// An instance nobody reaches is withdrawn at its deadline, and a starter that comes later
        /// finds no launch waiting rather than a stale one.
        #[test]
        fn a_launch_nobody_reaches_is_withdrawn_at_its_deadline() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let began = Instant::now();
            let reached = listener
                .accept(Instant::now() + Duration::from_millis(300))
                .expect("the wait");
            assert!(reached.is_none(), "nobody reached it");
            assert!(
                began.elapsed() < Duration::from_secs(10),
                "the wait ended at its deadline, not later: {:?}",
                began.elapsed()
            );
            assert!(
                matches!(
                    connect(&endpoint, soon()).expect("the pipe is looked for"),
                    Reached::NoInstance
                ),
                "a late starter finds nothing waiting"
            );
        }

        /// Two launches waiting at once are each reached by one starter, and each starter's frame
        /// arrives at one of them only.
        #[test]
        fn two_waiting_launches_are_reached_once_each() {
            let endpoint = endpoint();
            let first = LaunchListener::create(&endpoint).expect("an instance");
            let second = LaunchListener::create(&endpoint).expect("a second instance");
            let starters: Vec<_> = b"ab"
                .iter()
                .copied()
                .map(|mark| {
                    let endpoint = endpoint.clone();
                    std::thread::spawn(move || {
                        let Reached::Connected(mut stream) =
                            connect(&endpoint, soon()).expect("the pipe is reached")
                        else {
                            panic!("a waiting instance is reached");
                        };
                        stream.send(&[mark], soon()).expect("sent");
                        stream.receive(soon()).expect("the answer")
                    })
                })
                .collect();
            let mut seen = Vec::new();
            for listener in [first, second] {
                let mut stream = listener
                    .accept(soon())
                    .expect("the wait")
                    .expect("a starter reached it");
                let mark = stream.receive(soon()).expect("a mark");
                stream.send(&mark, soon()).expect("echoed");
                seen.extend(mark);
            }
            let mut answers: Vec<u8> = starters
                .into_iter()
                .flat_map(|starter| starter.join().expect("a starter finishes"))
                .collect();
            seen.sort_unstable();
            answers.sort_unstable();
            assert_eq!(seen, vec![b'a', b'b']);
            assert_eq!(
                answers,
                vec![b'a', b'b'],
                "each starter heard only its own launch"
            );
        }

        /// A frame that declares more than the launch pipe's bound is refused before it is read.
        #[test]
        fn a_frame_over_the_bound_is_refused() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let reaching = {
                let endpoint = endpoint.clone();
                std::thread::spawn(move || {
                    let Reached::Connected(mut stream) =
                        connect(&endpoint, soon()).expect("the pipe is reached")
                    else {
                        panic!("a waiting instance is reached");
                    };
                    let refused = stream.send(&vec![0_u8; MAX_LAUNCH_FRAME + 1], soon());
                    assert!(refused.is_err(), "an oversized frame is not sent");
                    // A raw head that declares too much, as a hostile end could write it.
                    let declared = u32::try_from(MAX_LAUNCH_FRAME + 1).expect("fits");
                    stream
                        .write_all(&declared.to_le_bytes(), soon())
                        .expect("the head is written");
                })
            };
            let mut stream = listener
                .accept(soon())
                .expect("the wait")
                .expect("a starter reached it");
            let refused = stream.receive(soon()).expect_err("the frame is refused");
            assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
            reaching.join().expect("the starter's end finishes");
        }

        /// What a started process is given to run: long enough to be looked at, and it ends by
        /// itself.
        fn waiting_command() -> (std::path::PathBuf, String) {
            let shell =
                std::path::PathBuf::from(std::env::var_os("COMSPEC").expect("a command shell"));
            let line = format!("\"{}\" /d /c ping -n 6 127.0.0.1 >nul", shell.display());
            (shell, line)
        }

        /// Under this process's own job the start does what the job allows, and never runs a child
        /// silently inside a job that would end it: under `cargo test`, whose job kills on close
        /// and forbids breakaway, nothing is started.
        #[test]
        fn a_start_from_this_process_follows_its_own_job() {
            let (shell, line) = waiting_command();
            let directory = std::env::temp_dir();
            let plan = job_plan(crate::paths::current_job_limit_flags().expect("this job"));
            let session = current_session().expect("this session");
            let outcome = start_child(&ChildCommand {
                application: &shell,
                command_line: &line,
                directory: &directory,
                environment: &[],
                session,
            });
            match (plan, outcome) {
                (JobPlan::Refuse, Err(refusal)) => {
                    assert!(
                        refusal.detail.contains("ends its members when it closes"),
                        "the refusal names the job: {refusal}"
                    );
                    assert_eq!(refusal.remaining_pid, None, "nothing was created");
                }
                (JobPlan::Plain | JobPlan::BreakAway, Ok(started)) => {
                    assert!(!started.in_job, "a child that could leave the job left it");
                }
                (JobPlan::BreakAway, Err(refusal)) => {
                    assert!(
                        refusal.detail.contains("still inside a job"),
                        "a child a job above held was refused: {refusal}"
                    );
                    assert_eq!(refusal.remaining_pid, None, "and ended");
                }
                (JobPlan::StayInJob, Ok(started)) => assert!(started.in_job),
                (plan, outcome) => panic!("under {plan:?} the start gave {outcome:?}"),
            }
        }

        /// The variable that makes the helper test below act as a starter in the jobs its parent
        /// built, and says which case it is.
        const ROLE: &str = "KR_STARTER_TEST_ROLE";

        /// Acts as a starter, once its parent has put it in the jobs a case needs.
        #[test]
        #[ignore = "a helper process of the job tests below, which start it themselves"]
        fn a_starter_in_the_jobs_its_parent_built() {
            let Some(role) = std::env::var_os(ROLE) else {
                return;
            };
            let mut word = String::new();
            std::io::stdin()
                .read_line(&mut word)
                .expect("the parent's word that the jobs are in place");
            let session = current_session().expect("this session");
            let session = if role == "another-session" {
                session + 1
            } else {
                session
            };
            let (shell, line) = waiting_command();
            let directory = std::env::temp_dir();
            let outcome = start_child(&ChildCommand {
                application: &shell,
                command_line: &line,
                directory: &directory,
                environment: &[("KR_STARTER_TEST_MARK".to_owned(), "set".to_owned())],
                session,
            });
            match outcome {
                Ok(started) => println!(
                    "result started {} {} {} {}",
                    started.identity.pid.get(),
                    started.identity.start_value.get(),
                    started.in_job,
                    started.session
                ),
                Err(refusal) => println!(
                    "result refused remaining={:?} {}",
                    refusal.remaining_pid, refusal.detail
                ),
            }
        }

        /// Runs the helper as a starter inside `jobs`, outermost first, and returns the line it
        /// reported with the jobs, which are closed when they are dropped.
        fn starter_in(role: &str, jobs: &[u32]) -> (String, Vec<Job>) {
            let mut helper =
                std::process::Command::new(std::env::current_exe().expect("this test executable"))
                    .args([
                        "starter::tests::windows::a_starter_in_the_jobs_its_parent_built",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ROLE, role)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("the helper starts");
            let built: Vec<Job> = jobs
                .iter()
                .map(|flags| {
                    let job = Job::create(*flags).expect("a job");
                    job.assign(helper.as_handle())
                        .expect("the helper is put in it");
                    job
                })
                .collect();
            writeln!(helper.stdin.take().expect("the helper's input"), "go")
                .expect("the word is given");
            let output = std::io::BufReader::new(helper.stdout.take().expect("its output"));
            // Read to the end: the helper's test harness writes after the result line, and a pipe
            // closed under it fails the helper. The harness prints a test's name before running
            // it, so the result may follow the name on the same line.
            let lines: Vec<String> = output.lines().map_while(std::result::Result::ok).collect();
            let reported = lines
                .iter()
                .find_map(|line| line.find("result ").map(|at| line[at..].to_owned()))
                .unwrap_or_default();
            let status = helper.wait().expect("the helper ends");
            assert!(status.success(), "the helper ran cleanly: {status:?}");
            (reported, built)
        }

        /// The nesting a breakaway decision cannot see through: a starter whose own job permits
        /// breakaway, under a job that kills on close and does not, asks for its child to leave;
        /// the child leaves the inner job only, is still inside the outer one, and is ended rather
        /// than run there.
        #[test]
        fn a_child_a_job_above_will_not_let_go_is_ended_and_refused() {
            let (reported, _jobs) = starter_in("nested", &[KILL_ON_JOB_CLOSE, BREAKAWAY_OK]);
            assert!(
                reported.starts_with("result refused remaining=None")
                    && reported.contains("still inside a job"),
                "the child was refused and ended: {reported:?}"
            );
        }

        /// A starter in a job that neither kills on close nor permits breakaway, as an
        /// `InteractiveToken` task's, runs its child in that job, in its own session, and reports
        /// the identity Windows gives the child.
        #[test]
        fn a_child_in_a_job_that_neither_kills_nor_lets_go_runs_there() {
            let (reported, _jobs) = starter_in("keeping", &[0]);
            let words: Vec<&str> = reported.split(' ').collect();
            assert_eq!(&words[..2], ["result", "started"], "started: {reported:?}");
            let pid: u32 = words[2].parse().expect("a process identifier");
            let start_value: u64 = words[3].parse().expect("a start value");
            assert_eq!(words[4], "true", "the child is in the starter's job");
            assert_eq!(
                words[5],
                current_session().expect("this session").to_string(),
                "the child is in the daemon's session"
            );
            let identity = crate::identity::process_start_identity(pid)
                .expect("the child is still running and can be described");
            assert_eq!(
                identity.start_value.get(),
                start_value,
                "the identity reported is the child's own"
            );
        }

        /// A child that lands in a login session other than the daemon's is ended before it runs.
        #[test]
        fn a_child_in_another_session_than_the_daemons_is_ended() {
            let (reported, _jobs) = starter_in("another-session", &[0]);
            assert!(
                reported.starts_with("result refused remaining=None")
                    && reported.contains("login session"),
                "the child was refused and ended: {reported:?}"
            );
        }
    }
}
