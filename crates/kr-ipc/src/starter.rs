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

use std::path::Path;

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
/// claim it left before, deadline and all, rather than a later one, and a claim once taken stays
/// taken for the rest of its boot: a retry cannot publish it again.
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
}

/// The largest claim or session record this host reads.
const MAX_RECORD_LEN: u64 = 4096;

/// The suffix of a claim: the request, as it was left.
const CLAIM: &str = "claim";

/// The suffix of the marker that says a claim was taken.
const TAKEN: &str = "taken";

/// Leaves `claim` for this environment's starter.
///
/// Leaving the same request twice leaves it once: the file is named for the request, is never
/// replaced, and stays until a later boot, so a retry can neither move the deadline the first
/// attempt set nor make a claim that was taken takeable again.
///
/// # Errors
///
/// Returns an error when the claims directory cannot be made or the claim cannot be written.
pub fn leave_claim(environment: &EnvironmentPaths, claim: &StartClaim) -> Result<()> {
    let directory = environment.start_claims_dir();
    crate::paths::create_private_tree(environment.runtime_root(), &directory)?;
    let path = directory.join(format!("{}.{CLAIM}", claim.request));
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
/// Taking a claim creates its taken marker, which only one creation can do: of any number of
/// starters looking at once, one takes each claim and every other finds it taken. A claim that has
/// lapsed is taken like any other and not returned, so nothing acts on it; the claim and its marker
/// stay for the rest of the boot, so the request cannot be taken again. A claim, and its marker,
/// from an earlier boot are removed. A claim that cannot be read is passed over, since nothing
/// could act on it. A name in the directory that is not a claim is left alone.
///
/// # Errors
///
/// Returns an error when the directory cannot be read, or a claim's taken marker cannot be
/// created for a reason other than another starter creating it first.
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
    let mut requests: Vec<Uuid> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let request: Uuid = name
                .to_str()?
                .strip_suffix(&format!(".{CLAIM}"))?
                .parse()
                .ok()?;
            (format!("{request}.{CLAIM}") == name.to_str()?).then_some(request)
        })
        .collect();
    requests.sort();
    for request in requests {
        let path = directory.join(format!("{request}.{CLAIM}"));
        let marker = directory.join(format!("{request}.{TAKEN}"));
        // A claim that cannot be read is passed over rather than ending the look: nothing could
        // act on it, and the claims after it are still looked at. Another starter removing it as
        // an earlier boot's while this one reads is the ordinary case, which Windows reports as
        // the name gone or as access refused to a file whose removal is under way.
        let Ok(claim) = read_claim(&path) else {
            continue;
        };
        if claim.boot != *boot {
            // An earlier boot's request: its deadline is on a clock that has restarted, and
            // nothing can act on it now. Whichever starter's removal takes, it goes; one that
            // fails here because another is removing it too changes nothing.
            for stale in [&marker, &path] {
                let _ = std::fs::remove_file(stale);
            }
            continue;
        }
        // Creating the marker refuses a name that exists, so exactly one of the starters that
        // create it at once succeeds. A rename of the claim would not do: on Windows it works
        // through a handle opened first, and two starters that had both opened the claim would
        // both succeed.
        match crate::paths::create_new_owner_only_file(&marker, &[]) {
            Ok(()) => {}
            Err(IpcError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        let taken = TakenClaim { claim };
        if taken.admits(boot, now_boot_ms) {
            return Ok(Some(taken));
        }
    }
    Ok(None)
}

/// What withdrawing a claim found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withdrawal {
    /// No starter had taken the claim, and none can take it now: nothing is started for it.
    Withdrawn,
    /// A starter took the claim first. That says nothing of what the starter did with it: a
    /// lapsed claim is taken and not acted on, and a start can fail after it was admitted.
    Taken,
}

/// Withdraws the claim for `request`, as the command that left it does once it stops waiting for
/// the start, or once the run meant to take it failed.
///
/// The command takes the claim itself, by creating its taken marker as a starter would. Only one
/// creation of the marker succeeds, so either the command withdraws the claim and no starter can
/// take it afterwards, or a starter took it first and the command learns so.
///
/// # Errors
///
/// Returns an error when the marker can be neither created nor found to exist.
pub fn withdraw_claim(environment: &EnvironmentPaths, request: Uuid) -> Result<Withdrawal> {
    let marker = environment
        .start_claims_dir()
        .join(format!("{request}.{TAKEN}"));
    match crate::paths::create_new_owner_only_file(&marker, &[]) {
        Ok(()) => Ok(Withdrawal::Withdrawn),
        Err(IpcError::Io { source, .. }) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(Withdrawal::Taken)
        }
        Err(error) => Err(error),
    }
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
    ChildCommand, ChildRefusal, LaunchListener, LaunchStream, LogAccess, MAX_LAUNCH_FRAME,
    NamedLock, PeerProcess, Reached, StartedChild, account_sid, connect, current_session,
    current_user_sid, in_any_job, open_log, pipe_client_is_this_user, process_facts, start_child,
};

#[cfg(all(windows, any(test, feature = "testing")))]
pub use self::windows::{Job, end_process};

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
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
        ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
        ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_SEM_TIMEOUT, FILETIME, GENERIC_READ,
        GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenSessionId, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThread, GetProcessTimes,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
        OpenProcessToken, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
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
            // Read before the descriptor is freed, whose release can replace it.
            let failure = (handle == INVALID_HANDLE_VALUE).then(io::Error::last_os_error);
            drop(descriptor);
            if let Some(error) = failure {
                return Err(error);
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
        /// so no later starter can reach it. A deadline that has passed when this is called, or
        /// that passes while a reach is being withdrawn, is `None` too, even for a starter that
        /// reached the instance already: that starter finds the pipe closed and starts nothing.
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
    /// Returns a timeout when `deadline` has passed, a permission error when the server runs as
    /// another account, and the operating system's error when the pipe cannot be opened for any
    /// other reason.
    pub fn connect(endpoint: &Endpoint, deadline: Instant) -> io::Result<Reached> {
        let name = pipe_name(endpoint);
        loop {
            if Instant::now() >= deadline {
                return Err(timed_out());
            }
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

    /// A lock every process of this user on the machine can take by one name, held until dropped.
    ///
    /// A named mutex: the operating system gives it to one holder at a time and hands it on when
    /// its holder ends, however it ends. It belongs to the thread that took it, so it is not
    /// passed to another.
    #[derive(Debug)]
    pub struct NamedLock {
        mutex: OwnedHandle,
        _thread: std::marker::PhantomData<*const ()>,
    }

    impl NamedLock {
        /// Takes the lock named `name` within `bound`.
        ///
        /// A name in the `Global\` namespace is one lock for every session on the machine. A lock
        /// another account made first cannot be opened, and is refused rather than waited for.
        ///
        /// # Errors
        ///
        /// Returns a timeout when another holder keeps it past `bound`, and the operating
        /// system's error when it cannot be made or opened.
        pub fn acquire(name: &str, bound: std::time::Duration) -> io::Result<Self> {
            use windows_sys::Win32::Foundation::WAIT_ABANDONED;
            use windows_sys::Win32::System::Threading::CreateMutexW;

            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: no attributes, not owned on creation, and a terminated name; the call returns
            // a new handle to the one mutex of that name, or null.
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            let mutex = unsafe { OwnedHandle::from_raw_handle(handle) };
            let wait = u32::try_from(bound.as_millis())
                .unwrap_or(u32::MAX)
                .min(u32::MAX - 1);
            // SAFETY: the handle is open for the length of the wait.
            match unsafe { WaitForSingleObject(mutex.as_raw_handle(), wait) } {
                // A holder that ended without releasing it leaves it abandoned, and the wait takes it.
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self {
                    mutex,
                    _thread: std::marker::PhantomData,
                }),
                _ => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{name} was held by another process for {bound:?}"),
                )),
            }
        }
    }

    impl Drop for NamedLock {
        fn drop(&mut self) {
            use windows_sys::Win32::System::Threading::ReleaseMutex;

            // SAFETY: the mutex is open and owned by this thread, which took it.
            unsafe {
                ReleaseMutex(self.mutex.as_raw_handle());
            }
        }
    }

    /// Whether process `pid` runs inside any job.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the process cannot be opened or asked.
    pub fn in_any_job(pid: u32) -> io::Result<bool> {
        let process = open_process(pid)?;
        let mut in_job: windows_sys::core::BOOL = 0;
        // SAFETY: the process is open with a right this call accepts, a null job asks about any
        // job, and `in_job` is a live out parameter.
        let asked = unsafe {
            IsProcessInJob(
                process.as_raw_handle(),
                std::ptr::null_mut(),
                &raw mut in_job,
            )
        };
        if asked == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(in_job != 0)
    }

    /// Returns the login session this process runs in.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when this process's token cannot be read.
    pub fn current_session() -> io::Result<u32> {
        Token::of(current_process())?.session()
    }

    /// Returns the account this process runs as, as its security identifier's text, `S-1-5-...`.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when this process's token cannot be read.
    pub fn current_user_sid() -> io::Result<String> {
        let user = Token::of(current_process())?.user()?;
        // SAFETY: the buffer holds a `TOKEN_USER` the kernel wrote, aligned for it, and the
        // identifier it points at lies inside the buffer, which outlives the conversion.
        let sid = unsafe { std::ptr::read(user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_text(sid)
    }

    /// Resolves an account's name, `name` or `DOMAIN\name`, to its security identifier's text.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when no account has that name.
    pub fn account_sid(name: &str) -> io::Result<String> {
        use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

        let account: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid_size = 0_u32;
        let mut domain_size = 0_u32;
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: a null buffer with a zero size asks for the sizes, which is all this call is
        // for; its expected failure is ignored.
        let _ = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                account.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sid_size,
                std::ptr::null_mut(),
                &raw mut domain_size,
                &raw mut kind,
            )
        };
        if sid_size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sid = vec![0_u64; usize::try_from(sid_size).unwrap_or(0).div_ceil(8)];
        let mut domain = vec![0_u16; usize::try_from(domain_size).unwrap_or(0).max(1)];
        // SAFETY: both buffers hold at least the sizes the call above reported, which this call is
        // told, and `kind` is a live out parameter.
        let found = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &raw mut sid_size,
                domain.as_mut_ptr(),
                &raw mut domain_size,
                &raw mut kind,
            )
        };
        if found == 0 {
            return Err(io::Error::last_os_error());
        }
        sid_text(sid.as_mut_ptr().cast())
    }

    /// Writes a security identifier in its text form.
    fn sid_text(sid: windows_sys::Win32::Security::PSID) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` points at a live identifier and `text` is a live out parameter.
        let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
        if converted == 0 || text.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0_usize;
        // SAFETY: the buffer the conversion allocated is terminated, so the scan stops inside it.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: the buffer holds `length` code units before its terminator.
        let written = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: the buffer came from the conversion above and is freed exactly once.
        unsafe {
            LocalFree(text.cast());
        }
        Ok(written)
    }

    /// What the environment's daemon log is opened for.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LogAccess {
        /// Appending, for the daemon's output: every write lands at the file's end, wherever
        /// another handle has left it.
        Append,
        /// Reading and truncating, for the command that starts the daemon, which reads what the
        /// start wrote and empties the log once it has grown too large. Truncating needs the right
        /// to write the file's data, which a handle opened for appending lacks.
        ReadAndTruncate,
    }

    /// Opens the environment's daemon log for `access`, creating it where it is absent, and takes
    /// it only when it is a regular file whose access-control list grants no account this host
    /// does not trust.
    ///
    /// It is opened without following a reparse point, so a link planted under its name opens as
    /// the link and is refused rather than written through. A file created here carries the list
    /// the environment's owner-only state directory gives everything created in it.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::UntrustedFile`](crate::IpcError::UntrustedFile) for a link, something
    /// other than a regular file, or a list that grants another account, and an I/O failure when
    /// it cannot be opened or its list cannot be read.
    pub fn open_log(path: &Path, access: LogAccess) -> crate::Result<std::fs::File> {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let untrusted = |reason| crate::IpcError::UntrustedFile {
            path: path.to_path_buf(),
            reason,
        };
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .create(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match access {
            LogAccess::Append => options.append(true),
            LogAccess::ReadAndTruncate => options.write(true),
        };
        let file = options
            .open(path)
            .map_err(|error| crate::IpcError::io("open", path, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| crate::IpcError::io("inspect", path, error))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(untrusted(
                "this file must not be a symbolic link or a junction",
            ));
        }
        if !metadata.is_file() {
            return Err(untrusted("this file must be a regular file"));
        }
        match crate::paths::check_access_list(file.as_handle(), &path.display().to_string(), false)
        {
            Ok(()) => Ok(file),
            Err(crate::paths::AccessListRefusal::Policy(_)) => Err(untrusted(
                "this file's access-control list grants an account this host does not trust",
            )),
            Err(crate::paths::AccessListRefusal::Unreadable(detail)) => Err(crate::IpcError::io(
                "inspect",
                path,
                io::Error::other(detail),
            )),
        }
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
        /// Where the child's standard output and standard error go: a file the starter opened,
        /// which the child is given and nothing else of the starter's is. `None` gives it neither.
        pub output: Option<BorrowedHandle<'a>>,
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
        // The child gets a console of its own that shows no window. Every console program it runs
        // shares that console: without one, each would be given a console of its own, whose
        // window would appear on the desktop of the person signed in, and whose creation fails
        // now and then when several are created at once.
        let mut creation = CREATE_SUSPENDED
            | CREATE_NEW_PROCESS_GROUP
            | CREATE_NO_WINDOW
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
        // The output file goes to the child as an inheritable copy named in a list of the handles
        // it may inherit, so nothing else this starter holds reaches it. Both live until the
        // create has returned.
        let handed = match command.output.map(Handed::output).transpose() {
            Ok(handed) => handed,
            Err(error) => {
                return Err(ChildRefusal::nothing_created(format!(
                    "the output file could not be handed to {}: {error}",
                    command.application.display()
                )));
            }
        };
        // SAFETY: all-zero is the documented initial state of both structures; the size field of
        // the first is set next.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
        let mut inherit = 0;
        if let Some(handed) = &handed {
            startup.StartupInfo.cb =
                u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
            startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdOutput = handed.handle.as_raw_handle();
            startup.StartupInfo.hStdError = handed.handle.as_raw_handle();
            startup.lpAttributeList = handed.list.pointer();
            creation |= EXTENDED_STARTUPINFO_PRESENT;
            inherit = 1;
        }
        let mut created: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every string is terminated and outlives the call, the command line is a mutable
        // buffer as the call requires, the environment is either absent or a terminated block of
        // wide strings, a handle is inherited only when it is named in the attribute list the
        // extended structure carries, which with the handle outlives the call, and `created` is a
        // live out parameter.
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit,
                creation,
                block
                    .as_ref()
                    .map_or(std::ptr::null(), |block| block.as_ptr().cast()),
                directory.as_ptr(),
                (&raw const startup).cast::<STARTUPINFOW>(),
                &raw mut created,
            )
        };
        drop(handed);
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
            // What decides is the wait, not the termination's own answer: a child that has already
            // ended cannot be terminated again, and is gone all the same.
            // SAFETY: the process handle is open with the rights to terminate and to wait, which a
            // creator's handle carries.
            let ended = unsafe {
                TerminateProcess(process, 1);
                WaitForSingleObject(process, END_BOUND_MS) == WAIT_OBJECT_0
            };
            ChildRefusal {
                detail,
                remaining_pid: (!ended).then_some(self.pid),
            }
        }
    }

    /// A file handed to a child as its standard output and standard error: an inheritable copy of
    /// the starter's handle, and the list that names it as the one handle the child inherits.
    struct Handed {
        handle: OwnedHandle,
        list: AttributeList,
    }

    impl Handed {
        fn output(file: BorrowedHandle<'_>) -> io::Result<Self> {
            let mut copy: HANDLE = std::ptr::null_mut();
            // SAFETY: the file handle is borrowed for the call, both process handles are this
            // process's own pseudo-handle, and `copy` is a live out parameter.
            let duplicated = unsafe {
                DuplicateHandle(
                    current_process(),
                    file.as_raw_handle(),
                    current_process(),
                    &raw mut copy,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if duplicated == 0 || copy.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            let handle = unsafe { OwnedHandle::from_raw_handle(copy) };
            let list = AttributeList::inheriting(handle.as_raw_handle())?;
            Ok(Self { handle, list })
        }
    }

    /// A process attribute list naming the one handle a child inherits.
    ///
    /// The list keeps a pointer to the handle's value rather than the value, so the value lives in
    /// the list's own allocation for as long as the list does.
    struct AttributeList {
        buffer: Vec<usize>,
        handles: Box<[HANDLE; 1]>,
    }

    impl AttributeList {
        fn inheriting(handle: HANDLE) -> io::Result<Self> {
            let mut size = 0_usize;
            // SAFETY: a null list with a zero size asks for the size, which is all this call is
            // for; its expected failure is ignored.
            let _ = unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut size)
            };
            if size == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut list = Self {
                buffer: vec![0_usize; size.div_ceil(std::mem::size_of::<usize>())],
                handles: Box::new([handle]),
            };
            // SAFETY: the buffer holds at least `size` bytes, aligned for the list, and `size`
            // says so.
            let initialised = unsafe {
                InitializeProcThreadAttributeList(list.as_pointer(), 1, 0, &raw mut size)
            };
            if initialised == 0 {
                // Nothing was initialised, so the list must not be deleted either.
                let error = io::Error::last_os_error();
                list.buffer = Vec::new();
                return Err(error);
            }
            // SAFETY: the list was initialised for one attribute, and the handle array it points
            // at is boxed with it and lives exactly as long as it does.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    list.as_pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    list.handles.as_ptr().cast(),
                    std::mem::size_of::<[HANDLE; 1]>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if updated == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(list)
        }

        /// The list, for a call that changes it.
        fn as_pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.buffer.as_mut_ptr().cast()
        }

        /// The list, for the create, which only reads it.
        fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.buffer.as_ptr().cast_mut().cast()
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            if !self.buffer.is_empty() {
                // SAFETY: the list was initialised in this buffer and is deleted exactly once.
                unsafe { DeleteProcThreadAttributeList(self.as_pointer()) };
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

    /// Ends the process `identity` names, for a test that had the Task Scheduler start it and
    /// must not leave it running.
    ///
    /// The process is opened and its creation time read from that handle, and it is ended through
    /// the same handle only when that is the identity's: a process that has taken the identifier
    /// since is never ended. Returns whether the process `identity` names is gone, ended here or
    /// ended before.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the process cannot be opened or read.
    #[cfg(any(test, feature = "testing"))]
    pub fn end_process(identity: &ProcessStartIdentity) -> io::Result<bool> {
        use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
        use windows_sys::Win32::System::Threading::{PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};

        let Ok(pid) = u32::try_from(identity.pid.get()) else {
            return Ok(true);
        };
        // SAFETY: three plain values; the call returns a new handle or null.
        let handle = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            // No process holds the identifier: the one named has ended.
            return if code(&error) == Some(ERROR_INVALID_PARAMETER) {
                Ok(true)
            } else {
                Err(error)
            };
        }
        // SAFETY: the call above returned a new handle that nothing else owns.
        let process = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the handle is open with the right to query it, and each out parameter is a live
        // local of the type the call writes.
        let read = unsafe {
            GetProcessTimes(
                process.as_raw_handle(),
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        let created =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        match windows_answer(pid, WindowsReading::Created(created), filetime_now()) {
            ProcessQuery::Present(current) if current.matches(identity) => {}
            // Another process holds the identifier now, or none does: the one named has ended.
            ProcessQuery::Present(_) | ProcessQuery::Gone => return Ok(true),
            ProcessQuery::CannotEstablish(error) => {
                return Err(io::Error::other(error.to_string()));
            }
        }
        // What decides is the wait, not the termination's own answer: a process that has already
        // ended cannot be terminated again, and is gone all the same.
        // SAFETY: the handle is open with the rights to terminate the process and to wait for it.
        let ended = unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
            WaitForSingleObject(process.as_raw_handle(), END_BOUND_MS) == WAIT_OBJECT_0
        };
        Ok(ended)
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
                same_sid(mine, theirs)
            };
            Ok(equal)
        }

        /// Opens the calling thread's token, which is the impersonated client's while a thread
        /// impersonates one.
        ///
        /// `OpenAsSelf` is set, so the access check for opening the token runs under this process's
        /// own context rather than the impersonated one; a client whose context could not open its
        /// own token still cannot stop this read.
        fn of_current_thread() -> io::Result<Self> {
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: a pseudo-handle for this thread, a query-only access mask, `OpenAsSelf` true,
            // and a live out parameter.
            let opened =
                unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
            if opened == 0 || token.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call above returned a new handle that nothing else owns.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(token) }))
        }
    }

    /// Whether two security identifiers name the same account.
    ///
    /// The decision the account checks turn on, factored out so it can be tested with identifiers
    /// built from their text form rather than from live tokens.
    fn same_sid(left: PSID, right: PSID) -> bool {
        // SAFETY: each pointer names a valid identifier for the duration of the call, or is null.
        unsafe { !left.is_null() && !right.is_null() && EqualSid(left, right) != 0 }
    }

    /// Impersonates the client at the other end of a named pipe for as long as it lives, and
    /// restores this thread's own token when it is dropped.
    ///
    /// A thread that returned to the runtime still carrying another account's token would run later
    /// work as that account, so a `RevertToSelf` that fails ends the process on a non-unwinding
    /// path rather than let that happen: there is no safe way to continue from it.
    struct ImpersonatedClient;

    impl ImpersonatedClient {
        fn of(pipe: BorrowedHandle<'_>) -> io::Result<Self> {
            // SAFETY: `pipe` is a borrowed handle to a connected named pipe; the call impersonates
            // that pipe's client on this thread and returns a boolean.
            if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self)
        }
    }

    impl Drop for ImpersonatedClient {
        fn drop(&mut self) {
            // A restoration this crate's own test makes fail, to prove the process then ends.
            #[cfg(test)]
            let fails = RESTORATION_FAILS.with(std::cell::Cell::get);
            #[cfg(not(test))]
            let fails = false;
            // SAFETY: restores this thread to its own token; the call has no preconditions.
            if fails || unsafe { RevertToSelf() } == 0 {
                // The thread must never re-enter the runtime still impersonating another account.
                std::process::abort();
            }
        }
    }

    #[cfg(test)]
    thread_local! {
        /// Makes the next account check unwind while it impersonates, for the restoration tests.
        static UNWIND_WHILE_IMPERSONATING: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        /// Makes every restoration on this thread report failure, for the test that the process
        /// then ends rather than continue as the client.
        static RESTORATION_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Whether the client connected to `pipe` runs as the account this process runs as.
    ///
    /// The calling thread must not already be impersonating anyone: the thread is restored with
    /// `RevertToSelf`, which leaves it with this process's own token, not with a token it held
    /// before. Every caller in this crate calls it from a runtime thread that never impersonates.
    ///
    /// The client's token is read from the connection itself, by impersonating it only long enough
    /// to open the thread token; the impersonation is always undone before this returns. Because the
    /// token comes from the connection and not from a process looked up by identifier, a client whose
    /// process has exited and whose identifier was reused cannot be taken for this account. An
    /// anonymous or otherwise unreadable client context is an error, which the caller refuses.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the client cannot be impersonated or its token
    /// read, or when this process's own token cannot be read.
    pub fn pipe_client_is_this_user(pipe: BorrowedHandle<'_>) -> io::Result<bool> {
        // This process's own token is opened before impersonating, so the comparison is against this
        // process and not the client this thread is about to take on.
        let own = Token::of(current_process())?;
        let client = {
            let _guard = ImpersonatedClient::of(pipe)?;
            #[cfg(test)]
            assert!(
                !UNWIND_WHILE_IMPERSONATING.with(|flag| flag.replace(false)),
                "an unwind this crate's own test injected while impersonating"
            );
            Token::of_current_thread()
            // `_guard` drops here, restoring this thread, before the result is unwrapped below.
        }?;
        client.same_user_as(&own)
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
    /// outlives what it writes into.
    ///
    /// The deadline is kept exactly. An operation is not begun once it has passed, even one that
    /// could finish at once, and an operation the wait gave up on is a timeout even if it finished
    /// while it was being cancelled: what missed the deadline is never reported as done.
    fn complete(
        handle: HANDLE,
        deadline: Instant,
        begin: impl FnOnce(*mut OVERLAPPED) -> windows_sys::core::BOOL,
    ) -> io::Result<u32> {
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        let event = Event::new()?;
        // SAFETY: all-zero is the structure's documented initial state; its event is set next.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0.as_raw_handle();
        let mut gave_up = false;
        if begin(&raw mut overlapped) == 0 {
            let error = io::Error::last_os_error();
            if code(&error) != Some(ERROR_IO_PENDING) {
                return Err(error);
            }
            // SAFETY: the event is open for the whole of this function.
            let waited =
                unsafe { WaitForSingleObject(event.0.as_raw_handle(), millis_until(deadline)) };
            if waited != WAIT_OBJECT_0 {
                gave_up = true;
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
        let error = (finished == 0).then(io::Error::last_os_error);
        if gave_up {
            return Err(timed_out());
        }
        match error {
            None => Ok(transferred),
            Some(error) if code(&error) == Some(ERROR_OPERATION_ABORTED) => Err(timed_out()),
            Some(error) => Err(error),
        }
    }

    /// The error a missed deadline is reported as.
    fn timed_out() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the other end of the launch pipe did not answer in time",
        )
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
    #[cfg(test)]
    mod account {
        use std::os::windows::io::{AsHandle as _, FromRawHandle as _, OwnedHandle};
        use std::time::{Duration, Instant};

        use windows_sys::Win32::Foundation::{
            ERROR_NO_TOKEN, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
        };
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_ANONYMOUS,
            SECURITY_SQOS_PRESENT,
        };

        use super::{
            LaunchListener, LaunchStream, PSID, RESTORATION_FAILS, Reached, Side, Token,
            UNWIND_WHILE_IMPERSONATING, connect, pipe_client_is_this_user, pipe_name, same_sid,
        };
        use crate::paths::Endpoint;

        /// One identifier parsed from its text form, freed when it is dropped.
        struct Sid(PSID);

        impl Sid {
            fn parse(text: &str) -> Self {
                let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
                let mut sid: PSID = std::ptr::null_mut();
                // SAFETY: `wide` is a terminated wide string held for the call, and `sid` is a live
                // out parameter the call fills with a freshly allocated identifier.
                let parsed = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) };
                assert!(
                    parsed != 0 && !sid.is_null(),
                    "the identifier {text} parses"
                );
                Self(sid)
            }
        }

        impl Drop for Sid {
            fn drop(&mut self) {
                // SAFETY: the identifier came from the parse above and is freed exactly once.
                unsafe {
                    LocalFree(self.0.cast());
                }
            }
        }

        fn endpoint() -> Endpoint {
            Endpoint::from_name(format!("kalareach-test-{}", crate::new_uuid()))
                .expect("a short name")
        }

        fn soon() -> Instant {
            Instant::now() + Duration::from_secs(20)
        }

        /// Whether this thread carries a token of its own, which it does only while impersonating.
        fn impersonating() -> bool {
            match Token::of_current_thread() {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(
                        error.raw_os_error(),
                        Some(ERROR_NO_TOKEN.cast_signed()),
                        "a thread without a token of its own says so: {error}"
                    );
                    false
                }
            }
        }

        /// A launch-pipe instance a client of this account has reached and sent one byte on, so its
        /// account can be read: Windows impersonates a pipe's client only once the server has read
        /// something it sent.
        fn spoken_to() -> (LaunchStream, LaunchStream) {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let reaching = std::thread::spawn(move || {
                let Reached::Connected(mut client) =
                    connect(&endpoint, soon()).expect("the pipe is reached")
                else {
                    panic!("a waiting instance is reached");
                };
                client.send(b"x", soon()).expect("the client speaks");
                client
            });
            let mut server = listener
                .accept(soon())
                .expect("the wait")
                .expect("a client reached it");
            assert_eq!(server.receive(soon()).expect("its byte"), b"x");
            (server, reaching.join().expect("the client finishes"))
        }

        /// The decision the account checks turn on: identifiers are the same account or they are
        /// not, and a missing identifier is never a match.
        #[test]
        fn the_same_identifier_matches_and_a_different_one_does_not() {
            let system = Sid::parse("S-1-5-18");
            let system_again = Sid::parse("S-1-5-18");
            let local_service = Sid::parse("S-1-5-19");
            assert!(
                same_sid(system.0, system_again.0),
                "one account matches itself"
            );
            assert!(
                !same_sid(system.0, local_service.0),
                "two accounts do not match"
            );
            assert!(
                !same_sid(std::ptr::null_mut(), system.0),
                "a missing identifier never matches"
            );
        }

        /// A client of this account is read from the connection as this account, and the thread
        /// that read it carries no token of its own afterwards.
        #[test]
        fn a_client_of_this_account_is_read_and_the_thread_is_itself_again() {
            let (server, _client) = spoken_to();
            assert!(!impersonating(), "the thread starts as itself");
            assert!(
                pipe_client_is_this_user(server.pipe.as_handle()).expect("the account is read"),
                "a client of this account is this account"
            );
            assert!(!impersonating(), "and the thread is itself again");
        }

        /// A client that opened the pipe anonymously gives no account to read, which is an error
        /// rather than a pass, and the thread is itself again afterwards.
        #[test]
        fn an_anonymous_client_is_not_read_and_the_thread_is_itself_again() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let name = pipe_name(&endpoint);
            // SAFETY: `name` is a terminated wide string; no attributes or template are given.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(
                handle, INVALID_HANDLE_VALUE,
                "the anonymous client opens the pipe"
            );
            let mut client = LaunchStream {
                // SAFETY: the call above returned a new handle that nothing else owns.
                pipe: unsafe { OwnedHandle::from_raw_handle(handle) },
                side: Side::Client,
            };
            let mut server = listener
                .accept(soon())
                .expect("the wait")
                .expect("the anonymous client reached it");
            client.send(b"x", soon()).expect("the client speaks");
            assert_eq!(server.receive(soon()).expect("its byte"), b"x");
            assert!(
                pipe_client_is_this_user(server.pipe.as_handle()).is_err(),
                "an anonymous client has no account to read"
            );
            assert!(!impersonating(), "and the thread is itself again");
        }

        /// An unwind while the client is impersonated still restores the thread on the way out.
        #[test]
        fn an_unwind_while_impersonating_leaves_the_thread_itself_again() {
            let (server, _client) = spoken_to();
            UNWIND_WHILE_IMPERSONATING.with(|flag| flag.set(true));
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pipe_client_is_this_user(server.pipe.as_handle())
            }));
            assert!(unwound.is_err(), "the injected unwind happened");
            assert!(!impersonating(), "and the thread is itself again");
        }

        /// A restoration that fails ends the process without unwinding and without going on as
        /// the client. Run in a process of its own, which this starts, since the process ends.
        #[test]
        fn a_restoration_that_fails_ends_the_process() {
            let this = std::env::current_exe().expect("this test binary");
            let output = std::process::Command::new(this)
                .args([
                    "--exact",
                    "starter::windows::account::a_process_whose_restoration_fails",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("KR_TEST_RESTORATION_FAILS", "1")
                .output()
                .expect("the process starts");
            let printed = String::from_utf8_lossy(&output.stdout);
            // `abort` ends a Windows process through the fast-fail path, which reports this status.
            assert_eq!(
                output.status.code(),
                Some(0xC000_0409_u32.cast_signed()),
                "the process ended through abort: {printed}"
            );
            assert!(
                printed.contains("impersonating"),
                "it reached the check: {printed}"
            );
            assert!(
                !printed.contains("continued"),
                "it did not go on after the failed restoration: {printed}"
            );
            assert!(
                !printed.contains("unwound"),
                "and it did not unwind: {printed}"
            );
        }

        /// The process [`a_restoration_that_fails_ends_the_process`] starts. It does nothing unless
        /// that test asks, so a run that includes ignored tests is not ended by it.
        #[test]
        #[ignore = "a helper process of the restoration test, which starts it itself"]
        fn a_process_whose_restoration_fails() {
            use std::io::Write as _;

            struct Unwound;
            impl Drop for Unwound {
                fn drop(&mut self) {
                    println!("unwound");
                }
            }

            if std::env::var_os("KR_TEST_RESTORATION_FAILS").is_none() {
                return;
            }
            let (server, _client) = spoken_to();
            RESTORATION_FAILS.with(|flag| flag.set(true));
            let _unwound = Unwound;
            println!("impersonating");
            std::io::stdout().flush().expect("flushes");
            let _ = pipe_client_is_this_user(server.pipe.as_handle());
            println!("continued");
        }
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
    }

    /// A command withdraws the claim it left once it stops waiting: a claim no starter took is
    /// withdrawn, and no starter takes it afterwards; one a starter took first is found taken,
    /// whether the starter acted on it or it had lapsed.
    #[test]
    fn a_claim_is_withdrawn_unless_a_starter_took_it_first() {
        let host = TempHost::create();
        let environment = host.environment();
        let unwanted = claim(10_000);
        leave_claim(&environment, &unwanted).expect("the claim is left");
        assert_eq!(
            withdraw_claim(&environment, unwanted.request).expect("the claim is withdrawn"),
            Withdrawal::Withdrawn
        );
        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "no starter takes a withdrawn claim"
        );

        let live = claim(10_000);
        leave_claim(&environment, &live).expect("the claim is left");
        let lapsed = claim(1_000);
        leave_claim(&environment, &lapsed).expect("a second claim is left");
        // A starter stops at the first claim it may act on; one that looks after it takes the
        // lapsed claim and acts on nothing.
        let taken = take_claim(&environment, &boot(1), 5_000)
            .expect("the directory is read")
            .expect("the live claim is taken");
        assert_eq!(taken.claim(), &live);
        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "nothing else may be acted on"
        );
        assert_eq!(
            withdraw_claim(&environment, live.request).expect("the marker is found"),
            Withdrawal::Taken,
            "the live one"
        );
        assert_eq!(
            withdraw_claim(&environment, lapsed.request).expect("the marker is found"),
            Withdrawal::Taken,
            "and the lapsed one, which was taken and not acted on"
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

    /// A request left again after its claim was taken is not taken again, whatever deadline the
    /// retry carries: the claim stays taken for the rest of its boot.
    #[test]
    fn a_request_left_again_after_it_was_taken_is_not_taken_again() {
        let host = TempHost::create();
        let environment = host.environment();
        let first = claim(10_000);
        leave_claim(&environment, &first).expect("the claim is left");
        take_claim(&environment, &boot(1), 5_000)
            .expect("the directory is read")
            .expect("the claim is taken");
        let retried = StartClaim {
            deadline_boot_ms: 60_000,
            ..first.clone()
        };
        leave_claim(&environment, &retried).expect("a retry succeeds");
        assert!(
            take_claim(&environment, &boot(1), 5_000)
                .expect("the directory is read")
                .is_none(),
            "the request was taken once, and is not taken again"
        );
        assert!(
            take_claim(&environment, &boot(1), 30_000)
                .expect("the directory is read")
                .is_none(),
            "nor once the first deadline has passed, whatever the retry carried"
        );
    }

    /// A lapsed claim is never handed to a starter and stays taken; one from another boot is
    /// removed; what is not a claim is left where it is.
    #[test]
    fn a_lapsed_claim_or_another_boots_is_removed_and_not_taken() {
        let host = TempHost::create();
        let environment = host.environment();
        let lapsing = claim(1_000);
        leave_claim(&environment, &lapsing).expect("a claim that lapses");
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
        let mut left: Vec<String> = std::fs::read_dir(environment.start_claims_dir())
            .expect("the directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let mut expected = vec![
            format!("{}.claim", lapsing.request),
            format!("{}.taken", lapsing.request),
            "notes.txt".to_owned(),
        ];
        expected.sort();
        assert_eq!(
            left, expected,
            "the lapsed claim stays taken, the other boot's is gone, the stranger is untouched"
        );
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

    /// A claim that cannot be read is passed over, and a live claim beside it is still taken.
    #[test]
    fn a_claim_that_cannot_be_read_is_passed_over() {
        let host = TempHost::create();
        let environment = host.environment();
        let live = claim(60_000);
        leave_claim(&environment, &live).expect("the live claim");
        for _ in 0..4 {
            let garbled = environment
                .start_claims_dir()
                .join(format!("{}.{CLAIM}", crate::new_uuid()));
            std::fs::write(&garbled, b"not a claim").expect("a claim nobody could read");
        }
        let taken = take_claim(&environment, &boot(1), 5_000)
            .expect("the look succeeds")
            .expect("the live claim is taken");
        assert_eq!(taken.claim(), &live);
    }

    /// Starters racing over a directory that holds claims of an earlier boot as well as a live one
    /// all finish their look, whichever of them removes the stale claims, and one takes the live
    /// claim.
    #[test]
    fn starters_racing_past_an_earlier_boots_claims_still_find_the_live_one() {
        let host = TempHost::create();
        let environment = host.environment();
        for _ in 0..16 {
            let stale = StartClaim {
                boot: boot(9),
                ..claim(60_000)
            };
            leave_claim(&environment, &stale).expect("an earlier boot's claim");
        }
        let live = claim(60_000);
        leave_claim(&environment, &live).expect("the live claim");
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let takers: Vec<_> = (0..8)
            .map(|_| {
                let environment = environment.clone();
                let start = std::sync::Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    take_claim(&environment, &boot(1), 5_000)
                })
            })
            .collect();
        let mut taken = Vec::new();
        for taker in takers {
            let look = taker.join().expect("the taker finishes");
            let found = look.expect("a look that races another starter's removal still succeeds");
            taken.extend(found);
        }
        assert_eq!(taken.len(), 1, "one starter took the live claim");
        assert_eq!(taken[0].claim(), &live);
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

        /// A deadline that has passed hands nothing over, even to a starter that reached the
        /// instance already: the instance is withdrawn and that starter finds the pipe closed.
        #[test]
        fn a_starter_already_there_is_handed_nothing_once_the_deadline_has_passed() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            let Reached::Connected(mut starter) =
                connect(&endpoint, soon()).expect("the pipe is reached")
            else {
                panic!("a waiting instance is reached");
            };
            assert!(
                listener.accept(Instant::now()).expect("the wait").is_none(),
                "nothing is handed over after the deadline"
            );
            let closed = starter
                .receive(soon())
                .expect_err("the pipe was closed under it");
            assert_eq!(closed.kind(), std::io::ErrorKind::UnexpectedEof);
        }

        /// A read or a write whose deadline has passed is a timeout, even when it could finish at
        /// once; and reaching the pipe after the deadline is a timeout too.
        #[test]
        fn an_operation_after_its_deadline_is_a_timeout_even_when_it_could_finish_at_once() {
            let endpoint = endpoint();
            let listener = LaunchListener::create(&endpoint).expect("an instance");
            assert_eq!(
                connect(&endpoint, Instant::now())
                    .expect_err("too late to reach it")
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            let Reached::Connected(mut starter) =
                connect(&endpoint, soon()).expect("the pipe is reached")
            else {
                panic!("a waiting instance is reached");
            };
            let mut daemon = listener
                .accept(soon())
                .expect("the wait")
                .expect("the starter reached it");
            starter.send(b"waiting", soon()).expect("sent");
            assert_eq!(
                daemon
                    .receive(Instant::now())
                    .expect_err("the read is too late")
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            assert_eq!(
                daemon
                    .send(b"late", Instant::now())
                    .expect_err("the write is too late")
                    .kind(),
                std::io::ErrorKind::TimedOut
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

        /// This process's account is named by its identifier, and its name resolves to the same
        /// identifier, whether it is given bare or with its domain.
        #[test]
        fn this_account_is_found_by_its_name_and_its_identifier() {
            let own = current_user_sid().expect("this process's account");
            assert!(
                own.starts_with("S-1-"),
                "an identifier in its text form: {own}"
            );
            let user = std::env::var("USERNAME").expect("this account's name");
            let domain = std::env::var("USERDOMAIN").expect("this account's domain");
            assert_eq!(
                account_sid(&format!("{domain}\\{user}")).expect("the qualified name"),
                own
            );
            assert_eq!(account_sid(&user).expect("the bare name"), own);
            assert!(
                account_sid("kalareach-no-such-account-4f1c").is_err(),
                "an unknown name names no account"
            );
        }

        /// A named lock has one holder at a time: a second taker waits while it is held, and takes
        /// it once it is let go.
        #[test]
        fn a_named_lock_has_one_holder_at_a_time() {
            let name = format!("Global\\kalareach-test-{}", crate::new_uuid());
            let held = NamedLock::acquire(&name, Duration::from_secs(5)).expect("the first holder");
            let waiting = {
                let name = name.clone();
                std::thread::spawn(move || {
                    NamedLock::acquire(&name, Duration::from_millis(300)).map(|_| ())
                })
            };
            assert_eq!(
                waiting
                    .join()
                    .expect("the second taker finishes")
                    .expect_err("it is held")
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            drop(held);
            let later = {
                let name = name.clone();
                std::thread::spawn(move || {
                    NamedLock::acquire(&name, Duration::from_secs(5)).map(|_| ())
                })
            };
            later
                .join()
                .expect("the later taker finishes")
                .expect("it is taken once it is let go");
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
                output: None,
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

        /// The variable that names the file the helper hands its child as the child's output.
        const OUTPUT: &str = "KR_STARTER_TEST_OUTPUT";

        /// What a started process is given to run when it has somewhere to write: a line to each of
        /// its standard output and standard error, and then it ends.
        fn writing_command() -> (std::path::PathBuf, String) {
            let shell =
                std::path::PathBuf::from(std::env::var_os("COMSPEC").expect("a command shell"));
            let line = format!(
                "\"{}\" /d /c \"echo to its output& echo to its error 1>&2\"",
                shell.display()
            );
            (shell, line)
        }

        /// The variable that has the helper below say whether it has a console.
        const CONSOLE: &str = "KR_STARTER_TEST_CONSOLE";

        /// What a started process is given to run when the case asks about its console: this test
        /// executable, as the helper below.
        fn console_command() -> (std::path::PathBuf, String) {
            let executable = std::env::current_exe().expect("this test executable");
            let line = format!(
                "\"{}\" starter::tests::windows::a_child_that_says_whether_it_has_a_console --exact \
                 --ignored --nocapture --test-threads=1",
                executable.display()
            );
            (executable, line)
        }

        /// Says on its standard output whether this process has a console, which only a process
        /// with one can open for writing.
        #[test]
        #[ignore = "a helper process the console test below has a starter start"]
        fn a_child_that_says_whether_it_has_a_console() {
            if std::env::var_os(CONSOLE).is_none() {
                return;
            }
            let console = std::fs::OpenOptions::new()
                .write(true)
                .open("CONOUT$")
                .is_ok();
            println!("console {console}");
        }

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
            let written = std::env::var_os(OUTPUT).map(|path| {
                open_log(std::path::Path::new(&path), LogAccess::Append)
                    .expect("the output file this case names")
            });
            let mut environment = vec![("KR_STARTER_TEST_MARK".to_owned(), "set".to_owned())];
            let (shell, line) = if role == "console" {
                environment.push((CONSOLE.to_owned(), "1".to_owned()));
                console_command()
            } else if written.is_some() {
                writing_command()
            } else {
                (shell, line)
            };
            let outcome = start_child(&ChildCommand {
                application: &shell,
                command_line: &line,
                directory: &directory,
                environment: &environment,
                session,
                output: written.as_ref().map(|file| file.as_handle()),
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
            starter_writing_to(role, jobs, None)
        }

        /// Runs the helper as [`starter_in`] does, handing its child `output` as the child's
        /// standard output and standard error when one is given.
        fn starter_writing_to(
            role: &str,
            jobs: &[u32],
            output: Option<&std::path::Path>,
        ) -> (String, Vec<Job>) {
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("this test executable"));
            command
                .args([
                    "starter::tests::windows::a_starter_in_the_jobs_its_parent_built",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(ROLE, role)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            if let Some(output) = output {
                command.env(OUTPUT, output);
            }
            let mut helper = command.spawn().expect("the helper starts");
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

        /// A directory of one test's own under the temporary directory, removed when dropped.
        struct Scratch(std::path::PathBuf);

        impl Scratch {
            fn create() -> Self {
                let path =
                    std::env::temp_dir().join(format!("kr-starter-output-{}", crate::new_uuid()));
                std::fs::create_dir(&path).expect("a directory of this test's own");
                Self(path)
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// A file the starter hands its child is where the child's standard output and standard
        /// error both go, appended to what the file already held.
        #[test]
        fn a_child_writes_its_output_and_its_errors_to_the_file_it_is_handed() {
            let directory = Scratch::create();
            let log = directory.0.join("controller.log");
            std::fs::write(&log, "an earlier start\r\n").expect("what the log held before");
            let (reported, _jobs) = starter_writing_to("keeping", &[0], Some(&log));
            let words: Vec<&str> = reported.split(' ').collect();
            assert_eq!(&words[..2], ["result", "started"], "started: {reported:?}");
            let pid: u32 = words[2].parse().expect("a process identifier");
            let start_value: u64 = words[3].parse().expect("a start value");
            // The child writes two lines and ends; the number stops naming it once it has.
            let deadline = Instant::now() + Duration::from_secs(30);
            while crate::identity::process_start_identity(pid)
                .is_ok_and(|identity| identity.start_value.get() == start_value)
            {
                assert!(
                    Instant::now() < deadline,
                    "the child ended within the bound"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            let written = std::fs::read_to_string(&log).expect("the log");
            assert!(
                written.starts_with("an earlier start"),
                "what was there stays: {written:?}"
            );
            assert!(
                written.contains("to its output") && written.contains("to its error"),
                "both streams reach the file: {written:?}"
            );
        }

        /// A child the starter creates has a console of its own, which shows no window: a console
        /// program it runs shares it rather than being given one, whose window would appear on
        /// the desktop of the person signed in.
        #[test]
        fn a_child_has_a_console_of_its_own() {
            let directory = Scratch::create();
            let log = directory.0.join("controller.log");
            let (reported, _jobs) = starter_writing_to("console", &[0], Some(&log));
            assert!(
                reported.starts_with("result started "),
                "started: {reported:?}"
            );
            let deadline = Instant::now() + Duration::from_secs(60);
            let said = loop {
                let written = std::fs::read_to_string(&log).unwrap_or_default();
                if written.contains("console ") || Instant::now() > deadline {
                    break written;
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            assert!(said.contains("console true"), "the child said: {said:?}");
        }

        /// The daemon log is taken only as a regular file whose list grants no account this host
        /// does not trust; a new one is created, and one that is there is appended to.
        #[test]
        fn a_log_is_opened_only_as_a_regular_file_of_this_users_alone() {
            use std::io::Write as _;

            let directory = Scratch::create();
            let log = directory.0.join("controller.log");
            let mut opened = open_log(&log, LogAccess::Append).expect("a new log is created");
            opened.write_all(b"first\n").expect("written");
            drop(opened);
            let mut opened = open_log(&log, LogAccess::Append).expect("the log is opened again");
            opened.write_all(b"second\n").expect("appended");
            drop(opened);
            assert_eq!(
                std::fs::read_to_string(&log).expect("the log"),
                "first\nsecond\n"
            );

            let folder = directory.0.join("a-directory");
            std::fs::create_dir(&folder).expect("a directory where the log would be");
            for access in [LogAccess::Append, LogAccess::ReadAndTruncate] {
                assert!(
                    open_log(&folder, access).is_err(),
                    "a directory is not a log"
                );
            }

            let shared = directory.0.join("shared.log");
            crate::paths::create_file_with_descriptor(&shared, "D:P(A;;GA;;;OW)(A;;FR;;;WD)")
                .expect("a log everyone may read");
            for access in [LogAccess::Append, LogAccess::ReadAndTruncate] {
                assert!(
                    matches!(
                        open_log(&shared, access),
                        Err(crate::IpcError::UntrustedFile { .. })
                    ),
                    "a log another account may read is refused"
                );
            }
        }

        /// The command that starts the daemon empties a log that has grown too large through the
        /// handle it checked, while a daemon's handle appends to it: the daemon's next line lands
        /// at the start of the emptied file, not after a gap where the old lines were.
        #[test]
        fn a_log_opened_for_reading_is_emptied_while_a_daemon_appends_to_it() {
            use std::io::{Read as _, Write as _};

            let directory = Scratch::create();
            let log = directory.0.join("controller.log");
            let mut daemon = open_log(&log, LogAccess::Append).expect("the daemon's handle");
            daemon.write_all(b"an earlier start\n").expect("written");
            let mut command =
                open_log(&log, LogAccess::ReadAndTruncate).expect("the command's handle");
            let mut earlier = String::new();
            command.read_to_string(&mut earlier).expect("read");
            assert_eq!(earlier, "an earlier start\n");
            command.set_len(0).expect("the log is emptied");
            daemon.write_all(b"this start\n").expect("appended");
            drop(daemon);
            assert_eq!(
                std::fs::read_to_string(&log).expect("the log"),
                "this start\n"
            );
        }
    }
}
