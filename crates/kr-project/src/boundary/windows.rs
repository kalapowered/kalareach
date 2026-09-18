//! The Windows boundary: an application container per invocation, inside a job object.
//!
//! Windows has no single call that confines a process the way the other two platforms do, so the
//! boundary here is three mechanisms that each hold one of the guarantees.
//!
//! * **Execution and writes** come from an application container. A process in one is judged
//!   against its container's own identity as well as the account's: it reaches a file only where
//!   that file's permissions name the container. This invocation's container is granted read and
//!   write on the directories the operation owns **without the execute right**, so a driver, filter,
//!   hook or credential helper planted in the repository, in the staging directory or in this
//!   invocation's own temporary directory cannot be executed however it came to be there; and it is
//!   granted read and execute on Git's own installation, which is the only thing that may run.
//! * **The network** comes from the same container's capabilities. A local operation is given none
//!   at all, so it reaches no address whatever its configuration says. A remote one is given the
//!   client capability, which permits reaching the network and does **not** bound which ports it
//!   reaches: the port list this host builds is enforced on the other two platforms and not on this
//!   one, and bounding it here would need a system-wide filtering policy an ordinary account cannot
//!   set. That difference is stated rather than implied, here and in `crates/kr-project/README.md`.
//! * **Descendants** come from a job object the process is created inside, with breakaway refused
//!   and the job ending everything in it when this host lets go. That is what makes a cancellation
//!   here end the remote helper, the ssh process and the credential helper rather than only Git.
//!
//! ## What this costs, and what it refuses
//!
//! Granting a container read and execute on Git's own installation is a change to that
//! installation's permissions, and where Git is installed somewhere only an administrator may
//! change — `C:\Program Files\Git` is the ordinary case — this host cannot make it. It does not run
//! Git anyway: every grant is attempted before anything starts, and a grant this host cannot make
//! refuses the invocation and says so. Nothing here falls back to running Git outside its
//! container.
//!
//! A container also reaches a file only where that file's permissions name it **or** name every
//! application package, and this host cannot know which other permissions a repository already
//! carries. So the grants this host makes on the directories an operation owns are paired with a
//! refusal of the execute right to the same container, which no other permission can add back.
//!
//! Every grant this host makes is taken away again when the invocation ends, and the container
//! profile is deleted with it. A grant whose removal fails is left, and this host does not pretend
//! otherwise: the profile is per-invocation and named after nothing, so what is left names a
//! container that no longer exists.

#![expect(
    unsafe_code,
    reason = "an application container, a job object and a process created inside both are calls \
              with out-parameters and handle ownership that only the caller can promise; this \
              module holds those calls and nothing else"
)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
    REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_GROUP,
    TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, FreeSid,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE,
    SID_AND_ATTRIBUTES, WinCapabilityInternetClientSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList, ResumeThread,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use super::{Confinement, Invocation, OpenedDirectory, Reach};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "a per-invocation application container whose grants on the repository carry no execute right, \
     inside a job object that ends every process it started";

/// The rights a container is given on a directory an operation owns.
///
/// Read and write and nothing else. `FILE_EXECUTE` is deliberately absent: it is what makes a file
/// in the repository runnable, and the whole of the execution guarantee here is that it is not
/// granted anywhere but on Git's own installation.
const OWNED_DIRECTORY_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// The rights a container is given on Git's own installation.
const PROGRAM_RIGHTS: u32 = FILE_GENERIC_READ | FILE_EXECUTE;

/// One enclosed Git child, and everything that goes when it does.
#[derive(Debug)]
pub struct Spawned {
    process: OwnedHandle,
    /// Held for as long as the child is: closing it ends every process in it.
    _job: OwnedHandle,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    /// The container profile and the grants, both taken away when this is dropped.
    _container: Container,
}

impl Spawned {
    /// Takes the child's standard output, which is read once.
    pub fn stdout(&mut self) -> Option<std::fs::File> {
        self.stdout.take()
    }

    /// Takes the child's standard error, which is read once.
    pub fn stderr(&mut self) -> Option<std::fs::File> {
        self.stderr.take()
    }

    /// Returns the child's exit status when it has one.
    ///
    /// # Errors
    ///
    /// Returns whatever waiting on the child failed with.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let handle = self.process.as_raw_handle() as HANDLE;
        // SAFETY: the handle is this process's own, owned by `self` and open for the call.
        let waited = unsafe { WaitForSingleObject(handle, 0) };
        if waited == WAIT_TIMEOUT {
            return Ok(None);
        }
        if waited != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut code: u32 = 0;
        // SAFETY: the same handle, and an out-parameter this call owns for its duration.
        if unsafe { GetExitCodeProcess(handle, &raw mut code) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(std::os::windows::process::ExitStatusExt::from_raw(
            code,
        )))
    }

    /// Ends the child and everything it started, and says whether it could confirm that.
    ///
    /// The job holds every process this invocation created, including a process that tried to
    /// leave it, so ending the job ends all of them rather than only Git.
    pub fn end(&mut self) -> bool {
        let job = self._job.as_raw_handle() as HANDLE;
        // SAFETY: the job handle is this process's own and owned by `self`.
        let ended = unsafe { TerminateJobObject(job, 1) } != 0;
        if !ended {
            return false;
        }
        let handle = self.process.as_raw_handle() as HANDLE;
        // SAFETY: the process handle is this process's own and owned by `self`.
        unsafe { WaitForSingleObject(handle, 5_000) == WAIT_OBJECT_0 }
    }
}

/// The application container one invocation runs in, and the grants made for it.
#[derive(Debug)]
struct Container {
    name: Vec<u16>,
    sid: OwnedSid,
    capabilities: Vec<OwnedSid>,
    granted: Vec<PathBuf>,
}

impl Container {
    /// Records one path the container was given an entry on, once.
    fn record(&mut self, path: &Path) {
        if !self.granted.iter().any(|held| held == path) {
            self.granted.push(path.to_owned());
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        for path in &self.granted {
            let _ = set_access(path, self.sid.as_psid(), 0, REVOKE_ACCESS);
        }
        // SAFETY: the name is this process's own NUL-terminated buffer.
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

/// A security identifier this process holds a copy of.
///
/// The copy is what every call here points at, because a `Vec` this process owns has a lifetime
/// this code can reason about. Where the identifier also came from a call that allocated one, that
/// original pointer is kept beside the copy and freed the way its own call requires.
#[derive(Debug)]
struct OwnedSid {
    bytes: Vec<u8>,
    /// The pointer the platform allocated, when one was allocated, so it can be freed as itself.
    allocated: Option<PSID>,
}

impl OwnedSid {
    fn as_psid(&self) -> PSID {
        self.bytes.as_ptr().cast_mut().cast()
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if let Some(allocated) = self.allocated {
            // SAFETY: the pointer came from a call that allocated an identifier and nothing else
            // holds it; the copy beside it is an ordinary Rust allocation and is not touched here.
            unsafe {
                FreeSid(allocated);
            }
        }
    }
}

/// Starts one Git invocation inside its boundary.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when the container cannot be created, a grant cannot be
/// made, the job cannot be built or the process cannot be started. Nothing here starts Git outside
/// its container.
pub fn start(invocation: &Invocation<'_>, confinement: &Confinement) -> Result<Spawned> {
    let container = build(confinement)?;
    let job = job_object()?;
    let (out_read, out_write) = pipe()?;
    let (err_read, err_write) = pipe()?;
    let nul = open_nul()?;

    let mut capabilities: Vec<SID_AND_ATTRIBUTES> = container
        .capabilities
        .iter()
        .map(|capability| SID_AND_ATTRIBUTES {
            Sid: capability.as_psid(),
            Attributes: SE_GROUP_ENABLED as u32,
        })
        .collect();
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: container.sid.as_psid(),
        Capabilities: if capabilities.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities.as_mut_ptr()
        },
        CapabilityCount: u32::try_from(capabilities.len()).unwrap_or(0),
        Reserved: 0,
    };
    let mut jobs: [HANDLE; 1] = [job.as_raw_handle() as HANDLE];

    let mut inheritable: [HANDLE; 3] = [
        nul.as_raw_handle() as HANDLE,
        out_write.as_raw_handle() as HANDLE,
        err_write.as_raw_handle() as HANDLE,
    ];
    let mut attributes = AttributeList::create(3)?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        std::ptr::from_mut(&mut security).cast(),
        std::mem::size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        jobs.as_mut_ptr().cast(),
        std::mem::size_of::<HANDLE>(),
    )?;
    // Exactly these three. Without the list a child inherits every inheritable handle this process
    // holds, which during two invocations at once is the other one's pipes: its output would then
    // stay open after its own Git had gone, and this host would read a complete result as a
    // truncated one.
    attributes.set(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inheritable.as_mut_ptr().cast(),
        std::mem::size_of::<HANDLE>() * inheritable.len(),
    )?;

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nul.as_raw_handle() as HANDLE;
    startup.StartupInfo.hStdOutput = out_write.as_raw_handle() as HANDLE;
    startup.StartupInfo.hStdError = err_write.as_raw_handle() as HANDLE;
    startup.lpAttributeList = attributes.pointer();

    let mut command = command_line(invocation);
    let environment = environment_block(invocation.environment);
    // The directory the handle names, rather than the path the caller gave: the two are resolved in
    // the same moment and the identity is confirmed below before anything the child produced is
    // read.
    let directory = wide(final_path(&confinement.working)?.as_os_str());
    let program = wide(invocation.program.as_os_str());
    let mut information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is to a buffer this call owns for its duration, and the command line is
    // the mutable buffer the call is documented to require.
    let started = unsafe {
        CreateProcessW(
            program.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            std::ptr::from_mut(&mut startup).cast(),
            &raw mut information,
        )
    };
    if started == 0 {
        return Err(ProjectError::GitFailed {
            detail: format!(
                "{} could not start inside its boundary: {}",
                invocation.described,
                std::io::Error::last_os_error()
            )
            .into(),
        });
    }
    // SAFETY: both handles came from the call above and are this process's to own.
    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.cast()) };
    drop(out_write);
    drop(err_write);
    drop(nul);
    // The process was given a path, and it is not running yet. This is where that path is answered
    // for, before the process can do anything at all: the object at the name is opened again and
    // required to be the one this host opened before the spawn. A refusal here leaves a process
    // that never ran, and the job it was created in ends it when this host lets go of the handle.
    let confirmed = confinement.working.confirm_path();
    // SAFETY: the thread handle came from the call above and nothing else holds it.
    let resumed = unsafe {
        let resumed = confirmed.is_ok() && ResumeThread(information.hThread) != u32::MAX;
        CloseHandle(information.hThread);
        resumed
    };
    confirmed?;
    if !resumed {
        return Err(ProjectError::GitFailed {
            detail: format!(
                "{} was created inside its boundary and could not be started: {}",
                invocation.described,
                std::io::Error::last_os_error()
            )
            .into(),
        });
    }
    Ok(Spawned {
        process,
        _job: job,
        stdout: Some(out_read.into()),
        stderr: Some(err_read.into()),
        _container: container,
    })
}

/// Creates the container for one invocation and makes every grant it needs.
fn build(confinement: &Confinement) -> Result<Container> {
    let mut name = String::from("KalaReach.Git.");
    for byte in uuid::Uuid::new_v4().as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    let name = wide(OsStr::new(&name));
    let display = wide(OsStr::new("KalaReach repository operation"));
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: the two names are this process's own NUL-terminated buffers and the identifier is an
    // out-parameter this call owns for its duration.
    let created = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            std::ptr::null(),
            0,
            &raw mut sid,
        )
    };
    if created < 0 || sid.is_null() {
        return Err(ProjectError::GitFailed {
            detail: "this invocation could not be given a container of its own, so Git is not run"
                .into(),
        });
    }
    let sid = OwnedSid {
        bytes: sid_bytes(sid),
        allocated: Some(sid),
    };
    let mut capabilities = Vec::new();
    if matches!(confinement.reach, Reach::Outbound(_)) {
        capabilities.push(well_known(WinCapabilityInternetClientSid)?);
    }
    let mut container = Container {
        name,
        sid,
        capabilities,
        granted: Vec::new(),
    };
    // Read and write on the directories this operation owns, and the execute right refused to the
    // same container: a refusal beats every grant, including one a repository already carries for
    // every application package, so a program planted in the repository cannot be executed whatever
    // else its permissions say.
    for directory in confinement.written() {
        grant(
            &mut container,
            directory.path(),
            OWNED_DIRECTORY_RIGHTS,
            GRANT_ACCESS,
        )?;
        grant(&mut container, directory.path(), FILE_EXECUTE, DENY_ACCESS)?;
    }
    // Read and execute on Git's own installation, which is the only thing that may run.
    for program in confinement.executables() {
        grant(&mut container, program, PROGRAM_RIGHTS, GRANT_ACCESS)?;
    }
    let exec_path = confinement.exec_path.clone();
    grant(&mut container, &exec_path, PROGRAM_RIGHTS, GRANT_ACCESS)?;
    // A container's reads are confined too, so what Git reads outside the directories this
    // operation owns is granted by name rather than assumed.
    for readable in &confinement.readable {
        grant(&mut container, readable, FILE_GENERIC_READ, GRANT_ACCESS)?;
    }
    Ok(container)
}

/// Adds one entry for the container on one path, and records it for removal.
fn grant(container: &mut Container, path: &Path, rights: u32, mode: i32) -> Result<()> {
    set_access(path, container.sid.as_psid(), rights, mode).map_err(|error| {
        ProjectError::GitFailed {
            detail: format!(
                "{} could not be made reachable by this invocation's container, so Git is not run: \
                 {error}",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
        }
    })?;
    container.record(path);
    Ok(())
}

/// Adds or removes one entry from a path's permissions.
fn set_access(path: &Path, sid: PSID, rights: u32, mode: i32) -> std::io::Result<()> {
    let wide_path = wide(path.as_os_str());
    let mut existing: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the path is this process's own NUL-terminated buffer; the two out-parameters point
    // into memory the call allocates and this function frees below.
    let read = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut existing,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if read != 0 {
        return Err(std::io::Error::from_raw_os_error(read as i32));
    }
    let mut entry: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    entry.grfAccessPermissions = rights;
    entry.grfAccessMode = mode;
    // A directory's entry is inherited by what is in it and what is made in it, which is what
    // makes the grant cover the files an operation writes rather than only the directory itself.
    entry.grfInheritance = if path.is_dir() {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    entry.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_GROUP,
        ptstrName: sid.cast(),
    };
    let mut updated: *mut ACL = std::ptr::null_mut();
    // SAFETY: the entry and the existing list are this process's for the call, and the new list is
    // an out-parameter this function frees below.
    let built = unsafe { SetEntriesInAclW(1, &raw const entry, existing, &raw mut updated) };
    let outcome = if built == 0 {
        // SAFETY: the path and the new list are this process's own for the call.
        let written = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                updated,
                std::ptr::null_mut(),
            )
        };
        if written == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(written as i32))
        }
    } else {
        Err(std::io::Error::from_raw_os_error(built as i32))
    };
    // SAFETY: both were allocated by the calls above and nothing else holds them.
    unsafe {
        if !updated.is_null() {
            LocalFree(updated.cast());
        }
        if !descriptor.is_null() {
            LocalFree(descriptor.cast());
        }
    }
    outcome
}

/// Returns one of the system's own capability identifiers.
fn well_known(kind: i32) -> Result<OwnedSid> {
    let mut bytes = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut length = u32::try_from(bytes.len()).unwrap_or(0);
    // SAFETY: the buffer and its length are this process's own for the call.
    let built = unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if built == 0 {
        return Err(ProjectError::GitFailed {
            detail: "this invocation's container could not be given the capability its transport \
                     needs, so Git is not run"
                .into(),
        });
    }
    bytes.truncate(length as usize);
    Ok(OwnedSid {
        bytes,
        allocated: None,
    })
}

/// Copies one identifier out of the memory a call allocated for it.
fn sid_bytes(sid: PSID) -> Vec<u8> {
    // The identifier's length is in its own second byte: one header byte, one count of
    // sub-authorities, six bytes of authority, and four bytes for each sub-authority.
    // SAFETY: the pointer came from a call that allocated a whole identifier.
    let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
    let length = 8 + 4 * count;
    // SAFETY: the identifier is that many bytes long, by its own count.
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    bytes.to_vec()
}

/// Creates the job every process of this invocation is made inside.
///
/// Nothing may leave it: no breakaway right is given, so a process created with one is created in
/// the job anyway, and closing the handle ends everything still in it.
fn job_object() -> Result<OwnedHandle> {
    // SAFETY: an unnamed job with default permissions.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(ProjectError::GitFailed {
            detail: "this invocation could not be given a job of its own, so Git is not run".into(),
        });
    }
    // SAFETY: the handle came from the call above and is this process's to own.
    let job = unsafe { OwnedHandle::from_raw_handle(job.cast()) };
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the handle is this process's own and the structure is owned for the call.
    let set = unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            std::ptr::from_mut(&mut limits).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    if set == 0 {
        return Err(ProjectError::GitFailed {
            detail: "this invocation's job could not be told to end what it holds, so Git is not \
                     run"
            .into(),
        });
    }
    Ok(job)
}

/// Creates one pipe and returns the end this host reads and the end the child writes.
fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: both are out-parameters this call owns for its duration.
    let made = unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) };
    if made == 0 {
        return Err(ProjectError::GitFailed {
            detail: "this invocation's output could not be read, so Git is not run".into(),
        });
    }
    // SAFETY: the write end is the child's and is marked to be passed to it; the read end is this
    // host's alone and is not.
    unsafe {
        SetHandleInformation(write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
        Ok((
            OwnedHandle::from_raw_handle(read.cast()),
            OwnedHandle::from_raw_handle(write.cast()),
        ))
    }
}

/// Opens the empty device the child's input comes from.
fn open_nul() -> Result<OwnedHandle> {
    let name = wide(OsStr::new("NUL"));
    // SAFETY: the name is this process's own NUL-terminated buffer.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ProjectError::GitFailed {
            detail: "this invocation could not be given an empty input, so Git is not run".into(),
        });
    }
    // SAFETY: the handle came from the call above and is this process's to own.
    unsafe {
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        Ok(OwnedHandle::from_raw_handle(handle.cast()))
    }
}

/// The attribute list a process is created with.
struct AttributeList {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for AttributeList {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttributeList")
    }
}

impl AttributeList {
    fn create(entries: u32) -> Result<Self> {
        let mut size: usize = 0;
        // SAFETY: the call is asked for the size it needs and writes only that out-parameter.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), entries, 0, &raw mut size);
        }
        let mut bytes = vec![0_u8; size];
        // SAFETY: the buffer is this process's own and exactly the size the call asked for.
        let built = unsafe {
            InitializeProcThreadAttributeList(
                bytes.as_mut_ptr().cast::<LPPROC_THREAD_ATTRIBUTE_LIST>() as _,
                entries,
                0,
                &raw mut size,
            )
        };
        if built == 0 {
            return Err(ProjectError::GitFailed {
                detail: "this invocation's boundary could not be attached to it, so Git is not run"
                    .into(),
            });
        }
        Ok(Self { bytes })
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.bytes.as_mut_ptr().cast()
    }

    fn set(&mut self, attribute: usize, value: *mut std::ffi::c_void, size: usize) -> Result<()> {
        let list = self.pointer();
        // SAFETY: the list is this process's own and the value outlives the process creation it is
        // used for, because both are held by the caller until then.
        let set = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if set == 0 {
            return Err(ProjectError::GitFailed {
                detail: "this invocation's boundary could not be attached to it, so Git is not run"
                    .into(),
            });
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list is this process's own and nothing else holds it.
        unsafe {
            DeleteProcThreadAttributeList(self.bytes.as_mut_ptr().cast());
        }
    }
}

/// Returns the path the working directory's handle names, with nothing left to resolve.
fn final_path(working: &OpenedDirectory) -> Result<PathBuf> {
    // The handle this host already opened and verified, rather than the name opened again: opening
    // the name again is the very thing a substitution would answer differently.
    let handle = std::os::windows::io::AsHandle::as_handle(working.handle().handle());
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: the handle is borrowed from the directory this invocation holds open, and the buffer
    // is this process's own for the call.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            handle.as_raw_handle() as HANDLE,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(0),
            0,
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(ProjectError::Destination {
            detail: "the directory this invocation runs in could not be named, so Git is not run"
                .into(),
        });
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

/// Returns one string as the wide, NUL-terminated form every call here takes.
fn wide(text: &OsStr) -> Vec<u16> {
    let mut wide: Vec<u16> = text.encode_wide().collect();
    wide.push(0);
    wide
}

/// Returns the command line one invocation runs with, quoted as this platform reads it.
fn command_line(invocation: &Invocation<'_>) -> Vec<u16> {
    let mut line = String::new();
    push_quoted(&mut line, &invocation.program.as_os_str().to_string_lossy());
    for argument in invocation.arguments {
        line.push(' ');
        push_quoted(&mut line, &argument.to_string_lossy());
    }
    wide(OsStr::new(&line))
}

/// Adds one argument to a command line, quoted so it is read back as one argument.
fn push_quoted(line: &mut String, argument: &str) {
    line.push('"');
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                line.push('\\');
            }
            '"' => {
                for _ in 0..=backslashes {
                    line.push('\\');
                }
                backslashes = 0;
                line.push('"');
            }
            other => {
                backslashes = 0;
                line.push(other);
            }
        }
    }
    for _ in 0..backslashes {
        line.push('\\');
    }
    line.push('"');
}

/// Returns the environment block one invocation runs with.
fn environment_block(environment: &[(OsString, OsString)]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in environment {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}
