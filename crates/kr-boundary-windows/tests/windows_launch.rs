//! What the launcher, the job, the descriptors and the error mode do, shown on a Windows guest.
//!
//! These cases start real children under a real logon token of a throwaway account and read the
//! platform's own answers: which job a child is in before it runs, which handles it holds, who may
//! open it, which error mode it inherited and whether a crash leaves a dump. They run only in a
//! disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored afterwards, with the
//! variables the guest's runner sets up:
//!
//! - `KR_BOUNDARY_BIN` names a directory that holds `kr-launch-stand-in.exe` and, under `raw`, the
//!   broker built with the `testing` feature.
//!
//! A case that changes the machine (the crash reporting settings) puts it back when it ends.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    GetAce, GetAclInformation, GetSecurityDescriptorControl, ImpersonateLoggedOnUser,
    OWNER_SECURITY_INFORMATION, RevertToSelf, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetExitCodeProcess, GetThreadId, OpenProcess, OpenThread,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use kr_boundary_windows::env::{EnvBlock, Kind, QualifiedGit, RootPaths, build_env};
use kr_boundary_windows::quote::quote_command_line;
use kr_boundary_windows::win::ffi::{Handle, Sid, system_windows_directory};
use kr_boundary_windows::win::job::{Job, LIMIT_FLAGS, Limits, ReadBack, State};
use kr_boundary_windows::win::launch::{
    ChildSpec, InvocationId, LaunchError, ResumePermit, Std, SuspendedChild, TokenSpec,
    VerifiedPath, launch, pipe,
};
use kr_boundary_windows::win::sd::{OwnedSd, Principals, SdKind, descriptor, descriptor_from_text};
use kr_boundary_windows::win::{account, acl, broker, token};

const STILL_ACTIVE: u32 = 259;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_VM_READ: u32 = 0x0010;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const SYSTEM_SID: &str = "S-1-5-18";
const GUEST_GIT: &str = r"C:\Program Files\Git";

fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the stand-in and the broker"),
    )
}

/// A throwaway account with its token, its folders and everything a launch needs.
struct Fixture {
    account: String,
    sid: Sid,
    group: Sid,
    token: Handle,
    dir: PathBuf,
    scratch: PathBuf,
    stand_in: PathBuf,
    env: EnvBlock,
    descriptor: OwnedSd,
    /// A list that gives the group every right on the process, for the controls that show what the
    /// system would do with a crash if nothing else stood in the way.
    full_descriptor: OwnedSd,
}

impl Fixture {
    fn new() -> Fixture {
        assert!(
            token::current_is_administrator().unwrap(),
            "the case must run elevated"
        );
        broker::init();
        for privilege in [
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
        ] {
            token::enable_privilege(privilege).unwrap();
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let account = format!("krlaunch{}", &id[..6]);
        let sid = account::create(&account).expect("the throwaway account is made");
        let group = token::new_invocation_group();
        let token = token::boundary_token(&account, &group).expect("the boundary token is made");
        let dir = PathBuf::from(r"C:\Users\Public").join(format!("krlaunch-{}", &id[..12]));
        std::fs::create_dir_all(&dir).unwrap();
        let readable = descriptor(
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )
        .unwrap();
        acl::set_protected(&dir, &readable).unwrap();
        // The folder a child may write: the group may modify it, nothing else is named.
        let scratch = dir.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let private = descriptor(
            SdKind::PrivateRoot,
            &Principals {
                group: Some(group.clone()),
                ..Principals::default()
            },
        )
        .unwrap();
        acl::set_protected(&scratch, &private).unwrap();
        // The private root's own folders, made under it so that they inherit the group's right.
        std::fs::create_dir_all(scratch.join("tmp")).unwrap();
        std::fs::create_dir_all(scratch.join("home")).unwrap();
        let stand_in = dir.join("kr-launch-stand-in.exe");
        std::fs::copy(bin().join("kr-launch-stand-in.exe"), &stand_in).unwrap();
        let env = build_env(
            Kind::Proof,
            &RootPaths {
                system: system_windows_directory().unwrap(),
                boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
                private_root: scratch.display().to_string(),
            },
            None,
            &QualifiedGit {
                dir: GUEST_GIT.to_owned(),
            },
        )
        .unwrap();
        let descriptor = descriptor(
            SdKind::ProcessThread,
            &Principals {
                group: Some(group.clone()),
                ..Principals::default()
            },
        )
        .unwrap();
        let full_descriptor = descriptor_from_text(&format!(
            "O:SYD:P(A;;0x1fffff;;;{})(A;;0x1fffff;;;SY)",
            group.to_text()
        ))
        .unwrap();
        Fixture {
            account,
            sid,
            group,
            token,
            dir,
            scratch,
            stand_in,
            env,
            descriptor,
            full_descriptor,
        }
    }

    fn spec<'a>(
        &'a self,
        job: &'a Job,
        program: &Path,
        arguments: &[&str],
        stdout: Std,
        stderr: Std,
    ) -> ChildSpec<'a> {
        self.spec_with(job, program, arguments, stdout, stderr, &self.descriptor)
    }

    fn spec_with<'a>(
        &'a self,
        job: &'a Job,
        program: &Path,
        arguments: &[&str],
        stdout: Std,
        stderr: Std,
        descriptor: &'a OwnedSd,
    ) -> ChildSpec<'a> {
        let name = program.display().to_string();
        let mut parts = vec![name.as_str()];
        parts.extend_from_slice(arguments);
        ChildSpec {
            token: TokenSpec::Boundary(&self.token),
            job,
            program: VerifiedPath::new(program).unwrap(),
            command_line: quote_command_line(&parts),
            cwd: &self.dir,
            env: &self.env,
            stdin: Std::Nul,
            stdout,
            stderr,
            process_descriptor: descriptor,
            thread_descriptor: descriptor,
        }
    }

    /// The stand-in, started suspended with its output in a pipe.
    fn start(&self, job: &Job, arguments: &[&str]) -> (SuspendedChild, Handle) {
        let (read, write) = pipe().unwrap();
        let child = launch(self.spec(job, &self.stand_in, arguments, Std::Pipe(write), Std::Nul))
            .expect("the stand-in is started");
        (child, read)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = account::delete(&self.account);
        let _ = account::delete_profile(&self.sid);
    }
}

const INVOCATION: InvocationId = InvocationId([7; 16]);

fn resume(child: SuspendedChild) -> kr_boundary_windows::win::launch::Child {
    let permit = ResumePermit::for_cases(INVOCATION, &child);
    child.resume(permit).expect("the child is resumed")
}

/// Everything the pipe holds until every writer has closed it.
fn read_to_end(pipe: &Handle) -> String {
    let mut text = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        let mut read = 0_u32;
        // SAFETY: the pipe is open and the buffer is the length given.
        let ok = unsafe {
            ReadFile(
                pipe.raw(),
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &raw mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return String::from_utf8_lossy(&text).into_owned();
        }
        text.extend_from_slice(&chunk[..read as usize]);
    }
}

/// What the pipe holds now, without waiting for more.
fn available(pipe: &Handle) -> String {
    let mut ready = 0_u32;
    // SAFETY: the pipe is open and the out-parameter is local.
    let peeked = unsafe {
        PeekNamedPipe(
            pipe.raw(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &raw mut ready,
            std::ptr::null_mut(),
        )
    };
    if peeked == 0 || ready == 0 {
        return String::new();
    }
    let mut chunk = vec![0_u8; ready as usize];
    let mut read = 0_u32;
    // SAFETY: the pipe is open and the buffer is `ready` bytes.
    unsafe {
        ReadFile(
            pipe.raw(),
            chunk.as_mut_ptr().cast(),
            ready,
            &raw mut read,
            std::ptr::null_mut(),
        );
    }
    String::from_utf8_lossy(&chunk[..read as usize]).into_owned()
}

/// Reads until the text holds the needle, polling the pipe up to a deadline.
fn read_until(pipe: &Handle, needle: &str, deadline: Duration) -> String {
    let started = Instant::now();
    let mut text = String::new();
    while !text.contains(needle) {
        text.push_str(&available(pipe));
        assert!(
            started.elapsed() < deadline,
            "{needle:?} did not come; the pipe holds {text:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    text
}

fn exit_code(process: &Handle) -> u32 {
    let mut code = 0_u32;
    // SAFETY: the process handle is open.
    unsafe {
        GetExitCodeProcess(process.raw(), &raw mut code);
    }
    code
}

fn value_of(text: &str, key: &str) -> String {
    let marker = format!("{key}=");
    let start = text
        .find(&marker)
        .unwrap_or_else(|| panic!("{key} is in {text:?}"))
        + marker.len();
    text[start..]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn parse_mode(text: &str) -> u32 {
    u32::from_str_radix(value_of(text, "error-mode").trim_start_matches("0x"), 16).unwrap()
}

fn own_error_mode() -> u32 {
    // SAFETY: reads the process's own error mode.
    unsafe { GetErrorMode() }
}

fn processes() -> Vec<(u32, u32, String)> {
    // SAFETY: a snapshot of the processes, read through the platform's own record.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let snapshot = Handle::new(snapshot, "the process snapshot").unwrap();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = Vec::new();
        let mut more = Process32FirstW(snapshot.raw(), &raw mut entry);
        while more != 0 {
            let length = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(0);
            found.push((
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                String::from_utf16_lossy(&entry.szExeFile[..length]),
            ));
            more = Process32NextW(snapshot.raw(), &raw mut entry);
        }
        found
    }
}

fn pids_named(prefix: &str) -> BTreeSet<u32> {
    processes()
        .into_iter()
        .filter(|(_, _, name)| name.to_lowercase().starts_with(prefix))
        .map(|(pid, _, _)| pid)
        .collect()
}

/// The process and every descendant of it, read by parent identifier.
fn tree_of(root: u32) -> BTreeSet<u32> {
    let all = processes();
    let mut tree = BTreeSet::from([root]);
    loop {
        let before = tree.len();
        for (pid, parent, _) in &all {
            if tree.contains(parent) {
                tree.insert(*pid);
            }
        }
        if tree.len() == before {
            return tree;
        }
    }
}

// ---- the handle table of a process that has not run ----

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

/// The values of the handles a process holds, as the system's own table lists them.
fn handle_values(process: &Handle) -> Vec<usize> {
    const PROCESS_HANDLE_INFORMATION: i32 = 51;
    const LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    let mut words = 1 << 13;
    loop {
        let mut buffer = vec![0_u64; words];
        let mut returned = 0_u32;
        // SAFETY: the buffer is aligned and as long as the length given.
        let status = unsafe {
            NtQueryInformationProcess(
                process.raw(),
                PROCESS_HANDLE_INFORMATION,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &raw mut returned,
            )
        };
        if status == LENGTH_MISMATCH {
            words *= 4;
            continue;
        }
        assert_eq!(status, 0, "the handle table could be read");
        // The record: a count, a reserved word, then entries of five words each.
        let count = buffer[0] as usize;
        return (0..count)
            .map(|index| buffer[2 + index * 5] as usize)
            .collect();
    }
}

fn inheritable_event() -> Handle {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the attributes are this function's own for the call.
    let raw = unsafe { CreateEventW(&raw const attributes, 0, 0, std::ptr::null()) };
    Handle::new(raw, "an inheritable event").unwrap()
}

// ---- descriptors read back from a kernel object ----

struct Security {
    owner: String,
    protected: bool,
    allowed: Vec<(String, u32)>,
}

fn security_of(object: HANDLE) -> Security {
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: the object is open and the out-parameters are local; the descriptor is freed below.
    unsafe {
        let status = GetSecurityInfo(
            object,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        );
        assert_eq!(status, 0, "the descriptor could be read");
        let mut control = 0_u16;
        let mut revision = 0_u32;
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision);
        let mut size: ACL_SIZE_INFORMATION = std::mem::zeroed();
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );
        let mut allowed = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            GetAce(dacl, index, &raw mut ace);
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            assert_eq!((*ace).Header.AceType, 0, "every entry allows");
            let sid = Sid::from_ptr((&raw mut (*ace).SidStart).cast());
            allowed.push((sid.to_text(), (*ace).Mask));
        }
        let found = Security {
            owner: Sid::from_ptr(owner).to_text(),
            protected: control & 0x1000 != 0,
            allowed,
        };
        LocalFree(descriptor);
        found
    }
}

fn open_process(pid: u32, access: u32) -> Result<Handle, u32> {
    // SAFETY: opens a process by identifier; the result is checked.
    let raw = unsafe { OpenProcess(access, 0, pid) };
    Handle::new(raw, "a process").map_err(|error| error.code)
}

/// What opening a process asks of the platform when the caller is the boundary token and nothing
/// else: the token's invocation group is the only entry that can match.
fn open_as(token: &Handle, pid: u32, access: u32) -> Result<(), u32> {
    let token = token.raw() as usize;
    std::thread::spawn(move || {
        // SAFETY: the token handle outlives the thread because the caller joins it.
        unsafe {
            assert_ne!(
                ImpersonateLoggedOnUser(token as HANDLE),
                0,
                "the token can be impersonated"
            );
        }
        let opened = open_process(pid, access).map(|_| ());
        // SAFETY: ends the impersonation this thread began.
        unsafe {
            RevertToSelf();
        }
        opened
    })
    .join()
    .unwrap()
}

fn open_thread_as(token: &Handle, thread_id: u32, access: u32) -> Result<(), u32> {
    let token = token.raw() as usize;
    std::thread::spawn(move || {
        // SAFETY: as in `open_as`.
        unsafe {
            assert_ne!(
                ImpersonateLoggedOnUser(token as HANDLE),
                0,
                "the token can be impersonated"
            );
        }
        // SAFETY: opens a thread by identifier; the result is checked.
        let raw = unsafe { OpenThread(access, 0, thread_id) };
        let opened = Handle::new(raw, "a thread")
            .map(|_| ())
            .map_err(|error| error.code);
        // SAFETY: ends the impersonation this thread began.
        unsafe {
            RevertToSelf();
        }
        opened
    })
    .join()
    .unwrap()
}

// ---- the cases ----

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_is_in_its_job_and_has_run_nothing_until_it_is_resumed() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    assert_eq!(job.state(), State::Fresh);
    let (suspended, output) = fixture.start(&job, &["report"]);
    assert!(
        suspended.in_job_checked,
        "the launcher asked and was told the child is in the job"
    );
    assert!(
        job.contains(&suspended.process).unwrap(),
        "in the job before the resume"
    );
    assert_eq!(
        job.process_ids().unwrap(),
        [suspended.pid],
        "the job holds the child alone"
    );
    assert_eq!(job.active_processes().unwrap(), 1);
    assert_eq!(exit_code(&suspended.process), STILL_ACTIVE);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        available(&output),
        "",
        "a child that was not resumed has written nothing"
    );
    let child = resume(suspended);
    let text = read_to_end(&output);
    assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
    assert_eq!(
        value_of(&text, "in-job"),
        "true",
        "the child itself reports it is in a job"
    );
    assert_eq!(value_of(&text, "pid"), child.pid.to_string());
    let ended = job.end(&[&child], Duration::from_secs(10));
    assert!(ended.all_exited && ended.active_zero);
    assert_eq!(job.state(), State::Ended);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn exactly_the_three_standard_handles_reach_a_child_whatever_else_is_open_or_launching() {
    let fixture = Fixture::new();
    // Handles that a careless launch would pass on: inheritable, open in the broker, in no list.
    let decoys: Vec<Handle> = (0..16).map(|_| inheritable_event()).collect();
    let decoy_values: Vec<usize> = decoys.iter().map(|handle| handle.raw() as usize).collect();
    let one = |fixture: &Fixture| {
        let job = Job::new(Limits::INVOCATION).unwrap();
        let (read, write) = pipe().unwrap();
        let (error_read, error_write) = pipe().unwrap();
        let listed = [write.raw() as usize, error_write.raw() as usize];
        let suspended = launch(fixture.spec(
            &job,
            &fixture.stand_in,
            &["handles"],
            Std::Pipe(write),
            Std::Pipe(error_write),
        ))
        .unwrap();
        let before: Vec<usize> = handle_values(&suspended.process);
        let child = resume(suspended);
        let text = read_to_end(&read);
        drop(read_to_end(&error_read));
        assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
        let after: BTreeSet<usize> = text
            .lines()
            .filter(|line| line.contains("inherit=1"))
            .map(|line| {
                usize::from_str_radix(
                    line.split_whitespace()
                        .nth(1)
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap()
            })
            .collect();
        (before, after, listed)
    };
    let mut seen = Vec::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..3)
            .map(|_| scope.spawn(|| (0..4).map(|_| one(&fixture)).collect::<Vec<_>>()))
            .collect();
        seen.extend((0..4).map(|_| one(&fixture)));
        for worker in workers {
            seen.extend(worker.join().unwrap());
        }
    });
    assert_eq!(seen.len(), 16);
    for (before, after, listed) in seen {
        let table: BTreeSet<usize> = before.iter().copied().collect();
        println!(
            "before the resume {table:x?}; inheritable after {after:x?}; the pipe ends {listed:x?}"
        );
        assert_eq!(
            table.len(),
            3,
            "the child's table before the resume holds three handles: {table:x?}"
        );
        for listed in listed {
            assert!(
                table.contains(&listed),
                "the pipe end {listed:#x} reached the child"
            );
        }
        assert_eq!(
            after, table,
            "the inheritable handles after the resume are the three that were there before"
        );
        for decoy in &decoy_values {
            assert!(!table.contains(decoy), "the decoy {decoy:#x} was inherited");
        }
    }
    drop(decoys);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_process_and_thread_name_the_group_and_the_system_and_the_group_cannot_change_them() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (suspended, output) = fixture.start(&job, &["spawn-hold"]);
    let group = fixture.group.to_text();
    let expected = [
        (group.clone(), 0x0013_ffff_u32),
        (SYSTEM_SID.to_owned(), 0x001f_ffff_u32),
    ];
    for (what, object) in [
        ("process", suspended.process.raw()),
        ("thread", suspended.thread.raw()),
    ] {
        let found = security_of(object);
        assert_eq!(found.owner, SYSTEM_SID, "the {what}'s owner");
        assert!(found.protected, "the {what}'s list is protected");
        let mut allowed = found.allowed.clone();
        allowed.sort();
        let mut want = expected.to_vec();
        want.sort();
        assert_eq!(allowed, want, "the {what}'s entries");
    }
    let pid = suspended.pid;
    // SAFETY: the thread handle is open.
    let thread_id = unsafe { GetThreadId(suspended.thread.raw()) };
    let child = resume(suspended);
    let text = read_until(&output, "grandchild pid=", Duration::from_secs(30));
    let grandchild: u32 = value_of(&text, "grandchild pid").parse().unwrap();
    // The group may use the child and may not change who else may.
    assert_eq!(
        open_as(
            &fixture.token,
            pid,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        ),
        Ok(())
    );
    assert_eq!(
        open_as(&fixture.token, pid, WRITE_DAC),
        Err(5),
        "no right to change the list"
    );
    assert_eq!(
        open_as(&fixture.token, pid, WRITE_OWNER),
        Err(5),
        "no right to change the owner"
    );
    assert_eq!(
        open_thread_as(&fixture.token, thread_id, THREAD_QUERY_LIMITED_INFORMATION),
        Ok(())
    );
    assert_eq!(open_thread_as(&fixture.token, thread_id, WRITE_DAC), Err(5));
    // Every process in the job has a descriptor that names the group and the system and nobody else:
    // the child's own, and its descendant's, which comes from the token's default list.
    let in_job = job.process_ids().unwrap();
    assert!(in_job.contains(&pid) && in_job.contains(&grandchild));
    for process in in_job {
        let open = open_process(process, READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let found = security_of(open.raw());
        for (sid, _) in &found.allowed {
            assert!(
                *sid == group || sid == SYSTEM_SID,
                "process {process} names {sid}"
            );
        }
        assert!(
            found.allowed.iter().any(|(sid, _)| *sid == group),
            "process {process} names the invocation's group"
        );
    }
    let ended = job.end(&[&child], Duration::from_secs(10));
    assert!(ended.all_exited && ended.active_zero);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_job_holds_the_whole_tree_with_the_limits_asked_for_and_ends_every_process() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    assert_eq!(
        job.read_back().unwrap(),
        ReadBack {
            flags: LIMIT_FLAGS,
            active_processes: 16,
            memory_bytes: 1 << 30,
        },
        "the flags and both caps as the platform reports them"
    );
    assert_eq!(LIMIT_FLAGS, 0x2608);
    let (suspended, output) = fixture.start(&job, &["spawn-hold"]);
    let child = resume(suspended);
    let text = read_until(&output, "grandchild pid=", Duration::from_secs(30));
    let grandchild: u32 = value_of(&text, "grandchild pid").parse().unwrap();
    let listed: BTreeSet<u32> = job.process_ids().unwrap().into_iter().collect();
    assert_eq!(
        listed,
        tree_of(child.pid),
        "the job's process list is the child's tree read by parent"
    );
    assert!(listed.contains(&grandchild));
    // The job's own count is the list's length. A console program that a detached child starts
    // without the detached flag gets a console host of its own, which is in the job too: the names
    // are printed so that the census of a real operation can be told what to expect.
    let names: Vec<String> = processes()
        .into_iter()
        .filter(|(pid, _, _)| listed.contains(pid))
        .map(|(pid, parent, name)| format!("{name} (pid {pid}, parent {parent})"))
        .collect();
    println!("the job holds: {}", names.join(", "));
    assert_eq!(job.active_processes().unwrap() as usize, listed.len());
    let ended = job.end(&[&child], Duration::from_secs(10));
    assert!(
        ended.all_exited,
        "every retained process object is signalled"
    );
    assert!(ended.active_zero, "the job counts no active process");
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(
        open_process(grandchild, READ_CONTROL)
            .map_or(true, |process| exit_code(&process) != STILL_ACTIVE),
        "the grandchild is gone with the job"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_that_asks_to_break_away_from_the_job_is_refused_or_stays_in() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (suspended, output) = fixture.start(&job, &["breakaway"]);
    let child = resume(suspended);
    let text = read_to_end(&output);
    println!("breakaway: {text}");
    assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
    if text.contains("breakaway-refused") {
        // The platform refused the flag: nothing left the job.
    } else {
        assert!(text.contains("breakaway-started"));
        assert!(
            text.lines()
                .filter(|line| line.starts_with("report"))
                .all(|line| line.contains("in-job=true")),
            "a grandchild that was started with the flag is still in a job"
        );
    }
    job.end(&[&child], Duration::from_secs(10));
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_suspended_child_that_is_dropped_is_ended_and_leaves_no_process() {
    let fixture = Fixture::new();
    let job = Job::new(Limits::INVOCATION).unwrap();
    let (suspended, _output) = fixture.start(&job, &["sleep", "600000"]);
    let pid = suspended.pid;
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: both handles are open; the copy is closed below by its owner.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            suspended.process.raw(),
            GetCurrentProcess(),
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        );
    }
    let copy = Handle::new(copy, "a copy of the process handle").unwrap();
    assert_eq!(job.active_processes().unwrap(), 1);
    drop(suspended);
    // SAFETY: the copy is open.
    assert_eq!(
        unsafe { WaitForSingleObject(copy.raw(), 0) },
        WAIT_OBJECT_0,
        "the process ended at the drop"
    );
    assert_ne!(exit_code(&copy), STILL_ACTIVE);
    assert!(
        !pids_named("kr-launch-stand-in").contains(&pid),
        "no process is left"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_runs_only_with_the_permit_made_for_it() {
    let fixture = Fixture::new();
    let job = Job::new(Limits::INVOCATION).unwrap();
    let marker = fixture.scratch.join("permit.txt");
    let marker_text = marker.display().to_string();
    let (first, _) = fixture.start(&job, &["marker", &marker_text]);
    let (second, second_output) = fixture.start(&job, &["report"]);
    assert_ne!(first.pid, second.pid);
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: both handles are open; the copy is owned by the value made below.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            first.process.raw(),
            GetCurrentProcess(),
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        );
    }
    let first_process = Handle::new(copy, "a copy of the first process").unwrap();
    // The second child's permit does not let the first run: the first is refused and ended.
    let other = ResumePermit::for_cases(INVOCATION, &second);
    let refused = first.resume(other);
    assert!(matches!(refused, Err(LaunchError::PermitForAnotherChild)));
    // SAFETY: the copy is open.
    assert_eq!(
        unsafe { WaitForSingleObject(first_process.raw(), 30_000) },
        WAIT_OBJECT_0,
        "the refused child was ended"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert!(!marker.exists(), "the refused child never ran");
    // The second child runs with its own.
    let runs = resume(second);
    assert_eq!(runs.wait(Duration::from_secs(30)).unwrap(), Some(0));
    assert!(read_to_end(&second_output).contains("report pid="));
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_launch_that_cannot_use_the_job_attribute_starts_nothing() {
    let fixture = Fixture::new();
    let job = Job::new(Limits::INVOCATION).unwrap();
    // A handle to the job that may only query it: the platform cannot make a process in that job.
    let restricted = job.query_only_copy().unwrap();
    let marker = fixture.scratch.join("started.txt");
    let marker_text = marker.display().to_string();
    let before = pids_named("kr-launch-stand-in");
    let result = launch(fixture.spec(
        &restricted,
        &fixture.stand_in,
        &["marker", &marker_text],
        Std::Nul,
        Std::Nul,
    ));
    let error = result.expect_err("a job that may not be used takes no child");
    println!("a launch into a job it may not use: {error}");
    assert!(
        matches!(error, LaunchError::NotStarted(_) | LaunchError::Job(_)),
        "nothing was created: {error:?}"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(!marker.exists(), "the program did not run");
    assert_eq!(
        pids_named("kr-launch-stand-in"),
        before,
        "no process was made"
    );
    assert_eq!(job.active_processes().unwrap(), 0, "the job holds nothing");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_job_that_has_ended_takes_no_new_child() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    job.end(&[], Duration::from_secs(10));
    let marker = fixture.scratch.join("started.txt");
    let marker_text = marker.display().to_string();
    let before = pids_named("kr-launch-stand-in");
    let result = launch(fixture.spec(
        &job,
        &fixture.stand_in,
        &["marker", &marker_text],
        Std::Nul,
        Std::Nul,
    ));
    assert!(matches!(result, Err(LaunchError::Job(_))));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!marker.exists(), "the program did not run");
    assert_eq!(
        pids_named("kr-launch-stand-in"),
        before,
        "no process was made"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_sees_exactly_the_environment_it_was_given() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (suspended, output) = fixture.start(&job, &["environment"]);
    let child = resume(suspended);
    let text = read_to_end(&output);
    assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
    let seen: BTreeSet<(String, String)> = text
        .lines()
        .filter_map(|line| line.strip_prefix("variable "))
        .filter_map(|rest| rest.split_once('='))
        .map(|(name, value)| (name.to_uppercase(), value.to_owned()))
        .collect();
    let given: BTreeSet<(String, String)> = fixture
        .env
        .pairs()
        .into_iter()
        .map(|(name, value)| (name.to_uppercase(), value))
        .collect();
    assert_eq!(seen, given);
    job.end(&[&child], Duration::from_secs(10));
}

/// The arguments `CommandLineToArgvW` makes of a line.
fn system_split(line: &str) -> Vec<String> {
    let wide: Vec<u16> = line.encode_utf16().chain([0]).collect();
    let mut count = 0_i32;
    // SAFETY: the line is NUL-terminated; the array is freed below.
    unsafe {
        let array = CommandLineToArgvW(wide.as_ptr(), &raw mut count);
        assert!(!array.is_null());
        let arguments = (0..count as usize)
            .map(|index| {
                let mut length = 0;
                while *(*array.add(index)).add(length) != 0 {
                    length += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(*array.add(index), length))
            })
            .collect();
        LocalFree(array.cast());
        arguments
    }
}

const AWKWARD: &[&str] = &[
    "",
    "plain",
    "two words",
    "tab\there",
    "a\"b",
    "\"",
    "\"\"",
    "ends with a backslash\\",
    "ends with two\\\\",
    "\\",
    "\\\\",
    "\\\"",
    "\\\\\"",
    "a\\b",
    "a\\\\b c",
    r"C:\path with space\dir\",
    "--format=%H %s",
    "--message=it's \"quoted\" and ends\\",
    "ünïcödé and 日本語",
    "=",
];

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_quoted_command_line_is_split_back_by_the_system_and_by_a_real_child() {
    let fixture = Fixture::new();
    let program = r"C:\Program Files\Git\mingw64\bin\git.exe";
    for argument in AWKWARD {
        let line = quote_command_line(&[program, argument, "after"]);
        assert_eq!(
            system_split(&line),
            [program, argument, "after"],
            "CommandLineToArgvW on {line}"
        );
    }
    // The whole table in one line, started as a real child, whose own startup splits it.
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let mut arguments = vec!["arguments"];
    arguments.extend_from_slice(AWKWARD);
    let (suspended, output) = fixture.start(&job, &arguments);
    let child = resume(suspended);
    let text = read_to_end(&output);
    assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
    let seen: Vec<&str> = text.lines().collect();
    let want: Vec<String> = AWKWARD
        .iter()
        .map(|argument| format!("argument {argument:?}"))
        .collect();
    assert_eq!(seen, want);
    job.end(&[&child], Duration::from_secs(10));
}

// ---- the error mode and the crash reporting ----

fn guest_git() -> PathBuf {
    Path::new(GUEST_GIT)
        .join("mingw64")
        .join("bin")
        .join("git.exe")
}

/// Crash reporting for a program, in the way an administrator would turn dumps on: a folder every
/// account may write. Put back when dropped.
struct Dumps {
    keys: Vec<String>,
    folder: PathBuf,
}

impl Dumps {
    fn new(images: &[&str], folder: &Path) -> Dumps {
        std::fs::create_dir_all(folder).unwrap();
        let granted = Command::new("icacls.exe")
            .arg(folder)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .unwrap();
        assert!(
            granted.status.success(),
            "the dump folder is open to every account"
        );
        let mut keys = Vec::new();
        for image in images {
            let key = format!(
                r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\{image}"
            );
            for (name, kind, value) in [
                ("DumpFolder", "REG_EXPAND_SZ", folder.display().to_string()),
                ("DumpType", "REG_DWORD", "2".to_owned()),
                ("DumpCount", "REG_DWORD", "20".to_owned()),
            ] {
                let added = Command::new("reg.exe")
                    .args(["add", &key, "/v", name, "/t", kind, "/d", &value, "/f"])
                    .output()
                    .unwrap();
                assert!(
                    added.status.success(),
                    "the dump setting {name} for {image}"
                );
            }
            keys.push(key);
        }
        Dumps {
            keys,
            folder: folder.to_owned(),
        }
    }

    fn dumps(&self) -> BTreeSet<String> {
        std::fs::read_dir(&self.folder)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.to_lowercase().ends_with(".dmp"))
            .collect()
    }

    fn has_dump_of(&self, pid: u32) -> bool {
        self.dumps()
            .iter()
            .any(|name| name.contains(&format!(".{pid}.")))
    }
}

impl Drop for Dumps {
    fn drop(&mut self) {
        for key in &self.keys {
            let _ = Command::new("reg.exe").args(["delete", key, "/f"]).output();
        }
    }
}

/// The names of the files in a folder, for a diagnostic.
fn names_in(folder: &str) -> String {
    std::fs::read_dir(folder)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|error| format!("unreadable: {error}"))
}

/// Waits until a crash that was expected to be reported has written its dump, and says how long
/// that took after the crashed process ended. A dump may be written before the process has gone,
/// so the time can be nothing.
fn wait_for_dump(dumps: &Dumps, pid: u32, deadline: Duration) -> Duration {
    let started = Instant::now();
    loop {
        let reporting = pids_named("werfault");
        if dumps.has_dump_of(pid) && reporting.is_empty() {
            return started.elapsed();
        }
        if started.elapsed() >= deadline {
            panic!(
                "the control crash of {pid} left no dump, so a case that sees none shows nothing. \
                 dumps: [{}]; error-reporting processes: {reporting:?}; WER Temp: [{}]; \
                 report queue: [{}]; events: {}",
                names_in(&dumps.folder.display().to_string()),
                names_in(r"C:\ProgramData\Microsoft\Windows\WER\Temp"),
                names_in(r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue"),
                application_error_events("")
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The crash reports the system's event log holds for the last few minutes, one line each.
fn application_error_events(image: &str) -> String {
    let query = "*[System[Provider[@Name='Application Error'] and TimeCreated[timediff(@SystemTime) <= 600000]]]";
    let output = Command::new("wevtutil.exe")
        .args([
            "qe",
            "Application",
            &format!("/q:{query}"),
            "/c:30",
            "/rd:true",
            "/f:text",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.split("Event[")
        .filter(|event| event.contains(image))
        .map(|event| {
            event
                .lines()
                .filter(|line| line.contains("Date:") || line.contains("Faulting process id"))
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether the system's event log names a crash of this process.
fn logged_a_crash_of(pid: u32) -> bool {
    application_error_events("")
        .to_lowercase()
        .contains(&format!("faulting process id: {:#x}", pid))
}

/// How a crash case starts the stand-in.
#[derive(Clone, Copy)]
struct Start {
    /// The error mode of the process that starts the child, which the child inherits: none leaves
    /// the broker's own.
    mode: Option<u32>,
    /// Whether the child's process gives its group every right, as a control.
    full: bool,
}

const AS_THE_BROKER_DOES: Start = Start {
    mode: None,
    full: false,
};

/// Runs the stand-in and returns what it wrote, the process that crashed and how it ended.
fn crash_run(fixture: &Fixture, arguments: &[&str], how: Start) -> (String, Vec<u32>, Option<u32>) {
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (read, write) = pipe().unwrap();
    // A child inherits the mode its parent has when the child is made.
    let kept = how.mode.map(set_own_error_mode);
    let descriptor = if how.full {
        &fixture.full_descriptor
    } else {
        &fixture.descriptor
    };
    let made = launch(fixture.spec_with(
        &job,
        &fixture.stand_in,
        arguments,
        Std::Pipe(write),
        Std::Nul,
        descriptor,
    ));
    if let Some(kept) = kept {
        set_own_error_mode(kept);
    }
    let child = resume(made.expect("the stand-in is started"));
    let text = read_to_end(&read);
    let code = child.wait(Duration::from_secs(60)).unwrap();
    let pids: Vec<u32> = text
        .lines()
        .filter(|line| line.starts_with("crash "))
        .map(|line| value_of(line, "pid").parse().unwrap())
        .collect();
    job.end(&[&child], Duration::from_secs(10));
    (text, pids, code)
}

fn set_own_error_mode(mode: u32) -> u32 {
    // SAFETY: sets the process's error mode, which has no memory safety condition.
    unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(mode) }
}

/// Git run as the boundary token with the stand-in as its external diff program, which Git starts
/// as its own child.
fn git_with_helper(fixture: &Fixture, job: &Job) -> (String, String, Option<u32>) {
    let one = fixture.scratch.join("one.txt");
    let two = fixture.scratch.join("two.txt");
    std::fs::write(&one, "one\n").unwrap();
    std::fs::write(&two, "two\n").unwrap();
    let helper = fixture.stand_in.display().to_string().replace('\\', "/");
    let config = format!("diff.external={helper}");
    let (read, write) = pipe().unwrap();
    let (error_read, error_write) = pipe().unwrap();
    let suspended = launch(fixture.spec(
        job,
        &guest_git(),
        &[
            "-c",
            &config,
            "diff",
            "--no-index",
            "--ext-diff",
            &one.display().to_string(),
            &two.display().to_string(),
        ],
        Std::Pipe(write),
        Std::Pipe(error_write),
    ))
    .unwrap();
    let git = resume(suspended);
    let text = read_to_end(&read);
    let errors = read_to_end(&error_read);
    let code = git.wait(Duration::from_secs(60)).unwrap();
    (text, errors, code)
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_child_a_grandchild_and_a_child_of_git_inherit_the_brokers_error_mode() {
    let fixture = Fixture::new();
    let mode = own_error_mode();
    assert_eq!(
        mode & 0x0002,
        0x0002,
        "the broker's mode asks for no crash reporting"
    );
    assert_eq!(mode & 0x8000, 0x8000, "and for no open-file box");
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    // A child, and its grandchild.
    let (suspended, output) = fixture.start(&job, &["spawn"]);
    let child = resume(suspended);
    let text = read_to_end(&output);
    assert_eq!(child.wait(Duration::from_secs(30)).unwrap(), Some(0));
    let modes: Vec<u32> = text.lines().map(parse_mode).collect();
    assert_eq!(modes, [mode, mode], "the child and its grandchild: {text}");
    // A child of the pinned Git.
    let (text, errors, code) = git_with_helper(&fixture, &job);
    println!("git ended with {code:?}\nstdout: {text}\nstderr: {errors}");
    let helper = text
        .lines()
        .find(|line| line.starts_with("diff "))
        .unwrap_or_else(|| {
            panic!("Git ran the helper: exit {code:?}, stdout {text:?}, stderr {errors:?}")
        });
    assert_eq!(
        parse_mode(helper),
        mode,
        "a child of git.exe inherits the mode too"
    );
    job.end(&[&child], Duration::from_secs(10));
}

/// Whether a crash that the system reports has its dump after a bound, and how soon.
fn dump_within(dumps: &Dumps, pid: u32, bound: Duration) -> Option<Duration> {
    let started = Instant::now();
    loop {
        if dumps.has_dump_of(pid) && pids_named("werfault").is_empty() {
            return Some(started.elapsed());
        }
        if started.elapsed() >= bound {
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_crash_of_a_child_a_grandchild_or_git_s_child_leaves_no_dump_where_the_default_mode_does() {
    let fixture = Fixture::new();
    let dumps = Dumps::new(&["kr-launch-stand-in.exe"], &fixture.dir.join("dumps"));
    let default_mode = Start {
        mode: Some(0),
        full: false,
    };
    let default_and_open = Start {
        mode: Some(0),
        full: true,
    };
    // What the system does with these crashes when the broker's mode is not in the way, and what
    // each stands in the way of. The first is the control that must dump: a child started from the
    // default mode, its process open to its group. The others say why a crash may leave no dump
    // even then.
    let (text, open, code) = crash_run(&fixture, &["crash-fail-fast"], default_and_open);
    println!("control, default mode, process open to its group: {text} ended {code:?}");
    let (text, restricted, code) = crash_run(&fixture, &["crash-fail-fast"], default_mode);
    println!("observation, default mode, the broker's descriptor: {text} ended {code:?}");
    let (text, grandchild, code) = crash_run(&fixture, &["spawn-crash", "fail-fast"], default_mode);
    println!("control, default mode, a grandchild: {text} ended {code:?}");
    let (text, asked, code) = crash_run(
        &fixture,
        &["crash-default-mode", "fail-fast"],
        AS_THE_BROKER_DOES,
    );
    println!("observation, the child asks for the default mode: {text} ended {code:?}");
    let seen = |what: &str, pid: u32| {
        let found = dump_within(&dumps, pid, Duration::from_secs(25));
        println!(
            "{what}: dump {found:?}; logged by the system: {}",
            logged_a_crash_of(pid)
        );
        found
    };
    let control = seen("default mode, process open to its group", open[0]);
    seen("default mode, the broker's descriptor", restricted[0]);
    let grandchild_control = seen(
        "default mode, a grandchild",
        grandchild[1.min(grandchild.len() - 1)],
    );
    seen("the child asks for the default mode itself", asked[0]);
    println!(
        "WER Temp now holds [{}]",
        names_in(r"C:\ProgramData\Microsoft\Windows\WER\Temp")
    );
    let latency = control
        .or(grandchild_control)
        .expect("a crash that nothing stands in the way of is reported: otherwise a case that sees no dump shows nothing");
    let settle = (latency * 3).max(Duration::from_secs(20));
    let before = dumps.dumps();
    let mut crashed = Vec::new();
    // The claims: the broker's mode, set in the process that starts the child.
    for (arguments, how) in [
        (
            &["crash-fail-fast"][..],
            Start {
                mode: None,
                full: true,
            },
        ),
        (&["crash-fail-fast"][..], AS_THE_BROKER_DOES),
        (&["crash-access-violation"][..], AS_THE_BROKER_DOES),
        (&["spawn-crash", "fail-fast"][..], AS_THE_BROKER_DOES),
        (&["spawn-crash", "access-violation"][..], AS_THE_BROKER_DOES),
    ] {
        let (text, pids, code) = crash_run(&fixture, arguments, how);
        println!("{arguments:?}: {text} ended {code:?}");
        assert!(!pids.is_empty(), "{arguments:?} crashed a process");
        crashed.extend(pids);
    }
    // A child of the pinned Git that fail-fasts.
    std::fs::write(fixture.dir.join("diff-mode.txt"), "crash-fail-fast").unwrap();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (text, errors, code) = git_with_helper(&fixture, &job);
    println!("git with a crashing helper ended {code:?}\nstdout: {text}\nstderr: {errors}");
    assert!(
        text.contains("crash pid="),
        "Git's helper crashed: {text} {errors}"
    );
    crashed.extend(
        text.lines()
            .filter(|line| line.starts_with("crash "))
            .map(|line| value_of(line, "pid").parse::<u32>().unwrap()),
    );
    job.end(&[], Duration::from_secs(10));
    // Nothing was reported: no dump and no error-reporting process for a crash that has ended, for
    // as long as three times the control took.
    let started = Instant::now();
    while started.elapsed() < settle {
        assert!(
            pids_named("werfault").is_empty(),
            "the system started error reporting"
        );
        assert_eq!(dumps.dumps(), before, "a dump was written");
        std::thread::sleep(Duration::from_millis(250));
    }
    println!(
        "no dump and no reporting process in {settle:?} after {} crashes",
        crashed.len()
    );
    for pid in crashed {
        println!(
            "crash of {pid} logged by the system: {}",
            logged_a_crash_of(pid)
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_brokers_own_crash_leaves_no_dump_where_the_default_mode_does() {
    let work = PathBuf::from(r"C:\Users\Public").join(format!(
        "krbroker-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir_all(&work).unwrap();
    let broker_exe = work.join("kr-boundary-broker.exe");
    std::fs::copy(
        bin().join("raw").join("kr-boundary-broker.exe"),
        &broker_exe,
    )
    .unwrap();
    let dumps = Dumps::new(&["kr-boundary-broker.exe"], &work.join("dumps"));
    // The broker is started from a process whose own mode is the default, so that only the
    // broker's own start-up can set the mode it crashes under.
    let kept = set_own_error_mode(0);
    let crash = |kind: &str, default_mode: bool| -> u32 {
        let mut command = Command::new(&broker_exe);
        command.arg(format!("--crash-after-init={kind}"));
        if default_mode {
            command.arg("--default-error-mode");
        }
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let status = child.wait().unwrap();
        println!(
            "the broker {kind} (default mode asked again: {default_mode}) pid {pid} ended with {status}"
        );
        pid
    };
    let control = crash("fail-fast", true);
    let latency = wait_for_dump(&dumps, control, Duration::from_secs(90));
    println!("the control crash of the broker had its dump {latency:?} after its end");
    let control_access = crash("access-violation", true);
    wait_for_dump(&dumps, control_access, Duration::from_secs(90));
    let settle = (latency * 3).max(Duration::from_secs(20));
    let before = dumps.dumps();
    let claimed = [crash("fail-fast", false), crash("access-violation", false)];
    let started = Instant::now();
    while started.elapsed() < settle {
        assert!(
            pids_named("werfault").is_empty(),
            "the system started error reporting for the broker"
        );
        assert_eq!(dumps.dumps(), before, "a dump of the broker was written");
        std::thread::sleep(Duration::from_millis(250));
    }
    println!("no dump of the broker and no reporting process in {settle:?} after two crashes");
    for (what, pid) in [
        ("control fail-fast", control),
        ("control access violation", control_access),
        ("fail-fast", claimed[0]),
        ("access violation", claimed[1]),
    ] {
        println!(
            "the broker's {what} (pid {pid}) is in the system's crash log: {}",
            logged_a_crash_of(pid)
        );
    }
    set_own_error_mode(kept);
    drop(dumps);
    let _ = std::fs::remove_dir_all(&work);
}

// ---- the doors out of the job ----

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_four_ways_to_start_a_program_outside_the_job_start_nothing_from_a_launched_child() {
    let fixture = Fixture::new();
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    // First, which of the programs the script needs can run as a child at all: each is run under the
    // boundary token and under the broker's own, and its exit code and output are printed.
    let system = system_windows_directory().unwrap();
    let system32 = Path::new(&system).join("System32");
    let shell = system32
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    for (what, program, arguments) in [
        (
            "cmd",
            system32.join("cmd.exe"),
            vec!["/c", "echo hello & exit 5"],
        ),
        (
            "powershell",
            shell.clone(),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output hello; exit 5",
            ],
        ),
    ] {
        for token_name in ["boundary", "own"] {
            let (read, write) = pipe().unwrap();
            let (error_read, error_write) = pipe().unwrap();
            let mut spec = fixture.spec(
                &job,
                &program,
                &arguments,
                Std::Pipe(write),
                Std::Pipe(error_write),
            );
            if token_name == "own" {
                spec.token = TokenSpec::Own;
            }
            let child = resume(launch(spec).unwrap());
            let code = child.wait(Duration::from_secs(60)).unwrap();
            println!(
                "{what} as {token_name}: exit {code:?}, stdout {:?}, stderr {:?}",
                read_to_end(&read),
                read_to_end(&error_read)
            );
        }
    }
    let program = fixture.stand_in.display().to_string();
    let scratch = fixture.scratch.display().to_string();
    let script = format!(
        r#"$m = '{program}'; $d = '{scratch}'
'ran' | Out-File -FilePath "$d\ran.txt"
function Form($name, [scriptblock]$body) {{ try {{ & $body; "$name finished" }} catch {{ "$name failed: $($_.Exception.GetType().Name) $($_.Exception.Message.Trim())" }} }}
Form 'wmi' {{ $r = ([wmiclass]'Win32_Process').Create("`"$m`" marker `"$d\wmi.txt`""); "wmi returned $($r.ReturnValue)" }}
Form 'task' {{ schtasks.exe /create /tn KrLaunchTask /tr "`"$m`" marker `"$d\task.txt`"" /sc once /st 00:00 /f; schtasks.exe /run /tn KrLaunchTask }}
Form 'bits' {{ bitsadmin.exe /create /download KrLaunchJob; bitsadmin.exe /addfile KrLaunchJob C:\Windows\System32\drivers\etc\hosts "$d\bits-out.txt"; bitsadmin.exe /setnotifycmdline KrLaunchJob $m "x marker $d\bits.txt"; bitsadmin.exe /resume KrLaunchJob; Start-Sleep 10; bitsadmin.exe /complete KrLaunchJob }}
Form 'com' {{ $a = [Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application')); $a.Document.ActiveView.ExecuteShellCommand($m, $d, "marker `"$d\com.txt`"", '7') }}
'done' | Out-File -FilePath "$d\done.txt""#
    );
    // The script crosses as an encoded command, so that no quoting rule of PowerShell's own decides
    // what it reads.
    let units: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let encoded = base64(&units);
    let powershell = Path::new(&system_windows_directory().unwrap())
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let (read, write) = pipe().unwrap();
    let (error_read, error_write) = pipe().unwrap();
    let suspended = launch(fixture.spec(
        &job,
        &powershell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ],
        Std::Pipe(write),
        Std::Pipe(error_write),
    ))
    .unwrap();
    let shell = resume(suspended);
    let finished = shell.wait(Duration::from_secs(240)).unwrap();
    let text = read_to_end(&read);
    let errors = read_to_end(&error_read);
    println!("PowerShell ended with {finished:?}\nstdout: {text}\nstderr: {errors}");
    println!("scratch holds: [{}]", names_in(&scratch));
    assert!(
        fixture.scratch.join("ran.txt").exists(),
        "the script ran, so each form was tried"
    );
    assert!(
        fixture.scratch.join("done.txt").exists(),
        "the script reached its end"
    );
    for marker in ["wmi.txt", "task.txt", "bits.txt", "com.txt"] {
        assert!(
            !fixture.scratch.join(marker).exists(),
            "{marker}: a program started outside the job"
        );
    }
    let in_job: BTreeSet<u32> = job.process_ids().unwrap().into_iter().collect();
    let outside: Vec<u32> = pids_named("kr-launch-stand-in")
        .difference(&in_job)
        .copied()
        .collect();
    assert!(
        outside.is_empty(),
        "stand-in processes outside the job: {outside:?}"
    );
    job.end(&[&shell], Duration::from_secs(10));
    let _ = Command::new("schtasks.exe")
        .args(["/delete", "/tn", "KrLaunchTask", "/f"])
        .output();
    let _ = Command::new("bitsadmin.exe")
        .args(["/reset", "/allusers"])
        .output();
}

/// Standard base64, for the encoded command.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                text.push(char::from(
                    ALPHABET[(word >> (18 - 6 * index) & 63) as usize],
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}
