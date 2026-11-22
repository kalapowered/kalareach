//! How an invocation lives and ends in the broker, shown on a Windows guest: that a refusal the
//! broker sends before it closes a connection reaches a client that reads it in parts, the phases of
//! an invocation on the fixture tree, the one ending function and what proves an end, and what a
//! restart of the broker makes of an invocation that was cut short.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored
//! afterwards, each one alone from a clean machine.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, FILETIME, GENERIC_READ,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, SecurityImpersonation,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, ReadFile, SECURITY_SQOS_PRESENT, SYNCHRONIZE, WriteFile,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken, TerminateProcess,
};

use kr_boundary_windows::env::{Kind as EnvKind, QualifiedGit, RootPaths, build_env};
use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::frame::invocation::{
    Cleanup, Command, EndedBy, Identity, InvocationReply, InvocationRequest, LineEndings,
    OperateRequest, RefusedKind, read_reply, write_request,
};
use kr_boundary_windows::frame::{self, Class, Response};
use kr_boundary_windows::journal::replay::read_file;
use kr_boundary_windows::journal::rows::{Label, ObjectKind, RootName, Row, Rule};
use kr_boundary_windows::lifecycle::{Left, UNCERTAIN_END_WORDS};
use kr_boundary_windows::manifest::Manifest;
use kr_boundary_windows::pipe_access;
use kr_boundary_windows::win::boot::BootMarker;
use kr_boundary_windows::win::client::ClientIdentity;
use kr_boundary_windows::win::ffi::{Handle, Sid, system_windows_directory, wide};
use kr_boundary_windows::win::install::Paths;
use kr_boundary_windows::win::launch::VerifiedPath;
use kr_boundary_windows::win::lifecycle::fixture::{FixtureTrees, Plan};
use kr_boundary_windows::win::lifecycle::testing as hooks;
use kr_boundary_windows::win::lifecycle::{
    Blocked, ChildPlan, Environment, Recovered, recover, run_invocation,
};
use kr_boundary_windows::win::pipe::{
    Connection, Kind, Listener, ServerProcess, Stop, connect_held,
};
use kr_boundary_windows::win::rights::ImpersonationToken;
use kr_boundary_windows::win::sd::descriptor_from_text;
use kr_boundary_windows::win::{account, acl, boot, broker, scan, session, token};

mod common;
use common::Scratch;

fn runs_as_the_system() -> bool {
    token::current_user().is_ok_and(|user| user.to_text().is_ok_and(|text| text == "S-1-5-18"))
}

fn open_pipe(name: &str) -> Result<Handle, u32> {
    let name = wide(name);
    // SAFETY: the name is NUL-terminated; the result is checked.
    let opened = unsafe {
        CreateFileW(
            name.as_ptr(),
            pipe_access::CLIENT,
            0,
            null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | 0x0001_0000,
            null_mut(),
        )
    };
    if opened == INVALID_HANDLE_VALUE {
        // SAFETY: reads the last error of this thread.
        return Err(unsafe { GetLastError() });
    }
    Ok(Handle::new(opened, "a pipe").unwrap())
}

fn open_when_it_exists(name: &str) -> Handle {
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match open_pipe(name) {
            Ok(pipe) => return pipe,
            Err(code) => {
                assert!(
                    std::time::Instant::now() < until,
                    "the pipe did not open: {code}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn write_all(pipe: &Handle, bytes: &[u8]) {
    let mut written = 0_u32;
    // SAFETY: the pipe is open and the buffer is the length given.
    let done = unsafe {
        WriteFile(
            pipe.raw(),
            bytes.as_ptr(),
            bytes.len() as u32,
            &raw mut written,
            null_mut(),
        )
    };
    assert_ne!(done, 0, "the write on the pipe");
}

fn framed(body: &str) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// Reads exactly `size` bytes with one call, or says why not.
fn read_exactly(pipe: &Handle, size: usize) -> Result<Vec<u8>, u32> {
    let mut buffer = vec![0_u8; size];
    let mut got = 0_u32;
    // SAFETY: the pipe is open and the buffer is the length given.
    let done = unsafe {
        ReadFile(
            pipe.raw(),
            buffer.as_mut_ptr(),
            size as u32,
            &raw mut got,
            null_mut(),
        )
    };
    if done == 0 {
        // SAFETY: reads the last error of this thread.
        return Err(unsafe { GetLastError() });
    }
    buffer.truncate(got as usize);
    Ok(buffer)
}

/// The broker's two pipes, served by this process until the case ends.
struct BrokerLoop {
    stop: Arc<Stop>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl BrokerLoop {
    fn start() -> BrokerLoop {
        assert!(
            std::fs::metadata(Kind::Persons.name()).is_err(),
            "the machine is not clean: the broker's pipe is in use"
        );
        let stop = Stop::new().unwrap();
        let thread = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                let everyone = Sid::parse("S-1-1-0").unwrap();
                broker::testing::serve(
                    Manifest::begin(),
                    Paths::system().expect("the system's folders are read"),
                    &[everyone],
                    stop,
                )
            }
        });
        BrokerLoop {
            stop,
            thread: Some(thread),
        }
    }

    fn end(mut self) -> Result<(), String> {
        self.stop.set();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for BrokerLoop {
    fn drop(&mut self) {
        self.stop.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The broker closes a connection right after it sends a refusal. A client that reads the length
/// and then the body, with a pause between the two reads, gets the whole refusal and not a broken
/// pipe: the close waits until the client has read what was sent.
#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_refusal_reaches_a_client_that_reads_its_length_and_its_body_apart() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    broker::init();
    let broker_loop = BrokerLoop::start();
    let pipe = open_when_it_exists(Kind::Persons.name());
    write_all(&pipe, &framed(r#"{"request":"hello","version":99}"#));
    let length = read_exactly(&pipe, 4).expect("the length of the refusal");
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    // A client that does something else between its two reads: the broker has long since sent its
    // answer and would have closed the connection.
    std::thread::sleep(Duration::from_millis(500));
    let body = read_exactly(&pipe, length)
        .unwrap_or_else(|code| panic!("the body of the refusal was lost: the pipe's error {code}"));
    let answer: Response = serde_json::from_slice(&body).unwrap();
    assert!(
        matches!(
            answer,
            Response::Refused {
                reason: frame::Refusal::Version,
                ..
            }
        ),
        "{answer:?}"
    );
    drop(pipe);
    assert_eq!(broker_loop.end(), Ok(()));
}

// ---- The phases and the ending, run on the fixture tree.

const GUEST_GIT: &str = r"C:\Program Files\Git";

fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the stand-in"),
    )
}

fn prepare() {
    broker::init();
    for privilege in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        token::enable_privilege(privilege).unwrap();
    }
}

fn request() -> OperateRequest {
    OperateRequest {
        protocol_version: 1,
        class: Class::Checkout,
        directory: r"C:\fixture".to_owned(),
        command: Command::Log,
        arguments: Vec::new(),
        identity: Identity {
            name: "A Person".to_owned(),
            email: "person@example.com".to_owned(),
        },
        line_endings: LineEndings::Input,
    }
}

fn own_primary_token() -> Handle {
    let mut raw: HANDLE = null_mut();
    // SAFETY: opens this process's own token for the two rights named; owned below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut raw,
        )
    };
    assert_ne!(opened, 0, "this process's token is opened");
    Handle::new(raw, "this process's token").unwrap()
}

fn process_handle(pid: u32) -> Handle {
    // SAFETY: opens a process by number for a limited query and a wait; the result is checked.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    Handle::new(raw, "a process").unwrap()
}

fn creation_of(process: &Handle) -> u64 {
    let (mut created, mut a, mut b, mut c) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the process is open for a limited query and the out-parameters are local.
    unsafe {
        GetProcessTimes(
            process.raw(),
            &raw mut created,
            &raw mut a,
            &raw mut b,
            &raw mut c,
        );
    }
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

/// The client of the cases: this process, whose process the data pipes' connections come from. The
/// handle that the broker waits on for the client's end can be another process's.
fn client_of(process_to_wait_on: Option<u32>) -> ClientIdentity {
    let pid = std::process::id();
    let own = process_handle(pid);
    let creation_time = creation_of(&own);
    let waited = process_to_wait_on.map_or(own, process_handle);
    ClientIdentity {
        pid,
        process: waited,
        creation_time,
        user_sid: token::current_user().unwrap(),
        token: ImpersonationToken::duplicate_of(&own_primary_token()).unwrap(),
    }
}

fn paths_under(dir: &Path) -> Paths {
    let journal = dir.join("journal");
    let run = dir.join("run");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    Paths {
        program: dir.join("program"),
        program_top: dir.join("top"),
        data: dir.join("data"),
        journal,
        run,
        git: dir.join("git"),
        staging: dir.join("staging"),
        manifest: dir.join("manifest"),
        prior: dir.join("prior"),
    }
}

/// What a case reads after an invocation: the fixture's counts and lock, and the journal's rows.
struct Life {
    dir: PathBuf,
    account: String,
    trees: Arc<FixtureTrees>,
    env: Arc<Environment>,
}

/// What a stand-in child runs: the program copied into the folder, with these arguments.
fn stand_in_plan(dir: &Path, arguments: &[&str]) -> Plan {
    let stand_in = dir.join("kr-launch-stand-in.exe");
    if std::fs::metadata(&stand_in).is_err() {
        std::fs::copy(bin().join("kr-launch-stand-in.exe"), &stand_in).unwrap();
    }
    let arguments: Vec<String> = arguments.iter().map(|text| (*text).to_owned()).collect();
    let scratch = dir.to_path_buf();
    let program = stand_in;
    Box::new(move |root: &kr_boundary_windows::win::root::PrivateRoot| {
        let name = program.display().to_string();
        let mut parts = vec![name.as_str()];
        parts.extend(arguments.iter().map(String::as_str));
        let env = build_env(
            EnvKind::Proof,
            &RootPaths {
                system: system_windows_directory().map_err(|failure| failure.to_string())?,
                boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
                private_root: root.path().display().to_string(),
            },
            None,
            &QualifiedGit {
                dir: GUEST_GIT.to_owned(),
            },
        )
        .map_err(|failure| failure.to_string())?;
        Ok(ChildPlan {
            program: VerifiedPath::new(&program).map_err(|failure| failure.to_string())?,
            command_line: kr_boundary_windows::quote::quote_command_line(&parts),
            cwd: scratch.clone(),
            env,
        })
    })
}

impl Life {
    /// The primary child runs the stand-in with these arguments. `edit` changes the waits.
    fn open(
        dir: &Path,
        account: &str,
        arguments: &[&str],
        grants: u64,
        edit: impl FnOnce(&mut Environment),
    ) -> Life {
        let trees =
            FixtureTrees::new(dir.to_path_buf(), stand_in_plan(dir, arguments)).with_grants(grants);
        Life::around(dir, account, trees, edit)
    }

    /// The tree has a reader child, which runs the stand-in with `reader`, before the grant.
    fn open_reading(
        dir: &Path,
        account: &str,
        reader: &[&str],
        arguments: &[&str],
        grants: u64,
        edit: impl FnOnce(&mut Environment),
    ) -> Life {
        let trees = FixtureTrees::new(dir.to_path_buf(), stand_in_plan(dir, arguments))
            .with_reader(stand_in_plan(dir, reader))
            .with_grants(grants);
        Life::around(dir, account, trees, edit)
    }

    fn around(
        dir: &Path,
        account: &str,
        trees: FixtureTrees,
        edit: impl FnOnce(&mut Environment),
    ) -> Life {
        let trees = Arc::new(trees);
        let stop = Stop::new().unwrap();
        let name = account.to_owned();
        let mut env = Environment::new(
            Box::new(move |_| Ok(name.clone())),
            paths_under(dir),
            Arc::clone(&stop),
            Arc::clone(&trees) as Arc<dyn kr_boundary_windows::win::lifecycle::Trees>,
            vec![Sid::parse("S-1-1-0").unwrap()],
            &BootMarker {
                id: "lifetime-boot-marker".to_owned(),
                trusted: true,
                reason: None,
                made: false,
            },
        );
        edit(&mut env);
        Life {
            dir: dir.to_path_buf(),
            account: account.to_owned(),
            trees,
            env: Arc::new(env),
        }
    }

    /// A second life over the same folders and a fresh fixture: the broker after a restart.
    fn restarted(&self, grants: u64) -> Life {
        Life::open(
            &self.dir,
            &self.account,
            &["sleep", "60000"],
            grants,
            |_| {},
        )
    }

    fn rows(&self) -> Vec<Row> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(self.dir.join("journal")).unwrap() {
            let path = entry.unwrap().path();
            let id = path.file_stem().unwrap().to_string_lossy().into_owned();
            let bytes = std::fs::read(&path).unwrap();
            if let kr_boundary_windows::journal::replay::Reading::Invocation(invocation) =
                read_file(&id, &bytes, "lifetime-boot-marker")
            {
                found.extend(invocation.rows);
            }
        }
        found
    }

    fn ended(&self) -> bool {
        self.rows()
            .last()
            .is_some_and(|row| matches!(row, Row::End { .. }))
    }

    fn releases(&self) -> u32 {
        self.trees.counts.releases.load(Ordering::SeqCst)
    }
}

/// How a client behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum How {
    /// Connects both pipes and reads the reply.
    Reads,
    /// Connects both pipes, waits for the child to say it runs, and sends a cancel.
    Cancels,
    /// Connects both pipes, waits for the child to say it runs, and closes the connection.
    Leaves,
    /// Connects no pipe.
    NeverConnects,
}

fn open_data_pipe(name: &str) -> Handle {
    let wide = wide(name);
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        // SAFETY: the name is NUL-terminated; the result is checked.
        let opened = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if opened != INVALID_HANDLE_VALUE {
            return Handle::new(opened, "a data pipe").unwrap();
        }
        assert!(Instant::now() < until, "the data pipe {name} did not open");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_file(path: &Path) -> String {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && !text.is_empty()
        {
            return text;
        }
        assert!(Instant::now() < until, "{} was not written", path.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs one invocation: the broker's side on a thread, the client's side here. The replies come
/// back in order. `marker` is the file the child writes when it runs.
fn run_one(
    life: &Life,
    how: How,
    client: ClientIdentity,
    marker: Option<&Path>,
) -> Vec<InvocationReply> {
    let mut listener = Listener::bind(
        Kind::Persons,
        &[Sid::parse("S-1-1-0").unwrap()],
        Stop::new().unwrap(),
    )
    .unwrap();
    let env = Arc::clone(&life.env);
    let server = std::thread::spawn(move || {
        let mut connection = loop {
            match listener.accept() {
                Ok(Some(connection)) => break connection,
                Ok(None) => panic!("the listener was stopped"),
                Err(_) => {}
            }
        };
        run_invocation(&mut connection, client, &request(), &env);
    });
    let me = ServerProcess::open(std::process::id()).unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    let mut connection: Connection = loop {
        match connect_held(Kind::Persons, &me) {
            Ok(connection) => break connection,
            Err(failure) => {
                assert!(Instant::now() < until, "the pipe did not open: {failure}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    let mut replies = Vec::new();
    connection.set_deadline(Some(Instant::now() + Duration::from_secs(120)));
    let first = read_reply(&mut connection).expect("the first reply");
    replies.push(first.clone());
    let InvocationReply::Accepted {
        invocation,
        stdout_pipe,
        stderr_pipe,
    } = first
    else {
        server.join().unwrap();
        return replies;
    };
    let pipes = (how != How::NeverConnects)
        .then(|| (open_data_pipe(&stdout_pipe), open_data_pipe(&stderr_pipe)));
    if matches!(how, How::Cancels | How::Leaves) {
        wait_for_file(marker.expect("a marker for a client that acts on a running child"));
    }
    match how {
        How::Cancels => write_request(&mut connection, &InvocationRequest::Cancel { invocation })
            .expect("the cancel is sent"),
        How::Leaves => {
            drop(pipes);
            drop(connection);
            server.join().unwrap();
            return replies;
        }
        How::Reads | How::NeverConnects => {}
    }
    match read_reply(&mut connection) {
        Ok(reply) => replies.push(reply),
        Err(failure) => panic!("the last reply was not read: {failure}"),
    }
    drop(pipes);
    server.join().unwrap();
    replies
}

/// A throwaway account for a case, deleted at its end, and the folder the case works in.
struct Setting {
    scratch: Scratch,
    account: String,
}

impl Setting {
    fn new() -> Setting {
        assert!(
            token::current_is_administrator().unwrap(),
            "the case must run elevated"
        );
        prepare();
        let id = uuid::Uuid::new_v4().simple().to_string();
        let account = format!("krlife{}", &id[..8]);
        account::create(&account).expect("the throwaway account is made");
        let scratch = Scratch::new();
        // The folders the broker reads, made before any case looks at them.
        paths_under(&scratch.dir);
        // The one folder the stand-in, which runs as the boundary account, may write in.
        let marks = scratch.path("marks");
        std::fs::create_dir_all(&marks).unwrap();
        acl::set_protected(
            &marks,
            &descriptor_from_text("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")
                .unwrap(),
        )
        .unwrap();
        Setting { scratch, account }
    }

    /// A file in the folder the stand-in may write: where it says that it runs.
    fn mark(&self, name: &str) -> PathBuf {
        self.scratch.path("marks").join(name)
    }

    fn life(&self, arguments: &[&str], grants: u64) -> Life {
        Life::open(&self.scratch.dir, &self.account, arguments, grants, |_| {})
    }
}

impl Drop for Setting {
    fn drop(&mut self) {
        hooks::set_hook(None);
        let _ = account::delete(&self.account);
    }
}

/// Takes away the journals of the invocations so far, so that the rows a case reads next are the
/// next invocation's.
fn forget_journals(setting: &Setting) {
    for entry in std::fs::read_dir(setting.scratch.path("journal")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
}

fn kinds(rows: &[Row]) -> Vec<String> {
    rows.iter().map(|row| format!("{:?}", row.kind())).collect()
}

/// Waits until the session is not in the system's list: an observed state, not a time.
fn absent_session(luid: u64) {
    assert_eq!(
        session::wait_absent(luid, Duration::from_secs(60)),
        kr_boundary_windows::lifecycle::Session::Absent,
        "the session {luid} is still in the system's list"
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_normal_ending_leaves_no_session_and_journals_the_whole_life() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let life = setting.life(&["exit", "0"], 2);
    let seen = Arc::new(Mutex::new(0_u64));
    hooks::set_hook(Some(Arc::new({
        let seen = Arc::clone(&seen);
        move |name| {
            if name == "token made" {
                *seen.lock().unwrap() = hooks::session();
            }
        }
    })));
    let replies = run_one(&life, How::Reads, client_of(None), None);
    let luid = *seen.lock().unwrap();
    assert_ne!(luid, 0, "the session of the invocation was read");
    // The invocation's end is proved by the session: it left the list, and the broker waited for that.
    absent_session(luid);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                ended_by: EndedBy::Exit,
                exit: Some(0),
                cleanup: Cleanup::Clean,
                ..
            })
        ),
        "{replies:?}"
    );
    assert!(life.ended(), "{:?}", kinds(&life.rows()));
    let names = kinds(&life.rows());
    assert_eq!(
        names,
        [
            "Begin",
            "RootIntent",
            "RootMade",
            "Grant",
            "Grant",
            "GrantComplete",
            "ProcessStarted",
            "JobEnded",
            "ReleaseIntent",
            "ObjectReleased",
            "ReleaseIntent",
            "ObjectReleased",
            "RootRemoved",
            "ReleaseVerified",
            "End"
        ]
    );
    assert_eq!(life.releases(), 1);
    assert_eq!(life.trees.counts.closed.load(Ordering::SeqCst), 1);
    assert!(!life.trees.locked(), "the slot is free");
}

/// Keeps a copy of the invocation's token for the case: the broker's own handle closes, this one
/// does not.
fn hold_the_token(held: &Arc<Mutex<Option<Handle>>>) {
    let held = Arc::clone(held);
    hooks::set_hook(Some(Arc::new(move |name| {
        if name == "token made" {
            *held.lock().unwrap() = Some(copy_of_the_token());
        }
    })));
}

/// A copy of the token the broker made for the invocation in progress, in this process.
fn copy_of_the_token() -> Handle {
    let mut copy: HANDLE = null_mut();
    // SAFETY: duplicates a handle of this process into this process; the source is the token the
    // broker made, open while the hook that calls this runs.
    let done = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            hooks::token_handle() as HANDLE,
            GetCurrentProcess(),
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(done, 0, "the token is copied");
    Handle::new(copy, "the held token").unwrap()
}

/// What an end that is not proved leaves: the reply says uncertain, the rows say so, nothing is
/// released, the slot is blocked and the tree held, and a request is refused with the words of the
/// uncertain end.
fn expect_an_uncertain_end(life: &Life, replies: &[InvocationReply]) {
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                cleanup: Cleanup::Uncertain,
                ..
            })
        ),
        "{replies:?}"
    );
    let names = kinds(&life.rows());
    assert!(names.iter().any(|name| name == "EndUncertain"), "{names:?}");
    assert!(!life.ended(), "{names:?}");
    assert!(
        !names
            .iter()
            .any(|name| name == "ReleaseIntent" || name == "RootRemoved"),
        "{names:?}"
    );
    assert_eq!(
        life.releases(),
        0,
        "nothing is released on an end that is not proved"
    );
    assert_eq!(life.trees.blocked(), Some(Blocked::Uncertain));
    assert_eq!(
        life.trees.counts.closed.load(Ordering::SeqCst),
        0,
        "the tree stays held"
    );
    // A request on the blocked project is refused with the words of the uncertain end.
    let again = run_one(life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            again.last(),
            Some(InvocationReply::Refused { kind: RefusedKind::Leftover, detail }) if detail == UNCERTAIN_END_WORDS
        ),
        "{again:?}"
    );
}

/// What an end that a held handle keeps from being proved leaves: the reply says uncertain, the
/// rows say so, nothing is released, the slot is blocked and the tree held, a request is refused
/// with the words of the uncertain end, and a restart finds the session still there. `release`
/// lets the held handle go, and the next try proves the end and finishes it.
fn expect_uncertain_until_released(
    life: &Life,
    replies: &[InvocationReply],
    release: impl FnOnce(),
) {
    expect_an_uncertain_end(life, replies);
    // The same try again, with the handle still held, finds the session still there.
    let broker = life.restarted(1);
    let first_try = recover(&broker.env).unwrap();
    assert!(
        matches!(first_try.invocations.as_slice(), [Recovered::Uncertain(..)]),
        "{:?}",
        first_try.invocations
    );
    assert_eq!(broker.releases(), 0);
    // Closing the handle clears it at the next try.
    let luid = hooks::session();
    release();
    absent_session(luid);
    let next_try = recover(&broker.env).unwrap();
    assert!(
        matches!(next_try.invocations.as_slice(), [Recovered::Ended(..)]),
        "{:?}",
        next_try.invocations
    );
    assert_eq!(
        broker.releases(),
        1,
        "the release ran once the end was proved"
    );
    assert!(broker.ended());
    assert!(!broker.trees.locked(), "the slot is free");
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_held_token_handle_makes_the_end_uncertain_and_closing_it_clears_it_at_the_next_try() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let life = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["exit", "0"],
        1,
        |env| {
            env.bounds.session = Duration::from_secs(2);
        },
    );
    let held = Arc::new(Mutex::new(None));
    hold_the_token(&held);
    let replies = run_one(&life, How::Reads, client_of(None), None);
    expect_uncertain_until_released(&life, &replies, || {
        drop(held.lock().unwrap().take().expect("a handle was held"));
    });
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_held_process_object_makes_the_end_uncertain_and_closing_it_clears_it_at_the_next_try() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let marker = setting.mark("holding.txt");
    let said = marker.display().to_string();
    // The child runs long enough for a handle to its process to be taken, and then ends by itself:
    // the process is gone and its object stays, because this handle keeps it.
    let life = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "1500", &said],
        1,
        |env| {
            env.bounds.session = Duration::from_secs(2);
        },
    );
    let held: Arc<Mutex<Option<Handle>>> = Arc::new(Mutex::new(None));
    let taker = std::thread::spawn({
        let held = Arc::clone(&held);
        move || {
            let pid: u32 = wait_for_file(&marker).trim().parse().unwrap();
            *held.lock().unwrap() = Some(process_handle(pid));
        }
    });
    let replies = run_one(&life, How::Reads, client_of(None), None);
    taker.join().unwrap();
    expect_uncertain_until_released(&life, &replies, || {
        drop(
            held.lock()
                .unwrap()
                .take()
                .expect("a process object was held"),
        );
    });
}

/// Seconds from `from` to `to`, negative when `to` is earlier.
fn seconds_between(from: std::time::SystemTime, to: std::time::SystemTime) -> i64 {
    match to.duration_since(from) {
        Ok(forward) => forward.as_secs() as i64,
        Err(back) => -(back.duration().as_secs() as i64),
    }
}

/// Moves the system's clock and puts it back when it is dropped: to the time it began at plus the
/// time that has passed since. The host's time synchronisation would correct a moved clock while a
/// move is measured, so that service stays stopped for as long as the clock is held.
struct Clock {
    began: std::time::SystemTime,
    at: Instant,
}

impl Clock {
    fn new() -> Clock {
        let stopped = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Stop-Service -Name vmictimesync -Force -ErrorAction Stop",
            ])
            .status()
            .unwrap();
        assert!(
            stopped.success(),
            "the time synchronisation was not stopped: {stopped}"
        );
        Clock {
            began: std::time::SystemTime::now(),
            at: Instant::now(),
        }
    }

    fn adjust(seconds: i64) {
        let status = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Set-Date -Adjust ([TimeSpan]::FromSeconds({seconds})) | Out-Null"),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "the clock was not moved: {status}");
    }

    /// Moves the clock by `seconds` and says how far it moved.
    fn move_by(&self, seconds: i64) -> i64 {
        let was = std::time::SystemTime::now();
        Clock::adjust(seconds);
        seconds_between(was, std::time::SystemTime::now())
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        let right = self.began + self.at.elapsed();
        let off = seconds_between(std::time::SystemTime::now(), right);
        if off.abs() > 2 {
            Clock::adjust(off);
        }
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Start-Service -Name vmictimesync -ErrorAction SilentlyContinue",
            ])
            .status();
    }
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn the_boot_marker_is_the_same_across_a_change_of_the_clock_and_a_journal_reads_the_same_boot() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // The service's key is the installation's; the marker is made under it.
    let key = std::process::Command::new("reg")
        .args([
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\KalaReachBoundary",
            "/f",
        ])
        .output()
        .unwrap();
    assert!(key.status.success(), "the service's key was not made");
    let first = boot::marker().unwrap();
    assert!(first.trusted && first.made, "{first:?}");
    let life = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["exit", "0"],
        1,
        |env| env.boot.clone_from(&first.id),
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    expect_clean_end(&replies, EndedBy::Exit);
    let begin = life
        .rows()
        .into_iter()
        .find_map(|row| match row {
            Row::Begin { boot_marker, .. } => Some(boot_marker),
            _ => None,
        })
        .expect("the journal has its first row");
    assert_eq!(begin, first.id, "the first row records the marker");
    // Whether a journal reads the boot it began in as the current one.
    let same_boot = |current: &str| {
        let path = std::fs::read_dir(setting.scratch.path("journal"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let id = path.file_stem().unwrap().to_string_lossy().into_owned();
        match read_file(&id, &std::fs::read(&path).unwrap(), current) {
            kr_boundary_windows::journal::replay::Reading::Invocation(found) => found.same_boot,
            kr_boundary_windows::journal::replay::Reading::MadeNothing => {
                panic!("the file holds an invocation")
            }
        }
    };
    assert!(same_boot(&first.id));
    // The clock goes a day forward, and then two days back, past the time of the first row.
    let clock = Clock::new();
    for seconds in [86_400, -172_800] {
        let moved = clock.move_by(seconds);
        assert!(
            (moved - seconds).abs() < 600,
            "the clock moved {moved} s, not {seconds} s"
        );
        let again = boot::marker().unwrap();
        assert_eq!(
            (again.id.as_str(), again.made, again.trusted),
            (first.id.as_str(), false, true),
            "the marker changed with the clock"
        );
        assert!(same_boot(&again.id), "the journal reads another boot");
    }
    drop(clock);
    assert_eq!(boot::marker().unwrap().id, first.id);
}

fn expect_clean_end(replies: &[InvocationReply], by: EndedBy) {
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished { ended_by, cleanup: Cleanup::Clean, .. }) if *ended_by == by
        ),
        "{replies:?}"
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_cancel_a_disconnect_and_a_deadline_each_end_through_the_one_ending_function() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let marker = setting.mark("running.txt");
    let running = marker.display().to_string();
    // The client asks for the end.
    let life = setting.life(&["sleep", "120000", &running], 1);
    let replies = run_one(&life, How::Cancels, client_of(None), Some(&marker));
    expect_clean_end(&replies, EndedBy::Cancel);
    assert!(life.ended() && life.releases() == 1 && !life.trees.locked());
    // The client's connection ends: the broker cannot answer, and the end is the same.
    std::fs::remove_file(&marker).unwrap();
    let life = setting.life(&["sleep", "120000", &running], 1);
    let replies = run_one(&life, How::Leaves, client_of(None), Some(&marker));
    assert_eq!(replies.len(), 1, "{replies:?}");
    let until = Instant::now() + Duration::from_secs(60);
    while !life.ended() {
        assert!(
            Instant::now() < until,
            "the invocation did not end: {:?}",
            kinds(&life.rows())
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(life.releases() == 1 && !life.trees.locked());
    // The deadline passes.
    let life = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "120000"],
        1,
        |env| {
            env.bounds.deadline = Duration::from_secs(3);
        },
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    expect_clean_end(&replies, EndedBy::Deadline);
    assert!(life.ended() && life.releases() == 1);
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn the_end_of_the_clients_process_and_the_stop_of_the_service_each_end_the_invocation() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // A stand-in for the client's process that ends a little after the invocation began.
    let mut helper = std::process::Command::new("ping")
        .args(["-n", "6", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let life = setting.life(&["sleep", "120000"], 1);
    let replies = run_one(&life, How::Reads, client_of(Some(helper.id())), None);
    helper.wait().unwrap();
    expect_clean_end(&replies, EndedBy::ClientExit);
    assert!(life.ended() && life.releases() == 1);
    // The service's stop: the invocation ends and its end is proved.
    let marker = setting.mark("stopped.txt");
    let running = marker.display().to_string();
    let life = setting.life(&["sleep", "120000", &running], 1);
    let stop = Arc::clone(&life.env.stop);
    let waiter = std::thread::spawn({
        let marker = marker.clone();
        move || {
            wait_for_file(&marker);
            stop.set();
        }
    });
    // The connection has a stop of its own in this case, so the reply is still delivered.
    let replies = run_one(&life, How::Reads, client_of(None), Some(&marker));
    waiter.join().unwrap();
    expect_clean_end(&replies, EndedBy::Stop);
    assert!(life.ended() && life.releases() == 1);
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_program_that_cannot_start_is_a_refusal_when_nothing_is_left_and_not_started_when_something_is()
{
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let life = setting.life(&["exit", "0"], 1);
    std::fs::remove_file(setting.scratch.path("kr-launch-stand-in.exe")).unwrap();
    let replies = run_one(&life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Refused {
                kind: RefusedKind::Operation,
                ..
            })
        ),
        "{replies:?}"
    );
    assert!(
        life.ended() && life.releases() == 1 && !life.trees.locked(),
        "{:?}",
        kinds(&life.rows())
    );
    // With something left on the tree, the reply says the operation did not start.
    forget_journals(&setting);
    let life = setting.life(&["exit", "0"], 1);
    std::fs::remove_file(setting.scratch.path("kr-launch-stand-in.exe")).unwrap();
    life.trees.leave(vec![Left {
        object: r"C:\fixture\left.txt".to_owned(),
        reason: "a case's leftover".to_owned(),
    }]);
    let replies = run_one(&life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                ended_by: EndedBy::NotStarted,
                exit: None,
                cleanup: Cleanup::Failed { .. },
                ..
            })
        ),
        "{replies:?}"
    );
    assert!(!life.ended(), "{:?}", kinds(&life.rows()));
    assert!(matches!(life.trees.blocked(), Some(Blocked::Leftover(_))));
    let again = run_one(&life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            again.last(),
            Some(InvocationReply::Refused { kind: RefusedKind::Leftover, detail }) if detail.contains("left.txt")
        ),
        "{again:?}"
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_client_that_never_connects_its_pipes_is_refused_after_the_bound_and_the_invocation_ends() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let life = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["exit", "0"],
        1,
        |env| {
            env.bounds.connect = Duration::from_secs(2);
        },
    );
    let replies = run_one(&life, How::NeverConnects, client_of(None), None);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Refused {
                kind: RefusedKind::Transport,
                ..
            })
        ),
        "{replies:?}"
    );
    assert!(
        life.ended() && life.releases() == 1 && !life.trees.locked(),
        "{:?}",
        kinds(&life.rows())
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_child_that_hides_from_the_scan_changes_nothing_because_the_end_rests_on_the_session() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let marker = setting.mark("hidden.txt");
    // The client cancels only when this file says the checks on the hidden child are over.
    let checked = setting.mark("hidden-checked.txt");
    let running = marker.display().to_string();
    let life = setting.life(&["hide", "120000", &running], 1);
    let seen = Arc::new(Mutex::new(0_u64));
    hooks::set_hook(Some(Arc::new({
        let seen = Arc::clone(&seen);
        move |name| {
            if name == "token made" {
                *seen.lock().unwrap() = hooks::session();
            }
        }
    })));
    let tracker = std::thread::spawn({
        let marker = marker.clone();
        let checked = checked.clone();
        move || {
            // What the child says of itself, and whether a limited query on it is refused under the
            // service's conditions: a token that holds no privilege, as the service's holds no
            // debug privilege.
            let said = wait_for_file(&marker);
            let pid: u32 = said.split_whitespace().next().unwrap().parse().unwrap();
            let refusal = without_privileges(|| {
                // SAFETY: opens a process by number for a limited query; the answer is read.
                let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                if opened.is_null() {
                    // SAFETY: reads the calling thread's last error.
                    Some(unsafe { GetLastError() })
                } else {
                    drop(Handle::new(opened, "the hidden child").unwrap());
                    None
                }
            });
            // The child stays until this point: the client's cancel waits for the file.
            note(
                checked.parent().unwrap(),
                checked.file_name().unwrap().to_str().unwrap(),
                "checked",
            );
            (said, pid, refusal)
        }
    });
    let replies = run_one(&life, How::Cancels, client_of(None), Some(&checked));
    let (said, pid, refusal) = tracker.join().unwrap();
    assert_eq!(
        said.trim(),
        format!("{pid} hidden"),
        "the child did not hide, or said something else"
    );
    assert_eq!(
        refusal,
        Some(ERROR_ACCESS_DENIED),
        "a limited query on the hidden child, under a token without privileges, is refused"
    );
    // The child is in the job: it ends with it, whether or not it could be looked at, and the
    // session is gone.
    expect_clean_end(&replies, EndedBy::Cancel);
    absent_session(*seen.lock().unwrap());
    assert!(life.ended() && life.releases() == 1);
}

/// Runs an invocation in which the service is told to stop at `point`, with a copy of the token
/// held so that the end cannot be proved, and returns the replies.
fn stopped_at(
    setting: &Setting,
    point: &'static str,
    reading: bool,
    how: How,
) -> Vec<InvocationReply> {
    let edit = |env: &mut Environment| {
        env.bounds.session = Duration::from_secs(2);
    };
    let life = if reading {
        Life::open_reading(
            &setting.scratch.dir,
            &setting.account,
            &["sleep", "120000"],
            &["exit", "0"],
            1,
            edit,
        )
    } else {
        Life::open(
            &setting.scratch.dir,
            &setting.account,
            &["sleep", "120000"],
            1,
            edit,
        )
    };
    let held = Arc::new(Mutex::new(None));
    let stop = Arc::clone(&life.env.stop);
    hooks::set_hook(Some(Arc::new({
        let held = Arc::clone(&held);
        move |name| {
            if name == "token made" {
                *held.lock().unwrap() = Some(copy_of_the_token());
            }
            if name == point {
                stop.set();
            }
        }
    })));
    let replies = run_one(&life, how, client_of(None), None);
    let luid = hooks::session();
    hooks::set_hook(None);
    drop(held.lock().unwrap().take());
    absent_session(luid);
    replies
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_stop_of_the_service_during_the_reader_or_the_wait_for_the_pipes_ends_by_the_stop() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // The reader is running when the service is told to stop, and the end cannot be proved.
    let replies = stopped_at(&setting, "reader resumed", true, How::Reads);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                ended_by: EndedBy::Stop,
                exit: None,
                cleanup: Cleanup::Uncertain,
                ..
            })
        ),
        "{replies:?}"
    );
    // The service is told to stop while the client is to connect the data pipes.
    forget_journals(&setting);
    let replies = stopped_at(&setting, "accepted", false, How::NeverConnects);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                ended_by: EndedBy::Stop,
                exit: None,
                cleanup: Cleanup::Uncertain,
                ..
            })
        ),
        "{replies:?}"
    );
}

/// Runs `body` on this thread under a copy of this process's token that holds no privilege, which is
/// the service's condition: its token holds no debug privilege and gets none.
fn without_privileges<T>(body: impl FnOnce() -> T) -> T {
    let mut process_token: HANDLE = null_mut();
    // SAFETY: opens this process's token for copying; the result is checked and owned below.
    unsafe {
        assert_ne!(
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                &raw mut process_token
            ),
            0,
            "this process's token opens"
        );
    }
    let process_token = Handle::new(process_token, "this process's token").unwrap();
    let mut restricted: HANDLE = null_mut();
    // SAFETY: makes a copy that holds no privilege; the result is checked and owned below.
    unsafe {
        assert_ne!(
            CreateRestrictedToken(
                process_token.raw(),
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                0,
                null(),
                &raw mut restricted
            ),
            0,
            "the token loses its privileges"
        );
    }
    let restricted = Handle::new(restricted, "the token without privileges").unwrap();
    let mut impersonation: HANDLE = null_mut();
    // SAFETY: makes an impersonation copy; the result is checked and owned below.
    unsafe {
        assert_ne!(
            DuplicateTokenEx(
                restricted.raw(),
                TOKEN_IMPERSONATE | TOKEN_QUERY,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut impersonation
            ),
            0,
            "the token is copied for impersonation"
        );
    }
    let impersonation = Handle::new(impersonation, "the impersonation token").unwrap();
    // SAFETY: sets this thread's token for the body and takes it away after.
    unsafe {
        assert_ne!(SetThreadToken(null(), impersonation.raw()), 0);
    }
    let result = body();
    // SAFETY: takes the token from this thread.
    unsafe {
        SetThreadToken(null(), null_mut());
    }
    result
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn the_scan_reports_a_process_that_refuses_a_limited_look_and_not_one_that_is_gone() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    prepare();
    let scratch = Scratch::new();
    let marker = scratch.path("hidden.txt");
    // A process that took every entry out of its own permission list: a limited look is refused.
    let mut child = std::process::Command::new(bin().join("kr-launch-stand-in.exe"))
        .args(["hide", "120000", &marker.display().to_string()])
        .spawn()
        .unwrap();
    let said = wait_for_file(&marker);
    let pid = child.id();
    let created = creation_of(&process_handle(pid));
    // A number that no process has.
    let gone = u32::MAX - 3;
    let group = Sid::parse("S-1-9-1-2-3-4").unwrap();
    let facts = scan::Facts {
        group: &group,
        job: None,
        since: 0,
    };
    let report = without_privileges(|| {
        scan::testing::scan_listed(&facts, &[(pid, created), (gone, u64::MAX)])
    });
    child.kill().unwrap();
    let _ = child.wait();
    assert!(
        said.trim() == format!("{pid} hidden"),
        "the child did not hide: {said:?}"
    );
    assert!(
        report
            .reports
            .iter()
            .any(|line| line.starts_with(&format!("process {pid} "))),
        "a process that refuses a limited look is reported: {report:?}"
    );
    assert!(
        !report
            .reports
            .iter()
            .any(|line| line.starts_with(&format!("process {gone} "))),
        "a process that is gone is not reported: {report:?}"
    );
}

// ---- A broker that crashes with an invocation alive, and the restart that finishes it.

/// Where the child records what it did, for the parent to read.
fn note(dir: &Path, file: &str, text: &str) {
    std::fs::write(dir.join(file), text).unwrap();
}

/// The broker the crash cases start: it runs one invocation on the fixture, and at the named point
/// it ends its own process, as a crash does. With `KR_LIFE_HOLD` it first gives the invocation's
/// token to the process that started it, so that a handle outlives the crash. With
/// `KR_LIFE_HOLD_ROOT` it keeps a file of the private root open without sharing from the moment the
/// root is made, so that the removal of the root cannot delete it.
#[test]
#[ignore = "started by the crash cases as the broker that they crash"]
fn the_broker_that_the_crash_cases_crash() {
    let Ok(point) = std::env::var("KR_LIFE_CRASH") else {
        return;
    };
    let dir = PathBuf::from(std::env::var("KR_LIFE_DIR").unwrap());
    let account = std::env::var("KR_LIFE_ACCOUNT").unwrap();
    let parent: u32 = std::env::var("KR_LIFE_PARENT").unwrap().parse().unwrap();
    let hold = std::env::var("KR_LIFE_HOLD").is_ok();
    let reading = std::env::var("KR_LIFE_READER").is_ok();
    let hold_root = std::env::var("KR_LIFE_HOLD_ROOT").is_ok();
    prepare();
    let marker = dir.join("marks").join("child-running.txt");
    let running = marker.display().to_string();
    // With a reader, the reader is the child that runs: it sleeps, and the primary is never reached.
    let life = if reading {
        Life::open_reading(
            &dir,
            &account,
            &["sleep", "120000", &running],
            &["exit", "0"],
            1,
            |_| {},
        )
    } else {
        Life::open(&dir, &account, &["sleep", "120000", &running], 1, |_| {})
    };
    let reached = Arc::new(AtomicU32::new(0));
    let hook_dir = dir.clone();
    let hook_marker = marker.clone();
    let held_file: Arc<Mutex<Option<std::fs::File>>> = Arc::new(Mutex::new(None));
    hooks::set_hook(Some(Arc::new(move |name| {
        if hooks::session() != 0 {
            note(&hook_dir, "session.txt", &hooks::session().to_string());
        }
        if hold_root && name == "after RootMade" {
            let root = std::fs::read_dir(hook_dir.join("run"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(root.join("held.lock"))
                .unwrap();
            *held_file.lock().unwrap() = Some(file);
        }
        if name != point {
            return;
        }
        if hold {
            // SAFETY: opens the starting process for handle duplication and gives it a copy of the
            // token; the copy's value, as that process knows it, is written for it to read.
            unsafe {
                let target = OpenProcess(PROCESS_DUP_HANDLE, 0, parent);
                let mut copy: HANDLE = null_mut();
                DuplicateHandle(
                    GetCurrentProcess(),
                    hooks::token_handle() as HANDLE,
                    target,
                    &raw mut copy,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                );
                note(&hook_dir, "held.txt", &(copy as usize).to_string());
            }
        }
        if reading {
            // The reader is at its work before the broker is cut off.
            wait_for_file(&hook_marker);
        }
        note(&hook_dir, "crashed-at.txt", name);
        reached.store(1, Ordering::SeqCst);
        // SAFETY: ends this process at once, as a crash does.
        unsafe {
            TerminateProcess(GetCurrentProcess(), 99);
        }
    })));
    let how = if marker.exists() {
        How::Reads
    } else {
        How::Cancels
    };
    let _ = run_one(&life, how, client_of(None), Some(&marker));
}

/// Starts the broker child that crashes at `point` and returns its exit code.
fn crash_child(setting: &Setting, point: &str, hold: bool, reading: bool, root_file: bool) -> i32 {
    let me = std::env::current_exe().unwrap();
    let mut command = std::process::Command::new(me);
    command
        .args([
            "--ignored",
            "--exact",
            "the_broker_that_the_crash_cases_crash",
            "--test-threads=1",
        ])
        .env("KR_LIFE_CRASH", point)
        .env("KR_LIFE_DIR", &setting.scratch.dir)
        .env("KR_LIFE_ACCOUNT", &setting.account)
        .env("KR_LIFE_PARENT", std::process::id().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if hold {
        command.env("KR_LIFE_HOLD", "1");
    }
    if reading {
        command.env("KR_LIFE_READER", "1");
    }
    if root_file {
        command.env("KR_LIFE_HOLD_ROOT", "1");
    }
    let mut child = command.spawn().unwrap();
    let until = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        if Instant::now() >= until {
            child.kill().unwrap();
            return -2;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn clear_run(setting: &Setting) {
    for file in ["session.txt", "held.txt", "crashed-at.txt"] {
        let _ = std::fs::remove_file(setting.scratch.path(file));
    }
    let _ = std::fs::remove_file(setting.mark("child-running.txt"));
    for entry in std::fs::read_dir(setting.scratch.path("journal")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
}

/// Every point of the lifecycle, in order: a name before and after each journal row, and the named
/// places between them.
const POINTS: [&str; 32] = [
    "admitted",
    "tree resolved",
    "token made",
    "before Begin",
    "after Begin",
    "job made",
    "before RootIntent",
    "after RootIntent",
    "before RootMade",
    "after RootMade",
    "before Grant",
    "after Grant",
    "before GrantComplete",
    "after GrantComplete",
    "accepted",
    "connected",
    "suspended",
    "before ProcessStarted",
    "after ProcessStarted",
    "resumed",
    "waiting",
    "ending",
    "job ended",
    "before JobEnded",
    "after JobEnded",
    "end check made",
    "before ReleaseIntent",
    "after ObjectReleased",
    "root removed",
    "before ReleaseVerified",
    "before End",
    "after End",
];

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_broker_that_crashes_at_each_point_is_finished_by_the_restart_with_its_session_gone() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let mut failures = Vec::new();
    for point in POINTS {
        clear_run(&setting);
        let code = crash_child(&setting, point, false, false, false);
        if code != 99 {
            failures.push(format!(
                "{point}: the broker ended with {code}, not by the crash"
            ));
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(setting.scratch.path("session.txt")) {
            // The processes are gone with the job and the session leaves the list: observed.
            let luid: u64 = text.trim().parse().unwrap();
            if session::wait_absent(luid, Duration::from_secs(60))
                != kr_boundary_windows::lifecycle::Session::Absent
            {
                failures.push(format!("{point}: the session {luid} stayed"));
                continue;
            }
        }
        let broker = Life::open(
            &setting.scratch.dir,
            &setting.account,
            &["sleep", "60000"],
            1,
            |_| {},
        );
        let recovery = recover(&broker.env).unwrap();
        let rows = broker.rows();
        let begun = rows.iter().any(|row| matches!(row, Row::Begin { .. }));
        let wrong = recovery
            .invocations
            .iter()
            .any(|each| !matches!(each, Recovered::Ended(_)));
        if wrong || broker.trees.locked() || (begun && !broker.ended()) {
            failures.push(format!(
                "{point}: recovery {:?}, locked {}, rows {:?}",
                recovery.invocations,
                broker.trees.locked(),
                kinds(&rows)
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_crash_with_a_handle_held_on_purpose_keeps_the_grants_and_the_slot_until_the_handle_is_closed()
{
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    clear_run(&setting);
    assert_eq!(crash_child(&setting, "waiting", true, false, false), 99);
    let luid: u64 = std::fs::read_to_string(setting.scratch.path("session.txt"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let value: usize = wait_for_file(&setting.scratch.path("held.txt"))
        .trim()
        .parse()
        .unwrap();
    let held = Handle::new(value as HANDLE, "the handle held across the crash").unwrap();
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |env| {
            env.bounds.session = Duration::from_secs(2);
        },
    );
    let first = recover(&broker.env).unwrap();
    assert!(
        matches!(first.invocations.as_slice(), [Recovered::Uncertain(..)]),
        "{:?}",
        first.invocations
    );
    assert_eq!(broker.releases(), 0);
    assert_eq!(broker.trees.blocked(), Some(Blocked::Uncertain));
    assert!(
        broker
            .rows()
            .iter()
            .any(|row| matches!(row, Row::Grant { .. })),
        "the grants stay journalled"
    );
    // The slot stays blocked after the restart, whatever else is asked of it.
    drop(held);
    absent_session(luid);
    let second = recover(&broker.env).unwrap();
    assert!(
        matches!(second.invocations.as_slice(), [Recovered::Ended(..)]),
        "{:?}",
        second.invocations
    );
    assert_eq!(broker.releases(), 1);
    assert!(!broker.trees.locked() && broker.ended());
}

// ---- Journals as a crash leaves them.

/// A journal of an invocation that began and made nothing else, with the rows after `Begin`.
fn write_journal(setting: &Setting, rows: &[Row]) -> PathBuf {
    let id = [9_u8; 16];
    let mut journal = kr_boundary_windows::win::journal::Journal::create(
        &setting.scratch.path("journal"),
        kr_boundary_windows::win::launch::InvocationId(id),
    )
    .unwrap();
    journal
        .append(&Row::Begin {
            invocation: hex::encode(id),
            boot_marker: "lifetime-boot-marker".to_owned(),
            session_luid: 0x7fff_0001,
            group_sid: "S-1-9-1-2-3-4".to_owned(),
            client_sid: "S-1-5-18".to_owned(),
            client_pid: 4,
            client_creation_time: 1,
            chain: vec![FileKey::ntfs(0x5151, 1), FileKey::ntfs(0x5151, 2)],
            tree_path: r"C:\fixture".to_owned(),
        })
        .unwrap();
    for row in rows {
        journal.append(row).unwrap();
    }
    journal.path().to_path_buf()
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_torn_tail_a_root_intent_without_its_made_row_and_a_release_intent_without_its_result_are_finished()
 {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let key = FileKey::ntfs(0x5151, 1000);
    let name = RootName::from_bytes([5; 16]);
    // A root that was begun and made on disk but never recorded as made.
    let path = write_journal(
        &setting,
        &[
            Row::RootIntent { name: name.clone() },
            Row::Grant {
                key,
                path: r"C:\fixture\granted0".to_owned(),
                kind: ObjectKind::File,
                owner: "S-1-9-1-2-3-4".to_owned(),
                dacl_bytes: vec![1, 2, 3],
                control_flags: 0,
                protected: false,
                link_count: 1,
                added_ace: "S-1-9-1-2-3-4".to_owned(),
            },
            Row::GrantComplete { count: 1 },
            Row::ReleaseIntent {
                key,
                rule: Rule::Group,
                new_owner: None,
                new_dacl_bytes: vec![1, 2, 3],
                label: Label::Keep,
                protected_target: false,
            },
        ],
    );
    std::fs::create_dir_all(setting.scratch.path("run").join(name.as_str()).join("tmp")).unwrap();
    // The last row is cut short, as a crash in the middle of a write leaves it.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&[40, 0, 0, 0, 1, 2, 3]);
    std::fs::write(&path, &bytes).unwrap();
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |_| {},
    );
    let recovery = recover(&broker.env).unwrap();
    assert!(
        matches!(recovery.invocations.as_slice(), [Recovered::Ended(_)]),
        "{:?}",
        recovery.invocations
    );
    assert!(broker.ended(), "{:?}", kinds(&broker.rows()));
    let names = kinds(&broker.rows());
    assert!(
        names.iter().any(|each| each == "ObjectReleased"),
        "{names:?}"
    );
    assert!(names.iter().any(|each| each == "RootRemoved"), "{names:?}");
    assert!(
        std::fs::metadata(setting.scratch.path("run").join(name.as_str())).is_err(),
        "the root that was only begun is removed by its recorded name"
    );
    assert_eq!(broker.releases(), 1);
    assert!(!broker.trees.locked());
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_journal_with_a_damaged_middle_record_keeps_its_tree_blocked() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    let path = write_journal(
        &setting,
        &[
            Row::RootIntent {
                name: RootName::from_bytes([6; 16]),
            },
            Row::GrantComplete { count: 0 },
        ],
    );
    // The damage is in the second record, which a valid record follows: the first row is whole, so
    // the tree's chain is known and the slot can be kept.
    let mut bytes = std::fs::read(&path).unwrap();
    let last =
        kr_boundary_windows::journal::framing::encode(&Row::GrantComplete { count: 0 }.to_bytes())
            .unwrap()
            .len();
    let middle = bytes.len() - last - 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |_| {},
    );
    let recovery = recover(&broker.env).unwrap();
    assert!(
        matches!(recovery.invocations.as_slice(), [Recovered::Unreadable(..)]),
        "{:?}",
        recovery.invocations
    );
    assert!(
        broker.trees.locked(),
        "an unreadable journal keeps its tree blocked"
    );
    assert!(matches!(broker.trees.blocked(), Some(Blocked::Leftover(_))));
}

/// A reader that ends with the code 0 and leaves a live process refuses the operation before the
/// grant: no `Grant`, `GrantComplete` or `ProcessStarted` row stands. Two ends are right. Where the
/// logon session leaves the system's list, the reply is the refusal, the tree is closed and the
/// slot is free. On a guest, Defender's real-time protection holds a token of the account on some
/// runs (its process gains a token handle while the reader's process is alive), so the session
/// stays past the end's bound: the end is then not proved, the journal holds `EndUncertain` that
/// names the logon session, the reply is `finished` with `NotStarted` and an uncertain cleanup, the
/// slot stays closed, and the next request is refused with the words of the uncertain end.
#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_reader_that_ends_and_leaves_a_live_descendant_refuses_the_operation_before_the_grant() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // The reader ends with the code 0 and a process it started is still alive in the job.
    let life = Life::open_reading(
        &setting.scratch.dir,
        &setting.account,
        &["leave"],
        &["exit", "0"],
        1,
        |_| {},
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    let rows = life.rows();
    let names = kinds(&rows);
    // Whichever end follows, the operation never reached its grant or its primary.
    assert!(
        !names
            .iter()
            .any(|name| name == "Grant" || name == "GrantComplete" || name == "ProcessStarted"),
        "no grant is made while a process of the reader lives: {names:?}"
    );
    match replies.last() {
        // The end is proved: the refusal, the tree closed and the slot free.
        Some(InvocationReply::Refused {
            kind: RefusedKind::Operation,
            detail,
        }) if detail.contains("reader of the project ended and left") => {
            assert!(
                life.ended() && life.releases() == 1 && !life.trees.locked(),
                "{names:?}"
            );
            absent_session(hooks::session());
        }
        // The end is not proved: the logon session stays in the system's list.
        Some(InvocationReply::Finished {
            exit: None,
            ended_by: EndedBy::NotStarted,
            cleanup: Cleanup::Uncertain,
            ..
        }) => {
            assert!(
                rows.iter().any(|row| matches!(
                    row,
                    Row::EndUncertain { reason } if reason.contains("logon session")
                )),
                "{rows:?}"
            );
            expect_an_uncertain_end(&life, &replies);
        }
        other => panic!("{other:?} {names:?}"),
    }
}

/// Whether the process with this number is still running.
fn still_running(pid: u32) -> bool {
    // SAFETY: opens a process by number for a limited query; a process that cannot be opened is
    // gone; the exit code is read into a local.
    unsafe {
        let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if raw.is_null() {
            return false;
        }
        let process = Handle::new(raw, "a process").unwrap();
        let mut code = 0_u32;
        GetExitCodeProcess(process.raw(), &raw mut code) != 0 && code == 259
    }
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_reader_child_ends_before_the_grant_and_one_that_refuses_or_overruns_ends_the_invocation() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // A reader that accepts runs and ends, and the journal has no row for it: the primary child's
    // is the only row of a process.
    let marker = setting.mark("reader.txt");
    let said = marker.display().to_string();
    let life = Life::open_reading(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "1", &said],
        &["exit", "0"],
        1,
        |_| {},
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    expect_clean_end(&replies, EndedBy::Exit);
    let pid: u32 = wait_for_file(&marker).trim().parse().unwrap();
    assert!(!still_running(pid), "the reader ended");
    let names = kinds(&life.rows());
    assert_eq!(
        names
            .iter()
            .filter(|name| *name == "ProcessStarted")
            .count(),
        1,
        "{names:?}"
    );
    assert!(life.ended() && life.releases() == 1 && !life.trees.locked());
    // A reader that ends with another code refuses the operation, before the grant and before the
    // primary child: the invocation ends clean and the project is free.
    forget_journals(&setting);
    let life = Life::open_reading(
        &setting.scratch.dir,
        &setting.account,
        &["exit", "3"],
        &["exit", "0"],
        1,
        |_| {},
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Refused { kind: RefusedKind::Operation, detail }) if detail.contains("code 3")
        ),
        "{replies:?}"
    );
    let names = kinds(&life.rows());
    assert!(
        !names
            .iter()
            .any(|name| name == "ProcessStarted" || name == "GrantComplete"),
        "{names:?}"
    );
    assert!(
        life.ended() && life.releases() == 1 && !life.trees.locked(),
        "{names:?}"
    );
    absent_session(hooks::session());
    // A reader that does not end within its bound is ended with the job, and the end is proved.
    forget_journals(&setting);
    let life = Life::open_reading(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "120000"],
        &["exit", "0"],
        1,
        |env| {
            env.bounds.reader = Duration::from_secs(2);
        },
    );
    let replies = run_one(&life, How::Reads, client_of(None), None);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Refused { kind: RefusedKind::Operation, detail }) if detail.contains("did not end in time")
        ),
        "{replies:?}"
    );
    absent_session(hooks::session());
    assert!(
        life.ended() && life.releases() == 1 && !life.trees.locked(),
        "{:?}",
        kinds(&life.rows())
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_crash_while_a_reader_child_runs_is_finished_by_the_restart_with_its_session_gone() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    clear_run(&setting);
    assert_eq!(
        crash_child(&setting, "reader resumed", false, true, false),
        99
    );
    let luid: u64 = std::fs::read_to_string(setting.scratch.path("session.txt"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pid: u32 = wait_for_file(&setting.mark("child-running.txt"))
        .trim()
        .parse()
        .unwrap();
    // The journal says nothing of the reader: no process row.
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |_| {},
    );
    let names = kinds(&broker.rows());
    assert!(
        names.iter().any(|name| name == "RootMade")
            && !names.iter().any(|name| name == "ProcessStarted"),
        "{names:?}"
    );
    // The job's last handle closed with the broker, so the reader ended with it.
    let until = Instant::now() + Duration::from_secs(30);
    while still_running(pid) {
        assert!(Instant::now() < until, "the reader {pid} still runs");
        std::thread::sleep(Duration::from_millis(100));
    }
    let recovery = recover(&broker.env).unwrap();
    assert!(
        matches!(recovery.invocations.as_slice(), [Recovered::Ended(_)]),
        "{:?}",
        recovery.invocations
    );
    absent_session(luid);
    let names = kinds(&broker.rows());
    assert!(
        broker.ended() && names.iter().any(|name| name == "RootRemoved"),
        "{names:?}"
    );
    assert!(broker.releases() == 1 && !broker.trees.locked());
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_crash_after_a_root_leftover_is_finished_by_the_restart_when_the_root_can_now_be_removed() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    clear_run(&setting);
    // The broker holds a file of the private root open, so the removal leaves it; the broker is cut
    // off after the first leftover row of the root and before any row that ends the invocation.
    assert_eq!(
        crash_child(&setting, "after Leftover", false, false, true),
        99
    );
    let luid: u64 = std::fs::read_to_string(setting.scratch.path("session.txt"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    absent_session(luid);
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |_| {},
    );
    let before = broker.rows();
    assert!(
        matches!(
            before.last(),
            Some(Row::Leftover {
                class: kr_boundary_windows::journal::rows::LeftoverClass::Root,
                ..
            })
        ),
        "{:?}",
        kinds(&before)
    );
    // The process that held the file is gone: the removal now succeeds.
    let recovery = recover(&broker.env).unwrap();
    assert!(
        matches!(recovery.invocations.as_slice(), [Recovered::Ended(_)]),
        "{:?}",
        recovery.invocations
    );
    let rows = broker.rows();
    assert!(
        matches!(rows.last(), Some(Row::End { root_leftovers: 0 })),
        "{:?}",
        kinds(&rows)
    );
    assert!(
        rows.iter().any(|row| matches!(row, Row::RootRemoved))
            && rows
                .iter()
                .any(|row| matches!(row, Row::LeftoverCleared { .. })),
        "{:?}",
        kinds(&rows)
    );
    assert!(broker.releases() == 1 && !broker.trees.locked());
    assert_eq!(
        std::fs::read_dir(setting.scratch.path("run"))
            .unwrap()
            .count(),
        0,
        "the private root is gone"
    );
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_restart_in_another_boot_proves_an_end_only_when_no_session_of_a_boundary_account_stands() {
    if !runs_as_the_system() {
        eprintln!("skipped: needs the system's token");
        return;
    }
    let setting = Setting::new();
    // An invocation that began under the boot marker the cases use and did not end. Its recorded
    // session number is one that no session has, so the rule of the same boot would find it gone.
    write_journal(&setting, &[]);
    // A session of the boundary account stands.
    let made = token::boundary_token(&setting.account, &token::new_invocation_group())
        .expect("a logon of the boundary account");
    let luid = session::session_of(&made).unwrap();
    // The broker now runs in another boot: the recorded number means nothing, and the end is proved
    // only when no session of either boundary account exists.
    let broker = Life::open(
        &setting.scratch.dir,
        &setting.account,
        &["sleep", "60000"],
        1,
        |env| env.boot = "another-boot-marker".to_owned(),
    );
    let first = recover(&broker.env).unwrap();
    assert!(
        matches!(first.invocations.as_slice(), [Recovered::Uncertain(..)]),
        "{:?}",
        first.invocations
    );
    assert_eq!(
        broker.releases(),
        0,
        "nothing is released on an end that is not proved"
    );
    assert_eq!(broker.trees.blocked(), Some(Blocked::Uncertain));
    // The session leaves: the next try proves the end and finishes the invocation.
    drop(made);
    absent_session(luid);
    let second = recover(&broker.env).unwrap();
    assert!(
        matches!(second.invocations.as_slice(), [Recovered::Ended(..)]),
        "{:?}",
        second.invocations
    );
    assert_eq!(broker.releases(), 1);
    assert!(broker.ended() && !broker.trees.locked());
}
