//! The private overlapped pipes an agent's streams are made of, run on Windows.
//!
//! A server's input and output must be ends the runtime reads and writes without blocking a thread,
//! and no other process may hold or open them. Each stream is a named pipe made private at its
//! creation: a name no other pipe has, an access list with one entry for this account, one instance
//! that this worker's own client takes before the agent exists, and only the agent's end made
//! inheritable.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.45 | A client that connects in the window between the pipe's creation and the agent's end refuses the start, and no process is created; a name that is taken refuses the start; this worker's ends are not inheritable and have an access list of one entry; the agent holds three client ends and no end of ours; the ends read and write through the runtime; an overlapped start made where no runtime runs is refused |
//!
//! The seams these cases use are process-wide, so each runs alone.

#![cfg(windows)]

use std::io::Read as _;
use std::os::windows::io::AsRawHandle as _;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kr_worker::windows::job::AgentJob;
use kr_worker::windows::launch::{Environment, Spec, Stdio, seams, start};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use windows_sys::Win32::Foundation::{
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, LocalFree,
};
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Pipes::GetNamedPipeInfo;

/// What names a case that is the child of another: the same test program, run as the agent.
const CHILD_MARKER: &str = "KR_PIPES_CHILD";

/// How long a case waits for what it started.
const PATIENCE: Duration = Duration::from_secs(60);

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Makes this case the only one running, because the seams it sets are process-wide.
fn alone() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn system_program(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join(name)
}

fn own_environment() -> Environment {
    Environment::of_this_process_with(&[]).expect("this process's environment")
}

/// A runtime the case enters for the starts it makes, because an overlapped end belongs to one.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

/// The number of entries in the access list of the object `handle` names.
#[expect(unsafe_code, reason = "reading an access list has no safe form")]
fn access_list_entries(handle: HANDLE) -> u16 {
    use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;

    let mut list: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the handle is open for the call, the out-parameters are locals this thread owns, and
    // the descriptor the call allocates is freed below.
    let read = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut list,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(read, 0, "the access list is read");
    assert!(!list.is_null(), "the object has an access list");
    // SAFETY: the call reported a list inside the descriptor, which is alive until freed.
    let entries = unsafe { (*list).AceCount };
    // SAFETY: the descriptor is the call's own allocation and nothing else holds it.
    unsafe { LocalFree(descriptor) };
    entries
}

/// Whether the handle can be inherited by a process this one creates.
#[expect(unsafe_code, reason = "reading a handle's flags has no safe form")]
fn inheritable(handle: HANDLE) -> bool {
    let mut flags = 0_u32;
    // SAFETY: the handle is open for the call and the flags are a local this thread owns.
    let read = unsafe { GetHandleInformation(handle, &raw mut flags) };
    assert_ne!(read, 0, "the handle's flags are read");
    flags & HANDLE_FLAG_INHERIT != 0
}

/// A launch's start of `program` with overlapped ends for the streams named, in a job of its own.
fn overlapped(
    job: &AgentJob,
    program: &std::path::Path,
    arguments: &[&str],
    environment: &Environment,
    streams: [Stdio; 3],
) -> std::io::Result<kr_worker::windows::launch::Child> {
    let arguments: Vec<String> = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
    let [stdin, stdout, stderr] = streams;
    start(&Spec {
        program,
        arguments: &arguments,
        directory: &std::env::temp_dir(),
        environment,
        session: None,
        agent: job,
        stdin,
        stdout,
        stderr,
    })
}

/// KR-REQ-07.45: a client of the same account that connects after the worker's end of a pipe exists
/// and before the agent's end is opened takes the one instance, so the start fails by name, nothing
/// is created, and the client reads the end of the file when the worker's end is closed.
#[test]
fn a_competing_client_in_the_window_refuses_the_start() {
    let _alone = alone();
    let runtime = runtime();
    let _enter = runtime.enter();
    let job = AgentJob::create_owning().expect("a job");
    let competitor: Arc<Mutex<Option<std::thread::JoinHandle<usize>>>> = Arc::default();
    let slot = Arc::clone(&competitor);
    seams::after_server_create(Some(Box::new(move |name: &str| {
        let name = name.to_owned();
        let (connected, wait_connected) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut file = std::fs::File::open(&name).expect("the competitor connects");
            connected.send(()).expect("the case waits");
            let mut read = Vec::new();
            file.read_to_end(&mut read).expect("reads to the end");
            read.len()
        });
        wait_connected
            .recv_timeout(PATIENCE)
            .expect("the competitor connected");
        *slot.lock().expect("a slot") = Some(reader);
    })));

    let refused = overlapped(
        &job,
        &system_program("ping.exe"),
        &["-n", "2", "127.0.0.1"],
        &own_environment(),
        [Stdio::Overlapped, Stdio::Null, Stdio::Null],
    );
    seams::after_server_create(None);
    let why = refused.expect_err("the start is refused").to_string();
    assert!(
        why.contains("another process connected to the server's pipe"),
        "{why}"
    );
    assert_eq!(
        job.total_processes().expect("the job's count"),
        0,
        "no process was created, not even one that has ended"
    );
    let reader = competitor
        .lock()
        .expect("a slot")
        .take()
        .expect("the competitor ran");
    // The runtime closes a dropped server end when its driver next runs, so the case runs it until
    // the competitor has read the end of the file.
    runtime
        .block_on(tokio::time::timeout(PATIENCE, async {
            while !reader.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }))
        .expect("the worker's end is closed once the runtime runs");
    assert_eq!(
        reader.join().expect("the competitor ends"),
        0,
        "the competitor reads the end of the file"
    );
}

/// KR-REQ-07.45: a pipe of the name the start would use refuses the create, and the start says the
/// name was taken, so a name another process made first is never used.
#[test]
fn a_taken_name_refuses_the_start() {
    let _alone = alone();
    let runtime = runtime();
    let _enter = runtime.enter();
    let name = format!(r"\\.\pipe\kr-server-taken-{}", std::process::id());
    let held = tokio::net::windows::named_pipe::ServerOptions::new()
        .create(&name)
        .expect("a pipe of that name");
    seams::fix_name(Some(name));
    let job = AgentJob::create_owning().expect("a job");
    let refused = overlapped(
        &job,
        &system_program("ping.exe"),
        &["-n", "2", "127.0.0.1"],
        &own_environment(),
        [Stdio::Null, Stdio::Overlapped, Stdio::Null],
    );
    seams::fix_name(None);
    let why = refused.expect_err("the start is refused").to_string();
    assert!(
        why.contains("the server's pipe name was already taken"),
        "{why}"
    );
    assert_eq!(
        job.total_processes().expect("the job's count"),
        0,
        "no process was created, not even one that has ended"
    );
    drop(held);
}

/// The child's side of the next case: it lists the pipe handles this process holds, each as a
/// client or a server end, and is run only by that case.
#[test]
fn the_child_reports_its_pipe_handles() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    let mut lines = String::new();
    for value in (4..(1_usize << 16)).step_by(4) {
        let handle = value as HANDLE;
        // SAFETY: an invalid handle value answers with an unknown type and an error, and no value
        // here is written through.
        #[expect(unsafe_code, reason = "asking about a handle has no safe form")]
        let kind = unsafe { GetFileType(handle) };
        if kind != FILE_TYPE_PIPE {
            continue;
        }
        let mut flags = 0_u32;
        // SAFETY: the handle is a pipe this process holds; the flags are a local, and the other
        // answers are not asked for.
        #[expect(unsafe_code, reason = "asking about a pipe has no safe form")]
        let asked = unsafe {
            GetNamedPipeInfo(
                handle,
                &raw mut flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if asked == 0 {
            // An anonymous pipe: not one of ours.
            lines.push_str(&format!("PIPE {value} other\n"));
            continue;
        }
        let end = if flags & 1 == 0 { "client" } else { "server" };
        lines.push_str(&format!("PIPE {value} {end}\n"));
    }
    // A line of its own, because the harness has written the case's name on the line before.
    print!("\n{lines}");
}

/// KR-REQ-07.45: this worker's ends are private and the agent holds three client ends and no other
/// end of ours. The agent is this same test program, run with the three streams overlapped, and it
/// says which pipe handles it holds.
#[test]
fn the_worker_end_is_private_and_the_child_holds_three_ends() {
    let _alone = alone();
    let runtime = runtime();
    let _enter = runtime.enter();
    let job = AgentJob::create_owning().expect("a job");
    let marker = [(CHILD_MARKER, std::ffi::OsStr::new("1"))];
    let environment = Environment::of_this_process_with(&marker).expect("an environment");
    let me = std::env::current_exe().expect("this program");
    let mut child = overlapped(
        &job,
        &me,
        &[
            "--exact",
            "the_child_reports_its_pipe_handles",
            "--nocapture",
            "--test-threads=1",
        ],
        &environment,
        [Stdio::Overlapped, Stdio::Overlapped, Stdio::Overlapped],
    )
    .expect("the start");
    let ends = [
        child.overlapped_stdin.take().expect("an input end"),
        child.overlapped_stdout.take().expect("an output end"),
        child.overlapped_stderr.take().expect("an error end"),
    ];
    for end in &ends {
        let raw = end.as_raw_handle();
        assert!(
            !inheritable(raw.cast()),
            "this worker's end is not inheritable"
        );
        assert_eq!(
            access_list_entries(raw.cast()),
            1,
            "this worker's end has one entry in its access list"
        );
    }
    let mut output = ends.into_iter().nth(1).expect("the output end");
    let text = runtime.block_on(async {
        let mut text = String::new();
        tokio::time::timeout(PATIENCE, output.read_to_string(&mut text))
            .await
            .expect("the agent ends in time")
            .expect("the output reads to its end");
        text
    });
    let held: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("PIPE "))
        .collect();
    assert_eq!(
        held.len(),
        3,
        "the agent holds its three standard ends and no other pipe: {text}"
    );
    assert!(
        held.iter().all(|line| line.ends_with(" client")),
        "every pipe handle the agent holds is the client end: {text}"
    );
    let _ = child.wait();
}

/// KR-REQ-07.45: the worker's ends are read and written through the runtime, whichever stream.
#[test]
fn the_ends_read_and_write_through_the_runtime() {
    let _alone = alone();
    let runtime = runtime();
    let _enter = runtime.enter();
    let job = AgentJob::create_owning().expect("a job");
    let mut child = overlapped(
        &job,
        &system_program("findstr.exe"),
        &["^"],
        &own_environment(),
        [Stdio::Overlapped, Stdio::Overlapped, Stdio::Overlapped],
    )
    .expect("the start");
    let mut input = child.overlapped_stdin.take().expect("an input end");
    let mut output = child.overlapped_stdout.take().expect("an output end");
    let mut errors = child.overlapped_stderr.take().expect("an error end");
    let (said, nothing) = runtime.block_on(async {
        input
            .write_all(b"hello\r\n")
            .await
            .expect("the input is written");
        input.shutdown().await.expect("the input is closed");
        drop(input);
        let mut said = String::new();
        let mut nothing = String::new();
        tokio::time::timeout(PATIENCE, async {
            output
                .read_to_string(&mut said)
                .await
                .expect("the output reads");
            errors
                .read_to_string(&mut nothing)
                .await
                .expect("the errors read");
        })
        .await
        .expect("the agent ends in time");
        (said, nothing)
    });
    assert_eq!(said, "hello\r\n");
    assert_eq!(nothing, "");
    let _ = child.wait();
}

/// KR-REQ-07.45: where no runtime runs, an overlapped end cannot be made, and the start says so
/// before it creates anything.
#[test]
fn an_overlapped_start_without_a_runtime_is_refused_before_a_process_exists() {
    let _alone = alone();
    let job = AgentJob::create_owning().expect("a job");
    let refused = overlapped(
        &job,
        &system_program("ping.exe"),
        &["-n", "2", "127.0.0.1"],
        &own_environment(),
        [Stdio::Null, Stdio::Overlapped, Stdio::Null],
    );
    let why = refused.expect_err("refused").to_string();
    assert!(why.contains("runtime"), "{why}");
    assert_eq!(
        job.total_processes().expect("the job's count"),
        0,
        "no process was created, not even one that has ended"
    );
}
