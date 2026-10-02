//! The broker's endpoint, registration and credential, run on Windows.
//!
//! A launched agent's bridge reaches the worker on a named pipe that carries its owner's own
//! access list, and the credential it presents is published as a file the host proves is closed to
//! other accounts. Everything here runs a real pipe, real files with real access-control lists and
//! real processes started the way a launch starts them, so it exists only on that platform. What it
//! covers, row by row:
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-11.32, KR-REQ-12.14 | The endpoint a launch binds is a named pipe in the local namespace; the kernel names the process that connects to it; the owner arriving over the network is refused |
//! | KR-REQ-11.43, KR-REQ-05.09 | A bridge the launched application started, presenting the launch's registration and credential, is admitted and named by the kernel; a wrong credential, an environment session identifier alone, a presented identity the kernel did not name, a browser's headers, a process outside every job and a process in another launch's job are each refused |
//! | KR-REQ-11.23, KR-REQ-12.14 | The registration directory and the credential file are read back by their access-control lists, from the opened object: an ordinary directory, a widened one and a link are refused, and so is a credential file another account was granted |
//! | KR-REQ-12.02 | A launch on this platform publishes the registration and the credential and starts the agent in its job, and one into a directory open to another account starts nothing |
//!
//! The pipe's own refusal of another account and of a restricted token is the pipe's list, which
//! `kr-ipc`'s own suite runs against the listener this endpoint binds.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::gateway::NativeFraming;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ApplicationInstanceId, EnvironmentId, LaunchProfileId, PluginId, SessionId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::broker::{
    BoundEndpoint, BridgeSurface, Broker, Framing, InstalledBridge, Launched, ListenerAddress,
    NativeGateway, NativeLaunch,
};
use kr_worker::persistence::JournalHealth;

mod common;

use common::LIVENESS_DEADLINE;

/// The security identifier of the Everyone group, which no list this host trusts may name.
const EVERYONE: &str = "S-1-1-0";

/// The word a helper process is told by its last arguments: what it presents to the endpoint.
const MODES: [&str; 6] = [
    "good",
    "wrong_credential",
    "session_only",
    "other_identity",
    "browser",
    "none",
];

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance(which: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([which; 16]))
}

fn package() -> PluginId {
    PluginId::new("kalareach/claude-code").expect("valid")
}

/// A private directory, made the way the host makes one, and removed by the caller.
fn private_directory() -> PathBuf {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("kr-we-{name}"));
    kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
    directory
}

/// Runs a program and fails when it does.
fn run(program: &str, arguments: &[&std::ffi::OsStr]) {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("{program} starts: {error}"));
    assert!(
        output.status.success(),
        "{program} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Grants an account full control of a path, adding to whatever list it already carries.
///
/// Adding an entry is what every account may do to a thing it owns, so it is reliable across
/// hosts in a way that narrowing a list is not. The grant carries no inheritance flags: the
/// object's own list is what the host reads.
fn grant_full(path: &Path, account: &str) {
    run(
        "icacls.exe",
        &[
            path.as_os_str(),
            "/grant".as_ref(),
            format!("*{account}:F").as_ref(),
        ],
    );
}

fn launch_for(which: u8) -> NativeLaunch {
    NativeLaunch {
        profile_id: LaunchProfileId::new("lp-1").expect("valid"),
        expected_process: None,
        native_terminal: None,
        application_instance_id: instance(which),
        plugin_id: package(),
        installed_protocol_version: "1".to_owned(),
        framing: Framing::new(NativeFraming::JsonLines),
        site: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        os_user: "agent-user".to_owned(),
    }
}

fn this_executable() -> PathBuf {
    std::env::current_exe().expect("this test's executable")
}

/// The profile of an agent that is this test binary running one of its helpers.
fn agent_profile(arguments: &[&str]) -> LaunchProfile {
    LaunchProfile {
        profile_id: LaunchProfileId::new("lp-1").expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        binary: BinaryIdentity {
            resolved_path: this_executable().to_string_lossy().into_owned(),
            digest: Digest256::from_bytes([3; 32]),
            version: "1".to_owned(),
            distribution: "build".to_owned(),
        },
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        authentication: AuthenticationState::Authenticated,
        mode: IntegrationMode::Gateway,
        resolved_at: TimestampMs::new(1),
    }
}

/// An agent this host started, ended with everything in its job when the test ends, however it
/// ends.
struct Launch {
    broker: Arc<Broker>,
    gateway: NativeGateway,
    directory: PathBuf,
    child: Option<std::process::Child>,
    process: ProcessStartIdentity,
}

impl Launch {
    /// Launches an agent that starts one helper presenting `mode`, to the registration of
    /// `towards` where one is given and to its own otherwise.
    fn start(which: u8, mode: &str, towards: Option<&Launch>) -> Self {
        assert!(MODES.contains(&mode));
        let directory = private_directory();
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let installed = InstalledBridge {
            plugin_id: package(),
            application: "claude-code".to_owned(),
            surfaces: [BridgeSurface::Hook].into_iter().collect(),
            forwarder: this_executable(),
        };
        let mut gateway = NativeGateway::bind(Arc::clone(&broker), &directory, launch_for(which))
            .expect("the endpoint binds")
            .with_bridge(installed)
            .expect("the bridge belongs to this connector");
        let registration = towards.map_or_else(
            || "-".to_owned(),
            |other| {
                other
                    .directory
                    .join("registration")
                    .to_string_lossy()
                    .into_owned()
            },
        );
        let intent = broker
            .prepare_launch(
                agent_profile(&[
                    "--ignored",
                    "--exact",
                    "agent_runs_a_helper",
                    "--nocapture",
                    "--test-threads=1",
                    mode,
                    &registration,
                ]),
                kr_worker::broker::ForegroundMark::idle(4),
                None,
            )
            .expect("the launch is prepared");
        let Launched { child, process, .. } = gateway
            .launch(
                &intent,
                &kr_worker::broker::ForegroundMark::idle(4),
                IntegrationMode::Gateway,
                TimestampMs::new(1),
            )
            .expect("the agent is started");
        Self {
            broker,
            gateway,
            directory,
            child: Some(child),
            process,
        }
    }

    /// The processes this launch's job holds.
    fn members(&self) -> Vec<u32> {
        kr_worker::windows::job::agent_job(&self.process)
            .expect("the launch's job is kept")
            .process_ids()
            .expect("the job lists its processes")
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        if let Some(job) = kr_worker::windows::job::agent_job(&self.process) {
            let _ = job.terminate(1);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        kr_worker::windows::job::release_agent(&self.process);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

// ---------------------------------------------------------------------------------------------
// The helper processes: an agent that starts a bridge, and the bridge. They are tests that do
// nothing unless a test above starts them with `--ignored`, so each is a real process of its own.

/// The argument a helper was given at `back` places from the end.
fn argument_from_end(back: usize) -> String {
    let arguments: Vec<String> = std::env::args().collect();
    arguments[arguments.len() - back].clone()
}

/// The agent a launch starts: it starts one bridge helper, which is then its descendant, and stays
/// until the launch's job ends it.
#[test]
#[ignore = "a process the tests below start as the launched agent"]
fn agent_runs_a_helper() {
    let mode = argument_from_end(2);
    let registration = argument_from_end(1);
    if mode != "none" {
        let mut command = std::process::Command::new(this_executable());
        command
            .args([
                "--ignored",
                "--exact",
                "a_bridge_helper",
                "--nocapture",
                "--test-threads=1",
                mode.as_str(),
                registration.as_str(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let _helper = command.spawn().expect("the helper starts");
        std::thread::sleep(Duration::from_secs(600));
    } else {
        std::thread::sleep(Duration::from_secs(600));
    }
}

/// The bridge: it reads the registration a launch published, presents what `mode` says to the
/// endpoint it names, and stays until it is ended.
#[test]
#[ignore = "a process the tests below start as a bridge"]
fn a_bridge_helper() {
    let mode = argument_from_end(2);
    let registration = match argument_from_end(1).as_str() {
        "-" => PathBuf::from(std::env::var_os("KR_REGISTRATION").expect("the launch names one")),
        other => PathBuf::from(other),
    };
    // The launch publishes its files after it starts the agent, so they are waited for as a
    // condition: the registration is written last, whole, and names the credential that is
    // already there.
    let started = std::time::Instant::now();
    let text = loop {
        if let Ok(text) = std::fs::read_to_string(&registration)
            && text.contains("framing=")
        {
            break text;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the registration never appeared"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("the registration names {name}"))
            .to_owned()
    };
    let pipe = field("endpoint");
    let name = pipe
        .strip_prefix(r"\\.\pipe\")
        .expect("a local pipe")
        .to_owned();
    let stored = kr_ipc::paths::read_owner_only_file(Path::new(&field("credential")), 256)
        .expect("the credential file is the owner's")
        .expect("the credential file is there");
    let credential = match mode.as_str() {
        "wrong_credential" => "07".repeat(32),
        "session_only" => String::new(),
        _ => String::from_utf8(stored).expect("hexadecimal"),
    };
    let me = kr_ipc::identity::current_process_start_identity().expect("this process");
    // Another real process's identity, which the operating system reads back as it presents it.
    let presented = match mode.as_str() {
        "other_identity" => {
            let parent = kr_ipc::identity::process_start_identity(
                u32::try_from(field("pid").parse::<u64>().expect("a number")).expect("a pid"),
            )
            .expect("the launched agent");
            parent
        }
        _ => me,
    };
    let headers = if mode == "browser" {
        serde_json::json!({ "origin": "https://example.test" })
    } else {
        serde_json::json!({})
    };
    let hello = serde_json::json!({
        "kr_hello": {
            "credential": credential,
            "pid": presented.pid.get(),
            "start": presented.start_value.get(),
            "session": "KR_SESSION=abc",
            "headers": headers,
            "bridge": { "application": "claude-code", "surface": "hook" },
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let endpoint = kr_ipc::paths::Endpoint::from_name(name).expect("a usable name");
        let mut connection = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("the bridge connects");
        let mut line = hello.to_string().into_bytes();
        line.push(b'\n');
        connection
            .write_all(&line)
            .await
            .expect("the hello is written");
        let mut sink = [0_u8; 1024];
        // Until the worker closes the connection or the launch ends this process.
        while let Ok(read) = connection.read(&mut sink).await {
            if read == 0 {
                break;
            }
        }
    });
    std::thread::sleep(Duration::from_secs(600));
}

// ---------------------------------------------------------------------------------------------
// The endpoint.

/// A named pipe made with the default access list and accepting remote callers, which is what the
/// control of the network test opens over the machine's own file-sharing server.
struct RemoteAcceptingPipe(windows_sys::Win32::Foundation::HANDLE);

impl RemoteAcceptingPipe {
    #[expect(
        unsafe_code,
        reason = "a pipe that accepts remote callers is made by the system call that takes the \
                  flag; no safe wrapper in this repository sets it, and this is a test's control"
    )]
    fn create(name: &str) -> Self {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_ACCEPT_REMOTE_CLIENTS, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };
        let wide: Vec<u16> = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the name is a null-terminated wide buffer that lives for the call, and a null
        // security descriptor asks for the default one, which names the creating account.
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(
            handle, INVALID_HANDLE_VALUE,
            "a pipe that accepts remote callers"
        );
        Self(handle)
    }
}

impl Drop for RemoteAcceptingPipe {
    #[expect(unsafe_code, reason = "the handle this value owns is closed once")]
    fn drop(&mut self) {
        // SAFETY: the handle was created by `create` and nothing else closes it.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// KR-REQ-11.32 and KR-REQ-12.14: the endpoint a launch binds is a named pipe in the local
/// namespace, the registration publishes exactly that path, and the kernel names the process that
/// connects to it: a process of its own, with the start identity the kernel gives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_32_the_endpoint_is_a_local_pipe_and_the_kernel_names_the_process_that_connects()
{
    let directory = private_directory();
    let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
    let address = endpoint.address().clone();
    let ListenerAddress::NamedPipe(name) = address.clone() else {
        panic!("this platform binds a named pipe");
    };
    assert!(address.is_local());
    assert!(
        address.for_diagnostics().starts_with(r"\\.\pipe\kr-a-"),
        "the path the registration publishes is the local namespace's"
    );

    // A process of its own connects: a PowerShell that opens the pipe by its name and waits.
    let mut child = std::process::Command::new(kr_worker::testing::powershell())
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "$client = [System.IO.Pipes.NamedPipeClientStream]::new('.', '{name}', \
                 [System.IO.Pipes.PipeDirection]::InOut); $client.Connect(60000); \
                 Start-Sleep -Seconds 60"
            ),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the client starts");
    let accepted = tokio::time::timeout(LIVENESS_DEADLINE, endpoint.accept())
        .await
        .expect("a connection arrives")
        .expect("it is accepted");
    let named = accepted.peer.process().clone();
    assert!(accepted.peer.is_owner());
    assert_eq!(
        named.pid.get(),
        u64::from(child.id()),
        "the kernel names the connecting process"
    );
    assert_eq!(
        named,
        kr_ipc::identity::process_start_identity(child.id()).expect("the client's identity"),
        "with the start identity the kernel gives it"
    );
    assert_ne!(
        named.pid.get(),
        u64::from(std::process::id()),
        "and it is not the listener"
    );
    let _ = child.kill();
    let _ = child.wait();
    drop(accepted);
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-05.02 and KR-REQ-11.32: the owner arriving over the network is refused. A named pipe can
/// be opened from another machine by name, through the machine's file-sharing server, unless the
/// pipe refuses remote callers, and that is also how its own owner arrives when it names this
/// machine over the network. So the owner tries that path twice: to a pipe made with the default
/// list and accepting remote callers, which shows that the path is open on this machine and that
/// the owner is admitted arriving that way, and to the launch's own pipe, which differs from it in
/// carrying the owner-only list and refusing remote callers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_32_the_owner_arriving_over_the_network_is_refused() {
    let directory = private_directory();
    let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
    let ListenerAddress::NamedPipe(name) = endpoint.address().clone() else {
        panic!("this platform binds a named pipe");
    };
    let control = format!("kr-network-control-{}", kr_ipc::new_uuid());
    let accepting = RemoteAcceptingPipe::create(&control);
    let over_the_network = |name: String| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!(r"\\localhost\pipe\{name}"))
    };
    let path_is_open = tokio::task::spawn_blocking({
        let control = control.clone();
        move || over_the_network(control)
    })
    .await
    .expect("the open finishes");
    if let Err(error) = path_is_open {
        panic!(
            "the owner does not reach a pipe that accepts remote callers over this machine's own \
             file-sharing server, so whether the launch's pipe refuses a network caller was not \
             established: {error}. The Server service has to be running."
        );
    }
    let refused = tokio::task::spawn_blocking(move || over_the_network(name))
        .await
        .expect("the open finishes");
    // An access denial, and not a name that was not found or a pipe that was busy: those would say
    // nothing about whether the pipe refuses a network caller.
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied),
        "the launch's pipe refuses a caller that arrives over the network"
    );
    drop(accepting);
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------------------------
// The launch binding.

/// KR-REQ-11.43, KR-REQ-12.14 and KR-REQ-05.09: a bridge the launched application started, which
/// presents the registration and the credential the launch published, is admitted and named by the
/// kernel: the process that connected is the helper in the launch's job, and the application that
/// started it is the launched agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_a_bridge_the_launch_started_is_admitted_and_named_by_the_kernel() {
    let launch = Launch::start(2, "good", None);
    let admitted = tokio::time::timeout(LIVENESS_DEADLINE, launch.gateway.accept_bridge())
        .await
        .expect("the bridge reaches the endpoint")
        .expect("it is authenticated and admitted");
    let bridge = admitted.process.identity.clone();
    assert!(
        launch
            .members()
            .contains(&u32::try_from(bridge.pid.get()).expect("a pid")),
        "the process the kernel named is one the launch's job holds"
    );
    assert_ne!(
        bridge, launch.process,
        "it is not the launched agent itself"
    );
    assert_eq!(
        admitted.process.starter.as_ref(),
        Some(&launch.process),
        "and the launched agent is the process that started it"
    );
    assert_eq!(
        bridge,
        kr_ipc::identity::process_start_identity(u32::try_from(bridge.pid.get()).expect("a pid"))
            .expect("the helper's identity"),
        "with the identity the kernel gives it"
    );
    drop(admitted);
}

/// KR-REQ-11.43 and KR-REQ-05.09: each of these is refused, and a refusal closes the connection
/// without a word: the private exchange of another launch, an environment session identifier alone,
/// a presented identity the kernel did not name, and what a browser adds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_a_wrong_credential_a_session_identifier_alone_a_presented_identity_the_kernel_did_not_name_and_a_browser_are_each_refused()
 {
    for (what, mode) in [
        ("a credential that is not this launch's", "wrong_credential"),
        (
            "an environment session identifier and no credential",
            "session_only",
        ),
        (
            "an identity the kernel did not name for this connection",
            "other_identity",
        ),
        ("a connection carrying what a browser adds", "browser"),
    ] {
        let launch = Launch::start(2, mode, None);
        let refused = tokio::time::timeout(LIVENESS_DEADLINE, launch.gateway.accept_bridge())
            .await
            .expect("the bridge reaches the endpoint")
            .err()
            .unwrap_or_else(|| panic!("{what} is refused"));
        assert_eq!(
            refused.code(),
            kr_protocol::error::ErrorCode::PermissionDenied,
            "{what}: {refused}"
        );
    }
}

/// KR-REQ-11.43 and KR-REQ-12.14: a process outside every job holds the registration and the
/// credential of a launch, which is what a process of the same account can read, and is refused:
/// the launch binding is the job the launch started in. The control is the test above, where the
/// same helper, started by the launched agent, is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_a_process_outside_every_job_is_refused() {
    let launch = Launch::start(2, "none", None);
    let registration = launch.directory.join("registration");
    let mut outside = std::process::Command::new(this_executable())
        .args([
            "--ignored",
            "--exact",
            "a_bridge_helper",
            "--nocapture",
            "--test-threads=1",
            "good",
            registration.to_str().expect("a path"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the helper starts");
    let refused = tokio::time::timeout(LIVENESS_DEADLINE, launch.gateway.accept_bridge())
        .await
        .expect("the process reaches the endpoint")
        .err()
        .expect("a process outside the job is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        !launch.members().contains(&outside.id()),
        "the job does not hold it"
    );
    let _ = outside.kill();
    let _ = outside.wait();
}

/// KR-REQ-11.43 and KR-REQ-12.14: a process in another launch's job, with this launch's
/// registration and credential, is refused: a job holds one launch's processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_43_a_process_in_another_launchs_job_is_refused() {
    let launch = Launch::start(2, "none", None);
    let other = Launch::start(3, "good", Some(&launch));
    let refused = tokio::time::timeout(LIVENESS_DEADLINE, launch.gateway.accept_bridge())
        .await
        .expect("the process reaches the endpoint")
        .err()
        .expect("a process in another launch's job is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        other.members().len() >= 2,
        "the other launch's job holds the helper that connected"
    );
}

// ---------------------------------------------------------------------------------------------
// The registration and the credential.

/// KR-REQ-11.23 and KR-REQ-12.14: the directory a launch publishes into is read back by its
/// access-control list, from the opened directory: one the host made passes, and an ordinary one,
/// one another account was granted and a link to a good one are refused.
#[test]
fn kr_req_11_23_a_registration_directory_is_checked_by_its_list() {
    let private = private_directory();
    kr_worker::broker::process::check_private_directory(&private)
        .expect("the directory the host made is private");

    let ordinary = std::env::temp_dir().join(format!("kr-we-ordinary-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&ordinary).expect("an ordinary directory");
    assert!(
        kr_worker::broker::process::check_private_directory(&ordinary).is_err(),
        "an ordinary directory carries the profile's own inherited list"
    );

    let widened = private_directory();
    kr_worker::broker::process::check_private_directory(&widened).expect("private first");
    grant_full(&widened, EVERYONE);
    assert!(
        kr_worker::broker::process::check_private_directory(&widened).is_err(),
        "a list another account was granted is refused"
    );

    let link = std::env::temp_dir().join(format!("kr-we-link-{}", kr_ipc::new_uuid()));
    run(
        "cmd.exe",
        &[
            "/d".as_ref(),
            "/c".as_ref(),
            "mklink".as_ref(),
            "/J".as_ref(),
            link.as_os_str(),
            private.as_os_str(),
        ],
    );
    assert!(
        kr_worker::broker::process::check_private_directory(&link).is_err(),
        "a junction to a private directory is not the directory it names"
    );

    let _ = std::fs::remove_dir(&link);
    for directory in [&private, &ordinary, &widened] {
        let _ = std::fs::remove_dir_all(directory);
    }
}

/// KR-REQ-11.23: the credential file the host writes is the owner's, and one another account was
/// granted is refused by the host's own read, which checks the list from the opened file. A second
/// write to the same name is refused, so a file another writer planted is never written into.
#[test]
fn kr_req_11_23_the_credential_file_is_owner_only_and_a_widened_one_is_refused() {
    let directory = private_directory();
    let path = directory.join("credential");
    let launched = kr_worker::broker::ManagedProcess::new(
        instance(2),
        kr_ipc::identity::current_process_start_identity().expect("this process"),
        kr_worker::broker::TransportHandle {
            transport: kr_worker::broker::BrokerTransport::PrivateSocket,
            application_instance_id: instance(2),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: kr_ipc::identity::current_process_start_identity().expect("this process"),
        },
        kr_worker::broker::Credential::generate().expect("a credential"),
        true,
        TimestampMs::new(1),
    );
    launched
        .write_registration(&path)
        .expect("the credential is written");
    let stored = kr_ipc::paths::read_owner_only_file(&path, 256)
        .expect("a file the host wrote is the owner's")
        .expect("it is there");
    assert_eq!(stored.len(), 64, "sixty-four hexadecimal characters");
    assert!(stored.iter().all(u8::is_ascii_hexdigit));
    assert!(
        launched.write_registration(&path).is_err(),
        "a name that is taken is never written into"
    );

    grant_full(&path, EVERYONE);
    assert!(
        kr_ipc::paths::read_owner_only_file(&path, 256).is_err(),
        "a file another account was granted is refused by the host's own read"
    );

    let ordinary = std::env::temp_dir().join(format!("kr-we-ordinary-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&ordinary).expect("an ordinary directory");
    assert!(
        launched
            .write_registration(&ordinary.join("credential"))
            .is_err(),
        "nothing is written into a directory the host cannot show is private"
    );
    assert!(!ordinary.join("credential").exists());
    for directory in [&directory, &ordinary] {
        let _ = std::fs::remove_dir_all(directory);
    }
}

/// KR-REQ-12.02: a launch on this platform publishes the registration and the credential and
/// starts the agent in its job. The registration names the pipe by its path and carries no secret;
/// the credential file is the owner's; the agent is a member of the job the host keeps for it.
#[test]
fn kr_req_12_02_a_launch_publishes_its_files_and_starts_the_agent_in_its_job() {
    let launch = Launch::start(2, "none", None);
    let registration = std::fs::read_to_string(launch.directory.join("registration"))
        .expect("the registration is published");
    assert!(
        registration.contains(&format!(
            "endpoint={}\n",
            launch.gateway.address().for_diagnostics()
        )),
        "it names the pipe by its path: {registration}"
    );
    assert!(registration.contains("pid="));
    assert!(
        registration.contains("credential=") && !registration.contains("0909"),
        "it names the file the private exchange is in and carries none of it"
    );
    let stored = kr_ipc::paths::read_owner_only_file(&launch.directory.join("credential"), 256)
        .expect("the credential file is the owner's")
        .expect("it is there");
    assert_eq!(stored.len(), 64);
    assert!(
        launch
            .members()
            .contains(&u32::try_from(launch.process.pid.get()).expect("a pid")),
        "the agent was started in the job the host keeps for it"
    );
    assert!(
        launch.broker.binding_state(instance(2)).is_ok(),
        "and its instance is registered"
    );
}

/// KR-REQ-12.02: a launch into a directory another account was granted starts nothing. The
/// endpoint was bound while the directory was private, and the launch reads it again before it
/// starts anything.
#[test]
fn kr_req_12_02_a_launch_into_a_directory_open_to_another_account_starts_nothing() {
    let directory = private_directory();
    let broker =
        Arc::new(Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"));
    let mut gateway = NativeGateway::bind(Arc::clone(&broker), &directory, launch_for(2))
        .expect("the endpoint binds");
    let intent = broker
        .prepare_launch(
            agent_profile(&[
                "--ignored",
                "--exact",
                "agent_runs_a_helper",
                "--nocapture",
                "none",
                "-",
            ]),
            kr_worker::broker::ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    grant_full(&directory, EVERYONE);
    let refused = gateway
        .launch(
            &intent,
            &kr_worker::broker::ForegroundMark::idle(4),
            IntegrationMode::Gateway,
            TimestampMs::new(1),
        )
        .expect_err("a directory another account was granted is refused");
    assert!(refused.to_string().contains("not owner-only"), "{refused}");
    assert!(
        gateway.last_started().is_none(),
        "and no process was started only to be stopped"
    );
    assert!(broker.binding_state(instance(2)).is_err());
    let _ = std::fs::remove_dir_all(&directory);
}
