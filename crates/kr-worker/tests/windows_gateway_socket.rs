//! The premise of the gateway's Unix-domain socket on Windows: the real Codex 0.155.1 terminal
//! connects to a socket this host binds, and the kernel names the Codex process that connected.
//!
//! Everything else the Windows gateway does rests on this. The terminal is started the way a person
//! starts it against a remote App Server, `codex --remote unix://<path>`, with no login, on a
//! pseudo-console, and the listener is the one the gateway binds, in a private folder. What is
//! shown is that the WebSocket upgrade request arrives on the socket and that the peer the broker
//! reads from the kernel (the process, its start, and its account) is the Codex process the test
//! started, whose image is `codex.exe`.
//!
//! The case needs the real executable, so it is ignored by default. Name it and run the case:
//!
//! ```text
//! KR_CODEX_EXE=C:\path\to\codex.exe cargo test --locked -p kr-worker --test windows_gateway_socket -- --ignored --nocapture
//! ```
//!
//! It prints the Windows build and the Codex version it ran against, so a run on each guest records
//! both.

#![cfg(windows)]

use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use kr_worker::broker::{BoundEndpoint, ListenerAddress, Stream};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::io::AsyncReadExt as _;

/// The variable that names the Windows `codex.exe` this case runs.
const EXECUTABLE_VARIABLE: &str = "KR_CODEX_EXE";

/// The release the Codex package is qualified against.
const RELEASE: &str = "0.155.1";

/// How long the terminal is given to connect and send its first request.
const CONNECT_WAIT: Duration = Duration::from_secs(60);

/// The real executable this run names.
fn codex() -> PathBuf {
    let path = std::env::var_os(EXECUTABLE_VARIABLE)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("{EXECUTABLE_VARIABLE} names the Windows codex.exe {RELEASE} this case runs")
        });
    assert!(
        path.is_absolute() && path.is_file(),
        "{EXECUTABLE_VARIABLE} names a file by an absolute path: {}",
        path.display()
    );
    path
}

/// What a program the test starts says on its standard output, trimmed.
fn said_by(program: &str, arguments: &[&str]) -> String {
    let output = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("{program} runs: {error}"));
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// KR-REQ-07.45: the real Codex terminal, started with no login against `--remote unix://<path>`,
/// connects to a socket the broker binds in a private folder, the WebSocket upgrade arrives, and the
/// kernel's reading of the peer is the Codex process: its identifier, its account and its image.
#[ignore = "runs the real Codex 0.155.1: set KR_CODEX_EXE to its codex.exe and run with --ignored"]
#[tokio::test(flavor = "multi_thread")]
async fn the_real_codex_terminal_connects_to_a_socket_this_host_binds_and_the_kernel_names_it() {
    let codex = codex();
    let version = said_by(codex.to_str().expect("a text path"), &["--version"]);
    assert!(
        version.contains(RELEASE),
        "this case runs against Codex {RELEASE}: {version}"
    );

    let directory = std::env::temp_dir().join(format!(
        "kr-c-{}",
        kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect::<String>()
    ));
    kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
    let home = directory.join("home");
    std::fs::create_dir(&home).expect("a Codex home with no login");

    let endpoint = BoundEndpoint::bind_named(&directory, "gw.sock").expect("the socket binds");
    let ListenerAddress::PrivateSocket(path) = endpoint.address().clone() else {
        panic!("a named bind on this platform is a socket");
    };

    // The terminal runs on a pseudo-console, as it does in the managed shell.
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("a pseudo-console is opened");
    let mut command = CommandBuilder::new(&codex);
    command.args(["--remote", &format!("unix://{}", path.display())]);
    command.env("CODEX_HOME", &home);
    command.cwd(&directory);
    let mut child = pair
        .slave
        .spawn_command(command)
        .expect("the terminal starts");
    drop(pair.slave);
    let mut output = pair
        .master
        .try_clone_reader()
        .expect("the console's output is read");
    // What the terminal draws is read and dropped, so the console never waits on a reader.
    let draining = tokio::task::spawn_blocking(move || {
        let mut sink = [0_u8; 4096];
        while output.read(&mut sink).is_ok_and(|read| read > 0) {}
    });

    let accepted = tokio::time::timeout(CONNECT_WAIT, endpoint.accept())
        .await
        .expect("the terminal connected within the wait")
        .expect("the connection is accepted and its peer named");
    let started = child.process_id().expect("the terminal has a process");
    assert_eq!(
        accepted.peer.process().pid.get(),
        u64::from(started),
        "the kernel names the terminal's own process"
    );
    assert!(accepted.peer.is_owner(), "its account is this account");
    let facts = kr_ipc::starter::process_facts(started).expect("the process is read");
    assert!(
        facts
            .image
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("codex.exe")),
        "the peer's image is codex.exe: {}",
        facts.image.display()
    );

    let Stream::Uds(mut stream) = accepted.stream else {
        panic!("the accepted stream is a Unix-domain socket's");
    };
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    tokio::time::timeout(CONNECT_WAIT, async {
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).await.expect("the request is read");
            assert!(
                read > 0,
                "the terminal closed before it finished its request"
            );
            head.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .expect("the terminal sent its request within the wait");
    let request = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(request.starts_with("get "), "an upgrade request: {request}");
    assert!(
        request.contains("upgrade: websocket"),
        "a WebSocket upgrade: {request}"
    );

    eprintln!(
        "premise: {} ; {version} ; process {started} ; {}",
        said_by("cmd", &["/c", "ver"]),
        facts.image.display()
    );

    child.kill().expect("the terminal is ended");
    drop(stream);
    drop(pair.master);
    let _ = draining.await;
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&directory);
}
