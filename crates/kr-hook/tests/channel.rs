//! Claude Code's Channels server through the forwarder and the worker's own listener.
//!
//! The worker's gateway launches a stand-in application (a shell: `/bin/sh` on Unix and a copy of
//! `cmd.exe` on Windows), which starts `kr-hook claude-code
//! channel` over its own standard input and output, as Claude Code starts a channel server. This
//! test speaks MCP to it as Claude Code does, and speaks the private exchange to it as the worker
//! does, through the connection the worker admitted.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | every case: the channel registration's own invocation, admitted by the worker |
//! | KR-REQ-12.18 | `kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else` |
//! | KR-REQ-11.34 | `kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else`: core code alone carries the frames, beside the unchanged terminal |

mod common;

use std::io::{BufRead as _, Write as _};
use std::sync::mpsc::Receiver;

use common::launched::{self, Launch};
use common::{LIVENESS, Placed};
use kr_worker::broker::{AdmittedBridge, BridgeSurface};

/// What the channel writes to Claude Code, one JSON document per line, as it arrives.
fn read_lines(launch: &mut Launch) -> Receiver<serde_json::Value> {
    let stdout = launch
        .application
        .stdout
        .take()
        .expect("the channel writes to the application's output");
    let (lines, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let value = serde_json::from_str(&line).expect("each line is JSON");
            if lines.send(value).is_err() {
                break;
            }
        }
    });
    receiver
}

fn next(lines: &Receiver<serde_json::Value>) -> serde_json::Value {
    lines
        .recv_timeout(LIVENESS)
        .expect("the channel wrote to Claude Code")
}

/// Writes one MCP message to the channel, as Claude Code does.
fn to_channel(launch: &mut Launch, message: &serde_json::Value) {
    let input = launch
        .requests
        .as_mut()
        .expect("the channel's input is open");
    writeln!(input, "{message}").expect("written");
    input.flush().expect("and it goes");
}

async fn from_worker(admitted: &mut AdmittedBridge, frame: &serde_json::Value) {
    admitted
        .stream
        .write_frame(frame.to_string().as_bytes())
        .await
        .expect("the worker writes to the channel");
}

async fn to_worker(admitted: &mut AdmittedBridge) -> Option<serde_json::Value> {
    tokio::time::timeout(LIVENESS, admitted.stream.read_frame())
        .await
        .expect("the channel wrote to the worker, or closed")
        .expect("a whole frame")
        .map(|body| serde_json::from_slice(&body).expect("the frame is JSON"))
}

fn installed(placed: &Placed, surfaces: &[BridgeSurface]) -> kr_worker::broker::InstalledBridge {
    launched::installed(&placed.forwarder, surfaces)
}

/// The code the channel ended with, which the application ends with too.
fn exit_code(launch: &Launch) -> Option<i32> {
    let code = launch.application.exit_code();
    assert!(code.is_some(), "the channel ended");
    code
}

fn permission_request(request_id: &str, input_preview: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel/permission_request",
        "params": {
            "request_id": request_id,
            "tool_name": "Bash",
            "description": "Run shell command",
            "input_preview": input_preview,
            "added_by_a_later_release": true,
        },
    })
}

fn verdict(request_id: &str, behavior: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel/permission",
        "params": {"request_id": request_id, "behavior": behavior},
    })
}

fn message(content: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel",
        "params": {"content": content, "meta": {"chat_id": "1"}},
    })
}

/// KR-REQ-12.18, KR-REQ-11.34, KR-REQ-11.42: the channel is admitted by the worker, completes
/// Claude Code's handshake declaring the Channels pair at a revision Claude Code registers a
/// channel over, and then carries frames both ways as JSON lines up to the exchange's one-MiB
/// bound: a message into the session, a relayed approval out with its correlation at
/// `params.request_id`, and the verdict back. What fails its check is not forwarded and never
/// becomes a message: a verdict for a request this channel did not relay, a second verdict, a
/// malformed one, a message with an undocumented member and an unknown method. An approval past the
/// bound is left to the terminal. When Claude Code closes its end, the channel exits 0 and the
/// worker reads the end of the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else() {
    let placed = Placed::new();
    let mut launch = Launch::channel(
        &placed,
        installed(&placed, &[BridgeSurface::Hook, BridgeSurface::Channel]),
    );
    let lines = read_lines(&mut launch);
    let mut admitted = launch.accept().await.expect("the channel is admitted");
    assert_eq!(admitted.surface, BridgeSurface::Channel);

    to_channel(
        &mut launch,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "claude-code", "version": "2.1.278"},
            },
        }),
    );
    let answer = next(&lines);
    assert_eq!(answer["id"], 0);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        answer["result"]["capabilities"]["experimental"],
        serde_json::json!({"claude/channel": {}, "claude/channel/permission": {}})
    );
    assert!(
        answer["result"]["capabilities"]["tools"].is_null(),
        "no tools"
    );
    assert!(
        answer["result"]["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("<channel source=\"kalareach\">")),
        "{answer}"
    );
    to_channel(
        &mut launch,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // A message into the session.
    from_worker(&mut admitted, &message("build failed on main")).await;
    assert_eq!(next(&lines), message("build failed on main"));

    // A tool approval out, with only the four documented fields.
    to_channel(
        &mut launch,
        &permission_request("abcde", "{\"command\":\"ls\"}"),
    );
    assert_eq!(
        to_worker(&mut admitted).await,
        Some(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/claude/channel/permission_request",
            "params": {
                "request_id": "abcde",
                "tool_name": "Bash",
                "description": "Run shell command",
                "input_preview": "{\"command\":\"ls\"}",
            },
        }))
    );
    // A malformed verdict first: it goes nowhere and leaves the request answerable.
    from_worker(&mut admitted, &verdict("abcde", "yes abcde")).await;
    // The verdict back, correlated by the identifier.
    from_worker(&mut admitted, &verdict("abcde", "allow")).await;
    assert_eq!(next(&lines), verdict("abcde", "allow"));

    // None of these is forwarded, and none becomes a message.
    for refused in [
        verdict("zzzzz", "allow"),
        verdict("abcde", "deny"),
        serde_json::json!({"method": "notifications/claude/channel",
            "params": {"content": "x", "meta": {"chat-id": "1"}}}),
        serde_json::json!({"method": "notifications/claude/channel",
            "params": {"content": "x", "reply_to": "someone"}}),
        serde_json::json!({"method": "tools/call", "id": 7, "params": {"name": "reply"}}),
    ] {
        from_worker(&mut admitted, &refused).await;
    }
    from_worker(&mut admitted, &message("after the refusals")).await;
    assert_eq!(
        next(&lines),
        message("after the refusals"),
        "the next thing Claude Code reads is the next valid frame"
    );

    // A message close to the exchange's bound still goes whole.
    let large = "m".repeat(1_048_000);
    from_worker(&mut admitted, &message(&large)).await;
    let delivered = next(&lines);
    assert_eq!(
        delivered["params"]["content"].as_str().map(str::len),
        Some(large.len())
    );

    // An approval past the bound is not relayed; the next one is.
    to_channel(
        &mut launch,
        &permission_request("bcdef", &"p".repeat(1_100_000)),
    );
    to_channel(&mut launch, &permission_request("cdefg", "{}"));
    assert_eq!(
        to_worker(&mut admitted).await.expect("a frame")["params"]["request_id"],
        "cdefg"
    );

    // Claude Code closes its end.
    launch.close_input();
    assert_eq!(exit_code(&launch), Some(0));
    assert_eq!(
        to_worker(&mut admitted).await,
        None,
        "the worker reads the end of the channel"
    );
}

/// KR-REQ-12.18: when the worker ends the channel, the channel ends its MCP session and exits
/// with a failure that says why, so Claude Code shows the server as gone rather than as a channel
/// nothing will ever reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_a_channel_the_worker_ends_ends_its_session() {
    let placed = Placed::new();
    let mut launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Channel]));
    let lines = read_lines(&mut launch);
    let admitted = launch.accept().await.expect("the channel is admitted");
    to_channel(
        &mut launch,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "claude-code", "version": "2.1.278"}},
        }),
    );
    assert_eq!(next(&lines)["id"], 0);
    to_channel(
        &mut launch,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    drop(admitted);
    assert_eq!(
        exit_code(&launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE))
    );
}

/// Waits, within the liveness bound, until the process `identity` names has ended.
async fn gone(identity: &kr_protocol::identity::ProcessStartIdentity, what: &str) {
    use kr_ipc::identity::{ProcessState, process_state};

    let deadline = std::time::Instant::now() + LIVENESS;
    while process_state(identity) != ProcessState::Ended {
        assert!(
            std::time::Instant::now() < deadline,
            "{what} is still running: {identity:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A launch ends every process it started when it goes, the channel the application started
/// included, while the case that made it still holds the channel's input and the worker's end of
/// its connection, as a case that stops early does: nothing is left for the channel to notice on
/// its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_that_goes_ends_the_channel_it_started() {
    use kr_ipc::identity::process_start_identity;

    let placed = Placed::new();
    let mut launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Channel]));
    let admitted = launch.accept().await.expect("the channel is admitted");
    let channel = admitted.process.identity.clone();
    let application =
        process_start_identity(launch.application.id()).expect("the application is running");
    let input = launch.requests.take();
    // The control of the check `a_launch_that_goes_at_once_leaves_nothing_it_started` makes on
    // Windows: while the channel runs, the system's list of the processes that run this forwarder
    // names it.
    #[cfg(windows)]
    assert!(
        running_forwarders(&placed.forwarder)
            .contains(&u32::try_from(channel.pid.get()).expect("a process identifier")),
        "the check finds the channel while it runs"
    );

    drop(launch);
    gone(&application, "the application").await;
    gone(&channel, "the channel the application started").await;
    drop((input, admitted));
}

/// Ends the application of a launch from outside the launch, as a person or another program may,
/// and waits until it has ended.
///
/// It has ended once it is waiting to be collected, which only its launch does.
#[cfg(unix)]
async fn end_from_outside(application: &kr_protocol::identity::ProcessStartIdentity, pid: u32) {
    let pid = pid.to_string();
    let _ = application;
    let ended = std::process::Command::new("kill")
        .args(["-KILL", &pid])
        .status()
        .expect("kill runs");
    assert!(ended.success(), "the application is ended from outside");
    let deadline = std::time::Instant::now() + LIVENESS;
    loop {
        let listed = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .expect("ps runs");
        if String::from_utf8_lossy(&listed.stdout)
            .trim_start()
            .starts_with('Z')
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the application ended from outside"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Ends the application of a launch from outside the launch, as a person or another program may,
/// and waits until it has ended.
#[cfg(windows)]
async fn end_from_outside(application: &kr_protocol::identity::ProcessStartIdentity, pid: u32) {
    use kr_ipc::identity::{ProcessState, process_state};

    let ended = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output()
        .expect("taskkill runs");
    assert!(
        ended.status.success(),
        "the application is ended from outside: {}",
        String::from_utf8_lossy(&ended.stdout)
    );
    let deadline = std::time::Instant::now() + LIVENESS;
    while process_state(application) != ProcessState::Ended {
        assert!(
            std::time::Instant::now() < deadline,
            "the application ended from outside"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A launch whose application was ended from outside before the launch went, leaving the channel
/// it started to another parent, still ends that channel when it goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_ends_its_channel_after_its_application_was_ended_from_outside() {
    use kr_ipc::identity::{ProcessState, process_start_identity, process_state};

    let placed = Placed::new();
    let mut launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Channel]));
    let admitted = launch.accept().await.expect("the channel is admitted");
    let channel = admitted.process.identity.clone();
    let application =
        process_start_identity(launch.application.id()).expect("the application is running");
    let input = launch.requests.take();

    end_from_outside(&application, launch.application.id()).await;
    assert_eq!(
        process_state(&channel),
        ProcessState::Running,
        "the channel outlives the application it was started by"
    );

    drop(launch);
    gone(&application, "the application").await;
    gone(&channel, "the channel the ended application started").await;
    drop((input, admitted));
}

/// Waits, within the liveness bound, until no process of the application's group runs and none
/// runs the forwarder `forwarder` names.
///
/// What `pgrep` found: it says no process matched with its status, and anything else it says
/// fails the case rather than reading as nothing left.
#[cfg(unix)]
async fn nothing_left(application: u32, forwarder: &std::path::Path) {
    let group = application.to_string();
    let forwarder = forwarder.to_string_lossy().into_owned();
    let listed = |arguments: [&str; 2]| {
        let listed = std::process::Command::new("pgrep")
            .args(arguments)
            .output()
            .expect("pgrep runs");
        match listed.status.code() {
            Some(0) => String::from_utf8_lossy(&listed.stdout).trim().to_owned(),
            Some(1) => String::new(),
            _ => panic!(
                "pgrep {arguments:?} failed ({}): {}",
                listed.status,
                String::from_utf8_lossy(&listed.stderr)
            ),
        }
    };
    let deadline = std::time::Instant::now() + LIVENESS;
    loop {
        let in_group = listed(["-g", &group]);
        let forwarding = listed(["-f", &forwarder]);
        if in_group.is_empty() && forwarding.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "left in the application's group {group}: [{in_group}]; running the forwarder: \
             [{forwarding}]"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// The processes that run the forwarder `forwarder` names, as the system lists them by the file each
/// runs.
///
/// Both paths are made full by the file system before they are compared, so a temporary directory's
/// short names and the case of a name decide nothing.
#[cfg(windows)]
fn running_forwarders(forwarder: &std::path::Path) -> Vec<u32> {
    let full = std::fs::canonicalize(forwarder).expect("the forwarder's full path");
    let listed = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Process -Name kr-hook -ErrorAction SilentlyContinue | \
             ForEach-Object { \"$($_.Id)`t$($_.Path)\" }; exit 0",
        ])
        .output()
        .expect("powershell runs");
    assert!(
        listed.status.success(),
        "the processes are listed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(_, path)| std::fs::canonicalize(path.trim()).is_ok_and(|path| path == full))
        .map(|(id, _)| id.trim().parse().expect("a process identifier"))
        .collect()
}

/// Waits, within the liveness bound, until no process runs the forwarder `forwarder` names.
///
/// A launch on Windows holds what it starts in a job, which its launch has ended and found empty
/// when it goes; the processes that run this copy of the forwarder are asked the system for
/// besides, by the file each runs, so a process the job did not hold would be found.
#[cfg(windows)]
async fn nothing_left(_application: u32, forwarder: &std::path::Path) {
    let deadline = std::time::Instant::now() + LIVENESS;
    loop {
        let running = running_forwarders(forwarder);
        if running.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "running the forwarder: {running:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A launch that goes as soon as it has started, before or after its application has started the
/// channel, leaves nothing it started: no process is left in the application's group, and none
/// runs the forwarder this case placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_that_goes_at_once_leaves_nothing_it_started() {
    let placed = Placed::new();
    let launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Channel]));
    let application = launch.application.id();

    drop(launch);
    nothing_left(application, &placed.forwarder).await;
}

/// KR-REQ-05.09, KR-REQ-11.43: a channel the installation did not register is refused before
/// Claude Code's handshake is answered, and the forwarder exits with a failure rather than serving
/// a channel nothing stands behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_05_09_a_channel_the_installation_does_not_have_is_refused() {
    let placed = Placed::new();
    let launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Hook]));
    let refused = launch
        .accept()
        .await
        .expect_err("a registration the installation does not have is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        refused.to_string().contains("channel registration"),
        "{refused}"
    );
    assert_eq!(
        exit_code(&launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE))
    );
}

/// A channel whose standard error is a named pipe this test holds, launched and admitted, with
/// Claude Code's handshake done.
///
/// The pipe is a FIFO, which only Unix has; the hook's own case of a standard error nobody reads,
/// which runs on both platforms, is `neutral_answer`'s.
///
/// The launch runs the channel through a script of this test's own, which points standard error at
/// the pipe and then becomes the installed forwarder, so the process the worker admits is the
/// forwarder, started by the application, as it is in every other case here.
#[cfg(unix)]
struct Diagnosed {
    launch: Launch,
    lines: Receiver<serde_json::Value>,
    admitted: AdmittedBridge,
    /// The pipe's reading end, which a test reads or leaves unread.
    diagnostics: std::fs::File,
    /// A writing end of this test's own, which keeps the pipe from ending before the test is done.
    held: std::fs::File,
    _script: Placed,
    _placed: Placed,
}

#[cfg(unix)]
impl Diagnosed {
    /// Starts a channel whose standard error is a pipe, full before the channel starts when `full`
    /// says so, and empty otherwise.
    async fn start(full: bool) -> Self {
        use rustix::fs::{Mode, OFlags};

        let placed = Placed::new();
        let pipe = placed.host.root().join("diagnostics");
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "the named pipe is made: {made}");
        // The reading end first, without waiting for a writer; then the test's own writing end,
        // which a reader being there lets open at once.
        let diagnostics = std::fs::File::from(
            rustix::fs::open(
                &pipe,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("the pipe's reading end"),
        );
        rustix::io::ioctl_fionbio(&diagnostics, false).expect("a reading end that waits");
        let held = std::fs::File::from(
            rustix::fs::open(&pipe, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
                .expect("a writing end of the test's own"),
        );
        if full {
            fill(&held);
        }

        // Written aside and placed by a process of its own, as a program this process starts is.
        let text = placed.host.root().join("channel.text");
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\nexec 2>'{}'\nexec '{}' \"$@\"\n",
                pipe.display(),
                placed.forwarder.display()
            ),
        )
        .expect("the script");
        let script = Placed::beside(
            kr_ipc::testing::TempHost::create(),
            placed.host.root().join("bin").join("channel"),
        );
        kr_ipc::testing::place_program(&text, &script.forwarder);

        let mut launch = Launch::channel(&script, installed(&placed, &[BridgeSurface::Channel]));
        let lines = read_lines(&mut launch);
        let admitted = launch.accept().await.expect("the channel is admitted");
        to_channel(
            &mut launch,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "claude-code", "version": "2.1.278"}},
            }),
        );
        assert_eq!(next(&lines)["id"], 0);
        to_channel(
            &mut launch,
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        Self {
            launch,
            lines,
            admitted,
            diagnostics,
            held,
            _script: script,
            _placed: placed,
        }
    }
}

/// A frame the channel refuses, which names `index`, so the report of it can be told apart.
#[cfg(unix)]
fn refused(index: usize) -> serde_json::Value {
    serde_json::json!({"method": format!("notifications/unknown/{index}"), "params": {}})
}

/// Fills a pipe until it takes nothing more, and leaves its writing end waiting again.
#[cfg(unix)]
fn fill(pipe: &std::fs::File) {
    rustix::io::ioctl_fionbio(pipe, true).expect("a pipe that says when it is full");
    let mut writer = pipe;
    // Whole pages first, then single bytes, so no room is left that one short line could take.
    for size in [4096_usize, 1] {
        let bytes = vec![b'.'; size];
        loop {
            match writer.write(&bytes) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("the pipe could not be filled: {error}"),
            }
        }
    }
    rustix::io::ioctl_fionbio(pipe, false).expect("the pipe waits again");
}

/// KR-REQ-12.18: a standard error nobody reads cannot stop the channel. With standard error a pipe
/// that is full before the channel starts and is never read, the worker sends more refused frames
/// than any queue of reports could hold, and then a message: the message reaches Claude Code, and
/// the channel still ends, with its failure, when the worker closes it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_a_standard_error_nobody_reads_cannot_stop_the_channel() {
    /// More refusals than any bounded queue of reports this channel keeps.
    const REFUSALS: usize = 1_000;

    let Diagnosed {
        launch,
        lines,
        mut admitted,
        diagnostics,
        held,
        _script,
        _placed,
    } = Diagnosed::start(true).await;
    let sending = tokio::spawn(async move {
        for index in 0..REFUSALS {
            from_worker(&mut admitted, &refused(index)).await;
        }
        from_worker(&mut admitted, &message("after the refusals")).await;
        admitted
    });
    let arrived = lines.recv_timeout(LIVENESS);
    assert_eq!(
        arrived.ok(),
        Some(message("after the refusals")),
        "the message reaches Claude Code while nobody reads standard error"
    );
    let admitted = sending.await.expect("the worker's frames were all read");
    drop(admitted);
    assert_eq!(
        exit_code(&launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE)),
        "the channel ends when the worker closes it"
    );
    drop(held);
    drop(diagnostics);
}

/// KR-REQ-12.18, the control: while standard error is read, every refusal is reported, one line
/// each, in the order the frames came, and the message after them still reaches Claude Code.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_every_refusal_is_reported_in_order_while_standard_error_is_read() {
    /// Fewer refusals than a queue of reports holds, so none can be dropped however slowly the
    /// reports are written.
    const REFUSALS: usize = 16;

    let Diagnosed {
        launch,
        lines,
        mut admitted,
        diagnostics,
        held,
        _script,
        _placed,
    } = Diagnosed::start(false).await;
    let reading = std::thread::spawn(move || {
        let mut said = String::new();
        let mut diagnostics = diagnostics;
        let _ = std::io::Read::read_to_string(&mut diagnostics, &mut said);
        said
    });
    for index in 0..REFUSALS {
        from_worker(&mut admitted, &refused(index)).await;
    }
    from_worker(&mut admitted, &message("after the refusals")).await;
    assert_eq!(next(&lines), message("after the refusals"));
    drop(admitted);
    assert_eq!(
        exit_code(&launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE))
    );
    // The channel has ended, so once this test's own writing end goes, the pipe ends.
    drop(held);
    let said = reading.join().expect("the diagnostics are read");
    let reported: Vec<&str> = said
        .lines()
        .filter(|line| line.contains("not forwarded"))
        .collect();
    assert_eq!(reported.len(), REFUSALS, "{said}");
    for (index, line) in reported.iter().enumerate() {
        assert!(
            line.starts_with("kr-hook: ")
                && line.contains(&format!("\"notifications/unknown/{index}\"")),
            "refusal {index} in its place: {said}"
        );
    }
}
