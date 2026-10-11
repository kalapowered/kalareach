//! The application server a session starts, and how it is ended.
//!
//! The server here is the Codex stand-in, a real program speaking the pinned release's protocol,
//! started the way a session starts one. The ownership record is the real one, so what the ladder
//! ends is what a session would have recorded. Build the stand-in before a package-scoped run
//! (`cargo build -p kr-codex-stand-in`); a run of the workspace builds it first.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-07.60 | a server is started in a group of its own with the presented environment less the two variables that name the launch, in the directory asked, only when the executable is the one the record names; an ending that needs no more than the end of its input, one that needs a terminate, and one that needs force each end the server and what the session recorded below it, a command that outlived a server that died included; the server's error stream is read and only its last part kept |
//! | KR-REQ-07.66 | a process the ladder ends by force is noted as forced, and none that ended when it was asked is |

#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, current_process_start_identity, process_state};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::server::{Ended, MAX_ERROR_BYTES, Owned, Server, ServerSpec};
use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

/// How long a wait for something to happen is given: the first start of a program that was just
/// built or copied can take the system most of a minute.
const LIVENESS: Duration = Duration::from_secs(180);

/// A shell command that ignores terminate and starts a process of its own, which inherits that.
const STUBBORN: &str = r#"["/bin/sh", "-c", "trap '' TERM; sleep 120 & wait"]"#;
const PLAIN: &str = r#"["/bin/sh", "-c", "sleep 120 & wait"]"#;

/// The stand-in as a session would run it: a copy on the internal disk, and what its digest is.
/// The directory is removed when the last test that holds the copy ends.
struct StandIn {
    directory: tempfile::TempDir,
    executable: PathBuf,
    digest: Digest256,
}

fn stand_in() -> Arc<StandIn> {
    static SHARED: Mutex<Weak<StandIn>> = Mutex::new(Weak::new());
    let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(copy) = shared.upgrade() {
        return copy;
    }
    let tests = std::env::current_exe().expect("this test's path");
    let built = tests
        .parent()
        .and_then(Path::parent)
        .expect("the directory the programs are built in")
        .join("codex-stand-in");
    assert!(
        built.is_file(),
        "{} is not built; run `cargo build -p kr-codex-stand-in` first",
        built.display()
    );
    let directory = tempfile::Builder::new()
        .prefix("kr-server-")
        .tempdir()
        .expect("a directory");
    let executable = directory.path().join("codex");
    // Placed and started once where nothing is waited for: the first start of a program at a new
    // path is the one the system checks, and it can take most of a minute.
    let _ = kr_ipc::testing::place_and_start_once(&built, &executable, &["--version"]);
    let digest = Digest256::from_bytes(
        Sha256::digest(std::fs::read(&executable).expect("the copy is read")).into(),
    );
    let copy = Arc::new(StandIn {
        directory,
        executable,
        digest,
    });
    *shared = Arc::downgrade(&copy);
    copy
}

fn presented(variants: &str, command: &str) -> Vec<(OsString, OsString)> {
    [
        ("KR_STAND_IN", variants),
        ("KR_STAND_IN_COMMAND", command),
        ("KR_REGISTRATION", "/not/for/the/server"),
        ("KR_CREDENTIAL", "not-for-the-server"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
    .collect()
}

async fn start(stand_in: &StandIn, variants: &str, command: &str) -> Server {
    let environment = presented(variants, command);
    Server::start(&ServerSpec {
        executable: &stand_in.executable,
        digest: &stand_in.digest,
        arguments: &[
            "app-server".to_owned(),
            "--listen".to_owned(),
            "stdio://".to_owned(),
        ],
        directory: stand_in.directory.path(),
        presented: &environment,
    })
    .await
    .expect("the server starts")
}

/// The session's record of what runs below a server, and what the ladder noted as forced.
struct Record {
    owned: Mutex<OwnedProcesses>,
    forced: Mutex<Vec<ProcessStartIdentity>>,
    /// Every process the record has named below the server, whenever it was asked.
    named: Mutex<Vec<ProcessStartIdentity>>,
}

impl Record {
    fn of(server: &Server) -> Self {
        let mut owned = OwnedProcesses::establish(
            OwnershipBoundary::TerminalGroup {
                group: u32::MAX - 1,
                terminal: None,
            },
            current_process_start_identity().expect("this process"),
        );
        owned.add_backend(server.identity().clone());
        Self {
            owned: Mutex::new(owned),
            forced: Mutex::new(Vec::new()),
            named: Mutex::new(Vec::new()),
        }
    }
}

impl Owned for Record {
    fn below(&self, server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity> {
        let mut owned = self.owned.lock().expect("the record");
        owned.observe();
        let below = owned.below_backend(server);
        let mut named = self.named.lock().expect("the list");
        for process in &below {
            if !named.contains(process) {
                named.push(process.clone());
            }
        }
        below
    }

    fn forced(&self, process: &ProcessStartIdentity) {
        self.owned.lock().expect("the record").note_forced(process);
        self.forced.lock().expect("the list").push(process.clone());
    }

    fn unsignalled(&self, process: &ProcessStartIdentity, why: &str) {
        self.owned
            .lock()
            .expect("the record")
            .note_unestablished(format!("process {} was not signalled: {why}", process.pid));
    }
}

/// A session with the server up to the approval it asks for, which is when its command runs.
struct Session {
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    input: kr_worker::broker::server::Input,
    approval: serde_json::Value,
}

async fn write(session: &mut Session, frame: &serde_json::Value) {
    session
        .input
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("the server reads");
}

async fn read(session: &mut Session) -> serde_json::Value {
    let line = tokio::time::timeout(LIVENESS, session.lines.next_line())
        .await
        .expect("the server writes")
        .expect("it is readable")
        .expect("it has not ended");
    serde_json::from_str(&line).expect("a frame")
}

async fn to_the_approval(server: &Server) -> Session {
    let (output, input) = server.take_pipes().expect("the pipes");
    let mut session = Session {
        lines: BufReader::new(output).lines(),
        input,
        approval: serde_json::Value::Null,
    };
    write(
        &mut session,
        &serde_json::json!({"id":"initialize","method":"initialize","params":{
            "clientInfo":{"name":"test","title":null,"version":"0"},
            "capabilities":{"experimentalApi":true,"requestAttestation":false,"optOutNotificationMethods":null}}}),
    )
    .await;
    assert_eq!(read(&mut session).await["id"], "initialize");
    assert_eq!(
        read(&mut session).await["method"],
        "remoteControl/status/changed"
    );
    write(&mut session, &serde_json::json!({"method":"initialized"})).await;
    write(
        &mut session,
        &serde_json::json!({"id":2,"method":"thread/start","params":{}}),
    )
    .await;
    assert!(read(&mut session).await["result"]["thread"]["id"].is_string());
    assert_eq!(read(&mut session).await["method"], "thread/started");
    write(
        &mut session,
        &serde_json::json!({"id":3,"method":"turn/start","params":{
            "threadId":"thread-1","input":[{"type":"text","text":"go","text_elements":[]}]}}),
    )
    .await;
    assert!(read(&mut session).await["result"]["turn"].is_object());
    assert_eq!(read(&mut session).await["method"], "turn/started");
    session.approval = read(&mut session).await;
    assert_eq!(
        session.approval["method"],
        "item/commandExecution/requestApproval"
    );
    session
}

/// The command the server started, as the record has it: the process whose identifier the server
/// said, read below the server.
async fn command_of(server: &Server, record: &Record) -> ProcessStartIdentity {
    let started = Instant::now();
    loop {
        let said = server.error_tail().lines().find_map(|line| {
            line.strip_prefix("stand-in: started command ")
                .map(str::to_owned)
        });
        if let Some(pid) = said.and_then(|pid| pid.trim().parse::<u64>().ok())
            && let Some(command) = record
                .below(server.identity())
                .into_iter()
                .find(|process| process.pid.get() == pid)
        {
            return command;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the server started no command"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn gone(process: &ProcessStartIdentity) -> bool {
    process_state(process) == ProcessState::Ended
}

/// How long a wait for something that is prompt when the code is right is given.
const PROMPT: Duration = Duration::from_secs(30);

/// Waits until the process is gone, and says whether it went.
async fn goes(process: &ProcessStartIdentity) -> bool {
    let started = Instant::now();
    while !gone(process) {
        if started.elapsed() >= PROMPT {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// Waits until the server's error stream has said `text`, and says whether it did. What the server
/// wrote before it ended is read by a task of its own, which is a moment behind.
async fn says(server: &Server, text: &str) -> bool {
    let started = Instant::now();
    while !server.error_tail().contains(text) {
        if started.elapsed() >= PROMPT {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// A server ends with its input, and its command with it: nothing is forced or left.
#[tokio::test]
async fn kr_req_07_60_a_server_that_ends_with_its_input_leaves_nothing() {
    let stand_in = stand_in();
    let server = start(&stand_in, "", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let command = command_of(&server, &record).await;
    assert!(!gone(&command), "the command runs while the server does");

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Input);
    assert!(retirement.forced.is_empty(), "{:?}", retirement.forced);
    assert!(retirement.survivors.is_empty());
    assert!(gone(server.identity()) && gone(&command));
}

/// A server that ignores the end of its input is asked to terminate, and ends its command itself.
#[tokio::test]
async fn kr_req_07_60_a_server_that_ignores_its_input_ends_when_asked_to_terminate() {
    let stand_in = stand_in();
    let server = start(&stand_in, "ignore-eof", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let command = command_of(&server, &record).await;

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Terminate);
    assert!(retirement.forced.is_empty(), "{:?}", retirement.forced);
    assert!(gone(server.identity()) && gone(&command));
    // The server ended its command itself, which it does only when it is asked to terminate and
    // not hung up on: a hang-up kills it at once, and the ladder's sweep ends the command instead.
    assert!(
        says(&server, "stand-in: ending its commands").await,
        "{}",
        server.error_tail()
    );
}

/// A server that ignores both is ended by force, and so is the command it leaves behind, which
/// ignores a terminate too: both are noted as forced.
#[tokio::test]
async fn kr_req_07_66_a_server_and_a_command_that_ignore_a_terminate_are_ended_by_force() {
    let stand_in = stand_in();
    let server = start(&stand_in, "ignore-eof,ignore-term", STUBBORN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let command = command_of(&server, &record).await;

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Force);
    assert!(retirement.forced.contains(server.identity()));
    assert!(
        retirement.forced.contains(&command),
        "{:?}",
        retirement.forced
    );
    assert!(retirement.survivors.is_empty());
    assert!(gone(server.identity()) && gone(&command));
    assert_eq!(*record.forced.lock().expect("the list"), retirement.forced);
}

/// A server that dies with its command running leaves a command no parent names, and the ladder
/// ends it from what the session recorded while the server ran.
#[tokio::test]
async fn kr_req_07_60_a_command_that_outlives_a_server_that_died_is_ended_by_what_was_recorded() {
    let stand_in = stand_in();
    let server = start(&stand_in, "die-first", STUBBORN).await;
    let record = Record::of(&server);
    let mut session = to_the_approval(&server).await;
    let command = command_of(&server, &record).await;
    // The approval is answered and the server dies.
    let id = session.approval["id"].clone();
    write(
        &mut session,
        &serde_json::json!({"id": id, "result": {"decision": "accept"}}),
    )
    .await;
    let started = Instant::now();
    while !gone(server.identity()) {
        assert!(started.elapsed() < LIVENESS, "the server died");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!gone(&command), "the command outlived the server");

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Already);
    assert!(
        retirement.forced.contains(&command),
        "{:?}",
        retirement.forced
    );
    assert!(retirement.survivors.is_empty());
    assert!(gone(&command));
}

/// A server that writes without end to its error stream is not stopped by it, and only the last of
/// what it wrote is kept.
#[tokio::test]
async fn kr_req_07_60_a_server_that_floods_its_error_stream_goes_on_and_only_its_last_part_is_kept()
{
    let stand_in = stand_in();
    let server = start(&stand_in, "flood-stderr", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    // The lines are numbered. The first is gone once more than the bound has been written after
    // it, and what is left is the end of what was written.
    let started = Instant::now();
    loop {
        let tail = server.error_tail();
        if !tail.contains("stand-in noise 0 ") && tail.len() >= MAX_ERROR_BYTES - 4096 {
            assert!(tail.len() <= MAX_ERROR_BYTES + 4, "{} bytes", tail.len());
            let numbers: Vec<u32> = tail
                .lines()
                .filter_map(|line| line.strip_prefix("stand-in noise "))
                .filter_map(|rest| rest.split(' ').next()?.parse().ok())
                .collect();
            assert!(
                numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
                "what is kept is the end of the stream without a gap: {numbers:?}"
            );
            assert!(numbers[0] > 0, "{numbers:?}");
            break;
        }
        assert!(started.elapsed() < LIVENESS, "the tail never rolled over");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let retirement = server.retire(&record).await;
    assert!(retirement.survivors.is_empty());
}

/// A program is started only when it is the executable the record names, named by an absolute
/// path, with an environment whose names are names.
#[tokio::test]
async fn kr_req_07_60_a_server_is_started_only_as_the_record_names_it() {
    let stand_in = stand_in();
    let directory = stand_in.directory.path();
    let environment = presented("", PLAIN);
    let arguments = [
        "app-server".to_owned(),
        "--listen".to_owned(),
        "stdio://".to_owned(),
    ];
    let wrong = Digest256::from_bytes([1; 32]);
    let refused = Server::start(&ServerSpec {
        executable: &stand_in.executable,
        digest: &wrong,
        arguments: &arguments,
        directory,
        presented: &environment,
    })
    .await
    .expect_err("an executable the record does not name is not started");
    assert!(refused.contains("signed record"), "{refused}");

    let relative = Server::start(&ServerSpec {
        executable: Path::new("codex"),
        digest: &stand_in.digest,
        arguments: &arguments,
        directory,
        presented: &environment,
    })
    .await
    .expect_err("a relative path names two files and is not started");
    assert!(relative.contains("absolute"), "{relative}");

    // A name with an equals sign in it would set another variable than the one it spells.
    let mut forged = presented("", PLAIN);
    forged.push((
        OsString::from("KR_CREDENTIAL=forged"),
        OsString::from("value"),
    ));
    let forged = Server::start(&ServerSpec {
        executable: &stand_in.executable,
        digest: &stand_in.digest,
        arguments: &arguments,
        directory,
        presented: &forged,
    })
    .await
    .expect_err("an environment with a name that is not one is not started");
    assert!(forged.contains("environment"), "{forged}");
}

/// A server is started in a group of its own, in the directory asked, with the presented
/// environment less the two variables of the launch and nothing of the worker's own.
#[tokio::test]
async fn kr_req_07_60_a_server_is_started_as_a_session_runs_it() {
    let stand_in = stand_in();
    let mut environment = presented("report-environment", PLAIN);
    environment.push((OsString::from("VISIBLE"), OsString::from("to-the-server")));
    let arguments = [
        "app-server".to_owned(),
        "--listen".to_owned(),
        "stdio://".to_owned(),
    ];
    let server = Server::start(&ServerSpec {
        executable: &stand_in.executable,
        digest: &stand_in.digest,
        arguments: &arguments,
        directory: stand_in.directory.path(),
        presented: &environment,
    })
    .await
    .expect("the server starts");
    // The stand-in says its directory and each variable it was given, and then that it is done.
    assert!(
        says(&server, "stand-in: environment reported").await,
        "{}",
        server.error_tail()
    );
    let said = server.error_tail();
    assert!(
        said.lines()
            .any(|line| line == "stand-in: variable VISIBLE=to-the-server"),
        "{said}"
    );
    for withheld in ["KR_REGISTRATION", "KR_CREDENTIAL"] {
        assert!(
            !said.contains(&format!("variable {withheld}=")),
            "{withheld} reached the server: {said}"
        );
    }
    assert!(
        !said.contains("variable HOME="),
        "the worker's own environment reached the server: {said}"
    );
    let directory = said
        .lines()
        .find_map(|line| line.strip_prefix("stand-in: directory "))
        .expect("the stand-in said its directory");
    assert_eq!(
        std::fs::canonicalize(directory).expect("the directory"),
        std::fs::canonicalize(stand_in.directory.path()).expect("the directory asked"),
    );

    // The server leads a group of its own.
    let pid = server.identity().pid.get().to_string();
    let group = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid])
        .output()
        .expect("ps runs");
    assert_eq!(String::from_utf8_lossy(&group.stdout).trim(), pid);
    let record = Record::of(&server);
    let retirement = server.retire(&record).await;
    assert!(retirement.survivors.is_empty());
}

/// A server that is dropped without being retired is ended: nothing a holder of its pipes does
/// keeps it.
#[tokio::test]
async fn kr_req_07_60_a_server_that_is_dropped_is_ended() {
    let stand_in = stand_in();
    let server = start(&stand_in, "ignore-eof,ignore-term", PLAIN).await;
    let identity = server.identity().clone();
    // Another holder of the pipes, which the guard must not wait for.
    let pipes = server.take_pipes();
    assert!(!gone(&identity));
    drop(server);
    let ended = goes(&identity).await;
    // Whatever the guard did, nothing is left running by this test.
    let _ = kr_ipc::identity::stop_process(&identity, kr_ipc::identity::Stop::Kill);
    drop(pipes);
    assert!(ended, "the server outlived its guard");
}

/// A server that starts a command whenever it is told to end, and does not end, leaves commands
/// that appeared after the first look at the record: each is recorded by a look just before the
/// server is ended, and ended with it.
#[tokio::test]
async fn kr_req_07_60_a_command_started_while_the_server_is_being_ended_is_ended_too() {
    let stand_in = stand_in();
    let server = start(&stand_in, "ignore-eof,ignore-term,spawn-late", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let _first = command_of(&server, &record).await;

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Force);
    assert!(retirement.survivors.is_empty(), "{retirement:?}");
    // The command of the turn, one for the end of the input and one for the terminate: each was
    // recorded, and each is gone.
    let started: Vec<u64> = server
        .error_tail()
        .lines()
        .filter_map(|line| line.strip_prefix("stand-in: started command "))
        .filter_map(|pid| pid.trim().parse().ok())
        .collect();
    assert_eq!(started.len(), 3, "{}", server.error_tail());
    let named = record.named.lock().expect("the list").clone();
    for pid in started {
        let recorded = named
            .iter()
            .find(|process| process.pid.get() == pid)
            .unwrap_or_else(|| panic!("command {pid} was never recorded: {named:?}"));
        assert!(gone(recorded), "command {pid} is still running");
    }
}

/// A write that waits on a server that reads nothing is not left waiting when the input is closed.
#[tokio::test]
async fn kr_req_07_60_a_write_that_waits_on_the_servers_input_ends_when_the_input_is_closed() {
    use tokio::io::AsyncWriteExt as _;

    // A server that never reads its input: the pipe fills and a write waits.
    let sleep = Path::new("/bin/sleep");
    let digest = Digest256::from_bytes(Sha256::digest(std::fs::read(sleep).expect("sleep")).into());
    let environment = presented("", PLAIN);
    let server = Server::start(&ServerSpec {
        executable: sleep,
        digest: &digest,
        arguments: &["300".to_owned()],
        directory: Path::new("/"),
        presented: &environment,
    })
    .await
    .expect("sleep starts");
    let (_output, input) = server.take_pipes().expect("the pipes");
    let mut writer = input.clone();
    let mut closer = input;
    let (parked, waiting) = tokio::sync::oneshot::channel();
    let writing = tokio::spawn(async move {
        use std::pin::Pin;
        use std::task::Poll;
        use tokio::io::AsyncWrite as _;
        let block = vec![b'x'; 1 << 20];
        let mut sent = 0;
        let mut parked = Some(parked);
        // Written until the pipe is full, and then it is said that the write waits.
        std::future::poll_fn(|cx| {
            loop {
                match Pin::new(&mut writer).poll_write(cx, &block[sent..]) {
                    Poll::Ready(Ok(count)) => {
                        sent += count;
                        if sent == block.len() {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        if let Some(parked) = parked.take() {
                            let _ = parked.send(());
                        }
                        return Poll::Pending;
                    }
                }
            }
        })
        .await
    });
    tokio::time::timeout(PROMPT, waiting)
        .await
        .expect("the write reached a full pipe")
        .expect("the write said so");
    // The close is another holder's.
    closer.shutdown().await.expect("the input closes");
    let ended = tokio::time::timeout(PROMPT, writing)
        .await
        .expect("the waiting write was woken")
        .expect("the task ends");
    assert!(ended.is_err(), "the write failed as the input was closed");
}
