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
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, current_process_start_identity, process_state};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::server::{Ended, MAX_ERROR_BYTES, Owned, Server, ServerSpec};
use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

/// How long a wait for something to happen is given: the first start of a program that was just
/// built or copied can take the system most of a minute.
const LIVENESS: Duration = Duration::from_secs(180);

/// A shell command that ignores terminate and starts a process of its own, which inherits that.
const STUBBORN: &str = r#"["/bin/sh", "-c", "trap '' TERM; sleep 120 & wait"]"#;
const PLAIN: &str = r#"["/bin/sh", "-c", "sleep 120 & wait"]"#;

/// The stand-in as a session would run it: a copy on the internal disk, and what its digest is.
fn stand_in() -> &'static (PathBuf, Digest256) {
    static COPY: OnceLock<(PathBuf, Digest256)> = OnceLock::new();
    COPY.get_or_init(|| {
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
        let directory = std::env::temp_dir().join(format!("kr-server-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let copy = directory.join("codex");
        std::fs::copy(&built, &copy).expect("the program is copied");
        let digest = Digest256::from_bytes(
            Sha256::digest(std::fs::read(&copy).expect("the copy is read")).into(),
        );
        (copy, digest)
    })
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

fn work_directory() -> PathBuf {
    let (copy, _) = stand_in();
    copy.parent().expect("a directory").to_path_buf()
}

async fn start(variants: &str, command: &str) -> Server {
    let (copy, digest) = stand_in();
    let environment = presented(variants, command);
    Server::start(&ServerSpec {
        executable: copy,
        digest,
        arguments: &[
            "app-server".to_owned(),
            "--listen".to_owned(),
            "stdio://".to_owned(),
        ],
        directory: &work_directory(),
        presented: &environment,
    })
    .await
    .expect("the server starts")
}

/// The session's record of what runs below a server, and what the ladder noted as forced.
struct Record {
    owned: Mutex<OwnedProcesses>,
    forced: Mutex<Vec<ProcessStartIdentity>>,
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
        }
    }
}

impl Owned for Record {
    fn below(&self, server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity> {
        let mut owned = self.owned.lock().expect("the record");
        owned.observe();
        owned.below_backend(server)
    }

    fn forced(&self, process: &ProcessStartIdentity) {
        self.owned.lock().expect("the record").note_forced(process);
        self.forced.lock().expect("the list").push(process.clone());
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

/// A server ends with its input, and its command with it: nothing is forced or left.
#[tokio::test]
async fn kr_req_07_60_a_server_that_ends_with_its_input_leaves_nothing() {
    let server = start("", PLAIN).await;
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
    let server = start("ignore-eof", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let command = command_of(&server, &record).await;

    let retirement = server.retire(&record).await;
    assert_eq!(retirement.ended, Ended::Terminate);
    assert!(retirement.forced.is_empty(), "{:?}", retirement.forced);
    assert!(gone(server.identity()) && gone(&command));
}

/// A server that ignores both is ended by force, and so is the command it leaves behind, which
/// ignores a terminate too: both are noted as forced.
#[tokio::test]
async fn kr_req_07_66_a_server_and_a_command_that_ignore_a_terminate_are_ended_by_force() {
    let server = start("ignore-eof,ignore-term", STUBBORN).await;
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
    let server = start("die-first", STUBBORN).await;
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
    let server = start("flood-stderr", PLAIN).await;
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let started = Instant::now();
    loop {
        let tail = server.error_tail();
        if tail.len() >= MAX_ERROR_BYTES - 4096 {
            assert!(tail.len() <= MAX_ERROR_BYTES + 4, "{} bytes", tail.len());
            assert!(tail.contains("stand-in noise"));
            break;
        }
        assert!(started.elapsed() < LIVENESS, "the tail never filled");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let retirement = server.retire(&record).await;
    assert!(retirement.survivors.is_empty());
}

/// A program is started only when it is the executable the record names, in a group of its own,
/// with the presented environment less the two variables of the launch, in the directory asked.
#[tokio::test]
async fn kr_req_07_60_a_server_is_started_only_as_the_record_names_it_and_as_a_session_runs_it() {
    let (copy, _) = stand_in();
    let directory = work_directory();
    let environment = presented("", PLAIN);
    let arguments = [
        "app-server".to_owned(),
        "--listen".to_owned(),
        "stdio://".to_owned(),
    ];
    let wrong = Digest256::from_bytes([1; 32]);
    let refused = Server::start(&ServerSpec {
        executable: copy,
        digest: &wrong,
        arguments: &arguments,
        directory: &directory,
        presented: &environment,
    })
    .await
    .expect_err("an executable the record does not name is not started");
    assert!(refused.contains("signed record"), "{refused}");

    // The environment and the directory are read from a program that prints them.
    let env = Path::new("/usr/bin/env");
    let env_digest = Digest256::from_bytes(Sha256::digest(std::fs::read(env).expect("env")).into());
    let mut with = presented("", PLAIN);
    with.push((OsString::from("VISIBLE"), OsString::from("to-the-server")));
    let printer = Server::start(&ServerSpec {
        executable: env,
        digest: &env_digest,
        arguments: &[],
        directory: &directory,
        presented: &with,
    })
    .await
    .expect("env starts");
    let (mut output, _input) = printer.take_pipes().expect("the pipes");
    let mut printed = String::new();
    tokio::time::timeout(LIVENESS, output.read_to_string(&mut printed))
        .await
        .expect("env ends")
        .expect("it is readable");
    assert!(
        printed.lines().any(|line| line == "VISIBLE=to-the-server"),
        "{printed}"
    );
    for withheld in ["KR_REGISTRATION", "KR_CREDENTIAL"] {
        assert!(
            !printed.contains(withheld),
            "{withheld} reached the server: {printed}"
        );
    }
    assert!(
        !printed.lines().any(|line| line.starts_with("HOME=")),
        "the worker's own environment reached the server: {printed}"
    );

    // The server leads a group of its own.
    let server = start("", PLAIN).await;
    let pid = server.identity().pid.get().to_string();
    let group = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid])
        .output()
        .expect("ps runs");
    assert_eq!(String::from_utf8_lossy(&group.stdout).trim(), pid);
    let record = Record::of(&server);
    let _session = to_the_approval(&server).await;
    let retirement = server.retire(&record).await;
    assert!(retirement.survivors.is_empty());
}
