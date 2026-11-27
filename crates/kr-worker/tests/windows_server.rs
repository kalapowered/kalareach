//! The application server a session starts on Windows, and how it is ended.
//!
//! The server here is the Codex stand-in, a real program speaking the pinned release's protocol,
//! started the way a session starts one: in a job of its own, inside the session's job, on private
//! pipes. The commands it starts run in jobs of their own, as the release's server runs them, so
//! each is a job nested under the server's. The ending is of the server's job: there is no request
//! to terminate on Windows, so a server that ignores the end of its input is ended by force when
//! the window is over. Build the stand-in before a package-scoped run
//! (`cargo build -p kr-codex-stand-in`); a run of the workspace builds it first.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.60 | The server is started only as the record names it, with the presented environment less the two launch variables, in its job and the session's; it ends with its input and its commands with it; a dropped server leaves nothing; a session whose job has gone starts no server |
//! | KR-REQ-07.53 | Nothing is forced before the window is over |
//! | KR-REQ-07.66 | A server that ignores the end of its input is ended by force, and so is its command |
//! | KR-REQ-07.64 | A command's own job nests under the server's and the session's, and does not stop the launch or the ending |

#![cfg(windows)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::server::{Emptiness, Ended, Owned, Server, ServerSpec};
use kr_worker::windows::job::{MemberReading, SessionJob, record};
use kr_worker::windows::launch::seams;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

/// How long a wait for something to happen is given: the first start of a program that was just
/// built or copied can take the system most of a minute.
const LIVENESS: Duration = Duration::from_secs(180);

/// How long a wait for something that is prompt when the code is right is given.
const PROMPT: Duration = Duration::from_secs(30);

/// The five seconds an ending has before anything in it is forced.
const FIVE_SECONDS: Duration = Duration::from_secs(5);

/// A command that waits far longer than any case takes.
const PLAIN: &str = r#"["ping.exe", "-n", "120", "127.0.0.1"]"#;

/// The stand-in as a session would run it: a copy in a directory of its own, and what its digest
/// is. The directory is removed when the last case that holds the copy ends.
struct StandIn {
    directory: tempfile::TempDir,
    executable: PathBuf,
    digest: Digest256,
}

fn built_stand_in() -> PathBuf {
    let tests = std::env::current_exe().expect("this case's path");
    let built = tests
        .parent()
        .and_then(Path::parent)
        .expect("the directory the programs are built in")
        .join("codex-stand-in.exe");
    assert!(
        built.is_file(),
        "{} is not built; run `cargo build -p kr-codex-stand-in` first",
        built.display()
    );
    built
}

fn stand_in() -> Arc<StandIn> {
    static SHARED: Mutex<Weak<StandIn>> = Mutex::new(Weak::new());
    let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(copy) = shared.upgrade() {
        return copy;
    }
    let directory = tempfile::Builder::new()
        .prefix("kr-server-")
        .tempdir()
        .expect("a directory");
    let executable = directory.path().join("codex.exe");
    // Placed and started once where nothing is waited for: the first start of a program at a new
    // path is the one the system checks, and it can take most of a minute.
    let _ = kr_ipc::testing::place_and_start_once(&built_stand_in(), &executable, &["--version"]);
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

/// A session's job, recorded under a root shell's number that no process has.
struct Session {
    job: Arc<SessionJob>,
    root: u32,
}

fn session() -> Session {
    static NEXT: AtomicU32 = AtomicU32::new(0x7e00_0000);
    let job = Arc::new(SessionJob::create().expect("the session's job"));
    let root = NEXT.fetch_add(4, Ordering::SeqCst);
    record(root, &job);
    Session { job, root }
}

/// The environment a launch presents: what the stand-in is told, the two variables of the launch,
/// and what a program needs to find the system's own programs.
fn presented(variants: &str, command: &str) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<(OsString, OsString)> = [
        ("STAND_IN", variants),
        ("STAND_IN_COMMAND", command),
        ("KR_REGISTRATION", "/not/for/the/server"),
        ("KR_CREDENTIAL", "not-for-the-server"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
    .collect();
    for name in ["PATH", "SystemRoot", "windir"] {
        environment.push((
            OsString::from(name),
            std::env::var_os(name).expect("a system variable"),
        ));
    }
    environment
}

fn arguments() -> [String; 3] {
    [
        "app-server".to_owned(),
        "--listen".to_owned(),
        "stdio://".to_owned(),
    ]
}

/// Held by every case while a start creates its process, and by the case that sets a hook on the
/// create alone, because the hook is process-wide.
static CREATES: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

async fn start(stand_in: &StandIn, session: &Session, variants: &str, command: &str) -> Server {
    let environment = presented(variants, command);
    let _creating = CREATES.read().await;
    Server::start(
        &ServerSpec {
            executable: &stand_in.executable,
            digest: &stand_in.digest,
            arguments: &arguments(),
            directory: stand_in.directory.path(),
            presented: &environment,
        },
        session.root,
    )
    .await
    .expect("the server starts")
}

/// What the ending noted, as a session's record would.
#[derive(Default)]
struct Record {
    forced: Mutex<Vec<ProcessStartIdentity>>,
    unsignalled: Mutex<Vec<String>>,
}

impl Owned for Record {
    fn below(&self, _server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity> {
        Vec::new()
    }

    fn left(&self, _process: &ProcessStartIdentity) -> bool {
        false
    }

    fn forced(&self, process: &ProcessStartIdentity) {
        self.forced
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(process.clone());
    }

    fn unsignalled(&self, process: &ProcessStartIdentity, why: &str) {
        self.unsignalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!("process {} was not ended: {why}", process.pid));
    }
}

/// A session with the server up to the approval it asks for, which is when its command runs.
struct Conversation {
    lines: tokio::io::Lines<BufReader<kr_worker::broker::server::Output>>,
    input: kr_worker::broker::server::Input,
    approval: serde_json::Value,
}

async fn write(conversation: &mut Conversation, frame: &serde_json::Value) {
    conversation
        .input
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("the server reads");
}

async fn read(conversation: &mut Conversation) -> serde_json::Value {
    let line = tokio::time::timeout(LIVENESS, conversation.lines.next_line())
        .await
        .expect("the server writes")
        .expect("it is readable")
        .expect("it has not ended");
    serde_json::from_str(&line).expect("a frame")
}

async fn to_the_approval(server: &Server) -> Conversation {
    let (output, input) = server.take_pipes().expect("the pipes");
    let mut conversation = Conversation {
        lines: BufReader::new(output).lines(),
        input,
        approval: serde_json::Value::Null,
    };
    write(
        &mut conversation,
        &serde_json::json!({"id":"initialize","method":"initialize","params":{
            "clientInfo":{"name":"test","title":null,"version":"0"},
            "capabilities":{"experimentalApi":true,"requestAttestation":false,"optOutNotificationMethods":null}}}),
    )
    .await;
    assert_eq!(read(&mut conversation).await["id"], "initialize");
    assert_eq!(
        read(&mut conversation).await["method"],
        "remoteControl/status/changed"
    );
    write(
        &mut conversation,
        &serde_json::json!({"method":"initialized"}),
    )
    .await;
    write(
        &mut conversation,
        &serde_json::json!({"id":2,"method":"thread/start","params":{}}),
    )
    .await;
    assert!(read(&mut conversation).await["result"]["thread"]["id"].is_string());
    assert_eq!(read(&mut conversation).await["method"], "thread/started");
    write(
        &mut conversation,
        &serde_json::json!({"id":3,"method":"turn/start","params":{
            "threadId":"thread-1","input":[{"type":"text","text":"go","text_elements":[]}]}}),
    )
    .await;
    assert!(read(&mut conversation).await["result"]["turn"].is_object());
    assert_eq!(read(&mut conversation).await["method"], "turn/started");
    conversation.approval = read(&mut conversation).await;
    assert_eq!(
        conversation.approval["method"],
        "item/commandExecution/requestApproval"
    );
    conversation
}

/// The command the server started, as the system names it now: the process whose identifier the
/// server said on its error stream.
async fn command_of(server: &Server) -> ProcessStartIdentity {
    let started = Instant::now();
    loop {
        let said = server.error_tail().lines().find_map(|line| {
            line.strip_prefix("stand-in: started command ")
                .map(str::to_owned)
        });
        if let Some(pid) = said.and_then(|pid| pid.trim().parse::<u32>().ok())
            && let Ok(identity) = kr_ipc::identity::started_process_identity(pid)
        {
            return identity;
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

/// Waits until the server's error stream has said `text`, and says whether it did. What the server
/// wrote is read by a task of its own, which is a moment behind.
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

/// Watches `processes` from now on, and returns when each was first seen gone, in the order given.
fn watch_until_gone(processes: Vec<ProcessStartIdentity>) -> tokio::task::JoinHandle<Vec<Instant>> {
    tokio::spawn(async move {
        let mut seen: Vec<Option<Instant>> = vec![None; processes.len()];
        while seen.iter().any(Option::is_none) {
            for (process, at) in processes.iter().zip(seen.iter_mut()) {
                if at.is_none() && gone(process) {
                    *at = Some(Instant::now());
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        seen.into_iter().flatten().collect()
    })
}

/// A server ends with its input, and its command with it: nothing is forced or left.
#[tokio::test]
async fn kr_req_07_60_a_server_that_ends_with_its_input_leaves_nothing() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "", PLAIN).await;
    let _conversation = to_the_approval(&server).await;
    let command = command_of(&server).await;
    assert!(!gone(&command), "the command runs while the server does");

    let record = Record::default();
    let retirement = server.retire(&record, Instant::now().into()).await;
    assert_eq!(retirement.ended, Ended::Input);
    assert!(retirement.forced.is_empty(), "{:?}", retirement.forced);
    assert!(retirement.survivors.is_empty());
    assert_eq!(retirement.emptiness, Emptiness::Empty);
    assert!(gone(server.identity()) && gone(&command));
}

/// A server that ignores the end of its input is ended by force when the five seconds are over, and
/// so is its command: both are noted as forced, and neither is gone before.
#[tokio::test]
async fn kr_req_07_66_a_server_that_ignores_its_input_is_forced_when_the_window_is_over() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "ignore-eof", PLAIN).await;
    let _conversation = to_the_approval(&server).await;
    let command = command_of(&server).await;

    let record = Record::default();
    let begun = Instant::now();
    let watching = watch_until_gone(vec![server.identity().clone(), command.clone()]);
    let retirement = server.retire(&record, begun.into()).await;
    assert_eq!(retirement.ended, Ended::Force);
    assert!(retirement.forced.contains(server.identity()));
    assert!(
        retirement.forced.contains(&command),
        "{:?}",
        retirement.forced
    );
    assert!(retirement.survivors.is_empty());
    assert_eq!(retirement.emptiness, Emptiness::Empty);
    assert_eq!(
        *record.forced.lock().expect("the list"),
        retirement.forced,
        "what the ending noted is what it reports"
    );
    assert!(gone(server.identity()) && gone(&command));
    // KR-REQ-07.53: both were there until the five seconds were over, and no longer.
    for (what, went) in ["the server", "its command"]
        .into_iter()
        .zip(watching.await.expect("the watch is joined"))
    {
        assert!(
            went.duration_since(begun) >= FIVE_SECONDS,
            "{what} was forced {:?} after the ending began",
            went.duration_since(begun)
        );
    }
}

/// A server that dies with its command running leaves a command no parent names, and the ending
/// ends it with the job that held it.
#[tokio::test]
async fn kr_req_07_60_a_command_that_outlives_a_server_that_died_is_ended_with_its_job() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "die-first", PLAIN).await;
    let mut conversation = to_the_approval(&server).await;
    let command = command_of(&server).await;
    // The approval is answered and the server dies.
    let id = conversation.approval["id"].clone();
    write(
        &mut conversation,
        &serde_json::json!({"id": id, "result": {"decision": "accept"}}),
    )
    .await;
    let started = Instant::now();
    while !gone(server.identity()) {
        assert!(started.elapsed() < LIVENESS, "the server died");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!gone(&command), "the command outlived the server");

    let record = Record::default();
    let begun = Instant::now();
    let watching = watch_until_gone(vec![command.clone()]);
    let retirement = server.retire(&record, begun.into()).await;
    assert_eq!(retirement.ended, Ended::Already);
    assert_eq!(retirement.forced, vec![command.clone()]);
    assert!(retirement.survivors.is_empty());
    assert_eq!(retirement.emptiness, Emptiness::Empty);
    assert!(gone(&command));
    // KR-REQ-07.53: it was waited for until the five seconds were over, and no longer.
    let went = watching.await.expect("the watch is joined")[0];
    assert!(
        went.duration_since(begun) >= FIVE_SECONDS,
        "the command was forced {:?} after the ending began",
        went.duration_since(begun)
    );
}

/// KR-REQ-07.64: the command's own job nests under the server's and the session's, which does not
/// stop the launch (the command started and says it is in a job of its own) or the ending (the
/// nested job's processes are ended with the server's).
#[tokio::test]
async fn kr_req_07_64_a_command_in_a_job_of_its_own_nests_under_the_servers_and_ends_with_it() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "", PLAIN).await;
    let _conversation = to_the_approval(&server).await;
    let command = command_of(&server).await;
    let pid = u32::try_from(command.pid.get()).expect("a process number");
    assert!(
        says(&server, &format!("command {pid} runs in a job of its own")).await,
        "{}",
        server.error_tail()
    );
    // The command is in the server's job and in the session's, whatever job it made for itself.
    let held = server
        .job()
        .process_ids()
        .expect("the server's job is read");
    assert!(held.contains(&pid), "{held:?}");
    assert!(matches!(session.job.member(pid), MemberReading::Held(_)));

    let retirement = server
        .retire(&Record::default(), Instant::now().into())
        .await;
    assert!(retirement.survivors.is_empty());
    assert_eq!(retirement.emptiness, Emptiness::Empty);
    assert!(gone(&command));
}

/// A server is started with the presented environment less the two variables of the launch and
/// nothing of the worker's own, in the directory asked, in its own job and the session's.
#[tokio::test]
async fn kr_req_07_60_a_server_is_started_as_a_session_runs_it() {
    let stand_in = stand_in();
    let session = session();
    let mut environment = presented("report-environment", PLAIN);
    environment.push((OsString::from("VISIBLE"), OsString::from("to-the-server")));
    // A name the launch presents in another case is the same variable.
    environment.push((OsString::from("=C:"), OsString::from(r"C:\")));
    let creating = CREATES.read().await;
    let server = Server::start(
        &ServerSpec {
            executable: &stand_in.executable,
            digest: &stand_in.digest,
            arguments: &arguments(),
            directory: stand_in.directory.path(),
            presented: &environment,
        },
        session.root,
    )
    .await
    .expect("the server starts");
    drop(creating);
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
    assert!(
        said.lines()
            .any(|line| line == r"stand-in: variable =C:=C:\"),
        "the per-drive name was passed on as it was presented: {said}"
    );
    for withheld in ["KR_REGISTRATION", "KR_CREDENTIAL"] {
        assert!(
            !said.contains(&format!("variable {withheld}=")),
            "{withheld} reached the server: {said}"
        );
    }
    assert!(
        !said.contains("variable USERPROFILE="),
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

    // The server is in its own job and in the session's.
    let pid = u32::try_from(server.identity().pid.get()).expect("a process number");
    assert!(server.job().process_ids().expect("its job").contains(&pid));
    assert!(matches!(session.job.member(pid), MemberReading::Held(_)));
    let retirement = server
        .retire(&Record::default(), Instant::now().into())
        .await;
    assert!(retirement.survivors.is_empty());
}

/// A program is started only when it is the executable the record names, named by an absolute
/// path, with an environment whose names are names.
#[tokio::test]
async fn kr_req_07_60_a_server_is_started_only_as_the_record_names_it() {
    let stand_in = stand_in();
    let session = session();
    let directory = stand_in.directory.path();
    let environment = presented("", PLAIN);
    let wrong = Digest256::from_bytes([1; 32]);
    let refused = Server::start(
        &ServerSpec {
            executable: &stand_in.executable,
            digest: &wrong,
            arguments: &arguments(),
            directory,
            presented: &environment,
        },
        session.root,
    )
    .await
    .expect_err("an executable the record does not name is not started");
    assert!(refused.contains("signed record"), "{refused}");

    let relative = Server::start(
        &ServerSpec {
            executable: Path::new("codex.exe"),
            digest: &stand_in.digest,
            arguments: &arguments(),
            directory,
            presented: &environment,
        },
        session.root,
    )
    .await
    .expect_err("a relative path names two files and is not started");
    assert!(relative.contains("absolute"), "{relative}");

    // A name with an equals sign in it would set another variable than the one it spells, and one
    // variable named twice in two cases is not one the system reads back as it was given.
    for (name, why) in [
        ("KR_CREDENTIAL=forged", "a name that holds an ="),
        ("stand_in", "a name that repeats another in another case"),
    ] {
        let mut forged = presented("", PLAIN);
        forged.push((OsString::from(name), OsString::from("value")));
        let refused = Server::start(
            &ServerSpec {
                executable: &stand_in.executable,
                digest: &stand_in.digest,
                arguments: &arguments(),
                directory,
                presented: &forged,
            },
            session.root,
        )
        .await
        .expect_err(why);
        assert!(refused.contains("environment"), "{why}: {refused}");
    }
}

/// A server started from another file than the one the record names is refused: another program
/// is given the digest of the stand-in, and no server starts from it.
#[tokio::test]
async fn kr_req_07_60_a_server_started_from_another_file_is_refused() {
    let stand_in = stand_in();
    let session = session();
    let other = Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join("ping.exe");
    let environment = presented("", PLAIN);
    let refused = Server::start(
        &ServerSpec {
            executable: &other,
            digest: &stand_in.digest,
            arguments: &arguments(),
            directory: stand_in.directory.path(),
            presented: &environment,
        },
        session.root,
    )
    .await
    .expect_err("another file is not started under the stand-in's digest");
    assert!(refused.contains("signed record"), "{refused}");
}

/// A session whose job has gone starts no server: the start fails by name before any process is
/// made, rather than start one the session does not hold.
#[tokio::test]
async fn kr_req_07_60_a_full_start_without_a_session_job_fails_by_name() {
    let stand_in = stand_in();
    let gone = session();
    let root = gone.root;
    drop(gone);
    let environment = presented("", PLAIN);
    let refused = Server::start(
        &ServerSpec {
            executable: &stand_in.executable,
            digest: &stand_in.digest,
            arguments: &arguments(),
            directory: stand_in.directory.path(),
            presented: &environment,
        },
        root,
    )
    .await
    .expect_err("a session that has no job starts no server");
    assert!(refused.contains("session's job has gone"), "{refused}");
}

/// A server that is dropped without being retired is ended, and so is its command: nothing a holder
/// of its pipes does keeps either. This is what a server that could not be recorded comes to.
#[tokio::test]
async fn kr_req_07_60_a_server_that_is_dropped_is_ended_with_its_command() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "ignore-eof", PLAIN).await;
    let identity = server.identity().clone();
    // Another holder of the pipes, which the guard must not wait for.
    let conversation = to_the_approval(&server).await;
    let command = command_of(&server).await;
    assert!(!gone(&identity));
    drop(server);
    let started = Instant::now();
    while !(gone(&identity) && gone(&command)) {
        assert!(
            started.elapsed() < PROMPT,
            "the server or its command outlived its guard"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(conversation);
}

/// A start that is given up while its process is being created ends what that creates: the future
/// that awaits the start is dropped at the moment the pipe's two ends are being made, and no
/// process of the file is left. A running program holds its file, so the case can delete the copy
/// only once nothing runs from it.
#[tokio::test]
async fn kr_req_07_60_a_start_dropped_during_the_create_leaves_no_process() {
    /// Clears the hook when the case ends, however it ends.
    struct ClearsTheHook;
    impl Drop for ClearsTheHook {
        fn drop(&mut self) {
            seams::after_server_create(None);
        }
    }
    let _alone = CREATES.write().await;
    let _clears = ClearsTheHook;
    let session = session();
    let own = tempfile::Builder::new()
        .prefix("kr-given-up-")
        .tempdir()
        .expect("a directory");
    let executable = own.path().join("codex.exe");
    let _ = kr_ipc::testing::place_and_start_once(&built_stand_in(), &executable, &["--version"]);
    let digest = Digest256::from_bytes(
        Sha256::digest(std::fs::read(&executable).expect("the copy is read")).into(),
    );

    let (reached, wait_reached) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    seams::after_server_create(Some(Box::new(move |_name: &str| {
        let _ = reached.send(());
        let _ = released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(LIVENESS);
    })));
    let root = session.root;
    let (path, directory) = (executable.clone(), own.path().to_path_buf());
    let starting = tokio::spawn(async move {
        let environment = presented("", PLAIN);
        Server::start(
            &ServerSpec {
                executable: &path,
                digest: &digest,
                arguments: &arguments(),
                directory: &directory,
                presented: &environment,
            },
            root,
        )
        .await
        .map(|_| ())
    });
    wait_reached
        .recv_timeout(LIVENESS)
        .expect("the start reached the pipe's creation");
    starting.abort();
    let _ = starting.await;
    release.send(()).expect("the start is released");

    // The program the closure created is ended by the closure, so the copy can be removed.
    let started = Instant::now();
    loop {
        if std::fs::remove_file(&executable).is_ok() {
            break;
        }
        assert!(
            started.elapsed() < PROMPT,
            "a process of the file the start was given up on is still running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Neither the server's job nor the session's sets a restriction on the user interface: the
/// desktop and the clipboard are what a command makes of them, which a sandbox that makes a private
/// desktop of its own needs.
#[tokio::test]
async fn kr_req_07_60_the_server_job_and_the_session_job_set_no_ui_restriction() {
    let stand_in = stand_in();
    let session = session();
    let server = start(&stand_in, &session, "", PLAIN).await;
    assert_eq!(server.job().ui_restrictions().expect("the server's job"), 0);
    assert_eq!(session.job.ui_restrictions().expect("the session's job"), 0);
    let retirement = server
        .retire(&Record::default(), Instant::now().into())
        .await;
    assert_eq!(retirement.emptiness, Emptiness::Empty);
}
