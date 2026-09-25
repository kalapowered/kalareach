//! `kr new` starting this environment's control daemon: itself, under the standalone start, or
//! through the user's own service manager, under the service start.
//!
//! What these establish, with the real `kr`, `kr-controller` and `kr-worker` on a real environment
//! tree. KR-REQ-07.12: with the standalone start selected and no daemon running, `kr new` starts
//! one, detached from itself: in a session and a process group of its own, with no controlling
//! terminal and none of the command's own streams, working in the environment's own directory.
//! Then it goes on as it would against a daemon that was already there. Three commands starting one
//! at once leave one daemon, at one generation, holding every session they created. A daemon that
//! does not come up within the bound ends the command with a failure of its own name and leaves no
//! second daemon, whether it cannot take the environment or is slow to start; a slow one is left to
//! come up and is then used. The start is selected by a command that needs no daemon, on a host
//! where none has ever run, and `kr doctor` reports it with the document it came from.
//! KR-REQ-07.13: with the start selected, neither the command that selects it nor the `kr new`
//! that starts the daemon runs a service-manager, lingering or privilege tool, the daemon it starts
//! runs nothing but read-only queries of the service manager, and nothing is written in the home
//! they are given. KR-REQ-08.02: `kr status` on a session the started daemon holds reports each
//! terminal attachment's presentation and the reason for it.
//!
//! The installation is laid out the way a package lays it out: `kr`, its restoration guard, the
//! daemon and the worker side by side on the internal disk, where `kr` finds the daemon beside
//! itself. The daemon there is a short script, which is what `kr` starts. It hands over to a copy of
//! this test binary, which supervises the real daemon: it starts it with its keys in the
//! environment's own `secrets` directory, which is what every harness in this repository gives a
//! daemon so that nothing reaches the credential store of the person running the tests, and with
//! every other argument and the whole environment `kr` gave it. The supervisor records the daemon's
//! process number in the test's own tree and holds the daemon as a child it has not collected until
//! the test's lifeline closes, however the test ended; it then ends the daemon and collects it.
//! Only a process's own parent signals it, and only before collecting it, so no number is ever
//! signalled after it could have passed to something else, and the test process signals nothing.
//! Every runtime and state directory is inside the test's own temporary tree.
//!
//! The service start. KR-REQ-07.12 and KR-REQ-26.04: `kr host startup --set service` writes the
//! definition of a per-user service in the home it is given, records it and has the service
//! manager take it; three `kr new` commands at once then converge on the one daemon the manager
//! starts, whose parent is the manager; `kr doctor` reports that the definition matches; `--clear`
//! removes the definition and its record and the daemon keeps serving; and a definition kr did not
//! write, one changed since, or one that has gone is named and never replaced. The installation for
//! these has the real daemon behind a script that hands over to it with `exec`, so the process the
//! manager starts is the daemon itself. On macOS the manager is launchd, and the definition, in the
//! test's own home, is loaded under a label that names the test's own environment. On Linux it is a
//! user manager of the test's own, run in a delegated scope with the test's home as its home, so it
//! reads the definition from there; ending the scope ends everything it started. A host with no
//! user manager says why these did not run, unless `KR_REQUIRE_SERVICE_MANAGER` is set.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::identity::{ProcessQuery, ProcessState};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::{ActionId, AttachmentId, BuildId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, SessionListParams, SessionListResult};
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long a command, or anything a test waits for, is given. It fails when the thing never
/// happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// How long the streams of a command that has ended are given to reach their end, and how long a
/// daemon is given to end once its lifeline has closed.
const STREAMS_DEADLINE: Duration = Duration::from_secs(10);

/// The name the real daemon is placed under, beside the script `kr` runs as the daemon.
const DAEMON_UNDER_TEST: &str = "kr-controller-under-test";

/// The name this test binary's copy is placed under, beside the script that hands over to it.
const SUPERVISOR_PROGRAM: &str = "startup-supervisor";

/// The test the supervisor runs as.
const SUPERVISOR_TEST: &str = "supervise_one_daemon_when_asked";

/// Set, to the real daemon's path, when this binary runs as a daemon's supervisor.
const SUPERVISE: &str = "KR_STARTUP_TEST_SUPERVISE";

/// The daemon's arguments, one to a line, when this binary runs as a daemon's supervisor.
const SUPERVISED_ARGUMENTS: &str = "KR_STARTUP_TEST_ARGUMENTS";

/// The file in a test's own tree that each daemon script records its daemon's process number in.
const LAUNCHED: &str = "launched-daemons";

/// The file in a test's own tree that each supervisor records its own process number in when it
/// starts.
const STARTS: &str = "daemon-starts";

/// The FIFO in a test's own tree that the test holds open for as long as it runs.
const LIFELINE: &str = "daemon-lifeline";

/// When present in a test's own tree, how many supervisors have to have started before any of them
/// starts its daemon, so that the daemons meet at the environment's lock.
const BARRIER: &str = "daemon-barrier";

/// When present in a test's own tree, how many seconds each supervisor waits before it starts its
/// daemon, which is what a daemon slow to come up looks like from outside.
const DELAY: &str = "daemon-delay";

/// The tools a service, lingering or a privilege would be obtained through.
const RECORDING_TOOLS: [&str; 8] = [
    "systemctl",
    "systemd-run",
    "loginctl",
    "launchctl",
    "sudo",
    "doas",
    "pkexec",
    "runuser",
];

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Starts every process this file starts, one at a time.
///
/// A pipe is made and only then marked to close when a program is started, and on macOS those are
/// two steps. A process another test's thread starts in between inherits both ends, and a `kr`
/// that inherits them hands them on to the daemon it starts, which outlives it: the pipe then
/// never reaches its end, and the command that made it looks as if it had left something holding
/// its output. Starting one process at a time closes that window for every pipe this file makes.
fn spawning<T>(start: impl FnOnce() -> T) -> T {
    static SPAWNING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_at_a_time = SPAWNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    start()
}

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    // `<target>/<profile>/deps/<this test>`: the executables are in `<target>/<profile>`.
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// The installation these tests run, on the internal disk: `kr` and its guard, and beside them the
/// daemon script, the daemon it runs and the worker.
///
/// A build of this crate alone that has not built the daemon and the worker yet fails here and
/// says why, rather than passing without having tested anything.
fn installation() -> &'static Path {
    static PLACED: OnceLock<PathBuf> = OnceLock::new();
    PLACED.get_or_init(|| {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller"),
            beside_this_test("kr-worker"),
        ) else {
            panic!(
                "the kr-controller and kr-worker executables are not built beside this test, so \
                 this check cannot run; a workspace test run builds them, and so does \
                 `cargo build -p kr-controller -p kr-worker`"
            );
        };
        let directory = support::command_binaries();
        // Each is started once where nothing is timed, so the operating system's check of a newly
        // written executable is paid here rather than inside the start `kr new` waits for.
        kr_ipc::testing::place_and_start_once(
            &worker,
            &directory.join("kr-worker"),
            &["--version"],
        );
        let daemon = directory.join(DAEMON_UNDER_TEST);
        kr_ipc::testing::place_and_start_once(&controller, &daemon, &["--version"]);
        let supervisor = directory.join(SUPERVISOR_PROGRAM);
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test binary"),
            &supervisor,
            &["--list"],
        );
        // Written under a name nothing runs, and placed under the one `kr` runs by a copy, like
        // every program these tests start: no descriptor this process holds is ever open on it.
        let source = directory.join("kr-controller.sh");
        std::fs::write(&source, daemon_script(&daemon, &supervisor))
            .expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory.to_path_buf()
    })
}

/// The daemon `kr` finds beside itself in these tests: a script that hands over, with everything
/// `kr` gave it, to this test binary's copy running as the daemon's supervisor.
fn daemon_script(daemon: &Path, supervisor: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         exec /usr/bin/env {SUPERVISE}='{}' {SUPERVISED_ARGUMENTS}=\"$(printf '%s\\n' \"$@\")\" \
         '{}' {SUPERVISOR_TEST} --exact --quiet\n",
        daemon.display(),
        supervisor.display()
    )
}

/// Not a check of its own: the entry point the daemon script runs this binary's copy through, with
/// [`SUPERVISE`] set, to supervise one daemon. The test harness running it without that variable
/// finds nothing to supervise.
#[test]
fn supervise_one_daemon_when_asked() {
    if let Some(daemon) = std::env::var_os(SUPERVISE) {
        supervise(Path::new(&daemon));
    }
}

/// Supervises one daemon for a test.
///
/// It opens the test's lifeline, records itself, and waits at the test's barrier or out the test's
/// delay when the test asks for either. A lifeline that has closed by then means the test has
/// ended, and nothing is started. Otherwise it starts the real daemon as its child, with its keys
/// in the environment's own `secrets` directory and everything else `kr` gave the script, records
/// the daemon's process number, and waits for the lifeline to close. Only then does it end the
/// daemon and collect it. Rust collects a child only when asked, so a daemon that ended by itself in
/// the meantime is still this process's uncollected child, its number is still its own, and
/// signalling it reaches nothing else.
fn supervise(daemon: &Path) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let arguments: Vec<String> = std::env::var(SUPERVISED_ARGUMENTS)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let state = arguments
        .windows(2)
        .find(|pair| pair[0] == "--state-dir")
        .map(|pair| PathBuf::from(&pair[1]))
        .expect("kr names the state tree");
    let tree = state
        .parent()
        .expect("the state tree is inside the test's own tree")
        .to_path_buf();
    // One write of the whole line: supervisors append to the same record at once, and a line
    // written in two pieces could be split by another's.
    let record = |name: &str, pid: u32| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tree.join(name))
            .expect("opens a record");
        file.write_all(record_line(pid).as_bytes())
            .expect("records a process");
    };
    // Read without waiting, so a closed lifeline is seen as its end rather than waited on.
    let lifeline = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(tree.join(LIFELINE))
        .expect("opens the lifeline");
    record(STARTS, std::process::id());
    let waited = Instant::now();
    if let Ok(wanted) = std::fs::read_to_string(tree.join(BARRIER)) {
        let wanted: usize = wanted.trim().parse().expect("a number of starts");
        while std::fs::read_to_string(tree.join(STARTS))
            .unwrap_or_default()
            .lines()
            .count()
            < wanted
            && waited.elapsed() < Duration::from_secs(30)
            && !closed(&lifeline)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if let Ok(seconds) = std::fs::read_to_string(tree.join(DELAY)) {
        let delay = Duration::from_secs(seconds.trim().parse().expect("a number of seconds"));
        while waited.elapsed() < delay && !closed(&lifeline) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if closed(&lifeline) {
        return;
    }
    // Held from the moment it starts, so it is ended and collected however this supervisor's run
    // ends, a failure to record it included.
    let daemon = Supervised(
        Command::new(daemon)
            .arg("--secret-store")
            .arg("file")
            .args(&arguments)
            .env_remove(SUPERVISE)
            .env_remove(SUPERVISED_ARGUMENTS)
            .spawn()
            .expect("starts the daemon"),
    );
    record(LAUNCHED, daemon.0.id());
    while !closed(&lifeline) {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(daemon);
}

/// The line a record names one process with: its number, and its start identity, so the test can
/// tell it from whatever holds the number later.
///
/// A daemon can end before it is recorded, as one that cannot take the environment does, and on
/// macOS the kernel stops describing a process once it has ended, collected or not. Such a process
/// is named as one that has ended rather than failing the record.
fn record_line(pid: u32) -> String {
    let identity = kr_ipc::identity::started_process_identity(pid).expect("the start identity");
    format!(
        "{pid}\t{}\n",
        serde_json::to_string(&identity).expect("encodes the identity")
    )
}

/// A daemon a supervisor started.
struct Supervised(Child);

impl Drop for Supervised {
    fn drop(&mut self) {
        // This process's own child, not collected yet, so the number is still its.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether nothing holds the lifeline open any more, which is how a supervisor learns the test has
/// ended.
fn closed(lifeline: &std::fs::File) -> bool {
    use std::io::Read as _;

    let mut byte = [0; 1];
    match (&*lifeline).read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => error.kind() != std::io::ErrorKind::WouldBlock,
    }
}

/// A host tree of a test's own, where the standalone start is tried.
///
/// However a test ends, each daemon `kr` started in the tree is ended before the tree goes, by the
/// supervisor that started it; every supervisor has ended; and then, through the tree, every worker
/// a daemon recorded.
struct Standalone {
    tree: teardown::Tree,
    home: PathBuf,
    /// The lifeline every supervisor in this tree waits on, held open for as long as the test runs.
    lifeline: Option<std::fs::File>,
}

impl Drop for Standalone {
    fn drop(&mut self) {
        for why in self.end_what_was_started() {
            self.tree.hold(why);
        }
    }
}

impl Standalone {
    /// Ends every supervisor this test's commands started, and with it every daemon, waits for them,
    /// and returns whatever could not be established as ended, which keeps the tree.
    ///
    /// The lifeline closes first, which is what closes admission: a supervisor that has not started
    /// its daemon by then starts none, and one that has ends it. Every supervisor records itself,
    /// with its start identity, before it can start anything, and ends only after its daemon has
    /// been ended and collected, so waiting for the recorded supervisors waits for every daemon too;
    /// the daemons' own records are waited for as well. Each process is named by its start
    /// identity, so a number given to something else is not mistaken for it.
    ///
    /// Two things are not waited for. A supervisor that records itself after the records are read
    /// finds the lifeline closed, starts nothing and ends by itself. A record that cannot be read,
    /// such as one cut off part way by a full disk, is returned as what it is, and every record that
    /// can be read is still waited for. Nothing here panics: this runs while a failing test unwinds,
    /// and a second panic there would end the whole suite.
    fn end_what_was_started(&mut self) -> Vec<String> {
        drop(self.lifeline.take());
        let (mut identities, mut unresolved) = self.identities(STARTS);
        let (launched, unreadable) = self.identities(LAUNCHED);
        identities.extend(launched);
        unresolved.extend(unreadable);
        let begun = Instant::now();
        for identity in identities {
            loop {
                match kr_ipc::identity::process_state(&identity) {
                    ProcessState::Ended => break,
                    ProcessState::Running if begun.elapsed() < STREAMS_DEADLINE => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ProcessState::Running => {
                        unresolved.push(format!(
                            "the process {} this test started did not end once its lifeline \
                             closed",
                            identity.pid.get()
                        ));
                        break;
                    }
                    ProcessState::Unknown { detail } => {
                        unresolved.push(format!(
                            "whether the process {} this test started has ended cannot be \
                             established: {detail}",
                            identity.pid.get()
                        ));
                        break;
                    }
                }
            }
        }
        unresolved
    }

    /// The start identities one record in this tree names, in the order they were recorded, and a
    /// sentence for each line that does not name one.
    fn identities(
        &self,
        name: &str,
    ) -> (
        Vec<kr_protocol::identity::ProcessStartIdentity>,
        Vec<String>,
    ) {
        let mut identities = Vec::new();
        let mut unreadable = Vec::new();
        for line in std::fs::read_to_string(self.tree.root().join(name))
            .unwrap_or_default()
            .lines()
        {
            match line
                .split_once('\t')
                .map(|(_, identity)| serde_json::from_str(identity))
            {
                Some(Ok(identity)) => identities.push(identity),
                Some(Err(_)) | None => unreadable.push(format!(
                    "the record {name} holds a line that names no process: {line:?}"
                )),
            }
        }
        (identities, unreadable)
    }

    fn create() -> Self {
        let tree = teardown::Tree::create();
        let home = tree.root().join("home");
        std::fs::create_dir_all(&home).expect("a home of this test's own");
        let fifo = tree.root().join(LIFELINE);
        let made = spawning(|| Command::new("mkfifo").arg(&fifo).status()).expect("runs mkfifo");
        assert!(made.success(), "makes the lifeline");
        // Open for reading and writing, which does not wait for a reader. This is the only end
        // that writes, so a script reading the lifeline reaches its end exactly when this closes.
        let lifeline = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .expect("holds the lifeline");
        Self {
            tree,
            home,
            lifeline: Some(lifeline),
        }
    }

    /// Selects the standalone start as `kr host startup --set standalone` records it: the first
    /// revision of a document that chooses it and nothing else.
    fn select_standalone(&self) {
        kr_ipc::paths::write_owner_only_file(
            &self.document(),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("writes the configuration document");
    }

    /// Where this environment's configuration document is.
    ///
    /// Its state directory was chosen with `KR_STATE_DIR`, so the document is inside it on every
    /// platform.
    fn document(&self) -> PathBuf {
        self.tree.environment().state_dir().join("config.json")
    }

    /// Writes one of the files the daemon scripts read in this tree.
    fn ask_the_scripts(&self, name: &str, value: &str) {
        std::fs::write(self.tree.root().join(name), value).expect("writes the request");
    }

    /// `kr` from the installation, against this tree and nothing else, with nothing of this test's
    /// own environment but the temporary directory.
    fn kr(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(installation().join("kr"));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.tree.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.paths().state_root(),
            )
            .current_dir(installation())
            .stdin(Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        command
    }

    /// `kr new` for an invisible, headless session of `/bin/sh` working in this tree.
    fn new_session(&self) -> Command {
        let cwd = self.tree.root().display().to_string();
        self.kr(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ])
    }

    /// Closes a session this test created, through the daemon that holds it.
    fn close(&self, created: &Value) {
        let session = created["session_id"]
            .as_str()
            .expect("a session identifier");
        let output = start(self.kr(&["--json", "close", session])).finish("kr close");
        let closed = document(&output, "kr close");
        assert!(output.status.success(), "{closed}");
    }

    /// The daemons `kr` started in this tree, by process number, in the order they started.
    fn launched(&self) -> Vec<u32> {
        self.recorded(LAUNCHED)
    }

    /// The processes one record in this tree names, in the order they were recorded.
    fn recorded(&self, name: &str) -> Vec<u32> {
        std::fs::read_to_string(self.tree.root().join(name))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split('\t').next()?.trim().parse().ok())
            .collect()
    }

    /// The daemons `kr` started in this tree that are running now.
    ///
    /// A daemon that could not take the environment ends by itself and waits for its supervisor to
    /// collect it, which counts as ended. Its number stays its own until then, so each number here
    /// names the daemon it was recorded for.
    fn running(&self) -> Vec<u32> {
        self.launched()
            .into_iter()
            .filter(|pid| match kr_ipc::identity::query_process(*pid) {
                ProcessQuery::Present(identity) => match kr_ipc::identity::process_state(&identity)
                {
                    ProcessState::Running => true,
                    ProcessState::Ended => false,
                    ProcessState::Unknown { detail } => {
                        panic!("whether daemon {pid} is running cannot be established: {detail}")
                    }
                },
                ProcessQuery::Gone => false,
                ProcessQuery::CannotEstablish(error) => {
                    panic!("whether daemon {pid} is running cannot be established: {error}")
                }
            })
            .collect()
    }

    /// Waits until exactly one daemon `kr` started here is running, and returns it.
    ///
    /// A daemon that lost the environment's lock ends moments after it tried, so the answer is
    /// waited for rather than read once.
    fn one_daemon(&self) -> u32 {
        let started = Instant::now();
        loop {
            let running = self.running();
            if running.len() == 1 {
                return running[0];
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "one daemon was to be left of those started, {:?}, and these are running: \
                 {running:?}",
                self.launched()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether anything answers on this environment's endpoint now.
    fn answers(&self) -> bool {
        answers(&self.tree.environment())
    }

    /// Asks this environment's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        ask(&self.tree.environment(), method, params)
    }

    /// Establishes that a daemon is detached from whatever started it: it leads a session and a
    /// process group of its own, has no controlling terminal, and works in the environment's own
    /// directory.
    fn assert_detached(&self, pid: u32) {
        let process = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process number"))
            .expect("a process number");
        assert_eq!(
            rustix::process::getsid(Some(process)).expect("its session"),
            process,
            "the daemon leads a session of its own"
        );
        assert_eq!(
            rustix::process::getpgid(Some(process)).expect("its process group"),
            process,
            "and a process group of its own"
        );
        assert_eq!(
            kr_ipc::identity::controlling_terminal(pid).expect("its controlling terminal"),
            None,
            "and has no controlling terminal"
        );
        let environment = self.tree.environment();
        assert_eq!(
            working_directory(pid),
            std::fs::canonicalize(environment.state_dir()).expect("the state directory"),
            "and works in the environment's own directory"
        );
    }
}

/// Whether anything answers on an environment's endpoint now.
fn answers(environment: &kr_ipc::paths::EnvironmentPaths) -> bool {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        tokio::time::timeout(
            STREAMS_DEADLINE,
            LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
        )
        .await
        .is_ok_and(|reached| reached.is_ok())
    })
}

/// Asks an environment's daemon one question.
fn ask<T: kr_protocol::wire::WireMessage>(
    environment: &kr_ipc::paths::EnvironmentPaths,
    method: Method,
    params: &impl serde::Serialize,
) -> T {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon");
        client
            .request(method, params)
            .await
            .expect("the call reaches the daemon")
            .expect("the daemon answers")
            .to_typed()
            .expect("decodes")
    })
}

/// The working directory of a process of this user's.
fn working_directory(pid: u32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).expect("reads its working directory")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let listed = spawning(|| {
            Command::new("/usr/sbin/lsof")
                .args(["-a", "-d", "cwd", "-Fn", "-p", &pid.to_string()])
                .output()
        })
        .expect("lists its working directory");
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .find_map(|line| line.strip_prefix('n'))
            .map(PathBuf::from)
            .expect("its working directory is listed")
    }
}

/// A `kr` that has been started, and the threads reading what it prints.
///
/// One that a failing test leaves behind is waited for rather than left running, so nothing it
/// starts outlives the tree it was started in.
struct Running {
    child: Option<Child>,
    stdout: Receiver<Vec<u8>>,
    stderr: Receiver<Vec<u8>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let started = Instant::now();
        while matches!(child.try_wait(), Ok(None)) && started.elapsed() < LIVENESS_DEADLINE {
            std::thread::sleep(Duration::from_millis(20));
        }
        // This test's own child, not collected yet, so the number is still its.
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Starts `kr`, reading both its output streams on threads of their own.
fn start(mut command: Command) -> Running {
    let mut child = spawning(|| {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .expect("kr starts");
    let stdout = read_aside(child.stdout.take().expect("its standard output"));
    let stderr = read_aside(child.stderr.take().expect("its standard error"));
    Running {
        child: Some(child),
        stdout,
        stderr,
    }
}

fn read_aside(mut stream: impl std::io::Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    receiver
}

impl Running {
    /// Waits for `kr` to end, within the deadline, and for both of its streams to reach their end.
    ///
    /// A stream that stays open after `kr` has ended is held by something `kr` started, which is
    /// what a daemon given the command's own output would do, and that fails the test.
    fn finish(mut self, what: &str) -> Output {
        let mut child = self
            .child
            .take()
            .expect("a kr that has not been waited for");
        let started = Instant::now();
        let status = loop {
            match child.try_wait().expect("waits for kr") {
                Some(status) => break status,
                None if started.elapsed() < LIVENESS_DEADLINE => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                None => {
                    // This test's own child, not collected yet, so the number is still its.
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{what} did not end within {LIVENESS_DEADLINE:?}");
                }
            }
        };
        let stdout = self.stdout.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!(
                "{what} ended and its standard output is still open: something it started holds it"
            )
        });
        let stderr = self.stderr.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!(
                "{what} ended and its standard error is still open: something it started holds it"
            )
        });
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

/// Runs a command to its end and reads the one document it printed.
fn document(output: &Output, what: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{what} printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Every path under `root`, and the content of every file, in order.
fn every_path_under(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut found = Vec::new();
    let mut waiting = vec![root.to_path_buf()];
    while let Some(directory) = waiting.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                waiting.push(path.clone());
                found.push((path, None));
            } else {
                let content = std::fs::read(&path).ok();
                found.push((path, content));
            }
        }
    }
    found.sort();
    found
}

/// One call a recording tool recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Recorded {
    /// The process that made the call.
    caller: u32,
    /// That process's name, as the listing of processes gives it.
    name: String,
    /// The tool.
    tool: String,
    /// Every argument, in order.
    arguments: Vec<String>,
}

/// Places the recording tools in `tools`: each records the call it was given and the process that
/// made it in `calls`, and fails the way a host with no service manager and no privilege tool
/// would.
fn recording_tools(tools: &Path, calls: &Path) {
    std::fs::create_dir_all(tools).expect("a directory for the recording tools");
    for tool in RECORDING_TOOLS {
        // Written aside as text and placed by a process of its own, so that no child another test
        // starts meanwhile holds a tool open for writing when the daemon starts it.
        let text = tools.join(format!("{tool}.text"));
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\n\
                 {{\n\
                 \x20 printf '%s\\t%s\\t%s' \"$PPID\" \"$(ps -o comm= -p \"$PPID\" 2>/dev/null)\" '{tool}'\n\
                 \x20 for argument in \"$@\"; do printf '\\t%s' \"$argument\"; done\n\
                 \x20 printf '\\n'\n\
                 }} >> '{}'\n\
                 exit 1\n",
                calls.display()
            ),
        )
        .expect("writes a recording tool");
        kr_ipc::testing::place_program(&text, &tools.join(tool));
    }
}

/// The calls recorded in `calls`, in the order they were made.
fn recorded_calls(calls: &Path) -> Vec<Recorded> {
    std::fs::read_to_string(calls)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let caller = fields
                .next()
                .and_then(|field| field.trim().parse().ok())
                .unwrap_or_else(|| panic!("a recorded call names its caller: {line}"));
            let name = fields.next().unwrap_or_default().trim().to_owned();
            let tool = fields.next().unwrap_or_default().to_owned();
            Recorded {
                caller,
                name,
                tool,
                arguments: fields.map(str::to_owned).collect(),
            }
        })
        .collect()
}

/// Whether one recorded call is one the standalone start may make.
///
/// Only the daemon `kr` started may make one, and only in one of the exact read-only forms a
/// daemon asks the platform's service manager with: `systemctl --user show`, `loginctl show-user`
/// or `show-session`, and `launchctl print`. A call `kr` itself makes, a call from anything else,
/// and every other form of every tool is refused, with what it was.
fn allowed(call: &Recorded, daemons: &[u32]) -> Result<(), String> {
    if !daemons.contains(&call.caller) {
        return Err(format!(
            "{} (process {}), which is not the daemon kr started, ran {} {:?}",
            call.name, call.caller, call.tool, call.arguments
        ));
    }
    let arguments: Vec<&str> = call.arguments.iter().map(String::as_str).collect();
    let query = matches!(
        (call.tool.as_str(), arguments.as_slice()),
        ("systemctl", ["--user", "show", ..])
            | ("loginctl", ["show-user" | "show-session", ..])
            | ("launchctl", ["print", ..])
    );
    if query {
        Ok(())
    } else {
        Err(format!(
            "the daemon ran {} {:?}, which is not a read-only query",
            call.tool, call.arguments
        ))
    }
}

/// KR-REQ-07.12: three first invocations at once converge on one control daemon.
///
/// Three `kr new` commands start together with the standalone start selected and no daemon
/// running, and each starts a daemon: the daemons are held until all three have been started, so
/// all three meet at the environment's singleton lock. Each command creates its session; one daemon
/// is left of the three, the environment's generation advanced once, and every session is in that
/// daemon's registry. The daemon leads a session and a process group of its own, has no controlling
/// terminal and works in the environment's own directory, and every command's own output ended with
/// the command.
#[test]
fn three_first_invocations_at_once_converge_on_one_daemon() {
    let host = Standalone::create();
    host.select_standalone();
    host.ask_the_scripts(BARRIER, "3");

    let started: Vec<Running> = (0..3).map(|_| start(host.new_session())).collect();
    let mut sessions = Vec::new();
    let mut documents = Vec::new();
    for (index, running) in started.into_iter().enumerate() {
        let what = format!("kr new {index}");
        let output = running.finish(&what);
        let created = document(&output, &what);
        assert!(
            output.status.success(),
            "{what} created its session: {created}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(created["state"], "live", "{what}: {created}");
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        sessions.push(session_id);
        documents.push(created);
    }

    assert_eq!(
        host.launched().len(),
        3,
        "each command started a daemon, and the three met at the lock"
    );
    let daemon = host.one_daemon();
    let info: HostInfoResult = host.ask(Method::HostInfo, &());
    assert_eq!(info.environment_id, host.tree.environment_id());
    assert_eq!(
        info.generation.get(),
        1,
        "the environment's generation advanced once, for the one daemon that took it"
    );
    let listed: SessionListResult = host.ask(
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::some(host.tree.environment_id()),
            include_closed: false,
        },
    );
    for session_id in &sessions {
        assert!(
            listed
                .sessions
                .iter()
                .any(|summary| summary.session_id == *session_id),
            "session {session_id} is in the one daemon's registry: {:?}",
            listed.sessions
        );
    }
    host.assert_detached(daemon);
    for created in &documents {
        host.close(created);
    }
}

/// KR-REQ-07.12: a daemon that cannot take the environment is named when the command gives up, and
/// no second daemon is left.
///
/// The environment is held by a daemon that has taken its singleton lock and never answers, which
/// is what a daemon stuck in its own start looks like from outside; this test holds the lock
/// itself. `kr new` starts a daemon, which cannot take the environment and ends, waits out its
/// bound for an answer, and fails with `ENVIRONMENT_UNAVAILABLE`, saying how long it waited and the
/// last line of the daemon's log. The daemon it started has ended, and nothing answers for the
/// environment.
#[test]
fn a_daemon_that_does_not_come_up_in_time_is_named_and_no_second_one_is_left() {
    let host = Standalone::create();
    host.select_standalone();
    let environment = host.tree.environment();
    let held = kr_controller::singleton::SingletonLock::acquire(
        &environment.singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("this test holds the environment");

    let output = start(host.new_session()).finish("kr new");
    let failure = document(&output, "kr new");
    assert_ne!(output.status.code(), Some(0), "nothing was created");
    assert_eq!(failure["ok"], false, "{failure}");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did not answer within 30 seconds"),
        "the failure says how long it waited: {message}"
    );
    assert!(
        message.contains("another control daemon already owns environment"),
        "and what the daemon it started said: {message}"
    );

    let launched = host.launched();
    assert_eq!(launched.len(), 1, "the command started one daemon");
    let started = Instant::now();
    while !host.running().is_empty() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that could not take the environment ended: {launched:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let daemon =
        rustix::process::Pid::from_raw(i32::try_from(launched[0]).expect("a process number"))
            .expect("a process number");
    assert!(
        rustix::process::test_kill_process(daemon).is_ok(),
        "the daemon that ended by itself still holds its number, because its supervisor has not \
         collected it"
    );
    assert!(!host.answers(), "and nothing answers for the environment");
    drop(held);
}

/// KR-REQ-07.12: a daemon slow to come up is named when the command gives up, is left to come up,
/// and is then the environment's one daemon.
///
/// The daemon this `kr new` starts does not begin until after the command's bound, which is what a
/// daemon waiting on a slow machine or on a person looks like from outside. The command fails with
/// `ENVIRONMENT_UNAVAILABLE`, saying the process it started is still running. It is not ended: it
/// comes up, and the next `kr new` finds it answering, starts nothing, and creates its session
/// there.
#[test]
fn a_daemon_slow_to_come_up_is_named_left_to_come_up_and_then_used() {
    let host = Standalone::create();
    host.select_standalone();
    host.ask_the_scripts(DELAY, "40");

    let output = start(host.new_session()).finish("the first kr new");
    let failure = document(&output, "the first kr new");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did not answer within 30 seconds") && message.contains("still running"),
        "the failure says how long it waited and that what it started is still running: {message}"
    );

    let started = Instant::now();
    while !host.answers() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that was slow to start came up"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = start(host.new_session()).finish("the second kr new");
    let created = document(&output, "the second kr new");
    assert!(output.status.success(), "{created}");
    assert_eq!(
        host.launched().len(),
        1,
        "the second command found the daemon answering and started none"
    );
    let daemon = host.one_daemon();
    host.assert_detached(daemon);
    host.close(&created);
}

/// KR-REQ-07.13, KR-REQ-07.12: with the standalone start selected, nothing is installed and no
/// privilege is sought.
///
/// Each tool a service, lingering or a privilege would be obtained through is replaced on the
/// `PATH` both commands are given by one that records the call and the process that made it, and
/// fails the way it would on a host with no service manager. The daemon `kr new` starts inherits
/// that `PATH`, so it finds the same tools. Neither `kr host startup` nor `kr new` runs any of
/// them. The daemon runs nothing but the read-only queries the allow-list names, and on Linux it
/// does run one: `systemctl --user show`, asking whether there is a user manager. Nothing is
/// written, removed or changed in the home the commands were given, and nothing appears where a
/// per-user service definition would go.
#[test]
fn selecting_and_using_the_standalone_start_installs_nothing_and_seeks_no_privilege() {
    let host = Standalone::create();
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    recording_tools(&tools, &calls);
    let path = format!("{}:/usr/bin:/bin", tools.display());
    // The recording tools record: one run through the same `PATH` is found, and then forgotten.
    let checked = spawning(|| {
        Command::new("/bin/sh")
            .args(["-c", "loginctl enable-linger"])
            .env("PATH", &path)
            .status()
    })
    .expect("runs a recording tool");
    assert!(
        !checked.success(),
        "a recording tool fails as a missing one would"
    );
    let recorded = recorded_calls(&calls);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(
        (recorded[0].tool.as_str(), recorded[0].arguments.clone()),
        ("loginctl", vec!["enable-linger".to_owned()])
    );
    std::fs::remove_file(&calls).expect("forgets the check");
    let before = every_path_under(&host.home);

    let with_tools = |mut command: Command| {
        command
            .env("PATH", &path)
            .env("XDG_CONFIG_HOME", host.home.join(".config"));
        command
    };
    let selected = start(with_tools(host.kr(&[
        "--json",
        "host",
        "startup",
        "--set",
        "standalone",
    ])))
    .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    let output = start(with_tools(host.new_session())).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    let daemon = host.one_daemon();
    host.assert_detached(daemon);
    // What the daemon asks when it is asked about itself, which is what `kr doctor` asks.
    let _: HostInfoResult = host.ask(Method::HostInfo, &());
    host.close(&created);

    let daemons = host.launched();
    let recorded = recorded_calls(&calls);
    for call in &recorded {
        if let Err(refused) = allowed(call, &daemons) {
            panic!("{refused}; everything recorded: {recorded:?}");
        }
    }
    if cfg!(target_os = "linux") {
        assert!(
            recorded.iter().any(|call| {
                daemons.contains(&call.caller)
                    && call.tool == "systemctl"
                    && call.arguments == ["--user", "show", "--property=Version", "--value"]
            }),
            "the daemon's query of the user manager went through the recording tool, in exactly \
             the form it asks, so the tools it runs by name are the ones on the PATH it \
             inherited: {recorded:?}"
        );
    }
    assert!(
        every_path_under(&host.home) == before,
        "nothing was written, removed or changed in the home the commands were given"
    );
    for definitions in [".config/systemd", "Library/LaunchAgents"] {
        assert!(
            !host.home.join(definitions).exists(),
            "no service definition was written: {definitions}"
        );
    }
}

/// KR-REQ-07.13: the allow-list refuses every call that would install, enable, start or obtain
/// anything, from the daemon as from anybody else, and admits the read-only queries and nothing
/// more.
#[test]
fn the_allow_list_refuses_every_mutating_or_privileged_call() {
    let daemon = 4242;
    let call = |caller: u32, tool: &str, arguments: &[&str]| Recorded {
        caller,
        name: "kr-controller".to_owned(),
        tool: tool.to_owned(),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
    };
    for (tool, arguments) in [
        ("sudo", &["true"][..]),
        ("doas", &["true"][..]),
        ("pkexec", &["true"][..]),
        ("runuser", &["-u", "somebody", "true"][..]),
        ("systemctl", &["--user", "enable", "kalareach.service"][..]),
        (
            "systemctl",
            &["--user", "link", "/tmp/kalareach.service"][..],
        ),
        ("systemctl", &["--user", "start", "kalareach.service"][..]),
        ("systemctl", &["show", "--property=Version"][..]),
        (
            "systemd-run",
            &["--user", "--unit", "kalareach", "true"][..],
        ),
        ("loginctl", &["enable-linger"][..]),
        ("loginctl", &["enable-linger", "somebody"][..]),
        (
            "launchctl",
            &["bootstrap", "gui/501", "/tmp/kalareach.plist"][..],
        ),
        ("launchctl", &["load", "/tmp/kalareach.plist"][..]),
        ("launchctl", &["enable", "gui/501/kalareach"][..]),
    ] {
        assert!(
            allowed(&call(daemon, tool, arguments), &[daemon]).is_err(),
            "{tool} {arguments:?} is refused"
        );
    }
    for (tool, arguments) in [
        (
            "systemctl",
            &["--user", "show", "--property=Version", "--value"][..],
        ),
        ("loginctl", &["show-user", "501", "--property=Linger"][..]),
        ("loginctl", &["show-session", "3", "--property=Leader"][..]),
        ("launchctl", &["print", "gui/501"][..]),
    ] {
        assert_eq!(
            allowed(&call(daemon, tool, arguments), &[daemon]),
            Ok(()),
            "{tool} {arguments:?} is a read-only query"
        );
        assert!(
            allowed(&call(daemon + 1, tool, arguments), &[daemon]).is_err(),
            "and made by anything but the daemon, it is refused: {tool} {arguments:?}"
        );
    }
}

/// KR-REQ-07.12, KR-REQ-26.13: the start is selected with no daemon running, and `kr doctor`
/// reports it with the document it came from.
///
/// `kr host startup` shows that nothing is selected, refuses a way of starting this build does not
/// know with nothing written, and selects the standalone start as one validated edit at the next
/// revision, with no daemon asked and none started. `kr new` then starts one, and `kr doctor`
/// reports the selection with the document as its source and as applying at the next start.
/// Clearing it is an edit too, and the report goes back to the product default.
#[test]
fn the_start_is_selected_with_no_daemon_and_the_doctor_names_its_source() {
    let host = Standalone::create();

    let shown = start(host.kr(&["--json", "host", "startup"])).finish("kr host startup");
    let unchosen = document(&shown, "kr host startup");
    assert!(shown.status.success(), "{unchosen}");
    assert_eq!(unchosen["startup"]["controller"], Value::Null, "{unchosen}");
    assert_eq!(unchosen["startup"]["source"], "default", "{unchosen}");

    let refused =
        start(host.kr(&["host", "startup", "--set", "elsewhere"])).finish("kr host startup");
    assert_eq!(refused.status.code(), Some(2), "a usage failure");
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains("standalone") && said.contains("service"),
        "the refusal names what can be chosen: {said}"
    );
    assert!(!host.document().exists(), "and nothing was written");

    let selected = start(host.kr(&["--json", "host", "startup", "--set", "standalone"]))
        .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    assert_eq!(
        chosen["startup"]["source"], "host_configuration",
        "{chosen}"
    );
    assert_eq!(chosen["startup"]["revision"], "1", "{chosen}");
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document was written"))
            .expect("the document is JSON");
    assert_eq!(written["revision"], 1, "{written}");
    assert_eq!(written["startup"]["controller"], "standalone", "{written}");
    assert!(
        host.launched().is_empty(),
        "selecting the start starts nothing"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let reported = |what: &str| {
        // A diagnostic that did not pass makes the command's status a failure, and the document it
        // printed is still the whole report.
        let output = start(host.kr(&["--json", "doctor"])).finish(what);
        let report = document(&output, what);
        report["configuration"]["values"]
            .as_array()
            .and_then(|values| {
                values
                    .iter()
                    .find(|value| value["key"] == "startup.controller")
                    .cloned()
            })
            .unwrap_or_else(|| panic!("{what} reports the startup: {report}"))
    };
    let row = reported("kr doctor");
    assert_eq!(row["value"], "standalone", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");
    assert_eq!(
        row["origin"],
        host.document().display().to_string(),
        "{row}"
    );
    assert_eq!(row["effect"], "next_start", "{row}");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    assert_eq!(none["startup"]["controller"], Value::Null, "{none}");
    let row = reported("kr doctor after the clear");
    assert_eq!(row["value"], "none", "{row}");
    assert_eq!(row["source"], "default", "{row}");
    host.close(&created);
}

/// KR-REQ-07.12: the start is chosen and used on a host where no daemon has ever run.
///
/// Such a host has the environment's identity, which the first command of any kind allocates, and
/// none of the environment's directories. `kr host startup --set standalone` writes the choice
/// there with no daemon running, making the directories it needs as a daemon would, and `kr new`
/// then starts the daemon and creates its session.
#[test]
fn the_start_is_chosen_and_used_where_no_daemon_has_ever_run() {
    let host = Standalone::create();
    std::fs::remove_dir_all(host.tree.paths().runtime_root()).expect("no runtime tree");
    std::fs::remove_dir_all(host.tree.paths().state_root().join("environments"))
        .expect("no environment directories");

    let selected = start(host.kr(&["--json", "host", "startup", "--set", "standalone"]))
        .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    assert!(host.document().is_file(), "the choice was written");

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    host.assert_detached(host.one_daemon());
    host.close(&created);
}

/// Attaches a terminal to a session over its worker's own endpoint, and returns the connection the
/// attachment lives on with it. The attachment lasts as long as the connection does.
async fn terminal_attachment(
    host: &Standalone,
    session_id: SessionId,
    dimensions: Dimensions,
    profile: Option<&str>,
) -> (LocalClient, AttachmentId) {
    let descriptor = kr_ipc::descriptor::read_all(&host.tree.environment())
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .expect("the session's descriptor is published");
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the worker");
    client
        .verify_worker(&descriptor)
        .await
        .expect("the worker answers its descriptor's challenge");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: descriptor.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable(profile.map(str::to_owned)),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    (client, attached.attachment.attachment_id)
}

/// KR-REQ-08.02: `kr status` reports each terminal attachment's presentation and the reason for it.
///
/// Two terminals attach to a session the started daemon holds: one at the session's own size that
/// declared no terminal profile, and one with a qualified profile at another size. Both are shown
/// a projection, each for a reason of its own, and `kr status` says which and why, in text and in
/// `--json`, as the session's own worker reports it. Neither reason passes with time, so what is
/// read does not depend on when it is read.
#[test]
fn status_reports_each_terminal_attachments_presentation_and_its_reason() {
    let host = Standalone::create();
    host.select_standalone();
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let session_id: SessionId = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("parses");
    let display = created["display_number"].to_string();
    let canonical = Dimensions::new(
        created["dimensions"]["columns"].as_u64().expect("columns"),
        created["dimensions"]["rows"].as_u64().expect("rows"),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let ((undeclared_client, undeclared), (smaller_client, smaller)) = runtime.block_on(async {
        (
            terminal_attachment(&host, session_id, canonical, None).await,
            terminal_attachment(
                &host,
                session_id,
                Dimensions::new(canonical.columns() - 20, canonical.rows() - 10),
                Some("xterm-256color"),
            )
            .await,
        )
    });

    let status = start(host.kr(&["--json", "status", &display])).finish("kr status");
    let report = document(&status, "kr status");
    assert!(status.status.success(), "{report}");
    let terminals = report["terminal_attachments"]
        .as_array()
        .unwrap_or_else(|| panic!("kr status lists the terminal attachments: {report}"));
    let reported = |attachment: AttachmentId| {
        terminals
            .iter()
            .find(|entry| entry["attachment_id"] == attachment.to_string())
            .unwrap_or_else(|| panic!("attachment {attachment} is listed: {report}"))
    };
    let entry = reported(undeclared);
    assert_eq!(entry["presentation"], "viewport", "{entry}");
    assert_eq!(
        entry["presentation_reason"], "no_terminal_profile",
        "{entry}"
    );
    let entry = reported(smaller);
    assert_eq!(entry["presentation"], "viewport", "{entry}");
    assert_eq!(entry["presentation_reason"], "size_mismatch", "{entry}");

    let shown = start(host.kr(&["status", &display])).finish("kr status");
    assert!(shown.status.success());
    let printed = String::from_utf8_lossy(&shown.stdout);
    for expected in [
        format!("attachment {undeclared}: viewport (no_terminal_profile)"),
        format!("attachment {smaller}: viewport (size_mismatch)"),
    ] {
        assert!(printed.contains(&expected), "{expected}: {printed}");
    }

    drop((undeclared_client, smaller_client));
    host.close(&created);
}

/// A worker of this test's own for `session_id`, which publishes its descriptor, proves itself as a
/// session's worker does and answers `session.read`, and never answers `events.snapshot`.
///
/// It runs on the runtime it is started from, for as long as that runtime runs.
async fn a_worker_that_withholds_its_attachments(host: &Standalone, session_id: SessionId) {
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};

    let environment = host.tree.environment();
    let environment_id = host.tree.environment_id();
    let display = kr_protocol::session::DisplayNumber::new(9);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = kr_ipc::verify::WorkerIdentity::generate(
        session_id,
        SessionEpoch::V1,
        boot.clone(),
        process.clone(),
        kr_protocol::hello::PROTOCOL_VERSION,
    )
    .expect("a session key");
    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let endpoint_text = endpoint.as_text();
    kr_ipc::descriptor::publish(
        &environment,
        &kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            boot_identity: boot.clone(),
            process_start_identity: process,
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: endpoint_text.clone(),
            worker_public_key: *identity.public_key(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: kr_protocol::scalars::TimestampMs::new(0),
        },
    )
    .expect("publishes the descriptor");
    let read = kr_protocol::session::SessionReadResult {
        session: kr_protocol::session::SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            state: kr_protocol::session::SessionState::Live,
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            shell_path: "/bin/sh".to_owned(),
            cwd: "/".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            dimensions: Dimensions::new(120, 40),
            attachment_count: kr_protocol::scalars::U64::new(1),
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
        },
        endpoint: Nullable::some(endpoint_text.clone()),
        launch_profile: Nullable::null(),
        last_command_block: Nullable::null(),
        outstanding_launches: Nullable::null(),
    };
    let boot_epoch = kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(async move {
        while let Ok((connection, peer)) = listener.accept().await {
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                let answer = match frame {
                    ControlFrame::Hello(_) => {
                        ControlFrame::HelloAck(Box::new(kr_protocol::local::LocalHelloAck {
                            selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                            role: kr_protocol::local::LocalRole::Worker,
                            connection_id,
                            environment_id,
                            boot_identity: boot.clone(),
                            peer: peer.to_wire(),
                            action_window: kr_protocol::hello::ActionWindow {
                                action_window_id: kr_protocol::ids::ActionWindowId::new(
                                    "withholding-worker",
                                )
                                .expect("a window identifier"),
                                connection_id,
                                boot_epoch,
                                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                                valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
                            },
                            capabilities: CanonicalSet::new(),
                            max_receive: kr_protocol::hello::ReceiveLimits::default(),
                        }))
                    }
                    ControlFrame::VerifyChallenge(challenge) => ControlFrame::VerifyProof(
                        identity
                            .answer(&challenge, &endpoint_text)
                            .expect("proves itself"),
                    ),
                    ControlFrame::Request(request)
                        if request.method.method() == Some(Method::SessionRead) =>
                    {
                        ControlFrame::Response(Response {
                            request_id: request.request_id,
                            outcome: Outcome::Ok(ParamsValue::from_typed(&read).expect("encodes")),
                        })
                    }
                    // `events.snapshot`, and anything else, is never answered.
                    _ => continue,
                };
                if writer.write_message(&answer).await.is_err() {
                    break;
                }
            }
        }
    });
}

/// KR-REQ-08.02: a worker that answers the session read and never the question about its
/// attachments leaves `kr status` the session, and the attachments are reported as not read.
///
/// `kr status` waits its bound for the second answer, prints the session it has, and says why the
/// attachments are missing: `terminal_attachments` is null and `terminal_attachments_unread` names
/// the bound.
#[test]
fn status_reports_the_session_when_its_worker_withholds_the_attachments() {
    let host = Standalone::create();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    let session_id = SessionId::new(kr_ipc::new_uuid());
    runtime.block_on(a_worker_that_withholds_its_attachments(&host, session_id));

    let started = Instant::now();
    let output = start(host.kr(&["--json", "status", &session_id.to_string()])).finish("kr status");
    let report = document(&output, "kr status");
    assert!(output.status.success(), "{report}");
    assert_eq!(report["session_id"], session_id.to_string(), "{report}");
    assert_eq!(report["state"], "live", "{report}");
    assert_eq!(report["terminal_attachments"], Value::Null, "{report}");
    let unread = report["terminal_attachments_unread"]
        .as_str()
        .unwrap_or_default();
    assert!(
        unread.contains("did not answer within 10 seconds"),
        "the status says why the attachments are missing: {report}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "and it waited its bound rather than for ever: {:?}",
        started.elapsed()
    );
    drop(runtime);
}

/// KR-REQ-07.12: a supervisor still waiting to start its daemon when its test ends starts nothing,
/// and the test's teardown waits for it.
///
/// The daemon is held back past the command's bound, and the test ends while it is held: what a
/// failing test's teardown does, run here on purpose. The supervisor sees the lifeline close, starts
/// no daemon and ends, and teardown has waited for it by the time it returns. The command then gives
/// up at its bound as it would with no daemon.
#[test]
fn a_supervisor_still_waiting_when_its_test_ends_starts_nothing() {
    let mut host = Standalone::create();
    host.select_standalone();
    host.ask_the_scripts(DELAY, "40");
    let running = start(host.new_session());
    let begun = Instant::now();
    while host.identities(STARTS).0.is_empty() {
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the supervisor recorded itself"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let supervisor = host.identities(STARTS).0.remove(0);

    assert_eq!(host.end_what_was_started(), Vec::<String>::new());
    assert_eq!(
        kr_ipc::identity::process_state(&supervisor),
        ProcessState::Ended,
        "the supervisor ended with its test"
    );
    assert!(host.launched().is_empty(), "and started no daemon");

    let output = running.finish("kr new");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
}

/// A record names a process that ended before it was recorded as one that has ended, rather than
/// failing: on macOS the kernel stops describing a process once it has ended, collected or not,
/// which is what a daemon that could not take the environment does.
#[test]
fn a_process_that_ended_before_it_was_recorded_is_recorded_as_ended() {
    let mut child = spawning(|| Command::new("/usr/bin/true").spawn()).expect("starts a process");
    let pid = child.id();
    let begun = Instant::now();
    // Ended, and not collected: this test has not waited for it yet.
    while match kr_ipc::identity::query_process(pid) {
        ProcessQuery::Gone => false,
        ProcessQuery::Present(identity) => {
            kr_ipc::identity::process_state(&identity) != ProcessState::Ended
        }
        ProcessQuery::CannotEstablish(error) => panic!("{error}"),
    } {
        assert!(begun.elapsed() < LIVENESS_DEADLINE, "the process ended");
        std::thread::sleep(Duration::from_millis(20));
    }
    let line = record_line(pid);
    let (number, identity) = line
        .trim_end()
        .split_once('\t')
        .expect("a number and an identity");
    assert_eq!(number, pid.to_string());
    let identity: kr_protocol::identity::ProcessStartIdentity =
        serde_json::from_str(identity).expect("an identity");
    assert_eq!(
        kr_ipc::identity::process_state(&identity),
        ProcessState::Ended,
        "{line}"
    );
    let _ = child.wait();
}

/// A record cut off part way is reported, and every record that can be read is still waited for.
#[test]
fn a_partial_record_is_reported_and_the_others_are_still_waited_for() {
    let mut host = Standalone::create();
    let ended = serde_json::to_string(&kr_ipc::identity::ended_process_identity(4242))
        .expect("encodes an identity");
    let starts = host.tree.root().join(STARTS);
    std::fs::write(&starts, format!("4242\t{ended}\n4243\t{{\"pid\":\"42\n"))
        .expect("writes the records");

    let unresolved = host.end_what_was_started();
    assert_eq!(unresolved.len(), 1, "{unresolved:?}");
    assert!(unresolved[0].contains("names no process"), "{unresolved:?}");
    // Put right, so this test's own teardown finds nothing to keep the tree for.
    std::fs::write(&starts, format!("4242\t{ended}\n")).expect("writes the records");
}

/// A test that fails with a partial record keeps its tree and does not end the suite: the teardown
/// that runs while it unwinds reports the record rather than panicking a second time.
#[test]
fn a_failing_test_with_a_partial_record_keeps_its_tree_and_does_not_end_the_suite() {
    let root = std::sync::Mutex::new(None);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = Standalone::create();
        *root.lock().expect("the root") = Some(host.tree.root().to_path_buf());
        std::fs::write(host.tree.root().join(LAUNCHED), "4243\t{\"pid\":\"42\n")
            .expect("writes a partial record");
        panic!("a test that fails with a partial record");
    }));
    assert!(
        failed.is_err(),
        "the test failed, and this process is still here"
    );
    let root = root
        .lock()
        .expect("the root")
        .take()
        .expect("the tree was made");
    assert!(root.is_dir(), "the tree was kept for somebody to look at");
    // Nothing runs in it: the only record names no process. This test made it, so it removes it.
    std::fs::remove_dir_all(&root).expect("removes the kept tree");
}

// ------------------------------------------------------------------------------------------------
// The service start
// ------------------------------------------------------------------------------------------------

/// Set where the service-start tests must run: a host with no user service manager then fails
/// them, rather than saying why they did not run.
const REQUIRE_SERVICE_MANAGER: &str = "KR_REQUIRE_SERVICE_MANAGER";

/// How long one call to a service manager in a test's teardown may take.
const TEARDOWN_BOUND: Duration = Duration::from_secs(60);

/// The installation the service-start tests run, on the internal disk: `kr` and its guard, the
/// worker, the real daemon, and beside them the `kr-controller` a definition names.
///
/// That `kr-controller` is a script that hands over, with `exec`, to the real daemon with its keys
/// in the environment's own `secrets` directory, so that nothing reaches the credential store of the
/// person running the tests. The handover replaces the script's process rather than starting a
/// child, so the process the service manager started is the daemon itself, and the manager is the
/// daemon's parent.
fn service_installation() -> &'static Path {
    static PLACED: OnceLock<PathBuf> = OnceLock::new();
    PLACED.get_or_init(|| {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller"),
            beside_this_test("kr-worker"),
        ) else {
            panic!(
                "the kr-controller and kr-worker executables are not built beside this test, so \
                 this check cannot run; a workspace test run builds them, and so does \
                 `cargo build -p kr-controller -p kr-worker`"
            );
        };
        let directory = support::command_binaries().join("service");
        std::fs::create_dir(&directory).expect("a directory for the service installation");
        for source in [
            Path::new(env!("CARGO_BIN_EXE_kr")),
            Path::new(env!("CARGO_BIN_EXE_kr-attach-guard")),
        ] {
            let name = source.file_name().expect("the binary has a name");
            kr_ipc::testing::place_and_start_once(source, &directory.join(name), &["--version"]);
        }
        kr_ipc::testing::place_and_start_once(
            &worker,
            &directory.join("kr-worker"),
            &["--version"],
        );
        let daemon = directory.join(DAEMON_UNDER_TEST);
        kr_ipc::testing::place_and_start_once(&controller, &daemon, &["--version"]);
        let source = directory.join("kr-controller.sh");
        std::fs::write(
            &source,
            format!(
                "#!/bin/sh\nexec '{}' --secret-store file \"$@\"\n",
                daemon.display()
            ),
        )
        .expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory
    })
}

/// Runs a command to its end within `bound`, ending and collecting it when it has not ended.
///
/// For teardown, which must not panic: every failure is returned as what it was.
fn bounded(mut command: Command, bound: Duration) -> Result<Output, String> {
    let what = format!("{command:?}");
    let mut child = spawning(|| {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .map_err(|error| format!("{what} could not be started: {error}"))?;
    let stdout = child.stdout.take().map(read_aside);
    let stderr = child.stderr.take().map(read_aside);
    let begun = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if begun.elapsed() < bound => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                // This test's own child, not collected yet, so the number is still its.
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what} did not end within {bound:?}"));
            }
        }
    };
    let collect = |stream: Option<Receiver<Vec<u8>>>| {
        stream
            .and_then(|stream| stream.recv_timeout(STREAMS_DEADLINE).ok())
            .unwrap_or_default()
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

/// The parent of a process of this user's, and the parent's name.
fn parent_of(pid: u32) -> (u32, String) {
    let asked = |arguments: &[&str]| {
        let output =
            spawning(|| Command::new("/bin/ps").args(arguments).output()).expect("runs ps");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    let parent: u32 = asked(&["-o", "ppid=", "-p", &pid.to_string()])
        .parse()
        .expect("ps names the parent");
    let name = asked(&["-o", "comm=", "-p", &parent.to_string()]);
    (parent, name)
}

/// A user service manager of a test's own: a second `systemd --user`, run in a scope of the user
/// manager of whoever runs the tests, with that scope's cgroup delegated to it.
///
/// Its home is the test's own, so it reads unit files from there, and its runtime directory is its
/// own, so `systemctl --user` reaches it through `XDG_RUNTIME_DIR` and nothing else. It starts
/// nothing by itself: its default target has no dependencies. Ending the scope ends every process
/// in it, the manager and whatever the manager started, workers included, which is how a test's
/// teardown ends it. Where that cannot be established, the test's tree and the manager's runtime
/// directory are both kept.
#[cfg(target_os = "linux")]
struct UserManager {
    /// The scope it runs in.
    scope: String,
    /// The manager, which `systemd-run` became: this test process's own child.
    process: Option<Child>,
    /// Its runtime directory, outside the test's tree.
    runtime: PathBuf,
    /// What keeps the test's tree when this manager's scope cannot be established as ended.
    holder: teardown::Holder,
}

#[cfg(target_os = "linux")]
impl UserManager {
    /// Starts a manager whose home is `home`, or says why none can be started here.
    fn start(home: &Path, holder: teardown::Holder) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let program = ["/usr/lib/systemd/systemd", "/lib/systemd/systemd"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_file())
            .ok_or("this host has no systemd to run a user manager with")?;
        let mut asked = Command::new("systemctl");
        asked.args(["--user", "show", "--property=Version", "--value"]);
        let answered = bounded(asked, STREAMS_DEADLINE)?;
        if !answered.status.success() {
            return Err(format!(
                "no user manager answers for whoever runs these tests, so there is no scope to run \
                 a manager of the test's own in: {}",
                String::from_utf8_lossy(&answered.stderr).trim()
            ));
        }
        let units = home.join(".config/systemd/user");
        std::fs::create_dir_all(&units).map_err(|error| error.to_string())?;
        std::fs::write(
            units.join("kr-test-idle.target"),
            "[Unit]\nDescription=Nothing, so that this manager starts only what a test asks for\n\
             DefaultDependencies=no\n",
        )
        .map_err(|error| error.to_string())?;
        let runtime =
            std::env::temp_dir().join(format!("krm-{}", &kr_ipc::new_uuid().to_string()[..8]));
        std::fs::create_dir(&runtime).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let log = std::fs::File::create(runtime.join("manager.log"))
            .map_err(|error| error.to_string())?;
        let scope = format!("kr-test-manager-{}.scope", kr_ipc::new_uuid());
        let process = spawning(|| {
            let mut command = Command::new("systemd-run");
            command
                .args(["--user", "--scope", "--quiet", "--property=Delegate=yes"])
                .arg(format!("--unit={scope}"))
                .args(["--", "env", "-i"])
                .arg(format!("HOME={}", home.display()))
                .arg(format!("XDG_RUNTIME_DIR={}", runtime.display()))
                .arg("PATH=/usr/bin:/bin");
            command
                .arg(&program)
                .args([
                    "--user",
                    "--unit=kr-test-idle.target",
                    "--log-target=console",
                ])
                .stdin(Stdio::null())
                .stdout(log.try_clone().expect("the log twice"))
                .stderr(log)
                .spawn()
        })
        .map_err(|error| format!("systemd-run could not be started: {error}"))?;
        let mut manager = Self {
            scope,
            process: Some(process),
            runtime,
            holder,
        };
        let begun = Instant::now();
        loop {
            let mut asked = manager.systemctl(&["show", "--property=Version", "--value"]);
            asked.env_remove("DBUS_SESSION_BUS_ADDRESS");
            if bounded(asked, STREAMS_DEADLINE).is_ok_and(|answer| answer.status.success()) {
                return Ok(manager);
            }
            let ended = manager
                .process
                .as_mut()
                .is_some_and(|process| matches!(process.try_wait(), Ok(Some(_))));
            if ended || begun.elapsed() > LIVENESS_DEADLINE {
                return Err(format!(
                    "the test's user manager did not come up: {}",
                    std::fs::read_to_string(manager.runtime.join("manager.log"))
                        .unwrap_or_default()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `systemctl --user` pointed at this manager and at nothing else: with no session bus named,
    /// a manager that did not answer on its own socket is not replaced by the user's own.
    fn systemctl(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new("systemctl");
        command
            .arg("--user")
            .args(arguments)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        command
    }

    /// The manager's own process.
    fn pid(&self) -> u32 {
        self.process.as_ref().expect("the manager is running").id()
    }
}

#[cfg(target_os = "linux")]
impl Drop for UserManager {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;

        // The scope belongs to the user manager of whoever runs the tests, so it is asked there.
        let mut stop = Command::new("systemctl");
        stop.args(["--user", "stop", &self.scope]);
        let stopped = bounded(stop, TEARDOWN_BOUND);
        if !stopped.as_ref().is_ok_and(|answer| answer.status.success()) {
            eprintln!("stopping {}: {stopped:?}", self.scope);
            let mut kill = Command::new("systemctl");
            kill.args(["--user", "kill", "--signal=SIGKILL", &self.scope]);
            let killed = bounded(kill, TEARDOWN_BOUND);
            eprintln!("killing what is in {}: {killed:?}", self.scope);
        }
        if let Some(mut process) = self.process.take() {
            let begun = Instant::now();
            while matches!(process.try_wait(), Ok(None)) && begun.elapsed() < STREAMS_DEADLINE {
                std::thread::sleep(Duration::from_millis(20));
            }
            // This test's own child, not collected yet, so the number is still its.
            let _ = process.kill();
            let _ = process.wait();
        }
        // Whether the scope is gone is asked of the manager that held it: a scope with nothing
        // left in it goes by itself, and the manager then describes it as inactive. Only an answer
        // that says so counts; a question that failed establishes nothing.
        let mut shown = Command::new("systemctl");
        shown.args([
            "--user",
            "show",
            "--property=ActiveState",
            "--value",
            &self.scope,
        ]);
        let state = bounded(shown, STREAMS_DEADLINE).and_then(|answer| {
            if answer.status.success() {
                Ok(String::from_utf8_lossy(&answer.stdout).trim().to_owned())
            } else {
                Err(format!(
                    "systemctl --user show answered {:?}: {}",
                    answer.status.code(),
                    String::from_utf8_lossy(&answer.stderr).trim()
                ))
            }
        });
        if !matches!(state.as_deref(), Ok("inactive" | "failed")) {
            // Both are kept: something may still be running in them.
            self.holder.hold(format!(
                "the scope {} of the test's user manager could not be established as ended ({state:?}); \
                 its runtime directory is kept at {}",
                self.scope,
                self.runtime.display()
            ));
            return;
        }
        // The manager makes directories nobody may write in its runtime directory, which could not
        // be removed otherwise.
        let mut waiting = vec![self.runtime.clone()];
        while let Some(directory) = waiting.pop() {
            let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
            for entry in std::fs::read_dir(&directory)
                .into_iter()
                .flatten()
                .flatten()
            {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    waiting.push(entry.path());
                }
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&self.runtime) {
            eprintln!(
                "the test's user manager left {}: {error}",
                self.runtime.display()
            );
        }
    }
}

/// A unit file's command line that creates `mark` and nothing else: each word quoted as systemd
/// reads it, with its specifier character doubled, and environment expansion off.
#[cfg(target_os = "linux")]
fn touching(mark: &Path) -> String {
    let word = |value: &str| {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
        )
    };
    format!(
        "{} {} {}",
        word(":/usr/bin/touch"),
        word("--"),
        word(&mark.display().to_string())
    )
}

/// A D-Bus address for the socket at `path`: letters, digits and `-_/.` as they are, and every
/// other byte as `%` and its two hex digits, which every D-Bus library reads back.
#[cfg(target_os = "linux")]
fn bus_address(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    let mut address = "unix:path=".to_owned();
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-_/.".contains(byte) {
            address.push(char::from(*byte));
        } else {
            address.push_str(&format!("%{byte:02x}"));
        }
    }
    address
}

/// A host tree of a test's own where the service start is chosen: a home of the test's own that
/// the definition is written in, and the user service manager that starts the daemon.
///
/// On macOS that manager is launchd, and the definition is loaded into this user's own domain under
/// a label that names the tree's own environment, so no other test has it. On Linux it is a
/// [`UserManager`] of the test's own.
///
/// However a test ends, the daemon the manager started is ended through the manager first. On
/// Linux the test's own manager ends next, and with its scope everything it started, workers
/// included; on macOS the tree then ends every worker the daemon recorded. A tree in which that
/// cannot be established is kept.
struct ServiceHost {
    // Dropped first, while the tree is still there to be kept.
    #[cfg(target_os = "linux")]
    manager: UserManager,
    tree: teardown::Tree,
    home: PathBuf,
}

impl Drop for ServiceHost {
    fn drop(&mut self) {
        if let Err(why) = self.end_the_daemon() {
            self.tree.hold(why);
        }
    }
}

impl ServiceHost {
    /// A tree with a user service manager, or none where this host has no manager to test with,
    /// having said why; a host that sets [`REQUIRE_SERVICE_MANAGER`] fails instead.
    fn create() -> Option<Self> {
        let tree = teardown::Tree::create();
        let home = tree.root().join("home");
        std::fs::create_dir_all(&home).expect("a home of this test's own");
        #[cfg(target_os = "macos")]
        {
            let domain = format!("user/{}", kr_ipc::paths::current_uid());
            let mut print = Command::new("/bin/launchctl");
            print.args(["print", &domain]);
            match bounded(print, STREAMS_DEADLINE) {
                Ok(printed) if printed.status.success() => Some(Self { tree, home }),
                answered => Self::not_here(&format!(
                    "launchd has no {domain} domain for this user to load a definition into: \
                     {answered:?}"
                )),
            }
        }
        #[cfg(target_os = "linux")]
        {
            match UserManager::start(&home, tree.holder()) {
                Ok(manager) => Some(Self {
                    manager,
                    tree,
                    home,
                }),
                Err(why) => Self::not_here(&why),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            drop((tree, home));
            Self::not_here("this platform has no service start")
        }
    }

    /// Says why a service test did not run, or fails it where it has to run.
    fn not_here(why: &str) -> Option<Self> {
        assert!(
            std::env::var_os(REQUIRE_SERVICE_MANAGER).is_none(),
            "{REQUIRE_SERVICE_MANAGER} is set and the service start cannot be tested here: {why}"
        );
        eprintln!("the service start is not tested here: {why}");
        None
    }

    /// The label the service manager knows this environment's daemon by.
    fn label(&self) -> String {
        format!("kr-controller-{}", self.tree.environment_id())
    }

    /// Where the definition of this environment's daemon belongs, in the test's own home.
    fn definition(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", self.label()))
        } else {
            self.home
                .join(".config/systemd/user")
                .join(format!("{}.service", self.label()))
        }
    }

    /// Where `kr host startup` records the definition it wrote.
    fn record(&self) -> PathBuf {
        self.tree
            .environment()
            .state_dir()
            .join("controller-service.json")
    }

    /// Where this environment's configuration document is.
    fn document(&self) -> PathBuf {
        self.tree.environment().state_dir().join("config.json")
    }

    /// `kr` from the service installation, against this tree, this home and this host's manager.
    fn kr(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(service_installation().join("kr"));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.tree.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.paths().state_root(),
            )
            .current_dir(service_installation())
            .stdin(Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        #[cfg(target_os = "linux")]
        command.env("XDG_RUNTIME_DIR", &self.manager.runtime);
        command
    }

    /// `kr new` for an invisible, headless session of `/bin/sh` working in this tree.
    fn new_session(&self) -> Command {
        let cwd = self.tree.root().display().to_string();
        self.kr(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ])
    }

    /// Chooses the service start as a person does, and returns what `kr host startup` reported.
    fn select_service(&self) -> Value {
        let output = start(self.kr(&["--json", "host", "startup", "--set", "service"]))
            .finish("kr host startup");
        let chosen = document(&output, "kr host startup");
        assert!(
            output.status.success(),
            "{chosen}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(chosen["startup"]["controller"], "service", "{chosen}");
        let definition = &chosen["startup"]["definition"];
        assert_eq!(definition["state"], "matches", "{chosen}");
        assert_eq!(definition["label"], self.label(), "{chosen}");
        assert_eq!(
            definition["path"],
            self.definition().display().to_string(),
            "{chosen}"
        );
        chosen
    }

    /// Has the test's user manager read its unit files again, as a person does after changing
    /// one.
    #[cfg(target_os = "linux")]
    fn reload(&self) {
        let reloaded = bounded(self.manager.systemctl(&["daemon-reload"]), STREAMS_DEADLINE)
            .expect("the manager reloads");
        assert!(
            reloaded.status.success(),
            "the manager reloads: {}",
            String::from_utf8_lossy(&reloaded.stderr)
        );
    }

    /// Closes a session this test created, through the daemon that holds it.
    fn close(&self, created: &Value) {
        let session = created["session_id"]
            .as_str()
            .expect("a session identifier");
        let output = start(self.kr(&["--json", "close", session])).finish("kr close");
        let closed = document(&output, "kr close");
        assert!(output.status.success(), "{closed}");
    }

    /// Whether anything answers on this environment's endpoint now.
    fn answers(&self) -> bool {
        answers(&self.tree.environment())
    }

    /// Asks this environment's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        ask(&self.tree.environment(), method, params)
    }

    /// The process the service manager says the daemon's job is running, when it says one is.
    fn daemon(&self) -> Option<u32> {
        #[cfg(target_os = "macos")]
        {
            let uid = kr_ipc::paths::current_uid();
            [format!("gui/{uid}"), format!("user/{uid}")]
                .into_iter()
                .find_map(|domain| {
                    let mut print = Command::new("/bin/launchctl");
                    print.args(["print", &format!("{domain}/{}", self.label())]);
                    let printed = bounded(print, STREAMS_DEADLINE).ok()?;
                    String::from_utf8_lossy(&printed.stdout)
                        .lines()
                        .find_map(|line| line.strip_prefix("\tpid = ")?.trim().parse().ok())
                })
        }
        #[cfg(target_os = "linux")]
        {
            let unit = format!("{}.service", self.label());
            let shown = bounded(
                self.manager
                    .systemctl(&["show", "--property=MainPID", "--value", &unit]),
                STREAMS_DEADLINE,
            )
            .ok()?;
            String::from_utf8_lossy(&shown.stdout)
                .trim()
                .parse()
                .ok()
                .filter(|pid| *pid != 0)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Establishes that the service manager started the daemon: its parent is the manager, it
    /// leads a process group of its own outside the session this test runs in, it has no
    /// controlling terminal, and it works in the environment's own directory.
    fn assert_started_by_the_manager(&self, pid: u32) {
        let (parent, name) = parent_of(pid);
        #[cfg(target_os = "macos")]
        assert!(
            parent == 1 && name.ends_with("launchd"),
            "launchd started the daemon: its parent is {parent} ({name})"
        );
        #[cfg(target_os = "linux")]
        assert!(
            parent == self.manager.pid() && name == "systemd",
            "the user manager started the daemon: its parent is {parent} ({name}), and the \
             manager is {}",
            self.manager.pid()
        );
        let process = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process number"))
            .expect("a process number");
        assert_eq!(
            rustix::process::getpgid(Some(process)).expect("its process group"),
            process,
            "the daemon leads a process group of its own"
        );
        assert_ne!(
            rustix::process::getsid(Some(process)).expect("its session"),
            rustix::process::getsid(None).expect("this test's session"),
            "and is outside the session this test and its commands run in"
        );
        assert_eq!(
            kr_ipc::identity::controlling_terminal(pid).expect("its controlling terminal"),
            None,
            "and has no controlling terminal"
        );
        assert_eq!(
            working_directory(pid),
            std::fs::canonicalize(self.tree.environment().state_dir())
                .expect("the state directory"),
            "and works in the environment's own directory"
        );
    }

    /// Ends the daemon through the service manager that started it, and says what could not be
    /// established as ended.
    fn end_the_daemon(&self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let uid = kr_ipc::paths::current_uid();
            for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
                let target = format!("{domain}/{}", self.label());
                let loaded = |target: &str| {
                    let mut print = Command::new("/bin/launchctl");
                    print.args(["print", target]);
                    bounded(print, STREAMS_DEADLINE).map(|printed| printed.status.success())
                };
                if !loaded(&target)? {
                    continue;
                }
                let mut bootout = Command::new("/bin/launchctl");
                bootout.args(["bootout", &target]);
                let removed = bounded(bootout, TEARDOWN_BOUND)?;
                if loaded(&target)? {
                    return Err(format!(
                        "{target} is still loaded after it was removed: {}",
                        String::from_utf8_lossy(&removed.stderr).trim()
                    ));
                }
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            // Ending the manager's scope ends the daemon too; stopping it here first means nothing
            // is started while the rest ends.
            let unit = format!("{}.service", self.label());
            let stopped = bounded(self.manager.systemctl(&["stop", &unit]), TEARDOWN_BOUND)?;
            let shown = bounded(
                self.manager
                    .systemctl(&["show", "--property=ActiveState", "--value", &unit]),
                STREAMS_DEADLINE,
            )?;
            match String::from_utf8_lossy(&shown.stdout).trim() {
                "inactive" | "failed" => Ok(()),
                state => Err(format!(
                    "{unit} is {state} after it was stopped: {}",
                    String::from_utf8_lossy(&stopped.stderr).trim()
                )),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Ok(())
        }
    }
}

/// KR-REQ-07.12: with the service start chosen, three first invocations at once converge on the
/// one control daemon the user's service manager starts.
///
/// `kr host startup --set service` writes the definition in the test's own home and has the
/// manager take it. Three `kr new` commands then start together with no daemon running, and each
/// asks the manager to start the daemon. The manager starts one: its parent is the manager, the
/// environment's generation advanced once, and every session the three commands created is in its
/// registry. The commands write nothing in the home: asking a manager to start what it was given
/// installs nothing.
#[test]
fn three_first_invocations_at_once_converge_on_the_one_daemon_the_service_manager_starts() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let before = every_path_under(&host.home);

    let started: Vec<Running> = (0..3).map(|_| start(host.new_session())).collect();
    let mut sessions = Vec::new();
    let mut documents = Vec::new();
    for (index, running) in started.into_iter().enumerate() {
        let what = format!("kr new {index}");
        let output = running.finish(&what);
        let created = document(&output, &what);
        assert!(
            output.status.success(),
            "{what} created its session: {created}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(created["state"], "live", "{what}: {created}");
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        sessions.push(session_id);
        documents.push(created);
    }

    let daemon = host
        .daemon()
        .expect("the service manager reports the daemon it started");
    host.assert_started_by_the_manager(daemon);
    let info: HostInfoResult = host.ask(Method::HostInfo, &());
    assert_eq!(info.environment_id, host.tree.environment_id());
    assert_eq!(
        info.generation.get(),
        1,
        "the environment's generation advanced once, for the one daemon the manager started"
    );
    let listed: SessionListResult = host.ask(
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::some(host.tree.environment_id()),
            include_closed: false,
        },
    );
    for session_id in &sessions {
        assert!(
            listed
                .sessions
                .iter()
                .any(|summary| summary.session_id == *session_id),
            "session {session_id} is in the one daemon's registry: {:?}",
            listed.sessions
        );
    }
    assert!(
        every_path_under(&host.home) == before,
        "kr new wrote, removed or changed nothing in the home: it only asked the manager"
    );
    for created in &documents {
        host.close(created);
    }
}

/// KR-REQ-07.12, KR-REQ-26.04: the service start's definition and its record are what
/// `kr host startup --set service` wrote, `kr doctor` reports the choice, its source and that the
/// definition matches, and `--clear` removes the definition and its record without ending the
/// daemon, which keeps serving.
#[test]
fn clearing_the_service_start_removes_its_definition_and_record_and_the_daemon_keeps_serving() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    assert!(host.definition().is_file(), "the definition was written");
    let record: Value =
        serde_json::from_slice(&std::fs::read(host.record()).expect("the record was written"))
            .expect("the record is JSON");
    assert_eq!(
        record["path"],
        host.definition().display().to_string(),
        "the record names the definition: {record}"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let daemon = host
        .daemon()
        .expect("the service manager reports the daemon it started");

    // A diagnostic that did not pass makes the command's status a failure, and the document it
    // printed is still the whole report.
    let reported = |what: &str| {
        let output = start(host.kr(&["--json", "doctor"])).finish(what);
        document(&output, what)
    };
    let report = reported("kr doctor");
    let row = report["configuration"]["values"]
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["key"] == "startup.controller")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the startup: {report}"));
    assert_eq!(row["value"], "service", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");
    let check = report["doctor"]["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["id"] == "startup-definition")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the definition: {report}"));
    assert_eq!(check["status"], "ok", "{check}");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    assert_eq!(none["startup"]["controller"], Value::Null, "{none}");
    let removed: Vec<&str> = none["removed"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it removed: {none}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for path in [host.definition(), host.record()] {
        assert!(
            removed.contains(&path.display().to_string().as_str()),
            "{} is among what the clear removed: {none}",
            path.display()
        );
        assert!(!path.exists(), "{} is gone", path.display());
    }
    assert!(host.answers(), "and the daemon keeps serving");
    assert_eq!(
        host.daemon(),
        Some(daemon),
        "the same daemon, which nothing ended"
    );
    let listed = start(host.kr(&["--json", "list"])).finish("kr list");
    assert!(
        listed.status.success(),
        "a command reaches it: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let report = reported("kr doctor after the clear");
    let row = report["configuration"]["values"]
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["key"] == "startup.controller")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the startup: {report}"));
    assert_eq!(row["value"], "none", "{row}");
    assert_eq!(row["source"], "default", "{row}");
    assert!(
        report["doctor"]["checks"]
            .as_array()
            .is_some_and(|checks| checks
                .iter()
                .all(|check| check["id"] != "startup-definition")),
        "and no definition is left to report: {report}"
    );
    host.close(&created);
}

/// KR-REQ-07.12, KR-REQ-26.04: a definition kr did not write, under the label this environment's
/// daemon would have, is refused and left exactly as it was: nothing is recorded, the choice is not
/// made, and the manager is asked to load or start nothing under that label.
#[test]
fn a_foreign_definition_under_the_same_label_is_refused_and_left_as_it_was() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let foreign = b"# another program's definition, under the label this environment would use\n";
    std::fs::create_dir_all(host.definition().parent().expect("a directory"))
        .expect("the directory definitions live in");
    std::fs::write(host.definition(), foreign).expect("writes a foreign definition");

    let output = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup");
    let refused = document(&output, "kr host startup");
    assert_eq!(output.status.code(), Some(2), "refused: {refused}");
    let message = refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&host.definition().display().to_string())
            && message.contains("did not write"),
        "the refusal names the definition and whose it is not: {message}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the foreign definition"),
        foreign,
        "the definition is left exactly as it was"
    );
    assert!(!host.record().exists(), "nothing was recorded");
    assert!(!host.document().exists(), "and the choice was not made");
    assert_eq!(
        host.daemon(),
        None,
        "and nothing was started under the label"
    );
    assert!(!host.answers());
}

/// KR-REQ-07.12: with the service start chosen, a definition that was changed after kr wrote it, or
/// that has gone, stops `kr new` with a failure that names it and the setup action. The command
/// replaces nothing and starts nothing.
#[test]
fn a_definition_that_was_changed_or_has_gone_is_named_and_never_replaced() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let mut changed = std::fs::read(host.definition()).expect("the definition");
    changed.extend_from_slice(b"\n");
    std::fs::write(host.definition(), &changed).expect("changes the definition");

    let output = start(host.new_session()).finish("kr new with the definition changed");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("changed") && message.contains("kr host startup --set service"),
        "the failure names what is wrong and what to do about it: {message}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "the changed definition was not replaced"
    );

    std::fs::remove_file(host.definition()).expect("removes the definition");
    let output = start(host.new_session()).finish("kr new with the definition gone");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("missing") && message.contains("kr host startup --set service"),
        "the failure names what is wrong and what to do about it: {message}"
    );
    assert!(
        !host.definition().exists(),
        "and nothing was written in its place"
    );
    assert_eq!(host.daemon(), None, "nothing was started");
    assert!(!host.answers());
}

/// KR-REQ-07.12: the service start is chosen and used on a host where no daemon has ever run.
///
/// Such a host has the environment's identity and none of the environment's directories.
/// `kr host startup --set service` makes the directories the record lives in, writes and records the
/// definition, and `kr new` then has the manager start the daemon and creates its session.
#[test]
fn the_service_start_is_chosen_and_used_where_no_daemon_has_ever_run() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    std::fs::remove_dir_all(host.tree.paths().runtime_root()).expect("no runtime tree");
    std::fs::remove_dir_all(host.tree.paths().state_root().join("environments"))
        .expect("no environment directories");

    host.select_service();
    assert!(host.record().is_file(), "the record was written");
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the service manager reports the daemon it started"),
    );
    host.close(&created);
}

/// KR-REQ-07.12: a service manager holding anything but the definition kr wrote is not asked to
/// start it, and kr does not change what it holds either.
///
/// The file is exactly what kr wrote, and the manager holds something else under its label: on
/// macOS launchd holds the job with an argument added, and on Linux the user manager reads a
/// drop-in of the unit's own that runs another command. `kr new` names what the manager holds and
/// the setup action, and nothing is started. The setup names the same thing and its remedy, which
/// is the person's to apply, and changes nothing in the manager. Once the person has applied it,
/// the setup has the manager take the definition, and `kr new` goes on.
#[test]
fn a_manager_holding_anything_but_the_definition_kr_wrote_is_not_asked_to_start_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let chosen = host.select_service();
    let written = std::fs::read(host.definition()).expect("the definition");
    #[cfg(target_os = "macos")]
    {
        let domain = chosen["startup"]["definition"]["domain"]
            .as_str()
            .expect("a domain")
            .to_owned();
        let target = format!("{domain}/{}", host.label());
        let launchctl = |arguments: &[&str]| {
            let mut command = Command::new("/bin/launchctl");
            command.args(arguments);
            let answer = bounded(command, STREAMS_DEADLINE).expect("launchctl answers");
            assert!(
                answer.status.success(),
                "launchctl {arguments:?}: {}",
                String::from_utf8_lossy(&answer.stderr)
            );
        };
        let other = String::from_utf8(written.clone())
            .expect("text")
            .replacen(
                "\t\t<string>--runtime-dir</string>",
                "\t\t<string>--worker</string>\n\t\t<string>/usr/bin/false</string>\n\t\t<string>--runtime-dir</string>",
                1,
            );
        launchctl(&["bootout", &target]);
        std::fs::write(host.definition(), other).expect("another form");
        let path = host.definition().display().to_string();
        launchctl(&["bootstrap", &domain, &path]);
        // The file is kr's again, and launchd still holds the other form.
        std::fs::write(host.definition(), &written).expect("the definition kr wrote");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = &chosen;
        let drop_ins = host
            .definition()
            .with_file_name(format!("{}.service.d", host.label()));
        std::fs::create_dir_all(&drop_ins).expect("a drop-in directory");
        std::fs::write(
            drop_ins.join("override.conf"),
            "[Service]\nExecStart=\nExecStart=/bin/true\n",
        )
        .expect("a drop-in");
        host.reload();
    }

    let output = start(host.new_session()).finish("kr new");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("kr host startup --set service"),
        "the failure names what the manager holds and the setup action: {message}"
    );
    assert_eq!(host.daemon(), None, "nothing was started");
    assert!(!host.answers());
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        written,
        "and the definition kr wrote was not touched"
    );

    let refused = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup while the manager holds another form");
    let refusal = document(&refused, "kr host startup");
    assert_ne!(refused.status.code(), Some(0), "{refusal}");
    let message = refusal["message"].as_str().unwrap_or_default();
    #[cfg(target_os = "macos")]
    {
        let domain = chosen["startup"]["definition"]["domain"]
            .as_str()
            .expect("a domain");
        let target = format!("{domain}/{}", host.label());
        assert!(
            message.contains(&format!("launchctl bootout {target}")),
            "the setup names the remedy and leaves it to the person: {message}"
        );
        // Still the other form: the setup did not replace it.
        let mut print = Command::new("/bin/launchctl");
        print.args(["print", &target]);
        let printed = bounded(print, STREAMS_DEADLINE).expect("launchctl answers");
        assert!(
            String::from_utf8_lossy(&printed.stdout).contains("/usr/bin/false"),
            "launchd still holds the other form"
        );
        let mut bootout = Command::new("/bin/launchctl");
        bootout.args(["bootout", &target]);
        let removed = bounded(bootout, STREAMS_DEADLINE).expect("launchctl answers");
        assert!(removed.status.success(), "the person removes it");
    }
    #[cfg(target_os = "linux")]
    {
        let drop_ins = host
            .definition()
            .with_file_name(format!("{}.service.d", host.label()));
        assert!(
            message.contains("one of them sets ExecStart")
                && message.contains(&format!(
                    "systemctl --user cat {}.service shows",
                    host.label()
                )),
            "the setup says what the drop-in sets and where the person sees it: {message}"
        );
        assert!(
            !message.contains("override.conf") && !message.contains("/bin/true"),
            "and repeats neither its name nor what it holds: {message}"
        );
        std::fs::remove_dir_all(drop_ins).expect("the person removes the drop-in");
    }
    host.select_service();
    let output = start(host.new_session()).finish("kr new once the setup ran again");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux no drop-in changes the command the user manager runs for the daemon,
/// wherever the drop-in is: in the directory every service reads, or in the unit's own directory
/// reached through a link to a directory that is also named `service.d`.
///
/// For each, `kr new` names the command the manager would run and the setup action, and nothing
/// is started: the other command leaves a mark when it runs, and there is none. Once the person
/// has removed the drop-in, `kr new` goes on.
#[cfg(target_os = "linux")]
#[test]
fn no_drop_in_anywhere_changes_the_command_the_user_manager_runs() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let units = host
        .definition()
        .parent()
        .expect("the user unit directory")
        .to_path_buf();
    let own = units.join(format!("{}.service.d", host.label()));
    let linked = host.tree.root().join("overrides/service.d");
    let mark = host.tree.root().join("the-other-command-ran");
    for (place, drop_in) in [
        (
            "a drop-in every service reads",
            units.join("service.d/zz-command.conf"),
        ),
        (
            "a drop-in in the unit's own directory, linked to one named service.d",
            linked.join("zz-command.conf"),
        ),
    ] {
        let directory = drop_in.parent().expect("a drop-in directory");
        std::fs::create_dir_all(directory).expect("a drop-in directory");
        std::fs::write(
            &drop_in,
            format!("[Service]\nExecStart=\nExecStart={}\n", touching(&mark)),
        )
        .expect("a drop-in");
        if directory == linked {
            std::os::unix::fs::symlink(&linked, &own).expect("the unit's own directory, linked");
        }
        host.reload();

        let output = start(host.new_session()).finish("kr new");
        let failure = document(&output, "kr new");
        assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{place}: {failure}");
        let message = failure["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("one of them sets ExecStart")
                && message.contains("ExecStartEx with a command kr did not write"),
            "{place}: the failure says the manager would run another command: {message}"
        );
        assert!(
            !message.contains("/usr/bin/touch") && !message.contains("zz-command.conf"),
            "{place}: and repeats neither that command nor the drop-in's name: {message}"
        );
        assert!(
            message.contains("kr host startup --set service"),
            "{place}: and the setup action: {message}"
        );
        assert!(!mark.exists(), "{place}: the other command never ran");
        assert_eq!(host.daemon(), None, "{place}: nothing was started");
        assert!(!host.answers(), "{place}: nothing answers");

        std::fs::remove_file(&drop_in).expect("the person removes the drop-in");
        if own.is_symlink() {
            std::fs::remove_file(&own).expect("and the link");
        }
        host.reload();
    }

    let output = start(host.new_session()).finish("kr new once the drop-ins are gone");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux every question kr puts to the user manager and every request it makes
/// go through `systemctl --user` from the same environment, so the manager whose definition kr
/// checked is the manager it asks to start the daemon.
///
/// Two managers are reachable. The test's own, named by the runtime directory, holds the
/// definition kr wrote. A second one holds another unit under the same name whose command leaves a
/// mark, and is reachable over the message bus its own `dbus.socket` starts. With
/// `SYSTEMCTL_FORCE_BUS=1` and that bus named, `systemctl` reaches the second manager for every
/// call: kr checks what that manager holds, refuses it, and asks nothing to start, so the mark never
/// appears. Without them, the test's own manager starts the daemon.
#[cfg(target_os = "linux")]
#[test]
fn the_user_manager_kr_checks_is_the_one_it_asks() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let other_home = host.tree.root().join("other-home");
    let other_units = other_home.join(".config/systemd/user");
    std::fs::create_dir_all(&other_units).expect("the other manager's unit directory");
    let mark = host.tree.root().join("the-other-manager-ran-its-unit");
    let other_unit = other_units.join(format!("{}.service", host.label()));
    std::fs::write(
        &other_unit,
        format!("[Service]\nType=exec\nExecStart={}\n", touching(&mark)),
    )
    .expect("another unit under the same name");
    let other = UserManager::start(&other_home, host.tree.holder()).and_then(|other| {
        let started = bounded(other.systemctl(&["start", "dbus.socket"]), STREAMS_DEADLINE)?;
        if started.status.success() {
            Ok(other)
        } else {
            Err(format!(
                "its dbus.socket did not start: {}",
                String::from_utf8_lossy(&started.stderr).trim()
            ))
        }
    });
    let other = match other {
        Ok(other) => other,
        Err(why) => {
            assert!(
                std::env::var_os(REQUIRE_SERVICE_MANAGER).is_none(),
                "a second manager with a bus of its own could not be started: {why}"
            );
            eprintln!("the manager choice is not tested here: {why}");
            return;
        }
    };
    let bus = bus_address(&other.runtime.join("bus"));
    let over_the_bus = |command: &mut Command| {
        command
            .env("SYSTEMCTL_FORCE_BUS", "1")
            .env("DBUS_SESSION_BUS_ADDRESS", &bus);
    };
    // The second manager answers on its bus before kr is pointed there.
    let begun = Instant::now();
    loop {
        let mut asked = Command::new("systemctl");
        asked.args(["--user", "show", "--property=Version", "--value"]);
        over_the_bus(&mut asked);
        if bounded(asked, STREAMS_DEADLINE).is_ok_and(|answer| answer.status.success()) {
            break;
        }
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the second manager did not answer on its bus"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut elsewhere = host.new_session();
    over_the_bus(&mut elsewhere);
    let output = start(elsewhere).finish("kr new pointed at the other manager");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("from a file other than the definition kr wrote"),
        "the failure says the other manager holds another file: {message}"
    );
    assert!(
        !message.contains(&other_unit.display().to_string()),
        "and does not repeat the file the other manager names: {message}"
    );
    assert!(
        !mark.exists(),
        "the other manager was asked to start nothing"
    );
    assert_eq!(host.daemon(), None, "and the test's own started nothing");
    assert!(!host.answers(), "nothing answers");

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the test's own manager reports the daemon it started"),
    );
    assert!(!mark.exists(), "and the other manager still ran nothing");
    host.close(&created);
    drop(other);
}

/// KR-REQ-07.12: on Linux a drop-in that sets the daemon's command is refused even when the
/// manager prints the command exactly as kr wrote it. The drop-in keeps kr's program and words
/// and only joins two of them into one, which `systemctl show` prints the same way, so it is the
/// drop-in itself that is read: the command comes from kr's own file or not at all.
#[cfg(target_os = "linux")]
#[test]
fn a_drop_in_that_resplits_the_command_is_refused_though_it_prints_the_same() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let written = std::fs::read_to_string(host.definition()).expect("the definition");
    let command = written
        .lines()
        .find(|line| line.starts_with("ExecStart="))
        .expect("the definition's command");
    let resplit = command.replacen("\"--runtime-dir\" \"", "\"--runtime-dir ", 1);
    assert_ne!(
        resplit, command,
        "the command names its runtime directory: {command}"
    );
    let own = host
        .definition()
        .with_file_name(format!("{}.service.d", host.label()));
    std::fs::create_dir_all(&own).expect("the unit's own drop-in directory");
    let drop_in = own.join("20-resplit.conf");
    // Once as plain lines, and once as systemd also reads it: keys continued onto the next line
    // with a backslash, and lines ended by carriage returns alone.
    let continued = resplit.replacen("ExecStart=", "ExecStart\\\r=", 1);
    for contents in [
        format!("[Service]\nExecStart=\n{resplit}\n"),
        format!("[Service]\rExecStart\\\r=\r{continued}\r"),
    ] {
        std::fs::write(&drop_in, &contents).expect("a drop-in");
        host.reload();

        let output = start(host.new_session()).finish("kr new");
        let failure = document(&output, "kr new");
        assert_eq!(
            failure["code"], "HOST_NOT_CONFIGURED",
            "{contents:?}: {failure}"
        );
        let message = failure["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("one of them sets ExecStart"),
            "{contents:?}: the failure says what the drop-in sets: {message}"
        );
        assert!(
            !message.contains("20-resplit.conf"),
            "{contents:?}: and does not repeat the drop-in's name: {message}"
        );
        assert_eq!(host.daemon(), None, "{contents:?}: nothing was started");
        assert!(!host.answers(), "{contents:?}: nothing answers");
    }
}

/// KR-REQ-07.12: on Linux a drop-in every service reads that leaves commands alone, such as the
/// timeout policy some distributions ship for every user service, is the host's own: the setup
/// names it and `kr new` has the manager start the daemon under it.
#[cfg(target_os = "linux")]
#[test]
fn a_host_wide_timeout_drop_in_is_the_hosts_and_the_daemon_starts_under_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let every_service = host
        .definition()
        .parent()
        .expect("the user unit directory")
        .join("service.d");
    std::fs::create_dir_all(&every_service).expect("the directory every service reads");
    let drop_in = every_service.join("10-timeout-abort.conf");
    std::fs::write(&drop_in, "[Service]\nTimeoutStopFailureMode=abort\n").expect("a drop-in");

    let chosen = host.select_service();
    assert!(
        chosen["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains(&drop_in.display().to_string())))),
        "the setup names the drop-in the manager reads: {chosen}"
    );
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the service manager reports the daemon it started"),
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux a drop-in that leaves the command alone is the person's own. `kr host
/// startup --set service` takes the definition and names the drop-in, and `kr new` has the user
/// manager start the daemon under it.
#[cfg(target_os = "linux")]
#[test]
fn a_drop_in_that_leaves_the_command_alone_is_the_persons_and_the_daemon_starts_under_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let own = host
        .definition()
        .with_file_name(format!("{}.service.d", host.label()));
    std::fs::create_dir_all(&own).expect("the unit's own drop-in directory");
    let drop_in = own.join("10-host-policy.conf");
    std::fs::write(
        &drop_in,
        "[Service]\nEnvironment=KR_TEST_HOST_POLICY=kept\n",
    )
    .expect("a drop-in");

    let chosen = host.select_service();
    assert!(
        chosen["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains(&drop_in.display().to_string())))),
        "the setup names the drop-in the manager reads: {chosen}"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pid = host
        .daemon()
        .expect("the service manager reports the daemon it started");
    host.assert_started_by_the_manager(pid);
    let environment = std::fs::read(format!("/proc/{pid}/environ")).expect("its environment");
    assert!(
        environment
            .split(|byte| *byte == 0)
            .any(|entry| entry == b"KR_TEST_HOST_POLICY=kept"),
        "the manager started the daemon under the person's drop-in"
    );
    host.close(&created);
}

/// KR-REQ-26.04: `--clear` leaves a definition that was changed after kr wrote it, says so, and
/// removes the record, so the file is no longer taken for kr's: the next `--set service` refuses it
/// and leaves it as it is.
#[test]
fn clearing_leaves_a_definition_changed_since_kr_wrote_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let mut changed = std::fs::read(host.definition()).expect("the definition");
    changed.extend_from_slice(b"\n");
    std::fs::write(host.definition(), &changed).expect("changes the definition");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    let left = none["left"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it left: {none}"));
    assert!(
        left.iter()
            .any(|entry| entry["path"] == host.definition().display().to_string()),
        "the changed definition is among what the clear left: {none}"
    );
    let removed: Vec<&str> = none["removed"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it removed: {none}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        removed,
        [host.record().display().to_string().as_str()],
        "only the record: {none}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "left exactly as it was"
    );
    assert!(!host.record().exists());

    let refused = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup");
    let refusal = document(&refused, "kr host startup");
    assert_eq!(refused.status.code(), Some(2), "{refusal}");
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not write"),
        "{refusal}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "and it is still as it was"
    );
}
