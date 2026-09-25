//! `kr new` starting this environment's control daemon itself, under the standalone start.
//!
//! What these establish, with the real `kr`, `kr-controller` and `kr-worker` on a real environment
//! tree. KR-REQ-07.12: with the standalone start selected and no daemon running, `kr new` starts
//! one, detached from itself: in a session and a process group of its own, with no controlling
//! terminal and none of the command's own streams, working in the environment's own directory.
//! Then it goes on as it would against a daemon that was already there. Three commands doing that
//! at once leave one daemon, at one generation, holding every session they created; and a daemon
//! that does not come up within the bound ends the command with a failure of its own name and
//! leaves no second daemon. The start is selected by a command that needs no daemon, and
//! `kr doctor` reports it with the document it came from. KR-REQ-07.13: with the start selected,
//! neither the command that selects it nor the `kr new` that starts the daemon runs a
//! service-manager, lingering or privilege tool found through its `PATH`, and neither writes
//! anything into the home it is given. KR-REQ-08.02: `kr status` on a session the started daemon
//! holds reports each terminal attachment's presentation and the reason for it.
//!
//! The installation is laid out the way a package lays it out: `kr`, its restoration guard, the
//! daemon and the worker side by side on the internal disk, where `kr` finds the daemon beside
//! itself. The daemon there is a short script that runs the real one with its keys in the
//! environment's own `secrets` directory, which is what every harness in this repository gives a
//! daemon so that nothing reaches the credential store of the person running the tests, and that
//! records its process number in the test's own tree, so the test can find what `kr` started and
//! end it when the test ends. Every other argument the daemon is given is `kr`'s own. Every
//! runtime and state directory is inside the test's own temporary tree.

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

/// How long the streams of a command that has ended are given to reach their end.
const STREAMS_DEADLINE: Duration = Duration::from_secs(10);

/// The name the real daemon is placed under, beside the script `kr` runs as the daemon.
const DAEMON_UNDER_TEST: &str = "kr-controller-under-test";

/// The file in a test's own tree that the daemon script records each process number in.
const LAUNCHED: &str = "launched-daemons";

/// The tools a service, lingering or a privilege would be obtained through.
const RECORDING_TOOLS: [&str; 7] = [
    "systemctl",
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
        // Written under a name nothing runs, and placed under the one `kr` runs by a copy, like
        // every program these tests start: no descriptor this process holds is ever open on it.
        let source = directory.join("kr-controller.sh");
        std::fs::write(&source, daemon_script(&daemon)).expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory.to_path_buf()
    })
}

/// The daemon `kr` finds beside itself in these tests.
///
/// The real daemon, with its keys in the environment's own `secrets` directory. Before it takes
/// over, the script records its own process number beside the state tree it was given, which is
/// the test's own tree, so the process `kr` started is one the test can name.
fn daemon_script(daemon: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         state=\n\
         previous=\n\
         for argument in \"$@\"; do\n\
         \x20 if [ \"$previous\" = --state-dir ]; then state=$argument; fi\n\
         \x20 previous=$argument\n\
         done\n\
         if [ -n \"$state\" ]; then echo $$ >> \"$state/../{LAUNCHED}\"; fi\n\
         exec '{}' --secret-store file \"$@\"\n",
        daemon.display()
    )
}

/// A host tree of a test's own, where the standalone start is tried.
///
/// However a test ends, each daemon `kr` started in the tree is ended before the tree goes, and
/// then, through the tree, every worker a daemon recorded.
struct Standalone {
    tree: teardown::Tree,
    home: PathBuf,
}

impl Drop for Standalone {
    fn drop(&mut self) {
        for pid in self.launched() {
            if let Err(why) = end_daemon(pid, self.tree.paths().state_root()) {
                self.tree.hold(why);
            }
        }
    }
}

impl Standalone {
    fn create() -> Self {
        let tree = teardown::Tree::create();
        let home = tree.root().join("home");
        std::fs::create_dir_all(&home).expect("a home of this test's own");
        Self { tree, home }
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
        std::fs::read_to_string(self.tree.root().join(LAUNCHED))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    /// Waits until exactly one daemon `kr` started here is running, and returns it.
    ///
    /// A daemon that lost the environment's lock ends by itself, and one that ended moments ago
    /// may not have been collected yet, so the answer is waited for rather than read once.
    fn one_daemon(&self) -> u32 {
        let started = Instant::now();
        loop {
            let launched = self.launched();
            let running: Vec<u32> = launched
                .iter()
                .copied()
                .filter(|pid| {
                    matches!(
                        kr_ipc::identity::query_process(*pid),
                        ProcessQuery::Present(_)
                    )
                })
                .collect();
            if running.len() == 1 {
                return running[0];
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "one daemon was to be left of those started, {launched:?}, and these are running: \
                 {running:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Asks this environment's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
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

/// The working directory of a process of this user's.
fn working_directory(pid: u32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).expect("reads its working directory")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let listed = Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-Fn", "-p", &pid.to_string()])
            .output()
            .expect("lists its working directory");
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .find_map(|line| line.strip_prefix('n'))
            .map(PathBuf::from)
            .expect("its working directory is listed")
    }
}

/// Ends a daemon `kr` started in a test's tree, and waits for it to be gone.
///
/// The number comes from the tree's own record, and it is acted on only while it still names that
/// daemon: a process holding it now whose command line does not name the tree's state directory is
/// somebody else's, and is left alone. Its start identity is read before the signal and compared
/// after it, so a number the kernel has given to something else by then reads as the daemon gone.
fn end_daemon(pid: u32, state_root: &Path) -> Result<(), String> {
    let identity = match kr_ipc::identity::query_process(pid) {
        ProcessQuery::Gone => return Ok(()),
        ProcessQuery::CannotEstablish(error) => {
            return Err(format!("daemon {pid} could not be looked at: {error}"));
        }
        ProcessQuery::Present(identity) => identity,
    };
    let described = Command::new("/bin/ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("daemon {pid} could not be described: {error}"))?;
    let expected = format!("--state-dir {}", state_root.display());
    if !String::from_utf8_lossy(&described.stdout).contains(&expected) {
        return Ok(());
    }
    let process =
        rustix::process::Pid::from_raw(i32::try_from(pid).map_err(|_| "a process number")?)
            .ok_or("a process number")?;
    for signal in [rustix::process::Signal::TERM, rustix::process::Signal::KILL] {
        let _ = rustix::process::kill_process(process, signal);
        let started = Instant::now();
        while started.elapsed() < STREAMS_DEADLINE {
            if !matches!(
                kr_ipc::identity::process_state(&identity),
                ProcessState::Running
            ) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Err(format!("daemon {pid} did not end"))
}

/// A `kr` that has been started, and the threads reading what it prints.
struct Running {
    child: Child,
    stdout: Receiver<Vec<u8>>,
    stderr: Receiver<Vec<u8>>,
}

/// Starts `kr`, reading both its output streams on threads of their own.
fn start(mut command: Command) -> Running {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr starts");
    let stdout = read_aside(child.stdout.take().expect("its standard output"));
    let stderr = read_aside(child.stderr.take().expect("its standard error"));
    Running {
        child,
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
        let started = Instant::now();
        let status = loop {
            match self.child.try_wait().expect("waits for kr") {
                Some(status) => break status,
                None if started.elapsed() < LIVENESS_DEADLINE => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                None => {
                    // This test's own child, not collected yet, so the number is still its.
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("{what} did not end within {LIVENESS_DEADLINE:?}");
                }
            }
        };
        let stdout = self.stdout.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!("{what} ended and its standard output is still open: something it started holds it")
        });
        let stderr = self.stderr.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!("{what} ended and its standard error is still open: something it started holds it")
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

/// KR-REQ-07.12: three first invocations at once converge on one control daemon.
///
/// Three `kr new` commands start together with the standalone start selected and no daemon
/// running. Each creates its session; one daemon is left of those they started, the environment's
/// generation advanced once, and every session is in that daemon's registry. The daemon leads a
/// session and a process group of its own, has no controlling terminal and works in the
/// environment's own directory, and every command's own output ended with the command.
#[test]
fn three_first_invocations_at_once_converge_on_one_daemon() {
    let host = Standalone::create();
    host.select_standalone();

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

    let launched = host.launched();
    assert!(
        (1..=3).contains(&launched.len()),
        "each command starts at most one daemon, and one was started: {launched:?}"
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

/// KR-REQ-07.12: a daemon that does not come up in time ends the command with a failure of its own
/// name, and leaves no second daemon.
///
/// The environment is held by a daemon that has taken its singleton lock and never answers, which
/// is what a daemon stuck in its own start looks like from outside; this test holds the lock
/// itself. `kr new` starts a daemon, which cannot take the environment and ends, waits out its
/// bound for an answer, and fails with `ENVIRONMENT_UNAVAILABLE`, saying how long it waited and
/// what the daemon it started said. Nothing it started is left running, and nothing answers for
/// the environment.
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
    while !launched
        .iter()
        .all(|pid| matches!(kr_ipc::identity::query_process(*pid), ProcessQuery::Gone))
    {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that could not take the environment ended: {launched:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    assert!(
        runtime
            .block_on(LocalClient::connect(
                &endpoint,
                LocalClientKind::Cli,
                build()
            ))
            .is_err(),
        "and nothing answers for the environment"
    );
    drop(held);
}

/// KR-REQ-07.13, KR-REQ-07.12: with the standalone start selected, nothing is installed and no
/// privilege is sought.
///
/// Neither the command that selects the start nor the `kr new` that starts the daemon runs a
/// service-manager, lingering or privilege tool found through its `PATH` (the tools the
/// unconfigured case is checked against, each replaced there by one that records being run), and
/// nothing is written, removed or changed in the home the two commands are given. The daemon that
/// was started searches the platform's own directories for the tools it uses, so the caller's
/// `PATH` is never where it finds one.
#[test]
fn selecting_and_using_the_standalone_start_installs_nothing_and_seeks_no_privilege() {
    use std::os::unix::fs::PermissionsExt as _;

    let host = Standalone::create();
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    std::fs::create_dir_all(&tools).expect("a directory for the recording tools");
    for tool in RECORDING_TOOLS {
        let path = tools.join(tool);
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"{tool} $*\" >> '{}'\n", calls.display()),
        )
        .expect("writes a recording tool");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("makes it runnable");
    }
    let path = format!("{}:/usr/bin:/bin", tools.display());
    // The recording tools record: one run through the same `PATH` is found, and then forgotten.
    Command::new("/bin/sh")
        .args(["-c", "loginctl enable-linger"])
        .env("PATH", &path)
        .status()
        .expect("runs a recording tool");
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap_or_default(),
        "loginctl enable-linger\n"
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
    host.assert_detached(host.one_daemon());
    host.close(&created);

    assert!(
        !calls.exists(),
        "no service manager, lingering or privilege tool was run: {}",
        std::fs::read_to_string(&calls).unwrap_or_default()
    );
    assert!(
        every_path_under(&host.home) == before,
        "no service definition, no lingering setting and nothing else was written, removed or \
         changed in the home the commands were given"
    );
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
        start(host.kr(&["host", "startup", "--set", "service"])).finish("kr host startup");
    assert_eq!(refused.status.code(), Some(2), "a usage failure");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("standalone"),
        "the refusal names what can be chosen: {}",
        String::from_utf8_lossy(&refused.stderr)
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
