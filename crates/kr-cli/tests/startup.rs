//! `kr new` starting this environment's control daemon itself, under the standalone start.
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
//! itself. The daemon there is a short script, which is what `kr` starts. It runs the real daemon
//! with its keys in the environment's own `secrets` directory, which is what every harness in this
//! repository gives a daemon so that nothing reaches the credential store of the person running the
//! tests. Every other argument the daemon is given is `kr`'s own, and so is its environment. The
//! script records the daemon's process number in the test's own tree, and holds the daemon as its
//! own child until the test ends: the test holds a lifeline open, and when it closes, however the
//! test ended, the script ends the daemon it started, which it has not collected and whose number
//! is therefore still its own. Every runtime and state directory is inside the test's own temporary
//! tree.

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

/// The file in a test's own tree that each daemon script records its daemon's process number in.
const LAUNCHED: &str = "launched-daemons";

/// The file in a test's own tree that each daemon script records its own process number in when
/// it starts.
const STARTS: &str = "daemon-starts";

/// The FIFO in a test's own tree that the test holds open for as long as it runs.
const LIFELINE: &str = "daemon-lifeline";

/// When present in a test's own tree, how many daemon scripts have to have started before any of
/// them starts its daemon, so that the daemons meet at the environment's lock.
const BARRIER: &str = "daemon-barrier";

/// When present in a test's own tree, how many seconds each daemon script waits before it starts
/// its daemon, which is what a daemon slow to come up looks like from outside.
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
/// It opens the test's lifeline first, records itself, and waits at the test's barrier or for the
/// test's delay when the test asks for either. It then starts the real daemon, with its keys in
/// the environment's own `secrets` directory, the rest of `kr`'s arguments and none of its own
/// descriptors, as a child of its own, and records the daemon's process number. It then waits for
/// the lifeline to close and ends the daemon, which it has not collected until then: a daemon that
/// ended by itself stays a process nobody has collected, and its number cannot be given to anything
/// else before this script is done with it.
fn daemon_script(daemon: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         state=\n\
         previous=\n\
         for argument in \"$@\"; do\n\
         \x20 if [ \"$previous\" = --state-dir ]; then state=$argument; fi\n\
         \x20 previous=$argument\n\
         done\n\
         tree=\"$state/..\"\n\
         exec 3< \"$tree/{LIFELINE}\"\n\
         echo $$ >> \"$tree/{STARTS}\"\n\
         if [ -f \"$tree/{BARRIER}\" ]; then\n\
         \x20 wanted=$(cat \"$tree/{BARRIER}\")\n\
         \x20 tries=0\n\
         \x20 while [ $(( $(wc -l < \"$tree/{STARTS}\") )) -lt \"$wanted\" ] && [ \"$tries\" -lt 600 ]; do\n\
         \x20   sleep 0.05\n\
         \x20   tries=$((tries + 1))\n\
         \x20 done\n\
         fi\n\
         if [ -f \"$tree/{DELAY}\" ]; then sleep \"$(cat \"$tree/{DELAY}\")\"; fi\n\
         '{}' --secret-store file \"$@\" 3<&- &\n\
         daemon=$!\n\
         echo \"$daemon\" >> \"$tree/{LAUNCHED}\"\n\
         read -r _ <&3\n\
         kill \"$daemon\" 2>/dev/null\n\
         wait \"$daemon\"\n",
        daemon.display()
    )
}

/// A host tree of a test's own, where the standalone start is tried.
///
/// However a test ends, each daemon `kr` started in the tree is ended before the tree goes, by the
/// script that started it, and then, through the tree, every worker a daemon recorded.
struct Standalone {
    tree: teardown::Tree,
    home: PathBuf,
    /// The lifeline every daemon script in this tree waits on, held open for as long as the test
    /// runs.
    lifeline: Option<std::fs::File>,
}

impl Drop for Standalone {
    fn drop(&mut self) {
        // Each daemon, named by its start identity while its script still holds it, so a number
        // given to something else afterwards is not mistaken for it.
        let mut daemons = Vec::new();
        for pid in self.launched() {
            match kr_ipc::identity::query_process(pid) {
                ProcessQuery::Present(identity) => daemons.push(identity),
                ProcessQuery::Gone => {}
                ProcessQuery::CannotEstablish(error) => self.tree.hold(format!(
                    "whether the daemon {pid} this test started has ended cannot be established: \
                     {error}"
                )),
            }
        }
        // The cue for every daemon script to end the daemon it started.
        drop(self.lifeline.take());
        let started = Instant::now();
        for identity in daemons {
            loop {
                match kr_ipc::identity::process_state(&identity) {
                    ProcessState::Ended => break,
                    ProcessState::Running if started.elapsed() < STREAMS_DEADLINE => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ProcessState::Running => {
                        self.tree.hold(format!(
                            "the daemon {} this test started did not end once its lifeline closed",
                            identity.pid.get()
                        ));
                        break;
                    }
                    ProcessState::Unknown { detail } => {
                        self.tree.hold(format!(
                            "whether the daemon {} this test started has ended cannot be \
                             established: {detail}",
                            identity.pid.get()
                        ));
                        break;
                    }
                }
            }
        }
    }
}

impl Standalone {
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
        std::fs::read_to_string(self.tree.root().join(LAUNCHED))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    /// The daemons `kr` started in this tree that are running now.
    ///
    /// A daemon that could not take the environment ends by itself and waits for its script to
    /// collect it, which counts as ended.
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
            tokio::time::timeout(
                STREAMS_DEADLINE,
                LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
            )
            .await
            .is_ok_and(|reached| reached.is_ok())
        })
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
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::create_dir_all(tools).expect("a directory for the recording tools");
    for tool in RECORDING_TOOLS {
        let path = tools.join(tool);
        std::fs::write(
            &path,
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
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("makes it runnable");
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

    assert_eq!(host.launched().len(), 1, "the command started one daemon");
    let started = Instant::now();
    while !host.running().is_empty() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that could not take the environment ended: {:?}",
            host.launched()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
            recorded.iter().any(|call| call.tool == "systemctl"),
            "the daemon's query of the user manager went through the recording tool, so the \
             tools it runs by name are the ones on the PATH it inherited: {recorded:?}"
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
