//! `kr new` and `kr attach` for a session in an enrolled environment, against real daemons and
//! workers.
//!
//! The source is a host tree with a daemon of its own, where the destination is enrolled. The
//! destination is a second tree with no daemon running: what stands for a stopped WSL distribution
//! is a stand-in for `wsl.exe` that runs the destination's own `kr bridge --stdio` with only what a
//! login in that environment would give it. Nothing else is stood in for. Creating and attaching
//! are the two actions section 3 lets start the environment they name, so the destination's daemon
//! is started by the helper, through the destination's own configured startup, and the session
//! lives in the destination's tree and nowhere else.
//!
//! The command and the daemon are copied to the internal disk, every process works inside a tree of
//! this test's own, and each daemon keeps its keys in its own tree rather than in a keychain.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Returns an executable the workspace builds beside this test, or says what to build.
fn beside_this_test(name: &str) -> PathBuf {
    let executable = std::env::current_exe().expect("this test binary");
    // `<target>/<profile>/deps/<this test>`: the executables are in `<target>/<profile>`.
    let candidate = executable
        .parent()
        .and_then(Path::parent)
        .map(|profile| profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
        .filter(|candidate| candidate.is_file());
    candidate.unwrap_or_else(|| {
        panic!(
            "the {name} executable is not built beside this test, so this check cannot run; a \
             workspace test run builds it, and so does `cargo build -p kr-controller -p kr-worker`"
        )
    })
}

/// The installation these tests run, on the internal disk: `kr` and its guard, and beside them the
/// daemon `kr` starts when the environment's own startup says to, and the worker it starts.
///
/// The daemon is a short script that adds the one thing a test must not leave to a keychain, which
/// is where its keys are kept, and hands over to the real daemon.
fn installation() -> &'static Path {
    static PLACED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PLACED.get_or_init(|| {
        let directory = support::command_binaries();
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-worker"),
            &directory.join("kr-worker"),
            &["--version"],
        );
        let real = directory.join("kr-controller-under-test");
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-controller"),
            &real,
            &["--version"],
        );
        let source = directory.join("kr-controller.sh");
        std::fs::write(
            &source,
            format!(
                "#!/bin/sh\nexec '{}' --secret-store file \"$@\"\n",
                real.display()
            ),
        )
        .expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory.to_path_buf()
    })
}

/// What the stand-in for `wsl.exe` does: record how it was run, and run what follows `--exec` in the
/// destination's own environment, with what a login there would give it and nothing of the caller's.
fn stand_in(tools: &Path, destination: &Path, home: &Path) -> String {
    let temporary = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    format!(
        r##"#!/bin/sh
printf '%s\n' "$*" >>'{tools}/invocations'
while [ "$#" -gt 0 ] && [ "$1" != "--exec" ]; do shift; done
shift
exec /usr/bin/env -i PATH=/usr/bin:/bin HOME='{home}' TMPDIR='{temporary}' \
  KR_RUNTIME_DIR='{runtime}' KR_STATE_DIR='{state}' "$@"
"##,
        tools = tools.display(),
        home = home.display(),
        runtime = destination.join("r").display(),
        state = destination.join("s").display(),
    )
}

/// What the stand-in for `ssh` does: skip the options and the host, and run what follows them in
/// the destination's own environment, as the login on the other side would.
fn ssh_stand_in(destination: &Path, home: &Path) -> String {
    let temporary = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    format!(
        r##"#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
shift
exec /usr/bin/env -i PATH=/usr/bin:/bin HOME='{home}' TMPDIR='{temporary}' \
  KR_RUNTIME_DIR='{runtime}' KR_STATE_DIR='{state}' "$@"
"##,
        home = home.display(),
        runtime = destination.join("r").display(),
        state = destination.join("s").display(),
    )
}

/// The source host's daemon, a destination with none, and the stand-in between them.
struct World {
    source: teardown::Tree,
    destination: teardown::Tree,
    home: PathBuf,
    tools: PathBuf,
    daemon: Option<std::process::Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        // The destination's daemon was started by a helper and is its own, so it is asked to make
        // way the way the product's own update asks, and the tree then ends what it started.
        self.stop_destination_daemon();
        if let Some(mut daemon) = self.daemon.take()
            && let Err(error) = daemon.kill().and_then(|()| daemon.wait().map(|_| ()))
        {
            self.source.hold(format!(
                "the source daemon this test started could not be established as ended: {error}"
            ));
        }
    }
}

impl World {
    async fn start() -> Self {
        let source = teardown::Tree::create();
        let destination = teardown::Tree::create();
        let home = destination.root().join("home");
        std::fs::create_dir_all(&home).expect("the destination user's home");
        let tools = source.root().join("tools");
        std::fs::create_dir_all(&tools).expect("a directory for the stand-in");
        let text = tools.join("wsl.exe.text");
        std::fs::write(&text, stand_in(&tools, destination.root(), &home)).expect("the stand-in");
        kr_ipc::testing::place_program(&text, &tools.join("wsl.exe"));
        let ssh_text = tools.join("ssh.text");
        std::fs::write(&ssh_text, ssh_stand_in(destination.root(), &home))
            .expect("the ssh stand-in");
        kr_ipc::testing::place_program(&ssh_text, &tools.join("ssh"));
        // The destination chooses the standalone start, as a person sets a distribution up.
        kr_ipc::paths::write_owner_only_file(
            &destination.environment().state_dir().join("config.json"),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("writes the destination's configuration document");

        let log = std::fs::File::create(source.root().join("daemon.log")).expect("the log");
        let child = std::process::Command::new(installation().join("kr-controller"))
            .current_dir(source.root())
            .arg("--runtime-dir")
            .arg(source.root().join("r"))
            .arg("--state-dir")
            .arg(source.root().join("s"))
            .arg("--worker")
            .arg(installation().join("kr-worker"))
            // The daemon runs `ssh` for a host that is asked who it is, so the stand-in is first
            // on its path too.
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    tools.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the source daemon starts");
        let world = Self {
            source,
            destination,
            home,
            tools,
            daemon: Some(child),
        };
        let endpoint = world
            .source
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the source daemon did not answer"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        world
    }

    /// `kr` on the source host, with nothing of this test's environment, and the stand-in first on
    /// its path.
    fn kr(&self, arguments: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(support::kr());
        command
            .args(arguments)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.tools.display()))
            .env("TERM", "xterm-256color")
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.source.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.source.paths().state_root(),
            )
            .current_dir("/")
            .stdin(std::process::Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        command
    }

    /// Runs `kr` on the source host to its end.
    fn run(&self, arguments: &[&str]) -> std::process::Output {
        self.kr(arguments).output().expect("runs kr")
    }

    /// Records the destination in the source host's own inventory, as a WSL distribution.
    fn enrol_destination(&self) {
        let environment = self.destination.environment_id().to_string();
        let helper = support::kr().display().to_string();
        let enrolled = self.run(&[
            "bridge",
            "enrol",
            "--access",
            "wsl",
            "--label",
            "dest",
            "--target",
            "Test-Distro",
            "--user",
            "tester",
            "--helper",
            &helper,
            "--environment-id",
            &environment,
        ]);
        assert!(
            enrolled.status.success(),
            "enrolling: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );
    }

    /// How many times the stand-in was run.
    fn invocations(&self) -> usize {
        std::fs::read_to_string(self.tools.join("invocations"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    /// Whether anything answers on the destination's endpoint now.
    fn destination_answers(&self) -> bool {
        let endpoint = self
            .destination
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        on_a_thread_of_its_own(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
            )
            .await
            .is_ok_and(|reached| reached.is_ok())
        })
    }

    /// Asks the destination's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage + Send>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        let endpoint = self
            .destination
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let params = kr_protocol::envelope::ParamsValue::from_typed(params).expect("parameters");
        on_a_thread_of_its_own(async {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("reaches the destination's daemon");
            client
                .request(method, &params)
                .await
                .expect("the call reaches the daemon")
                .expect("the daemon answers")
                .to_typed()
                .expect("decodes")
        })
    }

    /// Asks the destination's daemon to make way, which is how the product stops one, and waits
    /// until nothing answers. Best effort: this runs when a test ends, whichever way it ended.
    fn stop_destination_daemon(&self) {
        use kr_protocol::update::{
            HandoverStep, HostUpdateHandoverParams, HostUpdateHandoverResult, ReleaseName,
        };

        if !self.destination_answers() {
            return;
        }
        let endpoint = self
            .destination
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let environment = self.destination.environment_id();
        on_a_thread_of_its_own(async move {
            let target = ReleaseName::new("0.0.0+000000000000").expect("a release name");
            let Ok(mut client) =
                LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await
            else {
                return;
            };
            let step = |step: HandoverStep, attempt| {
                (
                    kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                    HostUpdateHandoverParams {
                        step,
                        target: target.clone(),
                        attempt,
                    },
                )
            };
            let (action, params) = step(
                HandoverStep::Prepare,
                kr_protocol::scalars::Nullable::null(),
            );
            let Ok(Ok(prepared)) = client
                .mutate(
                    Method::HostUpdateHandover,
                    action,
                    kr_protocol::envelope::ActionTarget::environment(environment),
                    &params,
                )
                .await
            else {
                return;
            };
            let Ok(prepared) = prepared.to_typed::<HostUpdateHandoverResult>() else {
                return;
            };
            let (action, params) = step(HandoverStep::Stop, prepared.attempt);
            let _ = client
                .mutate(
                    Method::HostUpdateHandover,
                    action,
                    kr_protocol::envelope::ActionTarget::environment(environment),
                    &params,
                )
                .await;
        });
        let started = Instant::now();
        while self.destination_answers() && started.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Creates an invisible session in the destination through the bridge, and returns what `kr`
    /// printed of it.
    fn create_in_destination(&self) -> Value {
        let created = self.run(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--environment",
            "dest",
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ]);
        assert!(
            created.status.success(),
            "kr new --environment dest: {}; it said {}",
            String::from_utf8_lossy(&created.stdout),
            String::from_utf8_lossy(&created.stderr)
        );
        serde_json::from_slice(&created.stdout).expect("kr printed JSON")
    }
}

/// Runs a future to its end on a thread of its own, where blocking is allowed.
///
/// A test is itself on a runtime, and a drop that has to ask a daemon something runs on it too:
/// neither may start a second runtime on the thread it is running on.
fn on_a_thread_of_its_own<T: Send>(future: impl std::future::Future<Output = T> + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime")
                    .block_on(future)
            })
            .join()
            .expect("the thread ran to its end")
    })
}

/// The directory a path resolves to, so a comparison is of places and not of how they were named.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("the path is there")
}

/// KR-REQ-03.14, 03.15: `kr new --environment <label>` for a stopped environment starts what it
/// needs there, through the destination's own configured startup, and creates the session in the
/// destination: it starts where the destination user's home is, and it is in no environment but
/// that one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_created_through_a_bridge_starts_the_destinations_daemon_and_lives_there() {
    let world = World::start().await;
    world.enrol_destination();
    assert!(
        !world.destination_answers(),
        "the destination has no daemon before the create"
    );
    assert_eq!(world.invocations(), 0, "enrolling started nothing there");

    let created = world.create_in_destination();
    assert_eq!(created["state"], "live", "{created}");
    assert_eq!(
        created["environment_id"],
        world.destination.environment_id().to_string(),
        "the session is the destination's own: {created}"
    );
    // Nothing of the invoking host's working directory crossed: it starts at the home the
    // destination's own login gave the helper.
    assert_eq!(
        resolved(Path::new(created["cwd"].as_str().expect("a directory"))),
        resolved(&world.home),
        "{created}"
    );
    assert!(
        world.destination_answers(),
        "the destination's daemon was started for the create"
    );
    let listed: kr_protocol::session::SessionListResult = world.ask(
        Method::SessionList,
        &kr_protocol::session::SessionListParams {
            environment_id: kr_protocol::scalars::Nullable::null(),
            include_closed: false,
        },
    );
    assert_eq!(listed.sessions.len(), 1, "{:?}", listed.sessions);
    assert_eq!(
        listed.sessions[0].session_id.to_string(),
        created["session_id"].as_str().expect("a session"),
    );
    // The source host's own daemon holds no session: the one that was created is not here.
    let here = world.run(&["--json", "list"]);
    let here: Value = serde_json::from_slice(&here.stdout).expect("kr list printed JSON");
    assert_eq!(here["sessions"].as_array().map_or(0, Vec::len), 0, "{here}");
    // One bridge to read the host's defaults and create; nothing else was started on the way.
    assert!(world.invocations() >= 1);
}

/// KR-REQ-03.14: what cannot be reached through a process bridge, or cannot be presented there, is
/// refused before anything is started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_bridge_cannot_serve_is_refused_before_anything_is_started() {
    let world = World::start().await;
    world.enrol_destination();
    // A terminal application opens where the session runs, and an enrolled environment has no
    // screen of this host's to open one on.
    let terminal = world.run(&["new", "--terminal", "--environment", "dest"]);
    assert!(!terminal.status.success());
    assert!(
        String::from_utf8_lossy(&terminal.stderr).contains("--terminal"),
        "{}",
        String::from_utf8_lossy(&terminal.stderr)
    );
    // An environment reached by logging in to it has no process bridge to open.
    let ssh = world.run(&[
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "build-host",
        "--target",
        "build.example",
        "--user",
        "tester",
        "--helper",
        "/usr/local/bin/kr",
        "--environment-id",
        "55555555-5555-4555-8555-555555555555",
    ]);
    assert!(
        ssh.status.success(),
        "{}",
        String::from_utf8_lossy(&ssh.stderr)
    );
    let refused = world.run(&["new", "--invisible", "--environment", "build-host"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("not reached by a process bridge"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    // And a name that is neither an environment of this host nor an enrolled one.
    let unknown = world.run(&["new", "--invisible", "--environment", "no-such-environment"]);
    assert!(!unknown.status.success());
    assert_eq!(
        world.invocations(),
        0,
        "no bridge was opened for any of them"
    );
    assert!(!world.destination_answers());
}

/// KR-REQ-03.14: attaching to a session that has closed says how it ended, before this terminal is
/// touched, in an environment whose daemon is stopped: attaching is allowed to start what it needs
/// to learn that, and starts nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attach_to_a_closed_session_in_a_stopped_environment_says_how_it_ended() {
    let world = World::start().await;
    world.enrol_destination();
    let created = world.create_in_destination();
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();

    // Close it where it lives, through the destination's own daemon, and stop that daemon, as
    // stopping a distribution does.
    let mut close = std::process::Command::new(support::kr());
    close
        .args(["--json", "close", &session])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            world.destination.paths().runtime_root(),
        )
        .env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            world.destination.paths().state_root(),
        )
        .current_dir("/");
    assert!(close.output().expect("runs kr").status.success());
    // Closing is asynchronous: the daemon stops once the destination records the closure, and a
    // distribution that stopped in the middle of one would leave nothing to be asked about it.
    let started = Instant::now();
    loop {
        let listed: kr_protocol::session::SessionListResult = world.ask(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: kr_protocol::scalars::Nullable::null(),
                include_closed: true,
            },
        );
        if listed.sessions.iter().any(|summary| {
            summary.session_id.to_string() == session
                && summary.state == kr_protocol::session::SessionState::Closed
        }) {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the session did not close: {listed:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    world.stop_destination_daemon();
    assert!(!world.destination_answers());

    let before = world.invocations();
    let attached = world.run(&["--json", "attach", &session, "--environment", "dest"]);
    let report: Value = serde_json::from_slice(&attached.stdout).unwrap_or_else(|error| {
        panic!(
            "kr attach printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&attached.stdout),
            String::from_utf8_lossy(&attached.stderr)
        )
    });
    assert!(!attached.status.success(), "{report}");
    assert_eq!(report["code"], "SESSION_CLOSED", "{report}");
    assert!(
        report["closure"].is_object(),
        "the destination's record of how it ended came with the refusal: {report}"
    );
    assert!(
        world.invocations() > before,
        "a bridge was opened to ask the destination"
    );
    assert!(
        world.destination_answers(),
        "asking a stopped environment what became of a session is allowed to start its daemon"
    );
}

/// A terminal, with `kr attach` running on it through a shell that reports how it ended.
struct Terminal {
    _pty: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
    writer: Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

impl Terminal {
    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default(),
        )
        .into_owned()
    }

    fn expect_within(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {marker:?} in the terminal: {}",
                started.elapsed(),
                self.text().escape_debug()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn types(&self, text: &str) {
        let mut writer = self.writer.lock().expect("the writer");
        writer.write_all(text.as_bytes()).expect("types");
        writer.flush().expect("flushes");
    }
}

impl World {
    /// Runs `kr attach` for a display number in the destination, on a terminal that answers the
    /// command's questions about what it is.
    fn attach_on_a_terminal(&self, display: &str) -> Terminal {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut builder = CommandBuilder::new("/bin/sh");
        builder.arg("-c");
        builder.arg(format!(
            "{} attach {display} --environment dest; printf 'attach-finished-%s\\n' \"$?\"",
            support::kr().display()
        ));
        builder.env_clear();
        builder.env("PATH", format!("{}:/usr/bin:/bin", self.tools.display()));
        builder.env("TERM", "xterm-256color");
        builder.env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            self.source.paths().runtime_root(),
        );
        builder.env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            self.source.paths().state_root(),
        );
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            builder.env("TMPDIR", temporary);
        }
        builder.cwd("/");
        let shell = pty.slave.spawn_command(builder).expect("starts the shell");
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        let mut reader = pty.master.try_clone_reader().expect("a reader");
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut seen) = collected.lock() {
                    seen.extend_from_slice(&buffer[..read]);
                }
            }
        });
        let writer = Arc::new(std::sync::Mutex::new(
            pty.master.take_writer().expect("a writer"),
        ));
        let terminal = Terminal {
            _pty: pty,
            shell,
            seen,
            writer,
        };
        // The command asks the terminal what it is before it changes anything, and a terminal
        // answers. Without the answer the bounded handshake fails and there is nothing to attach.
        terminal.expect_within("\x1b[c", "the command asked this terminal what it is");
        terminal.types("\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        terminal
    }
}

/// KR-REQ-03.14, 03.15: a terminal attached through a bridge to a live session in the destination
/// carries what is typed to the session's shell there, and what the shell prints back, and the
/// shell is the destination user's, started in the destination's home with the destination's own
/// environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_attached_through_a_bridge_reaches_the_shell_in_the_destination() {
    let world = World::start().await;
    world.enrol_destination();
    let created = world.create_in_destination();
    let display = created["display_number"].to_string();

    let terminal = world.attach_on_a_terminal(&display);
    terminal.types("printf 'in-%s %s %s\\n' destination \"$PWD\" \"${HOME:+home-set}\"\r");
    terminal.expect_within(
        "in-destination",
        "what was typed reached the shell and its output came back",
    );
    let text = terminal.text();
    assert!(
        text.contains(&world.home.display().to_string())
            || text.contains(&resolved(&world.home).display().to_string()),
        "the shell started in the destination's home: {}",
        text.escape_debug()
    );
    assert!(
        text.contains("home-set"),
        "and has a home of its own, which is the destination's: {}",
        text.escape_debug()
    );
    // Ending the session from where it lives ends the attachment, and the command says it did.
    terminal.types("exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// KR-REQ-25.26: `kr bridge enrol --access ssh --probe` learns the destination's identity from its
/// helper over ssh, and a refresh then registers the helper's scoped channel for the record. The
/// destination has to be running: asking over ssh starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ssh_host_is_enrolled_by_asking_its_helper_and_registers_its_channel() {
    let world = World::start().await;
    // The destination's daemon is started by a create, as for any environment that is running.
    world.enrol_destination();
    let _ = world.create_in_destination();

    let helper = support::kr().display().to_string();
    // The stand-in runs the helper as this test's own account, as a login of that name would.
    let account = String::from_utf8(
        std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .expect("id runs")
            .stdout,
    )
    .expect("a name")
    .trim()
    .to_owned();
    let enrolled = world.run(&[
        "--json",
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "sshdest",
        "--target",
        "build.example",
        "--user",
        &account,
        "--helper",
        &helper,
        "--probe",
    ]);
    assert!(
        enrolled.status.success(),
        "{}; it said {}",
        String::from_utf8_lossy(&enrolled.stdout),
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let row: Value = serde_json::from_slice(&enrolled.stdout).expect("kr printed JSON");
    assert_eq!(
        row["row"]["enrolment"]["environment_id"],
        world.destination.environment_id().to_string(),
        "the identity is the destination's own, learned from its helper: {row}"
    );
    assert_eq!(row["row"]["readiness"]["channel_scoped"], false, "{row}");

    let refreshed = world.run(&["--json", "bridge", "refresh", "sshdest"]);
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    let refreshed: Value = serde_json::from_slice(&refreshed.stdout).expect("kr printed JSON");
    assert_eq!(
        refreshed["verification"]["environment_id"],
        world.destination.environment_id().to_string(),
        "{refreshed}"
    );
    assert_eq!(
        refreshed["row"]["readiness"]["channel_scoped"], true,
        "{refreshed}"
    );
    assert_eq!(refreshed["started"], false, "{refreshed}");

    // The identity a destination answers with is checked against one the person gave.
    let wrong = world.run(&[
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "other",
        "--target",
        "build.example",
        "--user",
        &account,
        "--helper",
        &helper,
        "--environment-id",
        "66666666-6666-4666-8666-666666666666",
        "--probe",
    ]);
    assert!(!wrong.status.success());
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("different environment"),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
}
