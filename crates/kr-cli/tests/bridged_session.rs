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

/// What a login in the destination gives the helper as its `HOME`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Login {
    /// The destination user's home, as `wsl.exe --user` and a container runtime's exec set it.
    Home,
    /// None at all.
    NoHome,
    /// A value that is not an absolute path.
    RelativeHome,
}

/// What the stand-in for `wsl.exe` does: record how it was run, and run what follows `--exec` in the
/// destination's own environment, with what a login there would give it and nothing of the caller's.
fn stand_in(tools: &Path, destination: &Path, home: &Path, login: Login) -> String {
    let temporary = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    let home_variable = match login {
        Login::Home => format!("HOME='{}'", home.display()),
        Login::NoHome => String::new(),
        Login::RelativeHome => "HOME=relative/home".to_owned(),
    };
    format!(
        r##"#!/bin/sh
printf '%s\n' "$*" >>'{tools}/invocations'
# What the platform says of the distribution, which a test sets to say it is stopped
# (`distribution-state`) and to say it prints its words in another language (`host-language`).
# Asking runs nothing in the distribution, as the real command does not. Like the real command it
# writes UTF-16LE, and the listings of names print nothing else.
if [ "$1" = "--list" ]; then
  state="$(cat '{tools}/distribution-state' 2>/dev/null || echo Running)"
  case "$*" in
    "--list --all --quiet")
      printf 'Test-Distro\r\n' | iconv -f UTF-8 -t UTF-16LE
      ;;
    "--list --running --quiet")
      if [ "$state" = Running ]; then printf 'Test-Distro\r\n' | iconv -f UTF-8 -t UTF-16LE; fi
      ;;
    "--list --verbose")
      word="$state"
      if [ "$(cat '{tools}/host-language' 2>/dev/null)" = de ]; then
        if [ "$state" = Running ]; then word='Wird ausgeführt'; else word='Beendet'; fi
      fi
      printf '  NAME          STATE      VERSION\r\n  Test-Distro   %s   2\r\n' "$word" \
        | iconv -f UTF-8 -t UTF-16LE
      ;;
    *)
      echo "the stand-in for wsl.exe has no answer for: $*" >&2
      exit 2
      ;;
  esac
  exit 0
fi
# The helper is this process, which becomes it, so a test can name the one it means to end.
printf '%s\n' "$$" >'{tools}/last-bridge.pid'
# A test that wants the destination unreachable from some run onward says from which.
if [ -f '{tools}/unreachable-after' ] \
  && [ "$(wc -l <'{tools}/invocations')" -gt "$(cat '{tools}/unreachable-after')" ]; then
  exit 1
fi
while [ "$#" -gt 0 ] && [ "$1" != "--exec" ]; do shift; done
shift
exec /usr/bin/env -i PATH=/usr/bin:/bin {home_variable} TMPDIR='{temporary}' \
  KR_RUNTIME_DIR='{runtime}' KR_STATE_DIR='{state}' "$@"
"##,
        tools = tools.display(),
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
        Self::start_with(Login::Home).await
    }

    async fn start_with(login: Login) -> Self {
        let source = teardown::Tree::create();
        let destination = teardown::Tree::create();
        let home = destination.root().join("home");
        std::fs::create_dir_all(&home).expect("the destination user's home");
        let tools = source.root().join("tools");
        std::fs::create_dir_all(&tools).expect("a directory for the stand-in");
        let text = tools.join("wsl.exe.text");
        std::fs::write(&text, stand_in(&tools, destination.root(), &home, login))
            .expect("the stand-in");
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
        // A rootless container runtime finds its own storage and sockets through these.
        for variable in [
            "HOME",
            "XDG_RUNTIME_DIR",
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
        ] {
            if let Some(value) = std::env::var_os(variable) {
                command.env(variable, value);
            }
        }
        command
    }

    /// Runs `kr` on the source host to its end.
    fn run(&self, arguments: &[&str]) -> std::process::Output {
        self.kr(arguments).output().expect("runs kr")
    }

    /// Records the destination in the source host's own inventory, as a WSL distribution.
    fn enrol_destination(&self) {
        let enrolled = self.enrolling(None);
        assert!(
            enrolled.status.success(),
            "enrolling: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );
    }

    /// Records the destination in the source host's own inventory, naming `clipboard` as where its
    /// clipboard writes go, and returns what `kr` said.
    fn enrolling(&self, clipboard: Option<&str>) -> std::process::Output {
        let environment = self.destination.environment_id().to_string();
        let helper = support::kr().display().to_string();
        let mut arguments = vec![
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
        ];
        if let Some(clipboard) = clipboard {
            arguments.extend(["--clipboard", clipboard]);
        }
        self.run(&arguments)
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
        // Nothing answering is not the daemon gone: it gives up its endpoint before it ends, and
        // a command that starts the next one in between is told another daemon owns the
        // environment. The environment's lock is the operating system's word that the process has
        // ended, and it is the one the next daemon takes.
        let lock = self.destination.environment().singleton_lock();
        while started.elapsed() < Duration::from_secs(60) {
            if kr_controller::singleton::SingletonLock::hold(
                &lock,
                self.destination.environment_id(),
            )
            .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Closes `session` where it lives, through the destination's own daemon, and waits until that
    /// daemon says it is closed and its worker has ended.
    ///
    /// Closing is asynchronous: a daemon stopped before the destination records the closure would
    /// leave nothing to be asked about it.
    fn close_in_destination(&self, session: &str) {
        let worker = worker_process(&self.destination, session);
        let mut close = std::process::Command::new(support::kr());
        close
            .args(["--json", "close", session])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.destination.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.destination.paths().state_root(),
            )
            .current_dir("/");
        assert!(close.output().expect("runs kr").status.success());
        self.wait_until_closed_in_destination(session, &worker);
    }

    /// What the destination's daemon wrote to its log, from the end, for a failure to say.
    fn destination_daemon_log(&self) -> String {
        let log = self
            .destination
            .environment()
            .state_dir()
            .join("controller.log");
        let text = std::fs::read_to_string(&log)
            .unwrap_or_else(|error| format!("(no log at {}: {error})", log.display()));
        let from = text.len().saturating_sub(4000);
        text[text.ceil_char_boundary(from)..].to_owned()
    }

    /// Refreshes the enrolment `label` through `kr` and returns what it printed. A refusal of the
    /// destination's answer is not a failed command: the row comes back with no verification.
    fn refreshed(&self, label: &str) -> Value {
        let refreshed = self.run(&["--json", "bridge", "refresh", label]);
        assert!(
            refreshed.status.success(),
            "{}",
            String::from_utf8_lossy(&refreshed.stderr)
        );
        serde_json::from_slice(&refreshed.stdout).expect("kr printed JSON")
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
            "kr new --environment dest: {}; it said {}; the destination's daemon logged {}",
            String::from_utf8_lossy(&created.stdout),
            String::from_utf8_lossy(&created.stderr),
            self.destination_daemon_log()
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
    world.close_in_destination(&session);
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
    pty: portable_pty::PtyPair,
    /// The modes the terminal was in before anything ran on it, which a command has to leave it in.
    before: rustix::termios::Termios,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
    writer: Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

/// The descriptor a terminal's state is read through: a pseudo-terminal pair shares one line
/// discipline, so the master answers for the state the command set on the slave.
fn terminal_fd(pty: &portable_pty::PtyPair) -> std::os::fd::BorrowedFd<'_> {
    let raw = pty
        .master
        .as_raw_fd()
        .expect("the terminal has a descriptor");
    // The descriptor belongs to the pair, which outlives every use of this borrow.
    #[expect(
        unsafe_code,
        reason = "borrowing a descriptor the caller owns has no safe form"
    )]
    unsafe {
        std::os::fd::BorrowedFd::borrow_raw(raw)
    }
}

impl Terminal {
    /// The terminal's modes now.
    fn modes(&self) -> rustix::termios::Termios {
        rustix::termios::tcgetattr(terminal_fd(&self.pty)).expect("reads the modes")
    }

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
        self.expect_nth_within(marker, 1, what);
    }

    /// Waits until `marker` has been seen `count` times.
    fn expect_nth_within(&self, marker: &str, count: usize, what: &str) {
        let started = Instant::now();
        while self.text().matches(marker).count() < count {
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

    /// Waits for the shell to print `marker` followed by `count` values, each ended by `|`, and
    /// returns them.
    ///
    /// The command typed to print them names its values as `%s`, which is what tells its echo from
    /// its output: only output has a value where the echo has a placeholder.
    fn reported_within(&self, marker: &str, count: usize, what: &str) -> Vec<String> {
        let started = Instant::now();
        loop {
            let text = self.text();
            let printed = text.match_indices(marker).find_map(|(at, _)| {
                let line = text[at + marker.len()..].lines().next()?;
                if line.starts_with('%') {
                    return None;
                }
                let values: Vec<&str> = line.split('|').collect();
                // The last part is what follows the final separator, and a line still being
                // written has not reached it.
                (values.len() == count + 1).then(|| {
                    values[..count]
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect()
                })
            });
            if let Some(printed) = printed {
                return printed;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for the shell to print {marker:?}: {}",
                started.elapsed(),
                text.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl World {
    /// Runs a shell command on a terminal of its own, in the source host's environment, and
    /// returns that terminal. The command asks it nothing yet: answering is the test's.
    fn terminal_running(&self, command: &str) -> Terminal {
        self.terminal_running_in(Path::new("/"), command, &[])
    }

    /// As [`Self::terminal_running`], in `directory` and with `variables` added to the terminal's
    /// environment.
    fn terminal_running_in(
        &self,
        directory: &Path,
        command: &str,
        variables: &[(&str, &std::ffi::OsStr)],
    ) -> Terminal {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let before = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the modes");
        let mut builder = CommandBuilder::new("/bin/sh");
        builder.arg("-c");
        builder.arg(command);
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
        for (name, value) in variables {
            builder.env(name, value);
        }
        builder.cwd(directory);
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
        Terminal {
            before,
            pty,
            shell,
            seen,
            writer,
        }
    }

    /// Runs `kr attach` for a display number in the destination, on a terminal that answers the
    /// command's questions about what it is.
    fn attach_on_a_terminal(&self, display: &str) -> Terminal {
        let terminal = self.terminal_running(&format!(
            "{} attach {display} --environment dest; printf 'attach-finished-%s\\n' \"$?\"",
            support::kr().display()
        ));
        // The command asks the terminal what it is before it changes anything, and a terminal
        // answers. Without the answer the bounded handshake fails and there is nothing to attach.
        terminal.expect_within("\x1b[c", "the command asked this terminal what it is");
        terminal.types("\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        terminal
    }

    /// Runs `kr attach` for a display number of the source host's own environment, on a terminal
    /// that answers the command's questions about what it is.
    fn attach_here_on_a_terminal(&self, display: &str) -> Terminal {
        let terminal = self.terminal_running(&format!(
            "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
            support::kr().display()
        ));
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
    // The directory is read once its line is whole, which its closing `|` says. A terminal is read
    // as the system hands it over, and a line the shell wrote in one piece can be handed over in two.
    terminal.types("printf 'in-%s|%s|\\n' destination \"$PWD\"\r");
    let printed = terminal.reported_within(
        "in-destination|",
        1,
        "what was typed reached the shell and its output came back",
    );
    assert_eq!(
        resolved(Path::new(&printed[0])),
        resolved(&world.home),
        "the shell started in the destination's home"
    );
    // Ending the session from where it lives ends the attachment, and the command says it did.
    terminal.types("exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// What a shell created through a bridge has as `HOME` and starts in, for a destination whose login
/// gave the helper this `HOME`.
async fn a_shell_has_a_home_and_starts_in_it(login: Login) {
    let world = World::start_with(login).await;
    world.enrol_destination();
    let created = world.create_in_destination();
    let display = created["display_number"].to_string();

    let terminal = world.attach_on_a_terminal(&display);
    terminal.types("printf 'reports|%s|%s|\\n' \"$HOME\" \"$PWD\"\r");
    let printed = terminal.reported_within("reports|", 2, "the shell reported its home");
    let (home, directory) = (&printed[0], &printed[1]);
    assert!(
        home.starts_with('/'),
        "the shell's HOME is an absolute path: {home:?}"
    );
    assert_eq!(
        resolved(Path::new(home)),
        resolved(Path::new(directory)),
        "the shell starts in the directory its HOME names"
    );
    if login == Login::Home {
        assert_eq!(
            resolved(Path::new(home)),
            resolved(&world.home),
            "and it is the destination user's own"
        );
    }
    terminal.types("exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// KR-REQ-03.14, 03.15: the destination user's `HOME`, as the login gave it, is the shell's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_created_through_a_bridge_has_the_destination_users_home() {
    a_shell_has_a_home_and_starts_in_it(Login::Home).await;
}

/// KR-REQ-03.14, 03.15: a login that gave the helper no `HOME` still leaves the shell with one,
/// and it is the directory the shell starts in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_created_through_a_bridge_has_a_home_when_the_login_gave_none() {
    a_shell_has_a_home_and_starts_in_it(Login::NoHome).await;
}

/// KR-REQ-03.14, 03.15: a `HOME` that is not an absolute path is not carried into the shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_created_through_a_bridge_has_no_relative_home() {
    a_shell_has_a_home_and_starts_in_it(Login::RelativeHome).await;
}

/// Runs `kr new --attach` with `arguments` on a terminal in `directory` that answers every question
/// the command asks about what it is, with `variables` added to the terminal's own environment, and
/// returns the terminal once the shell the command attaches is the person's.
fn a_created_session_attached_on_a_terminal(
    world: &World,
    directory: &Path,
    arguments: &str,
    variables: &[(&str, &std::ffi::OsStr)],
) -> Terminal {
    let terminal = world.terminal_running_in(
        directory,
        &format!(
            "{} new --attach --palette probe {arguments} --shell /bin/sh --startup interactive \
             --headless; printf 'create-finished-%s\\n' \"$?\"",
            support::kr().display()
        ),
        variables,
    );
    terminal.expect_nth_within("\x1b[c", 1, "the command asked this terminal what it is");
    terminal.types("\x1b]10;rgb:ffff/ffff/ffff\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c");
    terminal.expect_nth_within("\x1b[c", 2, "the attachment asked this terminal what it is");
    terminal.types("\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
    terminal
}

/// KR-REQ-03.14, 03.15, 07.25: a session created through a bridge for a person who is shown it
/// starts from what a login in the destination gives and from nothing of the terminal that asked:
/// its `HOME` and its `PATH` are the destination login's, where the terminal has others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shown_session_created_through_a_bridge_has_the_destination_logins_variables() {
    let world = World::start().await;
    world.enrol_destination();
    let source_home = world.source.root().join("source-home");
    std::fs::create_dir_all(&source_home).expect("the terminal's own home");
    let terminal = a_created_session_attached_on_a_terminal(
        &world,
        Path::new("/"),
        "--environment dest",
        &[("HOME", source_home.as_os_str())],
    );
    terminal.types("printf 'reports|%s|%s|\\n' \"$HOME\" \"$PATH\"\r");
    let printed =
        terminal.reported_within("reports|", 2, "the shell reported its login's variables");
    assert_eq!(
        resolved(Path::new(&printed[0])),
        resolved(&world.home),
        "HOME is the destination user's and not the terminal's"
    );
    assert_eq!(
        printed[1], "/usr/bin:/bin",
        "PATH is what the destination's login gave and not the terminal's, which has the stand-in first"
    );
    terminal.types("exit\r");
    terminal.expect_within("create-finished-", "the command ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// KR-REQ-07.25: a session created here for a person who is shown it carries the terminal's
/// environment, and a variable of it that is not text does not stop the create: the others arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_created_from_a_terminal_whose_environment_is_not_all_text_is_still_created() {
    use std::os::unix::ffi::OsStrExt as _;

    let world = World::start().await;
    let terminal = a_created_session_attached_on_a_terminal(
        &world,
        Path::new("/"),
        "",
        &[
            ("EXAMPLE_KEPT", std::ffi::OsStr::new("kept")),
            ("EXAMPLE_BYTES", std::ffi::OsStr::from_bytes(b"\xff\xfe")),
        ],
    );
    terminal.types("printf 'reports|%s|\\n' \"$EXAMPLE_KEPT\"\r");
    let printed = terminal.reported_within(
        "reports|",
        1,
        "the shell reported the variable it was given",
    );
    assert_eq!(printed[0], "kept", "the text variable reached the shell");
    terminal.types("exit\r");
    terminal.expect_within("create-finished-", "the command ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// KR-REQ-07.25: a session created here from a directory whose name is not text is not started in
/// the other directory a lossy rendering of that name spells.
///
/// Both directories exist: one holds the terminal, and the other is named by the text a name with
/// bytes that are not text is shown as. The file systems macOS uses refuse the first, so only
/// Linux can make it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_created_from_a_directory_whose_name_is_not_text_is_not_started_in_a_lookalike() {
    use std::os::unix::ffi::OsStrExt as _;

    let world = World::start().await;
    let directory = world
        .source
        .root()
        .join(std::ffi::OsStr::from_bytes(b"not-text-\xff"));
    let lookalike = world.source.root().join("not-text-\u{fffd}");
    std::fs::create_dir(&directory).expect("a directory whose name is not text");
    std::fs::create_dir(&lookalike).expect("the directory its lossy name spells");
    let terminal = a_created_session_attached_on_a_terminal(&world, &directory, "", &[]);
    terminal.types("printf 'reports|%s|\\n' \"$PWD\"\r");
    let printed = terminal.reported_within("reports|", 1, "the shell reported where it started");
    assert_ne!(
        resolved(Path::new(&printed[0])),
        resolved(&lookalike),
        "the shell started in the directory a lossy rendering of the terminal's spells"
    );
    terminal.types("exit\r");
    terminal.expect_within("create-finished-", "the command ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// Creates a session through a bridge from a terminal that is asked for its colours while the
/// person types five bytes, with the destination unreachable for the attachment that follows, and
/// returns what the terminal showed.
///
/// `answer_the_attachment` says whether the terminal answers the attachment's own questions about
/// what it is: where it does not, the attachment fails there, and where it does, it fails reaching
/// the destination.
async fn a_create_that_is_not_attached(answer_the_attachment: bool) -> String {
    let world = World::start().await;
    world.enrol_destination();
    // The bridge that creates is the first run of the stand-in; the one that attaches is the
    // second, and the destination is unreachable from there.
    std::fs::write(
        world.tools.join("unreachable-after"),
        (world.invocations() + 1).to_string(),
    )
    .expect("says from which run the destination is unreachable");

    let terminal = world.terminal_running(&format!(
        "{} new --attach --palette probe --environment dest --shell /bin/sh --startup interactive \
         --headless; printf 'create-finished-%s\\n' \"$?\"",
        support::kr().display()
    ));
    // The command asks this terminal for its colours, and the person types while it does.
    terminal.expect_nth_within("\x1b[c", 1, "the command asked this terminal what it is");
    terminal
        .types("\x1b]10;rgb:ffff/ffff/ffff\x1b\\typed\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c");
    if answer_the_attachment {
        terminal.expect_nth_within("\x1b[c", 2, "the attachment asked this terminal what it is");
        terminal.types("\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
    }
    terminal.expect_within("create-finished-", "the command ended");
    let text = terminal.text();
    let mut shell = terminal.shell;
    let _ = shell.wait();
    assert!(
        world.invocations() >= 2 || !answer_the_attachment,
        "the attachment tried the destination"
    );
    text
}

/// KR-REQ-03.14, 03.15: the helper of an attachment dying is a lost connection and not the end of
/// the session. The attachment ends saying so, with the code a host that cannot be reached has, the
/// terminal is the person's again as it was before, and the session is still alive where it lives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_dies_during_an_attachment_ends_it_as_a_lost_connection_and_frees_the_terminal()
 {
    let world = World::start().await;
    world.enrol_destination();
    let created = world.create_in_destination();
    let display = created["display_number"].to_string();
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();

    let terminal = world.attach_on_a_terminal(&display);
    terminal.types("printf 'live-%s\\n' 1\r");
    terminal.expect_within("live-1", "the attachment is carrying a session");
    assert!(
        !terminal
            .modes()
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON),
        "the attachment holds the terminal in raw mode while it is live"
    );

    // The helper is the bridge's far end. It is ended outright, as a distribution shut down under
    // it would end it.
    let helper = std::fs::read_to_string(world.tools.join("last-bridge.pid"))
        .expect("the stand-in recorded the helper it became");
    let ended = std::process::Command::new("kill")
        .args(["-KILL", helper.trim()])
        .status()
        .expect("sends the signal");
    assert!(ended.success(), "the helper was ended");

    terminal.expect_within(
        "the connection to the session ended",
        "the attachment said the connection was lost",
    );
    terminal.expect_within(
        "the bridge to the environment failed",
        "and, once the terminal was given back, why the bridge stopped",
    );
    terminal.expect_within(
        "attach-finished-3",
        "with the code of a host that was not reached",
    );
    let started = Instant::now();
    let after = loop {
        let modes = terminal.modes();
        if modes
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON)
        {
            break modes;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the terminal was not given back"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        after.local_modes.bits(),
        terminal.before.local_modes.bits(),
        "the terminal's local modes are as they were"
    );
    assert_eq!(
        after.input_modes.bits(),
        terminal.before.input_modes.bits(),
        "and its input modes"
    );
    assert!(
        terminal
            .text()
            .as_bytes()
            .windows(kr_cli::terminal::RESET_SEQUENCES.len())
            .any(|window| window == kr_cli::terminal::RESET_SEQUENCES),
        "and what the session had set on it was reset: {}",
        terminal.text().escape_debug()
    );

    // The helper was a way to the session, and the session did not end with it.
    let listed: kr_protocol::session::SessionListResult = world.ask(
        Method::SessionList,
        &kr_protocol::session::SessionListParams {
            environment_id: kr_protocol::scalars::Nullable::null(),
            include_closed: true,
        },
    );
    let summary = listed
        .sessions
        .iter()
        .find(|summary| summary.session_id.to_string() == session)
        .expect("the destination still lists the session");
    assert_ne!(
        summary.state,
        kr_protocol::session::SessionState::Closed,
        "a lost bridge does not close the session"
    );
    let mut shell = terminal.shell;
    let _ = shell.wait();
}

/// KR-REQ-03.14, 03.15, 07.04: what the person typed while the creating terminal was asked for its
/// colours is theirs. When the session is made and the attachment to it then fails, the command
/// says how many bytes were never delivered, as a create in this host does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_bridged_attachment_cannot_reach_the_session_says_what_typing_was_lost() {
    let text = a_create_that_is_not_attached(true).await;
    assert!(
        text.contains("5 bytes typed while this terminal was asked for its colours"),
        "the five bytes the person typed are accounted for: {}",
        text.escape_debug()
    );
    assert!(
        text.contains("created session"),
        "and the session is reported as made, once: {}",
        text.escape_debug()
    );
}

/// The same, where the attachment fails before it reaches the destination, asking this terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_bridged_attachment_cannot_ask_the_terminal_says_what_typing_was_lost() {
    let text = a_create_that_is_not_attached(false).await;
    assert!(
        text.contains("5 bytes typed while this terminal was asked for its colours"),
        "the five bytes the person typed are accounted for: {}",
        text.escape_debug()
    );
}

/// The control for the two above: where the attachment succeeds, what the person typed while the
/// terminal was asked for its colours reaches the session's shell, and nothing is reported lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_was_typed_while_a_create_asked_for_colours_reaches_the_bridged_shell() {
    let world = World::start().await;
    world.enrol_destination();
    let terminal = world.terminal_running(&format!(
        "{} new --attach --palette probe --environment dest --shell /bin/sh --startup interactive \
         --headless; printf 'create-finished-%s\\n' \"$?\"",
        support::kr().display()
    ));
    terminal.expect_nth_within("\x1b[c", 1, "the command asked this terminal what it is");
    // The five bytes begin a command, which the person finishes once the shell is theirs.
    terminal
        .types("\x1b]10;rgb:ffff/ffff/ffff\x1b\\echo \x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c");
    terminal.expect_nth_within("\x1b[c", 2, "the attachment asked this terminal what it is");
    terminal.types("\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
    terminal.types("delivered-$((1+1))\r");
    // The command typed in two parts is run once, and the sum is not in what was typed.
    terminal.expect_within("delivered-2", "the command typed in two parts ran");
    terminal.types("exit\r");
    terminal.expect_within("create-finished-", "the command ended with the session");
    let text = terminal.text();
    assert!(
        !text.contains("bytes typed while this terminal was asked"),
        "nothing typed is reported as lost where it was delivered: {}",
        text.escape_debug()
    );
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

    // The user the destination's helper answers as is the one the person named, and an enrolment
    // that names another is refused rather than recorded to fail at the first refresh.
    let wrong_user = world.run(&[
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "someone",
        "--target",
        "build.example",
        "--user",
        "someone-else",
        "--helper",
        &helper,
        "--probe",
    ]);
    assert!(!wrong_user.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_user.stderr).contains("a different user"),
        "{}",
        String::from_utf8_lossy(&wrong_user.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&world.run(&["--json", "bridge", "list"]).stdout)
            .contains("someone"),
        "nothing was recorded for it"
    );

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

// ---------------------------------------------------------------------------------------------
// An SSH host over a real `ssh` and a real `sshd`.

/// The program `name` on this host's search path, or `None` with the reason a test gives for
/// standing down. A run that sets `KR_REQUIRE_SSHD` treats a missing program as a failure instead,
/// so a host that should have them cannot pass without running.
fn program(name: &str) -> Option<PathBuf> {
    let found = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .chain(["/usr/sbin".into(), "/usr/local/sbin".into()])
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os("KR_REQUIRE_SSHD").is_none(),
            "KR_REQUIRE_SSHD is set and this host has no {name}"
        );
        eprintln!("skipped: this host has no {name}, which this test needs");
    }
    found
}

/// A private `sshd`, run as the current user on a loopback port, with a host key and an authorised
/// key made for this test, and stopped when it is dropped. It reads and writes nothing of the
/// account's `~/.ssh`: its keys are in the directory it is given, it runs none of the account's
/// `~/.ssh/rc`, and the `ssh` that reaches it is given its own configuration, which names the
/// server's port, the client key and the host keys this login trusts. The remote command still
/// runs under the account's own shell, which reads whatever startup files that shell reads for a
/// command it is given. Every session starts with `environment`, which is how the helper finds
/// the environment it is the helper of.
struct PrivateSshd {
    child: std::process::Child,
    port: u16,
    directory: PathBuf,
    ssh: PathBuf,
    host_key: PathBuf,
}

impl Drop for PrivateSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PrivateSshd {
    /// Starts one, or says why this host cannot: no `sshd` to run, no `ssh-keygen` to make keys
    /// with, or no `ssh` to reach it.
    fn start(directory: &Path, environment: &str) -> Option<Self> {
        use std::os::unix::fs::PermissionsExt as _;

        let sshd = program("sshd")?;
        let keygen = program("ssh-keygen")?;
        let ssh = program("ssh")?;
        std::fs::create_dir_all(directory).expect("a directory for the server's keys");
        let make = |name: &str| {
            let path = directory.join(name);
            let made = std::process::Command::new(&keygen)
                .current_dir(directory)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path)
                .status()
                .expect("ssh-keygen runs");
            assert!(made.success(), "ssh-keygen makes a {name}");
            path
        };
        let host_key = make("hostkey");
        let client_key = make("clientkey");
        let authorised = directory.join("authorized_keys");
        std::fs::copy(client_key.with_extension("pub"), &authorised).expect("an authorised key");
        for path in [&authorised, &host_key, &client_key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only keys");
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free loopback port")
            .port();
        let log = std::fs::File::create(directory.join("sshd.log")).expect("a log");
        let child = std::process::Command::new(sshd)
            .current_dir(directory)
            .args(["-D", "-e", "-f", "/dev/null", "-h"])
            .arg(&host_key)
            .arg("-p")
            .arg(port.to_string())
            .args(["-o", "ListenAddress=127.0.0.1", "-o", "PidFile=none"])
            .args([
                "-o",
                "UsePAM=no",
                "-o",
                "StrictModes=no",
                "-o",
                "PermitUserRC=no",
            ])
            .arg("-o")
            .arg(format!("AuthorizedKeysFile={}", authorised.display()))
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "KbdInteractiveAuthentication=no"])
            .arg("-o")
            .arg(format!("SetEnv {environment}"))
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("a log handle"))
            .stderr(log)
            .spawn()
            .expect("sshd starts");
        let server = Self {
            child,
            port,
            directory: directory.to_path_buf(),
            ssh,
            host_key,
        };
        // Ready is a connection that is accepted, not a moment that has passed.
        let started = Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "sshd never accepted a connection: {}",
                server.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(server)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("sshd.log")).unwrap_or_default()
    }

    /// Makes the program the daemon runs as `ssh` in `tools`: the real `ssh`, given a
    /// configuration file of this test's own, because `ssh` finds the account's `~/.ssh/config`
    /// from the account database and no variable moves it. Every argument the daemon passes
    /// follows the configuration unchanged, and each run is written to `ssh-invocations`. The
    /// host `kr-test-sshd` is this server, and `public` is the host key this login trusts for it.
    fn reached_through(&self, tools: &Path, public: &Path) {
        let key = self.directory.join("clientkey");
        std::fs::write(
            self.directory.join("ssh_config"),
            format!(
                "Host kr-test-sshd\n  HostName 127.0.0.1\n  Port {port}\n  IdentityFile {key}\n  \
                 IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {known}\n  \
                 GlobalKnownHostsFile /dev/null\n  LogLevel ERROR\n",
                port = self.port,
                key = key.display(),
                known = self.directory.join("known_hosts").display()
            ),
        )
        .expect("the configuration of this test's own");
        self.trust(public);
        let text = tools.join("ssh.real.text");
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{tools}/ssh-invocations'\n\
                 exec '{ssh}' -F '{config}' \"$@\"\n",
                tools = tools.display(),
                ssh = self.ssh.display(),
                config = self.directory.join("ssh_config").display()
            ),
        )
        .expect("the program that runs ssh");
        kr_ipc::testing::place_program(&text, &tools.join("ssh"));
    }

    /// Makes `public`, a public key file, the one host key this login trusts for the server.
    fn trust(&self, public: &Path) {
        let key = std::fs::read_to_string(public).expect("a public key");
        let mut fields = key.split_whitespace();
        let (kind, material) = (
            fields.next().expect("a type"),
            fields.next().expect("a key"),
        );
        std::fs::write(
            self.directory.join("known_hosts"),
            format!("[127.0.0.1]:{} {kind} {material}\n", self.port),
        )
        .expect("the host keys this login trusts");
    }

    /// The server's own host key, public half.
    fn host_public(&self) -> PathBuf {
        self.host_key.with_extension("pub")
    }
}

/// KR-REQ-25.26: an SSH host registers its identity and its scoped channel through a real `ssh` to
/// a real `sshd`. The daemon runs the `ssh` of this host, the `sshd` is a private one on a loopback
/// port whose helper is the destination's own `kr bridge --stdio`, and what registers is what the
/// helper answers: the enrolment learns the destination's identity from it and a refresh records
/// the channel for that record. An identity the person did not give is refused and recorded
/// nowhere, and a host whose key this login does not trust registers nothing and takes back what
/// an earlier answer had registered, which the same host's key puts right again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ssh_host_registers_its_identity_and_channel_through_a_real_ssh_to_a_real_sshd() {
    let world = World::start().await;
    // The destination's daemon is started by a create, as for any environment that is running.
    world.enrol_destination();
    let _ = world.create_in_destination();
    let environment = format!(
        "KR_RUNTIME_DIR={} KR_STATE_DIR={} HOME={}",
        world.destination.root().join("r").display(),
        world.destination.root().join("s").display(),
        world.home.display()
    );
    let Some(server) = PrivateSshd::start(&world.source.root().join("sshd"), &environment) else {
        return;
    };
    server.reached_through(&world.tools, &server.host_public());

    let helper = support::kr().display().to_string();
    let account = String::from_utf8(
        std::process::Command::new("/usr/bin/id")
            .current_dir("/")
            .arg("-un")
            .output()
            .expect("id runs")
            .stdout,
    )
    .expect("a name")
    .trim()
    .to_owned();
    // The rows `kr bridge list` prints, from a command that succeeded.
    let rows = || -> Vec<Value> {
        let listed = world.run(&["--json", "bridge", "list"]);
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let listed: Value = serde_json::from_slice(&listed.stdout).expect("kr printed JSON");
        listed["rows"].as_array().expect("rows").clone()
    };
    let channel_scoped = |label: &str| -> bool {
        rows()
            .iter()
            .find(|row| row["enrolment"]["label"] == label)
            .unwrap_or_else(|| panic!("no row for {label}"))["readiness"]["channel_scoped"]
            .as_bool()
            .expect("a flag")
    };
    let accepted = || server.log().matches("Accepted publickey for").count();
    let enrolled = world.run(&[
        "--json",
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "sshdest",
        "--target",
        "kr-test-sshd",
        "--user",
        &account,
        "--helper",
        &helper,
        "--probe",
    ]);
    assert!(
        enrolled.status.success(),
        "{}; it said {}; sshd logged {}",
        String::from_utf8_lossy(&enrolled.stdout),
        String::from_utf8_lossy(&enrolled.stderr),
        server.log()
    );
    let row: Value = serde_json::from_slice(&enrolled.stdout).expect("kr printed JSON");
    assert_eq!(
        row["row"]["enrolment"]["environment_id"],
        world.destination.environment_id().to_string(),
        "the identity is the destination's own, learned from its helper over ssh: {row}"
    );
    assert_eq!(row["row"]["readiness"]["channel_scoped"], false, "{row}");

    let refreshed = world.run(&["--json", "bridge", "refresh", "sshdest"]);
    assert!(
        refreshed.status.success(),
        "{}; sshd logged {}",
        String::from_utf8_lossy(&refreshed.stderr),
        server.log()
    );
    let refreshed: Value = serde_json::from_slice(&refreshed.stdout).expect("kr printed JSON");
    assert_eq!(
        refreshed["verification"]["environment_id"],
        world.destination.environment_id().to_string(),
        "{refreshed}"
    );
    assert_eq!(refreshed["verification"]["os_user"], account, "{refreshed}");
    assert_eq!(
        refreshed["row"]["readiness"]["channel_scoped"], true,
        "{refreshed}"
    );
    assert_eq!(refreshed["started"], false, "{refreshed}");
    assert!(
        server.log().contains("Accepted publickey for"),
        "the server authenticated the key this test made: {}",
        server.log()
    );
    // An identity the person did not give is refused, and nothing is recorded for it.
    let wrong = world.run(&[
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "other",
        "--target",
        "kr-test-sshd",
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
    assert!(
        rows()
            .iter()
            .all(|row| row["enrolment"]["label"] != "other"),
        "nothing was recorded for it"
    );

    // A record that names an identity the destination's helper does not answer with registers
    // nothing: the helper is reached and answers, and the daemon refuses an answer that is not the
    // record's.
    let named = world.run(&[
        "--json",
        "bridge",
        "enrol",
        "--access",
        "ssh",
        "--label",
        "mismatch",
        "--target",
        "kr-test-sshd",
        "--user",
        &account,
        "--helper",
        &helper,
        "--environment-id",
        "66666666-6666-4666-8666-666666666666",
    ]);
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stderr)
    );
    let refused = world.refreshed("mismatch");
    assert!(refused["verification"].is_null(), "{refused}");
    assert_eq!(
        refused["row"]["readiness"]["channel_scoped"], false,
        "{refused}"
    );
    assert!(
        !channel_scoped("mismatch"),
        "no channel for another identity"
    );
    assert!(
        channel_scoped("sshdest"),
        "and the record whose identity the helper answered with keeps its own"
    );

    // A server whose host key this login does not trust is not asked anything: ssh refuses it
    // before the helper starts, and the channel an earlier answer had registered is taken back.
    // Trusting the server's own key again registers it again.
    let stranger = server.directory.join("stranger");
    let made = std::process::Command::new(program("ssh-keygen").expect("ssh-keygen"))
        .current_dir(&server.directory)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&stranger)
        .status()
        .expect("ssh-keygen runs");
    assert!(made.success());
    server.trust(&stranger.with_extension("pub"));
    let accepted_before = accepted();
    let untrusted = world.refreshed("sshdest");
    assert!(untrusted["verification"].is_null(), "{untrusted}");
    assert_eq!(
        untrusted["row"]["readiness"]["channel_scoped"], false,
        "{untrusted}"
    );
    assert_eq!(
        accepted(),
        accepted_before,
        "ssh refused the server before it authenticated: {}",
        server.log()
    );
    assert!(
        !channel_scoped("sshdest"),
        "a host this login does not trust holds no channel"
    );
    server.trust(&server.host_public());
    let again = world.refreshed("sshdest");
    assert_eq!(again["row"]["readiness"]["channel_scoped"], true, "{again}");
    assert!(
        channel_scoped("sshdest"),
        "the trusted host registers again"
    );

    let invoked = std::fs::read_to_string(world.tools.join("ssh-invocations"))
        .expect("the ssh of this host was run");
    assert!(
        invoked
            .lines()
            .all(|line| line.ends_with(&format!("-- kr-test-sshd {helper} bridge --stdio"))),
        "every ssh run asked the helper for its bridge and nothing else: {invoked}"
    );
}

// ---------------------------------------------------------------------------------------------
// A real container with a Linux `kr` in it.

/// The runtime these use, and the image it starts. The base image carries a shell and the C library
/// the binaries are linked against, and nothing of KalaReach. The image a container is started from
/// adds Git, which the daemon needs wherever it runs: a daemon on a host without it says so and
/// does not start.
const RUNTIME: &str = "podman";
const CONTAINER_IMAGE: &str = "docker.io/library/debian:stable-slim";
const INSTALLED_IMAGE: &str = "localhost/kalareach-bridge-test:git-1";

/// Where the directory holding the Linux programs is mounted inside the container.
const MOUNTED: &str = "/kr";

/// What a shell is typed, in which it writes a line of ordinary output, then asks its terminal to
/// write the clipboard, ring the bell and say what it is: what an export must keep out of its file.
const TYPED_WITH_SIDE_EFFECTS: &str = "printf 'out-%s\\n' marker; \
     printf '\\033]52;c;c2VjcmV0LXRva2Vu\\007\\007\\033[c'; printf 'after-%s\\n' marker\r";

/// The output an export file carries, joined from its chunks.
fn exported_output(document: &Value) -> Vec<u8> {
    document["output"]["chunks"]
        .as_array()
        .expect("chunks")
        .iter()
        .flat_map(|chunk| {
            kr_protocol::scalars::from_base64url(chunk["base64url"].as_str().expect("base64url"))
                .expect("decodes")
        })
        .collect()
}

fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The process a session's worker runs as, from the descriptor the worker published, which is read
/// while the session runs because the daemon retires it when it records the session's closure.
fn worker_process(
    tree: &teardown::Tree,
    session: &str,
) -> kr_protocol::identity::ProcessStartIdentity {
    kr_ipc::descriptor::read(
        &tree.environment(),
        session.parse().expect("a session identifier"),
    )
    .expect("reads the descriptor")
    .expect("the session is published")
    .process_start_identity
}

/// Waits until the kernel says a worker's process has ended.
///
/// A session that has closed is listed as closed while its worker is still ending, and what a
/// worker leaves is read, and a daemon is stopped, only once the daemon has seen the worker end, so
/// a test that goes on to export, to read the worker's journal or to stop the daemon asks for this
/// first: it is the question the daemon asks.
fn worker_ended(worker: &kr_protocol::identity::ProcessStartIdentity) {
    let started = Instant::now();
    while !matches!(
        kr_ipc::identity::process_state(worker),
        kr_ipc::identity::ProcessState::Ended
    ) {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the worker did not end"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs a session in the destination through a bridge that prints `TYPED_WITH_SIDE_EFFECTS`, ends it
/// by exiting its shell, and returns its identifier once the destination says it is closed and its
/// worker has ended, which is what an export of it needs.
fn a_closed_session_in_the_destination(world: &World) -> String {
    let created = world.create_in_destination();
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();
    let display = created["display_number"].to_string();
    let worker = worker_process(&world.destination, &session);
    let terminal = world.attach_on_a_terminal(&display);
    terminal.types(TYPED_WITH_SIDE_EFFECTS);
    terminal.expect_within("after-marker", "the shell printed past its side effects");
    // The engine answered the shell's question about the terminal, as a terminal would, and the
    // answer reached the shell as typing: the line discipline's kill character clears it.
    terminal.types("\x15exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
    world.wait_until_closed_in_destination(&session, &worker);
    session
}

impl World {
    /// Waits until the destination's daemon says `session` is closed, which its shell ending or a
    /// close brings about, and until the kernel says the process of its worker, `worker`, has
    /// ended.
    ///
    /// The daemon lists a session as closed while its worker is still ending, and what the worker
    /// leaves is read, and a daemon stopped, only once that worker has ended: the worker is named
    /// by every caller, so that none of them goes on without waiting for it.
    fn wait_until_closed_in_destination(
        &self,
        session: &str,
        worker: &kr_protocol::identity::ProcessStartIdentity,
    ) {
        worker_ended(worker);
        let started = Instant::now();
        loop {
            let listed: kr_protocol::session::SessionListResult = self.ask(
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
                return;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the session did not close: {listed:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Where an export file goes: a name that is not there yet.
    fn export_path(&self, name: &str) -> PathBuf {
        self.source.root().join(format!("{name}.json"))
    }
}

/// What a terminal is shown of a clipboard write: the escape that begins one, then the selection and
/// the content the shell wrote. The shell's own echo of what was typed holds these characters as
/// text, so only a write that reached the terminal as the escape itself matches.
const CLIPBOARD_WRITE_SEEN: &str = "\x1b]52;c;c2VjcmV0";

/// What is typed to a shell to write the clipboard, and then to say it has finished.
const TYPED_CLIPBOARD_WRITE: &str =
    "printf '\\033]52;c;c2VjcmV0\\007'; printf 'written-%s\\n' marker\r";

/// Attaches a terminal to a new session in the destination, has the shell there write the clipboard,
/// and returns what the terminal was shown, once the shell has said it finished and the session has
/// ended. The session's identifier is returned with it.
fn clipboard_write_through_a_bridge(world: &World) -> (String, String) {
    let created = world.create_in_destination();
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();
    let display = created["display_number"].to_string();
    let worker = worker_process(&world.destination, &session);
    let terminal = world.attach_on_a_terminal(&display);
    terminal.types(TYPED_CLIPBOARD_WRITE);
    terminal.expect_within("written-marker", "the shell finished writing the clipboard");
    terminal.types("exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let shown = terminal.text();
    let mut shell = terminal.shell;
    let _ = shell.wait();
    world.wait_until_closed_in_destination(&session, &worker);
    (session, shown)
}

/// The host events the destination's journal holds for a closed session, as (kind, detail).
fn host_events_in_destination(world: &World, session: &str) -> Vec<(String, String)> {
    let session_id: kr_protocol::ids::SessionId = session.parse().expect("an identifier");
    let journal = kr_worker::journal::Journal::open_read_only(
        world.destination.environment().journal_database(session_id),
    )
    .expect("the closed session's journal opens");
    journal
        .host_events()
        .expect("reads the host events")
        .into_iter()
        .map(|event| (event.kind, event.detail))
        .collect()
}

/// KR-REQ-18.11: a clipboard write from a session in an enrolled environment reaches the attaching
/// terminal only where the owner named the terminal as that environment's clipboard destination. The
/// control: the write is written to the terminal when the environment names it, and the same write
/// where it names nothing is sent to nobody and is a host event in the destination's own journal that
/// says what was asked and how much and keeps none of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clipboard_write_from_a_bridged_session_reaches_only_a_terminal_the_owner_named() {
    let named = World::start().await;
    let enrolled = named.enrolling(Some("terminal"));
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let (_, shown) = clipboard_write_through_a_bridge(&named);
    assert!(
        shown.contains(CLIPBOARD_WRITE_SEEN),
        "the terminal the owner named is written to: {}",
        shown.escape_debug()
    );

    let unnamed = World::start().await;
    unnamed.enrol_destination();
    let (session, shown) = clipboard_write_through_a_bridge(&unnamed);
    assert!(
        !shown.contains(CLIPBOARD_WRITE_SEEN),
        "no destination is named, so the terminal is not written to: {}",
        shown.escape_debug()
    );
    assert_eq!(
        host_events_in_destination(&unnamed, &session),
        vec![(
            "clipboard_write_declined".to_owned(),
            "Clipboard, 6 bytes".to_owned()
        )],
        "what was asked is recorded where the session lives, and none of its content"
    );
}

/// KR-REQ-18.11: the same write in a session on this host's own environment is written to the
/// attaching terminal, with no destination recorded anywhere: a local terminal is the destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clipboard_write_from_a_session_on_this_host_reaches_its_terminal() {
    let world = World::start().await;
    let created = world.run(&[
        "--json",
        "new",
        "--invisible",
        "--headless",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).expect("kr printed JSON");
    let display = created["display_number"].to_string();
    let terminal = world.attach_here_on_a_terminal(&display);
    terminal.types(TYPED_CLIPBOARD_WRITE);
    terminal.expect_within("written-marker", "the shell finished writing the clipboard");
    terminal.types("exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let shown = terminal.text();
    let mut shell = terminal.shell;
    let _ = shell.wait();
    assert!(
        shown.contains(CLIPBOARD_WRITE_SEEN),
        "{}",
        shown.escape_debug()
    );
}

/// KR-REQ-18.11: the one clipboard destination an enrolment can name is the terminal; any other
/// name is refused when the record is made and nothing is recorded, and `terminal` is recorded as
/// named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_can_name_only_the_terminal_as_its_clipboard_destination() {
    let world = World::start().await;
    for other in ["clipboard-sync", "ssh://elsewhere", "Terminal", ""] {
        let refused = world.enrolling(Some(other));
        assert!(!refused.status.success(), "{other:?} is refused");
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("only clipboard destination"),
            "{other:?}: {}",
            String::from_utf8_lossy(&refused.stderr)
        );
    }
    let listed = world.run(&["--json", "bridge", "list"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("kr printed JSON");
    assert_eq!(
        listed["rows"].as_array().map_or(0, Vec::len),
        0,
        "nothing was recorded: {listed}"
    );

    let accepted = world.enrolling(Some("terminal"));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let listed = world.run(&["--json", "bridge", "list"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("kr printed JSON");
    assert_eq!(
        listed["rows"][0]["enrolment"]["clipboard_destination"], "terminal",
        "{listed}"
    );
    assert_eq!(
        listed["rows"][0]["enrolment"]["takes_clipboard_writes"], true,
        "{listed}"
    );
}

/// KR-REQ-18.11, KR-REQ-25.25: `kr export` of a closed session in an enrolled environment reads the
/// destination's archive through a bridge and writes one file, owner-only, that carries what the
/// session printed and none of what it asked the terminal to do, with the clipboard write, the
/// bell and the question counted as omissions. It opens a bridge that starts nothing, so a
/// destination that was running is still the one that was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_through_a_bridge_carries_the_output_and_none_of_its_side_effects() {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::start().await;
    world.enrol_destination();
    let session = a_closed_session_in_the_destination(&world);
    assert!(
        world.destination_answers(),
        "the destination is running, as it was left"
    );

    let file = world.export_path("through-a-bridge");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        file.to_str().expect("a path"),
    ]);
    assert!(
        exported.status.success(),
        "kr export: {}; it said {}; the destination's daemon logged {}",
        String::from_utf8_lossy(&exported.stdout),
        String::from_utf8_lossy(&exported.stderr),
        world.destination_daemon_log()
    );
    let said: Value = serde_json::from_slice(&exported.stdout).expect("kr printed JSON");
    assert_eq!(said["ok"], true, "{said}");
    assert_eq!(said["session_id"], session.as_str(), "{said}");

    let bytes = std::fs::read(&file).expect("the file was written");
    let document: Value = serde_json::from_slice(&bytes).expect("the file is JSON");
    assert_eq!(document["format"], "kalareach-session-export/1");
    assert_eq!(document["session"]["session_id"], session.as_str());
    assert_eq!(document["closure"]["reason"], "root_exit", "{document}");
    let output = exported_output(&document);
    assert!(
        holds(&output, "out-marker"),
        "{}",
        String::from_utf8_lossy(&output).escape_debug()
    );
    assert!(holds(&output, "after-marker"));
    // The shell's own echo of what was typed holds the escape sequences as text, and what it printed
    // holds them as bytes: neither is in the file as a clipboard write, a bell or a question.
    for gone in ["\x1b]52", "\x07", "\x1b[c"] {
        assert!(
            !holds(&output, gone),
            "{} is not carried: {}",
            gone.escape_debug(),
            String::from_utf8_lossy(&output).escape_debug()
        );
    }
    let whole = String::from_utf8_lossy(&bytes);
    assert!(!whole.contains("c2VjcmV0LXRva2Vu"), "{whole}");
    for kind in [
        "clipboard_write",
        "bell",
        "terminal_query",
        "output_timestamps",
    ] {
        assert!(
            document["omissions"]
                .as_array()
                .expect("omissions")
                .iter()
                .any(|omission| omission["kind"] == kind),
            "{kind} is declared: {}",
            document["omissions"]
        );
    }
    assert_eq!(
        std::fs::metadata(&file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        world.destination_answers(),
        "an export leaves the destination's daemon running"
    );

    // The file is never replaced.
    let again = world.run(&[
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        file.to_str().expect("a path"),
    ]);
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("already exists"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(
        std::fs::read(&file).expect("reads"),
        bytes,
        "and is left as it was"
    );
}

/// KR-REQ-18.11: an export of a session in a stopped environment is refused and starts nothing, where
/// a create or an attach would start it: no bridge is run in the distribution, the platform is only
/// asked, and no file is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_from_a_stopped_environment_starts_nothing() {
    let world = World::start().await;
    world.enrol_destination();
    let session = a_closed_session_in_the_destination(&world);
    world.stop_destination_daemon();
    std::fs::write(world.tools.join("distribution-state"), "Stopped")
        .expect("the platform's answer");
    let before = world.invocations();

    let file = world.export_path("stopped");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        file.to_str().expect("a path"),
    ]);
    let said: Value = serde_json::from_slice(&exported.stdout).unwrap_or_else(|error| {
        panic!(
            "kr export printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&exported.stdout),
            String::from_utf8_lossy(&exported.stderr)
        )
    });
    assert!(!exported.status.success(), "{said}");
    assert_eq!(said["code"], "ENVIRONMENT_UNAVAILABLE", "{said}");
    assert!(!file.exists(), "no file was made");
    let asked = std::fs::read_to_string(world.tools.join("invocations")).expect("the record");
    let since: Vec<&str> = asked.lines().skip(before).collect();
    assert!(
        since.iter().all(|line| line.starts_with("--list")),
        "the platform was asked and nothing was run in the distribution: {since:?}"
    );
    assert!(
        !world.destination_answers(),
        "nothing started the destination's daemon"
    );
}

/// KR-REQ-03.14: a distribution is read as running or as stopped on a Windows host that prints the
/// states of `wsl.exe --list --verbose` in a language other than English. A person on that host
/// enrols the running distribution, has a session exported from it, and is refused the export once
/// the distribution is stopped, with nothing started to find out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_distribution_is_read_as_running_or_stopped_in_whatever_language_the_host_prints() {
    let world = World::start().await;
    std::fs::write(world.tools.join("host-language"), "de").expect("the host's language");
    world.enrol_destination();
    let session = a_closed_session_in_the_destination(&world);

    let file = world.export_path("in-german");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        file.to_str().expect("a path"),
    ]);
    assert!(
        exported.status.success(),
        "a running distribution is exported from: {}{}",
        String::from_utf8_lossy(&exported.stdout),
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(file.exists(), "the export made its file");

    world.stop_destination_daemon();
    std::fs::write(world.tools.join("distribution-state"), "Stopped")
        .expect("the platform's answer");
    let before = world.invocations();
    let refused_file = world.export_path("in-german-stopped");
    let refused = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        refused_file.to_str().expect("a path"),
    ]);
    let said: Value = serde_json::from_slice(&refused.stdout).unwrap_or_else(|error| {
        panic!(
            "kr export printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        )
    });
    assert!(!refused.status.success(), "{said}");
    assert_eq!(said["code"], "ENVIRONMENT_UNAVAILABLE", "{said}");
    assert!(!refused_file.exists(), "no file was made");
    let asked = std::fs::read_to_string(world.tools.join("invocations")).expect("the record");
    let since: Vec<&str> = asked.lines().skip(before).collect();
    assert!(
        since.iter().all(|line| line.starts_with("--list")),
        "the platform was asked and nothing was run in the distribution: {since:?}"
    );
}

/// KR-REQ-18.11: a bound of no bytes is refused before anything is asked of the environment: the
/// platform is not asked, no bridge is run, and no file is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_of_no_bytes_is_refused_before_the_environment_is_asked() {
    let world = World::start().await;
    world.enrol_destination();
    let before = world.invocations();
    let file = world.export_path("no-bytes");
    let refused = world.run(&[
        "export",
        "1",
        "--environment",
        "dest",
        "--max-bytes",
        "0",
        "--output",
        file.to_str().expect("a path"),
    ]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--max-bytes"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!file.exists(), "no file was made");
    assert_eq!(
        world.invocations(),
        before,
        "the platform was not asked and no bridge was run"
    );
}

/// KR-REQ-18.11: where the destination's privacy mode is on, no session is exported, closed ones
/// included, and the refusal names privacy mode and writes nothing. The control is the first test:
/// the same session with the mode off is exported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_from_an_environment_in_privacy_mode_writes_nothing() {
    let world = World::start().await;
    world.enrol_destination();
    let session = a_closed_session_in_the_destination(&world);
    let mut privacy = std::process::Command::new(support::kr());
    privacy
        .args(["--json", "privacy", "on"])
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
    let turned_on = privacy.output().expect("runs kr");
    assert!(
        String::from_utf8_lossy(&turned_on.stdout).contains("\"enabled\": true"),
        "{}; {}",
        String::from_utf8_lossy(&turned_on.stdout),
        String::from_utf8_lossy(&turned_on.stderr)
    );

    let file = world.export_path("private");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        file.to_str().expect("a path"),
    ]);
    let said: Value = serde_json::from_slice(&exported.stdout).unwrap_or_else(|error| {
        panic!(
            "kr export printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&exported.stdout),
            String::from_utf8_lossy(&exported.stderr)
        )
    });
    assert!(!exported.status.success(), "{said}");
    assert_eq!(said["code"], "PERMISSION_DENIED", "{said}");
    assert!(
        said["message"]
            .as_str()
            .is_some_and(|message| message.contains("privacy mode is on")),
        "{said}"
    );
    assert!(!file.exists(), "nothing was written");
}

/// KR-REQ-18.11, KR-REQ-25.25: the same command exports a session of this host's own environment,
/// through its daemon and not through a bridge, with the same file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_of_a_session_on_this_host_is_the_same_file() {
    let world = World::start().await;
    let created = world.run(&[
        "--json",
        "new",
        "--invisible",
        "--headless",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).expect("kr printed JSON");
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();
    let display = created["display_number"].to_string();
    let worker = worker_process(&world.source, &session);
    let terminal = world.attach_here_on_a_terminal(&display);
    terminal.types(TYPED_WITH_SIDE_EFFECTS);
    terminal.expect_within("after-marker", "the shell printed past its side effects");
    // The engine answered the shell's question about the terminal, as a terminal would, and the
    // answer reached the shell as typing: the line discipline's kill character clears it.
    terminal.types("\x15exit\r");
    terminal.expect_within("attach-finished-", "the attachment ended with the session");
    let mut shell = terminal.shell;
    let _ = shell.wait();
    worker_ended(&worker);
    let started = Instant::now();
    loop {
        let listed = world.run(&["--json", "list", "--include-closed"]);
        let listed: Value = serde_json::from_slice(&listed.stdout).expect("kr list printed JSON");
        if listed["sessions"]
            .as_array()
            .is_some_and(|sessions| sessions.iter().any(|row| row["state"] == "closed"))
        {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the session did not close: {listed}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // A bare file name, which is made in the directory the command is run in. The command writes the
    // file and then makes the name durable, and a name with no directory in it is not a failure.
    let file = world.export_path("here");
    let exported = world
        .kr(&["--json", "export", &display, "--output", "here.json"])
        .current_dir(world.source.root())
        .output()
        .expect("runs kr");
    assert!(
        exported.status.success(),
        "kr export: {}; it said {}",
        String::from_utf8_lossy(&exported.stdout),
        String::from_utf8_lossy(&exported.stderr)
    );
    let document: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("written")).expect("JSON");
    assert_eq!(document["session"]["session_id"], session.as_str());
    let output = exported_output(&document);
    assert!(
        holds(&output, "out-marker"),
        "{}",
        String::from_utf8_lossy(&output).escape_debug()
    );
    assert!(!holds(&output, "\x1b]52"));
    assert_eq!(
        world.invocations(),
        0,
        "no bridge was opened for a session of this host's own"
    );
}

fn runtime_available() -> bool {
    let present = std::process::Command::new(RUNTIME)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !present {
        eprintln!("skipped, because {RUNTIME} is not installed on this machine");
    }
    present
}

fn podman(arguments: &[&str]) -> std::process::Output {
    std::process::Command::new(RUNTIME)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the runtime runs")
}

/// Puts the images in the runtime's store, once per run of this suite, before any container starts:
/// the base image, and the one that adds Git to it.
fn image_present() {
    static PULLED: std::sync::Once = std::sync::Once::new();
    PULLED.call_once(|| {
        if !podman(&["image", "exists", CONTAINER_IMAGE])
            .status
            .success()
        {
            let pulled = podman(&["pull", "--quiet", CONTAINER_IMAGE]);
            assert!(
                pulled.status.success(),
                "the image is pulled: {}",
                String::from_utf8_lossy(&pulled.stderr)
            );
        }
        if podman(&["image", "exists", INSTALLED_IMAGE])
            .status
            .success()
        {
            return;
        }
        let context = tempfile::tempdir().expect("an empty build context");
        let mut build = std::process::Command::new(RUNTIME)
            .args(["build", "--quiet", "--pull=never", "--tag", INSTALLED_IMAGE])
            .args(["--file", "-"])
            .arg(context.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the runtime builds");
        build
            .stdin
            .take()
            .expect("the build reads its file from standard input")
            .write_all(
                format!(
                    "FROM {CONTAINER_IMAGE}\nRUN apt-get update -qq && \\\n    \
                     DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
                     git && rm -rf /var/lib/apt/lists/*\n"
                )
                .as_bytes(),
            )
            .expect("writes the file");
        let built = build.wait_with_output().expect("the build ends");
        assert!(
            built.status.success(),
            "the image that adds Git is built: {}",
            String::from_utf8_lossy(&built.stderr)
        );
    });
}

/// The directory mounted into the container: `kr`, the daemon that adds the one thing a test must
/// not leave to a keychain (where its keys are kept) before it hands over, and the worker.
fn programs_for_a_container() -> &'static Path {
    static PLACED: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();
    &PLACED
        .get_or_init(|| {
            let directory = tempfile::tempdir().expect("a directory on the internal disk");
            let place = |source: &Path, name: &str| {
                kr_ipc::testing::place_program(source, &directory.path().join(name));
            };
            place(&support::kr(), "kr");
            place(&beside_this_test("kr-worker"), "kr-worker");
            place(&beside_this_test("kr-controller"), "kr-controller-real");
            let script = directory.path().join("kr-controller.text");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\nexec {MOUNTED}/kr-controller-real --secret-store file \"$@\"\n"
                ),
            )
            .expect("writes the daemon script");
            kr_ipc::testing::place_program(&script, &directory.path().join("kr-controller"));
            let path = directory.path().to_path_buf();
            (directory, path)
        })
        .1
}

/// A container this test made, removed by the identifier the runtime issued however the test ends.
struct Container {
    id: String,
    name: String,
}

impl Container {
    fn start() -> Self {
        image_present();
        let name = format!("kr-acc-{}", &kr_ipc::new_uuid().to_string()[..8]);
        let mount = format!("{}:{MOUNTED}:ro", programs_for_a_container().display());
        let started = podman(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            &name,
            "--user",
            "root",
            "--volume",
            &mount,
            "--",
            INSTALLED_IMAGE,
            "sleep",
            "900",
        ]);
        assert!(
            started.status.success(),
            "the container starts: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        let printed = String::from_utf8_lossy(&started.stdout).into_owned();
        let id = printed
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("the runtime printed an identifier")
            .trim()
            .to_owned();
        assert!(
            kr_protocol::identity::is_container_identifier(&id),
            "the runtime issued a whole identifier: {id}"
        );
        Self { id, name }
    }

    /// Runs one command inside, as root, and says what it printed.
    fn inside(&self, arguments: &[&str]) -> std::process::Output {
        let mut command = vec!["exec", "--user", "root", "--", self.id.as_str()];
        command.extend_from_slice(arguments);
        podman(&command)
    }

    /// Chooses the standalone start for the daemon in this container, as a person sets one up,
    /// then starts the daemon and waits until it answers.
    fn serve(&self) {
        let chosen = self.inside(&[
            &format!("{MOUNTED}/kr"),
            "host",
            "startup",
            "--set",
            "standalone",
        ]);
        assert!(
            chosen.status.success(),
            "{}",
            String::from_utf8_lossy(&chosen.stderr)
        );
        let started = podman(&[
            "exec",
            "--detach",
            "--user",
            "root",
            "--",
            &self.id,
            &format!("{MOUNTED}/kr-controller"),
            "--worker",
            &format!("{MOUNTED}/kr-worker"),
        ]);
        assert!(
            started.status.success(),
            "{}",
            String::from_utf8_lossy(&started.stderr)
        );
        let deadline = Instant::now() + LIVENESS_DEADLINE;
        while !self
            .inside(&[&format!("{MOUNTED}/kr"), "list"])
            .status
            .success()
        {
            assert!(
                Instant::now() < deadline,
                "the daemon in the container did not answer"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The environment identity the daemon in this container reports for itself.
    fn environment_id(&self) -> String {
        let doctor = self.inside(&[&format!("{MOUNTED}/kr"), "--json", "doctor"]);
        assert!(
            doctor.status.success(),
            "{}",
            String::from_utf8_lossy(&doctor.stderr)
        );
        let document: Value = serde_json::from_slice(&doctor.stdout).expect("doctor printed JSON");
        document["host"]["environment_id"]
            .as_str()
            .unwrap_or_else(|| panic!("doctor names the environment: {document}"))
            .to_owned()
    }

    fn state(&self) -> String {
        let inspected = podman(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Status}}",
            "--",
            &self.id,
        ]);
        String::from_utf8_lossy(&inspected.stdout).trim().to_owned()
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // By the identifier this test recorded, never by a name somebody else might hold now.
        let _ = podman(&["rm", "--force", "--time", "0", "--", &self.id]);
        let _ = &self.name;
    }
}

impl World {
    /// Enrols the container by the identifier its runtime issued, asking its helper which
    /// environment it is.
    fn enrol_container(&self, container: &Container, label: &str) -> Value {
        let helper = format!("{MOUNTED}/kr");
        let enrolled = self.run(&[
            "--json",
            "bridge",
            "enrol",
            "--access",
            "container",
            "--label",
            label,
            "--target",
            &container.id,
            "--user",
            "root",
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
        serde_json::from_slice(&enrolled.stdout).expect("kr printed JSON")
    }
}

/// KR-REQ-03.17: an enrolled container, reached by the identifier its runtime issued and by the user
/// and helper the record names, answers a real bridge: the identity it reports is the one its own
/// daemon has, the host holds a record of the channel, and a session made through it is in the
/// container and nowhere else. The Linux `kr`, `kr-controller` and `kr-worker` run inside a real
/// container; nothing stands in for the runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolled_container_answers_a_bridge_and_a_session_made_through_it_lives_there() {
    if !runtime_available() {
        return;
    }
    let container = Container::start();
    container.serve();
    let world = World::start().await;

    let row = world.enrol_container(&container, "box");
    assert_eq!(
        row["row"]["enrolment"]["environment_id"],
        container.environment_id(),
        "the identity is the container's own daemon's: {row}"
    );
    assert_eq!(
        row["row"]["enrolment"]["target"], container.id,
        "and the record keeps the identifier the runtime issued, not its name: {row}"
    );

    let refreshed = world.run(&["--json", "bridge", "refresh", "box"]);
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    let refreshed: Value = serde_json::from_slice(&refreshed.stdout).expect("kr printed JSON");
    assert_eq!(
        refreshed["verification"]["environment_id"],
        container.environment_id(),
        "{refreshed}"
    );
    assert_eq!(
        refreshed["verification"]["role"], "controller",
        "{refreshed}"
    );
    assert_eq!(refreshed["row"]["status"], "running", "{refreshed}");
    assert_eq!(
        refreshed["row"]["readiness"]["channel_scoped"], true,
        "{refreshed}"
    );
    assert_eq!(refreshed["started"], false, "{refreshed}");

    let created = world.run(&[
        "--json",
        "new",
        "--invisible",
        "--headless",
        "--environment",
        "box",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
    ]);
    assert!(
        created.status.success(),
        "{}; it said {}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).expect("kr printed JSON");
    assert_eq!(created["state"], "live", "{created}");
    assert_eq!(
        created["environment_id"],
        container.environment_id(),
        "{created}"
    );
    let session = created["session_id"]
        .as_str()
        .expect("a session")
        .to_owned();

    // The session is the container's: its own `kr` lists it, and its worker is a process there.
    let listed = container.inside(&[&format!("{MOUNTED}/kr"), "--json", "list"]);
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("kr printed JSON");
    assert!(
        listed["sessions"]
            .as_array()
            .is_some_and(|sessions| sessions.iter().any(|entry| entry["session_id"] == session)),
        "{listed}"
    );
    assert!(
        container.inside(&["/bin/sh", "-c", "ls /proc/[0-9]*/exe | head -c 0; for p in /proc/[0-9]*; do case \"$(readlink $p/exe)\" in */kr-worker) exit 0;; esac; done; exit 1"])
            .status
            .success(),
        "a kr-worker is running inside the container"
    );
    let here = world.run(&["--json", "list"]);
    let here: Value = serde_json::from_slice(&here.stdout).expect("kr list printed JSON");
    assert_eq!(here["sessions"].as_array().map_or(0, Vec::len), 0, "{here}");
}

/// KR-REQ-03.14, 03.17: a stopped container is listed from the cache and started by a create, and by
/// nothing a listing does; the container's own daemon is then started by the container's own startup,
/// and the identity is the one it had before it stopped. A refresh told to start it and an attach
/// start it by the same step, which this test does not drive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_container_is_started_by_a_create_and_keeps_its_identity() {
    if !runtime_available() {
        return;
    }
    let container = Container::start();
    container.serve();
    let world = World::start().await;
    let enrolled = world.enrol_container(&container, "box");
    let identity = container.environment_id();
    assert_eq!(enrolled["row"]["enrolment"]["environment_id"], identity);

    let stopped = podman(&["stop", "--time", "0", "--", &container.id]);
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(container.state(), "exited");

    // Another container starts while this one is stopped, as on any host that runs more than one.
    // The new mount takes the device number the stopped container's filesystem had, so the
    // filesystem it comes back on is the same one under another device number.
    let _neighbour = Container::start();

    // A listing and a plain refresh read and observe, and start nothing.
    let listed = world.run(&["--json", "bridge", "list"]);
    assert!(listed.status.success());
    let observed = world.run(&["--json", "bridge", "refresh", "box"]);
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    let observed: Value = serde_json::from_slice(&observed.stdout).expect("kr printed JSON");
    assert_eq!(
        observed["row"]["status"], "environment_stopped",
        "{observed}"
    );
    assert_eq!(observed["verification"], Value::Null, "{observed}");
    assert_eq!(
        container.state(),
        "exited",
        "neither a listing nor a refresh starts a container"
    );

    // A create is allowed to: the container, and then the daemon its own startup chooses.
    let created = world.run(&[
        "--json",
        "new",
        "--invisible",
        "--headless",
        "--environment",
        "box",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
    ]);
    assert!(
        created.status.success(),
        "{}; it said {}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).expect("kr printed JSON");
    assert_eq!(
        container.state(),
        "running",
        "the create started the container"
    );
    assert_eq!(created["state"], "live", "{created}");
    assert_eq!(
        created["environment_id"], identity,
        "the same installation answered after it stopped: {created}"
    );
}
