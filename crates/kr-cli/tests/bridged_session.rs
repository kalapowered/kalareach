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

use std::io::Write;
use std::path::{Path, PathBuf};
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
#[path = "support/user_manager.rs"]
mod user_manager;

use support::terminal::{self, Answering, Collected, Keys};

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

/// Held by the four cases that start a container or put a stand-in for the container runtime first
/// on `kr`'s path, so that these four do not run beside each other. The cases below that run a
/// stand-in runtime of their own, in a directory of their own, share nothing with them and take no
/// turn.
///
/// Without it `podman exec` stalled in the real-container cases of whole-suite runs on the build
/// box, and with it they passed; what the stalled call waited for is not established. Every call
/// this harness makes to the runtime is bounded as well, so a stall under the turn fails the case
/// that made the call and names it. A removal that fails in `Drop` fails the case that passed.
static CONTAINER_RUNTIME_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
fn ssh_stand_in(tools: &Path, destination: &Path, home: &Path) -> String {
    let temporary = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    format!(
        r##"#!/bin/sh
# A test that wants the destination unreachable says so with a file, and the connection is refused
# the way `ssh` refuses one.
if [ -f '{tools}/unreachable' ]; then
  echo 'ssh: connect to host build.example port 22: Connection refused' >&2
  exit 255
fi
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
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

/// The identifier the stand-in for `podman` issues for its one container: 64 hexadecimal digits,
/// which is what a runtime issues and what a record keeps.
const STAND_IN_CONTAINER_ID: &str =
    "3f1a9c0d5e7b2468a1c3e5f7092b4d6e8a0c2e4f61738495a6b7c8d9e0f1a2b3";

/// The name the stand-in for `podman` knows its container by.
const STAND_IN_CONTAINER_NAME: &str = "devbox";

/// What the stand-in for `podman` does: record how it was run, answer the three questions a host
/// asks a runtime (what identifier a name resolves to, whether the container runs, and to start it),
/// and run what follows the container in the destination's own environment, as the runtime's exec
/// does, with what a login there would give it and nothing of the caller's. Where a test says the
/// helper is unreachable, the runtime still answers and the program cannot be started in the
/// container.
fn podman_stand_in(tools: &Path, destination: &Path, home: &Path) -> String {
    let temporary = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    format!(
        r##"#!/bin/sh
case "$1" in
  --version) echo 'podman version 5.0.0'; exit 0 ;;
esac
printf '%s\n' "$*" >>'{tools}/podman-invocations'
case "$1" in
  container)
    # container inspect --format <format> -- <name or identifier>
    if [ "$6" != '{name}' ] && [ "$6" != '{id}' ]; then
      echo "Error: no container with name or ID \"$6\" found: no such container" >&2
      exit 125
    fi
    case "$4" in
      '{{{{.Id}}}}') echo '{id}' ;;
      '{{{{.State.Running}}}}') cat '{tools}/container-running' 2>/dev/null || echo true ;;
      *) echo "the stand-in for podman has no answer for: $*" >&2; exit 2 ;;
    esac
    exit 0
    ;;
  start)
    # start -- <container>
    if [ "$3" != '{id}' ]; then
      echo "Error: no container with name or ID \"$3\" found: no such container" >&2
      exit 125
    fi
    echo true >'{tools}/container-running'
    echo '{id}'
    exit 0
    ;;
  exec)
    # exec --interactive --user <user> -- <container> <helper> bridge --stdio
    printf '%s\n' "$$" >'{tools}/last-bridge.pid'
    # A test that wants the helper unreachable says so with a file: the container runs, and the
    # runtime cannot start the program in it.
    if [ -f '{tools}/unreachable' ]; then
      echo 'Error: crun: executable file not found in $PATH: No such file or directory' >&2
      exit 127
    fi
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
    shift
    if [ "$1" != '{id}' ]; then
      echo "Error: no container with name or ID \"$1\" found: no such container" >&2
      exit 125
    fi
    if [ "$(cat '{tools}/container-running' 2>/dev/null || echo true)" != true ]; then
      echo "Error: can only create exec sessions on running containers: container state improper" >&2
      exit 125
    fi
    shift
    exec /usr/bin/env -i PATH=/usr/bin:/bin HOME='{home}' TMPDIR='{temporary}' \
      KR_RUNTIME_DIR='{runtime}' KR_STATE_DIR='{state}' "$@"
    ;;
esac
echo "the stand-in for podman has no answer for: $*" >&2
exit 2
"##,
        tools = tools.display(),
        name = STAND_IN_CONTAINER_NAME,
        id = STAND_IN_CONTAINER_ID,
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
    /// How long a run of `kr` is given before it fails the case that ran it.
    kr_bound: Duration,
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
        std::fs::write(&ssh_text, ssh_stand_in(&tools, destination.root(), &home))
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
            kr_bound: KR_CALL_BOUND,
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

    /// Runs `kr` on the source host to its end, within the world's bound for a run of it.
    fn run(&self, arguments: &[&str]) -> std::process::Output {
        to_its_end(self.kr(arguments), self.kr_bound)
    }

    /// Puts a stand-in for the container runtime first on the path of `kr` and of the daemon, for
    /// a test that needs a named container where no runtime is installed. Every other test of this
    /// suite that reaches a container uses the runtime of the machine, which this must not shadow,
    /// so it is placed by the test that wants it and by no other.
    fn stand_in_for_the_container_runtime(&self) {
        let text = self.tools.join("podman.text");
        std::fs::write(
            &text,
            podman_stand_in(&self.tools, self.destination.root(), &self.home),
        )
        .expect("the podman stand-in");
        kr_ipc::testing::place_program(&text, &self.tools.join("podman"));
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
            "--shell-mode",
            "native_compat",
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
    seen: Collected,
    writer: Keys,
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
        String::from_utf8_lossy(&terminal::bytes(&self.seen)).into_owned()
    }

    /// Answers the command's questions about what this terminal is. The answer is typed by the
    /// thread that collects what the terminal is sent, the moment the question that ends the
    /// exchange has arrived: the exchange has one second in all.
    fn answers_what_it_is(&self) {
        let answering = self.replies_to_question(1, b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        self.typed(answering, "the command asked this terminal what it is");
    }

    /// Types `reply` the moment the terminal has been asked what it is `nth` times, by the command
    /// or by a command it started.
    fn replies_to_question(&self, nth: usize, reply: &[u8]) -> Answering {
        terminal::reply_to(&self.seen, 0, b"\x1b[c", nth, reply, &self.writer)
    }

    /// Owes the replies to the first question the command asks this terminal and, when there is
    /// one, to the second that the attachment it starts asks, and returns what waits for each.
    ///
    /// The second is owed first: the first reply lets the command go on, and the attachment's
    /// exchange has one second in all from the moment it asks, so the reply to its question has to
    /// be owed before the reply that lets it ask can be typed.
    fn replies_to_the_questions(
        &self,
        first: &[u8],
        second: Option<&[u8]>,
    ) -> (Answering, Option<Answering>) {
        let second = second.map(|reply| self.replies_to_question(2, reply));
        (self.replies_to_question(1, first), second)
    }

    /// Requires that `answering` was typed, and names `what` was asked when it was not.
    fn typed(&self, answering: Answering, what: &str) {
        assert!(
            answering.typed_within(LIVENESS_DEADLINE),
            "{what}: the answer was not typed within {LIVENESS_DEADLINE:?}; the terminal was \
             sent: {}",
            self.text().escape_debug()
        );
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
        let seen = terminal::collect(pty.master.try_clone_reader().expect("a reader"));
        let writer = terminal::keys(pty.master.take_writer().expect("a writer"));
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
        terminal.answers_what_it_is();
        terminal
    }

    /// Runs `kr attach` for a display number of the source host's own environment, on a terminal
    /// that answers the command's questions about what it is.
    fn attach_here_on_a_terminal(&self, display: &str) -> Terminal {
        let terminal = self.terminal_running(&format!(
            "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
            support::kr().display()
        ));
        terminal.answers_what_it_is();
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
            "{} new --attach --palette probe {arguments} --shell /bin/sh --shell-mode native_compat \
             --startup interactive \
             --headless; printf 'create-finished-%s\\n' \"$?\"",
            support::kr().display()
        ),
        variables,
    );
    let (colours, what_it_is) = terminal.replies_to_the_questions(
        b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c",
        Some(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c"),
    );
    terminal.typed(colours, "the command asked this terminal what it is");
    if let Some(what_it_is) = what_it_is {
        terminal.typed(what_it_is, "the attachment asked this terminal what it is");
    }
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
        "{} new --attach --palette probe --environment dest --shell /bin/sh --shell-mode native_compat \
         --startup interactive \
         --headless; printf 'create-finished-%s\\n' \"$?\"",
        support::kr().display()
    ));
    // The command asks this terminal for its colours, and the person types while it does.
    let (colours, what_it_is) = terminal.replies_to_the_questions(
        b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\typed\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c",
        answer_the_attachment.then_some(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c".as_slice()),
    );
    terminal.typed(colours, "the command asked this terminal what it is");
    if let Some(what_it_is) = what_it_is {
        terminal.typed(what_it_is, "the attachment asked this terminal what it is");
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
        "{} new --attach --palette probe --environment dest --shell /bin/sh --shell-mode native_compat \
         --startup interactive \
         --headless; printf 'create-finished-%s\\n' \"$?\"",
        support::kr().display()
    ));
    // The five bytes begin a command, which the person finishes once the shell is theirs.
    let (colours, what_it_is) = terminal.replies_to_the_questions(
        b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\echo \x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c",
        Some(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c"),
    );
    terminal.typed(colours, "the command asked this terminal what it is");
    if let Some(what_it_is) = what_it_is {
        terminal.typed(what_it_is, "the attachment asked this terminal what it is");
    }
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
///
/// KR-REQ-18.11, the part about a named SSH environment: it is enrolled under a label with the
/// target, user and helper the person names, the probe takes its identity from the helper there
/// and refuses a user or an identity the person did not name, and a refresh registers the
/// helper's scoped channel. Not shown here: a connection that fails.
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

/// The account this test runs as, which the stand-ins run a helper as, as a login of that name would.
fn own_account() -> String {
    String::from_utf8(
        std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .expect("id runs")
            .stdout,
    )
    .expect("a name")
    .trim()
    .to_owned()
}

/// The length a person is told of a sentence the host said: "[message withheld, 52 bytes]".
fn withheld_bytes(shown: &str) -> Option<u64> {
    shown
        .strip_prefix("[message withheld, ")?
        .strip_suffix(" bytes]")?
        .parse()
        .ok()
}

/// How many times the stand-in for `podman` was run, and the lines of how.
fn podman_invocations(world: &World) -> Vec<String> {
    std::fs::read_to_string(world.tools.join("podman-invocations"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// KR-REQ-18.11, the part about a named container environment, run on a machine with no container
/// runtime by standing one in: the container is enrolled by the name the person types and the record
/// keeps the identifier the runtime issued for it; the probe takes the identity from the helper in
/// it; a refresh registers the helper's scoped channel and starts nothing; and a container that is
/// stopped is reported stopped by a refresh, which starts neither it nor a helper in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_container_is_enrolled_by_name_and_a_refresh_of_it_starts_nothing() {
    let _turn = CONTAINER_RUNTIME_TURN.lock().await;
    let world = World::start().await;
    world.stand_in_for_the_container_runtime();
    // The destination's daemon is started by a create, as for any environment that is running.
    world.enrol_destination();
    let _ = world.create_in_destination();

    let helper = support::kr().display().to_string();
    let enrolled = world.run(&[
        "--json",
        "bridge",
        "enrol",
        "--access",
        "container",
        "--label",
        "box",
        "--target",
        STAND_IN_CONTAINER_NAME,
        "--user",
        &own_account(),
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
        row["row"]["enrolment"]["target"], STAND_IN_CONTAINER_ID,
        "the record keeps the identifier the runtime issued, not the name typed: {row}"
    );
    assert_eq!(
        row["row"]["enrolment"]["environment_id"],
        world.destination.environment_id().to_string(),
        "the identity is the one the helper in the container reports: {row}"
    );

    let refreshed = world.refreshed("box");
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

    // The list shows the container under its label and its access class.
    let listed = world.run(&["bridge", "list"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.contains(&format!("box  container  {STAND_IN_CONTAINER_ID}")),
        "{listed}"
    );

    // The container stops. A refresh says so, and neither starts it nor runs anything in it.
    std::fs::write(world.tools.join("container-running"), "false\n").expect("the state");
    let before = podman_invocations(&world).len();
    let stopped = world.refreshed("box");
    assert_eq!(stopped["row"]["status"], "environment_stopped", "{stopped}");
    assert_eq!(stopped["started"], false, "{stopped}");
    assert!(stopped["verification"].is_null(), "{stopped}");
    let asked = podman_invocations(&world);
    assert!(
        asked[before..]
            .iter()
            .all(|line| line.starts_with("container inspect ")),
        "the runtime was asked about the container and nothing was started: {asked:?}"
    );
}

/// KR-REQ-18.11, the part about connection diagnostics, for a named SSH host and a named container:
/// when the connection fails, the refresh still comes back, with no verification and no scoped
/// channel, in the person's lines it speaks of no protocol it did not hear, and what an earlier
/// refresh established for the record is taken back rather than left standing beside the failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_fails_claims_nothing_for_an_ssh_host_or_a_container() {
    let _turn = CONTAINER_RUNTIME_TURN.lock().await;
    let world = World::start().await;
    world.stand_in_for_the_container_runtime();
    world.enrol_destination();
    let _ = world.create_in_destination();
    let helper = support::kr().display().to_string();
    let account = own_account();
    // Both name the destination's own identity, so the second enrolment replaces the first record:
    // each is tried to its end before the other is enrolled.
    for (label, access, target) in [
        ("sshdest", "ssh", "build.example"),
        ("box", "container", STAND_IN_CONTAINER_NAME),
    ] {
        let enrolled = world.run(&[
            "bridge", "enrol", "--access", access, "--label", label, "--target", target, "--user",
            &account, "--helper", &helper, "--probe",
        ]);
        assert!(
            enrolled.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );
        let answered = world.refreshed(label);
        assert_eq!(
            answered["row"]["readiness"]["channel_scoped"], true,
            "{label}: the channel is scoped while the destination answers: {answered}"
        );

        let switch = world.tools.join("unreachable");
        std::fs::write(&switch, "").expect("the switch");
        let failed = world.refreshed(label);
        assert!(failed["verification"].is_null(), "{label}: {failed}");
        assert_eq!(
            failed["row"]["readiness"]["channel_scoped"], false,
            "{label}: what an earlier answer established is taken back: {failed}"
        );
        assert!(
            failed["connection"]
                .as_str()
                .and_then(withheld_bytes)
                .is_some_and(|bytes| bytes > 0),
            "{label}: the result says what opening the connection did: {failed}"
        );
        // What the person reads: the record's label and where it stands, then the host's sentence
        // about the connection as its class and length, as every sentence of the host's is shown,
        // and no line that claims a protocol nothing spoke.
        let said = world.run(&["bridge", "refresh", label]);
        let said = String::from_utf8_lossy(&said.stdout);
        let lines: Vec<&str> = said.lines().collect();
        assert_eq!(lines.len(), 2, "{label}: {said}");
        assert!(lines[0].starts_with(&format!("{label} is ")), "{said}");
        assert!(
            withheld_bytes(lines[1].trim_start()).is_some_and(|bytes| bytes > 0),
            "{label}: the connection's sentence is shown as its class and length: {said}"
        );
        std::fs::remove_file(&switch).expect("the switch is taken away");
    }
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
///
/// KR-REQ-18.11, the part about a named SSH environment reached through a real `ssh` and `sshd`:
/// the probe takes its identity from the helper there, a refresh registers the helper's scoped
/// channel and the user it answers as, an identity the person did not give is refused and recorded
/// nowhere, and a host whose key this login does not trust registers nothing.
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
        "--shell-mode",
        "native_compat",
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
    assert_eq!(document["format"], "kalareach-session-export/2");
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
    for kind in ["clipboard_write", "bell", "terminal_query"] {
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
    // Whether the destination could prove its clock depends on the host, so that is not asserted;
    // that every byte has a time does not.
    assert!(
        !document["omissions"]
            .as_array()
            .expect("omissions")
            .iter()
            .any(|omission| omission["kind"] == "output_timestamps"),
        "every byte has a time: {}",
        document["omissions"]
    );
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

/// KR-REQ-25.25 and KR-REQ-18.11: `kr export` of a closed session reads when the destination's
/// worker wrote each part of the output, from the record the worker left, and writes it two ways.
/// The semantic JSON gives each piece the wall-clock reading of its first byte; `--format asciicast`
/// writes a recording that plays the same output at those times, with the clipboard write, the bell
/// and the question counted in its header and none of them in its events. No time is invented: both
/// lie between the moment the session was started and the moment it was closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_export_can_be_a_recording_that_plays_the_output_at_the_times_it_was_written() {
    let world = World::start().await;
    world.enrol_destination();
    let started = kr_ipc::now_ms().get();
    let session = a_closed_session_in_the_destination(&world);
    let finished = kr_ipc::now_ms().get();

    let json = world.export_path("timed-json");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--output",
        json.to_str().expect("a path"),
    ]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let document: Value =
        serde_json::from_slice(&std::fs::read(&json).expect("the file")).expect("the file is JSON");
    assert_eq!(document["format"], "kalareach-session-export/2");
    let chunks = document["output"]["chunks"].as_array().expect("chunks");
    assert!(!chunks.is_empty());
    for chunk in chunks {
        let at: u64 = chunk["at_ms"]
            .as_str()
            .unwrap_or_else(|| panic!("every piece has a time: {chunk}"))
            .parse()
            .expect("digits");
        assert!(
            (started..=finished).contains(&at),
            "{at} is not in {started}..={finished}"
        );
    }
    assert!(
        !document["omissions"]
            .as_array()
            .expect("omissions")
            .iter()
            .any(|omission| omission["kind"] == "output_timestamps"),
        "nothing carries no time: {}",
        document["omissions"]
    );

    let cast = world.export_path("timed-cast");
    let exported = world.run(&[
        "--json",
        "export",
        &session,
        "--environment",
        "dest",
        "--format",
        "asciicast",
        "--output",
        cast.to_str().expect("a path"),
    ]);
    assert!(
        exported.status.success(),
        "{}; the destination's daemon logged {}",
        String::from_utf8_lossy(&exported.stderr),
        world.destination_daemon_log()
    );
    let said: Value = serde_json::from_slice(&exported.stdout).expect("kr printed JSON");
    assert_eq!(said["format"], "kalareach-session-recording/1", "{said}");
    let recording = std::fs::read_to_string(&cast).expect("the recording");
    let mut lines = recording.lines();
    let header: Value = serde_json::from_str(lines.next().expect("a header")).expect("JSON");
    assert_eq!(header["version"], 2);
    let begun = header["timestamp"].as_u64().expect("seconds");
    assert!(
        (started / 1000..=finished / 1000).contains(&begun),
        "the recording begins at {begun}, outside {started}..={finished}"
    );
    let mut played = String::new();
    let mut last = 0.0_f64;
    let longest = (finished - started) as f64 / 1000.0;
    for line in lines {
        let event: Value = serde_json::from_str(line).expect("an event");
        let at = event[0].as_f64().expect("seconds");
        assert!(
            at >= last && at <= longest,
            "{at} after {last}, within {longest}"
        );
        last = at;
        played.push_str(event[2].as_str().expect("text"));
    }
    assert!(played.contains("out-marker"), "{}", played.escape_debug());
    assert!(played.contains("after-marker"));
    for gone in ["\x1b]52", "\x07", "\x1b[c"] {
        assert!(!played.contains(gone), "{}", gone.escape_debug());
    }
    let kinds: Vec<_> = header["kalareach"]["omissions"]
        .as_array()
        .expect("omissions")
        .iter()
        .map(|omission| omission["kind"].as_str().unwrap_or_default().to_owned())
        .collect();
    for kind in ["clipboard_write", "bell", "terminal_query"] {
        assert!(
            kinds.iter().any(|found| found == kind),
            "{kind} in {kinds:?}"
        );
    }
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
        "--shell-mode",
        "native_compat",
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

/// Whether this machine has the container runtime. A case skips itself where it has not, and says
/// so on a line that starts with the suite's name and goes on `: skipped, because `, which is the
/// form the conformance report reads as a case that did not run, never as one that passed.
fn runtime_available() -> bool {
    match Runtime::podman().why_unavailable() {
        None => true,
        Some(why) => {
            eprintln!("bridged_session: skipped, because {why}");
            false
        }
    }
}

/// How long a call that starts, asks about or acts on one container is given: `run`, `exec`,
/// `inspect`, `stop`, `rm`, `image exists`, and the `--version` check.
const QUICK_CALL_BOUND: Duration = Duration::from_secs(60);

/// How long a call that fetches or builds an image is given.
const SLOW_CALL_BOUND: Duration = Duration::from_secs(300);

/// How long one run of `kr` is given in these cases: far longer than any of them takes. A `kr`
/// that never ends fails the case that ran it, with the call named, and does not hold the suite or
/// the turn on the container runtime.
const KR_CALL_BOUND: Duration = Duration::from_secs(300);

/// Runs `command` to its end within `bound`, or fails the case, naming the call.
fn to_its_end(command: std::process::Command, bound: Duration) -> std::process::Output {
    user_manager::bounded(command, bound).unwrap_or_else(|why| panic!("{why}"))
}

/// The container runtime a case drives, and how long it gives each call. A runtime that never
/// answers fails the case that called it, with the call named, and does not hold the suite.
struct Runtime {
    program: PathBuf,
    quick: Duration,
    slow: Duration,
}

impl Runtime {
    fn podman() -> Self {
        Self {
            program: PathBuf::from(RUNTIME),
            quick: QUICK_CALL_BOUND,
            slow: SLOW_CALL_BOUND,
        }
    }

    /// Runs one call to its end within `bound`, or says what went wrong with the call named.
    fn run(&self, arguments: &[&str], bound: Duration) -> Result<std::process::Output, String> {
        let mut command = std::process::Command::new(&self.program);
        command.args(arguments);
        user_manager::bounded(command, bound)
    }

    /// Runs one quick call. A call that does not end fails the case.
    fn call(&self, arguments: &[&str]) -> std::process::Output {
        self.run(arguments, self.quick)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// Whether the program is there to run: a path names a file, and a bare name is on `PATH`.
    fn installed(&self) -> bool {
        self.installed_in(std::env::var_os("PATH").as_deref())
    }

    /// [`Runtime::installed`], for the directories `path` lists.
    fn installed_in(&self, path: Option<&std::ffi::OsStr>) -> bool {
        if self.program.components().count() > 1 {
            return self.program.is_file();
        }
        path.is_some_and(|path| {
            std::env::split_paths(path).any(|directory| directory.join(&self.program).is_file())
        })
    }

    /// Why a case that needs this runtime cannot run here, or nothing where it can. A program
    /// that is there and fails `--version` is no runtime this machine has. One that is there and
    /// does not answer it fails the case instead.
    fn why_unavailable(&self) -> Option<String> {
        if !self.installed() {
            return Some(format!(
                "{} is not installed on this machine",
                self.program.display()
            ));
        }
        let answered = self.call(&["--version"]);
        (!answered.status.success()).then(|| {
            format!(
                "{} is installed and `--version` ended with {}",
                self.program.display(),
                answered.status
            )
        })
    }

    /// Whether this machine has the runtime: [`Runtime::why_unavailable`] has nothing to say.
    fn is_available(&self) -> bool {
        self.why_unavailable().is_none()
    }

    /// Puts the images in the runtime's store: the base image, and the one that adds Git to it.
    fn ensure_images(&self) {
        if !self
            .call(&["image", "exists", CONTAINER_IMAGE])
            .status
            .success()
        {
            let pulled = self
                .run(&["pull", "--quiet", CONTAINER_IMAGE], self.slow)
                .unwrap_or_else(|why| panic!("{why}"));
            assert!(
                pulled.status.success(),
                "the image is pulled: {}",
                String::from_utf8_lossy(&pulled.stderr)
            );
        }
        if self
            .call(&["image", "exists", INSTALLED_IMAGE])
            .status
            .success()
        {
            return;
        }
        let context = tempfile::tempdir().expect("an empty build context");
        let file = context.path().join("Containerfile");
        std::fs::write(
            &file,
            format!(
                "FROM {CONTAINER_IMAGE}\nRUN apt-get update -qq && \\\n    \
                 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
                 git && rm -rf /var/lib/apt/lists/*\n"
            ),
        )
        .expect("writes the file");
        let built = self
            .run(
                &[
                    "build",
                    "--quiet",
                    "--pull=never",
                    "--tag",
                    INSTALLED_IMAGE,
                    "--file",
                    file.to_str().expect("a path of text"),
                    context.path().to_str().expect("a path of text"),
                ],
                self.slow,
            )
            .unwrap_or_else(|why| {
                panic!(
                    "{why}; a build that did not end may have left its working container, which \
                     `{RUNTIME} ps --all --external` lists"
                )
            });
        assert!(
            built.status.success(),
            "the image that adds Git is built: {}",
            String::from_utf8_lossy(&built.stderr)
        );
    }
}

/// Puts the images in the runtime's store, once per run of this suite, before any container starts.
fn image_present() {
    static PULLED: std::sync::Once = std::sync::Once::new();
    images_present_once(&PULLED, &Runtime::podman());
}

/// Puts the images in `runtime`'s store the first time it is called with `once`. A call that
/// fails, as a stalled one does, with the call named, leaves `once` open: the next case asks again
/// and fails the same way with the call named, where a `Once` that a panic had poisoned would fail
/// it with a word about the poisoning and nothing about the runtime.
fn images_present_once(once: &std::sync::Once, runtime: &Runtime) {
    once.call_once_force(|_| runtime.ensure_images());
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

/// A container this test made, removed when the test ends by any way that runs destructors: by
/// the identifier the runtime issued, and until it has issued one by the name this test gave the
/// container. A test binary that is killed runs none, and leaves the container.
struct Container {
    runtime: Runtime,
    id: String,
    name: String,
}

impl Container {
    fn start() -> Self {
        image_present();
        Self::create(Runtime::podman(), programs_for_a_container())
    }

    /// Starts a container that mounts `programs`.
    fn create(runtime: Runtime, programs: &Path) -> Self {
        let name = format!("kr-acc-{}", kr_ipc::new_uuid());
        let mount = format!("{}:{MOUNTED}:ro", programs.display());
        // The guard exists before the first call that can make the container: a call that makes it
        // and then stalls or fails still leaves a guard that removes it, by the name just given.
        let mut container = Self {
            runtime,
            id: String::new(),
            name,
        };
        let started = container.runtime.call(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            &container.name,
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
        container.id = id;
        container
    }

    /// What names the container to the runtime: the identifier it issued, and until it has issued
    /// one, the name this test gave it. That name holds a whole random UUID, so no other container
    /// has it.
    fn target(&self) -> &str {
        if self.id.is_empty() {
            &self.name
        } else {
            &self.id
        }
    }

    /// Runs one command inside, as root, and says what it printed.
    fn inside(&self, arguments: &[&str]) -> std::process::Output {
        let mut command = vec!["exec", "--user", "root", "--", self.id.as_str()];
        command.extend_from_slice(arguments);
        self.runtime.call(&command)
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
        let started = self.runtime.call(&[
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
        self.wait_until_it_answers(LIVENESS_DEADLINE);
    }

    /// Waits until the daemon in this container answers `kr list`, for as long as `within`, and
    /// fails the case, saying how the last asking ended, when it does not.
    fn wait_until_it_answers(&self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            match self.answers() {
                Ok(()) => return,
                Err(last) => {
                    assert!(
                        Instant::now() < deadline,
                        "the daemon in the container did not answer within {within:?}; the last \
                         asking ended with {last}"
                    );
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    /// Asks the daemon in this container for `kr list`, and says how the asking ended when the
    /// daemon did not answer it. An asking that has not ended within the runtime's quick bound is a
    /// stall and not a missing answer: it fails the case with the command named, where a retry
    /// would hide it. A probe that ends with an error, as `kr` does while the daemon is not up, is
    /// asked again.
    fn answers(&self) -> Result<(), String> {
        let asked = self
            .runtime
            .run(
                &[
                    "exec",
                    "--user",
                    "root",
                    "--",
                    self.id.as_str(),
                    &format!("{MOUNTED}/kr"),
                    "list",
                ],
                self.runtime.quick,
            )
            .unwrap_or_else(|why| panic!("asking the daemon in the container: {why}"));
        if asked.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{}: {}",
                asked.status,
                String::from_utf8_lossy(&asked.stderr).trim()
            ))
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
        let inspected = self.runtime.call(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Status}}",
            "--",
            &self.id,
        ]);
        String::from_utf8_lossy(&inspected.stdout).trim().to_owned()
    }

    /// Removes the container, whether or not the runtime made it. Says why when it could not: the
    /// runtime refused, or the call did not end. It does not panic for either.
    fn remove(&self) -> Result<(), String> {
        let removed = self.runtime.run(
            &[
                "rm",
                "--force",
                "--ignore",
                "--time",
                "0",
                "--",
                self.target(),
            ],
            self.runtime.quick,
        )?;
        if removed.status.success() {
            Ok(())
        } else {
            Err(format!(
                "the runtime said: {}",
                String::from_utf8_lossy(&removed.stderr).trim()
            ))
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let Err(why) = self.remove() else {
            return;
        };
        let record = format!(
            "the container {} ({}) was not removed and may still be running: {why}",
            self.name,
            self.target()
        );
        // Written to standard error directly: the test harness drops what `eprintln!` prints for a
        // case that passes, and a failed write must not panic here either.
        let _ = writeln!(std::io::stderr(), "{record}");
        // A case that passes must not leave a container behind, so it fails. A case that is
        // already failing has said so, and a destructor that panics while one unwinds aborts the
        // whole test binary and cleans up nothing after it in any case still running.
        if !std::thread::panicking() {
            panic!("{record}");
        }
    }
}

/// How long a stand-in runtime gives each call in the cases that stall it: far less than a stall
/// lasts, and far more than a call that answers takes.
const STAND_IN_BOUND: Duration = Duration::from_secs(5);

/// How long a stand-in runtime gives a call that fetches or builds an image: more than
/// [`STAND_IN_BOUND`], so that a call given the wrong one of the two shows in the bound a failure
/// names, and still less than a stall lasts.
const STAND_IN_SLOW_BOUND: Duration = Duration::from_secs(15);

/// How long a stalled call of a stand-in runtime lasts: longer than [`STAND_IN_SLOW_BOUND`], so
/// that a harness that does not end the call by its bound waits for it, and a case that shows the
/// bound fails instead of hanging.
const STAND_IN_STALL_SECONDS: u32 = 40;

/// What a stand-in runtime says to a call it refuses.
const STAND_IN_REFUSAL: &str = "Error: the stand-in runtime refuses this call";

/// The shell patterns that match the first arguments `words` name, or one that matches nothing.
fn first_arguments(words: &[&str]) -> String {
    if words.is_empty() {
        "'-no-such-call-'".to_owned()
    } else {
        words.join("|")
    }
}

/// A stand-in for the container runtime that answers every call with success and no output, and
/// says no image exists, except the calls whose command it is told to stall or to refuse (the
/// first argument: `exec`, `run`, `rm`, `build`, `pull`, `container`, `image`, `--version`). A
/// stalled call prints nothing and does not end within any bound a case gives it, as `podman exec`
/// did on the build box. A refused call says [`STAND_IN_REFUSAL`] on standard error and ends with
/// the runtime's own code for a call it could not do. It records every call in `calls` in its
/// directory, one line of arguments each, whether it stalls or refuses the call or not.
fn stand_in_runtime(directory: &Path, stalls: &[&str], refuses: &[&str]) -> Runtime {
    let text = directory.join("runtime.text");
    std::fs::write(
        &text,
        format!(
            r##"#!/bin/sh
printf '%s\n' "$*" >>'{calls}'
case "$1" in
  {stalled}) exec sleep {STAND_IN_STALL_SECONDS} ;;
  {refused}) echo '{STAND_IN_REFUSAL}' >&2; exit 125 ;;
  image) exit 1 ;;
esac
exit 0
"##,
            calls = directory.join("calls").display(),
            stalled = first_arguments(stalls),
            refused = first_arguments(refuses),
        ),
    )
    .expect("the stand-in runtime");
    let program = directory.join("podman");
    kr_ipc::testing::place_program(&text, &program);
    Runtime {
        program,
        quick: STAND_IN_BOUND,
        slow: STAND_IN_SLOW_BOUND,
    }
}

/// The calls a stand-in runtime was given, one line of arguments each.
fn recorded_calls(directory: &Path) -> Vec<String> {
    std::fs::read_to_string(directory.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A container the harness holds by the identifier a stand-in runtime issued.
fn held_in(runtime: Runtime) -> Container {
    Container {
        runtime,
        id: STAND_IN_CONTAINER_ID.to_owned(),
        name: "kr-acc-stand-in".to_owned(),
    }
}

/// What a panic said.
fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default()
}

/// Runs this test binary again with `arguments`, as a process of its own, and gives what it did.
/// For a case that needs what a process writes to its own standard error, or what it does with a
/// `PATH` of its own, which a thread of this one cannot give it.
fn this_binary_with(arguments: &[&str], path: Option<&Path>) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().expect("this binary"));
    command.args(arguments);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    to_its_end(command, Duration::from_secs(120))
}

/// A removal that stalls is an error the harness reports, and one that stalls while a failed
/// assertion unwinds aborts nothing: a destructor that panics then ends the whole test binary and
/// leaves the cleanup of every other case in flight undone.
#[test]
fn a_removal_that_stalls_is_an_error_and_aborts_nothing_while_an_assertion_fails() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &["rm"], &[]));
    let why = container
        .remove()
        .expect_err("a removal that never ends is an error and not a panic");
    assert!(why.contains("\"rm\""), "the call is named: {why}");
    assert!(
        recorded_calls(directory.path())
            .iter()
            .any(|call| call.starts_with("rm ")
                && call.ends_with(&format!(" -- {STAND_IN_CONTAINER_ID}"))),
        "a container the runtime issued an identifier for is removed by it"
    );

    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = container;
        panic!("an assertion of the case fails");
    }));
    assert_eq!(
        panic_message(failed.expect_err("the assertion's own panic is what unwinds")),
        "an assertion of the case fails"
    );
    let removals = recorded_calls(directory.path())
        .iter()
        .filter(|call| call.starts_with("rm "))
        .count();
    assert_eq!(removals, 2, "the unwinding case tried to remove it too");
}

/// A removal the runtime refuses is an error that says what the runtime said, and not a removal.
#[test]
fn a_removal_the_runtime_refuses_is_an_error_that_says_what_it_said() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &[], &["rm"]));
    let why = container
        .remove()
        .expect_err("a refused removal is an error");
    assert!(why.contains(STAND_IN_REFUSAL), "{why}");
    // Nothing was made, so there is nothing for the destructor to remove either.
    std::mem::forget(container);
}

/// A case that passes while its container could not be removed fails: the container is still
/// there, running a process, on a machine that other cases and other people share.
#[test]
fn a_case_that_passes_fails_when_its_container_could_not_be_removed() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &[], &["rm"]));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = container;
    }));
    let said = panic_message(failed.expect_err("a container left behind fails the case"));
    assert!(
        said.contains("was not removed and may still be running")
            && said.contains(STAND_IN_REFUSAL),
        "{said}"
    );
}

/// Run by the case below as a process of its own: a case that fails while its container cannot be
/// removed.
#[test]
#[ignore = "run as a process of its own by a_container_that_cannot_be_removed_is_recorded_whatever_the_harness_captures"]
fn a_case_fails_while_its_container_cannot_be_removed() {
    let directory = tempfile::tempdir().expect("a directory");
    let _held = held_in(stand_in_runtime(directory.path(), &[], &["rm"]));
    panic!("the case's own assertion fails");
}

/// The record of a container that could not be removed reaches standard error when the case that
/// held it fails, though the test harness holds back what a case prints, and the binary ends with
/// the failure and not with an abort.
#[test]
fn a_container_that_cannot_be_removed_is_recorded_whatever_the_harness_captures() {
    let ran = this_binary_with(
        &[
            "--ignored",
            "--exact",
            "a_case_fails_while_its_container_cannot_be_removed",
        ],
        None,
    );
    let said = String::from_utf8_lossy(&ran.stderr);
    assert!(
        said.contains("was not removed and may still be running"),
        "{said}"
    );
    assert_eq!(
        ran.status.code(),
        Some(101),
        "the failed case ends the binary as a test failure: {}",
        ran.status
    );
}

/// A start that stalls after the runtime made the container leaves it removed: the guard exists
/// before the call that makes the container, and removes it by the name just given, which holds a
/// whole random UUID so that it can name no other container, and by force, since the container may
/// be running.
#[test]
fn a_container_start_that_stalls_after_the_runtime_made_the_container_removes_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let runtime = stand_in_runtime(directory.path(), &["run"], &[]);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Container::create(runtime, directory.path())
    }));
    let said = panic_message(
        failed
            .err()
            .expect("a start that never ends fails the case"),
    );
    assert!(said.contains("\"run\""), "the call is named: {said}");

    let calls = recorded_calls(directory.path());
    let name = calls
        .iter()
        .find(|call| call.starts_with("run "))
        .and_then(|call| call.split(' ').skip_while(|word| *word != "--name").nth(1))
        .expect("the start named the container it made");
    let uuid = name
        .strip_prefix("kr-acc-")
        .expect("the name starts as a harness container's does");
    assert!(
        uuid.parse::<kr_protocol::scalars::Uuid>().is_ok(),
        "the name holds a whole UUID: {name}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("rm --force --ignore ")
                && call.ends_with(&format!(" -- {name}"))),
        "the container is removed by force, by the name it was given: {calls:?}"
    );
}

/// A runtime that is installed and never answers `--version` fails the case with the call named,
/// where a runtime that is not installed skips it.
#[test]
fn a_runtime_that_never_answers_its_version_fails_the_case_and_is_not_skipped() {
    let directory = tempfile::tempdir().expect("a directory");
    let stalled = stand_in_runtime(directory.path(), &["--version"], &[]);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stalled.is_available()));
    let said = panic_message(failed.expect_err("a runtime that does not answer fails the case"));
    assert!(said.contains("\"--version\""), "the call is named: {said}");

    let absent = Runtime {
        program: directory.path().join("no-such-runtime"),
        ..stalled
    };
    assert!(
        !absent.is_available(),
        "a runtime that is not installed is skipped"
    );
}

/// A runtime is found on the `PATH` it is looked for on, and nowhere else: a case that cannot find
/// it skips itself, so a search that finds it nowhere would skip both real-container cases on
/// every machine.
#[test]
fn a_runtime_is_found_on_the_path_it_is_looked_for_on_and_nowhere_else() {
    let empty = tempfile::tempdir().expect("a directory");
    let holding = tempfile::tempdir().expect("a directory");
    std::fs::write(holding.path().join("podman"), "").expect("a file of the name");
    let runtime = Runtime {
        program: PathBuf::from("podman"),
        quick: STAND_IN_BOUND,
        slow: STAND_IN_SLOW_BOUND,
    };
    let path = std::env::join_paths([empty.path(), holding.path()]).expect("a path");
    assert!(runtime.installed_in(Some(&path)));
    assert!(!runtime.installed_in(Some(empty.path().as_os_str())));
    assert!(!runtime.installed_in(None));
    let by_path = Runtime {
        program: holding.path().join("podman"),
        ..runtime
    };
    assert!(
        by_path.installed_in(None),
        "a program named by a path is there when the file is"
    );
}

/// A machine with no runtime says so on the line the conformance report reads as a case that did
/// not run, for each of the two real-container cases, so that it never counts them as passed.
#[test]
fn a_machine_without_the_runtime_says_so_in_the_form_the_conformance_report_reads() {
    let empty = tempfile::tempdir().expect("a directory");
    let ran = this_binary_with(
        &[
            "--nocapture",
            "--exact",
            "an_enrolled_container_answers_a_bridge_and_a_session_made_through_it_lives_there",
            "a_stopped_container_is_started_by_a_create_and_keeps_its_identity",
        ],
        Some(empty.path()),
    );
    assert!(ran.status.success(), "{}", ran.status);
    let said = String::from_utf8_lossy(&ran.stderr);
    let lines = said
        .lines()
        .filter(|line| line.starts_with("bridged_session: skipped, because "))
        .count();
    assert_eq!(lines, 2, "one line for each case: {said}");
}

/// A runtime image check that stalls fails every case that asks, each with the call named: the
/// first fails with the call named and the next does not fail with a word about the first.
#[test]
fn an_image_check_that_stalls_fails_every_case_that_asks_and_names_the_call() {
    let directory = tempfile::tempdir().expect("a directory");
    let runtime = stand_in_runtime(directory.path(), &["image"], &[]);
    let once = std::sync::Once::new();
    for case in ["first", "second"] {
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            images_present_once(&once, &runtime);
        }));
        let said = panic_message(failed.expect_err("a check that never ends fails the case"));
        assert!(
            said.contains("\"image\"") && said.contains("\"exists\""),
            "the {case} case is told the call: {said}"
        );
    }
}

/// An image pull that never ends fails the case with the pull named, within the bound a call that
/// fetches an image is given.
#[test]
fn an_image_pull_that_never_ends_fails_the_case_and_names_the_pull() {
    let directory = tempfile::tempdir().expect("a directory");
    let runtime = stand_in_runtime(directory.path(), &["pull"], &[]);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.ensure_images()));
    let said = panic_message(failed.expect_err("a pull that never ends fails the case"));
    assert!(
        said.contains("\"pull\"") && said.contains(&format!("{STAND_IN_SLOW_BOUND:?}")),
        "the call and the bound it was given are named: {said}"
    );
}

/// An image build that never ends fails the case with the build named, within the bound a call that
/// builds an image is given, and does not hold the suite.
#[test]
fn an_image_build_that_never_ends_fails_the_case_and_names_the_build() {
    let directory = tempfile::tempdir().expect("a directory");
    let runtime = stand_in_runtime(directory.path(), &["build"], &[]);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.ensure_images()));
    let said = panic_message(failed.expect_err("a build that never ends fails the case"));
    assert!(
        said.contains("\"build\"") && said.contains(&format!("{STAND_IN_SLOW_BOUND:?}")),
        "the call and the bound it was given are named: {said}"
    );
    assert!(
        said.contains("working container"),
        "what a build that did not end may leave is named: {said}"
    );
    assert!(
        recorded_calls(directory.path())
            .iter()
            .any(|call| call.starts_with("build ")),
        "the build was started"
    );
}

/// A probe of the daemon in a container that stalls fails the case with the command named. It is
/// not counted as one more asking that got no answer, which the next good asking would cover.
#[test]
fn a_probe_that_stalls_fails_the_case_and_names_the_command() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &["exec"], &[]));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| container.answers()));
    let said = panic_message(failed.expect_err("a stalled probe fails the case"));
    assert!(
        said.contains("\"exec\"") && said.contains("\"list\"") && said.contains("\"/kr/kr\""),
        "the command is named: {said}"
    );
}

/// A daemon that never answers fails the case with how the last asking ended, and not with a
/// sentence that says nothing of what `kr` or the runtime said.
#[test]
fn a_daemon_that_never_answers_fails_the_case_and_says_how_the_last_asking_ended() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &[], &["exec"]));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        container.wait_until_it_answers(Duration::from_secs(1));
    }));
    let said = panic_message(failed.expect_err("a daemon that never answers fails the case"));
    assert!(
        said.contains(STAND_IN_REFUSAL) && said.contains("125"),
        "the last asking is described: {said}"
    );
}

/// A call to the container runtime that never ends fails the case that made it, with the call
/// named, and does not hold the suite.
#[test]
fn a_runtime_call_that_never_ends_fails_the_case_that_made_it_and_names_the_call() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(stand_in_runtime(directory.path(), &["container"], &[]));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| container.state()));
    let said = panic_message(failed.expect_err("a call that never ends fails the case"));
    assert!(
        said.contains("\"inspect\"") && said.contains(STAND_IN_CONTAINER_ID),
        "the call is named: {said}"
    );
    assert!(said.contains("did not end within"), "{said}");
}

/// A call that waits for its turn to start a process is held to its bound from the call, and
/// not from the moment the turn comes: a start that holds the turn longer than the bound fails the
/// call, which says that the turn is why.
#[test]
fn a_call_that_waits_for_the_turn_to_start_a_process_is_bounded_from_the_call() {
    let (taken, has_taken) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        user_manager::spawning(|| {
            taken.send(()).expect("the turn was taken");
            // Let go when the case is done with the turn, or after a time in any case.
            let _ = released.recv_timeout(Duration::from_secs(20));
        });
    });
    has_taken.recv().expect("the holder took the turn");
    let refused = user_manager::bounded(
        std::process::Command::new("/usr/bin/true"),
        Duration::from_secs(1),
    );
    release.send(()).expect("the holder is waiting");
    holder.join().expect("the holder ended");
    let why = refused.expect_err("a call that could not start within its bound fails");
    assert!(why.contains("could not be started within"), "{why}");
}

/// A call that does not end within its bound is asked to end before it is killed, so that a
/// program that cleans up after itself, as an image build does, is given the chance: a program that
/// is killed outright leaves what it started.
#[test]
fn a_call_that_does_not_end_is_asked_to_end_before_it_is_killed() {
    let directory = tempfile::tempdir().expect("a directory");
    let ready = directory.path().join("ready");
    let asked = directory.path().join("asked-to-end");
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("trap ': > \"$2\"; kill $!; exit 0' TERM; sleep 30 & : > \"$1\"; wait")
        .arg("program")
        .arg(&ready)
        .arg(&asked)
        .spawn()
        .expect("starts the program");
    // The program is ended only once it is ready to be asked.
    let begun = Instant::now();
    while !ready.exists() {
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the program did not get ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let failed = user_manager::end_and_collect(&mut child);
    assert_eq!(failed, "", "ending it failed");
    assert!(
        asked.exists(),
        "the program was killed without being asked to end"
    );
}

/// A run of `kr` that does not end within its bound fails the case that ran it, with the call
/// named. A bound of nothing is one that no run of `kr` meets, so this needs no stalled program.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kr_run_that_does_not_end_within_its_bound_fails_the_case_and_names_the_call() {
    let mut world = World::start().await;
    world.kr_bound = Duration::ZERO;
    let failed =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| world.run(&["--version"])));
    let said = panic_message(failed.expect_err("a run that outlasts its bound fails the case"));
    assert!(
        said.contains("\"--version\"") && said.contains("within"),
        "the call is named: {said}"
    );
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
    let _turn = CONTAINER_RUNTIME_TURN.lock().await;
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
        "{}; it said {}",
        String::from_utf8_lossy(&refreshed.stdout),
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
        "--shell-mode",
        "native_compat",
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
    let _turn = CONTAINER_RUNTIME_TURN.lock().await;
    let container = Container::start();
    container.serve();
    let world = World::start().await;
    let enrolled = world.enrol_container(&container, "box");
    let identity = container.environment_id();
    assert_eq!(enrolled["row"]["enrolment"]["environment_id"], identity);

    let stopped = container
        .runtime
        .call(&["stop", "--time", "0", "--", &container.id]);
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
        "--shell-mode",
        "native_compat",
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
