//! The plugin runtime as the product starts it: a real daemon, real workers with real shells, a
//! real plugin host process, and a package that ships a real component.
//!
//! Nothing here starts the plugin host but the daemon. A package whose package ships a component is
//! installed and enabled through the catalogue; a program it recognises runs in a session; the
//! worker binds the package, asks the daemon for the runtime, and registers the binding's
//! component with the process the daemon started. What the tests look at is what a person's host
//! has: the processes the supervisor was asked to start, the descriptor the daemon published, the
//! runtime's own report of what it holds, and what each worker reports of its bindings.
//!
//! Everything a launched process opens is on the internal disk, under the test's own tree, and the
//! three programs it launches (the worker, the plugin host and the stand-in agent) are copies placed
//! there. The test components are built by `scripts/build-plugin-fixtures.sh`.

#![cfg(unix)]

#[path = "plugin_world/ended.rs"]
mod ended;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ended::kill;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor, detect,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Enrolment, InstallationGrant, RepositoryId, RepositoryKind,
};
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{HostHealth, HostProtocol};
use kr_protocol::admission::{ComponentState, PluginRuntimeState, PluginRuntimeWanted};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, PluginId, SessionEpoch, SessionId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCreateParams, SessionCreateResult, ShellMode};

mod teardown;

/// The catalogue's own builder of signed generations, for a package this test writes.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// How long a test waits for something the product does on its own. Generous, because a loaded
/// machine is slow and none of these waits is timed by the product itself.
const PATIENCE: Duration = Duration::from_secs(90);

/// How long a test waits for a binding to be registered with the plugin runtime.
///
/// A registration compiles the component at background priority, and a machine that other work
/// keeps busy leaves such a thread a tenth of a processor or less, so the compile takes tens of
/// minutes. A registration that runs out its own deadline in the meantime is offered again by the
/// worker after a delay that doubles up to ten minutes, and the offer after the compile ends is the
/// one that registers. The wait ends as soon as the runtime holds the binding; this bounds only a
/// binding that is never registered.
const REGISTRATION_PATIENCE: Duration = Duration::from_secs(60 * 60);

/// The variable that makes a placed copy of this binary a program a person starts in a session. It
/// names the process the program belongs to, which is the test run that started it, as the
/// process's number and the value the system gave for when it started (`pid:start`, from
/// [`owner_of`]), and the program stays running while that process is and while the file
/// [`STAND_IN_RUNNING`] names is there. A binding ends with its program, so the program has to
/// outlast any wait for a registration; it ends with the run, whichever way the run ends.
const STAND_IN: &str = "KR_RUNTIME_STAND_IN";

/// The variable that names a file the stand-in writes its process identifier to once it runs.
const STAND_IN_RUNNING: &str = "KR_RUNTIME_STAND_IN_RUNNING";

/// The variable that makes the stand-in print a numbered line every so often while it runs.
const STAND_IN_TICKS: &str = "KR_RUNTIME_STAND_IN_TICKS";

/// The environment variable that makes an unbuilt component set a failure.
const REQUIRE_FIXTURES: &str = "KR_REQUIRE_PLUGIN_FIXTURES";

/// The value that names the running process `pid` to the stand-in program: its number and the value
/// the system gave for when it started, so that a number the system gives to another process later,
/// or before the program looks, is not taken for it.
fn owner_of(pid: u32) -> String {
    let started = kr_ipc::identity::process_start_identity(pid).expect("the process runs");
    format!("{}:{}", started.pid.get(), started.start_value.get())
}

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(owner) = std::env::var(STAND_IN) {
        // The run that started it, held by the identity it had when it was named. A run that is
        // already gone, whose number is another process's now, or that cannot be looked up is none
        // the program can stay for: it says nothing of itself and ends.
        let owner = owner
            .split_once(':')
            .and_then(|(pid, start)| Some((pid.parse::<u32>().ok()?, start.parse::<u64>().ok()?)))
            .and_then(|(pid, start)| {
                kr_ipc::identity::process_start_identity(pid)
                    .ok()
                    .filter(|found| found.start_value.get() == start)
            });
        let Some(owner) = owner else {
            return;
        };
        let running = std::env::var_os(STAND_IN_RUNNING).map(PathBuf::from);
        if let Some(running) = &running {
            std::fs::write(running, std::process::id().to_string()).expect("says it is running");
        }
        // It stays while the run is there and the file that says it is running is there, and a look
        // at the run that does not answer, or at the file that fails, is not its being gone. The
        // test's tree takes the file with it, which ends a program that a session's shell holds in
        // the background, where the shell's end would not reach it; a run that is stopped before it
        // removes its tree ends it by the run's own end.
        let stays = || {
            kr_ipc::identity::process_state(&owner) != ProcessState::Ended
                && running
                    .as_ref()
                    .is_none_or(|file| file.try_exists().unwrap_or(true))
        };
        // A program that keeps the terminal busy: a numbered line every so often, so what the
        // session shows after something happens can be told from what it had already shown.
        if std::env::var_os(STAND_IN_TICKS).is_some() {
            let mut tick = 0_u64;
            while stays() {
                println!("tick-{tick}");
                tick += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
        } else {
            while stays() {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// How long the case below waits for the program to say it runs and to end with its run. Neither
/// is decided by it: the program does both within a moment, and this ends only one that never does.
const PROGRAM_PATIENCE: Duration = Duration::from_secs(60 * 60);

/// A process this case started, ended when the case is over however it ends.
struct Started(std::process::Child);

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// The program a test runs in a session belongs to the test run that started it, and ends with that
// run however the run ends. A run that is interrupted leaves its tree behind, and a program that
// waited for the tree to go, or for a time it was given, would go on running after it.
//
// The run here is another process, which the case ends; the program is the placed copy of this
// binary, as a session starts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stand_in_program_ends_with_the_test_run_that_started_it() {
    let tree = tempfile::tempdir().expect("a directory on the internal disk");
    let placed = tree.path().join("example-agent");
    kr_ipc::testing::place_and_start_once(
        &std::env::current_exe().expect("this test's own binary"),
        &placed,
        &["--exact", "the_stand_in_program", "--test-threads", "1"],
    );
    let running = tree.path().join("agent-running");
    let mut run = Started(
        std::process::Command::new("sleep")
            .arg("1000000")
            .spawn()
            .expect("a process to stand for the test run"),
    );
    let mut program = Started(
        std::process::Command::new(&placed)
            .args([
                "--exact",
                "the_stand_in_program",
                "--test-threads",
                "1",
                "--nocapture",
            ])
            .env(STAND_IN, owner_of(run.0.id()))
            .env(STAND_IN_RUNNING, &running)
            .env(STAND_IN_TICKS, "1")
            .current_dir(tree.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the program starts"),
    );
    // The lines it prints while it stays, read on a thread of their own so that reading them holds
    // nothing up.
    let ticks = {
        use std::io::BufRead as _;

        let output = program.0.stdout.take().expect("the program's output");
        let (said, ticks) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output)
                .lines()
                .map_while(Result::ok)
            {
                if said.send(line).is_err() {
                    break;
                }
            }
        });
        ticks
    };
    until_within(PROGRAM_PATIENCE, "the program to say it runs", || async {
        std::fs::read_to_string(&running).ok()
    })
    .await;
    // It stays while its run lives: it has gone round its loop three times and is still there.
    until_within(
        PROGRAM_PATIENCE,
        "the program to go on while its run lives",
        || {
            let ended = program.0.try_wait().ok().flatten();
            assert!(
                ended.is_none(),
                "the program ended with its run still there: {ended:?}"
            );
            let seen = ticks.try_iter().any(|line| line == "tick-2");
            async move { seen.then_some(()) }
        },
    )
    .await;

    run.0.kill().expect("the run is ended");
    run.0.wait().expect("the run is collected");
    until_within(PROGRAM_PATIENCE, "the program to end with its run", || {
        let ended = program.0.try_wait().ok().flatten();
        async move { ended }
    })
    .await;
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("an identifier")
}

/// Loads the built test component the package ships, or says why the test cannot run.
fn well_behaved() -> Option<Vec<u8>> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/components/build");
    if !directory.is_dir() {
        let required = std::env::var(REQUIRE_FIXTURES).is_ok_and(|value| value == "1");
        assert!(
            !required,
            "{REQUIRE_FIXTURES}=1 and the test components are not built; run \
             scripts/build-plugin-fixtures.sh"
        );
        eprintln!(
            "skipping: the test components are not built. Run scripts/build-plugin-fixtures.sh"
        );
        return None;
    }
    Some(
        std::fs::read(directory.join("well-behaved.wasm"))
            .expect("the component build directory holds well-behaved.wasm"),
    )
}

/// Returns a program this workspace built, which sits beside this test's own binary.
fn beside_this_test(name: &str) -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let program = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        program.is_file(),
        "this test starts {name} and there is none at {}; build it with `cargo build -p {name}`, or \
         run the whole workspace's tests, which build it",
        program.display()
    );
    program
}

fn directory_url(path: &Path) -> url::Url {
    url::Url::from_directory_path(std::fs::canonicalize(path).expect("an existing directory"))
        .expect("an absolute path")
}

/// Writes the example declarative package with `component` shipped in it, into `into`.
fn write_package(into: &Path, component: &[u8]) {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/valid/example-declarative");
    std::fs::create_dir_all(into).expect("a package directory");
    std::fs::copy(
        example.join("presentation.json"),
        into.join("presentation.json"),
    )
    .expect("the presentation");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(example.join("plugin.json")).expect("the example manifest"),
    )
    .expect("a manifest");
    manifest["payloads"]
        .as_array_mut()
        .expect("the manifest lists its payloads")
        .push(serde_json::json!({
            "role": "component",
            "path": "component.wasm",
            "digest": kr_plugin_sdk::digest::PayloadDigest::of(component).to_string(),
            "size_bytes": component.len().to_string(),
        }));
    std::fs::write(
        into.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest).expect("a manifest"),
    )
    .expect("the manifest");
    std::fs::write(into.join("component.wasm"), component).expect("the component");
}

/// What the daemon asked its supervisor to start.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Requested {
    /// A session's worker.
    Worker(SessionId),
    /// A service that is not a worker, by its job label.
    Service(String),
}

/// What the supervisor was asked to start, in order, with the process each start produced.
type Record = Arc<Mutex<Vec<(Requested, Option<ProcessStartIdentity>)>>>;

/// The tree's own supervisor, recording what it is asked to start, and the processes that came of
/// it.
#[derive(Debug)]
struct Recording {
    inner: Box<dyn WorkerSupervisor>,
    requested: Record,
}

impl Recording {
    fn note(&self, what: Requested, outcome: &LaunchOutcome) {
        let process = match outcome {
            LaunchOutcome::Started(identity) => Some(identity.clone()),
            _ => None,
        };
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .push((what, process));
    }
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let outcome = self.inner.start(launch);
        self.note(Requested::Worker(launch.session_id), &outcome);
        outcome
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        let outcome = self.inner.start_service(launch);
        self.note(Requested::Service(launch.label.clone()), &outcome);
        outcome
    }

    fn describe(&self) -> &'static str {
        "the platform's supervisor, recording what it starts"
    }
}

/// Ends every plugin host the daemon started that is still running, by the identity it was
/// started under, before the tree that holds it goes. A host is not a worker, so the tree's own
/// teardown does not ask it to close.
///
/// A daemon in a process of its own is not seen by this test's supervisor, so the host it
/// published is ended too.
struct HostEnding {
    requested: Record,
    environment: EnvironmentPaths,
}

impl Drop for HostEnding {
    fn drop(&mut self) {
        let mut hosts: Vec<ProcessStartIdentity> = self
            .requested
            .lock()
            .map(|requested| {
                requested
                    .iter()
                    .filter(|(what, _)| matches!(what, Requested::Service(_)))
                    .filter_map(|(_, process)| process.clone())
                    .collect()
            })
            .unwrap_or_default();
        if let Ok(Some(published)) =
            launcher::read_descriptor(&self.environment, &HostProtocol::THIS)
        {
            hosts.push(published.process_start_identity);
        }
        // Seen to end, as the plugin world's teardown sees it: a host this test cannot end is a
        // process left running on the machine, and the test says so.
        let running = ended::end_hosts(&hosts, std::time::Instant::now() + Duration::from_secs(30));
        assert!(
            running.is_empty() || std::thread::panicking(),
            "this test left plugin hosts that were not seen to end ({running:?})"
        );
    }
}

/// The daemon this test started as a process of its own, in a process group of its own, ended
/// with that group however the test ends.
struct Apart {
    child: Option<std::process::Child>,
}

impl Apart {
    /// Ends the daemon and everything else in its group, as a terminal closing or a service
    /// manager stopping a unit that holds it would, and waits for it.
    fn end_with_its_group(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Some(group) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

impl Drop for Apart {
    fn drop(&mut self) {
        self.end_with_its_group();
    }
}

/// Stops a process that is running, as a signal from a terminal would, after checking that it is
/// still the process it was. It is not ended: it answers nothing until it is ended.
fn stop(process: &ProcessStartIdentity) {
    assert_eq!(
        kr_ipc::identity::process_state(process),
        ProcessState::Running,
        "the process is still the one it was"
    );
    let pid = rustix::process::Pid::from_raw(i32::try_from(process.pid.get()).expect("a pid"))
        .expect("a process");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stopped");
}

/// Waits until the kernel says `process` has ended.
async fn ended(process: &ProcessStartIdentity) {
    until("the process to end", || async {
        (kr_ipc::identity::process_state(process) == ProcessState::Ended).then_some(())
    })
    .await;
}

/// Asks `check` until it answers, or the patience runs out.
async fn until<T, Fut>(what: &str, check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    until_within(PATIENCE, what, check).await
}

/// As [`until`], with a patience the caller chooses.
async fn until_within<T, Fut>(patience: Duration, what: &str, mut check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    until_found(
        patience,
        what,
        || {
            let look = check();
            async move { look.await.ok_or_else(String::new) }
        },
        || async { String::new() },
    )
    .await
}

/// [`until_within`] for a look that says what it found when it found nothing, so that a wait that
/// runs out of patience says what its looks saw and when, and not only what it waited for: each
/// look that differed from the one before, with the seconds since the wait began when it was first
/// seen (the first eight and the last eight when there are more, and how many are left out).
///
/// `explain` is asked once, when the wait has run out, for what is worth saying of how things stand
/// at the end and is too slow to ask at each look.
async fn until_found<T, Fut, Why>(
    patience: Duration,
    what: &str,
    mut check: impl FnMut() -> Fut,
    explain: impl FnOnce() -> Why,
) -> T
where
    Fut: std::future::Future<Output = Result<T, String>>,
    Why: std::future::Future<Output = String>,
{
    let began = tokio::time::Instant::now();
    let deadline = began + patience;
    let mut looks: Vec<(Duration, String)> = Vec::new();
    loop {
        let seen = match check().await {
            Ok(found) => return found,
            Err(seen) => seen,
        };
        if !seen.is_empty() && looks.last().is_none_or(|(_, last)| *last != seen) {
            looks.push((began.elapsed(), seen));
        }
        if tokio::time::Instant::now() >= deadline {
            let end = explain().await;
            panic!(
                "waited {patience:?} for {what}{}{end}",
                looks_in_words(&looks)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The looks of a wait that ran out, each with the seconds since the wait began.
fn looks_in_words(looks: &[(Duration, String)]) -> String {
    const KEPT: usize = 8;
    if looks.is_empty() {
        return String::new();
    }
    let show = |(at, seen): &(Duration, String)| format!("after {:.1} s: {seen}", at.as_secs_f64());
    let shown = if looks.len() <= 2 * KEPT {
        looks.iter().map(show).collect::<Vec<_>>().join("; ")
    } else {
        format!(
            "{}; ({} left out); {}",
            looks[..KEPT]
                .iter()
                .map(show)
                .collect::<Vec<_>>()
                .join("; "),
            looks.len() - 2 * KEPT,
            looks[looks.len() - KEPT..]
                .iter()
                .map(show)
                .collect::<Vec<_>>()
                .join("; ")
        )
    };
    format!("; the looks that differed, by the seconds since the wait began: {shown}")
}

/// One look at the workers' reports of components.
struct Look {
    /// What the workers report, one entry to a binding whose package ships a component.
    reports: Vec<(
        kr_protocol::ids::BrokerBindingId,
        kr_protocol::admission::ComponentReport,
    )>,
    /// Whether the controller counted a current report from every worker. Where it did not, the
    /// reports may be the last ones accepted, which say nothing of where a component stands now.
    counted: bool,
}

/// What a look says of how current its reports are.
fn counting_in_words(counted: bool) -> &'static str {
    if counted {
        "the controller counted a current report from every worker"
    } else {
        "the controller could not count a current report from every worker, so these may be the \
         reports last accepted"
    }
}

/// What the workers' reports of components say, one binding to a phrase, for a wait that ran out:
/// whether the binding is `first` (otherwise it is named by the end of its identifier), its state
/// and its reason, and what `counting` says of how current they are.
fn reports_in_words(
    reports: &[(
        kr_protocol::ids::BrokerBindingId,
        kr_protocol::admission::ComponentReport,
    )],
    first: kr_protocol::ids::BrokerBindingId,
    counting: &str,
) -> String {
    if reports.is_empty() {
        return format!("no binding ({counting})");
    }
    let words = reports
        .iter()
        .map(|(binding, report)| {
            let identifier = binding.to_string();
            format!(
                "{} is {:?} ({})",
                if *binding == first {
                    "the first binding".to_owned()
                } else {
                    format!(
                        "the other binding (ending {})",
                        &identifier[identifier.len().saturating_sub(6)..]
                    )
                },
                report.state,
                report.reason.0.as_deref().unwrap_or("no reason")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{words} ({counting})")
}

/// A person at a session's terminal: an attachment that holds the input lease and types.
struct Typist {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
}

impl Typist {
    /// Types `text` into the terminal.
    async fn send(&mut self, text: &str) {
        self.client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch: self.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    input: kr_protocol::input::InputContent::Bytes {
                        bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
                    },
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the bytes reach the terminal");
        self.sequence += 1;
    }
}

/// A daemon hosting real workers over a catalogue whose package ships a component.
struct World {
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    worker: PathBuf,
    /// The program the package recognises, placed on the internal disk.
    agent: PathBuf,
    requested: Record,
    /// How much of `requested` an earlier daemon of this tree made: what the current one was asked
    /// to start is what follows.
    counted_from: usize,
    _published: tempfile::TempDir,
    /// Before the hosts, so a daemon in a process of its own is gone before they are ended.
    apart: Apart,
    /// Before the tree, so every host the daemon started is ended before the tree goes.
    _hosts: HostEnding,
    /// Last: it ends every worker the daemon started.
    tree: teardown::Tree,
}

impl Drop for World {
    /// Stops the daemon before anything it started is ended. A daemon that goes on serving starts
    /// a runtime in place of a host that was ended, after the hosts to end were listed, and that
    /// host is then left to a teardown that waits for it to close as a worker does and a host
    /// never does.
    fn drop(&mut self) {
        for serving in self.serving.drain(..) {
            serving.abort();
        }
        let Some(controller) = self.controller.take() else {
            return;
        };
        // The tasks the daemon runs let it go as they are dropped: a liveness condition, waited for
        // for as long as the loaded machine needs and no longer.
        let until = std::time::Instant::now() + Duration::from_secs(60);
        while Arc::strong_count(&controller) > 1 && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(controller);
    }
}

impl World {
    /// A world whose daemon runs in this process.
    async fn start(component: &[u8]) -> Self {
        let mut world = Self::prepare(component).await;
        world.run().await;
        world
    }

    /// A world whose daemon runs as a process of its own, in a group of its own, started with
    /// `services` selecting how it starts a service that is not a worker.
    async fn start_apart(component: &[u8], services: &str) -> Self {
        let mut world = Self::prepare(component).await;
        world.spawn_daemon(services).await;
        world
    }

    /// The tree, the three programs placed on it, and the package installed, with no daemon.
    async fn prepare(component: &[u8]) -> Self {
        let tree = teardown::Tree::create();
        // Placed on the internal disk and started once here, where nothing is timed. The runtime
        // is found beside the worker.
        let worker = tree.root().join("kr-worker");
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-worker"),
            &worker,
            &["--version"],
        );
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-plugin-host"),
            &tree
                .root()
                .join(format!("kr-plugin-host{}", std::env::consts::EXE_SUFFIX)),
            &["--version"],
        );
        let agent = tree.root().join("example-agent");
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test's own binary"),
            &agent,
            &["--exact", "the_stand_in_program", "--test-threads", "1"],
        );

        let published = tempfile::tempdir().expect("a directory on the internal disk");
        let package = published.path().join("package");
        write_package(&package, component);
        let generation = generations::Generation::build(
            published.path(),
            generations::GenerationSpec {
                package: Some(package),
                ..generations::GenerationSpec::default()
            },
        )
        .await;
        install(&tree, &generation).await;

        let requested = Arc::default();
        let environment = tree.environment();
        Self {
            controller: None,
            serving: Vec::new(),
            endpoint: environment.controller_endpoint().expect("an endpoint"),
            environment_id: tree.environment_id(),
            worker,
            agent,
            requested: Arc::clone(&requested),
            counted_from: 0,
            _published: published,
            apart: Apart { child: None },
            _hosts: HostEnding {
                requested,
                environment,
            },
            tree,
        }
    }

    /// Starts the daemon as a process of its own and waits until it answers.
    async fn spawn_daemon(&mut self, services: &str) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.tree.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let child = {
            use std::os::unix::process::CommandExt as _;
            std::process::Command::new(std::env::current_exe().expect("this test's own binary"))
                .args([
                    "--exact",
                    DAEMON_HALF,
                    "--include-ignored",
                    "--nocapture",
                    "--test-threads",
                    "1",
                ])
                .env(DAEMON_ROOT, self.tree.root())
                .env(DAEMON_WORKER, &self.worker)
                .env(DAEMON_SERVICES, services)
                .current_dir(self.tree.root())
                .stdin(std::process::Stdio::null())
                .stdout(log.try_clone().expect("duplicates the log"))
                .stderr(log)
                // A group of its own, so that ending it ends what is in the group and nothing of
                // this test.
                .process_group(0)
                .spawn()
                .unwrap_or_else(|error| panic!("the daemon starts: {error:?}"))
        };
        self.apart.child = Some(child);
        let endpoint = self.endpoint.clone();
        let root = self.tree.root().to_path_buf();
        until("the daemon to answer", || async {
            let found = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await;
            if found.is_err() {
                assert!(
                    std::fs::read_to_string(root.join("daemon.log"))
                        .map_or(true, |log| !log.contains("panicked")),
                    "the daemon did not start: {}",
                    std::fs::read_to_string(root.join("daemon.log")).unwrap_or_default()
                );
            }
            found.ok()
        })
        .await;
    }

    fn environment(&self) -> EnvironmentPaths {
        self.tree.environment()
    }

    /// Starts the daemon on the tree, serving its clients and its workers' rendezvous.
    async fn run(&mut self) {
        let environment = self.environment();
        let environment_id = self.environment_id;
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(Recording {
                inner: self.tree.supervisor(detect(&environment, &self.worker)),
                requested: Arc::clone(&self.requested),
            }),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let listener = Listener::bind(&self.endpoint).expect("binds the endpoint");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_clients(listener),
        ));
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_rendezvous(rendezvous),
        ));
        self.controller = Some(controller);
    }

    /// Stops the daemon and starts another on the same tree, the way a restart of the host does:
    /// every durable record stays, nothing held in memory does, and the workers and the plugin
    /// runtime go on running. What the new daemon is asked to start is counted from here.
    async fn restart(&mut self) {
        for serving in self.serving.drain(..) {
            serving.abort();
            let _ = serving.await;
        }
        let controller = self.controller.take().expect("a daemon");
        until("the stopped daemon to be let go", || async {
            (Arc::strong_count(&controller) == 1).then_some(())
        })
        .await;
        drop(controller);
        self.counted_from = self
            .requested
            .lock()
            .expect("the record is not poisoned")
            .len();
        self.run().await;
    }

    fn controller(&self) -> &Arc<Controller> {
        self.controller.as_ref().expect("a daemon")
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    fn target(&self, session: Option<(SessionId, SessionEpoch)>) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::from(session.map(|(session_id, _)| session_id)),
            session_epoch: Nullable::from(session.map(|(_, epoch)| epoch)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Creates a session with a real worker, and returns it once it is live.
    async fn session(&self) -> SessionCreateResult {
        self.client()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &SessionCreateParams {
                    environment_id: self.environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::some("/bin/sh".to_owned()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some(self.tree.root().display().to_string()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    environment_snapshot: Vec::new(),
                    palette: Nullable::null(),
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("the session is created")
            .to_typed()
            .expect("decodes")
    }

    /// Attaches to a session's terminal as a person at it does, with the input lease. Returns the
    /// attachment, which types.
    async fn attach_typist(&self, created: &SessionCreateResult) -> Typist {
        let session = &created.session;
        let endpoint = self
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let target = self.target(Some((session.session_id, session.session_epoch)));
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let acquired: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the lease is acquired")
            .to_typed()
            .expect("decodes");
        Typist {
            client,
            session_id: session.session_id,
            attachment_id: attached.attachment.attachment_id,
            epoch: acquired.lease.epoch,
            sequence: 0,
        }
    }

    /// Runs the program the package recognises in a session, and returns the attachment that typed
    /// it and the process once it is running. The worker finds the program in the terminal's
    /// foreground and binds the package to it.
    async fn run_agent(&self, created: &SessionCreateResult) -> (Typist, ProcessStartIdentity) {
        self.run_agent_with(created, "").await
    }

    /// [`Self::run_agent`], with `more` among the variables the program is started with.
    async fn run_agent_with(
        &self,
        created: &SessionCreateResult,
        more: &str,
    ) -> (Typist, ProcessStartIdentity) {
        let mut typing = self.attach_typist(created).await;
        let process = self.start_agent(&mut typing, more).await;
        (typing, process)
    }

    /// Types the program the package recognises at an attachment's prompt, and returns its process
    /// once it is running.
    async fn start_agent(&self, typing: &mut Typist, more: &str) -> ProcessStartIdentity {
        let running = self
            .tree
            .root()
            .join(format!("agent-running-{}", kr_ipc::new_uuid()));
        typing
            .send(&format!(
                "{STAND_IN}={} {more} {STAND_IN_RUNNING}='{}' '{}' --exact \
                 the_stand_in_program --test-threads 1 --nocapture\n",
                owner_of(std::process::id()),
                running.display(),
                self.agent.display()
            ))
            .await;
        let pid = until("the program the line started to run", || async {
            std::fs::read_to_string(&running)
                .ok()
                .and_then(|said| said.trim().parse::<u32>().ok())
        })
        .await;
        kr_ipc::identity::process_start_identity(pid).expect("the program runs")
    }

    /// Asks the daemon for the plugin runtime in the name of `session_id`, as this test's own
    /// process, which no session's worker is.
    async fn ask_as_this_process(&self, session_id: SessionId) -> PluginRuntimeState {
        let rendezvous = self
            .environment()
            .rendezvous_endpoint()
            .expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&rendezvous)
            .await
            .expect("connects to the rendezvous endpoint");
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Worker,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .expect("the hello is written");
        let acknowledged: ControlFrame = reader.read_message().await.expect("acknowledged");
        assert!(matches!(acknowledged, ControlFrame::HelloAck(_)));
        writer
            .write_message(&ControlFrame::PluginRuntimeWanted(PluginRuntimeWanted {
                session_id,
            }))
            .await
            .expect("the request is written");
        let answer: ControlFrame = reader.read_message().await.expect("answered");
        let ControlFrame::PluginRuntimeState(state) = answer else {
            panic!("the daemon answered {answer:?}");
        };
        state
    }

    /// Asks the daemon one question about a draft in the name of `session_id`, as this test's own
    /// process, which no session's worker is.
    async fn ask_about_a_draft_as_this_process(
        &self,
        session_id: SessionId,
        step: kr_protocol::insertion::DraftStep,
    ) -> kr_protocol::insertion::DraftAnswer {
        let rendezvous = self
            .environment()
            .rendezvous_endpoint()
            .expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&rendezvous)
            .await
            .expect("connects to the rendezvous endpoint");
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Worker,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .expect("the hello is written");
        let acknowledged: ControlFrame = reader.read_message().await.expect("acknowledged");
        assert!(matches!(acknowledged, ControlFrame::HelloAck(_)));
        writer
            .write_message(&ControlFrame::DraftWanted(Box::new(
                kr_protocol::insertion::DraftWanted {
                    session_id,
                    actor_id: kr_protocol::ids::ActorId::new(format!(
                        "local:{}",
                        kr_ipc::paths::current_uid()
                    ))
                    .expect("a principal"),
                    step,
                },
            )))
            .await
            .expect("the question is written");
        let answer: ControlFrame = reader.read_message().await.expect("answered");
        let ControlFrame::DraftAnswer(answer) = answer else {
            panic!("the daemon answered {answer:?}");
        };
        *answer
    }

    /// What the daemon was asked to start, in order.
    fn requested(&self) -> Vec<Requested> {
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .skip(self.counted_from)
            .map(|(what, _)| what.clone())
            .collect()
    }

    /// The services the daemon was asked to start.
    fn services(&self) -> Vec<String> {
        self.requested()
            .into_iter()
            .filter_map(|what| match what {
                Requested::Service(label) => Some(label),
                Requested::Worker(_) => None,
            })
            .collect()
    }

    /// The process identity the descriptor names, where a plugin runtime is published.
    fn published_host(&self) -> Option<ProcessStartIdentity> {
        launcher::read_descriptor(&self.environment(), &HostProtocol::THIS)
            .ok()
            .flatten()
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// Waits until the daemon has published a plugin runtime that answers a health call and whose
    /// process is running, and returns that process.
    ///
    /// The launcher publishes the descriptor a moment before it accepts the runtime's claim, and a
    /// runtime serves only once its claim is accepted, so an answer shows that its start is
    /// complete. One connection settles which process answered: the process returned is the one
    /// whose descriptor that connection verified, so a runtime that ended and was replaced
    /// meanwhile is not taken for the one that answered. No binding needs to be registered for it.
    async fn running_published_host(&self) -> ProcessStartIdentity {
        until(
            "the daemon to publish a plugin runtime that answers",
            || async {
                let client = PluginClient::connect(&self.environment()).await.ok()?;
                client.health().await.ok()?;
                let host = client.descriptor().process_start_identity.clone();
                (kr_ipc::identity::process_state(&host) == ProcessState::Running).then_some(host)
            },
        )
        .await
    }

    /// What the plugin runtime says it holds, asked as a connection of this test's own, which the
    /// runtime counts across every connection in its `live_bindings`.
    async fn health(&self) -> Option<HostHealth> {
        let client = PluginClient::connect(&self.environment()).await.ok()?;
        client.health().await.ok()
    }

    /// Waits until the plugin runtime holds `bindings` bindings, and returns what it reports. For a
    /// count that is already held or that falls; a count that rises needs a registration, and
    /// [`Self::registering`] waits for that.
    async fn holding(&self, bindings: u64) -> HostHealth {
        self.holding_within(PATIENCE, bindings).await
    }

    /// As [`Self::holding`], for a count that rises because a binding is registered, which a machine
    /// that other work keeps busy delays for as long as [`REGISTRATION_PATIENCE`].
    async fn registering(&self, bindings: u64) -> HostHealth {
        self.holding_within(REGISTRATION_PATIENCE, bindings).await
    }

    async fn holding_within(&self, patience: Duration, bindings: u64) -> HostHealth {
        until_within(
            patience,
            "the plugin runtime to hold the bindings",
            || async {
                self.health()
                    .await
                    .filter(|health| health.live_bindings == bindings)
            },
        )
        .await
    }

    /// Where each worker's last report says a binding's component stands, after every worker has
    /// been asked again.
    async fn components(&self) -> Vec<(ComponentState, Option<String>)> {
        self.reported()
            .await
            .into_iter()
            .map(|(_, report)| (report.state, report.reason.0))
            .collect()
    }

    /// Every binding whose package ships a component, as the workers report it after each has
    /// been asked again, or nothing when the controller could not count a current report from
    /// every worker and the reports are the last ones accepted.
    async fn reported_fresh(
        &self,
    ) -> Option<
        Vec<(
            kr_protocol::ids::BrokerBindingId,
            kr_protocol::admission::ComponentReport,
        )>,
    > {
        let look = self.looked().await;
        look.counted.then_some(look.reports)
    }

    /// Every binding whose package ships a component, as the workers last reported it after each
    /// has been asked again.
    async fn reported(
        &self,
    ) -> Vec<(
        kr_protocol::ids::BrokerBindingId,
        kr_protocol::admission::ComponentReport,
    )> {
        self.looked().await.reports
    }

    /// The workers' reports after each has been asked again, and whether the controller counted a
    /// current one from every worker.
    async fn looked(&self) -> Look {
        let controller = self.controller();
        let counted = controller.refresh_admissions().await;
        let reports = controller
            .reported_components()
            .into_iter()
            .map(|(_, binding_id, report)| (binding_id, report))
            .collect();
        Look { reports, counted }
    }

    /// How things stand with the workers' rounds at the end of a wait that ran out, for telling a
    /// worker that did not answer from a view the controller did not refresh: how many of the
    /// workers that gave reports have a round that has not ended, and what the catalogue noted.
    /// It is not a proof of either, since a round that timed out is no longer out, and it is asked
    /// once, when the wait has run out, because the catalogue's notes can take up to five seconds
    /// to read.
    async fn rounds_in_words(&self) -> String {
        let controller = self.controller();
        let mut workers = Vec::new();
        for (session_id, _, _) in controller.reported_components() {
            if !workers.contains(&session_id) {
                workers.push(session_id);
            }
        }
        let out = workers
            .iter()
            .filter(|worker| controller.admission_round_out(**worker))
            .count();
        let notes = controller.catalogue_warnings().await;
        format!(
            "; when the wait ran out, {out} of {} workers had a round that had not ended; the \
             catalogue's notes: {}",
            workers.len(),
            if notes.is_empty() {
                "none".to_owned()
            } else {
                notes.join(" | ")
            }
        )
    }

    /// The worker of a session, as the daemon's registry records it, for a daemon this test does
    /// not run in its own process.
    fn worker_in_registry(&self, session_id: SessionId) -> ProcessStartIdentity {
        kr_ipc::descriptor::read_all(&self.environment())
            .expect("the worker descriptors are readable")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the worker published its descriptor")
            .process_start_identity
    }

    /// The worker the daemon started for a session, as the supervisor reported it.
    fn worker_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .find_map(|(what, process)| match what {
                Requested::Worker(started) if *started == session_id => process.clone(),
                _ => None,
            })
            .expect("the supervisor reported the worker's process")
    }

    /// Attaches to a session's terminal and subscribes to its output.
    async fn observe(&self, created: &SessionCreateResult) -> LocalClient {
        let session = &created.session;
        let endpoint = self
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(Some((session.session_id, session.session_epoch))),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let mut streams = kr_protocol::scalars::CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the subscription succeeds");
        client
    }

    /// Waits until every binding the workers report has its component in `state`, and there are
    /// `count` of them. A component becomes registered after a registration, which a busy machine
    /// delays for as long as [`REGISTRATION_PATIENCE`].
    async fn components_are(
        &self,
        count: usize,
        state: ComponentState,
    ) -> Vec<(ComponentState, Option<String>)> {
        let patience = if state == ComponentState::Registered {
            REGISTRATION_PATIENCE
        } else {
            PATIENCE
        };
        until_within(patience, "the workers to report the components", || async {
            let found = self.components().await;
            (found.len() == count && found.iter().all(|(reported, _)| *reported == state))
                .then_some(found)
        })
        .await
    }
}

/// Enrols the generation as the owner acting directly, synchronises it, and installs and enables
/// its package, before any daemon opens the catalogue.
async fn install(tree: &teardown::Tree, generation: &generations::Generation) {
    let environment = tree.environment();
    let published = generation.directory();
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&published.join("metadata")),
                directory_url(&published.join("targets")),
                std::fs::read(published.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&plugin(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            tree.environment_id(),
            &plugin(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(tree.environment_id(), &plugin(), true)
        .await
        .expect("enabled");
}

/// KR-REQ-05.06 and KR-REQ-05.08: the plugin runtime is started by the daemon when a worker first
/// wants a component, and not before.
///
/// A session that runs nothing a package recognises, with the package installed and enabled and its
/// component admitted, leaves the supervisor asked for the worker and for nothing else, publishes no
/// runtime and has nothing listening for one. The first program the package recognises is what
/// starts it, as a job of its own beside the worker's, and the next session's binding is given the
/// same process rather than a second.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_runtime_starts_with_the_first_binding_that_wants_a_component_and_not_before() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let environment = world.environment();

    // The daemon has started, seeded nothing and been asked for nothing.
    assert!(world.published_host().is_none());
    assert!(world.services().is_empty());

    // A session with a worker and a shell, and a round of admissions answered by that worker: the
    // package is admitted to it, and nothing in it wants a component.
    let first = world.session().await;
    world.controller().refresh_admissions().await;
    assert_eq!(
        world.requested(),
        [Requested::Worker(first.session.session_id)],
        "the daemon was asked for the worker and nothing else"
    );
    assert!(world.published_host().is_none());
    assert!(
        PluginClient::connect(&environment).await.is_err(),
        "nothing is listening for a plugin runtime"
    );
    assert!(world.components().await.is_empty());

    // The program the package recognises runs, and its binding wants the component.
    let (_typing, _agent) = world.run_agent(&first).await;
    let health = world.registering(1).await;
    assert!(health.deadlines_enforceable);
    let services = world.services();
    assert_eq!(services.len(), 1, "{services:?}");
    assert!(services[0].starts_with("kr-plugin-host-"), "{services:?}");
    let host = world.published_host().expect("the runtime is published");
    world.components_are(1, ComponentState::Registered).await;

    // And it is a job of its own: the process the daemon's supervisor started is not in this
    // process's group, so a signal aimed at this process's group does not reach it. (Where the
    // platform has no service manager it is this process's child, in a group of its own.)
    assert_ne!(
        process_group(u32::try_from(host.pid.get()).expect("a pid")),
        process_group(std::process::id())
    );

    // A second session's binding is given the process that is running.
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.registering(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.services(), services, "no second runtime was started");
    assert_eq!(world.published_host(), Some(host));
}

/// Only the process the daemon recorded for a session can have the plugin runtime started for it.
///
/// Starting the runtime gives a requester no authority over anything, but it spends the daemon's
/// allowance of starts, so another process of the same user does not get to. This test's own
/// process asks in the name of a live session and of one nobody recorded, and is refused each time
/// with the reason and told when to ask again; nothing is started. The worker of the first session
/// is the control: it asks through the same endpoint in every other test here and is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_process_that_is_not_a_sessions_worker_cannot_have_the_plugin_runtime_started() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;

    for (session_id, why) in [
        (
            created.session.session_id,
            "is not the worker this daemon recorded",
        ),
        (
            SessionId::new(kr_ipc::new_uuid()),
            "has not recorded that session's worker",
        ),
    ] {
        let PluginRuntimeState::Unavailable(told) = world.ask_as_this_process(session_id).await
        else {
            panic!("a process that is not the session's worker was told the runtime is running");
        };
        assert!(told.reason.contains(why), "{}", told.reason);
        assert!(told.retry_after_ms.get() > 0);
    }
    assert!(world.services().is_empty());
    assert!(world.published_host().is_none());
}

/// Only the process the daemon recorded for a session reads, claims or settles what its drafts
/// hold. This test's own process, which no session's worker is, asks in the name of a live session
/// and of one nobody recorded, for each of the three questions, and is refused each time; the
/// draft is as it was, and the refusal for a worker the daemon has not recorded yet tells it to ask
/// again while the refusal for another process does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_process_that_is_not_a_sessions_worker_reads_claims_and_settles_nothing_of_its_drafts() {
    use kr_protocol::error::{ErrorCode, RetryCategory};
    use kr_protocol::insertion::{
        DraftAnswer, DraftStep, InsertionBegin, InsertionReport, ReportedOutcome,
    };
    use kr_protocol::scalars::U64;

    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;
    let session_id = created.session.session_id;
    let draft = {
        let service = world.controller().transfer().service();
        let actor =
            kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
                .expect("a principal");
        service
            .draft_create(
                &actor,
                &kr_protocol::transfer::DraftCreateParams {
                    environment_id: world.environment_id,
                    device_id: Nullable::null(),
                    session_id: Nullable::some(session_id),
                    application_instance_id: Nullable::null(),
                    text: "a draft".to_owned(),
                },
                None,
                None,
            )
            .expect("creates the draft")
            .draft
    };
    let transfer_id = kr_protocol::ids::TransferId::new(kr_ipc::new_uuid());
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let begin = InsertionBegin {
        action_id,
        draft_id: draft.draft_id,
        transfer_id,
        attempt: U64::new(0),
        max_count: U64::new(4),
        deadline_boot_ms: U64::new(u64::MAX),
    };
    let steps = [
        DraftStep::Facts {
            draft_id: draft.draft_id,
        },
        DraftStep::Begin(begin.clone()),
        DraftStep::Report(InsertionReport {
            action_id,
            draft_id: draft.draft_id,
            transfer_id,
            attempt: U64::new(0),
            outcome: ReportedOutcome::Failed {
                detail: "not mine to say".to_owned(),
            },
        }),
    ];
    for (session, code, retry) in [
        (
            session_id,
            ErrorCode::PermissionDenied,
            RetryCategory::ConfigurationChange,
        ),
        (
            SessionId::new(kr_ipc::new_uuid()),
            ErrorCode::ResourceUnavailable,
            RetryCategory::Transient,
        ),
    ] {
        for step in &steps {
            let answer = world
                .ask_about_a_draft_as_this_process(session, step.clone())
                .await;
            let DraftAnswer::Refused(error) = answer else {
                panic!("a process that is not the session's worker was answered: {answer:?}");
            };
            assert_eq!(error.code, code, "{error:?}");
            assert_eq!(error.retry, retry, "{error:?}");
        }
    }
    let unchanged = world
        .controller()
        .transfer()
        .service()
        .draft(
            &kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
                .expect("a principal"),
            draft.draft_id,
        )
        .expect("reads the draft");
    assert_eq!(unchanged, draft, "the refusals changed nothing");
}

/// The group a process is in, as the operating system reports it.
fn process_group(pid: u32) -> u32 {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .expect("lists the process");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a group")
}

/// How many updates of the screen a terminal has been sent, counted as they arrive.
///
/// The program the test runs prints a numbered line every moment, so the screen changes all the
/// time and every change is sent to an attached terminal. Counted all the time and not in windows:
/// a terminal that nobody reads for a while is resynchronised, and what a test then reads is the
/// resynchronisation. It stops reading when it is dropped.
struct Traffic {
    sent: Arc<std::sync::atomic::AtomicU64>,
    reading: tokio::task::JoinHandle<()>,
}

impl Traffic {
    fn watch(mut client: LocalClient) -> Self {
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = Arc::clone(&sent);
        let reading = tokio::spawn(async move {
            while let Ok(frame) = client.recv().await {
                if let kr_protocol::envelope::ControlFrame::Notification(notification) = frame
                    && notification
                        .event_type
                        .as_str()
                        .starts_with("session.projection.")
                {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        Self { sent, reading }
    }

    /// How many updates have arrived so far.
    fn count(&self) -> u64 {
        self.sent.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Traffic {
    fn drop(&mut self) {
        self.reading.abort();
    }
}

/// KR-REQ-05.07: a plugin runtime that ends with a registration unanswered takes no worker with it,
/// and its bindings come back.
///
/// A worker is running a program the package recognises, whose terminal changes every moment, in
/// the background of its session, and its binding is registered on the worker's connection to the
/// runtime. The runtime is stopped, which is what a runtime is that has hung: it is running and
/// answers nothing. A second program the package recognises is run in the same session; the worker
/// binds it and sends its registration on the connection it has, and that request is left
/// unanswered, which shows as the binding's report: pending, registering with the plugin runtime.
/// The runtime is then killed by the identity it was started under while that request is
/// outstanding. The worker and both programs go on, the terminal goes on being sent what it had not
/// been sent, both bindings are the same bindings, and the daemon starts a replacement under its
/// bound, which the worker registers both with again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_that_ends_with_a_registration_unanswered_takes_no_worker_with_it_and_its_bindings_come_back()
 {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;
    let traffic = Traffic::watch(world.observe(&created).await);
    let (mut typing, first_agent) = world
        .run_agent_with(&created, &format!("{STAND_IN_TICKS}=1"))
        .await;
    world.registering(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let first_binding = world.reported().await[0].0;
    let host = world.published_host().expect("the runtime is published");

    // The first program goes to the background of the session, still printing, and the runtime
    // hangs. The second program is run at the prompt it leaves.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    stop(&host);
    let second_agent = world.start_agent(&mut typing, "").await;

    // The worker has bound it and sent the registration, and nothing answers it.
    let registering = |report: &kr_protocol::admission::ComponentReport| {
        report.state == ComponentState::Pending
            && report.reason.0.as_deref() == Some("registering with the plugin runtime")
    };
    let second_binding = until_found(
        PATIENCE,
        "the second binding's registration to be sent and left unanswered",
        || async {
            let look = world.looked().await;
            match look
                .reports
                .iter()
                .find(|(binding, report)| *binding != first_binding && registering(report))
            {
                Some((binding, _)) => Ok(*binding),
                None => Err(reports_in_words(
                    &look.reports,
                    first_binding,
                    counting_in_words(look.counted),
                )),
            }
        },
        || world.rounds_in_words(),
    )
    .await;

    // The terminal goes on being sent updates while that request is unanswered, and the runtime
    // ends in the same look that finds both true: the registration is still outstanding then, and
    // a registration that had run out its limit and been sent again would not satisfy it.
    let sent = traffic.count();
    until(
        "the terminal to be sent updates while the registration is unanswered",
        || async {
            // A look the worker answered after it was asked, and not the last one accepted.
            let outstanding = world
                .reported_fresh()
                .await?
                .iter()
                .any(|(binding, report)| *binding == second_binding && registering(report));
            (outstanding && traffic.count() > sent + 20).then_some(())
        },
    )
    .await;
    kill(&host);
    ended(&host).await;

    // A replacement is the daemon's doing, on the worker's asking: a process that is not the first,
    // and the same two bindings registered with it.
    until("a replacement runtime to be published", || async {
        world
            .published_host()
            .filter(|published| *published != host)
    })
    .await;
    world.registering(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.services().len(), 2, "{:?}", world.services());
    let bindings: Vec<_> = world
        .reported()
        .await
        .into_iter()
        .map(|(binding, _)| binding)
        .collect();
    assert!(bindings.contains(&first_binding) && bindings.contains(&second_binding));

    // And nothing else went with it: the worker, the programs, and the terminal, which is sent
    // updates it had not been sent before the runtime ended.
    assert_eq!(
        kr_ipc::identity::process_state(&world.worker_of(created.session.session_id)),
        ProcessState::Running
    );
    for agent in [&first_agent, &second_agent] {
        assert_eq!(
            kr_ipc::identity::process_state(agent),
            ProcessState::Running
        );
    }
    let after_the_end = traffic.count();
    until("the terminal to be sent updates after the end", || async {
        Some(traffic.count()).filter(|count| *count > after_the_end + 20)
    })
    .await;
}

/// KR-REQ-05.07: a plugin runtime that keeps ending is not started without end, and the workers
/// are told why.
///
/// The daemon starts at most five in ten minutes. The runtime is killed each time it is published;
/// after the fifth start the next request is answered that the runtime cannot be reached, and the
/// binding's component is reported unavailable with that reason. A program run after that, while
/// the worker holds off for the time the daemon named, has its binding told the same reason as soon
/// as it is made, and not left pending.
///
/// The case waits for no registration, and the window the starts are counted in is held where it is
/// when the daemon starts, so no start leaves it however long a machine that other work keeps busy
/// takes over the others: what the case decides by is how many starts were made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_that_keeps_ending_is_started_five_times_and_the_binding_is_told_why() {
    let Some(component) = well_behaved() else {
        return;
    };
    let attempts = kr_controller::service::plugin_runtime::START_ATTEMPTS;
    let world = World::start(&component).await;
    world.controller().hold_plugin_start_window();
    let created = world.session().await;
    let (mut typing, agent) = world.run_agent(&created).await;

    let mut previous = None;
    for _ in 0..attempts {
        let host = until("a runtime to be published", || async {
            world
                .published_host()
                .filter(|published| Some(published) != previous.as_ref())
        })
        .await;
        kill(&host);
        ended(&host).await;
        previous = Some(host);
    }

    // The sixth is not started: the worker's binding says so.
    let reported = until(
        "the binding to be told the runtime is not started again",
        || async {
            world
                .components()
                .await
                .into_iter()
                .find(|(state, reason)| {
                    *state == ComponentState::Unavailable
                        && reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("not started again"))
                })
        },
    )
    .await;
    assert_eq!(reported.0, ComponentState::Unavailable);
    assert_eq!(world.services().len(), attempts);

    // A program run after that, while the worker holds off for the time the daemon named, is told
    // why its component is not registered as soon as it is bound, and not left pending.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    let _second_agent = world.start_agent(&mut typing, "").await;
    until("both bindings to be told why", || async {
        let found = world.components().await;
        (found.len() == 2
            && found.iter().all(|(state, reason)| {
                *state == ComponentState::Unavailable
                    && reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("not started again"))
            }))
        .then_some(())
    })
    .await;
    assert_eq!(world.services().len(), attempts);
    // And that cost the worker and its program nothing.
    assert_eq!(
        kr_ipc::identity::process_state(&world.worker_of(created.session.session_id)),
        ProcessState::Running
    );
    assert_eq!(
        kr_ipc::identity::process_state(&agent),
        ProcessState::Running
    );
}

/// KR-REQ-05.06: a daemon that restarts finds the plugin runtime where it was, and keeps it.
///
/// The runtime is a job of its own, so the daemon that started it can go. The workers hold their
/// connections to it directly, so their bindings are not interrupted, and a binding made after the
/// restart is given the same process: the new daemon looks for the runtime its predecessor
/// published, finds it answering, and starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_daemon_that_restarts_adopts_the_plugin_runtime_it_finds_and_starts_none() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start(&component).await;
    let first = world.session().await;
    let (_typing, _agent) = world.run_agent(&first).await;
    world.registering(1).await;
    let host = world.published_host().expect("the runtime is published");

    world.restart().await;

    // The first binding stayed registered through the restart, with no daemon to ask.
    assert_eq!(world.published_host(), Some(host.clone()));
    world.holding(1).await;
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.registering(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.published_host(), Some(host));
    assert!(
        world.services().is_empty(),
        "the restarted daemon was asked to start {:?}",
        world.services()
    );
}

/// A binding that ends frees its place in the plugin runtime, and only its own.
///
/// One worker holds two bindings, which is two programs the package recognises in one session: the
/// first is put in the background and the second run in front of it. The first exits. The runtime
/// holds one binding then, the second's, which is still the same binding and still registered. A
/// session that has run its program and finished does not keep an instance of its component, which
/// a connection could otherwise be made to hold sixty-four of. What this does not show is that the
/// worker's connection to the runtime stayed the same one: the host reports no connections, and a
/// link that closed its connection and registered the other binding again would pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_binding_that_ends_is_unbound_in_the_plugin_runtime_and_the_other_is_left_registered() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;
    let (mut typing, first_agent) = world.run_agent(&created).await;
    world.registering(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let first_binding = world.reported().await[0].0;

    // The first program is stopped from the terminal and continued in the background, and the
    // second is run at the prompt it leaves.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    let _second_agent = world.start_agent(&mut typing, "").await;
    world.registering(2).await;
    world.components_are(2, ComponentState::Registered).await;
    let second_binding = world
        .reported()
        .await
        .into_iter()
        .map(|(binding, _)| binding)
        .find(|binding| *binding != first_binding)
        .expect("a second binding");

    kill(&first_agent);
    ended(&first_agent).await;

    world.holding(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let surviving = world.reported().await;
    assert_eq!(surviving.len(), 1);
    assert_eq!(
        surviving[0].0, second_binding,
        "the binding that is left is the one whose program is still running"
    );
}

/// Where the daemon half finds the tree it serves.
const DAEMON_ROOT: &str = "KR_RUNTIME_DAEMON_ROOT";

/// The worker executable the daemon half starts.
const DAEMON_WORKER: &str = "KR_RUNTIME_DAEMON_WORKER";

/// How the daemon half starts a service that is not a worker: `job` through the platform's own
/// service manager, as the product does, or `child` as an ordinary child of the daemon.
const DAEMON_SERVICES: &str = "KR_RUNTIME_DAEMON_SERVICES";

/// The name of the daemon half, as the test harness selects it.
const DAEMON_HALF: &str = "serve_a_control_daemon_for_the_runtime_test";

/// The daemon half: serves a control daemon for the tree `KR_RUNTIME_DAEMON_ROOT` names until it is
/// killed. It does nothing at all unless a test started it.
#[test]
#[ignore = "the daemon half of the kill-tree test, run only as that test's own child process"]
fn serve_a_control_daemon_for_the_runtime_test() {
    let (Some(root), Some(worker)) = (
        std::env::var_os(DAEMON_ROOT),
        std::env::var_os(DAEMON_WORKER),
    ) else {
        return;
    };
    let services = std::env::var(DAEMON_SERVICES).unwrap_or_default();
    let root = PathBuf::from(root);
    let worker = PathBuf::from(worker);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            let paths = kr_ipc::paths::HostPaths::new(root.join("r"), root.join("s"))
                .expect("the host's roots");
            let environment_id = paths.open_environment_id().expect("the environment");
            let environment = paths.environment(environment_id);
            // A killed daemon's environment lock goes with its process; the start waits for the
            // kernel to let go of it, which is a liveness condition, not a measurement.
            let controller = kr_controller::testing::taken_over(|| {
                let secrets = environment.secrets_dir();
                Controller::start(ControllerSetup {
                    paths: environment.clone(),
                    environment_id,
                    identity: Box::new(move || {
                        let store = open_store_in(&secrets).expect("a secret store");
                        Ok(
                            ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                                .expect("an identity"),
                        )
                    }),
                    secret_store: StoreSelection::File,
                    boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                    supervisor: if services == "child" {
                        Box::new(AsChild {
                            inner: detect(&environment, &worker),
                        })
                    } else {
                        detect(&environment, &worker)
                    },
                    worker_program: worker.clone(),
                    build_id: build(),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                })
            })
            .await
            .unwrap_or_else(|error| panic!("the daemon did not start: {error}"));
            let rendezvous =
                Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                    .expect("binds the rendezvous");
            let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
                .expect("binds the client endpoint");
            let serving = tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
            let _ = Arc::clone(&controller).serve_clients(clients).await;
            let _ = serving.await;
        });
}

/// A supervisor that starts a worker as the platform does and a service as an ordinary child of
/// the daemon, in the daemon's own process group: what a plugin runtime would be if the daemon did
/// not start it as a job of its own. The control for the kill-tree test.
#[derive(Debug)]
struct AsChild {
    inner: Box<dyn WorkerSupervisor>,
}

impl WorkerSupervisor for AsChild {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.inner.start(launch)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        match std::process::Command::new(&launch.program)
            .args(&launch.arguments)
            .current_dir(&launch.working_directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => kr_controller::supervision::settle(child.id()),
            Err(error) => LaunchOutcome::NotStarted {
                detail: error.to_string(),
            },
        }
    }

    fn describe(&self) -> &'static str {
        "the platform's supervisor for a worker, and a child of the daemon for a service"
    }
}

/// KR-REQ-05.06: the plugin runtime is a job of its own, outside the daemon's kill tree.
///
/// The daemon is a process of its own in a group of its own, and a worker's binding is registered
/// with the runtime the daemon started. Everything in the daemon's group is killed, as it is when
/// what holds a daemon ends it. The runtime, the worker and the registration are as they were, and
/// a new daemon finds the runtime and is not asked to start another for the next binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_runtime_is_a_job_of_its_own_and_outlives_the_daemon_that_started_it() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start_apart(&component, "job").await;
    let first = world.session().await;
    let (_typing, _agent) = world.run_agent(&first).await;
    world.registering(1).await;
    let host = world.published_host().expect("the runtime is published");
    let worker = world.worker_in_registry(first.session.session_id);

    world.apart.end_with_its_group();

    // Nothing of the daemon's group was the runtime, the worker, or the worker's registration.
    assert_eq!(
        kr_ipc::identity::process_state(&host),
        ProcessState::Running
    );
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        ProcessState::Running
    );
    world.holding(1).await;

    // A new daemon is asked for a runtime by the next binding, and the one that is running is the
    // one it finds.
    world.spawn_daemon("job").await;
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.registering(2).await;
    assert_eq!(world.published_host(), Some(host));
}

/// The control for the test above: a plugin runtime that is an ordinary child of the daemon ends
/// with the daemon's group. If this did not end it, the test above would show nothing.
///
/// The runtime is started because a worker's binding holds a package that ships a component, and
/// the case goes on once the daemon has published it and it answers. It does not wait for the
/// binding to be registered: a registration compiles the component on a thread the runtime asks
/// the platform to hold at the lowest priority. The runtime of this case is an ordinary child of
/// the daemon, so it runs where the test is held, beside whatever else runs there, and a machine
/// that gives a lowest-priority thread next to nothing delays the registration by tens of minutes.
/// That the runtime ends with the daemon's group does not depend on the registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_started_as_a_child_of_the_daemon_ends_with_the_daemons_group() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start_apart(&component, "child").await;
    let created = world.session().await;
    let (_typing, _agent) = world.run_agent(&created).await;
    let host = world.running_published_host().await;

    world.apart.end_with_its_group();

    ended(&host).await;
}
