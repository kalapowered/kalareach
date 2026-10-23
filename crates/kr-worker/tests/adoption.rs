//! Adoption, and the session's announcement of its agent instances.
//!
//! In most cases this test process plays the root shell. The program adoption finds is this test
//! binary, placed as `claude` and started with the one case below that only sleeps, as this
//! process's own child in a process group of its own, as a shell with job control starts a
//! foreground job. It is a copy of this binary rather than of a system program, because macOS stops
//! a copy of a system program from running, and a link to one would run under the system program's
//! own name. The watch's own cases run a session whose root shell is a POSIX shell with job
//! control, which starts the same program as a foreground job when a line is typed into it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a program the root shell ran that the integration did not launch is adopted as a native terminal instance with no process record, its process placing the questions it asks and admitting no bridge, with the bypass its line was answered with, its bridges refused, and ended when it exits; a program the integration launched is not adopted; a view that installs the session's list and applies the announcements after it holds each instance once; the watch finds a program the root shell starts from a typed line within two seconds of it running, at once or after four silent seconds, and its end within two seconds of its exit, and looks when the integration asks about an invocation or reports a command starting |
//! | KR-REQ-11.13 | an adopted program is bound in the same step to the admitted package that recognises it, for the program found running, and the binding ends with it; a program two packages recognise equally well is adopted by neither, and the one left is selected; a package with no connector table adopts and binds what it recognises |
//! | KR-REQ-12.24 | a package of another publisher does not take a program from a shipped package by naming it, by a rule that declares itself exact or by one that names a location |
//! | KR-PERF-003 | a session nothing is happening in reads its terminal's foreground on no more than one interval in four, less often the longer it stays quiet, before and after its own traffic, and after an adopted program has ended |

#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kr_plugin_sdk::matching::MatchConfidence;
use kr_protocol::broker::IntegrationMode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, SessionId};
use kr_protocol::projection::{AgentInstanceEvent, AgentInstanceSummary};
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::Broker;
use kr_worker::broker::adoption::{ADOPTED_REFUSAL, Adoptions, Foreground};
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{ConnectorSource, ConnectorSources, fixture};
use kr_worker::broker::process::{BrokerTransport, Credential, ManagedProcess, TransportHandle};
use kr_worker::persistence::JournalHealth;

/// The variable that makes a placed copy of this binary the stand-in program: it sleeps for as
/// many seconds as it names.
const STAND_IN: &str = "KR_ADOPTION_STAND_IN";

/// The variable that names a file the stand-in writes to once it is running: its process
/// identifier, and when it started on [`monotonic`], for a test that measures from that moment.
const STAND_IN_RUNNING: &str = "KR_ADOPTION_STAND_IN_RUNNING";

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            let started = monotonic().as_nanos();
            std::fs::write(running, format!("{} {started}", std::process::id()))
                .expect("says it is running");
        }
        std::thread::sleep(Duration::from_secs(seconds.parse().unwrap_or(60)));
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// A host tree with packages admitted, the stand-in placed under the name they recognise, and one
/// session's adoptions on a broker of its own.
struct Setup {
    host: kr_ipc::testing::TempHost,
    broker: Arc<Broker>,
    adoptions: Adoptions,
    program: PathBuf,
    /// The first package admitted.
    plugin_id: kr_protocol::ids::PluginId,
    /// Every package admitted, in the order it was written.
    packages: Vec<ConnectorSource>,
    admissions: Admissions,
    sources: ConnectorSources,
}

impl Setup {
    /// The Claude Code connector admitted, and the stand-in placed as `claude`.
    fn new() -> Self {
        Self::with(fixture::COMMAND, |store, bin| {
            vec![fixture::claude_code_package(store, &bin.join("kr-hook")).expect("the package")]
        })
    }

    /// The packages `packages` writes in the store admitted, and the stand-in placed as `name`.
    fn with(name: &str, packages: impl FnOnce(&Path, &Path) -> Vec<ConnectorSource>) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let bin = host.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        let program = bin.join(name);
        kr_ipc::testing::place_program(
            &std::env::current_exe().expect("this test's own binary"),
            &program,
        );
        let store = host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let packages = packages(&store, &bin);
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let admitted: Vec<_> = packages.iter().map(testing::admitted).collect();
        let plugin_id = admitted[0].plugin_id.clone();
        // The packages are admitted, as the control daemon hands them over.
        let _ = testing::admit(&admissions, &sources, &broker, admitted, 1);
        let adoptions = Adoptions::new(Arc::clone(&broker), host.environment_id());
        Self {
            host,
            broker,
            adoptions,
            program,
            plugin_id,
            packages,
            admissions,
            sources,
        }
    }

    /// Hands over the next snapshot, at `round`, admitting the packages `admitted` names by
    /// their place in [`Setup::packages`].
    fn admit_only(&self, round: u64, admitted: &[usize]) {
        let _ = testing::admit(
            &self.admissions,
            &self.sources,
            &self.broker,
            admitted
                .iter()
                .map(|index| testing::admitted(&self.packages[*index]))
                .collect(),
            round,
        );
    }

    /// The package one adopted instance is bound to, where it is bound.
    fn bound_to(&self, instance: ApplicationInstanceId) -> Option<Digest256> {
        self.broker
            .live_bindings()
            .into_iter()
            .find(|live| live.application_instance_id == instance)
            .map(|live| live.release.package_digest)
    }

    /// Starts the stand-in as this process's own child, in a process group of its own.
    fn start(&self) -> Started {
        self.start_telling(None)
    }

    /// The same, the stand-in writing to `running` once it runs.
    fn start_telling(&self, running: Option<&Path>) -> Started {
        let mut command = Command::new(&self.program);
        command
            .args(["--exact", "the_stand_in_program", "--test-threads", "1"])
            .env(STAND_IN, "60")
            .current_dir(self.host.root());
        if let Some(running) = running {
            command.env(STAND_IN_RUNNING, running);
        }
        self.spawn_in_a_group(command)
    }

    /// Starts `script`, an executable file, as this process's own child in a process group of its
    /// own, as a shell starts a script typed as a command: the system runs it under the interpreter
    /// on its first line, with the script's path as the interpreter's argument.
    fn start_script(&self, script: &Path) -> Started {
        self.spawn_in_a_group(Command::new(script))
    }

    /// Starts `interpreter` given `script` by the relative path it is typed as in the host's
    /// directory, as a shell starts a script typed as `./name`.
    fn start_interpreter(&self, interpreter: &str, script: &str) -> Started {
        let mut command = Command::new(interpreter);
        command.arg(script).current_dir(self.host.root());
        self.spawn_in_a_group(command)
    }

    fn spawn_in_a_group(&self, mut command: Command) -> Started {
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the program starts");
        let process = kr_ipc::identity::process_start_identity(child.id())
            .expect("the program is identified");
        Started { child, process }
    }

    /// What the session would read with the stand-in in the foreground.
    fn foreground(
        started: &Started,
        answered: Vec<(String, Option<CommandBypassReason>)>,
    ) -> Foreground {
        Foreground {
            group: i32::try_from(started.child.id()).expect("a process identifier"),
            root_shell: kr_ipc::identity::current_process_start_identity().expect("this process"),
            answered,
        }
    }

    /// Looks until the stand-in is adopted: a program at a new path can take a while to start.
    fn adopt(&self, foreground: &Foreground) -> Vec<AgentInstanceSummary> {
        let started = std::time::Instant::now();
        loop {
            let told = self.adoptions.look(foreground);
            if !told.is_empty() || started.elapsed() > LIVENESS {
                return told;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The stand-in, running.
struct Started {
    child: Child,
    process: ProcessStartIdentity,
}

impl Started {
    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// KR-REQ-12.07: a program the root shell ran that the integration did not launch is recorded as
/// a native terminal instance with the profile it was observed running, and nothing else: no
/// process record, so nothing a bridge could authenticate against, and an announcement that says
/// its bridges are refused. It is adopted once, and ended when it exits.
#[test]
fn kr_req_12_07_a_program_the_integration_did_not_launch_is_adopted_without_a_launch_record() {
    let setup = Setup::new();
    let started = setup.start();
    let foreground = Setup::foreground(&started, Vec::new());

    let told = setup.adopt(&foreground);
    assert_eq!(told.len(), 1, "the stand-in is adopted: {told:?}");
    let summary = &told[0];
    assert_eq!(summary.mode, IntegrationMode::NativeTerminal);
    assert_eq!(summary.plugin_id.as_ref(), Some(&setup.plugin_id));
    assert!(
        summary.bypass.as_ref().is_none(),
        "its line was not answered"
    );
    assert!(!summary.ended_at.is_present());
    assert_eq!(
        summary.refusal.as_ref().map(String::as_str),
        Some(ADOPTED_REFUSAL)
    );
    let instance = summary.application_instance_id;
    assert_eq!(setup.adoptions.adopted(&started.process), Some(instance));

    assert!(
        !setup.broker.holds_process(&started.process),
        "an adopted program has no process record, so no launch stands behind it"
    );
    let profile = setup
        .broker
        .profile_of(instance)
        .expect("the profile it was observed running");
    assert_eq!(profile.mode, IntegrationMode::NativeTerminal);
    assert_eq!(
        summary.profile_id.as_ref(),
        Some(&profile.profile_id),
        "the announcement names the recorded profile"
    );
    assert!(
        profile.binary.resolved_path.ends_with("/claude"),
        "the kernel's executable: {}",
        profile.binary.resolved_path
    );
    assert_eq!(
        profile.arguments.get(1..),
        Some(
            &[
                "--exact".to_owned(),
                "the_stand_in_program".to_owned(),
                "--test-threads".to_owned(),
                "1".to_owned()
            ][..]
        ),
        "the kernel's argument vector"
    );
    assert!(setup.broker.binding_state(instance).is_ok());
    // KR-REQ-11.13: adopted and bound in one step, to the package that recognised it, for the
    // program it was found running.
    assert_eq!(
        setup.bound_to(instance),
        Some(setup.packages[0].package_digest),
        "the adopted instance is bound to the package that recognised it"
    );
    let bound = setup
        .broker
        .live_bindings()
        .into_iter()
        .find(|live| live.application_instance_id == instance)
        .expect("bound");
    assert_eq!(
        setup
            .broker
            .binding_record(bound.binding_id)
            .and_then(|record| record.executable)
            .map(|executable| executable.path),
        Some(profile.binary.resolved_path.clone())
    );

    // KR-REQ-12.07: its process places the questions it asks, and admits nothing: a channel that
    // says the program started it speaks for no instance.
    use kr_worker::questions::binding::{AgentBinding, AgentBindings as _, AgentPlacement};
    assert_eq!(
        setup.broker.binding_of(&started.process),
        AgentPlacement::Bound(AgentBinding {
            application_instance_id: instance,
            revision: None,
        }),
        "a question the adopted program asks is placed under its instance"
    );
    let process = started.process.clone();
    let connector = setup
        .sources
        .for_command(fixture::COMMAND)
        .expect("the admitted connector");
    let refused = setup
        .broker
        .open_bridge_channel(
            instance,
            &kr_worker::broker::bridge::BridgeProcess {
                identity: kr_protocol::identity::ProcessStartIdentity::new(
                    u64::from(std::process::id()),
                    kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
                    1,
                ),
                starter: Some(started.process.clone()),
                started: None,
            },
            &connector,
            Some(fixture::QUALIFIED_VERSION),
        )
        .expect_err("an adopted program's process admits no bridge");
    assert!(
        matches!(
            refused,
            kr_worker::broker::BrokerError::PermissionDenied { .. }
        ),
        "{refused}"
    );

    assert!(
        setup.adoptions.look(&foreground).is_empty(),
        "a program is adopted once"
    );
    assert!(setup.adoptions.sweep().is_empty(), "it is still running");

    started.end();
    let ended = setup.adoptions.sweep();
    assert_eq!(ended.len(), 1, "its end is announced: {ended:?}");
    assert_eq!(ended[0].application_instance_id, instance);
    assert!(ended[0].ended_at.is_present());
    assert!(
        setup.broker.binding_state(instance).is_err(),
        "the instance ended with its program"
    );
    assert!(
        setup.broker.live_bindings().is_empty(),
        "and its binding with it"
    );
    assert_eq!(
        setup.broker.binding_of(&process),
        AgentPlacement::Unbound,
        "and nothing is placed under an instance that has ended"
    );
}

/// KR-REQ-11.13: a program two admitted packages both recognise equally well is adopted by neither,
/// because the software development kit's rule selects neither and the host does not pick one on
/// their behalf. A rule that declares itself exact recognises a program found running no better
/// than an inferred one does: the worker has not established where the program came from, so a name
/// on disk is a guess whatever the rule declares. With one of the packages no longer admitted, the
/// one left is selected, and the program is adopted and bound to it.
#[test]
fn kr_req_11_13_a_program_two_packages_recognise_equally_well_is_adopted_by_neither() {
    let setup = Setup::with(fixture::COMMAND, |store, bin| {
        vec![
            fixture::claude_code_package(store, &bin.join("kr-hook")).expect("the package"),
            fixture::declarative_package(
                store,
                "claude-one",
                fixture::COMMAND,
                MatchConfidence::Exact,
            )
            .expect("the package"),
            fixture::declarative_package(
                store,
                "claude-two",
                fixture::COMMAND,
                MatchConfidence::Exact,
            )
            .expect("the package"),
        ]
    });
    let running = setup.host.root().join("running");
    let started = setup.start_telling(Some(&running));
    let deadline = std::time::Instant::now() + LIVENESS;
    while !std::fs::read_to_string(&running).is_ok_and(|said| !said.is_empty()) {
        assert!(std::time::Instant::now() < deadline, "the stand-in runs");
        std::thread::sleep(Duration::from_millis(20));
    }
    let foreground = Setup::foreground(&started, Vec::new());

    // Running the program the packages recognise, and looked at for two seconds.
    let looking = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < looking {
        assert!(
            setup.adoptions.look(&foreground).is_empty(),
            "equal matches adopt nothing"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(setup.broker.live_bindings().is_empty());

    setup.admit_only(2, &[1]);
    let told = setup.adopt(&foreground);
    assert_eq!(told.len(), 1, "adopted once one match is left: {told:?}");
    assert_eq!(
        told[0]
            .plugin_id
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("kalareach/claude-one"),
        "the package left is the one selected"
    );
    assert_eq!(
        setup.bound_to(told[0].application_instance_id),
        Some(setup.packages[1].package_digest)
    );
    started.end();
}

/// KR-REQ-12.24, KR-REQ-11.13: a package of another publisher does not take a program from a
/// package the repository ships by naming it. Whether its rule declares itself exact or names an
/// installation location the shipped package's rule does not, the worker finds the two equally good
/// claims on the program and selects neither, so the shipped package keeps the program only by the
/// person's choice and the other publisher's package can cause a conflict and nothing more. With
/// only the shipped package admitted the program is the shipped package's.
#[test]
fn kr_req_12_24_a_package_of_another_publisher_does_not_take_a_program_by_naming_it() {
    let imposter = |store: &Path, name: &str, suffix: serde_json::Value, confidence: &str| {
        fixture::declarative_package_with(store, name, |manifest| {
            manifest["publisher_id"] = serde_json::json!("example-vendor");
            manifest["match_rules"][0]["executable"]["file_stem"] =
                serde_json::json!(fixture::COMMAND);
            manifest["match_rules"][0]["executable"]["path_suffix"] = suffix;
            manifest["match_rules"][0]["distribution"] = serde_json::Value::Null;
            manifest["match_rules"][0]["confidence"] = serde_json::json!(confidence);
        })
        .expect("the package")
    };
    let setup = Setup::with(fixture::COMMAND, |store, bin| {
        vec![
            fixture::claude_code_package(store, &bin.join("kr-hook")).expect("the package"),
            imposter(store, "bold", serde_json::json!([]), "exact"),
            imposter(store, "placed", serde_json::json!(["bin"]), "inferred"),
        ]
    });
    let path = setup.program.display().to_string();
    let selected = |setup: &Setup| {
        setup
            .broker
            .admitted_match(&path)
            .map(|found| found.plugin_id.to_string())
    };
    assert_eq!(selected(&setup), None, "the three packages are in conflict");
    for (round, imposter) in [(2, 1), (3, 2)] {
        setup.admit_only(round, &[0, imposter]);
        assert_eq!(
            selected(&setup),
            None,
            "package {imposter} does not take the program from the shipped package"
        );
    }
    setup.admit_only(4, &[0]);
    assert_eq!(
        selected(&setup).as_deref(),
        Some("kalareach/claude-code"),
        "alone, the shipped package recognises it"
    );
}

/// KR-REQ-12.24: a publisher's name is vouched for by the root of the repository that lists it, and
/// two repositories can list one name. A package published under the name the shipped package has,
/// through another repository, does not take a program from it by naming an installation location,
/// though a package of that name through the same repository does: the second is one publisher's
/// choice between its own products, as the two Kimi profiles are, and the first is a stranger's.
#[test]
fn kr_req_12_24_a_package_under_the_same_publisher_name_in_another_repository_does_not_take_a_program()
 {
    let setup = Setup::with(fixture::COMMAND, |store, bin| {
        vec![
            fixture::claude_code_package(store, &bin.join("kr-hook")).expect("the package"),
            fixture::declarative_package_with(store, "placed", |manifest| {
                manifest["match_rules"][0]["executable"]["file_stem"] =
                    serde_json::json!(fixture::COMMAND);
                manifest["match_rules"][0]["executable"]["path_suffix"] =
                    serde_json::json!(["bin"]);
                manifest["match_rules"][0]["distribution"] = serde_json::Value::Null;
                manifest["match_rules"][0]["confidence"] = serde_json::json!("inferred");
            })
            .expect("the package"),
        ]
    });
    let path = setup.program.display().to_string();
    let selected = |setup: &Setup| {
        setup
            .broker
            .admitted_match(&path)
            .map(|found| found.plugin_id.to_string())
    };
    // Both through the repository the host seeded: one publisher's choice, by location.
    assert_eq!(selected(&setup).as_deref(), Some("kalareach/placed"));

    // The second through a repository of its own: the same name, another root.
    let shipped = testing::admitted(&setup.packages[0]);
    let mut stranger = testing::admitted(&setup.packages[1]);
    stranger.origin.enrolment_key = "another-root".to_owned();
    let _ = testing::admit(
        &setup.admissions,
        &setup.sources,
        &setup.broker,
        vec![shipped, stranger],
        2,
    );
    assert_eq!(
        selected(&setup),
        None,
        "equal claims from two roots bind neither"
    );
}

/// KR-REQ-11.13: a package with no connector table recognises and adopts a program the way a
/// connector does, as a native terminal instance with no registration, and binds it, with no
/// decoding trust.
#[test]
fn kr_req_11_13_a_package_with_no_connector_table_adopts_and_binds_what_it_recognises() {
    let setup = Setup::with("example-agent", |store, _| {
        vec![
            fixture::declarative_package(
                store,
                "example-declarative",
                "example-agent",
                MatchConfidence::Exact,
            )
            .expect("the package"),
        ]
    });
    let started = setup.start();
    let told = setup.adopt(&Setup::foreground(&started, Vec::new()));
    assert_eq!(told.len(), 1, "the stand-in is adopted: {told:?}");
    assert_eq!(told[0].plugin_id.as_ref(), Some(&setup.plugin_id));
    assert_eq!(told[0].mode, IntegrationMode::NativeTerminal);
    let instance = told[0].application_instance_id;
    assert_eq!(
        setup.bound_to(instance),
        Some(setup.packages[0].package_digest),
        "and bound to the package"
    );
    let bound = setup
        .broker
        .live_bindings()
        .into_iter()
        .find(|live| live.application_instance_id == instance)
        .and_then(|live| setup.broker.binding_record(live.binding_id))
        .expect("bound");
    assert!(
        bound.trust.is_none(),
        "a package with no table decodes nothing"
    );
    assert!(bound.connector_digest.is_none());
    started.end();
    assert_eq!(setup.adoptions.sweep().len(), 1, "its end is found");
    assert!(setup.broker.live_bindings().is_empty());
}

/// KR-REQ-12.07: a program the shell ran as typed is adopted with the reason its line was
/// answered with, matched to the file the kernel reports however the shell named it.
#[test]
fn kr_req_12_07_an_adopted_program_carries_the_bypass_its_line_was_answered_with() {
    let setup = Setup::new();
    let started = setup.start();
    let named = setup.host.root().join("named-claude");
    std::os::unix::fs::symlink(&setup.program, &named).expect("the name the shell found");
    let foreground = Setup::foreground(
        &started,
        vec![
            ("/nowhere/claude".to_owned(), None),
            (
                named.display().to_string(),
                Some(CommandBypassReason::AbsolutePath),
            ),
        ],
    );
    let told = setup.adopt(&foreground);
    assert_eq!(told.len(), 1, "the stand-in is adopted: {told:?}");
    assert_eq!(
        told[0].bypass.as_ref(),
        Some(&CommandBypassReason::AbsolutePath)
    );
    started.end();
}

/// KR-REQ-12.07: a program the integration launched is not adopted as well. The launch registered
/// the process that presented itself, and that process keeps its identity when it execs the
/// program, so the broker already holds it.
#[test]
fn kr_req_12_07_a_program_the_integration_launched_is_not_adopted() {
    let setup = Setup::new();
    let started = setup.start();
    let launched = ApplicationInstanceId::new(Uuid::from_bytes([7; 16]));
    setup
        .broker
        .register_instance(
            launched,
            IntegrationMode::NativeBridge,
            None,
            Some(ManagedProcess::new(
                launched,
                started.process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: launched,
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process: started.process.clone(),
                },
                Credential::from_bytes([9; 32]),
                TimestampMs::new(1),
            )),
        )
        .expect("the launch registered its process");
    let foreground = Setup::foreground(&started, Vec::new());

    // Long enough for the program to have started, which an adoption would need.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        assert!(
            setup.adoptions.look(&foreground).is_empty(),
            "a launched program is not adopted"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(setup.adoptions.adopted(&started.process), None);
    started.end();
}

/// A session with one attached view, and that view's own delivery stream.
fn session_and_view(
    host: &kr_ipc::testing::TempHost,
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    open_session(
        host,
        kr_worker::testing::posix_script("exec cat"),
        &[kr_protocol::attachment::AttachmentCapability::ObserveTerminal],
    )
}

/// The view every session in these tests is attached to.
const VIEW: kr_protocol::ids::AttachmentId =
    kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));

/// A session whose root shell runs `shell`, with one view attached with `capabilities`, and that
/// view's own delivery stream.
fn open_session(
    host: &kr_ipc::testing::TempHost,
    shell: kr_worker::pty::ShellCommand,
    capabilities: &[kr_protocol::attachment::AttachmentCapability],
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    for capability in capabilities {
        requested.insert(*capability);
    }
    let config = kr_worker::session::SessionConfig {
        session_id: session(),
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session())),
        spool_directory: Some(host.environment().session_spool(session())),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut opened = kr_worker::session::Session::open(config).expect("opens");
    opened.launch().expect("launches");
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id: session(),
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    opened.attach(&params, requested, VIEW).expect("attaches");
    let stream = opened.subscribe(VIEW).expect("subscribes");
    let runtime = Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            opened,
            Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    (runtime, stream)
}

/// One instance, as a launch or an adoption would announce it.
fn summary(number: u8) -> AgentInstanceSummary {
    AgentInstanceSummary {
        application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([number; 16])),
        plugin_id: Nullable::null(),
        profile_id: Nullable::null(),
        mode: IntegrationMode::NativeTerminal,
        bypass: Nullable::null(),
        started_at: TimestampMs::new(u64::from(number)),
        ended_at: Nullable::null(),
        refusal: Nullable::null(),
    }
}

/// The next announcement the view is sent, or none within a short wait.
async fn next_announcement(
    view: &mut kr_worker::output::OutputStream,
) -> Option<AgentInstanceEvent> {
    loop {
        match tokio::time::timeout(Duration::from_secs(2), view.recv()).await {
            Ok(Some(kr_worker::output::OutputDelivery::AgentInstance { event, bytes })) => {
                view.written(bytes);
                return Some(*event);
            }
            Ok(Some(delivery)) => view.written(delivery.len()),
            Ok(None) | Err(_) => return None,
        }
    }
}

/// What a view holds after it installs a list and applies the announcements above its sequence.
fn apply(
    list: &kr_protocol::projection::AgentInstanceList,
    events: &[AgentInstanceEvent],
) -> Vec<AgentInstanceSummary> {
    let mut held = list.instances.clone();
    for event in events {
        if event.sequence.get() <= list.sequence.get() {
            continue;
        }
        if event.instance.ended_at.is_present() {
            held.retain(|instance| {
                instance.application_instance_id != event.instance.application_instance_id
            });
        } else {
            held.push(event.instance.clone());
        }
    }
    held
}

/// KR-REQ-12.07: the session counts, keeps and publishes its announcements under one lock, so a
/// list taken between two announcements carries the first, and a view that installs it and applies
/// the announcements above its sequence ends with both, each once, and without one that ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_list_and_the_announcements_after_it_hold_each_instance_once() {
    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut view) = session_and_view(&host);

    runtime.session().announce_instance(summary(1));
    let resynchronised = runtime
        .session()
        .snapshot(kr_protocol::projection::AgentResourceSnapshot {
            snapshot_id: U64::ZERO,
            stream_generation: U64::ZERO,
            cursor: U64::ZERO,
            resources: Vec::new(),
            continue_after: Nullable::null(),
        })
        .agent_instances;
    runtime.session().announce_instance(summary(2));

    // The view was subscribed before either, so both are in its stream.
    let mut events = Vec::new();
    while let Some(event) = next_announcement(&mut view).await {
        events.push(event);
        if events.len() == 2 {
            break;
        }
    }
    assert_eq!(events.len(), 2, "both announcements reach the view");
    assert!(events[0].sequence.get() < events[1].sequence.get());
    assert_eq!(events[0].session_id, session());
    assert_eq!(resynchronised.instances, vec![summary(1)]);
    assert_eq!(
        apply(&resynchronised, &events),
        vec![summary(1), summary(2)],
        "each instance once"
    );

    // An instance that ends leaves the list, and a view applying its end drops it.
    let mut ended = summary(1);
    ended.ended_at = Nullable::some(TimestampMs::new(9));
    runtime.session().announce_instance(ended);
    let last = next_announcement(&mut view)
        .await
        .expect("the end reaches the view");
    events.push(last);
    let now = runtime.session().agent_instances();
    assert_eq!(now.instances, vec![summary(2)]);
    assert_eq!(apply(&resynchronised, &events), vec![summary(2)]);
    assert_eq!(apply(&now, &events), vec![summary(2)]);
}

/// KR-REQ-12.07: the watch ends an adopted program that exited at its next tick while another
/// program's image is still being read, since an identification runs on a thread of its own and
/// no tick waits for it; and a session that closes meanwhile ends every adoption, after which that
/// identification records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_slow_identification_holds_no_end_and_adopts_nothing_after_the_close() {
    let setup = Setup::new();
    let first = setup.start();
    let told = setup.adopt(&Setup::foreground(&first, Vec::new()));
    assert_eq!(told.len(), 1, "the first program is adopted");
    let first_instance = told[0].application_instance_id;

    let second = setup.start();
    let second_process = second.process.clone();
    let (arrived, release) = setup.adoptions.pause_before_reading();
    let adoptions = Arc::new(setup.adoptions);
    let foreground = Setup::foreground(&second, Vec::new());
    let group = foreground.group;
    let watching = tokio::spawn(kr_worker::broker::adoption::watch_foreground(
        Arc::clone(&adoptions),
        kr_worker::lifecycle::Activity::new(),
        move || Some(Some(group)),
        move || Some(Some(foreground.clone())),
    ));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS))
        .await
        .expect("joined")
        .expect("the second program's image read is reached");

    first.end();
    let ended = tokio::time::timeout(Duration::from_secs(2), async {
        while setup.broker.binding_state(first_instance).is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the first program's end is found while the second's image is being read"
    );

    let closed = adoptions.close();
    assert!(
        closed.is_empty(),
        "nothing else was adopted when the session closed: {closed:?}"
    );
    release.send(()).expect("the reading is let go");
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session")
        .expect("joined");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        adoptions.adopted(&second_process),
        None,
        "an identification that finished after the close records nothing"
    );
    second.end();
}

/// How long after its latest traffic a session counts as one nothing is happening in.
const QUIET_AFTER: Duration = Duration::from_secs(4);

/// How many intervals a quiet session is watched for.
const QUIET_INTERVALS: u32 = 16;

/// The most foreground reads a quiet session may make in [`QUIET_INTERVALS`]: one in four.
const QUIET_READS: usize = 4;

/// A session whose one view holds the input lease, and the view's own delivery stream.
struct Typing {
    runtime: Arc<kr_worker::runtime::SessionRuntime>,
    epoch: u64,
    sequence: u64,
    _view: kr_worker::output::OutputStream,
}

impl Typing {
    /// Starts a session whose root shell runs `shell`, with a view that can type into it.
    fn start(host: &kr_ipc::testing::TempHost, shell: kr_worker::pty::ShellCommand) -> Self {
        let (runtime, view) = open_session(
            host,
            shell,
            &[
                kr_protocol::attachment::AttachmentCapability::ObserveTerminal,
                kr_protocol::attachment::AttachmentCapability::Input,
            ],
        );
        let epoch = {
            let mut session = runtime.session();
            session
                .acquire_input(
                    VIEW,
                    kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
                    None,
                )
                .expect("takes the lease");
            session.lease().epoch.get()
        };
        Self {
            runtime,
            epoch,
            sequence: 0,
            _view: view,
        }
    }

    /// Types `bytes` into the terminal, as the view holding the lease does.
    fn type_in(&mut self, bytes: &[u8]) {
        self.runtime
            .session()
            .write_input(
                VIEW,
                self.epoch,
                self.sequence,
                bytes,
                None,
                std::time::Instant::now(),
            )
            .expect("the input is accepted");
        self.sequence += 1;
        self.runtime.flush_input();
    }

    /// How many times the terminal's foreground has been read.
    fn reads(&self) -> usize {
        self.runtime.session().foreground_reads().len()
    }

    /// Asserts that the session reads its foreground on no more than one interval in four over the
    /// next [`QUIET_INTERVALS`] intervals.
    ///
    /// From [`QUIET_AFTER`] on, the watch waits about a second and more between looks, a quarter of
    /// the time since the traffic, each wait longer than the one before, so it reads at most four
    /// times in these sixteen intervals; a watch on a clock reads on every interval. The window is
    /// fixed by the times the session recorded for its reads, so when this task wakes to count them
    /// changes nothing.
    async fn quiet(&self, what: &str) {
        let from = std::time::Instant::now();
        let until = from + kr_worker::broker::adoption::WATCH_INTERVAL * QUIET_INTERVALS;
        tokio::time::sleep_until(until.into()).await;
        let read = self
            .runtime
            .session()
            .foreground_reads()
            .into_iter()
            .filter(|at| *at > from && *at <= until)
            .count();
        assert!(
            read <= QUIET_READS,
            "{what} reads its foreground on no more than one interval in four: {read} reads in \
             {QUIET_INTERVALS} intervals"
        );
    }

    /// Closes the session and waits for it to have closed.
    async fn close(self) {
        let (_, gate) = self
            .runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested);
        gate.release();
        tokio::time::timeout(LIVENESS, self.runtime.wait_closed())
            .await
            .expect("the session closes");
    }
}

/// Waits up to `limit` for `condition` to hold, and says whether it held by then.
///
/// A condition first seen to hold after the deadline counts as not holding by it, however late
/// this task was woken to look: a bound is a bound on when it held, not on when it was checked.
async fn within(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if condition() {
            return tokio::time::Instant::now() <= deadline;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The system's monotonic clock, read the same way here and in the stand-in, so that a time one
/// process records can be compared with a time the other does.
fn monotonic() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(
        u64::try_from(now.tv_sec).expect("a time after the clock's start"),
        u32::try_from(now.tv_nsec).expect("a fraction of a second"),
    )
}

/// KR-PERF-003 and KR-REQ-12.07: a session nothing is happening in does not read its terminal's
/// foreground on every interval. The watch looks often while the root shell starts and after the
/// session's own input and output, and less and less often the longer nothing happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_perf_003_an_idle_session_does_not_read_its_foreground_on_every_interval() {
    let setup = Setup::new();
    let mut typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    // With the producer of the session's application following every look, which adds no read.
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let adoptions = Arc::new(setup.adoptions.following(producer));
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));

    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("a session nothing has happened in since its shell started")
        .await;

    // Its own input, and the output that comes of it, ask the watch to look again.
    let before = typing.reads();
    typing.type_in(b"kr-adoption-marker\n");
    assert!(
        within(Duration::from_secs(2), || typing.reads() > before).await,
        "the session's traffic asks the watch to look"
    );
    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("the same session once its traffic has settled")
        .await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// KR-REQ-12.07: a program the root shell starts from a line typed into the session, which the
/// integration did not launch, is found by the watch within two seconds of running and adopted,
/// its end is found within two seconds of its exit, and the session is quiet again after that. The
/// shell asks nothing, as a shell without the integration does, and runs the program as a job of
/// its own in the foreground, which neither reads nor writes the terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_the_watch_adopts_a_program_the_root_shell_starts_from_a_typed_line() {
    adopts_from_a_typed_line("").await;
}

/// KR-REQ-12.07: the same when the line keeps the root shell busy for four seconds before it
/// starts the program, with the root shell's own group holding the terminal and nothing written:
/// the watch looks less often by then, and still finds the program within two seconds of running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_the_watch_adopts_a_program_a_typed_line_starts_after_a_silent_delay() {
    adopts_from_a_typed_line("delay=$(sleep 4); ").await;
}

/// Types a line into a POSIX shell with job control that runs `before` and then the stand-in, and
/// holds the watch to its bounds.
async fn adopts_from_a_typed_line(before: &str) {
    let setup = Setup::new();
    let running = setup.host.root().join("running");
    let mut shell = kr_worker::testing::posix_script(&format!(
        "set -m; read line; {before}\"$KR_ADOPTION_PROGRAM\" --exact the_stand_in_program \
         --test-threads 1 </dev/null >/dev/null 2>&1; read line"
    ));
    shell.environment.extend([
        (
            "KR_ADOPTION_PROGRAM".to_owned(),
            setup.program.display().to_string(),
        ),
        (STAND_IN.to_owned(), "60".to_owned()),
        (STAND_IN_RUNNING.to_owned(), running.display().to_string()),
    ]);
    let mut typing = Typing::start(&setup.host, shell);
    let (arrived, release) = setup.adoptions.pause_before_reading();
    // Waiting before the program can start, so the moment the watch reaches it is taken as it
    // happens rather than whenever this test next looks.
    let reached = tokio::task::spawn_blocking(move || {
        arrived.recv_timeout(LIVENESS).ok().map(|()| monotonic())
    });
    let adoptions = Arc::new(setup.adoptions);
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));
    tokio::time::sleep(QUIET_AFTER).await;

    typing.type_in(b"\n");
    let mut said = None;
    assert!(
        within(LIVENESS, || {
            said = std::fs::read_to_string(&running).ok().and_then(|text| {
                let (pid, started) = text.trim().split_once(' ')?;
                Some((pid.parse::<u32>().ok()?, started.parse::<u64>().ok()?))
            });
            said.is_some()
        })
        .await,
        "the root shell starts the program"
    );
    let (pid, started) = said.expect("the program says it is running");
    let started = Duration::from_nanos(started);
    let reached = reached
        .await
        .expect("joined")
        .expect("the watch reaches the program");
    let took = reached.saturating_sub(started);
    println!("the watch reached the program {took:?} after it started running");
    assert!(
        took <= Duration::from_secs(2),
        "the watch reaches the program within two seconds of it running: {took:?}"
    );
    // Let go, unless it has already gone on by itself.
    let _ = release.send(());
    let process = kr_ipc::identity::process_start_identity(pid).expect("the program is identified");
    assert!(
        within(LIVENESS, || adoptions.adopted(&process).is_some()).await,
        "the program is adopted"
    );
    let instance = adoptions.adopted(&process).expect("adopted");
    assert!(
        !setup.broker.holds_process(&process),
        "with no process record behind it"
    );

    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(pid).expect("an identifier"))
            .expect("a process"),
        rustix::process::Signal::TERM,
    );
    assert!(
        within(Duration::from_secs(2), || setup
            .broker
            .binding_state(instance)
            .is_err())
        .await,
        "its end is found within two seconds of its exit"
    );
    assert_eq!(adoptions.adopted(&process), None);

    // The root shell has the terminal back and waits for its next line.
    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("a session whose adopted program has ended")
        .await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// A POSIX shell with job control that waits for a line, runs `command` as a foreground job with
/// the terminal closed to it, and waits for another.
fn job_shell(
    setup: &Setup,
    command: &str,
    more: &[(&str, String)],
) -> kr_worker::pty::ShellCommand {
    let mut shell = kr_worker::testing::posix_script(&format!(
        "set -m; read line; {command} </dev/null >/dev/null 2>&1; read line"
    ));
    shell.environment.extend([
        (
            "KR_ADOPTION_PROGRAM".to_owned(),
            setup.program.display().to_string(),
        ),
        (STAND_IN.to_owned(), "60".to_owned()),
    ]);
    shell.environment.extend(
        more.iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    );
    shell
}

/// Waits until what the producer publishes satisfies `held`, and returns it.
async fn application_where(
    published: &mut tokio::sync::watch::Receiver<kr_worker::application::Application>,
    held: impl FnMut(&kr_worker::application::Application) -> bool,
) -> kr_worker::application::Application {
    tokio::time::timeout(LIVENESS, published.wait_for(held))
        .await
        .expect("the application becomes what was expected")
        .expect("the producer is still there")
        .clone()
}

/// The program the root shell runs from a typed line is the session's application
/// for as long as it holds the terminal, named as a person knows it and with no state of its own
/// (the worker does not know what it is doing), and the root shell at its prompt is no
/// application and is ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_program_holding_the_terminal_is_the_application_until_the_prompt_returns() {
    use kr_protocol::session::ApplicationState;

    let setup = Setup::new();
    let running = setup.host.root().join("running");
    let shell = job_shell(
        &setup,
        "\"$KR_ADOPTION_PROGRAM\" --exact the_stand_in_program --test-threads 1",
        &[(STAND_IN_RUNNING, running.display().to_string())],
    );
    let mut typing = Typing::start(&setup.host, shell);
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let mut published = producer.subscribe();
    let adoptions = Arc::new(setup.adoptions.following(Arc::clone(&producer)));
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));
    assert_eq!(
        typing.runtime.session().summary().application_state.0,
        Some(ApplicationState::ShellReady),
        "a shell at its prompt is ready"
    );

    typing.type_in(b"\n");
    assert!(
        within(LIVENESS, || typing
            .runtime
            .session()
            .summary()
            .application_state
            .0
            .is_none())
        .await,
        "a program holding the terminal has no state of its own"
    );
    let program = application_where(&mut published, |held| held.name.is_some()).await;
    assert_eq!(program.name.as_deref(), Some("claude"));
    assert_eq!(program.state, None);
    assert_eq!(
        typing.runtime.session().summary().application.as_deref(),
        Some("claude"),
        "the session's summary names the program that holds the terminal"
    );

    let pid = std::fs::read_to_string(&running)
        .expect("the program says it is running")
        .split_whitespace()
        .next()
        .and_then(|pid| pid.parse::<i32>().ok())
        .expect("its process identifier");
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid).expect("a process"),
        rustix::process::Signal::TERM,
    );
    let back = application_where(&mut published, |held| held.name.is_none()).await;
    assert_eq!(back.state, Some(ApplicationState::ShellReady));
    assert_eq!(
        typing.runtime.session().summary().application,
        None,
        "and names none once the prompt is back"
    );
    assert_eq!(
        typing.runtime.session().summary().application_state.0,
        Some(ApplicationState::ShellReady),
        "and the prompt returning is the session's state again"
    );

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// A program that is a wrapper until it execs is named for what it is when each look
/// finds it, and the name follows the exec: the application is the wrapper while it runs and the
/// program once it has replaced it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrapper_that_execs_the_program_names_the_program_after_the_exec() {
    let setup = Setup::new();
    let go = setup.host.root().join("go");
    let shell = job_shell(
        &setup,
        "sh -c 'while [ ! -e \"$KR_ADOPTION_GO\" ]; do sleep 0.05; done; exec \"$KR_ADOPTION_PROGRAM\" \
         --exact the_stand_in_program --test-threads 1'",
        &[("KR_ADOPTION_GO", go.display().to_string())],
    );
    let mut typing = Typing::start(&setup.host, shell);
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let mut published = producer.subscribe();
    let adoptions = Arc::new(setup.adoptions.following(Arc::clone(&producer)));
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));

    typing.type_in(b"\n");
    let wrapper = application_where(&mut published, |held| held.name.is_some()).await;
    assert_ne!(
        wrapper.name.as_deref(),
        Some("claude"),
        "while the wrapper runs, it is what holds the terminal, whatever its interpreter is called"
    );

    std::fs::write(&go, b"").expect("lets the wrapper exec");
    let program = application_where(&mut published, |held| {
        held.name.as_deref() == Some("claude")
    })
    .await;
    assert_eq!(program.state, None);

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// Writes an executable script at `path`.
fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, body).expect("the script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the script can run");
}

/// When the shell's integration answered for exactly one command of the line and
/// the foreground program is running it, as the interpreter a script names runs the script it is
/// given, that command names the application and not the interpreter. Only that shows it: a
/// program that merely reads the script, or that has replaced the command, is named for its own
/// image. A program is not named until two looks have found the same group.
///
/// The interpreter is the process's image or the file its first argument names: macOS's `/bin/sh`
/// runs as the shell the machine selects and keeps its own path as the first argument, so the image
/// alone would name every such script for the shell. The first argument is the process's own claim,
/// which is enough to name a program for display and for the sleep demand's reason, and decides
/// nothing of authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_command_the_integration_answered_for_names_the_program_that_runs_it() {
    use kr_worker::application::Following;

    let setup = Setup::new();
    let assistant = setup.host.root().join("assistant");
    script(&assistant, "#!/bin/sh\nsleep 60\ntrue\n");
    let answered = vec![(assistant.display().to_string(), None)];
    let typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let mut following = Following::new(Arc::clone(&producer));

    // The system starts the script under the interpreter its first line names, with the script's
    // path as the interpreter's argument, so the script is what runs. One look is not a program:
    // it is published when the look after it finds the same.
    let started = setup.start_script(&assistant);
    let foreground = Setup::foreground(&started, answered.clone());
    following.look(Some(&foreground));
    assert_eq!(
        producer.application().name,
        None,
        "a program is not named on the first look that finds it"
    );
    let named = look_until_named(&mut following, &producer, &foreground);
    assert_eq!(
        named, "assistant",
        "the script the interpreter was given names it, not the interpreter"
    );
    following.look(None);
    assert_eq!(producer.application().name, None);
    started.end();

    // The same script given to its interpreter as a path relative to the directory it works in,
    // as `./assistant` is typed: the leader's own directory is where that path leads.
    let started = setup.start_interpreter("/bin/sh", "assistant");
    let foreground = Setup::foreground(&started, answered.clone());
    let named = look_until_named(&mut following, &producer, &foreground);
    assert_eq!(
        named, "assistant",
        "a script given by a relative path is the one that runs"
    );
    following.look(None);
    started.end();

    // A program that has the script among its arguments and is another program: `tail` reads the
    // script and runs nothing of it.
    let watcher = setup.host.root().join("watcher");
    script(&watcher, "#!/bin/sh\nexec tail -f \"$0\"\n");
    let started = setup.start_script(&watcher);
    let foreground = Setup::foreground(&started, vec![(watcher.display().to_string(), None)]);
    let named = look_until_named(&mut following, &producer, &foreground);
    assert_eq!(
        named, "tail",
        "a program that is given the script's path to read is not the script"
    );
    following.look(None);
    started.end();

    // The same command, answered for a line whose program has since replaced it: nothing the
    // program is running names the command, so the image does.
    let started = setup.start();
    let foreground = Setup::foreground(&started, answered);
    let replaced = look_until_named(&mut following, &producer, &foreground);
    assert_ne!(
        replaced, "assistant",
        "a program that is not running the command the line named is not named for it"
    );
    started.end();
    typing.close().await;
}

/// A shell that is not yet running the script the line named, and then execs the interpreter on
/// it, is named for the script once it runs it: the process and its image are the same before and
/// after, and the look before the exec found the script not running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_that_execs_the_script_the_line_named_is_named_for_it_once_it_runs_it() {
    use kr_worker::application::Following;

    let setup = Setup::new();
    let go = setup.host.root().join("go");
    let assistant = setup.host.root().join("assistant");
    script(&assistant, "#!/bin/sh\nsleep 60\ntrue\n");
    let typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let mut following = Following::new(Arc::clone(&producer));

    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(format!(
        "while [ ! -e '{}' ]; do sleep 0.05; done; exec /bin/sh '{}'",
        go.display(),
        assistant.display()
    ));
    let started = setup.spawn_in_a_group(command);
    let foreground = Setup::foreground(&started, vec![(assistant.display().to_string(), None)]);
    let before = look_until_name(&mut following, &producer, &foreground, |_| true);
    assert_ne!(
        before, "assistant",
        "a shell that is not running the script the line named is not named for it"
    );

    std::fs::write(&go, b"").expect("lets the shell exec the script");
    let after = look_until_name(&mut following, &producer, &foreground, |name| {
        name == "assistant"
    });
    assert_eq!(after, "assistant", "the script it runs now names it");
    started.end();
    typing.close().await;
}

/// A script that execs the interpreter that runs it on another script is no longer named for the
/// script it was: the process and its image are the same before and after, and the look before
/// the exec found the script running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_that_execs_its_interpreter_on_another_script_is_no_longer_named_for_itself() {
    use kr_worker::application::Following;

    let setup = Setup::new();
    let go = setup.host.root().join("go");
    let (assistant, other) = (
        setup.host.root().join("assistant"),
        setup.host.root().join("other"),
    );
    script(
        &assistant,
        &format!(
            "#!/bin/sh\nwhile [ ! -e '{}' ]; do sleep 0.05; done\nexec /bin/sh '{}'\n",
            go.display(),
            other.display()
        ),
    );
    script(&other, "#!/bin/sh\nsleep 60\ntrue\n");
    let typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let producer = kr_worker::application::Producer::new(Arc::downgrade(&typing.runtime));
    let mut following = Following::new(Arc::clone(&producer));

    let started = setup.start_script(&assistant);
    let foreground = Setup::foreground(&started, vec![(assistant.display().to_string(), None)]);
    let before = look_until_name(&mut following, &producer, &foreground, |_| true);
    assert_eq!(before, "assistant", "the script it runs names it");

    std::fs::write(&go, b"").expect("lets the script exec another");
    let after = look_until_name(&mut following, &producer, &foreground, |name| {
        name != "assistant"
    });
    assert_ne!(
        after, "other",
        "the script the line did not name is not what names the program"
    );
    started.end();
    typing.close().await;
}

/// Looks at `foreground` until two looks in a row have found the same group and the program is
/// named, and says the name.
fn look_until_named(
    following: &mut kr_worker::application::Following,
    producer: &kr_worker::application::Producer,
    foreground: &Foreground,
) -> String {
    look_until_name(following, producer, foreground, |_| true)
}

/// Looks at `foreground` until the program is named and `wanted` accepts the name, and says it.
fn look_until_name(
    following: &mut kr_worker::application::Following,
    producer: &kr_worker::application::Producer,
    foreground: &Foreground,
    wanted: impl Fn(&str) -> bool,
) -> String {
    let started = std::time::Instant::now();
    loop {
        following.look(Some(foreground));
        match producer.application().name {
            Some(name) if wanted(&name) => return name,
            Some(name) => {
                assert!(
                    started.elapsed() < LIVENESS,
                    "the program was still named {name:?} after {LIVENESS:?}"
                );
            }
            None => assert!(
                started.elapsed() < LIVENESS,
                "no program was named within {LIVENESS:?}"
            ),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// KR-REQ-12.07: the invocation the shell's integration asks about and a command it reports
/// starting each ask the watch to look, without any input or output, and a command's end does not.
/// A program a line runs is looked for as the line starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_command_the_integration_reports_starting_asks_the_watch_to_look() {
    use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
    use kr_worker::fence::{CommandHook, Effects, Step};

    let setup = Setup::new();
    let typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let hook = |hook: CommandHook| {
        let _ = typing.runtime.session().apply_fence_effects(Effects {
            steps: vec![Step::CommandHook(
                kr_protocol::ids::RequestId::new(1),
                Box::new(hook),
            )],
            ..Effects::default()
        });
    };
    let block = |exit_status: Option<u64>| RootCommandBlockParams {
        session_id: session(),
        prompt_generation: PromptGeneration::new(1),
        command: "claude".to_owned(),
        started_at_ms: TimestampMs::new(1),
        duration_ms: Nullable(exit_status.map(|_| kr_protocol::scalars::DurationMs::new(1))),
        exit_status: Nullable(exit_status.map(U64::new)),
        cwd: "/".to_owned(),
        cwd_revision: CwdRevision::new(0),
    };

    // The marks themselves, read before any watch runs to take them: the root program neither
    // reads nor writes, so nothing else marks this session meanwhile.
    let activity = typing.runtime.session().activity();
    let _ = activity.take_foreground();
    hook(CommandHook::Resolve(
        kr_protocol::root::RootCommandResolveParams {
            session_id: session(),
            prompt_generation: PromptGeneration::new(1),
            argv: vec!["claude".to_owned()],
            executable: "/usr/local/bin/claude".to_owned(),
            interactive: true,
            cwd: "/".to_owned(),
            cwd_revision: CwdRevision::new(0),
        },
    ));
    assert!(activity.take_foreground(), "the invocation asked about");
    hook(CommandHook::Block(Box::new(block(None))));
    assert!(activity.take_foreground(), "a command starting");
    hook(CommandHook::Block(Box::new(block(Some(0)))));
    assert!(
        !activity.take_foreground(),
        "a command's end asks for nothing"
    );

    // And the watch they wake.
    let adoptions = Arc::new(setup.adoptions);
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));
    tokio::time::sleep(QUIET_AFTER).await;
    typing.quiet("a session nothing has happened in").await;
    let before = typing.reads();
    hook(CommandHook::Block(Box::new(block(None))));
    assert!(
        within(Duration::from_secs(1), || typing.reads() > before).await,
        "a command starting asks the watch to look"
    );
    tokio::time::sleep(QUIET_AFTER).await;
    typing.quiet("the session after that command").await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}
