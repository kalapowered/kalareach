//! What a session's worker reports of the host's own metrics: the terminal parse faults of its
//! session and the failures of the adapters it brokers.
//!
//! Each case runs a worker service over a real session and a real shell. The shell writes the bytes
//! of a case to its terminal, the engine classifies them as it does for any program, and the
//! worker's report is read back as the control daemon reads it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-26.43 | each class of parse fault a program can write is counted under its closed label, once for each occurrence and the same on a second read; an adapter whose component the plugin runtime cannot run is counted once for each step into that state, and a package that is not a bundled connector is counted under no name |

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::admission::ComponentState;
use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, BuildId, ControllerGeneration, PluginId, PublisherId,
    SessionEpoch, SessionId,
};
use kr_protocol::metrics::{Adapter, Environment, Fault, Outcome, Report};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a case waits for the shell's bytes to be classified, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// A worker service over a live session whose root shell runs `script`.
struct World {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
}

impl World {
    async fn running(script: &str) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let current =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id(),
                SessionEpoch::V1,
                boot.clone(),
                current,
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let secrets =
            kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
        let controller = Arc::new(
            ControllerIdentity::initialise(secrets.store.as_ref(), environment_id)
                .expect("a controller identity"),
        );
        let journal_path = environment.journal_database(session_id());
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id: session_id(),
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script(script),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id())),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint,
                ServiceBinding {
                    environment_id,
                    boot_identity: boot,
                    controller_public_key: *controller.public_key(),
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        Self {
            _temp: temp,
            service,
            runtime,
        }
    }

    /// Waits until the worker's report counts every class in `classes`, and returns it.
    async fn report_counting(&self, classes: &[Fault]) -> Report {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        loop {
            let report = self.service.metrics();
            if classes.iter().all(|class| {
                report
                    .terminal_parse_fault
                    .iter()
                    .any(|series| series.fault == *class)
            }) {
                return report;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the report counts {:?} after {LIVENESS:?}, and not every class of {classes:?}",
                report.terminal_parse_fault,
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.runtime.session().force_close();
    }
}

/// What a report counts of the parse faults, as class and count.
fn faults(report: &Report) -> Vec<(Fault, u64)> {
    report
        .terminal_parse_fault
        .iter()
        .map(|series| (series.fault, series.count.get()))
        .collect()
}

/// KR-REQ-26.43: a program that writes each of the four classes of bytes the parser cannot make
/// sense of is counted under the class's closed label once for each, and reading the report again
/// adds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_26_43_each_class_of_parse_fault_a_program_writes_is_counted_once() {
    // A sequence the profile has no class for; text that is not UTF-8; a control sequence cut off
    // by CAN; and an operating-system command past the bound on a control string.
    let world = World::running(
        "printf 'ok\\355\\240\\200more'; printf '\\033[?77h'; printf '\\033[1\\030'; \
         printf '\\033]0;'; head -c 70000 /dev/zero | tr '\\0' x; printf '\\007'; \
         printf 'kr-faults-written'; exec cat",
    )
    .await;
    let classes = [
        Fault::UnterminatedSequence,
        Fault::InvalidEncoding,
        Fault::OversizedFrame,
        Fault::UnknownControl,
    ];
    let first = world.report_counting(&classes).await;
    // The shell has finished writing when its last marker is in the output; wait for the engine to
    // have read to it so that the totals are final before they are read twice.
    let deadline = tokio::time::Instant::now() + LIVENESS;
    loop {
        let seen = {
            let session = world.runtime.session();
            let mut raw = Vec::new();
            loop {
                let page = session
                    .history_page(raw.len() as u64, 1 << 20)
                    .expect("the session's output history");
                if page.bytes.is_empty() {
                    break;
                }
                raw.extend_from_slice(page.bytes.as_slice());
            }
            raw
        };
        if seen
            .windows(17)
            .any(|window| window == b"kr-faults-written")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the shell's last line was not retained within {LIVENESS:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let settled = world.service.metrics();
    assert_eq!(
        faults(&settled),
        vec![
            (Fault::UnterminatedSequence, 1),
            (Fault::InvalidEncoding, 1),
            (Fault::OversizedFrame, 1),
            (Fault::UnknownControl, 1),
        ],
        "each class once, in the report's fixed order (first read: {:?})",
        faults(&first)
    );
    assert_eq!(
        world.service.metrics(),
        settled,
        "a second read of the same totals adds nothing"
    );
    for series in &settled.terminal_parse_fault {
        assert_eq!(series.environment, Environment::Development);
    }
}

/// KR-REQ-26.43: an adapter whose component the plugin runtime cannot run is counted once for each
/// step into that state, the runtime saying so again is not another failure, and a package the
/// product does not bundle as a connector is counted under no name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_26_43_an_adapter_the_runtime_cannot_run_is_counted_once_for_each_step_into_it() {
    let world = World::running("exec cat").await;
    let broker = world.service.broker();
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
    broker
        .register_instance(instance, IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    let bind = |binding: u8, plugin: &str| {
        let binding_id = BrokerBindingId::new(Uuid::from_bytes([binding; 16]));
        broker
            .bind_descriptor(
                binding_id,
                instance,
                PluginId::new(plugin).expect("a package identifier"),
                PublisherId::new("kalareach").expect("a publisher"),
                Digest256::from_bytes([binding; 32]),
                BrokerGrants::granted([BrokerGrant::UpstreamAction]),
                None,
                TimestampMs::new(1),
            )
            .expect("the package is bound");
        binding_id
    };
    let codex = bind(7, "kalareach/codex");
    let example = bind(8, "kalareach/example-declarative");
    let adapters = |world: &World| -> Vec<(Adapter, Outcome, u64)> {
        world
            .service
            .metrics()
            .adapter_failure
            .iter()
            .map(|series| (series.adapter, series.outcome, series.count.get()))
            .collect()
    };

    assert_eq!(adapters(&world), vec![], "nothing has failed yet");

    broker.set_component_state(codex, ComponentState::Unavailable, Some("no runtime"));
    broker.set_component_state(codex, ComponentState::Unavailable, Some("no runtime still"));
    assert_eq!(
        adapters(&world),
        vec![(Adapter::Codex, Outcome::Unavailable, 1)],
        "the runtime saying again that it cannot run the component is one failure"
    );

    broker.set_component_state(codex, ComponentState::Registered, None);
    assert_eq!(adapters(&world).len(), 1, "running again is not a failure");
    broker.set_component_state(
        codex,
        ComponentState::Unavailable,
        Some("the runtime ended"),
    );
    assert_eq!(
        adapters(&world),
        vec![(Adapter::Codex, Outcome::Unavailable, 2)],
        "a second step into the state is a second failure"
    );

    broker.set_component_state(example, ComponentState::Unavailable, Some("no runtime"));
    assert_eq!(
        adapters(&world),
        vec![(Adapter::Codex, Outcome::Unavailable, 2)],
        "a package that is not a bundled connector is counted under no name"
    );
}
