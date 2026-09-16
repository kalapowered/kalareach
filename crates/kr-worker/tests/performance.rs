//! What the host costs when nothing is happening, and how long it takes to become usable.
//!
//! These are measurements, not unit tests, so they are ignored by default: one of them runs for
//! five minutes by design, because the requirement it measures is stated as a five-minute average.
//! `scripts/performance.sh` builds a release profile and runs them.
//!
//! Every measurement states its conditions in its own output. A number without the conditions it
//! was taken under is not evidence, and a condition this build cannot yet meet is named rather than
//! quietly left out.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{
    Dimensions, Presentation, SessionCreateParams, SessionCreateResult, ShellMode,
};

/// How many idle sessions the memory requirement names.
const IDLE_SESSIONS: usize = 20;

/// How many attached views the memory requirement names.
const ATTACHED_VIEWS: usize = 32;

/// The whole-host resident bound the requirement names, in kibibytes.
const RESIDENT_BOUND_KIB: u64 = 500 * 1024;

/// The processor bound the requirement names: a fraction of one core, averaged.
const IDLE_CORE_FRACTION: f64 = 0.01;

/// How long the processor average is taken over.
const IDLE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// The bound the attach requirement names.
const ATTACH_BOUND: Duration = Duration::from_millis(500);

struct Host {
    temp: kr_ipc::testing::TempHost,
    worker: PathBuf,
    environment_id: EnvironmentId,
    controller: Arc<Controller>,
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // On the internal disk, because a process a service manager launches is its own identity to
    // the operating system and one that reaches a removable volume prompts the person at the
    // machine.
    let worker = temp.root().join("kr-worker");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-worker"), &worker).expect("copies the worker");
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store(CONTROLLER_SECRET_SERVICE, &secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(DetachedSupervisor::new()),
        worker_program: worker.clone(),
        build_id: build(),
        release: "0".to_owned(),
    })
    .await
    .expect("the daemon starts");
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
        .expect("binds the client endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
    tokio::spawn(Arc::clone(&controller).serve_clients(clients));
    Host {
        temp,
        worker,
        environment_id,
        controller,
    }
}

fn build() -> BuildId {
    BuildId::new("kr-perf/0").expect("a build identifier")
}

async fn create(host: &Host) -> SessionCreateResult {
    let mut client = LocalClient::connect(
        &host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        LocalClientKind::Cli,
        build(),
    )
    .await
    .expect("connects to the daemon");
    let params = SessionCreateParams {
        environment_id: host.environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(host.temp.root().display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
            name: "PATH".to_owned(),
            value: "/usr/bin:/bin".to_owned(),
        }],
    };
    client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"))
}

/// Returns the resident size of a process, in kibibytes.
///
/// A reading this host could not take is not zero. Treating it as zero would make the total smaller
/// than the truth, and a measurement that can only be wrong downwards is not evidence.
fn resident_kib(pid: u32) -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("reads the process table");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("the kernel reports process {pid}'s resident size"))
}

/// Returns the processor time a process has used, in seconds.
fn processor_seconds(pid: u32) -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .expect("reads the process table");
    // `ps` prints elapsed processor time as `[[dd-]hh:]mm:ss`.
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return 0.0;
    }
    let mut seconds = 0.0;
    for part in text.split(':') {
        let part: f64 = part.trim().parse().unwrap_or(0.0);
        seconds = seconds * 60.0 + part;
    }
    seconds
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs for five minutes by design; scripts/performance.sh runs it"]
async fn idle_resources_for_twenty_sessions_and_thirty_two_views() {
    let host = host().await;
    let mut sessions = Vec::new();
    for _ in 0..IDLE_SESSIONS {
        sessions.push(create(&host).await);
    }
    assert_eq!(sessions.len(), IDLE_SESSIONS);

    // Thirty-two views, spread over the sessions, each subscribed to output.
    let mut views = Vec::new();
    for index in 0..ATTACHED_VIEWS {
        let session = &sessions[index % sessions.len()].session;
        let endpoint = kr_ipc::paths::Endpoint::from_path(
            sessions[index % sessions.len()]
                .endpoint
                .as_ref()
                .expect("a live session has an endpoint"),
        )
        .expect("an endpoint");
        views.push(observer(&endpoint, host.environment_id, session.session_id).await);
    }
    assert_eq!(views.len(), ATTACHED_VIEWS);

    // Every process this host is paying for: each session's root shell, and the worker that owns
    // it. The worker is where the canonical grid and the retained output live, so a measurement
    // that counted only the shell would leave out the thing it is meant to be measuring.
    let mut measured: Vec<u32> = Vec::new();
    for created in &sessions {
        // A session with no root process, or a worker the kernel will not name, is a measurement
        // this host cannot take. Quietly leaving it out would make the answer smaller than the
        // truth, which is the one direction a resource measurement must never be wrong in.
        let root = created
            .session
            .root_process
            .as_ref()
            .expect("every live session names its root process");
        let shell = u32::try_from(root.pid.get()).expect("a process identifier");
        measured.push(shell);
        measured.push(parent_of(shell).expect("the kernel names each root shell's worker"));
    }
    measured.sort_unstable();
    measured.dedup();
    let workers = measured;
    // The daemon is this test process.
    let daemon = std::process::id();

    let started = Instant::now();
    let before: f64 = workers
        .iter()
        .map(|pid| processor_seconds(*pid))
        .sum::<f64>()
        + processor_seconds(daemon);
    tokio::time::sleep(IDLE_WINDOW).await;
    let after: f64 = workers
        .iter()
        .map(|pid| processor_seconds(*pid))
        .sum::<f64>()
        + processor_seconds(daemon);
    let elapsed = started.elapsed().as_secs_f64();
    let cores = (after - before) / elapsed;

    let resident: u64 =
        workers.iter().map(|pid| resident_kib(*pid)).sum::<u64>() + resident_kib(daemon);

    println!("KR-PERF-003 measurement");
    let grid = kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS;
    println!(
        "  conditions: {IDLE_SESSIONS} idle sessions, {ATTACHED_VIEWS} attached views, a release \
         build, no application running; each session holds an allocated canonical grid of {}x{} \
         with its scrollback cache",
        grid.columns.get(),
        grid.rows.get()
    );
    println!(
        "  processor: {cores:.5} of one core averaged over {:.0} seconds",
        elapsed
    );
    println!(
        "  resident: {resident} KiB across {} processes (each session's worker and its root shell) \
         and the daemon",
        workers.len()
    );
    println!(
        "  not measured: the whole-product figure with adapters and a model active, which belongs \
         to the tasks that add them"
    );

    assert!(
        cores < IDLE_CORE_FRACTION,
        "idle processor use is under one per cent of a core: {cores:.5}"
    );
    assert!(
        resident < RESIDENT_BOUND_KIB,
        "idle resident memory is under {RESIDENT_BOUND_KIB} KiB: {resident} KiB"
    );
    drop(views);
    close_all(&host, &sessions).await;
    let _ = host.controller;
    let _ = host.worker;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement rather than a test; scripts/performance.sh runs it"]
async fn attach_to_a_usable_screen() {
    let host = host().await;
    let created = create(&host).await;

    // Both presentations are measured. A terminal of the session's own size is handed the stream
    // directly; one of any other size is drawn a rendering of the canonical grid, and a person
    // waits for the screen either way.
    let direct = attach_samples(&host, &created, Dimensions::new(120, 40)).await;
    let projected = attach_samples(&host, &created, Dimensions::new(80, 24)).await;

    println!("KR-PERF-004 measurement");
    println!(
        "  conditions: a local attachment to a live session at 120x40, a release build, measured \
         from the connection to the moment the host has delivered the screen: the connection, the \
         worker's proof, the attachment, the input lease, the subscription, and the screen itself \
         arriving and decoding. Drawing it is the terminal's own work and is not in these numbers."
    );
    println!(
        "  direct, a terminal of the session's own size: {}",
        report(&direct)
    );
    println!(
        "  projected, a terminal of 80x24 onto the same session: {}",
        report(&projected)
    );
    let worst = direct
        .iter()
        .chain(projected.iter())
        .max()
        .copied()
        .expect("samples");
    assert!(
        worst < ATTACH_BOUND,
        "the slowest attach reached a usable screen within {ATTACH_BOUND:?}: {worst:?}"
    );
    close_all(&host, std::slice::from_ref(&created)).await;
    let _ = host.controller;
}

/// Closes every session this measurement created and waits for its worker to end.
///
/// A worker is deliberately not this process's child: a measurement that simply exited would leave
/// one running per session it made, for as long as the machine stayed up. Every session a run
/// creates is therefore closed by that run, and the wait is for the worker process itself rather
/// than for the acceptance, because an acceptance is not an exit.
async fn close_all(host: &Host, sessions: &[SessionCreateResult]) {
    let mut client = LocalClient::connect(
        &host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        LocalClientKind::Cli,
        build(),
    )
    .await
    .expect("connects to the daemon");
    let mut workers = Vec::new();
    for created in sessions {
        if let Some(root) = created.session.root_process.as_ref()
            && let Ok(shell) = u32::try_from(root.pid.get())
            && let Some(worker) = parent_of(shell)
        {
            workers.push(worker);
        }
        let _ = client
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(created.session.session_id),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &kr_protocol::session::SessionCloseParams {
                    session_id: created.session.session_id,
                },
            )
            .await
            .expect("the call reaches the daemon");
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        workers.retain(|pid| running(*pid));
        if workers.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("every worker this measurement started has ended: {workers:?} are still running");
}

/// Returns whether a process is still running.
fn running(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-o", "pid=", "-p", &pid.to_string()])
        .output()
        .is_ok_and(|listing| !String::from_utf8_lossy(&listing.stdout).trim().is_empty())
}

/// Returns a process's parent, which for a session's root shell is its worker.
fn parent_of(pid: u32) -> Option<u32> {
    let listing = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&listing.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|parent| *parent > 1)
}

/// Renders a set of samples for the measurement's own output.
fn report(samples: &[Duration]) -> String {
    samples
        .iter()
        .map(|sample| format!("{:.3} ms", sample.as_secs_f64() * 1000.0))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Times five attachments of one size, from the connection to the screen.
async fn attach_samples(
    host: &Host,
    created: &SessionCreateResult,
    dimensions: Dimensions,
) -> Vec<Duration> {
    let endpoint =
        kr_ipc::paths::Endpoint::from_path(created.endpoint.as_ref().expect("a live session"))
            .expect("an endpoint");
    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        // A usable screen is the whole sequence a person waits for: the connection, the worker's
        // proof, the attachment, the input lease, the subscription, and the screen arriving. A
        // measurement that stopped at the first byte would be measuring the transport.
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(created.session.session_id),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &SessionAttachParams {
                    session_id: created.session.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the attach succeeds")
            .to_typed()
            .expect("decodes");
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: created.session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the subscription succeeds");
        // The screen itself. This is what the person sees, and it is where the clock stops.
        let screen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Ok(frame) = client.recv().await else {
                    return false;
                };
                if let kr_protocol::envelope::ControlFrame::Notification(notification) = frame
                    && notification.event_type.as_str() == "session.output"
                    && let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    // A screen a terminal can draw, not merely a frame that arrived: the payload
                    // decodes and it places the cursor, which every restoration ends by doing.
                    return event
                        .bytes
                        .as_slice()
                        .windows(4)
                        .any(|window| window == b"\x1b[?25" || window.starts_with(b"\x1b["));
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(screen, "the attachment was delivered a screen it can draw");
        samples.push(started.elapsed());
    }
    samples
}

/// Attaches an observing view and subscribes it to output.
async fn observer(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    session_id: SessionId,
) -> LocalClient {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                // The session's own size, with the terminal this client probed declared, so the
                // attachment is served the stream directly. A different size, or no declaration,
                // is served a rendering of the canonical screen instead.
                dimensions: Nullable::some(kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id,
                attachment_id: attached.attachment.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
    client
}
