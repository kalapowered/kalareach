//! A client that stops reading, on a real socket.
//!
//! Section 9 is explicit: a slow client is told to resynchronise and is never allowed to hold the
//! pseudo-terminal's read loop. A unit test on the fan-out cannot show the second half, because the
//! thing that would be held is a real socket with a real kernel buffer behind it. This one attaches
//! two clients over the worker's own endpoint, stops reading on one of them, and checks that the
//! other keeps receiving and that the session keeps running.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{ActionId, BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The bound one attachment's queue is given.
///
/// Smaller than the eight megabytes a session uses by default, so a client that stops reading
/// fills it in a moment rather than a minute. A client that is reading never approaches it.
const SEND_QUEUE_BYTES: usize = 256 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stops_reading_is_resynchronised_and_holds_nothing_up() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(1);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store = kr_crypto::store::open_store("KalaReachBackpressure", &environment.secrets_dir())
        .expect("a secret store");
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");

    // A shell that keeps producing for the whole test, rather than in one burst at startup. A
    // burst would be a race: a client that attached a moment late would subscribe past most of it
    // and never reach its bound. Roughly 140 KiB a second is many times one attachment's queue over
    // the window this test leaves a client not reading, and nothing at all for a client that reads.
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec![
                "-c".to_owned(),
                "while true; do i=0; while [ $i -lt 2000 ]; do printf 'line-%s-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n' $i; i=$((i+1)); done; sleep 1; done".to_owned(),
            ],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: SEND_QUEUE_BYTES,
        resident_bytes: 4 * 1024 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));

    // Two clients over the real endpoint. Neither knows about the other.
    let slow = attached(&endpoint, environment_id, session_id).await;
    let quick = attached(&endpoint, environment_id, session_id).await;

    // One of them reads as fast as it can.
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&received);
    let draining = tokio::spawn(async move {
        let mut quick = quick;
        while let Ok(message) = quick.recv().await {
            if let ControlFrame::Notification(notification) = message {
                match notification.event_type.as_str() {
                    "session.output" => {
                        counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    "session.resync" => return false,
                    _ => {}
                }
            }
        }
        true
    });

    // The other does not read at all for long enough to fall further behind than its bound allows.
    // Its socket fills, the worker's queue for it fills behind that, and it is told to
    // resynchronise. Nothing is read from it until then, which is the whole point.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // The session is still running, and the client that kept reading is still receiving: the one
    // that stopped reading held nothing up.
    assert_eq!(
        runtime.state(),
        SessionState::Live,
        "the session kept running while one client was not reading"
    );
    let before = received.load(std::sync::atomic::Ordering::Relaxed);
    assert!(before > 0, "the client that kept reading received output");
    // Waited for rather than sampled over a fixed window: what this asserts is that more arrives,
    // not how quickly a loaded machine delivers it.
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while received.load(std::sync::atomic::Ordering::Relaxed) <= before {
        assert!(
            Instant::now() < deadline,
            "waited {:?} for more output to reach the client that kept reading while the other \
             was not reading",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !draining.is_finished(),
        "the client that kept reading was not resynchronised"
    );

    // Now the client that stopped reading looks at what it was sent. What it finds is the marker,
    // not a hole it was never told about.
    let mut slow = slow;
    let mut resynchronised = false;
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while Instant::now() < deadline {
        // A timeout here is not an answer. The loop keeps looking until its own deadline rather
        // than concluding from one quiet moment that nothing is coming.
        let Ok(Ok(message)) = tokio::time::timeout(Duration::from_secs(5), slow.recv()).await
        else {
            continue;
        };
        if let ControlFrame::Notification(notification) = message
            && notification.event_type.as_str() == "session.resync"
        {
            resynchronised = true;
            break;
        }
    }
    assert!(
        resynchronised,
        "waited {:?} for the client that stopped reading to be told to resynchronise",
        started.elapsed()
    );
    draining.abort();
}

/// How long a wait for something to arrive is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never arrives. Thirty
/// seconds was inside the range the slowest reference hosts reach when several suites share them,
/// which turned these waits into coin tosses; two minutes is outside it. The poll intervals are
/// unchanged, so a wait that succeeds costs what it always did, and each failure says how long it
/// actually waited. What the assertions themselves say is untouched.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Attaches a client to the session and subscribes it to output.
async fn attached(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
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
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                // A client declares the terminal it probed. Direct mode needs it.
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
