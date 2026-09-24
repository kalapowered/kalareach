//! How a session's closure reaches its attachments, over the worker's own endpoint.
//!
//! A worker exists for its session, and when the session closes the worker goes and its
//! connections go with it. What each attachment is owed before that is how the session ended: the
//! closure record, as the last thing on its stream, after every byte of output it was sent. Only a
//! real shell, a real socket and real clients show the order the two arrive in, and the wait a
//! worker makes for them before it exits.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams, OutputEvent};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, DisplayNumber, SESSION_CLOSED_EVENT, ShellMode,
};
use kr_worker::runtime::{CLOSURE_NOTICE_TIMEOUT, SessionRuntime};
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

use common::{Keys, LIVENESS_DEADLINE, carries, take_the_keys};

/// A session this test hosts, served on its own endpoint.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    #[cfg_attr(
        not(unix),
        expect(
            dead_code,
            reason = "only the tests that set the transport ask the service"
        )
    )]
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

impl Drop for Host {
    /// Stops the shell this fixture started, however the test ended.
    ///
    /// Each application here waits on its terminal for a line only the test types, so a test that
    /// failed before typing it would leave one waiting. A session whose lock an earlier panic
    /// poisoned cannot be reached at all, and that refusal is caught rather than raised inside a
    /// drop that may already be unwinding.
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.runtime.session().force_close();
        }));
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Hosts a session whose shell runs `script`, and serves it on the worker's endpoint.
async fn host(script: &str) -> Host {
    host_on(script, &tokio::runtime::Handle::current()).await
}

/// Hosts a session whose shell runs `script`, with the session's own tasks on `tasks`.
///
/// Those are the tasks that ingest what the terminal gives, watch the root shell and time the paste
/// recogniser. The endpoint, its connections and a closure's sequence run where the caller does.
async fn host_on(script: &str, tasks: &tokio::runtime::Handle) -> Host {
    host_served(script, tasks, Listener::bind).await
}

/// Hosts a session whose shell runs `script`, served on a listener whose connections are given a
/// send buffer of [`SEND_BUFFER`].
///
/// A client that stops reading then holds what that buffer holds, which this test sets, rather
/// than what a platform's default holds.
#[cfg(unix)]
async fn host_on_a_narrow_transport(script: &str) -> Host {
    host_served(script, &tokio::runtime::Handle::current(), |endpoint| {
        Listener::bind_with_send_buffer(endpoint, SEND_BUFFER)
    })
    .await
}

/// Hosts a session whose shell runs `script`, with the session's own tasks on `tasks`, served on
/// the listener `bind` makes.
async fn host_served(
    script: &str,
    tasks: &tokio::runtime::Handle,
    bind: impl FnOnce(&kr_ipc::paths::Endpoint) -> kr_ipc::Result<Listener>,
) -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = {
        let _tasks = tasks.enter();
        Arc::new(
            SessionRuntime::start(
                session,
                std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        )
    };
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = bind(&endpoint).expect("binds the endpoint");
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
    Host {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

/// Attaches a terminal of the session's own size over a new connection.
async fn attach(host: &Host) -> (LocalClient, AttachmentId) {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
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
                session_id: Nullable::some(host.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id: host.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
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

/// Subscribes this client's attachment to the session's output and state.
///
/// It is the last call the client makes. A client drops the notifications that arrive while it is
/// waiting for an answer of its own, and everything from here on is a notification.
async fn subscribe(client: &mut LocalClient, host: &Host, attachment_id: AttachmentId) {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    streams.insert(EventStream::SessionState);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
}

/// Attaches, takes the input lease and subscribes, in that order.
async fn attached_holding_the_keys(host: &Host) -> (LocalClient, Keys) {
    let (mut client, attachment_id) = attach(host).await;
    let keys = take_the_keys(
        &mut client,
        host.environment_id,
        host.session_id,
        attachment_id,
    )
    .await;
    subscribe(&mut client, host, attachment_id).await;
    (client, keys)
}

/// Attaches and subscribes a terminal that only watches.
async fn watching(host: &Host) -> LocalClient {
    let (mut client, attachment_id) = attach(host).await;
    subscribe(&mut client, host, attachment_id).await;
    client
}

/// Polls until `condition` holds, and fails with how long it waited when it never does.
#[cfg(unix)]
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = tokio::time::Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for {what}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Waits for the session's own closure record.
async fn closed(host: &Host) -> ClosureRecord {
    tokio::time::timeout(LIVENESS_DEADLINE, host.runtime.wait_closed())
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the session to close"))
}

/// Reads one client's stream until the closure arrives, and returns the output before it and the
/// record it carried.
async fn until_the_closure(client: &mut LocalClient) -> (Vec<u8>, ClosureRecord) {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut output = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!(
                "the connection ended ({error}) before the closure arrived, after {:?}: {}",
                started.elapsed(),
                String::from_utf8_lossy(&output).escape_debug()
            ),
            Err(_) => panic!(
                "waited {:?} for the closure: {}",
                started.elapsed(),
                String::from_utf8_lossy(&output).escape_debug()
            ),
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        match notification.event_type.as_str() {
            "session.output" => {
                let event: OutputEvent = notification
                    .payload
                    .to_typed()
                    .expect("an output event decodes");
                output.extend_from_slice(event.bytes.as_slice());
            }
            SESSION_CLOSED_EVENT => {
                let record = notification
                    .payload
                    .to_typed()
                    .expect("the closure carries the session's closure record");
                return (output, record);
            }
            _ => {}
        }
    }
}

/// KR-REQ-07.52: a shell that exits closes its session, and every attachment is sent how, after
/// all the output it was owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_attachment_is_sent_the_closure_after_the_output_it_was_owed() {
    let host = host("read -r _; printf 'kr-last-words\\n'; exit 7").await;
    let (mut typing, mut keys) = attached_holding_the_keys(&host).await;
    let mut watcher = watching(&host).await;
    keys.release(&host.runtime);
    let record = closed(&host).await;
    assert_eq!(record.reason, ClosureReason::RootExit);
    assert_eq!(
        record.root_exit_code.as_ref().map(|code| code.get()),
        Some(7)
    );
    for (client, what) in [(&mut typing, "the typing"), (&mut watcher, "the watching")] {
        let (output, sent) = until_the_closure(client).await;
        assert!(
            carries(&output, b"kr-last-words"),
            "{what} attachment was sent the shell's last output before the closure: {}",
            String::from_utf8_lossy(&output).escape_debug()
        );
        assert_eq!(
            sent, record,
            "{what} attachment was sent the session's own record"
        );
    }
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "the worker is owed nothing once both have been sent it"
    );
}

/// An attachment whose client has gone is owed nothing, and the worker does not wait for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_has_gone_holds_nothing_up() {
    let host = host("read -r _; exit 0").await;
    let (mut staying, mut keys) = attached_holding_the_keys(&host).await;
    let gone = watching(&host).await;
    drop(gone);
    keys.release(&host.runtime);
    let record = closed(&host).await;
    let (_, sent) = until_the_closure(&mut staying).await;
    assert_eq!(sent, record);
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "a client that went before the closure owes the worker nothing"
    );
}

/// The send buffer each connection is given where a test sets what a client that stops reading
/// holds.
///
/// The operating system keeps a buffer of this order (Linux doubles what it is asked for), so a
/// frame of [`BATCH_BYTES`] that a client is not reading stops part way on every platform, and
/// whatever is queued behind that frame stays queued.
#[cfg(unix)]
const SEND_BUFFER: usize = 4 * 1024;

/// One batch of output, delivered as one frame fifty times larger than [`SEND_BUFFER`].
#[cfg(unix)]
const BATCH_BYTES: usize = 200 * 1024;

/// The scheduling allowance between the worker's wait and a timer set to the same bound just after
/// the wait took its own deadline.
///
/// Their deadlines are microseconds apart and one task waits for both, so this covers the timer's
/// own tick and a moment of scheduling with room to spare. It is an allowance measured against
/// this suite's machines, not something the runtime promises.
#[cfg(unix)]
const TIMER_SLACK: Duration = Duration::from_millis(250);

/// Gives the session `bytes` as its terminal would, and settles the screen as a quiet terminal
/// does: the two steps the worker takes with a batch its read loop hands over.
#[cfg(unix)]
fn write_output(host: &Host, bytes: &[u8]) {
    let mut session = host.runtime.session();
    let _ = session.ingest_output(bytes);
    let _ = session.quiesce_output();
}

/// Attaches and subscribes a terminal over a connection of its own, which reads nothing more until
/// the test reads it.
#[cfg(unix)]
async fn stalled(host: &Host) -> (LocalClient, AttachmentId) {
    let (mut client, attachment_id) = attach(host).await;
    subscribe(&mut client, host, attachment_id).await;
    (client, attachment_id)
}

/// Closes the session and waits for its record.
#[cfg(unix)]
async fn close(host: &Host) -> ClosureRecord {
    let (_, gate) = host.runtime.close(ClosureReason::CloseRequested);
    gate.release();
    closed(host).await
}

/// KR-REQ-07.52: a worker whose session has closed waits for an attachment that stopped reading to
/// be sent the closure, for its bound and no longer, and one that reads again is sent all the
/// output it was owed and then the closure.
///
/// The transport each client holds is one this test sets, and each client stops part way through a
/// frame far larger than it, so the notice queued behind that frame cannot be written until the
/// client reads, on any platform. The wait is the one a worker makes before it exits, started
/// here, so its start is known: it may not end before its bound, measured from before it began,
/// and it is measured against a timer set to the same bound as soon as the wait has taken its own
/// deadline, within a scheduling allowance. A machine busy enough to delay this test past both
/// deadlines can hide a wait that ran a little long; it cannot fail a wait that kept its bound.
///
/// Unix only, because the transport this sets is a Unix socket's buffer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stopped_reading_holds_the_worker_only_until_the_bound() {
    let host = host_on_a_narrow_transport("read -r _").await;
    let (never, never_attachment) = stalled(&host).await;
    let (mut resuming, resuming_attachment) = stalled(&host).await;
    write_output(&host, &vec![b'x'; BATCH_BYTES]);
    for (attachment_id, what) in [
        (never_attachment, "the client that never reads again"),
        (resuming_attachment, "the client that reads again"),
    ] {
        until(&format!("{what} to stop part way through a frame"), || {
            host.service.part_way_through_a_frame(attachment_id)
        })
        .await;
    }
    let record = close(&host).await;

    let wait = host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT);
    tokio::pin!(wait);
    let started = tokio::time::Instant::now();
    // The wait takes its deadline when it is first polled, and the timer is set just after that, so
    // whatever holds up the wait's first steps holds up the timer's start as well.
    let first =
        std::future::poll_fn(|context| std::task::Poll::Ready(wait.as_mut().poll(context))).await;
    assert!(
        first.is_pending(),
        "the wait did not end as it began: {first:?}"
    );
    let timer = tokio::time::sleep(CLOSURE_NOTICE_TIMEOUT);
    let ((delivered, waited), timed) = tokio::time::timeout(LIVENESS_DEADLINE, async {
        tokio::join!(
            async {
                let delivered = wait.await;
                (delivered, started.elapsed())
            },
            async {
                timer.await;
                started.elapsed()
            },
        )
    })
    .await
    .unwrap_or_else(|_| panic!("the wait was still going {LIVENESS_DEADLINE:?} after it began"));
    assert!(
        !delivered,
        "neither client that is not reading has been sent its notice"
    );
    assert!(
        waited >= CLOSURE_NOTICE_TIMEOUT,
        "the wait held for its bound of {CLOSURE_NOTICE_TIMEOUT:?}, and it ended after {waited:?}"
    );
    // The two deadlines are microseconds apart and one task waits for both, so a wait that keeps
    // its bound ends within a scheduling moment of the timer, and one with a longer bound later.
    assert!(
        waited.abs_diff(timed) < TIMER_SLACK,
        "the wait ended within {TIMER_SLACK:?} of a timer set to its bound of \
         {CLOSURE_NOTICE_TIMEOUT:?}: it ended after {waited:?}, and the timer after {timed:?}"
    );

    let (output, sent) = until_the_closure(&mut resuming).await;
    assert_eq!(
        sent, record,
        "the client that read again was sent the record"
    );
    assert_eq!(
        output.iter().filter(|byte| **byte == b'x').count(),
        BATCH_BYTES,
        "and every byte of the output it was owed before it"
    );
    assert!(
        !host
            .runtime
            .closure_delivered(Duration::from_millis(500))
            .await,
        "the notice of the client that is still not reading is still owed"
    );
    drop(never);
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "and once that client has gone the worker is owed nothing"
    );
}

/// KR-REQ-07.52, KR-REQ-09.23: a client that fell a whole queue behind is told to resynchronise,
/// and is still sent the closure, straight after the marker and as the last thing on its stream.
///
/// Falling behind loses output, not the news of how the session ended. The client stops reading
/// part way through a frame on a transport this test sets, and the session is given batches until
/// the client's queue is full and it is marked for resynchronisation. The session then closes, the
/// notice stays owed while the client reads nothing, and the client reading again finds what was
/// queued before the marker, the marker, and the closure.
///
/// Unix only, because the transport this sets is a Unix socket's buffer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_fell_a_queue_behind_is_sent_the_marker_and_then_the_closure() {
    let host = host_on_a_narrow_transport("read -r _").await;
    let (mut behind, attachment_id) = stalled(&host).await;
    let mut given = 0_usize;
    while !host.runtime.session().is_resynchronising(attachment_id) {
        assert!(
            given < 64 * BATCH_BYTES,
            "the client was not marked for resynchronisation after {given} bytes"
        );
        write_output(&host, &vec![b'x'; BATCH_BYTES]);
        given += BATCH_BYTES;
    }
    until("the client to stop part way through a frame", || {
        host.service.part_way_through_a_frame(attachment_id)
    })
    .await;
    let record = close(&host).await;
    assert!(
        !host
            .runtime
            .closure_delivered(Duration::from_millis(500))
            .await,
        "the notice of a client that is behind and not reading is owed"
    );

    let started = tokio::time::Instant::now();
    let mut output = 0_usize;
    let mut marked = false;
    let sent = loop {
        let remaining = LIVENESS_DEADLINE.saturating_sub(started.elapsed());
        let frame = match tokio::time::timeout(remaining, behind.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!(
                "the connection ended ({error}) before the closure, after {output} bytes of \
                 output and {} the marker",
                if marked { "after" } else { "before" }
            ),
            Err(_) => panic!("waited {LIVENESS_DEADLINE:?} for the closure"),
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        match notification.event_type.as_str() {
            "session.output" => {
                assert!(
                    !marked,
                    "nothing of the output reaches the client after the marker"
                );
                let event: OutputEvent = notification
                    .payload
                    .to_typed()
                    .expect("an output event decodes");
                output += event
                    .bytes
                    .as_slice()
                    .iter()
                    .filter(|byte| **byte == b'x')
                    .count();
            }
            "session.resync" => {
                assert!(!marked, "the client is marked once");
                marked = true;
            }
            SESSION_CLOSED_EVENT => {
                break notification
                    .payload
                    .to_typed::<ClosureRecord>()
                    .expect("the closure carries the session's closure record");
            }
            other => assert!(
                !marked,
                "nothing reaches the client between the marker and the closure, and {other} did"
            ),
        }
    };
    assert!(
        marked,
        "the client was told to resynchronise before the closure"
    );
    assert_eq!(sent, record, "and was sent the session's own record");
    assert!(
        output > 0 && output < given,
        "what was queued before the marker arrived, {output} of the {given} bytes given, and the \
         rest was not"
    );
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "and once it has the closure the worker is owed nothing"
    );
}

/// An attachment the session admitted that had not subscribed when the session closed is owed the
/// closure all the same, and is sent it when it subscribes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_that_subscribes_after_the_closure_is_sent_it_all_the_same() {
    let host = host("read -r _; exit 0").await;
    let (mut typing, mut keys) = attached_holding_the_keys(&host).await;
    let (mut late, late_attachment) = attach(&host).await;
    keys.release(&host.runtime);
    let record = closed(&host).await;
    let (_, sent) = until_the_closure(&mut typing).await;
    assert_eq!(sent, record);
    assert!(
        !host
            .runtime
            .closure_delivered(Duration::from_millis(500))
            .await,
        "the attachment that has not subscribed is still owed the closure"
    );
    subscribe(&mut late, &host, late_attachment).await;
    let (_, sent) = until_the_closure(&mut late).await;
    assert_eq!(sent, record, "it is sent the session's own record");
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "and the worker is owed nothing once it has been"
    );
}

/// A runtime for a session's own tasks that a test can hold still.
///
/// A worker on a busy machine can be seconds behind its terminal: the read loop, on a thread of its
/// own, has taken output that the task which ingests it has not reached yet, and a closure's drain
/// can end while the worker is in that state. Load makes the state last as long as the machine
/// decides. A hold makes it last as long as the test decides, and the read loop goes on reading
/// through it exactly as it does under load.
#[cfg(unix)]
struct SessionTasks {
    handle: tokio::runtime::Handle,
    holds: Option<tokio::sync::mpsc::UnboundedSender<Hold>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// One hold: it is said to have begun on the first, and it lasts until the second's sender goes.
#[cfg(unix)]
struct Hold {
    begun: tokio::sync::oneshot::Sender<()>,
    until: std::sync::mpsc::Receiver<()>,
}

#[cfg(unix)]
impl SessionTasks {
    /// Starts the runtime on a thread of its own, which is the only thread it has.
    fn start() -> Self {
        let (handles, handle) = std::sync::mpsc::channel();
        let (holds, mut requested) = tokio::sync::mpsc::unbounded_channel::<Hold>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the session's tasks");
            let _ = handles.send(runtime.handle().clone());
            runtime.block_on(async move {
                while let Some(hold) = requested.recv().await {
                    let _ = hold.begun.send(());
                    // The runtime's only thread waits here, so nothing on the runtime runs until
                    // the hold is over.
                    let _ = hold.until.recv();
                }
            });
            runtime.shutdown_background();
        });
        let handle = handle
            .recv()
            .expect("the session's tasks have a runtime to run on");
        Self {
            handle,
            holds: Some(holds),
            thread: Some(thread),
        }
    }

    /// The runtime the session's tasks are started on.
    const fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// Holds every task on the runtime still, from when this returns until what it returns goes.
    async fn hold(&self) -> std::sync::mpsc::Sender<()> {
        let (begun, has_begun) = tokio::sync::oneshot::channel();
        let (release, until) = std::sync::mpsc::channel();
        self.holds
            .as_ref()
            .expect("the session's tasks are running")
            .send(Hold { begun, until })
            .expect("the session's tasks are running");
        has_begun.await.expect("the hold begins");
        release
    }
}

#[cfg(unix)]
impl Drop for SessionTasks {
    /// Ends the runtime and the session's tasks with it, once any hold is over.
    fn drop(&mut self) {
        drop(self.holds.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Quotes a path for the shell a test session runs.
#[cfg(unix)]
fn quoted(path: &std::path::Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

/// The line a drain test's shell prints, and the only output it gives.
#[cfg(unix)]
const LAST_LINE: &[u8] = b"kr-read-before-the-closure";

/// How long a worker that does not wait for what it has read takes to write its record once its
/// drain period has ended.
///
/// Nothing lies between the two in such a worker but the record itself, so this is a scheduling
/// allowance. A drain test lets the worker go on after it, and a worker that waits correctly is
/// still waiting then.
#[cfg(unix)]
const RECORD_ALLOWANCE: Duration = Duration::from_secs(2);

/// A script that prints [`LAST_LINE`] once `gate` exists, and then waits on its terminal.
///
/// The gate is a file rather than a line typed at the terminal, because a typed line is echoed:
/// the echo would be output too, and the first read after the gate would be the echo instead of
/// the line.
#[cfg(unix)]
fn prints_once(gate: &std::path::Path) -> String {
    format!(
        "until [ -e {} ]; do sleep 0.05; done; printf '{}\\n'; read -r _",
        quoted(gate),
        String::from_utf8_lossy(LAST_LINE)
    )
}

/// Opens the gate, and returns once the read loop has read what the shell printed and stands
/// before counting it, with what lets it go on.
#[cfg(unix)]
async fn read_and_not_counted(host: &Host, gate: &std::path::Path) -> std::sync::mpsc::Sender<()> {
    let (arrived, release) = host.runtime.pause_after_next_read();
    std::fs::write(gate, b"").expect("opens the gate");
    tokio::time::timeout(LIVENESS_DEADLINE, arrived)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the line to be read"))
        .expect("the read loop says it has read the line");
    release
}

/// Asks the session to close, and returns once its drain period has ended and a worker that did not
/// wait for what it had read would have written its record.
#[cfg(unix)]
async fn close_past_the_drain(host: &Host) {
    let drained = host.runtime.watch_drain_end();
    let (_, gate) = host.runtime.close(ClosureReason::CloseRequested);
    gate.release();
    tokio::time::timeout(LIVENESS_DEADLINE, drained)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the drain to end"))
        .expect("the closure says its drain has ended");
    let _ = tokio::time::timeout(RECORD_ALLOWANCE, host.runtime.wait_closed()).await;
}

/// Checks that each client was sent [`LAST_LINE`] before the closure, and the session's own record.
#[cfg(unix)]
async fn each_was_sent_the_line_first(host: &Host, clients: [&mut LocalClient; 2]) {
    let record = closed(host).await;
    assert_eq!(record.reason, ClosureReason::CloseRequested);
    for (index, client) in clients.into_iter().enumerate() {
        let (output, sent) = until_the_closure(client).await;
        assert!(
            carries(&output, LAST_LINE),
            "attachment {index} was sent the line the worker had read before the closure: {}",
            String::from_utf8_lossy(&output).escape_debug()
        );
        assert_eq!(
            sent, record,
            "attachment {index} was sent the session's own record"
        );
    }
}

/// KR-REQ-07.52: output the worker read from the terminal before its drain ended reaches every
/// attachment before the closure, however far behind with it the worker is.
///
/// The session's own tasks are held still before the shell prints, so the line it prints is read
/// and counted and then waits to be ingested, which is where a busy machine leaves a worker for
/// seconds at a time. The close goes on around the hold, because its sequence runs beside the
/// endpoint rather than with the session's tasks. The tasks are let go once the drain has ended
/// and a worker that did not wait would have written its record: such a worker has put the
/// closure in front of the line by then, and the line reaches nobody.
///
/// Unix only: the shell's gate is a file named by a POSIX path. The drain this checks is the same
/// code on every platform.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_read_before_the_drain_ends_reaches_every_attachment_before_the_closure() {
    let tasks = SessionTasks::start();
    let marks = tempfile::tempdir().expect("a directory on the internal disk");
    let gate = marks.path().join("gate");
    let host = host_on(&prints_once(&gate), tasks.handle()).await;
    let mut first = watching(&host).await;
    let mut second = watching(&host).await;
    let held = tasks.hold().await;
    drop(read_and_not_counted(&host, &gate).await);
    close_past_the_drain(&host).await;
    drop(held);
    each_was_sent_the_line_first(&host, [&mut first, &mut second]).await;
}

/// KR-REQ-07.52: output from a read that had returned when the drain ended reaches every
/// attachment before the closure, even while the read loop has still to count it.
///
/// The read loop is stopped after the read that returned the line and before it counted it, and
/// the drain ends while it stands there. A worker that measured what it had read without waiting
/// for that read would leave the line out of the measure, write its record, and hand the line to
/// nobody once the read loop went on.
///
/// Unix only, for the same reason as the test above.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_returned_before_the_drain_ended_reaches_every_attachment_before_the_closure() {
    let marks = tempfile::tempdir().expect("a directory on the internal disk");
    let gate = marks.path().join("gate");
    let host = host(&prints_once(&gate)).await;
    let mut first = watching(&host).await;
    let mut second = watching(&host).await;
    let reading = read_and_not_counted(&host, &gate).await;
    close_past_the_drain(&host).await;
    drop(reading);
    each_was_sent_the_line_first(&host, [&mut first, &mut second]).await;
}
