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
    _service: Arc<WorkerService>,
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
    Host {
        _temp: temp,
        _service: service,
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

/// A client that has stopped reading keeps its notice owed, and the worker's wait for it ends at
/// the bound the caller gives rather than when the client comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stopped_reading_holds_the_worker_only_until_the_bound() {
    // More output than this client's queue holds, sent to a client that never reads any of it.
    let host = host("read -r _; head -c 2000000 /dev/zero | tr '\\0' x; read -r _; exit 0").await;
    let (stalled, mut keys) = attached_holding_the_keys(&host).await;
    keys.release(&host.runtime);
    // The session says when this client has fallen a whole queue behind: a megabyte it was owed
    // had not been taken off the connection. That is the moment the closure is let happen. A
    // local socket holds a few hundred kilobytes at the most, so the notice queued behind that
    // megabyte cannot be written while the client reads nothing; a transport that held it all
    // would let the notice through and fail the check below, never pass it wrongly.
    until(
        "the client that stopped reading to fall a whole queue behind",
        || host.runtime.session().is_resynchronising(keys.attachment()),
    )
    .await;
    keys.release(&host.runtime);
    closed(&host).await;
    assert!(
        !host
            .runtime
            .closure_delivered(Duration::from_millis(500))
            .await,
        "the notice of a client that is not reading is still owed"
    );
    drop(stalled);
    assert!(
        host.runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await,
        "and once that client has gone it is owed nothing"
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

/// How long after its grace and drain a closing worker is given to write its record, before this
/// test takes it that the worker is waiting for something else.
#[cfg(unix)]
const RECORD_ALLOWANCE: Duration = Duration::from_secs(3);

/// KR-REQ-07.52: output the worker read from the terminal before its drain ended reaches every
/// attachment before the closure, however far behind with it the worker is.
///
/// The session's own tasks are held still before the shell prints, so the line it prints is read
/// and waits to be ingested, which is where a busy machine leaves a worker for seconds at a time.
/// The close goes on around the hold: its sequence runs beside the endpoint rather than with the
/// session's tasks. The tasks are let go when the record is written or, for a worker that is
/// waiting for its own parsing instead, a while after it would have been. A worker that wrote the
/// record at the end of the drain has put the closure in front of the line by then, and the line
/// reaches nobody.
///
/// Unix only: the shell marks that it has printed with a file, named by a POSIX path. The drain
/// this checks is the same code on every platform.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_read_before_the_drain_ends_reaches_every_attachment_before_the_closure() {
    let tasks = SessionTasks::start();
    let marks = tempfile::tempdir().expect("a directory on the internal disk");
    let printed = marks.path().join("printed");
    let host = host_on(
        &format!(
            "read -r _; printf 'kr-read-before-the-closure\\n'; : > {}; read -r _",
            quoted(&printed)
        ),
        tasks.handle(),
    )
    .await;
    let (mut typing, mut keys) = attached_holding_the_keys(&host).await;
    let mut watcher = watching(&host).await;
    let held = tasks.hold().await;
    keys.release(&host.runtime);
    until("the shell to mark that it has printed its line", || {
        printed.exists()
    })
    .await;
    let (_, gate) = host.runtime.close(ClosureReason::CloseRequested);
    gate.release();
    let _ = tokio::time::timeout(
        kr_worker::session::GRACE_PERIOD + kr_worker::session::DRAIN_PERIOD + RECORD_ALLOWANCE,
        host.runtime.wait_closed(),
    )
    .await;
    drop(held);
    let record = closed(&host).await;
    assert_eq!(record.reason, ClosureReason::CloseRequested);
    for (client, what) in [(&mut typing, "the typing"), (&mut watcher, "the watching")] {
        let (output, sent) = until_the_closure(client).await;
        assert!(
            carries(&output, b"kr-read-before-the-closure"),
            "{what} attachment was sent the line the worker had read before the closure: {}",
            String::from_utf8_lossy(&output).escape_debug()
        );
        assert_eq!(
            sent, record,
            "{what} attachment was sent the session's own record"
        );
    }
}
