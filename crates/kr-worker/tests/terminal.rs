//! The terminal-engine boundary, over the worker's own endpoint.
//!
//! Section 8 makes the host the terminal, not whatever is attached to it. Three consequences are
//! only observable end to end, with a real shell writing real sequences into a real pseudo-terminal
//! and a real client reading them off a socket:
//!
//! * a query the application asks is answered once, by the host, and reaches no attached terminal;
//! * an attachment that joins mid-session is drawn the screen as it is, not replayed the bytes that
//!   produced it, so a bell that rang an hour ago does not ring again in somebody's office;
//! * a terminal of another size is shown a rendering of the canonical grid rather than a byte
//!   stream that assumes the session's width.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, TerminalPresentationMode,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{ActionId, BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The session's own size. An attachment of exactly this size takes the stream directly.
const CANONICAL: (u64, u64) = (80, 24);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    _runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host(script: &str) -> Host {
    host_sized(script, Dimensions::new(CANONICAL.0, CANONICAL.1)).await
}

async fn host_sized(script: &str, canonical: Dimensions) -> Host {
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
    let store = kr_crypto::store::open_store("KalaReachTerminal", &environment.secrets_dir())
        .expect("a secret store");
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: canonical,
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 1024 * 1024,
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
        _runtime: runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

/// Attaches a terminal of `dimensions` and subscribes it to output.
async fn attached(
    host: &Host,
    dimensions: Dimensions,
) -> (
    LocalClient,
    Option<TerminalPresentationMode>,
    kr_protocol::ids::AttachmentId,
) {
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
                dimensions: Nullable::some(dimensions),
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
    let presentation = attached.attachment.presentation.as_ref().copied();
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id: attached.attachment.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
    (client, presentation, attached.attachment.attachment_id)
}

/// Collects each output payload the worker sends this client for `window`, one per notification.
///
/// A direct attachment receives spans of the raw stream; a projection receives whole repaints of
/// the canonical screen. Which one a client is being served is visible in the payloads themselves,
/// which is why these are kept apart rather than run together.
async fn collect_payloads(client: &mut LocalClient, window: Duration) -> Vec<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        if let ControlFrame::Notification(notification) = frame
            && notification.event_type.as_str() == "session.output"
            && let Ok(event) = notification
                .payload
                .to_typed::<kr_protocol::recovery::OutputEvent>()
        {
            seen.push(event.bytes.as_slice().to_vec());
        }
    }
    seen
}

/// Collects payloads until one of them carries `marker`, and then for `window` longer.
///
/// The same two halves as [`collect_until`], kept apart for the same reason, with the payload
/// boundaries preserved: a test that asks what a repaint carried needs the repaints themselves and
/// not one run-together stream.
async fn collect_payloads_until(
    client: &mut LocalClient,
    marker: &[u8],
    window: Duration,
) -> Vec<Vec<u8>> {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut seen: Vec<Vec<u8>> = Vec::new();
    while !seen
        .iter()
        .any(|payload| payload.windows(marker.len()).any(|slice| slice == marker))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {:?} for a payload carrying {:?}: {:?}",
            started.elapsed(),
            String::from_utf8_lossy(marker),
            seen.iter()
                .map(|payload| String::from_utf8_lossy(payload).into_owned())
                .collect::<Vec<_>>()
        );
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining.min(Duration::from_secs(1)), client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                if let Ok(event) = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    seen.push(event.bytes.as_slice().to_vec());
                }
            }
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => panic!(
                "waited {:?} for a payload carrying {:?} and the connection ended ({error})",
                started.elapsed(),
                String::from_utf8_lossy(marker)
            ),
        }
    }
    seen.extend(collect_payloads(client, window).await);
    seen
}

/// Collects until `marker` has arrived, and then for `window` longer.
///
/// The two halves answer different questions. Whether the marker arrives at all is a liveness wait,
/// and a host with several suites on it can take far longer over it than the window a test wants to
/// watch afterwards; what arrives *beside* the marker is what that window is for, and lengthening
/// it would only make the suite slower. So the wait is bounded by [`LIVENESS_DEADLINE`] and the
/// window keeps its own length, and a marker that never arrives fails here, saying how long it
/// waited and for what.
async fn collect_until(client: &mut LocalClient, marker: &[u8], window: Duration) -> Vec<u8> {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut seen: Vec<u8> = Vec::new();
    while !seen.windows(marker.len()).any(|slice| slice == marker) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {:?} for {:?} to reach this terminal: {:?}",
            started.elapsed(),
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(&seen)
        );
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining.min(Duration::from_secs(1)), client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                if let Ok(event) = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    seen.extend_from_slice(event.bytes.as_slice());
                }
            }
            // A quiet moment is a busy machine, so the loop keeps looking; a connection that has
            // gone can never deliver the marker, and that is this wait's failure rather than a
            // partial answer for the caller to puzzle over.
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => panic!(
                "waited {:?} for {:?} to reach this terminal and the connection ended ({error}): \
                 {:?}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&seen)
            ),
        }
    }
    seen.extend_from_slice(&collect(client, window).await);
    seen
}

/// How long a wait for something to arrive is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never arrives. The
/// windows these waits had were inside the range the slowest reference hosts reach when several
/// suites share them; two minutes is outside it. The observation windows beside them are not waits
/// and keep their own lengths.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Collects everything the worker sends this client for `window`.
async fn collect(client: &mut LocalClient, window: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        if let ControlFrame::Notification(notification) = frame
            && notification.event_type.as_str() == "session.output"
            && let Ok(event) = notification
                .payload
                .to_typed::<kr_protocol::recovery::OutputEvent>()
        {
            seen.extend_from_slice(event.bytes.as_slice());
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_is_answered_by_the_host_and_reaches_no_attached_terminal() {
    // The shell asks the terminal what it is. A host that forwarded the question would have the
    // attached terminal answer it, and two attachments would answer it twice; a host that answered
    // nothing would leave an application that waits for a reply waiting for ever.
    //
    // The answer goes into the terminal's input, where the line discipline echoes it back out as
    // ordinary text. That echo is what makes the answer visible from outside the process.
    let host = host("printf '\\033[c'; sleep 20").await;
    let (mut client, presentation, _) =
        attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Direct),
        "the terminal is the session's size"
    );
    let seen = collect_until(&mut client, b"[?62;22c", Duration::from_secs(4)).await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(
        !text.contains("\u{1b}[c"),
        "the question never reaches an attached terminal: {text:?}"
    );
    assert!(
        text.contains("[?62;22c"),
        "the host's own answer was written into the application's input, where the terminal \
         echoed it: {text:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joining_late_draws_the_screen_rather_than_replaying_what_made_it() {
    // A bell, a clipboard write and some text, all before anybody attaches. What the attachment
    // gets is the text, on a screen; what it must not get is the bell or the clipboard write, which
    // were events when they happened and are not events now.
    let host = host("printf 'visible-line\\a\\033]52;c;aGVsbG8=\\033\\\\\\n'; sleep 20").await;
    // Enough for the shell to run and the worker to consume it.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (mut client, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    let seen = collect_until(&mut client, b"visible-line", Duration::from_secs(2)).await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(
        text.contains("visible-line"),
        "the screen's text is drawn: {text:?}"
    );
    assert!(
        !seen.contains(&0x07),
        "the bell does not ring again for somebody who was not there"
    );
    assert!(
        !text.contains("]52;"),
        "the clipboard is not written again: {text:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_of_another_size_is_projected_rather_than_sent_the_raw_stream() {
    let host = host("printf 'first\\nsecond\\n'; sleep 20").await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    // Half the session's width and height. A byte stream that assumed 80 columns would wrap this
    // terminal's lines in the wrong places and leave its cursor somewhere else entirely.
    let (mut client, presentation, _) = attached(&host, Dimensions::new(40, 12)).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal that is not the session's size is shown a projection"
    );
    let seen = collect_until(&mut client, b"first", Duration::from_secs(2)).await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(text.contains("first"), "the screen is drawn: {text:?}");
    // A projection places every row itself, which is what makes it independent of this terminal's
    // width. The absolute cursor address is how it does that.
    assert!(
        text.contains("\u{1b}[1;1H"),
        "the rows are placed rather than wrapped: {text:?}"
    );
    // Nothing is placed past the twelve rows this terminal has.
    assert!(
        !text.contains("\u{1b}[13;1H"),
        "no row is placed outside the viewport: {text:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_reaches_the_lease_holder_and_nobody_else() {
    let host = host("sleep 1; printf '\\a'; sleep 20").await;
    let (mut holder, _, held) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    let (mut watcher, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    // One of them takes the input lease, which is what makes it the single destination.
    holder
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(host.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id: held,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the lease is taken");

    let held = collect_until(&mut holder, &[0x07], Duration::from_secs(3)).await;
    let watched = collect(&mut watcher, Duration::from_secs(1)).await;
    assert!(
        held.contains(&0x07),
        "the bell reaches the attachment holding the input lease"
    );
    assert!(
        !watched.contains(&0x07),
        "and reaches nobody else, because a side effect has one destination"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_screen_a_restoration_cannot_carry_is_never_continued_as_a_raw_stream() {
    // Four columns, and the application has printed exactly four characters. The canonical grid
    // holds `abcd` with a pending wrap: the next character belongs on the row below. No sequence
    // sets a pending wrap, so a restoration cannot put a physical terminal into that state, and a
    // terminal given the raw `X` afterwards would replace the `d` instead of wrapping.
    let host = host_sized(
        "printf 'abcd'; sleep 1; printf 'X'; sleep 20",
        Dimensions::new(4, 5),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (mut client, _, _) = attached(&host, Dimensions::new(4, 5)).await;

    let payloads = collect_payloads_until(&mut client, b"X", Duration::from_secs(4)).await;
    let text: Vec<String> = payloads
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect();
    let carrying = text
        .iter()
        .filter(|payload| payload.contains('X'))
        .collect::<Vec<_>>();
    assert!(
        !carrying.is_empty(),
        "the attachment was shown the character the application printed: {text:?}"
    );
    for payload in carrying {
        assert!(
            payload.contains("abcd") && payload.contains("\u{1b}["),
            "the character arrives inside a repaint of the canonical screen rather than as a span \
             of the raw stream: {payload:?}"
        );
    }
}
