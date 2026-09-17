//! The snapshot and delta protocol, over the worker's own endpoint.
//!
//! A projected attachment used to be sent a rendering of the whole screen after every batch of
//! output. Section 8 forbids exactly that, and these tests are the evidence for what replaced it:
//! one snapshot, its rows in bounded pages, and then one bounded update per batch, each naming the
//! base it continues from.
//!
//! Everything here runs end to end — a real shell writing real sequences into a real
//! pseudo-terminal, and a real client reading notifications off a socket — because the properties
//! at stake are properties of what arrives at a client, not of a function's return value.

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
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::projection::{
    MAX_PROJECTION_PAGE_ROWS, PaletteProvenance, ProjectedBuffer, ProjectionDelta, ProjectionReset,
    ProjectionResetReason, ProjectionRowPage, ProjectionSnapshot,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams, EventsSubscribeResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use kr_worker::snapshot::PaletteChoice;

/// The session's own size. An attachment of exactly this size takes the stream directly.
const CANONICAL: (u64, u64) = (80, 24);

/// A terminal of another size, which is therefore projected.
const SMALLER: (u64, u64) = (40, 10);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host(script: &str) -> Host {
    host_with(
        script,
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await
}

async fn host_with(
    script: &str,
    canonical: Dimensions,
    palette: Option<PaletteChoice>,
    send_queue_bytes: usize,
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
    let store = kr_crypto::store::open_store("KalaReachSnapshot", &environment.secrets_dir())
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
        send_queue_bytes,
        resident_bytes: 1024 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    // The palette is chosen at creation, before anything has been produced. That is the only
    // moment it can be chosen honestly, which is why the seam is here and not on an attachment.
    if let Some(choice) = palette {
        session
            .set_initial_palette(choice)
            .expect("the palette is chosen before the session produces anything");
    }
    session.launch().expect("launches the shell");
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts the runtime"));

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

fn target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// One attachment and the connection it lives on.
struct Attached {
    client: LocalClient,
    attachment_id: AttachmentId,
    presentation: Option<TerminalPresentationMode>,
    subscribed: EventsSubscribeResult,
}

async fn attach(host: &Host, dimensions: Dimensions, profile: Option<&str>) -> Attached {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &SessionAttachParams {
                session_id: host.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable(profile.map(str::to_owned)),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    let presentation = attached.attachment.presentation.as_ref().copied();
    let attachment_id = attached.attachment.attachment_id;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    let subscribed: EventsSubscribeResult = client
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
        .expect("the subscription succeeds")
        .to_typed()
        .expect("decodes");
    Attached {
        client,
        attachment_id,
        presentation,
        subscribed,
    }
}

/// Attaches a client that claims the session's size, which is how a live resize happens.
///
/// A resize is not a client's own window changing: it is the *session's* geometry moving, which
/// every other attachment then sees. Only the owner can move it, so a test that wants a live resize
/// has to take the geometry first.
async fn attach_claiming(host: &Host, dimensions: Dimensions, profile: Option<&str>) -> Attached {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    // The claim needs the right as well as the flag: a terminal that asked to own the size and was
    // not granted the capability is not an owner, which is the rule this helper has to satisfy to
    // move the session's geometry at all.
    requested.insert(AttachmentCapability::Geometry);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &SessionAttachParams {
                session_id: host.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: true,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable(profile.map(str::to_owned)),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    let presentation = attached.attachment.presentation.as_ref().copied();
    let attachment_id = attached.attachment.attachment_id;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    let subscribed: EventsSubscribeResult = client
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
        .expect("the subscription succeeds")
        .to_typed()
        .expect("decodes");
    Attached {
        client,
        attachment_id,
        presentation,
        subscribed,
    }
}

/// One thing a projected client received, decoded.
#[derive(Debug)]
enum Event {
    Reset(ProjectionReset),
    Snapshot(Box<ProjectionSnapshot>),
    Rows(ProjectionRowPage),
    Delta(Box<ProjectionDelta>),
    Resync(kr_protocol::recovery::ResyncRequired),
    /// Anything else the session published, named so a test can prove it did not arrive.
    Other(#[expect(dead_code, reason = "read through Debug when a test reports one")] String),
}

/// Collects what a client receives for `window`.
async fn collect(client: &mut LocalClient, window: Duration) -> Vec<Event> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        let event = match notification.event_type.as_str() {
            "session.projection.reset" => notification
                .payload
                .to_typed()
                .map(Event::Reset)
                .unwrap_or_else(|error| Event::Other(error.to_string())),
            "session.projection.snapshot" => notification
                .payload
                .to_typed()
                .map(|header| Event::Snapshot(Box::new(header)))
                .unwrap_or_else(|error| Event::Other(error.to_string())),
            "session.projection.rows" => notification
                .payload
                .to_typed()
                .map(Event::Rows)
                .unwrap_or_else(|error| Event::Other(error.to_string())),
            "session.projection.delta" => notification
                .payload
                .to_typed()
                .map(|delta| Event::Delta(Box::new(delta)))
                .unwrap_or_else(|error| Event::Other(error.to_string())),
            "session.resync" => notification
                .payload
                .to_typed()
                .map(Event::Resync)
                .unwrap_or_else(|error| Event::Other(error.to_string())),
            other => Event::Other(other.to_owned()),
        };
        seen.push(event);
    }
    seen
}

/// Collects until the snapshot's last row page has arrived, or the window runs out.
async fn collect_until_installed(client: &mut LocalClient, window: Duration) -> Vec<Event> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        let complete = notification.event_type.as_str() == "session.projection.rows"
            && notification
                .payload
                .to_typed::<ProjectionRowPage>()
                .map(|page| !page.more)
                .unwrap_or_default();
        let event = match notification.event_type.as_str() {
            "session.projection.reset" => notification.payload.to_typed().map(Event::Reset).ok(),
            "session.projection.snapshot" => notification
                .payload
                .to_typed()
                .map(|header| Event::Snapshot(Box::new(header)))
                .ok(),
            "session.projection.rows" => notification.payload.to_typed().map(Event::Rows).ok(),
            "session.projection.delta" => notification
                .payload
                .to_typed()
                .map(|delta| Event::Delta(Box::new(delta)))
                .ok(),
            other => Some(Event::Other(other.to_owned())),
        };
        if let Some(event) = event {
            seen.push(event);
        }
        if complete {
            break;
        }
    }
    seen
}

/// Collects until this client is told to resynchronise, so the answer is immediate.
async fn collect_until_resync(
    client: &mut LocalClient,
    window: Duration,
) -> Option<kr_protocol::recovery::ResyncRequired> {
    let deadline = tokio::time::Instant::now() + window;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        if notification.event_type.as_str() == "session.resync"
            && let Ok(required) = notification
                .payload
                .to_typed::<kr_protocol::recovery::ResyncRequired>()
        {
            return Some(required);
        }
    }
    None
}

/// Subscribes again from a cursor, which is what a client does when it is told to resynchronise.
async fn resubscribe(host: &Host, attached: &mut Attached, from: u64) -> EventsSubscribeResult {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    attached
        .client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id: attached.attachment_id,
                streams,
                from_cursor: Nullable::some(kr_protocol::scalars::U64::new(from)),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds")
        .to_typed()
        .expect("decodes")
}

/// Collects the output batches a client receives for `window`, with the cursor each begins at.
async fn collect_output(client: &mut LocalClient, window: Duration) -> Vec<(u64, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        if notification.event_type.as_str() != "session.output" {
            continue;
        }
        if let Ok(event) = notification
            .payload
            .to_typed::<kr_protocol::recovery::OutputEvent>()
        {
            seen.push((event.cursor.get(), event.bytes.as_slice().to_vec()));
        }
    }
    seen
}

fn text_of(page: &ProjectionRowPage) -> Vec<String> {
    page.rows
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect()
}

/// KR-REQ-08.78 and KR-REQ-08.83: a snapshot carries the whole of what a screen is, then its rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_carries_the_state_of_a_screen_and_then_its_rows_in_pages() {
    // A screen in a state of its own, so that what the snapshot carries is the session's answer
    // rather than the defaults agreeing with the defaults: a window title and one pushed onto the
    // stack, a saved cursor, a scroll region, a mode the application turned on, a tab stop it set,
    // and the alternate character set designated as G1.
    let host = host(
        "printf 'hello from the session\\r\\n'; \
         printf '\\033]2;a session with a title\\033\\\\'; \
         printf '\\033[22;2t'; \
         printf '\\033]2;the title on top\\033\\\\'; \
         printf '\\0337'; \
         printf '\\033[3;18r'; \
         printf '\\033[?1000h'; \
         printf '\\033[5;1H\\033H'; \
         printf '\\033)0'; \
         sleep 20",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    assert_eq!(
        attached.presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal of another size is projected"
    );
    let events = collect_until_installed(&mut attached.client, Duration::from_secs(5)).await;

    let Some(Event::Reset(reset)) = events.first() else {
        panic!("the first thing a projected client receives is a reset: {events:?}");
    };
    assert_eq!(
        reset.reason,
        ProjectionResetReason::Attached,
        "and it says why"
    );

    let Some(Event::Snapshot(header)) = events.get(1) else {
        panic!("then the state of the screen: {events:?}");
    };
    assert_eq!(
        header.projection_generation, reset.projection_generation,
        "the snapshot belongs to the generation the reset named"
    );
    assert_eq!(
        header.output_cursor.get(),
        attached.subscribed.from_cursor.get(),
        "and it describes the cursor the subscription starts from"
    );
    assert_eq!(header.active_buffer, ProjectedBuffer::Primary);
    assert_eq!(
        header.dimensions,
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        "the canonical dimensions are the session's, not this client's"
    );
    assert_eq!(
        header.viewport.columns.get(),
        SMALLER.0,
        "and the viewport is this client's own window on them"
    );
    assert_eq!(header.viewport.rows.get(), SMALLER.1);
    assert!(
        header.modes.iter().any(|mode| mode.mode.get() == 7),
        "the mode state is carried: a client that did not know about autowrap could not put a \
         terminal back into it"
    );
    assert!(
        !header.tab_stops.is_empty(),
        "so are the tab stops, which a restoration has to reproduce"
    );
    assert!(
        header.cursor.column.get() <= CANONICAL.0,
        "the cursor is a canonical position"
    );
    // And every other field the requirement names, against a session that set each of them. A
    // snapshot that carried the defaults would pass an assertion that only checked a field was
    // present.
    assert_eq!(
        header.title.window, "the title on top",
        "the title the application set is the title the snapshot carries"
    );
    assert!(
        header
            .title_stack
            .iter()
            .any(|entry| entry.window.0.as_deref() == Some("a session with a title")),
        "and the stack it pushed one onto, which a restoration cannot rebuild from the screen: \
         {:?}",
        header.title_stack
    );
    assert_eq!(
        (header.margins.top.get(), header.margins.bottom.get()),
        (2, 17),
        "the scroll region is the one the application set, zero-based"
    );
    let saved = header
        .saved_cursors
        .iter()
        .find(|saved| saved.buffer == ProjectedBuffer::Primary)
        .expect("the cursor this session saved");
    assert_eq!(
        (saved.column.get(), saved.row.get()),
        (0, 1),
        "the cursor this session saved is carried where it was saved, because nothing on the \
         screen says where that was: the application printed one line and saved the cursor after \
         it"
    );
    assert!(
        header
            .modes
            .iter()
            .any(|mode| mode.mode.get() == 1000 && mode.enabled),
        "a mode the application turned on is carried as on: {:?}",
        header.modes
    );
    assert!(
        header.tab_stops.iter().any(|stop| stop.get() == 0),
        "the tab stop it set is among them: {:?}",
        header.tab_stops
    );
    assert_eq!(
        header.charsets.g1, "DecLineDrawing",
        "and the character set it designated, which decides what its next output means"
    );

    let pages: Vec<&ProjectionRowPage> = events
        .iter()
        .filter_map(|event| match event {
            Event::Rows(page) => Some(page),
            _ => None,
        })
        .collect();
    assert!(!pages.is_empty(), "the rows follow the state: {events:?}");
    assert!(
        pages
            .iter()
            .all(|page| page.rows.len() as u64 <= MAX_PROJECTION_PAGE_ROWS),
        "every page is inside the row bound"
    );
    assert!(
        pages.iter().take(pages.len() - 1).all(|page| page.more),
        "every page but the last says more follow"
    );
    assert!(
        !pages[pages.len() - 1].more,
        "and the last one says the screen is complete"
    );
    assert!(
        pages
            .iter()
            .all(|page| page.output_cursor == header.output_cursor),
        "every page belongs to the snapshot it completes"
    );
    let drawn: Vec<String> = pages
        .iter()
        .filter(|page| page.buffer == ProjectedBuffer::Primary)
        .flat_map(|page| text_of(page))
        .collect();
    assert!(
        drawn
            .iter()
            .any(|row| row.contains("hello from the session")),
        "the rows carry what the application wrote: {drawn:?}"
    );
    let ordered: Vec<u64> = pages
        .iter()
        .filter(|page| page.buffer == ProjectedBuffer::Primary)
        .flat_map(|page| page.rows.iter().map(|row| row.row.get()))
        .collect();
    let mut sorted = ordered.clone();
    sorted.sort_unstable();
    assert_eq!(ordered, sorted, "rows arrive in stable-identifier order");
    assert!(
        pages
            .iter()
            .any(|page| page.buffer == ProjectedBuffer::Alternate),
        "both buffers are carried, so leaving a full-screen application finds the shell as it was"
    );
}

/// KR-REQ-08.57, KR-REQ-08.83: ordinary output is a bounded update, never a repaint per batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_projected_attachment_receives_bounded_updates_rather_than_a_repaint_per_batch() {
    // Three separate batches, far enough apart that the read loop sees three reads.
    let host = host(
        "printf 'first\\r\\n'; sleep 0.4; printf 'second\\r\\n'; sleep 0.4; \
         printf 'third\\r\\n'; sleep 20",
    )
    .await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let events = collect(&mut attached.client, Duration::from_secs(4)).await;

    let snapshots = events
        .iter()
        .filter(|event| matches!(event, Event::Snapshot(_)))
        .count();
    assert_eq!(
        snapshots, 1,
        "one snapshot installs the client, and nothing repaints it afterwards: {events:?}"
    );
    let deltas: Vec<&ProjectionDelta> = events
        .iter()
        .filter_map(|event| match event {
            Event::Delta(delta) => Some(delta.as_ref()),
            _ => None,
        })
        .collect();
    assert!(
        deltas.len() >= 2,
        "the batches after the snapshot arrive as updates: {events:?}"
    );
    for delta in &deltas {
        assert!(
            (delta.rows.len() as u64) < CANONICAL.1,
            "an update carries the rows that changed, not the screen: {} of {} rows",
            delta.rows.len(),
            CANONICAL.1
        );
    }
    // And they carry the application's output rather than being empty messages with a valid cursor
    // chain: each batch's text is in the rows of one of them.
    let carried: Vec<String> = deltas
        .iter()
        .flat_map(|delta| {
            delta.rows.iter().map(|row| {
                row.runs
                    .iter()
                    .map(|run| run.text.as_str())
                    .collect::<String>()
            })
        })
        .collect();
    for batch in ["second", "third"] {
        assert!(
            carried.iter().any(|row| row.contains(batch)),
            "the {batch} batch reached the client as an update: {carried:?}"
        );
    }
    // The updates chain: each one continues from the cursor the previous one ended at.
    let mut held = events
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.output_cursor.get()),
            _ => None,
        })
        .expect("a snapshot");
    for delta in &deltas {
        assert_eq!(
            delta.base_cursor.get(),
            held,
            "every update names the base it continues from"
        );
        held = delta.next_cursor.get();
    }
}

/// KR-REQ-08.80: a client subscribes from a cursor, and the state it is given is the state there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribing_returns_the_state_at_a_cursor_and_queues_what_follows() {
    let host =
        host("printf 'before anybody attached\\r\\n'; sleep 0.6; printf 'after\\r\\n'; sleep 20")
            .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let at = attached.subscribed.from_cursor.get();
    assert!(
        at > 0,
        "the session had produced output before this client arrived"
    );
    let events = collect(&mut attached.client, Duration::from_secs(3)).await;
    let header = events
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(
        header.output_cursor.get(),
        at,
        "the state is the state at the cursor the subscription named"
    );
    let first = events
        .iter()
        .find_map(|event| match event {
            Event::Delta(delta) => Some(delta.as_ref()),
            _ => None,
        })
        .expect("an update for the output that followed");
    assert_eq!(
        first.base_cursor.get(),
        at,
        "and what followed is queued after it, with nothing in between"
    );
    let pages: Vec<&ProjectionRowPage> = events
        .iter()
        .filter_map(|event| match event {
            Event::Rows(page) => Some(page),
            _ => None,
        })
        .collect();
    let drawn: Vec<String> = pages.iter().flat_map(|page| text_of(page)).collect();
    assert!(
        drawn
            .iter()
            .any(|row| row.contains("before anybody attached")),
        "the screen it is given is the screen as it is, not the bytes that made it: {drawn:?}"
    );
    // And what followed the cursor arrived as rows, not merely as a delta with the right base: a
    // subscription that named the state at a cursor and then delivered nothing of what came after
    // it would satisfy every assertion above.
    let updated: Vec<String> = events
        .iter()
        .filter_map(|event| match event {
            Event::Delta(delta) => Some(
                delta
                    .rows
                    .iter()
                    .map(|row| {
                        row.runs
                            .iter()
                            .map(|run| run.text.as_str())
                            .collect::<String>()
                    })
                    .collect::<Vec<String>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        updated.iter().any(|row| row.contains("after")),
        "the output that followed the cursor was delivered as the rows it changed: {updated:?}"
    );
}

/// KR-REQ-08.83: a buffer switch replaces the screen, so it sends an explicit projection reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_buffer_switch_sends_an_explicit_projection_reset() {
    let host = host(
        "printf 'the shell\\r\\n'; sleep 0.6; printf '\\033[?1049h'; printf 'the application\\r\\n'; \
         sleep 20",
    )
    .await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let events = collect(&mut attached.client, Duration::from_secs(4)).await;

    let resets: Vec<&ProjectionReset> = events
        .iter()
        .filter_map(|event| match event {
            Event::Reset(reset) => Some(reset),
            _ => None,
        })
        .collect();
    assert!(
        resets
            .iter()
            .any(|reset| reset.reason == ProjectionResetReason::BufferSwitch),
        "the switch into the alternate buffer is a reset and says so: {events:?}"
    );
    let generations: Vec<u64> = resets
        .iter()
        .map(|reset| reset.projection_generation.get())
        .collect();
    assert!(
        generations.windows(2).all(|pair| pair[1] > pair[0]),
        "and each reset is a new generation, so the same cursor cannot name two screens: \
         {generations:?}"
    );
    let switched = events
        .iter()
        .filter_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .next_back()
        .expect("a snapshot after the switch");
    assert_eq!(
        switched.active_buffer,
        ProjectedBuffer::Alternate,
        "the fresh snapshot says which buffer is showing"
    );
}

/// KR-REQ-08.82: restoration emits rendering only, whatever the history contained.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_projection_carries_no_side_effect_the_history_contained() {
    // A bell, a clipboard write, a desktop notification, a title change, a hyperlink and a query,
    // all before anybody attaches. Only two of those are state; the rest happened.
    let host = host(
        "printf '\\a'; printf '\\033]52;c;c2VjcmV0\\033\\\\'; printf '\\033]99;;hello\\033\\\\'; \
         printf '\\033]2;a title\\033\\\\'; printf '\\033]8;;https://example.invalid/g\\033\\\\linked\\033]8;;\\033\\\\\\r\\n'; \
         printf '\\033[c'; sleep 20",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let events = collect_until_installed(&mut attached.client, Duration::from_secs(5)).await;

    // Nothing but the four projection events arrives. There is no variant that can ring, copy,
    // notify, download, launch or ask anything, so the closure is the proof.
    for event in &events {
        assert!(
            !matches!(event, Event::Other(_)),
            "a projected client receives projection events and nothing else: {event:?}"
        );
    }
    let header = events
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(
        header.title.window, "a title",
        "a title is state, so it is restored"
    );
    let linked: Vec<String> = events
        .iter()
        .filter_map(|event| match event {
            Event::Rows(page) => Some(page),
            _ => None,
        })
        .flat_map(|page| {
            page.rows.iter().flat_map(|row| {
                row.runs
                    .iter()
                    .filter_map(|run| run.hyperlink.as_ref().cloned())
            })
        })
        .collect();
    assert_eq!(
        linked,
        vec!["https://example.invalid/g".to_owned()],
        "a hyperlink is inert metadata on the cells it covers, restored so a later click works"
    );
}

/// KR-ACC-002: a hyperlink is still there, and still inert, after a reconnection and a resize.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hyperlink_survives_a_reconnection_and_a_resize() {
    let host = host(
        "printf '\\033]8;;https://example.invalid/guide\\033\\\\the guide\\033]8;;\\033\\\\\\r\\n'; sleep 20",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let link_of = |events: &[Event]| -> Vec<(u64, u64, u64, String)> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Rows(page) => Some(page),
                _ => None,
            })
            .flat_map(|page| {
                page.rows.iter().flat_map(|row| {
                    let id = row.row.get();
                    row.runs.iter().filter_map(move |run| {
                        run.hyperlink.as_ref().map(|uri| {
                            (
                                id,
                                run.column.get(),
                                run.column.get() + run.cells.get(),
                                uri.clone(),
                            )
                        })
                    })
                })
            })
            .collect()
    };

    let mut first = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let before = collect_until_installed(&mut first.client, Duration::from_secs(5)).await;
    let ranges = link_of(&before);
    assert_eq!(ranges.len(), 1, "the link covers its own cells: {ranges:?}");
    assert_eq!(ranges[0].3, "https://example.invalid/guide");
    drop(first);

    // A different size, on a new connection: the reconnection.
    let mut second = attach(&host, Dimensions::new(30, 8), Some("xterm-256color")).await;
    let after = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    let again = link_of(&after);
    assert_eq!(
        again, ranges,
        "the same range over the same cells of the same row, which is what an activation needs"
    );

    // And a live resize: the *session's* geometry moves under a client that is already watching.
    // Wider and taller, so nothing rewraps and the cells the link covers are the cells it covered:
    // a link that moved with a reflow would be a different question from a link that survived.
    let owner = attach_claiming(
        &host,
        Dimensions::new(CANONICAL.0 + 10, CANONICAL.1 + 4),
        Some("xterm-256color"),
    )
    .await;
    let resized = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    assert!(
        resized
            .iter()
            .any(|event| matches!(event, Event::Reset(reset)
                if reset.reason == ProjectionResetReason::Geometry)),
        "the watching client is told the geometry moved, rather than left to infer it: {resized:?}"
    );
    let header = resized
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a fresh screen follows the reset");
    assert_eq!(
        header.dimensions,
        Dimensions::new(CANONICAL.0 + 10, CANONICAL.1 + 4),
        "the screen it is given is the session's new size"
    );
    let after_resize = link_of(&resized);
    assert_eq!(
        after_resize, ranges,
        "and the link is over the same cells of the same row afterwards"
    );
    let _ = owner;
}

/// KR-REQ-08.83: a resize draws every client's fresh screen for the window that client has now.
///
/// The owner's own window is one of the things a resize changes, and the screen it is then given is
/// drawn for a window: a fresh screen built before the new window was recorded would carry the new
/// grid inside the old window, and for an idle application nothing would ever correct it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resize_draws_the_owners_fresh_screen_for_its_new_window() {
    let host = host("printf 'before the resize\r\n'; sleep 20").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // An owner with no declared profile: it owns the size and is still projected, because nothing
    // qualifies it to be handed the stream. That is the attachment whose window a resize moves.
    let mut owner = attach_claiming(&host, Dimensions::new(CANONICAL.0, CANONICAL.1), None).await;
    assert_eq!(
        owner.presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal that declared no profile is projected, whatever it owns"
    );
    let installed = collect_until_installed(&mut owner.client, Duration::from_secs(5)).await;
    let epoch = installed
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.viewport.columns.get()),
            _ => None,
        })
        .expect("a screen");
    assert_eq!(epoch, CANONICAL.0, "at the size it attached with");

    // The terminal's window changed, which is what a resize is.
    let geometry: kr_protocol::attachment::GeometryResult = owner
        .client
        .mutate(
            Method::TerminalResize,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::attachment::TerminalResizeParams {
                attachment_id: owner.attachment_id,
                dimensions: Dimensions::new(CANONICAL.0 + 10, CANONICAL.1 + 4),
                expected_geometry_epoch: kr_protocol::ids::GeometryEpoch::new(1),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the resize succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        geometry.geometry.dimensions,
        Dimensions::new(CANONICAL.0 + 10, CANONICAL.1 + 4),
        "the session took the size"
    );
    let after = collect_until_installed(&mut owner.client, Duration::from_secs(5)).await;
    let header = after
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a fresh screen after the resize");
    assert_eq!(
        header.dimensions,
        Dimensions::new(CANONICAL.0 + 10, CANONICAL.1 + 4),
        "the canonical size is the new one"
    );
    assert_eq!(
        (header.viewport.columns.get(), header.viewport.rows.get()),
        (CANONICAL.0 + 10, CANONICAL.1 + 4),
        "and so is the window it is drawn for"
    );
}

/// KR-REQ-08.44: the palette's provenance is recorded at creation and succession never moves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_palette_source_is_recorded_at_creation_and_succession_does_not_change_it() {
    let host = host_with(
        "sleep 20",
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        Some(PaletteChoice::DarkPreset),
        1024 * 1024,
    )
    .await;

    let mut first = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let before = collect_until_installed(&mut first.client, Duration::from_secs(5)).await;
    let mine = before
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.palette.clone()),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(
        mine.source,
        PaletteProvenance::DarkPreset,
        "the preset chosen at creation is what the session reports"
    );
    drop(first);

    // A second attachment, a different terminal, a different size. Section 8: attachment
    // succession does not silently change the palette.
    let mut second = attach(&host, Dimensions::new(30, 8), Some("xterm-kitty")).await;
    let after = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    let theirs = after
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.palette.clone()),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(
        theirs, mine,
        "the session's palette and its provenance are what every client is shown"
    );
}

/// KR-ACC-007 and KR-REQ-08.80: a slow projected client resynchronises and holds nothing up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_projected_client_is_resynchronised_and_the_session_carries_on() {
    // A queue small enough that a screen and a few updates fill it, and an application producing
    // output steadily. The slow client never reads; the quick one does.
    // The stream outlasts this test on purpose: what it proves is that the session keeps reading
    // *after* the slow client's queue fills, and an application that had stopped printing by then
    // would prove it by standing still.
    let host = host_with(
        "i=0; while [ $i -lt 3000 ]; do printf 'line %d of a steady stream\\r\\n' $i; \
         i=$((i+1)); sleep 0.01; done; sleep 20",
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        16 * 1024,
    )
    .await;
    let slow = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let mut quick = attach(&host, Dimensions::new(30, 8), Some("xterm-256color")).await;

    // The quick client keeps reading while the slow one does not read at all.
    let seen = collect(&mut quick.client, Duration::from_secs(4)).await;
    assert!(
        seen.iter().any(|event| matches!(event, Event::Delta(_))),
        "the session kept publishing to the client that was keeping up: {} events",
        seen.len()
    );

    let mut slow = slow;
    let theirs = collect(&mut slow.client, Duration::from_secs(4)).await;
    assert!(
        theirs.iter().any(|event| matches!(event, Event::Resync(_))),
        "and the slow one was told to resynchronise rather than being waited for: {} events",
        theirs.len()
    );
    let marker = theirs
        .iter()
        .find_map(|event| match event {
            Event::Resync(marker) => Some(marker),
            _ => None,
        })
        .expect("a marker");
    assert_eq!(
        marker.reason,
        kr_protocol::recovery::ResyncReason::SendQueueFull,
        "and it says why"
    );

    // The promise is about what happens *after* that queue fills, so the test measures from there:
    // the session's own read loop must keep going while this client is still not reading, and the
    // client that is reading must keep being served.
    assert!(
        host.runtime
            .session()
            .is_resynchronising(slow.attachment_id),
        "the session is holding this subscriber's place rather than waiting for it"
    );
    let at_overflow = host.runtime.session().output_cursor();
    let after = collect(&mut quick.client, Duration::from_secs(3)).await;
    let afterwards = host.runtime.session().output_cursor();
    assert!(
        afterwards > at_overflow,
        "the terminal was still being read after the queue filled: the output cursor stood at \
         {at_overflow} and is at {afterwards}"
    );
    // And what became of the client that was reading, named rather than inferred. It reads in
    // windows, so on a host that delivers faster than those windows it can fall behind too: the
    // same rule then applies to it and its own queue is the reason. What it must never be is a
    // client left with a hole and no word, and a subscriber that has been told to resynchronise is
    // sent nothing until it asks again, which is why "no events" is an answer here and not a
    // failure.
    let told = host
        .runtime
        .session()
        .is_resynchronising(quick.attachment_id);
    assert!(
        after
            .iter()
            .any(|event| matches!(event, Event::Delta(_) | Event::Rows(_) | Event::Snapshot(_)))
            || told,
        "the client that was reading was still being drawn the session, or had fallen behind too \
         and been told so: {} events",
        after.len()
    );
    assert_eq!(
        host.runtime.state(),
        kr_protocol::session::SessionState::Live,
        "while the session itself carried on"
    );
}

/// KR-REQ-08.83: the viewport names the first row of the visible page, which a scroll moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_viewport_names_the_first_row_of_the_page_and_a_scroll_moves_it() {
    // More lines than the grid has rows, so the page has moved off the first row.
    let host =
        host("i=0; while [ $i -lt 60 ]; do printf 'row %d\\r\\n' $i; i=$((i+1)); done; sleep 20")
            .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(SMALLER.0, SMALLER.1),
        Some("xterm-256color"),
    )
    .await;
    let events = collect_until_installed(&mut attached.client, Duration::from_secs(5)).await;
    let header = events
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a snapshot");
    let first_visible = events
        .iter()
        .filter_map(|event| match event {
            Event::Rows(page) if page.buffer == ProjectedBuffer::Primary => Some(page),
            _ => None,
        })
        .flat_map(|page| page.rows.iter().map(|row| row.row.get()))
        .min()
        .expect("the rows of the page");
    assert_eq!(
        header.viewport.top_row.get(),
        first_visible,
        "the window is anchored to the page's own first row"
    );
    assert!(
        first_visible > 0,
        "and the page has moved off the first row the session ever had"
    );
    assert!(
        header.oldest_retained_row.get() <= first_visible,
        "the snapshot states the oldest row still retained anywhere"
    );
}

/// Reads what the session says about one attachment right now.
async fn reported_presentation(
    host: &Host,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
) -> Option<TerminalPresentationMode> {
    let snapshot: kr_protocol::recovery::EventsSnapshotResult = client
        .request(
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id: host.session_id,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the snapshot succeeds")
        .to_typed()
        .expect("decodes");
    snapshot
        .attachments
        .iter()
        .find(|summary| summary.attachment_id == attachment_id)
        .and_then(|summary| summary.presentation.as_ref().copied())
}

/// KR-REQ-08.81: asking for a screen is beginning again, and beginning again meets a boundary.
///
/// An attachment that is already forwarding and subscribes afresh is not a continuous stream: what
/// it is given is a screen and a cursor, and those two have to name the same boundary however it
/// was being served a moment before. Without that, the one case the rule exists for - the middle
/// of a control sequence - reaches a terminal through the back door.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribing_again_while_the_parser_is_mid_sequence_is_served_a_projection() {
    // Complete output first, so the attachment is forwarded the stream, and then a sequence that
    // stays open while this test subscribes again.
    let host = host(
        "printf 'settled\\r\\n'; sleep 1.2; printf 'open\\033[1'; sleep 4; \
         printf 'm-closed\\r\\n'; sleep 20",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        Some("xterm-256color"),
    )
    .await;
    assert_eq!(
        attached.presentation,
        Some(TerminalPresentationMode::Direct),
        "a terminal of the session's own size on a settled stream is handed the stream"
    );

    // The application leaves the parser inside a sequence. This attachment is still forwarding.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let mut reader = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    // It asks for a screen, the way a client does after a decode failure of its own. What it is
    // given cannot be the middle of that sequence.
    let again = resubscribe(&host, &mut attached, 0).await;
    assert!(
        again.from_cursor.get() > 0,
        "the subscription starts where the session is"
    );
    assert_eq!(
        reported_presentation(&host, &mut reader, attached.attachment_id).await,
        Some(TerminalPresentationMode::Viewport),
        "and it is served a projection until the parser reaches ground"
    );
    let events = collect(&mut attached.client, Duration::from_millis(400)).await;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Snapshot(_) | Event::Rows(_) | Event::Delta(_))),
        "the screen it is given is the canonical grid: {events:?}"
    );

    // The sequence completes, and the attachment may forward again.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        reported_presentation(&host, &mut reader, attached.attachment_id).await,
        Some(TerminalPresentationMode::Direct),
        "once the parser is on ground it takes the stream back"
    );
}

/// KR-REQ-08.81: forwarding begins at a parser-ground boundary and nowhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_stays_projected_until_a_parser_ground_boundary_arrives() {
    // The application leaves the parser inside an incomplete control sequence and waits. A
    // terminal of the session's own size therefore cannot be handed the stream: the next byte it
    // would be given is the middle of that sequence.
    let host = host(
        "printf 'ready\\033[1'; sleep 1.2; printf 'm-done\\r\\n'; sleep 2; \
         printf 'after-the-handoff\\r\\n'; sleep 20",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut attached = attach(
        &host,
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        Some("xterm-256color"),
    )
    .await;
    assert_eq!(
        attached.presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal that would otherwise take the stream is held in a projection"
    );

    // Section 8's 250 ms. This is the required case: the window passes and the attachment is still
    // projected, because waiting longer would not make the stream safer and forwarding the middle
    // of a sequence is the one thing that is forbidden.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut reader = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    assert_eq!(
        reported_presentation(&host, &mut reader, attached.attachment_id).await,
        Some(TerminalPresentationMode::Viewport),
        "past the deadline it is still projected, and the session says so"
    );

    let held = collect(&mut attached.client, Duration::from_millis(200)).await;
    assert!(
        held.iter()
            .any(|event| matches!(event, Event::Snapshot(_) | Event::Rows(_) | Event::Delta(_))),
        "it is being sent something, and what it is being sent is the canonical grid: {held:?}"
    );
    assert!(
        held.iter().all(|event| !matches!(event, Event::Other(_))),
        "and never bytes, which would assume its terminal is already in the session's state: \
         {held:?}"
    );

    // The sequence completes. The parser reaches ground, and the attachment may forward from
    // there: the presentation changes and the subscriber is told to resynchronise, because the
    // screen it holds and the bytes it is about to be handed have to meet at that boundary.
    let resync = collect_until_resync(&mut attached.client, Duration::from_secs(3))
        .await
        .expect("the transition tells this subscriber to resynchronise");
    assert_eq!(
        reported_presentation(&host, &mut reader, attached.attachment_id).await,
        Some(TerminalPresentationMode::Direct),
        "once the parser is on ground the terminal takes the stream"
    );
    let boundary = resync.cursor.get();

    // The client answers it the way the command does: it subscribes again. What it is handed is a
    // screen and a byte cursor that name the same boundary, and the test proves they do by holding
    // the two apart: the screen carries what the completed sequence left on it, and what the
    // application writes afterwards arrives as bytes from that cursor on, once.
    let again = resubscribe(&host, &mut attached, boundary).await;
    let at = again.from_cursor.get();
    assert!(
        at >= boundary,
        "the subscription starts at the boundary or at the screen the session has reached since: \
         {at} against {boundary}"
    );
    assert!(
        again.gap.as_ref().is_none(),
        "with nothing missing: {:?}",
        again.gap
    );
    let batches = collect_output(&mut attached.client, Duration::from_secs(5)).await;
    let (first_cursor, screen) = batches.first().cloned().unwrap_or_else(|| {
        panic!("the terminal is handed its screen as bytes now that it is direct: {batches:?}")
    });
    assert_eq!(
        first_cursor, at,
        "and that screen is the state at the cursor the subscription named"
    );
    let rendered = String::from_utf8_lossy(&screen).into_owned();
    assert!(
        rendered.contains("m-done"),
        "the screen carries what the completed sequence left on it: {}",
        rendered.escape_debug()
    );
    assert!(
        !rendered.contains("after-the-handoff"),
        "and nothing the application had not written yet: {}",
        rendered.escape_debug()
    );
    let live: Vec<u8> = batches
        .iter()
        .skip(1)
        .flat_map(|(_, bytes)| bytes.clone())
        .collect();
    let live = String::from_utf8_lossy(&live).into_owned();
    assert!(
        live.contains("after-the-handoff"),
        "the bytes after it are the live stream from that cursor on: {}",
        live.escape_debug()
    );
    assert!(
        !live.contains("m-done"),
        "with nothing the screen already carried sent again: {}",
        live.escape_debug()
    );
    for (cursor, _) in batches.iter().skip(1) {
        assert!(
            *cursor >= at,
            "and every batch after it begins at or after that cursor"
        );
    }
}
