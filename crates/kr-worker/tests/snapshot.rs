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
    _runtime: Arc<SessionRuntime>,
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
        _runtime: runtime,
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

fn text_of(page: &ProjectionRowPage) -> Vec<String> {
    page.rows
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect()
}

/// KR-REQ-08.78 and KR-REQ-08.83: a snapshot carries the whole of what a screen is, then its rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_carries_the_state_of_a_screen_and_then_its_rows_in_pages() {
    let host = host("printf 'hello from the session\\r\\n'; sleep 20").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
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

    // A different size, on a new connection: the reconnection and the resize at once.
    let mut second = attach(&host, Dimensions::new(30, 8), Some("xterm-256color")).await;
    let after = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    let again = link_of(&after);
    assert_eq!(
        again, ranges,
        "the same range over the same cells of the same row, which is what an activation needs"
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
    let host = host_with(
        "i=0; while [ $i -lt 400 ]; do printf 'line %d of a steady stream\\r\\n' $i; i=$((i+1)); \
         sleep 0.01; done; sleep 20",
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
    let _ = slow.attachment_id;
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

/// KR-REQ-08.81: forwarding begins at a parser-ground boundary and nowhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_stays_projected_until_a_parser_ground_boundary_arrives() {
    // The application leaves the parser inside an incomplete control sequence and waits. A
    // terminal of the session's own size therefore cannot be handed the stream: the next byte it
    // would be given is the middle of that sequence.
    let host = host("printf 'ready\\033[1'; sleep 1.2; printf 'm-done\\r\\n'; sleep 20").await;
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
        held.iter().all(|event| !matches!(event, Event::Other(_))),
        "and what it is being sent is the canonical grid as state, not bytes: {held:?}"
    );

    // The sequence completes. The parser reaches ground, and the attachment may forward from there.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        reported_presentation(&host, &mut reader, attached.attachment_id).await,
        Some(TerminalPresentationMode::Direct),
        "once the parser is on ground the terminal takes the stream"
    );
}
