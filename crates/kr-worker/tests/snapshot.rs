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
    /// What the session recorded about the shell it started, so this fixture can stop that one
    /// process and no other.
    shell: Option<kr_protocol::identity::ProcessStartIdentity>,
}

impl Host {
    /// Closes the session the way a request does, and waits for it to finish closing.
    ///
    /// A test whose application stops by itself does not need this. One whose application prints
    /// until something stops it does, and this is the ordinary way to stop it: a close, the grace
    /// period, the forced stop and the drain. The wait is bounded so a closure that never finishes
    /// fails this test rather than holding the binary.
    async fn end(&self) {
        self.runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
        tokio::time::timeout(Duration::from_secs(30), self.runtime.wait_closed())
            .await
            .expect("the session finishes closing");
    }
}

impl Drop for Host {
    /// Stops the shell this fixture started, however the test ended.
    ///
    /// Exiting does not stop it. A shell a session owns runs in a terminal of its own, and a test
    /// binary that ends - because it finished, or because an assertion failed part of the way
    /// through - leaves it running and reparented. Most of these applications end by themselves
    /// soon afterwards; one prints until something stops it. So the process is stopped here, by
    /// the identity this session recorded when it started it: the kernel is asked what holds that
    /// number now, and nothing is signalled unless the answer is still the same process.
    fn drop(&mut self) {
        let Some(started) = self.shell.as_ref() else {
            return;
        };
        let Ok(pid) = u32::try_from(started.pid.get()) else {
            return;
        };
        let Ok(now) = kr_ipc::identity::started_process_identity(pid) else {
            return;
        };
        if !now.matches(started) {
            return;
        }
        // The group first, because the application's own children are in it, and then the process
        // itself for a platform that gave it no group of its own. Neither answer is acted on: a
        // shell that has already gone between the reading above and this line is not an error.
        for named in [format!("-{pid}"), pid.to_string()] {
            let _ = std::process::Command::new("kill")
                .arg("-KILL")
                .arg(named)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
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
    let shell = session.root_identity();
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
        runtime,
        session_id,
        environment_id,
        endpoint,
        shell,
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

/// Attaches a client that may type, which is what holding the input lease needs.
async fn attach_with_input(host: &Host, dimensions: Dimensions) -> Attached {
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
            target(host),
            &SessionAttachParams {
                session_id: host.session_id,
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

/// KR-REQ-08.83: succession moves the size, and every remaining client is drawn for its own window.
///
/// The owner leaving is a resize nobody asked for: the next attachment in the order becomes the
/// owner and its size becomes the session's. A client that was not told would keep drawing a screen
/// of the size that left, and for an idle application nothing would ever correct it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn succession_draws_the_remaining_client_for_the_size_it_inherits() {
    let host = host("printf 'before the succession\r\n'; sleep 20").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Two claiming attachments with no declared profile: the first owns the size, the second is
    // next in the order, and both are projected because nothing qualifies either for the stream.
    let owner = attach_claiming(&host, Dimensions::new(100, 30), None).await;
    let mut next = attach_claiming(&host, Dimensions::new(70, 20), None).await;
    let installed = collect_until_installed(&mut next.client, Duration::from_secs(5)).await;
    let first = installed
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a screen");
    assert_eq!(
        first.dimensions,
        Dimensions::new(100, 30),
        "the session is the first owner's size while it is here"
    );

    // The owner leaves, asked for by a third connection. It has to be a third: a request and the
    // notifications share one connection, and a client waiting for its own answer reads past
    // whatever arrived while it waited.
    let mut elsewhere = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let detached: kr_protocol::attachment::SessionDetachResult = elsewhere
        .mutate(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::attachment::SessionDetachParams {
                attachment_id: owner.attachment_id,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the detach succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        detached.geometry.dimensions,
        Dimensions::new(70, 20),
        "the size the survivor claimed is the session's now"
    );

    let after = collect_until_installed(&mut next.client, Duration::from_secs(5)).await;
    assert!(
        after.iter().any(|event| matches!(event, Event::Reset(reset)
                if reset.reason == ProjectionResetReason::Geometry)),
        "the survivor is told the geometry moved: {after:?}"
    );
    let header = after
        .iter()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.as_ref()),
            _ => None,
        })
        .expect("a fresh screen");
    assert_eq!(
        header.dimensions,
        Dimensions::new(70, 20),
        "and the screen it is given is the session's new size"
    );
    assert_eq!(
        (header.viewport.columns.get(), header.viewport.rows.get()),
        (70, 20),
        "drawn for the window it has"
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

/// KR-REQ-08.44: each form a creation can name records its own provenance, and every client is
/// shown the session's canonical palette rather than its own terminal's.
///
/// The palette is chosen through the seam a launch applies it at, and read from the screen every
/// client is installed with. `kr-worker/tests/session.rs` carries the other half: that a create
/// request's own field reaches that seam.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_palette_a_creation_can_name_is_recorded_as_what_it_was() {
    let shared = (
        kr_term::palette::Rgb::new(0xd0, 0xd4, 0xd8),
        kr_term::palette::Rgb::new(0x10, 0x12, 0x18),
    );
    for (choice, expected) in [
        (PaletteChoice::LightPreset, PaletteProvenance::LightPreset),
        (PaletteChoice::DarkPreset, PaletteProvenance::DarkPreset),
        (
            PaletteChoice::Shared {
                foreground: shared.0,
                background: shared.1,
            },
            PaletteProvenance::ClientPreference,
        ),
        (
            PaletteChoice::ProfileDefault,
            PaletteProvenance::ProfileDefault,
        ),
    ] {
        let host = host_with(
            "sleep 20",
            Dimensions::new(CANONICAL.0, CANONICAL.1),
            Some(choice),
            1024 * 1024,
        )
        .await;
        let mut watcher = attach(
            &host,
            Dimensions::new(SMALLER.0, SMALLER.1),
            Some("xterm-256color"),
        )
        .await;
        let seen = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
        let palette = seen
            .iter()
            .find_map(|event| match event {
                Event::Snapshot(header) => Some(header.palette.clone()),
                _ => None,
            })
            .expect("a snapshot");
        assert_eq!(
            palette.source, expected,
            "the form the creation named is the provenance the session records"
        );
        if matches!(choice, PaletteChoice::Shared { .. }) {
            assert_eq!(
                (
                    palette.foreground.red,
                    palette.foreground.green,
                    palette.foreground.blue
                ),
                (shared.0.r, shared.0.g, shared.0.b),
                "and the colours the client shared are the session's own"
            );
            assert_eq!(
                (
                    palette.background.red,
                    palette.background.green,
                    palette.background.blue
                ),
                (shared.1.r, shared.1.g, shared.1.b)
            );
        }
    }
}

/// KR-ACC-007 and KR-REQ-08.80: a slow projected client resynchronises and holds nothing up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_projected_client_is_resynchronised_and_the_session_carries_on() {
    // A queue small enough that a screen and a few updates fill it, and an application producing
    // output steadily. The slow client never reads; the quick one does.
    //
    // The stream outlasts this test, and it does so by never ending rather than by printing a
    // fixed number of lines and waiting. What is under test is that the session keeps reading
    // after the slow client's queue fills, and an application that had stopped printing by then
    // stands still for a reason that has nothing to do with the session: everything before the
    // reading - attaching, a window of collection, waiting for a queue to fill - takes as long as
    // the machine takes, and a producer with a life measured in seconds is a race against it. This
    // one stops when the session does, which is at the end of this test.
    let host = host_with(
        "i=0; while :; do printf 'line %d of a steady stream\\r\\n' $i; i=$((i+1)); \
         sleep 0.01; done",
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

    // The queue for the client that is not reading has filled, which is the condition this test is
    // about. The session knows, and it is asked rather than the client's own socket being read:
    // reading from that client is the one thing that would let the read loop off the hook.
    let mut slow = slow;
    let overflowed = {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            if host
                .runtime
                .session()
                .is_resynchronising(slow.attachment_id)
            {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        seen
    };
    assert!(
        overflowed,
        "the session is holding this subscriber's place rather than waiting for it"
    );
    let at_overflow = host.runtime.session().output_cursor();
    // The client that is still reading is given until it has something to show or has been told
    // to resynchronise itself. One window of collection is a second race beside the first: on a
    // busy machine the window can pass between two of the deliveries it is there to catch.
    let mut after = Vec::new();
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            after.extend(collect(&mut quick.client, Duration::from_secs(3)).await);
            if after
                .iter()
                .any(|event| matches!(event, Event::Delta(_) | Event::Rows(_) | Event::Snapshot(_)))
                || host
                    .runtime
                    .session()
                    .is_resynchronising(quick.attachment_id)
                || std::time::Instant::now() >= deadline
            {
                break;
            }
        }
    }
    // That the cursor moves is the assertion; how long it takes to move is the machine's business.
    // A window measured in seconds would be a second race beside the first one.
    let afterwards = {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut reached = host.runtime.session().output_cursor();
        while reached <= at_overflow && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            reached = host.runtime.session().output_cursor();
        }
        reached
    };
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

    // Only now is the silent client read, and what it finds is the marker rather than a hole it
    // was never told about.
    let theirs = collect(&mut slow.client, Duration::from_secs(4)).await;
    let marker = theirs
        .iter()
        .find_map(|event| match event {
            Event::Resync(marker) => Some(*marker),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("the slow client was told to resynchronise rather than waited for: {theirs:?}")
        });
    assert_eq!(
        marker.reason,
        kr_protocol::recovery::ResyncReason::SendQueueFull,
        "and it says why"
    );

    // And it recovers: a client that asks again is given a whole screen, which is what the marker
    // is for. Being told to resynchronise and then never being served would be the same hole by
    // another name.
    let again = resubscribe(&host, &mut slow, marker.cursor.get()).await;
    let _ = again;
    let recovered = collect_until_installed(&mut slow.client, Duration::from_secs(10)).await;
    assert!(
        recovered
            .iter()
            .any(|event| matches!(event, Event::Snapshot(_))),
        "it is given a fresh screen: {} events",
        recovered.len()
    );
    assert!(
        recovered
            .iter()
            .any(|event| matches!(event, Event::Rows(page) if !page.more)),
        "and the screen completes, so it is holding one"
    );
    assert_eq!(
        host.runtime.state(),
        kr_protocol::session::SessionState::Live,
        "while the session itself carried on"
    );

    // The application above prints until something stops it, so this is what stops it. A test that
    // left it running would hand the next run of this binary a process forking a hundred times a
    // second, and the next run's answer would depend on this one.
    host.end().await;
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

/// KR-REQ-08.79 and KR-ACC-007: a queue too small for any screen is refused, once and for good.
///
/// A projected client is installed from one screen: the reset, the header and every page of rows.
/// It can hold part of that and draw nothing, so a queue below the smallest screen this session can
/// be cut down to is a queue no screen can ever cross. Telling such a client its queue is full would
/// have it ask for the same screen again, and again. It is told when it asks instead, with the
/// figure it would need, and the refusal is one no retry of the same request can turn into a
/// success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queue_too_small_for_any_screen_is_refused_when_it_is_asked_for() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: temp.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "exec cat".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(CANONICAL.0, CANONICAL.1),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");

    // A terminal of another size, which is why it is projected and served a screen as state.
    let projected = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    session
        .attach(
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(SMALLER.0, SMALLER.1)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: requested.clone(),
            },
            requested,
            projected,
        )
        .expect("attaches");

    let minimum = session
        .minimum_projection_install(projected)
        .expect("the smallest screen this session can be installed with");
    assert!(
        minimum > 0,
        "an installation is never nothing: it is a reset, a header and a page at the very least"
    );

    let refusal = session
        .subscribe_within(projected, minimum - 1)
        .expect_err("a queue below the smallest screen is refused");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::InvalidArgument,
        "the refusal is definite: {refusal}"
    );
    assert_eq!(
        refusal.code().retry_category(),
        kr_protocol::error::RetryCategory::ConfigurationChange,
        "and not something a client may simply ask for again: {refusal}"
    );
    assert!(
        refusal.to_string().contains(&minimum.to_string()),
        "it names what the client would need: {refusal}"
    );
    assert!(
        !refusal
            .to_string()
            .to_ascii_lowercase()
            .contains("queue is full"),
        "and it is not the answer a client is given for falling behind: {refusal}"
    );

    // The figure is the bound itself, not a margin above it: a queue of exactly the minimum is a
    // queue a screen fits, so it is accepted.
    session
        .subscribe_within(projected, minimum)
        .expect("a queue of exactly the smallest screen is enough");
}

/// Reports where one attachment's window is looking, and returns where the host put it.
///
/// The same method a terminal reports its size through: a window's position is part of what a
/// viewport report is.
async fn report_viewport(
    host: &Host,
    attached: &mut Attached,
    dimensions: Dimensions,
    position: Option<kr_protocol::attachment::ViewportPosition>,
) -> kr_protocol::attachment::AttachmentViewportResult {
    attached
        .client
        .mutate(
            Method::AttachmentViewport,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &kr_protocol::attachment::AttachmentViewportParams {
                attachment_id: attached.attachment_id,
                dimensions,
                position: Nullable(position),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("a viewport report is not refused")
        .to_typed()
        .expect("decodes")
}

/// The stable row a completed installation says its window starts at.
fn installed_top_row(events: &[Event]) -> u64 {
    events
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.viewport.top_row.get()),
            _ => None,
        })
        .expect("a snapshot")
}

/// Every row of the active buffer a completed installation carried, by stable identifier.
fn installed_rows(events: &[Event], buffer: ProjectedBuffer) -> Vec<(u64, String)> {
    let mut rows: Vec<(u64, String)> = events
        .iter()
        .filter_map(|event| match event {
            Event::Rows(page) if page.buffer == buffer => Some(page),
            _ => None,
        })
        .flat_map(|page| {
            page.rows.iter().map(|row| {
                let text: String = row.runs.iter().map(|run| run.text.as_str()).collect();
                (row.row.get(), text)
            })
        })
        .collect();
    rows.sort_by_key(|(id, _)| *id);
    rows.dedup_by_key(|(id, _)| *id);
    rows
}

/// A session that prints `lines` numbered lines, waits, and then takes the alternate screen.
fn alternate_after(lines: u32) -> String {
    format!(
        "i=0; while [ $i -lt {lines} ]; do printf 'line %d\r\n' $i; i=$((i+1)); done; \
         sleep 3; printf '\x1b[?1049h'; sleep 20"
    )
}

/// A session that has printed `lines` numbered lines and is then idle.
fn numbered(lines: u32) -> String {
    format!(
        "i=0; while [ $i -lt {lines} ]; do printf 'line %d\\r\\n' $i; i=$((i+1)); done; sleep 20"
    )
}

/// KR-REQ-08.79, KR-REQ-08.83: a window above the live page is installed with the pages that
/// cover it, inside the same bounds and the same subscriber's queue as any other screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_viewport_above_the_live_page_installs_the_pages_that_cover_it() {
    let host = host_with(
        &numbered(400),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    assert_eq!(
        watcher.presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal of another size is projected"
    );
    let live = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    let live_top = installed_top_row(&live);
    assert!(
        live_top > 200,
        "the session has scrolled well past its first screen: {live_top}"
    );

    // Back one hundred rows, named as a distance because this client has not been given a row
    // identifier above the page it is looking at.
    let answer = report_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(100),
        )),
    )
    .await;
    let landed = match answer.position.0 {
        Some(kr_protocol::attachment::ViewportPosition::Row(row)) => row.get(),
        other => panic!("a window above the live page lands on a row: {other:?}"),
    };
    assert_eq!(
        landed,
        live_top - 100,
        "and it lands where it asked, a hundred rows above the live page"
    );

    // The pages that cover it arrive through the subscription this attachment already holds,
    // charged to its own queue, and the installation completes: a client holding part of a screen
    // holds none of it, so a last page proves the whole window crossed the queue.
    let history = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    assert_eq!(
        installed_top_row(&history),
        landed,
        "the screen it is given is drawn for the window it asked for"
    );
    assert!(
        history.iter().any(|event| matches!(event, Event::Rows(page)
            if !page.more && page.buffer == ProjectedBuffer::Primary)),
        "the installation completes rather than leaving the client holding part of a screen"
    );
    for event in &history {
        if let Event::Rows(page) = event {
            assert!(
                page.rows.len() as u64 <= MAX_PROJECTION_PAGE_ROWS,
                "every page stays inside section 8's row bound: {}",
                page.rows.len()
            );
        }
    }

    let rows = installed_rows(&history, ProjectedBuffer::Primary);
    let shown: Vec<&(u64, String)> = rows
        .iter()
        .filter(|(id, _)| *id >= landed && *id < landed + SMALLER.1)
        .collect();
    assert_eq!(
        shown.len() as u64,
        SMALLER.1,
        "the window's own rows are all there: {rows:?}"
    );
    assert!(
        shown[0].1.starts_with("line "),
        "and they are the session's retained rows rather than blanks: {:?}",
        shown[0]
    );
    // Historical rows are what the window is: the first row it holds is a hundred rows older than
    // the live page's first row, and the numbering says so.
    let first_of_window: u32 = shown[0].1["line ".len()..]
        .trim()
        .parse()
        .expect("the line carries its own number");
    let first_of_live: Vec<&(u64, String)> =
        rows.iter().filter(|(id, _)| *id == landed + 100).collect();
    if let Some((_, text)) = first_of_live.first() {
        let live_number: u32 = text["line ".len()..]
            .trim()
            .parse()
            .expect("the line carries its own number");
        assert_eq!(
            live_number - first_of_window,
            100,
            "a hundred rows above is a hundred lines earlier"
        );
    }

    // And back to the live screen, which is what no position at all means.
    let back = report_viewport(&host, &mut watcher, window, None).await;
    assert!(
        back.position.0.is_none(),
        "a report with no position is the live screen: {:?}",
        back.position.0
    );
    let again = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    assert!(
        installed_top_row(&again) >= live_top,
        "and the window follows the session again"
    );
}

/// KR-REQ-08.79, KR-REQ-08.83: a window naming a row the session gave up is shown the oldest page
/// there is, with the marker, rather than being refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_viewport_that_names_an_evicted_row_is_given_the_oldest_page_and_the_marker() {
    // Past the grid's own retention, so the oldest rows this session held are gone.
    let host = host_with(
        &numbered(4_500),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(6)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let live = collect_until_installed(&mut watcher.client, Duration::from_secs(10)).await;
    let oldest = live
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some((header.oldest_retained_row.get(), header.evicted)),
            _ => None,
        })
        .expect("a snapshot");
    assert!(
        oldest.0 > 0 && oldest.1,
        "this session has given up its oldest rows: {oldest:?}"
    );

    // Row zero is gone. The window is put where the rows begin instead.
    let answer = report_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Row(
            kr_protocol::scalars::U64::new(0),
        )),
    )
    .await;
    let landed = match answer.position.0 {
        Some(kr_protocol::attachment::ViewportPosition::Row(row)) => row.get(),
        other => panic!("an evicted row is answered with the oldest one there is: {other:?}"),
    };
    assert_eq!(
        landed, oldest.0,
        "which is the oldest row the session still retains"
    );

    let history = collect_until_installed(&mut watcher.client, Duration::from_secs(10)).await;
    assert_eq!(
        installed_top_row(&history),
        landed,
        "and the screen it is given starts there"
    );
    for event in &history {
        match event {
            Event::Snapshot(header) => {
                assert_eq!(header.oldest_retained_row.get(), oldest.0);
                assert!(header.evicted, "the header states the eviction");
            }
            Event::Rows(page) if page.buffer == ProjectedBuffer::Primary => {
                assert_eq!(
                    page.oldest_retained_row.get(),
                    oldest.0,
                    "every page states the oldest row it could have carried"
                );
                assert!(page.evicted, "and that rows below it are gone");
                assert!(
                    page.rows.iter().all(|row| row.row.get() >= oldest.0),
                    "no page carries a row the session no longer holds"
                );
            }
            _ => {}
        }
    }
}

/// KR-ACC-002 and section 8 line 495: the link ranges and the exact cells of a history page are
/// the same after a reconnection, which is what activation and a copy selection each need.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hyperlink_and_a_selection_in_history_survive_a_reconnection() {
    let host = host_with(
        "printf '\\033]8;;https://example.invalid/deep\\033\\\\the deep link\\033]8;;\\033\\\\\\r\\n'; \
         i=0; while [ $i -lt 200 ]; do printf 'line %d\\r\\n' $i; i=$((i+1)); done; sleep 20",
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Everything one page carries about its cells: the row, each run's column, its width and its
    // text, and the link over it. A copy selection reads exactly this.
    let cells_of = |events: &[Event]| -> Vec<(u64, u64, u64, String, Option<String>)> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Rows(page) if page.buffer == ProjectedBuffer::Primary => Some(page),
                _ => None,
            })
            .flat_map(|page| {
                page.rows.iter().flat_map(|row| {
                    let id = row.row.get();
                    row.runs.iter().map(move |run| {
                        (
                            id,
                            run.column.get(),
                            run.cells.get(),
                            run.text.clone(),
                            run.hyperlink.0.clone(),
                        )
                    })
                })
            })
            .filter(|(_, _, _, text, _)| text.contains("deep link"))
            .collect()
    };

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut first = attach(&host, window, Some("xterm-256color")).await;
    let live = collect_until_installed(&mut first.client, Duration::from_secs(5)).await;
    let live_top = installed_top_row(&live);
    assert!(
        live_top > 0,
        "the link has scrolled above the live page: {live_top}"
    );

    // The link is on the session's first row, so the window goes to the oldest rows there are.
    let answer = report_viewport(
        &host,
        &mut first,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Row(
            kr_protocol::scalars::U64::new(0),
        )),
    )
    .await;
    let landed = match answer.position.0 {
        Some(kr_protocol::attachment::ViewportPosition::Row(row)) => row.get(),
        other => panic!("a window at the first row is above the live page: {other:?}"),
    };
    let before = collect_until_installed(&mut first.client, Duration::from_secs(5)).await;
    let cells = cells_of(&before);
    assert_eq!(
        cells.len(),
        1,
        "the link's own run is in the page that covers it: {cells:?}"
    );
    assert_eq!(
        cells[0].4.as_deref(),
        Some("https://example.invalid/deep"),
        "with its target, as inert metadata"
    );
    drop(first);

    // A new connection, a new attachment, and the same window: the reconnection.
    let mut second = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    let answer = report_viewport(
        &host,
        &mut second,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Row(
            kr_protocol::scalars::U64::new(landed),
        )),
    )
    .await;
    assert!(
        matches!(
            answer.position.0,
            Some(kr_protocol::attachment::ViewportPosition::Row(row)) if row.get() == landed
        ),
        "the same window: {:?}",
        answer.position.0
    );
    let after = collect_until_installed(&mut second.client, Duration::from_secs(5)).await;
    assert_eq!(
        cells_of(&after),
        cells,
        "the same cells, in the same columns of the same row, under the same target"
    );
}

/// Section 8 line 459: passive scrollback does not seize the input lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scrolling_back_does_not_seize_the_input_lease() {
    let host = host_with(
        &numbered(300),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // One attachment that types, and one that watches. The watcher scrolls.
    let mut typist = attach_with_input(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    let lease: kr_protocol::input::InputAcquireResult = typist
        .client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id: typist.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the lease is granted")
        .to_typed()
        .expect("decodes");
    let held = lease.lease;
    assert_eq!(
        held.holder.0,
        Some(typist.attachment_id),
        "the typist holds the lease"
    );

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    for step in [40_u64, 80] {
        let _ = report_viewport(
            &host,
            &mut watcher,
            window,
            Some(kr_protocol::attachment::ViewportPosition::Above(
                kr_protocol::scalars::U64::new(step),
            )),
        )
        .await;
    }
    let _ = report_viewport(&host, &mut watcher, window, None).await;

    let after = host.runtime.session().lease();
    assert_eq!(
        after.holder.0,
        Some(typist.attachment_id),
        "scrolling took nothing: the lease is where it was"
    );
    assert_eq!(
        after.epoch, held.epoch,
        "and its epoch did not move, so nothing was taken over"
    );
}

/// Reports a window position and returns the answer, refusal and all.
async fn try_viewport(
    host: &Host,
    attached: &mut Attached,
    dimensions: Dimensions,
    position: Option<kr_protocol::attachment::ViewportPosition>,
) -> std::result::Result<
    kr_protocol::attachment::AttachmentViewportResult,
    kr_protocol::error::ProtocolError,
> {
    attached
        .client
        .mutate(
            Method::AttachmentViewport,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &kr_protocol::attachment::AttachmentViewportParams {
                attachment_id: attached.attachment_id,
                dimensions,
                position: Nullable(position),
            },
        )
        .await
        .expect("the call reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
}

/// Section 10's live-screen exception: a narrowed attachment is not shown retained rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_shown_only_the_live_screen_cannot_look_above_it() {
    let host = host_with(
        &numbered(300),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    // The same narrowing a forwarded caller is given: the screen that is showing, and no retained
    // content beyond it.
    host.runtime
        .session()
        .narrow_content(watcher.attachment_id, kr_worker::render::Scope::LiveScreen);

    let refusal = try_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(40),
        )),
    )
    .await
    .expect_err("a narrowed attachment cannot place its window in the history");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::UnsupportedCapability,
        "the refusal is about what this attachment may be shown: {refusal}"
    );
    assert!(
        refusal.message.contains("retained rows"),
        "and it says so: {refusal}"
    );

    // The live screen is still its own: a report with no position changes nothing and is answered.
    let answer = try_viewport(&host, &mut watcher, window, None)
        .await
        .expect("the live screen is what this attachment is shown");
    assert!(answer.position.0.is_none());
}

/// A window above the live page is not the live byte stream, whatever this terminal's size is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_reading_its_history_is_served_the_grid_rather_than_the_stream() {
    let host = host_with(
        &numbered(300),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The session's own size and a qualified profile: this terminal takes the stream directly.
    let canonical = Dimensions::new(CANONICAL.0, CANONICAL.1);
    let mut direct = attach(&host, canonical, Some("xterm-256color")).await;
    assert_eq!(
        direct.presentation,
        Some(TerminalPresentationMode::Direct),
        "a terminal of the session's size takes the stream"
    );

    let answer = report_viewport(
        &host,
        &mut direct,
        canonical,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(50),
        )),
    )
    .await;
    assert!(
        matches!(
            answer.position.0,
            Some(kr_protocol::attachment::ViewportPosition::Row(_))
        ),
        "the window is above the live page: {:?}",
        answer.position.0
    );
    assert_eq!(
        answer.presentation,
        TerminalPresentationMode::Viewport,
        "and a terminal reading its history is drawn the canonical grid, because the session's own \
         bytes cannot produce rows that have scrolled off it"
    );

    // And back: the live screen is the stream again.
    let back = report_viewport(&host, &mut direct, canonical, None).await;
    assert!(back.position.0.is_none());
    assert_eq!(
        back.presentation,
        TerminalPresentationMode::Direct,
        "a window on the live screen takes the stream once more"
    );
}

/// The cursor's row is a line of the live screen, and a window above it says where that begins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_above_the_live_page_says_where_the_live_screen_begins() {
    let host = host_with(
        &numbered(300),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let live = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    let installed = live
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.viewport),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(
        installed.screen_top_row, installed.top_row,
        "a window on the live screen has one origin"
    );

    let answer = report_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(60),
        )),
    )
    .await;
    let landed = match answer.position.0 {
        Some(kr_protocol::attachment::ViewportPosition::Row(row)) => row.get(),
        other => panic!("a window above the live page lands on a row: {other:?}"),
    };
    let history = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    let parked = history
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Snapshot(header) => Some(header.viewport),
            _ => None,
        })
        .expect("a snapshot");
    assert_eq!(parked.top_row.get(), landed, "the window is where it asked");
    assert_eq!(
        parked.screen_top_row.get(),
        landed + 60,
        "and the live screen still begins where it did, sixty rows below"
    );
}

/// A window that needs a larger screen than the queue this attachment holds is refused, once.
///
/// A window above the live page carries the rows it shows and the live screen behind them, so it
/// can be a larger screen than the one a subscriber was admitted for. Being told the window moved
/// and then that the queue is full is two answers where there should be one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_too_large_for_this_queue_is_refused_rather_than_resynchronised() {
    let host = host_with(
        &numbered(400),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;

    let mut session = host.runtime.session();
    // A queue of exactly the live screen, which is what this attachment is being shown.
    let live_minimum = session
        .minimum_projection_install(watcher.attachment_id)
        .expect("the smallest live screen");
    let _stream = session
        .subscribe_within(watcher.attachment_id, live_minimum)
        .expect("a queue of exactly the live screen is enough for the live screen");

    let above = Some(kr_protocol::attachment::ViewportPosition::Above(
        kr_protocol::scalars::U64::new(100),
    ));
    // The answer the dispatch asks for before it marks the effect. It is the same answer, asked
    // where a refusal is still a refusal: raised after the marker it would be an outcome nobody
    // can read, and the requests behind it would wait on a receipt that never resolves.
    let early = session
        .viewportable(watcher.attachment_id, window, above)
        .expect_err("a window this queue cannot carry is refused before anything is marked");
    assert_eq!(
        early.code(),
        kr_protocol::error::ErrorCode::InvalidArgument,
        "and it is the queue that refuses it: {early}"
    );
    assert!(early.to_string().contains("cannot carry this window"));
    // The narrowed case takes the same path, and is refused there too.
    session.narrow_content(watcher.attachment_id, kr_worker::render::Scope::LiveScreen);
    let narrowed = session
        .viewportable(watcher.attachment_id, window, above)
        .expect_err("a caller shown the live screen cannot look above it either");
    assert_eq!(
        narrowed.code(),
        kr_protocol::error::ErrorCode::UnsupportedCapability,
        "and that refusal is about what it may be shown: {narrowed}"
    );
    session.narrow_content(watcher.attachment_id, kr_worker::render::Scope::WholeScreen);

    let refusal = session
        .viewport(watcher.attachment_id, window, above)
        .expect_err("a window this queue cannot carry is refused");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::InvalidArgument,
        "the refusal is definite: {refusal}"
    );
    assert!(
        refusal.to_string().contains("cannot carry this window"),
        "and it says what it is about: {refusal}"
    );
    // Nothing was recorded, so the attachment is still looking at the live screen.
    let (_, landed) = session
        .viewport(watcher.attachment_id, window, None)
        .expect("the live screen is still where this window is");
    assert!(landed.is_none());
}

/// A full-screen application takes the screen, and every window comes back to the live screen.
///
/// The buffer it takes keeps no history and numbers its rows from its own beginning, so a window
/// above the shell's live page has nothing to be above any more. It is cleared where the session
/// sees the reset rather than where a client is published to, because a client that has fallen
/// behind is published nothing at all and would otherwise be restored to rows that are no longer
/// above anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_buffer_switch_brings_every_window_back_to_the_live_screen() {
    let host = host_with(
        "i=0; while [ $i -lt 300 ]; do printf 'line %d\\r\\n' $i; i=$((i+1)); done; \
         sleep 3; printf '\\033[?1049h'; sleep 20",
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    let answer = report_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(80),
        )),
    )
    .await;
    assert!(
        matches!(
            answer.position.0,
            Some(kr_protocol::attachment::ViewportPosition::Row(_))
        ),
        "the window is above the live page: {:?}",
        answer.position.0
    );

    // The application takes the screen while this client is reading its history. The projection
    // reset that carries the switch is what this test is waiting for.
    let switched = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut seen = false;
        while tokio::time::Instant::now() < deadline && !seen {
            let events = collect(&mut watcher.client, Duration::from_secs(2)).await;
            seen = events.iter().any(|event| {
                matches!(event, Event::Reset(reset)
                    if reset.reason == ProjectionResetReason::BufferSwitch)
            });
        }
        seen
    };
    assert!(switched, "the application took the screen");

    // The window came back with it, and nothing here asked for that: a report naming no position
    // would clear the window itself, so the session is asked where the window is instead.
    assert!(
        host.runtime
            .session()
            .history_window(watcher.attachment_id)
            .is_none(),
        "the window came back to the live screen with the screen that program took"
    );
}

/// And it comes back even for a client the session is publishing nothing to.
///
/// A subscriber that has fallen behind is told to resynchronise and is published nothing until it
/// asks again. A window cleared only where a client is published to would survive the switch for
/// exactly that client, and its next screen would put it back above rows that are no longer above
/// anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_buffer_switch_reaches_a_window_whose_client_is_behind() {
    let host = host_with(
        &alternate_after(300),
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        None,
        1024 * 1024,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let window = Dimensions::new(SMALLER.0, SMALLER.1);
    let mut watcher = attach(&host, window, Some("xterm-256color")).await;
    let _ = collect_until_installed(&mut watcher.client, Duration::from_secs(5)).await;
    let answer = report_viewport(
        &host,
        &mut watcher,
        window,
        Some(kr_protocol::attachment::ViewportPosition::Above(
            kr_protocol::scalars::U64::new(80),
        )),
    )
    .await;
    assert!(
        matches!(
            answer.position.0,
            Some(kr_protocol::attachment::ViewportPosition::Row(_))
        ),
        "the window is above the live page: {:?}",
        answer.position.0
    );

    // Behind, which is what stops it being published to at all.
    {
        let mut session = host.runtime.session();
        session.require_resync(
            watcher.attachment_id,
            kr_protocol::recovery::ResyncReason::SendQueueFull,
        );
        assert!(session.is_resynchronising(watcher.attachment_id));
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if host
            .runtime
            .session()
            .history_window(watcher.attachment_id)
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        host.runtime
            .session()
            .history_window(watcher.attachment_id)
            .is_none(),
        "the window came back even though nothing was published to this client"
    );
}
