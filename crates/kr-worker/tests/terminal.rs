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
//!
//! Every fixture here waits for a keystroke between the things it writes, and every test releases
//! the next step itself over the product's own input path. An application that printed on a
//! timetable of its own would be a second clock, and which of the two got where it was going first
//! would be the machine's decision rather than the host's.

use std::sync::Arc;

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
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

use common::{Keys, LIVENESS_DEADLINE, carries, produced, produced_times, retained, take_the_keys};

/// The session's own size. An attachment of exactly this size takes the stream directly.
const CANONICAL: (u64, u64) = (80, 24);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

impl Drop for Host {
    /// Stops the shell this fixture started, however the test ended.
    ///
    /// None of these applications ends by itself: each one waits on its terminal for a line that
    /// only this test types, so a test that returned early, because it finished or because an
    /// assertion failed part of the way through, would leave one waiting. `Session::force_close`
    /// is the host's own forced stop, and it signals through the handle the session holds rather
    /// than through a number that could by then name another process. A session whose lock an
    /// earlier panic poisoned cannot be reached at all, and that refusal is caught rather than
    /// raised, because a panic inside a drop that is already unwinding would take the whole test
    /// binary down and tell nobody why.
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.runtime.session().force_close();
        }));
    }
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
        dimensions: canonical,
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
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
        runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

/// What the session says one attachment is being served as.
fn presentation_of(host: &Host, attachment_id: AttachmentId) -> Option<TerminalPresentationMode> {
    host.runtime
        .session()
        .attachments()
        .into_iter()
        .find(|summary| summary.attachment_id == attachment_id)
        .and_then(|summary| summary.presentation.as_ref().copied())
}

/// Attaches a terminal of `dimensions`, takes the input lease for it and subscribes it to output.
///
/// The lease is taken before the subscription rather than after it, because a client drops the
/// notifications that arrive while it is waiting for an answer to a call of its own: the screen
/// this terminal is drawn is queued the moment it subscribes, and a call made after that could
/// take it away. Every keystroke this attachment sends afterwards goes through the session, so the
/// subscription is the last thing this client asks for.
async fn attached_holding_the_keys(
    host: &Host,
    dimensions: Dimensions,
) -> (LocalClient, Option<TerminalPresentationMode>, Keys) {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let (attachment_id, presentation) = attach_over(&mut client, host, dimensions).await;
    let keys = take_the_keys(
        &mut client,
        host.environment_id,
        host.session_id,
        attachment_id,
    )
    .await;
    subscribe_over(&mut client, host, attachment_id).await;
    (client, presentation, keys)
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
    let (attachment_id, presentation) = attach_over(&mut client, host, dimensions).await;
    subscribe_over(&mut client, host, attachment_id).await;
    (client, presentation, attachment_id)
}

/// Attaches a terminal of `dimensions` over this client, and says how it will be served.
async fn attach_over(
    client: &mut LocalClient,
    host: &Host,
    dimensions: Dimensions,
) -> (AttachmentId, Option<TerminalPresentationMode>) {
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
    (
        attached.attachment.attachment_id,
        attached.attachment.presentation.as_ref().copied(),
    )
}

/// Subscribes this client's attachment to the session's output.
async fn subscribe_over(client: &mut LocalClient, host: &Host, attachment_id: AttachmentId) {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
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

/// Collects a projected client's stream until one of its rows carries `marker`.
///
/// A projected attachment is sent the canonical grid as state rather than bytes, so three things
/// are returned: the bytes prove that none were sent, and the state and the rows are what it is
/// drawn from.
///
/// The run ends on a row the application produced where the test wanted it to end, and the tests
/// here pick a marker the application writes *after* this terminal joined. Everything the
/// attachment was owed before that is queued in front of it, which is what makes "and no bytes
/// arrived" a claim about the whole run rather than about a sample of it. A marker that never
/// arrives fails here, saying how long it waited and what it saw.
async fn collect_projection_until(
    client: &mut LocalClient,
    marker: &str,
) -> (
    Vec<u8>,
    Option<kr_protocol::projection::ProjectionSnapshot>,
    Vec<kr_protocol::projection::ProjectedRow>,
) {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut bytes = Vec::new();
    let mut header = None;
    let mut rows: Vec<kr_protocol::projection::ProjectedRow> = Vec::new();
    let drawn = |rows: &[kr_protocol::projection::ProjectedRow]| {
        rows.iter()
            .any(|row| row.runs.iter().any(|run| run.text.contains(marker)))
    };
    while !drawn(&rows) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!(
                "waited {:?} for {marker:?} to reach this terminal as a projected row and the \
                 connection ended ({error}): {rows:?}",
                started.elapsed()
            ),
            Err(_) => panic!(
                "waited {:?} for {marker:?} to reach this terminal as a projected row: {rows:?}",
                started.elapsed()
            ),
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        match notification.event_type.as_str() {
            "session.output" => {
                if let Ok(event) = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    bytes.extend_from_slice(event.bytes.as_slice());
                }
            }
            "session.projection.snapshot" => {
                if let Ok(snapshot) = notification
                    .payload
                    .to_typed::<kr_protocol::projection::ProjectionSnapshot>()
                {
                    header = Some(snapshot);
                }
            }
            "session.projection.rows" => {
                if let Ok(page) = notification
                    .payload
                    .to_typed::<kr_protocol::projection::ProjectionRowPage>()
                    && page.buffer == kr_protocol::projection::ProjectedBuffer::Primary
                {
                    rows.extend(page.rows);
                }
            }
            "session.projection.delta" => {
                if let Ok(delta) = notification
                    .payload
                    .to_typed::<kr_protocol::projection::ProjectionDelta>()
                {
                    rows.extend(delta.rows);
                }
            }
            _ => {}
        }
    }
    (bytes, header, rows)
}

/// Collects the bytes this client is sent until they carry `marker`.
///
/// There is no window afterwards. Each test here picks a marker the application writes at the
/// point where the run should end, so that everything the claim is about is queued in front of it;
/// a window would sample what arrived inside a length of time instead, and a length of time that
/// catches a delivery on an idle machine and misses it on a busy one proves nothing either way.
/// [`LIVENESS_DEADLINE`] is what a marker that never arrives fails at, and the failure says how
/// long it waited and what it saw.
async fn collect_until(client: &mut LocalClient, marker: &[u8]) -> Vec<u8> {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut seen: Vec<u8> = Vec::new();
    while !carries(&seen, marker) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, client.recv()).await {
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
            // Anything else this client is sent is not what this wait is about.
            Ok(Ok(_)) => {}
            // A connection that has gone can never deliver the marker, and that is this wait's
            // failure rather than a partial answer for the caller to puzzle over.
            Ok(Err(error)) => panic!(
                "waited {:?} for {:?} to reach this terminal and the connection ended ({error}): \
                 {:?}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&seen).escape_debug()
            ),
            Err(_) => panic!(
                "waited {:?} for {:?} to reach this terminal: {:?}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&seen).escape_debug()
            ),
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
    // ordinary text. That echo is what makes the answer visible from outside the process, and it
    // is why this is the one fixture here that leaves the echo on.
    //
    // The question is asked twice, because the two halves of the claim are about different
    // moments. The first time nobody is attached and nobody holds the input lease: section 8 gives
    // the host's own replies a lane of their own that requires no human lease and never acquires
    // one, so an answer that waited for somebody to be holding the keys would never come. The
    // second time this terminal is attached and watching, which is the only way to see what an
    // attachment is sent.
    let host = host(
        "printf '\\033[c'; read -r _; printf 'kr-joined.\\n'; read -r _; \
         printf '\\033[c'; read -r _; printf 'kr-asked.\\n'; read -r _",
    )
    .await;
    produced(&host.runtime, b"[?62;22c").await;

    let (mut client, presentation, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Direct),
        "the terminal is the session's size"
    );
    // One line, released before the second question, that ends the run carrying the screen this
    // terminal was drawn. What follows it is live, so the answer found there is an answer this
    // attachment was sent rather than one it was shown a picture of.
    keys.release(&host.runtime);
    let drawn = collect_until(&mut client, b"kr-joined.").await;

    // The second question, and then a line that follows it. The run ends on that line rather than
    // on the answer, so what it carries is everything the question produced: a host that forwarded
    // the question would have put it in this same stream, in front of its own answer.
    keys.release(&host.runtime);
    produced_times(&host.runtime, b"[?62;22c", 2).await;
    keys.release(&host.runtime);
    let seen = collect_until(&mut client, b"kr-asked.").await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(
        !text.contains("\u{1b}[c") && !String::from_utf8_lossy(&drawn).contains("\u{1b}[c"),
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
    let host = host(
        "stty -echo -echonl || exit 1; \
         printf 'visible-line\\a\\033]52;c;aGVsbG8=\\033\\\\\\n'; read -r _; \
         printf 'kr-joined.\\n'; read -r _",
    )
    .await;
    // The whole of it has been through the engine before anybody attaches. The marker is the last
    // of what the application wrote, ending in the line ending the terminal produced, so nothing
    // of it is still on its way when this terminal joins.
    produced(&host.runtime, b"\x1b]52;c;aGVsbG8=\x1b\\\r\n").await;
    let (mut client, _, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    // One line written after this terminal joined. The screen it was drawn is queued in front of
    // that line, so a run ending there carries the whole of what joining late was sent: a bell or
    // a clipboard write inside the drawing would be in it.
    keys.release(&host.runtime);
    let seen = collect_until(&mut client, b"kr-joined.").await;
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

/// KR-REQ-08.01, KR-REQ-08.03: a terminal that does not match the session's geometry is projected:
/// it is installed with the canonical grid and sent its rows, never the byte stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_of_another_size_is_projected_rather_than_sent_the_raw_stream() {
    let host = host(
        "stty -echo -echonl || exit 1; printf 'first\\nsecond\\n'; read -r _; \
         printf 'third\\n'; read -r _; printf 'fourth\\n'; read -r _",
    )
    .await;
    produced(&host.runtime, b"second\r\n").await;
    // Half the session's width and height. A byte stream that assumed 80 columns would wrap this
    // terminal's lines in the wrong places and leave its cursor somewhere else entirely.
    let (mut client, presentation, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(40, 12)).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Viewport),
        "a terminal that is not the session's size is shown a projection"
    );
    // A third line, written after this terminal joined, so the run covers both halves of the
    // claim: the screen it was installed with and the output that followed. A fourth line closes
    // it, released once the third is through the engine: a host that sent this terminal the third
    // line as bytes as well as rows would have queued those bytes in front of the fourth line's
    // row, and a run that ended at the third line's own row would have stopped in front of them.
    keys.release(&host.runtime);
    produced(&host.runtime, b"third\r\n").await;
    keys.release(&host.runtime);
    let (bytes, header, rows) = collect_projection_until(&mut client, "fourth").await;
    assert!(
        bytes.is_empty(),
        "no byte stream that assumes the session's width is sent: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    let header = header.expect("the state of the canonical screen");
    assert_eq!(
        header.dimensions,
        Dimensions::new(CANONICAL.0, CANONICAL.1),
        "the grid it is shown is the session's own"
    );
    assert_eq!(
        (header.viewport.columns.get(), header.viewport.rows.get()),
        (40, 12),
        "and the window is this terminal's own size"
    );
    let drawn: Vec<String> = rows
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    assert!(
        drawn.iter().any(|row| row.contains("first")),
        "the screen reaches it as canonical rows: {drawn:?}"
    );
    // Every cell carries the canonical column it occupies, which is what makes the projection
    // independent of this terminal's width: the client places each run itself.
    assert!(
        rows.iter()
            .flat_map(|row| row.runs.iter())
            .all(|run| run.column.get() + run.cells.get() <= CANONICAL.0),
        "and every run sits inside the canonical grid"
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: a side effect reaches the one attachment holding the input lease,
/// under the host's policy, and no other terminal watching the same output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_reaches_the_lease_holder_and_nobody_else() {
    // The bell, a clipboard write and a line of text in one write. The bell and the clipboard
    // write are side effects and have one destination; the text is output and reaches every
    // terminal watching, which is what makes it a marker both of them can wait for. A watcher that
    // has been sent the text has been sent everything the side effects could have come with.
    //
    // The clipboard write carries `secret`, which is the case section 8 names: a broadcast would
    // put it on every attached device.
    let host = host(
        "stty -echo -echonl || exit 1; read -r _; \
         printf '\\a\\033]52;c;c2VjcmV0\\033\\\\kr-rang.\\n'; read -r _; \
         printf 'kr-after.\\n'; read -r _",
    )
    .await;
    // One of them takes the input lease, which is what makes it the single destination, and what
    // lets it release the write.
    let (mut holder, _, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    let (mut watcher, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    keys.release(&host.runtime);
    // A second line, released once the first is through the engine, ends both runs past everything
    // the bell could have arrived with rather than at the line it was written on.
    produced(&host.runtime, b"kr-rang.\r\n").await;
    keys.release(&host.runtime);

    let rang = collect_until(&mut holder, b"kr-after.").await;
    let watched = collect_until(&mut watcher, b"kr-after.").await;
    assert!(
        rang.contains(&0x07),
        "the bell reaches the attachment holding the input lease: {:?}",
        String::from_utf8_lossy(&rang).escape_debug()
    );
    assert!(
        !watched.contains(&0x07),
        "and reaches nobody else, because a side effect has one destination: {:?}",
        String::from_utf8_lossy(&watched).escape_debug()
    );
    assert!(
        carries(&rang, b"]52;c;c2VjcmV0"),
        "the clipboard write reaches the lease holder, under the default policy: {:?}",
        String::from_utf8_lossy(&rang).escape_debug()
    );
    assert!(
        !carries(&watched, b"]52;") && !carries(&watched, b"c2VjcmV0"),
        "and the secret reaches no other terminal: {:?}",
        String::from_utf8_lossy(&watched).escape_debug()
    );
}

/// KR-REQ-08.38, KR-REQ-08.06: with nobody holding the input lease a side effect has no
/// destination, so it is recorded as a durable host event and reaches no attached terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_with_no_lease_holder_is_a_host_event_and_reaches_no_terminal() {
    // Two terminals watch and neither takes the keys, so nobody can release the application by
    // typing. It waits for a file this test creates once both are watching, on the internal disk
    // like everything else a launched process touches.
    let gate = std::env::temp_dir().join(format!("kalareach-gate-{}", kr_ipc::new_uuid()));
    let host = host(&format!(
        "stty -echo -echonl || exit 1; while [ ! -e '{}' ]; do sleep 0.1; done; \
         printf '\\a\\033]52;c;c2VjcmV0\\033\\\\kr-rang.\\n'; sleep 120",
        gate.display()
    ))
    .await;
    let (mut first, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    let (mut second, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    assert!(
        !host.runtime.session().lease().holder.is_present(),
        "watching is not taking the keys"
    );
    std::fs::write(&gate, b"").expect("opens the gate");

    let first_saw = collect_until(&mut first, b"kr-rang.").await;
    let second_saw = collect_until(&mut second, b"kr-rang.").await;
    for (who, saw) in [("first", &first_saw), ("second", &second_saw)] {
        assert!(
            !saw.contains(&0x07) && !carries(saw, b"]52;"),
            "the {who} watcher is sent neither side effect: {:?}",
            String::from_utf8_lossy(saw).escape_debug()
        );
    }

    // Both are in the session's own journal, which is what makes them durable: the bell, and the
    // clipboard write recorded by its size rather than by the secret it carried.
    let recorded = {
        let session = host.runtime.session();
        session
            .journal()
            .expect("this session keeps a journal")
            .host_events()
            .expect("reads the host events")
    };
    let kinds: Vec<&str> = recorded.iter().map(|event| event.kind.as_str()).collect();
    assert!(
        kinds.contains(&"bell") && kinds.contains(&"clipboard_write"),
        "both side effects are host events: {recorded:?}"
    );
    assert!(
        recorded
            .iter()
            .all(|event| !event.detail.contains("secret") && !event.detail.contains("c2VjcmV0")),
        "and the clipboard's content is not kept: {recorded:?}"
    );
    let _ = std::fs::remove_file(&gate);
}

/// KR-REQ-08.48: the host's own answer travels on a lane of its own. Asked while the person has a
/// bracketed paste open, it waits for the paste to close rather than landing inside it, reaches
/// the application after the question it answers, and neither needs nor takes the input lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_waits_for_an_open_paste_and_takes_no_lease() {
    // The application turns bracketed paste on, asks its question only when this test says so,
    // and reads its input only once the paste is over, so the order it reads things in is the
    // order the host wrote them. `cat -v` shows each escape as a caret, which makes that order
    // visible in the output.
    let gates = std::env::temp_dir().join(format!("kalareach-gates-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&gates).expect("a directory for this test's gates");
    let (ask, read) = (gates.join("ask"), gates.join("read"));
    let host = host(&format!(
        "stty raw -echo || exit 1; printf '\\033[?2004hkr-ready.'; \
         while [ ! -e '{}' ]; do sleep 0.1; done; printf '\\033[c'; \
         while [ ! -e '{}' ]; do sleep 0.1; done; exec cat -v",
        ask.display(),
        read.display()
    ))
    .await;
    let (_client, _, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    produced(&host.runtime, b"kr-ready.").await;
    let (holder, epoch) = {
        let session = host.runtime.session();
        let lease = session.lease();
        (lease.holder, lease.epoch.get())
    };

    // The person starts a paste, and the application asks its question while it is open.
    keys.type_bytes(&host.runtime, b"\x1b[200~kr-pasted-");
    std::fs::write(&ask, b"").expect("opens the gate");
    produced(&host.runtime, b"\x1b[c").await;
    // The rest of the paste, and its end.
    keys.type_bytes(&host.runtime, b"text\x1b[201~");
    std::fs::write(&read, b"").expect("opens the gate");

    // The answer arrives, and it arrives after the end of the paste rather than inside it.
    produced(&host.runtime, b"^[[?62;22c").await;
    let seen = retained(&host.runtime);
    assert!(
        carries(&seen, b"^[[200~kr-pasted-text^[[201~^[[?62;22c"),
        "the paste reaches the application whole, and the answer after it: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    let session = host.runtime.session();
    assert_eq!(
        session.lease().holder,
        holder,
        "the answer neither needed nor took the input lease"
    );
    assert_eq!(session.lease().epoch.get(), epoch);
    drop(session);
    let _ = std::fs::remove_dir_all(&gates);
}

/// KR-REQ-08.47: output direct mode cannot carry moves a direct terminal to projection, and it is
/// shown U+FFFD where the malformed bytes were rather than the bytes themselves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_output_moves_a_direct_terminal_to_projection_with_replacement_characters() {
    // A surrogate, which is never valid UTF-8, between two runs of good text, written only once
    // this terminal has joined, and then a line that ends the run.
    let host = host(
        "stty -echo -echonl || exit 1; read -r _; printf 'kr-ok\\355\\240\\200more\\n'; \
         read -r _; printf 'kr-after.\\n'; read -r _",
    )
    .await;
    let (mut client, presentation, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Direct),
        "the terminal is the session's size and qualified, so it starts with the live stream"
    );
    keys.release(&host.runtime);
    produced(&host.runtime, b"more\r\n").await;

    // The terminal is told that what it holds no longer continues, which is how a direct
    // attachment learns it has become a projected one. Everything it was sent as bytes before
    // that is read on the way.
    let started = tokio::time::Instant::now();
    let mut sent = Vec::new();
    loop {
        let remaining =
            (started + LIVENESS_DEADLINE).saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            panic!(
                "waited {:?} to be told the screen no longer continues; sent {:?}",
                started.elapsed(),
                String::from_utf8_lossy(&sent).escape_debug()
            );
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        match notification.event_type.as_str() {
            "session.output" => {
                if let Ok(event) = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    sent.extend_from_slice(event.bytes.as_slice());
                }
            }
            "session.resync" => break,
            _ => {}
        }
    }
    assert_eq!(
        presentation_of(&host, keys.attachment()),
        Some(TerminalPresentationMode::Viewport),
        "the batch could not be carried, so the attachment is projected"
    );
    // A client that is told so asks again, and what it is given now is the canonical screen.
    subscribe_over(&mut client, &host, keys.attachment()).await;
    keys.release(&host.runtime);
    let (bytes, _, rows) = collect_projection_until(&mut client, "kr-after.").await;
    assert!(
        !carries(&sent, b"\xed\xa0\x80") && !carries(&bytes, b"\xed\xa0\x80"),
        "the malformed bytes never reach the terminal: {:?} then {:?}",
        String::from_utf8_lossy(&sent).escape_debug(),
        String::from_utf8_lossy(&bytes).escape_debug()
    );
    let drawn: Vec<String> = rows
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    assert!(
        drawn
            .iter()
            .any(|row| row.contains("kr-ok\u{fffd}") && row.contains("more")),
        "they are drawn as U+FFFD between the good text: {drawn:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_screen_a_restoration_cannot_carry_is_never_continued_as_a_raw_stream() {
    // Four columns, and the application has printed exactly four characters. The canonical grid
    // holds `abcd` with a pending wrap: the next character belongs on the row below. No sequence
    // sets a pending wrap, so a restoration cannot put a physical terminal into that state, and a
    // terminal given the raw `X` afterwards would replace the `d` instead of wrapping.
    //
    // The `X` is written only once this terminal has joined, and that is the whole of the claim.
    // An application printing it on a timetable of its own can print it first, and then the screen
    // is one a restoration carries perfectly - `abcd` on one row, `X` on the next, no pending wrap
    // - and this terminal is handed the stream, correctly, with the `X` inside the restoration.
    let host = host_sized(
        "stty -echo -echonl || exit 1; printf 'abcd'; read -r _; printf 'X'; read -r _; \
         printf 'Y'; read -r _",
        Dimensions::new(4, 5),
    )
    .await;
    produced(&host.runtime, b"abcd").await;
    let (mut client, _, mut keys) = attached_holding_the_keys(&host, Dimensions::new(4, 5)).await;

    // The screen it is installed with, before anything else is written: the state a restoration
    // could not have carried is in it, which is why this attachment is painted rather than
    // continued.
    let (installed, header, installed_rows) = collect_projection_until(&mut client, "abcd").await;
    let header = header.expect("the state of the canonical screen");
    assert!(
        header.cursor.pending_wrap,
        "the attachment holds the canonical screen, pending wrap and all: {:?}",
        header.cursor
    );
    assert_eq!(
        presentation_of(&host, keys.attachment()),
        Some(TerminalPresentationMode::Viewport),
        "the screen it was given could not carry the pending wrap, so the host paints it rather \
         than continuing the stream into it"
    );

    // The character, and then one more released once the first is through the engine. The run ends
    // on the second, so a host that painted the `X` and *also* continued the stream into this
    // terminal would have queued those bytes in front of it.
    keys.release(&host.runtime);
    produced(&host.runtime, b"X").await;
    keys.release(&host.runtime);
    let (afterwards, _, later_rows) = collect_projection_until(&mut client, "Y").await;
    assert!(
        !installed.contains(&b'X') && !afterwards.contains(&b'X'),
        "the character never arrives as a span of the raw stream: {:?} then {:?}",
        String::from_utf8_lossy(&installed),
        String::from_utf8_lossy(&afterwards)
    );
    let rows: Vec<kr_protocol::projection::ProjectedRow> = installed_rows
        .into_iter()
        .chain(later_rows.into_iter())
        .collect();
    let drawn: Vec<String> = rows
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    assert!(
        drawn.iter().any(|row| row.contains('X')),
        "the character the application printed reaches it as a canonical cell: {drawn:?}"
    );
    assert!(
        drawn.iter().any(|row| row.contains("abcd")),
        "on a screen that still holds what was there before it: {drawn:?}"
    );
}
