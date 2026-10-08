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

use common::{
    Keys, LIVENESS_DEADLINE, carried_times, carries, produced, produced_times, retained,
    take_the_keys,
};

/// Whether `bytes` carry a bell: a BEL that is not inside a string. A BEL that ends an
/// operating-system command, as one does a window title, is that command's terminator and not a
/// bell, and a Windows pseudo-console ends the title it writes that way.
fn has_a_bell(bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == 0x07 {
            return true;
        }
        if bytes[at] == 0x1b && bytes.get(at + 1) == Some(&b']') {
            at += 2;
            while at < bytes.len()
                && bytes[at] != 0x07
                && !(bytes[at] == 0x1b && bytes.get(at + 1) == Some(&b'\\'))
            {
                at += 1;
            }
            at += if bytes.get(at) == Some(&0x07) { 1 } else { 2 };
        } else {
            at += 1;
        }
    }
    false
}

/// Bytes shown as their escaped text, which a failure message prints under `{:?}` as it is and not
/// as the structure that escapes it.
struct Shown(String);

impl Shown {
    fn of(bytes: &[u8]) -> Self {
        Self(String::from_utf8_lossy(bytes).escape_debug().to_string())
    }
}

impl std::fmt::Debug for Shown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::fmt::Display for Shown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

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
        time: kr_worker::action::time::TimeSources::system(),
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
                Shown::of(&seen)
            ),
            Err(_) => panic!(
                "waited {:?} for {:?} to reach this terminal: {:?}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                Shown::of(&seen)
            ),
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console answers the terminal's queries itself, so the query this case waits for never reaches the output and the host's answer is never asked for"
)]
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
         printf 'visible-line\\a\\033]52;c;aGVsbG8=\\033\\134\\n'; read -r _; \
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
         printf '\\a\\033]52;c;c2VjcmV0\\033\\134kr-rang.\\n'; read -r _; \
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
        has_a_bell(&rang),
        "the bell reaches the attachment holding the input lease: {:?}",
        Shown::of(&rang)
    );
    assert!(
        !has_a_bell(&watched),
        "and reaches nobody else, because a side effect has one destination: {:?}",
        Shown::of(&watched)
    );
    assert!(
        carries(&rang, b"]52;c;c2VjcmV0"),
        "the clipboard write reaches the lease holder, under the default policy: {:?}",
        Shown::of(&rang)
    );
    assert!(
        !carries(&watched, b"]52;") && !carries(&watched, b"c2VjcmV0"),
        "and the secret reaches no other terminal: {:?}",
        Shown::of(&watched)
    );
}

/// Collects the output this client is sent until the worker tells it to begin again.
///
/// Everything the worker wrote to this terminal ahead of that marker is what the terminal has been
/// given by the time it is asked to install a fresh screen. A connection that ends first, or a
/// marker that never arrives, fails here with what was seen.
async fn collect_until_told_to_begin_again(client: &mut LocalClient) -> Vec<u8> {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut seen: Vec<u8> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification))) => {
                match notification.event_type.as_str() {
                    "session.output" => {
                        if let Ok(event) = notification
                            .payload
                            .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            seen.extend_from_slice(event.bytes.as_slice());
                        }
                    }
                    "session.resync" => return seen,
                    _ => {}
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!(
                "waited {:?} for this terminal to be told to begin again and the connection ended \
                 ({error}): {:?}",
                started.elapsed(),
                Shown::of(&seen)
            ),
            Err(_) => panic!(
                "waited {:?} for this terminal to be told to begin again: {:?}",
                started.elapsed(),
                Shown::of(&seen)
            ),
        }
    }
}

/// The clipboard write the tests below split in half: `secret`, as the host renders it.
const CLIPBOARD_WRITE: &[u8] = b"\x1b]52;c;c2VjcmV0\x1b\\";

/// The application begins a clipboard write, waits for a line, and finishes it.
const SPLIT_CLIPBOARD_WRITE: &str = "stty -echo -echonl || exit 1; printf '\\033]52;c;c2Vj'; read -r _; \
     printf 'cmV0\\033\\134kr-rang.\\n'; read -r _";

/// KR-REQ-08.06, KR-REQ-08.38: a side effect that began before a terminal of another size joined,
/// and was completed after, reaches the terminal holding the input lease whole. It is neither
/// dropped, because the screen the terminal joined on already covers the cursor the sequence began
/// at, nor cut where that screen ends: an operating-system command that is sent in part leaves the
/// terminal inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back an unfinished sequence, so the first half of the clipboard write this case waits for never reaches the output"
)]
async fn a_side_effect_begun_before_a_terminal_joined_reaches_its_holder_whole() {
    let host = host(SPLIT_CLIPBOARD_WRITE).await;
    produced(&host.runtime, b"]52;c;c2Vj").await;
    // Another size, so it is served a projection for as long as it is attached, and takes the keys.
    let (mut holder, presentation, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(40, 12)).await;
    assert_eq!(presentation, Some(TerminalPresentationMode::Viewport));
    keys.release(&host.runtime);
    let (bytes, _, _) = collect_projection_until(&mut holder, "kr-rang.").await;
    assert!(
        carries(&bytes, CLIPBOARD_WRITE),
        "the clipboard write reaches the terminal holding the lease whole: {}",
        Shown::of(&bytes)
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: the byte that completes a side effect can also be the byte that
/// lets a held terminal take the stream. The terminal is then told to begin again on it, and the
/// effect it is owed is written before that, not dropped with the stream it replaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back an unfinished sequence, so the first half of the clipboard write this case waits for never reaches the output"
)]
async fn a_side_effect_completed_by_the_byte_that_releases_a_held_holder_reaches_it() {
    let host = host(SPLIT_CLIPBOARD_WRITE).await;
    produced(&host.runtime, b"]52;c;c2Vj").await;
    let (mut holder, _, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    assert!(
        host.runtime.session().forwarding_held(keys.attachment()),
        "the terminal joined inside the sequence, so it waits for a boundary to take the stream"
    );
    keys.release(&host.runtime);
    let before_the_marker = collect_until_told_to_begin_again(&mut holder).await;
    assert!(
        carries(&before_the_marker, CLIPBOARD_WRITE),
        "the clipboard write reached the terminal before it was told to begin again: {}",
        Shown::of(&before_the_marker)
    );
    // And once, not again with the screen it installs.
    subscribe_over(&mut holder, &host, keys.attachment()).await;
    let installed = collect_until(&mut holder, b"kr-rang.").await;
    assert!(
        !carries(&installed, b"]52;"),
        "the screen it installs carries no clipboard write: {}",
        Shown::of(&installed)
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
         printf '\\a\\033]52;c;c2VjcmV0\\033\\134kr-rang.\\n'; sleep 120",
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
            !has_a_bell(saw) && !carries(saw, b"]52;"),
            "the {who} watcher is sent neither side effect: {:?}",
            Shown::of(saw)
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
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console answers the terminal's queries itself, so the query this case waits for never reaches the output"
)]
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
        Shown::of(&seen)
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

/// KR-REQ-08.49: when the person with a paste open goes away, the paste is closed before the host's
/// held answer is written, so the answer never lands inside a paste nobody is left to finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console answers the terminal's queries itself, so the query this case waits for never reaches the output"
)]
async fn losing_the_paste_holder_closes_the_paste_before_a_held_reply() {
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

    // A paste is open when the application asks, so the answer waits.
    keys.type_bytes(&host.runtime, b"\x1b[200~kr-pasted-");
    std::fs::write(&ask, b"").expect("opens the gate");
    produced(&host.runtime, b"\x1b[c").await;
    // The person holding the paste goes away without finishing it.
    {
        let mut session = host.runtime.session();
        session.detach(keys.attachment()).expect("detaches");
        host.runtime.flush_locked(&mut session);
    }
    std::fs::write(&read, b"").expect("opens the gate");

    produced(&host.runtime, b"^[[?62;22c").await;
    let seen = retained(&host.runtime);
    assert!(
        carries(&seen, b"^[[200~kr-pasted-^[[201~^[[?62;22c"),
        "the host closed the paste before it delivered the answer: {}",
        Shown::of(&seen)
    );
    let _ = std::fs::remove_dir_all(&gates);
}

/// Reads what this client is sent for up to `window`, or until the output carries `marker`, and says
/// whether the marker arrived. Output bytes are kept in `seen`. A client told to resynchronise asks
/// for its screen again, which is what a terminal that fell behind does, and goes on reading.
async fn read_output(
    client: &mut LocalClient,
    host: &Host,
    attachment_id: AttachmentId,
    seen: &mut Vec<u8>,
    marker: Option<&[u8]>,
    window: std::time::Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        if marker.is_some_and(|marker| carries(seen, marker)) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification))) => {
                match notification.event_type.as_str() {
                    "session.output" => {
                        if let Ok(event) = notification
                            .payload
                            .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            seen.extend_from_slice(event.bytes.as_slice());
                        }
                    }
                    "session.resync" => subscribe_over(client, host, attachment_id).await,
                    _ => {}
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!("the connection ended while it was being read: {error}"),
            Err(_) => return false,
        }
    }
}

/// A terminal attached to an application that floods the host with questions, at the moment the
/// host has reported the flood as degraded and before anything is typed.
struct Flooded {
    host: Host,
    client: LocalClient,
    keys: Keys,
    /// Everything the attached terminal has been sent so far.
    seen: Vec<u8>,
}

/// Starts the flooding application and waits until the host has reported the flood as degraded.
///
/// A background loop asks the host what it is as fast as the shell can print, while the
/// application waits for a line from the person. The line it reads carries the host's answers in
/// front of what the person typed, so it says only whether the typing was at the end.
///
/// The loop starts only when this releases it, once its terminal is attached and holds the keys.
/// Attaching and taking the lease are mutations, and a mutation has a deadline: sent while the
/// flood was already running, each would wait on a session the flood keeps busy for as long as the
/// machine is slow, and the test would be racing that deadline rather than watching the lane
/// degrade. Nothing after the release has a deadline of its own.
async fn flooded_application() -> Flooded {
    let host = host(
        "stty raw -echo || exit 1; printf 'kr-ready.'; IFS= read -r _; \
         (while :; do printf '\\033[c'; done) & flood=$!; \
         printf 'kr-flooding.'; IFS= read -r line; kill $flood; \
         case \"$line\" in *kr-typed) printf 'kr-typed:kr-end' ;; *) printf 'kr-lost:kr-end' ;; esac; \
         read -r _",
    )
    .await;
    let (mut client, _, mut keys) =
        attached_holding_the_keys(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    produced(&host.runtime, b"kr-ready.").await;
    keys.release(&host.runtime);
    produced(&host.runtime, b"kr-flooding.").await;
    // The flood has outrun the lane's budget, and the host says so out of band, before the person
    // types anything.
    let degraded = || {
        host.runtime
            .session()
            .terminal_diagnostics()
            .into_iter()
            .find(|(kind, _)| *kind == kr_term::diag::DiagnosticKind::ResponseLaneDegraded)
            .map_or(0, |(_, count)| count)
    };
    // This terminal keeps reading all the while, as a terminal does, so it is never the slow
    // client a flood leaves behind; everything it is sent is kept for the checks that follow.
    let mut seen = Vec::new();
    let started = tokio::time::Instant::now();
    while degraded() == 0 {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for the flood to be reported as degraded",
            started.elapsed()
        );
        read_output(
            &mut client,
            &host,
            keys.attachment(),
            &mut seen,
            None,
            std::time::Duration::from_millis(20),
        )
        .await;
    }
    Flooded {
        host,
        client,
        keys,
        seen,
    }
}

/// KR-REQ-08.50: an application flooding the host with questions is answered within the lane's
/// budget with its degradation reported out of band; none of the questions reaches the attached
/// terminal, and the person's typing is not starved by the answers: the pseudo-terminal takes every
/// byte of the line typed to it while the flood goes on.
///
/// The host's part of typing ends at the pseudo-terminal. The lease's queue holds a line from the
/// moment the host accepts it until the writer has had it taken, and gives each byte back as the
/// terminal accepts it: a queue that has emptied, under the lease that queued the line, is a line
/// the terminal took whole. The writer also gives bytes back when a batch's authority has run out
/// or the lease has changed, and neither can be the case here: the line is typed with no
/// deadline, and the lease is compared before and after. The queue is a count and not a record of
/// the bytes, so it shows neither their order, which the writer's design gives, nor what the
/// application read of them. What the application then does with the line is the next test's
/// question, which the shell and the operating system's terminal answer as much as this host does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console answers the terminal's queries itself, so a flood of them never reaches the host to be degraded"
)]
async fn a_query_flood_is_degraded_rather_than_forwarded_and_the_typed_line_is_taken_whole() {
    let Flooded {
        host,
        mut client,
        mut keys,
        mut seen,
    } = flooded_application().await;
    // Typed once. `type_bytes` has the session say that it took every byte of the line, and hands
    // the batch to the writer.
    let lease = host.runtime.session().lease();
    keys.type_bytes(&host.runtime, b"kr-typed\n");
    let queued = host.runtime.session().queued_lease_bytes();
    let started = tokio::time::Instant::now();
    while queued.load() > 0 {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for the pseudo-terminal to take the typed line; {} of its bytes are still \
             queued for it",
            started.elapsed(),
            queued.load()
        );
        read_output(
            &mut client,
            &host,
            keys.attachment(),
            &mut seen,
            None,
            std::time::Duration::from_millis(20),
        )
        .await;
    }
    // A change of lease also empties the count, with nothing written: it is the same lease that
    // queued the line and that is now done with it.
    let after = host.runtime.session().lease();
    assert_eq!(
        (after.epoch, after.holder),
        (lease.epoch, lease.holder),
        "the lease the line was typed under is the one that is left"
    );
    assert!(
        !carries(&seen, b"\x1b[c"),
        "no question is forwarded to the attached terminal: {}",
        Shown::of(&seen[seen.len().saturating_sub(256)..])
    );
}

/// The application's half of the flood: the shell that floods the host reads the line typed to it,
/// ends the flood and answers, so what arrives is its answer at the end of the questions it was
/// given.
///
/// This is not run by default, because whether that answer arrives is decided by the shell and the
/// operating system's terminal, below this host. A bare pseudo-terminal with none of this crate's
/// code in it, running the same shell and answering its questions as the host does, leaves the
/// shell's answer undelivered in some runs on macOS while the machine is held busy: from about one
/// run in a thousand to about one in a hundred. In each of them the pseudo-terminal took every
/// byte of the line and its input queue is empty, the shell has read the line and run what follows
/// it, and what it wrote next cannot be read at the terminal's master until the shell ends, or
/// until a newline typed again ends its next read. That is why the line is not typed again here: a
/// newline typed again delivers the answer, which would hide a line the host lost.
///
/// The shell was also instrumented, with a file it writes after its read to say where it had got
/// to. That variant stalled more often, about one run in eight under a heavier load, and the
/// loads were not the same, so the two are not separated. It did not stall in 600 runs when it
/// waited for the flood it stopped before it answered, nor in 800 when `/usr/bin/printf` wrote its
/// answer. This types the line once and decides by the answer. Run it with `--ignored` to watch
/// the shell's side of the flood.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "the shell's answer to a line typed into a flood is sometimes not delivered on macOS, with no part of this crate in the path; the pseudo-terminal's taking of the line is the default case"]
async fn a_flooded_application_answers_the_line_typed_to_it() {
    let Flooded {
        host,
        mut client,
        mut keys,
        mut seen,
    } = flooded_application().await;
    // The line arrives among whatever answers the lane let through, and the flood stops.
    keys.type_bytes(&host.runtime, b"kr-typed\n");
    assert!(
        read_output(
            &mut client,
            &host,
            keys.attachment(),
            &mut seen,
            Some(b":kr-end"),
            LIVENESS_DEADLINE,
        )
        .await,
        "waited {LIVENESS_DEADLINE:?} for the application's last line to reach this terminal: {}",
        Shown::of(&seen[seen.len().saturating_sub(256)..])
    );
    let written = retained(&host.runtime);
    assert!(
        carries(&written, b"kr-typed:kr-end"),
        "what the person typed reached the application whole; it wrote {}",
        Shown::of(&written[written.len().saturating_sub(256)..])
    );
    assert!(
        !carries(&seen, b"\x1b[c"),
        "no question is forwarded to the attached terminal: {}",
        Shown::of(&seen[seen.len().saturating_sub(256)..])
    );
}

/// KR-REQ-08.50: a terminal that reconnects is replayed neither the application's question nor the
/// host's answer. The answer was written into the application's input once, when it was asked;
/// the terminal that comes back, even one resuming from a position before the question, is drawn
/// the screen as it is, and nothing in its stream asks its own terminal the question again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console answers the terminal's queries itself, so the host's answer this case waits for is never sent"
)]
async fn a_reconnecting_terminal_is_replayed_neither_the_question_nor_the_answer() {
    // The application asks once, when this test opens the gate, and then shows everything it is
    // given as text, so every answer the host writes into its input can be counted.
    let gates = std::env::temp_dir().join(format!("kalareach-gates-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&gates).expect("a directory for this test's gates");
    let ask = gates.join("ask");
    let host = host(&format!(
        "stty raw -echo || exit 1; printf 'kr-ready.'; \
         while [ ! -e '{}' ]; do sleep 0.1; done; printf '\\033[c'; exec cat -v",
        ask.display()
    ))
    .await;
    let (mut first, _, _) = attached(&host, Dimensions::new(CANONICAL.0, CANONICAL.1)).await;
    produced(&host.runtime, b"kr-ready.").await;
    // Where this terminal had got to before the question.
    let before_the_question = host.runtime.session().output_cursor();
    std::fs::write(&ask, b"").expect("opens the gate");
    let answered = collect_until(&mut first, b"^[[?62;22c").await;
    assert!(
        !carries(&answered, b"\x1b[c"),
        "the question never reached the attached terminal: {}",
        Shown::of(&answered)
    );

    // The connection goes, and the attachment with it.
    drop(first);
    let started = tokio::time::Instant::now();
    while !host.runtime.session().attachments().is_empty() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for the lost connection's attachment to go",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // The terminal comes back and asks to resume from where it was before the question.
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects again");
    let dimensions = Dimensions::new(CANONICAL.0, CANONICAL.1);
    let (attachment_id, presentation) = attach_over(&mut client, &host, dimensions).await;
    assert_eq!(
        presentation,
        Some(TerminalPresentationMode::Direct),
        "the terminal is the session's size, so it takes the stream directly"
    );
    let mut keys = take_the_keys(
        &mut client,
        host.environment_id,
        host.session_id,
        attachment_id,
    )
    .await;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::some(kr_protocol::scalars::U64::new(before_the_question)),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
    // A line typed after the reconnection ends the run, so everything the reconnection was sent
    // is in front of it.
    keys.type_bytes(&host.runtime, b"kr-back.");
    let seen = collect_until(&mut client, b"kr-back.").await;
    assert!(
        !carries(&seen, b"\x1b[c"),
        "the question is not replayed to a reconnecting terminal, whose own terminal would answer \
         it: {}",
        Shown::of(&seen)
    );
    assert!(
        !carries(&seen, b"\x1b[?62;22c"),
        "and neither is the answer: {}",
        Shown::of(&seen)
    );
    let written = retained(&host.runtime);
    assert_eq!(
        carried_times(&written, b"^[[?62;22c"),
        1,
        "the application was answered once, and not again when the terminal came back: {}",
        Shown::of(&written)
    );
    assert!(
        carries(&written, b"^[[?62;22ckr-back."),
        "what was typed after the reconnection follows the one answer directly: {}",
        Shown::of(&written)
    );
    let _ = std::fs::remove_dir_all(&gates);
}

/// KR-REQ-08.47: output direct mode cannot carry moves a direct terminal to projection, and it is
/// shown U+FFFD where the malformed bytes were rather than the bytes themselves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console decodes the bytes itself and writes valid text, so the malformed bytes this case sends never reach the host"
)]
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
                Shown::of(&sent)
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
        Shown::of(&sent),
        Shown::of(&bytes)
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

/// What the worker says a share's issuer would be shown of the screen, for a scope that includes
/// the live screen or one that does not.
async fn screen_previewed(
    host: &Host,
    include_live_screen: bool,
) -> kr_protocol::sharing::SessionScreenPreviewResult {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .request(
            Method::SessionScreenPreview,
            &kr_protocol::sharing::SessionScreenPreviewParams {
                session_id: host.session_id,
                history: kr_protocol::grant::HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the preview is answered")
        .to_typed()
        .expect("decodes")
}

/// KR-REQ-10.50: the preview of a shared live screen is the text of the buffer that is showing and
/// nothing behind it. The application printed a line on the primary screen, switched to the
/// alternate one and printed another: the preview carries the second and not the first, which a
/// recipient would see only if the application went back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_screen_preview_is_the_buffer_that_is_showing_and_not_the_one_behind_it() {
    let host = host(
        "printf 'on the primary screen\\n'; printf '\\033[?1049h'; \
         printf 'on the alternate screen\\n'; read -r _",
    )
    .await;
    produced(&host.runtime, b"on the alternate screen\r\n").await;

    let preview = screen_previewed(&host, true)
        .await
        .screen
        .0
        .expect("a scope that includes the screen is shown it");
    assert!(!preview.truncated);
    assert!(
        preview
            .lines
            .iter()
            .any(|line| line == "on the alternate screen"),
        "{preview:?}"
    );
    assert!(
        !preview.lines.iter().any(|line| line.contains("primary")),
        "the buffer that is not showing is not previewed: {preview:?}"
    );
}

/// KR-REQ-10.50: what has scrolled off the screen is not previewed. The application printed sixty
/// numbered lines on a screen of twenty-four, so the preview ends on the sixtieth and begins
/// where the screen does, with the first thirty-six nowhere in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_screen_preview_holds_no_line_that_scrolled_off() {
    let host =
        host("i=1; while [ $i -le 60 ]; do printf 'line %s\\n' $i; i=$((i+1)); done; read -r _")
            .await;
    produced(&host.runtime, b"line 60\r\n").await;

    let preview = screen_previewed(&host, true)
        .await
        .screen
        .0
        .expect("a scope that includes the screen is shown it");
    assert_eq!(preview.lines.last().map(String::as_str), Some("line 60"));
    assert!(
        preview.lines.len() <= usize::try_from(CANONICAL.1).expect("rows"),
        "{preview:?}"
    );
    for scrolled in ["line 1", "line 12", "line 36"] {
        assert!(
            !preview.lines.iter().any(|line| line == scrolled),
            "{scrolled:?} scrolled off: {preview:?}"
        );
    }
}

/// KR-REQ-10.50: a scope that does not include the live screen is shown none of it, whatever is on
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_scope_without_the_live_screen_previews_none_of_it() {
    let host = host("printf 'a secret on the screen\\n'; read -r _").await;
    produced(&host.runtime, b"a secret on the screen\r\n").await;
    assert_eq!(screen_previewed(&host, false).await.screen.0, None);
}

/// KR-REQ-10.50: a screen too large for a preview comes back cut and says so, which is what a
/// caller that must show all of what it shares needs to refuse it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_screen_larger_than_a_preview_comes_back_marked_cut() {
    let host = host_sized(
        "i=1; while [ $i -le 280 ]; do printf 'row %s\\n' $i; i=$((i+1)); done; read -r _",
        Dimensions::new(80, 300),
    )
    .await;
    produced(&host.runtime, b"row 280\r\n").await;

    let preview = screen_previewed(&host, true)
        .await
        .screen
        .0
        .expect("a scope that includes the screen is shown it");
    assert!(preview.truncated, "{preview:?}");
    assert_eq!(preview.lines.len(), kr_protocol::sharing::MAX_PREVIEW_LINES);
}

/// KR-REQ-10.50: a row the grid had to cut to keep it inside its byte bound is a screen the
/// preview did not show whole, even when what remains is shorter than a preview line. The
/// application drew five hundred cells of a link whose identifier is as long as a link may be,
/// alternating bold and plain so that every cell is a run with a copy of the link of its own: the
/// grid stops the row at its bound after fewer cells than a preview line holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_row_the_grid_cut_is_a_screen_the_preview_says_was_cut() {
    let identifier = "i".repeat(2_026);
    let host = host_sized(
        &format!(
            "printf '\\033]8;id={identifier};https://e.invalid/\\033\\\\'; \
             i=0; while [ $i -lt 1000 ]; do printf 'a\\033[1mb\\033[0m'; i=$((i+1)); done; \
             printf 'END\\n'; read -r _"
        ),
        Dimensions::new(2_048, 4),
    )
    .await;
    produced(&host.runtime, b"END\r\n").await;

    let preview = screen_previewed(&host, true)
        .await
        .screen
        .0
        .expect("a scope that includes the screen is shown it");
    let shown = preview.lines.first().expect("the row is there");
    assert!(
        shown.chars().count() < kr_protocol::sharing::MAX_PREVIEW_LINE_CHARS,
        "the grid stopped the row before the preview's own cut could: {}",
        shown.chars().count()
    );
    assert!(preview.truncated, "{preview:?}");
}
