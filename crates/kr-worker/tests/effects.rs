//! Where a side effect goes once the application has caused it, in a session of this process.
//!
//! Section 8 gives a bell, a clipboard write or a notification one destination: the attachment that
//! holds the input lease. An effect that reaches that attachment's stream is delivered; one that
//! cannot, because there is nobody to send it to, is a durable host event in the session's journal.
//! There is no third outcome, and these tests follow each effect to one of the two.
//!
//! The session runs in this process with a shell that only waits, so every byte of output is one a
//! test gives it, and each delivery is read from the stream the way the worker's service reads it.

use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::recovery::ResyncReason;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::output::{OutputDelivery, OutputStream};
use kr_worker::session::{Session, SessionConfig};

/// A bell, as the host renders it.
const BELL: &[u8] = &[0x07];

/// `secret` written to the clipboard, as the host renders it.
const CLIPBOARD_WRITE: &[u8] = b"\x1b]52;c;c2VjcmV0\x1b\\";

/// A session that waits, and the directory its journal lives in.
struct Fixture {
    session: Session,
    session_id: SessionId,
    _host: kr_ipc::testing::TempHost,
}

impl Fixture {
    fn new() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("sleep 120"),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(host.environment().journal_database(session_id)),
            spool_directory: Some(host.environment().session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 1024 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens");
        session.launch().expect("launches");
        Self {
            session,
            session_id,
            _host: host,
        }
    }

    /// Attaches a terminal of the session's size that declares `profile` and asks to type.
    fn attach(&mut self, profile: &str) -> AttachmentId {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some(profile.to_owned()),
            requested,
        };
        let id = AttachmentId::new(kr_ipc::new_uuid());
        self.session
            .attach(&params, params.requested.clone(), id)
            .expect("attaches");
        id
    }

    /// Takes the input lease for `attachment`.
    fn take_the_keys(&mut self, attachment: AttachmentId) {
        self.session
            .acquire_input(attachment, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("the lease is granted");
    }

    /// Subscribes `attachment` as the worker's service does: its screen, then its stream.
    fn subscribe(&mut self, attachment: AttachmentId) -> OutputStream {
        self.session.join(attachment).expect("joins");
        let stream = self.session.subscribe(attachment).expect("subscribes");
        self.session
            .install_projection(attachment)
            .expect("installs");
        stream
    }

    /// Gives the session output as its terminal would.
    fn output(&mut self, bytes: &[u8]) {
        let _ = self.session.ingest_output(bytes);
    }

    /// The host events the session's journal holds, as (kind, output cursor).
    fn host_events(&self) -> Vec<(String, u64)> {
        self.session
            .journal()
            .expect("the session keeps a journal")
            .host_events()
            .expect("reads the host events")
            .into_iter()
            .map(|event| (event.kind, event.output_cursor))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.session.force_close();
    }
}

/// Everything queued on a stream, in order, as what it is.
fn drained(stream: &mut OutputStream) -> Vec<String> {
    let mut seen = Vec::new();
    while let Some(delivery) = stream.try_recv() {
        stream.written(delivery.len());
        seen.push(match delivery {
            OutputDelivery::Effect { cursor, bytes } => format!("effect {cursor} {bytes:?}"),
            OutputDelivery::Bytes { cursor, .. } => format!("bytes {cursor}"),
            OutputDelivery::Resync(_) => "resync".to_owned(),
            OutputDelivery::Projection { .. } => "projection".to_owned(),
            other => format!("{other:?}"),
        });
    }
    seen
}

/// The delivery an effect is: the cursor its sequence began at, and the bytes that perform it.
fn effect(cursor: u64, bytes: &[u8]) -> String {
    format!("effect {cursor} {:?}", bytes.to_vec())
}

/// KR-REQ-08.06, KR-REQ-08.38: an effect reaches the stream of the attachment that holds the lease,
/// at the cursor its sequence began at, and nothing is recorded: it had a destination.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_for_the_lease_holder_is_delivered_and_not_recorded() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    let _ = drained(&mut stream);

    fixture.output(b"ab\x07");
    let seen = drained(&mut stream);
    assert_eq!(
        seen.iter()
            .filter(|seen| seen.starts_with("effect"))
            .collect::<Vec<_>>(),
        vec![&effect(2, BELL)],
        "{seen:?}"
    );
    assert!(fixture.host_events().is_empty());
}

/// KR-REQ-08.38: the lease holder has not subscribed to output, so the effect has nowhere to go and
/// is a durable host event, not lost and not shown to anybody else.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_for_a_holder_with_no_subscription_is_a_host_event() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    let watcher = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut watching = fixture.subscribe(watcher);
    let _ = drained(&mut watching);

    fixture.output(b"\x07");
    assert_eq!(fixture.host_events(), vec![("bell".to_owned(), 0)]);
    assert!(
        !drained(&mut watching)
            .iter()
            .any(|seen| seen.starts_with("effect")),
        "nobody else is sent it"
    );
}

/// KR-REQ-08.38: the holder has been told to begin again and has not come back, so the effect has
/// nowhere to go and is a durable host event; the holder is sent nothing but its marker.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_for_a_holder_still_beginning_again_is_a_host_event() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    let _ = drained(&mut stream);
    fixture
        .session
        .require_resync(holder, ResyncReason::ProjectionReset);
    assert_eq!(drained(&mut stream), vec!["resync".to_owned()]);

    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(
        fixture.host_events(),
        vec![("clipboard_write".to_owned(), 0)]
    );
    assert!(drained(&mut stream).is_empty());
}

/// KR-REQ-08.38: an effect the holder's queue has no room for tells it to begin again, and is a
/// durable host event, not dropped behind the marker.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_a_full_queue_cannot_take_is_a_host_event() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    fixture.session.join(holder).expect("joins");
    let mut stream = fixture
        .session
        .subscribe_within(holder, 8)
        .expect("subscribes with a queue of eight bytes");
    let _ = drained(&mut stream);

    fixture.output(CLIPBOARD_WRITE);
    assert!(fixture.session.is_resynchronising(holder));
    assert_eq!(drained(&mut stream), vec!["resync".to_owned()]);
    assert_eq!(
        fixture.host_events(),
        vec![("clipboard_write".to_owned(), 0)]
    );
}

/// KR-REQ-08.38: the byte that completes an effect can also end the lease, because it negotiates a
/// keyboard encoding the holder's terminal cannot send. The effect was the holder's when the
/// application caused it and nobody holds the lease when it is delivered: it has no destination,
/// and is a durable host event rather than anybody's.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_whose_lease_ended_in_the_same_batch_is_a_host_event() {
    let mut fixture = Fixture::new();
    // GNU screen implements neither enhanced keyboard protocol.
    let holder = fixture.attach("screen-256color");
    let watcher = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut holding = fixture.subscribe(holder);
    let mut watching = fixture.subscribe(watcher);
    let _ = drained(&mut holding);
    let _ = drained(&mut watching);

    fixture.output(b"\x07\x1b[>4;2m");
    assert!(
        !fixture.session.lease().holder.is_present(),
        "the keys were taken from the holder"
    );
    assert_eq!(fixture.host_events(), vec![("bell".to_owned(), 0)]);
    for stream in [&mut holding, &mut watching] {
        assert!(
            !drained(stream)
                .iter()
                .any(|seen| seen.starts_with("effect")),
            "neither terminal is sent it"
        );
    }
}

/// What a stream was sent, leaving out the output spans and the screens: the effects and the
/// markers, which are what the order of is about.
fn effects_and_markers(stream: &mut OutputStream) -> Vec<String> {
    drained(stream)
        .into_iter()
        .filter(|seen| seen.starts_with("effect") || seen == "resync")
        .collect()
}

/// KR-REQ-08.06, KR-REQ-08.38, KR-REQ-27.06: a terminal that joined inside a clipboard write is held
/// on a projection until the sequence ends, and the byte that ends it both completes the effect it
/// is owed and lets the terminal take the stream, which tells it to begin again. The effect is sent
/// before that marker: a stream that has been told to resynchronise is sent nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_completed_by_the_byte_that_releases_a_held_holder_reaches_it_before_its_marker()
{
    let mut fixture = Fixture::new();
    fixture.output(b"\x1b]52;c;c2Vj");
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    assert!(
        fixture.session.forwarding_held(holder),
        "it joined inside the sequence, so it waits for a boundary to take the stream"
    );
    let _ = drained(&mut stream);

    fixture.output(b"cmV0\x1b\\");
    assert_eq!(
        effects_and_markers(&mut stream),
        vec![effect(0, CLIPBOARD_WRITE), "resync".to_owned()]
    );
    assert!(fixture.host_events().is_empty(), "it reached its holder");
}

/// KR-REQ-08.06, KR-REQ-08.38: a bell and a switch to the alternate buffer in one write. The switch
/// tells a terminal that takes the stream directly to begin again, and the bell it is owed goes out
/// before the marker rather than being dropped behind it.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_in_a_batch_that_switches_buffers_reaches_a_direct_holder_before_its_marker() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    let _ = drained(&mut stream);

    fixture.output(b"\x07\x1b[?1049hX");
    assert_eq!(
        effects_and_markers(&mut stream),
        vec![effect(0, BELL), "resync".to_owned()]
    );
    assert!(fixture.host_events().is_empty(), "it reached its holder");
}
