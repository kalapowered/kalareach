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
        self.attach_sized(profile, Dimensions::new(80, 24))
    }

    /// The same for a terminal of `dimensions`, which is served a projection when it is not the
    /// session's own size.
    fn attach_sized(&mut self, profile: &str, dimensions: Dimensions) -> AttachmentId {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(dimensions),
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
            OutputDelivery::Effect(owed) => {
                format!("effect {} {:?}", owed.effect.at, owed.bytes.to_vec())
            }
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

/// KR-REQ-08.38: every effect a holder that cannot take them was owed is recorded, in the order the
/// application caused them, however many one read of output holds. They are kept in one
/// transaction, so a holder that has stopped taking output costs the read loop one commit for the
/// output it reads and not one for each bell in it.
#[tokio::test(flavor = "multi_thread")]
async fn the_bells_of_one_read_a_holder_cannot_take_are_all_recorded_in_order() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    // No subscription: the holder has nowhere to be sent them.
    let output: Vec<u8> = (0..200).flat_map(|_| *b"x\x07").collect();
    fixture.output(&output);
    let recorded = fixture.host_events();
    assert_eq!(recorded.len(), 200, "{recorded:?}");
    assert!(recorded.iter().all(|(kind, _)| kind == "bell"));
    let cursors: Vec<u64> = recorded.iter().map(|(_, cursor)| *cursor).collect();
    let expected: Vec<u64> = (0..200).map(|bell| 2 * bell + 1).collect();
    assert_eq!(
        cursors, expected,
        "in the order they happened, at their own cursors"
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: the holder of the lease is a terminal of another size, served a
/// projection. The effect is owed to it all the same, and queued on its stream; a terminal of the
/// session's size that is only watching is sent nothing, and nothing is recorded.
#[tokio::test(flavor = "multi_thread")]
async fn an_effect_for_a_projected_holder_is_delivered_to_it_and_to_nobody_else() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach_sized("xterm-256color", Dimensions::new(40, 12));
    let watcher = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut holding = fixture.subscribe(holder);
    let mut watching = fixture.subscribe(watcher);
    let _ = drained(&mut holding);
    let _ = drained(&mut watching);

    fixture.output(b"\x07");
    let held = drained(&mut holding);
    assert!(
        held.contains(&effect(0, BELL)),
        "the projected holder is sent its bell: {held:?}"
    );
    assert!(
        !drained(&mut watching)
            .iter()
            .any(|seen| seen.starts_with("effect")),
        "and the terminal that only watches is not"
    );
    assert!(fixture.host_events().is_empty());
}

/// What a stream was sent as clipboard writes: the effects that carry `CLIPBOARD_WRITE` bytes.
fn clipboard_writes(stream: &mut OutputStream) -> usize {
    drained(stream)
        .iter()
        .filter(|seen| seen.starts_with("effect") && seen.contains("[27, 93, 53, 50"))
        .count()
}

impl Fixture {
    /// The host events the journal holds, as (kind, detail).
    fn host_event_details(&self) -> Vec<(String, String)> {
        self.session
            .journal()
            .expect("the session keeps a journal")
            .host_events()
            .expect("reads the host events")
            .into_iter()
            .map(|event| (event.kind, event.detail))
            .collect()
    }
}

/// KR-REQ-18.11, KR-REQ-08.38: a clipboard write the application asks for while the lease is held
/// by an attachment whose terminal takes none is sent to nobody, whoever else is watching, and is a
/// durable host event of its own kind. The control: the same write for a holder whose terminal takes
/// clipboard writes is delivered to it and recorded nowhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_clipboard_write_for_a_holder_whose_terminal_takes_none_is_a_host_event() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    let watcher = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(holder);
    fixture.take_the_keys(holder);
    let mut holding = fixture.subscribe(holder);
    let mut watching = fixture.subscribe(watcher);
    let _ = drained(&mut holding);
    let _ = drained(&mut watching);

    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(
        clipboard_writes(&mut holding),
        0,
        "the holder's terminal takes none"
    );
    assert_eq!(
        clipboard_writes(&mut watching),
        0,
        "and nobody else is given what it declined"
    );
    assert_eq!(
        fixture.host_event_details(),
        vec![(
            "clipboard_write_declined".to_owned(),
            "Clipboard, 6 bytes".to_owned()
        )],
        "the host event says what was asked and how much, and keeps none of it"
    );

    // The control.
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.take_the_keys(holder);
    let mut holding = fixture.subscribe(holder);
    let _ = drained(&mut holding);
    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(clipboard_writes(&mut holding), 1);
    assert!(fixture.host_events().is_empty());
}

/// KR-REQ-18.11: what a terminal declines is the clipboard write and nothing else: a bell, a
/// notification and the rest of what the application asks of a terminal still reach it, and a clipboard
/// read still gets its empty answer from the host.
#[tokio::test(flavor = "multi_thread")]
async fn a_holder_whose_terminal_takes_no_clipboard_writes_is_still_sent_everything_else() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(holder);
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    let _ = drained(&mut stream);

    fixture.output(b"ab\x07");
    let seen = drained(&mut stream);
    assert!(seen.contains(&effect(2, BELL)), "{seen:?}");
    assert!(
        fixture.host_events().is_empty(),
        "{:?}",
        fixture.host_events()
    );
}

/// KR-REQ-18.11: a clipboard write goes to whoever holds the lease when the application caused it,
/// and a terminal that takes none does not become one that does by taking the lease, nor the other
/// way about: one write for each side of a takeover is decided by the holder it was caused under.
#[tokio::test(flavor = "multi_thread")]
async fn a_lease_taken_between_two_clipboard_writes_sends_the_second_to_the_new_holder() {
    // A declines and holds; B takes clipboard writes and takes the lease after the first write.
    let mut fixture = Fixture::new();
    let first = fixture.attach("xterm-256color");
    let second = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(first);
    fixture.take_the_keys(first);
    let mut first_stream = fixture.subscribe(first);
    let mut second_stream = fixture.subscribe(second);
    let _ = drained(&mut first_stream);
    let _ = drained(&mut second_stream);

    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(clipboard_writes(&mut first_stream), 0);
    assert_eq!(clipboard_writes(&mut second_stream), 0);
    fixture.take_the_keys(second);
    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(
        clipboard_writes(&mut second_stream),
        1,
        "the new holder takes it"
    );
    assert_eq!(
        clipboard_writes(&mut first_stream),
        0,
        "the old one is sent nothing"
    );
    assert_eq!(
        fixture.host_events(),
        vec![("clipboard_write_declined".to_owned(), 0)],
        "only the write the first holder declined is a host event"
    );

    // The other way: A takes them and holds; B declines and takes the lease.
    let mut fixture = Fixture::new();
    let first = fixture.attach("xterm-256color");
    let second = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(second);
    fixture.take_the_keys(first);
    let mut first_stream = fixture.subscribe(first);
    let mut second_stream = fixture.subscribe(second);
    let _ = drained(&mut first_stream);
    let _ = drained(&mut second_stream);

    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(clipboard_writes(&mut first_stream), 1);
    fixture.take_the_keys(second);
    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(
        clipboard_writes(&mut second_stream),
        0,
        "the new holder takes none"
    );
    assert_eq!(
        clipboard_writes(&mut first_stream),
        0,
        "and the old one is not sent it"
    );
    assert_eq!(
        fixture.host_events(),
        vec![(
            "clipboard_write_declined".to_owned(),
            CLIPBOARD_WRITE.len() as u64
        )]
    );
}

/// KR-REQ-18.11, KR-REQ-08.38: a clipboard write whose sequence is split across a takeover is
/// decided where the sequence completes, as every effect is: by the holder at that moment.
#[tokio::test(flavor = "multi_thread")]
async fn a_clipboard_write_split_across_a_takeover_is_decided_where_it_completes() {
    let mut fixture = Fixture::new();
    let first = fixture.attach("xterm-256color");
    let second = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(first);
    fixture.take_the_keys(first);
    let mut first_stream = fixture.subscribe(first);
    let mut second_stream = fixture.subscribe(second);
    let _ = drained(&mut first_stream);
    let _ = drained(&mut second_stream);

    fixture.output(b"\x1b]52;c;c2Vj");
    fixture.take_the_keys(second);
    fixture.output(b"cmV0\x1b\\");
    assert_eq!(
        clipboard_writes(&mut second_stream),
        1,
        "it completed under the second holder, whose terminal takes it"
    );
    assert_eq!(clipboard_writes(&mut first_stream), 0);
    assert!(
        fixture.host_events().is_empty(),
        "{:?}",
        fixture.host_events()
    );

    // And the converse: begun under a holder that takes writes, completed under one that does not.
    let mut fixture = Fixture::new();
    let first = fixture.attach("xterm-256color");
    let second = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(second);
    fixture.take_the_keys(first);
    let mut first_stream = fixture.subscribe(first);
    let mut second_stream = fixture.subscribe(second);
    let _ = drained(&mut first_stream);
    let _ = drained(&mut second_stream);

    fixture.output(b"\x1b]52;c;c2Vj");
    fixture.take_the_keys(second);
    fixture.output(b"cmV0\x1b\\");
    assert_eq!(clipboard_writes(&mut first_stream), 0);
    assert_eq!(clipboard_writes(&mut second_stream), 0);
    assert_eq!(
        fixture.host_events(),
        vec![("clipboard_write_declined".to_owned(), 0)]
    );
}

/// KR-REQ-18.11: nobody holding the lease is still the content-free host event it always was, whether
/// or not the attachments there are decline clipboard writes: a write with no holder is not declined
/// by anybody.
#[tokio::test(flavor = "multi_thread")]
async fn a_clipboard_write_with_no_lease_holder_is_the_host_event_it_always_was() {
    let mut fixture = Fixture::new();
    let watcher = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(watcher);
    let mut watching = fixture.subscribe(watcher);
    let _ = drained(&mut watching);

    fixture.output(CLIPBOARD_WRITE);
    assert_eq!(clipboard_writes(&mut watching), 0);
    assert_eq!(
        fixture.host_events(),
        vec![("clipboard_write".to_owned(), 0)]
    );
}

/// KR-REQ-08.38: every clipboard write a holder's terminal declined in one read is recorded, in the
/// order the application caused them, in one transaction, as the bells a holder cannot take are.
#[tokio::test(flavor = "multi_thread")]
async fn the_clipboard_writes_of_one_read_a_terminal_declines_are_all_recorded_in_order() {
    let mut fixture = Fixture::new();
    let holder = fixture.attach("xterm-256color");
    fixture.session.decline_clipboard_writes(holder);
    fixture.take_the_keys(holder);
    let mut stream = fixture.subscribe(holder);
    let _ = drained(&mut stream);

    let output: Vec<u8> = (0..50)
        .flat_map(|_| CLIPBOARD_WRITE.iter().copied().chain(*b"x"))
        .collect();
    fixture.output(&output);
    let recorded = fixture.host_events();
    assert_eq!(recorded.len(), 50, "{recorded:?}");
    assert!(
        recorded
            .iter()
            .all(|(kind, _)| kind == "clipboard_write_declined")
    );
    let step = CLIPBOARD_WRITE.len() as u64 + 1;
    let cursors: Vec<u64> = recorded.iter().map(|(_, cursor)| *cursor).collect();
    assert_eq!(
        cursors,
        (0..50).map(|write| write * step).collect::<Vec<_>>()
    );
    assert_eq!(clipboard_writes(&mut stream), 0);
}
