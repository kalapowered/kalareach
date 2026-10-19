//! The single input lease, its epoch, and the paste framing that hangs off it.
//!
//! Every test here names the requirement row it closes. What they have in common is that none of
//! them can be answered by a unit test: whether a keystroke reached an application, whether a
//! paste was closed before somebody else typed, and whether an approval prompt executed once are
//! questions about a real pseudo-terminal with a real program reading it.
//!
//! The root programs put the terminal into raw mode with the echo off first. That is what makes
//! the session's output the bytes the *application* received rather than the bytes the line
//! discipline repeated back as they arrived, which is the only way to tell the two apart.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::{BoundLink, Client, Codec, LocalClient};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::ActorIngress;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ConnectionId, ControllerGeneration, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputWriteParams, InputWriteResult};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

/// The bracketed-paste start delimiter.
const PASTE_START: &[u8] = b"\x1b[200~";

/// The bracketed-paste end delimiter.
const PASTE_END: &[u8] = b"\x1b[201~";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn configuration(host: &kr_ipc::testing::TempHost, script: &str) -> SessionConfig {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(script),
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
    }
}

/// A terminal attachment that declares `profile` and asks to observe and to type.
fn terminal(session_id: SessionId, profile: Option<&str>) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable(profile.map(str::to_owned)),
        requested,
    }
}

/// A semantic attachment, which builds its keys through the shared typed encoder.
fn semantic(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveSemantic);
    requested.insert(AttachmentCapability::Input);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Semantic,
        claim_geometry: false,
        dimensions: Nullable::null(),
        terminal_profile_id: Nullable::null(),
        requested,
    }
}

/// Attaches `params` to `session` and returns the identifier it was given.
fn attach(session: &mut Session, params: &SessionAttachParams) -> AttachmentId {
    let id = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(params, params.requested.clone(), id)
        .expect("attaches");
    id
}

fn connection() -> ConnectionId {
    ConnectionId::new(kr_ipc::new_uuid())
}

/// Reads everything the session has retained.
fn retained(session: &Session) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = session
            .history_page(cursor, 1024 * 1024)
            .expect("reads the retained output");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        seen.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    seen
}

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never happens. The five
/// and ten second windows these waits had were inside the range the slowest reference hosts reach
/// when several suites share them, which turned each of them into a coin toss; two minutes is
/// outside it. The poll intervals are unchanged, so a wait that succeeds costs what it always did.
/// What is deliberately *not* raised is a window that asserts something never arrives, or one that
/// samples what arrives inside it: those are not waiting for anything.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Waits for `marker` to appear in the session's retained output.
///
/// A marker that never appears is a failure here rather than partial output a caller has to make
/// sense of, and the failure says how long it waited and what for. A shell that ends before it
/// writes the marker fails the wait at once, with what it wrote.
async fn retained_within(runtime: &SessionRuntime, marker: &[u8], within: Duration) -> Vec<u8> {
    common::retained_carrying(runtime, marker, 1, within).await
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Feeds the canonical grid the sequence an application writes to negotiate `encoding`.
///
/// Going through `ingest_output` rather than setting a flag is the point: the canonical parser is
/// the only thing that knows what an application negotiated, and the re-evaluation has to run off
/// what it decided.
fn negotiates(session: &mut Session, bytes: &[u8]) {
    session.ingest_output(bytes);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.60: `input.acquire` checks the encoder or returns INPUT_INCOMPATIBLE.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.60, KR-REQ-23.36.
#[tokio::test(flavor = "multi_thread")]
async fn the_keys_go_only_to_a_controller_that_produces_the_negotiated_protocol() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let kitty = attach(&mut session, &terminal(session_id, Some("xterm-kitty")));
    let unasked = attach(&mut session, &terminal(session_id, None));
    let typed = attach(&mut session, &semantic(session_id));

    // Nothing negotiated: the ordinary encoding, which every declared terminal sends.
    session
        .acquire_input(xterm, connection(), None)
        .expect("a declared terminal types the ordinary encoding");
    let refused = session
        .acquire_input(unasked, connection(), None)
        .expect_err("a terminal nobody asked about establishes nothing in either direction");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::InputIncompatible
    );

    // The application asks for all keys as escape codes, which is the Kitty protocol.
    negotiates(&mut session, b"\x1b[=8;1u");
    let refused = session
        .acquire_input(xterm, connection(), None)
        .expect_err("xterm implements modifyOtherKeys and not this");
    let error = refused.to_protocol_error();
    assert_eq!(error.code, ErrorCode::InputIncompatible);
    assert!(
        error.message.contains("Kitty"),
        "the refusal names what the application reads: {}",
        error.message
    );
    assert!(
        session.subscribe(xterm).is_ok(),
        "and it keeps everything else it had"
    );
    session
        .acquire_input(kitty, connection(), None)
        .expect("a terminal that implements the protocol takes the keys");
    session
        .acquire_input(typed, connection(), None)
        .expect("and so does a controller that builds its keys from the logical key");

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.60: `modifyOtherKeys` is a level, so the comparison is against the level in force.
#[tokio::test(flavor = "multi_thread")]
async fn a_modifier_encoding_is_compared_at_the_level_the_application_asked_for() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    // GNU screen implements neither enhanced protocol; xterm implements modifyOtherKeys.
    let screen = attach(&mut session, &terminal(session_id, Some("screen-256color")));
    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    session
        .acquire_input(screen, connection(), None)
        .expect("the ordinary encoding is within reach of every declared terminal");

    negotiates(&mut session, b"\x1b[>4;2m");
    let refused = session
        .acquire_input(screen, connection(), None)
        .expect_err("screen does not implement modifyOtherKeys");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::InputIncompatible
    );
    session
        .acquire_input(xterm, connection(), None)
        .expect("xterm does, at this level");

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.61: a mid-session mode change re-evaluates every controller, both directions.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.61: legacy to enhanced takes the keys from a holder that cannot send the new protocol.
#[tokio::test(flavor = "multi_thread")]
async fn turning_an_enhanced_protocol_on_takes_the_keys_from_a_terminal_that_cannot_send_it() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let acquired = session
        .acquire_input(xterm, connection(), None)
        .expect("takes the keys under the ordinary encoding");
    let epoch = acquired.lease.epoch.get();
    assert_eq!(acquired.lease.holder.as_ref(), Some(&xterm));

    // The application turns the Kitty protocol on mid-session. Nothing asked the host to
    // re-evaluate; parsing the output is what tells it.
    negotiates(&mut session, b"\x1b[=8;1u");

    let lease = session.lease();
    assert!(
        !lease.holder.is_present(),
        "the keys were taken from a holder that can no longer produce what the application reads"
    );
    assert!(
        lease.epoch.get() > epoch,
        "and the release advanced the epoch: {} then {}",
        epoch,
        lease.epoch.get()
    );
    // The previous holder learns on its next write, which is the whole of what it is told.
    let refused = session
        .write_input(xterm, epoch, 0, b"x", None, std::time::Instant::now())
        .expect_err("its epoch went with the lease");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.61: enhanced back to legacy leaves an encoding that terminal does produce.
#[tokio::test(flavor = "multi_thread")]
async fn turning_it_off_again_lets_that_terminal_take_the_keys_back() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    session
        .acquire_input(xterm, connection(), None)
        .expect("takes the keys");
    negotiates(&mut session, b"\x1b[=8;1u");
    assert!(!session.lease().holder.is_present(), "taken as above");
    assert!(
        session.acquire_input(xterm, connection(), None).is_err(),
        "and not regained while the protocol is in force"
    );

    // The application empties the Kitty flags, which is what leaving a full-screen mode does.
    negotiates(&mut session, b"\x1b[=0;1u");
    let regained = session
        .acquire_input(xterm, connection(), None)
        .expect("the ordinary encoding is one it produces");
    assert_eq!(regained.lease.holder.as_ref(), Some(&xterm));

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.61: a holder that can produce both keeps the keys across every change.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_that_produces_both_keeps_the_keys_across_the_change() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let typed = attach(&mut session, &semantic(session_id));
    let acquired = session
        .acquire_input(typed, connection(), None)
        .expect("takes the keys");
    let epoch = acquired.lease.epoch.get();
    for negotiation in [
        &b"\x1b[=8;1u"[..],
        &b"\x1b[>4;2m"[..],
        &b"\x1b[=0;1u"[..],
        &b"\x1b[>4;0m"[..],
    ] {
        negotiates(&mut session, negotiation);
        let lease = session.lease();
        assert_eq!(
            lease.holder.as_ref(),
            Some(&typed),
            "the re-evaluation fires only on an incompatibility"
        );
        assert_eq!(
            lease.epoch.get(),
            epoch,
            "and an epoch that did not move is what says nothing happened"
        );
    }

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// The negotiations the companion's raw terminal view is to take the keys under: each with the
/// sequence an application writes for it, and the one that puts the ordinary encoding back.
const COMPANION_NEGOTIATIONS: &[(&str, &[u8], &[u8])] = &[
    ("the ordinary encoding", b"", b""),
    ("modifyOtherKeys level 1", b"\x1b[>4;1m", b"\x1b[>4;0m"),
    ("modifyOtherKeys level 2", b"\x1b[>4;2m", b"\x1b[>4;0m"),
    ("Kitty flags 1", b"\x1b[=1;1u", b"\x1b[=0;1u"),
    ("Kitty flags 2", b"\x1b[=2;1u", b"\x1b[=0;1u"),
    ("Kitty flags 3", b"\x1b[=3;1u", b"\x1b[=0;1u"),
];

/// The companion's raw terminal view: a terminal attachment that declares its own profile, whose
/// keys are built through the shared encoder.
fn companion_view(session_id: SessionId) -> SessionAttachParams {
    terminal(session_id, Some("kalareach-companion"))
}

/// KR-REQ-08.60: the companion's view takes the keys over every encoding it supplies: the
/// ordinary one, modifyOtherKeys at either level, and the Kitty protocol with disambiguation,
/// event types or both.
#[tokio::test(flavor = "multi_thread")]
async fn the_companions_view_takes_the_keys_over_each_encoding_it_supplies() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let view = attach(&mut session, &companion_view(session_id));
    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    for (name, negotiation, ordinary) in COMPANION_NEGOTIATIONS {
        negotiates(&mut session, negotiation);
        let acquired = session
            .acquire_input(view, connection(), None)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(acquired.lease.holder.as_ref(), Some(&view), "{name}");
        // Another controller takes the keys back, so the next negotiation starts from a lease
        // the view does not hold.
        negotiates(&mut session, ordinary);
        session
            .acquire_input(xterm, connection(), None)
            .unwrap_or_else(|error| panic!("{name}, back to the ordinary encoding: {error:?}"));
    }

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.60: the companion's view is refused what it does not produce, with the code a view
/// reads as a refusal of the take: alternate keys, and every key as an escape code.
#[tokio::test(flavor = "multi_thread")]
async fn the_companions_view_is_refused_an_encoding_it_does_not_produce() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let view = attach(&mut session, &companion_view(session_id));
    for (name, negotiation) in [
        ("alternate keys", &b"\x1b[=5;1u"[..]),
        ("every key as an escape code", &b"\x1b[=9;1u"[..]),
    ] {
        negotiates(&mut session, negotiation);
        let refused = session
            .acquire_input(view, connection(), None)
            .expect_err(name);
        assert_eq!(
            refused.to_protocol_error().code,
            ErrorCode::InputIncompatible,
            "{name}"
        );
        assert!(
            session.subscribe(view).is_ok(),
            "{name}: and it keeps everything else it had"
        );
    }

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.61: the companion's view keeps the keys across a change between encodings it
/// supplies, and loses them, explicitly, the moment the application asks for one it does not; back
/// on one it supplies, it takes them again.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_the_companions_view_cannot_follow_ends_its_lease() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let view = attach(&mut session, &companion_view(session_id));
    let acquired = session
        .acquire_input(view, connection(), None)
        .expect("takes the keys under the ordinary encoding");
    let epoch = acquired.lease.epoch.get();
    for negotiation in [
        &b"\x1b[=1;1u"[..],
        &b"\x1b[=3;1u"[..],
        &b"\x1b[=0;1u"[..],
        &b"\x1b[>4;2m"[..],
    ] {
        negotiates(&mut session, negotiation);
        let lease = session.lease();
        assert_eq!(
            lease.holder.as_ref(),
            Some(&view),
            "kept across a change it supplies"
        );
        assert_eq!(
            lease.epoch.get(),
            epoch,
            "and nothing happened to the lease"
        );
    }

    // The application asks for alternate keys as well, which the view does not produce.
    negotiates(&mut session, b"\x1b[=5;1u");
    let lease = session.lease();
    assert!(
        !lease.holder.is_present(),
        "the keys were taken from the view rather than left to send an encoding it only advertised"
    );
    assert!(
        lease.epoch.get() > epoch,
        "and the release advanced the epoch"
    );
    let refused = session
        .write_input(view, epoch, 0, b"x", None, std::time::Instant::now())
        .expect_err("its epoch went with the lease");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);

    negotiates(&mut session, b"\x1b[=1;1u");
    let regained = session
        .acquire_input(view, connection(), None)
        .expect("back on an encoding it supplies, it takes the keys again");
    assert_eq!(regained.lease.holder.as_ref(), Some(&view));

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.62, KR-ACC-008: one lease with an epoch, and an immediate linearised takeover.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.62: the takeover does not wait, and the previous epoch is invalid the moment it ends.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_is_immediate_and_the_previous_epoch_is_invalid_at_once() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let first = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let second = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(first, connection(), None)
        .expect("the first holder");
    let before = held.lease.epoch.get();
    let taken = session
        .acquire_input(second, connection(), None)
        .expect("nothing waits for the first holder's consent");
    assert_eq!(taken.lease.holder.as_ref(), Some(&second));
    assert_eq!(
        taken.lease.epoch.get(),
        before + 1,
        "one lease, one monotonic epoch"
    );
    let refused = session
        .write_input(first, before, 0, b"x", None, std::time::Instant::now())
        .expect_err("the previous epoch is already gone");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
    // A conditional acquire at a stale epoch is refused rather than taking the lease anyway.
    let stale = session
        .acquire_input(first, connection(), Some(before))
        .expect_err("the epoch it expected is not the one in force");
    assert_eq!(stale.to_protocol_error().code, ErrorCode::LeaseLost);
    assert_eq!(
        session.lease().holder.as_ref(),
        Some(&second),
        "and a refused acquire leaves the lease where it was"
    );

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// A prompt that can be answered twice, so a test can tell "answered once" from "cannot answer".
///
/// It reads one byte, reports what it did with it under a number, and then waits for another. A
/// fixture that printed once and became `cat` could not report a second execution, so it could not
/// tell a host that prevented one from a host that allowed it.
const APPROVAL_PROMPT: &str = "stty raw -echo; printf 'kr-approve?'; i=1; \
     while [ $i -le 4 ]; do answer=$(dd bs=1 count=1 2>/dev/null); \
     printf 'kr-granted:%s:%s.' \"$i\" \"$answer\"; i=$((i+1)); done; exec cat";

/// KR-ACC-008: a takeover ends the other lease, and the approval executes once.
///
/// The prompt is the shape a plugin-style approval takes in a terminal: the application writes the
/// question and reads one answer. Two controllers, on two connections, both try to answer it. The
/// fixture can report as many executions as reach it, so one report is evidence rather than a
/// property of the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_ends_the_other_lease_and_the_approval_executes_once() {
    let wired = wired(APPROVAL_PROMPT).await;
    let mut first = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut second = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let held_by_first = attach_over(&mut first, &wired, Some("xterm-256color")).await;
    let held_by_second = attach_over(&mut second, &wired, Some("xterm-256color")).await;
    let first_lease = acquire_over(&mut first, &wired, held_by_first)
        .await
        .expect("the first holder");
    retained_within(&wired.runtime, b"kr-approve?", LIVENESS_DEADLINE).await;

    // The second controller takes the keys while the prompt is waiting for an answer.
    let second_lease = acquire_over(&mut second, &wired, held_by_second)
        .await
        .expect("the takeover");
    assert_eq!(
        second_lease.lease.holder.as_ref(),
        Some(&held_by_second),
        "the lease moved"
    );

    // Both answer. The first one's lease has ended, so its answer is refused on the wire.
    let refused = write_over(
        &mut first,
        &wired,
        held_by_first,
        first_lease.lease.epoch,
        0,
        b"y",
    )
    .await
    .expect_err("the lease it held has ended");
    assert_eq!(refused.code, ErrorCode::LeaseLost);
    write_over(
        &mut second,
        &wired,
        held_by_second,
        second_lease.lease.epoch,
        0,
        b"n",
    )
    .await
    .expect("the holder's answer reaches the application");

    // The whole report, answer and terminator, rather than the label in front of it: the
    // application writes the line in one go but the session retains what has arrived, so a wait for
    // the label alone can return before the answer is in it.
    retained_within(&wired.runtime, b"kr-granted:1:n.", LIVENESS_DEADLINE).await;
    // Given a moment in which a second execution could have been reported, it was not.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = retained(&wired.runtime.session());
    assert_eq!(
        count(&seen, b"kr-granted:"),
        1,
        "the approval executed exactly once: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    assert!(
        contains(&seen, b"kr-granted:1:n."),
        "and with the answer of the actor that held the keys: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    assert!(
        !contains(&seen, b"kr-granted:2:"),
        "the prompt is still waiting rather than having consumed both answers"
    );
    assert_eq!(
        second_lease.discarded_bytes.get(),
        0,
        "the takeover discarded nothing here, because the first holder had not written yet"
    );

    // And the fixture can report a second execution, which is what makes one report above
    // evidence rather than a property of the fixture: the holder answers the next prompt and a
    // second line appears.
    write_over(
        &mut second,
        &wired,
        held_by_second,
        second_lease.lease.epoch,
        1,
        b"y",
    )
    .await
    .expect("the next prompt's answer");
    let seen = retained_within(&wired.runtime, b"kr-granted:2:y.", LIVENESS_DEADLINE).await;
    assert!(
        contains(&seen, b"kr-granted:2:y."),
        "a second approval is reportable, and reports the answer it was given: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    assert_eq!(
        count(&seen, b"kr-granted:"),
        2,
        "two prompts, two answers, one each"
    );

    drop(first);
    drop(second);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.63: a write without the lease is LEASE_LOST, and implicit acquisition is local-only.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.63: a write never acquires, whoever sends it.
#[tokio::test(flavor = "multi_thread")]
async fn a_write_without_the_lease_is_refused_and_never_acquires_it() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let holder = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let other = attach(&mut session, &terminal(session_id, Some("xterm-256color")));

    // Nobody holds it yet. A write does not take it.
    let refused = session
        .write_input(other, 0, 0, b"x", None, std::time::Instant::now())
        .expect_err("no lease, no write");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
    assert!(
        !session.lease().holder.is_present(),
        "and the lease is still unheld: a write is not an acquisition"
    );

    let held = session
        .acquire_input(holder, connection(), None)
        .expect("the holder acquires explicitly");
    let epoch = held.lease.epoch.get();
    // Somebody else's write, at the epoch actually in force, is still refused.
    let refused = session
        .write_input(other, epoch, 0, b"x", None, std::time::Instant::now())
        .expect_err("the epoch is right and the actor is not");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
    assert_eq!(session.lease().holder.as_ref(), Some(&holder));

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.63: a network client cannot assert that it is local.
///
/// The ingress of a caller is constructed by the host from how the caller arrived, never read from
/// anything the caller sent, and the local endpoint constructs exactly one value.
#[test]
fn a_caller_cannot_label_its_own_ingress() {
    let envelope = kr_worker::service::local_actor(
        kr_protocol::ids::ActorId::new("owner:test").expect("an actor"),
        connection(),
        ControllerGeneration::new(1),
    );
    assert_eq!(envelope.ingress, ActorIngress::LocalIpc);
    // And the registry lets a paired device acquire the lease only by asking for it: there is no
    // entry it can reach that acquires as a side effect of writing.
    let kr_protocol::authority::AuthorityDecision::Listed(write) = kr_protocol::method::decide(
        Method::InputWrite.as_str(),
        MethodVersion::V1,
        ActorIngress::PairedDevice,
    ) else {
        panic!("input.write is listed");
    };
    assert!(
        write.summary.contains("current lease epoch"),
        "the entry says the write belongs to a lease it does not create: {}",
        write.summary
    );
    let kr_protocol::authority::AuthorityDecision::Listed(acquire) = kr_protocol::method::decide(
        Method::InputAcquire.as_str(),
        MethodVersion::V1,
        ActorIngress::PairedDevice,
    ) else {
        panic!("input.acquire is listed");
    };
    assert!(
        acquire.summary.contains("no implicit remote acquisition"),
        "and the acquire entry says so outright: {}",
        acquire.summary
    );
}

/// KR-REQ-08.63: a caller that claims a paired-device ingress is refused, not believed.
///
/// The worker's own endpoint is the local operating-system path and constructs the ingress itself.
/// A mutation the control daemon forwards carries an ingress the daemon verified, and the worker
/// checks it: an actor labelled as a paired device is refused at this endpoint, so a network client
/// cannot reach the lease by asserting that it is local.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_caller_claiming_a_network_ingress_is_refused_the_lease() {
    let wired = wired("sleep 120").await;
    let mut local = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attachment_id = attach_over(&mut local, &wired, Some("xterm-256color")).await;

    // A control daemon's own connection, proved for the generation this worker accepts.
    let mut daemon = BoundLink::connect(&wired.endpoint, build())
        .await
        .expect("connects");
    let identity = Arc::clone(&wired.controller);
    let boot = wired.boot.clone();
    daemon
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");

    let params = kr_protocol::envelope::ParamsValue::from_typed(&InputAcquireParams {
        session_id: wired.session_id,
        attachment_id,
        expected_epoch: Nullable::null(),
    })
    .expect("encodes");
    let mutation = kr_protocol::envelope::MutationRequest {
        request_id: kr_protocol::ids::RequestId::new(1),
        method: Method::InputAcquire.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        target: wired.target(),
        params,
        grant_id: Nullable::null(),
        expected: kr_protocol::envelope::ParamsValue::from_typed(&std::collections::BTreeMap::<
            String,
            u64,
        >::new())
        .expect("encodes"),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-that-does-not-exist")
            .expect("a window identifier"),
        requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
    };
    let claiming_a_device = kr_protocol::actor::ActorEnvelope {
        actor_id: kr_protocol::ids::ActorId::new("device:elsewhere").expect("an actor"),
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: ControllerGeneration::new(1),
        connection_id: connection(),
    };
    let refused = daemon
        .forward(
            &mutation,
            &claiming_a_device,
            &[kr_protocol::rights::ActionRight::TerminalInput]
                .into_iter()
                .collect(),
            kr_protocol::scalars::U64::new(kr_ipc::clock::boot_elapsed_ms() + 5_000),
            None,
        )
        .await
        .expect("reaches the worker")
        .expect_err("this endpoint serves the local ingress");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    assert!(
        !wired.runtime.session().lease().holder.is_present(),
        "and nothing was handed over on the strength of a label"
    );

    drop(local);
    drop(daemon);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-08.60, KR-REQ-23.36: the encoder check refuses over the wire, with its own code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_incompatible_controller_is_refused_the_lease_over_the_wire() {
    // The application asks for all keys as escape codes before anybody attaches.
    let wired = wired("stty raw -echo; printf '\\033[=8;1ukr-ready.'; exec cat").await;
    retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    // GNU screen implements neither enhanced protocol.
    let screen = attach_over(&mut client, &wired, Some("screen-256color")).await;
    let refused = acquire_over(&mut client, &wired, screen)
        .await
        .expect_err("it cannot produce what the application reads");
    assert_eq!(refused.code, ErrorCode::InputIncompatible);
    assert!(
        refused.message.contains("Kitty"),
        "and the refusal names the encoding: {}",
        refused.message
    );
    // It still observes, which is what the row leaves it.
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: wired.session_id,
                attachment_id: screen,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("and goes on watching the session it cannot type into");

    // A terminal that does implement it takes the keys.
    let kitty = attach_over(&mut client, &wired, Some("xterm-kitty")).await;
    acquire_over(&mut client, &wired, kitty)
        .await
        .expect("a terminal that implements the protocol");

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-08.61, KR-REQ-08.64: a lease the host ends by itself reports what it interrupted.
#[tokio::test(flavor = "multi_thread")]
async fn a_lease_the_host_ends_reports_its_interrupted_input_to_the_next_holder() {
    let host = kr_ipc::testing::TempHost::create();
    // The application enables bracketed paste and reads nothing, so what is written stops at the
    // line discipline and the accounting has something to count.
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; sleep 120",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let xterm = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let typed = attach(&mut session, &semantic(session_id));
    let held = session
        .acquire_input(xterm, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    {
        let mut session = runtime.session();
        // A paste is opened and a delimiter prefix is left half-arrived.
        session
            .write_input(
                xterm,
                epoch,
                0,
                b"\x1b[200~half",
                None,
                std::time::Instant::now(),
            )
            .expect("the start and part of the body");
        session
            .write_input(xterm, epoch, 1, b"\x1b[20", None, std::time::Instant::now())
            .expect("four bytes of a delimiter");
        assert!(session.paste_open());
        // Now the application turns on a protocol this terminal cannot produce. Nobody asked for
        // the release, so there is no answer for it to be reported in.
        session.ingest_output(b"\x1b[=8;1u");
        assert!(
            !session.lease().holder.is_present(),
            "the keys were taken from it"
        );
        let interrupted = session.interrupted_input();
        assert!(
            interrupted.bytes >= 4,
            "the undelivered prefix is counted rather than dropped: {}",
            interrupted.bytes
        );
        assert!(
            interrupted.closed_open_paste,
            "and the paste it had open is reported as closed"
        );
    }

    // The next holder is told, once, and then it is nobody's any more.
    let next = {
        let mut session = runtime.session();
        session
            .acquire_input(typed, connection(), None)
            .expect("a controller that can produce it")
    };
    assert!(
        next.discarded_bytes.get() >= 4,
        "the interruption reaches the next holder: {}",
        next.discarded_bytes.get()
    );
    assert!(next.closed_open_paste);
    assert_eq!(
        runtime.session().interrupted_input(),
        kr_worker::session::Interrupted::default(),
        "reported once, not once per acquire"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.64, KR-PERF-002: bracketed-paste framing per lease.
// ---------------------------------------------------------------------------------------------

/// A session whose application has turned no bracketed paste on, with the input lease held, and the
/// epoch it is held at.
async fn with_no_paste_mode_on() -> (
    kr_ipc::testing::TempHost,
    Arc<SessionRuntime>,
    kr_protocol::ids::AttachmentId,
    u64,
) {
    let host = kr_ipc::testing::TempHost::create();
    // No bracketed paste, so an Escape is an Escape.
    let config = configuration(&host, "stty raw -echo; printf 'kr-ready.'; exec cat");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let id = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(id, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
    (host, runtime, id, epoch)
}

/// KR-REQ-08.64: a plain Escape is not held when the mode is off and no paste is open.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_escape_is_not_held_when_the_mode_is_off_and_no_paste_is_open() {
    let (_host, runtime, id, epoch) = with_no_paste_mode_on().await;

    let accepted = {
        let mut session = runtime.session();
        session
            .write_input(id, epoch, 0, b"\x1b", None, std::time::Instant::now())
            .expect("accepted")
    };
    assert_eq!(
        accepted.held_prefix_bytes, 0,
        "nothing is held: the mode is off and no paste is open"
    );
    assert_eq!(accepted.forwarded_bytes, 1);

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.64: and the Escape reaches the application at once.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn a_plain_escape_reaches_the_application_with_no_paste_prefix_hold() {
    let (_host, runtime, id, epoch) = with_no_paste_mode_on().await;

    runtime
        .session()
        .write_input(id, epoch, 0, b"\x1b", None, std::time::Instant::now())
        .expect("accepted");
    runtime.flush_input();
    let seen = retained_within(&runtime, b"kr-ready.\x1b", LIVENESS_DEADLINE).await;
    assert!(
        contains(&seen, b"kr-ready.\x1b"),
        "and it arrived at once: {seen:?}"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.64, KR-PERF-002: a delimiter split across frames is recognised once, payload kept.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console begins its output with mode sequences of its own and holds back an unfinished sequence, which this case reads as the application's bytes"
)]
async fn a_delimiter_split_across_frames_reaches_the_application_once_with_its_payload() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let id = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(id, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    // Four bytes of the start delimiter, then the rest with its payload behind it.
    {
        let mut session = runtime.session();
        let first = session
            .write_input(id, epoch, 0, b"\x1b[20", None, std::time::Instant::now())
            .expect("accepted");
        assert_eq!(first.forwarded_bytes, 0, "an incomplete delimiter is held");
        assert_eq!(first.held_prefix_bytes, 4);
        let second = session
            .write_input(
                id,
                epoch,
                1,
                b"0~pasted\x1b[201~",
                None,
                std::time::Instant::now(),
            )
            .expect("accepted");
        assert_eq!(second.held_prefix_bytes, 0);
    }
    runtime.flush_input();
    let seen = retained_within(&runtime, PASTE_END, LIVENESS_DEADLINE).await;
    assert_eq!(
        count(&seen, PASTE_START),
        1,
        "one start delimiter, emitted once: {seen:?}"
    );
    assert!(
        contains(&seen, b"\x1b[200~pasted\x1b[201~"),
        "with the payload it arrived with, in order: {seen:?}"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.64: a paste open at a takeover is closed before the new lease's first byte.
///
/// The mode is switched off while the paste is open, which is the case the row calls out: framing
/// is tracked while canonical paste mode is enabled *and* until an already-open paste is safely
/// terminated, so turning the mode off mid-paste does not abandon the framing.
#[tokio::test(flavor = "multi_thread")]
async fn a_paste_open_when_the_mode_was_turned_off_is_still_closed_before_the_new_lease_writes() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let second = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(first, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    {
        let mut session = runtime.session();
        session
            .write_input(
                first,
                epoch,
                0,
                b"\x1b[200~half",
                None,
                std::time::Instant::now(),
            )
            .expect("the start and part of the body");
        assert!(session.paste_open(), "the paste is open");
        // The application turns canonical paste mode off with a paste still open.
        session.ingest_output(b"\x1b[?2004l");
        assert!(
            session.paste_open(),
            "and the framing is still tracked, because the paste has not been terminated"
        );
    }
    runtime.flush_input();
    retained_within(&runtime, b"half", LIVENESS_DEADLINE).await;

    let taken = {
        let mut session = runtime.session();
        let taken = session
            .acquire_input(second, connection(), None)
            .expect("the takeover");
        assert!(
            taken.closed_open_paste,
            "the takeover reports that it closed a paste the application was inside"
        );
        taken
    };
    {
        let mut session = runtime.session();
        session
            .write_input(
                second,
                taken.lease.epoch.get(),
                0,
                b"kr-after.",
                None,
                std::time::Instant::now(),
            )
            .expect("the new lease's first bytes");
    }
    runtime.flush_input();

    let seen = retained_within(&runtime, b"kr-after.", LIVENESS_DEADLINE).await;
    let terminator = seen
        .windows(PASTE_END.len())
        .position(|window| window == PASTE_END)
        .expect("the paste was closed");
    let after = seen
        .windows(b"kr-after.".len())
        .position(|window| window == b"kr-after.")
        .expect("the new lease's bytes arrived");
    assert!(
        terminator < after,
        "and the close came first: {terminator} then {after}"
    );
    assert_eq!(
        count(&seen, PASTE_END),
        1,
        "closed once, not once per attempt"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.64: an incomplete delimiter is discarded on source loss and the loss is reported.
///
/// Source loss here is the source going: the attachment that sent those bytes detaches. The
/// application echoes what it receives, so the prefix's absence from the echo is evidence that it
/// never arrived rather than evidence of an application that writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_incomplete_delimiter_is_discarded_on_source_loss_and_counted() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let leaving = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let next = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(leaving, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    {
        let mut session = runtime.session();
        // An ordinary byte, which the application echoes.
        session
            .write_input(
                leaving,
                epoch,
                0,
                b"kr-typed.",
                None,
                std::time::Instant::now(),
            )
            .expect("ordinary bytes");
    }
    runtime.flush_input();
    retained_within(&runtime, b"kr-typed.", LIVENESS_DEADLINE).await;

    // Then four bytes of a delimiter, which the application does not see, and the source going,
    // both while this hold on the session lasts. A held prefix has a deadline of its own, and the
    // host forwards it when that passes; waiting for anything in between would be waiting to see
    // which of the two happened first on this machine. What is under test is what the detach finds
    // and reports, so the detach follows the prefix without letting go.
    {
        let mut session = runtime.session();
        let accepted = session
            .write_input(
                leaving,
                epoch,
                1,
                b"\x1b[20",
                None,
                std::time::Instant::now(),
            )
            .expect("the first four bytes of a delimiter");
        assert_eq!(accepted.held_prefix_bytes, 4);
        session.detach(leaving).expect("detaches");
        let interrupted = session.interrupted_input();
        assert_eq!(
            interrupted.bytes, 4,
            "exactly the prefix that was never delivered, counted once"
        );
        assert!(
            !interrupted.closed_open_paste,
            "no paste was open, so none was closed"
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let session = runtime.session();
        let seen = retained(&session);
        assert!(
            contains(&seen, b"kr-typed."),
            "the application echoes what it receives, which is how this test can tell: {seen:?}"
        );
        assert!(
            !contains(&seen, b"\x1b[20"),
            "and the prefix never reached it: {seen:?}"
        );
    }

    // And the next holder is told what was lost.
    let acquired = {
        let mut session = runtime.session();
        session
            .acquire_input(next, connection(), None)
            .expect("the next holder")
    };
    assert_eq!(
        acquired.discarded_bytes.get(),
        4,
        "reported to whoever takes the keys next"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.65: focus, scrollback, replies and an idle window never seize the lease.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.65.
#[tokio::test(flavor = "multi_thread")]
async fn focus_scrollback_replies_and_an_idle_window_never_seize_the_lease() {
    let host = kr_ipc::testing::TempHost::create();
    // The application turns focus reporting on and asks the host a question, so both the focus
    // events and the host's own reply exist on the input path.
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?1004h\\033[c'; printf 'kr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let holder = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(holder, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    // An idle window opens. It observes and it takes nothing.
    let idle = {
        let mut session = runtime.session();
        let idle = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
        session.subscribe(idle).expect("it watches");
        assert_eq!(
            session.lease().holder.as_ref(),
            Some(&holder),
            "opening a view is not taking control"
        );
        assert_eq!(session.lease().epoch.get(), epoch);
        idle
    };

    {
        let mut session = runtime.session();
        // A focus event from the holder, which is an ordinary input byte sequence.
        session
            .write_input(holder, epoch, 0, b"\x1b[I", None, std::time::Instant::now())
            .expect("the holder's focus event is forwarded");
        assert_eq!(session.lease().epoch.get(), epoch, "and moves nothing");
        // The idle window's focus event is refused: only the holder changes the application's
        // focus state.
        let refused = session
            .write_input(idle, epoch, 0, b"\x1b[I", None, std::time::Instant::now())
            .expect_err("another view cannot change the application's focus state");
        assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
        // Passive scrollback: reading the retained history takes nothing either.
        let _ = session.history_page(0, 4096).expect("reads scrollback");
        assert_eq!(session.lease().epoch.get(), epoch);
        assert_eq!(session.lease().holder.as_ref(), Some(&holder));
        // The host's own reply to the application's question travelled on the input path and is
        // not a lease event.
        session.pump_replies();
        assert_eq!(session.lease().epoch.get(), epoch);
        assert_eq!(session.lease().holder.as_ref(), Some(&holder));
    }

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.66: no keystroke journal, and delivery is not proof of effect.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.66: the host retains output, never input, and an accepted write is not an effect.
///
/// It runs over the wire because that is where the comparison is: the attach and the acquire are
/// recorded actions with receipts of their own, and the keystrokes between them are not. A journal
/// with the first and not the second is the whole of what the row asks for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_journals_a_keystroke_and_reaching_the_terminal_is_not_an_effect() {
    // A shell that reads nothing. Every byte written reaches the terminal and no application acts
    // on any of it, which is exactly the gap between delivery and effect.
    let wired = wired("stty raw -echo; printf 'kr-ready.'; sleep 120").await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, Some("xterm-256color")),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InputAcquireParams {
                session_id: wired.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("acquires")
        .to_typed()
        .expect("decodes");
    retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    let secret = b"kr-secret-keystrokes";
    let accepted: InputWriteResult = client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch: lease.lease.epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: Bytes::new(secret.to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("accepted")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        accepted.forwarded_bytes.get(),
        secret.len() as u64,
        "the host accepted every byte and held none of them back as a delimiter prefix"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut session = wired.runtime.session();
    let seen = retained(&session);
    assert!(
        !contains(&seen, secret),
        "the retained stream is what the application wrote, and it wrote none of this"
    );
    assert!(
        !contains(&seen, b"kr-secret"),
        "not even a fragment of it: an output snapshot is not an input journal"
    );
    // Nor is there a receipt carrying them. `input.write` is an ordered stream, not a recorded
    // action: a retry of a keystroke is a keystroke typed twice, which nothing may do for a person.
    let journal = session
        .journal_mut()
        .expect("this session retains receipts");
    let events = journal
        .events_after(0, 1_000)
        .expect("reads the receipt events");
    assert!(
        !events.is_empty(),
        "the attach and the acquire are recorded"
    );
    let mut methods = Vec::new();
    for event in events {
        let receipt = journal
            .read(event.actor_id.clone(), event.action_id)
            .expect("reads the receipt")
            .expect("the event names a receipt");
        methods.push(receipt.method.as_str().to_owned());
    }
    assert!(
        methods
            .iter()
            .any(|method| method == Method::SessionAttach.as_str()),
        "the attach is one of them: {methods:?}"
    );
    assert!(
        !methods
            .iter()
            .any(|method| method == Method::InputWrite.as_str()),
        "and no receipt names a keystroke: {methods:?}"
    );
    drop(session);

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.36: the input method group, over the wire.
// ---------------------------------------------------------------------------------------------

struct Wired {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The control daemon's identity, for the one test that connects as a daemon.
    controller: Arc<ControllerIdentity>,
    /// The boot identity a generation token is signed over.
    boot: kr_protocol::identity::BootIdentity,
}

impl Wired {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }
}

/// Starts a worker service over its own local endpoint, with a real session behind it.
async fn wired(script: &str) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let config = configuration(&temp, script);
    let session_id = config.session_id;
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
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");
    let boot_identity = boot.clone();

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
    Wired {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller: Arc::new(controller),
        boot: boot_identity,
    }
}

/// An interrupt naming an action the protocol does not have.
///
/// The method accepts exactly one action, so the refusal has to happen whether the caller sends a
/// different one or an invented one, and only a hand-built request can send an invented one.
#[derive(serde::Serialize)]
struct InventedInterrupt<'a> {
    session_id: SessionId,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    action: &'a str,
}

/// Attaches a terminal declaring `profile` over `client`, and returns its identifier.
async fn attach_over(
    client: &mut Client<impl Codec>,
    wired: &Wired,
    profile: Option<&str>,
) -> AttachmentId {
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, profile),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    attached.attachment.attachment_id
}

/// Takes the input lease over `client`.
async fn acquire_over(
    client: &mut Client<impl Codec>,
    wired: &Wired,
    attachment_id: AttachmentId,
) -> Result<kr_protocol::input::InputAcquireResult, kr_protocol::error::ProtocolError> {
    client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InputAcquireParams {
                session_id: wired.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
}

/// Writes input over `client`.
async fn write_over(
    client: &mut Client<impl Codec>,
    wired: &Wired,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    bytes: &[u8],
) -> Result<InputWriteResult, kr_protocol::error::ProtocolError> {
    client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(sequence),
                bytes: Bytes::new(bytes.to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
}

/// KR-REQ-23.36: the input methods check the encoder, the lease epoch and the sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_input_methods_check_the_encoder_the_lease_epoch_and_the_sequence() {
    let wired = wired("stty raw -echo; printf 'kr-ready.'; exec cat").await;
    // Waited for, because until the root program has put the terminal into raw mode with the echo
    // off the line discipline echoes input as well, and a byte that came back twice would be read
    // as the host having written it twice.
    retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, Some("xterm-256color")),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: wired.session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("subscribes");

    // A write before the lease exists is refused over the wire, with the code the row names.
    let refused = client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch: kr_protocol::ids::InputLeaseEpoch::new(0),
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: Bytes::new(b"x".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("no lease");
    assert_eq!(refused.code, ErrorCode::LeaseLost);

    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InputAcquireParams {
                session_id: wired.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("acquires")
        .to_typed()
        .expect("decodes");
    let epoch = lease.lease.epoch;

    // In order.
    let accepted: InputWriteResult = client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: Bytes::new(b"kr-one.".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("accepted")
        .to_typed()
        .expect("decodes");
    assert_eq!(accepted.sequence.get(), 0);
    assert_eq!(accepted.forwarded_bytes.get(), 7);

    // The same sequence again is refused: positions are acknowledged per connection and never
    // replayed.
    let repeated = client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: Bytes::new(b"kr-again.".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("out of order");
    assert_eq!(repeated.code, ErrorCode::InvalidArgument);

    // A stale epoch is `LEASE_LOST` rather than an argument failure, because the lease is what
    // moved.
    let stale = client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id: wired.session_id,
                attachment_id,
                epoch: kr_protocol::ids::InputLeaseEpoch::new(epoch.get() + 7),
                sequence: kr_protocol::ids::InputSequence::new(1),
                bytes: Bytes::new(b"x".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("stale epoch");
    assert_eq!(stale.code, ErrorCode::LeaseLost);

    // The interrupt takes only the configured native action.
    let invented = client
        .mutate(
            Method::InputInterrupt,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InventedInterrupt {
                session_id: wired.session_id,
                attachment_id,
                epoch,
                action: "run_this_instead",
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("an invented action is not an interrupt");
    assert_eq!(invented.code, ErrorCode::InvalidArgument);

    // And the release ends it, at the epoch the caller holds and no other.
    let wrong = client
        .mutate(
            Method::InputRelease,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputReleaseParams {
                session_id: wired.session_id,
                attachment_id,
                epoch: kr_protocol::ids::InputLeaseEpoch::new(epoch.get() + 1),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("not the epoch it holds");
    assert_eq!(wrong.code, ErrorCode::LeaseLost);
    let released: kr_protocol::input::InputLeaseResult = client
        .mutate(
            Method::InputRelease,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputReleaseParams {
                session_id: wired.session_id,
                attachment_id,
                epoch,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("releases")
        .to_typed()
        .expect("decodes");
    assert!(!released.lease.holder.is_present());
    assert!(released.lease.epoch.get() > epoch.get());

    // What was accepted did reach the application, which is what the ordered stream is for.
    let seen = retained_within(&wired.runtime, b"kr-one.", LIVENESS_DEADLINE).await;
    assert_eq!(count(&seen, b"kr-one."), 1);
    assert!(
        !contains(&seen, b"kr-again."),
        "and what was refused did not"
    );

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-23.36: an attachment without the input capability cannot type, whatever it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_without_the_input_capability_cannot_write() {
    let wired = wired("stty raw -echo; printf 'kr-ready.'; exec cat").await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let mut observer = terminal(wired.session_id, Some("xterm-256color"));
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    observer.requested = requested;
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &observer,
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    assert!(
        !attached
            .attachment
            .granted
            .contains(&AttachmentCapability::Input),
        "it asked to observe and nothing more"
    );

    let refused = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InputAcquireParams {
                session_id: wired.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("an attachment identifier is not permission");
    // The refusal names the capability the attachment was not granted. What matters to the row is
    // that holding the identifier bought nothing: the lease is not handed to an attachment the
    // host never granted input to.
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(
        refused.message.contains("input"),
        "and it says which capability is missing: {}",
        refused.message
    );
    assert!(
        !wired.runtime.session().lease().holder.is_present(),
        "and the lease was not handed over"
    );

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-08.65: a frame that is not this connection's business is refused rather than ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_connection_that_never_acquires_leaves_the_lease_where_it_was() {
    let wired = wired("stty raw -echo; printf 'kr-ready.'; exec cat").await;
    let mut holder = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attached: kr_protocol::attachment::SessionAttachResult = holder
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, Some("xterm-256color")),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let lease: kr_protocol::input::InputAcquireResult = holder
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &InputAcquireParams {
                session_id: wired.session_id,
                attachment_id: attached.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("acquires")
        .to_typed()
        .expect("decodes");

    // A second connection attaches, subscribes and then does nothing at all.
    let mut idle = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let watching: kr_protocol::attachment::SessionAttachResult = idle
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, Some("xterm-256color")),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    idle.request(
        Method::EventsSubscribe,
        &EventsSubscribeParams {
            session_id: wired.session_id,
            attachment_id: watching.attachment.attachment_id,
            streams,
            from_cursor: Nullable::null(),
        },
    )
    .await
    .expect("reaches the worker")
    .expect("subscribes");
    // It receives output, which is what watching is.
    let mut received = false;
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        // A quiet moment is a busy machine rather than an answer, so only a connection that has
        // gone ends this before the deadline does.
        match tokio::time::timeout(Duration::from_secs(2), idle.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                received = true;
                break;
            }
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(_)) => break,
        }
    }
    assert!(
        received,
        "waited {:?} for the idle window to be shown the session",
        started.elapsed()
    );
    assert_eq!(
        wired.runtime.session().lease().epoch.get(),
        lease.lease.epoch.get(),
        "and it took nothing: an attached idle window does not seize the lease"
    );
    assert_eq!(
        wired.runtime.session().lease().holder.as_ref(),
        Some(&attached.attachment.attachment_id)
    );

    drop(holder);
    drop(idle);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

// ---------------------------------------------------------------------------------------------
// The writer's own expiry fence: authority that ends while a batch waits for the terminal.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.62 and KR-REQ-08.64, in part.
///
/// The host checks a forwarded batch's authority deadline when it accepts it. That answer goes
/// stale: an accepted batch waits for the writer, and the writer waits for an application that
/// may not be reading. The deadline therefore travels with the bytes and is asked again at the
/// boundary that actually hands them over.
///
/// What this covers is that last boundary and nothing else. It says nothing about what a remote
/// write without the lease is answered with, about what a reconnection discards, or about the
/// dispatch lease a remote mutation needs.
#[tokio::test(flavor = "multi_thread")]
async fn a_batch_whose_authority_ran_out_while_it_waited_is_never_written() {
    let host = kr_ipc::testing::TempHost::create();
    // Raw mode with the echo off: what comes back is what the application received, not what the
    // line discipline repeated.
    let config = configuration(&host, "stty raw -echo; printf 'kr-ready.'; exec cat");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let id = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(id, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();

    // The machine's own continuous clock, driven by hand: a grant that runs out between the
    // moment a batch is accepted and the moment the terminal takes it is not something the real
    // clock can be asked to arrange.
    let clock = kr_ipc::clock::ManualSharedClock::new();
    let runtime = Arc::new(
        SessionRuntime::start(session, std::sync::Arc::new(clock.clone())).expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", Duration::from_secs(10)).await;
    let deadline = kr_ipc::clock::SharedClock::boot_elapsed_ms(&clock) + 1_000;

    // Inside the deadline, and delivered.
    {
        let mut session = runtime.session();
        session
            .write_input(id, epoch, 0, b"kr-inside", Some(deadline), Instant::now())
            .expect("accepted");
        runtime.flush_input();
    }
    let seen = retained_within(&runtime, b"kr-inside", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-inside"),
        "a batch written under authority that still stands reaches the application: {seen:?}"
    );

    // Accepted while the grant still stood, handed to the writer after it had run out.
    {
        let mut session = runtime.session();
        session
            .write_input(id, epoch, 1, b"kr-expired", Some(deadline), Instant::now())
            .expect("accepted");
        clock.advance(Duration::from_secs(5));
        runtime.flush_input();
    }
    // A batch behind it under authority that has not run out. The writer is serial, so once this
    // one has arrived the one in front of it has either arrived or was never written.
    {
        let mut session = runtime.session();
        let later = kr_ipc::clock::SharedClock::boot_elapsed_ms(&clock) + 60_000;
        session
            .write_input(id, epoch, 2, b"kr-after", Some(later), Instant::now())
            .expect("accepted");
        runtime.flush_input();
    }
    let seen = retained_within(&runtime, b"kr-after", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-after"),
        "the writer is still delivering what its authority admits: {seen:?}"
    );
    assert!(
        !contains(&seen, b"kr-expired"),
        "nothing written after the deadline reaches the pseudo-terminal: {seen:?}"
    );

    // The dropped batch is not still owed against the session's input budget, and neither is it
    // still counted against the lease that queued it: an application that stopped reading would
    // otherwise be blamed for bytes nothing is going to write.
    let session = runtime.session();
    assert_eq!(
        session
            .input()
            .lock()
            .queued_input_bytes()
            .load(std::sync::atomic::Ordering::Acquire),
        0,
        "the budget the dropped batch held is given back"
    );
    assert_eq!(
        session.input().lock().queued_lease_bytes().load(),
        0,
        "and so is the lease's share of it"
    );
    drop(session);

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.62 and KR-REQ-08.64, in part.
///
/// A held delimiter prefix carries the authority that admitted it. It is also the one thing a
/// takeover discards outright, and what is discarded takes its deadline with it: leaving the
/// deadline behind would put an ended actor's authority on the next actor's first keystrokes.
#[tokio::test(flavor = "multi_thread")]
async fn a_discarded_prefix_takes_its_authority_deadline_with_it() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let second = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(first, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();

    let clock = kr_ipc::clock::ManualSharedClock::new();
    let runtime = Arc::new(
        SessionRuntime::start(session, std::sync::Arc::new(clock.clone())).expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", Duration::from_secs(10)).await;
    let deadline = kr_ipc::clock::SharedClock::boot_elapsed_ms(&clock) + 1_000;

    // One boundary for all of it. The recogniser's own timer would otherwise release the prefix
    // before the takeover, and this test is about what the takeover discards.
    {
        let mut session = runtime.session();
        // Four bytes of a paste delimiter, which the recogniser holds rather than forwards.
        let accepted = session
            .write_input(first, epoch, 0, b"\x1b[20", Some(deadline), Instant::now())
            .expect("accepted");
        assert_eq!(
            accepted.held_prefix_bytes, 4,
            "the recogniser is holding a partial delimiter"
        );
        // The next actor takes the lease, which discards that prefix.
        let taken = session
            .acquire_input(second, connection(), None)
            .expect("the keys move");
        let next_epoch = taken.lease.epoch.get();
        // The grant behind the discarded prefix runs out. It has nothing left to fence.
        clock.advance(Duration::from_secs(5));
        session
            .write_input(second, next_epoch, 0, b"kr-next", None, Instant::now())
            .expect("accepted");
        runtime.flush_input();
    }
    let seen = retained_within(&runtime, b"kr-next", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-next"),
        "the next holder's input is not fenced by a deadline the previous holder's prefix \
         carried: {seen:?}"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.64, in part.
///
/// A push can complete the prefix it was holding and start a new one out of its own bytes. The new
/// prefix is that write's, so it carries that write's authority: the deadline of the write whose
/// bytes have all been forwarded no longer applies to anything.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console begins its output with mode sequences of its own and holds back an unfinished sequence, which this case reads as the application's bytes"
)]
async fn a_prefix_made_only_of_the_newer_bytes_keeps_the_newer_deadline() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let id = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let held = session
        .acquire_input(id, connection(), None)
        .expect("the keys");
    let epoch = held.lease.epoch.get();

    let clock = kr_ipc::clock::ManualSharedClock::new();
    let runtime = Arc::new(
        SessionRuntime::start(session, std::sync::Arc::new(clock.clone())).expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", Duration::from_secs(10)).await;
    let now = kr_ipc::clock::SharedClock::boot_elapsed_ms(&clock);
    let early = now + 1_000;
    let late = now + 600_000;

    // One boundary for all of it: the recogniser's own timer takes the same lock, so it cannot
    // release the held byte before this test has said what the clock reads.
    {
        let mut session = runtime.session();
        let accepted = session
            .write_input(id, epoch, 0, b"\x1b[20", Some(early), Instant::now())
            .expect("accepted");
        assert_eq!(accepted.held_prefix_bytes, 4);
        // This write finishes that delimiter and starts a prefix of its own out of its last byte.
        let accepted = session
            .write_input(id, epoch, 1, b"0~\x1b", Some(late), Instant::now())
            .expect("accepted");
        assert_eq!(
            (accepted.forwarded_bytes, accepted.held_prefix_bytes),
            (6, 1),
            "the delimiter goes and one byte of the next one is held"
        );
        // The first write's authority runs out. The delimiter it completed goes with it; the byte
        // still held is not its byte.
        clock.advance(Duration::from_secs(5));
        let released =
            session.expire_paste_prefix(Instant::now() + std::time::Duration::from_secs(1));
        assert_eq!(released, 1, "the held byte is released by its own deadline");
        runtime.flush_input();
    }
    let seen = retained_within(&runtime, b"kr-ready.\x1b", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-ready.\x1b"),
        "a prefix made of the second write's bytes is admitted by the second write's \
         authority: {seen:?}"
    );
    assert!(
        !contains(&seen, PASTE_START),
        "and the delimiter the first write's authority admitted is not: {seen:?}"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-PERF-002: what the recogniser's deadline does not wait for.
// ---------------------------------------------------------------------------------------------

/// The root program of the cases below: it echoes what it reads, with bracketed paste enabled, so
/// the host holds a lone Escape for its deadline.
const BRACKETED_ECHO: &str = "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat";

/// What the session's worker has written for the application once it is ready, and an attachment
/// that holds the input lease.
async fn typist(wired: &Wired) -> (LocalClient, AttachmentId, kr_protocol::ids::InputLeaseEpoch) {
    retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attachment = attach_over(&mut client, wired, Some("xterm-256color")).await;
    let lease = acquire_over(&mut client, wired, attachment)
        .await
        .expect("acquires");
    (client, attachment, lease.lease.epoch)
}

/// KR-PERF-002: a held prefix's deadline runs from the write's arrival at the worker, and not from
/// the moment the session came free for it.
///
/// The session can be busy with something else when a lone Escape arrives. The application's wait
/// for the Escape is bounded by the recogniser's deadline from the write, so a deadline that began
/// when the session was taken would add the wait for the session to it. The write is stopped before
/// it takes the session, which stands in for whatever held the session, and the deadline it set is
/// read back from the instants the session's recorder kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console begins its output with mode sequences of its own, so this case cannot tell the application's enabling of bracketed paste from them"
)]
async fn a_prefix_waits_for_its_deadline_from_the_write_whatever_held_the_session() {
    let wired = wired(BRACKETED_ECHO).await;
    let (mut client, attachment, epoch) = typist(&wired).await;
    wired.runtime.trace().arm();

    let (arrived, release) = wired.service.pause_input_before_the_session();
    let write = write_over(&mut client, &wired, attachment, epoch, 0, b"\x1b");
    let standing_in = tokio::task::spawn_blocking(move || {
        arrived
            .recv_timeout(LIVENESS_DEADLINE)
            .expect("the write reached the pause");
        // From here until the write is let go it is waiting for a session that is not free.
        let session_came_free = Instant::now();
        release.send(()).expect("lets the write go");
        session_came_free
    });
    let (accepted, session_came_free) = tokio::join!(write, standing_in);
    let accepted = accepted.expect("the write is accepted");
    let session_came_free = session_came_free.expect("the pause ends");
    assert_eq!(accepted.held_prefix_bytes.get(), 1, "the Escape is held");

    let trace = wired.runtime.trace();
    let recording = trace.recording();
    let deadline = recording
        .events
        .iter()
        .find(|event| event.site == kr_worker::trace::Site::InputAcceptance && event.value != 0)
        .map(|event| event.value)
        .expect("the acceptance of a held prefix recorded the deadline it set");
    let began = deadline
        - u64::try_from(kr_worker::input::RECOGNISER_DEADLINE.as_nanos()).expect("nanoseconds");
    assert!(
        began <= trace.offset(session_came_free),
        "the deadline ran from {began} ns, after the write had waited until {} ns for the session",
        trace.offset(session_came_free)
    );

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-PERF-002: a lone Escape reaches the application at its deadline while the worker is reading
/// the processes the session owns.
///
/// The observation is stopped while it reads, which is where a reading that kept the session would
/// keep the write, and then the timer, out of it for as long as the kernel took to answer. Both
/// have to get through while it is stopped, and the Escape has to arrive before it is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn a_lone_escape_is_forwarded_at_its_deadline_while_the_session_s_processes_are_being_read() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let wired = wired(BRACKETED_ECHO).await;
    let (mut client, attachment, epoch) = typist(&wired).await;

    let (reading, resume) = wired.runtime.pause_in_next_observation();
    wired.runtime.observe_now();
    tokio::time::timeout(LIVENESS_DEADLINE, reading)
        .await
        .expect("the observation reached its reading")
        .expect("the observation is reading");

    // A regression leaves the paused observation holding the session, and then the write waits for
    // it for as long as the pause lasts. A thread of its own lets the observation go after a while
    // and says so, so that the case fails naming the wait instead of waiting with it.
    let written = Arc::new(AtomicBool::new(false));
    let let_go_by_the_watchdog = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (written, let_go) = (Arc::clone(&written), Arc::clone(&let_go_by_the_watchdog));
        let resume = resume.clone();
        std::thread::spawn(move || {
            for _ in 0..300 {
                if written.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let_go.store(true, Ordering::Release);
            let _ = resume.send(());
        })
    };
    let accepted = write_over(&mut client, &wired, attachment, epoch, 0, b"\x1b")
        .await
        .expect("the write is accepted");
    written.store(true, Ordering::Release);
    assert!(
        !let_go_by_the_watchdog.load(Ordering::Acquire),
        "the write was kept waiting by the observation until it was let go"
    );
    assert_eq!(accepted.held_prefix_bytes.get(), 1, "the Escape is held");
    let seen = retained_within(&wired.runtime, b"kr-ready.\x1b", LIVENESS_DEADLINE).await;
    assert!(
        contains(&seen, b"kr-ready.\x1b"),
        "the Escape reached the application while the observation was still reading: {seen:?}"
    );

    resume.send(()).expect("lets the observation go");
    watchdog.join().expect("the watchdog ends");
    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// A root program that keeps what it reads in `received` as well as echoing it, with bracketed
/// paste enabled. What reached the application can then be read without the session's output,
/// which a case that stops the output ingest cannot use.
fn bracketed_recording(received: &std::path::Path) -> String {
    format!(
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec tee '{}'",
        received.display()
    )
}

/// Lets the stopped step go, with `release`, after a while unless `done` says it is not needed, and
/// says whether it had to.
///
/// A regression leaves the stopped step holding what the case waits for, and then the case waits
/// for as long as the stop lasts. A thread of its own lets the step go after a while and says so,
/// so that the case fails naming the wait instead of waiting with it.
fn release_after_a_while(
    release: impl Fn() + Send + 'static,
    done: &Arc<std::sync::atomic::AtomicBool>,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let let_go = Arc::new(AtomicBool::new(false));
    let thread = {
        let (done, let_go) = (Arc::clone(done), Arc::clone(&let_go));
        std::thread::spawn(move || {
            for _ in 0..300 {
                if done.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let_go.store(true, Ordering::Release);
            release();
        })
    };
    (let_go, thread)
}

/// Types one ordinary byte, and returns what lets go of the write of its echo once that write is
/// waiting on the disk.
///
/// The application echoes the byte, the ingest records the echo, and the write of it to the spool
/// is the next one made with the session let go: the segment the session's opening output went to
/// holds bytes, and a write after a retention pass opens it again by itself. The write of the
/// opening output is waited for first, so that it is not the one the pause stops.
async fn until_the_output_waits_on_the_disk(
    wired: &Wired,
    client: &mut Client<impl Codec>,
    attachment: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
) -> std::sync::mpsc::Sender<()> {
    let runtime = Arc::clone(&wired.runtime);
    tokio::task::spawn_blocking(move || runtime.wait_for_the_spool_write())
        .await
        .expect("the wait ends");
    let (writing, resume) = wired.runtime.pause_in_next_spool_write();
    write_over(client, wired, attachment, epoch, 0, b"x")
        .await
        .expect("the byte is accepted");
    assert!(
        matches!(
            tokio::time::timeout(LIVENESS_DEADLINE, writing).await,
            Ok(Ok(()))
        ),
        "the session's output waited on the disk"
    );
    resume
}

/// KR-PERF-002: a lone Escape reaches the application at its deadline while the session's output
/// is waiting on the disk.
///
/// The spool takes every batch of output the application writes, and a disk that is busy with
/// other work can keep a write waiting for as long as it likes. The write is stopped at that
/// moment, which is where an ingest that kept the session across it would keep the Escape's write,
/// and then the timer, out of the session for as long as the disk took to answer. The Escape has
/// to arrive before the write is let go. What the application received is read from the file it
/// keeps, because the session's output is what is stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn a_lone_escape_reaches_the_application_while_the_session_s_output_is_waiting_on_the_disk() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let received = kept.path().join("received");
    let wired = wired(&bracketed_recording(&received)).await;
    let (mut client, attachment, epoch) = typist(&wired).await;

    let resume = until_the_output_waits_on_the_disk(&wired, &mut client, attachment, epoch).await;

    let accepted_or_not = Arc::new(AtomicBool::new(false));
    let (let_go, watchdog) = release_after_a_while(
        {
            let resume = resume.clone();
            move || {
                let _ = resume.send(());
            }
        },
        &accepted_or_not,
    );
    let accepted = write_over(&mut client, &wired, attachment, epoch, 1, b"\x1b")
        .await
        .expect("the Escape is accepted");
    accepted_or_not.store(true, Ordering::Release);
    assert!(
        !let_go.load(Ordering::Acquire),
        "the Escape's write was kept waiting by the output's write to the disk until it was let go"
    );
    assert_eq!(accepted.held_prefix_bytes.get(), 1, "the Escape is held");

    let arrived = tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            if std::fs::read(&received).is_ok_and(|seen| contains(&seen, b"x\x1b")) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        arrived.is_ok(),
        "the Escape reached the application while the output was still being written"
    );
    assert!(
        !let_go.load(Ordering::Acquire),
        "and the write was not let go for it to"
    );

    resume.send(()).expect("lets the write go");
    watchdog.join().expect("the watchdog ends");
    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-PERF-002: a lone Escape reaches the application while a question's caller is being
/// identified.
///
/// A question or an alert names the session it is asked in, and the worker asks the kernel who the
/// caller is before it creates anything. The kernel's answer is a walk up the caller's parents,
/// and it takes as long as the kernel takes. The binding is stopped at that moment, which is where
/// a worker that kept the session across it would keep the Escape's write, and then the timer, out
/// of the session for as long as the kernel took to answer. The Escape has to arrive before the
/// binding is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn a_lone_escape_reaches_the_application_while_a_question_s_caller_is_being_identified() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let received = kept.path().join("received");
    let wired = wired(&bracketed_recording(&received)).await;
    let (mut client, attachment, epoch) = typist(&wired).await;

    let (arrived, release) = wired.service.pause_in_binding();
    let mut asker = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let (target, session_id) = (wired.target(), wired.session_id);
    let asking = tokio::spawn(async move {
        asker
            .mutate(
                Method::QuestionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::question::QuestionCreateParams {
                    session_id,
                    request_id: "push-anyway".to_owned(),
                    agent_name: Nullable::some("kr-test-agent".to_owned()),
                    context: "The build finished with two failing tests.".to_owned(),
                    question: "Push the branch anyway?".to_owned(),
                    kind: kr_protocol::question::QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: Nullable::null(),
                    wait_ms: Nullable::null(),
                },
            )
            .await
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS_DEADLINE))
        .await
        .expect("the wait ends")
        .expect("the question's caller is being identified");

    let accepted_or_not = Arc::new(AtomicBool::new(false));
    let (let_go, watchdog) = release_after_a_while(
        {
            let release = release.clone();
            move || {
                let _ = release.send(());
            }
        },
        &accepted_or_not,
    );
    let accepted = write_over(&mut client, &wired, attachment, epoch, 0, b"\x1b")
        .await
        .expect("the Escape is accepted");
    accepted_or_not.store(true, Ordering::Release);
    assert!(
        !let_go.load(Ordering::Acquire),
        "the Escape's write was kept waiting by the identification of a question's caller until \
         it was let go"
    );
    assert_eq!(accepted.held_prefix_bytes.get(), 1, "the Escape is held");
    let arrived = tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            if std::fs::read(&received).is_ok_and(|seen| contains(&seen, b"\x1b")) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        arrived.is_ok(),
        "the Escape reached the application while the caller was still being identified"
    );
    assert!(
        !let_go.load(Ordering::Acquire),
        "and the identification was not let go for it to"
    );

    release.send(()).expect("lets the identification go");
    watchdog.join().expect("the watchdog ends");
    let _ = asking.await;
    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-PERF-002: a close that is admitted discards the prefix the recogniser holds and accepts no
/// input after it.
///
/// A closing session reads the processes it owns with the session held, for as long as the kernel
/// takes, while it waits out its grace period. No keystroke can be waiting for that: from the
/// moment the close is admitted what the recogniser held goes with the lease, nothing is forwarded
/// at a deadline, and a write is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn a_close_discards_the_prefix_the_recogniser_holds_and_accepts_no_input() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, BRACKETED_ECHO);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment = attach(&mut session, &terminal(session_id, Some("xterm-256color")));
    let epoch = session
        .acquire_input(attachment, connection(), None)
        .expect("the keys")
        .lease
        .epoch
        .get();
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    retained_within(&runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    // One boundary for all of it: the recogniser's own timer would otherwise forward the Escape
    // before the close is admitted.
    let gate = {
        let mut session = runtime.session();
        let accepted = session
            .write_input(attachment, epoch, 0, b"\x1b", None, Instant::now())
            .expect("accepted");
        assert_eq!(accepted.held_prefix_bytes, 1, "the Escape is held");
        let (acceptance, gate) = runtime.close_locked(&mut session, ClosureReason::CloseRequested);
        assert!(acceptance.initiated, "the close is admitted");
        assert!(
            session.paste_deadline().is_none(),
            "nothing is held for a deadline to forward"
        );
        assert!(
            session
                .write_input(attachment, epoch, 1, b"x", None, Instant::now())
                .is_err(),
            "and no further input is accepted"
        );
        gate
    };
    gate.release();
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the closure completed");
    assert_eq!(record.reason, ClosureReason::CloseRequested);
    let seen = retained(&runtime.session());
    assert!(
        !contains(&seen, b"kr-ready.\x1b"),
        "the application never received the Escape: {seen:?}"
    );
}

/// KR-PERF-002: the output that has been ingested can be read while it is waiting on the disk.
///
/// A reader of the session's retained output takes the session, as the input measurement's poll
/// does. Output the application has written is retained when the ingest has recorded it, and the
/// disk is a further step; a reader behind the disk would see the output as late as the disk is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_is_readable_from_the_session_while_it_is_waiting_on_the_disk() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let wired = wired(BRACKETED_ECHO).await;
    let (mut client, attachment, epoch) = typist(&wired).await;

    let resume = until_the_output_waits_on_the_disk(&wired, &mut client, attachment, epoch).await;

    let read = Arc::new(AtomicBool::new(false));
    let (let_go, watchdog) = release_after_a_while(
        {
            let resume = resume.clone();
            move || {
                let _ = resume.send(());
            }
        },
        &read,
    );
    let runtime = Arc::clone(&wired.runtime);
    let seen = tokio::task::spawn_blocking(move || retained(&runtime.session()))
        .await
        .expect("the read ends");
    read.store(true, Ordering::Release);
    assert!(
        !let_go.load(Ordering::Acquire),
        "the read of the retained output was kept waiting by the output's write to the disk until \
         it was let go"
    );
    assert!(
        contains(&seen, b"kr-ready.x"),
        "the echo was retained before the disk had taken it: {seen:?}"
    );

    resume.send(()).expect("lets the write go");
    watchdog.join().expect("the watchdog ends");
    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// What a held prefix's path records: each acquisition of the session with the instants it began
/// to wait, held the session and let go of it, the timer's wake against its deadline, and the
/// observation of the session's processes, in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "a Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a sequence, so the Escape this case waits for does not come back"
)]
async fn the_recorder_keeps_each_acquisition_on_a_held_prefix_s_path() {
    use kr_worker::trace::Site;

    let wired = wired(BRACKETED_ECHO).await;
    let (mut client, attachment, epoch) = typist(&wired).await;
    let trace = wired.runtime.trace();
    trace.arm();

    write_over(&mut client, &wired, attachment, epoch, 0, b"\x1b")
        .await
        .expect("the write is accepted");
    retained_within(&wired.runtime, b"kr-ready.\x1b", LIVENESS_DEADLINE).await;
    wired.runtime.observe_now();
    // The observation's result is put back by a wake of its own, after the reading. A recording
    // gives each event once, so what it gives is kept here as it comes.
    let mut events = Vec::new();
    let mut overflowed = false;
    let (observation, put_back) = tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            let recording = trace.recording();
            overflowed |= recording.overflowed;
            events.extend(recording.events);
            // An observation that was under way when the recorder was armed leaves a put-back and
            // no reading, so the pair is the first reading and the first put-back after it.
            if let Some(read) = events
                .iter()
                .position(|event| event.site == Site::Observation)
                && let Some(wake) = events[read..].iter().find(|event| {
                    event.site == Site::SupervisionWake
                        && event.value == kr_worker::runtime::SUPERVISION_PUT_BACK
                })
            {
                return (events[read], *wake);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the observation's result was put back");
    // What had not finished being stored when the pair was found.
    let last = trace.recording();
    overflowed |= last.overflowed;
    events.extend(last.events);
    assert!(!overflowed, "a hold's events fit the recorder");

    let of = |site: Site| {
        events
            .iter()
            .filter(move |event| event.site == site)
            .copied()
            .collect::<Vec<_>>()
    };
    for site in [
        Site::InputAcceptance,
        Site::TimerLook,
        Site::TimerForward,
        Site::Ingest,
        Site::SupervisionWake,
    ] {
        let events = of(site);
        assert!(!events.is_empty(), "{site:?} was recorded");
        for event in events {
            assert!(
                event.begun <= event.held && event.held <= event.released,
                "{site:?} began to wait, held the session and let go of it in that order: {event:?}"
            );
        }
    }
    let accepted = of(Site::InputAcceptance)[0];
    assert!(
        accepted.value != 0,
        "the acceptance kept the deadline it set"
    );
    let woke = of(Site::TimerWake)[0];
    assert_eq!(
        woke.begun, accepted.value,
        "the timer slept for that deadline"
    );
    assert!(woke.held >= woke.begun, "and woke at or after it");
    let forwarded = of(Site::TimerForward)[0];
    assert!(
        forwarded.held >= woke.held,
        "and took the session after waking"
    );
    assert!(
        observation.begun <= observation.held,
        "the observation read for a span"
    );
    assert!(
        put_back.held >= observation.held,
        "and its result was put back after the reading ended"
    );

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-07.13: a process the session started is recorded by an observation made with the session
/// let go.
///
/// The observation reads the processes on a copy of the record and puts what it found back, so
/// that the session is free while the kernel answers. What it found has to arrive in the record the
/// way it did when the reading kept the session. The supervision observes on its own once the
/// session has done something, and when it does is the machine's to say, so the case asks for one
/// and waits for the process it was told of rather than for a change.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_process_the_session_started_is_recorded_by_an_observation_made_with_the_session_let_go()
{
    let wired = wired("stty raw -echo; sleep 600 & printf 'kr-ready.%s;' \"$!\"; exec cat").await;
    // The shell says which process it started, between `kr-ready.` and a semicolon.
    let job: u64 = tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            let told = String::from_utf8_lossy(&retained(&wired.runtime.session())).into_owned();
            if let Some(pid) = told
                .split_once("kr-ready.")
                .and_then(|(_, rest)| rest.split_once(';'))
                .and_then(|(pid, _)| pid.parse().ok())
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the shell says which process it started");
    let recorded = |wired: &Wired| {
        wired
            .runtime
            .session()
            .owned()
            .expect("the session records what it owns")
            .record()
            .processes
            .iter()
            .any(|identity| identity.pid.get() == job)
    };

    wired.runtime.observe_now();
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while !recorded(&wired) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the process the shell started was recorded");

    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-07.13: a closure goes on once the observation of the session's processes that was under
/// way when it began has been put back.
///
/// Each step of a closure that observes the processes waits for an observation that has copied the
/// record out and not yet put its result back, so that the closure does not stop what the record
/// names before the record names what that reading found. The observation is stopped while it
/// reads, a close is begun and released, and the closure has to complete once the observation is
/// let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_goes_on_once_the_observation_under_way_has_been_put_back() {
    let wired = wired("stty raw -echo; printf 'kr-ready.'; exec cat").await;
    retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;

    let (reading, resume) = wired.runtime.pause_in_next_observation();
    wired.runtime.observe_now();
    tokio::time::timeout(LIVENESS_DEADLINE, reading)
        .await
        .expect("the observation reached its reading")
        .expect("the observation is reading");
    let (_, gate) = wired.runtime.close(ClosureReason::CloseRequested);
    gate.release();
    resume.send(()).expect("lets the observation go");

    let record = tokio::time::timeout(LIVENESS_DEADLINE, wired.runtime.wait_closed())
        .await
        .expect("the closure completed");
    assert_eq!(record.reason, ClosureReason::CloseRequested);
}

// ---------------------------------------------------------------------------------------------
// KR-PERF-002: a keystroke waits behind no disk work.
// ---------------------------------------------------------------------------------------------

/// What keeps the session, or something under it, busy while a held prefix waits.
#[derive(Clone, Copy, Debug)]
enum Stalled {
    /// The commit of a mutation's dispatch marker, which the mutation makes with the session held.
    Marker,
    /// The same commit, made by a thread that blocks and hands nothing off, as a commit to a busy
    /// disk does.
    BlockedMarker,
    /// The commit of the maintenance pass that prunes the receipt journal.
    Prune,
    /// The same commit, made by a thread that blocks and hands nothing off.
    BlockedPrune,
    /// The commit of a question to the ledger, made with the session held as a mutation makes it.
    Question,
    /// The commit of a host event the output ingest records with the session held.
    HostEvent,
    /// The same commit, made by a thread that blocks and hands nothing off.
    BlockedHostEvent,
    /// The session itself, held by something that takes as long as it likes.
    Session,
}

/// Where a held prefix's deadline falls in relation to the stall.
#[derive(Clone, Copy, Debug)]
enum Timing {
    /// The write arrives while the stall is in force.
    Arrives,
    /// The write was accepted before the stall began and is held; its deadline passes inside it.
    DeadlineFalls,
}

/// A root program that keeps what it reads in a file as well as echoing it, with bracketed paste
/// enabled, and that writes a sequence of its own into its output when a named pipe is written to.
///
/// What reached the application can then be read without the worker, which a case that stops the
/// worker's session cannot use.
fn triggered_recording(
    received: &std::path::Path,
    trigger: &std::path::Path,
    output: &str,
) -> String {
    format!(
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; \
         ( while cat '{}' >/dev/null; do printf '{output}'; done ) & exec tee '{}'",
        trigger.display(),
        received.display()
    )
}

/// A worker with a session whose application keeps what it is typed, and the attachment typing.
struct Rig {
    _kept: tempfile::TempDir,
    /// The file the application keeps what it reads in, which a Windows host does not read.
    #[cfg_attr(windows, allow(dead_code))]
    received: std::path::PathBuf,
    trigger: std::path::PathBuf,
    wired: Wired,
    client: LocalClient,
    attachment: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    /// What the application has been typed so far, in the order it was handed to the worker.
    typed: Vec<u8>,
    questions: u32,
}

impl Rig {
    /// Starts the worker. `output` is what the application prints when the trigger is pulled.
    async fn start(output: &str) -> Self {
        Self::from_script(|received, trigger| triggered_recording(received, trigger, output)).await
    }

    /// Starts the worker with an application that reads nothing until the trigger is pulled, and
    /// keeps all it reads.
    async fn start_late() -> Self {
        Self::from_script(|received, trigger| {
            format!(
                "stty raw -echo; printf '\\033[?2004hkr-ready.'; cat '{}' >/dev/null; \
                 exec tee '{}'",
                trigger.display(),
                received.display()
            )
        })
        .await
    }

    async fn from_script(
        script: impl FnOnce(&std::path::Path, &std::path::Path) -> String,
    ) -> Self {
        let kept = tempfile::tempdir().expect("a directory for what the application keeps");
        let received = kept.path().join("received");
        let trigger = kept.path().join("trigger");
        // A Windows host has no named pipe to make this way; the cases that pull the trigger are
        // not run there.
        #[cfg(unix)]
        {
            let made = std::process::Command::new("mkfifo")
                .arg(&trigger)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "the trigger is made");
        }
        let wired = wired(&script(&received, &trigger)).await;
        let (client, attachment, epoch) = typist(&wired).await;
        Self {
            _kept: kept,
            received,
            trigger,
            wired,
            client,
            attachment,
            epoch,
            sequence: 0,
            typed: Vec::new(),
            questions: 0,
        }
    }

    /// Hands the worker one write, and returns what it answered and when the write began.
    async fn write(&mut self, bytes: &[u8]) -> (InputWriteResult, Instant) {
        let began = Instant::now();
        let accepted = write_over(
            &mut self.client,
            &self.wired,
            self.attachment,
            self.epoch,
            self.sequence,
            bytes,
        )
        .await
        .expect("the write is accepted");
        self.sequence += 1;
        self.typed.extend_from_slice(bytes);
        (accepted, began)
    }

    /// What the application has received, read from the file it keeps.
    #[cfg(not(windows))]
    fn received(&self) -> Vec<u8> {
        std::fs::read(&self.received).unwrap_or_default()
    }

    /// What the application has been handed, read from what the terminal's writer wrote.
    ///
    /// A Windows pseudo-console holds back a lone Escape, which it cannot tell from the start of a
    /// sequence, so the application does not see one for a while whatever the host did, and a file
    /// the application keeps says nothing of the host's wait. What the writer wrote to the
    /// pseudo-console is the host's last step, and it is the same observation on every platform
    /// that touches nothing of the session's.
    #[cfg(windows)]
    fn received(&self) -> Vec<u8> {
        self.wired
            .runtime
            .input()
            .terminal_writes()
            .into_iter()
            .filter(|write| write.of_a_lease)
            .flat_map(|write| write.bytes)
            .collect()
    }

    /// Waits until the application has received everything typed so far, and says when that was.
    async fn until_everything_typed_arrived(&self) -> Option<Instant> {
        tokio::time::timeout(LIVENESS_DEADLINE, async {
            loop {
                if self.received() == self.typed {
                    return Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .ok()
    }

    /// Pulls the trigger: the application prints what it was told to.
    async fn pull_the_trigger(&self) {
        let trigger = self.trigger.clone();
        tokio::task::spawn_blocking(move || std::fs::write(trigger, b"x"))
            .await
            .expect("the trigger task ends")
            .expect("the trigger is pulled");
    }

    async fn close(self) {
        let Self { client, wired, .. } = self;
        drop(client);
        wired
            .runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
    }
}

/// A stall that has begun: what lets it go, and the work that is stopped in it.
struct Standing {
    release: std::sync::mpsc::Sender<()>,
    stopped: Option<tokio::task::JoinHandle<()>>,
}

/// Begins `stalled` and returns once the work is stopped in it.
async fn stall(rig: &mut Rig, stalled: Stalled) -> Standing {
    let wired = &rig.wired;
    let (reached, release, stopped) = match stalled {
        Stalled::Marker | Stalled::BlockedMarker => {
            let (reached, release) = {
                let mut session = wired.runtime.session();
                let journal = session.journal_mut().expect("this session keeps a journal");
                if matches!(stalled, Stalled::Marker) {
                    journal.stall_next_marker()
                } else {
                    journal.stall_next_marker_blocking()
                }
            };
            let mut other = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            let (target, session_id) = (wired.target(), wired.session_id);
            let attaching = tokio::spawn(async move {
                let _ = other
                    .mutate(
                        Method::SessionAttach,
                        ActionId::new(kr_ipc::new_uuid()),
                        target,
                        &terminal(session_id, Some("xterm-256color")),
                    )
                    .await;
            });
            (reached, release, Some(attaching))
        }
        Stalled::Prune | Stalled::BlockedPrune => {
            let (reached, release) = {
                let mut session = wired.runtime.session();
                let journal = session.journal_mut().expect("this session keeps a journal");
                if matches!(stalled, Stalled::Prune) {
                    journal.stall_next_prune()
                } else {
                    journal.stall_next_prune_blocking()
                }
            };
            // As maintenance runs: a task of the worker's own runtime.
            let service = Arc::clone(&wired.service);
            let pass = tokio::spawn(async move { service.maintain_now() });
            let pass = tokio::spawn(async move {
                let _ = pass.await;
            });
            (reached, release, Some(pass))
        }
        Stalled::Question => {
            let (reached, release) = wired.service.questions().stall_next_commit();
            // As a question's creation is made: with the session held, by a source that is inside
            // it. A caller outside the session is refused before anything is committed.
            rig.questions += 1;
            let request_id = format!("push-anyway-{}", rig.questions);
            let (service, runtime) = (Arc::clone(&wired.service), Arc::clone(&wired.runtime));
            let session_id = wired.session_id;
            let asking = tokio::task::spawn_blocking(move || {
                let _session = runtime.session();
                let source = kr_worker::questions::VerifiedSource {
                    process: kr_ipc::identity::current_process_start_identity()
                        .expect("a process identity"),
                    executable: Some("kr-test-agent".to_owned()),
                    session_member: true,
                    ancestry: true,
                    launch_channel: false,
                    connection_id: ConnectionId::new(kr_ipc::new_uuid()),
                };
                let now = kr_worker::questions::Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: kr_ipc::clock::boot_elapsed_ms(),
                };
                let _ = service.questions().create(
                    &source,
                    &kr_protocol::question::QuestionCreateParams {
                        session_id,
                        request_id,
                        agent_name: Nullable::some("kr-test-agent".to_owned()),
                        context: "The build finished with two failing tests.".to_owned(),
                        question: "Push the branch anyway?".to_owned(),
                        kind: kr_protocol::question::QuestionKind::Confirm,
                        choices: Vec::new(),
                        requested_expiry_ms: Nullable::null(),
                        wait_ms: Nullable::null(),
                    },
                    now,
                );
            });
            let asking = tokio::spawn(async move {
                let _ = asking.await;
            });
            (reached, release, Some(asking))
        }
        Stalled::HostEvent | Stalled::BlockedHostEvent => {
            // The attachment's terminal takes no clipboard writes, so one the application asks for
            // is a host event, and the ingest records it with the session held.
            let (reached, release) = {
                let mut session = wired.runtime.session();
                session.decline_clipboard_writes(rig.attachment);
                let journal = session.journal_mut().expect("this session keeps a journal");
                if matches!(stalled, Stalled::HostEvent) {
                    journal.stall_next_host_events()
                } else {
                    journal.stall_next_host_events_blocking()
                }
            };
            rig.pull_the_trigger().await;
            (reached, release, None)
        }
        Stalled::Session => {
            let (reached, release) = wired.runtime.hold_the_session();
            (reached, release, None)
        }
    };
    tokio::time::timeout(LIVENESS_DEADLINE, reached)
        .await
        .unwrap_or_else(|_| panic!("{stalled:?}: the work did not reach its stall"))
        .unwrap_or_else(|_| panic!("{stalled:?}: the stall was dropped before it was reached"));
    Standing { release, stopped }
}

/// Lets a stall go after a while, and says whether it had to.
///
/// A regression leaves the stall holding what the case waits for, and the case then fails naming
/// the wait: the stall is let go after `after`, and what arrives later arrives too late.
struct LetGo {
    done: Arc<std::sync::atomic::AtomicBool>,
    let_go: Arc<std::sync::atomic::AtomicBool>,
    /// The moment the stall was let go, when it had to be.
    let_go_at: Arc<std::sync::Mutex<Option<Instant>>>,
    thread: std::thread::JoinHandle<()>,
}

impl LetGo {
    fn after(release: std::sync::mpsc::Sender<()>, after: Duration) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (done, let_go) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let let_go_at = Arc::new(std::sync::Mutex::new(None));
        let thread = {
            let (done, let_go, let_go_at) = (
                Arc::clone(&done),
                Arc::clone(&let_go),
                Arc::clone(&let_go_at),
            );
            std::thread::spawn(move || {
                let began = Instant::now();
                while began.elapsed() < after {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                if !done.load(Ordering::Acquire) {
                    *let_go_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
                    let_go.store(true, Ordering::Release);
                    let _ = release.send(());
                }
            })
        };
        Self {
            done,
            let_go,
            let_go_at,
            thread,
        }
    }

    /// Says the stall is no longer needed, and returns whether it had to be let go.
    fn finish(self) -> bool {
        self.finish_at().is_some()
    }

    /// Says the stall is no longer needed, and returns the moment it was let go when it had to be.
    fn finish_at(self) -> Option<Instant> {
        use std::sync::atomic::Ordering;

        self.done.store(true, Ordering::Release);
        self.thread.join().expect("the watchdog ends");
        let at = *self
            .let_go_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert_eq!(at.is_some(), self.let_go.load(Ordering::Acquire));
        at
    }
}

/// Something that writes to the disk the test runs on for as long as it lives, the way a process
/// beside the worker does.
struct DiskWriter {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl DiskWriter {
    fn beside(directory: &std::path::Path) -> Self {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let path = directory.join("disk-writer");
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let block = vec![0x5a_u8; 4 * 1024 * 1024];
                while !stop.load(Ordering::Acquire) {
                    if let Ok(mut file) = std::fs::File::create(&path) {
                        let _ = file.write_all(&block);
                        let _ = file.sync_all();
                    }
                }
                let _ = std::fs::remove_file(&path);
            })
        };
        Self { stop, thread }
    }

    fn stop(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.thread.join().expect("the disk writer ends");
    }
}

/// One prefix typed under one stall: the bytes the application has received once the prefix has
/// been handed to it, and how long after the write began that was.
///
/// What the application received is read from the file it keeps, which touches nothing of the
/// worker's, so the observation waits for no lock of the session's. The stall is let go only after
/// the prefix has been seen, or after `stalled_for` where a case bounds it. A prefix the
/// application read only after the stall was let go has waited for it unless the worker had written
/// it to the terminal by then: a box too busy to run the application is not the worker holding the
/// prefix back ([`kept_waiting_by_the_stall`]).
async fn a_prefix_meets(
    rig: &mut Rig,
    stalled: Stalled,
    timing: Timing,
    prefix: &[u8],
    stalled_for: Duration,
) -> Duration {
    // A held prefix whose deadline falls inside the stall is accepted first, and the recogniser's
    // timer is stopped at that deadline, so that the stall can begin before the prefix is
    // forwarded.
    let at_deadline = match timing {
        Timing::Arrives => None,
        Timing::DeadlineFalls => {
            let (reached, go) = rig.wired.runtime.pause_the_timer_at_its_deadline();
            let (accepted, _) = rig.write(prefix).await;
            assert_eq!(
                accepted.held_prefix_bytes.get(),
                prefix.len() as u64,
                "{stalled:?}, {timing:?}: the prefix {prefix:?} is held"
            );
            tokio::time::timeout(LIVENESS_DEADLINE, reached)
                .await
                .expect("the timer reached the deadline")
                .expect("the timer is waiting");
            Some(go)
        }
    };

    let standing = stall(rig, stalled).await;
    let letting_go = LetGo::after(standing.release.clone(), stalled_for);
    let began = match at_deadline {
        Some(go) => {
            let began = Instant::now();
            go.send(()).expect("lets the timer go on");
            began
        }
        None => {
            let (accepted, began) = rig.write(prefix).await;
            assert_eq!(
                accepted.held_prefix_bytes.get(),
                prefix.len() as u64,
                "{stalled:?}, {timing:?}: the prefix {prefix:?} is held"
            );
            began
        }
    };
    let arrived = rig.until_everything_typed_arrived().await;
    let let_go_at = letting_go.finish_at();
    let arrived = arrived.unwrap_or_else(|| {
        panic!(
            "{stalled:?}, {timing:?}: the application never received {prefix:?}: {:?}",
            rig.received()
        )
    });
    let hold = arrived.duration_since(began);
    eprintln!("{stalled:?}, {timing:?}, {prefix:?}: received {hold:?} after the write began");
    let written = the_write_that_completed(rig);
    assert!(
        !kept_waiting_by_the_stall(rig, let_go_at),
        "{stalled:?}, {timing:?}: {prefix:?} was kept waiting by the stall until it was let go \
         ({hold:?}, written to the terminal {:?} after the write began)",
        written.map(|written| written.saturating_duration_since(began))
    );
    if let_go_at.is_some() {
        eprintln!(
            "{stalled:?}, {timing:?}, {prefix:?}: written to the terminal before the stall was let \
             go, and read by the application {hold:?} after the write began"
        );
    }

    // A stall that was let go has gone already, and nothing is left to receive a second release.
    let released = standing.release.send(());
    assert!(
        released.is_ok() || let_go_at.is_some(),
        "{stalled:?}, {timing:?}: the stall could not be let go"
    );
    if let Some(stopped) = standing.stopped {
        let _ = stopped.await;
    }
    hold
}

/// When the worker had written everything the rig has typed to the terminal: the moment of the
/// write that brought the lease's bytes written, counted from the start, to the length typed. None
/// while it has not.
///
/// A write is recorded after it returns, so a write of an earlier step can be recorded late; that
/// one counts toward the bytes before this step's and never reaches the length typed by this one.
fn the_write_that_completed(rig: &Rig) -> Option<Instant> {
    let mut written = 0;
    rig.wired
        .runtime
        .input()
        .terminal_writes()
        .into_iter()
        .filter(|write| write.of_a_lease)
        .find_map(|write| {
            written += write.bytes.len();
            (written >= rig.typed.len()).then_some(write.at)
        })
}

/// Whether the worker kept what was typed waiting for the stall, given the moment the stall was let
/// go when it had to be. The application can read late on a busy box; that is not the worker holding
/// the bytes. They were held if the worker had not written them all to the terminal by the time the
/// stall was let go.
fn kept_waiting_by_the_stall(rig: &Rig, let_go_at: Option<Instant>) -> bool {
    let_go_at.is_some_and(|let_go_at| {
        the_write_that_completed(rig).is_none_or(|written| written > let_go_at)
    })
}

/// The case behind the first three forced cases: a lone Escape under one stall, with the stall
/// let go after `stalled_for` at the latest.
async fn a_lone_escape_meets(stalled: Stalled, timing: Timing, stalled_for: Duration) {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    a_prefix_meets(&mut rig, stalled, timing, b"\x1b", stalled_for).await;
    rig.close().await;
}

/// What the application prints when its trigger is pulled: a clipboard write.
const HOST_EVENT_OUTPUT: &str = "\\033]52;c;aGk=\\007";

/// Every prefix of the bracketed-paste start delimiter that the recogniser holds, shortest first,
/// and the longest prefix of the end delimiter, which the start's do not include.
fn the_held_prefixes() -> Vec<&'static [u8]> {
    let mut prefixes: Vec<&'static [u8]> = (1..PASTE_START.len())
        .map(|length| &PASTE_START[..length])
        .collect();
    prefixes.push(&PASTE_END[..PASTE_END.len() - 1]);
    prefixes
}

/// How many times the split delimiter is offered before a run is taken for one that cannot keep the
/// recogniser's deadline at all.
const SPLIT_ATTEMPTS: u32 = 20;

/// KR-PERF-002: the delimiter split across two writes, with `stalled` in force. The first part is
/// held; the second arrives within the recogniser's deadline and completes it, so the delimiter is
/// forwarded once whole and the paste it opens is recognised. A watchdog lets the stall go if
/// either write waits for it.
///
/// The claim is about a second part that reaches the recogniser inside its deadline, and the
/// deadline is the recogniser's own, kept exactly. Whether it did is read from the recogniser,
/// which keeps the last prefix it forwarded because it had held it for the deadline:
///
/// - No such prefix since the first write began: the first part was still held when the second
///   arrived, which is inside the deadline however busy the box was, and the delimiter must be
///   whole. This is the claim.
/// - Such a prefix: the first part ran out of time before the second reached the recogniser, as
///   it is meant to, and says nothing of the claim. It must have been held for the whole
///   deadline, and begun to be held after the first write began; anything shorter is a recogniser
///   that forwards too soon, and the case fails. The delimiter is offered again.
async fn a_delimiter_split_across_two_writes_meets(rig: &mut Rig, stalled: Stalled) {
    for attempt in 1..=SPLIT_ATTEMPTS {
        let delimiters_before = count(&rig.received(), PASTE_START);
        let standing = stall(rig, stalled).await;
        let letting_go = LetGo::after(standing.release.clone(), Duration::from_secs(5));
        let (first, first_began) = rig.write(&PASTE_START[..4]).await;
        assert_eq!(
            first.held_prefix_bytes.get(),
            4,
            "{stalled:?}: the first part is held"
        );
        // The rest of the delimiter, and a payload behind it, in one write.
        let rest = [&PASTE_START[4..], &b"kr-payload"[..]].concat();
        let (second, _) = rig.write(&rest).await;
        let (expiry, opened) = {
            let input = rig.wired.runtime.input().lock();
            (
                input
                    .last_expiry()
                    .filter(|expired| expired.since >= first_began),
                input.paste_open(),
            )
        };
        if let Some(expired) = expiry {
            assert!(
                expired.now.saturating_duration_since(expired.since)
                    >= kr_worker::input::RECOGNISER_DEADLINE,
                "{stalled:?}: the recogniser forwarded the first part after holding it for {:?}, \
                 before its deadline",
                expired.now.saturating_duration_since(expired.since)
            );
            assert!(
                !opened,
                "{stalled:?}: a prefix that had run out of time still completed the delimiter and \
                 opened a paste"
            );
        } else {
            assert_eq!(
                second.forwarded_bytes.get(),
                (PASTE_START.len() + b"kr-payload".len()) as u64,
                "{stalled:?}: the second part reached the worker inside the recogniser's deadline \
                 and completes the delimiter, which is forwarded whole with the payload behind it"
            );
            assert!(
                opened,
                "{stalled:?}: the delimiter was recognised, which is what opens a paste: a prefix \
                 that had expired and was forwarded with the bytes behind it opens none"
            );
        }
        let arrived = rig.until_everything_typed_arrived().await;
        let let_go_at = letting_go.finish_at();
        assert!(
            !kept_waiting_by_the_stall(rig, let_go_at),
            "{stalled:?}: the split delimiter was kept waiting by the stall until it was let go"
        );
        assert!(
            arrived.is_some(),
            "{stalled:?}: the delimiter did not reach the application whole while the stall was in force: {:?}",
            rig.received()
        );
        // A stall that was let go has gone already, and nothing is left to receive a second
        // release.
        let released = standing.release.send(());
        assert!(
            released.is_ok() || let_go_at.is_some(),
            "{stalled:?}: the stall could not be let go"
        );
        if let Some(stopped) = standing.stopped {
            let _ = stopped.await;
        }
        if expiry.is_some() {
            // Nothing is held and no paste is open, so the next attempt starts from a clean
            // recogniser.
            eprintln!(
                "{stalled:?}: attempt {attempt} of the split delimiter reached the recogniser after \
                 its deadline, and is offered again"
            );
            continue;
        }
        assert_eq!(
            count(&rig.received(), PASTE_START) - delimiters_before,
            1,
            "{stalled:?}: the delimiter was forwarded once"
        );
        return;
    }
    panic!(
        "{stalled:?}: none of {SPLIT_ATTEMPTS} attempts at the split delimiter reached the \
         recogniser inside its deadline"
    );
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reaches the application while `stalled` is in force, with a disk writer beside the
/// worker when `beside_a_disk_writer` says so.
async fn every_prefix_meets(stalled: Stalled, beside_a_disk_writer: bool) {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let writer = beside_a_disk_writer.then(|| DiskWriter::beside(rig._kept.path()));
    for timing in [Timing::Arrives, Timing::DeadlineFalls] {
        for prefix in the_held_prefixes() {
            a_prefix_meets(&mut rig, stalled, timing, prefix, Duration::from_secs(5)).await;
        }
    }
    a_delimiter_split_across_two_writes_meets(&mut rig, stalled).await;
    if let Some(writer) = writer {
        writer.stop();
    }
    rig.close().await;
}

macro_rules! forced_cases {
    ($($(#[$meta:meta])* $name:ident: $stalled:expr, $timing:expr, $millis:expr;)*) => {
        $(
            $(#[$meta])*
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                a_lone_escape_meets($stalled, $timing, Duration::from_millis($millis)).await;
            }
        )*
    };
}

forced_cases! {
    /// KR-PERF-002: a lone Escape that arrives while a mutation's marker commit is stalled for
    /// 100 ms reaches the application before the stall ends.
    a_lone_escape_arriving_during_a_marker_commit_stalled_100_ms_reaches_the_application:
        Stalled::Marker, Timing::Arrives, 100;
    /// KR-PERF-002: the same, stalled for 300 ms.
    a_lone_escape_arriving_during_a_marker_commit_stalled_300_ms_reaches_the_application:
        Stalled::Marker, Timing::Arrives, 300;
    /// KR-PERF-002: a held Escape whose deadline passes inside a marker commit stalled for 100 ms.
    a_held_escape_whose_deadline_falls_in_a_marker_commit_stalled_100_ms_reaches_the_application:
        Stalled::Marker, Timing::DeadlineFalls, 100;
    /// KR-PERF-002: the same, stalled for 300 ms.
    a_held_escape_whose_deadline_falls_in_a_marker_commit_stalled_300_ms_reaches_the_application:
        Stalled::Marker, Timing::DeadlineFalls, 300;
    /// KR-PERF-002: a lone Escape that arrives while the maintenance prune's commit is stalled.
    a_lone_escape_arriving_during_a_stalled_maintenance_prune_reaches_the_application:
        Stalled::Prune, Timing::Arrives, 300;
    /// KR-PERF-002: a held Escape whose deadline passes inside a stalled maintenance prune.
    a_held_escape_whose_deadline_falls_in_a_stalled_maintenance_prune_reaches_the_application:
        Stalled::Prune, Timing::DeadlineFalls, 300;
    /// KR-PERF-002: a lone Escape that arrives while a question's commit is stalled.
    a_lone_escape_arriving_during_a_stalled_question_commit_reaches_the_application:
        Stalled::Question, Timing::Arrives, 300;
    /// KR-PERF-002: a held Escape whose deadline passes inside a stalled question commit.
    a_held_escape_whose_deadline_falls_in_a_stalled_question_commit_reaches_the_application:
        Stalled::Question, Timing::DeadlineFalls, 300;
    /// KR-PERF-002: a lone Escape that arrives while the ingest's host-event commit is stalled.
    #[cfg_attr(windows, ignore = "the application's input is read through a named pipe trigger")]
    a_lone_escape_arriving_during_a_stalled_host_event_commit_reaches_the_application:
        Stalled::HostEvent, Timing::Arrives, 300;
    /// KR-PERF-002: a held Escape whose deadline passes inside a stalled host-event commit.
    #[cfg_attr(windows, ignore = "the application's input is read through a named pipe trigger")]
    a_held_escape_whose_deadline_falls_in_a_stalled_host_event_commit_reaches_the_application:
        Stalled::HostEvent, Timing::DeadlineFalls, 300;
    /// KR-PERF-002: a lone Escape that arrives while the session is held for 100 ms.
    a_lone_escape_arriving_while_the_session_is_held_100_ms_reaches_the_application:
        Stalled::Session, Timing::Arrives, 100;
    /// KR-PERF-002: the same, held for 300 ms.
    a_lone_escape_arriving_while_the_session_is_held_300_ms_reaches_the_application:
        Stalled::Session, Timing::Arrives, 300;
    /// KR-PERF-002: a held Escape whose deadline passes while the session is held for 100 ms.
    a_held_escape_whose_deadline_falls_while_the_session_is_held_100_ms_reaches_the_application:
        Stalled::Session, Timing::DeadlineFalls, 100;
    /// KR-PERF-002: the same, held for 300 ms.
    a_held_escape_whose_deadline_falls_while_the_session_is_held_300_ms_reaches_the_application:
        Stalled::Session, Timing::DeadlineFalls, 300;
}

/// KR-PERF-002: a lone Escape reaches the application while a commit blocks the one thread the
/// worker's runtime has.
///
/// A commit to a busy disk blocks the thread it is made on and hands nothing back. On a host with
/// one processor the runtime has one thread for its tasks, so a mutation that made its commits on
/// that thread would stop the connection reading the Escape and the timer forwarding it, whatever
/// the input path takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_lone_escape_reaches_the_application_while_a_commit_blocks_the_only_thread_of_the_runtime()
 {
    a_lone_escape_meets(Stalled::BlockedMarker, Timing::Arrives, LIVENESS_DEADLINE).await;
}

/// KR-PERF-002: a lone Escape reaches the application while the maintenance pass's commit blocks
/// the one thread the worker's runtime has.
///
/// Maintenance runs as a task of the worker's runtime, and its prune commits with the session
/// held. On one thread, a pass that kept the thread for that commit would stop the connection and
/// the timer whatever the input path takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_lone_escape_reaches_the_application_while_a_prune_blocks_the_only_thread_of_the_runtime()
{
    a_lone_escape_meets(Stalled::BlockedPrune, Timing::Arrives, LIVENESS_DEADLINE).await;
}

/// KR-PERF-002: a lone Escape reaches the application while the ingest's host-event commit blocks
/// the one thread the worker's runtime has.
///
/// The ingest records a host event with the session held, on a task of the worker's runtime. On
/// one thread, an ingest that kept the thread for that commit would stop the connection and the
/// timer whatever the input path takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn a_lone_escape_reaches_the_application_while_a_host_event_commit_blocks_the_only_thread_of_the_runtime()
 {
    a_lone_escape_meets(
        Stalled::BlockedHostEvent,
        Timing::Arrives,
        LIVENESS_DEADLINE,
    )
    .await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_marker_commit() {
    every_prefix_meets(Stalled::Marker, false).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_maintenance_prune() {
    every_prefix_meets(Stalled::Prune, false).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_question_commit() {
    every_prefix_meets(Stalled::Question, false).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_host_event_commit() {
    every_prefix_meets(Stalled::HostEvent, false).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_while_the_session_is_held() {
    every_prefix_meets(Stalled::Session, false).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_marker_commit_beside_a_disk_writer()
 {
    every_prefix_meets(Stalled::Marker, true).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_maintenance_prune_beside_a_disk_writer()
 {
    every_prefix_meets(Stalled::Prune, true).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_question_commit_beside_a_disk_writer()
 {
    every_prefix_meets(Stalled::Question, true).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_during_a_stalled_host_event_commit_beside_a_disk_writer()
 {
    every_prefix_meets(Stalled::HostEvent, true).await;
}

/// KR-PERF-002: every prefix length of the start delimiter, and the delimiter split across two
/// writes, reach the application while the stall is in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_held_prefix_reaches_the_application_while_the_session_is_held_beside_a_disk_writer()
{
    every_prefix_meets(Stalled::Session, true).await;
}

// ---------------------------------------------------------------------------------------------
// KR-PERF-002: what the input domain keeps exact while the session is busy.
// ---------------------------------------------------------------------------------------------

/// As [`write_over`], for a connection moved into a task of its own.
async fn write_in(
    client: &mut LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    bytes: &[u8],
) -> Result<InputWriteResult, kr_protocol::error::ProtocolError> {
    client
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(sequence),
                bytes: Bytes::new(bytes.to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
}

/// KR-PERF-002, KR-REQ-08.62: a takeover in the middle of a burst of keystrokes counts exactly what
/// it discards, whether or not the session is held while the burst runs.
///
/// One attachment types a burst while the application reads nothing, and another takes the lease
/// part way through. Every byte the first was told was accepted is either in the application's
/// file or in the count the takeover reports, once. With the session held, the takeover waits for
/// it while the keystrokes go on without it, and takes the lease when the session comes free.
async fn a_takeover_in_a_burst_counts_what_it_discards(hold_the_session: bool) {
    const WRITES: usize = 4_000;
    const LENGTH: usize = 200;
    const BEFORE_THE_TAKEOVER: usize = 100;

    let mut rig = Rig::start_late().await;
    let mut other = LocalClient::connect(&rig.wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let second = attach_over(&mut other, &rig.wired, Some("xterm-256color")).await;

    let held = hold_the_session.then(|| rig.wired.runtime.hold_the_session());
    let held = match held {
        Some((reached, release)) => {
            tokio::time::timeout(LIVENESS_DEADLINE, reached)
                .await
                .expect("the session is held")
                .expect("the holder holds it");
            Some(release)
        }
        None => None,
    };

    let progress = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (session_id, attachment, epoch) = (rig.wired.session_id, rig.attachment, rig.epoch);
    // The first attachment's connection goes to the task that types the burst, and the rig keeps
    // one that nothing uses.
    let spare = LocalClient::connect(&rig.wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut first = std::mem::replace(&mut rig.client, spare);
    let bursting = {
        let progress = Arc::clone(&progress);
        tokio::spawn(async move {
            let bytes = [b'k'; LENGTH];
            let mut accepted = 0_u64;
            for sequence in 0..WRITES {
                let Ok(written) = write_in(
                    &mut first,
                    session_id,
                    attachment,
                    epoch,
                    sequence as u64,
                    &bytes,
                )
                .await
                else {
                    break;
                };
                accepted += written.forwarded_bytes.get() + written.held_prefix_bytes.get();
                progress.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            (accepted, first)
        })
    };
    let begun = async {
        while progress.load(std::sync::atomic::Ordering::Acquire) < BEFORE_THE_TAKEOVER {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let taking = acquire_over(&mut other, &rig.wired, second);
    let taken = if let Some(release) = held {
        // The takeover waits for the session. The burst has gone on without it: a watchdog lets
        // the session go after a while, and then the burst has waited for it.
        let letting_go = LetGo::after(release.clone(), Duration::from_secs(10));
        let (taken, began) = tokio::join!(taking, async {
            let began = tokio::time::timeout(Duration::from_secs(20), begun).await;
            let _ = release.send(());
            began
        });
        assert!(
            !letting_go.finish(),
            "the burst was kept waiting by the held session until it was let go"
        );
        began.expect("the burst went on while the session was held");
        taken
    } else {
        tokio::time::timeout(LIVENESS_DEADLINE, begun)
            .await
            .expect("the burst began");
        taking.await
    }
    .expect("the takeover is granted");
    let (accepted, first) = bursting.await.expect("the burst ends");
    let discarded = taken.discarded_bytes.get();

    rig.pull_the_trigger().await;
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            let delivered = rig.received().len() as u64;
            assert!(
                delivered + discarded <= accepted,
                "more bytes are accounted for ({delivered} kept and {discarded} discarded) than \
                 were accepted ({accepted})"
            );
            if delivered + discarded == accepted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{accepted} bytes were accepted and {} are in the application's file with {discarded} \
             discarded",
            rig.received().len()
        )
    });
    assert!(
        discarded > 0,
        "the case is about bytes the application had not read, and none was left"
    );

    drop((first, other));
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn a_takeover_in_a_burst_counts_exactly_what_it_discards() {
    a_takeover_in_a_burst_counts_what_it_discards(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn a_takeover_waiting_for_a_held_session_counts_exactly_what_it_discards() {
    a_takeover_in_a_burst_counts_what_it_discards(true).await;
}

/// KR-PERF-002: output that turns bracketed paste off while a prefix is held releases
/// the prefix at once, and the application receives it once.
///
/// The recogniser's timer is stopped at the prefix's deadline, so only the mode change can have let
/// it go, and it is let go on after the application has the prefix: the timer then finds nothing
/// to forward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn output_that_turns_paste_mode_off_releases_a_held_prefix_once() {
    let mut rig = Rig::start("\\033[?2004l").await;
    let (reached, go) = rig.wired.runtime.pause_the_timer_at_its_deadline();
    let (held, _) = rig.write(b"\x1b").await;
    assert_eq!(held.held_prefix_bytes.get(), 1, "the Escape is held");
    tokio::time::timeout(LIVENESS_DEADLINE, reached)
        .await
        .expect("the timer reached the deadline")
        .expect("the timer is waiting");

    rig.pull_the_trigger().await;
    assert!(
        rig.until_everything_typed_arrived().await.is_some(),
        "the mode change did not release the prefix: {:?}",
        rig.received()
    );
    go.send(()).expect("lets the timer go on");
    // Whatever the timer does now, it is ahead of this byte, and the application receives the
    // Escape once.
    rig.write(b"m").await;
    assert!(
        rig.until_everything_typed_arrived().await.is_some(),
        "the application received {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: a reply the application is owed waits for an open paste, and the
/// keystroke that closes the paste lets it out, wherever the session is meanwhile.
///
/// The application asks the terminal a question inside a paste. The answer must not land in the
/// middle of what the person is pasting; once the paste ends it is written without anything else
/// happening. With the session held, the keystroke that ends the paste is accepted without it and
/// the answer, which needs it, follows when it comes free.
async fn a_reply_waits_for_an_open_paste(hold_the_session_when_it_closes: bool) {
    let mut rig = Rig::start("\\033[ckr-asked.").await;
    let (opened, _) = rig.write(b"\x1b[200~hello").await;
    assert_eq!(
        opened.forwarded_bytes.get(),
        11,
        "the paste is opened and forwarded"
    );
    assert!(rig.until_everything_typed_arrived().await.is_some());

    rig.pull_the_trigger().await;
    retained_within(&rig.wired.runtime, b"kr-asked.", LIVENESS_DEADLINE).await;
    assert_eq!(
        rig.received(),
        rig.typed,
        "the answer was written into the middle of the paste"
    );

    let held = if hold_the_session_when_it_closes {
        let (reached, release) = rig.wired.runtime.hold_the_session();
        tokio::time::timeout(LIVENESS_DEADLINE, reached)
            .await
            .expect("the session is held")
            .expect("the holder holds it");
        Some(release)
    } else {
        None
    };
    let letting_go = held
        .as_ref()
        .map(|release| LetGo::after(release.clone(), Duration::from_secs(10)));
    rig.write(b"\x1b[201~").await;
    let typed = rig.typed.clone();
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while !rig.received().starts_with(&typed) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the end of the paste reached the application");
    if let Some(letting_go) = letting_go {
        assert!(
            !letting_go.finish(),
            "the end of the paste was kept waiting by the held session until it was let go"
        );
    }
    if let Some(release) = held {
        assert_eq!(
            rig.received(),
            typed,
            "the answer was written while the session was held, which it cannot be"
        );
        release.send(()).expect("lets the session go");
    }
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while rig.received().len() <= typed.len() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the answer was written once the paste had ended");
    let received = rig.received();
    assert!(
        received.starts_with(&typed) && received[typed.len()..].starts_with(b"\x1b[?"),
        "the answer follows the end of the paste: {received:?}"
    );
    rig.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn a_reply_waits_for_an_open_paste_and_the_end_of_the_paste_lets_it_out() {
    a_reply_waits_for_an_open_paste(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn the_end_of_a_paste_lets_a_reply_out_when_the_session_comes_free() {
    a_reply_waits_for_an_open_paste(true).await;
}

/// KR-PERF-002: the replies one drain of the response lane did not take come out behind the
/// keystrokes that follow.
///
/// The application asks the terminal for the colour of two hundred palette entries inside a paste,
/// which is more than one drain of the lane takes. The keystroke that ends the paste lets the first
/// of them out, and the ordinary keystrokes after it, which take the input domain and not the
/// session, ask for the rest. The application prints nothing after it asks, so there is no output
/// for the ingest to drain the lane behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "the application's input is read through a named pipe trigger"
)]
async fn replies_one_drain_of_the_lane_did_not_take_follow_the_keystrokes_that_come_after() {
    const ENTRIES: usize = 200;
    let mut rig = Rig::from_script(|received, trigger| {
        format!(
            "stty raw -echo; printf '\\033[?2004hkr-ready.'; \
             ( while cat '{}' >/dev/null; do i=0; \
               while [ $i -lt {ENTRIES} ]; do printf '\\033]4;%d;?\\033\\\\' $i; i=$((i+1)); done; \
               printf 'kr-asked.'; done ) & exec cat > '{}'",
            trigger.display(),
            received.display()
        )
    })
    .await;
    retained_within(&rig.wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
    rig.write(b"\x1b[200~hello").await;
    assert!(rig.until_everything_typed_arrived().await.is_some());

    rig.pull_the_trigger().await;
    retained_within(&rig.wired.runtime, b"kr-asked.", LIVENESS_DEADLINE).await;
    assert_eq!(
        count(&rig.received(), b"\x1b]4;"),
        0,
        "an answer was written into the middle of the paste"
    );

    rig.write(b"\x1b[201~").await;
    let answered = tokio::time::timeout(Duration::from_secs(20), async {
        while count(&rig.received(), b"\x1b]4;") < ENTRIES {
            rig.write(b"k").await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        answered.is_ok(),
        "the keystrokes after the paste did not let out the rest of the lane: {} of {ENTRIES} \
         answers reached the application",
        count(&rig.received(), b"\x1b]4;")
    );
    rig.close().await;
}

/// KR-PERF-002: once a close is admitted a keystroke is refused at once, and it does
/// not wait for the session to be free to hear so.
///
/// The close takes the lease and the held prefix with it and moves the lifecycle, all in the input
/// domain. A write that arrives while the session is busy with the closure's own work is refused
/// from that domain, and what the recogniser held is never forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keystroke_after_a_close_is_refused_without_waiting_for_the_session() {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let (reached, go) = rig.wired.runtime.pause_the_timer_at_its_deadline();
    let (held, _) = rig.write(b"\x1b").await;
    assert_eq!(held.held_prefix_bytes.get(), 1, "the Escape is held");
    tokio::time::timeout(LIVENESS_DEADLINE, reached)
        .await
        .expect("the timer reached the deadline")
        .expect("the timer is waiting");

    let (_, gate) = rig.wired.runtime.close(ClosureReason::CloseRequested);
    let (held_session, release) = rig.wired.runtime.hold_the_session();
    tokio::time::timeout(LIVENESS_DEADLINE, held_session)
        .await
        .expect("the session is held")
        .expect("the holder holds it");
    let letting_go = LetGo::after(release.clone(), Duration::from_millis(300));
    go.send(()).expect("lets the timer go on");
    let refused = write_over(
        &mut rig.client,
        &rig.wired,
        rig.attachment,
        rig.epoch,
        1,
        b"x",
    )
    .await
    .expect_err("a keystroke after a close is refused");
    assert!(
        !letting_go.finish(),
        "the refusal waited for the session to come free ({refused:?})"
    );
    release.send(()).expect("lets the session go");
    gate.release();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        rig.received().is_empty(),
        "what the recogniser held, or the refused byte, reached the application: {:?}",
        rig.received()
    );
    rig.close().await;
}

// ---------------------------------------------------------------------------------------------
// KR-PERF-002: a keystroke waits for no mutation and no read on its own connection.
// ---------------------------------------------------------------------------------------------

/// Where the raw requests of these cases begin numbering, apart from the identifiers a client
/// gives the calls it makes itself.
const OWN_REQUESTS: u64 = 1_000_000;

/// What a connection has been answered, by request identifier, and in which order.
#[derive(Default)]
struct Answers {
    outcomes:
        std::collections::BTreeMap<kr_protocol::ids::RequestId, kr_protocol::envelope::Outcome>,
    order: Vec<kr_protocol::ids::RequestId>,
}

impl Answers {
    /// Reads `client` until `id` has been answered, or until `within` has passed.
    async fn until(
        &mut self,
        client: &mut LocalClient,
        id: kr_protocol::ids::RequestId,
        within: Duration,
    ) -> Option<kr_protocol::envelope::Outcome> {
        let deadline = tokio::time::Instant::now() + within;
        while !self.outcomes.contains_key(&id) {
            let frame = tokio::time::timeout_at(deadline, client.recv())
                .await
                .ok()?
                .expect("the connection is read");
            if let ControlFrame::Response(response) = frame {
                self.order.push(response.request_id);
                self.outcomes.insert(response.request_id, response.outcome);
            }
        }
        self.outcomes.get(&id).cloned()
    }
}

/// Sends one `input.write` on the rig's own connection without waiting for its answer.
///
/// Returns the request and the instant before the frame was written, which is no later than its
/// arrival on the socket.
async fn send_key(rig: &mut Rig, bytes: &[u8]) -> (kr_protocol::ids::RequestId, Instant) {
    let id = kr_protocol::ids::RequestId::new(OWN_REQUESTS + rig.sequence);
    let frame = key_frame(rig, id, bytes);
    rig.sequence += 1;
    rig.typed.extend_from_slice(bytes);
    let began = Instant::now();
    rig.client
        .writer()
        .write_message(&frame)
        .await
        .expect("the key is written");
    (id, began)
}

/// The `input.write` frame for the rig's next sequence number.
fn key_frame(rig: &Rig, id: kr_protocol::ids::RequestId, bytes: &[u8]) -> ControlFrame {
    ControlFrame::Request(kr_protocol::envelope::Request {
        request_id: id,
        method: Method::InputWrite.into(),
        method_version: MethodVersion::V1,
        params: kr_protocol::envelope::ParamsValue::from_typed(&InputWriteParams {
            session_id: rig.wired.session_id,
            attachment_id: rig.attachment,
            epoch: rig.epoch,
            sequence: kr_protocol::ids::InputSequence::new(rig.sequence),
            bytes: Bytes::new(bytes.to_vec()),
        })
        .expect("encodes"),
    })
}

/// Sends one mutation on the rig's own connection without waiting for its answer.
async fn send_mutation<T: serde::Serialize>(
    rig: &mut Rig,
    method: Method,
    params: &T,
) -> kr_protocol::ids::RequestId {
    let mutation = rig
        .client
        .compose(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            rig.wired.target(),
            params,
        )
        .await
        .expect("the mutation is composed");
    let id = mutation.request_id;
    rig.client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("the mutation is written");
    id
}

/// A viewport report at the size the typist attached with, which changes nothing and is journalled
/// like any mutation.
fn viewport_report(rig: &Rig) -> kr_protocol::attachment::AttachmentViewportParams {
    kr_protocol::attachment::AttachmentViewportParams {
        attachment_id: rig.attachment,
        dimensions: Dimensions::new(80, 24),
        position: Nullable::null(),
        column: kr_protocol::scalars::U64::new(0),
    }
}

/// Stops the commit of the next dispatch marker, sends the mutation `method` on the rig's own
/// connection, and returns once the mutation is stopped in that commit.
async fn stall_own<T: serde::Serialize>(
    rig: &mut Rig,
    method: Method,
    params: &T,
) -> (Standing, kr_protocol::ids::RequestId) {
    let (reached, release) = {
        let mut session = rig.wired.runtime.session();
        let journal = session.journal_mut().expect("this session keeps a journal");
        journal.stall_next_marker()
    };
    let id = send_mutation(rig, method, params).await;
    tokio::time::timeout(LIVENESS_DEADLINE, reached)
        .await
        .unwrap_or_else(|_| panic!("{method:?}: the mutation did not reach its stall"))
        .unwrap_or_else(|_| panic!("{method:?}: the stall was dropped before it was reached"));
    (
        Standing {
            release,
            stopped: None,
        },
        id,
    )
}

/// What a lone Escape that follows work on its own connection comes to: the hold, once the
/// application has it and its answer has been read, with the work still stopped.
///
/// The watchdog lets the stall go after five seconds at the latest, as the other cases do, so a
/// regression fails naming the wait and not by hanging.
async fn an_escape_meets(
    rig: &mut Rig,
    standing: &Standing,
    answers: &mut Answers,
    what: &str,
) -> (kr_protocol::ids::RequestId, Duration) {
    let letting_go = LetGo::after(standing.release.clone(), Duration::from_secs(5));
    let (escape, began) = send_key(rig, b"\x1b").await;
    let arrived = rig.until_everything_typed_arrived().await;
    let answer = answers
        .until(&mut rig.client, escape, LIVENESS_DEADLINE)
        .await;
    let had_to_be_let_go = letting_go.finish();
    let arrived = arrived.unwrap_or_else(|| {
        panic!(
            "{what}: the application never received the Escape: {:?}",
            rig.received()
        )
    });
    let hold = arrived.duration_since(began);
    eprintln!("{what}: the Escape was received {hold:?} after the write began");
    assert!(
        !had_to_be_let_go,
        "{what}: the Escape was kept waiting until the work on its own connection was let go \
         ({hold:?})"
    );
    assert!(
        matches!(answer, Some(kr_protocol::envelope::Outcome::Ok(_))),
        "{what}: the Escape was answered {answer:?}"
    );
    (escape, hold)
}

/// KR-PERF-002: a lone Escape that follows a journalled mutation on the same connection reaches
/// the application while that mutation is stopped in its commit, with a disk writer beside.
///
/// A client sends its keys and its mutations (a resize, a viewport report) on one connection. The
/// worker used to read no frame from a connection until that connection's mutation had returned,
/// so the Escape waited for the mutation's commits and then for the recogniser's deadline. The
/// clock starts before the Escape is written, which is no later than its arrival on the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lone_escape_sent_after_a_mutation_on_its_own_connection_reaches_the_application_while_the_mutation_is_stalled()
 {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let disk = DiskWriter::beside(rig._kept.path());
    let report = viewport_report(&rig);
    let (standing, viewport) = stall_own(&mut rig, Method::AttachmentViewport, &report).await;
    let mut answers = Answers::default();
    let (escape, _) = an_escape_meets(
        &mut rig,
        &standing,
        &mut answers,
        "a stalled viewport report",
    )
    .await;
    assert!(
        !answers.outcomes.contains_key(&viewport),
        "the stalled mutation was answered before its stall was let go"
    );

    standing.release.send(()).expect("lets the stall go");
    let answer = answers
        .until(&mut rig.client, viewport, LIVENESS_DEADLINE)
        .await;
    assert!(
        matches!(answer, Some(kr_protocol::envelope::Outcome::Ok(_))),
        "the viewport report was answered {answer:?}"
    );
    assert_eq!(
        answers.order,
        vec![escape, viewport],
        "the Escape was not answered ahead of the mutation it followed"
    );
    disk.stop();
    rig.close().await;
}

/// KR-PERF-002: a lone Escape that follows a read on the same connection reaches the application
/// while that read waits for a session another connection's mutation is holding.
///
/// A read takes the session, and a mutation on another connection holds it across its commits. The
/// connection used to read nothing more until its read was answered, so the Escape behind it waited
/// as long.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lone_escape_sent_after_a_read_waiting_for_the_session_reaches_the_application_while_it_is_held()
 {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let standing = stall(&mut rig, Stalled::Marker).await;
    let read = kr_protocol::ids::RequestId::new(OWN_REQUESTS / 2);
    rig.client
        .writer()
        .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: read,
            method: Method::SessionRead.into(),
            method_version: MethodVersion::V1,
            params: kr_protocol::envelope::ParamsValue::from_typed(
                &kr_protocol::session::SessionReadParams {
                    session_id: rig.wired.session_id,
                },
            )
            .expect("encodes"),
        }))
        .await
        .expect("the read is written");
    let mut answers = Answers::default();
    let (escape, _) = an_escape_meets(
        &mut rig,
        &standing,
        &mut answers,
        "a read waiting for the session",
    )
    .await;
    assert!(
        !answers.outcomes.contains_key(&read),
        "the read was answered while the session was held"
    );

    standing.release.send(()).expect("lets the stall go");
    if let Some(stopped) = standing.stopped {
        let _ = stopped.await;
    }
    let answer = answers
        .until(&mut rig.client, read, LIVENESS_DEADLINE)
        .await;
    assert!(
        matches!(answer, Some(kr_protocol::envelope::Outcome::Ok(_))),
        "the read was answered {answer:?}"
    );
    assert_eq!(
        answers.order,
        vec![escape, read],
        "the Escape was not answered ahead of the read it followed"
    );
    rig.close().await;
}

/// KR-PERF-002: a key that follows a mutation which can change what the key meets still waits for
/// it.
///
/// A client that sends `session.detach` and then a key for the attachment has the key refused,
/// because the detach is applied first. The key is not answered while the detach is stopped in its
/// commit, and nothing reaches the application.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_sent_after_a_detach_on_its_own_connection_waits_for_it_and_is_refused() {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let detach = kr_protocol::attachment::SessionDetachParams {
        attachment_id: Nullable::some(rig.attachment),
        line_token: Nullable::null(),
    };
    let (standing, detach_id) = stall_own(&mut rig, Method::SessionDetach, &detach).await;
    let (key, _) = send_key(&mut rig, b"x").await;
    let mut answers = Answers::default();
    assert!(
        answers
            .until(&mut rig.client, key, Duration::from_millis(300))
            .await
            .is_none(),
        "the key was answered while the detach it follows was stopped in its commit"
    );

    standing.release.send(()).expect("lets the stall go");
    let detached = answers
        .until(&mut rig.client, detach_id, LIVENESS_DEADLINE)
        .await;
    assert!(
        matches!(detached, Some(kr_protocol::envelope::Outcome::Ok(_))),
        "the detach was answered {detached:?}"
    );
    let refused = answers.until(&mut rig.client, key, LIVENESS_DEADLINE).await;
    match refused {
        Some(kr_protocol::envelope::Outcome::Error(error)) => {
            assert_eq!(error.code, ErrorCode::AmbiguousAttachment);
        }
        other => panic!("the key after the detach was answered {other:?}"),
    }
    assert_eq!(answers.order, vec![detach_id, key]);
    assert!(
        rig.received().is_empty(),
        "the key reached the application: {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: every frame sent around a mutation is answered once and the keys arrive in order.
///
/// Keys and viewport reports are interleaved while a viewport report is stopped in its commit,
/// more of the reports than the worker reads ahead of a key, and more keys follow once the stall is
/// let go. Each request identifier is answered once, every key is accepted, and the application
/// has the keys in the order they were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_frames_sent_around_a_mutation_on_its_own_connection_are_each_answered_once_and_the_keys_stay_in_order()
 {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let report = viewport_report(&rig);
    let (standing, first) = stall_own(&mut rig, Method::AttachmentViewport, &report).await;
    // A watchdog: while the worker reads nothing, as it did before, the frames below fill the
    // socket and the stall has to be let go for them to be written.
    let letting_go = LetGo::after(standing.release.clone(), Duration::from_secs(5));
    let mut keys = Vec::new();
    let mut reports = vec![first];
    keys.push(send_key(&mut rig, b"a").await.0);
    for _ in 0..10 {
        reports.push(send_mutation(&mut rig, Method::AttachmentViewport, &report).await);
    }
    keys.push(send_key(&mut rig, b"b").await.0);
    for _ in 0..10 {
        reports.push(send_mutation(&mut rig, Method::AttachmentViewport, &report).await);
    }
    keys.push(send_key(&mut rig, b"c").await.0);
    // The keys sent before the reports past the read-ahead are answered while the stall holds. A
    // worker that reads nothing meanwhile answers nothing, and this gives up with the watchdog.
    let mut answers = Answers::default();
    let _ = answers
        .until(&mut rig.client, keys[1], Duration::from_secs(5))
        .await;
    let _ = letting_go.finish();
    // Whatever the stall still held is let go; a stall already let go has nothing to send to.
    let _ = standing.release.send(());

    for id in keys.iter().chain(&reports) {
        let answer = answers.until(&mut rig.client, *id, LIVENESS_DEADLINE).await;
        assert!(
            matches!(answer, Some(kr_protocol::envelope::Outcome::Ok(_))),
            "request {id:?} was answered {answer:?}"
        );
    }
    let mut seen = answers.order.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        answers.order.len(),
        "a request was answered twice: {:?}",
        answers.order
    );
    assert_eq!(answers.order.len(), keys.len() + reports.len());
    assert!(
        rig.until_everything_typed_arrived().await.is_some(),
        "the application did not receive the keys in the order they were sent: {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: a key frame cut part way when the mutation it follows ends is read whole.
///
/// The worker reads ahead of the mutation, and the mutation can end while the key is part read. The
/// rest of the key arrives afterwards and the key is answered once, accepted and delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_frame_cut_part_way_when_the_mutation_before_it_ends_is_read_whole() {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let report = viewport_report(&rig);
    let (standing, viewport) = stall_own(&mut rig, Method::AttachmentViewport, &report).await;
    let id = kr_protocol::ids::RequestId::new(OWN_REQUESTS + rig.sequence);
    let frame = key_frame(&rig, id, b"k");
    rig.sequence += 1;
    rig.typed.extend_from_slice(b"k");
    let bytes =
        kr_ipc::framed::FrameWriter::encode(kr_protocol::frame::StreamKind::Control, &frame)
            .expect("encodes");
    let cut = 4 + (bytes.len() - 4) / 2;
    rig.client
        .writer()
        .write_frame(&bytes[..cut])
        .await
        .expect("the first part is written");
    // The task reading ahead takes the first part while the mutation finishes its remaining
    // commits, and a task that has not yet taken it leaves the whole frame to the loop. The frame
    // is read whole and answered once either way, which is all this case asserts.
    standing.release.send(()).expect("lets the stall go");
    let mut answers = Answers::default();
    let answer = answers
        .until(&mut rig.client, viewport, LIVENESS_DEADLINE)
        .await;
    assert!(matches!(
        answer,
        Some(kr_protocol::envelope::Outcome::Ok(_))
    ));
    rig.client
        .writer()
        .write_frame(&bytes[cut..])
        .await
        .expect("the rest is written");
    let answer = answers.until(&mut rig.client, id, LIVENESS_DEADLINE).await;
    assert!(
        matches!(answer, Some(kr_protocol::envelope::Outcome::Ok(_))),
        "the key was answered {answer:?}"
    );
    assert_eq!(answers.order, vec![viewport, id]);
    assert!(
        rig.until_everything_typed_arrived().await.is_some(),
        "the application did not receive the key: {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: a client that goes away after a key sent behind a mutation leaves nothing behind.
///
/// The peer is gone when the worker answers the key, and when the mutation ends. Neither writes to
/// a stream that cannot take it, and the connection's attachment is given up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_goes_after_a_key_sent_behind_its_mutation_leaves_nothing_held() {
    let mut rig = Rig::start(HOST_EVENT_OUTPUT).await;
    let report = viewport_report(&rig);
    let (standing, _) = stall_own(&mut rig, Method::AttachmentViewport, &report).await;
    let _ = send_key(&mut rig, b"x").await;
    let Rig {
        client,
        wired,
        attachment,
        ..
    } = rig;
    drop(client);
    standing.release.send(()).expect("lets the stall go");
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while wired
            .runtime
            .session()
            .attachment_capabilities(attachment)
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the connection's attachment was given up");
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// A paired device's attachment on the control daemon's proxy link to the worker, holding the
/// input lease, with an application that keeps what it reads.
///
/// The daemon forwards a device's frames over a link of its own that declares itself a proxy, so
/// this is the connection a device's keys reach the worker on.
struct Proxied {
    _kept: tempfile::TempDir,
    received: std::path::PathBuf,
    wired: Wired,
    link: BoundLink,
    actor: kr_protocol::actor::ActorEnvelope,
    attachment: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    typed: Vec<u8>,
}

impl Proxied {
    async fn start() -> Self {
        let kept = tempfile::tempdir().expect("a directory for what the application keeps");
        let received = kept.path().join("received");
        let wired = wired(&format!(
            "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec tee '{}'",
            received.display()
        ))
        .await;
        retained_within(&wired.runtime, b"kr-ready.", LIVENESS_DEADLINE).await;
        let mut link = BoundLink::connect(&wired.endpoint, build())
            .await
            .expect("connects");
        let role = kr_protocol::local::ControllerConnectionRole::Proxy;
        link.send(&ControlFrame::ControllerRole(role))
            .await
            .expect("declares the role");
        match link.recv().await.expect("the worker answers") {
            ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
            other => panic!("the worker answered {other:?}"),
        }
        let identity = Arc::clone(&wired.controller);
        let boot = wired.boot.clone();
        link.present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
        let actor = kr_protocol::actor::ActorEnvelope {
            actor_id: kr_protocol::ids::ActorId::new("device:phone").expect("an actor"),
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid())),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(1),
            connection_id: connection(),
        };
        let mut proxied = Self {
            _kept: kept,
            received,
            wired,
            link,
            actor,
            attachment: AttachmentId::new(kr_ipc::new_uuid()),
            epoch: kr_protocol::ids::InputLeaseEpoch::new(0),
            sequence: 0,
            typed: Vec::new(),
        };
        let attached: kr_protocol::attachment::SessionAttachResult = proxied
            .forward(
                Method::SessionAttach,
                &terminal(proxied.wired.session_id, Some("xterm-256color")),
            )
            .await
            .expect("the device attaches")
            .to_typed()
            .expect("an attachment");
        proxied.attachment = attached.attachment.attachment_id;
        let lease: kr_protocol::input::InputAcquireResult = proxied
            .forward(
                Method::InputAcquire,
                &InputAcquireParams {
                    session_id: proxied.wired.session_id,
                    attachment_id: proxied.attachment,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the device takes the lease")
            .to_typed()
            .expect("a lease");
        proxied.epoch = lease.lease.epoch;
        proxied
    }

    /// The mutation `method`, as the daemon forwards it for the device, and its answer.
    async fn forward<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError> {
        let mutation = self.mutation(method, params).await;
        self.link
            .forward(
                &mutation,
                &self.actor,
                &self.rights(),
                Self::deadline(),
                None,
            )
            .await
            .expect("reaches the worker")
    }

    async fn mutation<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
    ) -> kr_protocol::envelope::MutationRequest {
        self.link
            .compose(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                self.wired.target(),
                params,
            )
            .await
            .expect("the mutation is composed")
    }

    fn rights(&self) -> CanonicalSet<kr_protocol::rights::ActionRight> {
        [
            kr_protocol::rights::ActionRight::SessionView,
            kr_protocol::rights::ActionRight::TerminalInput,
        ]
        .into_iter()
        .collect()
    }

    fn deadline() -> kr_protocol::scalars::U64 {
        kr_protocol::scalars::U64::new(kr_ipc::clock::boot_elapsed_ms() + 120_000)
    }

    /// Sends a forwarded mutation without waiting for its answer.
    async fn send_forwarded<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
    ) -> kr_protocol::ids::RequestId {
        let mutation = self.mutation(method, params).await;
        let id = mutation.request_id;
        self.link
            .send(&ControlFrame::Forwarded(Box::new(
                kr_protocol::local::ForwardedMutation {
                    mutation,
                    actor: self.actor.clone(),
                    grant_rights: self.rights(),
                    accepted_deadline_boot_ms: Self::deadline(),
                    history: None,
                    screen_basis: None,
                    workflow_run_id: None,
                    lease: None,
                },
            )))
            .await
            .expect("the mutation is written");
        id
    }

    /// Sends a forwarded `input.write` without waiting for its answer.
    async fn send_key(&mut self, bytes: &[u8]) -> (kr_protocol::ids::RequestId, Instant) {
        let id = kr_protocol::ids::RequestId::new(OWN_REQUESTS + self.sequence);
        let params = InputWriteParams {
            session_id: self.wired.session_id,
            attachment_id: self.attachment,
            epoch: self.epoch,
            sequence: kr_protocol::ids::InputSequence::new(self.sequence),
            bytes: Bytes::new(bytes.to_vec()),
        };
        self.sequence += 1;
        self.typed.extend_from_slice(bytes);
        let began = Instant::now();
        self.link
            .send(&ControlFrame::ForwardedRead(Box::new(
                kr_protocol::local::ForwardedRequest {
                    request: kr_protocol::envelope::Request {
                        request_id: id,
                        method: Method::InputWrite.into(),
                        method_version: MethodVersion::V1,
                        params: kr_protocol::envelope::ParamsValue::from_typed(&params)
                            .expect("encodes"),
                    },
                    actor: self.actor.clone(),
                    authority_deadline_boot_ms: Nullable::null(),
                    history: None,
                },
            )))
            .await
            .expect("the key is written");
        (id, began)
    }

    fn received(&self) -> Vec<u8> {
        std::fs::read(&self.received).unwrap_or_default()
    }
}

/// KR-PERF-002: a key the control daemon forwards for a paired device reaches the application while
/// the device's own mutation, forwarded on the same link before it, is stopped in its commit.
///
/// The daemon forwards a device's frames on one link of its own, which is a controller connection.
/// The worker used to read nothing more from such a connection until the mutation ahead had
/// returned, so a key the daemon forwarded behind it waited for the mutation's commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_key_sent_after_a_forwarded_mutation_reaches_the_application_while_the_mutation_is_stalled()
 {
    let mut proxied = Proxied::start().await;
    let (reached, release) = {
        let mut session = proxied.wired.runtime.session();
        let journal = session.journal_mut().expect("this session keeps a journal");
        journal.stall_next_marker()
    };
    let report = kr_protocol::attachment::AttachmentViewportParams {
        attachment_id: proxied.attachment,
        dimensions: Dimensions::new(80, 24),
        position: Nullable::null(),
        column: kr_protocol::scalars::U64::new(0),
    };
    let viewport = proxied
        .send_forwarded(Method::AttachmentViewport, &report)
        .await;
    tokio::time::timeout(LIVENESS_DEADLINE, reached)
        .await
        .expect("the mutation reached its stall")
        .expect("the stall was not dropped");

    let letting_go = LetGo::after(release.clone(), Duration::from_secs(5));
    let (escape, began) = proxied.send_key(b"\x1b").await;
    let arrived = tokio::time::timeout(LIVENESS_DEADLINE, async {
        loop {
            if proxied.received() == proxied.typed {
                return Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    let had_to_be_let_go = letting_go.finish();
    eprintln!(
        "a forwarded Escape behind a stalled forwarded viewport report: received {:?} after the write began",
        arrived.as_ref().map(|at| at.duration_since(began))
    );
    assert!(
        !had_to_be_let_go,
        "the forwarded Escape was kept waiting until the mutation before it was let go"
    );
    assert!(arrived.is_ok(), "the application never received the Escape");

    // The key is answered ahead of the mutation, which is still stopped.
    let first = loop {
        match tokio::time::timeout(LIVENESS_DEADLINE, proxied.link.recv()).await {
            Ok(Ok(ControlFrame::Response(response))) => break response,
            Ok(Ok(_)) => {}
            other => panic!("the link ended before the key was answered: {other:?}"),
        }
    };
    assert_eq!(first.request_id, escape, "the key was answered first");
    assert!(matches!(
        first.outcome,
        kr_protocol::envelope::Outcome::Ok(_)
    ));

    release.send(()).expect("lets the stall go");
    let second = loop {
        match tokio::time::timeout(LIVENESS_DEADLINE, proxied.link.recv()).await {
            Ok(Ok(ControlFrame::Response(response))) => break response,
            Ok(Ok(_)) => {}
            other => panic!("the link ended before the mutation was answered: {other:?}"),
        }
    };
    assert_eq!(second.request_id, viewport);
    assert!(matches!(
        second.outcome,
        kr_protocol::envelope::Outcome::Ok(_)
    ));
    proxied
        .wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}
