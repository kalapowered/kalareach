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

use kr_ipc::client::LocalClient;
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
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
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

/// Waits for `marker` in the runtime's retained output, or gives up after `within`.
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
/// sense of, and the failure says how long it waited and what for.
async fn retained_within(runtime: &SessionRuntime, marker: &[u8], within: Duration) -> Vec<u8> {
    let started = tokio::time::Instant::now();
    let deadline = started + within;
    loop {
        let seen = retained(&runtime.session());
        if contains(&seen, marker) {
            return seen;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {:?} for {:?} in the session's retained output: {:?}",
            started.elapsed(),
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(&seen)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    let mut daemon = LocalClient::connect(&wired.endpoint, LocalClientKind::Controller, build())
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

/// KR-REQ-08.64: a plain Escape is not held when the mode is off and no paste is open.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_escape_reaches_the_application_with_no_paste_prefix_hold() {
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
    _service: Arc<WorkerService>,
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
        _service: service,
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
    client: &mut LocalClient,
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
    client: &mut LocalClient,
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
    client: &mut LocalClient,
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
        runtime.flush_locked(&mut session);
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
        runtime.flush_locked(&mut session);
    }
    // A batch behind it under authority that has not run out. The writer is serial, so once this
    // one has arrived the one in front of it has either arrived or was never written.
    {
        let mut session = runtime.session();
        let later = kr_ipc::clock::SharedClock::boot_elapsed_ms(&clock) + 60_000;
        session
            .write_input(id, epoch, 2, b"kr-after", Some(later), Instant::now())
            .expect("accepted");
        runtime.flush_locked(&mut session);
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
            .queued_input_bytes()
            .load(std::sync::atomic::Ordering::Acquire),
        0,
        "the budget the dropped batch held is given back"
    );
    assert_eq!(
        session.queued_lease_bytes().load(),
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
        runtime.flush_locked(&mut session);
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
        runtime.flush_locked(&mut session);
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
