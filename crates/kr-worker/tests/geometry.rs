//! Who owns the session's rows and columns, and what happens when they leave.
//!
//! Every test names the requirement row it closes. Size ownership is deliberately not the same
//! thing as observing a session or holding its input, and most of what is proved here is that
//! opening a window, reporting a size or taking the keys moves nothing: a phone opening a view
//! cannot shrink a desktop TUI, and only a deliberate transfer moves the size at all.
//!
//! The tests that have to establish that the *pseudo-terminal* moved run a root program that
//! reports its own size when the kernel tells it the window changed. Nothing else can tell a
//! bookkeeping change apart from a real resize.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::ActorIngress;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentConfigureParams, AttachmentViewportParams,
    AttachmentViewportResult, GeometryResult, SessionAttachParams, SessionDetachParams,
    TerminalGeometryTransferParams, TerminalPresentationMode, TerminalResizeParams,
};
use kr_protocol::authority::{AuthorityDecision, CapabilityRequirement};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{
    ClosureReason, Dimensions, DisplayNumber, INVISIBLE_DEFAULT_DIMENSIONS, MAX_CELLS, MAX_COLUMNS,
    MAX_ROWS, ShellMode,
};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The session's own size in these tests. An attachment of exactly this size takes the stream.
const CANONICAL: Dimensions = Dimensions::new(80, 24);

/// A root program that reports its own size whenever the kernel says the window changed.
///
/// Nothing else distinguishes a bookkeeping change from a resize the application actually saw.
const REPORTS_ITS_SIZE: &str = "stty raw -echo; \
     trap 'printf kr-size:; stty size' WINCH; \
     printf 'kr-ready.'; while :; do sleep 0.2; done";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn configuration(
    host: &kr_ipc::testing::TempHost,
    script: &str,
    dimensions: Dimensions,
) -> SessionConfig {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![
                ("TERM".to_owned(), "xterm-256color".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("PS1".to_owned(), String::new()),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions,
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    }
}

/// A terminal attachment of `dimensions` that may or may not register a geometry claim.
fn terminal(session_id: SessionId, dimensions: Dimensions, claim: bool) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Geometry);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: claim,
        dimensions: Nullable::some(dimensions),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// The conversation view of a desktop application: structured state, and no claim on the size.
fn conversation_view(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveSemantic);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Semantic,
        claim_geometry: false,
        dimensions: Nullable::null(),
        terminal_profile_id: Nullable::null(),
        requested,
    }
}

fn attach(session: &mut Session, params: &SessionAttachParams) -> AttachmentId {
    let id = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(params, params.requested.clone(), id)
        .expect("attaches");
    id
}

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

async fn retained_within(runtime: &SessionRuntime, marker: &[u8], within: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let seen = retained(&runtime.session());
        if contains(&seen, marker) {
            return seen;
        }
        if tokio::time::Instant::now() >= deadline {
            return seen;
        }
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

// ---------------------------------------------------------------------------------------------
// KR-REQ-01.13, KR-REQ-08.67, KR-REQ-08.68: the first eligible claim owns, and a view never does.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-01.13, KR-REQ-08.67, KR-REQ-08.68.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_eligible_claim_owns_the_size_and_a_conversation_view_never_claims() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120", CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    // The conversation view arrives first and claims nothing, so the session keeps the size it
    // was created at.
    let view = attach(&mut session, &conversation_view(session_id));
    assert!(!session.geometry().owner.is_present());
    assert_eq!(session.geometry().dimensions, CANONICAL);
    // And it cannot register one, however it asks.
    let refused = session
        .configure(view, true)
        .expect_err("a semantic attachment cannot claim geometry");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::InvalidArgument);
    // Nor at attach time.
    let mut claiming_view = conversation_view(session_id);
    claiming_view.claim_geometry = true;
    let refused = session
        .attach(
            &claiming_view,
            claiming_view.requested.clone(),
            AttachmentId::new(kr_ipc::new_uuid()),
        )
        .expect_err("semantic mode requires claim_geometry false");
    assert_eq!(refused.to_protocol_error().code, ErrorCode::InvalidArgument);

    // A terminal that claims takes it.
    let first = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(100, 30), true),
    );
    assert_eq!(session.geometry().owner.as_ref(), Some(&first));
    assert_eq!(session.geometry().dimensions, Dimensions::new(100, 30));

    // A second terminal opening does not. Being newer is not a reason to resize the one running.
    let second = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(60, 20), true),
    );
    assert_eq!(session.geometry().owner.as_ref(), Some(&first));
    assert_eq!(session.geometry().dimensions, Dimensions::new(100, 30));

    // A claim without the geometry right is not eligible, whatever the request said.
    let mut observe_only = terminal(session_id, Dimensions::new(40, 10), true);
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    observe_only.requested = requested.clone();
    let restricted = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(&observe_only, requested, restricted)
        .expect("attaches, and watches");
    assert_eq!(session.geometry().owner.as_ref(), Some(&first));
    // Even once the owner has gone, an ineligible claim does not inherit.
    session.detach(first).expect("detaches");
    assert_eq!(
        session.geometry().owner.as_ref(),
        Some(&second),
        "the oldest remaining eligible claim succeeds, not the newest attachment"
    );

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.69: a claim is added or withdrawn without displacing the owner.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.69, KR-REQ-08.73.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_is_added_or_withdrawn_without_displacing_the_owner() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120", CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let owner = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(100, 30), true),
    );
    // A passive preview: open, watching, claiming nothing.
    let preview = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(60, 20), false),
    );
    let before = session.geometry();

    // Entering the preview's explicit terminal-control mode registers a claim. It does not move
    // the size.
    let added = session.configure(preview, true).expect("registers a claim");
    assert_eq!(added.owner.as_ref(), Some(&owner));
    assert_eq!(added.dimensions, before.dimensions);

    // Withdrawing the owner's claim runs the same succession a detach does.
    let withdrawn = session.configure(owner, false).expect("withdraws");
    assert_eq!(withdrawn.owner.as_ref(), Some(&preview));
    assert_eq!(withdrawn.dimensions, Dimensions::new(60, 20));
    assert!(
        withdrawn.epoch.get() > before.epoch.get(),
        "every ownership change advances the epoch"
    );

    // The attachment that withdrew is still attached and still watching, and it cannot resize.
    let refused = session
        .resize(owner, Dimensions::new(10, 10), withdrawn.epoch.get())
        .expect_err("it gave up the claim it owned by");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::GeometryNotOwner
    );

    // With every claim withdrawn the last geometry is retained, and the next claim takes it.
    let unowned = session.configure(preview, false).expect("withdraws");
    assert!(!unowned.owner.is_present());
    assert_eq!(unowned.dimensions, Dimensions::new(60, 20));
    let regained = session.configure(owner, true).expect("registers again");
    assert_eq!(regained.owner.as_ref(), Some(&owner));
    assert_eq!(
        regained.dimensions,
        Dimensions::new(100, 30),
        "and supplies its own dimensions"
    );

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.70: every terminal attachment reports a viewport; only the owner's resize moves it.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.70: the pseudo-terminal moves for the owner and for nobody else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_owners_resize_moves_the_pseudo_terminal() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, REPORTS_ITS_SIZE, CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let owner = attach(&mut session, &terminal(session_id, CANONICAL, true));
    let watcher = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(60, 20), false),
    );
    let epoch = session.geometry().epoch.get();
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    retained_within(&runtime, b"kr-ready.", Duration::from_secs(10)).await;

    // The watcher reports the size it is looking at. It is a report, not an insistence.
    {
        let mut session = runtime.session();
        let presentation = session
            .viewport(watcher, Dimensions::new(52, 14))
            .expect("every terminal attachment reports its own size");
        assert_eq!(presentation, TerminalPresentationMode::Viewport);
        assert_eq!(
            session.geometry().dimensions,
            CANONICAL,
            "and the canonical geometry did not move"
        );
        assert_eq!(session.geometry().epoch.get(), epoch);
        // Nor may it resize.
        let refused = session
            .resize(watcher, Dimensions::new(52, 14), epoch)
            .expect_err("it holds no claim");
        assert_eq!(
            refused.to_protocol_error().code,
            ErrorCode::GeometryNotOwner
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let session = runtime.session();
        assert!(
            !contains(&retained(&session), b"kr-size:"),
            "the application was never told about a size nobody owned"
        );
    }

    // The owner resizes, and the application is told.
    {
        let mut session = runtime.session();
        let changed = session
            .resize(owner, Dimensions::new(100, 30), epoch)
            .expect("the owner moves the size");
        assert_eq!(changed.dimensions, Dimensions::new(100, 30));
        assert_eq!(changed.epoch.get(), epoch + 1);
    }
    let seen = retained_within(&runtime, b"kr-size:30 100", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-size:30 100"),
        "the kernel moved with the bookkeeping: {}",
        String::from_utf8_lossy(&seen)
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.71, KR-REQ-08.72: the dimension limits, the default and the page bounds.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.71: all three constraints apply at once, with checked multiplication.
#[tokio::test(flavor = "multi_thread")]
async fn all_three_dimension_limits_apply_at_once_and_a_refusal_changes_nothing() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120", CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let owner = attach(&mut session, &terminal(session_id, CANONICAL, true));
    let epoch = session.geometry().epoch.get();

    // Each independent maximum is valid on its own.
    for valid in [
        Dimensions::new(MAX_COLUMNS, 1),
        Dimensions::new(1, MAX_ROWS),
        Dimensions::new(512, 512),
    ] {
        valid.validate().expect("within every bound");
    }
    // And the pair of them is not: the independent maxima need not be valid together.
    for refused in [
        Dimensions::new(MAX_COLUMNS + 1, 1),
        Dimensions::new(1, MAX_ROWS + 1),
        Dimensions::new(0, 24),
        Dimensions::new(80, 0),
        Dimensions::new(MAX_COLUMNS, MAX_ROWS),
        // The product overflows a 64-bit multiplication, which is why it is checked rather than
        // computed and compared.
        Dimensions::new(u64::MAX, u64::MAX),
    ] {
        let error = session
            .resize(owner, refused, epoch)
            .expect_err("a violated constraint is refused");
        let reported = error.to_protocol_error();
        assert_eq!(reported.code, ErrorCode::InvalidArgument, "{refused:?}");
        assert!(
            reported.message.contains("2048")
                || reported.message.contains("1024")
                || reported.message.contains("262144"),
            "the refusal names the violated limit: {}",
            reported.message
        );
        assert_eq!(
            session.geometry().dimensions,
            CANONICAL,
            "and nothing about the current grid moved"
        );
        assert_eq!(session.geometry().epoch.get(), epoch);
    }
    assert_eq!(MAX_COLUMNS.checked_mul(MAX_ROWS), Some(2_097_152));
    const { assert!(MAX_COLUMNS * MAX_ROWS > MAX_CELLS) };

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// KR-REQ-08.72: the invisible default, the page bounds and the semantic-snapshot bounds.
#[tokio::test(flavor = "multi_thread")]
async fn the_invisible_default_and_every_page_bound_are_what_section_eight_states() {
    assert_eq!(INVISIBLE_DEFAULT_DIMENSIONS, Dimensions::new(120, 40));
    // The engine's own page bound, which is the row count a history page may carry.
    assert_eq!(
        kr_term::budget::BudgetLimits::DEFAULT.history_page_rows,
        1_000
    );
    assert_eq!(
        kr_protocol::recovery::MAX_HISTORY_PAGE_BYTES,
        1024 * 1024,
        "and a page's encoded size"
    );
    assert_eq!(
        kr_protocol::semantic::MAX_SEMANTIC_SNAPSHOT_BYTES,
        16 * 1024 * 1024
    );
    assert_eq!(kr_protocol::semantic::MAX_SEMANTIC_TREE_DEPTH, 16);
    assert_eq!(kr_protocol::semantic::MAX_SEMANTIC_TREE_NODES, 20_000);

    let host = kr_ipc::testing::TempHost::create();
    // A session created with no size starts at the invisible default.
    let config = configuration(&host, "sleep 120", INVISIBLE_DEFAULT_DIMENSIONS);
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    assert_eq!(session.geometry().dimensions, INVISIBLE_DEFAULT_DIMENSIONS);

    // A page never exceeds its bound, however much is asked for.
    let page = session
        .history_page(0, u64::MAX)
        .expect("reads what is retained");
    assert!(
        page.bytes.as_slice().len() as u64 <= kr_protocol::recovery::MAX_HISTORY_PAGE_BYTES,
        "a page is bounded even when more is asked for"
    );

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.73: succession on departure, withdrawal and loss of authority.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.73: the oldest remaining eligible claim succeeds and supplies its own dimensions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_oldest_remaining_claim_succeeds_and_the_application_is_resized_to_it() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, REPORTS_ITS_SIZE, CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = attach(&mut session, &terminal(session_id, CANONICAL, true));
    let middle = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(100, 30), true),
    );
    let last = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(60, 20), true),
    );
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    retained_within(&runtime, b"kr-ready.", Duration::from_secs(10)).await;

    {
        let mut session = runtime.session();
        let succeeded = session.detach(first).expect("detaches").geometry;
        assert_eq!(
            succeeded.owner.as_ref(),
            Some(&middle),
            "join order decides, not who is newest or nearest"
        );
        assert_eq!(succeeded.dimensions, Dimensions::new(100, 30));
    }
    let seen = retained_within(&runtime, b"kr-size:30 100", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-size:30 100"),
        "and the application was resized to the successor's size: {}",
        String::from_utf8_lossy(&seen)
    );

    // With every eligible claim gone the last geometry is retained rather than reset.
    {
        let mut session = runtime.session();
        session.detach(middle).expect("detaches");
        let retained_geometry = session.detach(last).expect("detaches").geometry;
        assert!(!retained_geometry.owner.is_present());
        assert_eq!(
            retained_geometry.dimensions,
            Dimensions::new(60, 20),
            "a session nobody is watching keeps the size its shell is running at"
        );
    }

    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.74: the explicit transfer, with the expected epoch and one notification for everybody.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.74, KR-REQ-23.35: the transfer quotes the epoch it expects and tells everyone at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_quotes_the_expected_epoch_and_notifies_every_attachment_at_once() {
    let wired = wired(REPORTS_ITS_SIZE, CANONICAL).await;
    let mut desk = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut phone = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let desk_attachment = attach_over(&mut desk, &wired, CANONICAL, true).await;
    let phone_attachment = attach_over(&mut phone, &wired, Dimensions::new(48, 16), true).await;
    subscribe_over(&mut desk, &wired, desk_attachment).await;
    subscribe_over(&mut phone, &wired, phone_attachment).await;
    retained_within(&wired.runtime, b"kr-ready.", Duration::from_secs(10)).await;

    let epoch = wired.runtime.session().geometry().epoch;
    // A stale epoch is refused. The size is not moved by a caller working from a view that has
    // already changed.
    let refused: kr_protocol::error::ProtocolError = phone
        .mutate(
            Method::TerminalGeometryTransfer,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &TerminalGeometryTransferParams {
                attachment_id: phone_attachment,
                expected_geometry_epoch: kr_protocol::ids::GeometryEpoch::new(epoch.get() + 5),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("a stale epoch");
    assert_eq!(refused.code, ErrorCode::GeometryNotOwner);
    assert_eq!(
        wired.runtime.session().geometry().owner.as_ref(),
        Some(&desk_attachment),
        "and the owner is untouched"
    );

    // The deliberate "use this terminal's size" action.
    let transferred: GeometryResult = phone
        .mutate(
            Method::TerminalGeometryTransfer,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &TerminalGeometryTransferParams {
                attachment_id: phone_attachment,
                expected_geometry_epoch: epoch,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("transfers")
        .to_typed()
        .expect("decodes");
    assert_eq!(transferred.geometry.owner.as_ref(), Some(&phone_attachment));
    assert_eq!(transferred.geometry.dimensions, Dimensions::new(48, 16));
    assert_eq!(transferred.geometry.epoch.get(), epoch.get() + 1);

    // Both attachments learn, and they learn the same thing: the size changed under all of them,
    // so each is told its view is no longer continuous.
    assert!(
        resynchronised(&mut desk, Duration::from_secs(10)).await,
        "the desk's view of a session at another size is not continuous with what it had"
    );
    assert!(
        resynchronised(&mut phone, Duration::from_secs(10)).await,
        "and neither is the phone's"
    );
    let seen = retained_within(&wired.runtime, b"kr-size:16 48", Duration::from_secs(10)).await;
    assert!(
        contains(&seen, b"kr-size:16 48"),
        "and the shell was resized rather than replaced: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !wired.runtime.session().lease().holder.is_present(),
        "moving the size is not taking the keys"
    );

    drop(desk);
    drop(phone);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-08.74: taking the keys does not also take the size.
#[tokio::test(flavor = "multi_thread")]
async fn a_keyboard_takeover_leaves_the_size_exactly_where_it_was() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120", CANONICAL);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let mut typing = terminal(session_id, Dimensions::new(48, 16), true);
    typing.requested.insert(AttachmentCapability::Input);
    let owner = attach(&mut session, &terminal(session_id, CANONICAL, true));
    let other = attach(&mut session, &typing);
    let before = session.geometry();

    session
        .acquire_input(
            other,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
            None,
        )
        .expect("takes the keys");
    let after = session.geometry();
    assert_eq!(after.owner.as_ref(), Some(&owner), "the size did not move");
    assert_eq!(after.dimensions, before.dimensions);
    assert_eq!(
        after.epoch.get(),
        before.epoch.get(),
        "and its epoch did not move either"
    );

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-08.75: equal-size direct sharing, and a clipped viewport for any other size.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.75: a terminal of the session's size shares the stream; another size is clipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_equal_sized_terminal_shares_the_stream_and_a_smaller_one_is_clipped_not_reflowed() {
    // A line wider than the narrow terminal, written once. What each attachment is shown of it is
    // the whole question: the same bytes, or a rendering of the grid clipped to its own window.
    let wide = "wrapme-".repeat(9);
    let wired = wired(
        &format!("stty raw -echo; printf '{wide}'; printf 'kr-ready.'; sleep 120"),
        CANONICAL,
    )
    .await;
    let mut same = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut narrow = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let same_attachment = attach_over(&mut same, &wired, CANONICAL, false).await;
    let narrow_attachment = attach_over(&mut narrow, &wired, Dimensions::new(40, 24), false).await;
    assert_eq!(
        presentation_of(&wired, same_attachment),
        Some(TerminalPresentationMode::Direct),
        "the same size, a qualified profile and a carryable stream together"
    );
    assert_eq!(
        presentation_of(&wired, narrow_attachment),
        Some(TerminalPresentationMode::Viewport),
        "and any other size is a clipped viewport of the canonical grid"
    );

    subscribe_over(&mut same, &wired, same_attachment).await;
    subscribe_over(&mut narrow, &wired, narrow_attachment).await;
    let direct = collect(&mut same, Duration::from_secs(3)).await;
    let clipped = collect(&mut narrow, Duration::from_secs(3)).await;

    // The narrow terminal is shown the left of each canonical row. Nothing is rewrapped for it, so
    // the part of the row beyond its window is simply not there.
    assert!(
        contains(&clipped, b"wrapme-wrapme-"),
        "the left of the row is drawn: {}",
        String::from_utf8_lossy(&clipped)
    );
    // The row is nine repetitions wide on a grid eighty columns across, so it occupies one
    // canonical row and nothing wrapped. A forty-column window shows the left forty columns of it,
    // which holds five whole repetitions and part of a sixth. What the row does *not* do is appear
    // again on a following row: clipping drops what is outside the window, and reflowing would have
    // moved it.
    assert!(
        count(&clipped, b"wrapme-") <= 5,
        "the window shows the left of the row and no more: {} repetitions",
        count(&clipped, b"wrapme-")
    );
    assert_eq!(
        count(&direct, b"wrapme-"),
        9,
        "while the equal-sized terminal receives the session's own bytes, all of them"
    );

    drop(same);
    drop(narrow);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.35: the attachment method group, its rights and its owner epoch.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-23.35: each attachment method needs exactly the right section 23 names for it.
#[test]
fn every_attachment_method_requires_the_right_its_row_names() {
    let entry = |method: Method| {
        let AuthorityDecision::Listed(entry) =
            kr_protocol::method::decide(method.as_str(), MethodVersion::V1, ActorIngress::LocalIpc)
        else {
            panic!("{} is listed", method.as_str());
        };
        entry
    };
    let rights = |method: Method| entry(method).unconditional_rights().collect::<Vec<_>>();

    // A view is enough to observe, to detach one's own attachment and to report a viewport.
    for method in [
        Method::SessionAttach,
        Method::SessionDetach,
        Method::AttachmentViewport,
    ] {
        assert!(
            rights(method).contains(&ActionRight::SessionView),
            "{} needs a view",
            method.as_str()
        );
    }
    // A geometry claim needs the geometry right as well, and only when it is a claim.
    let attach = entry(Method::SessionAttach);
    assert!(
        !attach
            .unconditional_rights()
            .any(|right| right == ActionRight::TerminalGeometry),
        "observing does not need the geometry right"
    );
    assert!(
        attach.required_rights.iter().any(|required| matches!(
            required.authority,
            kr_protocol::authority::RequiredAuthority::Right {
                right: ActionRight::TerminalGeometry
            }
        )),
        "and claiming does"
    );
    assert!(rights(Method::TerminalResize).contains(&ActionRight::TerminalGeometry));
    assert!(
        rights(Method::TerminalGeometryTransfer).contains(&ActionRight::TerminalGeometryTransfer),
        "the transfer has its own right, so ordinary geometry authority cannot steal a size"
    );
    assert!(rights(Method::TerminalPaletteSet).contains(&ActionRight::TerminalPalette));

    // The owner epoch is a capability of the methods that move the size, and of no other.
    for method in [Method::TerminalResize, Method::TerminalGeometryTransfer] {
        let CapabilityRequirement::Required {
            capability_id,
            revision,
        } = entry(method).capability
        else {
            panic!("{} carries the geometry epoch", method.as_str());
        };
        assert_eq!(capability_id, "terminal.geometry");
        assert_eq!(
            revision,
            kr_protocol::authority::RevisionBinding::GeometryEpoch
        );
    }
    assert_eq!(
        entry(Method::AttachmentViewport).capability,
        CapabilityRequirement::None,
        "a report is not a change, so it quotes no epoch"
    );
}

/// KR-REQ-23.35: the attachment methods over the wire, including the owner epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_attachment_methods_answer_with_the_geometry_and_the_epoch_they_produced() {
    let wired = wired("sleep 120", CANONICAL).await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let owner = attach_over(&mut client, &wired, CANONICAL, true).await;
    let epoch = wired.runtime.session().geometry().epoch;

    // A viewport report answers with the canonical geometry it did not change, and with the
    // presentation it produced.
    let reported: AttachmentViewportResult = client
        .mutate(
            Method::AttachmentViewport,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &AttachmentViewportParams {
                attachment_id: owner,
                dimensions: Dimensions::new(52, 14),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("reports")
        .to_typed()
        .expect("decodes");
    assert_eq!(reported.geometry.dimensions, CANONICAL);
    assert_eq!(reported.geometry.epoch, epoch);
    assert_eq!(reported.presentation, TerminalPresentationMode::Viewport);

    // A resize at a stale epoch is refused; at the current one it moves the size and the epoch.
    let stale = client
        .mutate(
            Method::TerminalResize,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &TerminalResizeParams {
                attachment_id: owner,
                dimensions: Dimensions::new(100, 30),
                expected_geometry_epoch: kr_protocol::ids::GeometryEpoch::new(epoch.get() + 3),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("a stale epoch");
    assert_eq!(stale.code, ErrorCode::GeometryNotOwner);
    let resized: GeometryResult = client
        .mutate(
            Method::TerminalResize,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &TerminalResizeParams {
                attachment_id: owner,
                dimensions: Dimensions::new(100, 30),
                expected_geometry_epoch: epoch,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("resizes")
        .to_typed()
        .expect("decodes");
    assert_eq!(resized.geometry.dimensions, Dimensions::new(100, 30));
    assert_eq!(resized.geometry.epoch.get(), epoch.get() + 1);

    // Withdrawing the claim over the wire runs succession and answers with the result.
    let withdrawn: GeometryResult = client
        .mutate(
            Method::AttachmentConfigure,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &AttachmentConfigureParams {
                attachment_id: owner,
                claim_geometry: false,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("withdraws")
        .to_typed()
        .expect("decodes");
    assert!(!withdrawn.geometry.owner.is_present());
    assert_eq!(
        withdrawn.geometry.dimensions,
        Dimensions::new(100, 30),
        "with no eligible claim the last geometry is retained"
    );

    // And a detach answers with the geometry after succession and how many remain.
    let detached: kr_protocol::attachment::SessionDetachResult = client
        .mutate(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &SessionDetachParams {
                attachment_id: owner,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("detaches")
        .to_typed()
        .expect("decodes");
    assert_eq!(detached.remaining.get(), 0, "a live session may have none");
    assert_eq!(detached.geometry.dimensions, Dimensions::new(100, 30));

    drop(client);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

// ---------------------------------------------------------------------------------------------
// Geometry admission against the session's own budget.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-08.71: a geometry the session's budget cannot admit is refused through `session.attach`.
///
/// The bound the grid is refused by is the session's resident budget rather than the dimension
/// limits, so the refusal is a resource rather than an argument, and the claim that would have
/// produced it does not take the size on the way past.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_the_session_budget_cannot_admit_is_refused_at_attach_and_owns_nothing() {
    let host = kr_ipc::testing::TempHost::create();
    // A budget that admits the starting grid and nothing much larger.
    let mut config = configuration(&host, "sleep 120", Dimensions::new(80, 24));
    config.resident_bytes = 512 * 1024;
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let large = terminal(session_id, Dimensions::new(2_000, 130), true);
    let refused = session
        .attach(
            &large,
            large.requested.clone(),
            AttachmentId::new(kr_ipc::new_uuid()),
        )
        .expect_err("the two screen buffers of that grid do not fit this session's budget");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::ResourceUnavailable
    );
    assert!(
        !session.geometry().owner.is_present(),
        "and a refused attach owns nothing"
    );
    assert_eq!(session.geometry().dimensions, Dimensions::new(80, 24));

    // The same bound reaches a resize the same way.
    let owner = attach(
        &mut session,
        &terminal(session_id, Dimensions::new(80, 24), true),
    );
    let epoch = session.geometry().epoch.get();
    let refused = session
        .resize(owner, Dimensions::new(2_000, 130), epoch)
        .expect_err("the budget refuses it here too");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::ResourceUnavailable
    );
    assert_eq!(session.geometry().dimensions, Dimensions::new(80, 24));
    assert_eq!(
        session.geometry().epoch.get(),
        epoch,
        "a change that never happened did not advance an epoch"
    );

    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
    runtime.close(ClosureReason::CloseRequested).1.release();
}

// ---------------------------------------------------------------------------------------------
// The wire harness.
// ---------------------------------------------------------------------------------------------

struct Wired {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
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

async fn wired(script: &str, dimensions: Dimensions) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let config = configuration(&temp, script, dimensions);
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
    let store = kr_crypto::store::open_store("KalaReachGeometry", &environment.secrets_dir())
        .expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");

    let mut session = Session::open(config).expect("opens the session");
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
    Wired {
        _temp: temp,
        _service: service,
        runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

async fn attach_over(
    client: &mut LocalClient,
    wired: &Wired,
    dimensions: Dimensions,
    claim: bool,
) -> AttachmentId {
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id, dimensions, claim),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    attached.attachment.attachment_id
}

async fn subscribe_over(client: &mut LocalClient, wired: &Wired, attachment_id: AttachmentId) {
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
}

fn presentation_of(wired: &Wired, attachment_id: AttachmentId) -> Option<TerminalPresentationMode> {
    wired
        .runtime
        .session()
        .attachments()
        .into_iter()
        .find(|summary| summary.attachment_id == attachment_id)
        .and_then(|summary| summary.presentation.as_ref().copied())
}

/// Waits for this client to be told that its view is no longer continuous.
async fn resynchronised(client: &mut LocalClient, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            return false;
        };
        if let ControlFrame::Notification(notification) = frame
            && notification.event_type.as_str() == "session.resync"
        {
            return true;
        }
    }
    false
}

/// Collects everything this client is sent for `window`.
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
