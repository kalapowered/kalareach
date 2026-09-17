//! A session with a real shell in a real pseudo-terminal.
//!
//! These exercise the parts a unit test cannot reach: a shell that actually runs, output that
//! actually arrives through the fan-out, and a closure that actually terminates a process group.

use std::time::Duration;

use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};
use kr_protocol::session::{
    ClosureReason, Dimensions, DisplayNumber, OwnershipCoverage, SessionState, ShellMode,
};
use kr_worker::output::OutputDelivery;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::session::{Session, SessionConfig};

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never happens. Thirty
/// seconds, and the shorter windows beside it, were inside the range the slowest reference hosts
/// reach when several suites share them, which turned these waits into coin tosses; two minutes is
/// outside it. The poll intervals are unchanged, so a wait that succeeds costs what it always did.
/// What is deliberately *not* raised is a window that asserts something never arrives, or one that
/// samples what arrives inside it: those are not waiting for anything.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn configuration(host: &kr_ipc::testing::TempHost, script: &str) -> SessionConfig {
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
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    }
}

fn terminal_attachment(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: true,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

async fn collect(stream: &mut kr_worker::output::OutputStream, marker: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        // A quiet moment is not an answer. What ends this is the marker, a stream that has closed,
        // or the deadline; a gap between deliveries is a busy machine rather than a host that has
        // stopped.
        match tokio::time::timeout(Duration::from_secs(1), stream.recv()).await {
            Ok(Some(OutputDelivery::Bytes { bytes, .. })) => {
                seen.extend_from_slice(&bytes);
                if seen.windows(marker.len()).any(|window| window == marker) {
                    break;
                }
            }
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_runs_a_shell_and_its_output_reaches_an_attachment() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "printf 'kr-session-marker\\n'; exec cat");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    assert_eq!(session.state(), SessionState::Creating);
    session.launch().expect("launches");
    assert_eq!(session.state(), SessionState::Live);
    assert!(session.root_identity().is_some());

    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    let result = session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    assert_eq!(
        result.geometry.owner.as_ref(),
        Some(&attachment_id),
        "the first eligible claim owns the size"
    );
    let mut stream = session.subscribe(attachment_id).expect("subscribes");

    let runtime = SessionRuntime::start(
        session,
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
    )
    .expect("starts");
    let seen = collect(&mut stream, b"kr-session-marker").await;
    assert!(
        seen.windows(17)
            .any(|window| window == b"kr-session-marker"),
        "the shell's output reached the attachment: {seen:?}"
    );

    // Input goes to the shell in order and comes back through the same stream.
    {
        let mut session = runtime.session();
        session
            .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the lease");
        let epoch = session.lease().epoch.get();
        session
            .write_input(
                attachment_id,
                epoch,
                0,
                b"kr-input-marker\n",
                None,
                std::time::Instant::now(),
            )
            .expect("writes");
    }
    runtime.flush_input();
    let echoed = collect(&mut stream, b"kr-input-marker").await;
    assert!(
        echoed
            .windows(15)
            .any(|window| window == b"kr-input-marker"),
        "input reached the shell and its output came back: {echoed:?}"
    );

    // Detaching removes the attachment and the session stays live with none.
    {
        let mut session = runtime.session();
        let detached = session.detach(attachment_id).expect("detaches");
        assert_eq!(detached.remaining.get(), 0);
        assert_eq!(session.state(), SessionState::Live);
    }

    let runtime = std::sync::Arc::new(runtime);
    let (acceptance, gate) = runtime.close(ClosureReason::CloseRequested);
    assert_eq!(acceptance.state, SessionState::Closing);
    assert!(acceptance.initiated);
    assert!(
        acceptance.closure.is_none(),
        "the acceptance comes before the record"
    );
    gate.release();
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the closure finishes");
    assert_eq!(record.session_id, session_id);
    assert_eq!(record.reason, ClosureReason::CloseRequested);
    assert_eq!(record.terminated.len(), 1);
    assert_eq!(runtime.state(), SessionState::Closed);
    let _ = record.ownership_coverage;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_shell_that_exits_closes_the_session_and_nothing_restarts_it() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "printf 'bye\\n'; exit 7");
    let runtime = std::sync::Arc::new(
        kr_worker::runtime::start(
            config,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts a session"),
    );
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes on its own");
    assert!(
        matches!(
            record.reason,
            ClosureReason::RootExit | ClosureReason::RootSignal
        ),
        "the record names the root shell's own exit: {:?}",
        record.reason
    );
    assert_eq!(runtime.state(), SessionState::Closed);
    // Nothing starts a second shell.
    assert!(runtime.session().root_identity().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_refuses_input_and_a_second_close_joins_the_first() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "exec cat");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::ObserveTerminal);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    session
        .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();

    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    let (first, gate) = runtime.close(ClosureReason::CloseRequested);
    assert!(first.initiated);
    // Input is rejected from the moment the state changed, before anything was signalled.
    let refused = runtime.session().write_input(
        attachment_id,
        epoch,
        0,
        b"x",
        None,
        std::time::Instant::now(),
    );
    assert!(refused.is_err(), "a closing session rejects input");
    // A second request joins the closure already under way rather than starting another.
    let (second, second_gate) = runtime.close(ClosureReason::CloseRequested);
    assert!(!second.initiated);
    assert_eq!(second.state, SessionState::Closing);
    second_gate.release();
    gate.release();
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the closure finishes");
    assert_eq!(record.session_id, session_id);
    assert!(matches!(
        record.ownership_coverage,
        OwnershipCoverage::Complete | OwnershipCoverage::Incomplete
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_attachment_is_resynchronised_and_the_others_keep_receiving() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "i=0; while [ $i -lt 400 ]; do printf 'kr-bulk-%s-0123456789012345678901234567890123456789\\n' $i; i=$((i+1)); done; printf 'kr-bulk-end\\n'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let quick_id = AttachmentId::new(kr_ipc::new_uuid());
    let slow_id = AttachmentId::new(kr_ipc::new_uuid());
    for id in [quick_id, slow_id] {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        session
            .attach(&terminal_attachment(session_id), requested, id)
            .expect("attaches");
    }
    let mut quick = session.subscribe(quick_id).expect("subscribes");
    // A bound small enough that an attachment which stops reading reaches it. The other keeps the
    // session's own bound, so one client's queue cannot affect another's.
    let mut slow = session.subscribe_within(slow_id, 1024).expect("subscribes");

    let runtime = SessionRuntime::start(
        session,
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
    )
    .expect("starts");
    // The quick subscriber drains; the slow one is left alone until afterwards.
    let seen = collect(&mut quick, b"kr-bulk-end").await;
    assert!(
        seen.windows(11).any(|window| window == b"kr-bulk-end"),
        "the reading attachment received everything, unaffected by the one that did not"
    );

    let mut resynchronised = false;
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), slow.recv()).await {
            Ok(Some(OutputDelivery::Resync(_))) => {
                resynchronised = true;
                break;
            }
            // A quiet moment is a busy machine, not an answer.
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    assert!(
        resynchronised,
        "waited {:?} for the attachment that stopped reading to be told to resynchronise",
        started.elapsed()
    );
    let _ = runtime.state();
    let _ = EnvironmentId::new(Uuid::NIL);
}

/// Opens a live session with one attachment holding the lease inside an open bracketed paste.
///
/// This is the state every closure and detach path has to be able to end cleanly: the application
/// has been given a paste start, so something has to give it the end, and bytes the previous lease
/// handed to the writer must not reach the application after that lease is gone.
async fn mid_paste(
    host: &kr_ipc::testing::TempHost,
    mut config: SessionConfig,
) -> (std::sync::Arc<SessionRuntime>, AttachmentId, u64) {
    let _ = host;
    config.shell.arguments = vec!["-c".to_owned(), "exec cat".to_owned()];
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    session
        .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    // The application has turned bracketed paste on, and a paste has started.
    session.set_bracketed_paste(true);
    session
        .write_input(
            attachment_id,
            epoch,
            0,
            b"\x1b[200~pasted",
            None,
            std::time::Instant::now(),
        )
        .expect("writes the start of a paste");
    assert!(session.paste_open(), "the application is inside a paste");
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.flush_input();
    (runtime, attachment_id, epoch)
}

#[tokio::test(flavor = "multi_thread")]
async fn detaching_mid_paste_publishes_the_fence_and_closes_the_paste() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "exec cat");
    let (runtime, attachment_id, epoch) = mid_paste(&host, config).await;

    {
        let mut session = runtime.session();
        session.detach(attachment_id).expect("detaches");
        runtime.flush_locked(&mut session);
    }
    let session = runtime.session();
    assert!(!session.paste_open(), "the detach closed the open paste");
    assert!(
        session.input_fence() > epoch,
        "and released the lease the attachment held"
    );
    assert_eq!(
        runtime.input_fence(),
        session.input_fence(),
        "the writer is comparing against the fence the detach moved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_shell_that_exits_mid_paste_publishes_the_fence_and_closes_the_paste() {
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "exec cat");
    let (runtime, attachment_id, epoch) = mid_paste(&host, config).await;

    // End of transmission at a `cat` reading a terminal ends the shell, which is the root-exit
    // closure path: nothing asked for it, so nothing else is going to publish the fence.
    {
        let mut session = runtime.session();
        session
            .write_input(
                attachment_id,
                epoch,
                1,
                b"\n\x04\x04",
                None,
                std::time::Instant::now(),
            )
            .expect("writes end of transmission");
        runtime.flush_locked(&mut session);
    }
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes when its root shell exits");
    assert!(matches!(
        record.reason,
        ClosureReason::RootExit | ClosureReason::RootSignal
    ));
    let session = runtime.session();
    assert!(
        !session.paste_open(),
        "the root-exit closure closed the open paste"
    );
    assert!(
        session.input_fence() > epoch,
        "and released the lease the attachment held"
    );
    assert_eq!(
        runtime.input_fence(),
        session.input_fence(),
        "the writer is comparing against the fence the closure moved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_desktop_that_ends_mid_paste_publishes_the_fence_and_closes_the_paste() {
    let host = kr_ipc::testing::TempHost::create();
    let mut config = configuration(&host, "exec cat");
    // A desktop-bound worker whose login is not the one this host is in. Section 7 ends such a
    // session with `desktop_lost`, and nothing asked for that closure either.
    config.worker_profile = WorkerProfile::DesktopBound;
    config.desktop = DesktopBinding {
        desktop_session_id: Nullable::null(),
        login_generation: Nullable::some(kr_protocol::scalars::U64::new(u64::MAX)),
    };
    let (runtime, _attachment_id, epoch) = mid_paste(&host, config).await;

    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes when its desktop ends");
    assert_eq!(record.reason, ClosureReason::DesktopLost);
    let session = runtime.session();
    assert!(
        !session.paste_open(),
        "the desktop-loss closure closed the open paste"
    );
    assert!(
        session.input_fence() > epoch,
        "and released the lease the attachment held"
    );
    assert_eq!(
        runtime.input_fence(),
        session.input_fence(),
        "the writer is comparing against the fence the closure moved"
    );
}

/// Returns `bytes` of input made of complete lines.
///
/// A line discipline in its ordinary mode holds a completed line for the application to read and
/// stops taking more once it is holding all it can. Input without a line ending is discarded
/// instead, which tests nothing.
fn lines(bytes: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(bytes);
    while input.len() < bytes {
        let remaining = bytes - input.len();
        let run = remaining.min(80).saturating_sub(1);
        input.extend(std::iter::repeat_n(b'a', run));
        input.push(b'\n');
    }
    input.truncate(bytes);
    input
}

/// Reads everything the session has retained, as raw bytes.
///
/// The raw history is what the application actually produced, before the canonical grid decides
/// what any of it means, which is what a test about delivery has to look at.
fn retained(runtime: &SessionRuntime) -> Vec<u8> {
    let session = runtime.session();
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

/// Waits for `marker` to appear in the session's retained output.
async fn retained_within(runtime: &SessionRuntime, marker: &[u8], within: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let seen = retained(runtime);
        if seen.windows(marker.len()).any(|window| window == marker) {
            return seen;
        }
        if tokio::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn input_beyond_the_session_budget_is_refused_rather_than_acknowledged() {
    let host = kr_ipc::testing::TempHost::create();
    // A shell that never reads its input. Everything written to the terminal stops at the line
    // discipline, which is exactly the state the budget exists for.
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    session
        .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );

    // The protocol's own frame limit, written again and again by a lease holder that is within its
    // rights on every single frame. The lines are what make the terminal stop taking them: a line
    // discipline holds a completed line for the application to read, so an application that never
    // reads is a terminal that fills.
    let frame = lines(kr_protocol::limits::MAX_INPUT_FRAME_LEN);
    let mut refusal = None;
    let mut accepted = 0_u64;
    for sequence in 0..64 {
        let outcome = {
            let mut session = runtime.session();
            let outcome = session.write_input(
                attachment_id,
                epoch,
                sequence,
                &frame,
                None,
                std::time::Instant::now(),
            );
            if outcome.is_ok() {
                runtime.flush_locked(&mut session);
            }
            outcome
        };
        match outcome {
            Ok(_) => accepted += 1,
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let refusal = refusal.expect("the queue is bounded, so the writes stop being accepted");
    assert_eq!(
        refusal.to_protocol_error().code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "the refusal names the reason rather than acknowledging bytes nothing has taken"
    );
    assert!(
        accepted > 0,
        "an application that is not reading still accepts what fits"
    );
    assert!(
        runtime
            .session()
            .queued_input_bytes()
            .load(std::sync::atomic::Ordering::Acquire)
            <= kr_worker::session::MAX_QUEUED_INPUT_BYTES,
        "and nothing beyond the budget was ever queued"
    );
    let runtime = std::sync::Arc::clone(&runtime);
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_closes_a_delivered_paste_and_abandons_the_old_lease_bytes() {
    // The end of the paste arrives in a frame of its own, behind the body.
    takeover_mid_paste(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_closes_a_paste_whose_end_was_in_the_half_that_never_arrived() {
    // One frame carries the whole paste, start to end. The framer reads it as a paste that opened
    // and closed, so nothing about the batch's *final* framing says a terminator is needed; what
    // needs one is the half of it the application actually received.
    takeover_mid_paste(true).await;
}

/// Takes the lease over from a writer that is part way through a paste.
///
/// `one_frame` decides where the end of the paste is: behind the body in a frame of its own, or in
/// the same frame as the start. Either way the application is given the start and not the end, and
/// either way it must be given an end before the next actor's input.
async fn takeover_mid_paste(one_frame: bool) {
    let host = kr_ipc::testing::TempHost::create();
    // The application sets the modes a full-screen application sets, then reads nothing for five
    // seconds, so the writer is inside a batch when the takeover happens, and then reads
    // everything, so what it was given can be looked at. Each mode earns its place: without the
    // line discipline holding whole lines the terminal stops taking input rather than discarding
    // it, which is what makes the writer wait; with the echo off the output is what the
    // application received rather than what the terminal repeated back as it arrived; and
    // bracketed paste is what makes the host track the framing at all.
    let config = configuration(
        &host,
        "stty raw -echo; printf '\\033[?2004hkr-ready\\n'; sleep 5; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = AttachmentId::new(kr_ipc::new_uuid());
    let second = AttachmentId::new(kr_ipc::new_uuid());
    for id in [first, second] {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        session
            .attach(&terminal_attachment(session_id), requested, id)
            .expect("attaches");
    }
    session
        .acquire_input(first, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    // Nothing is written until the application has set those modes. Bracketed paste is the
    // application's own, read from the canonical grid rather than asserted here, because that is
    // where the framer reads it from in production.
    let ready = retained_within(&runtime, b"kr-ready", LIVENESS_DEADLINE).await;
    assert!(
        ready.windows(8).any(|window| window == b"kr-ready"),
        "the application is running and its terminal is in the mode this test needs"
    );
    assert!(
        runtime.session().engine().bracketed_paste(),
        "and it has turned bracketed paste on"
    );

    // A paste that starts, a body far larger than the terminal will take while nothing is reading,
    // and the terminator behind it. The terminator is accepted, so the framer considers the paste
    // closed; it has not been written, so the application does not.
    const BODY: usize = 32 * 1024;
    let mut start = Vec::from(b"\x1b[200~");
    start.extend(lines(BODY));
    if one_frame {
        start.extend_from_slice(b"\x1b[201~");
    }
    {
        let mut session = runtime.session();
        session
            .write_input(first, epoch, 0, &start, None, std::time::Instant::now())
            .expect("writes the start of the paste");
        if !one_frame {
            session
                .write_input(
                    first,
                    epoch,
                    1,
                    b"\x1b[201~",
                    None,
                    std::time::Instant::now(),
                )
                .expect("writes the terminator");
        }
        runtime.flush_locked(&mut session);
    }

    // The takeover has to happen while the writer is *inside* that batch: the terminal has taken
    // the start of the paste and everything after it is waiting for an application that is not
    // reading. A terminal takes a whole write or none of it, so the queue counter cannot show that
    // the writer has begun; the notice the lease change left for it can. The writer clears that
    // notice when it takes it, and it is queued ahead of the paste, so a cleared notice means the
    // writer has moved on to the batch that opens the paste.
    let notice = runtime.session().lease_change_queued();
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    while notice.load(std::sync::atomic::Ordering::Acquire) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the writer began the batch that opens the paste"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let queued = runtime.session().queued_lease_bytes();
    assert!(
        queued.load() > 0,
        "and is waiting inside it, because the application is not reading"
    );
    let taken = {
        let mut session = runtime.session();
        let taken = session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the lease over");
        runtime.flush_locked(&mut session);
        taken
    };
    assert!(
        taken.discarded_bytes.get() > 0,
        "the takeover reports the bytes it did not deliver: {taken:?}"
    );
    let next_epoch = taken.lease.epoch.get();
    {
        let mut session = runtime.session();
        session
            .write_input(
                second,
                next_epoch,
                0,
                b"kr-new-lease\n",
                None,
                std::time::Instant::now(),
            )
            .expect("the new lease writes");
        runtime.flush_locked(&mut session);
    }

    let seen = retained_within(&runtime, b"kr-new-lease", LIVENESS_DEADLINE).await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    let terminator = text
        .find("\u{1b}[201~")
        .expect("the application was given the end of the paste it was given the start of");
    let new_lease = text
        .find("kr-new-lease")
        .expect("and then the next actor's input");
    assert!(
        terminator < new_lease,
        "the paste was closed before the new lease's input reached the application"
    );
    // And the rest of the old lease's batch never arrived: the writer abandoned it at the takeover
    // rather than finishing it once the application started reading. The comparison is against
    // what the batch actually held, not its length in bytes, because the line endings are not `a`.
    let sent = start.iter().filter(|byte| **byte == b'a').count();
    let body = seen.iter().filter(|byte| **byte == b'a').count();
    assert!(
        body * 2 < sent,
        "a partly written batch of an ended lease is abandoned, not completed: {body} of {sent}"
    );
    let runtime = std::sync::Arc::clone(&runtime);
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_publishes_the_fence_before_it_counts_what_the_old_lease_left() {
    // The receipt says how many of the previous holder's bytes never reached the application. That
    // answer is only true if the writer had already stopped writing them when it was counted, so
    // the fence goes out with the lease change itself and the count is taken afterwards. Counting
    // first would report bytes as discarded that a writer still on the old fence went on to write.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = AttachmentId::new(kr_ipc::new_uuid());
    let second = AttachmentId::new(kr_ipc::new_uuid());
    for id in [first, second] {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        session
            .attach(&terminal_attachment(session_id), requested, id)
            .expect("attaches");
    }
    session
        .acquire_input(first, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );

    // More than the terminal of an application that never reads will take, so the writer is still
    // holding some of it when the lease changes.
    let batch = lines(256 * 1024);
    {
        let mut session = runtime.session();
        session
            .write_input(first, epoch, 0, &batch, None, std::time::Instant::now())
            .expect("writes");
        runtime.flush_locked(&mut session);
    }
    // The lease changes while the writer is part way through: some of the batch is with the
    // application and the rest is waiting for a terminal that has no room.
    let total = batch.len();
    let queued = runtime.session().queued_lease_bytes();
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    loop {
        let waiting = queued.load();
        if waiting > 0 && waiting < total {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the writer delivered some of the batch and is waiting with the rest: {waiting}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let taken = {
        let mut session = runtime.session();
        let taken = session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the lease over");
        // Read before the flush, because the receipt already exists: whatever it reported as
        // discarded has to be bytes the writer can no longer write, and the fence is what stops it.
        assert_eq!(
            runtime.input_fence(),
            taken.lease.epoch.get(),
            "the writer was told the lease changed before the bytes it was holding were counted"
        );
        assert_eq!(
            session.queued_lease_bytes().load(),
            0,
            "and the count the receipt took belongs to the lease that ended"
        );
        runtime.flush_locked(&mut session);
        taken
    };
    assert!(
        taken.discarded_bytes.get() > 0,
        "the takeover reports what it did not deliver: {taken:?}"
    );
    let runtime = std::sync::Arc::clone(&runtime);
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_geometry_the_session_budget_cannot_admit_is_refused_before_anything_moves() {
    // A size is refused by what it would cost, not only by what the kernel will take: both screen
    // buffers at that geometry have to fit the session's budget, and one that does not is refused
    // before a cell is allocated. The answer names a resource rather than the caller's argument,
    // because the same size is one another session runs at and a client answers it by asking for a
    // size that fits.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    let before = session.geometry();

    let refused = session
        .resize(
            attachment_id,
            Dimensions::new(2_048, 128),
            before.epoch.get(),
        )
        .expect_err("a geometry that does not fit the session's budget is refused");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "the refusal names the resource: {refused}"
    );
    let after = session.geometry();
    assert_eq!(
        (after.dimensions, after.epoch),
        (before.dimensions, before.epoch),
        "and the terminal the application is looking at did not move"
    );
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_reports_exactly_the_bytes_the_application_never_received() {
    // The receipt is a promise about what reached the application, so it has to be exact in both
    // directions: a byte counted as discarded must not arrive afterwards, and a byte that arrived
    // must not be counted. The lease change and the writer share one boundary, so no write of the
    // ended lease's bytes can begin after the count, and none was part way through while it was
    // taken.
    let host = kr_ipc::testing::TempHost::create();
    // Raw mode, so every byte the application receives is the byte that was written, and nothing
    // is read for five seconds, so the writer is inside the batch when the lease changes.
    let config = configuration(
        &host,
        "stty raw -echo; printf 'kr-up\\n'; sleep 5; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let first = AttachmentId::new(kr_ipc::new_uuid());
    let second = AttachmentId::new(kr_ipc::new_uuid());
    for id in [first, second] {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        session
            .attach(&terminal_attachment(session_id), requested, id)
            .expect("attaches");
    }
    session
        .acquire_input(first, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    // Nothing in this test's own markers is an `a`, because `a` is what the counting is about.
    let ready = retained_within(&runtime, b"kr-up", LIVENESS_DEADLINE).await;
    assert!(
        ready.windows(5).any(|window| window == b"kr-up"),
        "the application is running and its terminal takes bytes as they are"
    );

    // Nothing but `a`, so what the application received can be counted against what was sent.
    const SENT: usize = 256 * 1024;
    let batch = vec![b'a'; SENT];
    {
        let mut session = runtime.session();
        session
            .write_input(first, epoch, 0, &batch, None, std::time::Instant::now())
            .expect("writes");
        runtime.flush_locked(&mut session);
    }
    // The lease changes while the writer is part way through: some of the batch is with the
    // application and the rest is waiting for a terminal that has no room.
    let total = batch.len();
    let queued = runtime.session().queued_lease_bytes();
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    loop {
        let waiting = queued.load();
        if waiting > 0 && waiting < total {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the writer delivered some of the batch and is waiting with the rest: {waiting}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let taken = {
        let mut session = runtime.session();
        let taken = session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the lease over");
        runtime.flush_locked(&mut session);
        taken
    };
    let discarded = usize::try_from(taken.discarded_bytes.get()).expect("fits");
    assert!(
        discarded > 0 && discarded < SENT,
        "some of it reached the application and some did not: {discarded} of {SENT}"
    );

    // The application starts reading, and what it echoes is what it was given. Nothing the receipt
    // called discarded may appear in it, and nothing it received may be missing from it.
    let next_epoch = taken.lease.epoch.get();
    {
        let mut session = runtime.session();
        session
            .write_input(
                second,
                next_epoch,
                0,
                b"kr-next",
                None,
                std::time::Instant::now(),
            )
            .expect("the new lease writes");
        runtime.flush_locked(&mut session);
    }
    let _ = retained_within(&runtime, b"kr-next", LIVENESS_DEADLINE).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = retained(&runtime);
    let received = seen.iter().filter(|byte| **byte == b'a').count();
    assert_eq!(
        received + discarded,
        SENT,
        "every byte was either received or reported as discarded, and none was both: \
         {received} received, {discarded} discarded, {SENT} sent"
    );
    let runtime = std::sync::Arc::clone(&runtime);
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_succession_the_budget_refuses_leaves_the_size_unowned_rather_than_with_who_left() {
    // The attachment that owned the size has gone, and the one next in line asks for a geometry
    // this session cannot afford. The size stays where it was, because nothing moved it, but it
    // cannot stay with an attachment that is not there any more: a session naming an owner nobody
    // can reach is a session whose next eligible claim has nowhere to go.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let owner = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(&terminal_attachment(session_id), requested.clone(), owner)
        .expect("attaches the owner");

    // The one next in line, at a size whose two screen buffers do not fit the session's budget.
    let waiting = AttachmentId::new(kr_ipc::new_uuid());
    let mut params = terminal_attachment(session_id);
    params.claim_geometry = true;
    params.dimensions = Nullable::some(Dimensions::new(2_048, 128));
    session
        .attach(&params, requested, waiting)
        .expect("attaches the one next in line");

    let before = session.geometry();
    let refused = session
        .detach(owner)
        .expect_err("the succession is refused");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "and it is refused for what it would cost: {refused}"
    );
    let after = session.geometry();
    assert_eq!(
        after.dimensions, before.dimensions,
        "the terminal the application is looking at did not move"
    );
    assert!(
        after.owner.0.is_none(),
        "and the size is not left with the attachment that has gone: {:?}",
        after.owner
    );
    assert!(
        after.epoch.get() > before.epoch.get(),
        "the ownership that changed advanced the epoch, so a client holding the state from before \
         the owner left cannot transfer the size against it: {} then {}",
        before.epoch.get(),
        after.epoch.get()
    );
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_claim_the_budget_refuses_leaves_the_size_unowned_rather_than_with_who_withdrew()
 {
    // The attachment that owned the size withdraws its claim, and the one next in line asks for a
    // geometry this session cannot afford. The withdrawal happened: the attachment asked for it and
    // the claim is gone. So the size cannot go back to it either, for the same reason a departed
    // owner does not get it back - an attachment that holds no claim is not an owner, and a session
    // naming one has nowhere for its next eligible claim to go, and nothing stops the one that
    // withdrew from resizing the session it gave up.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let owner = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(&terminal_attachment(session_id), requested.clone(), owner)
        .expect("attaches the owner");

    // The one next in line, at a size whose two screen buffers do not fit the session's budget.
    let waiting = AttachmentId::new(kr_ipc::new_uuid());
    let mut params = terminal_attachment(session_id);
    params.claim_geometry = true;
    params.dimensions = Nullable::some(Dimensions::new(2_048, 128));
    session
        .attach(&params, requested, waiting)
        .expect("attaches the one next in line");

    let before = session.geometry();
    let refused = session
        .configure(owner, false)
        .expect_err("the succession the withdrawal produced is refused");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "and it is refused for what it would cost: {refused}"
    );

    let after = session.geometry();
    assert_eq!(
        after.dimensions, before.dimensions,
        "the terminal the application is looking at did not move"
    );
    assert!(
        session
            .attachments()
            .iter()
            .any(|attachment| attachment.attachment_id == owner && !attachment.claim_geometry),
        "the claim the attachment withdrew is withdrawn"
    );
    assert!(
        after.owner.0.is_none(),
        "and the size is not left with the attachment that withdrew its claim: {:?}",
        after.owner
    );
    assert!(
        after.epoch.get() > before.epoch.get(),
        "the ownership that changed advanced the epoch, so a client holding the state from before \
         the claim went cannot transfer the size against it: {} then {}",
        before.epoch.get(),
        after.epoch.get()
    );
    let refused = session
        .resize(owner, Dimensions::new(100, 30), after.epoch.get())
        .expect_err("what withdrew its claim cannot resize the session it gave up");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::GeometryNotOwner,
        "and it is refused as not the owner: {refused}"
    );

    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

#[tokio::test(flavor = "multi_thread")]
async fn input_for_a_terminal_that_has_gone_is_refused_rather_than_acknowledged() {
    // The writer sets this latch on its way out, and it goes out for one reason: a terminal that
    // will take nothing more. An acknowledgement after that would say bytes reached an application
    // that nothing can reach, which is the one thing an acknowledgement must not mean.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    session
        .attach(&terminal_attachment(session_id), requested, attachment)
        .expect("attaches");
    let held = session
        .acquire_input(attachment, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the keys");
    let epoch = held.lease.epoch.get();
    session
        .write_input(
            attachment,
            epoch,
            0,
            b"before",
            None,
            std::time::Instant::now(),
        )
        .expect("an ordinary write while the terminal is there");

    session
        .terminal_gone_latch()
        .store(true, std::sync::atomic::Ordering::Release);

    let refused = session
        .write_input(
            attachment,
            epoch,
            1,
            b"after",
            None,
            std::time::Instant::now(),
        )
        .expect_err("the terminal takes nothing more");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "and it is the resource it is rather than a closure: {refused}"
    );
    assert_eq!(
        session.state(),
        SessionState::Live,
        "the session itself is still open; what happened to the shell is the monitor's question"
    );

    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// An attachment that never declared what terminal it is, which is what `--no-probe` chooses.
fn undeclared_attachment(session_id: SessionId) -> SessionAttachParams {
    let mut params = terminal_attachment(session_id);
    params.claim_geometry = false;
    params.terminal_profile_id = Nullable::null();
    params
}

#[tokio::test(flavor = "multi_thread")]
async fn a_controller_whose_keys_cannot_be_established_is_refused_the_keys() {
    // Section 8: `input.acquire` checks that the attachment can supply the encoding the application
    // reads. An attachment nobody was allowed to ask about is left in whatever encoding its
    // terminal already had, and the host will not put it into another: it cannot be shown to send
    // what the application reads, in either direction, so it is refused control and keeps
    // everything else.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 120");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");

    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    let declared = AttachmentId::new(kr_ipc::new_uuid());
    // A terminal that implements the protocol this test then has the application negotiate. What a
    // declared name buys is what that terminal is known to implement, so the name has to be one
    // whose keyboard covers the encoding the application asks for.
    let kitty_capable = SessionAttachParams {
        terminal_profile_id: Nullable::some("xterm-kitty".to_owned()),
        ..terminal_attachment(session_id)
    };
    session
        .attach(&kitty_capable, requested.clone(), declared)
        .expect("attaches the one that declared its terminal");
    let undeclared = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(&undeclared_attachment(session_id), requested, undeclared)
        .expect("attaches the one that declared nothing");

    // The application has negotiated nothing, which is the case the previous round allowed: a
    // terminal left in an enhanced protocol by whatever ran before this attachment sends key
    // events this application reads as something else entirely.
    let refused = session
        .acquire_input(undeclared, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect_err("what its keys mean was never established");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::InputIncompatible,
        "and it is refused as the incompatibility it is: {refused}"
    );

    // And the other direction: the application asks for all keys as escape codes.
    session.ingest_output(b"\x1b[=8;1u");
    let refused = session
        .acquire_input(undeclared, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect_err("the keys it would send are not the keys the application reads");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::InputIncompatible,
        "under an enhanced protocol too: {refused}"
    );
    assert!(
        session.subscribe(undeclared).is_ok(),
        "it goes on watching the session it cannot type into"
    );
    session
        .acquire_input(declared, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("the one whose terminal the host may put into the protocol takes the keys");

    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
}

/// Returns the number a marker line carries, from bytes an attachment received.
fn marked_number(output: &[u8], marker: &[u8]) -> Option<u64> {
    let at = output
        .windows(marker.len())
        .position(|window| window == marker)?
        + marker.len();
    let digits: Vec<u8> = output[at..]
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    String::from_utf8(digits).ok()?.parse().ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_shell_that_exits_at_once_is_noticed_before_the_first_wait() {
    // The exit can happen before anything is watching for it: the shell is launched, and it is
    // gone by the time the supervision has opened the child signal it would have been reported on.
    // So the shell's status is asked for once before that supervision waits at all, and this is the
    // case that proves it.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "printf 'kr-leaving\\n'; exit 7");
    let started = tokio::time::Instant::now();
    let runtime = std::sync::Arc::new(
        kr_worker::runtime::start(
            config,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts a session"),
    );
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes on its own");
    let taken = started.elapsed();

    assert_eq!(record.reason, ClosureReason::RootExit);
    assert_eq!(
        record.root_exit_code.0.map(kr_protocol::scalars::U64::get),
        Some(7),
        "the shell's own status"
    );
    assert!(
        taken < kr_worker::lifecycle::IDLE_SWEEP_INTERVAL / 2,
        "and nothing waited for the sweep to come round: {taken:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_shell_that_exits_after_the_session_settles_is_noticed_by_its_own_exit() {
    // The case the child signal is actually for. The session is quiet for seconds before the shell
    // exits, so nothing the session does can be what wakes the host, and a descendant holds the
    // terminal open across the exit, so the terminal hanging up is not the evidence either. What is
    // left is the exit itself, against a sweep that would not come round for thirty seconds.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "sleep 30 & printf 'kr-settling\\n'; sleep 3; exit 7");
    let started = tokio::time::Instant::now();
    let runtime = std::sync::Arc::new(
        kr_worker::runtime::start(
            config,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts a session"),
    );
    let record = tokio::time::timeout(Duration::from_secs(45), runtime.wait_closed())
        .await
        .expect("the session closes on its own");
    let taken = started.elapsed();

    assert_eq!(record.reason, ClosureReason::RootExit);
    assert_eq!(
        record.root_exit_code.0.map(kr_protocol::scalars::U64::get),
        Some(7),
        "the shell's own status"
    );
    assert!(
        taken < kr_worker::lifecycle::IDLE_SWEEP_INTERVAL / 2,
        "the exit reached the host rather than the sweep finding it: {taken:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_that_ends_before_the_session_does_is_still_in_its_record() {
    // What the observation cadence is for. A closure signals what is still running, so a job that
    // started and finished while the session was live is in the record only because the host had
    // already seen it, and what makes the host look is the session's own traffic. The shell names
    // the job and says when it has collected it, so the closure happens after the job is certainly
    // gone rather than after a guess at how long it would take. It writes a line part way through
    // as well: a subscriber that hears nothing for long enough stops listening, and the session
    // this test wants is one that is running something rather than one that has gone quiet.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(
        &host,
        "sleep 4 & printf 'kr-job %s\\n' \"$!\"; sleep 2; printf 'kr-waiting\\n'; wait; \
         printf 'kr-reaped\\n'; exec cat",
    );
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    let mut stream = session.subscribe(attachment_id).expect("subscribes");
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );

    let seen = collect(&mut stream, b"kr-reaped").await;
    let job = marked_number(&seen, b"kr-job ").unwrap_or_else(|| {
        panic!(
            "the shell names the job it started: {}",
            String::from_utf8_lossy(&seen)
        )
    });
    assert!(
        seen.windows(9).any(|window| window == b"kr-reaped"),
        "the shell collected the job before this closes the session: {}",
        String::from_utf8_lossy(&seen)
    );
    assert_eq!(
        runtime.state(),
        SessionState::Live,
        "the shell is still there"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the closure finishes");

    assert_eq!(record.reason, ClosureReason::CloseRequested);
    assert!(
        record
            .terminated
            .iter()
            .any(|process| process.identity.pid.get() == job),
        "the record names the job the shell started and collected, process {job}: {:?}",
        record.terminated
    );
    assert!(
        record
            .terminated
            .iter()
            .any(|process| process.name.0.as_deref() == Some("the session's root shell")),
        "and says which of them was the root shell: {:?}",
        record.terminated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_that_has_already_ended_is_a_closed_session_rather_than_a_failed_launch() {
    // A shell can be gone before the host has read its start identity: a startup file that says
    // `exit`, a program that cannot open what it needs, a command that is not the shell it was
    // declared to be. On macOS the kernel then refuses to describe the process at all, and a host
    // that took that for a launch failure would report a shell that ran as a shell that never
    // started, and lose its status with the error. This session ran, so it closes.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "exit 3");
    let runtime = std::sync::Arc::new(
        kr_worker::runtime::start(config).expect("the shell ran, so the session was created"),
    );
    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes on the root shell's exit");

    assert_eq!(record.reason, ClosureReason::RootExit);
    assert_eq!(
        record.root_exit_code.0.map(kr_protocol::scalars::U64::get),
        Some(3),
        "with the status the shell left, read from the child rather than guessed"
    );
    let root = record
        .terminated
        .iter()
        .find(|process| process.name.0.as_deref() == Some("the session's root shell"))
        .unwrap_or_else(|| {
            panic!(
                "the record names the shell it stopped: {:?}",
                record.terminated
            )
        });
    assert_eq!(
        Some(&root.identity),
        runtime.session().root_identity().as_ref(),
        "and the identity in the record is the one the host held for the shell"
    );
    assert!(
        !root.forced,
        "a shell that had already left was not forced to: {root:?}"
    );
    assert_eq!(
        record.ownership_coverage,
        OwnershipCoverage::Incomplete,
        "the boundary is a terminal process group, which never claims complete coverage"
    );
    assert!(
        record.surviving.is_empty(),
        "and nothing is left behind: {:?}",
        record.surviving
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_the_host_described_keeps_the_identity_the_kernel_gave_it() {
    // The other side of the same path. This shell waits to be told to leave, so it is certainly
    // alive while the host reads it and the identity in the record is the kernel's own rather than
    // the reserved one that says nobody could take a reading. Nothing here rests on how long a
    // sleep takes: the shell exits when this test writes to it, and not before. Its exit is then
    // collected by the supervision rather than at launch, which is why the wait below allows for
    // either wake that can find it, the child signal or the sweep behind it.
    let host = kr_ipc::testing::TempHost::create();
    let config = configuration(&host, "printf 'kr-alive\\n'; read leave; exit 5");
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    session
        .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let mut stream = session.subscribe(attachment_id).expect("subscribes");
    let described = session
        .root_identity()
        .expect("the host read the shell it started");
    assert_ne!(
        described.start_value.get(),
        kr_ipc::identity::START_VALUE_UNREAD,
        "the kernel described this shell, so its identity is a reading"
    );
    let runtime = std::sync::Arc::new(SessionRuntime::start(session).expect("starts"));

    // The shell says it is there, and then it is told to leave. Both are events rather than delays.
    let seen = collect(&mut stream, b"kr-alive").await;
    assert!(
        seen.windows(8).any(|window| window == b"kr-alive"),
        "the shell was running and reading: {}",
        String::from_utf8_lossy(&seen)
    );
    {
        let mut session = runtime.session();
        session
            .write_input(
                attachment_id,
                epoch,
                0,
                b"leave\n",
                std::time::Instant::now(),
            )
            .expect("writes the line the shell is waiting for");
        runtime.flush_locked(&mut session);
    }

    let record = tokio::time::timeout(LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .expect("the session closes on the root shell's exit");

    assert_eq!(record.reason, ClosureReason::RootExit);
    assert_eq!(
        record.root_exit_code.0.map(kr_protocol::scalars::U64::get),
        Some(5)
    );
    assert!(
        record
            .terminated
            .iter()
            .any(|process| process.identity == described),
        "and the record carries that same identity: {:?}",
        record.terminated
    );
}
