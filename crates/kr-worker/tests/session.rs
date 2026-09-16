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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(delivery)) = tokio::time::timeout(Duration::from_secs(5), stream.recv()).await
        else {
            break;
        };
        if let OutputDelivery::Bytes { bytes, .. } = delivery {
            seen.extend_from_slice(&bytes);
            if seen.windows(marker.len()).any(|window| window == marker) {
                break;
            }
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

    let runtime = SessionRuntime::start(session).expect("starts");
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
    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
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
    let runtime = std::sync::Arc::new(kr_worker::runtime::start(config).expect("starts a session"));
    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
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

    let runtime = std::sync::Arc::new(SessionRuntime::start(session).expect("starts"));
    let (first, gate) = runtime.close(ClosureReason::CloseRequested);
    assert!(first.initiated);
    // Input is rejected from the moment the state changed, before anything was signalled.
    let refused =
        runtime
            .session()
            .write_input(attachment_id, epoch, 0, b"x", std::time::Instant::now());
    assert!(refused.is_err(), "a closing session rejects input");
    // A second request joins the closure already under way rather than starting another.
    let (second, second_gate) = runtime.close(ClosureReason::CloseRequested);
    assert!(!second.initiated);
    assert_eq!(second.state, SessionState::Closing);
    second_gate.release();
    gate.release();
    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
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

    let runtime = SessionRuntime::start(session).expect("starts");
    // The quick subscriber drains; the slow one is left alone until afterwards.
    let seen = collect(&mut quick, b"kr-bulk-end").await;
    assert!(
        seen.windows(11).any(|window| window == b"kr-bulk-end"),
        "the reading attachment received everything, unaffected by the one that did not"
    );

    let mut resynchronised = false;
    for _ in 0..200 {
        let Ok(Some(delivery)) = tokio::time::timeout(Duration::from_secs(5), slow.recv()).await
        else {
            break;
        };
        if matches!(delivery, OutputDelivery::Resync(_)) {
            resynchronised = true;
            break;
        }
    }
    assert!(
        resynchronised,
        "the attachment that stopped reading was told to resynchronise"
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
            std::time::Instant::now(),
        )
        .expect("writes the start of a paste");
    assert!(session.paste_open(), "the application is inside a paste");
    let runtime = std::sync::Arc::new(SessionRuntime::start(session).expect("starts"));
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
                std::time::Instant::now(),
            )
            .expect("writes end of transmission");
        runtime.flush_locked(&mut session);
    }
    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
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

    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
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
    let runtime = std::sync::Arc::new(SessionRuntime::start(session).expect("starts"));

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
    let runtime = std::sync::Arc::new(SessionRuntime::start(session).expect("starts"));
    // Nothing is written until the application has set those modes. Bracketed paste is the
    // application's own, read from the canonical grid rather than asserted here, because that is
    // where the framer reads it from in production.
    let ready = retained_within(&runtime, b"kr-ready", Duration::from_secs(30)).await;
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
            .write_input(first, epoch, 0, &start, std::time::Instant::now())
            .expect("writes the start of the paste");
        if !one_frame {
            session
                .write_input(first, epoch, 1, b"\x1b[201~", std::time::Instant::now())
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
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
                std::time::Instant::now(),
            )
            .expect("the new lease writes");
        runtime.flush_locked(&mut session);
    }

    let seen = retained_within(&runtime, b"kr-new-lease", Duration::from_secs(30)).await;
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
