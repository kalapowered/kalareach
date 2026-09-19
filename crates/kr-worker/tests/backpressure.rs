//! A client that stops reading, on a real socket.
//!
//! Section 9 is explicit: a slow client is told to resynchronise and is never allowed to hold the
//! pseudo-terminal's read loop. A unit test on the fan-out cannot show the second half, because the
//! thing that would be held is a real socket with a real kernel buffer behind it. This one attaches
//! two clients over the worker's own endpoint, stops reading on one of them, and checks that the
//! other keeps receiving and that the session keeps running.
//!
//! # What this asserts, and what it deliberately does not
//!
//! The requirement is about **order**, not about speed: while one client is not reading, the
//! session keeps running and another client keeps receiving. So the progress is watched as it
//! happens rather than sampled after a fixed window, because how fast a host with four processors
//! delivers a burst in a debug build is not what section 9 promises.
//!
//! The reading client can itself fall behind on a slow host, and then the same rule applies to it:
//! it is told to resynchronise. That is the bound working, not a failure, so the test names what
//! ended its stream — a resynchronisation, a closed connection or a panic — instead of asserting
//! only that something did. A client that was never told anything is the failure, and that is what
//! these assertions distinguish.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{ActionId, BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The bound one attachment's queue is given.
///
/// Smaller than the eight megabytes a session uses by default, so a client that stops reading
/// fills it in a moment rather than a minute. A client that is reading never approaches it.
const SEND_QUEUE_BYTES: usize = 256 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stops_reading_is_resynchronised_and_holds_nothing_up() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(1);
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

    // A shell that keeps producing for the whole test, rather than in one burst at startup. A
    // burst would be a race: a client that attached a moment late would subscribe past most of it
    // and never reach its bound. Roughly 140 KiB a second is many times one attachment's queue over
    // the window this test leaves a client not reading, and nothing at all for a client that reads.
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec![
                "-c".to_owned(),
                "while true; do i=0; while [ $i -lt 2000 ]; do printf 'line-%s-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n' $i; i=$((i+1)); done; sleep 1; done".to_owned(),
            ],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: SEND_QUEUE_BYTES,
        resident_bytes: 4 * 1024 * 1024,
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

    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
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

    // Two clients over the real endpoint. Neither knows about the other.
    let (slow, slow_id) = attached(&endpoint, environment_id, session_id).await;
    let (quick, _) = attached(&endpoint, environment_id, session_id).await;

    // One of them reads as fast as it can, and says what ended its stream.
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&received);
    let draining = tokio::spawn(async move {
        let mut quick = quick;
        loop {
            match quick.recv().await {
                Ok(ControlFrame::Notification(notification)) => {
                    match notification.event_type.as_str() {
                        "session.output" => {
                            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        "session.resync" => {
                            let reason = notification
                                .payload
                                .to_typed::<kr_protocol::recovery::ResyncRequired>()
                                .map(|marker| marker.reason);
                            return Drained::Resynchronised(reason.ok());
                        }
                        _ => {}
                    }
                }
                Ok(_) => {}
                Err(error) => return Drained::Closed(error.to_string()),
            }
        }
    });

    // The other does not read at all for long enough to fall further behind than its bound allows:
    // its socket fills, the worker's queue for it fills behind that, and it is told to
    // resynchronise. Nothing is read from it until the end of this test, which is the whole point.
    //
    // Two things are watched through that same window, and neither is a measurement of how fast
    // this host is. The session's own output cursor is the read loop's position in the stream: if
    // it advances, the pseudo-terminal was read while a client was not reading, which is exactly
    // what section 9 promises. The other is the client that *is* reading, which shows the fan-out
    // reaching somebody while one peer is silent.
    let before = runtime.session().output_cursor();
    let advances = progress(&received, Duration::from_secs(10)).await;
    let after = runtime.session().output_cursor();
    let counted = received.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "the pseudo-terminal was read while one client was not reading: the output cursor stood \
         at {before} and is at {after}"
    );
    assert!(
        counted > 0,
        "the client that kept reading received output while the other was not reading: \
         {advances} arrivals and {counted} batches in ten seconds, on {}",
        finished(&draining)
    );

    // The moment the promise is actually about. Everything above could have happened before the
    // silent client's queue filled; what section 9 requires is that the read loop keeps going
    // *after* it has. So the test waits for the overflow itself, which the session knows about,
    // and then measures again from there.
    let overflowed = {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut seen = false;
        while Instant::now() < deadline {
            if runtime.session().is_resynchronising(slow_id) {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        seen
    };
    assert!(
        overflowed,
        "the queue for the client that stopped reading filled, which is the condition this test \
         is about: {} batches reached the other one, on {}",
        received.load(std::sync::atomic::Ordering::Relaxed),
        finished(&draining)
    );
    let at_overflow = runtime.session().output_cursor();
    let read_at_overflow = received.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        read_at_overflow > 0,
        "the client that kept reading had received output by the time the other one's queue filled"
    );
    // Waited for rather than sampled over a fixed window: what this asserts is what happens after
    // the overflow, not how quickly a loaded machine gets there. Two things have to happen, and
    // they are waited for together under one deadline, because either one alone can be true of a
    // moment rather than of the session: the terminal goes on being read, which is the cursor
    // moving past where it stood when the queue filled, and the client that kept up either
    // receives more or falls behind too and is told so. A wait that ended on the second alone
    // could end on output buffered before the overflow.
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let (afterwards, read_after) = loop {
        let afterwards = runtime.session().output_cursor();
        let read_after = received.load(std::sync::atomic::Ordering::Relaxed);
        if afterwards > at_overflow && (read_after > read_at_overflow || draining.is_finished()) {
            break (afterwards, read_after);
        }
        assert!(
            Instant::now() < deadline,
            "waited {:?} for the session to read past {at_overflow} - it is at {afterwards} - and \
             for the client that kept reading either to receive more than {read_at_overflow} \
             batches or to be told it had fallen behind too, on {}",
            started.elapsed(),
            finished(&draining)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        afterwards > at_overflow,
        "the pseudo-terminal was still being read after the queue filled: the output cursor stood \
         at {at_overflow} and is at {afterwards} after {:?}, on {}",
        started.elapsed(),
        finished(&draining)
    );
    assert!(
        read_after > read_at_overflow || draining.is_finished(),
        "and output still reached the client that was reading, or that client had fallen behind \
         too and been told so, after {:?}",
        started.elapsed()
    );

    // The session is still running: the one that stopped reading held nothing up.
    assert_eq!(
        runtime.state(),
        SessionState::Live,
        "the session kept running while one client was not reading"
    );

    // Now the client that stopped reading looks at what it was sent. What it finds is the marker,
    // not a hole it was never told about.
    let mut slow = slow;
    let mut resynchronised = false;
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while Instant::now() < deadline {
        // A timeout here is not an answer. The loop keeps looking until its own deadline rather
        // than concluding from one quiet moment that nothing is coming.
        let Ok(Ok(message)) = tokio::time::timeout(Duration::from_secs(5), slow.recv()).await
        else {
            continue;
        };
        if let ControlFrame::Notification(notification) = message
            && notification.event_type.as_str() == "session.resync"
        {
            resynchronised = true;
            break;
        }
    }
    assert!(
        resynchronised,
        "waited {:?} for the client that stopped reading to be told to resynchronise",
        started.elapsed()
    );

    // And what became of the client that kept reading, named rather than inferred. It may have
    // fallen behind too on a host that delivers more slowly than it reads, and then the same rule
    // applies to it and its own queue is the reason. What it must never be is a client whose
    // connection ended without a word, or a reader that panicked.
    if draining.is_finished() {
        match draining.await {
            // It fell behind too, which happens on a host that cannot write to two peers as fast
            // as one application produces. The same rule then applies to it, and its own queue is
            // the reason: what it must never be is a client that was left with a hole.
            Ok(Drained::Resynchronised(reason)) => assert_eq!(
                reason,
                Some(kr_protocol::recovery::ResyncReason::SendQueueFull),
                "the client that kept reading was resynchronised for its own queue, after \
                 receiving {} batches",
                received.load(std::sync::atomic::Ordering::Relaxed)
            ),
            Ok(Drained::Closed(detail)) => panic!(
                "the client that kept reading lost its connection without being told to \
                 resynchronise: {detail}"
            ),
            Err(error) => panic!("the client that kept reading stopped on a panic: {error}"),
        }
    } else {
        draining.abort();
    }
}

/// What ended the reading client's stream.
#[derive(Debug)]
enum Drained {
    /// It was told to resynchronise, with the reason the marker carried.
    Resynchronised(Option<kr_protocol::recovery::ResyncReason>),
    /// Its connection ended.
    Closed(String),
}

/// Describes a reader that has already finished, for a failure message.
fn finished(handle: &tokio::task::JoinHandle<Drained>) -> &'static str {
    if handle.is_finished() {
        "a stream that had already ended"
    } else {
        "a stream that was still open"
    }
}

/// Counts how many times `counter` advances over `window`, waiting the whole of it.
///
/// The window is waited out rather than cut short at the first good news, because the other client
/// has to be left unread for long enough to fall behind. Counting advances through the same window
/// is what makes this an assertion about order: while one client was not reading, another was
/// receiving.
async fn progress(counter: &Arc<std::sync::atomic::AtomicUsize>, window: Duration) -> usize {
    let deadline = Instant::now() + window;
    let mut seen = counter.load(std::sync::atomic::Ordering::Relaxed);
    let mut advances = 0;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = counter.load(std::sync::atomic::Ordering::Relaxed);
        if now > seen {
            advances += 1;
            seen = now;
        }
    }
    advances
}

/// How long a wait for something to arrive is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never arrives. Thirty
/// seconds was inside the range the slowest reference hosts reach when several suites share them,
/// which turned these waits into coin tosses; two minutes is outside it. The poll intervals are
/// unchanged, so a wait that succeeds costs what it always did, and each failure says how long it
/// actually waited. What the assertions themselves say is untouched.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Attaches a client to the session and subscribes it to output.
async fn attached(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
) -> (LocalClient, kr_protocol::ids::AttachmentId) {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
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
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id,
                attachment_id: attached.attachment.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
    (client, attached.attachment.attachment_id)
}
