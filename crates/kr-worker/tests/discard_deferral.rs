//! The discard of retained output while a write of that output to the spool is in flight.
//!
//! A person who turns privacy mode on must not have retained output read after the call answers,
//! and a write to the spool that does not return must not stop the worker. So the discard never
//! waits for the write: it leaves the output where it is, nothing can read it meanwhile, and it is
//! made by the task that saw the write end. What is proved here runs the real runtime, the real
//! pump and the real privacy call; the session's own cases are in `privacy.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_ipc::client::BoundLink;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    AttachmentId, BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::privacy::{PrivacyCompletion, PrivacyGenerationAck, PrivacyGenerationNotice};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::privacy::PrivacyGeneration;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

/// How long a step that must happen may take before the case says it did not.
const LIVENESS: Duration = Duration::from_secs(60);

/// The view the session's one attachment is, which holds the input lease.
const VIEW: AttachmentId = AttachmentId::new(Uuid::from_bytes([5; 16]));

struct Host {
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    epoch: u64,
    sequence: u64,
    _view: kr_worker::output::OutputStream,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: kr_ipc::testing::TempHost,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A session whose root shell prints `ready` and then echoes what it is typed, with one view that
/// holds the input lease. The worker serves the local endpoint only when `serve` says so: it is
/// what runs the host's maintenance, and a case about the pump runs without it.
async fn host(serve: bool) -> Host {
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
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("printf kr-ready; exec cat"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Geometry);
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    session.attach(&params, requested, VIEW).expect("attaches");
    let view = session.subscribe(VIEW).expect("subscribes");
    session
        .acquire_input(
            VIEW,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
            None,
        )
        .expect("takes the lease");
    let epoch = session.lease().epoch.get();
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    if serve {
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        tokio::spawn(Arc::clone(&service).serve(listener));
    }
    let host = Host {
        temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
        epoch,
        sequence: 0,
        _view: view,
    };
    common::produced(&host.runtime, b"kr-ready").await;
    host
}

/// The daemon's authority connection, speaking for generation one.
async fn authority(host: &Host) -> BoundLink {
    let role = ControllerConnectionRole::Authority;
    let mut client = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    client
        .send(&ControlFrame::ControllerRole(role))
        .await
        .expect("declares the role");
    match client.recv().await.expect("the worker answers") {
        ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
        other => panic!("the worker answered {other:?}"),
    }
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

/// Tells the session its privacy generation as the daemon does, and returns the answer.
async fn tell_privacy(
    host: &Host,
    authority: &mut BoundLink,
    generation: u64,
    enabled: bool,
) -> PrivacyGenerationAck {
    authority
        .send(&ControlFrame::PrivacyGeneration(PrivacyGenerationNotice {
            environment_id: host.environment_id,
            generation: U64::new(generation),
            enabled,
        }))
        .await
        .expect("writes the notice");
    loop {
        match tokio::time::timeout(LIVENESS, authority.recv())
            .await
            .expect("the worker answers in time")
            .expect("the worker answers")
        {
            ControlFrame::PrivacyGenerationAck(ack) => return *ack,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

impl Host {
    /// Types one byte into the terminal as the view holding the lease does. The terminal echoes
    /// it, and the pump records the echo.
    fn type_one(&mut self, byte: u8) {
        self.runtime
            .session()
            .write_input(
                VIEW,
                self.epoch,
                self.sequence,
                &[byte],
                None,
                std::time::Instant::now(),
            )
            .expect("the input is accepted");
        self.sequence += 1;
        self.runtime.flush_input();
    }

    /// Waits for the write of the output so far, then stops the next write of the pump's with the
    /// session let go, types a byte, and returns the end that lets the write go once that write is
    /// waiting on the disk.
    async fn with_a_write_in_flight(&mut self) -> std::sync::mpsc::Sender<()> {
        let runtime = Arc::clone(&self.runtime);
        tokio::task::spawn_blocking(move || runtime.wait_for_the_spool_write())
            .await
            .expect("the write so far is waited for");
        let (arrived, resume) = self.runtime.pause_in_next_spool_write();
        self.type_one(b'x');
        assert!(
            matches!(tokio::time::timeout(LIVENESS, arrived).await, Ok(Ok(()))),
            "the pump's write is waiting on the disk"
        );
        resume
    }

    /// The segment files the session's spool holds.
    fn segments(&self) -> usize {
        std::fs::read_dir(self.temp.environment().session_spool(self.session_id))
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "out"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Everything a reader of the session's history is told, from the start of the output.
    fn read(&self) -> (kr_protocol::recovery::HistoryPageResult, u64, u64) {
        let session = self.runtime.session();
        (
            session.history_page(0, 1024 * 1024).expect("a page"),
            session.oldest_retained_cursor(),
            session.retained_output_bytes(),
        )
    }
}

/// Lets the stopped write go, with `release`, after a while unless `done` says it is not needed,
/// and says whether it had to.
///
/// A regression leaves the stopped write holding what the case waits for, and then the case waits
/// for as long as the stop lasts. This lets the write go and says so, so that the case fails
/// naming the wait instead of waiting with it.
fn release_after_a_while(
    release: std::sync::mpsc::Sender<()>,
    done: &Arc<AtomicBool>,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
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
            let _ = release.send(());
        })
    };
    (let_go, thread)
}

/// Whether an answer lists the history as unavailable. The answer's other parts are the
/// attention store's, which a host with no daemon's attention connection leaves outstanding.
fn lists_history(completion: &PrivacyCompletion) -> bool {
    matches!(
        completion,
        PrivacyCompletion::Unavailable { unavailable, .. }
            if unavailable.iter().any(|one| one.subsystem == "history")
    )
}

/// Waits until the privacy call's first hold has raised the fence, which is what a case that lets
/// the write go next has to follow.
async fn until_privacy_is_on(host: &Host) {
    tokio::time::timeout(LIVENESS, async {
        while !host.runtime.session().privacy().is_enabled() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the privacy call took its first hold");
}

/// Waits until the session's own cleanup has nothing left to do.
async fn until_the_cleanup_is_done(host: &Host) {
    tokio::time::timeout(LIVENESS, async {
        while host.runtime.session().privacy_cleanup_failure().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the owed discard was made");
}

/// The discard that a write in flight left owed is made by the pump right after the write it was
/// waiting for, with no further output and no pass of maintenance (this host serves nothing, so
/// none runs): the pump's own task is what is left to do it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pump_makes_the_owed_discard_right_after_the_write_it_waited_for() {
    let mut host = host(false).await;
    let resume = host.with_a_write_in_flight().await;
    let (_, before_oldest, _) = host.read();
    assert_eq!(before_oldest, 0, "the output is read until privacy is on");

    // The privacy call's first hold, with the write in flight: it answers without waiting for it.
    let done = Arc::new(AtomicBool::new(false));
    let (let_go, watchdog) = release_after_a_while(resume.clone(), &done);
    let runtime = Arc::clone(&host.runtime);
    let enabling = tokio::task::spawn_blocking(move || {
        runtime
            .session()
            .enable_privacy(PrivacyGeneration::new(1), &mut [])
            .map(|_| ())
    })
    .await
    .expect("the first hold ends");
    done.store(true, Ordering::Release);
    watchdog.join().expect("the watchdog ends");
    enabling.expect("privacy is enabled");
    assert!(
        !let_go.load(Ordering::Acquire),
        "the discard waited for the write in flight until it was let go"
    );
    assert!(
        host.runtime.session().privacy_cleanup_failure().is_some(),
        "the discard is owed while the write is in flight"
    );
    let (page, oldest, retained) = host.read();
    assert!(page.bytes.as_slice().is_empty(), "no retained byte is read");
    assert_eq!((oldest, retained), (page.next_cursor.get(), 0));

    resume.send(()).expect("the write is let go");
    until_the_cleanup_is_done(&host).await;
    assert_eq!(host.segments(), 0, "the spool is emptied");
    assert_eq!(host.read().0, page, "what a reader is told did not change");
}

/// The privacy call answers complete when the write in flight ends inside its bound: the call
/// waits for it with nothing held, and its second hold makes the discard.
///
/// The pump is stopped between the end of its write and its own hold, and let go only after the
/// call's answer has been read, so the discard that the answer reports was made by the call's
/// second hold and by nobody else: a call with no second hold answers that the history is
/// unavailable, whichever of the two the scheduler runs first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_call_whose_write_ends_inside_its_bound_answers_complete() {
    let mut host = host(true).await;
    host.service
        .set_privacy_write_wait(Duration::from_secs(120));
    let mut authority = authority(&host).await;
    let resume = host.with_a_write_in_flight().await;
    let (pump_arrived, pump_go) = host.runtime.pause_after_next_spool_write();
    let letting_go = {
        let (runtime, resume) = (Arc::clone(&host.runtime), resume.clone());
        tokio::spawn(async move {
            while !runtime.session().privacy().is_enabled() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = resume.send(());
        })
    };
    let ack = tell_privacy(&host, &mut authority, 1, true).await;
    letting_go.await.expect("the write was let go");
    assert!(ack.enabled);
    assert!(
        !lists_history(&ack.completion),
        "the history is removed: {:?}",
        ack.completion
    );
    assert_eq!(host.segments(), 0);
    assert!(
        matches!(
            tokio::time::timeout(LIVENESS, pump_arrived).await,
            Ok(Ok(()))
        ),
        "the pump's write ended and the pump stood at its pause, so it made no discard"
    );
    pump_go.send(()).expect("the pump is let go");
}

/// At its bound the call answers with the completion that lists history as unavailable, and no
/// retained byte can be read. The notice the daemon sends again finds the discard done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_call_whose_write_outlasts_its_bound_lists_history_unavailable() {
    let mut host = host(true).await;
    host.service
        .set_privacy_write_wait(Duration::from_millis(50));
    let mut authority = authority(&host).await;
    let resume = host.with_a_write_in_flight().await;
    let ack = tell_privacy(&host, &mut authority, 1, true).await;
    assert!(ack.enabled);
    assert!(
        lists_history(&ack.completion),
        "the write is still in flight: {:?}",
        ack.completion
    );
    let (page, _, retained) = host.read();
    assert!(page.bytes.as_slice().is_empty(), "no retained byte is read");
    assert_eq!(retained, 0);

    resume.send(()).expect("the write is let go");
    until_the_cleanup_is_done(&host).await;
    let again = tell_privacy(&host, &mut authority, 1, true).await;
    assert!(
        !lists_history(&again.completion),
        "the notice sent again finds the history removed: {:?}",
        again.completion
    );
    assert_eq!(host.segments(), 0);
}

/// A pass of maintenance that finds the discard owed and a write in flight leaves it owed and ends:
/// it holds the dispatch barrier and the session for its own work, not for the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_maintenance_pass_with_a_write_in_flight_does_not_wait_for_it() {
    let mut host = host(false).await;
    let resume = host.with_a_write_in_flight().await;
    // The first hold, with the write in flight, under a watchdog that lets the write go if the hold
    // waits for it, so that a regression ends this case by a failed assertion and not by a limit.
    let enabled = Arc::new(AtomicBool::new(false));
    let (held_for_the_write, first_watchdog) = release_after_a_while(resume.clone(), &enabled);
    let runtime = Arc::clone(&host.runtime);
    let enabling = tokio::task::spawn_blocking(move || {
        runtime
            .session()
            .enable_privacy(PrivacyGeneration::new(1), &mut [])
            .map(|_| ())
    })
    .await
    .expect("the first hold ends");
    enabled.store(true, Ordering::Release);
    first_watchdog.join().expect("the watchdog ends");
    enabling.expect("privacy is enabled");
    assert!(
        !held_for_the_write.load(Ordering::Acquire),
        "the first hold waited for the write in flight until it was let go"
    );

    let done = Arc::new(AtomicBool::new(false));
    let (let_go, watchdog) = release_after_a_while(resume.clone(), &done);
    let service = Arc::clone(&host.service);
    tokio::task::spawn_blocking(move || service.maintain_now())
        .await
        .expect("the pass ends");
    done.store(true, Ordering::Release);
    watchdog.join().expect("the watchdog ends");
    assert!(
        !let_go.load(Ordering::Acquire),
        "the pass waited for the write in flight until it was let go"
    );
    assert!(
        host.runtime.session().privacy_cleanup_failure().is_some(),
        "the pass left the discard owed"
    );
    resume.send(()).expect("the write is let go");
    until_the_cleanup_is_done(&host).await;
}

/// Sustained output does not starve the discard: the output typed while the write is stopped waits
/// behind it, and the discard is made within one cycle of that output, by the pump's hold after the
/// write or by the appender's gate at the next batch, whichever meets it first, so that none of
/// that output is retained. The case does not tell the two apart: it proves the bound of one cycle,
/// and no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_discard_is_made_within_one_cycle_of_sustained_output() {
    let mut host = host(false).await;
    let resume = host.with_a_write_in_flight().await;
    let runtime = Arc::clone(&host.runtime);
    tokio::task::spawn_blocking(move || {
        runtime
            .session()
            .enable_privacy(PrivacyGeneration::new(1), &mut [])
            .map(|_| ())
    })
    .await
    .expect("the first hold ends")
    .expect("privacy is enabled");
    let ended = host.runtime.session().output_cursor();
    for byte in *b"abcdef" {
        host.type_one(byte);
    }
    until_privacy_is_on(&host).await;
    resume.send(()).expect("the write is let go");
    until_the_cleanup_is_done(&host).await;
    // The six bytes were echoed and taken in, behind the write, and kept by nobody.
    tokio::time::timeout(LIVENESS, async {
        while host.runtime.session().output_cursor() < ended + 6 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the output typed behind the write was taken in");
    assert_eq!(host.segments(), 0, "none of what followed was retained");
    assert_eq!(host.read().2, 0);
}
