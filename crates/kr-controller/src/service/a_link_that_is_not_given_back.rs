//! This daemon's link to a worker, given up whenever what it carried did not end whole.
//!
//! The link goes back into its slot only once the work it was taken for ended whole. Opened and
//! failed, an exchange over it that failed, or the future that held it dropped part way, it is
//! closed instead and the worker's lease stops renewing with it, before the slot is released; a
//! wait for the slot that runs out holds nothing and gives nothing up, and a complete answer, a
//! refusal included, leaves the link and the lease as they were.
//!
//! The worker here stalls: it proves itself, reads whatever arrives and answers none of it, so the
//! daemon's exchange is part way through until a test drops its future. A test knows the exchange
//! has begun by the frame reaching the worker, and learns what was given up from the daemon's own
//! records: the slot, the lease issuer and the next link the daemon opens.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ConnectionId, SessionId};
use kr_protocol::scalars::U64;

use super::a_close_a_worker_never_answers::{self as world, Silent};
use crate::service::Controller;

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a daemon that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// What a stalling worker has been sent.
#[derive(Debug, Default)]
struct Heard {
    /// Every frame after the handshake, in arrival order.
    frames: std::sync::Mutex<Vec<ControlFrame>>,
    /// How many connections it has accepted.
    connections: AtomicUsize,
}

impl Heard {
    fn frames(&self) -> usize {
        self.frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// An endpoint that proves itself as a worker, and then reads what it is sent and answers none of
/// it, so the connection stays open with an exchange part way through.
fn stalling(
    heard: Arc<Heard>,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                heard.connections.fetch_add(1, Ordering::SeqCst);
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let heard = Arc::clone(&heard);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let answers = world::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &kr_protocol::scalars::CanonicalSet::new(),
                        );
                        match answers {
                            Some(answers) => {
                                for answer in answers {
                                    if writer.write_message(&answer).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            None => heard
                                .frames
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(frame),
                        }
                    }
                });
            }
        })
    }
}

/// A daemon with one stalling worker in its directory, which has acknowledged the revision in
/// force, so its lease renews.
async fn stalled() -> (Silent, Arc<Heard>) {
    let heard = Arc::new(Heard::default());
    let silent = world::fake_world(stalling(Arc::clone(&heard))).await;
    world::acknowledged(&silent.controller, silent.session_id);
    (silent, heard)
}

/// Waits until `done` holds, and fails the test after [`WAIT`].
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Whether the daemon would give this worker a lease now.
fn leases(controller: &Controller, session_id: SessionId) -> bool {
    controller
        .leases
        .renew(session_id, controller.generation, &*controller.clock)
        .expect("a decision")
        .is_ok()
}

/// What the daemon holds in the worker's slot: a link, or nothing.
async fn slot_holds_a_link(controller: &Controller, session_id: SessionId) -> bool {
    let slot = Arc::clone(
        controller
            .connections
            .lock()
            .await
            .get(&session_id)
            .expect("the daemon has a slot for the worker"),
    );
    slot.lock().await.is_some()
}

/// Starts `work` as a task, waits until the worker has been sent `frames` frames, so that the
/// exchange is part way through, and drops the task's future.
async fn abandoned_part_way<F>(heard: &Heard, frames: usize, work: F)
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let task = tokio::spawn(work);
    until("the worker was sent the exchange", || {
        heard.frames() >= frames
    })
    .await;
    task.abort();
    assert!(
        task.await.is_err_and(|ended| ended.is_cancelled()),
        "the future was dropped part way through its exchange"
    );
}

/// What was given up, once an exchange that carried the worker's link was dropped part way:
/// the lease stopped renewing, the slot holds no link, and the next link the daemon opens is a
/// connection of its own, over which nothing of the abandoned exchange can arrive.
async fn the_link_was_given_up(silent: &Silent, heard: &Heard, connections_before: usize) {
    let controller = &silent.controller;
    assert!(
        controller.leases.is_fenced(silent.session_id),
        "the worker's lease stops renewing"
    );
    assert!(!leases(controller, silent.session_id));
    assert!(
        !slot_holds_a_link(controller, silent.session_id).await,
        "the link was closed and not put back"
    );
    let mut next = controller
        .worker_client(&silent.worker)
        .await
        .expect("the next caller opens a link of its own");
    assert_eq!(
        heard.connections(),
        connections_before + 1,
        "over a new connection"
    );
    next.give_back();
}

/// KR-REQ-09.12: a read of a session dropped while it waits for its answer closes the link and
/// stops the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let worker = silent.worker.clone();
    abandoned_part_way(&heard, 1, async move {
        controller.read_from_worker(&worker).await
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a read that runs out of patience while it waits for its answer closes the link and
/// stops the lease, as one dropped does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_runs_out_of_patience_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let refused = silent
        .controller
        .read_from_worker_within(&silent.worker, Some(Duration::from_millis(200)))
        .await
        .expect_err("the worker never answers");
    assert!(
        refused.to_string().contains("did not answer in time"),
        "{refused}"
    );
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: an announcement of an authority revision dropped while it waits for the worker's
/// acknowledgement closes the link and stops the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announcement_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    abandoned_part_way(&heard, 1, async move {
        controller.announce_authority_revision().await
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: the same for the later pages of the fence evidence the daemon asks the worker for
/// once its acknowledgement said names remain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_for_evidence_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    assert!(controller.leases.acknowledge(
        session_id,
        binding,
        revision,
        Some(kr_protocol::action::FenceEvidence {
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            remaining: U64::new(3),
            omitted: U64::ZERO,
        }),
    ));
    abandoned_part_way(&heard, 1, async move {
        controller
            .collect_owed_evidence(session_id, binding, revision)
            .await;
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a close dropped while it waits for the worker's answer closes the link and stops
/// the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let carried = world::admission(&controller, silent.accepted).await;
    let mutation = world::close_request(silent.environment_id, silent.session_id);
    let actor = silent.actor.clone();
    let accepted = silent.accepted;
    abandoned_part_way(&heard, 1, async move {
        controller
            .session_close(&mutation, &actor, Some(accepted), carried)
            .await
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: the daemon's own acknowledgement of a revision for one worker, dropped while it
/// waits, closes the link and stops the lease, before the slot is released: what stops the renewal
/// is the link's own loss, taken at the path it was on, and not a later look at the binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acknowledgement_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    abandoned_part_way(&heard, 1, async move {
        controller.acknowledge_worker_revision(session_id).await
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a privacy generation told to a worker that never answers closes the link and stops
/// the lease, and the daemon is not held across the exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_notice_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let daemon = Arc::downgrade(&silent.controller);
    let notice = crate::privacy::Notice {
        session_id: silent.session_id,
        generation: kr_worker::privacy::PrivacyGeneration::new(1),
        enabled: true,
    };
    abandoned_part_way(&heard, 1, async move {
        super::start::tell_privacy(&daemon, notice).await
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a round of plugin admissions dropped while it waits for the worker closes the link
/// and stops the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_round_of_admissions_dropped_part_way_gives_up_its_link() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    controller.plugin_bridge.recorded(
        session_id,
        silent.worker.descriptor.process_start_identity.clone(),
    );
    abandoned_part_way(&heard, 1, async move {
        controller.admissions_round(session_id).await;
    })
    .await;
    the_link_was_given_up(&silent, &heard, 1).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a link that cannot be opened is a failure of the path, and the lease stops
/// renewing with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_cannot_be_opened_stops_the_lease() {
    let (silent, _heard) = stalled().await;
    assert!(leases(&silent.controller, silent.session_id));
    // The endpoint goes: nothing accepts there any more.
    silent.serving.abort();
    let _ = silent.serving.await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while kr_ipc::endpoint::Connection::connect(&silent.worker.endpoint)
        .await
        .is_ok()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker's endpoint still accepts after {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let refused = silent
        .controller
        .worker_client(&silent.worker)
        .await
        .expect_err("no link can be opened to a worker that is not there");
    drop(refused);
    assert!(
        silent.controller.leases.is_fenced(silent.session_id),
        "the lease stops renewing"
    );
    assert!(!leases(&silent.controller, silent.session_id));
}

/// KR-REQ-09.12: a wait for the link that runs out holds nothing and gives nothing up. Another
/// operation has the link; a read that gives up waiting for it leaves that operation's link and the
/// lease as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wait_for_the_link_that_runs_out_gives_nothing_up() {
    let (silent, heard) = stalled().await;
    let mut elsewhere = silent
        .controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    let refused = silent
        .controller
        .read_from_worker_within(&silent.worker, Some(Duration::from_millis(100)))
        .await
        .expect_err("the link is not free");
    assert!(
        refused.to_string().contains("busy for too long"),
        "{refused}"
    );
    assert!(
        !silent.controller.leases.is_fenced(silent.session_id),
        "nothing was given up by a wait that ran out"
    );
    assert!(leases(&silent.controller, silent.session_id));
    assert!(
        elsewhere.holds_the_connection(),
        "the other operation keeps its link"
    );
    elsewhere.give_back();
    drop(elsewhere);
    assert!(slot_holds_a_link(&silent.controller, silent.session_id).await);
    assert_eq!(heard.connections(), 1, "one link served both");
    silent.serving.abort();
}

/// KR-REQ-09.12: a worker's complete answer is a whole exchange, a refusal included, and its link
/// goes back and the lease renews. A close the worker refuses is the case: the worker answers it
/// at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_worker_gives_leaves_its_link_and_the_lease() {
    let recorded: world::Recorded = Arc::default();
    let silent = world::fake_worker(Some(Arc::clone(&recorded))).await;
    world::acknowledged(&silent.controller, silent.session_id);
    let controller = &silent.controller;
    let carried = world::admission(controller, silent.accepted).await;

    let refused = controller
        .session_close(
            &world::close_request(silent.environment_id, silent.session_id),
            &silent.actor,
            Some(silent.accepted),
            carried,
        )
        .await
        .expect_err("the worker refuses the close");
    assert!(!refused.to_string().is_empty());
    assert!(
        !controller.leases.is_fenced(silent.session_id),
        "a complete answer gave nothing up"
    );
    assert!(leases(controller, silent.session_id));
    assert!(
        slot_holds_a_link(controller, silent.session_id).await,
        "the link is kept for the next caller"
    );
    silent.serving.abort();
}

/// A daemon and a real worker that serves its session, bound to this daemon's generation and
/// listed in its directory as a worker that has reported itself is. The worker has acknowledged the
/// revision in force, so its lease renews.
///
/// The worker runs on a runtime of its own, which every task it starts belongs to, so that letting
/// the fixture go ends them all together. The worker is stopped before the daemon is let go, and
/// the daemon before the tree they share.
pub(super) struct Served {
    /// Declared first, so the worker is stopped before anything else is let go.
    _stopping: Stopping,
    pub(super) controller: Arc<Controller>,
    pub(super) worker: crate::directory::KnownWorker,
    pub(super) session_id: SessionId,
    /// Declared last, so the tree is removed after the fixture's own handles to it are gone.
    _temp: kr_ipc::testing::TempHost,
}

/// What stops the worker of a [`Served`] when the fixture goes.
struct Stopping {
    service: Arc<kr_worker::service::WorkerService>,
    worker_runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Stopping {
    /// Signals the shell the worker runs to stop, and then ends every task of the worker and waits
    /// for them to be gone, whether the test ended or failed, so that the worker's session no
    /// longer holds the tree when it is removed. The shell is not waited for: the worker offers
    /// nothing that joins its child, so it may stay unreaped until the test process ends, as with
    /// the other fixtures that run a real worker. A poisoned session lock means the worker has
    /// already panicked: the shell is then not signalled.
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut session = self.service.runtime().session();
            let _ = session.request_stop();
            let _ = session.force_close();
        }));
        // Dropped on a thread of its own, because a runtime may not be dropped inside the context
        // of another. Dropping it waits for every task and thread of the worker to be gone, with no
        // bound, so the tree is never released while the worker still holds it. Nothing on this
        // fixture's path runs blocking work that does not end.
        if let Some(runtime) = self.worker_runtime.take() {
            std::thread::scope(|scope| {
                scope.spawn(move || drop(runtime));
            });
        }
    }
}

impl Served {
    pub(super) async fn start() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = Controller::start(world::setup(&temp))
            .await
            .expect("the daemon starts");
        let identity = Self::identity_of(&controller, SessionId::new(kr_ipc::new_uuid()));
        Self::serving(
            temp,
            controller,
            identity,
            kr_protocol::session::DisplayNumber::new(1),
        )
        .await
    }

    /// A daemon and a real worker, with the reservation the worker was started for: claimed, as
    /// one is once its worker has been admitted, and with the worker not yet in the directory, as a
    /// daemon that has not found it yet holds it.
    pub(super) async fn claimed() -> (Self, kr_protocol::worker::ReservationId) {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = Controller::start(world::setup(&temp))
            .await
            .expect("the daemon starts");
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let mut identity = None;
        let reservation = super::a_create_that_launches_nothing::seed_claim_as(
            &controller,
            &actor_id,
            kr_protocol::identity::WorkerProfile::HeadlessUser,
            |reservation| {
                let made = Self::identity_of(&controller, reservation.session_id);
                let key = *made.public_key();
                identity = Some(made);
                key
            },
        )
        .await;
        let world = Self::serving(
            temp,
            controller,
            identity.expect("the worker was made for its claim"),
            reservation.display_number,
        )
        .await;
        world
            .controller
            .directory
            .lock()
            .await
            .remove(world.session_id);
        (world, reservation.reservation_id)
    }

    /// The identity a worker of `session_id` has under `controller`'s boot.
    fn identity_of(controller: &Controller, session_id: SessionId) -> Arc<WorkerIdentity> {
        Arc::new(
            WorkerIdentity::generate(
                session_id,
                kr_protocol::ids::SessionEpoch::V1,
                controller.boot_identity.clone(),
                kr_ipc::identity::current_process_start_identity().expect("a process identity"),
                kr_protocol::hello::PROTOCOL_VERSION,
            )
            .expect("a session key"),
        )
    }

    /// A hold on a reservation of no session, for a test that makes the daemon publish this worker
    /// with neither a report nor a recovery to have taken one.
    pub(super) async fn held(&self) -> super::recovery::ReservationHold {
        self.controller
            .hold_reservation(kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()))
            .await
    }

    /// Serves a real worker for `identity` on the endpoint of `display_number`, in the directory of
    /// `controller`, with the revision in force acknowledged.
    async fn serving(
        temp: kr_ipc::testing::TempHost,
        controller: Arc<Controller>,
        identity: Arc<WorkerIdentity>,
        display_number: kr_protocol::session::DisplayNumber,
    ) -> Self {
        use kr_protocol::ids::SessionEpoch;

        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let session_id = identity.session_id();
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let worker_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime of the worker's own");
        let (service, endpoint) = {
            let identity = Arc::clone(&identity);
            let environment = environment.clone();
            let boot_identity = controller.boot_identity.clone();
            let controller_public_key = *controller.identity.public_key();
            let controller_generation = controller.generation;
            let build_id = controller.build_id.clone();
            worker_runtime
                .spawn(async move {
                    let mut session =
                        kr_worker::session::Session::open(kr_worker::session::SessionConfig {
                            session_id,
                            session_epoch: SessionEpoch::V1,
                            environment_id,
                            display_number,
                            shell: kr_worker::testing::posix_script("exec cat"),
                            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
                            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                            desktop: kr_protocol::identity::DesktopBinding::none(),
                            dimensions: kr_protocol::session::Dimensions::new(80, 24),
                            journal_path: Some(journal_path.clone()),
                            spool_directory: Some(environment.session_spool(session_id)),
                            worker_endpoint: None,
                            send_queue_bytes: 1024 * 1024,
                            resident_bytes: 64 * 1024,
                            time: kr_worker::action::time::TimeSources::system(),
                            launch_profile: kr_protocol::session::LaunchProfile::default(),
                        })
                        .expect("opens the session");
                    session.launch().expect("launches the shell");
                    let runtime = Arc::new(
                        kr_worker::runtime::SessionRuntime::start(
                            session,
                            Arc::new(kr_ipc::clock::SystemSharedClock),
                        )
                        .expect("starts the runtime"),
                    );
                    let endpoint = environment
                        .worker_endpoint(display_number)
                        .expect("an endpoint");
                    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
                    let service = Arc::new(
                        kr_worker::service::WorkerService::new(
                            runtime,
                            identity,
                            endpoint.clone(),
                            kr_worker::service::ServiceBinding {
                                environment_id,
                                boot_identity,
                                controller_public_key,
                                controller_generation,
                                journal_path: Some(journal_path),
                                build_id,
                            },
                        )
                        .expect("a worker service"),
                    );
                    tokio::spawn(Arc::clone(&service).serve(listener));
                    (service, endpoint)
                })
                .await
                .expect("the worker is started")
        };
        let worker = crate::directory::KnownWorker {
            descriptor: kr_protocol::worker::WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number,
                boot_identity: identity.boot_identity().clone(),
                process_start_identity: identity.process_start_identity().clone(),
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: *identity.public_key(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                published_at_ms: kr_ipc::now_ms(),
            },
            endpoint,
        };
        controller
            .directory
            .lock()
            .await
            .insert(worker.clone(), None);
        world::acknowledged(&controller, session_id);
        Self {
            _stopping: Stopping {
                service,
                worker_runtime: Some(worker_runtime),
            },
            controller,
            worker,
            session_id,
            _temp: temp,
        }
    }

    /// A daemon and a real worker, with the row the registry holds of a worker it has recorded.
    pub(super) async fn recorded() -> Self {
        let world = Self::start().await;
        world
            .controller
            .registry
            .lock()
            .await
            .adopt_worker(
                &world.row(),
                // A headless worker is bound to no desktop.
                Some(&kr_protocol::identity::DesktopBinding::none()),
            )
            .expect("the registry records the worker");
        world
    }

    /// The registry's row for the worker.
    pub(super) fn row(&self) -> crate::registry::WorkerRecord {
        let descriptor = &self.worker.descriptor;
        crate::registry::WorkerRecord {
            session_id: self.session_id,
            display_number: descriptor.display_number,
            public_key: descriptor.worker_public_key,
            process_identity: descriptor.process_start_identity.clone(),
            endpoint: descriptor.endpoint.clone(),
            profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            state: kr_protocol::session::SessionState::Live,
            acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
        }
    }

    /// Whether the registry has a closure recorded for the session.
    pub(super) async fn has_a_closure(&self) -> bool {
        self.controller
            .registry
            .lock()
            .await
            .closure(self.session_id)
            .expect("the registry answers")
            .is_some()
    }

    /// The same worker, still running, with a daemon that is started again on the environment
    /// after the first has let go of it: what the first left in the registry and on disk is all the
    /// second has to go by, as a daemon that starts finds its workers.
    pub(super) async fn restarted(self) -> Self {
        let Self {
            _stopping,
            controller,
            worker,
            session_id,
            _temp,
        } = self;
        drop(controller);
        let controller = crate::testing::taken_over(|| Controller::start(world::setup(&_temp)))
            .await
            .expect("the daemon starts again");
        Self {
            _stopping,
            controller,
            worker,
            session_id,
            _temp,
        }
    }

    /// A control daemon of the next generation takes the worker over, which fences every
    /// connection of this daemon's generation. Returns its connection, which holds the worker.
    pub(super) async fn a_newer_generation_takes_over(&self) -> kr_ipc::client::LocalClient {
        let controller = &self.controller;
        let mut client = kr_ipc::client::LocalClient::connect(
            &self.worker.endpoint,
            kr_protocol::local::LocalClientKind::Controller,
            controller.build_id.clone(),
        )
        .await
        .expect("connects");
        let newer = kr_protocol::ids::ControllerGeneration::new(controller.generation.get() + 1);
        let boot = controller.boot_identity.clone();
        let identity = &controller.identity;
        client
            .present_generation(|nonce| {
                identity
                    .generation_token(newer, &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .expect("the worker accepts the newer generation");
        client
    }
}

/// KR-REQ-09.12: a worker that a newer control daemon has taken over refuses the old daemon's link
/// as a link that no longer speaks for it. The answer is a complete one, and still the link is
/// closed and not put back and the worker's lease stops renewing, where an ordinary refusal
/// ([`a_refusal_the_worker_gives_leaves_its_link_and_the_lease`]) leaves both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_a_newer_generation_fenced_is_given_up_with_the_lease() {
    let served = Served::start().await;
    let controller = &served.controller;
    let mut link = controller
        .worker_client(&served.worker)
        .await
        .expect("the daemon opens its link");
    link.give_back();
    drop(link);
    assert!(leases(controller, served.session_id), "the lease renews");
    assert!(slot_holds_a_link(controller, served.session_id).await);

    let _newer = served.a_newer_generation_takes_over().await;

    let refused = controller
        .read_from_worker(&served.worker)
        .await
        .expect_err("the worker refuses the old daemon's link");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        controller.leases.is_fenced(served.session_id),
        "the worker's lease stops renewing"
    );
    assert!(!leases(controller, served.session_id));
    assert!(
        !slot_holds_a_link(controller, served.session_id).await,
        "the link was closed and not put back"
    );
}

/// An endpoint that proves itself as a worker and answers the handshake, and ends its side of every
/// connection once `close` is raised, counting each it ended.
///
/// Each connection watches `close` from the moment it is accepted, so raising it is seen by a
/// connection that is between two frames as well as by one that is waiting for the next.
fn closing(
    close: Arc<tokio::sync::watch::Sender<bool>>,
    ended: Arc<AtomicUsize>,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let mut closed = close.subscribe();
                let ended = Arc::clone(&ended);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    loop {
                        tokio::select! {
                            _ = closed.changed() => break,
                            read = reader.read_message::<ControlFrame>() => {
                                let Ok(frame) = read else { break };
                                let answers = world::handshake(
                                    &frame,
                                    &identity,
                                    &endpoint_text,
                                    connection_id,
                                    &peer,
                                    &kr_protocol::scalars::CanonicalSet::new(),
                                );
                                for answer in answers.into_iter().flatten() {
                                    if writer.write_message(&answer).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    drop((reader, writer));
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
        })
    }
}

/// KR-REQ-09.12: the notice that a caller has its acceptance is written over the link the daemon
/// holds, and a link that takes it whole is kept with the lease. A worker with no link is not
/// opened one for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delivery_confirmed_over_a_link_that_takes_it_keeps_the_link_and_the_lease() {
    let (silent, heard) = stalled().await;
    let controller = &silent.controller;
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());

    controller.confirm_delivery(action_id).await;
    assert_eq!(heard.connections(), 0, "no link is opened to be told");
    assert_eq!(heard.frames(), 0);

    let mut link = controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    link.give_back();
    drop(link);
    controller.confirm_delivery(action_id).await;
    until("the worker was told", || heard.frames() >= 1).await;
    assert!(
        !controller.leases.is_fenced(silent.session_id),
        "a notice that was taken gave nothing up"
    );
    assert!(leases(controller, silent.session_id));
    assert!(slot_holds_a_link(controller, silent.session_id).await);
    assert_eq!(heard.connections(), 1, "over the link it had");
    silent.serving.abort();
}

/// KR-REQ-09.12: a link the notice cannot be written to is given up with the lease, and the next
/// caller opens a link of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delivery_that_cannot_be_written_gives_up_its_link() {
    let close = Arc::new(tokio::sync::watch::channel(false).0);
    let ended = Arc::new(AtomicUsize::new(0));
    let silent = world::fake_world(closing(Arc::clone(&close), Arc::clone(&ended))).await;
    world::acknowledged(&silent.controller, silent.session_id);
    let controller = &silent.controller;
    let mut link = controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    link.give_back();
    drop(link);
    assert!(leases(controller, silent.session_id));

    // The worker ends its side of the connection; the daemon holds a link to nothing.
    close.send_replace(true);
    until("the worker ended its side", || {
        ended.load(Ordering::SeqCst) >= 1
    })
    .await;
    // A write to a socket is refused only once nothing holds its other end, and a process another
    // test has forked a moment ago holds a copy of every descriptor this one has open until it runs
    // its program. So the worker having dropped its connection does not yet make a write to it
    // fail, and the notice is asked for once the daemon's own read of the link says the worker is
    // gone.
    assert!(
        slot_holds_a_link(controller, silent.session_id).await,
        "the daemon's link to the worker is still in its slot"
    );
    let mut link = controller
        .worker_client(&silent.worker)
        .await
        .expect("the slot's link is taken");
    tokio::time::timeout(WAIT, link.client().recv())
        .await
        .expect("the daemon's link learns that its worker has gone")
        .expect_err("a worker that ended its side sends nothing more");
    link.give_back();
    drop(link);
    controller
        .confirm_delivery(kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()))
        .await;
    assert!(
        controller.leases.is_fenced(silent.session_id),
        "the lease stops renewing"
    );
    assert!(!leases(controller, silent.session_id));
    assert!(
        !slot_holds_a_link(controller, silent.session_id).await,
        "the link was closed and not put back"
    );
    silent.serving.abort();
}

/// What a wait for the link that runs out leaves: no worker given up, the link the other operation
/// holds still its own, and the lease issuer's path as it was.
async fn nothing_given_up_by_a_wait_that_ran_out(
    silent: &Silent,
    mut elsewhere: super::workers::WorkerLink,
) {
    assert!(
        !silent.controller.leases.is_fenced(silent.session_id),
        "nothing was given up by a wait that ran out"
    );
    assert!(
        elsewhere.holds_the_connection(),
        "the other operation keeps its link"
    );
    elsewhere.give_back();
}

/// KR-REQ-09.12: an announcement whose wait for the link runs out, because another operation holds
/// it, gives up no path: the worker is reported pending, as a worker that did not answer is, and
/// the control path in force stays what it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announcement_whose_wait_for_the_link_runs_out_gives_nothing_up() {
    let (silent, _heard) = stalled().await;
    let elsewhere = silent
        .controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    let barrier = silent
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement reports");
    assert!(
        !barrier.holds() && barrier.pending() == vec![silent.session_id],
        "the worker is pending: {barrier:?}"
    );
    nothing_given_up_by_a_wait_that_ran_out(&silent, elsewhere).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a request for the later pages of fence evidence whose wait for the link runs out
/// gives up no path either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_for_evidence_whose_wait_for_the_link_runs_out_gives_nothing_up() {
    let (silent, _heard) = stalled().await;
    let controller = &silent.controller;
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    assert!(controller.leases.acknowledge(
        session_id,
        binding,
        revision,
        Some(kr_protocol::action::FenceEvidence {
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            remaining: U64::new(3),
            omitted: U64::ZERO,
        }),
    ));
    let elsewhere = controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    controller
        .collect_owed_evidence(session_id, binding, revision)
        .await;
    nothing_given_up_by_a_wait_that_ran_out(&silent, elsewhere).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: the daemon's acknowledgement of a revision for one worker, whose wait for the link
/// runs out, gives up no path: it has not asked the worker anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acknowledgement_whose_wait_for_the_link_runs_out_gives_nothing_up() {
    let (silent, heard) = stalled().await;
    let elsewhere = silent
        .controller
        .worker_client(&silent.worker)
        .await
        .expect("the daemon opens its link to the worker");
    let refused = silent
        .controller
        .acknowledge_worker_revision(silent.session_id)
        .await
        .expect_err("the worker has not acknowledged anything");
    drop(refused);
    assert_eq!(heard.frames(), 0, "the worker was asked nothing");
    nothing_given_up_by_a_wait_that_ran_out(&silent, elsewhere).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: what a link gives up is the control path in force when it was taken. An
/// announcement that bound the worker to a path before another operation took the link, and then
/// waits behind it, has that path given up with the link when the operation's exchange does not end
/// whole: the acknowledgement it then gets over the link it opens is refused, and the worker is
/// reported pending until the next announcement, which fails safe. Bound after the link was taken
/// the path is a later one, which the loss leaves alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_path_an_announcement_bound_before_a_link_was_taken_is_given_up_with_it() {
    let (silent, _heard) = stalled().await;
    let controller = &silent.controller;
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();

    // The announcement binds the worker to a path, as it does before it asks for the link.
    let announced_over = controller.leases.bind(session_id);
    // Another operation takes the link, reading the path in force, and its exchange does not end
    // whole: the link is dropped with its work not done.
    let link = controller
        .worker_client(&silent.worker)
        .await
        .expect("the other operation takes the link");
    drop(link);
    assert!(
        controller.leases.is_fenced(session_id),
        "that path was given up with the link"
    );
    // The announcement's acknowledgement over the link it then opens is about the path it bound.
    assert!(
        !controller
            .leases
            .acknowledge(session_id, announced_over, revision, None),
        "its acknowledgement is refused"
    );
    let report = controller
        .leases
        .begin_round()
        .report(revision, [session_id]);
    assert!(
        !report.holds() && report.pending() == vec![session_id],
        "and the worker is pending: {report:?}"
    );

    // The next announcement binds a new path and is accepted.
    let next = controller.leases.bind(session_id);
    assert!(
        controller
            .leases
            .acknowledge(session_id, next, revision, None)
    );
    assert!(leases(controller, session_id));
    silent.serving.abort();
}
