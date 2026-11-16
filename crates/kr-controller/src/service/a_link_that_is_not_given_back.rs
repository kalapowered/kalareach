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
use kr_protocol::ids::{AuthorityRevision, ConnectionId, SessionId};
use kr_protocol::scalars::U64;
use kr_transport::lease::WorkerBinding;

use super::a_close_a_worker_never_answers::{self as world, Silent};
use super::barrier::{Asked, PASS_ASK_BOUND};
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
    /// How long an answering worker ([`answering`]) takes over the acknowledgement of each
    /// announcement it is sent from now on, in the order they arrive. It answers at once when none
    /// is left.
    delays: std::sync::Mutex<std::collections::VecDeque<Duration>>,
    /// What an answering worker ([`answering`]) waits for before it answers each announcement it is
    /// sent from now on, in the order they arrive: the gate opens, or its end is dropped, and the
    /// worker goes on to its pause. It goes straight to the pause when none is left.
    gates: std::sync::Mutex<std::collections::VecDeque<tokio::sync::oneshot::Receiver<()>>>,
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

/// An endpoint that proves itself as a worker and acknowledges each announcement it is sent, after
/// the pause that [`Heard::delays`] holds for it, with a fence that names nothing and has nothing
/// more to say. It answers nothing else.
fn answering(
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
                        if let Some(answers) = answers {
                            for answer in answers {
                                if writer.write_message(&answer).await.is_err() {
                                    return;
                                }
                            }
                            continue;
                        }
                        let announced = match &frame {
                            ControlFrame::AuthorityRevision(notice) => Some(notice.revision),
                            _ => None,
                        };
                        heard
                            .frames
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(frame);
                        let Some(revision) = announced else {
                            continue;
                        };
                        let gate = heard
                            .gates
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .pop_front();
                        let pause = heard
                            .delays
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .pop_front()
                            .unwrap_or_default();
                        if let Some(gate) = gate {
                            let _ = gate.await;
                        }
                        tokio::time::sleep(pause).await;
                        let ack = ControlFrame::AuthorityRevisionAck(
                            kr_protocol::worker::AuthorityRevisionAck {
                                session_id: identity.session_id(),
                                revision,
                                fence: Some(evidence(0)),
                            },
                        );
                        if writer.write_message(&ack).await.is_err() {
                            return;
                        }
                    }
                });
            }
        })
    }
}

/// A daemon with one answering worker in its directory ([`answering`]), which has acknowledged the
/// revision in force, so its lease renews.
async fn answered() -> (Silent, Arc<Heard>) {
    let heard = Arc::new(Heard::default());
    let silent = world::fake_world_reached(answering(Arc::clone(&heard))).await;
    world::acknowledged(&silent.controller, silent.session_id);
    (silent, heard)
}

/// A daemon with one stalling worker in its directory, which has acknowledged the revision in
/// force, so its lease renews.
///
/// The daemon has the worker on record as one its publisher sends no statement of what the host's
/// local owner may do, before it lists the worker. A worker not yet reached is one the publisher
/// goes to by itself, on its own schedule, and the link it opens and gives back would land in the
/// slot while a case looks at what the slot holds.
async fn stalled() -> (Silent, Arc<Heard>) {
    let heard = Arc::new(Heard::default());
    let silent = world::fake_world_reached(stalling(Arc::clone(&heard))).await;
    world::acknowledged(&silent.controller, silent.session_id);
    (silent, heard)
}

/// Stops the daemon's evidence pass before its next pass does anything, waits until it has stopped
/// there, and returns the end that lets it go. The pass stays stopped for as long as that end is
/// kept, so a case keeps it until its last assertion.
///
/// The pass is the daemon's own, and it runs by itself every few seconds: it asks the workers that
/// owe names for them, and asks the workers that have not acknowledged the revision in force. A
/// frame that it sends to a case's worker is counted as one of the case's, or takes a gate meant
/// for the case's own ask. Holding a round stops only the pass's collection of names; its asks of
/// pending workers go on. So a case whose worker owes names or is pending stops the whole pass,
/// before it makes the worker one or the other.
async fn without_an_evidence_pass(controller: &Controller) -> tokio::sync::oneshot::Sender<()> {
    let (arrived, release) = controller.stop_before_an_evidence_pass_for_tests();
    tokio::time::timeout(WAIT, arrived)
        .await
        .expect("a pass of the daemon began")
        .expect("the pass says that it has arrived");
    release
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
        controller.read_from_worker_within(&worker, None).await
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
    let _pass = without_an_evidence_pass(&silent.controller).await;
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
            .collect_owed_evidence(session_id, binding, revision, None)
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
            .into_answer_for_test()
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
        .into_answer_for_test()
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

/// What is left of a [`Served`] once its daemon is taken from it ([`Served::into_daemon`]): the
/// worker, stopped before the tree they share is removed.
pub(super) struct Standing {
    /// Declared first, so the worker is stopped before anything else is let go.
    _stopping: Stopping,
    /// Declared last, so the tree is removed after the worker's handles to it are gone.
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

    /// The worker's service, so that a test can read what the worker holds.
    pub(super) fn service(&self) -> &Arc<kr_worker::service::WorkerService> {
        &self._stopping.service
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

    /// Leaves the daemon holding nothing of the worker, as a daemon that has not found it yet holds
    /// it: no entry in the directory and no slot in the connection table.
    ///
    /// The daemon's own tasks open the slot of a worker the directory lists as soon as they have a
    /// reason to, and this fixture lists its worker from the start. A fixture that took only the
    /// directory entry could be left with a slot one of them opened in between, which nothing but a
    /// closure's own tidying removes. A slot is made only while the directory lists the worker, and
    /// the directory is taken first, so none can be made once it is out.
    pub(super) async fn forget_the_worker(&self) {
        self.controller
            .directory
            .lock()
            .await
            .remove(self.session_id);
        self.controller
            .connections
            .lock()
            .await
            .remove(&self.session_id);
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
            level: kr_protocol::retained::Level::this(),
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

    /// The daemon, apart from what keeps the rest of the fixture standing: the worker, and the tree
    /// they share, until the returned [`Standing`] is dropped.
    pub(super) fn into_daemon(self) -> (Arc<Controller>, Standing) {
        let Self {
            _stopping,
            controller,
            _temp,
            ..
        } = self;
        (controller, Standing { _stopping, _temp })
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
    pub(super) async fn a_newer_generation_takes_over(&self) -> kr_ipc::client::BoundLink {
        let controller = &self.controller;
        let mut client =
            kr_ipc::client::BoundLink::connect(&self.worker.endpoint, controller.build_id.clone())
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
        .read_from_worker_within(&served.worker, None)
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
///
/// The daemon has the worker on record as one its publisher sends no statement of what the host's
/// local owner may do, before it lists the worker. A worker not yet reached is one the publisher
/// goes to by itself, and it would take the link over and tell the worker again while this case
/// has the worker end its side: the write that fails would then be the publisher's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delivery_that_cannot_be_written_gives_up_its_link() {
    let close = Arc::new(tokio::sync::watch::channel(false).0);
    let ended = Arc::new(AtomicUsize::new(0));
    let silent = world::fake_world_reached(closing(Arc::clone(&close), Arc::clone(&ended))).await;
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
    let _pass = without_an_evidence_pass(controller).await;
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
        .collect_owed_evidence(session_id, binding, revision, None)
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

/// The evidence of a worker's fence that names nothing and says `remaining` more names are to come.
fn evidence(remaining: u64) -> kr_protocol::action::FenceEvidence {
    kr_protocol::action::FenceEvidence {
        rejected_actions: Vec::new(),
        possibly_executed: Vec::new(),
        remaining: U64::new(remaining),
        omitted: U64::ZERO,
    }
}

/// A worker whose last result reads revisions it has not been asked about, as the daemon holds it
/// after this sequence: the announcements of the `older` revisions were refused for the moment and
/// the worker fenced them by itself, and the announcement of revision 5 was acknowledged with
/// evidence that was whole. The result of 5 reads the older ones, of which the daemon has no
/// report. Returns the worker's binding, the revision acknowledged and the older ones.
fn after_refusals_and_a_whole_acknowledgement(
    controller: &Controller,
    session_id: SessionId,
    older: &[u64],
) -> (WorkerBinding, AuthorityRevision, Vec<AuthorityRevision>) {
    let binding = controller.leases.binding(session_id);
    let held = AuthorityRevision::new(2);
    let older: Vec<AuthorityRevision> = older.iter().copied().map(AuthorityRevision::new).collect();
    let newer = AuthorityRevision::new(5);
    for revision in &older {
        controller.leases.announced(session_id, held, &[*revision]);
    }
    controller.leases.announced(session_id, held, &[newer]);
    assert!(
        controller
            .leases
            .acknowledge_announced(session_id, binding, newer, Some(evidence(0))),
        "the acknowledgement of the newer revision is accepted"
    );
    assert_eq!(
        controller.leases.unasked_before(session_id, newer),
        older,
        "the result of the newer revision reads the ones the worker was not asked about"
    );
    (binding, newer, older)
}

/// KR-REQ-09.12: the waits before an ask's first exchange count against the ask's bound, and an
/// exchange that would get less than one exchange's time does not begin.
///
/// Another operation holds the registry, which the ask reads before anything goes to the worker,
/// for six of the ask's eight seconds. The announcement would begin with two seconds left, inside
/// the five an exchange may take, and a bound that cut it would drop the link with the
/// announcement on the wire: a link that goes out of its holder's hand stops the renewal of the
/// lease of a worker that has acknowledged before. So nothing is sent, and the link, opened for
/// it, goes back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_whose_waits_left_too_little_time_for_its_first_exchange_sends_nothing() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let registry = controller.registry.lock().await;
    let (asked, ()) = tokio::join!(
        tokio::time::timeout_at(
            deadline,
            controller.ask_worker_revision(session_id, Some(deadline)),
        ),
        async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            drop(registry);
        },
    );
    let asked = asked.expect("the ask ended by itself, before its bound could cut anything");
    assert_eq!(
        asked.unwrap_or(Asked::Failed),
        Asked::Failed,
        "an ask that could not begin its exchange has run out"
    );
    assert_eq!(heard.frames(), 0, "nothing was sent to the worker");
    assert!(
        !controller.leases.is_fenced(session_id),
        "the renewal of the worker's lease was not stopped"
    );
    assert!(leases(&controller, session_id));
    assert!(
        slot_holds_a_link(&controller, session_id).await,
        "the link went back whole"
    );
    assert_eq!(heard.connections(), 1);
    silent.serving.abort();
}

/// KR-REQ-09.12: the first exchange of an ask has its own time limit end at or before the instant
/// the caller's bound ends.
///
/// The ask is given seven seconds and nothing else ends it: the worker never answers, and no
/// timeout stands around the ask. The exchange begins, with time for one, and is over when the
/// seven seconds are, not after the ten an exchange has when no caller bounds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_exchange_of_an_ask_ends_by_the_deadline_it_was_given() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let began = tokio::time::Instant::now();
    let asked = controller
        .ask_worker_revision(session_id, Some(began + Duration::from_secs(7)))
        .await;
    let lasted = began.elapsed();
    assert_eq!(
        heard.frames(),
        1,
        "the announcement went: time was left for it"
    );
    assert!(
        lasted < Duration::from_secs(8),
        "the ask ended {lasted:?} after it began, past the seven seconds it was given"
    );
    assert_eq!(
        asked.unwrap_or(Asked::Failed),
        Asked::Failed,
        "the worker did not answer"
    );
    silent.serving.abort();
}

/// KR-REQ-09.12: a collection that waited for the worker's link while another operation held it
/// gives the link back whole when too little time is left once it has it.
///
/// The other holder keeps the link until two seconds before the ask's end, inside the five the wait
/// may take, and then lets it go. The check that gives the link back comes after the wait, so it
/// sees the time that the wait took: no page goes, the link is in its slot, the worker's lease goes
/// on renewing, and the names that were not asked for stay owed to the pass that collects them.
///
/// The case holds a round while it runs, as an announcement does, and takes it before the
/// acknowledgement that makes the worker owe names, so that the daemon's own pass, which gives way to
/// one, does not collect those names while the case waits and send a page of its own to the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_whose_wait_for_the_link_left_too_little_time_gives_the_link_back_whole() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    let _round = controller.leases.begin_round();
    assert!(
        controller
            .leases
            .acknowledge(session_id, binding, revision, Some(evidence(3)))
    );
    let mut elsewhere = controller
        .worker_client(&silent.worker)
        .await
        .expect("another operation takes the worker's link");
    let until = tokio::time::Instant::now() + Duration::from_secs(6);
    tokio::join!(
        controller.collect_owed_evidence(session_id, binding, revision, Some(until)),
        async {
            tokio::time::sleep(Duration::from_secs(4)).await;
            elsewhere.give_back();
            drop(elsewhere);
        },
    );
    assert_eq!(heard.frames(), 0, "no page went to the worker");
    assert!(
        !controller.leases.is_fenced(session_id),
        "the renewal of the worker's lease was not stopped"
    );
    assert!(leases(&controller, session_id));
    assert!(
        slot_holds_a_link(&controller, session_id).await,
        "the link is back in its slot"
    );
    assert_eq!(
        controller.leases.owing_names(),
        vec![session_id],
        "the names that were not asked for stay owed"
    );
    silent.serving.abort();
}

/// KR-REQ-09.12: a collection with too little time left does not wait for the link once for each
/// older revision it would ask about.
///
/// Another operation holds the link throughout. Two older revisions that the results read and the
/// worker was not asked about, and then two whose pages are still owed, would each wait five
/// seconds for it; with two seconds of the ask left, each returns at once.
///
/// The daemon's own pass is not held: it collects names at the registry's revision, which no
/// revision of this case's reports reaches, so it sends this worker nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_with_too_little_time_left_does_not_wait_for_the_link_for_each_older_revision()
{
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let (binding, newer, _older) =
        after_refusals_and_a_whole_acknowledgement(&controller, session_id, &[3, 4]);
    let elsewhere = controller
        .worker_client(&silent.worker)
        .await
        .expect("another operation takes the worker's link");

    let began = tokio::time::Instant::now();
    controller
        .collect_owed_evidence(
            session_id,
            binding,
            newer,
            Some(began + Duration::from_secs(2)),
        )
        .await;
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "the revisions the worker was not asked about waited {:?} for the link",
        began.elapsed()
    );

    for revision in [3, 4] {
        assert!(controller.leases.acknowledge(
            session_id,
            binding,
            AuthorityRevision::new(revision),
            Some(evidence(2)),
        ));
    }
    let began = tokio::time::Instant::now();
    controller
        .collect_owed_evidence(
            session_id,
            binding,
            newer,
            Some(began + Duration::from_secs(2)),
        )
        .await;
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "the revisions whose pages are owed waited {:?} for the link",
        began.elapsed()
    );
    assert_eq!(heard.frames(), 0, "nothing went to the worker");
    drop(elsewhere);
    silent.serving.abort();
}

/// KR-REQ-09.12: a collection that gave the link back before the first exchange of an older
/// revision leaves the worker owing names, so that a later pass asks for them.
///
/// The worker refused revision 4 for the moment and fenced it by itself, so the daemon holds no
/// report of it; revision 5 was then acknowledged with evidence that was whole, and its result
/// reads 4. The ask's time ran out before 4's first exchange. The worker owes names no report
/// says it owes, so the set the pass collects must hold it, or nothing asks again.
///
/// The daemon's own pass is not held: it collects names at the registry's revision, which no
/// revision of this case's reports reaches, so it sends this worker nothing. The case makes the
/// pass's collection itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_give_back_before_an_older_revisions_first_exchange_leaves_the_worker_owing_its_names() {
    let (silent, heard) = stalled().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let (binding, newer, older) =
        after_refusals_and_a_whole_acknowledgement(&controller, session_id, &[4]);
    assert!(
        controller.leases.owing_names().contains(&session_id),
        "the worker owes names before the collection: its result reads revisions with no report"
    );

    controller
        .collect_owed_evidence(
            session_id,
            binding,
            newer,
            Some(tokio::time::Instant::now() + Duration::from_secs(2)),
        )
        .await;
    assert_eq!(heard.frames(), 0, "the collection gave the link back");
    assert_eq!(
        controller.leases.owing_names(),
        vec![session_id],
        "the collection left the worker owing the names of {older:?}"
    );

    // The pass that collects the names owed asks with no bound of its own, and asks for the first
    // page of the older revisions.
    controller
        .collect_owed_evidence(session_id, binding, newer, None)
        .await;
    assert_eq!(
        heard.frames(),
        1,
        "the pass asked the worker for the older revision"
    );
    silent.serving.abort();
}

/// KR-REQ-09.12: an ask whose wait runs past its bound ends at the bound, with no link out, and
/// the names stay owed.
///
/// Another operation holds the registry across the whole of the ask's time, which the ask reads
/// before it sends anything. The bound is all that ends the wait: the ask has run out, so the pass
/// paces it as a failed ask, the worker's link was never taken, and its lease goes on renewing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_whose_wait_runs_past_its_bound_ends_at_it_with_no_link_out() {
    let (silent, heard) = stalled().await;
    let _pass = without_an_evidence_pass(&silent.controller).await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    assert!(
        controller
            .leases
            .acknowledge(session_id, binding, revision, Some(evidence(3)))
    );
    let registry = controller.registry.lock().await;
    let began = tokio::time::Instant::now();
    let asked = tokio::time::timeout(
        PASS_ASK_BOUND + Duration::from_secs(5),
        controller.ask_within_the_bound(session_id, began),
    )
    .await
    .expect("the ask was still waiting five seconds after its bound");
    let lasted = began.elapsed();
    drop(registry);
    assert_eq!(asked, Asked::Failed, "an ask that ran out is a failed ask");
    assert!(
        lasted >= PASS_ASK_BOUND && lasted < PASS_ASK_BOUND + Duration::from_secs(2),
        "the ask ended {lasted:?} after it began, which is its bound and no other time"
    );
    assert_eq!(heard.frames(), 0, "nothing went to the worker");
    assert!(
        !controller.leases.is_fenced(session_id),
        "no link was out, so none was given up"
    );
    assert!(leases(&controller, session_id));
    assert_eq!(
        controller.leases.owing_names(),
        vec![session_id],
        "the names stay owed for the pass's collection"
    );
    silent.serving.abort();
}

/// KR-REQ-09.12: the first exchange of an ask has a limit of its own that starts once the ask has
/// the worker's link.
///
/// Another operation keeps the link for seven of the ask's fifteen seconds. The announcement then
/// begins with eight seconds left, which is more than an exchange takes, and the worker answers it
/// four seconds later, inside them. A limit that started before the wait would have run out three
/// seconds before that answer, with the announcement on the wire, and a link that goes out of its
/// holder's hand stops the renewal of the lease of a worker that has acknowledged before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_exchange_of_an_ask_starts_its_limit_once_the_ask_has_the_link() {
    let (silent, heard) = answered().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    heard
        .delays
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push_back(Duration::from_secs(4));
    let mut elsewhere = controller
        .worker_client(&silent.worker)
        .await
        .expect("another operation takes the worker's link");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let (asked, ()) = tokio::join!(
        controller.ask_worker_revision(session_id, Some(deadline)),
        async {
            tokio::time::sleep(Duration::from_secs(7)).await;
            elsewhere.give_back();
            drop(elsewhere);
        },
    );
    assert_eq!(heard.frames(), 1, "the announcement went");
    assert_eq!(
        asked.unwrap_or(Asked::Failed),
        Asked::Acknowledged,
        "the worker answered within the time an exchange has"
    );
    assert!(
        !controller.leases.is_fenced(session_id),
        "the renewal of the worker's lease was not stopped"
    );
    assert!(leases(&controller, session_id));
    assert!(
        slot_holds_a_link(&controller, session_id).await,
        "the link is back in its slot"
    );
    silent.serving.abort();
}

/// Raises two barriers for changes that reach more grants than one notice names, while the
/// worker is not in the directory, so that a daemon that has recorded nothing of the worker tells
/// it three revisions in at least two notices. Then lists the worker again.
///
/// The barriers leave the worker pending, and the daemon's evidence pass asks a pending worker for
/// its acknowledgement by itself, as the case's own ask does. A held round does not stop those
/// asks, so the pass is stopped as a whole before the barriers are raised. Returns the end that
/// lets it go, which the case keeps until its last assertion: a frame of the pass would be counted
/// as the ask's second notice, or take the gate that holds the worker's first answer.
async fn after_barriers_that_need_several_notices(
    silent: &Silent,
) -> tokio::sync::oneshot::Sender<()> {
    let controller = &silent.controller;
    let session_id = silent.session_id;
    let pass = without_an_evidence_pass(controller).await;
    controller.directory.lock().await.remove(session_id);
    let bound = u32::try_from(kr_protocol::worker::MAX_REVISION_REACH_NAMES).expect("fits");
    let mut newest = AuthorityRevision::new(0);
    for first in [1_u32, 100_000] {
        let grants: std::collections::BTreeSet<_> = (first..first + bound / 2 + 1)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&number.to_be_bytes());
                kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
            })
            .collect();
        let reach = crate::service::Reach::Grants {
            holding_leases: grants.clone(),
            grants,
        };
        let debt = controller
            .owe_debt("a change", reach.clone())
            .expect("written");
        let own = controller.publish_debts(&[(debt, reach)]);
        controller.barrier(own).await.expect("a barrier");
        newest = controller
            .registry
            .lock()
            .await
            .authority_revision()
            .expect("readable");
    }
    assert!(
        controller
            .revision_notices(newest, AuthorityRevision::new(0), 0)
            .len()
            >= 2,
        "the worker is told in several notices"
    );
    // The worker has acknowledged the revision in force as far as the lease issuer knows, so that
    // its lease renews until something stops it.
    world::acknowledged(controller, session_id);
    controller
        .directory
        .lock()
        .await
        .insert(silent.worker.clone(), None);
    pass
}

/// Has another connection to the registry's file hold its write lock for `hold`, on a thread of its
/// own, as the device directory does while it records the host's clock. Answers once the lock is
/// held, with the handle of the thread, which ends when the lock has been let go.
async fn a_writer_ahead_on_the_registry_file(
    controller: &Controller,
    hold: Duration,
) -> tokio::task::JoinHandle<()> {
    let path = controller.paths().registry_database();
    let (taken, held) = tokio::sync::oneshot::channel();
    let writer = tokio::task::spawn_blocking(move || {
        let connection = rusqlite::Connection::open(path).expect("a second connection to the file");
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("the file's write lock is held");
        let _ = taken.send(());
        std::thread::sleep(hold);
        connection
            .execute_batch("ROLLBACK;")
            .expect("the file's write lock is let go");
    });
    held.await.expect("the writer ahead took the lock");
    writer
}

/// One ask of fifteen seconds, whose first notice begins after another operation has held the
/// registry for six. The worker answers that notice only once the case holds the registry again,
/// so the ask can record the answer, and send a second notice, only when the case lets the registry
/// go `release_at` after the ask began. The worker would answer a second notice four seconds after
/// it was sent. Returns what the ask said.
///
/// With `file_held_until`, another connection to the registry's file also holds its write lock,
/// from before the case lets the registry go until then after the ask began, so that the daemon's
/// write of the answer waits for the file, inside one poll, once the registry is let go.
async fn a_telling_that_waits_for_the_registry_between_its_notices(
    silent: &Silent,
    heard: &Heard,
    release_at: Duration,
    file_held_until: Option<Duration>,
) -> Asked {
    let controller = &silent.controller;
    let session_id = silent.session_id;
    {
        let mut delays = heard
            .delays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        delays.push_back(Duration::ZERO);
        delays.extend(std::iter::repeat_n(Duration::from_secs(4), 8));
    }
    let (open, gate) = tokio::sync::oneshot::channel();
    heard
        .gates
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push_back(gate);
    let began = tokio::time::Instant::now();
    let deadline = began + Duration::from_secs(15);
    let first = controller.registry.lock().await;
    let (asked, ()) = tokio::join!(
        tokio::time::timeout(
            deadline - began + Duration::from_secs(5),
            controller.ask_worker_revision(session_id, Some(deadline)),
        ),
        async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            drop(first);
            until("the first notice reached the worker", || {
                heard.frames() >= 1
            })
            .await;
            let held = controller.registry.lock().await;
            // The answer is given only now, so that the ask meets the held registry however late
            // this task came to it.
            let _ = open.send(());
            let writer = if let Some(until) = file_held_until {
                let hold = (began + until).saturating_duration_since(tokio::time::Instant::now());
                Some(a_writer_ahead_on_the_registry_file(controller, hold).await)
            } else {
                None
            };
            tokio::time::sleep_until(began + release_at).await;
            drop(held);
            if let Some(writer) = writer {
                writer.await.expect("the writer ahead let the file go");
            }
        },
    );
    asked
        .expect("the ask ended by itself, a few seconds after its bound at the latest")
        .unwrap_or(Asked::Failed)
}

/// What a telling that sent no notice after its first leaves behind: the first was the only frame,
/// the ask has run out, and the worker's lease goes on renewing over a link that is in its slot.
async fn the_second_notice_was_not_sent(silent: &Silent, heard: &Heard, asked: Asked) {
    let controller = &silent.controller;
    assert_eq!(
        heard.frames(),
        1,
        "only the first notice went to the worker"
    );
    assert_eq!(asked, Asked::Failed, "the ask ran out");
    assert!(
        !controller.leases.is_fenced(silent.session_id),
        "the renewal of the worker's lease was not stopped"
    );
    assert!(leases(controller, silent.session_id));
    assert!(
        slot_holds_a_link(controller, silent.session_id).await,
        "the link went back whole"
    );
    assert_eq!(heard.connections(), 1, "no other link was opened");
}

/// KR-REQ-09.12: the notices of one telling after the first begin only with an exchange's time left
/// before the ask's deadline, also after a wait for the registry between them.
///
/// The first notice is answered once the case holds the registry, a little after six seconds of the
/// ask's fifteen, and the ask can record the answer only when the registry is let go at twelve, so
/// the second would begin with three seconds left, inside the five an exchange takes, and the
/// worker would answer it four seconds later. A deadline that cut it would drop the
/// link with the notice on the wire and stop the worker's renewal. So nothing more is sent, and the
/// link goes back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_notice_that_would_begin_with_too_little_time_is_not_sent() {
    let (silent, heard) = answered().await;
    let _pass = after_barriers_that_need_several_notices(&silent).await;
    let asked = a_telling_that_waits_for_the_registry_between_its_notices(
        &silent,
        &heard,
        Duration::from_secs(12),
        None,
    )
    .await;
    the_second_notice_was_not_sent(&silent, &heard, asked).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a wait for the registry between two notices that runs past the ask's deadline ends
/// at it with the link given back whole.
///
/// The registry is held beyond the fifteen seconds. The deadline cuts the wait, nothing is on the
/// wire, and the renewal of the worker's lease, which a link dropped in the holder's hand would
/// stop, goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wait_for_the_registry_between_two_notices_that_runs_past_the_deadline_gives_the_link_back()
 {
    let (silent, heard) = answered().await;
    let _pass = after_barriers_that_need_several_notices(&silent).await;
    let asked = a_telling_that_waits_for_the_registry_between_its_notices(
        &silent,
        &heard,
        Duration::from_secs(17),
        None,
    )
    .await;
    the_second_notice_was_not_sent(&silent, &heard, asked).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: a notice after the first begins only with an exchange's time left, asked after a
/// wait for the registry that ended past the instant the wait is cut at.
///
/// The case lets the registry go at eight seconds of the ask's fifteen, before the cut at ten, but
/// another connection to the registry's file holds its write lock until eleven. The daemon's write
/// of the first answer waits for the file inside one poll, and the timeout that cuts the wait polls
/// the wait before it looks at its timer, so it finds the wait done and cuts nothing. Only the check
/// made after the wait stops a second notice, which would begin with four seconds left, inside the
/// five an exchange takes. So nothing more is sent, and the link goes back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_notice_is_not_sent_when_the_registry_file_holds_the_write_past_the_cut() {
    let (silent, heard) = answered().await;
    let _pass = after_barriers_that_need_several_notices(&silent).await;
    let asked = a_telling_that_waits_for_the_registry_between_its_notices(
        &silent,
        &heard,
        Duration::from_secs(8),
        Some(Duration::from_secs(11)),
    )
    .await;
    the_second_notice_was_not_sent(&silent, &heard, asked).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: the time limit of a page of evidence is an instant, taken once for the check that
/// time is left and for the timer, so that time passing between them cannot put its end behind
/// the ask's deadline.
///
/// The collection has eight seconds. The check finds all eight, and four go by before the page is
/// sent. A timer of five seconds that started then would end at nine; the page ends at five, by the
/// instant the check was made for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_whose_limit_starts_late_still_ends_by_the_deadline() {
    let (silent, heard) = stalled().await;
    let _pass = without_an_evidence_pass(&silent.controller).await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    assert!(
        controller
            .leases
            .acknowledge(session_id, binding, revision, Some(evidence(3)))
    );
    let (arrived, go) = controller.stop_before_a_pages_limit_for_tests();
    let began = tokio::time::Instant::now();
    let until = began + Duration::from_secs(8);
    tokio::join!(
        controller.collect_owed_evidence(session_id, binding, revision, Some(until)),
        async {
            arrived
                .await
                .expect("the request reached the stop before its limit");
            tokio::time::sleep(Duration::from_secs(4)).await;
            let _ = go.send(());
        },
    );
    let lasted = began.elapsed();
    assert_eq!(heard.frames(), 1, "the page was sent");
    assert!(
        lasted <= Duration::from_secs(8),
        "the page ended {lasted:?} after the collection began, past the eight seconds it had"
    );
    silent.serving.abort();
}
