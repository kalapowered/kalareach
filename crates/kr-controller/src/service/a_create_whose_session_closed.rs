//! A create whose worker reported itself and whose session closed before the create described it.
//!
//! The create answers with the session as its worker describes it. A closure that is recorded
//! between the worker's report and that description takes the worker out of what the daemon holds,
//! and the session is then closed rather than unknown: the closure is the answer, as it is to the
//! same create asked again afterwards. So is the closure of a worker that has ended before the
//! daemon has recorded one, as the worker of a command that ends at once does, and the closure of
//! a worker that ends while the create waits for it.

use std::sync::Arc;

use kr_protocol::identity::{DesktopBinding, ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::{AuthorityRevision, SessionId};
use kr_protocol::session::{SessionCreateResult, SessionState};
use kr_protocol::worker::WorkerDescriptor;

use super::a_close_a_worker_never_answers as world;
use super::a_create_that_launches_nothing::{create_params, seed_claim_as};
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use crate::directory::KnownWorker;
use crate::error::ControllerError;
use crate::registry::{Reservation, WorkerRecord};
use crate::service::Controller;

/// A daemon, a real worker that has reported itself, and the create it reported for.
async fn reported() -> (Served, Reservation) {
    let (world, reservation_id) = Served::claimed().await;
    let reservation = world
        .controller
        .registry
        .lock()
        .await
        .reservation(reservation_id)
        .expect("the registry answers")
        .expect("the reservation is recorded");
    world
        .controller
        .directory
        .lock()
        .await
        .insert(world.worker.clone(), None);
    (world, reservation)
}

/// What a create is answered with, for the worker `world` serves.
async fn answered(world: &Served, reservation: &Reservation) -> SessionCreateResult {
    to_a_result(
        answer(
            &world.controller,
            reservation,
            world.worker.endpoint.as_text(),
        )
        .await
        .expect("the create is answered"),
    )
}

fn to_a_result(answer: kr_protocol::envelope::ParamsValue) -> SessionCreateResult {
    answer.to_typed().expect("a create result")
}

/// The create's answer or its failure, for the worker the daemon lists for `reservation`.
async fn answer(
    controller: &Arc<Controller>,
    reservation: &Reservation,
    endpoint: String,
) -> crate::error::Result<kr_protocol::envelope::ParamsValue> {
    controller
        .answer_a_created_session(
            &create_params(controller.paths().environment_id()),
            reservation,
            endpoint,
        )
        .await
}

/// The registry's row for the worker of `reservation`, naming `process` as the worker's process.
fn worker_record(
    reservation: &Reservation,
    worker: &KnownWorker,
    process: ProcessStartIdentity,
) -> WorkerRecord {
    WorkerRecord {
        session_id: reservation.session_id,
        display_number: reservation.display_number,
        public_key: worker.descriptor.worker_public_key,
        process_identity: process,
        endpoint: worker.endpoint.as_text(),
        profile: WorkerProfile::HeadlessUser,
        state: SessionState::Live,
        acknowledged_revision: AuthorityRevision::new(0),
    }
}

/// A daemon and the create a worker reported for, with the worker as the daemon holds it once its
/// endpoint is gone, as the worker of a command that ended at once leaves it: the registry names
/// `process` as the worker's process, and the directory lists a worker whose endpoint was never
/// bound.
///
/// No worker lives here, and none was ever listed. A worker that lived would go on serving a
/// connection made before its endpoint path was taken away, and the daemon's own publisher opens a
/// connection to a worker the directory lists as soon as it has a reason to, so a read could be
/// answered over one. With none to reach, nothing the publisher or the create does can be.
struct Gone {
    controller: Arc<Controller>,
    reservation: Reservation,
    /// Declared last, so the tree is removed after the daemon's handles to it are gone.
    _temp: kr_ipc::testing::TempHost,
}

impl Gone {
    async fn with_the_worker_process(process: ProcessStartIdentity) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = Controller::start(world::setup(&temp))
            .await
            .expect("the daemon starts");
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let mut identity = None;
        let reservation = seed_claim_as(
            &controller,
            &actor_id,
            WorkerProfile::HeadlessUser,
            |reservation| {
                let made = kr_ipc::verify::WorkerIdentity::generate(
                    reservation.session_id,
                    kr_protocol::ids::SessionEpoch::V1,
                    controller.boot_identity.clone(),
                    kr_ipc::identity::current_process_start_identity().expect("a process identity"),
                    kr_protocol::hello::PROTOCOL_VERSION,
                )
                .expect("a session key");
                let key = *made.public_key();
                identity = Some(made);
                key
            },
        )
        .await;
        let identity = identity.expect("the worker was made for its claim");
        let endpoint = controller
            .paths()
            .worker_endpoint(reservation.display_number)
            .expect("an endpoint");
        let worker = KnownWorker {
            level: kr_protocol::retained::Level::this(),
            descriptor: WorkerDescriptor {
                session_id: reservation.session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                environment_id: controller.paths().environment_id(),
                display_number: reservation.display_number,
                boot_identity: identity.boot_identity().clone(),
                process_start_identity: process.clone(),
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: *identity.public_key(),
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: kr_ipc::now_ms(),
            },
            endpoint,
        };
        controller
            .registry
            .lock()
            .await
            .adopt_worker(
                &worker_record(&reservation, &worker, process),
                Some(&DesktopBinding::none()),
            )
            .expect("the registry records the worker");
        controller.directory.lock().await.insert(worker, None);
        Self {
            controller,
            reservation,
            _temp: temp,
        }
    }

    /// The create's answer or its failure.
    async fn answer(&self) -> crate::error::Result<kr_protocol::envelope::ParamsValue> {
        answer(
            &self.controller,
            &self.reservation,
            "unused: no worker lives here".to_owned(),
        )
        .await
    }

    async fn closure_is_recorded(&self) -> bool {
        self.controller
            .registry
            .lock()
            .await
            .closure(self.reservation.session_id)
            .expect("the registry answers")
            .is_some()
    }
}

fn assert_closed(answer: &SessionCreateResult, session_id: SessionId) {
    assert_eq!(answer.session.state, SessionState::Closed);
    assert_eq!(
        answer
            .session
            .closure
            .0
            .as_ref()
            .map(|record| record.session_id),
        Some(session_id),
        "the session carries its closure"
    );
    assert!(
        answer.endpoint.0.is_none(),
        "a closed session has no endpoint"
    );
    assert!(
        !answer.deduplicated,
        "an answer made for the create itself is not a replay of it"
    );
}

/// KR-REQ-09.12: a create whose session closed after its worker reported itself is answered from
/// the session's closure, with the session closed and no endpoint to attach to, whether the closure
/// has finished by the time the create looks for its worker or lands between that look and the
/// worker's description of the session. The control is the same create before any closure, which
/// is answered with the worker's own description of the session and its endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_session_closed_after_its_worker_reported_is_answered_from_the_closure() {
    let (world, reservation) = reported().await;
    let controller = &world.controller;

    let open = answered(&world, &reservation).await;
    assert_eq!(
        open.endpoint.0.as_deref(),
        Some(world.worker.endpoint.as_text().as_str())
    );
    assert_ne!(open.session.state, SessionState::Closed);

    // The closure lands between the create's look at the directory and its read of the worker.
    let (arrived, go) = controller.before_a_created_session_is_read.arm();
    let (during, ()) = tokio::join!(answered(&world, &reservation), async {
        arrived.await.expect("the create has found its worker");
        controller
            .retire(&closure_of(world.session_id))
            .await
            .expect("the closure is recorded");
        go.send(()).expect("the create is waiting");
    });
    assert_closed(&during, world.session_id);

    // The closure is complete when the create looks for its worker: nothing is in the directory.
    assert_closed(&answered(&world, &reservation).await, world.session_id);
}

/// KR-REQ-09.12: a create whose worker ended before the create could describe the session, with no
/// closure recorded yet, is answered from the closure the daemon establishes for a worker the
/// kernel says has ended: the session closed, with no endpoint to attach to. A command that ends at
/// once takes its worker with it, and the create meets the worker's endpoint gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_ended_before_it_was_described_is_answered_from_a_closure_for_it() {
    // A process identity that reads as ended without a question to the kernel, which no running
    // process can be mistaken for.
    let gone =
        Gone::with_the_worker_process(kr_ipc::identity::ended_process_identity(4_000_000)).await;
    assert!(!gone.closure_is_recorded().await, "no closure is recorded");

    let answered = to_a_result(gone.answer().await.expect("the create is answered"));
    assert_closed(&answered, gone.reservation.session_id);
}

/// KR-REQ-09.12: where no closure is established for a worker that cannot be reached, the create
/// fails as it did, with the failure of the connection. The worker here has no endpoint any more
/// and the kernel says its process is running, so nothing says its session ended, and the wait for
/// the worker's end gives up at its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_cannot_be_reached_and_has_not_ended_fails_with_the_connection() {
    let gone = Gone::with_the_worker_process(
        kr_ipc::identity::current_process_start_identity().expect("this process is described"),
    )
    .await;

    let refused = gone
        .answer()
        .await
        .expect_err("a worker that has not ended and cannot be reached leaves no answer");
    assert!(
        matches!(
            &refused,
            ControllerError::Ipc(kr_ipc::IpcError::Socket { operation: "connect", source })
                if source.kind() == std::io::ErrorKind::NotFound
        ),
        "the failure is the connection that was not made: {refused:?}"
    );
    assert!(!gone.closure_is_recorded().await, "no closure was invented");
}

/// A process this test holds, ended when the test lets it go.
#[cfg(unix)]
struct Held(std::process::Child);

#[cfg(unix)]
impl Held {
    fn start() -> Self {
        Self(
            std::process::Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("a process starts"),
        )
    }

    fn identity(&self) -> ProcessStartIdentity {
        kr_ipc::identity::process_start_identity(self.0.id())
            .expect("a running process is described")
    }

    /// Ends the process and collects it, so the kernel says it has ended.
    fn end(&mut self) {
        self.0.kill().expect("the process is ended");
        self.0.wait().expect("the process is collected");
    }
}

#[cfg(unix)]
impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// KR-REQ-09.12: a create whose worker closes its connection under the create's read and whose
/// process is still running is answered from the closure the daemon establishes once that process
/// ends, not with the failure of the connection. A worker that has finished its closure stops
/// accepting and drops its connections before its process ends, so the create waits for the end of
/// the process. The worker here goes at the create's read, and its process ends while the create
/// is held after a look that found the process running.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_ends_while_the_create_waits_for_it_is_answered_from_a_closure() {
    use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, reported_late};

    let script = Scripted::new();
    let world = reported_late(&script).await;
    let controller = Arc::clone(&world.controller);
    let reservation = controller
        .registry
        .lock()
        .await
        .reservation_for_session(world.session_id)
        .expect("the registry answers")
        .expect("the reservation is recorded");
    let mut process = Held::start();
    controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &worker_record(&reservation, &world.worker, process.identity()),
            Some(&DesktopBinding::none()),
        )
        .expect("the registry records the worker");

    // The worker ends the connection of the create's read, after its endpoint stops accepting, as a
    // worker does that has finished its closure, with its process still running.
    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let (looked, release) = controller.after_a_worker_is_looked_for_in_vain.arm();
    let mut create = tokio::spawn({
        let controller = Arc::clone(&controller);
        let endpoint = world.worker.endpoint.as_text();
        async move { answer(&controller, &reservation, endpoint).await }
    });
    tokio::select! {
        looked = looked => looked.expect("the create has looked for the end of the worker"),
        ended = &mut create => panic!("the create ended without waiting for its worker: {ended:?}"),
    }
    process.end();
    release.send(()).expect("the create is waiting");

    let answered: SessionCreateResult = create
        .await
        .expect("the create's task ends")
        .expect("the create is answered")
        .to_typed()
        .expect("a create result");
    assert_closed(&answered, world.session_id);
    world.serving.abort();
}
