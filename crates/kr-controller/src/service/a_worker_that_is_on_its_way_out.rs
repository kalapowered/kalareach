//! A closed session whose worker has not yet exited.
//!
//! A worker hands its closure over before it exits, and the closure erases the registry's row of it
//! and retires its descriptor. The reservation still names the process the launch ran, and that
//! process is the worker until the kernel says it ended: until then the worker may still write the
//! stores a read would migrate. These cases run a real daemon over such a session.

use kr_ipc::testing::TempHost;
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::session::DisplayNumber;

use super::a_migration_and_a_recovery_of_one_session::{
    RECOVERED, after_the_first_pass, closure_of, put_back_to_an_earlier_schema, version_of,
    written_journal,
};
use crate::attention::ClosedJournal;
use crate::registry::Reservation;
use crate::service::Controller;
use crate::service::net::tests::daemon;

/// A closed session of an earlier build whose launch's process is this one, which is running.
async fn closed_while_its_launchs_process_runs(
    controller: &Controller,
) -> (SessionId, Reservation) {
    let reservation = {
        let mut registry = controller.registry.lock().await;
        let admission = registry
            .reserve(
                &ActorId::new("local:test").expect("a principal"),
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([0x61; 32]),
                &[],
                kr_ipc::now_ms(),
            )
            .expect("reserves");
        registry
            .record_launch(
                admission.reservation.reservation_id,
                &kr_ipc::identity::current_process_start_identity().expect("this process"),
            )
            .expect("records the process the launch ran");
        admission.reservation
    };
    let session_id = reservation.session_id;
    written_journal(controller, session_id, None);
    put_back_to_an_earlier_schema(controller, session_id);
    // Recorded in the registry alone, so that no closure tail runs and migrates the journal on a
    // task of its own. The closure erases the worker's row, which is what the launch's process is
    // the only evidence left of.
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(session_id))
        .expect("the closure is recorded");
    (session_id, reservation)
}

async fn the_launchs_process_ends(controller: &Controller, reservation: &Reservation) {
    controller
        .registry
        .lock()
        .await
        .record_launch(
            reservation.reservation_id,
            &kr_ipc::identity::ended_process_identity(4_000_021),
        )
        .expect("records that the process ended");
}

/// KR-REQ-24.18: a read of a closed session is refused while the process its launch ran still
/// runs, and the store it would migrate is left as it is. Once the kernel says the process has
/// ended the same read is answered and brings the store forward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_is_refused_while_the_process_the_launch_ran_still_runs() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_the_first_pass(&controller).await;
    let (session_id, reservation) = closed_while_its_launchs_process_runs(&controller).await;

    let refused = controller.session_archive(session_id).await;
    assert!(
        refused.is_err(),
        "a worker the kernel has not said ended may still own its stores: {refused:?}"
    );
    assert_eq!(version_of(&controller, session_id), 3);

    the_launchs_process_ends(&controller, &reservation).await;
    let read = controller
        .session_archive(session_id)
        .await
        .expect("the archive answers once the process has ended");
    assert_eq!(
        read.summary.map(|summary| summary.cwd),
        Some(RECOVERED.to_owned())
    );
    assert_eq!(
        version_of(&controller, session_id),
        kr_worker::persistence::migration::CURRENT
    );
}

/// KR-REQ-24.18: the readers that do not ask whether a worker may remain before they read (the
/// list of closed sessions, the attention store's reading of a closed journal, and the transfer
/// sweep's question) leave the store as it is while the process the launch ran still runs, and
/// bring it forward once it has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_reader_migrates_a_store_while_the_process_the_launch_ran_still_runs() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_the_first_pass(&controller).await;
    let (session_id, reservation) = closed_while_its_launchs_process_runs(&controller).await;
    let closure = closure_of(session_id);
    let reach = controller.attention_reach();
    let sweep = |controller: &std::sync::Arc<Controller>| {
        let asked = std::sync::Arc::clone(controller);
        async move {
            tokio::task::spawn_blocking(move || {
                asked.retained_among(&std::collections::BTreeSet::from([session_id]))
            })
            .await
            .expect("the sweep ran")
            .expect("the sweep answered")
        }
    };

    let listed = controller
        .closed_session(&closure, DisplayNumber::new(1))
        .await;
    assert_ne!(
        listed.cwd, RECOVERED,
        "the list is built from the closure alone"
    );
    assert!(
        matches!(reach.closed_journal(session_id), ClosedJournal::HeldBack),
        "the attention store is told the journal is held back for now, and not that it is unreadable"
    );
    assert!(
        sweep(&controller).await.contains(&session_id),
        "the sweep reads the archive as it stands and keeps what a store it cannot read held"
    );
    assert_eq!(
        version_of(&controller, session_id),
        3,
        "and not one of them migrated the store"
    );

    the_launchs_process_ends(&controller, &reservation).await;
    let listed = controller
        .closed_session(&closure, DisplayNumber::new(1))
        .await;
    assert_eq!(
        listed.cwd, RECOVERED,
        "control: once it has ended it is read"
    );
    assert!(matches!(
        reach.closed_journal(session_id),
        ClosedJournal::Open(_)
    ));
    assert_eq!(
        version_of(&controller, session_id),
        kr_worker::persistence::migration::CURRENT
    );
}
