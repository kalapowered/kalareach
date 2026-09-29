//! Whether the registry shows a session's launch to be over, which is what lets privacy mode take a
//! session for ended.
//!
//! A worker that is not recorded may not have reported yet: a session whose launch is in progress
//! has a journal on the disk and no worker the registry lists. Only a launch the registry shows to
//! have produced no worker, or to have closed, or that it holds no record of, is over.

use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};

use super::a_change_that_waits_for_its_store::daemon;
use crate::registry::LaunchPhase;

/// KR-REQ-24.28: a reservation in any phase before its launch has failed or its session has
/// closed is a worker that may be starting or running, so its session is not over; a session the
/// registry holds no reservation for, one whose launch failed and one that closed are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_over_only_when_no_worker_can_still_come_of_it() {
    let (_temp, controller, _clock) = daemon().await;
    let mut asked: Vec<SessionId> = Vec::new();
    let mut expected: Vec<SessionId> = Vec::new();
    for (index, (phase, over)) in [
        (LaunchPhase::Reserved, false),
        (LaunchPhase::Spawned, false),
        (LaunchPhase::Claimed, false),
        (LaunchPhase::Live, false),
        (LaunchPhase::Fenced, false),
        (LaunchPhase::Failed, true),
        (LaunchPhase::Closed, true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut registry = controller.registry.lock().await;
        let reservation = registry
            .reserve(
                &ActorId::new("local:501").expect("a principal"),
                Uuid::from_bytes([u8::try_from(index).expect("a small index") + 1; 16]),
                Digest256::from_bytes([3; 32]),
                b"intent",
                TimestampMs::new(1),
            )
            .expect("reserves")
            .reservation;
        if phase != LaunchPhase::Reserved {
            registry
                .set_phase(reservation.reservation_id, phase)
                .expect("the phase is recorded");
        }
        asked.push(reservation.session_id);
        if over {
            expected.push(reservation.session_id);
        }
    }
    // A session the registry holds nothing for is over too: no launch can come of it.
    let unknown = SessionId::new(kr_ipc::new_uuid());
    asked.push(unknown);
    expected.push(unknown);

    let mut over = super::start::launches_over(&controller, &asked).await;
    over.sort_unstable();
    expected.sort_unstable();
    assert_eq!(over, expected);
    assert!(
        super::start::launches_over(&controller, &[])
            .await
            .is_empty(),
        "nothing asked, nothing over"
    );
}
