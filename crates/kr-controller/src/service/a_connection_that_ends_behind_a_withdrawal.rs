//! A connection that ends while the registrations are held.
//!
//! A withdrawal takes the registrations of the connections that ended before it lets go, and a
//! connection that ends after that has no one else to withdraw it: the commit it would have waited
//! for has ended already. A commit that ends by a panic leaves the same hold behind it.

use std::sync::Arc;

use kr_protocol::ids::{ActorId, ConnectionId};

use super::AdmittedConnection;
use super::a_transfer_left_unanswered::daemon;
use crate::authority::AdmittedMutation;

/// KR-REQ-09.12: a connection that ends after a withdrawal has taken the notes of the connections
/// that ended, and before the withdrawal lets go of the registrations, is withdrawn when the
/// withdrawal has let go. The withdrawal is stopped just after it takes the notes, a second
/// connection ends there, and nothing else withdraws that connection afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_ends_behind_a_withdrawal_is_withdrawn_when_it_lets_go() {
    let (_temp, controller) = daemon().await;
    let revision = controller.policy().authority_revision();
    let actor = ActorId::new("local:test").expect("a principal");
    let withdrawn = ConnectionId::new(kr_ipc::new_uuid());
    let ended = ConnectionId::new(kr_ipc::new_uuid());
    {
        let mut table = controller.admitted_write();
        for connection_id in [withdrawn, ended] {
            table.insert(
                connection_id,
                AdmittedConnection::new(actor.clone(), revision),
            );
        }
    }

    let (arrived, go) = controller.after_the_ended_are_taken.arm();
    let withdrawal = {
        let controller = Arc::clone(&controller);
        std::thread::spawn(move || {
            controller.admitted_withdraw().remove(&withdrawn);
        })
    };
    arrived.recv().expect("the withdrawal took the notes");

    controller.deregister(ended);
    go.send(()).expect("the withdrawal goes on");
    withdrawal.join().expect("the withdrawal ends");

    assert!(
        controller.admitted_read().is_empty(),
        "the connection that ended behind the withdrawal is withdrawn"
    );
}

/// KR-REQ-09.12: a commit that panics lets go of its hold on the registrations as one that ends
/// does, so a connection that ended inside it is withdrawn when the panic has been caught.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_ends_inside_a_commit_that_panics_is_withdrawn() {
    let (_temp, controller) = daemon().await;
    let revision = controller.policy().authority_revision();
    let actor = ActorId::new("local:test").expect("a principal");
    let committing = ConnectionId::new(kr_ipc::new_uuid());
    let ended = ConnectionId::new(kr_ipc::new_uuid());
    {
        let mut table = controller.admitted_write();
        for connection_id in [committing, ended] {
            table.insert(
                connection_id,
                AdmittedConnection::new(actor.clone(), revision),
            );
        }
    }
    let admission = AdmittedMutation {
        connection_id: committing,
        admitted_revision: revision,
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(60)),
    };

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = controller.under_registration(&admission, || {
            controller.deregister(ended);
            panic!("the commit fails after a connection ended inside it");
        });
    }));

    assert!(panicked.is_err(), "the commit ran and panicked");
    assert!(
        !controller.admitted_read().contains_key(&ended),
        "the connection that ended inside the commit is withdrawn"
    );
}
