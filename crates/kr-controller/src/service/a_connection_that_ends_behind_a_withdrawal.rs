//! A connection that ends while a withdrawal of registrations is under way.
//!
//! A withdrawal takes the registrations of the connections that ended before it lets go, and a
//! connection that ends after that has no one else to withdraw it: the commit it would have waited
//! for has ended already.

use std::sync::Arc;

use kr_protocol::ids::{ActorId, ConnectionId};

use super::AdmittedConnection;
use super::a_transfer_left_unanswered::daemon;

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
