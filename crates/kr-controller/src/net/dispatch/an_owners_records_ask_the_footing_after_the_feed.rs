//! The footing's question at the record of an owner's request and at the record of its answer is
//! asked after the authority feed's ask took its locks.
//!
//! A lease that ends while the feed's ask waits for its locks is found only by a question asked
//! after that wait: a question asked before it would pass on a lease that has ended, and the record
//! would be written for a subject that no lease serves. Each case stops the record at the feed's
//! locked ask, passes the lease's end there, and finds the subject decided again under the scope
//! that no lease serves. The caller of a case is decided under the local owner's lease and lands on
//! a paired connection, which is the connection the feed asks.
//!
//! The lease cannot be presented again at that place: a policy commit needs the pairing records'
//! write lock, which the record's transaction holds from before its first statement.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_pairing::confirm::sign_confirmation;
use kr_protocol::confirmation::{ConfirmationDisplay, OwnerConfirmationCompleteParams};
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::pairing::{ConfirmationChannel, SensitiveAction};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable};

use super::write_boundary::{Recording, paired_connection_expiring};
use crate::service::a_result_the_lease_ended_over::connected_under_a_lease_that_can_be_presented_again;
use crate::service::an_owner_establishes_the_clock::registry;
use crate::service::net::owner::{Caller, Resolved};

/// A display that a caller no lease serves may not be asked for or answered: making the host
/// exclusive.
fn making_exclusive() -> ConfirmationDisplay {
    ConfirmationDisplay::ExclusiveManagement {
        exclusive: true,
        organisation_ids: Vec::new(),
    }
}

/// The refusal a caller no lease serves is told for what it may not confirm.
fn closed_refusal() -> String {
    Caller::local(ActorId::new("local:test").expect("a principal"))
        .confirming_recovery_only(true)
        .refusal_to_confirm()
        .to_string()
}

fn resolved(display: ConfirmationDisplay, bootstrap: bool, digest: u8) -> Resolved {
    Resolved {
        action: SensitiveAction::ChangeHostAuthority,
        digest: Digest256::from_bytes([digest; 32]),
        destination: None,
        rights: CanonicalSet::new(),
        display,
        bootstrap,
    }
}

/// Asks for the confirmation that makes the host exclusive, and stops the record of the request at
/// the feed's locked ask; `ends` says whether the lease's time passes there.
/// Returns the request's result as its refusal, and the rows written.
async fn requested(ends: bool) -> (Result<(), String>, i64) {
    let (temp, controller, continuous, _presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let recording = Arc::new(Recording::default());
    let connection = paired_connection_expiring(
        &controller,
        72,
        &[ActionRight::SessionView],
        kr_protocol::grant::GrantExpiry::Never,
        Box::new(Arc::clone(&recording)),
    );
    let admitted = connection
        .admitted_at()
        .await
        .expect("the connection is admitted");
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let actor = ActorId::new("local:test").expect("a principal");
    let caller = controller
        .local_caller(&actor)
        .landed(controller.pairing_landing(
            connection.connection_id,
            Some(admitted),
            Some(deadline),
        ));
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([5; 32]),
    );
    let (arrived, go) = controller.pause_before_the_shares_lock();
    let owner = Arc::clone(controller.owner_authority());
    let asking = tokio::task::spawn_blocking(move || {
        owner.request(
            &caller,
            resolved(making_exclusive(), false, 6),
            action,
            &AtomicBool::new(false),
        )
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches the feed's locked ask");
    if ends {
        continuous.advance(Duration::from_secs(16 * 60));
    }
    go.send(()).expect("the record goes on");
    let answered = asking.await.expect("the request ends");
    let rows = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            [action.0.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    (
        answered.map(|_| ()).map_err(|refusal| refusal.to_string()),
        rows,
    )
}

/// KR-REQ-17.54: a lease that ends while the feed's ask waits for its locks is found by the
/// question asked after them: the confirmation that no lease serves is refused in the door's words
/// and nothing is written. The control: where the lease stands, it is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_lease_ends_while_the_feed_is_asked_is_decided_again_under_the_closed_scope()
 {
    let (answered, rows) = requested(false).await;
    answered.expect("the request is recorded where the lease stands");
    assert_eq!(rows, 1, "the control writes the record");
    let (answered, rows) = requested(true).await;
    assert_eq!(
        answered.expect_err("the request is refused"),
        closed_refusal()
    );
    assert_eq!(rows, 0, "nothing is written");
}

/// Asks for a challenge that the terminal can answer, then answers it, stopping the record of the
/// answer at the feed's locked ask; `ends` says whether the lease's time passes
/// there. Returns the answer's result as its refusal, and the acceptances written.
async fn answered(ends: bool) -> (Result<(), String>, i64) {
    let (temp, controller, continuous, _presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let recording = Arc::new(Recording::default());
    let connection = paired_connection_expiring(
        &controller,
        73,
        &[ActionRight::SessionView],
        kr_protocol::grant::GrantExpiry::Never,
        Box::new(Arc::clone(&recording)),
    );
    let admitted = connection
        .admitted_at()
        .await
        .expect("the connection is admitted");
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let actor = ActorId::new("local:test").expect("a principal");
    let landing =
        || controller.pairing_landing(connection.connection_id, Some(admitted), Some(deadline));
    let owner = Arc::clone(controller.owner_authority());
    let challenge = {
        let owner = Arc::clone(&owner);
        let caller = controller.local_caller(&actor).landed(landing());
        tokio::task::spawn_blocking(move || {
            owner.request(
                &caller,
                resolved(making_exclusive(), true, 7),
                (
                    ActionId::new(kr_ipc::new_uuid()),
                    Digest256::from_bytes([8; 32]),
                ),
                &AtomicBool::new(false),
            )
        })
        .await
        .expect("the request ends")
        .expect("the terminal is asked")
    };
    let key = AuthorisationKeyPair::generate().expect("a key");
    let params = OwnerConfirmationCompleteParams {
        proof: sign_confirmation(
            &key,
            &challenge.request,
            ConfirmationChannel::LocalBootstrapTerminal,
        )
        .expect("a proof"),
        bootstrap_signer: Nullable::some(*key.public()),
    };
    let confirmation = challenge.request.confirmation_id;
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([9; 32]),
    );
    let caller = controller.local_caller(&actor).landed(landing());
    let (arrived, go) = controller.pause_before_the_shares_lock();
    let answering = tokio::task::spawn_blocking({
        let owner = Arc::clone(&owner);
        move || owner.complete(&caller, &params, action, &AtomicBool::new(false))
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches the feed's locked ask");
    if ends {
        continuous.advance(Duration::from_secs(16 * 60));
    }
    go.send(()).expect("the record goes on");
    let answered = answering.await.expect("the answer ends");
    let answers = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM owner_confirmations WHERE confirmation_id = ?1",
            [confirmation.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    (
        answered.map(|_| ()).map_err(|refusal| refusal.to_string()),
        answers,
    )
}

/// KR-REQ-17.54: the same for the answer: a lease that ends while the feed's ask waits for its
/// locks is found by the question asked after them, and the confirmation that no lease serves is
/// refused in the door's words with no acceptance recorded. The control: where the lease stands, it
/// is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_lease_ends_while_the_feed_is_asked_is_decided_again_under_the_closed_scope()
 {
    let (answered_with, answers) = answered(false).await;
    answered_with.expect("the answer is recorded where the lease stands");
    assert_eq!(answers, 1, "the control records the acceptance");
    let (answered_with, answers) = answered(true).await;
    assert_eq!(
        answered_with.expect_err("the answer is refused"),
        closed_refusal()
    );
    assert_eq!(answers, 0, "no acceptance is recorded");
}
