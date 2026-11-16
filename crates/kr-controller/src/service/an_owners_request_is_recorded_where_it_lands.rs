//! Where an owner's request for a confirmation lands.
//!
//! The record of the request is written in one transaction. After the lookup it asks the authority
//! feed where that takes its locks, copies the bound of the local owner's lease, and asks the
//! footing's one question with the copy; where the bound ended or moved in the waits before the
//! copy, the subject is decided again under the scope that no lease serves; the feed is asked once
//! more with no lock; and the record is written with nothing allocated or awaited between the
//! question and the write.
//!
//! Each case stops the record at the last wait, after the feed was asked and before the bound is
//! copied, and ends what it ends there.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_protocol::confirmation::{ConfirmationDisplay, OwnerConfirmationRequestResult};
use kr_protocol::ids::ActionId;
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256};

use super::a_result_the_lease_ended_over::{
    Presenter, connected_under_a_lease_that_can_be_presented_again,
};
use super::an_owner_establishes_the_clock::{Door, registry};
use crate::error::ControllerError;
use crate::service::net::owner::{Caller, Resolved};

/// What ends in the last wait of the record.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// Nothing: the control.
    Nothing,
    /// The lease's time: the continuous clock passes its end.
    TheLeasesTime,
    /// The request's deadline: the continuous clock passes it, and the lease's end with it.
    TheDeadlinePasses,
    /// The lease is presented again, which publishes another lineage in the bound's cell.
    TheLeaseIsPresentedAgain,
}

/// What a request found at its record.
struct Found {
    answered: Result<OwnerConfirmationRequestResult, ControllerError>,
    copied: bool,
    rows: i64,
}

fn resolved(display: ConfirmationDisplay) -> Resolved {
    Resolved {
        action: SensitiveAction::ChangeHostAuthority,
        digest: Digest256::from_bytes([9; 32]),
        destination: None,
        rights: CanonicalSet::new(),
        display,
        bootstrap: false,
    }
}

fn establishing() -> ConfirmationDisplay {
    ConfirmationDisplay::EstablishClock
}

/// A display that a caller no lease serves may not be asked for: making the host exclusive.
fn making_exclusive() -> ConfirmationDisplay {
    ConfirmationDisplay::ExclusiveManagement {
        exclusive: true,
        organisation_ids: Vec::new(),
    }
}

/// The refusal a caller no lease serves is told for what it may not confirm.
fn closed_refusal() -> ControllerError {
    Caller::local(kr_protocol::ids::ActorId::new("local:test").expect("a principal"))
        .confirming_recovery_only(true)
        .refusal_to_confirm()
}

/// A presentation of the local owner's lease that has written its policy and is held at its
/// publishing stop, before the cell of the bound is swapped. The write has committed, so what it
/// holds back is only the swap: a record that is inside its transaction meets the bound moving.
pub(super) struct HeldPresentation {
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

/// Presents the lease again on a thread of its own and returns once it is held at its publishing
/// stop.
pub(super) async fn present_and_hold(presenter: Presenter) -> HeldPresentation {
    let (held, arrived) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        crate::grants::policy::publishing::stop_before_the_swap(move || {
            held.send(()).expect("the case waits for the stop");
            released.recv().expect("the case lets the swap go");
        });
        presenter.present(&[ActionRight::FilesRead]);
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the presentation reaches its publishing stop");
    HeldPresentation { release, thread }
}

impl HeldPresentation {
    /// Lets the swap go, and returns once the presentation has ended: the bound has moved.
    pub(super) async fn swap(self) {
        self.release.send(()).expect("the swap goes on");
        tokio::task::spawn_blocking(move || self.thread.join())
            .await
            .expect("the wait ends")
            .expect("the presentation ends");
    }
}

async fn recorded_with(ends: Ends, display: ConfirmationDisplay) -> Found {
    let (temp, controller, continuous, presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let door = Door::open(&temp, &controller).await;
    let revision = controller.admitted_revision(door.connection_id()).ok();
    // A deadline an hour away, so that what the case ends is the lease and not the deadline.
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let caller = controller
        .local_caller(door.actor_id())
        .landed(controller.pairing_landing(door.connection_id(), revision, Some(deadline)));
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([3; 32]),
    );
    // A lease presented again is a policy commit, which needs the pairing records' write lock, so it
    // lands in the wait for that lock, before the record's transaction begins; the lease's time
    // passes in the last wait, inside the transaction.
    let (arrived, go) = match ends {
        Ends::TheLeaseIsPresentedAgain => controller.pause_before_the_record_begins(),
        Ends::Nothing | Ends::TheLeasesTime | Ends::TheDeadlinePasses => {
            controller.pause_after_the_record_asks_the_feed()
        }
    };
    let owner = Arc::clone(controller.owner_authority());
    let asking = tokio::task::spawn_blocking(move || {
        let copied = AtomicBool::new(false);
        let answered = owner.request(&caller, resolved(display), action, &copied);
        (answered, copied.load(Ordering::Acquire))
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches its last wait");
    match ends {
        Ends::Nothing => {}
        Ends::TheLeasesTime => continuous.advance(Duration::from_secs(16 * 60)),
        Ends::TheDeadlinePasses => continuous.advance(Duration::from_secs(61 * 60)),
        Ends::TheLeaseIsPresentedAgain => {
            presenter.present(&[ActionRight::FilesRead]);
        }
    }
    go.send(()).expect("the record goes on");
    let (answered, copied) = asking.await.expect("the request ends");
    let rows = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            [action.0.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    Found {
        answered,
        copied,
        rows,
    }
}

/// As [`recorded_with`], for a bound that moves inside the record's transaction, after the feed's
/// locked ask: the presentation of the lease writes its policy while the record waits before its
/// transaction, is held at its publishing stop, and swaps the bound's cell in the last wait, which
/// stands at the end of the feed's ask.
async fn recorded_with_the_bound_moving_inside(display: ConfirmationDisplay) -> Found {
    let (temp, controller, _continuous, presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let door = Door::open(&temp, &controller).await;
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let caller = controller
        .local_caller(door.actor_id())
        .landed(controller.pairing_landing(door.connection_id(), revision, Some(deadline)));
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([3; 32]),
    );
    let (before, go_in) = controller.pause_before_the_record_begins();
    let (after_the_feed, go_on) = controller.pause_after_the_record_asks_the_feed();
    let owner = Arc::clone(controller.owner_authority());
    let asking = tokio::task::spawn_blocking(move || {
        let copied = AtomicBool::new(false);
        let answered = owner.request(&caller, resolved(display), action, &copied);
        (answered, copied.load(Ordering::Acquire))
    });
    tokio::task::spawn_blocking(move || before.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches the wait before its transaction");
    let held = present_and_hold(presenter).await;
    go_in.send(()).expect("the record begins");
    tokio::task::spawn_blocking(move || after_the_feed.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches the end of the feed's ask");
    held.swap().await;
    go_on.send(()).expect("the record goes on");
    let (answered, copied) = asking.await.expect("the request ends");
    let rows = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            [action.0.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    Found {
        answered,
        copied,
        rows,
    }
}

fn written(found: &Found) {
    let answered = found.answered.as_ref().expect("the request is answered");
    assert!(!found.copied, "the request was recorded here, not copied");
    assert!(
        matches!(
            &answered.request.action,
            SensitiveAction::ChangeHostAuthority
        ),
        "the challenge is the one asked for: {answered:?}"
    );
    assert_eq!(found.rows, 1, "the record is written once");
}

fn refused_as_a_caller_no_lease_serves(found: &Found) {
    let refusal = found.answered.as_ref().expect_err("the request is refused");
    let closed = closed_refusal();
    assert_eq!(refusal.to_string(), closed.to_string());
    assert_eq!(refusal.code(), closed.code());
    assert_eq!(found.rows, 0, "nothing is written");
}

/// KR-REQ-17.54: where the bound of the lease stands at the copy, the request is recorded, for a
/// subject that the recovery set holds and for one it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_lease_stands_at_its_question_is_recorded() {
    written(&recorded_with(Ends::Nothing, establishing()).await);
    written(&recorded_with(Ends::Nothing, making_exclusive()).await);
}

/// KR-REQ-17.54: a lease that ends in the last wait, after the feed was asked and before the bound
/// is copied, is found by the question, and the subject is decided again under the scope that no
/// lease serves: the confirmation of the clock is recorded, and the one the recovery set does not
/// hold is refused in the door's own words, with nothing written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_lease_ends_in_the_last_wait_is_decided_again_under_the_closed_scope() {
    written(&recorded_with(Ends::TheLeasesTime, establishing()).await);
    refused_as_a_caller_no_lease_serves(
        &recorded_with(Ends::TheLeasesTime, making_exclusive()).await,
    );
}

/// KR-REQ-17.54: a request whose deadline passes in the last wait is refused in the words of the
/// deadline, whole, whatever it asks for and whatever the scope that no lease serves holds: the
/// deadline is the footing's, and is not decided again under another scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_deadline_passes_in_the_last_wait_is_refused_in_the_deadlines_words() {
    for display in [establishing(), making_exclusive()] {
        let found = recorded_with(Ends::TheDeadlinePasses, display).await;
        let refusal = found.answered.as_ref().expect_err("the request is refused");
        let expired =
            crate::service::Lapse::Admission(crate::authority::AdmissionLapse::Expired).refusal();
        assert_eq!(refusal.to_string(), expired.to_string());
        assert_eq!(refusal.code(), expired.code());
        assert_eq!(found.rows, 0, "nothing is written");
    }
}

/// KR-REQ-17.54: a lease that is presented again in the last wait moves the bound to another
/// lineage, which counts as an ended lease: the subject is decided again under the closed scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_bound_moves_before_its_transaction_is_decided_again_under_the_closed_scope()
 {
    written(&recorded_with(Ends::TheLeaseIsPresentedAgain, establishing()).await);
    refused_as_a_caller_no_lease_serves(
        &recorded_with(Ends::TheLeaseIsPresentedAgain, making_exclusive()).await,
    );
}

/// A caller that no door landed is refused in the words of a mutation that carries no freshness,
/// and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_from_a_caller_with_no_landing_is_refused_and_writes_nothing() {
    let (temp, controller, ..) = connected_under_a_lease_that_can_be_presented_again().await;
    let door = Door::open(&temp, &controller).await;
    let caller = controller.local_caller(door.actor_id());
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([4; 32]),
    );
    let owner = Arc::clone(controller.owner_authority());
    let answered = tokio::task::spawn_blocking(move || {
        owner.request(
            &caller,
            resolved(establishing()),
            action,
            &AtomicBool::new(false),
        )
    })
    .await
    .expect("the request ends");
    let Err(ControllerError::WindowExpired { detail }) = answered else {
        panic!("a caller with no landing is refused as one that carries no freshness");
    };
    assert_eq!(
        detail,
        "this action carries no freshness, so it may be answered from what this host holds and \
         may not write"
    );
    let rows = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            [action.0.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    assert_eq!(rows, 0, "nothing is written");
}

/// KR-REQ-17.54: a lease presented again whose bound moves inside the record's transaction, after
/// the feed's locked ask and before the bound is copied, is found by the question: the subject is
/// decided again under the scope that no lease serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_bound_moves_inside_its_transaction_is_decided_again_under_the_closed_scope()
 {
    written(&recorded_with_the_bound_moving_inside(establishing()).await);
    refused_as_a_caller_no_lease_serves(
        &recorded_with_the_bound_moving_inside(making_exclusive()).await,
    );
}
