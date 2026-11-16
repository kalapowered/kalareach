//! Where the owner's list of outstanding confirmations lands.
//!
//! The local door lists the challenges twice, from the same entries and before the local owner's
//! lease is asked again: the list under the scope the caller was decided for, and the list under
//! the scope that no lease serves. The bound of the lease the first was decided under is held by
//! the list's carrier, since a read has no landing of its own. The writer asks the footing's one
//! question with that bound immediately before the transport takes any byte, and that question
//! alone chooses which list the transport takes.
//!
//! The order of events of each case: the daemon's read of the list ends (its last real wait is the
//! join of the blocking read that made both lists); the case makes the footing the door makes
//! after that read; the case ends what it ends, in a step of its own, with nothing running beside
//! it; the writer is then called, and its question stands after that step. The writer's own waits
//! are the lease's reading, which a method held to the lease takes and this method does not, and
//! the wait for room on a full socket, which a case cannot stage with the frame unstarted. The
//! replies are read whole.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kr_protocol::confirmation::{
    ConfirmationDisplay, OwnerConfirmationPendingParams, OwnerConfirmationPendingResult,
    PendingConfirmation,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActionId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256};

use super::a_result_the_lease_ended_over::connected_under_a_lease_that_can_be_presented_again;
use super::an_owner_establishes_the_clock::Door;
use crate::given::local_door::WrittenUnder;
use crate::service::net::owner::Resolved;

const REQUEST: RequestId = RequestId::new(11);

/// What ends between the daemon's read of the list and the writer's question.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// Nothing: the control.
    Nothing,
    /// The lease's time: the continuous clock passes its end.
    TheLeasesTime,
    /// The lease is presented again, which publishes another lineage in the bound's cell.
    TheLeaseIsPresentedAgain,
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

/// The reply that carries `list` to the request, as the door tells it.
fn told(list: &[PendingConfirmation]) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(
            ParamsValue::from_typed(&OwnerConfirmationPendingResult {
                pending: list.to_vec(),
            })
            .expect("the list encodes"),
        ),
    })
}

/// What the writer put on the connection when `ends` came after the daemon's read of the list and
/// before the writer's question, and the two lists that could have been written: the one the caller
/// was decided for and the one that no lease serves.
async fn written_when(ends: Ends) -> (ControlFrame, ControlFrame, ControlFrame) {
    let (temp, controller, continuous, presenter, mut writer, mut reader) =
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
    // Two challenges: the confirmation of the clock, which the scope that no lease serves holds,
    // and the one that makes the host exclusive, which it does not.
    let displays = [
        ConfirmationDisplay::EstablishClock,
        ConfirmationDisplay::ExclusiveManagement {
            exclusive: true,
            organisation_ids: Vec::new(),
        },
    ];
    let mut every = Vec::new();
    for (position, display) in displays.into_iter().enumerate() {
        let owner = Arc::clone(controller.owner_authority());
        let caller = caller.clone();
        let shown = display.clone();
        let action = (
            ActionId::new(kr_ipc::new_uuid()),
            Digest256::from_bytes([3 + u8::try_from(position).expect("a small position"); 32]),
        );
        let requested = tokio::task::spawn_blocking(move || {
            owner.request(&caller, resolved(display), action, &AtomicBool::new(false))
        })
        .await
        .expect("the request ends")
        .expect("the request is recorded");
        every.push(PendingConfirmation {
            request: requested.request,
            display: shown,
            answered: false,
        });
    }
    let closed = told(&every[..1]);
    let full = told(&every);
    let request = Request {
        request_id: REQUEST,
        method: Method::OwnerConfirmationPending.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&OwnerConfirmationPendingParams {})
            .expect("the parameters encode"),
    };
    let (answer, instead) = controller.local_read(door.actor_id(), &request).await;
    let under = WrittenUnder::of_a_read(controller.footing_of_a_request(door.connection_id()))
        .listing(instead);
    match ends {
        Ends::Nothing => {}
        Ends::TheLeasesTime => continuous.advance(Duration::from_secs(16 * 60)),
        Ends::TheLeaseIsPresentedAgain => presenter.present(&[ActionRight::FilesRead]),
    }
    let writing = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let stood = controller
                .write_answer(
                    &mut writer,
                    StreamKind::Control,
                    &answer,
                    Some(Method::OwnerConfirmationPending),
                    REQUEST,
                    &under,
                )
                .await;
            drop(writer);
            stood
        })
    };
    let read = tokio::time::timeout(Duration::from_secs(30), reader.read_message())
        .await
        .expect("the daemon wrote or ended the connection")
        .expect("the list reads");
    assert!(
        writing.await.expect("the write ends"),
        "the connection goes on"
    );
    (read, full, closed)
}

/// KR-REQ-17.54: where the bound the list was decided under stands at the question, the list the
/// caller was decided for is written, whole: both challenges, oldest first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_stands_at_its_question_is_written_whole() {
    let (read, full, closed) = written_when(Ends::Nothing).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, full);
}

/// KR-REQ-17.54: a lease that ends after the daemon's read of the list and before the writer's
/// question is found by the question: the list under the scope that no lease serves is written,
/// whole, and the challenge it does not hold is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_ends_before_the_question_is_written_under_the_closed_scope() {
    let (read, full, closed) = written_when(Ends::TheLeasesTime).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
}

/// KR-REQ-17.54: a lease that is presented again before the writer's question moves the bound to another
/// lineage, which counts as an ended lease: the list under the scope that no lease serves is
/// written, whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_moves_before_the_question_is_written_under_the_closed_scope() {
    let (read, full, closed) = written_when(Ends::TheLeaseIsPresentedAgain).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
}
