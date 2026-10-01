//! The answer to a revocation stays inside what one control frame decodes.
//!
//! | Requirement | Tests |
//! | --- | --- |
//! | KR-REQ-09.12 | `an_answer_inside_the_limits_is_kept_whole`, `an_answer_past_the_collection_bound_is_cut_to_what_decodes_and_counts_what_it_cut`, `every_list_is_cut_to_a_prefix_in_identity_order`, `a_worker_list_larger_than_a_frame_keeps_every_worker_whose_barrier_has_not_held`, `a_cut_barrier_reads_as_the_whole_one_would`, `names_that_alone_fill_a_frame_are_cut_to_what_one_frame_carries` |

use kr_cbor::Limits;
use kr_protocol::action::{
    BarrierState, FencedAction, PossiblyExecutedAction, RevocationBarrier, WorkerBarrier,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision, GrantId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::sharing::RevocationResult;

fn grant(index: u128) -> GrantId {
    GrantId::new(Uuid::from_bytes((0x1000_u128 + index).to_be_bytes()))
}

fn session(index: u128) -> SessionId {
    SessionId::new(Uuid::from_bytes((0x2000_u128 + index).to_be_bytes()))
}

fn action(index: u128) -> ActionId {
    ActionId::new(Uuid::from_bytes((0x3000_u128 + index).to_be_bytes()))
}

fn actor() -> ActorId {
    ActorId::new("device:phone").expect("a principal")
}

fn fenced(index: u128) -> FencedAction {
    FencedAction {
        actor_id: actor(),
        action_id: action(index),
    }
}

fn executed(index: u128) -> PossiblyExecutedAction {
    PossiblyExecutedAction {
        action_id: action(index),
        actor_id: actor(),
        method: Method::AgentApprovalRespond.into(),
        state: ReceiptState::Unknown,
    }
}

fn worker(index: u128, state: BarrierState) -> WorkerBarrier {
    WorkerBarrier {
        session_id: session(index),
        state,
        acknowledged_revision: Nullable::null(),
        rejected_actions: Vec::new(),
        rejected_actions_total: U64::new(0),
        possibly_executed: Vec::new(),
        possibly_executed_total: U64::new(0),
        omitted_actions: U64::new(0),
        names_pending: U64::new(0),
        detail: String::new(),
    }
}

fn revision() -> AuthorityRevision {
    AuthorityRevision::new(4)
}

/// The answer as the daemon writes it: inside a response frame on the control stream, then read
/// back by the decoder every caller has.
fn through_a_control_frame(answer: &RevocationResult) -> RevocationResult {
    let frame = ControlFrame::Response(Response {
        request_id: RequestId::new(7),
        outcome: Outcome::Ok(ParamsValue::from_typed(answer).expect("the answer is a value")),
    });
    let codec = FrameCodec::new(StreamKind::Control);
    let bytes = codec
        .encode_message(&frame)
        .expect("the answer fits one control frame");
    let (decoded, _) = codec
        .decode_message::<ControlFrame>(&bytes)
        .expect("the frame decodes");
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(result),
        ..
    }) = decoded
    else {
        panic!("a response");
    };
    result.to_typed().expect("the answer decodes")
}

/// An answer that fits is the revocation as it happened: nothing is cut, and each total is how many
/// its list holds.
#[test]
fn an_answer_inside_the_limits_is_kept_whole() {
    let mut named = worker(1, BarrierState::Acknowledged);
    named.rejected_actions = vec![fenced(1), fenced(2)];
    named.possibly_executed = vec![executed(3)];
    let answer = RevocationResult::bounded(
        revision(),
        (0..3).map(grant),
        RevocationBarrier::new(
            revision(),
            vec![named.clone(), worker(2, BarrierState::Ended)],
        ),
    );
    assert_eq!(answer.revoked_grants.len(), 3);
    assert_eq!(answer.revoked_grants_total.get(), 3);
    assert_eq!(answer.barrier.workers_total.get(), 2);
    assert_eq!(answer.barrier.workers[0].rejected_actions.len(), 2);
    assert_eq!(answer.barrier.workers[0].rejected_actions_total.get(), 2);
    assert_eq!(answer.barrier.workers[0].possibly_executed_total.get(), 1);
    assert!(answer.fits_a_frame());
    assert_eq!(through_a_control_frame(&answer), answer);
}

/// KR-REQ-09.12: a revocation that names more grants than a collection holds is answered with an
/// answer the decoder reads, and the answer says how many there were.
///
/// At the base the answer carried every grant, and the caller's decoder refused it.
#[test]
fn an_answer_past_the_collection_bound_is_cut_to_what_decodes_and_counts_what_it_cut() {
    let grants = Limits::DEFAULT.max_collection_len as u128 + 1;
    let answer = RevocationResult::bounded(
        revision(),
        (0..grants).map(grant),
        RevocationBarrier::new(revision(), Vec::new()),
    );
    assert_eq!(
        answer.revoked_grants_total.get(),
        grants as u64,
        "the total is counted before the cut"
    );
    assert!(
        answer.revoked_grants.len() <= Limits::DEFAULT.max_collection_len,
        "the list is cut to one collection"
    );
    assert!(answer.revoked_grants.len() < grants as usize);
    assert!(answer.fits_a_frame());
    let read = through_a_control_frame(&answer);
    assert_eq!(read, answer);
    assert_eq!(read.revoked_grants_total.get(), grants as u64);
}

/// The cut is the same every time and keeps the front of the identity order, so a caller that asks
/// again is told the same members.
#[test]
fn every_list_is_cut_to_a_prefix_in_identity_order() {
    let grants = Limits::DEFAULT.max_collection_len as u128 + 50;
    let mut crowded = worker(1, BarrierState::Acknowledged);
    // Given out of order: the cut sorts them.
    crowded.rejected_actions = (0..5_000).rev().map(fenced).collect();
    crowded.possibly_executed = (0..5_000).rev().map(executed).collect();
    let barrier = RevocationBarrier::new(revision(), vec![crowded]);
    let first =
        RevocationResult::bounded(revision(), (0..grants).rev().map(grant), barrier.clone());
    let again = RevocationResult::bounded(revision(), (0..grants).map(grant), barrier);
    assert_eq!(first, again, "the same revocation is answered the same way");

    let kept: Vec<GrantId> = first.revoked_grants.iter().copied().collect();
    let expected: Vec<GrantId> = (0..kept.len() as u128).map(grant).collect();
    assert_eq!(kept, expected, "the grants kept are the first in order");

    let crowded = &first.barrier.workers[0];
    assert!(crowded.rejected_actions.len() < 5_000);
    assert_eq!(crowded.rejected_actions_total.get(), 5_000);
    let expected: Vec<FencedAction> = (0..crowded.rejected_actions.len() as u128)
        .map(fenced)
        .collect();
    assert_eq!(crowded.rejected_actions, expected);
    assert!(crowded.possibly_executed.len() < 5_000);
    assert_eq!(crowded.possibly_executed_total.get(), 5_000);
    let expected: Vec<PossiblyExecutedAction> = (0..crowded.possibly_executed.len() as u128)
        .map(executed)
        .collect();
    assert_eq!(crowded.possibly_executed, expected);
    assert_eq!(through_a_control_frame(&first), first);
}

/// A host that holds more workers than a frame carries still answers: the workers whose barrier has
/// not held are kept before any that has, so the caller reads what it would of the whole.
#[test]
fn a_worker_list_larger_than_a_frame_keeps_every_worker_whose_barrier_has_not_held() {
    let workers = Limits::DEFAULT.max_collection_len as u128 * 3;
    let pending: Vec<u128> = vec![workers - 1, workers - 2, 0];
    let barrier = RevocationBarrier::new(
        revision(),
        (0..workers)
            .map(|index| {
                worker(
                    index,
                    if pending.contains(&index) {
                        BarrierState::Pending
                    } else {
                        BarrierState::Ended
                    },
                )
            })
            .collect(),
    );
    let answer = RevocationResult::bounded(revision(), std::iter::empty(), barrier);
    assert_eq!(answer.barrier.workers_total.get(), workers as u64);
    assert!(answer.barrier.workers.len() <= Limits::DEFAULT.max_collection_len);
    assert!((answer.barrier.workers.len() as u128) < workers);
    for index in &pending {
        assert!(
            answer
                .barrier
                .workers
                .iter()
                .any(|kept| kept.session_id == session(*index)),
            "the pending worker {index} is kept"
        );
    }
    assert!(answer.fits_a_frame());
    let read = through_a_control_frame(&answer);
    assert_eq!(read, answer);
    assert_eq!(read.barrier.pending().len(), pending.len());
    assert!(
        read.barrier
            .workers
            .windows(2)
            .all(|pair| pair[0].session_id < pair[1].session_id),
        "the workers kept are in session order"
    );
}

/// Whatever is cut, the barrier reads the way the whole one would: it holds on the cut list exactly
/// when it holds on the whole one, and a pending worker is never the one left out.
#[test]
fn a_cut_barrier_reads_as_the_whole_one_would() {
    let workers = Limits::DEFAULT.max_collection_len as u128 + 100;
    let every = |state_of: &dyn Fn(u128) -> BarrierState| {
        RevocationBarrier::new(
            revision(),
            (0..workers)
                .map(|index| worker(index, state_of(index)))
                .collect(),
        )
    };

    let none_pending = every(&|_| BarrierState::Acknowledged);
    assert!(none_pending.holds());
    let cut = RevocationResult::bounded(revision(), std::iter::empty(), none_pending).barrier;
    assert!(cut.workers.len() < workers as usize, "the list is cut");
    assert!(cut.holds(), "and still holds");
    assert_eq!(cut.workers_total.get(), workers as u64);

    let last_pending = every(&|index| {
        if index == workers - 1 {
            BarrierState::Pending
        } else {
            BarrierState::Acknowledged
        }
    });
    assert!(!last_pending.holds());
    let cut = RevocationResult::bounded(revision(), std::iter::empty(), last_pending).barrier;
    assert!(cut.workers.len() < workers as usize);
    assert!(!cut.holds(), "the last worker is pending and is kept");
    assert_eq!(cut.pending(), vec![session(workers - 1)]);

    let all_pending = every(&|_| BarrierState::Pending);
    let cut = RevocationResult::bounded(revision(), std::iter::empty(), all_pending).barrier;
    assert!(!cut.holds());
    assert_eq!(cut.workers_total.get(), workers as u64);
    assert_eq!(cut.pending().len(), cut.workers.len());
}

/// Names that alone fill a frame are cut by what the frame carries, not by a count: a worker with a
/// long detail line and many long action names still answers inside the frame.
#[test]
fn names_that_alone_fill_a_frame_are_cut_to_what_one_frame_carries() {
    let mut crowded = worker(1, BarrierState::Acknowledged);
    crowded.detail = "a worker that kept every name it was given ".repeat(50);
    crowded.rejected_actions = (0..4_000).map(fenced).collect();
    crowded.possibly_executed = (0..4_000).map(executed).collect();
    let mut second = worker(2, BarrierState::Acknowledged);
    second.possibly_executed = (0..4_000).map(executed).collect();
    let answer = RevocationResult::bounded(
        revision(),
        (0..Limits::DEFAULT.max_collection_len as u128).map(grant),
        RevocationBarrier::new(revision(), vec![crowded, second]),
    );
    assert!(answer.fits_a_frame());
    let read = through_a_control_frame(&answer);
    assert_eq!(read.revoked_grants_total.get(), 4_096);
    assert_eq!(read.barrier.workers[0].rejected_actions_total.get(), 4_000);
    assert_eq!(read.barrier.workers[0].possibly_executed_total.get(), 4_000);
    assert_eq!(read.barrier.workers[1].possibly_executed_total.get(), 4_000);
    assert!(
        read.barrier
            .workers
            .iter()
            .map(|worker| worker.possibly_executed.len())
            .sum::<usize>()
            < 8_000,
        "the names are cut to what the frame carries"
    );
}
