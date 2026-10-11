//! The answers to a voice stop and to a replacement of the voice grant stay inside what one control
//! frame decodes, however many actions the fence they owed named.
//!
//! | Requirement | Tests |
//! | --- | --- |
//! | KR-REQ-09.12 | `a_stop_whose_fence_named_more_actions_than_a_frame_holds_is_answered_in_a_frame`, `a_replacement_whose_fence_named_more_actions_than_a_frame_holds_is_answered_in_a_frame`, `a_barrier_that_fits_is_carried_whole` |

use kr_cbor::Limits;
use kr_protocol::action::{
    BarrierState, FencedAction, PossiblyExecutedAction, RevocationBarrier, WorkerBarrier,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::ids::{
    ActionId, ActorId, AuthorityRevision, DeviceId, GrantId, RequestId, SessionId, VoiceSessionId,
};
use kr_protocol::method::Method;
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::voice::{VoiceAction, VoiceGrantResult, VoiceGrantStatement, VoiceStopResult};
use kr_protocol::wire::WireMessage;
use serde::Serialize;

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

fn stopped() -> VoiceStopResult {
    VoiceStopResult {
        voice_session_id: VoiceSessionId::new(Uuid::from_bytes([0x41; 16])),
        revoked_grant_id: GrantId::new(Uuid::from_bytes([0x42; 16])),
        revoked_at_ms: TimestampMs::new(1_700_000_000_000),
        broker_notified: true,
        sessions_left_running: [session(1), session(2)].into_iter().collect(),
        barrier: Nullable::null(),
    }
}

fn replaced() -> VoiceGrantResult {
    let actions: CanonicalSet<VoiceAction> = [VoiceAction::Status].into_iter().collect();
    VoiceGrantResult {
        grant_id: GrantId::new(Uuid::from_bytes([0x43; 16])),
        device_id: DeviceId::new(Uuid::from_bytes([0x44; 16])),
        statement: VoiceGrantStatement::of(&actions),
        not_held_by_device: CanonicalSet::new(),
        barrier: Nullable::null(),
    }
}

/// A barrier whose pending worker, and one that has held, each name more actions than a collection
/// of the decoder holds.
fn a_crowded_barrier() -> RevocationBarrier {
    let names = Limits::DEFAULT.max_collection_len + 904;
    let mut pending = worker(1, BarrierState::Pending);
    pending.rejected_actions = (0..names as u128).rev().map(fenced).collect();
    pending.rejected_actions_total = U64::new(names as u64);
    pending.possibly_executed = (0..names as u128).rev().map(executed).collect();
    pending.possibly_executed_total = U64::new(names as u64);
    let mut held = worker(2, BarrierState::Acknowledged);
    held.rejected_actions = (0..names as u128).map(fenced).collect();
    held.rejected_actions_total = U64::new(names as u64);
    RevocationBarrier::new(revision(), vec![pending, held])
}

/// The answer as the daemon writes it, inside a response frame on the control stream, then read
/// back by the decoder every caller has; the host keeps and gives back the same bytes.
fn through_a_control_frame<T: WireMessage>(answer: &T) -> T {
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

/// The same answer kept as the claim keeps it and read back with the decoder's own limits.
fn kept_and_read_again<T: Serialize + WireMessage>(answer: &T) -> T {
    let kept = kr_cbor::to_canonical_vec(answer).expect("the claim keeps the answer");
    kr_cbor::from_canonical_slice(&kept, &Limits::DEFAULT).expect("a repeat is given it back")
}

/// KR-REQ-09.12: a fence can name more actions than one frame carries, and the stop it belongs to
/// takes effect whatever it named. The answer is cut as a revocation's is: it decodes, the totals
/// say what was cut, and the worker that has not held is still named as pending.
///
/// Without the cut the answer was encoded whole: the frame encoder refused it and the claim kept it,
/// so the device was given no answer and a repeat could not decode what was kept.
#[test]
fn a_stop_whose_fence_named_more_actions_than_a_frame_holds_is_answered_in_a_frame() {
    let whole = a_crowded_barrier();

    let answer = stopped().with_barrier(whole.clone());
    assert!(answer.fits_a_frame());
    let barrier = answer
        .barrier
        .0
        .clone()
        .expect("the stop carries its barrier");
    assert_eq!(barrier.pending(), whole.pending(), "pending is pending");
    assert_eq!(barrier.holds(), whole.holds());
    let crowded = &barrier.workers[0];
    assert_eq!(crowded.rejected_actions_total.get(), 5_000);
    assert!(crowded.rejected_actions.len() <= Limits::DEFAULT.max_collection_len);
    assert!(crowded.rejected_actions.len() < 5_000);
    assert_eq!(through_a_control_frame(&answer), answer);
    assert_eq!(kept_and_read_again(&answer), answer);
}

/// KR-REQ-09.12: the same for the replacement of the standing grant, which ends the calls under the
/// grant it replaces and owes the same fence.
#[test]
fn a_replacement_whose_fence_named_more_actions_than_a_frame_holds_is_answered_in_a_frame() {
    let whole = a_crowded_barrier();

    let answer = replaced().with_barrier(whole.clone());
    assert!(answer.fits_a_frame());
    let barrier = answer
        .barrier
        .0
        .clone()
        .expect("the replacement carries its barrier");
    assert_eq!(barrier.pending(), whole.pending());
    assert_eq!(barrier.workers[0].possibly_executed_total.get(), 5_000);
    assert_eq!(through_a_control_frame(&answer), answer);
    assert_eq!(kept_and_read_again(&answer), answer);
}

/// A barrier inside the limits is the barrier as it was, with nothing cut.
#[test]
fn a_barrier_that_fits_is_carried_whole() {
    let mut named = worker(1, BarrierState::Pending);
    named.rejected_actions = vec![fenced(1), fenced(2)];
    named.rejected_actions_total = U64::new(2);
    let whole = RevocationBarrier::new(revision(), vec![named, worker(2, BarrierState::Ended)]);

    let answer = stopped().with_barrier(whole.clone());

    assert_eq!(answer.barrier.0, Some(whole));
    assert!(answer.fits_a_frame());
}
