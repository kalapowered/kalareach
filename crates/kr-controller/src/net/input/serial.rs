//! The serial adapter: terminal input for a worker that does not state the input lane.
//!
//! Such a worker has no lane to bind, so the host carries each frame of the device's stream over
//! the link that carries the worker's other requests, as an `input.write`, and reads the worker's
//! answer before it reads the next frame: one call is outstanding for a stream at any time. A
//! device's window bounds what waits behind the call.
//!
//! The adapter keeps what the worker did and tells the device nothing else. A frame the worker
//! refused before it could accept it is told as refused, once for its epoch, and is never sent
//! again; the worker consumes a sequence it refuses for room, so a retry would only be refused
//! again. A frame that the worker may have accepted is told nothing, and the stream is cut, so the
//! device counts it uncertain; nothing is replayed. The adapter invents no count of discarded
//! bytes: the worker tells the lane nothing of its lease, so the device hears of a lease's end
//! from the worker's answer to the release or the detach that ends it, or not at all, and a view
//! whose typing the worker discards at a takeover is told nothing until its next frame is refused.
//!
//! The host's own check of a release's, a detach's or a launch's position is the only one for such
//! a worker ([`super::barrier`]), since the members that carry it are taken out of the request.
//!
//! This module, the strip of those members
//! ([`kr_protocol::retained::strip_input_lane_members`]) and the choice that
//! [`super::InputStreams::serves_lane`] makes go once no supported live worker lacks the
//! capability, which is from the cut that retains the level that first states the input lane.

use std::future::Future;
use std::sync::Arc;

use kr_protocol::envelope::{Outcome, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AttachmentId, RequestId, SessionId};
use kr_protocol::input::InputFrame;
use kr_transport::streams::{DataReader, StreamHandle};
use tokio::sync::{oneshot, watch};

use super::{End, Flow, Outstanding, ReadLetGo, lease_lost, refusal, write_request};
use crate::error::ControllerError;
use crate::service::net::chunks::DataDoor;
use crate::service::net::proxy::{Forwarded, WorkerProxy};

/// What the host makes of a call's result.
enum Class {
    /// The worker accepted the frame, or refused it before it could accept it: the device is told
    /// what the worker said.
    Answered(Outcome),
    /// The call was never sent: the authority behind the frame was withdrawn while the call waited
    /// to be written. The worker has none of the frame.
    NotSent(ProtocolError),
    /// The worker may have accepted the frame, or the host cannot know: nothing is told.
    Uncertain,
}

/// Reads the result of one call. Only an error that can precede acceptance is a refusal: the
/// worker gives these before it accepts a frame, and an older worker can accept a frame and then
/// replace its answer with the refusal of the link, which carries the mark that a refusal before
/// acceptance may carry as well, so a marked error shows nothing. Any other code, an answer that
/// never came and a link that was lost leave the outcome unknown.
fn classify(result: Result<Forwarded, ControllerError>) -> Class {
    match result {
        Ok(Forwarded {
            response,
            link_fenced,
            ..
        }) => match &response.outcome {
            Outcome::Ok(_) => Class::Answered(response.outcome),
            Outcome::Error(error) if !link_fenced && precedes_acceptance(error.code) => {
                Class::Answered(response.outcome)
            }
            Outcome::Error(_) => Class::Uncertain,
        },
        Err(error @ ControllerError::PermissionDenied { .. }) => {
            Class::NotSent(error.to_protocol_error())
        }
        Err(_) => Class::Uncertain,
    }
}

/// Whether a worker gives `code` only before it accepts a frame.
const fn precedes_acceptance(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::LeaseLost
            | ErrorCode::InvalidArgument
            | ErrorCode::SessionClosed
            | ErrorCode::ResourceUnavailable
            | ErrorCode::PermissionDenied
    )
}

/// The `input.write` that carries `frame` to the worker, or the refusal when the frame cannot be
/// encoded.
fn request_for(
    request_id: RequestId,
    session: SessionId,
    attachment: AttachmentId,
    frame: InputFrame,
) -> Result<Request, ProtocolError> {
    write_request(request_id, session, attachment, frame)
        .ok_or_else(|| refusal("this typing could not be encoded"))
}

/// Reads the stream and carries each frame to the worker in turn. Returns when the stream ends.
///
/// A read that is dropped part way resets the stream, so one read is kept pending across the
/// waits, and while a call is outstanding it takes no data and only watches for the device's
/// reset.
pub(super) async fn run(
    door: &Arc<DataDoor>,
    reader: &mut DataReader,
    flow: &Arc<Flow>,
    proxy: &Arc<WorkerProxy>,
    session: SessionId,
    attachment: AttachmentId,
    acks_flushed: oneshot::Receiver<()>,
) {
    let handle = reader.handle();
    let mut version = flow.subscribe();
    // Declared before the pending read, so it is dropped after it.
    let _let_go = ReadLetGo(&flow.stages);
    let (room, mut room_rx) = watch::channel(false);
    let mut next = Box::pin(reader.read_message_when::<InputFrame>(&mut room_rx));
    loop {
        // Marked before the state is looked at, the end included, so a change after the look is
        // never missed.
        version.borrow_and_update();
        if flow.ended().is_some() || handle.is_revoked() {
            break;
        }
        room.send_replace(true);
        tokio::select! {
            _ = version.changed() => {}
            read = &mut next => match read {
                Ok(Some(frame)) => {
                    flow.stages.frame_read();
                    room.send_replace(false);
                    drop(next);
                    next = Box::pin(reader.read_message_when::<InputFrame>(&mut room_rx));
                    if !flow.take(frame.epoch) {
                        // The epochs of the frames on a stream never go back: this one is not an
                        // honest device's, and the stream is cut as for a malformed frame.
                        flow.end(End::Cut);
                        return;
                    }
                    carry(door, flow, proxy, session, attachment, frame, &handle, &mut version, &mut next)
                        .await;
                }
                Ok(None) => {
                    // The device is done and nothing it wrote is waiting: the stream finishes.
                    flow.end(End::Graceful);
                    break;
                }
                Err(_) => {
                    flow.end(End::Cut);
                    return;
                }
            },
            () = handle.revoked() => return,
        }
    }
    if flow.ended() == Some(End::Graceful) {
        // What the device is owed is written, and the writing half finishes, before the pending
        // read is let go.
        flow.stages.read_ends();
        let _ = acks_flushed.await;
    }
}

/// Carries one frame: decides it afresh, as a key is decided, makes one call and tells the device
/// what the worker said. A frame behind a refusal of its epoch or a newer one is not passed on.
#[allow(clippy::too_many_arguments)]
async fn carry(
    door: &Arc<DataDoor>,
    flow: &Arc<Flow>,
    proxy: &Arc<WorkerProxy>,
    session: SessionId,
    attachment: AttachmentId,
    frame: InputFrame,
    handle: &StreamHandle,
    version: &mut watch::Receiver<u64>,
    resets: &mut (impl Future<Output = kr_transport::Result<Option<InputFrame>>> + Unpin),
) {
    let epoch = frame.epoch;
    let sequence = frame.sequence.get();
    if flow.lock().cut_off(epoch) {
        flow.refuse(epoch, sequence, lease_lost());
        return;
    }
    let decision = match door.remote.decide_an_input_frame(session).await {
        Ok(decision) => decision,
        Err(error) => {
            flow.refuse(epoch, sequence, error);
            return;
        }
    };
    let request_id = flow.next_request_id();
    let request = match request_for(request_id, session, attachment, frame) {
        Ok(request) => request,
        Err(error) => {
            flow.refuse(epoch, sequence, error);
            return;
        }
    };
    flow.stages.before_a_serial_call().await;
    {
        let mut state = flow.lock();
        state.in_flight += 1;
        state.outstanding.push_back(Outstanding {
            request_id,
            epoch,
            sequence,
            // The call bounds its own exchange, so this deadline is never read.
            deadline: tokio::time::Instant::now() + flow.stages.frame_deadline(),
            _unanswered: flow.stages.unanswered_frame(),
        });
    }
    // The call runs on a task of its own: a call dropped part way through its write breaks the
    // link for the worker's other requests, so the stream's end never drops it.
    let controller = Arc::clone(door.remote.controller());
    #[cfg(feature = "testing")]
    let scripted = flow.stages.scripted_call(&request);
    let proxy = Arc::clone(proxy);
    let mut call = tokio::spawn(async move {
        #[cfg(feature = "testing")]
        if let Some(scripted) = scripted {
            return scripted.await;
        }
        proxy
            .forward_read_whole(
                &request,
                &decision.actor,
                decision.authority_deadline,
                None,
                &|| controller.refuse_while_the_feed_refuses(&decision.standing),
            )
            .await
    });
    let joined = loop {
        version.borrow_and_update();
        if flow.ended().is_some() {
            // The end stands as it was decided: the frame is left with no word of its own.
            return;
        }
        tokio::select! {
            joined = &mut call => break joined,
            _ = version.changed() => {}
            _ = &mut *resets => {
                flow.end(End::Cut);
                return;
            }
            () = handle.revoked() => return,
        }
    };
    let class = joined.map_or(Class::Uncertain, classify);
    match class {
        Class::Answered(outcome) => {
            if !flow.answer(&Response {
                request_id,
                outcome,
            }) {
                flow.end(End::Cut);
            }
        }
        Class::NotSent(error) => {
            flow.unsent(request_id);
            flow.refuse(epoch, sequence, error);
            flow.end(End::Graceful);
        }
        Class::Uncertain => flow.end(End::Cut),
    }
}

#[cfg(test)]
mod tests {
    use kr_cbor::CanonicalValue;
    use kr_protocol::ids::InputLeaseEpoch;
    use kr_protocol::input::{InputContent, InputWriteParams};
    use kr_protocol::retained::{Level, RETAINED};
    use kr_protocol::scalars::{Bytes, Uuid};

    use super::*;

    fn written() -> Request {
        let frame = InputFrame {
            epoch: InputLeaseEpoch::new(3),
            sequence: kr_protocol::ids::InputSequence::new(0),
            bytes: Bytes::new(b"ls\r".to_vec()),
        };
        request_for(
            RequestId::new(1),
            SessionId::new(Uuid::from_bytes([1; 16])),
            AttachmentId::new(Uuid::from_bytes([2; 16])),
            frame,
        )
        .expect("the frame is written")
    }

    fn member<'a>(request: &'a Request, name: &str) -> Option<&'a CanonicalValue> {
        match request.params.as_value() {
            CanonicalValue::Map(map) => map.get(name),
            _ => panic!("the parameters of a write are a map"),
        }
    }

    /// Every worker the host serves reads the `input` union, so a frame is written as it is: the
    /// bytes inside the union, and no bytes at the top of the parameters.
    #[test]
    fn a_frame_is_written_as_the_input_union() {
        let request = written();
        assert!(
            member(&request, "input").is_some(),
            "this level reads the union"
        );
        assert!(member(&request, "bytes").is_none(), "no bytes at the top");
    }

    /// A worker of the retained level reads the frame as the bytes of the union: that level's own
    /// surface decodes the parameters, and what it reads is the bytes the device sent.
    #[test]
    fn a_worker_of_the_retained_level_reads_the_frame_as_bytes_in_the_union() {
        let request = written();
        let read: InputWriteParams = Level::retained(&RETAINED[0])
            .decode_value(&request.params)
            .expect("the retained level reads the parameters");
        assert_eq!(
            read.input,
            InputContent::Bytes {
                bytes: Bytes::new(b"ls\r".to_vec())
            },
            "the retained level reads the bytes of the union"
        );
    }
}
