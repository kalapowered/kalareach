//! The worker's side of an input lane: the bind, and the task that writes what the worker has to
//! say on it.
//!
//! A lane is a connection of the control daemon's, declared as an input proxy before it presents
//! its token. Its first frame names the proxy connection that owns the attachment and the
//! attachment itself. The worker binds it only under a live proxy of the same generation that owns
//! that attachment, and closes the link otherwise: no frame refuses a bind, because a frame is
//! what a lane that is not allowed to exist would be given a place to write.
//!
//! After the bind the lane carries the forwarded `input.write` of its attachment and nothing else.
//! Every frame the worker writes back goes through the lane's ordered queue in the input domain,
//! the answers to those writes included, and one task per lane writes the queue to the link.

use std::sync::Arc;

use kr_protocol::envelope::ControlFrame;
use kr_protocol::local::InputLane;

use super::{ConnectionState, WorkerService, Writing, write_frame};
use crate::error::{Result, WorkerError};
use crate::input_lane::LaneQueue;

impl WorkerService {
    /// Binds the lane a connection asked for, or closes the link.
    ///
    /// The parent mark, the parent's latch and its list of attachments are all read in the one
    /// hold of the input domain that registers the lane, so a bind cannot slip between the first
    /// step of the parent's withdrawal and its last.
    pub(super) fn bind_input_lane(&self, state: &mut ConnectionState, lane: &InputLane) {
        let refused = state.facts.lane.is_some()
            || !state.facts.negotiated
            || self.check_authority(&state.facts).is_err();
        let bound = if refused {
            None
        } else {
            let mut input = self.runtime.input().lock();
            input
                .bind_lane(lane.attachment_id, lane.proxy_connection, || {
                    self.parent_owns(state, lane)
                })
                .ok()
        };
        let Some(bound) = bound else {
            // The host reads the close as the refusal.
            self.withdraw(state.facts.connection_id);
            return;
        };
        state.facts.lane = Some(bound.id);
        state.pending_lane = Some(bound.queue);
    }

    /// Says whether the connection the lane names is a live proxy of this connection's generation
    /// that owns the attachment. Read inside the domain's hold, which only ever reads it.
    fn parent_owns(&self, state: &ConnectionState, lane: &InputLane) -> Result<()> {
        let refused = |detail: &str| WorkerError::PermissionDenied {
            detail: detail.to_owned(),
        };
        let authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        if authority.accepted_generation != state.facts.generation
            || !authority.proxy_connections.contains(&lane.proxy_connection)
        {
            return Err(refused(
                "an input lane binds only under a live proxy connection of its generation",
            ));
        }
        drop(authority);
        let admitted = self
            .admitted
            .lock()
            .expect("the connection registry is not poisoned");
        let Some(registration) = admitted.get(&lane.proxy_connection) else {
            return Err(refused("the connection this lane names is gone"));
        };
        if registration.withdrawn.is_set() {
            return Err(refused("the connection this lane names has been withdrawn"));
        }
        if !registration
            .attachments
            .lock()
            .expect("the attachment list is not poisoned")
            .contains(&lane.attachment_id)
        {
            return Err(refused(
                "the connection this lane names owns no such attachment",
            ));
        }
        Ok(())
    }

    /// Writes the lane's queue to its link until the queue is closed and empty or the link fails,
    /// and then closes the link.
    pub(super) async fn write_lane(
        self: Arc<Self>,
        queue: Arc<LaneQueue>,
        writable: Writing,
        writer: Arc<std::sync::Mutex<kr_ipc::framed::FrameWriter>>,
        withdrawn: Arc<super::Withdrawal>,
        connection_id: kr_protocol::ids::ConnectionId,
    ) {
        'lane: loop {
            // What is queued is taken before the closed flag is read, so a queue that closed
            // after the last take has nothing in it that this does not write.
            let closed = queue.is_closed();
            let frames: Vec<ControlFrame> = queue.drain();
            for frame in &frames {
                if !write_frame(&writable, &writer, frame, &withdrawn, true).await {
                    break 'lane;
                }
            }
            if closed {
                break;
            }
            if frames.is_empty() {
                queue.wait().await;
            }
        }
        self.withdraw(connection_id);
    }
}
