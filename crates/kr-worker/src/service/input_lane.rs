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
use kr_protocol::local::{ControllerConnectionRole, InputLane, LocalClientKind};

use super::{Authority, ConnectionState, WorkerService, Writing, write_frame};
use crate::error::{Result, WorkerError};
use crate::input_lane::LaneQueue;

impl WorkerService {
    /// Binds the lane a connection asked for, or closes the link.
    ///
    /// The lock order is the worker's one order, the authority lock before the input domain: this
    /// takes the authority lock first and keeps it through the hold of the domain that registers
    /// the lane, so that every check of the bind is made inside one hold of both. The generation,
    /// the set of proxies and the connection's own binding are read under the authority lock, and
    /// the parent mark, the parent's latch, its list of attachments and the registry of lanes in
    /// the domain's hold, so a bind cannot slip between the first step of the parent's withdrawal
    /// and its last, and a generation cannot be replaced between a check and the registration.
    pub(super) fn bind_input_lane(&self, state: &mut ConnectionState, lane: &InputLane) {
        let authority = self.lock_authority();
        let refused = state.facts.lane.is_some()
            || !state.facts.negotiated
            || (state.facts.client_kind == LocalClientKind::Controller
                && Self::check_bound(&state.facts, &authority).is_err());
        let bound = if refused {
            None
        } else {
            #[cfg(feature = "testing")]
            self.bind_stall.stand();
            let mut input = self.runtime.input().lock();
            input
                .bind_lane(lane.attachment_id, lane.proxy_connection, || {
                    self.parent_owns(&authority, state, lane)
                })
                .ok()
        };
        drop(authority);
        let Some(bound) = bound else {
            // The host reads the close as the refusal.
            self.withdraw(state.facts.connection_id);
            return;
        };
        state.facts.lane = Some(bound.id);
        state.pending_lane = Some(bound.queue);
    }

    /// Says whether the connection the lane names is a live proxy of this connection's generation
    /// that owns the attachment. Read inside the domain's hold, which only ever reads it, with the
    /// authority lock held by the caller: the registry and the attachment list come after both in
    /// the order of locks.
    fn parent_owns(
        &self,
        authority: &Authority,
        state: &ConnectionState,
        lane: &InputLane,
    ) -> Result<()> {
        let refused = |detail: &str| WorkerError::PermissionDenied {
            detail: detail.to_owned(),
        };
        if authority.accepted_generation != state.facts.generation
            || !authority.proxy_connections.contains(&lane.proxy_connection)
        {
            return Err(refused(
                "an input lane binds only under a live proxy connection of its generation",
            ));
        }
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

    /// Says where a frame owed to a lane connection goes, which is one rule for every frame the
    /// worker writes on a lane: once the lane's ready frame is queued, a frame reaches the link
    /// only through the lane's ordered queue, and before that nothing is written at all, so the
    /// host reads the close as the refusal. A frame owed to any other connection is handed back to
    /// be written as it always was.
    pub(super) fn on_the_lane(
        &self,
        state: &ConnectionState,
        frame: ControlFrame,
    ) -> Option<ControlFrame> {
        if state.facts.controller_role != ControllerConnectionRole::ProxyInput
            || !state.facts.controller
        {
            return Some(frame);
        }
        match state.facts.lane {
            Some(lane) => self.runtime.input().lock().lane_answer(lane, frame),
            None => self.withdraw(state.facts.connection_id),
        }
        None
    }

    /// Writes the lane's queue to its link until the queue is closed and empty or the link fails,
    /// and then closes the link.
    ///
    /// A queue that closes ends the link within `lane_close_bound` of the close, whatever the
    /// host reads: when the bound has passed, the write that is waiting for the host is cut and
    /// the connection withdrawn, which ends the lane's task, its registration and its window. The
    /// bound is five seconds, the one a closing session's acceptance is given, and it starts at
    /// the close, never earlier: a queue that is open is never cut. What is left to write at the
    /// close is the closed queue, at most 4,097 frames of a few hundred bytes, and any batch the
    /// writer took before it; a host that reads at an ordinary pace takes that from a local
    /// socket in far less. A host that reads more slowly than the bound allows loses its link
    /// too: the bound is a timeout on the close, and it does not tell a host that reads nothing
    /// from one that reads slowly.
    pub(super) async fn write_lane(
        self: Arc<Self>,
        queue: Arc<LaneQueue>,
        writable: Writing,
        writer: Arc<std::sync::Mutex<kr_ipc::framed::FrameWriter>>,
        withdrawn: Arc<super::Withdrawal>,
        connection_id: kr_protocol::ids::ConnectionId,
    ) {
        #[cfg(feature = "testing")]
        let _counted = Counted::begin(&self.lane_writers);
        #[cfg(feature = "testing")]
        self.lane_writer_stall.stand();
        let bound = self.lane_close_bound;
        let cut = async {
            queue.closed().await;
            tokio::time::sleep(bound).await;
        };
        tokio::pin!(cut);
        'lane: loop {
            // The closed flag is read before the queue is taken. Nothing is queued after a close,
            // so when the flag reads true the take holds everything that was ever queued, and the
            // lane ends after writing it.
            let closed = queue.is_closed();
            let frames: Vec<ControlFrame> = queue.drain();
            for frame in &frames {
                let written = tokio::select! {
                    written = write_frame(&writable, &writer, frame, &withdrawn, true) => written,
                    () = &mut cut => false,
                };
                if !written {
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

/// Counts a running lane writer for as long as it lives, for this host's own tests.
#[cfg(feature = "testing")]
struct Counted<'a>(&'a std::sync::atomic::AtomicUsize);

#[cfg(feature = "testing")]
impl<'a> Counted<'a> {
    fn begin(count: &'a std::sync::atomic::AtomicUsize) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(count)
    }
}

#[cfg(feature = "testing")]
impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
