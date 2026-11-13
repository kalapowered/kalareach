//! What a raw terminal view reads from and writes to its session through.
//!
//! A view on this machine's own host speaks to the session's worker over the local link it made
//! ([`LocalClient`]). A view on a host this device is paired with speaks to the same worker through
//! that host's daemon, over a connection of its own: an attachment, its subscription and the input
//! lease belong to the connection that made them, and a view's end is its connection's. The frames
//! are the same on both, so the view is written against this and runs unchanged on either.
//!
//! A paired connection is the transport of [`kr_client`], whose session would handle the host's
//! renewal of the action window; the view reads the frames itself, so this does what the session
//! would for the one frame that is not the view's: it keeps the window current.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use kr_client::shown::Shown;
use kr_client::transport::ControlTransport;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::hello::ActionWindow;
use kr_protocol::ids::{ActionId, ActionWindowId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};

/// Why the wire ended, in words a person reads.
#[derive(Debug)]
pub(super) struct Lost(pub(super) String);

/// What a call answered with: the host's refusal, or the value.
pub(super) type Answer = std::result::Result<ParamsValue, ProtocolError>;

/// How long a call whose write failed waits for the host's refusal of the connection, which the host
/// sends before it ends the connection and which the reader may not have queued yet.
const REFUSAL_WAIT: Duration = Duration::from_secs(2);

/// The request number before the first one the wire's own calls use. A paired connection numbers
/// its requests in sequence, as a session of the client library does, and the wire's calls and the
/// loop's carry on from one another.
const OWN_REQUESTS: u64 = 1;

/// A view's connection to its session.
pub(super) enum Wire {
    /// The worker on this machine, over the link made from its descriptor.
    Local(Box<LocalClient>),
    /// A host this device is paired with, over a connection opened for the view.
    Paired(Paired),
}

/// A paired connection the view reads itself.
///
/// The view's loop waits for a frame and for the page's commands together, and drops the wait for
/// the frame whenever a command wins. A transport's read is not safe to drop part way through a
/// frame, so a task of its own does the reading and the loop waits on a channel, which is.
pub(super) struct Paired {
    transport: Arc<dyn ControlTransport>,
    window: tokio::sync::watch::Receiver<ActionWindow>,
    frames: tokio::sync::mpsc::Receiver<Result<ControlFrame, Lost>>,
    reader: tokio::task::JoinHandle<()>,
    /// Frames read while a call waited for its answer, handed to the loop first.
    held: VecDeque<ControlFrame>,
    /// The share the view acts under, which every mutation names.
    grant_id: Option<GrantId>,
    next: u64,
    /// The first error the host answered with request identifier zero: its refusal of the
    /// connection itself, which a call that it answered is told apart from a refusal of its own
    /// request by ([`Wire::kept_refusal`]).
    refusal: Option<ProtocolError>,
}

impl Paired {
    /// A view's connection over `transport`, whose frames this view alone reads.
    ///
    /// # Errors
    ///
    /// Returns why the receive side could not be claimed.
    pub(super) fn over(
        transport: Arc<dyn ControlTransport>,
        grant_id: Option<GrantId>,
    ) -> Result<Self, Lost> {
        transport
            .claim_receiver()
            .map_err(|error| Lost(error.to_string()))?;
        let (renewed, window) = tokio::sync::watch::channel(transport.initial_action_window());
        let (sender, frames) = tokio::sync::mpsc::channel(256);
        let reading = Arc::clone(&transport);
        let reader = tokio::spawn(async move {
            loop {
                let frame = match reading.recv().await {
                    // The host renewed the window; the session would keep it, and so does this.
                    Ok(Some(ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)))) => {
                        let _ = renewed.send(window);
                        continue;
                    }
                    Ok(Some(ControlFrame::Event(ControlEvent::Keepalive))) => continue,
                    Ok(Some(frame)) => Ok(frame),
                    Ok(None) => Err(Lost("the connection ended".to_owned())),
                    Err(error) => Err(Lost(error.to_string())),
                };
                let ended = frame.is_err();
                if sender.send(frame).await.is_err() || ended {
                    return;
                }
            }
        });
        Ok(Self {
            transport,
            window,
            frames,
            reader,
            held: VecDeque::new(),
            grant_id,
            next: OWN_REQUESTS,
            refusal: None,
        })
    }
}

impl Drop for Paired {
    /// The connection is the view's: it ends with the view, which is what detaches its attachment.
    fn drop(&mut self) {
        self.reader.abort();
        self.transport.close();
    }
}

impl Wire {
    /// Why this device ended the connection, when it did: the account it was opened under left.
    pub(super) fn ended_by_this_device(&self) -> Option<String> {
        match self {
            Self::Local(_) => None,
            Self::Paired(paired) => paired
                .transport
                .ended_by_this_device()
                .map(|refusal| refusal.message),
        }
    }

    /// The host's refusal of the connection, when this wire has read it: the first error the host
    /// answered with request identifier zero, which no request of the view carries. A call that the
    /// host answered with an error equal to it was refused with the connection, whatever its code,
    /// since a request's refusal can carry the same code.
    pub(super) fn kept_refusal(&self) -> Option<ProtocolError> {
        match self {
            Self::Local(_) => None,
            Self::Paired(paired) => paired.refusal.clone(),
        }
    }

    /// The next frame, keeping the action window current.
    pub(super) async fn recv(&mut self) -> Result<ControlFrame, Lost> {
        match self {
            Self::Local(client) => client
                .recv()
                .await
                .map_err(|error| Lost(Shown::ipc(&error).to_string())),
            Self::Paired(paired) => {
                if let Some(frame) = paired.held.pop_front() {
                    return Ok(frame);
                }
                paired
                    .frames
                    .recv()
                    .await
                    .unwrap_or_else(|| Err(Lost("the connection ended".to_owned())))
            }
        }
    }

    /// Writes one frame. Returns whether it left.
    pub(super) async fn send(&mut self, frame: &ControlFrame) -> bool {
        match self {
            Self::Local(client) => client.writer().write_message(frame).await.is_ok(),
            Self::Paired(paired) => paired.transport.send(frame).await.is_ok(),
        }
    }

    /// The window a mutation quotes.
    pub(super) fn window_id(&self) -> ActionWindowId {
        match self {
            Self::Local(client) => client.action_window().action_window_id.clone(),
            Self::Paired(paired) => paired.window.borrow().action_window_id.clone(),
        }
    }

    /// The share every mutation names, when the view acts under one.
    pub(super) fn grant_id(&self) -> Option<GrantId> {
        match self {
            Self::Local(_) => None,
            Self::Paired(paired) => paired.grant_id,
        }
    }

    /// The number the view's loop numbers its requests from.
    ///
    /// A local link has the loop number apart from the ones the attach and the subscription were
    /// given, in a range of its own. A paired connection numbers its requests in sequence, as a
    /// session of the client library does, so the loop carries on from the last the opening used.
    pub(super) fn first_loop_request(&self) -> u64 {
        match self {
            Self::Local(_) => super::view::LOOP_REQUESTS,
            Self::Paired(paired) => paired.next,
        }
    }

    /// Calls a read and waits for its answer.
    pub(super) async fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<Answer, Lost> {
        match self {
            Self::Local(client) => client
                .request(method, params)
                .await
                .map_err(|error| Lost(Shown::ipc(&error).to_string())),
            Self::Paired(paired) => {
                paired.next += 1;
                let request_id = RequestId::new(paired.next);
                let params = ParamsValue::from_typed(params)
                    .map_err(|error| Lost(Shown::cbor(&error).to_string()))?;
                let frame = ControlFrame::Request(Request {
                    request_id,
                    method: method.into(),
                    method_version: MethodVersion::V1,
                    params,
                });
                self.send_and_wait(request_id, &frame).await
            }
        }
    }

    /// Calls a mutation and waits for its answer.
    pub(super) async fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        target: ActionTarget,
        params: &T,
    ) -> Result<Answer, Lost> {
        match self {
            Self::Local(client) => client
                .mutate(method, ActionId::new(kr_ipc::new_uuid()), target, params)
                .await
                .map_err(|error| Lost(Shown::ipc(&error).to_string())),
            Self::Paired(paired) => {
                paired.next += 1;
                let request_id = RequestId::new(paired.next);
                let frame = ControlFrame::Mutation(Box::new(
                    self.mutation(request_id, method, target, params)
                        .map_err(|error| Lost(Shown::cbor(&error).to_string()))?,
                ));
                self.send_and_wait(request_id, &frame).await
            }
        }
    }

    /// The mutation a view writes for `method`, quoting the current window and naming the share.
    pub(super) fn mutation<T: serde::Serialize + ?Sized>(
        &self,
        request_id: RequestId,
        method: Method,
        target: ActionTarget,
        params: &T,
    ) -> Result<MutationRequest, kr_cbor::CborError> {
        Ok(MutationRequest {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable(self.grant_id()),
            target,
            expected: ParamsValue::empty(),
            action_window_id: self.window_id(),
            requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
            params: ParamsValue::from_typed(params)?,
        })
    }

    /// Writes `frame` and reads until the answer to `request_id`, holding what arrives before it
    /// for the loop.
    async fn send_and_wait(
        &mut self,
        request_id: RequestId,
        frame: &ControlFrame,
    ) -> Result<Answer, Lost> {
        let Self::Paired(_) = self else {
            return Err(Lost("a local wire answers its own calls".to_owned()));
        };
        if !self.send(frame).await {
            // A host that refuses the connection answers with that refusal and ends it, so the
            // write can fail after the refusal was read and queued, or while it is on its way: the
            // call is answered with it, as it is when the refusal arrives while the call waits.
            return match self.refusal_before_the_end().await {
                Some(refusal) => Ok(Err(refusal)),
                None => Err(Lost("the connection ended".to_owned())),
            };
        }
        let mut waiting = Vec::new();
        let answer = loop {
            let frame = match self.recv().await {
                Ok(frame) => frame,
                Err(lost) => return Err(lost),
            };
            match frame {
                // An error with request identifier zero is the host's word on the connection
                // itself, which it refuses: the call is answered with it, as a host's own answer.
                ControlFrame::Response(response)
                    if response.request_id == RequestId::new(0)
                        && matches!(response.outcome, Outcome::Error(_)) =>
                {
                    break match response.outcome {
                        Outcome::Error(error) => {
                            self.keep_refusal(&error);
                            Err(error)
                        }
                        Outcome::Ok(value) => Ok(value),
                    };
                }
                ControlFrame::Response(response) if response.request_id == request_id => {
                    break match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    };
                }
                other => waiting.push(other),
            }
        };
        if let Self::Paired(paired) = self {
            for frame in waiting.into_iter().rev() {
                paired.held.push_front(frame);
            }
        }
        Ok(answer)
    }

    /// Keeps the host's refusal of the connection, the first one, for [`Self::kept_refusal`].
    fn keep_refusal(&mut self, refusal: &ProtocolError) {
        if let Self::Paired(paired) = self {
            paired.refusal.get_or_insert_with(|| refusal.clone());
        }
    }

    /// The host's refusal of the connection, when it is already read or arrives within
    /// [`REFUSAL_WAIT`], and none when the connection ended without one. What arrives before it is
    /// of no use to a call whose write failed, since the connection is over.
    async fn refusal_before_the_end(&mut self) -> Option<ProtocolError> {
        let Self::Paired(paired) = self else {
            return None;
        };
        if paired.refusal.is_some() {
            return paired.refusal.clone();
        }
        let waited = tokio::time::timeout(REFUSAL_WAIT, async {
            loop {
                let frame = match paired.held.pop_front() {
                    Some(frame) => frame,
                    None => match paired.frames.recv().await {
                        Some(Ok(frame)) => frame,
                        Some(Err(_)) | None => return None,
                    },
                };
                if let ControlFrame::Response(response) = frame
                    && response.request_id == RequestId::new(0)
                    && let Outcome::Error(error) = response.outcome
                {
                    return Some(error);
                }
            }
        })
        .await;
        let refusal = waited.ok().flatten()?;
        paired.refusal.get_or_insert_with(|| refusal.clone());
        Some(refusal)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_client::error::Result as ClientResult;
    use kr_client::transport::TransportFuture;
    use kr_protocol::envelope::Response;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::hello::ReceiveLimits;
    use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
    use kr_protocol::scalars::{TimestampMs, Uuid};
    use kr_protocol::session::SessionOpenParams;

    use super::*;

    /// A connection that the host refused and ended: every write fails, and the host's refusal, sent
    /// before it ended the connection, is what is read from it, once, if `refusal` holds one.
    #[derive(Debug)]
    struct Refused {
        refusal: Mutex<Option<ProtocolError>>,
    }

    impl ControlTransport for Refused {
        fn connection_id(&self) -> ConnectionId {
            ConnectionId::new(Uuid::from_bytes([7; 16]))
        }

        fn limits(&self) -> ReceiveLimits {
            ReceiveLimits::default()
        }

        fn initial_action_window(&self) -> ActionWindow {
            ActionWindow {
                action_window_id: ActionWindowId::new("window-1").expect("a window"),
                connection_id: self.connection_id(),
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(1),
                valid_for_ms: DurationMs::new(60_000),
            }
        }

        fn ended_by_this_device(&self) -> Option<ProtocolError> {
            None
        }

        fn send<'a>(&'a self, _: &'a ControlFrame) -> TransportFuture<'a, ()> {
            Box::pin(async { Err(kr_client::ClientError::ConnectionEnded) })
        }

        fn claim_receiver(&self) -> ClientResult<()> {
            Ok(())
        }

        fn stream_opener(&self) -> Option<Arc<dyn kr_client::transport::StreamOpener>> {
            None
        }

        fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
            let refusal = self.refusal.lock().expect("the refusal").take();
            Box::pin(async move {
                Ok(refusal.map(|error| {
                    ControlFrame::Response(Response {
                        request_id: RequestId::new(0),
                        outcome: Outcome::Error(error),
                    })
                }))
            })
        }

        fn revoke_streams(&self) {}

        fn close(&self) {}
    }

    fn wire_over(refusal: Option<ProtocolError>) -> Wire {
        let transport = Arc::new(Refused {
            refusal: Mutex::new(refusal),
        });
        Wire::Paired(Paired::over(transport, None).expect("a wire"))
    }

    fn open_params() -> SessionOpenParams {
        SessionOpenParams {
            session_id: Nullable::null(),
            grant_id: Nullable::null(),
        }
    }

    /// KR-REQ-19.08: a call whose write fails because the host refused the connection and ended it
    /// is answered with the host's refusal, which the reader has queued or is about to, and not with
    /// the connection having ended; the wire keeps it as the refusal of the connection.
    #[tokio::test]
    async fn a_call_whose_write_fails_after_the_hosts_refusal_is_answered_with_it() {
        let refusal = ProtocolError::new(ErrorCode::ResourceUnavailable, "no more connections");
        let mut wire = wire_over(Some(refusal.clone()));
        let answered = wire
            .request(Method::SessionOpen, &open_params())
            .await
            .expect("the call is answered with the host's refusal, not with the connection ended");
        assert_eq!(answered.expect_err("the host refused"), refusal);
        assert_eq!(wire.kept_refusal(), Some(refusal));
    }

    /// KR-REQ-19.08: a call whose write fails on a connection that ended with no refusal is told
    /// that the connection ended, and the wire holds no refusal of the connection.
    #[tokio::test]
    async fn a_call_whose_write_fails_on_a_connection_that_ended_with_no_refusal_says_so() {
        let mut wire = wire_over(None);
        let lost = wire
            .request(Method::SessionOpen, &open_params())
            .await
            .expect_err("nothing answered the call");
        assert_eq!(lost.0, "the connection ended");
        assert_eq!(wire.kept_refusal(), None);
    }
}
