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

/// The request number before the first one the wire's own calls use: a paired connection numbers
/// its requests in sequence from 2, after the first the host takes for its own, and a host that
/// sees a number jump ends the connection.
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
    /// given, in a range of its own. A paired connection numbers a connection's requests in
    /// sequence, and a host that sees a number jump ends the connection, so the loop carries on
    /// from the last the opening used.
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
            return Err(Lost("the connection ended".to_owned()));
        }
        let mut waiting = Vec::new();
        let answer = loop {
            let frame = match self.recv().await {
                Ok(frame) => frame,
                Err(lost) => return Err(lost),
            };
            match frame {
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
}
