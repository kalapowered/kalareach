//! A device's connection that can also send one `input.write` request as the wire carries it.
//!
//! The client library types through its input lane, whose frames carry bytes only, and has no call
//! for `input.write` any more. A host still answers that request from a device of an earlier
//! release, and its answer to key records for a worker of an earlier release is a rule of the host's.
//! The case that checks the rule sends the one request through this wrapper and reads its response.
//! Every other frame passes through as it is, and the response to the one request is read here and
//! never reaches the session.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::transport::{ControlTransport, DeviceEnd, Reach, StreamOpener, TransportFuture};
use kr_protocol::envelope::{ControlFrame, ParamsValue, Request, Response};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{ConnectionId, RequestId};
use kr_protocol::input::InputWriteParams;
use kr_protocol::method::Method;

/// How long the host has to answer the request.
const ANSWER_WAIT: Duration = Duration::from_secs(60);

/// The identifier the one request carries. The session numbers its own requests from one, so no
/// request of the session's meets it.
fn raw_request_id() -> RequestId {
    RequestId::new(1 << 40)
}

/// A connection's transport, with one request it can send itself.
#[derive(Debug)]
pub struct RawInput {
    inner: Arc<dyn ControlTransport>,
    waiting: Mutex<Option<tokio::sync::oneshot::Sender<Response>>>,
}

impl RawInput {
    /// Wraps `inner`.
    pub fn new(inner: impl ControlTransport + 'static) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(inner),
            waiting: Mutex::new(None),
        })
    }

    /// Sends one `input.write` request with `params` on this connection, and returns the host's
    /// response to it.
    ///
    /// # Errors
    ///
    /// Returns what stopped the exchange: the request that could not be sent, the connection
    /// ending, or the host not answering in time.
    pub async fn input_write(&self, params: &InputWriteParams) -> Result<Response, String> {
        let (tell, told) = tokio::sync::oneshot::channel();
        *self.waiting.lock().unwrap_or_else(PoisonError::into_inner) = Some(tell);
        let request = Request {
            request_id: raw_request_id(),
            method: Method::InputWrite.into(),
            method_version: Method::InputWrite.entry().version,
            params: ParamsValue::from_typed(params).map_err(|error| error.to_string())?,
        };
        self.inner
            .send(&ControlFrame::Request(request))
            .await
            .map_err(|error| format!("the input.write request was not sent: {error}"))?;
        tokio::time::timeout(ANSWER_WAIT, told)
            .await
            .map_err(|_| format!("the host did not answer input.write within {ANSWER_WAIT:?}"))?
            .map_err(|_| "the connection ended before the host answered input.write".to_owned())
    }
}

impl ControlTransport for RawInput {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }

    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }

    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }

    fn reach(&self) -> Option<Reach> {
        self.inner.reach()
    }

    fn ended_by_this_device(&self) -> Option<DeviceEnd> {
        self.inner.ended_by_this_device()
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        self.inner.send(frame)
    }

    fn send_before<'a>(
        &'a self,
        frame: &'a ControlFrame,
        not_after: tokio::time::Instant,
        wanted: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> TransportFuture<'a, bool> {
        self.inner.send_before(frame, not_after, wanted)
    }

    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            loop {
                match self.inner.recv().await? {
                    Some(ControlFrame::Response(response))
                        if response.request_id == raw_request_id() =>
                    {
                        let waiting = self
                            .waiting
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take();
                        if let Some(tell) = waiting {
                            let _ = tell.send(response);
                        }
                    }
                    frame => return Ok(frame),
                }
            }
        })
    }

    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        self.inner.stream_opener()
    }

    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }

    fn close(&self) {
        self.inner.close();
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn can_send(&self) -> bool {
        self.inner.can_send()
    }
}
