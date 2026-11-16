//! What a raw terminal view calls its session through, and what it reads from it.
//!
//! A view on this machine's own host and a view on a host this device is paired with both speak to
//! the session's worker through a [`Session`] of the client library, started in the ordered mode:
//! the view is the one consumer of the session's notifications, which reach it in the order the host
//! sent them, and it takes every answer by awaiting the call that asked. The frames are the same on
//! both links, so the view is written against this and runs unchanged on either.
//!
//! A connection belongs to its view: an attachment, its subscription and the input lease belong to
//! the connection that made them, and the view's end is its connection's.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use kr_client::error::ClientError;
use kr_client::ordered::{Ended, Ordered, OrderedEvents};
use kr_client::session::{ComposedMutation, Session};
use kr_client::shown::Shown;
use kr_client::transport::ControlTransport;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::scalars::DurationMs;

/// Why the link ended, in words a person reads.
#[derive(Debug)]
pub(super) struct Lost(pub(super) String);

/// What a call answered with: the host's refusal, or the value.
pub(super) type Answer = std::result::Result<ParamsValue, ProtocolError>;

/// What a call that the loop owns comes to: the value, or why the call failed.
pub(super) type Answered = std::result::Result<ParamsValue, ClientError>;

/// A call that has been started and is polled by whoever awaits it.
pub(super) type Call = BoxFuture<'static, Answered>;

/// How long a call that failed waits for the host's refusal of the connection, which the host sends
/// before it ends the connection and which the reader may not have handed on yet.
pub(super) const REFUSAL_WAIT: Duration = Duration::from_secs(2);

/// How many notifications the session's reader hands on before it waits for the view.
const EVENTS: usize = 256;

/// The view's way to call its session: shared with the futures of the calls it has started.
#[derive(Clone)]
pub(super) struct Link {
    session: Arc<Session>,
    /// The share the view acts under, which every mutation names.
    grant_id: Option<GrantId>,
}

/// The notifications of the view's session, in the order the host sent them.
pub(super) struct Events {
    events: OrderedEvents,
    /// What arrived while a call of the opening waited for its answer, handed to the loop first.
    held: VecDeque<Ordered>,
}

impl Link {
    /// A view's link over `transport`, whose frames this view alone reads.
    ///
    /// # Errors
    ///
    /// Returns why the receive side could not be claimed.
    pub(super) fn over(
        transport: Arc<dyn ControlTransport>,
        grant_id: Option<GrantId>,
    ) -> Result<(Self, Events), Lost> {
        let (session, events) =
            Session::start_ordered(transport, EVENTS).map_err(|error| Lost(error.to_string()))?;
        Ok((
            Self {
                session: Arc::new(session),
                grant_id,
            },
            Events {
                events,
                held: VecDeque::new(),
            },
        ))
    }

    /// The session, for what the lane and a detach need of it.
    pub(super) const fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Why this device ended the connection, when it did: the account it was opened under left.
    pub(super) fn ended_by_this_device(&self) -> Option<String> {
        self.session
            .transport()
            .ended_by_this_device()
            .map(|refusal| refusal.message)
    }

    /// The host's refusal of the connection, when the session has read it: the first error the
    /// host answered with request identifier zero, which no request of the view carries.
    pub(super) fn kept_refusal(&self) -> Option<ProtocolError> {
        self.session.connection_refusal()
    }

    /// Ends the connection and the session's reading, which the view's own end does after its last
    /// write.
    pub(super) fn close(&self) {
        self.session.close();
    }

    /// Starts a read, which the session retries when the host answers it as unavailable for now.
    pub(super) fn read<P>(&self, method: Method, params: P) -> Call
    where
        P: serde::Serialize + Send + Sync + 'static,
    {
        let session = Arc::clone(&self.session);
        Box::pin(async move { session.read::<_, ParamsValue>(method, &params).await })
    }

    /// Starts a mutation on `target`, quoting the session's current window and naming the share.
    pub(super) fn mutate<P>(&self, method: Method, target: ActionTarget, params: P) -> Call
    where
        P: serde::Serialize + Send + Sync + 'static,
    {
        let session = Arc::clone(&self.session);
        let grant_id = self.grant_id;
        Box::pin(async move {
            let settled = session
                .mutate(
                    method,
                    target,
                    grant_id,
                    &ParamsValue::empty(),
                    &params,
                    ttl(),
                )
                .await?;
            settled.to_typed::<ParamsValue>()
        })
    }

    /// Composes a mutation, which is written later and whole.
    ///
    /// # Errors
    ///
    /// Returns why the request could not be composed.
    pub(super) async fn compose<P>(
        &self,
        method: Method,
        target: ActionTarget,
        params: &P,
    ) -> Result<Arc<ComposedMutation>, ClientError>
    where
        P: serde::Serialize + Sync,
    {
        self.session
            .compose(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                self.grant_id,
                &ParamsValue::empty(),
                params,
                ttl(),
            )
            .await
            .map(Arc::new)
    }

    /// Writes a composed mutation whole, which the session's own close does not cut, and returns
    /// once its frame is on the connection, without waiting for the host's answer.
    ///
    /// # Errors
    ///
    /// Returns why nothing was sent.
    pub(super) async fn send_whole(&self, composed: &ComposedMutation) -> Result<(), ClientError> {
        self.session.send_whole(composed).await.map(drop)
    }

    /// Calls `call` while the view takes what the session's reader hands on, as the opening does,
    /// and says what it answered: the host's refusal or the value, or why the link ended. A call
    /// that failed is told apart by what the reader says of the end: the refusal of the connection
    /// that the host sent before it ended the connection is the call's answer, and is kept.
    ///
    /// # Errors
    ///
    /// Returns why the link ended.
    pub(super) async fn request(&self, events: &mut Events, call: Call) -> Result<Answer, Lost> {
        match events.during(call).await {
            Ok(value) => Ok(Ok(value)),
            Err(ClientError::Host(refusal)) => Ok(Err(refusal)),
            Err(failed) => match events.end_after(&failed).await {
                Err(refusal) => Ok(Err(refusal)),
                Ok(words) => Err(Lost(words)),
            },
        }
    }
}

/// How long a mutation's answer stays valid for the view.
fn ttl() -> DurationMs {
    DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get())
}

impl Events {
    /// The next item, the ones held first. The end of the session's reading is the
    /// [`Ordered::Ended`] item, and none follows it.
    pub(super) async fn recv(&mut self) -> Option<Ordered> {
        if let Some(item) = self.held.pop_front() {
            return Some(item);
        }
        self.events.recv().await
    }

    /// Waits for `call` while taking what the reader hands on: the reader waits for room while its
    /// channel is full, and an answer waits behind it. What arrives is kept for the loop.
    pub(super) async fn during<T>(&mut self, call: impl Future<Output = T>) -> T {
        tokio::pin!(call);
        loop {
            tokio::select! {
                biased;
                out = &mut call => return out,
                item = self.events.recv() => match item {
                    Some(item) => self.held.push_back(item),
                    None => return call.await,
                },
            }
        }
    }

    /// Reads to the end of the session after `failed`, the failure of a call: the host's refusal of
    /// the connection when it arrives within [`REFUSAL_WAIT`], and otherwise the words of how the
    /// link ended. What arrives before the end is of no use to a call whose link is over.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal of the connection, as the answer the call was owed.
    pub(super) async fn end_after(
        &mut self,
        failed: &ClientError,
    ) -> Result<String, ProtocolError> {
        let waited = tokio::time::timeout(REFUSAL_WAIT, async {
            loop {
                match self.recv().await {
                    Some(Ordered::Notification(_)) => {}
                    Some(Ordered::Ended(ended)) => return Some(ended),
                    None => return None,
                }
            }
        })
        .await;
        match waited.ok().flatten() {
            Some(Ended::Refused(refusal)) => Err(refusal),
            Some(ended) => Ok(ended_words(&ended)),
            None => Ok(words_of(failed)),
        }
    }

    /// Reads and drops what is left, so the session's reader is released: the end of the view.
    pub(super) async fn drain(&mut self) {
        while self.events.recv().await.is_some() {}
    }
}

/// What a link whose reading ended says, by the cause the reader read: on the local link a failed
/// read is the socket's own words, on the network the transport's, and a clean end of the
/// connection says so.
pub(super) fn ended_words(ended: &Ended) -> String {
    match ended {
        Ended::Finished => "the connection ended".to_owned(),
        Ended::Failed(error) => words_of(error),
        Ended::Refused(refusal) => refusal.message.clone(),
        Ended::Unexpected => "the host sent a frame this application does not read".to_owned(),
    }
}

/// What a failure of a call says of the link.
fn words_of(error: &ClientError) -> String {
    match error {
        ClientError::Ipc(error) => Shown::ipc(error).to_string(),
        ClientError::Transport(error) => error.to_string(),
        ClientError::ConnectionEnded => "the connection ended".to_owned(),
        other => other.to_string(),
    }
}

/// The answer a call is owed when the lane that held its place went away before it was written.
pub(super) fn unknown() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        "the request's place in the input stream was lost before it was written",
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_client::error::Result as ClientResult;
    use kr_client::transport::TransportFuture;
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::hello::{ActionWindow, ReceiveLimits};
    use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId, RequestId};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
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

        fn is_closed(&self) -> bool {
            false
        }
    }

    fn wire_over(refusal: Option<ProtocolError>) -> (Link, Events) {
        let transport = Arc::new(Refused {
            refusal: Mutex::new(refusal),
        });
        Link::over(transport, None).expect("a wire")
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
        let (wire, mut events) = wire_over(Some(refusal.clone()));
        let answered = wire
            .request(&mut events, wire.read(Method::SessionOpen, open_params()))
            .await
            .expect("the call is answered with the host's refusal, not with the connection ended");
        assert_eq!(answered.expect_err("the host refused"), refusal);
        assert_eq!(wire.kept_refusal(), Some(refusal));
    }

    /// KR-REQ-19.08: a call whose write fails on a connection that ended with no refusal is told
    /// that the connection ended, and the wire holds no refusal of the connection.
    #[tokio::test]
    async fn a_call_whose_write_fails_on_a_connection_that_ended_with_no_refusal_says_so() {
        let (wire, mut events) = wire_over(None);
        let lost = wire
            .request(&mut events, wire.read(Method::SessionOpen, open_params()))
            .await
            .expect_err("nothing answered the call");
        assert_eq!(lost.0, "the connection ended");
        assert_eq!(wire.kept_refusal(), None);
    }
}
