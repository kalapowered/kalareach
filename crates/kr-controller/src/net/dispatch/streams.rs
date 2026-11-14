//! What a data stream asks of the door: the admission of a stream, the answer to a frame that
//! arrived on one, and the output that writes the answers.

use std::sync::Arc;

use kr_protocol::actor::ActorEnvelope;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActorId, EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_transfer::service::StoredSubject;
use kr_transport::listener::ReceivedFrame;
use kr_transport::streams::DataWriter;

use super::output::{FrameSink, RemoteOutput, WITHDRAWN};
use super::{Answered, RemoteConnection};
use crate::service::net::chunks::ChunkAdmission;
use crate::service::net::proxy::WorkerProxy;
use crate::service::{Controller, FeedStanding};

/// A data stream's writer, as the connection's write boundary writes to it.
///
/// Every answer goes out through the writer's `write_message_while`, which asks the stream's
/// revoked state at each attempt to hand bytes over: no answer begins to go once the stream has
/// been taken away. A stream that is taken away fails the write and nothing more; closing the
/// connection is for the boundary to do when the connection's authority is what failed.
#[derive(Debug)]
struct DataSink {
    writer: tokio::sync::Mutex<DataWriter>,
    connection: iroh::endpoint::Connection,
}

impl FrameSink for DataSink {
    fn send_while<'a>(
        &'a self,
        frame: &'a ControlFrame,
        admits: kr_transport::codec::Admission<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            self.writer
                .lock()
                .await
                .write_message_while(frame, admits)
                .await
        })
    }

    fn close(&self) {
        self.connection.close(
            WITHDRAWN.into(),
            b"this connection's authority was withdrawn",
        );
    }
}

impl RemoteConnection {
    /// The principal this connection's device acts under.
    pub(crate) fn principal(&self) -> ActorId {
        self.device.principal()
    }

    /// The environment this host serves.
    pub(crate) fn environment_id(&self) -> EnvironmentId {
        self.controller.paths().environment_id()
    }

    /// The daemon this connection belongs to.
    pub(crate) const fn controller(&self) -> &Arc<Controller> {
        &self.controller
    }

    /// Decides whether this device may send chunks of `upload` on a stream: the registration, the
    /// authority feed's refusal, and the rights, selectors and scope the door decides for an
    /// `upload.chunk` that names the upload's session.
    ///
    /// # Errors
    ///
    /// Returns the refusal a request for the same would be given.
    pub(crate) async fn admit_a_chunk_stream(
        &self,
        upload: &StoredSubject,
    ) -> std::result::Result<(), ProtocolError> {
        self.admitted_at().await?;
        // A connection the feed refuses stays up, and what it may do is decided where each thing is
        // asked: a stream is something it asks.
        if let Some(refusal) = self.controller.feed_refusal_on(self.connection_id) {
            return Err(ProtocolError::new(
                kr_protocol::error::ErrorCode::PermissionDenied,
                refusal.detail(),
            ));
        }
        self.ask_naming(upload.session_id, Method::UploadChunk.entry(), false, None)?;
        Ok(())
    }

    /// The write boundary of one data stream: the connection's own authority and latch, a turn of
    /// its own, and the stream's writer.
    pub(crate) fn data_output(
        &self,
        writer: DataWriter,
        connection: iroh::endpoint::Connection,
    ) -> RemoteOutput {
        RemoteOutput::for_a_peer_receiving(
            Box::new(DataSink {
                writer: tokio::sync::Mutex::new(writer),
                connection,
            }),
            Arc::clone(&self.authority),
            &self.output.receive(),
        )
    }

    /// Answers one frame that arrived on an attachment-chunk stream, which the stream's policy
    /// has already held to the frames such a stream carries.
    pub(crate) async fn answer_on_a_stream(
        &self,
        received: ReceivedFrame,
        admission: &Arc<ChunkAdmission>,
    ) -> Option<Answered> {
        self.answer_via(received, Some(admission)).await
    }
}

/// What the host decided for one frame of typing: everything the worker is given with it, and the
/// grants the frame stands on, which the writer asks the feed about again immediately before the
/// frame goes to the worker.
#[derive(Clone, Debug)]
pub(crate) struct InputDecision {
    /// The actor the frame is attributed to, at the revision the decision was taken at.
    pub(crate) actor: ActorEnvelope,
    /// When the authority behind the frame runs out, as a remaining duration, or null.
    pub(crate) authority_deadline: Nullable<U64>,
    /// The grants the frame stands on.
    pub(crate) standing: FeedStanding,
}

impl RemoteConnection {
    /// The session and the open link to its worker, once this connection's route is fixed.
    pub(crate) async fn fixed_input_route(&self) -> Option<(SessionId, Arc<WorkerProxy>)> {
        let proxy = self
            .proxy
            .lock()
            .await
            .as_ref()
            .filter(|proxy| proxy.is_open())
            .map(Arc::clone)?;
        let (session, _grant) = (*self
            .fixed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))?;
        Some((session, proxy))
    }

    /// What the device this connection serves said it can receive, which a link opened for it is
    /// told.
    pub(crate) fn receive_limits(&self) -> kr_protocol::hello::ReceiveLimits {
        self.output.receive()
    }

    /// Resolves when this connection's grant choices change: the route may then be fixed.
    pub(crate) async fn until_the_route_may_have_changed(&self) {
        self.acting_changed.notified().await;
    }

    /// Decides one frame of typing for `session`, as a key sent on the control stream is decided:
    /// the registration and its revision, the authority feed's refusal, and the rights, selectors
    /// and scope the door decides for `input.write`, and the authority's deadline.
    ///
    /// # Errors
    ///
    /// Returns the refusal a key for the same would be given.
    pub(crate) async fn decide_an_input_frame(
        &self,
        session: SessionId,
    ) -> std::result::Result<InputDecision, ProtocolError> {
        let validated = self.admitted_at().await?;
        let asked = self.ask_naming(Some(session), Method::InputWrite.entry(), false, None)?;
        let authority_deadline = self.authority_deadline(&asked)?;
        let standing = self.feed_standing(&asked.acting.grant);
        self.controller
            .refuse_while_the_feed_refuses(&standing)
            .map_err(|error| error.to_protocol_error())?;
        Ok(InputDecision {
            actor: self.envelope(asked.acting.grant.grant_id, validated),
            authority_deadline,
            standing,
        })
    }

    /// Whether the authority feed refuses a frame that stands on `standing`, asked again
    /// immediately before the frame is written to the worker.
    pub(crate) fn feed_admits(&self, standing: &FeedStanding) -> bool {
        self.controller
            .refuse_while_the_feed_refuses(standing)
            .is_ok()
    }
}
