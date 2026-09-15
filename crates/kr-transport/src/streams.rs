//! Data streams: opening, header validation, and revocation when the control stream ends.
//!
//! Section 23 gives each stream kind its own stream, its own frame bound and a bounded 1 KiB header
//! validated against the established control connection before any data frame is accepted. It also
//! gives the control stream a power nothing else has: "Closing/failing the control stream revokes
//! every associated data stream and stops remote lease renewal."
//!
//! [`StreamRegistry`] is where that power lives. Every data stream registers a handle when it
//! opens; [`StreamRegistry::revoke_all`] resets each one and runs the revocation hook, which is how
//! the controller stops renewing the connection's dispatch leases. A revoked stream is reset rather
//! than finished, so the peer sees that the stream was taken away instead of a clean end it might
//! read as completion.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use iroh::endpoint::Connection;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::hello::ReceiveLimits;
use kr_protocol::ids::ConnectionId;
use kr_protocol::limits::MAX_STREAM_HEADER_LEN;

use crate::codec::{FrameReader, FrameWriter};
use crate::error::{Result, TransportError};
use crate::scheduler::{
    BulkStreamSlot, QueueReservation, StreamBudget, StreamClass, class_of, priority_of,
};

/// Returns the complete frame size a payload of this length is written as.
const fn framed_len(payload: usize) -> usize {
    payload.saturating_add(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN)
}

/// Why a stream header was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderRefusal {
    /// The header names another connection.
    #[error("the stream header names another connection")]
    WrongConnection,
    /// The header names a resource shape this stream kind does not use.
    #[error("the stream header does not describe this stream kind's resource")]
    WrongResource,
}

impl From<HeaderRefusal> for ProtocolError {
    fn from(refusal: HeaderRefusal) -> Self {
        Self::new(ErrorCode::PermissionDenied, refusal.to_string())
    }
}

/// Checks a header against the established control connection.
///
/// The connection identity has to match, because a header is the only thing that ties a new stream
/// to an authorised connection. The resource shape has to fit the kind, because an attachment
/// stream without a transfer, or a terminal stream without a session, names nothing the host could
/// authorise.
///
/// # Errors
///
/// Returns the first mismatch.
pub fn validate_header(
    header: &StreamHeader,
    connection_id: ConnectionId,
) -> std::result::Result<(), HeaderRefusal> {
    if header.connection_id != connection_id {
        return Err(HeaderRefusal::WrongConnection);
    }
    let resource = &header.resource;
    let fits = match header.kind {
        StreamKind::Control => true,
        StreamKind::TerminalOutput | StreamKind::TerminalInput => {
            resource.session_id.is_present() && resource.attachment_id.is_present()
        }
        StreamKind::SemanticUpdates => resource.session_id.is_present(),
        StreamKind::AttachmentChunks => resource.transfer_id.is_present(),
    };
    if fits {
        Ok(())
    } else {
        Err(HeaderRefusal::WrongResource)
    }
}

/// One open data stream.
///
/// Reads and writes go through this type rather than through the reader and writer directly,
/// because revocation has to reach an operation that is already waiting. Each one races the
/// revocation signal, so a stream that is revoked while a task is blocked on it returns
/// [`TransportError::ControlLost`] at once rather than waiting for a peer that will never send.
#[derive(Debug)]
pub struct DataStream {
    header: StreamHeader,
    writer: Option<FrameWriter>,
    reader: Option<FrameReader>,
    handle: StreamHandle,
    budget: Arc<StreamBudget>,
    /// The bulk slot this stream occupies, released when the stream is dropped.
    _bulk_slot: Option<BulkStreamSlot>,
    /// Removes this stream from its registry when it ends.
    _registration: Registration,
}

impl DataStream {
    /// Returns the header this stream was opened with.
    #[must_use]
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(&self) -> StreamKind {
        self.header.kind
    }

    /// Returns the handle that revokes this stream.
    #[must_use]
    pub fn handle(&self) -> StreamHandle {
        self.handle.clone()
    }

    /// Returns true once this stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.handle.is_revoked()
    }

    /// Writes one message, reserving queue space for it before it is handed to the connection.
    ///
    /// The message is encoded under the smaller of this stream kind's frame bound and the largest
    /// frame the connection's budget could ever admit, so a frame the budget would always refuse is
    /// refused as too large before it costs a write. The encoded payload is then shrunk to its
    /// exact length, because what the reservation covers has to be what the write actually holds.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] when the stream has been revoked,
    /// [`TransportError::LimitExceeded`] when the write would exceed the connection's queued
    /// bytes, and a framing or stream failure otherwise.
    pub async fn write_message<T: serde::Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let class = class_of(self.header.kind);
        let bound = self
            .writer
            .as_ref()
            .map_or(self.header.kind.max_payload_len(), FrameWriter::max_payload)
            .min(
                self.budget
                    .limits()
                    .ceiling_for(class)
                    .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN),
            );
        let payload = kr_cbor::to_canonical_vec_within(
            message,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(bound),
        )
        .map_err(kr_protocol::frame::FrameError::Cbor)?
        .into_boxed_slice();
        let reservation = self.budget.reserve(class, framed_len(payload.len()))?;
        self.write_reserved(&payload, reservation).await
    }

    /// Writes one already-canonical payload, reserving queue space for it first.
    ///
    /// # Errors
    ///
    /// As [`DataStream::write_message`].
    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let reservation = self
            .budget
            .reserve(class_of(self.header.kind), framed_len(payload.len()))?;
        self.write_reserved(payload, reservation).await
    }

    /// Writes a payload the connection's budget has already admitted.
    ///
    /// The reservation is held for as long as the bytes are the connection's to send, and released
    /// when the write finishes, fails or is revoked.
    async fn write_reserved(
        &mut self,
        payload: &[u8],
        _reservation: QueueReservation,
    ) -> Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| TransportError::Stream("this stream does not send".to_owned()))?;
        let handle = self.handle.clone();
        tokio::select! {
            outcome = writer.write_payload(payload) => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
        }
    }

    /// Reads one frame's payload, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] when the stream is revoked while the read is
    /// waiting, and a framing or stream failure otherwise.
    pub async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let handle = self.handle.clone();
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| TransportError::Stream("this stream does not receive".to_owned()))?;
        tokio::select! {
            outcome = reader.read_payload() => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
        }
    }

    /// Reads one frame and deserialises it, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// As [`DataStream::read_payload`].
    pub async fn read_message<T: serde::de::DeserializeOwned + serde::Serialize>(
        &mut self,
    ) -> Result<Option<T>> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let handle = self.handle.clone();
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| TransportError::Stream("this stream does not receive".to_owned()))?;
        tokio::select! {
            outcome = reader.read_message() => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
        }
    }
}

impl Drop for DataStream {
    fn drop(&mut self) {
        // A revoked stream is reset, not finished: the peer has to see that the stream was taken
        // away rather than a clean end of data it might read as completion.
        if self.handle.is_revoked() {
            if let Some(writer) = self.writer.as_mut() {
                writer.reset();
            }
            if let Some(reader) = self.reader.as_mut() {
                reader.stop();
            }
        }
    }
}

/// A shared marker that revokes one stream.
///
/// Revocation has to reach a stream that another task is already reading or writing, so the flag is
/// shared and the waiters are woken. [`StreamHandle::revoked`] is what an operation races against;
/// resetting the QUIC stream is what the peer sees.
#[derive(Clone, Debug)]
pub struct StreamHandle {
    revoked: Arc<std::sync::atomic::AtomicBool>,
    woken: Arc<tokio::sync::Notify>,
}

impl Default for StreamHandle {
    fn default() -> Self {
        Self {
            revoked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            woken: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl StreamHandle {
    /// Marks the stream revoked and wakes everything waiting on it.
    pub fn revoke(&self) {
        self.revoked
            .store(true, std::sync::atomic::Ordering::Release);
        self.woken.notify_waiters();
    }

    /// Returns true once the stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Resolves as soon as the stream is revoked.
    pub async fn revoked(&self) {
        loop {
            let waiting = self.woken.notified();
            if self.is_revoked() {
                return;
            }
            waiting.await;
            if self.is_revoked() {
                return;
            }
        }
    }
}

/// Removes one stream from its registry when the stream ends.
///
/// Without it a connection that runs many short transfers would accumulate an entry for each one,
/// and a registry that grows without bound is a leak whatever else it gets right.
#[derive(Debug)]
struct Registration {
    registry: std::sync::Weak<RegistryState>,
    key: StreamKey,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(state) = self.registry.upgrade() {
            state.remove(self.key);
        }
    }
}

/// A key that identifies one registered stream.
type StreamKey = u64;

/// What the registry does when the control stream ends.
pub trait RevocationHook: Send + Sync + std::fmt::Debug {
    /// Called once, after every data stream has been revoked.
    ///
    /// The controller stops renewing this connection's dispatch leases here. It does not kill the
    /// worker: section 9 is explicit that a healthy shell is never killed to force a revocation
    /// through.
    fn control_stream_lost(&self, connection_id: ConnectionId);
}

/// Every data stream of one connection.
#[derive(Debug)]
pub struct StreamRegistry {
    state: Arc<RegistryState>,
}

/// The shared half of a registry, so a stream can deregister itself when it ends.
#[derive(Debug)]
struct RegistryState {
    connection_id: ConnectionId,
    budget: Arc<StreamBudget>,
    hook: Option<Arc<dyn RevocationHook>>,
    limits: ReceiveLimits,
    streams: Mutex<RegistryStreams>,
    /// Woken when the control stream ends, so a stream that is waiting to open or be accepted stops
    /// waiting for a peer that will never answer.
    ended: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct RegistryStreams {
    next_key: StreamKey,
    open: HashMap<StreamKey, (StreamKind, StreamHandle)>,
    revoked: bool,
}

/// The negotiated bound on a frame of one kind, never above the kind's own ceiling.
fn effective_limit(kind: StreamKind, limits: ReceiveLimits) -> usize {
    let negotiated = match kind {
        StreamKind::TerminalInput => limits.max_input_frame_len,
        StreamKind::AttachmentChunks => limits.max_attachment_frame_len,
        StreamKind::Control | StreamKind::TerminalOutput | StreamKind::SemanticUpdates => {
            limits.max_control_frame_len
        }
    };
    usize::try_from(negotiated.get())
        .unwrap_or(usize::MAX)
        .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN)
        .min(kind.max_payload_len())
}

impl RegistryState {
    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryStreams> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remove(&self, key: StreamKey) {
        self.lock().open.remove(&key);
    }
}

impl StreamRegistry {
    /// Creates a registry for one connection.
    #[must_use]
    pub fn new(
        connection_id: ConnectionId,
        budget: Arc<StreamBudget>,
        hook: Option<Arc<dyn RevocationHook>>,
    ) -> Self {
        Self::with_limits(connection_id, budget, hook, ReceiveLimits::default())
    }

    /// Creates a registry that holds every stream to the limits the connection negotiated.
    ///
    /// A peer that said it could receive less than a stream kind's ceiling is held to what it said,
    /// in both directions.
    #[must_use]
    pub fn with_limits(
        connection_id: ConnectionId,
        budget: Arc<StreamBudget>,
        hook: Option<Arc<dyn RevocationHook>>,
        limits: ReceiveLimits,
    ) -> Self {
        Self {
            state: Arc::new(RegistryState {
                connection_id,
                budget,
                hook,
                limits,
                streams: Mutex::new(RegistryStreams::default()),
                ended: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Returns the connection these streams belong to.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.state.connection_id
    }

    /// Returns the shared send budget.
    #[must_use]
    pub fn budget(&self) -> &Arc<StreamBudget> {
        &self.state.budget
    }

    /// Opens a data stream to the peer, sending its bounded header first.
    ///
    /// A bulk stream is admitted against the connection's bulk limits before the QUIC stream is
    /// opened, so a peer cannot hold open more transfers than the connection allows.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended,
    /// [`TransportError::LimitExceeded`] when the bulk limits refuse the stream, and a stream error
    /// when the peer refuses it.
    pub async fn open(&self, connection: &Connection, header: StreamHeader) -> Result<DataStream> {
        validate_header(&header, self.state.connection_id)
            .map_err(|refusal| TransportError::Handshake(ProtocolError::from(refusal)))?;
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let class = class_of(header.kind);
        let bulk_slot = match class {
            StreamClass::Bulk => Some(self.state.budget.open_bulk()?),
            _ => None,
        };
        let limit = effective_limit(header.kind, self.state.limits);
        let (send, recv) = self.quic_until_revoked(connection.open_bi()).await?;
        let mut writer = FrameWriter::new(send, header.kind).with_max_payload(limit);
        writer.set_priority(priority_of(header.kind));
        // The header is bytes handed to the connection like any other, so it is charged like any
        // other.
        let header_charge = self.state.budget.reserve(class, MAX_STREAM_HEADER_LEN)?;
        self.until_revoked(writer.write_header(&header)).await?;
        drop(header_charge);
        let reader = FrameReader::new(recv, header.kind).with_max_payload(limit);
        let (handle, registration) = self.register(header.kind)?;
        Ok(DataStream {
            header,
            writer: Some(writer),
            reader: Some(reader),
            handle,
            budget: Arc::clone(&self.state.budget),
            _bulk_slot: bulk_slot,
            _registration: registration,
        })
    }

    /// Accepts a data stream the peer opened, reading and validating its header first.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended, and a handshake
    /// failure when the header does not belong to this connection or the stream carried early data.
    pub async fn accept(&self, connection: &Connection) -> Result<DataStream> {
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let (send, recv) = self.quic_until_revoked(connection.accept_bi()).await?;
        // The header is read on a control-bounded reader: the kind, and therefore the frame bound,
        // is not known until the header has been read, so it cannot decide how much to read.
        let mut reader = FrameReader::new(recv, StreamKind::Control);
        if reader.is_zero_rtt() {
            // A data stream exists only on an authorised connection, and authorisation cannot
            // complete in 0-RTT. A stream that carried early data therefore predates the
            // authorisation it claims, and is refused before its header is read.
            return Err(TransportError::Handshake(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "early data is not accepted on a data stream",
            )));
        }
        let header = self.until_revoked(reader.read_header()).await?;
        validate_header(&header, self.state.connection_id)
            .map_err(|refusal| TransportError::Handshake(ProtocolError::from(refusal)))?;
        let bulk_slot = match class_of(header.kind) {
            StreamClass::Bulk => Some(self.state.budget.open_bulk()?),
            _ => None,
        };
        let limit = effective_limit(header.kind, self.state.limits);
        let writer = FrameWriter::new(send, header.kind).with_max_payload(limit);
        writer.set_priority(priority_of(header.kind));
        let reader = reader.for_kind(header.kind).with_max_payload(limit);
        let (handle, registration) = self.register(header.kind)?;
        Ok(DataStream {
            header,
            writer: Some(writer),
            reader: Some(reader),
            handle,
            budget: Arc::clone(&self.state.budget),
            _bulk_slot: bulk_slot,
            _registration: registration,
        })
    }

    /// Revokes every data stream and stops remote lease renewal.
    ///
    /// Calling it twice is harmless; the hook runs once. A stream opened after this point is
    /// refused, so nothing can slip in behind the revocation.
    pub fn revoke_all(&self) {
        let handles = {
            let mut state = self.state.lock();
            if state.revoked {
                return;
            }
            state.revoked = true;
            state
                .open
                .drain()
                .map(|(_, (_, handle))| handle)
                .collect::<Vec<_>>()
        };
        for handle in handles {
            handle.revoke();
        }
        // A stream that is still waiting to open or be accepted has no handle yet, so it waits on
        // the registry itself.
        self.state.ended.notify_waiters();
        if let Some(hook) = &self.state.hook {
            hook.control_stream_lost(self.state.connection_id);
        }
    }

    /// Returns true once the control stream has ended.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state.lock().revoked
    }

    /// Returns how many data streams are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().open.len()
    }

    /// Returns true when no data stream is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Runs one step of opening or accepting a stream, giving up if the control stream ends first.
    ///
    /// The step's own error is preserved. A refused header is an `INVALID_ARGUMENT`, and turning it
    /// into a connection failure here would change what a peer is told about its own mistake.
    async fn until_revoked<T>(&self, step: impl Future<Output = Result<T>>) -> Result<T> {
        let ended = self.state.ended.notified();
        tokio::pin!(ended);
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        tokio::select! {
            outcome = step => outcome,
            () = &mut ended => Err(TransportError::ControlLost),
        }
    }

    /// Runs one QUIC step, giving up if the control stream ends first.
    async fn quic_until_revoked<T, E: std::fmt::Display>(
        &self,
        step: impl Future<Output = std::result::Result<T, E>>,
    ) -> Result<T> {
        self.until_revoked(async move {
            step.await
                .map_err(|error| TransportError::Stream(error.to_string()))
        })
        .await
    }

    fn register(&self, kind: StreamKind) -> Result<(StreamHandle, Registration)> {
        let mut state = self.state.lock();
        if state.revoked {
            return Err(TransportError::ControlLost);
        }
        let handle = StreamHandle::default();
        let key = state.next_key;
        state.next_key = state.next_key.wrapping_add(1);
        state.open.insert(key, (kind, handle.clone()));
        Ok((
            handle,
            Registration {
                registry: Arc::downgrade(&self.state),
                key,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::frame::StreamResource;
    use kr_protocol::ids::{AttachmentId, EnvironmentId, SessionId, TransferId};
    use kr_protocol::scalars::{Nullable, Uuid};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn connection_id(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn terminal_header(connection: ConnectionId) -> StreamHeader {
        StreamHeader {
            kind: StreamKind::TerminalOutput,
            connection_id: connection,
            stream_id: Nullable::null(),
            resource: StreamResource {
                environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
                session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
                attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
                transfer_id: Nullable::null(),
            },
        }
    }

    #[test]
    fn a_header_from_another_connection_is_refused() {
        let header = terminal_header(connection_id(1));
        assert_eq!(
            validate_header(&header, connection_id(2)),
            Err(HeaderRefusal::WrongConnection)
        );
        assert!(validate_header(&header, connection_id(1)).is_ok());
    }

    #[test]
    fn each_stream_kind_must_name_the_resource_it_uses() {
        let mut header = terminal_header(connection_id(1));
        header.resource.attachment_id = Nullable::null();
        assert_eq!(
            validate_header(&header, connection_id(1)),
            Err(HeaderRefusal::WrongResource)
        );

        header.kind = StreamKind::AttachmentChunks;
        assert_eq!(
            validate_header(&header, connection_id(1)),
            Err(HeaderRefusal::WrongResource)
        );
        header.resource.transfer_id = Nullable::some(TransferId::new(Uuid::from_bytes([6; 16])));
        assert!(validate_header(&header, connection_id(1)).is_ok());
    }

    #[test]
    fn a_header_stays_inside_its_one_kibibyte_bound() {
        let header = terminal_header(connection_id(1));
        let encoded = header.encode().expect("an encoded header");
        assert!(encoded.len() <= kr_protocol::limits::MAX_STREAM_HEADER_LEN);
    }

    #[derive(Debug, Default)]
    struct CountingHook(AtomicUsize);

    impl RevocationHook for CountingHook {
        fn control_stream_lost(&self, _connection_id: ConnectionId) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn losing_the_control_stream_revokes_every_stream_once() {
        let hook = Arc::new(CountingHook::default());
        let registry = StreamRegistry::new(
            connection_id(1),
            Arc::new(StreamBudget::new(crate::scheduler::SendLimits::default())),
            Some(hook.clone()),
        );
        let (first, first_registration) = registry
            .register(StreamKind::TerminalOutput)
            .expect("a handle");
        let (second, second_registration) = registry
            .register(StreamKind::AttachmentChunks)
            .expect("a handle");
        assert_eq!(registry.len(), 2);

        registry.revoke_all();
        assert!(first.is_revoked());
        assert!(second.is_revoked());
        assert!(registry.is_empty());
        assert_eq!(hook.0.load(Ordering::Acquire), 1);
        drop((first_registration, second_registration));

        registry.revoke_all();
        assert_eq!(hook.0.load(Ordering::Acquire), 1, "the hook runs once");
        assert!(matches!(
            registry.register(StreamKind::TerminalInput),
            Err(TransportError::ControlLost)
        ));
    }

    #[test]
    fn a_stream_that_ends_normally_leaves_the_registry() {
        let registry = StreamRegistry::new(
            connection_id(1),
            Arc::new(StreamBudget::new(crate::scheduler::SendLimits::default())),
            None,
        );
        for _ in 0..1_000 {
            let (_handle, registration) = registry
                .register(StreamKind::AttachmentChunks)
                .expect("a handle");
            assert_eq!(registry.len(), 1);
            drop(registration);
            assert!(registry.is_empty());
        }
    }

    #[tokio::test]
    async fn a_waiting_operation_wakes_the_moment_its_stream_is_revoked() {
        let handle = StreamHandle::default();
        let waiting = handle.clone();
        let waiter = tokio::spawn(async move { waiting.revoked().await });
        // Give the waiter a moment to park before the revocation arrives.
        tokio::task::yield_now().await;
        handle.revoke();
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the waiter woke")
            .expect("the task finished");
        // A handle that is already revoked resolves without waiting at all.
        handle.revoked().await;
    }
}
