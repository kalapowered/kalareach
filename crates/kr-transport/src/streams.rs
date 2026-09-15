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
use std::sync::{Arc, Mutex};

use iroh::endpoint::Connection;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::ids::ConnectionId;

use crate::codec::{FrameReader, FrameWriter};
use crate::error::{Result, TransportError};
use crate::scheduler::{BulkStreamSlot, StreamBudget, StreamClass, class_of, priority_of};

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
#[derive(Debug)]
pub struct DataStream {
    header: StreamHeader,
    writer: Option<FrameWriter>,
    reader: Option<FrameReader>,
    handle: StreamHandle,
    /// The bulk slot this stream occupies, released when the stream is dropped.
    _bulk_slot: Option<BulkStreamSlot>,
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

    /// Returns the writer, if this side sends on the stream.
    pub fn writer(&mut self) -> Option<&mut FrameWriter> {
        self.writer.as_mut()
    }

    /// Returns the reader, if this side receives on the stream.
    pub fn reader(&mut self) -> Option<&mut FrameReader> {
        self.reader.as_mut()
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
}

/// A shared marker that revokes one stream.
///
/// Revocation has to reach a stream that another task is reading or writing, so the flag is shared
/// and the owner checks it. Resetting the QUIC stream is what the peer sees; the flag is what this
/// side's loops see.
#[derive(Clone, Debug, Default)]
pub struct StreamHandle {
    revoked: Arc<std::sync::atomic::AtomicBool>,
}

impl StreamHandle {
    /// Marks the stream revoked.
    pub fn revoke(&self) {
        self.revoked
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Returns true once the stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::Acquire)
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
    connection_id: ConnectionId,
    budget: Arc<StreamBudget>,
    hook: Option<Arc<dyn RevocationHook>>,
    state: Mutex<RegistryState>,
}

#[derive(Debug, Default)]
struct RegistryState {
    next_key: StreamKey,
    streams: HashMap<StreamKey, (StreamKind, StreamHandle)>,
    revoked: bool,
}

impl StreamRegistry {
    /// Creates a registry for one connection.
    #[must_use]
    pub fn new(
        connection_id: ConnectionId,
        budget: Arc<StreamBudget>,
        hook: Option<Arc<dyn RevocationHook>>,
    ) -> Self {
        Self {
            connection_id,
            budget,
            hook,
            state: Mutex::new(RegistryState::default()),
        }
    }

    /// Returns the connection these streams belong to.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the shared bulk budget.
    #[must_use]
    pub fn budget(&self) -> &Arc<StreamBudget> {
        &self.budget
    }

    /// Opens a data stream to the peer, sending its header first.
    ///
    /// A bulk stream is admitted against the connection's bulk limits before the QUIC stream is
    /// opened, so a peer cannot hold open more transfers than the connection allows.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended,
    /// [`TransportError::LimitExceeded`] when the bulk limits refuse the stream, and a stream
    /// error when the peer refuses it.
    pub async fn open(&self, connection: &Connection, header: StreamHeader) -> Result<DataStream> {
        validate_header(&header, self.connection_id)
            .map_err(|refusal| TransportError::Handshake(ProtocolError::from(refusal)))?;
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let bulk_slot = match class_of(header.kind) {
            StreamClass::Bulk => Some(self.budget.open_bulk()?),
            _ => None,
        };
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| TransportError::Stream(error.to_string()))?;
        let mut writer = FrameWriter::new(send, header.kind);
        writer.set_priority(priority_of(header.kind));
        writer.write_header(&header).await?;
        let reader = FrameReader::new(recv, header.kind);
        let handle = self.register(header.kind)?;
        Ok(DataStream {
            header,
            writer: Some(writer),
            reader: Some(reader),
            handle,
            _bulk_slot: bulk_slot,
        })
    }

    /// Accepts a data stream the peer opened, reading and validating its header first.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended, and a handshake
    /// failure when the header does not belong to this connection.
    pub async fn accept(&self, connection: &Connection) -> Result<DataStream> {
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|error| TransportError::Stream(error.to_string()))?;
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
        let header = reader.read_header().await?;
        validate_header(&header, self.connection_id)
            .map_err(|refusal| TransportError::Handshake(ProtocolError::from(refusal)))?;
        let bulk_slot = match class_of(header.kind) {
            StreamClass::Bulk => Some(self.budget.open_bulk()?),
            _ => None,
        };
        let writer = FrameWriter::new(send, header.kind);
        writer.set_priority(priority_of(header.kind));
        let reader = reader.for_kind(header.kind);
        let handle = self.register(header.kind)?;
        Ok(DataStream {
            header,
            writer: Some(writer),
            reader: Some(reader),
            handle,
            _bulk_slot: bulk_slot,
        })
    }

    /// Revokes every data stream and stops remote lease renewal.
    ///
    /// Calling it twice is harmless; the hook runs once.
    pub fn revoke_all(&self) {
        let handles = {
            let mut state = self.lock();
            if state.revoked {
                return;
            }
            state.revoked = true;
            state
                .streams
                .drain()
                .map(|(_, (_, handle))| handle)
                .collect::<Vec<_>>()
        };
        for handle in handles {
            handle.revoke();
        }
        if let Some(hook) = &self.hook {
            hook.control_stream_lost(self.connection_id);
        }
    }

    /// Returns true once the control stream has ended.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.lock().revoked
    }

    /// Returns how many data streams are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().streams.len()
    }

    /// Returns true when no data stream is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn register(&self, kind: StreamKind) -> Result<StreamHandle> {
        let mut state = self.lock();
        if state.revoked {
            return Err(TransportError::ControlLost);
        }
        let handle = StreamHandle::default();
        let key = state.next_key;
        state.next_key = state.next_key.wrapping_add(1);
        state.streams.insert(key, (kind, handle.clone()));
        Ok(handle)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            Arc::new(StreamBudget::new(crate::scheduler::BulkLimits::default())),
            Some(hook.clone()),
        );
        let first = registry
            .register(StreamKind::TerminalOutput)
            .expect("a handle");
        let second = registry
            .register(StreamKind::AttachmentChunks)
            .expect("a handle");
        assert_eq!(registry.len(), 2);

        registry.revoke_all();
        assert!(first.is_revoked());
        assert!(second.is_revoked());
        assert!(registry.is_empty());
        assert_eq!(hook.0.load(Ordering::Acquire), 1);

        registry.revoke_all();
        assert_eq!(hook.0.load(Ordering::Acquire), 1, "the hook runs once");
        assert!(matches!(
            registry.register(StreamKind::TerminalInput),
            Err(TransportError::ControlLost)
        ));
    }
}
