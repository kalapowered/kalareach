//! Data streams: opening, accepting, header validation, and revocation when the control stream ends.
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
//!
//! # Accepting a stream
//!
//! A stream the peer opens is taken in two steps, so that one that never sends its header cannot
//! hold back another. [`StreamRegistry::accept_pending`] takes the stream from the connection and
//! nothing more, and hands back a [`PendingStream`]. [`PendingStream::open`] reads its header under
//! the header deadline, checks it, and returns the [`DataStream`]. At most
//! [`MAX_PENDING_HEADERS`] streams of a connection are pending at once, and a caller that opens
//! each one on a task of its own, as the listener does, reads their headers side by side.
//!
//! # Reading and writing
//!
//! A [`DataStream`] reads and writes through the same handle that revokes it, so a revocation
//! reaches an operation that is already waiting. [`DataStream::split`] gives the reading half to
//! one task and the writing half to another, which share the handle and keep the stream counted
//! against the connection until both are gone. A stream whose registry holds deadlines
//! ([`StreamRegistry::with_deadlines`]) is cut when its peer stops sending or stops reading.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use iroh::endpoint::{Connection, SendStream};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::hello::ReceiveLimits;
use kr_protocol::ids::ConnectionId;
use kr_protocol::limits::MAX_STREAM_HEADER_LEN;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::codec::{Admission, FrameReader, FrameWriter, STREAM_REVOKED};
use crate::deadlines::{Deadline, DeadlineKind, Deadlines};
use crate::error::{Result, TransportError};
use crate::scheduler::{
    BulkStreamSlot, QueueReservation, StreamBudget, StreamClass, class_of, priority_of,
};

/// How many streams of one connection may be waiting for their headers at once.
///
/// A header is read on a task of its own, so a stream that sends half of one holds a place for
/// as long as the header deadline and holds nothing back beyond that. The places bound the tasks
/// and the connection's QUIC stream limit is set with them in mind.
pub const MAX_PENDING_HEADERS: usize = 4;

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

/// What keeps a stream counted against its connection while any half of it is held.
///
/// The bulk slot is returned and the registry entry removed when the last half is dropped.
#[derive(Debug)]
struct Life {
    _bulk_slot: Option<BulkStreamSlot>,
    /// Removes this stream from its registry when it ends.
    _registration: Registration,
}

/// One open data stream.
///
/// Reads and writes go through this type rather than through the reader and writer directly,
/// because revocation has to reach an operation that is already waiting. Each one races the
/// revocation signal, so a stream that is revoked while a task is blocked on it returns
/// [`TransportError::ControlLost`] at once rather than waiting for a peer that will never send.
///
/// A task that has to read the next frame while another writes the answer to the last takes the
/// stream apart with [`DataStream::split`].
#[derive(Debug)]
pub struct DataStream {
    reader: DataReader,
    writer: DataWriter,
}

impl DataStream {
    /// Returns the header this stream was opened with.
    #[must_use]
    pub const fn header(&self) -> &StreamHeader {
        self.reader.header()
    }

    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(&self) -> StreamKind {
        self.reader.header().kind
    }

    /// Returns the handle that revokes this stream.
    #[must_use]
    pub fn handle(&self) -> StreamHandle {
        self.reader.handle()
    }

    /// Returns true once this stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.reader.is_revoked()
    }

    /// Returns the send priority the connection is using for this stream.
    ///
    /// `None` once the stream is closed. What comes back is the priority the connection installed,
    /// so a caller can see that the scheduler's decision reached the connection rather than only
    /// that the scheduler made it.
    #[must_use]
    pub fn priority(&self) -> Option<i32> {
        self.writer.priority()
    }

    /// Takes the stream apart into the half that reads and the half that writes.
    ///
    /// The halves share the stream's handle, so revoking either reaches the other, and the stream
    /// stays counted against its connection until both are dropped. Each half resets its own
    /// direction when it is dropped after a revocation.
    #[must_use]
    pub fn split(self) -> (DataReader, DataWriter) {
        (self.reader, self.writer)
    }

    /// Ends the stream by resetting it, so the peer sees that it was taken away.
    ///
    /// Dropping a stream that was not revoked finishes it instead, which the peer reads as a clean
    /// end of data. A host that refuses a stream resets it.
    pub fn reset(self) {
        self.reader.handle.revoke();
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
    /// bytes, [`TransportError::Deadline`] when the peer did not read it in time, and a framing or
    /// stream failure otherwise.
    pub async fn write_message<T: serde::Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        self.writer.write_message(message).await
    }

    /// Writes one message for as long as `admits` holds, and says whether it went.
    ///
    /// It reserves queue space and holds the write to the same bounds as
    /// [`DataStream::write_message`], and the write is made as
    /// [`FrameWriter::write_message_while`] makes it: `admits` is asked at every attempt to hand
    /// bytes to the stream, and a frame it refuses leaves the stream reset. A revocation ends the
    /// write with an error, and so does a refused reservation, never with `Ok(false)`: the
    /// stream's revoked state is asked at each attempt before `admits` is, so no byte goes after
    /// a revocation.
    ///
    /// # Errors
    ///
    /// As [`DataStream::write_message`].
    pub async fn write_message_while<T: serde::Serialize + ?Sized>(
        &mut self,
        message: &T,
        admits: Admission<'_>,
    ) -> Result<bool> {
        self.writer.write_message_while(message, admits).await
    }

    /// Writes one already-canonical payload, reserving queue space for it first.
    ///
    /// # Errors
    ///
    /// As [`DataStream::write_message`].
    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.writer.write_payload(payload).await
    }

    /// Reads one frame's payload, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] when the stream is revoked while the read is
    /// waiting, [`TransportError::Deadline`] when the peer stopped sending, and a framing or
    /// stream failure otherwise.
    pub async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        self.reader.read_payload().await
    }

    /// Reads one frame and deserialises it, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// As [`DataStream::read_payload`].
    pub async fn read_message<T: kr_protocol::wire::WireMessage>(&mut self) -> Result<Option<T>> {
        self.reader.read_message().await
    }
}

/// The half of a data stream that reads.
#[derive(Debug)]
pub struct DataReader {
    header: StreamHeader,
    reader: FrameReader,
    handle: StreamHandle,
    _life: Arc<Life>,
}

impl DataReader {
    /// Returns the header the stream was opened with.
    #[must_use]
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Returns the handle that revokes the stream, which both halves share.
    #[must_use]
    pub fn handle(&self) -> StreamHandle {
        self.handle.clone()
    }

    /// Returns true once the stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.handle.is_revoked()
    }

    /// Reads one frame's payload, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] when the stream is revoked, before the read or
    /// while it waits, [`TransportError::Deadline`] when the peer left the wait for a frame, or
    /// the frame itself, longer than its deadline allows, and a framing or stream failure
    /// otherwise. A read that was cut revokes the stream, so the writing half stops too.
    pub async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let handle = self.handle.clone();
        let unless = UnlessFinished::new(&handle);
        let outcome = tokio::select! {
            outcome = self.reader.read_payload() => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
        };
        self.handle.revoke_if_cut(unless.finish(outcome))
    }

    /// Reads one frame and deserialises it, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// As [`DataReader::read_payload`].
    pub async fn read_message<T: kr_protocol::wire::WireMessage>(&mut self) -> Result<Option<T>> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let handle = self.handle.clone();
        let unless = UnlessFinished::new(&handle);
        let outcome = tokio::select! {
            outcome = self.reader.read_message() => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
        };
        self.handle.revoke_if_cut(unless.finish(outcome))
    }
}

impl Drop for DataReader {
    fn drop(&mut self) {
        // A revoked stream is reset, not finished: the peer has to see that the stream was taken
        // away rather than a clean end of data it might read as completion.
        if self.handle.is_revoked() {
            self.reader.stop();
        }
    }
}

/// The half of a data stream that writes.
#[derive(Debug)]
pub struct DataWriter {
    kind: StreamKind,
    writer: FrameWriter,
    handle: StreamHandle,
    budget: Arc<StreamBudget>,
    deadlines: Option<Arc<dyn Deadlines>>,
    _life: Arc<Life>,
}

impl DataWriter {
    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Returns the handle that revokes the stream, which both halves share.
    #[must_use]
    pub fn handle(&self) -> StreamHandle {
        self.handle.clone()
    }

    /// Returns true once the stream has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.handle.is_revoked()
    }

    /// Returns the send priority the connection is using for this stream, or `None` once the
    /// stream is closed.
    #[must_use]
    pub fn priority(&self) -> Option<i32> {
        self.writer.priority()
    }

    /// Writes one message, reserving queue space for it first.
    ///
    /// # Errors
    ///
    /// As [`DataStream::write_message`].
    pub async fn write_message<T: serde::Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        let (payload, reservation) = self.encode(message)?;
        self.write_reserved(&payload, reservation).await
    }

    /// Writes one message for as long as `admits` holds, and says whether it went.
    ///
    /// The stream's revoked state is asked in the same poll as `admits`, before it, at each attempt
    /// to hand bytes to the stream, so nothing is written after a revocation even when the
    /// stream is writable at the moment it is revoked: the write ends with
    /// [`TransportError::ControlLost`] and the stream is reset.
    ///
    /// # Errors
    ///
    /// As [`DataStream::write_message`].
    pub async fn write_message_while<T: serde::Serialize + ?Sized>(
        &mut self,
        message: &T,
        admits: Admission<'_>,
    ) -> Result<bool> {
        let (payload, reservation) = self.encode(message)?;
        let handle = self.handle.clone();
        let unless = UnlessFinished::new(&handle);
        let mut deadline = Deadline::start(self.deadlines.as_ref(), DeadlineKind::Write);
        // A race between the write and the revocation can be won by the write when both are ready,
        // so the revoked state is part of what each attempt asks. The host's own refusal and this
        // one both stop the frame; only the host's is `Ok(false)`.
        let revoked_at_an_attempt = std::sync::atomic::AtomicBool::new(false);
        let admits_while_not_revoked = |attempt: &mut dyn FnMut()| {
            if handle.is_revoked() {
                revoked_at_an_attempt.store(true, std::sync::atomic::Ordering::Relaxed);
                return false;
            }
            admits(attempt)
        };
        let outcome = tokio::select! {
            outcome = self.writer.write_payload_while(&payload, &admits_while_not_revoked) => {
                match outcome {
                    Ok(false) if revoked_at_an_attempt.load(std::sync::atomic::Ordering::Relaxed) => {
                        Err(TransportError::ControlLost)
                    }
                    other => other,
                }
            }
            () = handle.revoked() => Err(TransportError::ControlLost),
            () = &mut deadline => Err(TransportError::Deadline(DeadlineKind::Write)),
        };
        drop(reservation);
        // A frame the caller's check refused leaves the stream reset, so the other half has
        // nothing more to read from it either.
        if matches!(outcome, Ok(false)) {
            self.handle.revoke();
        }
        self.handle.revoke_if_cut(unless.finish(outcome))
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
            .reserve(class_of(self.kind), framed_len(payload.len()))?;
        self.write_reserved(payload, reservation).await
    }

    /// Encodes a message under the bound it is written under, and reserves queue space for it.
    fn encode<T: serde::Serialize + ?Sized>(
        &self,
        message: &T,
    ) -> Result<(Box<[u8]>, QueueReservation)> {
        if self.handle.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let class = class_of(self.kind);
        let bound = self.writer.max_payload().min(
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
        Ok((payload, reservation))
    }

    /// Writes a payload the connection's budget has already admitted.
    ///
    /// The reservation is held for as long as the bytes are the connection's to send, and
    /// released when the write finishes, fails, is revoked or is cut by its deadline.
    async fn write_reserved(
        &mut self,
        payload: &[u8],
        _reservation: QueueReservation,
    ) -> Result<()> {
        let handle = self.handle.clone();
        let unless = UnlessFinished::new(&handle);
        let mut deadline = Deadline::start(self.deadlines.as_ref(), DeadlineKind::Write);
        let outcome = tokio::select! {
            outcome = self.writer.write_payload(payload) => outcome,
            () = handle.revoked() => Err(TransportError::ControlLost),
            () = &mut deadline => Err(TransportError::Deadline(DeadlineKind::Write)),
        };
        self.handle.revoke_if_cut(unless.finish(outcome))
    }
}

impl Drop for DataWriter {
    fn drop(&mut self) {
        // As the reading half: a revoked stream is reset, not finished.
        if self.handle.is_revoked() {
            self.writer.reset();
        }
    }
}

/// Revokes a stream whose read or write was dropped before it ended.
///
/// Part of a frame may have been taken or sent, and the stream can carry nothing more: its reader
/// or writer refuses every later call. Revoking is what tells the other half and makes dropping the
/// stream a reset.
struct UnlessFinished {
    handle: StreamHandle,
    finished: bool,
}

impl UnlessFinished {
    fn new(handle: &StreamHandle) -> Self {
        Self {
            handle: handle.clone(),
            finished: false,
        }
    }

    /// Passes `outcome` through, now that the operation ended by itself.
    fn finish<T>(mut self, outcome: T) -> T {
        self.finished = true;
        outcome
    }
}

impl Drop for UnlessFinished {
    fn drop(&mut self) {
        if !self.finished {
            self.handle.revoke();
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

    /// Passes an outcome through, revoking the stream first when it is a cut deadline.
    ///
    /// A stream whose peer stopped reading or sending is dead, and a write or a read that was
    /// dropped part way has left a frame in pieces. Revoking is what stops the other half and makes
    /// dropping the stream a reset.
    fn revoke_if_cut<T>(&self, outcome: Result<T>) -> Result<T> {
        if matches!(outcome, Err(TransportError::Deadline(_))) {
            self.revoke();
        }
        outcome
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
    /// What a stream's reads and writes are held to, when they are held to anything.
    deadlines: Option<Arc<dyn Deadlines>>,
    /// The places for streams that are waiting for their headers.
    pending: Arc<Semaphore>,
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
    /// Set when the revocation hook has run, which it does once.
    hook_ran: bool,
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

    fn is_revoked(&self) -> bool {
        self.lock().revoked
    }

    fn register(self: &Arc<Self>, kind: StreamKind) -> Result<(StreamHandle, Registration)> {
        let mut state = self.lock();
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
                registry: Arc::downgrade(self),
                key,
            },
        ))
    }

    /// Runs one step of opening or accepting a stream, giving up if the control stream ends first.
    ///
    /// The step's own error is preserved. A refused header is an `INVALID_ARGUMENT`, and turning it
    /// into a connection failure here would change what a peer is told about its own mistake.
    async fn until_revoked<T>(&self, step: impl Future<Output = Result<T>>) -> Result<T> {
        let ended = self.ended.notified();
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

    /// Runs one step under a deadline of `kind`, when the registry holds deadlines.
    async fn within<T>(
        &self,
        kind: DeadlineKind,
        step: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let mut deadline = Deadline::start(self.deadlines.as_ref(), kind);
        tokio::select! {
            outcome = step => outcome,
            () = &mut deadline => Err(TransportError::Deadline(kind)),
        }
    }

    /// Registers a stream, and joins it to the bulk slot it holds, if it holds one.
    fn life(
        self: &Arc<Self>,
        kind: StreamKind,
        bulk_slot: Option<BulkStreamSlot>,
    ) -> Result<(Arc<Life>, StreamHandle)> {
        let (handle, registration) = self.register(kind)?;
        let life = Arc::new(Life {
            _bulk_slot: bulk_slot,
            _registration: registration,
        });
        Ok((life, handle))
    }

    /// Builds the stream whose header has been admitted, from its two halves.
    fn stream(
        &self,
        header: StreamHeader,
        writer: FrameWriter,
        reader: FrameReader,
        life: Arc<Life>,
        handle: StreamHandle,
    ) -> DataStream {
        let reader = match &self.deadlines {
            Some(deadlines) => reader.with_deadlines(Arc::clone(deadlines)),
            None => reader,
        };
        DataStream {
            writer: DataWriter {
                kind: header.kind,
                writer,
                handle: handle.clone(),
                budget: Arc::clone(&self.budget),
                deadlines: self.deadlines.clone(),
                _life: Arc::clone(&life),
            },
            reader: DataReader {
                header,
                reader,
                handle,
                _life: life,
            },
        }
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
        Self::build(connection_id, budget, hook, limits, None)
    }

    /// Creates a registry as [`StreamRegistry::with_limits`] does, whose streams are also held to
    /// `deadlines`: a header that does not arrive, a frame that stops arriving, a wait for the next
    /// frame that does not end and a write the peer does not read are each cut when their deadline
    /// passes. A registry made without them waits for its peer as long as the peer takes.
    #[must_use]
    pub fn with_deadlines(
        connection_id: ConnectionId,
        budget: Arc<StreamBudget>,
        hook: Option<Arc<dyn RevocationHook>>,
        limits: ReceiveLimits,
        deadlines: Arc<dyn Deadlines>,
    ) -> Self {
        Self::build(connection_id, budget, hook, limits, Some(deadlines))
    }

    fn build(
        connection_id: ConnectionId,
        budget: Arc<StreamBudget>,
        hook: Option<Arc<dyn RevocationHook>>,
        limits: ReceiveLimits,
        deadlines: Option<Arc<dyn Deadlines>>,
    ) -> Self {
        Self {
            state: Arc::new(RegistryState {
                connection_id,
                budget,
                hook,
                limits,
                deadlines,
                pending: Arc::new(Semaphore::new(MAX_PENDING_HEADERS)),
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
        let (send, recv) = self.state.quic_until_revoked(connection.open_bi()).await?;
        let mut writer = FrameWriter::new(send, header.kind).with_max_payload(limit);
        writer.set_priority(priority_of(header.kind));
        let mut reader = FrameReader::new(recv, header.kind).with_max_payload(limit);
        let admitted = async {
            // The header is bytes handed to the connection like any other, so it is charged like
            // any other.
            let header_charge = self.state.budget.reserve(class, MAX_STREAM_HEADER_LEN)?;
            self.state
                .until_revoked(writer.write_header(&header))
                .await?;
            drop(header_charge);
            self.state.life(header.kind, bulk_slot)
        }
        .await;
        match admitted {
            Ok((life, handle)) => Ok(self.state.stream(header, writer, reader, life, handle)),
            Err(error) => {
                // A stream that failed to open is reset, never finished: the host must not
                // admit one that ends with no frame.
                writer.reset();
                reader.stop();
                Err(error)
            }
        }
    }

    /// Accepts a data stream the peer opened and reads its header, for a caller that takes one
    /// stream at a time and wants every kind.
    ///
    /// A host that takes streams from its peer on a connection uses [`StreamRegistry::accept_pending`]
    /// and opens each one on a task of its own, so that one stream with half a header does not hold
    /// the next.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended, and a handshake
    /// failure when the header does not belong to this connection or the stream carried early data.
    pub async fn accept(&self, connection: &Connection) -> Result<DataStream> {
        self.accept_pending(connection)
            .await?
            .open(StreamKind::ALL)
            .await
    }

    /// Takes the next stream the peer opened from the connection, without reading it.
    ///
    /// It waits for one of [`MAX_PENDING_HEADERS`] places first, so a connection never has more
    /// streams waiting for their headers than that, and the stream it returns holds its place until
    /// [`PendingStream::open`] has read the header and ended. A stream that carried QUIC early data
    /// is refused here, whatever its header says: a data stream exists only on an authorised
    /// connection, and authorisation cannot complete in 0-RTT.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ControlLost`] once the control stream has ended, a stream error
    /// when the connection can accept no more, and a handshake failure for a stream that carried
    /// early data, which is reset.
    pub async fn accept_pending(&self, connection: &Connection) -> Result<PendingStream> {
        if self.is_revoked() {
            return Err(TransportError::ControlLost);
        }
        let place = Arc::clone(&self.state.pending);
        let permit = self
            .state
            .until_revoked(async move {
                place
                    .acquire_owned()
                    .await
                    .map_err(|_| TransportError::ControlLost)
            })
            .await?;
        let (mut send, recv) = self
            .state
            .quic_until_revoked(connection.accept_bi())
            .await?;
        // The header is read on a control-bounded reader: the kind, and therefore the frame bound,
        // is not known until the header has been read, so it cannot decide how much to read.
        let mut reader = FrameReader::new(recv, StreamKind::Control);
        if reader.is_zero_rtt() {
            reader.stop();
            let _ = send.reset(iroh::endpoint::VarInt::from(STREAM_REVOKED));
            return Err(TransportError::Handshake(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "early data is not accepted on a data stream",
            )));
        }
        Ok(PendingStream {
            state: Arc::clone(&self.state),
            send: Some(send),
            reader: Some(reader),
            _place: permit,
        })
    }

    /// Revokes every data stream, without running the revocation hook.
    ///
    /// Every handle is revoked before this returns, whichever call revoked the registry first, and
    /// a stream opened after this point is refused. A host's hook is a statement about the whole
    /// connection, which may have more to undo than its streams, so the listener runs it once the
    /// connection's handler has gone ([`StreamRegistry::revoke_all`]) and revokes the streams as
    /// soon as the loss is declared.
    pub fn revoke_streams(&self) {
        let first = {
            let mut state = self.state.lock();
            if state.revoked {
                false
            } else {
                state.revoked = true;
                // Under the lock, so a second caller that finds the registry revoked finds every
                // handle revoked too. A handle's revocation is a flag and a wake-up and takes no lock.
                for (_, (_, handle)) in state.open.drain() {
                    handle.revoke();
                }
                true
            }
        };
        if first {
            // A stream that is still waiting to open or be accepted has no handle yet, so it waits
            // on the registry itself.
            self.state.ended.notify_waiters();
        }
    }

    /// Revokes every data stream and stops remote lease renewal.
    ///
    /// Calling it twice is harmless; the hook runs once, on the first call that reaches it, and
    /// whether or not the streams were revoked before ([`StreamRegistry::revoke_streams`]). A stream
    /// opened after this point is refused, so nothing can slip in behind the revocation.
    pub fn revoke_all(&self) {
        self.revoke_streams();
        let run = !std::mem::replace(&mut self.state.lock().hook_ran, true);
        if run && let Some(hook) = &self.state.hook {
            hook.control_stream_lost(self.state.connection_id);
        }
    }

    /// Returns true once the control stream has ended.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state.is_revoked()
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

    /// Registers a stream the way an admitted one is, for this module's tests.
    #[cfg(test)]
    fn register(&self, kind: StreamKind) -> Result<(StreamHandle, Registration)> {
        self.state.register(kind)
    }
}

/// A stream the peer opened whose header has not been read.
///
/// It holds one of its connection's places for streams waiting for their headers until
/// [`PendingStream::open`] has returned, and nothing else: no slot against the bulk limits, no
/// entry in the registry. Dropping it resets the stream.
#[derive(Debug)]
pub struct PendingStream {
    state: Arc<RegistryState>,
    send: Option<SendStream>,
    reader: Option<FrameReader>,
    _place: OwnedSemaphorePermit,
}

impl PendingStream {
    /// Reads the stream's header and admits it, or resets the stream.
    ///
    /// The header is read under the header deadline when the registry holds deadlines. It is then
    /// checked against the connection ([`validate_header`]) and its kind against `accepted`, and
    /// only a stream that passes both is given a bulk slot and a place in the registry. A stream
    /// that fails any step is reset, with nothing counted against the connection.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Deadline`] when no header arrived in time,
    /// [`TransportError::ControlLost`] once the control stream has ended, a handshake failure when
    /// the header does not belong to this connection or names a kind not in `accepted`,
    /// [`TransportError::LimitExceeded`] when the bulk limits refuse the stream, and a framing or
    /// stream failure when the header could not be read.
    pub async fn open(mut self, accepted: &[StreamKind]) -> Result<DataStream> {
        let state = Arc::clone(&self.state);
        let reader = self
            .reader
            .as_mut()
            .expect("a pending stream holds its reader until it is opened");
        let header = state
            .until_revoked(state.within(DeadlineKind::Header, reader.read_header()))
            .await?;
        validate_header(&header, state.connection_id)
            .map_err(|refusal| TransportError::Handshake(ProtocolError::from(refusal)))?;
        if !accepted.contains(&header.kind) {
            return Err(TransportError::Handshake(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host does not accept a stream of this kind",
            )));
        }
        // Everything that can still refuse the stream is done before its halves leave `self`, so a
        // refusal resets them rather than finishing the one that sends.
        let bulk_slot = match class_of(header.kind) {
            StreamClass::Bulk => Some(state.budget.open_bulk()?),
            _ => None,
        };
        let (life, handle) = state.life(header.kind, bulk_slot)?;
        let limit = effective_limit(header.kind, state.limits);
        let writer = FrameWriter::new(
            self.send
                .take()
                .expect("a pending stream holds its sender until it is opened"),
            header.kind,
        )
        .with_max_payload(limit);
        writer.set_priority(priority_of(header.kind));
        let reader = self
            .reader
            .take()
            .expect("a pending stream holds its reader until it is opened")
            .for_kind(header.kind)
            .with_max_payload(limit);
        Ok(state.stream(header, writer, reader, life, handle))
    }
}

impl Drop for PendingStream {
    fn drop(&mut self) {
        // A stream refused before it became one is reset, never finished: the peer must not read
        // a refusal as a clean end.
        if let Some(send) = self.send.as_mut() {
            let _ = send.reset(iroh::endpoint::VarInt::from(STREAM_REVOKED));
        }
        if let Some(reader) = self.reader.as_mut() {
            reader.stop();
        }
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

    /// KR-REQ-23.11: a stream header is checked against this control connection.
    #[test]
    fn a_header_from_another_connection_is_refused() {
        let header = terminal_header(connection_id(1));
        assert_eq!(
            validate_header(&header, connection_id(2)),
            Err(HeaderRefusal::WrongConnection)
        );
        assert!(validate_header(&header, connection_id(1)).is_ok());
    }

    /// KR-REQ-23.11: a stream header names its kind and the resource it is authorised for.
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

    /// KR-REQ-23.11: a stream header is at most 1 KiB.
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

    /// KR-REQ-23.18: losing the control stream revokes every data stream.
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

    /// KR-REQ-23.18: a revoked stream stops at once, even mid-read.
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
