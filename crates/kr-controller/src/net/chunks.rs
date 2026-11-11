//! The data streams a paired device sends an upload's chunks on.
//!
//! A device sends an attachment's bytes on a data stream of its own and never on the control
//! stream: a chunk is as large as a control frame may not be, and a stalled chunk must not hold a
//! control answer. The transport reads each stream's header under a deadline and hands the stream
//! over ([`kr_transport::listener::DataStreams`]); what this module decides is whether the host
//! serves it, in this order, each refusal a reset with nothing staged and nothing recorded:
//!
//! 1. **The environment** the header names is this host's.
//! 2. **The upload and the principal.** The transfer is one of *this device's* uploads, receiving
//!    and not expired. An unknown, foreign, owner's, cancelled or expired transfer gets one
//!    refusal. The lookup waits for a lookup place of the device's principal, and a place stays
//!    taken until the blocking lookup that holds it ends, however long ago its stream was given up
//!    and whichever connection it came on ([`ChunkStreams::lookups_of`]).
//! 3. **The authority** the door decides for an `upload.chunk` naming the upload's session, under
//!    the connection's scope.
//! 4. **One live stream for each transfer.** A newer stream for a transfer replaces the older,
//!    which is revoked ([`ChunkStreams::stand`]).
//!
//! Each frame the stream carries is held to the stream's policy ([`StreamPolicy`]), then waits for
//! the transfer's gate, so that at most one chunk of one transfer is in the transfer service across
//! streams, and then goes through the door as any mutation does ([`ChunkAdmission`]).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::ids::{ActorId, DeviceId, TransferId};
use kr_protocol::method::Method;
use kr_transport::clock::ContinuousClock;
use kr_transport::deadlines::{DeadlineKind, Deadlines};
use kr_transport::listener::{DataStreams, HostHandler, ReceivedFrame};
use kr_transport::streams::{DataStream, StreamHandle};
use tokio::sync::{OwnedMutexGuard, Semaphore};
use tokio::task::JoinSet;

use super::NetworkHost;
use super::dispatch::RemoteConnection;
use crate::transfer::carries;

/// The stream kinds this host takes from a paired device, besides the control stream.
///
/// The one list both the listener's configuration and the answer to `transfer.streams` are built
/// from, so a host never says it takes a stream its listener resets.
pub(crate) const ACCEPTED_STREAMS: [StreamKind; 1] = [StreamKind::AttachmentChunks];

/// How many lookups of a device's uploads one device principal has running at once, across all its
/// connections.
const LOOKUPS_PER_PRINCIPAL: usize = 2;

/// One transfer of one device principal.
type Key = (ActorId, TransferId);

/// The stream that serves a transfer now.
#[derive(Debug)]
struct Live {
    handle: StreamHandle,
}

/// Which stream serves each transfer, the gate that keeps one chunk of a transfer in the service at
/// a time, and the places a device principal's lookups wait for.
///
/// Host-wide, because a device that lost its connection resumes on another while the host still
/// holds the old one for up to the transport's idle timeout, and the two must not both act on one
/// transfer.
#[derive(Debug, Default)]
pub(super) struct ChunkStreams {
    live: Mutex<BTreeMap<Key, Arc<Live>>>,
    /// Weak, because a gate is held by whoever waits for it or holds its guard, and one nobody
    /// holds is free and is made again: removing the entry for a stream that ended never lets a
    /// second chunk of the transfer into the service beside one a blocking call still has in it.
    gates: Mutex<BTreeMap<Key, Weak<tokio::sync::Mutex<()>>>>,
    lookups: Mutex<BTreeMap<ActorId, Weak<Semaphore>>>,
    /// How many frames have begun to wait for a transfer's gate, for a suite to wait for the one it
    /// is holding behind another.
    #[cfg(feature = "testing")]
    gate_waits: tokio::sync::watch::Sender<u64>,
    /// Where a suite holds a frame that has the gate and has not yet asked whether its stream
    /// stands.
    #[cfg(feature = "testing")]
    after_the_gate: Hold,
    /// Where a suite holds an answer that the door has given and the stream has not yet written.
    #[cfg(feature = "testing")]
    after_a_chunk_is_answered: Hold,
}

/// A point a suite can stop one frame of a data stream at: it says the frame has arrived and waits
/// there until the suite lets it go. Armed once, it fires once.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
struct Hold(
    Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
);

#[cfg(feature = "testing")]
impl Hold {
    fn arm(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = tokio::sync::oneshot::channel();
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, going));
        (arrival, go)
    }

    async fn wait(&self) {
        let armed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
}

impl ChunkStreams {
    /// Makes `handle` the stream that serves `transfer` for `principal`, and revokes the stream it
    /// replaces. A revoked stream's reads and writes fail at once; work it already put into the
    /// transfer service is not cancelled, and the gate is what orders the newer behind it.
    ///
    /// A stream that is revoked already replaces nothing and is given no place: a stream the
    /// transport queued before its connection was lost must not revoke the stream the same device
    /// holds on its new connection. The revoked state is read under the registry's lock, and the
    /// transport revokes a lost connection's streams under its own, so a stream seen live here that
    /// is revoked a moment later is revoked by whoever replaces it next as any other is.
    pub(super) fn stand(
        self: &Arc<Self>,
        principal: &ActorId,
        transfer: TransferId,
        handle: &StreamHandle,
    ) -> Option<Arc<Standing>> {
        let key = (principal.clone(), transfer);
        let live = Arc::new(Live {
            handle: handle.clone(),
        });
        let mut registry = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if handle.is_revoked() {
            return None;
        }
        let replaced = registry.insert(key.clone(), Arc::clone(&live));
        drop(registry);
        if let Some(older) = replaced {
            older.handle.revoke();
        }
        Some(Arc::new(Standing {
            registry: Arc::clone(self),
            key,
            live,
        }))
    }

    /// The gate of one transfer: the one a blocking call still holds, or a new one.
    pub(super) fn gate_of(
        &self,
        principal: &ActorId,
        transfer: TransferId,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self
            .gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gates.retain(|_, gate| gate.strong_count() > 0);
        let key = (principal.clone(), transfer);
        if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(key, Arc::downgrade(&gate));
        gate
    }

    /// The places of one principal's lookups: those a lookup still running holds, or new ones.
    pub(super) fn lookups_of(&self, principal: &ActorId) -> Arc<Semaphore> {
        let mut lookups = self
            .lookups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lookups.retain(|_, places| places.strong_count() > 0);
        if let Some(places) = lookups.get(principal).and_then(Weak::upgrade) {
            return places;
        }
        let places = Arc::new(Semaphore::new(LOOKUPS_PER_PRINCIPAL));
        lookups.insert(principal.clone(), Arc::downgrade(&places));
        places
    }
}

#[cfg(feature = "testing")]
impl ChunkStreams {
    pub(super) fn gate_waits(&self) -> tokio::sync::watch::Receiver<u64> {
        self.gate_waits.subscribe()
    }

    pub(super) fn hold_after_the_gate(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_the_gate.arm()
    }

    pub(super) fn hold_after_a_chunk_is_answered(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_a_chunk_is_answered.arm()
    }

    /// Resolves once no chunk of `transfer` is in the transfer service: the gate is free.
    pub(super) async fn until_the_gate_is_free(&self, principal: &ActorId, transfer: TransferId) {
        let gate = self.gate_of(principal, transfer);
        let _free = gate.lock().await;
    }
}

impl ChunkStreams {
    #[cfg(feature = "testing")]
    fn note_a_wait_at_a_gate(&self) {
        self.gate_waits.send_modify(|waits| *waits += 1);
    }

    #[cfg(not(feature = "testing"))]
    #[allow(clippy::unused_self)]
    fn note_a_wait_at_a_gate(&self) {}
}

/// One stream's place in the registry, which it keeps until it is let go and gives back only if it
/// is still the stream that serves its transfer.
#[derive(Debug)]
pub(crate) struct Standing {
    registry: Arc<ChunkStreams>,
    key: Key,
    live: Arc<Live>,
}

impl Standing {
    /// Whether this stream may still put a chunk into the service: it is not revoked, and the
    /// registry still names it as the stream that serves its transfer.
    pub(crate) fn stands(&self) -> bool {
        !self.live.handle.is_revoked()
            && self
                .registry
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&self.key)
                .is_some_and(|serving| Arc::ptr_eq(serving, &self.live))
    }
}

impl Drop for Standing {
    fn drop(&mut self) {
        let mut live = self
            .registry
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if live
            .get(&self.key)
            .is_some_and(|serving| Arc::ptr_eq(serving, &self.live))
        {
            live.remove(&self.key);
        }
    }
}

/// What one chunk carries from its stream to the door and on to the transfer service.
///
/// The transfer's gate is held from before the door is called, and the service takes it into the
/// blocking call it makes ([`Self::take_gate`]), so it is released when that call ends and not when
/// the stream's task does: a task is aborted when its connection ends, and a chunk that is already
/// in the service stays there.
#[derive(Debug)]
pub(crate) struct ChunkAdmission {
    standing: Arc<Standing>,
    gate: Mutex<Option<OwnedMutexGuard<()>>>,
    /// Set when the service refused the chunk's admission, which ends the stream.
    refused: AtomicBool,
}

impl ChunkAdmission {
    fn new(standing: Arc<Standing>, gate: OwnedMutexGuard<()>) -> Arc<Self> {
        Arc::new(Self {
            standing,
            gate: Mutex::new(Some(gate)),
            refused: AtomicBool::new(false),
        })
    }

    /// Whether the stream the chunk arrived on may still put it into the service.
    pub(crate) fn stands(&self) -> bool {
        self.standing.stands()
    }

    /// Hands the gate to the call that is about to take the chunk into the service.
    pub(crate) fn take_gate(&self) -> Option<OwnedMutexGuard<()>> {
        self.gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Notes that the service refused the chunk's admission.
    pub(crate) fn note_refusal(&self) {
        self.refused.store(true, Ordering::Release);
    }

    fn was_refused(&self) -> bool {
        self.refused.load(Ordering::Acquire)
    }
}

/// What the policy decides for one frame of a chunk stream.
#[derive(Debug)]
pub(super) enum Ruling {
    /// The door decides it.
    Serve,
    /// It is refused, and `answer` tells the peer when there is a request to answer. `end` says
    /// whether the stream ends with it.
    Refuse {
        answer: Option<ControlFrame>,
        end: bool,
    },
}

/// Which frames a chunk stream carries.
///
/// A pure function of the frame and the stream's header, applied before the door: the chunk stream
/// carries `upload.chunk` for the transfer its header names and `download.chunk` reads (which the
/// door refuses by name), and every other frame ends the stream.
pub(super) struct StreamPolicy;

impl StreamPolicy {
    pub(super) fn admits(frame: &ControlFrame, header: &StreamHeader) -> Ruling {
        match frame {
            ControlFrame::Mutation(mutation) => {
                let method = mutation.method.method();
                if !carries(StreamKind::AttachmentChunks, method) {
                    return Self::wrong_stream(mutation.request_id);
                }
                if method == Some(Method::UploadChunk) {
                    if names(&mutation.params, header) {
                        Ruling::Serve
                    } else {
                        Self::another_transfer(mutation.request_id)
                    }
                } else {
                    Self::wrong_stream(mutation.request_id)
                }
            }
            ControlFrame::Request(request) => {
                let method = request.method.method();
                if carries(StreamKind::AttachmentChunks, method)
                    && method == Some(Method::DownloadChunk)
                {
                    // Refused by name at the door, and the stream stays: it is not a frame this
                    // stream could not carry.
                    Ruling::Serve
                } else {
                    Self::wrong_stream(request.request_id)
                }
            }
            // A frame that is neither is no frame of this host's to answer: the stream ends and
            // nothing is said on it.
            _ => Ruling::Refuse {
                answer: None,
                end: true,
            },
        }
    }

    fn wrong_stream(request_id: kr_protocol::ids::RequestId) -> Ruling {
        refusal(
            request_id,
            ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                "an attachment-chunk stream carries upload.chunk for the transfer its header \
                 names and nothing else",
            ),
        )
    }

    fn another_transfer(request_id: kr_protocol::ids::RequestId) -> Ruling {
        refusal(
            request_id,
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                "this stream carries the chunks of the transfer its header names, and this chunk \
                 names another",
            ),
        )
    }
}

fn refusal(request_id: kr_protocol::ids::RequestId, error: ProtocolError) -> Ruling {
    Ruling::Refuse {
        answer: Some(ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error),
        })),
        end: true,
    }
}

/// Whether `params` names the transfer the stream's header names. Compared as the encoded
/// identifiers, so a chunk's megabyte is neither decoded nor copied to decide it.
fn names(params: &ParamsValue, header: &StreamHeader) -> bool {
    let Some(transfer) = header.resource.transfer_id.0 else {
        return false;
    };
    let Ok(expected) = kr_cbor::to_canonical_value(&transfer) else {
        return false;
    };
    matches!(
        params.as_value(),
        kr_cbor::CanonicalValue::Map(map) if map.get("transfer_id") == Some(&expected)
    )
}

/// What serves one connection's data streams.
pub(super) struct ChunkDoor {
    pub(super) host: Arc<NetworkHost>,
    pub(super) remote: Arc<RemoteConnection>,
    pub(super) connection: iroh::endpoint::Connection,
    pub(super) device_id: DeviceId,
    pub(super) deadlines: Arc<dyn Deadlines>,
    pub(super) clock: Arc<dyn ContinuousClock>,
}

impl ChunkDoor {
    /// Takes the connection's data streams as the transport hands them over, one task for each,
    /// until the connection ends. The tasks' set is reaped as they end, so a device that opens
    /// streams the host refuses does not grow it for the life of the connection, and ending this
    /// task ends every stream task with it.
    pub(super) async fn serve(self: Arc<Self>, mut streams: DataStreams) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                stream = streams.recv() => match stream {
                    Some(stream) => {
                        tasks.spawn(Arc::clone(&self).serve_stream(stream));
                    }
                    None => break,
                },
            }
        }
    }

    /// Admits one stream, and serves its frames until it ends.
    async fn serve_stream(self: Arc<Self>, stream: DataStream) {
        let (mut reader, writer) = stream.split();
        let handle = reader.handle();
        let header = reader.header().clone();
        let principal = self.remote.principal();
        let Some(transfer) = header.resource.transfer_id.0 else {
            handle.revoke();
            return;
        };
        let admitted = async {
            if header.resource.environment_id != self.remote.environment_id() {
                return None;
            }
            let subject = self.look_up(&principal, transfer).await?;
            if subject.environment_id != header.resource.environment_id {
                return None;
            }
            // The header names the upload's session or none.
            if header
                .resource
                .session_id
                .0
                .is_some_and(|named| Some(named) != subject.session_id)
            {
                return None;
            }
            self.remote.admit_a_chunk_stream(&subject).await.ok()?;
            Some(())
        };
        // The transport's read can return after the revocation, so the stream's own state is asked
        // after each wait: the admission above waited for a place, a blocking lookup and the
        // registry's lock.
        if admitted.await.is_none() || handle.is_revoked() {
            handle.revoke();
            return;
        }
        let Some(standing) = self.host.chunks.stand(&principal, transfer, &handle) else {
            return;
        };
        let gate = self.host.chunks.gate_of(&principal, transfer);
        let output = self.remote.data_output(writer, self.connection.clone());
        loop {
            let frame = match reader.read_message::<ControlFrame>().await {
                Ok(Some(frame)) => frame,
                // The peer ended the stream between frames, or the transport ended it.
                Ok(None) | Err(_) => break,
            };
            // A read that was waiting when the stream was revoked can still return a whole frame.
            if handle.is_revoked() {
                break;
            }
            let hold = self.host.frame_read(&self.device_id, &frame);
            let received = ReceivedFrame::read(frame, self.clock.as_ref(), hold);
            match StreamPolicy::admits(received.frame(), &header) {
                Ruling::Serve => {}
                Ruling::Refuse { answer, end } => {
                    if let Some(answer) = answer {
                        let _ = output.send(&answer).await;
                    }
                    if end {
                        // Ended after the refusal was written, so that the peer reads it: a reset
                        // would discard what had not left yet.
                        return;
                    }
                    continue;
                }
            }
            // The newer stream's first frame waits here for the older's chunk to leave the
            // service, and a stream that is revoked meanwhile leaves.
            self.host.chunks.note_a_wait_at_a_gate();
            let held = tokio::select! {
                held = Arc::clone(&gate).lock_owned() => held,
                () = handle.revoked() => break,
            };
            #[cfg(feature = "testing")]
            self.host.chunks.after_the_gate.wait().await;
            if !standing.stands() {
                break;
            }
            let admission = ChunkAdmission::new(Arc::clone(&standing), held);
            let Some(answered) = self.remote.answer_on_a_stream(received, &admission).await else {
                handle.revoke();
                return;
            };
            #[cfg(feature = "testing")]
            self.host.chunks.after_a_chunk_is_answered.wait().await;
            if !self.remote.write_answer(&output, answered).await {
                handle.revoke();
                return;
            }
            if admission.was_refused() {
                // The service refused the chunk's admission: a fence is owed or the connection's
                // authority has gone. The device has been told, and nothing more is read.
                return;
            }
        }
        handle.revoke();
    }

    /// Looks up the device's upload for a header, under the principal's lookup places and the
    /// admission deadline. A lookup the deadline gave up on goes on and keeps its place until it
    /// ends.
    async fn look_up(
        &self,
        principal: &ActorId,
        transfer: TransferId,
    ) -> Option<kr_transfer::service::StoredSubject> {
        let mut deadline = self.deadlines.start(DeadlineKind::Admission);
        let places = self.host.chunks.lookups_of(principal);
        let place = tokio::select! {
            place = places.acquire_owned() => place.ok()?,
            () = &mut deadline => return None,
        };
        let controller = self.remote.controller();
        let lookup = controller
            .transfer
            .receiving_upload(principal.clone(), transfer, place);
        tokio::select! {
            found = lookup => found.ok(),
            () = &mut deadline => None,
        }
    }
}
