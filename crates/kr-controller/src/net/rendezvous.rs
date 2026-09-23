//! The host's side of a short-code invitation's rendezvous room.
//!
//! A code invitation reserves a four-character locator at a rendezvous origin, and a candidate
//! reaches the host through that locator's room: the service admits candidates, relays opaque
//! frames between each of them and the host, and never holds pairing authority. Everything the
//! room carries for a pairing is a [`RendezvousMessage`], and the room reads none of it.
//!
//! ```text
//!   candidate --room socket--> room <--room socket-- this host
//!       |                                               |
//!       |   admit, client_pake, client_confirmation,    |   host_pake, host_confirmation,
//!       |   bundle                                      |   bundle, refused
//!       |                                               |
//!       +-------- pair.finish over iroh (pre-auth) ---->+
//! ```
//!
//! This module holds three things: the room's frame vocabulary, which is the rendezvous service's
//! own wire contract (deterministic CBOR over a WebSocket); the [`Rendezvous`] a host reaches the
//! service through, so a test can put an in-process room where a deployment has the real one; and
//! [`serve_room`], the task that relays one invitation's room to the pairing service for as long
//! as the invitation is on offer. The pairing decisions themselves stay in kr-pairing, behind the
//! invitation's one lock: this module decodes, forwards and sends, and decides nothing.

use std::sync::{Arc, Weak};
use std::time::Duration;

use kr_crypto::secret::SymmetricKey;
use kr_pairing::platform::RendezvousHost;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::invitation::{MAX_RENDEZVOUS_MESSAGE_LEN, RendezvousMessage};
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::scalars::Bytes;
use kr_transport::listener::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use super::pairing::PairingHost;

/// The largest opaque payload one room frame carries.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 64 * 1024;

/// The largest a whole encoded room frame may be: the payload and the widest envelope around it.
pub const MAX_FRAME_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES + 64;

/// The largest integer the service's frames carry: the largest a JavaScript number holds exactly.
/// The service refuses a larger one, so the host does too.
pub const MAX_FRAME_INTEGER: u64 = (1 << 53) - 1;

/// The header a host presents its control token in, as unpadded base64url, when it attaches.
pub const CONTROL_TOKEN_HEADER: &str = "KR-Pair-Control-Token";

/// How long the host waits before attaching to its room again after the socket ended.
pub const REATTACH_DELAY: Duration = Duration::from_secs(1);

/// Why the room ended a socket or an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// A candidate socket reached its ten-second deadline.
    Deadline,
    /// The record's advertised expiry passed.
    Expired,
    /// The host closed the attempt, or released the record.
    Cancelled,
    /// Another socket took this role's slot.
    Superseded,
    /// A frame was not a frame of this vocabulary.
    Invalid,
    /// A frame carried more than [`MAX_FRAME_PAYLOAD_BYTES`].
    Oversize,
    /// An attempt relayed more than the service allows in total.
    Exhausted,
    /// No host was attached to carry the frame.
    HostGone,
}

/// A frame the room sends.
///
/// On the wire a frame is a map naming its `type` beside that type's members, which is how it
/// serialises. It decodes through [`decode_service_frame`], which reads the type first and then
/// exactly that type's members.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServiceFrame {
    /// The rendezvous record, which a candidate receives first. Untrusted until the PAKE confirms
    /// it.
    Record {
        /// The invitation the record names.
        invitation_id: InvitationId,
        /// The advertised expiry, in UTC milliseconds.
        expires_at_ms: u64,
    },
    /// The host's control token was accepted and the host slot is its own.
    Attached {
        /// The invitation the record names.
        invitation_id: InvitationId,
        /// The expiry the service holds, after clamping.
        expires_at_ms: u64,
    },
    /// A candidate declared an attempt.
    AttemptOpened {
        /// The candidate's attempt.
        attempt_id: AttemptId,
    },
    /// One attempt ended while the host socket stays open.
    AttemptClosed {
        /// The attempt.
        attempt_id: AttemptId,
        /// Why.
        reason: CloseReason,
    },
    /// One opaque frame of an attempt.
    Relay {
        /// The attempt it belongs to.
        attempt_id: AttemptId,
        /// The bytes, unread by the service.
        payload: Bytes,
    },
    /// The last frame on a socket the service is about to close.
    Closed {
        /// Why.
        reason: CloseReason,
    },
}

/// A frame the room accepts. It decodes through [`decode_client_frame`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// A candidate declares the attempt it is about to run.
    Attempt {
        /// The candidate's own attempt identity.
        attempt_id: AttemptId,
    },
    /// One opaque frame of an attempt.
    Relay {
        /// The attempt it belongs to.
        attempt_id: AttemptId,
        /// The bytes.
        payload: Bytes,
    },
    /// The host ends one candidate's attempt.
    CloseAttempt {
        /// The attempt.
        attempt_id: AttemptId,
    },
}

/// Encodes a frame as deterministic CBOR.
///
/// # Errors
///
/// Returns a reason when the frame cannot be encoded or is larger than one frame may be.
pub fn encode_frame<F: Serialize>(frame: &F) -> Result<Vec<u8>, String> {
    let bytes = kr_cbor::to_canonical_vec(frame).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "a room frame is at most {MAX_FRAME_BYTES} bytes, and this one is {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// The members of each frame type, read once the type is known.
///
/// A frame is decoded in two steps, the type and then that type's own members, rather than by
/// serde's internally tagged enums: those buffer the members first and lose the binary format's
/// representation of an identifier on the way.
mod wire {
    use kr_protocol::ids::{AttemptId, InvitationId};
    use kr_protocol::scalars::Bytes;
    use serde::{Deserialize, Serialize};

    use super::CloseReason;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Invitation {
        #[serde(rename = "type")]
        pub kind: String,
        pub invitation_id: InvitationId,
        pub expires_at_ms: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Attempt {
        #[serde(rename = "type")]
        pub kind: String,
        pub attempt_id: AttemptId,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AttemptClosed {
        #[serde(rename = "type")]
        pub kind: String,
        pub attempt_id: AttemptId,
        pub reason: CloseReason,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Relay {
        #[serde(rename = "type")]
        pub kind: String,
        pub attempt_id: AttemptId,
        pub payload: Bytes,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Closed {
        #[serde(rename = "type")]
        pub kind: String,
        pub reason: CloseReason,
    }
}

/// Reads a frame's type, refusing one longer than a frame may be before anything else is read.
fn frame_type(bytes: &[u8]) -> Result<(kr_cbor::CanonicalValue, String), String> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "a room frame is at most {MAX_FRAME_BYTES} bytes, and this one is {}",
            bytes.len()
        ));
    }
    let limits = kr_cbor::Limits {
        max_message_len: MAX_FRAME_BYTES,
        ..kr_cbor::Limits::DEFAULT
    };
    let value = kr_cbor::decode(bytes, &limits).map_err(|error| error.to_string())?;
    let kind = value
        .as_map()
        .and_then(|map| map.get("type"))
        .and_then(kr_cbor::CanonicalValue::as_text)
        .ok_or("a room frame is a map naming its type")?
        .to_owned();
    Ok((value, kind))
}

fn members<T: serde::de::DeserializeOwned + Serialize>(
    value: &kr_cbor::CanonicalValue,
) -> Result<T, String> {
    kr_cbor::from_canonical_value(value).map_err(|error| error.to_string())
}

/// Decodes a frame the room sends.
///
/// # Errors
///
/// Returns a reason when the bytes are not a canonical frame of the room's vocabulary with
/// exactly its type's members.
pub fn decode_service_frame(bytes: &[u8]) -> Result<ServiceFrame, String> {
    let (value, kind) = frame_type(bytes)?;
    let invitation = || {
        members::<wire::Invitation>(&value).and_then(|frame| {
            if frame.expires_at_ms > MAX_FRAME_INTEGER {
                return Err(format!(
                    "an expiry is at most {MAX_FRAME_INTEGER}, the largest integer the room carries"
                ));
            }
            Ok(frame)
        })
    };
    match kind.as_str() {
        "record" => invitation().map(|frame| ServiceFrame::Record {
            invitation_id: frame.invitation_id,
            expires_at_ms: frame.expires_at_ms,
        }),
        "attached" => invitation().map(|frame| ServiceFrame::Attached {
            invitation_id: frame.invitation_id,
            expires_at_ms: frame.expires_at_ms,
        }),
        "attempt_opened" => {
            members::<wire::Attempt>(&value).map(|frame| ServiceFrame::AttemptOpened {
                attempt_id: frame.attempt_id,
            })
        }
        "attempt_closed" => {
            members::<wire::AttemptClosed>(&value).map(|frame| ServiceFrame::AttemptClosed {
                attempt_id: frame.attempt_id,
                reason: frame.reason,
            })
        }
        "relay" => members::<wire::Relay>(&value).map(|frame| ServiceFrame::Relay {
            attempt_id: frame.attempt_id,
            payload: frame.payload,
        }),
        "closed" => members::<wire::Closed>(&value).map(|frame| ServiceFrame::Closed {
            reason: frame.reason,
        }),
        other => Err(format!("{other:?} is not a frame the room sends")),
    }
}

/// Decodes a frame the room accepts.
///
/// # Errors
///
/// Returns a reason when the bytes are not a canonical frame of the room's vocabulary with
/// exactly its type's members.
pub fn decode_client_frame(bytes: &[u8]) -> Result<ClientFrame, String> {
    let (value, kind) = frame_type(bytes)?;
    match kind.as_str() {
        "attempt" => members::<wire::Attempt>(&value).map(|frame| ClientFrame::Attempt {
            attempt_id: frame.attempt_id,
        }),
        "relay" => members::<wire::Relay>(&value).map(|frame| ClientFrame::Relay {
            attempt_id: frame.attempt_id,
            payload: frame.payload,
        }),
        "close_attempt" => {
            members::<wire::Attempt>(&value).map(|frame| ClientFrame::CloseAttempt {
                attempt_id: frame.attempt_id,
            })
        }
        other => Err(format!("{other:?} is not a frame the room accepts")),
    }
}

/// Encodes one pairing message as the payload of a relay frame.
///
/// # Errors
///
/// Returns a reason when the message cannot be encoded or is larger than a payload may be.
pub fn encode_message(message: &RendezvousMessage) -> Result<Bytes, String> {
    let bytes = kr_cbor::to_canonical_vec(message).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RENDEZVOUS_MESSAGE_LEN {
        return Err(format!(
            "a pairing message is at most {MAX_RENDEZVOUS_MESSAGE_LEN} bytes"
        ));
    }
    Ok(Bytes::new(bytes))
}

/// Decodes the payload of a relay frame as one pairing message, bounded before it is read.
///
/// # Errors
///
/// Returns a reason when the payload is not one canonical pairing message.
pub fn decode_message(payload: &[u8]) -> Result<RendezvousMessage, String> {
    if payload.len() > MAX_RENDEZVOUS_MESSAGE_LEN {
        return Err(format!(
            "a pairing message is at most {MAX_RENDEZVOUS_MESSAGE_LEN} bytes"
        ));
    }
    let limits = kr_cbor::Limits {
        max_message_len: MAX_RENDEZVOUS_MESSAGE_LEN,
        ..kr_cbor::Limits::DEFAULT
    };
    kr_cbor::from_canonical_slice(payload, &limits).map_err(|error| error.to_string())
}

/// One socket attached to a room, as frames in each direction.
///
/// Whoever opened the socket pumps it: an outgoing frame is sent on it, and every frame that
/// arrives is handed over here. `incoming` ends when the socket does.
#[derive(Debug)]
pub struct RoomSocket {
    /// Frames to send to the room.
    pub outgoing: mpsc::Sender<ClientFrame>,
    /// Frames the room sent.
    pub incoming: mpsc::Receiver<ServiceFrame>,
}

/// A rendezvous service, as a host reaches it.
///
/// The control requests are kr-pairing's [`RendezvousHost`]: a reservation and a release, which
/// the invitation's own state machine makes. Attaching to the room is the host's, because it is a
/// socket the host keeps open for as long as the invitation is on offer.
pub trait Rendezvous: RendezvousHost + Send + Sync {
    /// Opens the host's socket in the room of `locator` at `origin`, proving possession of the
    /// reservation's control token.
    fn attach(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>>;
}

/// What the room relay asks of the pairing service, one invitation at a time.
///
/// The pairing service answers each of these under the invitation's one lock, so a relay never
/// decides anything itself; the trait is what lets the relay's own lifecycle be exercised against
/// a host a test controls.
pub trait RoomHost: Send + Sync + 'static {
    /// Takes one message a candidate sent through the room and returns the frames to send back.
    fn room_step(
        &self,
        invitation_id: InvitationId,
        attempt_id: AttemptId,
        message: RendezvousMessage,
    ) -> Vec<ClientFrame>;

    /// Ends one candidate's attempt, charging no guess.
    fn room_abort(&self, invitation_id: InvitationId, attempt_id: AttemptId);

    /// Returns true while the invitation is on offer, consuming it first if its deadline has
    /// passed.
    fn room_is_open(&self, invitation_id: InvitationId) -> bool;
}

impl RoomHost for PairingHost {
    fn room_step(
        &self,
        invitation_id: InvitationId,
        attempt_id: AttemptId,
        message: RendezvousMessage,
    ) -> Vec<ClientFrame> {
        Self::room_step(self, invitation_id, attempt_id, message)
    }

    fn room_abort(&self, invitation_id: InvitationId, attempt_id: AttemptId) {
        Self::room_abort(self, invitation_id, attempt_id);
    }

    fn room_is_open(&self, invitation_id: InvitationId) -> bool {
        Self::room_is_open(self, invitation_id)
    }
}

/// Where one code invitation's room is, the token that proves the host holds it, and how long the
/// invitation has left.
#[derive(Clone)]
pub struct RoomTicket {
    /// The invitation the room serves.
    pub invitation_id: InvitationId,
    /// The origin the locator is reserved at.
    pub origin: RendezvousOrigin,
    /// The locator.
    pub locator: Locator,
    /// The reservation's control token.
    pub control_token: SymmetricKey,
    /// How long the invitation had left on the host's own clock when the relay started. The
    /// relay asks the host again when it runs out, so an idle room does not outlive its
    /// invitation.
    pub lifetime: Duration,
}

impl std::fmt::Debug for RoomTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoomTicket")
            .field("invitation_id", &self.invitation_id)
            .field("origin", &self.origin)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

/// How long the relay waits for the room to confirm it closed the attempts of an invitation that
/// ended, before it releases the locator anyway.
///
/// The room acknowledges a closed attempt with `attempt_closed` on the same socket, after every
/// frame the host sent before it. Releasing only then keeps the release from overtaking the last
/// answer a candidate is owed: the release is a separate request, and nothing orders it against
/// the socket otherwise.
pub const CLOSE_ACKNOWLEDGEMENT: Duration = Duration::from_secs(5);

/// How one attachment to the room ended.
enum Attachment {
    /// The owner ended the invitation and releases its locator, or the room says the record has
    /// expired or has another host: nothing to attach to again, and nothing to release here.
    Finished,
    /// The invitation ended by itself, its guesses spent or its deadline passed, or the pairing
    /// service let it go: nothing to attach to again, and its locator is released here.
    Over,
    /// The socket ended while the invitation is still on offer.
    Dropped,
}

/// What ended a wait of the relay's.
enum Interrupted {
    /// The owner ended the invitation.
    Stopped,
    /// The pairing service dropped the invitation without ending it: the daemon is going.
    Abandoned,
    /// The invitation's deadline passed on this host's clock.
    Deadline,
}

/// Relays one code invitation's room to the pairing service until the invitation ends.
///
/// The host attaches with its control token, and attaches again when the socket ends while the
/// invitation is still on offer: the room keeps candidates that arrive meanwhile and tells the
/// host about them when it is back. Every wait also watches two things of the host's own: the
/// owner ending the invitation through `stop`, and the invitation's deadline, when the host is
/// asked whether it is still on offer, so an idle room ends with its invitation. An invitation
/// that ended by itself, or that the pairing service let go without ending, has its locator
/// released here; one the owner ended is released by the owner's own call.
pub async fn serve_room<H: RoomHost>(
    host: Weak<H>,
    service: Arc<dyn Rendezvous>,
    ticket: RoomTicket,
    mut stop: watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + ticket.lifetime;
    loop {
        if *stop.borrow() {
            return;
        }
        if !offered(&host, ticket.invitation_id).await {
            release(&service, &ticket).await;
            return;
        }
        let attached = tokio::select! {
            attached = service.attach(&ticket.origin, &ticket.locator, &ticket.control_token) => attached,
            interrupted = interruption(&mut stop, Some(deadline)) => {
                match interrupted {
                    Interrupted::Stopped => return,
                    Interrupted::Abandoned => {
                        release(&service, &ticket).await;
                        return;
                    }
                    Interrupted::Deadline => continue,
                }
            }
        };
        let ended = match attached {
            Ok(socket) => relay(&host, &ticket, socket, &mut stop, deadline).await,
            Err(_) => Attachment::Dropped,
        };
        match ended {
            Attachment::Finished => return,
            Attachment::Over => {
                release(&service, &ticket).await;
                return;
            }
            Attachment::Dropped => {
                tokio::select! {
                    () = tokio::time::sleep(REATTACH_DELAY) => {}
                    interrupted = interruption(&mut stop, Some(deadline)) => {
                        match interrupted {
                            Interrupted::Stopped => return,
                            Interrupted::Abandoned => {
                                release(&service, &ticket).await;
                                return;
                            }
                            Interrupted::Deadline => {}
                        }
                    }
                }
            }
        }
    }
}

/// Waits for the owner to end the invitation, the pairing service to let it go, or `deadline`
/// when there is one.
///
/// A deadline that has already passed is reported at once, so a caller that asks again after it
/// has passed gets its answer from the host rather than waiting for ever.
async fn interruption(
    stop: &mut watch::Receiver<bool>,
    deadline: Option<tokio::time::Instant>,
) -> Interrupted {
    let deadline = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        changed = stop.changed() => match changed {
            Ok(()) => Interrupted::Stopped,
            Err(_) => Interrupted::Abandoned,
        },
        () = deadline => Interrupted::Deadline,
    }
}

/// Relays one attachment's frames until it ends.
async fn relay<H: RoomHost>(
    host: &Weak<H>,
    ticket: &RoomTicket,
    mut socket: RoomSocket,
    stop: &mut watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Attachment {
    let invitation_id = ticket.invitation_id;
    let mut deadline = Some(deadline);
    loop {
        let frame = tokio::select! {
            frame = socket.incoming.recv() => frame,
            interrupted = interruption(stop, deadline) => {
                match interrupted {
                    Interrupted::Stopped => return Attachment::Finished,
                    Interrupted::Abandoned => return Attachment::Over,
                    Interrupted::Deadline => {
                        // Asked once: the host consumes the invitation if it is due, and an
                        // invitation still on offer is served on until the owner or the room
                        // ends it.
                        deadline = None;
                        if offered(host, invitation_id).await {
                            continue;
                        }
                        return Attachment::Over;
                    }
                }
            }
        };
        let Some(frame) = frame else {
            return Attachment::Dropped;
        };
        let replies = match frame {
            ServiceFrame::Relay {
                attempt_id,
                payload,
            } => match decode_message(payload.as_slice()) {
                Ok(message) => match step(host, invitation_id, attempt_id, message).await {
                    Some(replies) => replies,
                    None => return Attachment::Over,
                },
                // A payload that is not one pairing message ends that attempt, and costs the
                // invitation nothing: no confirmation result was produced. It ends here, under
                // the invitation's lock, before anything queued behind it is read; the close
                // frame only tells the room.
                Err(_) => {
                    if !abort(host, invitation_id, attempt_id).await {
                        return Attachment::Over;
                    }
                    vec![ClientFrame::CloseAttempt { attempt_id }]
                }
            },
            ServiceFrame::AttemptClosed { attempt_id, .. } => {
                if !abort(host, invitation_id, attempt_id).await {
                    return Attachment::Over;
                }
                Vec::new()
            }
            ServiceFrame::Closed { reason } => {
                return match reason {
                    CloseReason::Expired | CloseReason::Cancelled | CloseReason::Superseded => {
                        Attachment::Finished
                    }
                    _ => Attachment::Dropped,
                };
            }
            // The attachment's confirmation, a candidate declaring an attempt before it sends
            // anything, and a candidate's own record: nothing to decide until a message arrives.
            ServiceFrame::Attached { .. }
            | ServiceFrame::AttemptOpened { .. }
            | ServiceFrame::Record { .. } => Vec::new(),
        };
        let closed: Vec<AttemptId> = replies
            .iter()
            .filter_map(|reply| match reply {
                ClientFrame::CloseAttempt { attempt_id } => Some(*attempt_id),
                _ => None,
            })
            .collect();
        for reply in replies {
            tokio::select! {
                sent = socket.outgoing.send(reply) => {
                    if sent.is_err() {
                        return Attachment::Dropped;
                    }
                }
                changed = stop.changed() => {
                    return match changed {
                        Ok(()) => Attachment::Finished,
                        Err(_) => Attachment::Over,
                    };
                }
            }
        }
        if !offered(host, invitation_id).await {
            // The last answers are on their way. The room confirms each attempt it closed after
            // the frames before it, and only then is the locator released.
            acknowledged(&mut socket, closed).await;
            return Attachment::Over;
        }
    }
}

/// Waits, for at most [`CLOSE_ACKNOWLEDGEMENT`], until the room has confirmed closing every one
/// of `closed`, or the socket ends.
async fn acknowledged(socket: &mut RoomSocket, mut closed: Vec<AttemptId>) {
    let waited = tokio::time::timeout(CLOSE_ACKNOWLEDGEMENT, async {
        while !closed.is_empty() {
            match socket.incoming.recv().await {
                Some(ServiceFrame::AttemptClosed { attempt_id, .. }) => {
                    closed.retain(|waiting| *waiting != attempt_id);
                }
                Some(ServiceFrame::Closed { .. }) | None => return,
                Some(_) => {}
            }
        }
    })
    .await;
    let _ = waited;
}

/// Runs one room step on a blocking thread: it takes the invitation's lock, which a durable write
/// may be holding. `None` means the pairing service is gone.
async fn step<H: RoomHost>(
    host: &Weak<H>,
    invitation_id: InvitationId,
    attempt_id: AttemptId,
    message: RendezvousMessage,
) -> Option<Vec<ClientFrame>> {
    let pairing = host.upgrade()?;
    Some(
        tokio::task::spawn_blocking(move || pairing.room_step(invitation_id, attempt_id, message))
            .await
            .unwrap_or_else(|_| vec![ClientFrame::CloseAttempt { attempt_id }]),
    )
}

/// Ends one attempt under the invitation's lock. False means the pairing service is gone.
async fn abort<H: RoomHost>(
    host: &Weak<H>,
    invitation_id: InvitationId,
    attempt_id: AttemptId,
) -> bool {
    let Some(pairing) = host.upgrade() else {
        return false;
    };
    let _ =
        tokio::task::spawn_blocking(move || pairing.room_abort(invitation_id, attempt_id)).await;
    true
}

/// Asks the pairing service whether the invitation is still on offer, off the runtime's threads:
/// the answer takes the invitation's lock, which a durable write may be holding.
async fn offered<H: RoomHost>(host: &Weak<H>, invitation_id: InvitationId) -> bool {
    let host = host.clone();
    tokio::task::spawn_blocking(move || {
        host.upgrade()
            .is_some_and(|pairing| pairing.room_is_open(invitation_id))
    })
    .await
    .unwrap_or(false)
}

/// Releases the room's locator, so a code that can no longer pair stops reaching the host.
///
/// Best effort: a record that is not released expires by itself within the invitation's five
/// minutes.
async fn release(service: &Arc<dyn Rendezvous>, ticket: &RoomTicket) {
    let service = Arc::clone(service);
    let ticket = ticket.clone();
    let _ = tokio::task::spawn_blocking(move || {
        service.release_locator(&ticket.origin, &ticket.locator, &ticket.control_token)
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::{Nonce256, Uuid};

    /// The frames are the rendezvous service's own wire: a CBOR map whose members are exactly the
    /// ones the service names, identifiers as sixteen-byte strings and the payload unaltered.
    #[test]
    fn a_frame_is_the_map_the_service_reads() {
        let attempt_id = AttemptId::new(Uuid::from_bytes([7; 16]));
        let frame = ClientFrame::Relay {
            attempt_id,
            payload: Bytes::new(vec![1, 2, 3]),
        };
        let bytes = encode_frame(&frame).expect("encodes");
        let mut expected = vec![0xa3];
        expected.extend_from_slice(&[0x64, b't', b'y', b'p', b'e']);
        expected.extend_from_slice(&[0x65, b'r', b'e', b'l', b'a', b'y']);
        expected.extend_from_slice(&[0x67]);
        expected.extend_from_slice(b"payload");
        expected.extend_from_slice(&[0x43, 1, 2, 3]);
        expected.extend_from_slice(&[0x6a]);
        expected.extend_from_slice(b"attempt_id");
        expected.push(0x50);
        expected.extend_from_slice(&[7; 16]);
        assert_eq!(bytes, expected);
        assert_eq!(decode_client_frame(&bytes).expect("decodes"), frame);
        assert!(
            decode_service_frame(&bytes).is_ok(),
            "a relay frame reads the same in both directions"
        );

        let invitation_id = InvitationId::new(Uuid::from_bytes([9; 16]));
        for sent in [
            ServiceFrame::Record {
                invitation_id,
                expires_at_ms: 1_764_003_600_000,
            },
            ServiceFrame::Attached {
                invitation_id,
                expires_at_ms: 1_764_003_600_000,
            },
            ServiceFrame::AttemptOpened { attempt_id },
            ServiceFrame::AttemptClosed {
                attempt_id,
                reason: CloseReason::HostGone,
            },
            ServiceFrame::Closed {
                reason: CloseReason::Deadline,
            },
        ] {
            let bytes = encode_frame(&sent).expect("encodes");
            assert_eq!(decode_service_frame(&bytes).expect("decodes"), sent);
        }
        for accepted in [
            ClientFrame::Attempt { attempt_id },
            ClientFrame::CloseAttempt { attempt_id },
        ] {
            let bytes = encode_frame(&accepted).expect("encodes");
            assert_eq!(decode_client_frame(&bytes).expect("decodes"), accepted);
            assert!(
                decode_service_frame(&bytes).is_err(),
                "the service never sends a client's frame"
            );
        }
        assert!(
            decode_service_frame(&vec![0; MAX_FRAME_BYTES + 1]).is_err(),
            "measured before it is read"
        );
        // The largest integer the service's own decoder holds exactly is the largest accepted.
        let at_the_edge = encode_frame(&ServiceFrame::Record {
            invitation_id,
            expires_at_ms: MAX_FRAME_INTEGER,
        })
        .expect("encodes");
        assert!(decode_service_frame(&at_the_edge).is_ok());
        let past_the_edge = encode_frame(&ServiceFrame::Attached {
            invitation_id,
            expires_at_ms: MAX_FRAME_INTEGER + 1,
        })
        .expect("encodes");
        assert!(decode_service_frame(&past_the_edge).is_err());
        let extra = kr_cbor::encode(&kr_cbor::CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries([
                ("type".to_owned(), kr_cbor::CanonicalValue::text("attempt")),
                (
                    "attempt_id".to_owned(),
                    kr_cbor::CanonicalValue::Bytes(vec![7; 16]),
                ),
                (
                    "x".to_owned(),
                    kr_cbor::CanonicalValue::integer(1).expect("an integer"),
                ),
            ])
            .expect("a canonical map"),
        ));
        assert!(
            decode_client_frame(&extra).is_err(),
            "a member the type does not name is refused"
        );
    }

    /// A relay payload is one pairing message, bounded before it is decoded.
    #[test]
    fn a_payload_is_one_bounded_pairing_message() {
        let message = RendezvousMessage::Admit {
            client_nonce: Nonce256::from_bytes([3; 32]),
        };
        let payload = encode_message(&message).expect("encodes");
        assert_eq!(
            decode_message(payload.as_slice()).expect("decodes"),
            message
        );
        assert!(decode_message(&vec![0; MAX_RENDEZVOUS_MESSAGE_LEN + 1]).is_err());
        assert!(
            decode_message(&[0xa0]).is_err(),
            "an empty map is no message"
        );
    }

    /// A host a relay test controls: on offer until its lifetime has passed, answering every
    /// step with the same frames.
    struct TestHost {
        opened: std::time::Instant,
        lifetime: Duration,
        replies: Vec<ClientFrame>,
    }

    impl RoomHost for TestHost {
        fn room_step(
            &self,
            _invitation_id: InvitationId,
            _attempt_id: AttemptId,
            _message: RendezvousMessage,
        ) -> Vec<ClientFrame> {
            self.replies.clone()
        }

        fn room_abort(&self, _invitation_id: InvitationId, _attempt_id: AttemptId) {}

        fn room_is_open(&self, _invitation_id: InvitationId) -> bool {
            self.opened.elapsed() < self.lifetime
        }
    }

    /// A service whose room sockets the test holds the far ends of.
    struct TestService {
        capacity: usize,
        released: std::sync::Mutex<u32>,
        rooms: std::sync::Mutex<Vec<(mpsc::Sender<ServiceFrame>, mpsc::Receiver<ClientFrame>)>>,
    }

    impl TestService {
        fn new(capacity: usize) -> Arc<Self> {
            Arc::new(Self {
                capacity,
                released: std::sync::Mutex::new(0),
                rooms: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn released(&self) -> u32 {
            *self.released.lock().expect("the count")
        }

        fn room(&self) -> Option<mpsc::Sender<ServiceFrame>> {
            self.rooms
                .lock()
                .expect("the rooms")
                .last()
                .map(|(sender, _)| sender.clone())
        }
    }

    impl RendezvousHost for TestService {
        fn reserve_locator(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _invitation_id: InvitationId,
            _advertised_expires_at_ms: kr_protocol::scalars::TimestampMs,
            _control_token_hash: kr_protocol::scalars::Digest256,
        ) -> kr_pairing::Result<bool> {
            Ok(true)
        }

        fn release_locator(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _control_token: &SymmetricKey,
        ) -> kr_pairing::Result<()> {
            *self.released.lock().expect("the count") += 1;
            Ok(())
        }
    }

    impl Rendezvous for TestService {
        fn attach(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _control_token: &SymmetricKey,
        ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>> {
            let (to_host, incoming) = mpsc::channel(self.capacity);
            let (outgoing, from_host) = mpsc::channel(self.capacity);
            self.rooms
                .lock()
                .expect("the rooms")
                .push((to_host, from_host));
            Box::pin(async move { Ok(RoomSocket { outgoing, incoming }) })
        }
    }

    fn ticket(lifetime: Duration) -> RoomTicket {
        RoomTicket {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            origin: RendezvousOrigin::new("https://rendezvous.example").expect("an origin"),
            locator: Locator::new("abcd").expect("a locator"),
            control_token: SymmetricKey::random().expect("a token"),
            lifetime,
        }
    }

    const WATCHDOG: Duration = Duration::from_secs(10);

    /// KR-REQ-10.33: an idle room ends with its invitation. Nothing arrives on the socket, the
    /// invitation's deadline passes on the host's clock, the host is asked and says it is over,
    /// and the relay releases the locator itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_room_ends_with_its_invitation() {
        let lifetime = Duration::from_millis(200);
        let host = Arc::new(TestHost {
            opened: std::time::Instant::now(),
            lifetime,
            replies: Vec::new(),
        });
        let service = TestService::new(8);
        let (_stop, stopped) = watch::channel(false);
        tokio::time::timeout(
            WATCHDOG,
            serve_room(
                Arc::downgrade(&host),
                Arc::clone(&service) as Arc<dyn Rendezvous>,
                ticket(lifetime),
                stopped,
            ),
        )
        .await
        .expect("the relay ends with its invitation");
        assert_eq!(service.released(), 1);
    }

    /// A relay that is waiting on a socket nobody reads still ends when the owner ends the
    /// invitation, and leaves the release to the owner's own call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_blocked_on_its_socket_still_stops() {
        let attempt_id = AttemptId::new(Uuid::from_bytes([2; 16]));
        let host = Arc::new(TestHost {
            opened: std::time::Instant::now(),
            lifetime: Duration::from_secs(300),
            replies: vec![ClientFrame::CloseAttempt { attempt_id }; 8],
        });
        let service = TestService::new(1);
        let (stop, stopped) = watch::channel(false);
        let relay = tokio::spawn(serve_room(
            Arc::downgrade(&host),
            Arc::clone(&service) as Arc<dyn Rendezvous>,
            ticket(Duration::from_secs(300)),
            stopped,
        ));
        let room = tokio::time::timeout(WATCHDOG, async {
            loop {
                if let Some(room) = service.room() {
                    break room;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the relay attaches");
        let payload = encode_message(&RendezvousMessage::Admit {
            client_nonce: Nonce256::from_bytes([3; 32]),
        })
        .expect("a message");
        room.send(ServiceFrame::Relay {
            attempt_id,
            payload,
        })
        .await
        .expect("the relay reads");
        // The first reply fills the socket and the second waits on it, which nobody reads.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!relay.is_finished(), "waiting on the socket");
        stop.send(true).expect("the relay listens");
        tokio::time::timeout(WATCHDOG, relay)
            .await
            .expect("the relay stops")
            .expect("it ended cleanly");
        assert_eq!(service.released(), 0, "the owner's own call releases it");
    }

    /// A relay whose invitation the pairing service let go without ending it, as a daemon that is
    /// going does, releases the locator it still holds the token for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_room_the_host_let_go_is_released() {
        let host = Arc::new(TestHost {
            opened: std::time::Instant::now(),
            lifetime: Duration::from_secs(300),
            replies: Vec::new(),
        });
        let service = TestService::new(8);
        let (stop, stopped) = watch::channel(false);
        let relay = tokio::spawn(serve_room(
            Arc::downgrade(&host),
            Arc::clone(&service) as Arc<dyn Rendezvous>,
            ticket(Duration::from_secs(300)),
            stopped,
        ));
        tokio::time::timeout(WATCHDOG, async {
            while service.room().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the relay attaches");
        drop(stop);
        tokio::time::timeout(WATCHDOG, relay)
            .await
            .expect("the relay ends")
            .expect("it ended cleanly");
        assert_eq!(service.released(), 1);
    }
}
