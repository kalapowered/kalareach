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
    match kind.as_str() {
        "record" => members::<wire::Invitation>(&value).map(|frame| ServiceFrame::Record {
            invitation_id: frame.invitation_id,
            expires_at_ms: frame.expires_at_ms,
        }),
        "attached" => members::<wire::Invitation>(&value).map(|frame| ServiceFrame::Attached {
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

/// Where one code invitation's room is, and the token that proves the host holds it.
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
}

impl std::fmt::Debug for RoomTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoomTicket")
            .field("invitation_id", &self.invitation_id)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// How one attachment to the room ended.
enum Attachment {
    /// The owner ended the invitation, which releases its locator, or the room says the record
    /// has expired or has another host: nothing to attach to again.
    Finished,
    /// The invitation ended by itself, its guesses spent or its deadline passed: nothing to
    /// attach to again, and its locator is released here.
    Over,
    /// The socket ended while the invitation is still on offer.
    Dropped,
}

/// Relays one code invitation's room to the pairing service until the invitation ends.
///
/// The host attaches with its control token, and attaches again when the socket ends while the
/// invitation is still on offer: the room keeps candidates that arrive meanwhile and tells the
/// host about them when it is back. `stop` ends it at once; so does the pairing service being
/// gone, and the room saying the record expired, was released or has another host.
pub async fn serve_room(
    host: Weak<PairingHost>,
    service: Arc<dyn Rendezvous>,
    ticket: RoomTicket,
    mut stop: watch::Receiver<bool>,
) {
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
            _ = stop.changed() => return,
        };
        let ended = match attached {
            Ok(socket) => relay(&host, &ticket, socket, &mut stop).await,
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
                    _ = stop.changed() => return,
                }
            }
        }
    }
}

/// Relays one attachment's frames until it ends.
async fn relay(
    host: &Weak<PairingHost>,
    ticket: &RoomTicket,
    mut socket: RoomSocket,
    stop: &mut watch::Receiver<bool>,
) -> Attachment {
    let invitation_id = ticket.invitation_id;
    loop {
        let frame = tokio::select! {
            frame = socket.incoming.recv() => frame,
            _ = stop.changed() => return Attachment::Finished,
        };
        let Some(frame) = frame else {
            return Attachment::Dropped;
        };
        let replies = match frame {
            ServiceFrame::Relay {
                attempt_id,
                payload,
            } => {
                let Some(pairing) = host.upgrade() else {
                    return Attachment::Finished;
                };
                // A payload that is not one pairing message ends that attempt, and costs the
                // invitation nothing: no confirmation result was produced.
                match decode_message(payload.as_slice()) {
                    Ok(message) => tokio::task::spawn_blocking(move || {
                        pairing.room_step(invitation_id, attempt_id, message)
                    })
                    .await
                    .unwrap_or_else(|_| vec![ClientFrame::CloseAttempt { attempt_id }]),
                    Err(_) => vec![ClientFrame::CloseAttempt { attempt_id }],
                }
            }
            ServiceFrame::AttemptClosed { attempt_id, .. } => {
                let Some(pairing) = host.upgrade() else {
                    return Attachment::Finished;
                };
                let _ = tokio::task::spawn_blocking(move || {
                    pairing.room_abort(invitation_id, attempt_id);
                })
                .await;
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
        for reply in replies {
            if socket.outgoing.send(reply).await.is_err() {
                return Attachment::Dropped;
            }
        }
        if !offered(host, invitation_id).await {
            return Attachment::Over;
        }
    }
}

/// Asks the pairing service whether the invitation is still on offer, off the runtime's threads:
/// the answer takes the invitation's lock, which a durable write may be holding.
async fn offered(host: &Weak<PairingHost>, invitation_id: InvitationId) -> bool {
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
}
