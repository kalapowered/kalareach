//! The rendezvous room's wire contract: the frames a host and a candidate exchange with the room.
//!
//! A short-code invitation reserves a four-character locator at a rendezvous origin, and a
//! candidate reaches the host through that locator's room: the service admits candidates, relays
//! opaque frames between each of them and the host, and never holds pairing authority. Both roles
//! speak the same vocabulary over a WebSocket, as deterministic CBOR:
//!
//! ```text
//!   candidate --room socket--> room <--room socket-- host
//!       |                                               |
//!       |   admit, client_pake, client_confirmation,    |   host_pake, host_confirmation,
//!       |   bundle                                      |   bundle, refused
//!       |                                               |
//!       +-------- pair.finish over iroh (pre-auth) ---->+
//! ```
//!
//! [`ServiceFrame`] is what the room sends and [`ClientFrame`] what it accepts, from either role.
//! Everything a pairing carries inside a relay frame is a [`RendezvousMessage`], which the room
//! reads none of; [`encode_message`] and [`decode_message`] are the relay payload's own codec.

use serde::{Deserialize, Serialize};

use crate::ids::{AttemptId, InvitationId};
use crate::invitation::{MAX_RENDEZVOUS_MESSAGE_LEN, RendezvousMessage};
use crate::scalars::Bytes;

/// The largest opaque payload one room frame carries.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 64 * 1024;

/// The largest a whole encoded room frame may be: the payload and the widest envelope around it.
pub const MAX_FRAME_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES + 64;

/// The largest integer the service's frames carry: the largest a JavaScript number holds exactly.
/// The service refuses a larger one, so its peers do too.
pub const MAX_FRAME_INTEGER: u64 = (1 << 53) - 1;

/// The header a host presents its control token in, as unpadded base64url, when it attaches.
///
/// A candidate presents nothing: the room serves it the record of the locator it asked for, and
/// the control token proves a host's reservation, which a candidate has no part in.
pub const CONTROL_TOKEN_HEADER: &str = "KR-Pair-Control-Token";

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
    use serde::{Deserialize, Serialize};

    use super::CloseReason;
    use crate::ids::{AttemptId, InvitationId};
    use crate::scalars::Bytes;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::{Nonce256, Uuid};

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
}
