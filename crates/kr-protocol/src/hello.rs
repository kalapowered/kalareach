//! `hello` negotiation and the `kr-connect/1` proof transcript.
//!
//! The first bidirectional stream performs `hello` and device authorisation before any session
//! data. A major mismatch returns `UNSUPPORTED_SCHEMA` without session data. A future major does
//! not silently change the transport ALPN.
//!
//! Before enabling authorised session, control or data streams, both endpoints prove their paired
//! authorisation keys over
//! `CBOR(["kr-connect/1", complete_client_offer, complete_host_selection, client_endpoint_id,
//! host_endpoint_id])`, encoded as KR-CBOR-1. Both mutual proofs are required: a holder of one
//! transport key alone cannot substitute the authorised application identity.

use kr_cbor::{CanonicalValue, CborError, sha256, signing_input};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtocolError};
use crate::ids::{
    ActionWindowId, BootEpoch, BuildId, CapabilityId, ClockEpoch, ConnectionId, DeviceId,
    DeviceKeyRevision,
};
use crate::limits::{
    MAX_ATTACHMENT_FRAME_LEN, MAX_CONTROL_FRAME_LEN, MAX_INPUT_FRAME_LEN,
    MAX_OUTSTANDING_MUTATIONS, MAX_SEND_QUEUE_BYTES,
};
use crate::scalars::{
    CanonicalSet, Digest256, DurationMs, EndpointKey, Nonce256, Signature64, TimestampMs, U64,
};

/// The stable transport ALPN.
///
/// A future protocol major does not change it. Version negotiation happens in `hello`.
pub const ALPN: &[u8] = b"kalareach";

/// The domain the connection proof transcript is separated by.
pub const CONNECT_DOMAIN: &str = "kr-connect/1";

/// One public protocol version.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    /// The major version. A mismatch is not negotiable.
    pub major: u16,
    /// The minor version. A peer selects the highest minor both sides support.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Builds a version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl core::fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

/// The protocol version this build implements.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// The receive limits a peer declares.
///
/// Both sides state their own bounds; the selection carries the negotiated values and the
/// transcript covers them, so a downgrade cannot be introduced after `hello`.
///
/// Each frame bound covers the complete frame, its four-byte length prefix included, which is the
/// same quantity [`crate::frame::StreamKind::max_frame_len`] bounds. A sender subtracts the prefix
/// to get the payload it may send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiveLimits {
    /// Maximum complete control frame, in bytes, length prefix included.
    pub max_control_frame_len: U64,
    /// Maximum complete input frame, in bytes, length prefix included.
    pub max_input_frame_len: U64,
    /// Maximum complete attachment frame, in bytes, length prefix included.
    pub max_attachment_frame_len: U64,
    /// Maximum outstanding mutations per session.
    pub max_outstanding_mutations: U64,
    /// Maximum queued bytes before the peer is resynchronised.
    pub max_send_queue_bytes: U64,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            max_control_frame_len: U64::new(MAX_CONTROL_FRAME_LEN as u64),
            max_input_frame_len: U64::new(MAX_INPUT_FRAME_LEN as u64),
            max_attachment_frame_len: U64::new(MAX_ATTACHMENT_FRAME_LEN as u64),
            max_outstanding_mutations: U64::new(MAX_OUTSTANDING_MUTATIONS as u64),
            max_send_queue_bytes: U64::new(MAX_SEND_QUEUE_BYTES as u64),
        }
    }
}

/// The client's complete `hello` offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientOffer {
    /// Every public protocol version the client offers.
    pub offered_versions: Vec<ProtocolVersion>,
    /// The client build identity.
    pub build_id: BuildId,
    /// The client's device identity.
    pub device_id: DeviceId,
    /// The revision of that device's purpose-separated keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The capabilities the client offers.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The client's own receive limits.
    pub max_receive: ReceiveLimits,
    /// A fresh client nonce.
    pub client_nonce: Nonce256,
}

/// The host's complete `hello` selection.
///
/// It echoes the client nonce as well as carrying its own, so the transcript binds one exact
/// offer to one exact selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSelection {
    /// A fresh host nonce.
    pub host_nonce: Nonce256,
    /// The client nonce this selection answers.
    pub client_nonce: Nonce256,
    /// The connection identity the host allocated.
    pub connection_id: ConnectionId,
    /// The version the host selected.
    pub selected_version: ProtocolVersion,
    /// The capabilities the host selected.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The negotiated limits.
    pub limits: ReceiveLimits,
    /// The host's iroh endpoint identity, validated against the paired record.
    pub endpoint_id: EndpointKey,
    /// The host's device identity.
    pub device_id: DeviceId,
    /// The revision of the host's purpose-separated keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The host boot epoch.
    pub boot_epoch: BootEpoch,
    /// The host clock epoch.
    pub clock_epoch: ClockEpoch,
}

/// The host's answer to a `hello` offer.
///
/// A major mismatch answers [`ErrorCode::UnsupportedSchema`] here and the connection carries no
/// session data. Every other refusal before device authorisation answers here too, so a client
/// never has to distinguish a closed stream from a rejected offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HelloReply {
    /// The host selected a version and its limits.
    Selected(Box<HostSelection>),
    /// The host refused the offer.
    Refused(ProtocolError),
}

/// One endpoint's `kr-connect/1` proof.
///
/// The signature covers the transcript built by [`connect_transcript`]. Nothing else travels with
/// it: every value the signature depends on is already in the offer, the selection or the two
/// endpoint identities, so a receiver reconstructs the transcript rather than trusting a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProof {
    /// The signature over the connection transcript, made with the paired authorisation key.
    pub signature: Signature64,
}

/// A host-issued action window.
///
/// Section 9: an original online request carries a window bound to this authenticated connection
/// and to the host's boot identity, and the host derives the accepted deadline from the earliest
/// of window expiry, receipt time plus the requested time to live, and any authority or subject
/// deadline. The window carries a *duration*, not an absolute wall-clock deadline: the client
/// schedules its renewal from that duration, while the host keeps the authoritative deadline on
/// its own suspend-aware continuous clock. `issued_at_ms` is the host's stamp, for display and
/// diagnosis only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionWindow {
    /// The window identity a mutation names.
    pub action_window_id: ActionWindowId,
    /// The connection the window is bound to.
    pub connection_id: ConnectionId,
    /// The host boot the window is bound to. A restart invalidates new admission through it.
    pub boot_epoch: BootEpoch,
    /// The host's stamp of when it issued the window, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// How long the window stays valid, at most [`crate::limits::MAX_ACTION_WINDOW`].
    pub valid_for_ms: DurationMs,
}

/// What the host returns once both proofs verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectAccepted {
    /// The host's own proof over the same transcript.
    pub host_proof: ConnectProof,
    /// The first action window of this connection.
    pub action_window: ActionWindow,
}

/// The host's answer to a client proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectReply {
    /// Both proofs verified; authorised streams may be opened.
    Accepted(Box<ConnectAccepted>),
    /// Authorisation failed. No authorised stream is ever enabled on this connection.
    Refused(ProtocolError),
}

/// Selects the highest version both sides listed.
///
/// A peer enumerates every version it supports rather than a range, so the selection is the
/// highest version present in both lists. Nothing here assumes that supporting one minor implies
/// supporting the ones below it; the specification states no such compatibility rule.
///
/// # Errors
///
/// Returns [`ErrorCode::UnsupportedSchema`] when the two lists share no version. A major mismatch
/// is the usual case, and it returns before any session data.
pub fn select_version(
    offered: &[ProtocolVersion],
    supported: &[ProtocolVersion],
) -> Result<ProtocolVersion, ErrorCode> {
    offered
        .iter()
        .filter(|candidate| supported.contains(candidate))
        .max()
        .copied()
        .ok_or(ErrorCode::UnsupportedSchema)
}

/// Builds the `kr-connect/1` proof transcript.
///
/// # Errors
///
/// Returns a CBOR error when the offer or selection cannot be represented in KR-CBOR-1.
pub fn connect_transcript(
    offer: &ClientOffer,
    selection: &HostSelection,
    client_endpoint_id: &EndpointKey,
    host_endpoint_id: &EndpointKey,
) -> Result<Vec<u8>, CborError> {
    signing_input(
        CONNECT_DOMAIN,
        vec![
            kr_cbor::to_canonical_value(offer)?,
            kr_cbor::to_canonical_value(selection)?,
            CanonicalValue::bytes(client_endpoint_id.as_bytes().as_slice()),
            CanonicalValue::bytes(host_endpoint_id.as_bytes().as_slice()),
        ],
    )
}

/// Builds the transcript and returns its SHA-256 digest.
///
/// # Errors
///
/// Returns a CBOR error when the offer or selection cannot be represented in KR-CBOR-1.
pub fn connect_transcript_digest(
    offer: &ClientOffer,
    selection: &HostSelection,
    client_endpoint_id: &EndpointKey,
    host_endpoint_id: &EndpointKey,
) -> Result<Digest256, CborError> {
    let transcript = connect_transcript(offer, selection, client_endpoint_id, host_endpoint_id)?;
    Ok(Digest256::from_bytes(sha256(&transcript)))
}
