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

use crate::error::ErrorCode;
use crate::ids::{
    BootEpoch, BuildId, CapabilityId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision,
};
use crate::limits::{
    MAX_ATTACHMENT_FRAME_LEN, MAX_CONTROL_FRAME_LEN, MAX_INPUT_FRAME_LEN,
    MAX_OUTSTANDING_MUTATIONS, MAX_SEND_QUEUE_BYTES,
};
use crate::scalars::{CanonicalSet, Digest256, EndpointKey, Nonce256, U64};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiveLimits {
    /// Maximum control frame payload, in bytes.
    pub max_control_frame_len: U64,
    /// Maximum input frame payload, in bytes.
    pub max_input_frame_len: U64,
    /// Maximum attachment frame payload, in bytes.
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
