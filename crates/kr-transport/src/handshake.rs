//! `hello` and the `kr-connect/1` mutual proof on the first bidirectional stream.
//!
//! Section 23 fixes the order: the first bidirectional stream performs `hello` and device
//! authorisation before any session data, and both endpoints prove their paired authorisation keys
//! over the complete offer, the complete selection and both endpoint identities before any
//! authorised stream is enabled.
//!
//! Four frames, in this order:
//!
//! 1. the client's [`ClientOffer`];
//! 2. the host's [`HelloReply`], which either selects a version or refuses;
//! 3. the client's [`ConnectProof`];
//! 4. the host's [`ConnectReply`], which either accepts with its own proof and this connection's
//!    first action window, or refuses.
//!
//! The host verifies the client's proof before it produces its own, so a peer that cannot prove
//! its authorisation key never obtains the host's signature over the transcript it chose.
//!
//! # What authenticates what
//!
//! iroh authenticates the two *transport* keys: the connection exists only between the two
//! endpoint identities. These proofs authenticate the two *authorisation* keys, which is a
//! different pair of keys for a different purpose. The paired record is looked up by the
//! authenticated endpoint identity, never by the device identity the peer claims, so the offer
//! cannot select another device's record. `verify_connect` then checks that the claimed device
//! identity and key revision match the record it selected, and that the live endpoints on both
//! sides are the paired ones.
//!
//! A connection whose endpoint has no paired record is not refused. It negotiates framing and
//! version like any other and then reaches the bounded pre-authorisation pairing surface in
//! [`crate::preauth`], and nothing else.

use std::sync::Arc;

use iroh::endpoint::Connection;
use kr_crypto::connect::{
    ChallengeLedger, ConnectProofs, PairedPeer, sign_connect, verify_connect,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{
    ActionWindow, ClientOffer, ConnectAccepted, ConnectProof, ConnectReply, HelloReply,
    HostSelection, PROTOCOL_VERSION, ProtocolVersion, ReceiveLimits, select_version,
};
use kr_protocol::ids::{
    BootEpoch, BuildId, CapabilityId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision,
};
use kr_protocol::scalars::{CanonicalSet, Digest256, EndpointKey, Nonce256};

use crate::codec::{FrameReader, FrameWriter};
use crate::error::{Result, TransportError};
use crate::random::{fresh_connection_id, fresh_nonce};
use crate::window::ActionWindowIssuer;

/// What one endpoint knows about itself.
///
/// Both roles use the same facts; only the direction of the exchange differs.
#[derive(Debug)]
pub struct LocalIdentity {
    /// This device's identity in the paired record.
    pub device_id: DeviceId,
    /// The revision of this device's purpose-separated keys.
    pub device_key_revision: DeviceKeyRevision,
    /// This device's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// This device's authorisation keypair. It signs the connection transcript and nothing on this
    /// connection is authorised without it.
    pub authorisation: AuthorisationKeyPair,
    /// This build's identity.
    pub build_id: BuildId,
    /// The capabilities this side offers or selects from.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The receive limits this side declares.
    pub max_receive: ReceiveLimits,
    /// Every public protocol version this build implements.
    pub supported_versions: Vec<ProtocolVersion>,
}

impl LocalIdentity {
    /// Builds an identity that offers exactly this build's protocol version, capabilities and
    /// default limits.
    #[must_use]
    pub fn new(
        device_id: DeviceId,
        device_key_revision: DeviceKeyRevision,
        endpoint_id: EndpointKey,
        authorisation: AuthorisationKeyPair,
        build_id: BuildId,
    ) -> Self {
        Self {
            device_id,
            device_key_revision,
            endpoint_id,
            authorisation,
            build_id,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            supported_versions: vec![PROTOCOL_VERSION],
        }
    }

    /// Returns the paired record this side presents of itself.
    #[must_use]
    pub fn as_paired_peer(&self) -> PairedPeer {
        PairedPeer {
            device_id: self.device_id,
            device_key_revision: self.device_key_revision,
            authorisation: *self.authorisation.public(),
            endpoint_id: self.endpoint_id,
        }
    }
}

/// The host facts a selection carries beyond the shared identity.
#[derive(Clone, Copy, Debug)]
pub struct HostEpochs {
    /// The host boot epoch. A restart invalidates admission through old connection windows.
    pub boot_epoch: BootEpoch,
    /// The host clock epoch. It advances when wall-clock trust changes.
    pub clock_epoch: ClockEpoch,
}

/// Where the host finds the paired record of an authenticated endpoint.
///
/// The lookup key is the endpoint identity iroh authenticated, so a caller cannot reach a record
/// by naming it. An endpoint with no record is an unpaired peer, which is a normal state, not a
/// failure: it is how a device pairs for the first time.
pub trait PairedDirectory: Send + Sync + std::fmt::Debug {
    /// Returns the paired record of `endpoint_id`, or `None` when the endpoint is not paired.
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer>;
}

/// An empty directory: every endpoint is unpaired.
///
/// A host with no devices paired yet uses this, and so does a host that serves only the
/// pre-authorisation pairing surface.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPairedDevices;

impl PairedDirectory for NoPairedDevices {
    fn paired_peer(&self, _endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        None
    }
}

/// What the host produced from one `hello` and proof exchange.
#[derive(Debug)]
pub enum Admitted {
    /// The peer proved a paired authorisation key. Authorised streams may be enabled.
    Authorised(Box<AuthorisedConnection>),
    /// The peer's endpoint is not paired. Only the pre-authorisation pairing surface is reachable.
    Unpaired(Box<UnpairedConnection>),
}

/// An authorised connection and its control stream.
#[derive(Debug)]
pub struct AuthorisedConnection {
    /// The connection identity the host allocated.
    pub connection_id: ConnectionId,
    /// The peer's device identity, from its paired record.
    pub peer_device_id: DeviceId,
    /// The peer's endpoint identity, as authenticated by iroh.
    pub peer_endpoint_id: EndpointKey,
    /// The digest of the transcript both sides signed. It identifies this exact negotiation.
    pub transcript_digest: Digest256,
    /// The complete offer, as signed.
    pub offer: ClientOffer,
    /// The complete selection, as signed.
    pub selection: HostSelection,
    /// The first action window of this connection.
    pub action_window: ActionWindow,
    /// The control stream's writer.
    pub control_writer: FrameWriter,
    /// The control stream's reader.
    pub control_reader: FrameReader,
}

impl AuthorisedConnection {
    /// Returns the limits both sides negotiated.
    #[must_use]
    pub const fn limits(&self) -> ReceiveLimits {
        self.selection.limits
    }

    /// Returns the protocol version in force.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.selection.selected_version
    }
}

/// A connection whose endpoint is not paired.
#[derive(Debug)]
pub struct UnpairedConnection {
    /// The connection identity the host allocated.
    pub connection_id: ConnectionId,
    /// The peer's endpoint identity, as authenticated by iroh.
    pub peer_endpoint_id: EndpointKey,
    /// The selection the host answered with.
    pub selection: HostSelection,
    /// The control stream's writer.
    pub control_writer: FrameWriter,
    /// The control stream's reader.
    pub control_reader: FrameReader,
    /// True when this stream carried QUIC 0-RTT data, in which case no mutation is admitted.
    pub early_data: bool,
}

/// Runs the host side of the handshake on a freshly accepted connection.
///
/// # Errors
///
/// Returns the failure this side records. The peer has already been told, in the reply frame, the
/// stable code it needs; the detail stays here.
pub async fn accept(
    connection: &Connection,
    identity: &LocalIdentity,
    epochs: HostEpochs,
    directory: &dyn PairedDirectory,
    challenges: &Arc<std::sync::Mutex<ChallengeLedger>>,
    windows: &ActionWindowIssuer,
) -> Result<Admitted> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|error| TransportError::Stream(error.to_string()))?;
    let early_data = recv.is_0rtt();
    accept_on(
        connection, send, recv, early_data, identity, epochs, directory, challenges, windows,
    )
    .await
}

/// Runs the host side of the handshake on a stream the caller already accepted.
///
/// A host that wants an accurate `early_data` answer has to accept the first stream itself, because
/// QUIC marks a stream as early data only when it is accepted while the handshake is still running.
/// [`crate::listener`] does exactly that and passes the result here.
///
/// # Errors
///
/// As [`accept`].
#[allow(clippy::too_many_arguments)]
pub async fn accept_on(
    connection: &Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    early_data: bool,
    identity: &LocalIdentity,
    epochs: HostEpochs,
    directory: &dyn PairedDirectory,
    challenges: &Arc<std::sync::Mutex<ChallengeLedger>>,
    windows: &ActionWindowIssuer,
) -> Result<Admitted> {
    let mut writer = FrameWriter::new(send, StreamKind::Control);
    let mut reader = FrameReader::new(recv, StreamKind::Control);
    writer.set_priority(crate::scheduler::priority_of(StreamKind::Control));

    let peer_endpoint_id = remote_endpoint_key(connection)?;

    // The offer is small and arrives before anything about the peer has been established, so it is
    // read under a much tighter bound than the control stream's.
    let offer: ClientOffer = reader
        .read_message_within(MAX_OFFER_LEN)
        .await?
        .ok_or_else(|| TransportError::handshake(ErrorCode::InvalidArgument, "no offer arrived"))?;

    let selected_version =
        match select_version(&offer.offered_versions, &identity.supported_versions) {
            Ok(version) => version,
            Err(code) => {
                let error = ProtocolError::new(code, "no offered protocol version is supported");
                writer
                    .write_message(&HelloReply::Refused(error.clone()))
                    .await?;
                writer.finish_and_flush(REFUSAL_FLUSH).await;
                return Err(TransportError::Handshake(error));
            }
        };

    let host_nonce = fresh_nonce()?;
    let connection_id = fresh_connection_id()?;
    let selection = HostSelection {
        host_nonce,
        client_nonce: offer.client_nonce,
        connection_id,
        selected_version,
        capabilities: intersect(&identity.capabilities, &offer.capabilities),
        limits: negotiate_limits(identity.max_receive, offer.max_receive),
        endpoint_id: identity.endpoint_id,
        device_id: identity.device_id,
        device_key_revision: identity.device_key_revision,
        boot_epoch: epochs.boot_epoch,
        clock_epoch: epochs.clock_epoch,
    };

    let paired = directory.paired_peer(&peer_endpoint_id);

    if early_data && paired.is_some() {
        // Section 23: reject early data for everything except the bounded pre-authorisation
        // pairing surface. An authorised connection is not that surface, so a handshake stream that
        // carried early data never becomes one. Nothing is lost: this build's client cannot offer
        // 0-RTT, because its endpoint keeps no session tickets.
        let error = ProtocolError::new(
            ErrorCode::PermissionDenied,
            "early data is not accepted on an authorised connection",
        );
        writer
            .write_message(&HelloReply::Refused(error.clone()))
            .await?;
        writer.finish_and_flush(REFUSAL_FLUSH).await;
        return Err(TransportError::Handshake(error));
    }

    let Some(paired) = paired else {
        // An unpaired endpoint still learns the framing and the selected version: without them it
        // could not speak to the pairing surface at all. It never sees a proof exchange, so it
        // never becomes an authorised connection by any path through this function.
        writer
            .write_message(&HelloReply::Selected(Box::new(selection.clone())))
            .await?;
        return Ok(Admitted::Unpaired(Box::new(UnpairedConnection {
            connection_id,
            peer_endpoint_id,
            selection,
            control_writer: writer,
            control_reader: reader,
            early_data,
        })));
    };

    // The challenge is held by a guard from here on. Every path out of this function that does not
    // consume it abandons it, including one that never reaches the proof at all: a ledger that
    // filled up with challenges nobody signed would stop the host accepting paired connections.
    let mut challenge = Challenge::issue(Arc::clone(challenges), host_nonce)?;
    writer
        .write_message(&HelloReply::Selected(Box::new(selection.clone())))
        .await?;

    let outcome = admit_paired_peer(
        &mut reader,
        &offer,
        &selection,
        identity,
        &paired,
        &peer_endpoint_id,
        directory,
        &mut challenge,
        windows,
    )
    .await;

    match outcome {
        Ok((digest, accepted)) => {
            let mut window_guard = WindowGuard {
                windows,
                action_window_id: Some(accepted.action_window.action_window_id.clone()),
            };
            let negotiated = usize::try_from(selection.limits.max_control_frame_len.get())
                .unwrap_or(usize::MAX)
                .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN);
            writer
                .write_message(&ConnectReply::Accepted(Box::new(accepted.clone())))
                .await?;
            window_guard.disarm();
            Ok(Admitted::Authorised(Box::new(AuthorisedConnection {
                connection_id,
                peer_device_id: paired.device_id,
                peer_endpoint_id,
                transcript_digest: digest,
                offer,
                selection,
                action_window: accepted.action_window,
                // From here the negotiated bound applies in both directions, not just the stream
                // kind's ceiling: a peer that said it could receive less is held to what it said.
                control_writer: writer.with_max_payload(negotiated),
                control_reader: reader.with_max_payload(negotiated),
            })))
        }
        Err(error) => {
            challenge.abandon();
            writer
                .write_message(&ConnectReply::Refused(error.to_protocol_error()))
                .await?;
            writer.finish_and_flush(REFUSAL_FLUSH).await;
            Err(error)
        }
    }
}

/// How long a refusal waits to be acknowledged before the connection is let go.
const REFUSAL_FLUSH: std::time::Duration = std::time::Duration::from_secs(2);

/// The largest `hello` offer this host will read, in bytes.
///
/// An offer carries a version list, a build identity, two identifiers, a capability set, five
/// limits and a nonce. Sixteen kibibytes is generous for that and far below the control bound,
/// which matters because the offer arrives before anything about the peer is established.
pub const MAX_OFFER_LEN: usize = 16 * 1024;

/// One issued connection challenge, released on every path that does not consume it.
///
/// The ledger is behind a synchronous lock and every operation on it is a set insertion or removal,
/// so nothing is ever held across an await. That is what lets the guard release the challenge from
/// `Drop`, which is the one place a cancelled handshake can still reach.
#[derive(Debug)]
struct Challenge {
    ledger: Arc<std::sync::Mutex<ChallengeLedger>>,
    nonce: Nonce256,
    outstanding: bool,
}

impl Challenge {
    fn issue(ledger: Arc<std::sync::Mutex<ChallengeLedger>>, nonce: Nonce256) -> Result<Self> {
        lock_ledger(&ledger).issue(&nonce)?;
        Ok(Self {
            ledger,
            nonce,
            outstanding: true,
        })
    }

    /// Frees the challenge without recording it as used.
    fn abandon(&mut self) {
        if self.outstanding {
            lock_ledger(&self.ledger).abandon(&self.nonce);
            self.outstanding = false;
        }
    }
}

impl Drop for Challenge {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn lock_ledger(
    ledger: &Arc<std::sync::Mutex<ChallengeLedger>>,
) -> std::sync::MutexGuard<'_, ChallengeLedger> {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[allow(clippy::too_many_arguments)]
async fn admit_paired_peer(
    reader: &mut FrameReader,
    offer: &ClientOffer,
    selection: &HostSelection,
    identity: &LocalIdentity,
    paired: &PairedPeer,
    peer_endpoint_id: &EndpointKey,
    directory: &dyn PairedDirectory,
    challenge: &mut Challenge,
    windows: &ActionWindowIssuer,
) -> Result<(Digest256, ConnectAccepted)> {
    let client_proof: ConnectProof = reader
        .read_message_within(MAX_OFFER_LEN)
        .await?
        .ok_or_else(|| {
            TransportError::handshake(ErrorCode::PermissionDenied, "no connection proof arrived")
        })?;

    // The host's own proof over the same transcript. It is produced before verification only
    // because both signatures are needed to check the pair; it is sent afterwards, and only if the
    // client's proof verified.
    let host_proof = sign_connect(
        &identity.authorisation,
        offer,
        selection,
        peer_endpoint_id,
        &identity.endpoint_id,
    )?;
    let proofs = ConnectProofs {
        client: client_proof.signature,
        host: host_proof,
    };
    let local = identity.as_paired_peer();

    let digest = {
        let mut ledger = lock_ledger(&challenge.ledger);
        let outcome = kr_crypto::connect::verify_connect_once(
            &mut ledger,
            &selection.host_nonce,
            offer,
            selection,
            paired,
            &local,
            peer_endpoint_id,
            &identity.endpoint_id,
            &proofs,
        );
        if outcome.is_ok() {
            // The ledger consumed it, so the guard has nothing left to release.
            challenge.outstanding = false;
        }
        outcome?
    };

    // The paired record is read again here, as late as the exchange allows: a device revoked, or a
    // key rotated, while this handshake was waiting for its proof must not be admitted under the
    // record that was current when the wait began. A revocation that lands after this point is the
    // host's dispatch barrier to enforce, which is where section 9 puts it.
    let current = directory.paired_peer(peer_endpoint_id).ok_or_else(|| {
        TransportError::handshake(
            ErrorCode::PermissionDenied,
            "the paired record was withdrawn during the handshake",
        )
    })?;
    if &current != paired {
        return Err(TransportError::handshake(
            ErrorCode::PermissionDenied,
            "the paired record changed during the handshake",
        ));
    }

    let action_window = windows.issue(selection.connection_id, selection.boot_epoch)?;
    Ok((
        digest,
        ConnectAccepted {
            host_proof: ConnectProof {
                signature: host_proof,
            },
            action_window,
        },
    ))
}

/// Retires an issued window unless the connection that would own it is admitted.
///
/// A window exists from the moment it is issued, which is before the acceptance frame is written.
/// A write that fails, or a cancellation between the two, would otherwise leave a window recorded
/// for a connection that never existed.
#[derive(Debug)]
struct WindowGuard<'a> {
    windows: &'a ActionWindowIssuer,
    action_window_id: Option<kr_protocol::ids::ActionWindowId>,
}

impl WindowGuard<'_> {
    fn disarm(&mut self) {
        self.action_window_id = None;
    }
}

impl Drop for WindowGuard<'_> {
    fn drop(&mut self) {
        if let Some(action_window_id) = self.action_window_id.take() {
            self.windows.retire(&action_window_id);
        }
    }
}

/// Runs the client side of the handshake on a connection it opened.
///
/// # Errors
///
/// Returns the first refusal or mismatch. A client that cannot verify the host's proof never
/// enables an authorised stream, whatever the host said.
pub async fn connect(
    connection: &Connection,
    identity: &LocalIdentity,
    host_record: &PairedPeer,
) -> Result<AuthorisedConnection> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| TransportError::Stream(error.to_string()))?;
    let mut writer = FrameWriter::new(send, StreamKind::Control);
    let mut reader = FrameReader::new(recv, StreamKind::Control);
    writer.set_priority(crate::scheduler::priority_of(StreamKind::Control));

    let host_endpoint_id = remote_endpoint_key(connection)?;

    let offer = ClientOffer {
        offered_versions: identity.supported_versions.clone(),
        build_id: identity.build_id.clone(),
        device_id: identity.device_id,
        device_key_revision: identity.device_key_revision,
        capabilities: identity.capabilities.clone(),
        max_receive: identity.max_receive,
        client_nonce: fresh_nonce()?,
    };
    writer.write_message(&offer).await?;

    let reply: HelloReply = reader
        .read_message_within(MAX_OFFER_LEN)
        .await?
        .ok_or_else(|| {
            TransportError::handshake(ErrorCode::ResourceUnavailable, "the host sent no reply")
        })?;
    let selection = match reply {
        HelloReply::Selected(selection) => *selection,
        HelloReply::Refused(error) => return Err(TransportError::Handshake(error)),
    };

    let client_signature = sign_connect(
        &identity.authorisation,
        &offer,
        &selection,
        &identity.endpoint_id,
        &host_endpoint_id,
    )?;
    writer
        .write_message(&ConnectProof {
            signature: client_signature,
        })
        .await?;

    let reply: ConnectReply = reader
        .read_message_within(MAX_OFFER_LEN)
        .await?
        .ok_or_else(|| {
            TransportError::handshake(ErrorCode::PermissionDenied, "the host sent no proof")
        })?;
    let accepted = match reply {
        ConnectReply::Accepted(accepted) => *accepted,
        ConnectReply::Refused(error) => return Err(TransportError::Handshake(error)),
    };

    // The client checks the same bindings the host did, from its own side. A host that selected a
    // weaker limit than it signed, or that presented another device's identity, fails here.
    let transcript_digest = verify_connect(
        &offer,
        &selection,
        &identity.as_paired_peer(),
        host_record,
        &identity.endpoint_id,
        &host_endpoint_id,
        &ConnectProofs {
            client: client_signature,
            host: accepted.host_proof.signature,
        },
    )?;

    if accepted.action_window.connection_id != selection.connection_id
        || accepted.action_window.boot_epoch != selection.boot_epoch
    {
        return Err(TransportError::handshake(
            ErrorCode::PermissionDenied,
            "the action window is not bound to this connection",
        ));
    }

    let negotiated = usize::try_from(selection.limits.max_control_frame_len.get())
        .unwrap_or(usize::MAX)
        .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN);
    Ok(AuthorisedConnection {
        connection_id: selection.connection_id,
        peer_device_id: host_record.device_id,
        peer_endpoint_id: host_endpoint_id,
        transcript_digest,
        offer,
        selection,
        action_window: accepted.action_window,
        control_writer: writer.with_max_payload(negotiated),
        control_reader: reader.with_max_payload(negotiated),
    })
}

/// Returns the peer's endpoint identity as iroh authenticated it.
fn remote_endpoint_key(connection: &Connection) -> Result<EndpointKey> {
    Ok(EndpointKey::from_bytes(*connection.remote_id().as_bytes()))
}

/// Returns the capabilities both sides offer.
///
/// A capability neither side named is not in force, and an unknown capability rejects rather than
/// being ignored, which is why the selection is an intersection rather than the host's own list.
fn intersect(
    host: &CanonicalSet<CapabilityId>,
    client: &CanonicalSet<CapabilityId>,
) -> CanonicalSet<CapabilityId> {
    host.iter()
        .filter(|capability| client.contains(capability))
        .cloned()
        .collect()
}

/// Returns the limits both sides can honour.
///
/// Each bound is the smaller of the two declarations: a peer never has to receive more than it
/// said it could, and the transcript covers the result, so the negotiated value cannot be lowered
/// afterwards without breaking both signatures.
fn negotiate_limits(host: ReceiveLimits, client: ReceiveLimits) -> ReceiveLimits {
    use kr_protocol::scalars::U64;
    let smaller = |left: U64, right: U64| U64::new(left.get().min(right.get()));
    ReceiveLimits {
        max_control_frame_len: smaller(host.max_control_frame_len, client.max_control_frame_len),
        max_input_frame_len: smaller(host.max_input_frame_len, client.max_input_frame_len),
        max_attachment_frame_len: smaller(
            host.max_attachment_frame_len,
            client.max_attachment_frame_len,
        ),
        max_outstanding_mutations: smaller(
            host.max_outstanding_mutations,
            client.max_outstanding_mutations,
        ),
        max_send_queue_bytes: smaller(host.max_send_queue_bytes, client.max_send_queue_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::U64;

    #[test]
    fn the_negotiated_limits_are_the_smaller_of_the_two_declarations() {
        let host = ReceiveLimits::default();
        let client = ReceiveLimits {
            max_input_frame_len: U64::new(1024),
            ..ReceiveLimits::default()
        };
        let negotiated = negotiate_limits(host, client);
        assert_eq!(negotiated.max_input_frame_len, U64::new(1024));
        assert_eq!(negotiated.max_control_frame_len, host.max_control_frame_len);
    }

    #[test]
    fn a_capability_only_one_side_offers_is_not_selected() {
        let shared = CapabilityId::new("shared").expect("a capability");
        let host_only = CapabilityId::new("host_only").expect("a capability");
        let client_only = CapabilityId::new("client_only").expect("a capability");
        let host: CanonicalSet<_> = [shared.clone(), host_only].into_iter().collect();
        let client: CanonicalSet<_> = [shared.clone(), client_only].into_iter().collect();
        let selected = intersect(&host, &client);
        assert_eq!(selected.len(), 1);
        assert!(selected.contains(&shared));
    }

    #[test]
    fn a_major_mismatch_is_an_unsupported_schema() {
        let offered = [ProtocolVersion::new(2, 0)];
        let supported = [PROTOCOL_VERSION];
        assert_eq!(
            select_version(&offered, &supported),
            Err(ErrorCode::UnsupportedSchema)
        );
    }
}
