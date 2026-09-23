//! The `kr-connect/1` mutual proof of section 23.
//!
//! Before either endpoint enables authorised session, control or data streams, both prove their
//! paired authorisation keys over
//! `CBOR(["kr-connect/1", complete_client_offer, complete_host_selection, client_endpoint_id,
//! host_endpoint_id])`.
//!
//! Both proofs are required. iroh authenticates the two transport keys; these signatures
//! authenticate the two *authorisation* keys, so a peer that holds only a transport key cannot
//! substitute the authorised application identity. The transcript carries the complete offer and
//! selection, which is what makes a downgrade visible: a selection that reports weaker limits than
//! the one the peer signed produces a different transcript and fails.

use std::collections::BTreeSet;

use kr_protocol::hello::{CONNECT_DOMAIN, ClientOffer, HostSelection, connect_transcript};
use kr_protocol::ids::{DeviceId, DeviceKeyRevision};
use kr_protocol::scalars::{AuthorisationKey, Digest256, EndpointKey, Nonce256, Signature64};

use crate::error::{CryptoError, Result};
use crate::keys::AuthorisationKeyPair;
use crate::sign::{self, SigningTranscript};

/// The paired record of one endpoint.
///
/// Verification checks the live connection against this record rather than against what the peer
/// says about itself. A stale key revision or a substituted endpoint fails here, before any
/// signature is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairedPeer {
    /// The device identity in the paired record.
    pub device_id: DeviceId,
    /// The key revision the paired record holds.
    pub device_key_revision: DeviceKeyRevision,
    /// The authorisation key the paired record holds.
    pub authorisation: AuthorisationKey,
    /// The iroh endpoint identity the paired record holds.
    pub endpoint_id: EndpointKey,
}

/// Both endpoints' proofs over one transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectProofs {
    /// The client's signature.
    pub client: Signature64,
    /// The host's signature.
    pub host: Signature64,
}

/// Signs the connection transcript with a device's authorisation key.
///
/// # Errors
///
/// Returns an encoding error when the offer or selection is outside KR-CBOR-1, and a library error
/// when libsodium fails.
pub fn sign_connect(
    key: &AuthorisationKeyPair,
    offer: &ClientOffer,
    selection: &HostSelection,
    client_endpoint_id: &EndpointKey,
    host_endpoint_id: &EndpointKey,
) -> Result<Signature64> {
    let transcript = SigningTranscript::from_canonical_bytes(
        CONNECT_DOMAIN,
        connect_transcript(offer, selection, client_endpoint_id, host_endpoint_id)?,
    )?;
    sign::sign(key, &transcript)
}

/// Verifies both proofs and every binding the transcript depends on.
///
/// The checks, in order:
///
/// 1. the selection echoes the client nonce, so one offer is bound to one selection;
/// 2. each side's declared key revision equals the paired record's, so a stale key is rejected;
/// 3. the selection's endpoint identity equals the host's paired endpoint;
/// 4. the live iroh endpoints equal the paired endpoints on both sides;
/// 5. both signatures verify over the exact transcript.
///
/// Returns the transcript digest, which the caller records for the connection.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] for the first binding that fails and
/// [`CryptoError::Authentication`] when a signature does not verify.
#[allow(clippy::too_many_arguments)]
pub fn verify_connect(
    offer: &ClientOffer,
    selection: &HostSelection,
    client: &PairedPeer,
    host: &PairedPeer,
    live_client_endpoint: &EndpointKey,
    live_host_endpoint: &EndpointKey,
    proofs: &ConnectProofs,
) -> Result<Digest256> {
    if !offer.offered_versions.contains(&selection.selected_version) {
        return Err(CryptoError::BindingMismatch {
            what: "the selected protocol version, which the client did not offer",
        });
    }
    if !selection.capabilities.is_subset(&offer.capabilities) {
        return Err(CryptoError::BindingMismatch {
            what: "a selected capability the client did not offer",
        });
    }
    if selection.limits.max_control_frame_len > offer.max_receive.max_control_frame_len
        || selection.limits.max_input_frame_len > offer.max_receive.max_input_frame_len
        || selection.limits.max_attachment_frame_len > offer.max_receive.max_attachment_frame_len
        || selection.limits.max_outstanding_mutations > offer.max_receive.max_outstanding_mutations
        || selection.limits.max_send_queue_bytes > offer.max_receive.max_send_queue_bytes
    {
        return Err(CryptoError::BindingMismatch {
            what: "a negotiated limit above what the client offered to receive",
        });
    }
    if selection.client_nonce != offer.client_nonce {
        return Err(CryptoError::BindingMismatch {
            what: "the host selection's echoed client nonce",
        });
    }
    if offer.device_id != client.device_id {
        return Err(CryptoError::BindingMismatch {
            what: "the client device identity",
        });
    }
    if selection.device_id != host.device_id {
        return Err(CryptoError::BindingMismatch {
            what: "the host device identity",
        });
    }
    if offer.device_key_revision != client.device_key_revision {
        return Err(CryptoError::BindingMismatch {
            what: "the client device key revision",
        });
    }
    if selection.device_key_revision != host.device_key_revision {
        return Err(CryptoError::BindingMismatch {
            what: "the host device key revision",
        });
    }
    if selection.endpoint_id != host.endpoint_id {
        return Err(CryptoError::BindingMismatch {
            what: "the host endpoint identity in the selection",
        });
    }
    if live_client_endpoint != &client.endpoint_id {
        return Err(CryptoError::BindingMismatch {
            what: "the live client endpoint identity",
        });
    }
    if live_host_endpoint != &host.endpoint_id {
        return Err(CryptoError::BindingMismatch {
            what: "the live host endpoint identity",
        });
    }

    let transcript = SigningTranscript::from_canonical_bytes(
        CONNECT_DOMAIN,
        connect_transcript(offer, selection, live_client_endpoint, live_host_endpoint)?,
    )?;
    sign::verify(&client.authorisation, &transcript, &proofs.client)?;
    sign::verify(&host.authorisation, &transcript, &proofs.host)?;
    Ok(transcript.digest())
}

/// Verifies a connection and consumes the challenge the host issued for it.
///
/// This is the entry point a host uses. [`verify_connect`] alone proves that the two devices
/// signed this transcript; it does not prove that the transcript is this connection's. The host
/// therefore supplies the nonce it retained when it opened this connection: the selection must
/// name that exact nonce, and it is consumed here, exactly once.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the selection names another connection's
/// challenge or when the challenge was not outstanding, and then whatever [`verify_connect`]
/// returns.
#[allow(clippy::too_many_arguments)]
pub fn verify_connect_once(
    ledger: &mut ChallengeLedger,
    issued_host_nonce: &Nonce256,
    offer: &ClientOffer,
    selection: &HostSelection,
    client: &PairedPeer,
    host: &PairedPeer,
    live_client_endpoint: &EndpointKey,
    live_host_endpoint: &EndpointKey,
    proofs: &ConnectProofs,
) -> Result<Digest256> {
    if &selection.host_nonce != issued_host_nonce {
        return Err(CryptoError::BindingMismatch {
            what: "the host challenge, which is not the one this connection issued",
        });
    }
    ledger.consume(issued_host_nonce)?;
    verify_connect(
        offer,
        selection,
        client,
        host,
        live_client_endpoint,
        live_host_endpoint,
        proofs,
    )
}

/// The challenges a host has issued and not yet consumed.
///
/// A host allocates its own 256-bit nonce for every connection, so a replayed transcript carries a
/// nonce the host issued once. The ledger holds each one from the moment it is issued until the
/// connection's proofs consume it; a nonce that is not outstanding is rejected, whether it was
/// never issued or has already been used.
///
/// The ledger is bounded, so a peer cannot make a host remember an unbounded number of challenges.
/// A full ledger is answered by ending idle connections, not by forgetting a challenge.
#[derive(Debug, Default)]
pub struct ChallengeLedger {
    outstanding: BTreeSet<[u8; 32]>,
    consumed: BTreeSet<[u8; 32]>,
    consumed_order: std::collections::VecDeque<[u8; 32]>,
    limit: usize,
}

impl ChallengeLedger {
    /// Creates a ledger that holds at most `limit` outstanding challenges.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self {
            outstanding: BTreeSet::new(),
            consumed: BTreeSet::new(),
            consumed_order: std::collections::VecDeque::new(),
            limit,
        }
    }

    /// Records a challenge the host has just issued.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the challenge is already outstanding, which
    /// for a 256-bit random nonce means a generator failure, and [`CryptoError::TooLarge`] when the
    /// ledger is full.
    pub fn issue(&mut self, host_nonce: &Nonce256) -> Result<()> {
        if self.outstanding.contains(host_nonce.as_bytes())
            || self.consumed.contains(host_nonce.as_bytes())
        {
            return Err(CryptoError::BindingMismatch {
                what: "a reissued connection challenge",
            });
        }
        if self.outstanding.len() >= self.limit {
            return Err(CryptoError::TooLarge {
                what: "the connection challenge ledger",
                limit: self.limit,
                actual: self.outstanding.len() + 1,
            });
        }
        self.outstanding.insert(*host_nonce.as_bytes());
        Ok(())
    }

    /// Consumes an outstanding challenge.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the challenge was never issued or has already
    /// been consumed.
    pub fn consume(&mut self, host_nonce: &Nonce256) -> Result<()> {
        if self.outstanding.remove(host_nonce.as_bytes()) {
            self.record_consumed(*host_nonce.as_bytes());
            Ok(())
        } else {
            Err(CryptoError::BindingMismatch {
                what: "a connection challenge that is not outstanding",
            })
        }
    }

    /// Drops a challenge whose connection ended before it was used.
    ///
    /// Abandoning a challenge is not the same as consuming one: it frees the slot, and the nonce
    /// can never be presented afterwards because it is no longer outstanding either way.
    pub fn abandon(&mut self, host_nonce: &Nonce256) {
        // An abandoned challenge was never part of a verified proof, so it is simply forgotten.
        // Recording it would make a host that opens and drops connections accumulate entries for
        // nonces nothing ever signed.
        self.outstanding.remove(host_nonce.as_bytes());
    }

    /// Remembers a consumed challenge, keeping at most `limit` of them.
    ///
    /// This guards against a generator that repeats, not against an attacker: the host chooses its
    /// own 256-bit nonce, so nothing a peer sends can steer which value is issued next. The set is
    /// bounded for the same reason the outstanding set is, and the oldest entry is dropped first.
    fn record_consumed(&mut self, host_nonce: [u8; 32]) {
        if self.consumed.insert(host_nonce) {
            self.consumed_order.push_back(host_nonce);
        }
        while self.consumed_order.len() > self.limit {
            if let Some(oldest) = self.consumed_order.pop_front() {
                self.consumed.remove(&oldest);
            }
        }
    }

    /// Returns how many challenges are outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns true when none is outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// Returns how many consumed challenges are still remembered.
    #[must_use]
    pub fn retained_consumed(&self) -> usize {
        self.consumed.len()
    }
}

/// Returns the domain the transcript is separated by, for callers that record it.
#[must_use]
pub const fn domain() -> &'static str {
    CONNECT_DOMAIN
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
    use kr_protocol::ids::{BootEpoch, BuildId, ClockEpoch, ConnectionId};
    use kr_protocol::scalars::{CanonicalSet, Uuid};

    struct Fixture {
        offer: ClientOffer,
        selection: HostSelection,
        client_keys: AuthorisationKeyPair,
        host_keys: AuthorisationKeyPair,
        client: PairedPeer,
        host: PairedPeer,
    }

    fn fixture() -> Fixture {
        let client_keys = AuthorisationKeyPair::generate().expect("a keypair");
        let host_keys = AuthorisationKeyPair::generate().expect("a keypair");
        let client = PairedPeer {
            device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            device_key_revision: DeviceKeyRevision::new(2),
            authorisation: *client_keys.public(),
            endpoint_id: EndpointKey::from_bytes([3; 32]),
        };
        let host = PairedPeer {
            device_id: DeviceId::new(Uuid::from_bytes([4; 16])),
            device_key_revision: DeviceKeyRevision::new(5),
            authorisation: *host_keys.public(),
            endpoint_id: EndpointKey::from_bytes([6; 32]),
        };
        let offer = ClientOffer {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: BuildId::new("kr/0.1.0+test").expect("a build identity"),
            device_id: client.device_id,
            device_key_revision: client.device_key_revision,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            client_nonce: Nonce256::from_bytes([7; 32]),
        };
        let selection = HostSelection {
            host_nonce: Nonce256::from_bytes([8; 32]),
            client_nonce: offer.client_nonce,
            connection_id: ConnectionId::new(Uuid::from_bytes([9; 16])),
            selected_version: PROTOCOL_VERSION,
            capabilities: CanonicalSet::new(),
            limits: ReceiveLimits::default(),
            endpoint_id: host.endpoint_id,
            device_id: host.device_id,
            device_key_revision: host.device_key_revision,
            boot_epoch: BootEpoch::new(1),
            clock_epoch: ClockEpoch::new(1),
        };
        Fixture {
            offer,
            selection,
            client_keys,
            host_keys,
            client,
            host,
        }
    }

    fn proofs(fixture: &Fixture) -> ConnectProofs {
        ConnectProofs {
            client: sign_connect(
                &fixture.client_keys,
                &fixture.offer,
                &fixture.selection,
                &fixture.client.endpoint_id,
                &fixture.host.endpoint_id,
            )
            .expect("a client proof"),
            host: sign_connect(
                &fixture.host_keys,
                &fixture.offer,
                &fixture.selection,
                &fixture.client.endpoint_id,
                &fixture.host.endpoint_id,
            )
            .expect("a host proof"),
        }
    }

    fn verify(fixture: &Fixture, proofs: &ConnectProofs) -> Result<Digest256> {
        verify_connect(
            &fixture.offer,
            &fixture.selection,
            &fixture.client,
            &fixture.host,
            &fixture.client.endpoint_id,
            &fixture.host.endpoint_id,
            proofs,
        )
    }

    /// KR-REQ-23.15: both endpoints prove their paired keys over one `kr-connect/1` transcript.
    #[test]
    fn both_proofs_verify_over_one_transcript() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        assert!(verify(&fixture, &proofs).is_ok());
    }

    /// KR-REQ-23.15: one proof cannot stand in for the other.
    #[test]
    fn one_proof_alone_is_not_enough() {
        let fixture = fixture();
        let mut proofs = proofs(&fixture);
        proofs.host = proofs.client;
        assert!(matches!(
            verify(&fixture, &proofs),
            Err(CryptoError::Authentication { .. })
        ));
    }

    /// KR-REQ-23.16: a stale paired key revision is refused.
    #[test]
    fn a_stale_key_revision_is_rejected() {
        let mut fixture = fixture();
        let proofs = proofs(&fixture);
        fixture.client.device_key_revision = DeviceKeyRevision::new(3);
        assert!(matches!(
            verify(&fixture, &proofs),
            Err(CryptoError::BindingMismatch {
                what: "the client device key revision"
            })
        ));
    }

    /// KR-REQ-23.15: the live endpoint must be the one the transcript names.
    #[test]
    fn a_substituted_live_endpoint_is_rejected() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        let other = EndpointKey::from_bytes([99; 32]);
        assert!(matches!(
            verify_connect(
                &fixture.offer,
                &fixture.selection,
                &fixture.client,
                &fixture.host,
                &other,
                &fixture.host.endpoint_id,
                &proofs,
            ),
            Err(CryptoError::BindingMismatch {
                what: "the live client endpoint identity"
            })
        ));
    }

    /// KR-REQ-23.16: a downgraded transcript does not verify.
    #[test]
    fn a_mismatched_transcript_does_not_verify() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        let mut downgraded = fixture;
        downgraded.selection.limits.max_control_frame_len = kr_protocol::scalars::U64::new(1024);
        assert!(matches!(
            verify(&downgraded, &proofs),
            Err(CryptoError::Authentication { .. })
        ));
    }

    /// KR-REQ-23.16: a selection that does not echo this offer's nonce is refused.
    #[test]
    fn an_unechoed_client_nonce_is_rejected() {
        let mut fixture = fixture();
        fixture.selection.client_nonce = Nonce256::from_bytes([77; 32]);
        let proofs = proofs(&fixture);
        assert!(matches!(
            verify(&fixture, &proofs),
            Err(CryptoError::BindingMismatch {
                what: "the host selection's echoed client nonce"
            })
        ));
    }

    /// KR-REQ-23.16: a challenge is used once and never reissued.
    #[test]
    fn a_challenge_is_consumed_once_and_never_returns() {
        let mut ledger = ChallengeLedger::with_limit(2);
        let first = Nonce256::from_bytes([1; 32]);
        let second = Nonce256::from_bytes([2; 32]);
        let third = Nonce256::from_bytes([3; 32]);

        assert!(ledger.issue(&first).is_ok());
        assert!(matches!(
            ledger.issue(&first),
            Err(CryptoError::BindingMismatch { .. })
        ));
        assert!(ledger.issue(&second).is_ok());
        assert!(matches!(
            ledger.issue(&third),
            Err(CryptoError::TooLarge { .. })
        ));

        assert!(ledger.consume(&first).is_ok());
        // Consuming frees the slot but never makes the nonce usable again, by either route.
        assert!(matches!(
            ledger.consume(&first),
            Err(CryptoError::BindingMismatch { .. })
        ));
        assert!(matches!(
            ledger.issue(&first),
            Err(CryptoError::BindingMismatch {
                what: "a reissued connection challenge"
            })
        ));
        assert!(ledger.issue(&third).is_ok());
        ledger.abandon(&second);
        assert!(matches!(
            ledger.consume(&second),
            Err(CryptoError::BindingMismatch { .. })
        ));
        assert_eq!(ledger.len(), 1);
        assert!(!ledger.is_empty());
    }

    #[test]
    fn the_ledger_stays_bounded_across_many_connections() {
        let mut ledger = ChallengeLedger::with_limit(4);
        for index in 0..1_000u32 {
            let nonce = Nonce256::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                bytes
            });
            ledger.issue(&nonce).expect("issued");
            if index % 2 == 0 {
                ledger.consume(&nonce).expect("consumed");
            } else {
                ledger.abandon(&nonce);
            }
        }
        assert_eq!(ledger.len(), 0);
        assert!(ledger.retained_consumed() <= 4);
    }

    /// KR-REQ-23.16: a set of proofs is accepted once.
    #[test]
    fn one_set_of_proofs_is_accepted_once() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        let mut ledger = ChallengeLedger::with_limit(4);
        ledger.issue(&fixture.selection.host_nonce).expect("issued");

        assert!(
            verify_connect_once(
                &mut ledger,
                &fixture.selection.host_nonce,
                &fixture.offer,
                &fixture.selection,
                &fixture.client,
                &fixture.host,
                &fixture.client.endpoint_id,
                &fixture.host.endpoint_id,
                &proofs,
            )
            .is_ok()
        );
        assert!(matches!(
            verify_connect_once(
                &mut ledger,
                &fixture.selection.host_nonce,
                &fixture.offer,
                &fixture.selection,
                &fixture.client,
                &fixture.host,
                &fixture.client.endpoint_id,
                &fixture.host.endpoint_id,
                &proofs,
            ),
            Err(CryptoError::BindingMismatch {
                what: "a connection challenge that is not outstanding"
            })
        ));
    }

    /// KR-REQ-23.16: another connection's challenge is refused.
    #[test]
    fn another_connections_challenge_is_rejected() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        let mut ledger = ChallengeLedger::with_limit(4);
        let other = Nonce256::from_bytes([42; 32]);
        ledger.issue(&other).expect("issued");
        assert!(matches!(
            verify_connect_once(
                &mut ledger,
                &other,
                &fixture.offer,
                &fixture.selection,
                &fixture.client,
                &fixture.host,
                &fixture.client.endpoint_id,
                &fixture.host.endpoint_id,
                &proofs,
            ),
            Err(CryptoError::BindingMismatch {
                what: "the host challenge, which is not the one this connection issued"
            })
        ));
    }

    /// KR-REQ-23.16: a selection outside what was offered is refused.
    #[test]
    fn a_selection_outside_the_offer_is_rejected() {
        let mut fixture = fixture();
        fixture.selection.selected_version = kr_protocol::hello::ProtocolVersion::new(9, 0);
        let proofs = proofs(&fixture);
        assert!(matches!(
            verify(&fixture, &proofs),
            Err(CryptoError::BindingMismatch {
                what: "the selected protocol version, which the client did not offer"
            })
        ));
    }

    /// KR-REQ-23.16: a limit above what the client offered is refused.
    #[test]
    fn a_limit_above_what_the_client_offered_is_rejected() {
        let mut fixture = fixture();
        fixture.selection.limits.max_control_frame_len = kr_protocol::scalars::U64::new(
            fixture.offer.max_receive.max_control_frame_len.get() + 1,
        );
        let proofs = proofs(&fixture);
        assert!(matches!(
            verify(&fixture, &proofs),
            Err(CryptoError::BindingMismatch {
                what: "a negotiated limit above what the client offered to receive"
            })
        ));
    }
}
