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
use crate::sign;

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
    let transcript = connect_transcript(offer, selection, client_endpoint_id, host_endpoint_id)?;
    sign::sign_bytes(key, &transcript)
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

    let transcript =
        connect_transcript(offer, selection, live_client_endpoint, live_host_endpoint)?;
    sign::verify_bytes(&client.authorisation, &transcript, &proofs.client)?;
    sign::verify_bytes(&host.authorisation, &transcript, &proofs.host)?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&transcript)))
}

/// Remembers the challenges a host has already admitted, so a transcript cannot be replayed.
///
/// The host allocates its own nonce for every connection, so a replayed transcript needs the
/// host's nonce as well as the client's. Recording the host nonce is therefore sufficient and
/// bounded: one entry per connection the host itself opened.
#[derive(Debug, Default)]
pub struct ChallengeLedger {
    seen: BTreeSet<[u8; 32]>,
    limit: usize,
}

impl ChallengeLedger {
    /// Creates a ledger that remembers at most `limit` challenges.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            limit,
        }
    }

    /// Records a fresh challenge, rejecting one that has already been used.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the challenge has been seen, and
    /// [`CryptoError::TooLarge`] when the ledger is full, which a caller answers by retiring old
    /// connections rather than by forgetting a challenge.
    pub fn admit(&mut self, host_nonce: &Nonce256) -> Result<()> {
        if self.seen.contains(host_nonce.as_bytes()) {
            return Err(CryptoError::BindingMismatch {
                what: "a reused connection challenge",
            });
        }
        if self.seen.len() >= self.limit {
            return Err(CryptoError::TooLarge {
                what: "the connection challenge ledger",
                limit: self.limit,
                actual: self.seen.len() + 1,
            });
        }
        self.seen.insert(*host_nonce.as_bytes());
        Ok(())
    }

    /// Forgets a challenge when its connection has ended.
    pub fn retire(&mut self, host_nonce: &Nonce256) {
        self.seen.remove(host_nonce.as_bytes());
    }

    /// Returns how many challenges are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns true when no challenge is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
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

    #[test]
    fn both_proofs_verify_over_one_transcript() {
        let fixture = fixture();
        let proofs = proofs(&fixture);
        assert!(verify(&fixture, &proofs).is_ok());
    }

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

    #[test]
    fn a_reused_challenge_is_rejected_and_a_retired_one_is_forgotten() {
        let mut ledger = ChallengeLedger::with_limit(2);
        let first = Nonce256::from_bytes([1; 32]);
        let second = Nonce256::from_bytes([2; 32]);
        let third = Nonce256::from_bytes([3; 32]);
        assert!(ledger.admit(&first).is_ok());
        assert!(matches!(
            ledger.admit(&first),
            Err(CryptoError::BindingMismatch { .. })
        ));
        assert!(ledger.admit(&second).is_ok());
        assert!(matches!(
            ledger.admit(&third),
            Err(CryptoError::TooLarge { .. })
        ));
        ledger.retire(&first);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.admit(&third).is_ok());
        assert!(!ledger.is_empty());
    }
}
