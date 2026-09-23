//! The authenticated bundle exchange that follows mutual confirmation.
//!
//! Section 10: after both confirmation tags verify, the two devices exchange their key bundles
//! through XChaCha20-Poly1305 under the two directional keys. Each message carries a fresh 24-byte
//! nonce and a sequence number, and its additional authenticated data is deterministic CBOR
//! holding the protocol domain, `T`, the direction, the sequence number and the message type. A
//! replayed sequence number and an unexpected phase are rejected, an individual frame cannot
//! exceed 64 KiB, and the whole exchange stays below 256 KiB.
//!
//! The encryption authenticates the bundle; the signature inside it binds the key-purpose
//! declarations to the authorisation key. Both are required: without the signature a device could
//! declare someone else's public key under one of its purposes, and without the encryption the
//! service would see the bundle.

use kr_cbor::CanonicalValue;
use kr_crypto::aead;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::secret::SymmetricKey;
use kr_crypto::sign::{self, SigningTranscript};
use kr_protocol::ids::PairingSequence;
use kr_protocol::pairing::DevicePublicKeys;
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, CLIENT_BUNDLE_DOMAIN, ClientBundle, HOST_BUNDLE_DOMAIN,
    HostBundle, MAX_PAIRING_EXCHANGE_LEN, MAX_PAIRING_FRAME_LEN, SignedClientBundle,
    SignedHostBundle, bundle_aad,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, EndpointKey, Nonce192};

use crate::error::{PairingError, Result};

/// One encrypted message of the bundle exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFrame {
    /// Which direction it travels.
    pub direction: BundleDirection,
    /// Its position in the exchange.
    pub sequence: PairingSequence,
    /// What it carries.
    pub message_type: BundleMessageType,
    /// The fresh 24-byte nonce.
    pub nonce: Nonce192,
    /// The ciphertext.
    pub ciphertext: Vec<u8>,
}

impl BundleFrame {
    /// Returns the size this frame counts against the exchange limit.
    ///
    /// It is the ciphertext plus the nonce, which is what actually travels; the direction, the
    /// sequence and the message type are authenticated rather than sent, because the receiver
    /// knows which phase it is in.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.ciphertext.len() + Nonce192::LEN
    }
}

/// Counts what one attempt has sent and received.
///
/// One counter per direction, and one total. Section 10 bounds the exchange as a whole, not each
/// message, so a peer cannot stay under the frame limit and send an unbounded number of frames.
#[derive(Debug, Default)]
pub struct ExchangeBudget {
    sent: u64,
    received: u64,
    total_bytes: usize,
}

impl ExchangeBudget {
    /// Creates an empty budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the sequence number the next outbound message uses, and records it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::TooLarge`] when the exchange has no room left.
    pub fn next_outbound(&mut self, size: usize) -> Result<PairingSequence> {
        self.charge(size)?;
        let sequence = PairingSequence::new(self.sent);
        self.sent += 1;
        Ok(sequence)
    }

    /// Accepts an inbound sequence number, which must be the next one in that direction.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ReplayedSequence`] when it repeats or skips, and
    /// [`PairingError::TooLarge`] when the exchange has no room left.
    pub fn accept_inbound(&mut self, sequence: PairingSequence, size: usize) -> Result<()> {
        if sequence.get() != self.received {
            return Err(PairingError::ReplayedSequence {
                sequence: sequence.get(),
            });
        }
        self.charge(size)?;
        self.received += 1;
        Ok(())
    }

    /// Returns how many bytes the exchange has used.
    #[must_use]
    pub const fn used_bytes(&self) -> usize {
        self.total_bytes
    }

    fn charge(&mut self, size: usize) -> Result<()> {
        if size > MAX_PAIRING_FRAME_LEN {
            return Err(PairingError::TooLarge {
                what: "a pairing frame",
                limit: MAX_PAIRING_FRAME_LEN,
                actual: size,
            });
        }
        let total = self.total_bytes.saturating_add(size);
        if total > MAX_PAIRING_EXCHANGE_LEN {
            return Err(PairingError::TooLarge {
                what: "the pairing bundle exchange",
                limit: MAX_PAIRING_EXCHANGE_LEN,
                actual: total,
            });
        }
        self.total_bytes = total;
        Ok(())
    }
}

/// Checks that a bundle's declared endpoint is the transport key it also declares.
///
/// Section 10 pairs an endpoint identity with a complete purpose-key bundle whose transport member
/// *is* that endpoint. Letting the two differ would give a candidate two identities: one the
/// connection authenticates and one the device record is written from, and a later connection to
/// the second would be to a device nobody proved possession of. The check runs on both sides: a
/// signer cannot build an inconsistent bundle and a receiver will not accept one.
///
/// It also rejects a bundle that reuses one key under two purposes, because purpose separation is
/// what stops a transport key being usable as an authorisation key.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`].
pub fn require_consistent_host_bundle(bundle: &HostBundle) -> Result<()> {
    require_consistent_keys(
        &bundle.keys,
        &bundle.endpoint_id,
        "the endpoint a host bundle declares, which is not its own transport key",
    )
}

/// Checks the same of a client bundle.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`].
pub fn require_consistent_client_bundle(bundle: &ClientBundle) -> Result<()> {
    require_consistent_keys(
        &bundle.keys,
        &bundle.endpoint_id,
        "the endpoint a client bundle declares, which is not its own transport key",
    )
}

/// Checks a declared endpoint against a key bundle, whichever side declared them.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`].
pub fn require_consistent_keys(
    keys: &DevicePublicKeys,
    endpoint_id: &EndpointKey,
    mismatch: &'static str,
) -> Result<()> {
    if !keys.purposes_are_distinct() {
        return Err(PairingError::ContextMismatch {
            what: "the key purposes of a bundle, two of which share a key",
        });
    }
    if keys.transport != *endpoint_id {
        return Err(PairingError::ContextMismatch { what: mismatch });
    }
    Ok(())
}

/// Signs a host bundle over `CBOR(["kr-pair/host-bundle/1", bundle, T])`.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when the bundle's endpoint is not its own transport
/// key, an encoding error when it is outside KR-CBOR-1, and a library error when libsodium fails.
pub fn sign_host_bundle(
    key: &AuthorisationKeyPair,
    bundle: HostBundle,
    transcript: Digest256,
) -> Result<SignedHostBundle> {
    require_consistent_host_bundle(&bundle)?;
    let signature = sign::sign(
        key,
        &bundle_transcript(HOST_BUNDLE_DOMAIN, &bundle, transcript)?,
    )?;
    Ok(SignedHostBundle {
        bundle,
        transcript,
        signature,
    })
}

/// Signs a client bundle over `CBOR(["kr-pair/client-bundle/1", bundle, T])`.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when the bundle's endpoint is not its own transport
/// key, an encoding error when it is outside KR-CBOR-1, and a library error when libsodium fails.
pub fn sign_client_bundle(
    key: &AuthorisationKeyPair,
    bundle: ClientBundle,
    transcript: Digest256,
) -> Result<SignedClientBundle> {
    require_consistent_client_bundle(&bundle)?;
    let signature = sign::sign(
        key,
        &bundle_transcript(CLIENT_BUNDLE_DOMAIN, &bundle, transcript)?,
    )?;
    Ok(SignedClientBundle {
        bundle,
        transcript,
        signature,
    })
}

/// Verifies a signed host bundle against the transcript this attempt produced.
///
/// The signature is checked against the authorisation key the bundle itself declares, which is the
/// point: it binds that declaration to the key that made it. Whether the device may be paired at
/// all is the owner's decision, later.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when the bundle names another transcript and
/// [`PairingError::AuthenticationFailed`] when the signature does not verify.
pub fn verify_host_bundle(signed: &SignedHostBundle, transcript: Digest256) -> Result<()> {
    if signed.transcript != transcript {
        return Err(PairingError::ContextMismatch {
            what: "the transcript a host bundle names",
        });
    }
    require_consistent_host_bundle(&signed.bundle)?;
    verify_bundle_signature(
        HOST_BUNDLE_DOMAIN,
        &signed.bundle,
        transcript,
        &signed.bundle.keys.authorisation,
        &signed.signature,
    )
}

/// Verifies a signed client bundle against the transcript this attempt produced.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] or [`PairingError::AuthenticationFailed`].
pub fn verify_client_bundle(signed: &SignedClientBundle, transcript: Digest256) -> Result<()> {
    if signed.transcript != transcript {
        return Err(PairingError::ContextMismatch {
            what: "the transcript a client bundle names",
        });
    }
    require_consistent_client_bundle(&signed.bundle)?;
    verify_bundle_signature(
        CLIENT_BUNDLE_DOMAIN,
        &signed.bundle,
        transcript,
        &signed.bundle.keys.authorisation,
        &signed.signature,
    )
}

fn bundle_transcript<T: serde::Serialize>(
    domain: &str,
    bundle: &T,
    transcript: Digest256,
) -> Result<SigningTranscript> {
    Ok(SigningTranscript::from_elements(
        domain,
        vec![
            kr_cbor::to_canonical_value(bundle)?,
            CanonicalValue::bytes(transcript.as_bytes().as_slice()),
        ],
    ))
}

fn verify_bundle_signature<T: serde::Serialize>(
    domain: &str,
    bundle: &T,
    transcript: Digest256,
    public: &AuthorisationKey,
    signature: &kr_protocol::scalars::Signature64,
) -> Result<()> {
    sign::verify(
        public,
        &bundle_transcript(domain, bundle, transcript)?,
        signature,
    )
    .map_err(|_| PairingError::AuthenticationFailed)
}

/// Seals one bundle message.
///
/// The nonce is generated inside the AEAD wrapper, so no caller can repeat one, and the sequence
/// number comes from the budget, so no caller can repeat one of those either.
///
/// # Errors
///
/// Returns an encoding error, a library error, or [`PairingError::TooLarge`] when the message or
/// the exchange is over its bound.
pub fn seal_bundle<T: serde::Serialize>(
    key: &SymmetricKey,
    transcript: Digest256,
    message_type: BundleMessageType,
    budget: &mut ExchangeBudget,
    bundle: &T,
) -> Result<BundleFrame> {
    let direction = message_type.direction();
    let plaintext = kr_cbor::to_canonical_vec(bundle)?;
    // The size is charged before the sequence number is issued, so a message that does not fit
    // does not consume one.
    let sequence = budget.next_outbound(aead::sealed_len(plaintext.len()) + Nonce192::LEN)?;
    let aad = bundle_aad(transcript, direction, sequence, message_type);
    let (nonce, ciphertext) = aead::seal(key, &aad, &plaintext)?;
    Ok(BundleFrame {
        direction,
        sequence,
        message_type,
        nonce,
        ciphertext,
    })
}

/// Opens one bundle message, checking its direction, phase and sequence number.
///
/// `expected` is the message type the state machine is waiting for. A frame of any other type is
/// an unexpected phase, which section 10 rejects rather than buffering.
///
/// # Errors
///
/// Returns [`PairingError::WrongPhase`], [`PairingError::ReplayedSequence`],
/// [`PairingError::TooLarge`] or [`PairingError::AuthenticationFailed`].
pub fn open_bundle<T: serde::de::DeserializeOwned + serde::Serialize>(
    key: &SymmetricKey,
    transcript: Digest256,
    expected: BundleMessageType,
    budget: &mut ExchangeBudget,
    frame: &BundleFrame,
) -> Result<T> {
    if frame.message_type != expected || frame.direction != expected.direction() {
        return Err(PairingError::WrongPhase {
            expected: expected.as_str(),
            actual: frame.message_type.as_str(),
        });
    }
    budget.accept_inbound(frame.sequence, frame.wire_len())?;
    let aad = bundle_aad(
        transcript,
        frame.direction,
        frame.sequence,
        frame.message_type,
    );
    let plaintext = aead::open(key, &frame.nonce, &aad, &frame.ciphertext)
        .map_err(|_| PairingError::AuthenticationFailed)?;
    Ok(kr_cbor::from_canonical_slice(
        plaintext.expose(),
        &kr_cbor::Limits::DEFAULT,
    )?)
}

/// Returns the SHA-256 of a bundle's canonical encoding.
///
/// `pair.finish` and the verification value both name the two bundle hashes, and this is what they
/// name: the bundle itself, not the signed wrapper, so the hash does not change when a signature
/// is recomputed.
///
/// # Errors
///
/// Returns an encoding error when the bundle is outside KR-CBOR-1.
pub fn bundle_hash<T: serde::Serialize>(bundle: &T) -> Result<Digest256> {
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(bundle)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{DeviceId, DeviceKeyRevision, InvitationId};
    use kr_protocol::pairing::{DeviceName, DevicePlatform, NetworkConfig, ProposedGrant};
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    fn transcript() -> Digest256 {
        Digest256::from_bytes([7; 32])
    }

    fn host_bundle(keys: &DeviceKeys) -> HostBundle {
        HostBundle {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            device_key_revision: DeviceKeyRevision::new(1),
            endpoint_id: *keys.transport.public(),
            keys: keys.public_keys(),
            network_config: NetworkConfig::empty(),
            proposed_grant: ProposedGrant {
                parent_grant_id: Nullable::null(),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: CanonicalSet::new(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            },
        }
    }

    fn client_bundle(keys: &DeviceKeys) -> ClientBundle {
        ClientBundle {
            endpoint_id: *keys.transport.public(),
            keys: keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            device_name: DeviceName::new("A laptop").expect("a name"),
            platform: DevicePlatform::Macos,
        }
    }

    /// KR-REQ-10.26: host and client bundles carry their declared contents, each signed with its
    /// own authorisation key, and a signature over another transcript is refused.
    #[test]
    fn a_bundle_round_trips_through_the_exchange() {
        let host_keys = DeviceKeys::generate().expect("keys");
        let client_keys = DeviceKeys::generate().expect("keys");
        let key = SymmetricKey::random().expect("a key");
        let mut sender = ExchangeBudget::new();
        let mut receiver = ExchangeBudget::new();

        let signed = sign_host_bundle(
            &host_keys.authorisation,
            host_bundle(&host_keys),
            transcript(),
        )
        .expect("a signed bundle");
        let frame = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");
        assert_eq!(frame.direction, BundleDirection::HostToClient);
        assert_eq!(frame.sequence.get(), 0);

        let opened: SignedHostBundle = open_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut receiver,
            &frame,
        )
        .expect("the bundle");
        assert_eq!(opened, signed);
        assert!(verify_host_bundle(&opened, transcript()).is_ok());

        // The client's bundle travels the other way and verifies against its own key.
        let signed_client = sign_client_bundle(
            &client_keys.authorisation,
            client_bundle(&client_keys),
            transcript(),
        )
        .expect("a signed bundle");
        assert!(verify_client_bundle(&signed_client, transcript()).is_ok());
        assert!(verify_client_bundle(&signed_client, Digest256::from_bytes([9; 32])).is_err());
    }

    /// KR-REQ-10.25: a replayed sequence number is refused.
    #[test]
    fn a_replayed_frame_is_rejected() {
        let keys = DeviceKeys::generate().expect("keys");
        let key = SymmetricKey::random().expect("a key");
        let mut sender = ExchangeBudget::new();
        let mut receiver = ExchangeBudget::new();
        let signed = sign_host_bundle(&keys.authorisation, host_bundle(&keys), transcript())
            .expect("a signed bundle");
        let frame = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");

        let _: SignedHostBundle = open_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut receiver,
            &frame,
        )
        .expect("the bundle");
        assert!(matches!(
            open_bundle::<SignedHostBundle>(
                &key,
                transcript(),
                BundleMessageType::HostBundle,
                &mut receiver,
                &frame,
            ),
            Err(PairingError::ReplayedSequence { sequence: 0 })
        ));
    }

    /// KR-REQ-10.25: a frame from another phase is refused.
    #[test]
    fn a_frame_of_another_type_is_an_unexpected_phase() {
        let keys = DeviceKeys::generate().expect("keys");
        let key = SymmetricKey::random().expect("a key");
        let mut sender = ExchangeBudget::new();
        let mut receiver = ExchangeBudget::new();
        let signed = sign_host_bundle(&keys.authorisation, host_bundle(&keys), transcript())
            .expect("a signed bundle");
        let frame = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");
        assert!(matches!(
            open_bundle::<SignedClientBundle>(
                &key,
                transcript(),
                BundleMessageType::ClientBundle,
                &mut receiver,
                &frame,
            ),
            Err(PairingError::WrongPhase { .. })
        ));
    }

    /// KR-REQ-10.24: `T` is inside the additional data, so a frame from another attempt fails.
    #[test]
    fn a_frame_from_another_attempt_does_not_authenticate() {
        let keys = DeviceKeys::generate().expect("keys");
        let key = SymmetricKey::random().expect("a key");
        let mut sender = ExchangeBudget::new();
        let mut receiver = ExchangeBudget::new();
        let signed = sign_host_bundle(&keys.authorisation, host_bundle(&keys), transcript())
            .expect("a signed bundle");
        let frame = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");
        // The transcript is inside the additional data, so the same frame under another attempt
        // fails to authenticate rather than decrypting.
        assert!(matches!(
            open_bundle::<SignedHostBundle>(
                &key,
                Digest256::from_bytes([8; 32]),
                BundleMessageType::HostBundle,
                &mut receiver,
                &frame,
            ),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    /// KR-REQ-10.25: a frame over 64 KiB is refused.
    #[test]
    fn a_frame_over_the_limit_is_refused_without_consuming_a_sequence_number() {
        let mut budget = ExchangeBudget::new();
        assert!(matches!(
            budget.next_outbound(MAX_PAIRING_FRAME_LEN + 1),
            Err(PairingError::TooLarge {
                what: "a pairing frame",
                ..
            })
        ));
        assert_eq!(budget.used_bytes(), 0);
        assert_eq!(budget.next_outbound(16).expect("a sequence").get(), 0);
    }

    /// KR-REQ-10.25: the whole exchange stays within 256 KiB.
    #[test]
    fn the_exchange_is_bounded_as_a_whole() {
        let mut budget = ExchangeBudget::new();
        let mut sent = 0usize;
        loop {
            match budget.next_outbound(MAX_PAIRING_FRAME_LEN) {
                Ok(_) => sent += MAX_PAIRING_FRAME_LEN,
                Err(PairingError::TooLarge {
                    what: "the pairing bundle exchange",
                    ..
                }) => break,
                Err(error) => panic!("unexpected {error}"),
            }
        }
        assert_eq!(sent, MAX_PAIRING_EXCHANGE_LEN);
        assert_eq!(budget.used_bytes(), MAX_PAIRING_EXCHANGE_LEN);
        assert_eq!(MAX_PAIRING_EXCHANGE_LEN, 256 * 1024);
        assert_eq!(MAX_PAIRING_FRAME_LEN, 64 * 1024);
    }

    /// KR-REQ-10.24: each bundle message is XChaCha20-Poly1305 under a fresh 24-byte nonce and the
    /// next sequence number, with CBOR([domain, T, direction, sequence, type]) as its additional
    /// data. The ciphertext opens under exactly that data and under no other direction, sequence,
    /// type or transcript.
    #[test]
    fn every_message_has_a_fresh_nonce_the_next_sequence_and_all_of_its_additional_data() {
        let keys = DeviceKeys::generate().expect("keys");
        let key = SymmetricKey::random().expect("a key");
        let mut sender = ExchangeBudget::new();
        let signed = sign_host_bundle(&keys.authorisation, host_bundle(&keys), transcript())
            .expect("a signed bundle");
        let first = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");
        let second = seal_bundle(
            &key,
            transcript(),
            BundleMessageType::HostBundle,
            &mut sender,
            &signed,
        )
        .expect("a frame");
        assert_eq!(first.nonce.as_bytes().len(), 24);
        assert_ne!(first.nonce, second.nonce, "every message has a fresh nonce");
        assert_eq!(first.sequence.get(), 0);
        assert_eq!(second.sequence.get(), 1);
        let plaintext = kr_cbor::to_canonical_vec(&signed).expect("canonical bytes");
        assert_eq!(
            first.ciphertext.len(),
            plaintext.len() + aead::TAG_LEN,
            "an AEAD ciphertext is the plaintext and its tag"
        );

        let aad = bundle_aad(
            transcript(),
            first.direction,
            first.sequence,
            first.message_type,
        );
        let CanonicalValue::Array(members) =
            kr_cbor::decode(&aad, &kr_cbor::Limits::DEFAULT).expect("canonical")
        else {
            panic!("the additional data is an array");
        };
        assert_eq!(
            members,
            vec![
                CanonicalValue::text(kr_protocol::pairing::PAIRING_DOMAIN),
                CanonicalValue::bytes(transcript().as_bytes().as_slice()),
                CanonicalValue::text("host_to_client"),
                CanonicalValue::Integer(0u64.into()),
                CanonicalValue::text(BundleMessageType::HostBundle.as_str()),
            ]
        );
        assert!(aead::open(&key, &first.nonce, &aad, &first.ciphertext).is_ok());
        for other in [
            bundle_aad(
                transcript(),
                BundleDirection::ClientToHost,
                first.sequence,
                first.message_type,
            ),
            bundle_aad(
                transcript(),
                first.direction,
                second.sequence,
                first.message_type,
            ),
            bundle_aad(
                transcript(),
                first.direction,
                first.sequence,
                BundleMessageType::ClientBundle,
            ),
            bundle_aad(
                Digest256::from_bytes([8; 32]),
                first.direction,
                first.sequence,
                first.message_type,
            ),
        ] {
            assert!(aead::open(&key, &first.nonce, &other, &first.ciphertext).is_err());
        }
    }

    /// KR-REQ-10.26: each device signs exactly CBOR([domain, its bundle, T]) with the authorisation
    /// key its bundle declares, so the signature binds the key-purpose declarations to that key and
    /// to this transcript.
    #[test]
    fn a_bundle_signature_covers_the_declarations_and_the_transcript() {
        let host_keys = DeviceKeys::generate().expect("keys");
        let client_keys = DeviceKeys::generate().expect("keys");
        let host = sign_host_bundle(
            &host_keys.authorisation,
            host_bundle(&host_keys),
            transcript(),
        )
        .expect("a signed bundle");
        let client = sign_client_bundle(
            &client_keys.authorisation,
            client_bundle(&client_keys),
            transcript(),
        )
        .expect("a signed bundle");
        for (domain, bundle, declared, signature) in [
            (
                HOST_BUNDLE_DOMAIN,
                kr_cbor::to_canonical_value(&host.bundle).expect("a value"),
                host.bundle.keys.authorisation,
                host.signature,
            ),
            (
                CLIENT_BUNDLE_DOMAIN,
                kr_cbor::to_canonical_value(&client.bundle).expect("a value"),
                client.bundle.keys.authorisation,
                client.signature,
            ),
        ] {
            let exact = SigningTranscript::from_elements(
                domain,
                vec![
                    bundle.clone(),
                    CanonicalValue::bytes(transcript().as_bytes().as_slice()),
                ],
            );
            assert!(sign::verify(&declared, &exact, &signature).is_ok());
            let elsewhere = SigningTranscript::from_elements(
                domain,
                vec![bundle, CanonicalValue::bytes([8u8; 32].as_slice())],
            );
            assert!(sign::verify(&declared, &elsewhere, &signature).is_err());
        }
    }

    #[test]
    fn a_bundle_hash_covers_the_bundle_and_not_its_signature() {
        let keys = DeviceKeys::generate().expect("keys");
        let bundle = host_bundle(&keys);
        let first = sign_host_bundle(&keys.authorisation, bundle.clone(), transcript())
            .expect("a signed bundle");
        let second = sign_host_bundle(&keys.authorisation, bundle.clone(), transcript())
            .expect("a signed bundle");
        assert_eq!(
            bundle_hash(&first.bundle).expect("a hash"),
            bundle_hash(&second.bundle).expect("a hash")
        );
        let mut other = bundle;
        other.device_key_revision = DeviceKeyRevision::new(2);
        assert_ne!(
            bundle_hash(&first.bundle).expect("a hash"),
            bundle_hash(&other).expect("a hash")
        );
    }

    /// KR-REQ-10.26: substituted keys or a substituted endpoint do not verify.
    #[test]
    fn a_bundle_whose_keys_were_substituted_does_not_verify() {
        let keys = DeviceKeys::generate().expect("keys");
        let impostor = DeviceKeys::generate().expect("keys");
        let mut signed = sign_host_bundle(&keys.authorisation, host_bundle(&keys), transcript())
            .expect("a signed bundle");
        // Declaring another device's keys under this bundle leaves the endpoint disagreeing with
        // the transport key, which is refused before the signature is even considered.
        signed.bundle.keys = impostor.public_keys();
        assert!(matches!(
            verify_host_bundle(&signed, transcript()),
            Err(PairingError::ContextMismatch { .. })
        ));
        // Substituting the endpoint too makes the bundle self-consistent, and then the signature
        // is what refuses it: it covers the declaration and is checked against the declared key.
        signed.bundle.endpoint_id = *impostor.transport.public();
        assert!(matches!(
            verify_host_bundle(&signed, transcript()),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    /// KR-REQ-10.26: a bundle must declare its own transport key as its endpoint.
    #[test]
    fn a_bundle_must_declare_its_own_transport_key_as_its_endpoint() {
        let keys = DeviceKeys::generate().expect("keys");
        let impostor = DeviceKeys::generate().expect("keys");

        let mut bundle = host_bundle(&keys);
        bundle.endpoint_id = *impostor.transport.public();
        assert!(
            matches!(
                sign_host_bundle(&keys.authorisation, bundle, transcript()),
                Err(PairingError::ContextMismatch { .. })
            ),
            "a signer cannot build an inconsistent bundle either"
        );

        let mut bundle = client_bundle(&keys);
        bundle.endpoint_id = *impostor.transport.public();
        assert!(matches!(
            sign_client_bundle(&keys.authorisation, bundle, transcript()),
            Err(PairingError::ContextMismatch { .. })
        ));
    }

    /// KR-REQ-10.26, KR-REQ-10.03: a bundle declaring one key under two purposes is refused.
    #[test]
    fn a_bundle_that_reuses_one_key_under_two_purposes_is_refused() {
        let keys = DeviceKeys::generate().expect("keys");
        let mut bundle = client_bundle(&keys);
        // The notification-preview key becomes the stored-envelope key: one key, two purposes.
        bundle.keys.notification_preview = kr_protocol::scalars::NotificationPreviewKey::from_bytes(
            *bundle.keys.stored_envelope.as_bytes(),
        );
        assert!(matches!(
            sign_client_bundle(&keys.authorisation, bundle, transcript()),
            Err(PairingError::ContextMismatch { .. })
        ));
    }
}
