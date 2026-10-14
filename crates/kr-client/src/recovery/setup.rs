//! Setting a host's backups up: the recovery kit, the bundle that goes with it, and the call that
//! gives the host what it keeps of them.
//!
//! The kit is made in the process that prints it. [`prepare_setup`] draws the seed and the bundle's
//! locator, seals the bundle under the key the seed, the origin and the locator derive, and builds
//! the one request the host's daemon is given. The daemon is given the recovery recipient's public
//! key, the locator and the sealed bundle, and never the seed: nothing in [`PreparedSetup::params`]
//! can open the bundle or a backup.
//!
//! The kit carries the origin as the daemon holds it, byte for byte, because the bundle's key is
//! derived from that text and a restore compares it byte for byte with the origin the restoring
//! host is configured for.
//!
//! # The fingerprint
//!
//! A person matches a kit to a host by [`kit_fingerprint`]: eight symbols of a domain-separated hash
//! of the recovery recipient's public key. It says nothing of the seed, and it identifies a kit only
//! if the person keeps it with the kit. The host keeps it with its setup, and `kr doctor` shows it.

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{
    CollectionLocator, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryContext,
    TrustedProducer, TrustedWriter,
};
use kr_protocol::backup_setup::BackupEnableParams;
use kr_protocol::ids::ArchiveId;
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, KeyId, StoredEnvelopeKey, TimestampMs, U64, Uuid,
};
use zeroize::Zeroizing;

use crate::recovery::bundle::fresh_locator;
use crate::recovery::kit::{ALPHABET, render_kit};
use crate::recovery::{RecoveryError, Result};

/// The domain the fingerprint's hash is taken in.
const FINGERPRINT_DOMAIN: &[u8] = b"kalareach-recovery-kit-fingerprint/1";

/// Symbols in a fingerprint.
const FINGERPRINT_SYMBOLS: usize = 8;

/// The fingerprint that matches a kit to a host: eight symbols of the recovery alphabet, in two
/// groups of four, of a hash of the recovery recipient's public key.
#[must_use]
pub fn kit_fingerprint(recovery_public_key: &StoredEnvelopeKey) -> String {
    let mut hashed = Vec::with_capacity(FINGERPRINT_DOMAIN.len() + 32);
    hashed.extend_from_slice(FINGERPRINT_DOMAIN);
    hashed.extend_from_slice(recovery_public_key.as_bytes());
    let digest = kr_cbor::sha256(&hashed);
    let mut out = String::with_capacity(FINGERPRINT_SYMBOLS + 1);
    for index in 0..FINGERPRINT_SYMBOLS {
        if index == FINGERPRINT_SYMBOLS / 2 {
            out.push('-');
        }
        // Five bits a symbol, counting from the first bit of the digest.
        let mut value = 0u8;
        for offset in 0..5 {
            let bit = index * 5 + offset;
            value = (value << 1) | ((digest[bit / 8] >> (7 - bit % 8)) & 1);
        }
        out.push(char::from(ALPHABET[usize::from(value)]));
    }
    out
}

/// What a setup is made from.
#[derive(Clone)]
pub struct SetupInputs<'a> {
    /// The storage service's origin, exactly as the host's daemon holds it.
    pub origin: &'a str,
    /// The archive the backups will be of, drawn by the caller.
    pub archive_id: ArchiveId,
    /// The host's backup writer, by identifier and public key.
    pub writer: (KeyId, AuthorisationKey),
    /// The host's producer, by identifier and public key.
    pub producer: (KeyId, StoredEnvelopeKey),
    /// The instant the setup is made at, which the writer's and the producer's entries carry.
    pub enabled_at_ms: TimestampMs,
    /// Whether this replaces backups that are set up for another archive.
    pub replace: bool,
}

/// A setup made and not yet sent.
pub struct PreparedSetup {
    /// The kit, rendered. It holds the seed and is cleared when dropped.
    pub kit: Zeroizing<String>,
    /// The fingerprint that matches the kit to the host.
    pub kit_fingerprint: String,
    /// The one call the host's daemon is given.
    pub params: BackupEnableParams,
}

impl std::fmt::Debug for SetupInputs<'_> {
    /// Which value it is. The origin and the keys are not shown.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SetupInputs")
            .finish_non_exhaustive()
    }
}

crate::debug_as_name!(PreparedSetup);

/// Draws a seed and a locator, and builds the kit, the sealed bundle and the call that carry them.
///
/// The bundle names the collection (the origin, the archive's identifier in its canonical
/// spelling, and the archive), the host's writer and the host's producer, and no checkpoint: the
/// host holds no seed, so it cannot advance one. It is revision one.
///
/// # Errors
///
/// Returns [`RecoveryError::Crypto`] when the system cannot draw random bytes or the keys cannot
/// be derived, [`RecoveryError::UnprintableKit`] and [`RecoveryError::KitTooLarge`] for an origin
/// the kit cannot hold, and [`RecoveryError::Service`] when no locator can be drawn.
pub fn prepare_setup(inputs: &SetupInputs<'_>) -> Result<PreparedSetup> {
    let seed = RecoverySeed::generate()?;
    let locator = fresh_locator()?;
    let kit = seed.to_kit(vec![inputs.origin.to_owned()], locator.clone());
    let rendered = render_kit(&kit)?;

    let context = RecoveryContext {
        service_origin: inputs.origin.to_owned(),
        bundle_locator: locator.clone(),
    };
    let bundle = RecoveryBundle {
        schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
        collections: vec![CollectionLocator {
            service_origin: inputs.origin.to_owned(),
            locator: inputs.archive_id.to_string(),
            archive_id: inputs.archive_id,
        }],
        trusted_writers: std::iter::once(TrustedWriter {
            writer_key_id: inputs.writer.0,
            signing_key: inputs.writer.1,
            enrolled_at_ms: inputs.enabled_at_ms,
        })
        .collect(),
        trusted_producers: std::iter::once(TrustedProducer {
            sender_key_id: inputs.producer.0,
            stored_envelope_key: inputs.producer.1,
            enrolled_at_ms: inputs.enabled_at_ms,
        })
        .collect(),
        checkpoints: std::iter::empty().collect(),
        revision: U64::new(1),
        written_at_ms: inputs.enabled_at_ms,
    };
    let key = seed.bundle_key_for(&context)?;
    let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle)?;

    let recipient = *seed.recipient()?.public();
    let fingerprint = kit_fingerprint(&recipient);
    let bundle_locator = locator
        .parse::<Uuid>()
        .map_err(|_| RecoveryError::MalformedKit {
            what: "a bundle locator that is not an identifier",
        })?;
    Ok(PreparedSetup {
        kit: rendered,
        kit_fingerprint: fingerprint.clone(),
        params: BackupEnableParams {
            archive_id: inputs.archive_id,
            recovery_public_key: recipient,
            kit_fingerprint: fingerprint,
            bundle_locator,
            sealed_bundle: Bytes::new(sealed),
            request_id: kr_transport::random::fresh_uuid_v4()
                .map_err(crate::error::ClientError::from)?,
            enabled_at_ms: inputs.enabled_at_ms,
            writer_key_id: inputs.writer.0,
            producer_key_id: inputs.producer.0,
            replace: inputs.replace,
        },
    })
}

#[cfg(test)]
mod tests {
    use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::recovery::files::kit_origin_for;
    use crate::recovery::kit::parse_kit;

    const ORIGIN: &str = "https://storage.example";

    fn inputs<'a>(
        origin: &'a str,
        writer: &AuthorisationKeyPair,
        producer: &StoredEnvelopeKeyPair,
    ) -> SetupInputs<'a> {
        SetupInputs {
            origin,
            archive_id: ArchiveId::new(Uuid::from_bytes([0x44; 16])),
            writer: (writer.key_id(), *writer.public()),
            producer: (producer.key_id(), *producer.public()),
            enabled_at_ms: TimestampMs::new(1_700_000_000_000),
            replace: false,
        }
    }

    /// A kit that setup made is the kit a restore reads: it parses, its origin is the one the
    /// daemon holds byte for byte (the restore's own check finds it), its checksum holds, and the
    /// bundle in the call opens under the key the kit's seed, origin and locator derive, and names
    /// the writer, the producer and the archive that setup was given and no checkpoint. The
    /// fingerprint is the one the recipient the kit's seed derives has, and the call carries
    /// nothing of the seed.
    #[test]
    fn the_kit_setup_makes_is_the_kit_a_restore_reads() {
        let writer = AuthorisationKeyPair::generate().expect("a key");
        let producer = StoredEnvelopeKeyPair::generate().expect("a key");
        let made = prepare_setup(&inputs(ORIGIN, &writer, &producer)).expect("a setup");

        let kit = parse_kit(&made.kit).expect("the printed kit reads back");
        assert_eq!(
            kit_origin_for(&kit, ORIGIN).as_deref(),
            Some(ORIGIN),
            "the restore's own check finds the origin the daemon holds"
        );
        assert_eq!(kit.bundle_locator, made.params.bundle_locator.to_string());

        let seed = RecoverySeed::from_kit(&kit).expect("the checksum holds");
        let context = kit.context(ORIGIN).expect("the kit names the origin");
        let key = seed.bundle_key_for(&context).expect("a key");
        let bundle =
            kr_crypto::archive::decrypt_recovery_bundle(&key, made.params.sealed_bundle.as_slice())
                .expect("the bundle opens under the kit");
        assert_eq!(bundle.collections.len(), 1);
        assert_eq!(bundle.collections[0].service_origin, ORIGIN);
        assert_eq!(bundle.collections[0].archive_id, made.params.archive_id);
        assert_eq!(
            bundle
                .trusted_writers
                .iter()
                .map(|w| w.writer_key_id)
                .collect::<Vec<_>>(),
            [writer.key_id()]
        );
        assert_eq!(
            bundle
                .trusted_producers
                .iter()
                .map(|p| p.stored_envelope_key)
                .collect::<Vec<_>>(),
            [*producer.public()]
        );
        assert!(bundle.checkpoints.iter().next().is_none());
        assert_eq!(bundle.revision.get(), 1);

        let recipient = *seed.recipient().expect("a recipient").public();
        assert_eq!(made.params.recovery_public_key, recipient);
        assert_eq!(made.kit_fingerprint, kit_fingerprint(&recipient));
        assert_eq!(made.params.kit_fingerprint, made.kit_fingerprint);

        // Nothing the daemon is given opens a bundle or a backup: the seed's bytes are in none of
        // the call's serialised form.
        let wire = serde_json::to_string(&made.params).expect("the call");
        let seed_bytes = kit.seed.expose();
        assert!(!wire.contains(&kr_protocol::scalars::to_base64url(seed_bytes)));
        assert!(
            !made
                .params
                .sealed_bundle
                .as_slice()
                .windows(seed_bytes.len())
                .any(|window| window == seed_bytes.as_slice())
        );
    }

    /// The fingerprint is two groups of four symbols of the recovery alphabet, the same for the
    /// same key and different for another, and a golden value pins it so that the kit a person keeps
    /// matches the host that was set up by a build that wrote it differently.
    #[test]
    fn the_fingerprint_is_eight_symbols_of_the_key() {
        let key = StoredEnvelopeKey::from_bytes([7; 32]);
        let fingerprint = kit_fingerprint(&key);
        assert_eq!(fingerprint.len(), 9);
        assert_eq!(fingerprint.as_bytes()[4], b'-');
        assert!(
            fingerprint
                .chars()
                .filter(|symbol| *symbol != '-')
                .all(|symbol| ALPHABET.contains(&u8::try_from(symbol).expect("ascii")))
        );
        assert_eq!(fingerprint, kit_fingerprint(&key));
        assert_ne!(
            fingerprint,
            kit_fingerprint(&StoredEnvelopeKey::from_bytes([8; 32]))
        );
        assert_eq!(fingerprint, GOLDEN);
    }

    /// Computed apart from this code: SHA-256 of the domain and thirty-two bytes of 0x07, the first
    /// forty bits in the recovery alphabet.
    const GOLDEN: &str = "TEP2-KN9Z";
}
