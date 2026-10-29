//! Where a notification-preview key is used, and where it is not.
//!
//! A device registers a separate X25519 preview key, and only preview envelopes are sealed to it.
//! A mailbox record, an archive key wrap and a recovery bundle never use it. The types keep the key
//! out of those calls in the first place (`seal_stored_envelope` and `wrap_object_key` take a
//! stored-envelope key, which the preview key is not; their documentation holds that as a compile
//! failure). These cases are for the two ways the types do not reach: the bytes of a preview key
//! made into a stored-envelope key by a caller who means to, and the backup and restore of key
//! material, which are bytes and not types.

use kr_crypto::CryptoError;
use kr_crypto::archive::{encrypt_object, wrap_object_key};
use kr_crypto::backup::{Admission, Material, may_back_up, may_restore, member_material};
use kr_crypto::envelope::{
    PreviewRefusal, open_notification_envelope, pad_notification_preview, seal_envelope,
};
use kr_crypto::keys::{NotificationPreviewKeyPair, StoredEnvelopeKeyPair, key_id};
use kr_crypto::sealed::seal_notification_preview;
use kr_protocol::archive::{KeyWrapContext, KeyWrapFormat, KeyWrapPurpose};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, EnvelopeId};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MailboxPayloadType, SealedEnvelope,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Nullable, StoredEnvelopeKey, TimestampMs, U64, Uuid};

const NOW_MS: u64 = 1_700_000_000_000;
const EXPIRES_MS: u64 = 1_700_000_100_000;

/// The plaintext of an envelope from `sender` to `recipient`, naming the keys by the purpose given.
fn plaintext(
    payload_type: MailboxPayloadType,
    sender: kr_protocol::scalars::KeyId,
    recipient: kr_protocol::scalars::KeyId,
) -> EnvelopePlaintext {
    EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id: EnvelopeId::new(Uuid::from_bytes([7; 16])),
        sender_key_id: sender,
        recipient_key_id: recipient,
        payload_type,
        created_at_ms: TimestampMs::new(NOW_MS),
        expires_at_ms: TimestampMs::new(EXPIRES_MS),
        grant_id: Nullable::null(),
        environment_id: Nullable::null(),
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        thread_id: Nullable::null(),
        payload: Bytes::new(b"the body".to_vec()),
    }
}

/// The public bytes of a preview key, made into a stored-envelope key: what a caller would have to
/// do to hand the preview key to a call that takes the other kind.
fn forced_into_a_stored_envelope_key(preview: &NotificationPreviewKeyPair) -> StoredEnvelopeKey {
    StoredEnvelopeKey::from_bytes(*preview.public().as_bytes())
}

/// KR-REQ-16.11: the preview key opens a preview envelope sealed to it, and a mailbox record is
/// neither sealed to it nor opened as a preview.
///
/// The control is the preview itself. The refusals are the two ways a mailbox record could meet the
/// key: sealed to its bytes, which the envelope's recipient check refuses because the key
/// identifier a stored-envelope recipient has is not the preview one; and sealed properly, which the
/// preview opener refuses as not a preview.
#[test]
fn a_preview_key_opens_preview_envelopes_and_a_mailbox_record_is_neither_sealed_to_it_nor_opened_as_one()
 {
    let host_preview = NotificationPreviewKeyPair::generate().expect("a keypair");
    let device_preview = NotificationPreviewKeyPair::generate().expect("a keypair");
    let host_stored = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let device_stored = StoredEnvelopeKeyPair::generate().expect("a keypair");

    // The control: a preview sealed to the preview key opens with it.
    let preview = plaintext(
        MailboxPayloadType::NotificationPreview,
        key_id(
            KeyPurpose::NotificationPreview,
            host_preview.public().as_bytes(),
        ),
        key_id(
            KeyPurpose::NotificationPreview,
            device_preview.public().as_bytes(),
        ),
    );
    let (padded, bucket) =
        pad_notification_preview(&kr_cbor::to_canonical_vec(&preview).expect("encoded"))
            .expect("padded");
    let (nonce, ciphertext) =
        seal_notification_preview(&host_preview, device_preview.public(), &padded).expect("sealed");
    let sealed = SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: preview.envelope_id,
            recipient_key_id: preview.recipient_key_id,
            sender_key_id: preview.sender_key_id,
            expires_at_ms: preview.expires_at_ms,
            payload_type: MailboxPayloadType::NotificationPreview,
            thread_id: preview.thread_id,
            size_bucket_bytes: U64::new(bucket),
        },
        nonce,
        ciphertext: Bytes::new(ciphertext),
    };
    open_notification_envelope(&device_preview, host_preview.public(), &sealed, NOW_MS)
        .expect("a preview sealed to the preview key opens with it");

    // A mailbox record sealed to the bytes of the preview key names the preview identifier, and the
    // seal refuses a recipient identifier that is not the stored-envelope one for those bytes.
    let to_the_preview_key = plaintext(
        MailboxPayloadType::StateReference,
        host_stored.key_id(),
        key_id(
            KeyPurpose::NotificationPreview,
            device_preview.public().as_bytes(),
        ),
    );
    let refused = seal_envelope(
        &host_stored,
        &forced_into_a_stored_envelope_key(&device_preview),
        &to_the_preview_key,
    )
    .expect_err("a mailbox record is not sealed to a preview key");
    assert!(
        matches!(refused, CryptoError::BindingMismatch { .. }),
        "{refused:?}"
    );

    // The control for that refusal: the same record to the device's stored-envelope key is sealed.
    let to_the_stored_key = plaintext(
        MailboxPayloadType::StateReference,
        host_stored.key_id(),
        device_stored.key_id(),
    );
    let record = seal_envelope(&host_stored, device_stored.public(), &to_the_stored_key)
        .expect("a mailbox record is sealed to the stored-envelope key");

    // And that record is not a preview: the preview opener refuses it by what it declares.
    let not_a_preview = open_notification_envelope(
        &device_preview,
        &kr_protocol::scalars::NotificationPreviewKey::from_bytes(*host_stored.public().as_bytes()),
        &record,
        NOW_MS,
    )
    .expect_err("a mailbox record is not opened as a preview");
    assert!(
        matches!(not_a_preview, PreviewRefusal::NotAPreview),
        "{}",
        not_a_preview.reason()
    );
}

/// KR-REQ-16.11: an archive key wrap is not made to a preview key.
///
/// A wrap authenticates the identifier of its recipient's stored-envelope key. One made to the bytes
/// of a preview key names them under the preview purpose, which is not the identifier a
/// stored-envelope recipient has, and `wrap_object_key` refuses it. The control is the same wrap to
/// the device's stored-envelope key.
#[test]
fn an_archive_key_wrap_is_made_to_a_stored_envelope_key_and_not_to_a_preview_key() {
    let producer = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let device = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let device_preview = NotificationPreviewKeyPair::generate().expect("a keypair");
    let object = encrypt_object(
        BackupObjectId::new(Uuid::from_bytes([0x22; 16])),
        b"an archived object",
    )
    .expect("an encrypted object");

    let context = |recipient: kr_protocol::scalars::KeyId| KeyWrapContext {
        format: KeyWrapFormat::V1,
        purpose: KeyWrapPurpose::ObjectKey,
        archive_id: ArchiveId::new(Uuid::from_bytes([0x11; 16])),
        backup_generation: BackupGeneration::new(1),
        object_id: object.reference.object_id,
        encrypted_object_hash: object.reference.encrypted_object_hash,
        sender_key_id: producer.key_id(),
        recipient_key_id: recipient,
    };

    wrap_object_key(
        &producer,
        device.public(),
        context(device.key_id()),
        &object.key,
    )
    .expect("a wrap to the stored-envelope key");

    let refused = wrap_object_key(
        &producer,
        &forced_into_a_stored_envelope_key(&device_preview),
        context(device_preview.key_id()),
        &object.key,
    )
    .expect_err("a wrap to a preview key is refused");
    assert!(
        matches!(refused, CryptoError::BindingMismatch { .. }),
        "{refused:?}"
    );
}

/// KR-REQ-16.11: a backup does not carry a preview private key, a restore puts none back, and an
/// archive member under the preview key's name is the key and not a session or a setting.
///
/// A recovery bundle and the archive it points at are made of what `may_back_up` admits. The
/// control is the material a backup does carry.
#[test]
fn a_backup_never_carries_a_preview_private_key_and_a_restore_never_puts_one_back() {
    assert!(may_back_up(Material::SessionData).is_allowed());
    assert!(may_restore(Material::SessionData).is_allowed());

    for admission in [
        may_back_up(Material::NotificationPreviewPrivateKey),
        may_restore(Material::NotificationPreviewPrivateKey),
    ] {
        assert!(
            matches!(admission, Admission::Refused { .. }),
            "{admission:?}"
        );
    }

    assert_eq!(
        member_material("keys/notification-preview/device"),
        Some(Material::NotificationPreviewPrivateKey),
        "a member in the preview key's place is recognised as the key, and so refused"
    );
}
