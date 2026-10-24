//! Opening a sealed notification preview, for a receiver the system starts for one message.
//!
//! A host seals a preview to a phone's notification-preview key and sends it through the gateway
//! beside a generic alert. A receiver (the Android messaging service, the iOS notification
//! extension) has the sealed envelope as the gateway sent it, the phone's private preview key from
//! the store it can read, and the public key of the host that sent it. It opens the envelope here,
//! in one function, so the checks are the ones the host's own tests make of what it sealed, and
//! the Kotlin and Swift halves only look the keys up, call this and show what it answers.
//!
//! # What is opened, and what is not
//!
//! The envelope is opened only if the routing record outside it matches what the seal
//! authenticated, the two key identifiers inside name the keys that opened it, the envelope has not
//! expired, and the alert the preview repeats inside the seal is the generic alert the message was
//! shown with: a gateway that changed the alert in transit is refused here, as the reader that can
//! open the preview is the one that can tell. A preview that opens to nothing to show (the host
//! sealed no text for it, or moved the text to an object this receiver does not read) is not
//! revealed: the alert the host chose stands.
//!
//! The answer is JSON text, so the Kotlin and Swift halves share one shape: `{"ok":true,"text":...}`
//! or `{"ok":false,"reason":...}` with a reason from a fixed list that names the check that refused
//! and nothing of what it refused.

use base64::Engine as _;
use kr_cbor::{CanonicalValue, Limits, decode};
use kr_crypto::envelope::open_notification_envelope;
use kr_crypto::secret::SecretVec;
use kr_crypto::store::{SecretName, SecretStore, load_notification_preview_key};
use kr_protocol::mailbox::SealedEnvelope;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::PushAlert;
use kr_protocol::scalars::NotificationPreviewKey;
use serde::Deserialize;
use zeroize::Zeroizing;

#[cfg(target_os = "ios")]
mod ios;

/// The scope a receiver's one-item store names its key under. It is only a name: the store holds
/// the one seed the receiver was handed, and answers for no other.
const SCOPE: &str = "receiver";

/// What a receiver is asked to open.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    /// The `preview` member of the message, as the gateway sent it: JSON text of a sealed envelope.
    preview: String,
    /// The public key of the host the preview says it came from, in standard base64.
    sender_key: String,
    /// The generic alert the message was shown with.
    alert: String,
    /// The phone's clock, in UTC milliseconds.
    now_ms: u64,
}

/// A store that holds one item, for a receiver that was handed a key and not a store.
pub struct OneSecret {
    name: SecretName,
    bytes: Zeroizing<Vec<u8>>,
}

impl OneSecret {
    /// A store whose one item is `bytes`, under `name`.
    #[must_use]
    pub fn new(name: SecretName, bytes: &[u8]) -> Self {
        Self {
            name,
            bytes: Zeroizing::new(bytes.to_vec()),
        }
    }
}

impl SecretStore for OneSecret {
    fn set(&self, _: &SecretName, _: &[u8]) -> kr_crypto::Result<()> {
        Err(kr_crypto::CryptoError::SecretStore {
            message: "a receiver's store is read only".to_owned(),
        })
    }

    fn get(&self, name: &SecretName) -> kr_crypto::Result<Option<SecretVec>> {
        Ok((*name == self.name).then(|| SecretVec::new(self.bytes.to_vec())))
    }

    fn delete(&self, _: &SecretName) -> kr_crypto::Result<()> {
        Err(kr_crypto::CryptoError::SecretStore {
            message: "a receiver's store is read only".to_owned(),
        })
    }

    fn describe(&self) -> String {
        "the one key a receiver was handed".to_owned()
    }
}

fn refused(reason: &str) -> String {
    serde_json::json!({ "ok": false, "reason": reason }).to_string()
}

/// Opens the preview `input` names with the phone's preview seed, and answers what to show.
///
/// `input` is `{"preview": text, "sender_key": base64, "alert": text, "now_ms": n}`; `seed` is the
/// 32-byte seed of the phone's notification-preview key, held only for the call. The answer is
/// `{"ok":true,"text":...}` or `{"ok":false,"reason":...}`; the reasons are `input`, `seed`,
/// `sender_key`, `not_a_preview`, `expired`, `size`, `authentication`, `keys`, `routing`,
/// `malformed`, `crypto`, `alert_mismatch` and `empty_preview`.
#[must_use]
pub fn open(input: &str, seed: &[u8]) -> String {
    let Ok(input) = serde_json::from_str::<Input>(input) else {
        return refused("input");
    };
    let Ok(name) = SecretName::device_key(SCOPE, KeyPurpose::NotificationPreview) else {
        return refused("seed");
    };
    let store = OneSecret::new(name, seed);
    let Ok(Some(recipient)) = load_notification_preview_key(&store, SCOPE) else {
        return refused("seed");
    };
    let sender = match base64::engine::general_purpose::STANDARD
        .decode(&input.sender_key)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    {
        Some(bytes) => NotificationPreviewKey::from_bytes(bytes),
        None => return refused("sender_key"),
    };
    let Ok(envelope) = serde_json::from_str::<SealedEnvelope>(&input.preview) else {
        return refused("not_a_preview");
    };
    let plaintext = match open_notification_envelope(&recipient, &sender, &envelope, input.now_ms) {
        Ok(plaintext) => plaintext,
        Err(refusal) => return refused(refusal.reason()),
    };
    // The body is read, not decoded into the host's type: the receiver needs two members of it,
    // and the host's type stays where the host keeps it.
    let Ok(CanonicalValue::Map(body)) = decode(plaintext.payload.as_slice(), &Limits::DEFAULT)
    else {
        return refused("malformed");
    };
    let (Some(alert), Some(summary)) = (
        body.get("alert").and_then(CanonicalValue::as_text),
        body.get("summary").and_then(CanonicalValue::as_text),
    ) else {
        return refused("malformed");
    };
    let alert_matches =
        serde_json::from_value::<PushAlert>(serde_json::Value::String(alert.to_owned()))
            .is_ok_and(|sealed| sealed.generic_text() == input.alert);
    if !alert_matches {
        return refused("alert_mismatch");
    }
    let summary = summary.trim();
    if summary.is_empty() {
        return refused("empty_preview");
    }
    serde_json::json!({ "ok": true, "text": summary }).to_string()
}
