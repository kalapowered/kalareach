//! The encrypted mailbox's delivery, answering as the Worker's mailbox does.
//!
//! One mailbox per recipient, addressed by the identifier of the recipient's stored-envelope key.
//! A host leaves a sealed item for a device that is not connected; the service stores ciphertext it
//! cannot read and decides only what the envelope's shape and the sequence of deliveries let it
//! decide. Reading and acknowledging are the device's, and this stand-in does not model them.
//!
//! The source is the web repository's `workers/api/src/mailbox/{index,mailbox}.ts`; each rule below
//! is one of its, and the fidelity table in the crate's documentation names the line.

use std::collections::BTreeMap;

use kr_client::services::ServiceHttpAnswer;
use kr_protocol::mailbox::{MAX_MAILBOX_BYTES, MAX_MAILBOX_ITEMS, SealedEnvelope};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::StoredEnvelopeKey;
use kr_protocol::service::ServiceRequestSignature;
use serde_json::{Value, json};

use crate::feed::key_text;
use crate::web::{answered, refusal};

/// The most items one writer may hold in one mailbox.
const ITEMS_PER_WRITER: u64 = 128;
/// The most stored bytes one writer may hold in one mailbox.
const BYTES_PER_WRITER: u64 = 4 * 1024 * 1024;

/// One item a mailbox holds.
#[derive(Clone, Debug)]
struct Item {
    envelope: SealedEnvelope,
    writer_key: String,
    stored_bytes: u64,
}

/// What a mailbox remembers of an envelope identifier it has carried: for good, where the Worker
/// keeps it until the item's expiry and a day more.
#[derive(Clone, Debug)]
struct Carried {
    sequence: u64,
    digest: String,
}

/// One recipient's mailbox.
#[derive(Debug, Default)]
pub(crate) struct Mailbox {
    items: BTreeMap<u64, Item>,
    carried: BTreeMap<String, Carried>,
    next_sequence: u64,
}

impl Mailbox {
    fn usage(&self) -> Value {
        let bytes: u64 = self.items.values().map(|item| item.stored_bytes).sum();
        json!({
            "items": self.items.len().to_string(),
            "bytes": bytes.to_string(),
            "item_limit": MAX_MAILBOX_ITEMS.to_string(),
            "byte_limit": MAX_MAILBOX_BYTES.to_string(),
        })
    }

    /// The sealed envelopes the mailbox holds, in the order they were stored.
    pub(crate) fn envelopes(&self) -> Vec<SealedEnvelope> {
        self.items
            .values()
            .map(|item| item.envelope.clone())
            .collect()
    }
}

fn invalid(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_REQUEST", message)
}

/// The identifier of a mailbox: the one the protocol derives from the recipient's key.
pub(crate) fn address_of(key: &StoredEnvelopeKey) -> String {
    let id = kr_crypto::keys::key_id(KeyPurpose::StoredEnvelope, key.as_bytes());
    serde_json::to_value(id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/// The digest an item is remembered by: what the stand-in stores of it, written the same way every
/// time, so a delivery sent again is told from another item under the same identifier.
fn digest_of(envelope: &SealedEnvelope) -> String {
    let encoded = serde_json::to_vec(envelope).expect("an envelope");
    kr_cbor::sha256(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `mailbox.deliver`: places one sealed item in a recipient's mailbox.
///
/// The order is the Worker's. The signature, the nonce and the freshness have been checked by the
/// route. Then the body, the mailbox the envelope is routed to, a repeat of an identifier this
/// mailbox has carried, the shape of the item, the thread it may replace, and only then the quota,
/// measured after the replacement so that a coalescing delivery into a full mailbox is not refused
/// for the space the item it replaces is about to give back.
pub(crate) fn deliver(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    body: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let Ok(recipient) = serde_json::from_value::<StoredEnvelopeKey>(body["recipient_key"].clone())
    else {
        return invalid("A mailbox is named by the recipient stored-envelope key it seals to.");
    };
    let address = address_of(&recipient);
    let Ok(envelope) = serde_json::from_value::<SealedEnvelope>(body["envelope"].clone()) else {
        return invalid("A delivery carries one sealed envelope.");
    };
    let routed = serde_json::to_value(envelope.routing.recipient_key_id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned();
    if routed != address {
        return invalid("That envelope is routed to another recipient.");
    }

    let writer_key = key_text(&signature.public_key);
    let mailbox = mailboxes.entry(address).or_default();
    let envelope_id = envelope.routing.envelope_id.to_string();
    let digest = digest_of(&envelope);

    if let Some(carried) = mailbox.carried.get(&envelope_id) {
        // The identifier has been delivered before, whether or not the item is still here. A repeat
        // of that delivery is answered with what the first one was told; a different item under
        // the same identifier is a conflict, because answering it as a duplicate would tell a
        // sender its item was stored when another one is.
        return if carried.digest == digest {
            answered(json!({
                "state": "duplicate",
                "sequence": carried.sequence.to_string(),
                "replaced_sequence": null,
                "stored": mailbox.usage(),
            }))
        } else {
            refusal(
                403,
                "FORBIDDEN",
                "That envelope identifier has already carried a different item.",
            )
        };
    }

    if let Err(broken) = envelope.check_structure(now_ms) {
        return invalid(&broken.to_string());
    }

    let stored_bytes = envelope.stored_bytes();
    let thread = envelope.routing.thread_id.as_ref().map(ToString::to_string);

    // The newest state notification of a thread replaces the older unread one from the same writer
    // and from nobody else's.
    let replaced = thread.as_ref().and_then(|thread| {
        mailbox
            .items
            .iter()
            .find(|(_, item)| {
                item.writer_key == writer_key
                    && item
                        .envelope
                        .routing
                        .thread_id
                        .as_ref()
                        .map(ToString::to_string)
                        .as_ref()
                        == Some(thread)
            })
            .map(|(sequence, _)| *sequence)
    });

    let held_items = mailbox.items.len() as u64 - u64::from(replaced.is_some());
    let held_bytes: u64 = mailbox
        .items
        .iter()
        .filter(|(sequence, _)| Some(**sequence) != replaced)
        .map(|(_, item)| item.stored_bytes)
        .sum();
    if held_items + 1 > MAX_MAILBOX_ITEMS {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This mailbox holds as many items as one may.",
        );
    }
    if held_bytes + stored_bytes > MAX_MAILBOX_BYTES {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This mailbox holds as many bytes of stored envelopes as one may.",
        );
    }
    let (mine_items, mine_bytes) = mailbox
        .items
        .iter()
        .filter(|(sequence, item)| Some(**sequence) != replaced && item.writer_key == writer_key)
        .fold((0u64, 0u64), |(items, bytes), (_, item)| {
            (items + 1, bytes + item.stored_bytes)
        });
    if mine_items + 1 > ITEMS_PER_WRITER || mine_bytes + stored_bytes > BYTES_PER_WRITER {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This sender holds as much of that mailbox as one sender may.",
        );
    }

    if let Some(sequence) = replaced {
        mailbox.items.remove(&sequence);
    }
    mailbox.next_sequence += 1;
    let sequence = mailbox.next_sequence;
    mailbox.items.insert(
        sequence,
        Item {
            envelope,
            writer_key,
            stored_bytes,
        },
    );
    mailbox
        .carried
        .insert(envelope_id, Carried { sequence, digest });
    answered(json!({
        "state": if replaced.is_some() { "coalesced" } else { "stored" },
        "sequence": sequence.to_string(),
        "replaced_sequence": replaced.map(|sequence| sequence.to_string()),
        "stored": mailbox.usage(),
    }))
}
