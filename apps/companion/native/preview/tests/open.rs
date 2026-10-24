//! A receiver opens what the host seals.
//!
//! Each case seals a preview the way the host does (`kr_delivery::preview::seal_preview`, the
//! host's own code) and hands the envelope to [`companion_preview::open`] as a receiver has it: the
//! JSON text of the `preview` member of the message, the phone's seed, the host's public key and
//! the generic alert the message was shown with. The golden is one such preview, sealed under fixed
//! test keys with an expiry far ahead, which the Kotlin and Swift halves read for what they own
//! (the parse and the lookups); `regenerate_the_golden` writes it again.

use base64::Engine as _;
use kr_crypto::keys::{DeviceKeys, NotificationPreviewKeyPair};
use kr_crypto::store::{MemoryStore, SecretName, SecretStore, store_device_keys};
use kr_delivery::preview::{PreviewBody, PreviewTarget, seal_preview};
use kr_protocol::ids::EnvelopeId;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::PushAlert;
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use serde_json::{Value, json};

const NOW_MS: u64 = 1_700_000_000_000;
const EXPIRES_MS: u64 = 4_000_000_000_000;
const GOLDEN: &str = include_str!("../../platform/fixtures/push/recorded-preview.json");

struct Phone {
    keys: DeviceKeys,
    seed: Vec<u8>,
}

fn phone() -> Phone {
    let keys = DeviceKeys::generate().expect("keys");
    let store = MemoryStore::new();
    store_device_keys(&store, "device", &keys).expect("stored");
    let seed = store
        .get(&SecretName::device_key("device", KeyPurpose::NotificationPreview).expect("a name"))
        .expect("readable")
        .expect("the seed")
        .expose()
        .to_vec();
    Phone { keys, seed }
}

fn body(alert: PushAlert, summary: &str) -> PreviewBody {
    PreviewBody {
        alert,
        rule: "attention.pending_input".to_owned(),
        summary: summary.to_owned(),
        session_id: Nullable::null(),
        environment_id: Nullable::null(),
        detail_object: Nullable::null(),
        observed_at_ms: TimestampMs::new(NOW_MS),
    }
}

/// What the host sends for `body`, as the gateway forwards it: the envelope's JSON text.
fn sealed_by(
    host: &NotificationPreviewKeyPair,
    phone: &Phone,
    body: &PreviewBody,
    expires: u64,
) -> String {
    let sealed = seal_preview(
        host,
        &PreviewTarget {
            recipient: *phone.keys.notification_preview.public(),
            revision: 1,
        },
        EnvelopeId::new(Uuid::from_bytes([5; 16])),
        body,
        TimestampMs::new(NOW_MS),
        TimestampMs::new(expires),
    )
    .expect("a sealed preview");
    serde_json::to_string(&sealed.envelope).expect("the envelope as text")
}

fn input(preview: &str, sender: &NotificationPreviewKeyPair, alert: &str, now: u64) -> String {
    json!({
        "preview": preview,
        "sender_key": base64::engine::general_purpose::STANDARD.encode(sender.public().as_bytes()),
        "alert": alert,
        "now_ms": now,
    })
    .to_string()
}

fn answer(text: &str) -> Value {
    serde_json::from_str(text).expect("the answer is JSON")
}

fn reason(answer: &Value) -> &str {
    assert_eq!(answer["ok"], false, "{answer}");
    answer["reason"].as_str().expect("a reason")
}

#[test]
fn a_receiver_shows_the_summary_the_host_sealed_to_this_phone() {
    let host = DeviceKeys::generate().expect("keys");
    let phone = phone();
    let alert = PushAlert::QuestionWaiting;
    let preview = sealed_by(
        &host.notification_preview,
        &phone,
        &body(alert, "  Allow scripts/release.sh?  "),
        EXPIRES_MS,
    );
    let opened = answer(&companion_preview::open(
        &input(
            &preview,
            &host.notification_preview,
            alert.generic_text(),
            NOW_MS,
        ),
        &phone.seed,
    ));
    assert_eq!(
        opened,
        json!({ "ok": true, "text": "Allow scripts/release.sh?" })
    );
}

#[test]
fn a_receiver_shows_nothing_it_cannot_vouch_for() {
    let host = DeviceKeys::generate().expect("keys");
    let phone = phone();
    let other = DeviceKeys::generate().expect("keys");
    let alert = PushAlert::ApprovalWaiting;
    let shown = alert.generic_text();
    let preview = sealed_by(
        &host.notification_preview,
        &phone,
        &body(alert, "an approval"),
        EXPIRES_MS,
    );
    let open =
        |preview: &str, sender: &NotificationPreviewKeyPair, shown: &str, now: u64, seed: &[u8]| {
            answer(&companion_preview::open(
                &input(preview, sender, shown, now),
                seed,
            ))
        };

    assert_eq!(
        reason(&open(
            &preview,
            &host.notification_preview,
            shown,
            NOW_MS,
            &other_seed()
        )),
        "authentication",
        "another phone's key"
    );
    assert_eq!(
        reason(&open(
            &preview,
            &other.notification_preview,
            shown,
            NOW_MS,
            &phone.seed
        )),
        "authentication",
        "a host this phone does not know"
    );
    assert_eq!(
        reason(&open(
            &preview,
            &host.notification_preview,
            PushAlert::WorkComplete.generic_text(),
            NOW_MS,
            &phone.seed
        )),
        "alert_mismatch",
        "an alert the gateway changed"
    );
    assert_eq!(
        reason(&open(
            &preview,
            &host.notification_preview,
            shown,
            EXPIRES_MS,
            &phone.seed
        )),
        "expired"
    );
    assert_eq!(
        reason(&open(
            "{\"not\":\"a preview\"}",
            &host.notification_preview,
            shown,
            NOW_MS,
            &phone.seed
        )),
        "not_a_preview"
    );
    assert_eq!(
        reason(&open(
            &preview,
            &host.notification_preview,
            shown,
            NOW_MS,
            &[0; 5]
        )),
        "seed",
        "a seed that is not a key"
    );
    assert_eq!(
        reason(&answer(&companion_preview::open("not json", &phone.seed))),
        "input"
    );
}

/// A preview with no text to show (the host sealed none for a session's item, or moved it to an
/// object the receiver does not read) opens and authenticates and is not revealed.
#[test]
fn a_preview_with_nothing_to_show_leaves_the_alert_the_host_chose() {
    let host = DeviceKeys::generate().expect("keys");
    let phone = phone();
    let alert = PushAlert::SessionNeedsAttention;
    let preview = sealed_by(
        &host.notification_preview,
        &phone,
        &body(alert, "   "),
        EXPIRES_MS,
    );
    let opened = answer(&companion_preview::open(
        &input(
            &preview,
            &host.notification_preview,
            alert.generic_text(),
            NOW_MS,
        ),
        &phone.seed,
    ));
    assert_eq!(reason(&opened), "empty_preview");
}

fn other_seed() -> Vec<u8> {
    phone().seed
}

/// The golden: one preview the host sealed, with the keys and what a receiver should show.
#[test]
fn the_golden_preview_opens_to_its_summary() {
    let golden: Value = serde_json::from_str(GOLDEN).expect("the golden");
    let seed = base64::engine::general_purpose::STANDARD
        .decode(golden["recipient_seed"].as_str().expect("a seed"))
        .expect("base64");
    let opened = answer(&companion_preview::open(
        &json!({
            "preview": golden["preview"],
            "sender_key": golden["sender_key"],
            "alert": golden["alert"],
            "now_ms": golden["now_ms"],
        })
        .to_string(),
        &seed,
    ));
    assert_eq!(opened, json!({ "ok": true, "text": golden["summary"] }));
}

/// Writes the golden again: `KR_WRITE_GOLDEN=<path> cargo test -p companion-preview -- --ignored`.
#[test]
#[ignore = "writes the golden fixture"]
fn regenerate_the_golden() {
    let path = std::env::var("KR_WRITE_GOLDEN").expect("the path to write the golden to");
    let host = DeviceKeys::generate().expect("keys");
    let phone = phone();
    let alert = PushAlert::QuestionWaiting;
    let summary = "Allow scripts/release.sh?";
    let preview = sealed_by(
        &host.notification_preview,
        &phone,
        &body(alert, summary),
        EXPIRES_MS,
    );
    let golden = json!({
        "note": "One preview sealed by the host's own code (kr_delivery::preview::seal_preview) under fixed test keys, with an expiry far ahead so the case does not depend on the date. Not recorded from a gateway: the gateway forwards the envelope text unchanged.",
        "preview": preview,
        "recipient_seed": base64::engine::general_purpose::STANDARD.encode(&phone.seed),
        "recipient_key_id": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(phone.keys.notification_preview.key_id().as_bytes()),
        "sender_key": base64::engine::general_purpose::STANDARD.encode(host.notification_preview.public().as_bytes()),
        "sender_key_id": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(host.notification_preview.key_id().as_bytes()),
        "alert": alert.generic_text(),
        "summary": summary,
        "now_ms": NOW_MS,
    });
    std::fs::write(
        path,
        serde_json::to_string_pretty(&golden).expect("text") + "\n",
    )
    .expect("written");
}
