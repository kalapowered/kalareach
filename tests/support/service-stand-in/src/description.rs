//! The service description route.
//!
//! The Worker publishes the description at `GET /.well-known/kalareach-service.json` as
//! `{ description, signature }` with no envelope, `signature` being absent while the deployment
//! holds no signing key (`workers/api/src/service-description.ts`). This route answers the same
//! and holds the reply a test gives it, and answers `404 NOT_FOUND` while it holds none, as a
//! service that publishes no description does.
//!
//! The route is held to `service-description.ts` and to the vector in
//! `crates/kr-client/tests/fixtures/service-description`, whose bytes the Worker's own encoder
//! made. [`signed`] rebuilds the bytes it signs from the origin and the description's JSON, field
//! by field, and not from the client's types, so a client that rebuilt them wrongly is told so by a
//! reply it should have accepted.

use base64::Engine as _;
use kr_client::services::ServiceHttpAnswer;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use serde_json::{Value, json};

/// Where the route is.
pub(crate) const PATH: &str = "/.well-known/kalareach-service.json";

/// The context the Worker names its signed bytes by.
const DOMAIN: &str = "kalareach-service-description-v1";

/// What the route answers: the reply a test published, as the text it was given, or nothing.
pub(crate) fn answer(published: Option<&[u8]>) -> ServiceHttpAnswer {
    published.map_or_else(not_found, |body| ServiceHttpAnswer {
        status: 200,
        body: body.to_vec(),
    })
}

fn not_found() -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 404,
        body: serde_json::to_vec(&json!({
            "ok": false,
            "error": { "code": "NOT_FOUND", "message": "There is nothing at this address." },
        }))
        .expect("a refusal"),
    }
}

/// The published reply for `description`, signed with `key` for the service at `origin`:
/// `{ description, signature }`, the signature being over that origin and the fields the Worker
/// signs, with a service the description does not name signed as null and a relay map it does not
/// name as an empty list.
///
/// # Panics
///
/// Panics when libsodium fails.
#[must_use]
pub fn signed(description: &Value, origin: &str, key: &AuthorisationKeyPair) -> Value {
    let text = |value: &Value| {
        if value.is_string() {
            value.clone()
        } else {
            Value::Null
        }
    };
    let named = |section: &str| json!({ "origin": text(&description[section]["origin"]) });
    let relay_urls = match &description["network"]["relay_urls"] {
        Value::Array(urls) => Value::Array(urls.clone()),
        _ => json!([]),
    };
    let signed = json!({
        "origin": origin,
        "schema_version": description["schema_version"],
        "network": {
            "relay_urls": relay_urls,
            "pkarr_publisher_url": text(&description["network"]["pkarr_publisher_url"]),
            "pkarr_resolver_url": text(&description["network"]["pkarr_resolver_url"]),
            "dns_origin": text(&description["network"]["dns_origin"]),
        },
        "authority": named("authority"),
        "mailbox": named("mailbox"),
        "relay": named("relay"),
    });
    let transcript = SigningTranscript::keyed(DOMAIN, &signed).expect("a transcript");
    let signature = sign(key, &transcript).expect("a signature");
    json!({
        "description": description,
        "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_bytes()),
    })
}
