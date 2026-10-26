//! The signed release matrix route.
//!
//! The Worker publishes the matrix at `GET /api/release-matrix` as `{ matrix, signature,
//! signing_key, serve }`, with no envelope on success, and answers `501 NOT_CONFIGURED` in the
//! service's envelope while it holds no signing key (`workers/api/src/ops/release.ts`). This route
//! answers the same, and holds the matrix a test gives it.
//!
//! The route is held to `release.ts` and to the vector in
//! `crates/kr-client/tests/fixtures/release-matrix`, whose bytes the Worker's own encoder made:
//! a local Worker cannot be run here, so no whole reply of one is recorded. [`signed`] rebuilds
//! the bytes it signs from the matrix's JSON, field by field, and not from the client's types, so
//! a client that rebuilt them wrongly is told so by a reply it should have accepted.

use kr_client::services::ServiceHttpAnswer;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use serde_json::{Value, json};

use base64::Engine as _;

/// Where the route is.
pub(crate) const PATH: &str = "/api/release-matrix";

/// The domain the Worker names its signed bytes by.
const DOMAIN: &str = "kr-release-matrix/1";

/// What the route answers: the matrix a test published, as the text it was given, or nothing.
pub(crate) fn answer(published: Option<&[u8]>) -> ServiceHttpAnswer {
    published.map_or_else(not_configured, |body| ServiceHttpAnswer {
        status: 200,
        body: body.to_vec(),
    })
}

fn not_configured() -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 501,
        body: serde_json::to_vec(&json!({
            "ok": false,
            "error": {
                "code": "NOT_CONFIGURED",
                "message": "This deployment holds no usable release-matrix signing key, so it publishes no signed matrix. RELEASE_MATRIX_SIGNING_KEY is the name of the secret.",
                "missing": ["RELEASE_MATRIX_SIGNING_KEY"],
            },
        }))
        .expect("a refusal"),
    }
}

/// The published reply for `matrix`, signed with `key`: the matrix, the signature over the fields
/// the Worker signs, the key's public half, and a `serve` answer that is `null`.
///
/// # Panics
///
/// Panics when `matrix` lacks a member the Worker signs, or when libsodium fails.
#[must_use]
pub fn signed(matrix: &Value, key: &AuthorisationKeyPair) -> Value {
    let tiers: Vec<Value> = matrix["tiers"]
        .as_array()
        .expect("tiers")
        .iter()
        .map(|tier| {
            json!({
                "id": tier["id"],
                "compatible": tier["compatible"],
                "client": range(&tier["client"]),
                "relay": range(&tier["relay"]),
                "discovery": range(&tier["discovery"]),
            })
        })
        .collect();
    let signed = json!({
        "schema_version": matrix["schemaVersion"],
        "revision": matrix["revision"],
        "issued_at": matrix["issuedAt"],
        "installed_client_window_days": matrix["installedClientWindowDays"],
        "alternatives": matrix["alternatives"],
        "tiers": tiers,
    });
    let transcript = SigningTranscript::keyed(DOMAIN, &signed).expect("a transcript");
    let signature = sign(key, &transcript).expect("a signature");
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    json!({
        "matrix": matrix,
        "signature": encode(signature.as_bytes()),
        "signing_key": encode(key.public().as_bytes()),
        "serve": Value::Null,
    })
}

fn range(held: &Value) -> Value {
    json!({ "minimum": held["minimum"], "maximum": held["maximum"] })
}
