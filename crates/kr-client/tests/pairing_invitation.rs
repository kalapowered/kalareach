//! The one invitation reader a device has, against the published QR vectors.
//!
//! A host issues its QR payloads as base64url canonical KR-CBOR-1, and `fixtures/pairing/` is
//! where those bytes are published for every implementation to read. This reader reads exactly
//! them, and nothing that only looks like them.

use std::path::PathBuf;

use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::invitation::{Invitation, read_invitation};
use kr_protocol::pairing::{QrPayload, RendezvousOrigin};

fn fixture(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pairing")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture")).expect("JSON")
}

fn text(document: &serde_json::Value, pointer: &str) -> String {
    document
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .expect("a text member")
        .to_owned()
}

fn origin(text: &str) -> RendezvousOrigin {
    RendezvousOrigin::new(text).expect("an origin")
}

/// KR-REQ-10.38: the published code payload reads as a code at the origin it names, and says so
/// when that origin is not the one this device is set to use.
#[test]
fn the_published_code_payload_reads_as_its_code_and_origin() {
    let document = fixture("codes.json");
    let text = text(&document, "/qr/code/text");
    let QrPayload::Code(published) = QrPayload::from_text(&text).expect("the vector") else {
        panic!("the code vector is a code payload");
    };
    let configured = published.rendezvous_origin.clone();

    let Invitation::Code(read) = read_invitation(&text, &configured).expect("an invitation") else {
        panic!("a code payload reads as a code invitation");
    };
    assert_eq!(read.origin, published.rendezvous_origin);
    assert_eq!(read.code.locator(), &published.code.locator());
    assert_eq!(
        read.code.normalised(),
        published.code.to_secret_text().replace('-', ""),
        "the code a device enters is the one the payload carries"
    );
    assert!(!read.names_another_origin);

    let Invitation::Code(elsewhere) =
        read_invitation(&text, &origin("https://pair.example.org")).expect("an invitation")
    else {
        panic!("a code payload reads as a code invitation");
    };
    assert!(
        elsewhere.names_another_origin,
        "a payload naming another origin is marked for the native confirmation"
    );
    assert_eq!(elsewhere.origin, published.rendezvous_origin);
}

/// KR-REQ-10.38: the published direct payload reads as that payload, member for member, and
/// surrounding whitespace, which a copied line carries, does not change it.
#[test]
fn the_published_direct_payload_reads_as_itself() {
    let document = fixture("codes.json");
    let text = text(&document, "/qr/direct/text");
    let QrPayload::Direct(published) = QrPayload::from_text(&text).expect("the vector") else {
        panic!("the direct vector is a direct payload");
    };
    for copied in [text.clone(), format!("  {text}\n")] {
        let Invitation::Direct(read) =
            read_invitation(&copied, &origin("https://reach.kala.to")).expect("an invitation")
        else {
            panic!("a direct payload reads as a direct invitation");
        };
        assert_eq!(read, published);
    }
}

/// KR-REQ-10.38: nothing but the canonical payloads is an invitation. The JSON forms nothing ever
/// issued, text that is not base64url, and a payload with an unknown mode are refused as not an
/// invitation; a payload of a later version says it needs a newer release.
#[test]
fn nothing_else_reads_as_an_invitation() {
    let configured = origin("https://reach.kala.to");
    for refused in [
        r#"{"version":1,"mode":"code","rendezvous_origin":"https://reach.kala.to","code":"aB3x-Yz7-9Qw"}"#,
        r#"{"version":1,"mode":"direct","invitation_id":"i-1","endpoint_id":"e-1","expires_at_ms":"1700000000000"}"#,
        "aB3x-Yz7-9Qw",
        "",
        "not base64url at all!",
    ] {
        let failure = read_invitation(refused, &configured).expect_err("not an invitation");
        assert_eq!(failure.kind, FailureKind::NotAnInvitation, "{refused}");
    }

    // A canonical map naming a mode this build does not know, and one of version 2.
    let unknown_mode = kr_cbor::encode(&kr_cbor::CanonicalValue::Map(
        kr_cbor::CanonicalMap::from_entries([
            ("mode".to_owned(), kr_cbor::CanonicalValue::text("guess")),
            (
                "version".to_owned(),
                kr_cbor::CanonicalValue::integer(1).expect("an integer"),
            ),
        ])
        .expect("a canonical map"),
    ));
    let failure = read_invitation(
        &kr_protocol::scalars::to_base64url(&unknown_mode),
        &configured,
    )
    .expect_err("an unknown mode");
    assert_eq!(failure.kind, FailureKind::NotAnInvitation);

    let document = fixture("codes.json");
    let canonical = hex_bytes(&text(&document, "/qr/code/canonical_hex"));
    let value = kr_cbor::decode(&canonical, &kr_cbor::Limits::DEFAULT).expect("the vector");
    let kr_cbor::CanonicalValue::Map(map) = &value else {
        panic!("a payload is a map");
    };
    let entries: Vec<(String, kr_cbor::CanonicalValue)> = map
        .entries()
        .iter()
        .map(|(key, member)| {
            if key == "version" {
                (
                    key.clone(),
                    kr_cbor::CanonicalValue::integer(2).expect("an integer"),
                )
            } else {
                (key.clone(), member.clone())
            }
        })
        .collect();
    let later = kr_cbor::encode(&kr_cbor::CanonicalValue::Map(
        kr_cbor::CanonicalMap::from_entries(entries).expect("a canonical map"),
    ));
    let failure = read_invitation(&kr_protocol::scalars::to_base64url(&later), &configured)
        .expect_err("a later version");
    assert_eq!(failure.kind, FailureKind::NewerInvitation);
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}
