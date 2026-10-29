//! The service description from the client's side: what a build accepts of what a service says of
//! itself, what vouches for it, and what it never acts on.
//!
//! KR-REQ-10.02, KR-REQ-17.12: discovery and relays are selected separately and each service is
//! selected independently, and a service names its own selection over a documented boundary. The
//! description is that boundary for a host's network. The vector is made by the Worker's own
//! encoder and `node:crypto` (`tests/fixtures/service-description/make-vector.mjs`), not by this
//! crate, and the service is the stand-in, held to the Worker's source, over loopback.

use kr_client::services::description::{
    self, Description, Refusal, Trust, Unread, fetch, is_managed, read,
};
use kr_client::services::http::HttpService;
use kr_client::services::matrix::{Document as Matrix, Pins, Refusal as MatrixRefusal};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::scalars::AuthorisationKey;
use kr_protocol::service::GatewayOrigin;
use kr_service_stand_in::signed_service_description;
use serde_json::{Value, json};

const ORIGIN: &str = "https://reach.kala.to";

fn origin(text: &str) -> GatewayOrigin {
    GatewayOrigin::new(text).expect("an origin")
}

fn key_of(text: &str) -> AuthorisationKey {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url");
    AuthorisationKey::from_bytes(bytes.try_into().expect("32 bytes"))
}

fn body(published: &Value) -> Vec<u8> {
    serde_json::to_vec(published).expect("text")
}

/// A description that names a relay, discovery and the three services.
fn whole() -> Value {
    json!({
        "schema_version": 1,
        "network": {
            "relay_urls": ["https://relay-1.example.test"],
            "pkarr_publisher_url": "https://ns1.example.test/pkarr",
            "pkarr_resolver_url": "https://ns1.example.test/pkarr",
        },
        "authority": { "origin": "https://service.example.test" },
        "mailbox": { "origin": "https://service.example.test" },
        "relay": { "origin": "https://service.example.test" },
    })
}

/// The reply of a service that holds no key.
fn unsigned(description: &Value) -> Vec<u8> {
    body(&json!({ "description": description }))
}

/* -------------------------------------------------------------------------- */
/* The Worker's own bytes                                                      */
/* -------------------------------------------------------------------------- */

/// The fixture's signature is over the signing input the Worker's own encoder wrote, made by
/// `node:crypto`. A client that verifies it rebuilt those bytes, field by field, in that order.
mod the_signing_bytes_agree_with_the_websites {
    use super::*;

    const VECTOR: &str = include_str!("fixtures/service-description/signed-description.json");

    fn vector() -> (Pins, Value) {
        let vector: Value = serde_json::from_str(VECTOR).expect("the vector");
        let key = key_of(vector["public_key"].as_str().expect("a key"));
        (Pins::of(vec![key]), vector)
    }

    fn accepted(published: &Value, pins: &Pins) -> Result<Description, Refusal> {
        read(
            &body(published),
            &origin(ORIGIN),
            &Trust::Pinned(pins.clone()),
        )
    }

    #[test]
    fn the_publishers_own_signature_verifies() {
        let (pins, vector) = vector();
        let description =
            accepted(&vector["published"], &pins).expect("the publisher's description is accepted");
        assert!(description.signed());
        let selection = description.selection();
        assert_eq!(
            selection.relay_urls,
            [
                "https://relay-1.reach.kala.to",
                "https://relay-2.reach.kala.to"
            ]
        );
        assert_eq!(
            selection.pkarr_publisher_url.as_deref(),
            Some("https://ns1.reach.kala.to/pkarr")
        );
        assert_eq!(selection.dns_origin, None);
        assert_eq!(
            selection.relay_origin.as_deref(),
            Some("https://reach.kala.to")
        );
    }

    #[test]
    fn nothing_the_signature_covers_can_change_and_verify() {
        let (pins, vector) = vector();
        let changed = |edit: &dyn Fn(&mut Value)| {
            let mut text = vector["published"].clone();
            edit(&mut text);
            accepted(&text, &pins).err()
        };
        // A relay changed, one added, one dropped, a discovery server changed, a service moved, a
        // service dropped and one added each fail: what is signed is the whole of what is read.
        let signature = Some(Refusal::Signature);
        assert_eq!(
            changed(&|text| text["description"]["network"]["relay_urls"][0] =
                json!("https://relay-9.reach.kala.to")),
            signature
        );
        assert_eq!(
            changed(&|text| text["description"]["network"]["relay_urls"]
                .as_array_mut()
                .expect("relays")
                .push(json!("https://relay-3.reach.kala.to"))),
            signature
        );
        assert_eq!(
            changed(&|text| {
                text["description"]["network"]["relay_urls"]
                    .as_array_mut()
                    .expect("relays")
                    .pop();
            }),
            signature
        );
        assert_eq!(
            changed(
                &|text| text["description"]["network"]["pkarr_resolver_url"] =
                    json!("https://ns2.reach.kala.to/pkarr")
            ),
            signature
        );
        assert_eq!(
            changed(&|text| text["description"]["authority"]["origin"] =
                json!("https://elsewhere.example.test")),
            signature
        );
        assert_eq!(
            changed(&|text| {
                text["description"]
                    .as_object_mut()
                    .expect("description")
                    .remove("mailbox");
            }),
            signature
        );
        assert_eq!(
            changed(&|text| text["description"]["network"]["dns_origin"] =
                json!("discovery.reach.kala.to")),
            signature
        );
        // What the signature does not cover is data this build never acts on.
        assert!(
            changed(&|text| text["description"]["note"] = json!("prose")).is_none(),
            "a member this build does not read is not covered, and not acted on"
        );
    }

    #[test]
    fn a_signature_for_the_matrix_is_never_a_description_and_the_reverse() {
        let (pins, vector) = vector();
        let matrix_reply = |signature: &Value| {
            body(&json!({
                "matrix": vector["matrix"],
                "signature": signature,
                "signing_key": vector["public_key"],
                "serve": null,
            }))
        };

        // The control: each signature verifies over its own bytes under the one key.
        assert!(accepted(&vector["published"], &pins).is_ok());
        assert!(Matrix::verify(&matrix_reply(&vector["matrix_signature"]), &pins).is_ok());

        // And neither verifies as the other, though one key made both.
        let mut as_description = vector["published"].clone();
        as_description["signature"] = vector["matrix_signature"].clone();
        assert_eq!(
            accepted(&as_description, &pins).err(),
            Some(Refusal::Signature)
        );
        assert_eq!(
            Matrix::verify(&matrix_reply(&vector["published"]["signature"]), &pins).err(),
            Some(MatrixRefusal::Signature)
        );
    }

    #[test]
    fn the_signed_bytes_begin_with_the_context() {
        let (_, vector) = vector();
        let bytes = hex(vector["signing_input_hex"].as_str().expect("hex"));
        let context = description::DOMAIN.as_bytes();
        assert!(
            bytes.windows(context.len()).any(|window| window == context),
            "the context is part of what is signed"
        );
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }
}

/* -------------------------------------------------------------------------- */
/* What it must hold                                                           */
/* -------------------------------------------------------------------------- */

mod what_a_description_must_hold {
    use super::*;

    fn tls_only(description: &Value) -> Result<Description, Refusal> {
        read(&unsigned(description), &origin(ORIGIN), &Trust::TlsOnly)
    }

    #[test]
    fn a_whole_description_is_read_into_what_the_document_names() {
        let description = tls_only(&whole()).expect("accepted");
        assert!(!description.signed());
        assert_eq!(description.ignored().count(), 0);
        let selection = description.selection();
        assert_eq!(selection.relay_urls, ["https://relay-1.example.test"]);
        assert_eq!(
            selection.authority_origin.as_deref(),
            Some("https://service.example.test")
        );
        assert_eq!(
            selection.mailbox_origin.as_deref(),
            Some("https://service.example.test")
        );
    }

    #[test]
    fn a_service_the_description_does_not_name_is_not_selected() {
        let description = tls_only(&json!({
            "schema_version": 1,
            "network": { "relay_urls": ["https://relay-1.example.test"], "dns_origin": null },
            "mailbox": null,
        }))
        .expect("accepted");
        let selection = description.selection();
        assert_eq!(selection.pkarr_publisher_url, None);
        assert_eq!(selection.dns_origin, None);
        assert_eq!(selection.authority_origin, None);
        assert_eq!(selection.mailbox_origin, None);
        assert_eq!(selection.relay_origin, None);
    }

    #[test]
    fn each_rule_is_its_own_refusal() {
        let with = |edit: &dyn Fn(&mut Value)| {
            let mut description = whole();
            edit(&mut description);
            tls_only(&description).err()
        };
        assert_eq!(
            with(&|d| d["schema_version"] = json!(2)),
            Some(Refusal::Version)
        );
        assert_eq!(
            with(&|d| {
                d.as_object_mut()
                    .expect("description")
                    .remove("schema_version");
            }),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            with(&|d| d["schema_version"] = json!("1")),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            with(&|d| d["network"]["relay_urls"] = json!("https://relay-1.example.test")),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            with(&|d| d["network"]["relay_urls"] = json!([7])),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            with(&|d| d["network"] = json!([])),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            with(&|d| d["authority"]["origin"] = json!(true)),
            Some(Refusal::Malformed)
        );
        // A description that names no relay and no discovery server has nothing to reach.
        assert_eq!(
            with(&|d| {
                d.as_object_mut().expect("description").remove("network");
            }),
            Some(Refusal::Empty)
        );
        assert_eq!(
            with(&|d| d["network"] = json!({ "relay_urls": [] })),
            Some(Refusal::Empty)
        );
    }

    #[test]
    fn a_member_that_resembles_a_name_is_refused_and_any_other_is_ignored() {
        let with = |edit: &dyn Fn(&mut Value)| {
            let mut description = whole();
            edit(&mut description);
            tls_only(&description)
        };
        // A misspelling would drop a service without a word, so it is refused as one.
        for misspelt in [
            |d: &mut Value| d["mailbx"] = json!({ "origin": "https://x.example.test" }),
            |d: &mut Value| d["Relay"] = json!({ "origin": "https://x.example.test" }),
            |d: &mut Value| d["network"]["relay_url"] = json!(["https://x.example.test"]),
            |d: &mut Value| d["network"]["pkarr_publisher_ur"] = json!("https://x.example.test"),
            |d: &mut Value| d["authority"]["orign"] = json!("https://x.example.test"),
        ] {
            assert_eq!(with(&misspelt).err(), Some(Refusal::Misspelt));
        }
        // A member of a later service is counted and named, and nothing is done with it.
        let accepted = with(&|d| {
            d["voice"] = json!({ "origin": "https://voice.example.test" });
            d["network"]["region"] = json!("eu");
        })
        .expect("accepted");
        assert_eq!(accepted.ignored().count(), 2);
        assert_eq!(accepted.ignored().names(), ["voice", "region"]);
    }

    #[test]
    fn plain_http_is_read_only_from_a_service_on_this_machine() {
        let plain = json!({
            "schema_version": 1,
            "network": { "relay_urls": ["http://127.0.0.1:3340"] },
        });
        let read_from = |text: &str, description: &Value| {
            read(&unsigned(description), &origin(text), &Trust::TlsOnly)
        };
        assert!(read_from("http://127.0.0.1:8787", &plain).is_ok());
        assert_eq!(
            read_from(ORIGIN, &plain).err(),
            Some(Refusal::Insecure),
            "a service on the internet does not send a host to plain http"
        );
        let elsewhere = json!({
            "schema_version": 1,
            "network": { "relay_urls": ["http://relay.example.test"] },
        });
        assert_eq!(
            read_from("http://127.0.0.1:8787", &elsewhere).err(),
            Some(Refusal::Insecure),
            "nor does a service on this machine send it to another machine's http"
        );
        let service = json!({
            "schema_version": 1,
            "network": { "relay_urls": ["https://relay-1.example.test"] },
            "authority": { "origin": "http://authority.example.test" },
        });
        assert_eq!(read_from(ORIGIN, &service).err(), Some(Refusal::Insecure));
    }

    #[test]
    fn a_text_that_is_not_a_published_description_is_unreadable() {
        for text in [
            &b"not json"[..],
            b"[]",
            b"{}",
            br#"{"description": "text"}"#,
            br#"{"description": {"schema_version": 1}, "description": {}}"#,
        ] {
            assert_eq!(
                read(text, &origin(ORIGIN), &Trust::TlsOnly).err(),
                Some(Refusal::Unreadable)
            );
        }
    }
}

/* -------------------------------------------------------------------------- */
/* What vouches for it                                                         */
/* -------------------------------------------------------------------------- */

mod what_vouches_for_it {
    use super::*;

    fn signed_by(key: &AuthorisationKeyPair, description: &Value) -> Vec<u8> {
        body(&signed_service_description(description, key))
    }

    #[test]
    fn a_service_you_run_is_read_under_the_key_you_name_and_no_other() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let other = AuthorisationKeyPair::generate().expect("a key pair");
        let reply = signed_by(&key, &whole());
        let service = origin("https://service.example.test");

        let accepted = read(
            &reply,
            &service,
            &Trust::Pinned(Pins::of(vec![*key.public()])),
        )
        .expect("accepted under the key that signed it");
        assert!(accepted.signed());
        assert_eq!(
            read(
                &reply,
                &service,
                &Trust::Pinned(Pins::of(vec![*other.public()]))
            )
            .err(),
            Some(Refusal::Signature)
        );
    }

    #[test]
    fn a_description_that_is_unsigned_or_signed_wrongly_is_refused_where_a_key_is_required() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let pinned = Trust::Pinned(Pins::of(vec![*key.public()]));
        let service = origin("https://service.example.test");
        let mut reply: Value = serde_json::from_slice(&signed_by(&key, &whole())).expect("a reply");

        assert!(
            read(&body(&reply), &service, &pinned).is_ok(),
            "the control"
        );
        for signature in [json!(null), json!(""), json!("not base64!"), json!("AAAA")] {
            reply["signature"] = signature;
            assert_eq!(
                read(&body(&reply), &service, &pinned).err(),
                Some(Refusal::Signature)
            );
        }
        reply.as_object_mut().expect("reply").remove("signature");
        assert_eq!(
            read(&body(&reply), &service, &pinned).err(),
            Some(Refusal::Signature),
            "no signature is not a signature"
        );
        // A person who said so takes the description on the connection alone, and a signature on
        // it is then ignored.
        reply["signature"] = json!("AAAA");
        assert!(read(&body(&reply), &service, &Trust::TlsOnly).is_ok());
    }

    #[test]
    fn a_key_is_given_as_the_text_a_service_publishes_it_in() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        use base64::Engine as _;
        let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public().as_bytes());
        assert!(Pins::from_key_text(&text).is_some());
        for refused in ["", "AAAA", "not a key", &format!("{text}=")] {
            assert!(Pins::from_key_text(refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn only_the_managed_origin_is_read_under_the_pinned_key() {
        assert!(is_managed(&origin("https://reach.kala.to")));
        assert!(!is_managed(&origin("https://service.example.test")));
        assert!(!is_managed(&origin("http://127.0.0.1:8787")));
    }
}

/* -------------------------------------------------------------------------- */
/* Asking for it                                                               */
/* -------------------------------------------------------------------------- */

mod asking_for_it {
    use super::*;

    #[tokio::test]
    async fn a_service_that_publishes_one_gives_it_and_one_that_does_not_is_told_so() {
        let served = kr_service_stand_in::serve().await;
        let service = origin(served.origin());
        let http = HttpService::new(service.clone()).expect("a transport");
        let key = AuthorisationKeyPair::generate().expect("a key pair");

        assert_eq!(
            fetch(&http, &service).await.err(),
            Some(Unread::NotPublished),
            "a service with no description answers 404"
        );

        let reply = signed_service_description(&whole(), &key);
        served.web().publish_service_description(&body(&reply));
        let text = fetch(&http, &service).await.expect("the reply");
        let description = read(
            &text,
            &service,
            &Trust::Pinned(Pins::of(vec![*key.public()])),
        )
        .expect("the stand-in signs as the Worker does");
        assert_eq!(
            description.selection().relay_urls,
            ["https://relay-1.example.test"]
        );

        served.web().withdraw_service_description();
        assert_eq!(
            fetch(&http, &service).await.err(),
            Some(Unread::NotPublished)
        );
    }
}
