//! The signed release matrix, from the client's side: what a build accepts, which tier serves it,
//! what it is told when none does, and what it never acts on.
//!
//! KR-REQ-17.46: client, relay and discovery compatibility are explicit in the signed release
//! matrix, the backward-compatible tier is first, and unsupported skew returns a route error with
//! the configured alternatives. The service is the stand-in held to the Worker's source, over
//! loopback, signing with a key the test makes; the vector is made by the Worker's own encoder and
//! `node:crypto` (`tests/fixtures/release-matrix/make-vector.mjs`), not by this crate.

use kr_client::error::ClientError;
use kr_client::retry::UserAction;
use kr_client::services::http::HttpService;
use kr_client::services::matrix::{
    Alternative, Document, HeldMatrix, Kept, Pins, Refusal, Unread, Verdict, fetch,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PackageVersion;
use kr_protocol::scalars::AuthorisationKey;
use kr_protocol::service::GatewayOrigin;
use kr_service_stand_in::signed_release_matrix;
use serde_json::{Value, json};

const ORIGIN: &str = "https://reach.kala.to";

fn build(major: u16, minor: u16, patch: u16) -> PackageVersion {
    PackageVersion::new(major, minor, patch)
}

fn range(low: &str, high: &str) -> Value {
    json!({ "minimum": low, "maximum": high })
}

/// A matrix of two tiers, the compatible one first.
fn matrix(revision: &str, compatible: (&str, &str), current: (&str, &str)) -> Value {
    json!({
        "schemaVersion": 1,
        "revision": revision,
        "issuedAt": "2026-10-27",
        "note": "Prose the signature does not cover.",
        "installedClientWindowDays": 90,
        "alternatives": ["direct", "self-hosted-relay", "self-hosted-discovery"],
        "tiers": [
            {
                "id": "compatible",
                "compatible": true,
                "note": "",
                "client": range(compatible.0, compatible.1),
                "relay": range("1.2.0", "1.2.99"),
                "discovery": range("1.2.0", "1.2.99"),
            },
            {
                "id": "current",
                "compatible": false,
                "note": "",
                "client": range(current.0, current.1),
                "relay": range("1.2.0", "1.2.99"),
                "discovery": range("1.2.0", "1.2.99"),
            },
        ],
    })
}

fn pins(key: &AuthorisationKeyPair) -> Pins {
    Pins::of(vec![*key.public()])
}

fn reply(matrix: &Value, key: &AuthorisationKeyPair) -> Vec<u8> {
    serde_json::to_vec(&signed_release_matrix(matrix, key)).expect("a reply")
}

/// Accepts `matrix`, signed by `key`, into `held` as read by `by` at `now`.
fn take(
    held: &HeldMatrix,
    key: &AuthorisationKeyPair,
    matrix: &Value,
    by: PackageVersion,
    now: u64,
) -> Result<Kept, Refusal> {
    held.accept(&pins(key), ORIGIN, by, now, &reply(matrix, key))
        .map(|update| update.kept)
}

/* -------------------------------------------------------------------------- */
/* C1: the bytes agree with the website's                                      */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: the bytes this client rebuilds for a published matrix are the bytes the
/// publisher signs.
///
/// The fixture's signature is over the signing input the Worker's own encoder wrote, made by
/// `node:crypto`. A client that verifies it rebuilt those bytes, field by field, in that order.
mod the_signing_bytes_agree_with_the_websites {
    use super::*;

    const VECTOR: &str = include_str!("fixtures/release-matrix/signed-matrix.json");

    fn vector() -> (Pins, Value) {
        let vector: Value = serde_json::from_str(VECTOR).expect("the vector");
        let key = vector["public_key"].as_str().expect("a key");
        let key = base64_key(key);
        (Pins::of(vec![key]), vector["published"].clone())
    }

    fn base64_key(text: &str) -> AuthorisationKey {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .expect("base64url");
        AuthorisationKey::from_bytes(bytes.try_into().expect("32 bytes"))
    }

    fn verify(published: &Value, pins: &Pins) -> Result<Document, Refusal> {
        Document::verify(&serde_json::to_vec(published).expect("text"), pins)
    }

    #[test]
    fn the_publishers_own_signature_verifies() {
        let (pins, published) = vector();
        let document = verify(&published, &pins).expect("the publisher's matrix is accepted");
        assert_eq!(document.revision(), 2);
        // Both ends are included and a range is read as the website reads it, white space ignored:
        // the second tier writes ` 0.78.0` and `0.78.99 `.
        assert_eq!(
            document.serve(build(0, 78, 99)),
            Verdict::Served { compatible: true }
        );
    }

    #[test]
    fn nothing_the_signature_covers_can_change_and_verify() {
        let (pins, published) = vector();
        let changed = |edit: &dyn Fn(&mut Value)| {
            let mut text = published.clone();
            edit(&mut text);
            verify(&text, &pins).err()
        };
        // A changed bound, a changed `compatible`, a changed alternative, a swapped tier order, a
        // changed revision and a changed window each fail.
        assert_eq!(
            changed(&|text| text["matrix"]["tiers"][0]["client"]["maximum"] = json!("0.79.98")),
            Some(Refusal::Signature)
        );
        assert_eq!(
            changed(&|text| text["matrix"]["tiers"][1]["compatible"] = json!(true)),
            Some(Refusal::Signature)
        );
        assert_eq!(
            changed(&|text| text["matrix"]["alternatives"][1] = json!("self-hosted-relays")),
            Some(Refusal::Signature)
        );
        assert_eq!(
            changed(&|text| {
                let tiers = text["matrix"]["tiers"].as_array_mut().expect("tiers");
                tiers.swap(0, 1);
                // The first tier of the swapped matrix is not compatible, so keep the rule that
                // names the signature as the one under test.
                tiers[0]["compatible"] = json!(true);
                tiers[1]["compatible"] = json!(false);
            }),
            Some(Refusal::Signature)
        );
        assert_eq!(
            changed(&|text| text["matrix"]["revision"] = json!("3")),
            Some(Refusal::Signature)
        );
        assert_eq!(
            changed(&|text| text["matrix"]["installedClientWindowDays"] = json!(91)),
            Some(Refusal::Signature)
        );
    }

    #[test]
    fn what_the_signature_does_not_cover_is_data() {
        let (pins, published) = vector();
        let mut text = published;
        text["matrix"]["note"] = json!("Other prose.");
        text["matrix"]["tiers"][0]["note"] = json!("Other prose.");
        text["serve"] = json!("some-other-tier");
        text["signing_key"] = json!("not even a key");
        text["a_member_a_later_service_adds"] = json!([1, 2, 3]);
        verify(&text, &pins).expect("an unsigned member changes nothing");
    }
}

/* -------------------------------------------------------------------------- */
/* The deployed document                                                       */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: the matrix the managed service publishes, saved whole as it was served, verifies
/// under the key this build pins and serves release 0.78.0 the compatible tier.
///
/// The fixture is a single reply of the public route, kept byte for byte. It is read again when the
/// pin or the schema changes, and replaced by a newer reply when the published ranges move.
mod the_deployed_document {
    use super::*;

    const DEPLOYED: &[u8] = include_bytes!("fixtures/release-matrix/deployed-revision-2.json");

    #[test]
    fn verifies_under_the_pin_and_serves_the_release_the_compatible_tier() {
        let document =
            Document::verify(DEPLOYED, &Pins::production()).expect("the deployed matrix verifies");
        assert_eq!(document.revision(), 2);
        assert_eq!(
            document.serve(build(0, 78, 0)),
            Verdict::Served { compatible: true },
            "the release the matrix was published for is in the compatible tier"
        );
        // The ends of the signed range are included and the versions outside it are in no tier.
        assert_eq!(
            document.serve(build(0, 77, 0)),
            Verdict::Served { compatible: true }
        );
        assert_eq!(
            document.serve(build(0, 79, 99)),
            Verdict::Served { compatible: true }
        );
        assert_eq!(document.serve(build(0, 76, 99)), Verdict::Skew);
        assert_eq!(document.serve(build(0, 80, 0)), Verdict::Skew);
    }

    #[test]
    fn every_pin_this_build_carries_is_a_key() {
        use base64::Engine as _;
        for pin in kr_client::services::matrix::PRODUCTION_PINS {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(pin)
                .expect("a pin is unpadded base64url");
            assert_eq!(bytes.len(), 32, "a pin is the 32 bytes of a public key");
        }
    }

    #[test]
    fn is_refused_under_another_key() {
        let other = AuthorisationKeyPair::generate().expect("a key pair");
        assert_eq!(
            Document::verify(DEPLOYED, &pins(&other)).err(),
            Some(Refusal::Signature)
        );
    }
}

/* -------------------------------------------------------------------------- */
/* C2: the choice                                                              */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: the compatible tier is first and a supported build is served it; a build in no
/// tier gets the route error with the alternatives.
mod the_choice {
    use super::*;

    /// A reader over loopback to the stand-in, which signs with a key the test made.
    struct Reader {
        served: kr_service_stand_in::Served,
        http: HttpService,
        origin: GatewayOrigin,
        key: AuthorisationKeyPair,
    }

    async fn reader() -> Reader {
        let served = kr_service_stand_in::serve().await;
        let origin = GatewayOrigin::new(served.origin()).expect("a loopback origin");
        let http = HttpService::new(origin.clone()).expect("a transport");
        Reader {
            served,
            http,
            origin,
            key: AuthorisationKeyPair::generate().expect("a key pair"),
        }
    }

    impl Reader {
        fn publish(&self, matrix: &Value) {
            self.served
                .web()
                .publish_release_matrix(&reply(matrix, &self.key));
        }

        async fn document(&self) -> Document {
            let body = fetch(&self.http, &self.origin).await.expect("a reply");
            Document::verify(&body, &pins(&self.key)).expect("an accepted reply")
        }
    }

    #[tokio::test]
    async fn a_supported_build_is_served_the_compatible_tier_first() {
        let reader = reader().await;
        // 0.78.20 is in both tiers; 0.78.70 only in the later one; 0.79.0 in neither.
        reader.publish(&matrix("2", ("0.77.0", "0.78.50"), ("0.78.0", "0.78.99")));
        let document = reader.document().await;

        assert_eq!(
            document.serve(build(0, 78, 20)),
            Verdict::Served { compatible: true },
            "a build in both tiers is served the compatible one"
        );
        assert_eq!(
            document.serve(build(0, 77, 0)),
            Verdict::Served { compatible: true },
            "both ends of a range are included"
        );
        assert_eq!(
            document.serve(build(0, 78, 70)),
            Verdict::Served { compatible: false },
            "a build only in a later tier is served that tier, and is told so"
        );
        assert_eq!(document.serve(build(0, 79, 0)), Verdict::Skew);
        assert_eq!(document.serve(build(0, 76, 99)), Verdict::Skew);
    }

    #[tokio::test]
    async fn the_unsigned_serve_answer_never_decides() {
        let reader = reader().await;
        let matrix = matrix("2", ("0.77.0", "0.78.50"), ("0.78.0", "0.78.99"));
        let mut published = signed_release_matrix(&matrix, &reader.key);
        // The service's own `serve` says a tier that contradicts the signed ranges.
        published["serve"] = json!("current");
        reader
            .served
            .web()
            .publish_release_matrix(&serde_json::to_vec(&published).expect("text"));
        let document = reader.document().await;
        assert_eq!(document.serve(build(0, 79, 0)), Verdict::Skew);
        assert_eq!(
            document.serve(build(0, 78, 20)),
            Verdict::Served { compatible: true }
        );
    }

    #[tokio::test]
    async fn a_build_in_no_tier_gets_the_route_error_with_the_alternatives() {
        let reader = reader().await;
        reader.publish(&matrix("7", ("0.77.0", "0.77.99"), ("0.77.0", "0.77.99")));
        let document = reader.document().await;
        assert_eq!(document.serve(build(0, 78, 0)), Verdict::Skew);

        let error = document.route_error(false);
        assert_eq!(error.code(), ErrorCode::UnsupportedCapability);
        assert_eq!(error.revision(), 7);
        assert_eq!(
            error.alternatives(),
            [
                Alternative::Direct,
                Alternative::SelfHostedRelay,
                Alternative::SelfHostedDiscovery
            ]
        );

        // A host that only uses relays is not told to connect directly.
        assert_eq!(
            document.route_error(true).alternatives(),
            [
                Alternative::SelfHostedRelay,
                Alternative::SelfHostedDiscovery
            ]
        );

        // The route error reaches a caller as any service refusal that asks for an update.
        match error.into_client_error() {
            ClientError::Refused {
                error,
                retry_after_seconds,
                action,
                service_code,
            } => {
                assert_eq!(error.code, ErrorCode::UnsupportedCapability);
                assert_eq!(retry_after_seconds, None);
                assert_eq!(action, UserAction::Update);
                assert_eq!(service_code, None);
            }
            other => panic!("not a service refusal: {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_alternative_this_build_does_not_know_is_left_out_and_counted() {
        let reader = reader().await;
        let mut matrix = matrix("7", ("0.77.0", "0.77.99"), ("0.77.0", "0.77.99"));
        matrix["alternatives"] = json!(["direct", "telepathy", "direct"]);
        reader.publish(&matrix);
        let error = reader.document().await.route_error(false);
        assert_eq!(error.alternatives(), [Alternative::Direct]);
        assert_eq!(error.unknown_alternatives(), 1);
    }

    #[tokio::test]
    async fn a_service_with_no_matrix_is_read_as_none() {
        let reader = reader().await;
        assert_eq!(
            fetch(&reader.http, &reader.origin).await.err(),
            Some(Unread::NoMatrix),
            "the Worker answers 501 while it holds no signing key"
        );
        reader.publish(&matrix("2", ("0.77.0", "0.78.50"), ("0.78.0", "0.78.99")));
        assert!(fetch(&reader.http, &reader.origin).await.is_ok());
        assert_eq!(reader.served.web().requests_to("/api/release-matrix"), 2);
    }
}

/* -------------------------------------------------------------------------- */
/* C3: nothing unverified is acted on                                          */
/* -------------------------------------------------------------------------- */

/// KR-REQ-17.46: a reply that is not accepted, and an older or conflicting revision, never decide
/// anything: the held copy decides, or nothing does.
mod nothing_unverified_is_acted_on {
    use super::*;

    const NOW: u64 = 1_000;

    fn this_build() -> PackageVersion {
        build(0, 78, 0)
    }

    fn skew_matrix(revision: &str) -> Value {
        // The compatible tier ends before this build: it is in no tier.
        matrix(revision, ("0.70.0", "0.77.99"), ("0.70.0", "0.77.99"))
    }

    fn supported_matrix(revision: &str) -> Value {
        matrix(revision, ("0.70.0", "0.78.99"), ("0.70.0", "0.78.99"))
    }

    fn standing(held: &HeldMatrix) -> Option<(u64, Verdict, bool)> {
        held.view(ORIGIN, this_build())
            .map(|view| (view.revision, view.verdict, view.by_this_build))
    }

    #[test]
    fn a_first_accepted_reply_is_held_and_decides() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let held = HeldMatrix::none();
        assert_eq!(standing(&held), None);
        assert_eq!(
            take(&held, &key, &skew_matrix("5"), this_build(), NOW),
            Ok(Kept::Replaced)
        );
        assert_eq!(standing(&held), Some((5, Verdict::Skew, true)));
        assert!(held.route_error(ORIGIN, this_build(), false).is_some());
    }

    /// Every way a reply is not accepted, over a copy that says `Served` and over one that says
    /// `Skew`: nothing changes.
    #[test]
    fn a_reply_that_is_not_accepted_changes_nothing_and_decides_nothing() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let stranger = AuthorisationKeyPair::generate().expect("a key pair");
        let pins = pins(&key);

        let refusals = |held: &HeldMatrix, forged: Vec<(Vec<u8>, Refusal)>| {
            for (body, expected) in forged {
                let before = standing(held);
                let gated = held.route_error(ORIGIN, this_build(), false).is_some();
                assert_eq!(
                    held.accept(&pins, ORIGIN, this_build(), NOW + 1, &body)
                        .err(),
                    Some(expected)
                );
                assert_eq!(standing(held), before, "{expected:?} changed what is held");
                assert_eq!(
                    held.route_error(ORIGIN, this_build(), false).is_some(),
                    gated,
                    "{expected:?} moved the gate"
                );
            }
        };

        // Replies the stand-in's signer made are accepted; these are not.
        let signed_by_stranger = reply(&skew_matrix("9"), &stranger);
        let after_signing = {
            let mut text = signed_release_matrix(&skew_matrix("9"), &key);
            text["matrix"]["tiers"][0]["client"]["maximum"] = json!("0.99.99");
            serde_json::to_vec(&text).expect("text")
        };
        let first_tier_not_compatible = {
            let mut matrix = skew_matrix("9");
            matrix["tiers"][0]["compatible"] = json!(false);
            reply(&matrix, &key)
        };
        let newer_schema = {
            let mut matrix = skew_matrix("9");
            matrix["schemaVersion"] = json!(2);
            serde_json::to_vec(&signed_release_matrix(&matrix, &key)).expect("text")
        };
        let not_a_counter = {
            let mut matrix = skew_matrix("9");
            matrix["revision"] = json!("9.5");
            reply(&matrix, &key)
        };
        let backwards_range = {
            let matrix = matrix("9", ("0.78.0", "0.70.0"), ("0.70.0", "0.77.99"));
            reply(&matrix, &key)
        };
        let not_json = b"<html>a proxy's error page</html>".to_vec();
        let names_a_member_twice = {
            let mut text = String::from_utf8(reply(&skew_matrix("9"), &key)).expect("text");
            text.insert_str(1, "\"signature\":\"x\",");
            text.into_bytes()
        };
        let forged = |body: Vec<u8>, expected| (body, expected);

        for held_matrix in [skew_matrix("5"), supported_matrix("5")] {
            let held = HeldMatrix::none();
            take(&held, &key, &held_matrix, this_build(), NOW).expect("a held copy");
            refusals(
                &held,
                vec![
                    forged(signed_by_stranger.clone(), Refusal::Signature),
                    forged(after_signing.clone(), Refusal::Signature),
                    forged(first_tier_not_compatible.clone(), Refusal::Malformed),
                    forged(newer_schema.clone(), Refusal::NewerSchema),
                    forged(not_a_counter.clone(), Refusal::Revision),
                    forged(backwards_range.clone(), Refusal::Malformed),
                    forged(not_json.clone(), Refusal::Unreadable),
                    forged(names_a_member_twice.clone(), Refusal::Unreadable),
                    forged(reply(&skew_matrix("4"), &key), Refusal::Older),
                    forged(reply(&supported_matrix("5"), &key), Refusal::Conflicts),
                ],
            );
        }
    }

    #[test]
    fn with_no_copy_a_reply_that_is_not_accepted_leaves_the_build_unread() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let stranger = AuthorisationKeyPair::generate().expect("a key pair");
        let held = HeldMatrix::none();
        assert_eq!(
            take(&held, &stranger, &skew_matrix("9"), this_build(), NOW),
            Err(Refusal::Signature)
        );
        let _ = key;
        assert_eq!(standing(&held), None, "no verdict is made of it");
        assert!(held.route_error(ORIGIN, this_build(), false).is_none());
    }

    #[test]
    fn a_higher_revision_replaces_and_the_same_revision_is_a_reread_by_the_reading_build() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let held = HeldMatrix::none();
        let older_build = build(0, 77, 4);
        take(&held, &key, &skew_matrix("5"), older_build, NOW).expect("held");
        // After an update the copy was read by the older build: this build does not act on its skew.
        let view = held.view(ORIGIN, this_build()).expect("a copy");
        assert_eq!(view.verdict, Verdict::Skew);
        assert!(!view.by_this_build);
        assert!(!view.gates());
        assert!(held.route_error(ORIGIN, this_build(), false).is_none());

        // The same revision, read again by this build, makes it this build's own finding.
        assert_eq!(
            take(&held, &key, &skew_matrix("5"), this_build(), NOW + 5),
            Ok(Kept::Refreshed)
        );
        let view = held.view(ORIGIN, this_build()).expect("a copy");
        assert!(view.by_this_build && view.gates());
        assert_eq!(view.fetched_at_ms, NOW + 5);

        // A higher revision that lists the build replaces it.
        assert_eq!(
            take(&held, &key, &supported_matrix("6"), this_build(), NOW + 9),
            Ok(Kept::Replaced)
        );
        assert_eq!(
            standing(&held),
            Some((6, Verdict::Served { compatible: true }, true))
        );
        assert!(held.route_error(ORIGIN, this_build(), false).is_none());
    }

    #[test]
    fn a_copy_read_from_another_origin_is_no_copy() {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let held = HeldMatrix::none();
        take(&held, &key, &skew_matrix("5"), this_build(), NOW).expect("held");
        assert!(
            held.view("https://elsewhere.example", this_build())
                .is_none()
        );
        assert!(
            held.route_error("https://elsewhere.example", this_build(), false)
                .is_none()
        );
        // And an older revision from the other origin is not "older than the one held".
        assert_eq!(
            held.accept(
                &pins(&key),
                "https://elsewhere.example",
                this_build(),
                NOW,
                &reply(&skew_matrix("1"), &key)
            )
            .map(|update| update.kept),
            Ok(Kept::Replaced)
        );
    }
}
