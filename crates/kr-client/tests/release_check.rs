//! The question a release asks before it is published: whether the signed release matrix the
//! managed service publishes lists a tier for the build being released.
//!
//! KR-REQ-17.46: a release is published only if the verified matrix serves its package version.
//! The check verifies as a host's daemon does, under keys the test chooses, over loopback to the
//! stand-in. `crates/kr-release-matrix-check/tests/exit_codes.rs` holds the program that calls it.

use kr_client::services::http::HttpService;
use kr_client::services::matrix::{Pins, Refusal, Supported, Unread, Unsupported, check_release};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::hello::PackageVersion;
use kr_protocol::service::GatewayOrigin;
use kr_service_stand_in::{Moment, serve, signed_release_matrix};
use serde_json::{Value, json};

fn release() -> PackageVersion {
    PackageVersion::new(0, 78, 0)
}

fn tier(id: &str, compatible: bool, highest: &str) -> Value {
    json!({
        "id": id,
        "compatible": compatible,
        "note": "",
        "client": { "minimum": "0.70.0", "maximum": highest },
        "relay": { "minimum": "1.2.0", "maximum": "1.2.99" },
        "discovery": { "minimum": "1.2.0", "maximum": "1.2.99" },
    })
}

fn matrix(revision: &str, compatible_highest: &str, current_highest: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "revision": revision,
        "issuedAt": "2026-10-27",
        "installedClientWindowDays": 90,
        "alternatives": ["direct", "self-hosted-relay"],
        "tiers": [
            tier("compatible", true, compatible_highest),
            tier("current", false, current_highest),
        ],
    })
}

async fn check(
    served: &kr_service_stand_in::Served,
    key: &AuthorisationKeyPair,
) -> Result<Supported, Unsupported> {
    let origin = GatewayOrigin::new(served.origin()).expect("a loopback origin");
    let http = HttpService::new(origin.clone()).expect("a transport");
    check_release(&http, &origin, &Pins::of(vec![*key.public()]), release()).await
}

async fn publishing(matrix: &Value, key: &AuthorisationKeyPair) -> kr_service_stand_in::Served {
    let served = serve().await;
    served
        .web()
        .publish_release_matrix(&serde_json::to_vec(&signed_release_matrix(matrix, key)).unwrap());
    served
}

#[tokio::test]
async fn a_release_the_compatible_tier_serves_is_supported() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let served = publishing(&matrix("4", "0.78.99", "0.78.99"), &key).await;
    assert_eq!(
        check(&served, &key).await,
        Ok(Supported {
            revision: 4,
            compatible: true
        })
    );
}

#[tokio::test]
async fn a_release_only_a_later_tier_serves_is_supported_and_says_so() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let served = publishing(&matrix("4", "0.77.99", "0.78.99"), &key).await;
    assert_eq!(
        check(&served, &key).await,
        Ok(Supported {
            revision: 4,
            compatible: false
        })
    );
}

#[tokio::test]
async fn a_release_in_no_tier_is_refused() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let served = publishing(&matrix("4", "0.77.99", "0.77.99"), &key).await;
    let refused = check(&served, &key).await.expect_err("a refusal");
    assert_eq!(refused, Unsupported::OutsideEveryTier { revision: 4 });
    assert_eq!(refused.exit_code(), 1);
}

#[tokio::test]
async fn a_matrix_signed_by_another_key_is_refused() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let stranger = AuthorisationKeyPair::generate().expect("a key pair");
    let served = publishing(&matrix("4", "0.78.99", "0.78.99"), &stranger).await;
    let refused = check(&served, &key).await.expect_err("a refusal");
    assert_eq!(refused, Unsupported::NotVerified(Refusal::Signature));
    assert_eq!(refused.exit_code(), 1);
}

/// The program is the one check against a floor set too high: a matrix below the first revision a
/// build reads is no matrix to that build, so the release is refused.
#[tokio::test]
async fn a_matrix_below_the_first_revision_the_build_reads_is_refused() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let served = publishing(&matrix("4", "0.78.99", "0.78.99"), &key).await;
    let origin = GatewayOrigin::new(served.origin()).expect("a loopback origin");
    let http = HttpService::new(origin.clone()).expect("a transport");
    let reads_from_five = Pins::of(vec![*key.public()]).from_revision(5);
    let refused = check_release(&http, &origin, &reads_from_five, release())
        .await
        .expect_err("a refusal");
    assert_eq!(refused, Unsupported::NotVerified(Refusal::BelowFirst));
    assert_eq!(refused.exit_code(), 1);
}

#[tokio::test]
async fn a_service_with_no_matrix_is_refused_and_one_that_does_not_answer_may_be_asked_again() {
    let key = AuthorisationKeyPair::generate().expect("a key pair");
    let served = serve().await;
    let refused = check(&served, &key).await.expect_err("a refusal");
    assert_eq!(refused, Unsupported::Unread(Unread::NoMatrix));
    assert_eq!(refused.exit_code(), 1);

    served.web().fail(
        "/api/release-matrix",
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    let down = check(&served, &key).await.expect_err("a fault");
    assert_eq!(down, Unsupported::Unread(Unread::Unreachable));
    assert_eq!(down.exit_code(), 2);
}
