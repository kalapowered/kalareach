//! The program a release runs before it is published, against the stand-in service.
//!
//! KR-REQ-17.46: no release is published whose package version the published, verified matrix
//! does not list. The program verifies under the key this build pins, which the stand-in does not
//! sign with, so what is held here is every way the answer is a refusal and the exit status each
//! gets; that a matrix signed by the pinned key is accepted is held by the library's cases
//! (`crates/kr-client/tests/release_check.rs`), where the test chooses the pin.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_service_stand_in::{Moment, serve, signed_release_matrix};
use serde_json::json;

const MATRIX: &str = "/api/release-matrix";

async fn run(arguments: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_kr-release-matrix-check"))
        .args(arguments)
        .output()
        .await
        .expect("the program runs")
}

fn code(output: &std::process::Output) -> i32 {
    output.status.code().expect("the program ends by itself")
}

/// A matrix that lists every client, signed by a key the program does not pin.
fn listing_everything(key: &AuthorisationKeyPair) -> Vec<u8> {
    let tier = |id: &str, compatible: bool| {
        json!({
            "id": id,
            "compatible": compatible,
            "note": "",
            "client": { "minimum": "0.0.0", "maximum": "999999.999999.999999" },
            "relay": { "minimum": "1.2.0", "maximum": "1.2.99" },
            "discovery": { "minimum": "1.2.0", "maximum": "1.2.99" },
        })
    };
    let matrix = json!({
        "schemaVersion": 1,
        "revision": "9",
        "issuedAt": "2026-10-27",
        "installedClientWindowDays": 90,
        "alternatives": ["direct"],
        "tiers": [tier("compatible", true)],
    });
    serde_json::to_vec(&signed_release_matrix(&matrix, key)).expect("a reply")
}

#[tokio::test]
async fn a_matrix_the_pin_does_not_verify_refuses_the_release() {
    let served = serve().await;
    let stranger = AuthorisationKeyPair::generate().expect("a key pair");
    served
        .web()
        .publish_release_matrix(&listing_everything(&stranger));
    let output = run(&["--origin", served.origin()]).await;
    assert_eq!(code(&output), 1);
    assert_eq!(
        served.web().requests_to(MATRIX),
        1,
        "it asked once and not again"
    );
}

#[tokio::test]
async fn a_service_that_publishes_no_matrix_refuses_the_release() {
    let served = serve().await;
    let output = run(&["--origin", served.origin()]).await;
    assert_eq!(
        code(&output),
        1,
        "the Worker answers 501 while it holds no key"
    );
}

#[tokio::test]
async fn a_service_that_does_not_answer_is_a_fault_that_asking_again_may_mend() {
    let served = serve().await;
    served.web().fail(
        MATRIX,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    );
    let output = run(&["--origin", served.origin()]).await;
    assert_eq!(code(&output), 2);
}

#[tokio::test]
async fn the_origin_is_required_and_has_no_default() {
    assert_eq!(code(&run(&[]).await), 64);
    assert_eq!(code(&run(&["--origin"]).await), 64);
    assert_eq!(code(&run(&["--origin", "not an origin"]).await), 64);
}
