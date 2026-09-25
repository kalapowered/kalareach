//! A target whose test runs under `tokio::test` in a package that has no `tokio` crate.

/// KR-REQ-03.32: a case a test under an attribute of a crate the package does not have calls.
fn case() -> u8 {
    3
}

#[tokio::test]
async fn calls_the_case_under_a_runtime_of_that_name() {
    assert_eq!(case(), 3);
}
