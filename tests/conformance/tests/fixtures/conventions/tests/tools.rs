//! A target that imports a crate under the name of a tool.

use tokio as clippy;

/// KR-REQ-03.25: a case a test under an attribute of the imported name calls.
fn case() -> u8 {
    3
}

#[clippy::test]
async fn calls_the_case_under_an_attribute_of_a_tools_name() {
    assert_eq!(case(), 3);
}
