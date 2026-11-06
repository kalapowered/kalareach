//! The one test of the tree.

/// KR-REQ-04.11.
#[test]
fn reads_what_the_macro_wrote() {
    assert_eq!(late::WRITTEN, b"written");
}
