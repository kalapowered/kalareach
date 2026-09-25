//! A test target of the 2015 edition, where a `use` path starts at the crate root.

/// KR-REQ-03.53: a case of a target whose paths the reading does not follow.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
