//! A module declaration with no file.

mod missing;

/// KR-REQ-03.63: a case beside a module the reading cannot read.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
