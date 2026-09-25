//! A module file a function declares, which the reading does not read.

#[allow(dead_code)]
fn hidden() {
    #[path = "hidden/definitions.rs"]
    mod definitions;
}

/// KR-REQ-03.54: a case beside a module file a function declares, whose macro takes a standard name.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
