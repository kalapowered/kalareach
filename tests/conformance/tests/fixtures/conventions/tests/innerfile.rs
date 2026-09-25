//! A module file with a `path` attribute at its top, which moves where the compiler looks for its
//! own modules.

mod carrier;

/// KR-REQ-03.67: a case beside a module file whose own `path` attribute the reading does not follow.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
