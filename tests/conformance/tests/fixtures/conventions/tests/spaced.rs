//! A module file whose inner `path` attribute is written with a space after its `#!`.

mod pages;

/// KR-REQ-03.69: a case beside a module file whose spaced inner attribute moves its modules.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
