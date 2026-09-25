//! A module file whose first line is `#!`, a character rustc reads as whitespace, and an attribute.

mod marked;

/// KR-REQ-03.70: a case beside a module file whose first line the compiler reads as an attribute.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
