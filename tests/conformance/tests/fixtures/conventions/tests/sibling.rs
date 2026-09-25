//! A module a `path` attribute loads, whose own module file is its sibling.

#[path = "loaded/parts.rs"]
mod parts;

/// KR-REQ-03.60: a case beside a module file the compiler finds beside the one a `path` loads.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
