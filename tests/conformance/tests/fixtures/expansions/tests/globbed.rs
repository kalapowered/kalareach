//! A target that brings in every name of another crate, which may hold a macro of any name.

#[allow(unused_imports)]
use expansions::*;

/// KR-REQ-03.16: a case beside a glob from outside the target.
fn case() -> u8 {
    3
}

#[test]
fn calls_a_case_beside_a_glob() {
    assert_eq!(case(), 3);
}
