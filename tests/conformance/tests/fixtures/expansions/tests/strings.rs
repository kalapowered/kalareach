//! A target one of whose tests writes a glob import as text, which imports nothing.

/// KR-REQ-03.31: a case a plain test calls, beside a test that writes a `use` as text.
fn case() -> u8 {
    3
}

#[test]
fn writes_a_glob_as_text() {
    let _ = stringify!(use external::*;);
}

#[test]
fn calls_the_case_beside_text() {
    assert_eq!(case(), 3);
}
