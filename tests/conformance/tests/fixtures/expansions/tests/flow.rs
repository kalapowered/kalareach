//! A case a plain test calls, which keys it.

/// KR-REQ-03.14: a case a plain test calls, which keys it.
fn plain() -> u8 {
    7
}

#[test]
fn calls_the_case_plainly() {
    assert_eq!(plain(), 7);
}
