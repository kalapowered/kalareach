//! A definition of a standard macro written as text, which the check reads as one all the same.

/// KR-REQ-03.45: a case beside a test that writes a definition of `println` as text.
fn case() -> u8 {
    3
}

#[test]
fn writes_a_macro_definition_as_text() {
    let _ = stringify!(macro_rules! println { () => {} });
}

#[test]
fn prints_and_calls_the_case() {
    println!("ok");
    assert_eq!(case(), 3);
}
