//! A target among whose items a macro is invoked, whose expansion may define a macro of any name.

make_assertions!();

/// KR-REQ-03.19: a case beside a macro invoked among the target's items.
fn case() -> u8 {
    3
}

#[test]
fn calls_a_case_beside_a_macro_invoked_among_the_items() {
    assert_eq!(case(), 3);
}
