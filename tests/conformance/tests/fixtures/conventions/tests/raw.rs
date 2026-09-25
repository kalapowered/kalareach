//! A target that defines a macro named `macro_rules` and invokes it by its raw name.

macro_rules! r#macro_rules {
    () => {
        fn case() -> u8 {
            4
        }
    };
}

/// KR-REQ-03.20: a case beside an invocation of a macro named `macro_rules`.
fn case() -> u8 {
    3
}

#[test]
fn invokes_a_macro_by_the_raw_name_macro_rules() {
    r#macro_rules!();
    assert_eq!(case(), 4);
}
