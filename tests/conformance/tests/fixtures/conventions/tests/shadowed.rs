//! A target that defines a macro under the name of a standard library macro.

/// KR-REQ-03.15: a case beside a macro that takes the name `println`.
fn case() -> u8 {
    3
}

macro_rules! println {
    () => {
        fn case() -> u8 {
            4
        }
    };
}

#[test]
fn calls_a_case_after_println() {
    println!();
    assert_eq!(case(), 4);
}
