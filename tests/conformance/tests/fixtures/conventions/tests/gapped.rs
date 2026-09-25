//! A target that defines a macro under a standard name with a comment inside the definition's head.

macro_rules /* a gap */ ! println {
    () => {
        fn case() -> u8 {
            4
        }
    };
}

/// KR-REQ-03.23: a case beside a macro whose definition a comment splits.
fn case() -> u8 {
    3
}

#[test]
fn calls_a_case_after_println() {
    println!();
    assert_eq!(case(), 4);
}
