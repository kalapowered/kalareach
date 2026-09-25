//! A target whose functions export macros under standard names from inside their bodies.

/// KR-REQ-03.21: a case beside a macro a test's body exports under a standard name.
fn case() -> u8 {
    3
}

#[test]
fn exports_println_after_invoking_it() {
    println!();
    assert_eq!(case(), 4);

    #[macro_export]
    macro_rules! println {
        () => {
            fn case() -> u8 {
                4
            }
        };
    }
}

/// KR-REQ-03.22: a case beside a macro another function exports under a standard name.
fn other_case() -> u8 {
    3
}

#[allow(dead_code)]
fn exports_assert_eq() {
    #[macro_export]
    macro_rules! assert_eq {
        ($left:expr, $right:expr) => {
            fn other_case() -> u8 {
                4
            }
        };
    }
}

#[test]
fn calls_beside_an_assert_eq_another_function_exports() {
    assert_eq!(other_case(), 3);
}
