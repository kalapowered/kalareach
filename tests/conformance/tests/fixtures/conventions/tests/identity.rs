//! A target's own `assert` around a `stringify!`, and a module named `core` inside a test.

macro_rules! assert {
    (stringify!($($tokens:tt)*)) => { $($tokens)* };
}

/// KR-REQ-03.48: a case a macro that the test's own `core` module exports defines again.
fn shared() {}

#[test]
fn example() {
    use core::println;
    mod core {
        assert!(stringify!(
            #[macro_export]
            macro_rules! println {
                () => { fn shared() {} };
            }
            pub use crate::*;
        ));
    }
    println!();
    shared();
}
