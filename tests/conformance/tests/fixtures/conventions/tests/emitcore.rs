//! A macro that emits what a `stringify!` holds, inside a module named `core` in a test.

macro_rules! emit {
    (stringify!($($tokens:tt)*)) => { $($tokens)* };
}

/// KR-REQ-03.49: a case a `println!` that the test's own `core` module aliases writes as text.
fn shared() {}

#[test]
fn example() {
    use core::println;
    mod core {
        emit!(stringify!(pub use std::stringify as println;));
    }
    println!(shared());
}
