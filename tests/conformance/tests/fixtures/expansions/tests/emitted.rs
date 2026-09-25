//! A macro that emits the tokens a `stringify!` in its arguments holds.

macro_rules! emit {
    (stringify!($($tokens:tt)*)) => { $($tokens)* };
}

#[allow(dead_code)]
fn exports() {
    emit!(stringify!(
        #[macro_export]
        macro_rules! println { () => { fn shared() {} }; }
    ));
}

/// KR-REQ-03.39: a case beside a macro another macro emits from what a `stringify!` holds.
fn shared() {}

#[test]
fn prints_and_calls_the_case() {
    println!();
    shared();
}
