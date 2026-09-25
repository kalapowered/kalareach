//! A target with a module named `core`, whose `use core::...` is not the standard library's.

mod core {
    macro_rules! custom {
        () => {
            fn shared() {}
        };
    }

    pub(crate) use custom as println;
}

/// KR-REQ-03.40: a case beside a macro a local `core` module brings in under a standard name.
fn shared() {}

#[test]
fn prints_through_the_local_core_and_calls_the_case() {
    use core::println;
    println!();
    shared();
}
