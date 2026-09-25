//! A module inside a test's body with a function of a keyed helper's name.

/// KR-REQ-03.28: a case a module inside a test's body has another of.
fn shared() {}

#[test]
fn calls_a_case_of_a_module_it_declares() {
    mod inner {
        fn shared() {}

        pub fn run() {
            self::shared();
        }
    }
    inner::run();
}
