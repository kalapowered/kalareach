//! Cases an inner attribute, a module inside a test, a `cfg` or a second definition hide.

mod outer {
    #![rewrite_all]

    mod inner {
        /// KR-REQ-03.26: a case under an enclosing module's inner attribute.
        fn case() -> u8 {
            3
        }

        #[test]
        fn calls_the_case_under_an_inner_attribute() {
            assert_eq!(case(), 3);
        }
    }
}

/// KR-REQ-03.27: a case whose own inner attribute may rewrite it.
fn rewritten() -> u8 {
    #![rewrite]
    3
}

#[test]
fn calls_a_case_with_an_inner_attribute() {
    assert_eq!(rewritten(), 3);
}

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

/// KR-REQ-03.29: a case a `cfg` may compile out of the build.
fn gated() -> u8 {
    3
}

#[test]
fn calls_a_case_under_a_cfg() {
    #[cfg(any())]
    gated();
}

/// KR-REQ-03.30: a case its module defines twice, one for each platform.
#[cfg(unix)]
fn twin() -> u8 {
    3
}

#[cfg(not(unix))]
fn twin() -> u8 {
    4
}

#[test]
fn calls_a_case_defined_twice() {
    assert!(twin() > 0);
}
