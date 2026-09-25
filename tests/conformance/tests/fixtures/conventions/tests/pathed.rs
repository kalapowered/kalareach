//! A module file a `path` attribute names from inside an inline module.

mod inline {
    #[path = "declared.rs"]
    pub mod declared;
}

/// KR-REQ-03.59: a case beside a module file the compiler finds under the inline module's directory.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
