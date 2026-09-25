//! An inline module whose `path` attribute moves the files of the modules inside it.

#[path = "elsewhere"]
mod inline {
    pub mod deep;
}

/// KR-REQ-03.61: a case beside a module file the compiler finds where the attribute points.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
