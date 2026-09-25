//! A module declared twice, one for each platform.

#[cfg(unix)]
mod inner {
    /// KR-REQ-03.36: a case in a module another declaration replaces on other platforms.
    pub fn case() -> u8 {
        3
    }
}

#[cfg(not(unix))]
mod inner {
    pub use crate::provider::*;
}

mod provider {
    pub fn case() -> u8 {
        4
    }
}

#[test]
fn calls_the_case_by_its_module() {
    assert!(inner::case() > 0);
}
