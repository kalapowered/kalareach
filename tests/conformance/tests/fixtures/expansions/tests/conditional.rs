//! Names a `cfg` may bring in or leave out of a build.

mod helpers {
    /// KR-REQ-03.43: a case an import under a `cfg` brings in on one platform only.
    pub fn shared() {}
}

mod other {
    pub fn shared() {}
}

#[cfg(unix)]
use helpers::shared;
#[cfg(not(unix))]
#[allow(unused_imports)]
use other::*;

#[test]
fn calls_a_name_a_cfg_imports() {
    shared();
}

#[cfg(unix)]
mod only_on_unix {
    /// KR-REQ-03.44: a case in a module a `cfg` leaves out on other platforms.
    pub fn case() -> u8 {
        3
    }

    #[test]
    fn calls_the_case_in_its_module() {
        assert_eq!(case(), 3);
    }
}
