//! A module a `cfg` leaves out, whose name an import takes in its place.

mod helpers {
    /// KR-REQ-03.42: a case a module under a `cfg` would lead to.
    pub fn shared() {}
}

#[cfg(any())]
mod bridge {
    pub use crate::helpers::shared;
}

#[allow(unused_imports)]
use replacement::bridge;

mod replacement {
    pub mod bridge {
        pub fn shared() {}
    }
}

#[test]
fn calls_through_the_name_of_a_module_a_cfg_leaves_out() {
    bridge::shared();
}
