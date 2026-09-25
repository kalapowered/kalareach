//! A `use` from the root of the paths, which names a crate outside the target, not the local module.

mod helpers {
    /// KR-REQ-03.64: a case whose name an absolute `use` brings in from another crate.
    pub fn shared() {}
}

use ::helpers::shared;

#[test]
fn example() {
    shared();
}
