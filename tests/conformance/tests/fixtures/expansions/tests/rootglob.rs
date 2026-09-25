//! A glob from the root of the paths, which names a crate outside the target, not the local module.

mod helpers {
    /// KR-REQ-03.68: a case whose name an absolute glob may bring in from another crate.
    pub fn shared() {}
}

#[allow(unused_imports)]
use ::helpers::*;

#[test]
fn example() {
    shared();
}
