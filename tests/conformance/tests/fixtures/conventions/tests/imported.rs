//! A `use` of a keyed helper's name from outside the target, in a module a glob brings in.

mod outside {
    pub use elsewhere::shared;
}

#[allow(unused_imports)]
use outside::*;

/// KR-REQ-03.52: a case whose name a crate outside the target may give a trait.
fn shared() {}

#[test]
fn example() {
    let _: Option<Box<dyn Send + shared()>> = None;
}
