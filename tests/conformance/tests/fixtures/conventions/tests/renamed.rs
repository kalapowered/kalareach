//! A trait renamed to a keyed helper's name, in a module whose names a glob brings in.

mod traits {
    pub use std::ops::Fn as shared;
}

#[allow(unused_imports)]
use traits::*;

/// KR-REQ-03.46: a case whose name a bound in a type takes for the renamed trait.
fn shared() {}

#[test]
fn example() {
    let _: Option<Box<dyn Send + shared()>> = None;
}
