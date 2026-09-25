//! A trait bound written like a call, whose name two globs bring in: one a function, one a trait.

mod functions {
    /// KR-REQ-03.37: a case of a name a trait brought in beside it also has.
    pub fn shared() {}
}

mod traits {
    #[allow(non_camel_case_types)]
    pub trait shared {}
}

#[allow(unused_imports)]
use functions::*;
#[allow(unused_imports)]
use traits::*;

#[test]
fn names_the_trait_in_a_bound() {
    let _: Option<Box<dyn Send + shared()>> = None;
}
