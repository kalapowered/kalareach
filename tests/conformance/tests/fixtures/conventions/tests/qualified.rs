//! A keyed helper named like the prelude's `Fn`, in a module whose glob brings the trait in.

mod helpers {
    #[allow(unused_imports)]
    pub use std::ops::*;

    /// KR-REQ-03.47: a case a bound in a type reaches by its path, as the trait.
    #[allow(non_snake_case)]
    pub fn Fn() {}
}

#[test]
fn example() {
    let _: Option<Box<dyn Send + helpers::Fn()>> = None;
}
