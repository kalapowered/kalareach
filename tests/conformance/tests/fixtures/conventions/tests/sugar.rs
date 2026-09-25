//! A function named like the prelude's `Fn`, and types that write the trait like a call.

/// KR-REQ-03.41: a case named like a trait a type writes like a call.
#[allow(non_snake_case)]
fn Fn() {}

#[test]
fn names_the_trait_in_types() {
    let _: Option<Box<dyn Send + Fn()>> = None;
    let _: Option<&dyn (Fn())> = None;
}
