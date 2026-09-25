//! An identifier outside ASCII that the compiler reads as a keyed helper's name.

/// KR-REQ-03.51: a case that a closure replaces, under a name the compiler normalises to its own.
#[allow(non_snake_case)]
fn Kelvin() -> u8 {
    3
}

#[test]
fn calls_the_case_beside_a_closure_of_its_normalised_name() {
    #[allow(non_snake_case)]
    let Kelvin = || 4;
    assert_eq!(Kelvin(), 4);
}
