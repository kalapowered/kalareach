//! Macros whose repetitions open or end inside an item's header, around a generic parameter named
//! `core` and around an enum's body whose variant takes a keyed helper's name.

/// KR-REQ-03.72: a case beside items whose headers a macro's repetition splits.
fn shared() {}

macro_rules! function {
    ($($empty:tt)*) => {
        fn $($empty)* other<core>() {}
    };
}

macro_rules! variant {
    ($($name:ident)?) => {
        $(enum $name)? { shared() }
    };
}

#[test]
fn makes_a_function() {
    function!();
}

#[test]
fn makes_a_variant() {
    variant!(E);
}

#[test]
fn example() {
    shared();
}
