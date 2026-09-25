//! Macros whose metavariables stand for a keyword or a `.`, around a generic parameter named `core`,
//! an enum's variant and a method that take names the conventions hold.

/// KR-REQ-03.73: a case beside macros whose metavariables write the items around names it holds.
fn len() -> usize {
    0
}

macro_rules! function {
    ($keyword:tt) => {
        $keyword other<core>() {}
    };
}

macro_rules! variant {
    ($keyword:tt) => {
        $keyword E { len() }
    };
}

macro_rules! measured {
    ($value:expr, $dot:tt) => {
        $value $dot len()
    };
}

#[test]
fn makes_a_function() {
    function!(fn);
}

#[test]
fn makes_a_variant() {
    variant!(enum);
}

#[test]
fn measures_a_vector() {
    assert_eq!(measured!(vec![1_u8], .), 1);
}

#[test]
fn example() {
    assert_eq!(len(), 0);
}

macro_rules! source {
    ($name:ident) => {
        mod holder {
            pub mod $name {}
        }
    };
}

macro_rules! importing {
    ($keyword:tt) => {
        $keyword holder::{core::self};
    };
}

#[test]
fn imports_a_module() {
    source!(core);
    importing!(use);
}
