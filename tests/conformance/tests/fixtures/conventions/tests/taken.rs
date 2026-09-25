//! Names a keyed helper shares with a constant and with a trait.

/// KR-REQ-03.34: a case a `cfg` leaves out, beside a constant of the same name.
#[cfg(any())]
fn constant() {}

#[allow(non_upper_case_globals)]
const constant: fn() = || {};

#[test]
fn calls_a_name_a_constant_also_takes() {
    constant();
}

/// KR-REQ-03.35: a case whose name its module also takes, for a trait.
fn imported() {}

#[allow(unused_imports)]
use std::ops::Fn as imported;

#[test]
fn names_a_trait_of_the_same_name_in_a_type() {
    let _: Option<&dyn imported()> = None;
}
