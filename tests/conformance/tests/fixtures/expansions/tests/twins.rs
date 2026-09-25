//! A case a `cfg` may leave out of a build, beside a test of the same name.

/// KR-REQ-03.33: a case a `cfg` leaves out, beside a test of the same name.
#[cfg(any())]
fn shared() {}

#[test]
fn shared() {}

#[test]
fn calls_a_name_a_test_also_takes() {
    shared();
}
