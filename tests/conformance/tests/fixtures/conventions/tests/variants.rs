//! Two definitions of one test, each under a `cfg` that decides whether a build has it.

/// KR-REQ-03.50: a case only the definition a build leaves out calls.
fn shared() {}

#[cfg(any())]
#[test]
fn example() {
    shared();
}

#[cfg(all())]
#[test]
fn example() {}
