//! Two definitions of one test in a target with no helper, each keyed to a row of its own.

#[cfg(any())]
/// KR-REQ-03.55: the row of the definition a build leaves out.
#[test]
fn example() {}

#[cfg(all())]
/// KR-REQ-03.56: the row of the definition a build has.
#[test]
fn example() {}
