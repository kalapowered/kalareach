//! A module whose `path` attribute is written with an escape.

#[path = "escaped/ki\u{6_4}.rs"]
mod child;

/// KR-REQ-03.71: a case the path the reading decodes would reach, where the compiler reads another file.
pub fn shared() {}

#[test]
fn example() {
    child::shared();
}
