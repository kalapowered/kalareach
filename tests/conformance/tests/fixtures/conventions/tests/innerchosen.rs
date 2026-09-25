//! An inline module whose files an inner `cfg_attr` may move.

mod nearby {
    #![cfg_attr(all(), path = "picked")]
    pub mod sub;
}

/// KR-REQ-03.66: a case beside a module whose files an inner `cfg_attr` chooses.
fn shared() {}

#[test]
fn example() {
    println!(shared());
}
