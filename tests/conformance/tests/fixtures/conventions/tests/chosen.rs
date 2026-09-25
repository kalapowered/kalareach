//! A module whose file a `cfg_attr` may choose.

#[cfg_attr(unix, path = "chosen/other.rs")]
mod options;

/// KR-REQ-03.62: a case beside a module whose file a `cfg_attr` chooses on some platforms.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case() {
    assert_eq!(case(), 3);
}
