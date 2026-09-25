//! A target with an item under a derive of another crate's, which may add items beside it.

#[derive(Debug, Clone, helpers::Generate)]
struct Fixture;

/// KR-REQ-03.38: a case beside an item a derive of another crate's may add to.
fn case() -> u8 {
    3
}

#[test]
fn calls_the_case_beside_a_derived_item() {
    let _ = Fixture;
    assert_eq!(case(), 3);
}
