//! A target whose cases and tests an attribute macro may rewrite.

#[rewrite_all]
mod inside {
    /// KR-REQ-03.17: a case in a module an attribute macro may rewrite.
    fn case() -> u8 {
        3
    }

    #[test]
    fn calls_the_case_in_a_module_an_attribute_may_rewrite() {
        assert_eq!(case(), 3);
    }
}

/// KR-REQ-03.18: a case an attribute macro of its own may rename.
#[rename_to(other)]
fn renamed() -> u8 {
    3
}

#[test]
fn calls_a_case_an_attribute_may_rename() {
    assert_eq!(renamed(), 3);
}
