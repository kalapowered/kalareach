//! KR-REQ-03.01: every test of this file.

/// KR-REQ-03.02: a documentation comment above a test.
#[test]
fn documented() {}

// KR-REQ-03.03, and KR-REQ-03.01 again: a plain comment directly above a test.
#[test]
fn commented() {}

#[test]
fn commented_inside() {
    // KR-REQ-03.04, 03.05: a comment inside the body, its second row written short.
    assert_eq!(1 + 1, 2);
}

// ------------------------------------------------------------------------------------------------
// KR-REQ-03.06: a section.
// ------------------------------------------------------------------------------------------------

#[test]
fn first_in_the_section() {}

#[test]
fn second_in_the_section() {}

// ------------------------------------------------------------------------------------------------
// A section that names nothing ends the one before it.
// ------------------------------------------------------------------------------------------------

#[test]
fn kr_req_03_07_named_by_its_name() {}

/// KR-REQ-03.08: a case several tests share.
fn shared() -> u8 {
    3
}

#[test]
fn calls_the_shared_case() {
    assert_eq!(shared(), 3);
}

#[test]
fn has_a_local_of_the_same_name() {
    let shared = || 4;
    assert_eq!(shared(), 4);
}

mod other {
    /// A case of this module's own, which names no row.
    fn shared() -> u8 {
        5
    }

    #[test]
    fn calls_its_own_case_of_the_same_name() {
        assert_eq!(shared(), 5);
    }

    #[test]
    fn calls_the_shared_case_by_its_path() {
        assert_eq!(super::shared(), 3);
    }
}

mod elsewhere {
    /// A case of this module's own, which names no row.
    pub fn shared() -> u8 {
        7
    }
}

mod imported {
    use super::elsewhere::shared;

    #[test]
    fn calls_the_case_it_imported() {
        assert_eq!(shared(), 7);
    }
}

#[test]
fn imports_a_case_of_the_same_name_inside_its_body() {
    use elsewhere::shared;
    assert_eq!(shared(), 7);
}

mod renamed {
    use super::cases::other_case as brought_up;

    #[test]
    fn calls_another_case_by_a_keyed_cases_name() {
        assert_eq!(brought_up(), 9);
    }
}

mod plain {
    /// A case of this module's own, which names no row.
    pub fn brought_up() -> u8 {
        8
    }
}

#[test]
fn calls_through_a_module_its_body_brings_in_under_another_name() {
    use plain as cases;
    assert_eq!(cases::brought_up(), 8);
}

mod hidden {
    /// KR-REQ-03.08: a case of the same name no glob outside this module can bring in.
    #[allow(dead_code)]
    fn check() {}
}

mod sealed {
    mod inner {
        /// KR-REQ-03.08: a case its module's re-export cannot carry past its module.
        #[allow(dead_code)]
        pub(super) fn probe() {}
    }

    #[allow(unused_imports)]
    pub use self::inner::*;
}

mod actual {
    /// A case of this module's own, which names no row.
    pub fn other() {}

    /// Another, which names no row either.
    pub fn another() {}
}

mod facade {
    pub use crate::actual::another as probe;
    pub use crate::actual::other as check;
}

#[allow(unused_imports)]
use hidden::*;
#[allow(unused_imports)]
use sealed::*;
use facade::*;

#[test]
fn calls_the_name_a_glob_brings_in_for_another_case() {
    check();
}

#[test]
fn calls_the_name_a_re_export_cannot_carry_out_of_its_module() {
    probe();
}

mod cases {
    mod deep {
        /// KR-REQ-03.08: the same case, written in a child module.
        pub fn brought_up() -> u8 {
            6
        }

        /// A case of this module's own, which names no row.
        pub fn other_case() -> u8 {
            9
        }
    }

    pub use deep::*;
}

#[test]
fn calls_a_case_its_module_brings_up() {
    assert_eq!(cases::brought_up(), 6);
}

#[test]
fn reads_the_table() {
    assert!(!forms::CASES.is_empty());
}
