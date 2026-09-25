//! Cases a macro can define again or move a call of, and a derive imported under a standard name.

use custom_derives::Clone;

/// KR-REQ-03.12: a case a macro can define again, or move a call of into another module.
fn shared() -> u8 {
    3
}

macro_rules! defines_a_case {
    () => {
        fn shared() -> u8 {
            4
        }
    };
}

#[test]
fn calls_a_name_after_a_macro_with_a_comment_before_its_bang() {
    defines_a_case /* a gap */ !();
    assert_eq!(shared(), 4);
}

macro_rules! captures {
    ($e:expr) => {{
        fn shared() -> u8 {
            5
        }
        $e
    }};
}

#[test]
fn calls_a_name_inside_a_macro_at_the_end_of_a_range() {
    let _ = 0..captures!(shared());
}

macro_rules! in_module {
    ($e:expr) => {{
        mod nested {
            fn shared() -> u8 {
                2
            }
            pub fn run() -> u8 {
                $e
            }
        }
        nested::run()
    }};
}

#[test]
fn calls_its_module_by_path_inside_a_macro_that_moves_the_call() {
    assert_eq!(in_module!(self::shared()), 2);
}

/// KR-REQ-03.13: a case beside a derive the target imports under a standard trait's name.
fn built() -> u8 {
    6
}

#[test]
fn calls_a_case_beside_a_derive_of_an_imported_name() {
    #[derive(Clone)]
    struct Fixture;
    assert_eq!(built(), 6);
}
