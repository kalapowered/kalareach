//! Calls that a macro or attribute may rewrite, move into another module, or give another meaning.

use custom_derives::Clone;

#[allow(non_snake_case)]
mod Pin {
    /// KR-REQ-03.11: a case of the name an expansion brings in for itself.
    pub fn new(_: &u8) {}
}

#[tokio::test]
async fn calls_a_name_inside_a_macro_that_brings_in_its_own() {
    tokio::select! {
        _ = async {} => { let _ = Pin::new(&1_u8); }
    }
}

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

/// KR-REQ-03.14: a case a plain test calls, which keys it.
fn plain() -> u8 {
    7
}

#[test]
fn calls_the_case_plainly() {
    assert_eq!(plain(), 7);
}
