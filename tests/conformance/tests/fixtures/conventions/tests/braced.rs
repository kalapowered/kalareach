//! Macros whose repetitions end right after an item's keyword, or open after a macro's braces in an
//! item's header.

/// KR-REQ-03.74: a case beside items whose headers a macro's repetition splits past what looks like
/// their end.
fn shared() {}

macro_rules! ty {
    () => {
        u8
    };
}

macro_rules! function {
    ($($attribute:meta)?) => {
        $(#[$attribute] fn)? first() {}
    };
}

macro_rules! returning {
    ($($empty:tt)*) => {
        fn second() -> ty!{} $($empty)* { 0 }
    };
}

#[test]
fn makes_functions() {
    function!(allow(dead_code));
    returning!();
    assert_eq!(second(), 0);
}

#[test]
fn example() {
    shared();
}
