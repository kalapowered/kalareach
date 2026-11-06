//! A test program that expands the macro, beside another that does.

const WRITTEN: &[u8] = embed::embed!();

#[test]
fn reads_what_the_macro_wrote_too() {
    assert!(WRITTEN.starts_with(b"written"));
}
