//! A test program that expands the macro, beside another that does, after the library has.

const WRITTEN: &[u8] = embed::embed!();

#[test]
fn reads_what_the_library_wrote_too() {
    assert_eq!(WRITTEN, shared::WRITTEN);
}
