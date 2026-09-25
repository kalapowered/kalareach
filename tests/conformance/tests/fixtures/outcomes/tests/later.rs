//! A test binary Cargo runs after the library's, so a step that stops at the library's failing
//! test never reaches it.

/// KR-REQ-04.07.
#[test]
fn runs_after_the_library() {}
