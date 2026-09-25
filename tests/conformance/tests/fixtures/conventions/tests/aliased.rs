//! A target that imports a standard macro under another standard macro's name.

use std::stringify /* a gap */ as println;

/// KR-REQ-03.24: a case whose call an aliased macro turns into text.
fn shared() {}

#[test]
fn writes_the_call_as_text() {
    let _ = println!(shared());
}
