//! The only test of its binary, so that the line the harness writes after the half line is the
//! test's own result.

use std::io::Write;

/// KR-REQ-04.11.
#[test]
fn leaves_half_a_line_on_standard_error() {
    // Standard error is written to directly, which the harness's capture does not reach, and the
    // line is left open: the next line the harness writes follows it, as it follows the first piece
    // of a message that is written in pieces.
    let _ = std::io::stderr().write_all(b"this host has no model file, ");
}
