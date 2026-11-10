//! Git's credential helper for the connection account. It speaks Git's helper protocol and holds
//! no secret: it answers `get` with nothing, and ignores `store` and `erase`.

use std::io::{self, Read as _};
use std::process::ExitCode;

fn main() -> ExitCode {
    let operation = std::env::args().nth(1).unwrap_or_default();
    // Git writes the request on standard input and waits for the helper to read it.
    let mut request = Vec::new();
    if io::stdin()
        .take(64 * 1024)
        .read_to_end(&mut request)
        .is_err()
    {
        return ExitCode::from(1);
    }
    match operation.as_str() {
        "get" | "store" | "erase" => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}
